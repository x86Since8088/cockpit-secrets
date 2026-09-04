# Architecture — cockpit-secrets

How a passphrase gets from a keyboard to a KDF and back out of existence, and
why the shape of the process tree — not a setting, not a policy — is what makes
"prompted every time" true.

Read [`CONTRACT.md`](CONTRACT.md) for the verb interface,
[`THREAT-MODEL.md`](THREAT-MODEL.md) for who we are defending against, and
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) for the hazard ids cited throughout.

---

## The whole picture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  BROWSER   https://edt1:9090/secrets                                │
  │                                                                     │
  │   index.html + secrets.js + secrets.css   (no build step, no CDN,   │
  │                                            no WASM, default CSP)    │
  │                                                                     │
  │   unlock modal ──▶ ONE function-scoped `pw` variable                │
  │                    │                                                │
  │                    │  no localStorage / sessionStorage / IndexedDB  │
  │                    │  no cookie · no global · no data-attribute     │
  │                    │  no <form> · autocomplete="off"        (I11)   │
  └────────────────────┼────────────────────────────────────────────────┘
                       │  cockpit.spawn(argv, {superuser: …})
                       │  JSON request written to the child's STDIN,
                       │  then the stream is CLOSED               (I10)
                       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  COCKPIT BRIDGE (cockpit-ws → cockpit-bridge, per session)          │
  │                                                                     │
  │  user class  : bridge runs as the logged-on user → fork/exec        │
  │  admin class : bridge escalates (pkexec/sudo) → fork/exec as root   │
  │                                                                     │
  │  The passphrase is bytes in a pipe. Not argv. Not the environment.  │
  └────────────────────┬────────────────────────────────────────────────┘
                       │  fd 0
                       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  /usr/local/sbin/secrets-admin      ← ONE PROCESS, ONE OPERATION    │
  │                                                                     │
  │  1. harden_process()   RLIMIT_CORE=0 · PR_SET_DUMPABLE=0 ·          │
  │                        umask 077 · mlockall(best effort, reported   │
  │                        honestly) · close inherited fds >2    (I14)  │
  │  2. read stdin, ≤1 MiB, parse ONE JSON object               (I10)   │
  │  3. load /etc/cockpit-secrets/safes.d/*.json, validate each         │
  │     against schema/safe-registry.schema.json; drop what fails (I1)  │
  │  4. resolve the request's `safe` ID to a path — the ONLY place a    │
  │     path is ever produced                                    (I4)   │
  │  5. access class gate, from KERNEL identity, on THIS verb     (I2,  │
  │     geteuid/getuid/getgroups/SUDO_UID — never the request body) I3  │
  │  6. lockout check for (uid, safe id)                        (I16)   │
  │                                                                     │
  │        ┌────────────── backends/base.py ──────────────┐             │
  │        │ Secret(bytearray)  open_safe_fd()  Limits    │             │
  │        │ atomic_replace()   LockFile()     redact()   │             │
  │        └───────────────────┬──────────────────────────┘             │
  │                            ▼                                        │
  │        backends/kdbx.py  (pykeepass)   backends/psafe3.py           │
  │                            │                                        │
  │  7. clamp KDF params BEFORE deriving                        (I7)    │
  │  8. derive · decrypt · VERIFY THE MAC (compare_digest)      (I6)    │
  │  9. only now may a value leave the adapter                          │
  │ 10. zero every Secret in `finally`                          (I14)   │
  │ 11. print ONE JSON object on stdout · audit line to disk    (I15)   │
  │ 12. exit — the address space, and the passphrase, are gone          │
  └────────────────────┬────────────────────────────────────────────────┘
                       │  os.open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)
                       │  os.fstat(FD) — never a second stat of the path
                       ▼                                          (I5)
  ┌─────────────────────────────────────────────────────────────────────┐
  │  /etc/cockpit-secrets/safes/lab-dc.kdbx     0600 root:root          │
  │  ~/.local/share/cockpit-secrets/mine.psafe3 0600 user:user          │
  │                                                                     │
  │  writes:  backup ring → <path>.tmp-<pid> → fsync → os.replace →     │
  │           fsync(dir), under <name>.kdbx.lock / <name>.plk           │
  │                                                       (I12, I13)    │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## Where the passphrase exists, hop by hop

This is the table the rest of the design answers to. "Lifetime" is how long the
passphrase is readable at that hop in the **default** configuration.

| # | Hop | Representation | Lifetime | What ends it | What could still read it |
|---|---|---|---|---|---|
| 1 | The user's keyboard, into `<input type=password>` | a DOM string in the input's `value` | from the first keystroke until the modal closes | `input.value = ""` and reassignment before the modal is removed | anything running in the Cockpit origin — which is why there is no CSP relaxation (I9) and no second page handling this |
| 2 | `secrets.js`, one function-scoped variable | a JS `String` on the GC heap | one `cockpit.spawn` call | overwritten (`pw = "\0".repeat(pw.length); pw = null`) then GC'd | an XSS anywhere in the Cockpit origin. It is never persisted, so a *later* XSS finds nothing (I11) |
| 3 | The Cockpit channel, browser → `cockpit-ws` | bytes inside the session's TLS/WebSocket frame | one round trip | the frame is consumed | Cockpit's own transport security, which we depend on and do not re-implement |
| 4 | `cockpit-bridge`, and the escalation helper for admin safes | bytes in a pipe buffer | until the helper reads them | `read()` drains the pipe; the bridge does not retain it | root. Documented as out of scope in THREAT-MODEL.md |
| 5 | `secrets-admin` stdin → the JSON parser | a Python `str` inside the parsed request dict | microseconds to milliseconds | process exit | **this is a copy we cannot wipe.** `str` is immutable and interned; see below |
| 6 | `Secret` — `bytearray` in the helper | wipeable bytes | one verb | `zero()` in `__exit__` and in a `finally` | root, or a swap page if `mlockall` failed (it is *reported*, never assumed) |
| 7 | `Secret.str_view()` → the KDF / `pykeepass` | a Python `str` again | the duration of the derivation | process exit | the leak we cannot close, stated plainly (I14) |
| 8 | The derived key, in the crypto library | library-internal buffers | the duration of the operation | process exit | root |
| 9 | Disk | **never** | — | — | — |

Hops 5 and 7 are the honest part. **Python cannot wipe a `str`**: it is immutable
and small strings are interned, so the moment the JSON parser produces the
passphrase, or `pykeepass` demands one, the interpreter owns a copy on the GC
heap that no code of ours can overwrite. `backends/base.py` says so in the
`Secret` docstring, `str_view()` is a method rather than a property so that every
use of it is greppable, and this document says so here rather than implying a
guarantee we do not have.

What we do instead of pretending: **make the window as short as a window can
be.** Hop 5 to hop 8 lasts one operation. The process then exits and the whole
address space — every `str` copy, every library buffer, every decrypted entry —
is returned to the kernel. That is measured in milliseconds, not hours, and it is
the single largest mitigation in the program.

### Where a *decrypted value* exists

Same idea, one hop shorter. A revealed password exists as a Python `str` inside
`secrets-admin` between the MAC verification and the `json.dumps`, then as JSON
on stdout, then in one JS variable that the UI re-masks and drops after
`Limits.REVEAL_SECONDS` (default 15 s, I17). It is never written to disk, never
placed in a browser storage API, and never included in `entries()` output —
`reveal` is the only door, one field at a time, and each opening is one audit
line naming the verb, the safe, the uid and the outcome, never the value (I15).

---

## Why one process per operation *is* the prompt-every-time guarantee

The requirement is "the passphrase is demanded on every unlock unless a key is
deliberately stored". There are two ways to meet it.

**The way that does not work** is a long-lived daemon that holds unlocked
databases and a policy saying "expire them after N minutes". Every bug in that
daemon, every missed timeout, every restart-that-restored-state, and every
"convenience" patch turns into a safe that is open when nobody is looking at it.
The policy is a promise, and promises are only as good as the code that keeps
them.

**The way this project works** is that there is nowhere to keep a handle:

- The browser calls `cockpit.spawn` **per verb**. The bridge forks a
  `secrets-admin`, writes one JSON request to its stdin, closes the stream,
  reads one JSON object back, and reaps the child.
- A handle is a 128-bit random token bound to `(uid, safe id, pid)`. When the
  process exits, the pid is gone and so is every key derived inside it. Nothing
  is written to `/run`, `/var/lib` or anywhere else that could outlive it.
- Therefore the *next* verb starts from a locked file and needs the passphrase
  again. Not because a timer fired. Because the thing that held the key does not
  exist any more.

That is what "true by construction rather than by policy" means: to break it you
would have to change the process model, not flip a setting. There is no
"remember this passphrase" checkbox to add, because there is no place to put the
answer.

Two deliberate, opt-in exceptions, and their shapes are chosen to keep the
property visible:

1. **The multi-verb `open` session.** A mutating flow (unlock → edit → save)
   needs several verbs under one unlock. It runs inside a **single**
   `secrets-admin` invocation held open on its stdin stream. The unlock still
   happened once, for this flow, in this process, and the session ends when the
   Cockpit channel closes, the idle timer fires, or `lock` is called. Closing the
   browser tab closes the channel, which kills the process, which ends the
   unlock. The lifetime is bounded by something the user can see.
2. **`secrets-agent` (I18), off by default, opt-in per safe.** An `AF_UNIX`
   socket in a `0700` per-user run dir, peer identity from `SO_PEERCRED`, handle
   bound to the creating uid, a hard idle timeout *and* an absolute lifetime
   neither of which any client can extend, and a persistent "unlocked — N s
   remaining" banner in the UI. An unlocked safe must never be invisible. This is
   the one place the project rebuilds the thing it exists to avoid, which is why
   it is per-safe, defaults off, and Task 7 is allowed to drop it entirely rather
   than ship it half-defended.

---

## Access classes, concretely

| | `access: "user"` | `access: "admin"` (**the default**) |
|---|---|---|
| **`cockpit.spawn` call** | `cockpit.spawn(["/usr/local/sbin/secrets-admin", VERB], {err: "message", superuser: null})` | `cockpit.spawn(["/usr/local/sbin/secrets-admin", VERB], {err: "message", superuser: "require"})` |
| **Helper `geteuid()`** | the logged-on user's uid | `0` — any other value and the verb is refused |
| **Helper `getuid()` / real caller** | same as euid | recovered from `SUDO_UID` / `PKEXEC_UID` when escalated, else `getuid()` |
| **Extra gate** | the safe file's `st_uid` must equal the caller | the real caller must be in one of the entry's `groups` (default: the host admin group, `sudo`/`wheel`) |
| **Safe file** | `0600`, owned by that user | `0600 root:root` |
| **Safe location** | a path that user owns, typically under `$HOME` | `/etc/cockpit-secrets/safes/`, dir `0700 root:root` |
| **Registry entry** | `0644 root:root` — the *entry* is root-owned even for a user safe | `0644 root:root` |
| **Blast radius of a helper bug** | that one user's own files | root |

`manifest.json` declares `"superuser": "try"`. The page is usable with no
escalation at all — user safes work, admin safes are listed but locked with the
reason shown — and gains the admin class when Cockpit's Administrative access is
turned on. When it is off, the UI shows Cockpit's own standard prompt to turn it
on rather than a bespoke error.

Three things about this that are easy to get wrong and are therefore stated
explicitly:

- **The class is re-derived and re-checked inside every verb**, not once at
  start-up and not at the point the safe list is built. A caller who can reach
  the helper can call any verb in any order.
- **The check reads the kernel, not the request.** `geteuid`, `getuid`,
  `getgroups`, `SUDO_UID`. A request field claiming `"access": "user"` on an
  admin safe changes nothing; it is not consulted.
- **The browser's version of the check is decoration.** The UI greys out what a
  caller cannot use so the page is honest about what is there, but greying out is
  not what stops anyone (I3). `cockpit-guac-rdp` learned this: its `I4` was an
  `if (t.admin && !isAdmin)` in JS, and it was bypassable by driving the backend
  directly.

## Two privilege levels, one binary

There is exactly one helper, `/usr/local/sbin/secrets-admin` (`0755 root:root`),
and it is invoked two ways. Running everything as root would make every
user-class safe a root-readable file and every helper bug a root bug; running
everything unescalated cannot open a root-owned safe at all. One binary, two
invocations, least privilege *per safe* rather than per plugin (I2).

The helper never trusts the invocation to tell it which mode it is in. It reads
the registry entry, sees the class, and asserts the euid it requires.

## The file, and the two things that go wrong around it

**Opening (I4, I5).** Verbs carry a registry `id`. The helper resolves it to a
path, then `os.open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` and `os.fstat` **the
returned fd** — never a second `stat` of the path, because the path can change
between the two calls and the fd cannot. The fstat must show a regular file, the
expected `st_uid`, and no group or other permission bits; no ancestor directory
may be group- or other-writable unless it is sticky. Everything afterwards uses
that same fd. This is what stops a user-class safe path being swapped for a
symlink to `/etc/shadow` between the registry read and the open, on a helper that
may be root.

**Writing (I12, I13).** Nothing touches disk until `save`, and `save` is:

1. re-verify the caller and the access class;
2. re-fingerprint the file — `(mtime_ns, size, sha256)` captured at unlock — and
   raise `conflict` on any mismatch, writing nothing;
3. copy the current file into the backup ring, `0600`, pruned to `keep`
   generations, **before the first new byte exists**;
4. write `<path>.tmp-<pid>` in the **same directory**, `O_EXCL`, `0600` — the
   same directory because `os.replace` is only atomic within a filesystem, and
   never `/tmp` because it is a different filesystem and world-readable;
5. `fsync` the temp fd, `os.replace` onto the target, `fsync` the directory fd;
6. clean up the temp file on every failure path.

The target file is never opened for writing. The only operation that touches it
is the rename, which is atomic, so a `SIGKILL` at any point leaves either the
whole old file or the whole new one. The whole sequence runs under the desktop
clients' own lock files — `<name>.kdbx.lock` for KeePass/KeePassXC, `<name>.plk`
for Password Safe — and a foreign lock is a `conflict` naming the holder, never a
forced write. We remove only a lock we created.

## What crosses which boundary

| Boundary | Crosses it | Never crosses it |
|---|---|---|
| browser → bridge | the JSON request, passphrase included, on stdin | anything on argv or in the environment (I10) |
| bridge → helper | fd 0 (the request), fd 1 (one JSON object), fd 2 (diagnostics) | inherited fds — `harden_process` closes everything above 2 |
| helper → backend | a `Secret`, a validated registry entry, an open validated fd | a caller-supplied path (I4) |
| backend → helper | metadata always; a decrypted value **only after the MAC verified** (I6) | a password in `entries()` output — `reveal` is the only door |
| helper → stdout | exactly one JSON object | a traceback, a value, a path from the request (I15) |
| helper → audit log | timestamp, verb, safe id, caller uid, outcome, duration | any value, any entry title, any traceback (I15) |
| helper → disk | the safe (atomically), the backup ring, the lock file | a temp file containing a secret; anything in `/tmp` |
| helper → browser storage | **nothing** | `localStorage`, `sessionStorage`, IndexedDB, cookies (I11) |

## The property everything above serves

> A decrypted value exists only inside one short-lived helper process, only after
> its MAC has verified, only for a caller the kernel says is entitled to it, and
> only for as long as one operation takes.

Every design decision in this document is downstream of that sentence. Where we
cannot achieve it — an unwipeable `str`, a root-equivalent attacker, a clipboard
that is a shared OS resource — the honest thing is written down here and in
[`THREAT-MODEL.md`](THREAT-MODEL.md) rather than papered over.
