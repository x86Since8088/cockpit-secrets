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
  │  3. load the registry: /etc/cockpit-secrets/safes.d/*.json, and     │
  │     — ONLY when euid != 0 — ~/.config/cockpit-secrets/safes.d/      │
  │     Validate each against schema/safe-registry.schema.json and      │
  │     drop what fails; force access:'user' on every per-user          │
  │     entry; a system id always wins a collision       (I1, C4)       │
  │  4. resolve the request's `safe` ID to a path — the ONLY place a    │
  │     path is ever produced                                    (I4)   │
  │  5. access class gate, from KERNEL identity, on THIS verb     (I2,  │
  │     geteuid/getuid/getgroups/SUDO_UID — never the request body) I3  │
  │  6. RESERVE one attempt — check AND increment, under an       I16,  │
  │     exclusive flock, before step 7: per (REAL uid, safe id)   I39,  │
  │     and per safe id                                           I40   │
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
   remaining" banner in the UI. An unlocked safe must never be invisible.

   **What it holds is a TICKET, not a key.** `secrets-admin` sends the agent a
   handle and never any key material, so the agent cannot hand a later helper
   process an unlocked database — which means the passphrase is still prompted
   on every unlock, and point 1 above is undisturbed. What the ticket buys is
   the *other* half of I18: an unlock that can be SEEN (`health.agent` answers
   with no handle and no passphrase, so a hold survives a page reload) and
   REVOKED (`lock` with a bare safe id reaches it after the helper that minted
   it has exited). The daemon's `put` still accepts optional key material,
   because I18 sanctions a real reattach as a per-safe opt-in and a future one
   will need it — but nothing in this tree produces any, and the helper strips
   a `material` key out of any reply at the door. docs/CONTRACT.md, "What the
   agent holds", is the authority; deleting that strip is the deliberate act
   that would start implementing a reattach.

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
| **Registry entry** | `0644 root:root` in the system registry, **or** `0600 <user>` in that user's own `~/.config/cockpit-secrets/safes.d/`, which only an unescalated helper reads and which cannot declare anything but `access: "user"` | `0644 root:root`, always |
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

## The registry is the trust root, and these are the first verbs that write it

Everything above this line treats the registry as a given. It is not: **it is what every other
control in this program is downstream of.**

- It says which files are safes. Nothing inside a KDBX or `.psafe3` file records who may open
  it, so if the access class is not imposed from outside the file it does not exist (I1).
- It says where each safe lives — the one place a path is ever produced, because no verb takes
  one (I4).
- It says what class each safe is, which decides whether the helper runs as root or as the
  user, which decides the blast radius of every bug below it (I2, I3).
- It says whether a safe may be written, exported, or opened with no passphrase at all.

Until 0.4.0 the only way to add a line to it was for root to open an editor. That was a real
control — an unforgeable one — and giving it up is what makes `safe-create` and `safe-import`
the most dangerous change in the project. Three things could have been built instead of what
was built, and naming them is how the design stays honest:

1. **An arbitrary-file-write primitive into a root-owned directory.** Closed by C1: the caller
   sends an `id`, never a path or any component of one, and the helper mints
   `<managed dir>/<id>.<ext>` itself. Closed again by C2: the id must match
   `^[a-z0-9][a-z0-9-]{1,62}$` *before* it reaches a filesystem call.
2. **A way for an unprivileged user to declare a root-owned file to be their own "user-class"
   safe.** Closed by the per-user registry's rules: a root-mode helper never opens it, every
   entry loaded from it is forced to `access: "user"`, and its `path` still has to survive
   `open_safe_fd` — a regular file **the caller owns**, `0600`, `O_NOFOLLOW`, `fstat` on the
   fd (I5). Declaring `/etc/shadow` a user safe produces `access-denied`, not a read.
3. **A way to overwrite an existing safe and destroy every credential in it.** Closed by C2's
   second half: an id already in the registry, a minted path that already exists, or a minted
   entry file that already exists is `conflict`. **Nothing here ever overwrites.** The only
   verb that destroys is `safe-delete`, which needs a token naming the safe and refuses unless
   the entry's path is one this program itself minted.

`docs/CONTRACT.md`, "The verbs that WRITE the registry", is the normative version of all of
that. What follows is where the bytes are.

### Creating a safe — `safe-create`

```
browser ─stdin JSON {id,label,format,access,new_password,keyfile_b64,make_keyfile,kdf}─▶
   │                                    secrets-admin (one process, one operation)
   │   1  validate id against new_id_pattern; label against the C0 and Cf bans
   │                                                 ← before any filesystem call
   │   2  access gate from kernel identity            ← admin unless the request says "user";
   │                                                    "user" while euid==0 is refused
   │   3  refuse a colliding id / minted path / minted entry file      → conflict
   │   4  Backend.create_new: build the database IN MEMORY (KDBX 4.1 + Argon2id, or
   │      PWS3 at the write floor), then RE-OPEN IT FROM COLD with the same
   │      passphrase through the reader an unlock will use.  It is the BACKEND
   │      that does both, so there is one implementation of "a created safe must
   │      read back" and no way for this file to skip it
   │   5  _land_new_safe:
   │        a  <managed dir>/<id>.<ext>.tmp-<pid> → fsync → os.replace → fsync(dir)  0600
   │        b  validate the entry against the schema → 50-<id>.json, same atomic path
   │        c  if (b) fails, UNLINK (a) again — a create leaves both halves or neither
   ▼
one JSON object · one audit line naming the verb, the id, the uid and the outcome
```

Step 4 is I24/I41 applied to creation: *every save re-opens its own bytes through the reader a
later unlock will use*, and a brand-new safe is a save with nothing before it. A safe nobody
can unlock must never become a registry entry.

Step 5c is I45, and it is why the two writes are one function rather than two statements. They
used to be two, with no `try` around the pair — so a registry write that failed (a read-only
`/etc`, ENOSPC, a `SIGKILL` in the window) left the file with nothing pointing at it, and that
BURNED THE ID from inside the program: `safe-create` answered `conflict`, `list` did not show
it, and `safe-forget` and `safe-delete` both needed an entry that did not exist. It is safe to
unlink there and nowhere else, because the path was minted seconds earlier, `_refuse_conflict`
proved nothing was at it, and step 5a created it.

**`safe-create` builds nothing itself.** It used to edit pykeepass's blank template in this
file, and doing so it inherited three published constants — the master seed, the encryption IV
and the inner protected-stream key — into every safe it made. The last of those is the
ChaCha20 key masking every protected value in the XML, so until the operator's first save it
was a public constant and two safes created here shared a keystream. It also called
`Secret.str_view()`, minting an unwipeable `str` of the new master passphrase — the exact hop
`backends/kdbx.py`'s own docstring says never happens inside it (I14). `Backend.create_new`
reseeds all three at the cipher's own nonce length and never touches `str_view`.

### Adopting a safe — `safe-import`, and where the uploaded bytes live at each moment

`safe-import` is **five ordinary verbs**, not a session: one `cockpit.spawn` per step, one
JSON object out of each, tied together by a `staging` token that `begin` mints and binds to
`(real uid, id, access class)`. The staging directory **outlives the helper process** — which
is the whole reason the steps can be separate verbs, and the reason the idle timer below is
load-bearing rather than decorative. **No credential travels before the commit step.**

```
  verb               bytes live here                              credential?
  ─────────────────────────────────────────────────────────────────────────────
  import-begin       nothing yet.  A staging directory is made:   NO
                     <staging root>/<32 hex>/ 0700, holding
                     `blob` and `meta.json`, each created
                     O_CREAT|O_EXCL|O_NOFOLLOW 0600.
                     NEVER the final path.  NEVER /tmp.
                     A declared total over MAX_SAFE_BYTES is
                     refused before one byte arrives.

  ...-chunk  ×N      in that staged file, and nowhere else.       NO
                     The cap is enforced INCREMENTALLY as each
                     chunk lands, never after.

  ...-inspect        same file.  sha256 of the whole thing is     NO
                     verified, the 4-byte signature must be one
                     of the two we know, the UNAUTHENTICATED
                     header is parsed, and the Limits KDF clamps
                     are applied to the DECLARED parameters —
                     so a KDF bomb dies here, before anyone is
                     asked for a passphrase.
                     A failure here DESTROYS the staging.

  ...-commit         the staged file is read ONCE into memory,     YES — first and
                     its declared sha256 re-verified against       only time
                     THOSE bytes, and THAT SAME ARRAY is what
                     must open with the credential and what is
                     then written.  There is no second read to
                     diverge from the first (I43).  Landing is
                     tmp → fsync → os.replace → fsync(dir), and
                     the file is UNLINKED AGAIN if the registry
                     entry cannot be written (I45).  Then the
                     staging is destroyed.
                     A WRONG PASSPHRASE KEEPS THE STAGING.

  ...-abort          staging destroyed.                           n/a
  idle 900 s         staging destroyed, counted from its LAST use  n/a
  channel drops      NOTHING HAPPENS.  The staging outlives the
                     process, so a closed tab leaves an encrypted
                     blob until the idle timer reaps it.  The page
                     calls abort on cancel; the timer covers the
                     case where it cannot.
  SIGKILL            same as a dropped channel, and swept the same
                     way — on the next verb of ANY kind, because
                     the sweep is in init_state.  Reported by
                     health.import_staging as a COUNT, never as
                     a token.
```

Two properties of that picture are the whole reason for its shape:

- **The only bytes that can ever land are bytes that are demonstrably a safe the uploader can
  already open.** That single sentence is what stops the verb being an arbitrary-write
  primitive, and it is why the credential is required at commit even though the file is
  already on the host by then.
- **The passphrase exists for one request, not for the whole upload.** Collecting it in the
  file picker would hold it in browser memory for as long as a 100 MiB transfer takes — the
  window I11 and I14 exist to shrink. And it costs nothing to wait, because a KDBX/PWS3
  header is *not secret*: anyone holding the file can read the format, version, cipher and KDF
  out of it, so `import-inspect` answers with no credential at all. The page must label that
  summary as read from an unauthenticated header, because on a tampered file it is what the
  tamperer wrote.

The staging root is `<state root>/import/`, `0700`, owned by the identity the helper is
running as — `/var/lib/cockpit-secrets/state/import/` for an admin-class import,
`~/.local/state/cockpit-secrets/state/import/` for a user-class one. One caller may hold at
most eight stagings at once, which bounds "start ten thousand uploads" without bounding
anything an honest operator does.

**And at most two of the expensive verbs may RUN at once** (`IMPORT_MAX_CONCURRENT`), taken as
a non-blocking `flock` on a slot file in that same root. The two bounds count different things
and only the first existed before 0.4.0: every helper invocation is its own process, so
`IMPORT_MAX_STAGINGS` did nothing at all about 32 simultaneous `import-inspect` calls against
ONE staging — which measured 7.6 GiB of resident memory across 32 root-capable processes in
under three seconds (I54). The (N+1)th caller is refused with `conflict`, never queued: a
caller queued behind two 128 MiB reads is a Cockpit channel held open for the duration.

One thing that directory does **not** buy, said here rather than left to be assumed: for the
admin class the helper runs as root, so the staging root cannot tell two administrators apart
— the same limitation `SO_PEERCRED` has on the agent. An admin-class staging is visible to any
administrator who can list it. It holds an encrypted safe its uploader already possessed, and
root is out of scope in THREAT-MODEL.md, but "only the operator who started it can see it" is
not a claim this design makes for the admin class.

Staging is **never** required to share a filesystem with the managed safe directory: the
commit copies through a temp file *in the target directory*, so `os.replace` is always
intra-filesystem and nothing here depends on how `/`, `/var` and `/home` are partitioned.

Staged bytes are an **encrypted** safe file. An orphaned staging directory is therefore a
disk-space problem rather than a disclosure — which is the reason the sweep is an idle timer
and not an emergency.

### Where the entry is written

| access class | the entry | written by |
|---|---|---|
| `admin` | `/etc/cockpit-secrets/safes.d/50-<id>.json`, `0644 root:root` | the escalated helper |
| `user` | `~/.config/cockpit-secrets/safes.d/50-<id>.json`, `0600 <user>` | the **unescalated** helper, running as that user |

Both are serialized, validated against `schema/safe-registry.schema.json` **before they touch
the filesystem**, and written by the same `atomic_replace` primitive as everything else
(I12/I13). A half-written entry is dropped by the loader — correct, fail-closed, and *silent*,
which is exactly why the rule is "never produce one" rather than "the loader copes".

## What crosses which boundary

| Boundary | Crosses it | Never crosses it |
|---|---|---|
| browser → bridge | the JSON request, passphrase included, on stdin | anything on argv or in the environment (I10) |
| bridge → helper | fd 0 (the request), fd 1 (one JSON object), fd 2 (diagnostics) | inherited fds — `harden_process` closes everything above 2 |
| helper → backend | a `Secret`, a validated registry entry, an open validated fd | a caller-supplied path (I4) |
| backend → helper | metadata always; a decrypted value **only after the MAC verified** (I6) | a password in `entries()` output — `reveal` is the only door |
| helper → stdout | exactly one JSON object | a traceback, a value, a path from the request (I15) |
| helper → audit log | timestamp, verb, safe id, caller uid, outcome, duration | any value, any entry title, any traceback (I15) |
| helper → disk | the safe (atomically), the backup ring, the lock file, a registry entry it minted | a temp file containing a secret; anything in `/tmp` |
| browser → helper, during an import | the **encrypted** safe file, in 512 KiB base64 chunks on the session's stdin | any credential before the commit frame — `password`/`keyfile_b64` on a begin, chunk or inspect frame is `invalid`, not ignored |
| helper → staging | encrypted uploaded bytes, in a `0700` helper-owned directory, `O_EXCL`, `0600` | the final path; `/tmp`; anything decrypted; the credential |
| root helper → a user's home | **nothing.** It never opens `~/.config/cockpit-secrets/safes.d/`, never writes a user-class safe, and refuses `access: "user"` outright | a per-user registry read, an entry write, a safe write, an `unlink` |
| helper → browser storage | **nothing** | `localStorage`, `sessionStorage`, IndexedDB, cookies (I11) |

## The property everything above serves

> A decrypted value exists only inside one short-lived helper process, only after
> its MAC has verified, only for a caller the kernel says is entitled to it, and
> only for as long as one operation takes.

Every design decision in this document is downstream of that sentence. Where we
cannot achieve it — an unwipeable `str`, a root-equivalent attacker, a clipboard
that is a shared OS resource — the honest thing is written down here and in
[`THREAT-MODEL.md`](THREAT-MODEL.md) rather than papered over.
