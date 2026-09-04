# Known issues register — cockpit-secrets

Every hazard identified for a Cockpit plugin that unlocks and fully manages KeePass (KDBX)
and Password Safe v3 safes, with severity, root cause, the mitigation that closes it, and the
task that owns it. Tasks cite these ids; a task is not done until its cited ids are either
MITIGATED or explicitly re-classified with a reason.

Legend — Sev: **C**ritical / **H**igh / **M**edium / **L**ow.
Status: OPEN / MITIGATED / BY-DESIGN / WONTFIX.

---

## Access control and identity

### I1 · A safe is a file, and files have no notion of "user safe" vs "admin safe" · Sev C · OPEN→(design closes)
Nothing in KDBX or PWS3 records who may open it. Access class is **our** concept and must be
imposed from outside the file, or it does not exist. **Mitigation:** a root-owned registry,
`/etc/cockpit-secrets/safes.d/*.json` (0644 root:root, directory 0755 root:root), is the only
source of safes. Each entry declares `access: "admin" | "user"`. **A registry entry with no
`access` key is `admin`** — the default is the restrictive one, and an unparseable entry is
dropped with a logged error rather than defaulted open. Owner: Task 2.

### I2 · Two access classes need two privilege levels, not one · Sev H · OPEN→(design closes)
Running everything as root makes every user safe a root-readable file and every bug a root
bug. **Mitigation:** one helper binary, two invocations. `access:"user"` safes are handled by
`cockpit.spawn([...])` with **no** superuser option — the helper runs as the logged-on user
under their own bridge, and can only reach files that user could already read. `access:"admin"`
safes require `cockpit.spawn([...], {superuser:"require"})`; the helper refuses the verb unless
`os.geteuid() == 0`. Least privilege per safe, not per plugin. Owner: Task 2.

### I3 · A browser-side access check is cosmetic · Sev C · OPEN→(design closes)
Verified in a sibling project: cockpit-guac-rdp `I4` shipped an `if (t.admin && !isAdmin)` in
JS and it was bypassable by driving the backend directly. **Mitigation:** the UI may *hide*
what a user cannot use, but every verb re-derives the caller's identity and re-checks the
class server-side. The test suite drives the helper directly as a non-admin and asserts
refusal. Owner: Task 2, Task 9.

### I4 · Client-supplied paths · Sev C · OPEN→(design closes)
If the browser can name the file to open, "user" access is meaningless — ask for
`/etc/cockpit-secrets/safes/root.kdbx` and see what happens. **Mitigation:** verbs take a
**registry id**, never a path. Path resolution happens only inside the helper, from the
registry. There is no verb that opens an arbitrary path. Owner: Task 2.

### I5 · Symlink and TOCTOU attacks on safe files · Sev H · OPEN→(design closes)
A `user` safe lives under a path the user controls, so they can swap it for a symlink to
`/etc/shadow` between the check and the open — and a root-mode helper would follow it.
**Mitigation:** open with `O_NOFOLLOW|O_CLOEXEC`, `fstat` the **fd** (never re-`stat` the
path), verify `st_uid` against the expected owner, reject anything not a regular file, reject
group/other-writable parents, and do every subsequent operation on that same fd. Owner: Task 2.

---

## Cryptography and file parsing

### I6 · Verify-before-use, and constant-time comparison · Sev C · OPEN→(design closes)
PWS3 puts its HMAC at the **end** of the file, so the format forces decrypt-then-authenticate;
KDBX4 authenticates per block but the inner XML is still attacker-shaped until the MAC checks
out. Returning any value before the MAC verifies turns a parser bug into a decryption oracle.
**Mitigation:** parse into memory, verify the MAC, and only then let a value escape the
backend adapter. All MAC and hash comparisons use `hmac.compare_digest`. A wrong password and
a corrupt file produce the **same** error taxonomy to the client, with the distinction only in
the audit log. Owner: Task 3, Task 4.

### I7 · KDF parameters are attacker-controlled · Sev H · OPEN→(design closes)
KDBX carries its Argon2 `m`/`t`/`p` in the header; PWS3 carries `ITER`. A hostile file can
demand 4 GiB of memory or 10^9 iterations and take the helper — and on the admin path, root —
with it. **Mitigation:** clamp before the KDF runs. Reject Argon2 `m` > 1 GiB, `t` > 32,
`p` > 8; reject PWS3 `ITER` outside [2048, 8388608] and **write** at the format's current
floor of 262144. Enforce an overall wall-clock and RSS budget on the derivation. Owner: Task 3, Task 4.

### I8 · XXE / entity expansion in the decrypted KDBX inner XML · Sev H · OPEN→(design closes)
KDBX4's payload is XML, parsed here by `lxml`. Entities and DTDs are a billion-laughs and
file-disclosure vector even though the XML is "ours" — it is only ours *after* it verifies.
**Mitigation:** construct the parser explicitly with `resolve_entities=False`,
`no_network=True`, `load_dtd=False`, `huge_tree=False`, and cap the decompressed inner size.
Assert it in a unit test with a hostile fixture — do not rely on a library default that can
change. Owner: Task 3.

### I9 · CSP weakening for in-browser crypto · Sev H · BY-DESIGN (avoided)
Doing Argon2 in the browser needs WASM, which needs `wasm-unsafe-eval` in the package
manifest CSP — a weaker policy on the one page that handles every password we own.
**Mitigation:** no browser-side crypto at all. The manifest adds **no** CSP relaxation; the
plugin must run clean under Cockpit's default `default-src 'self'`, which also means no inline
`<style>`/`<script>` and no `eval`. A test asserts the manifest contains no
`content-security-policy` key. Owner: Task 5.

### I10 · Secret material on argv / in the environment / in temp files · Sev C · OPEN→(design closes)
`/proc/<pid>/cmdline` and `/proc/<pid>/environ` are readable by the process owner and by root,
and argv reaches shell history and audit trails. **Mitigation:** the master password, key-file
contents and every decrypted value travel **only** on the helper's stdin/stdout as JSON frames.
No verb accepts a secret as an argument. No secret is ever written to a temp file. A test
reads `/proc/<pid>/cmdline` and `/proc/<pid>/environ` of a live helper mid-unlock and asserts
the passphrase is absent. Owner: Task 2, Task 8.

### I11 · Browser-side persistence of the master password · Sev C · OPEN→(design closes)
`localStorage` and `sessionStorage` are origin-wide and survive navigation; anything stored
there is readable by any XSS anywhere in Cockpit. **Mitigation:** the password lives in one
function-scoped JS variable, is sent, and is overwritten. No storage API, no `IndexedDB`, no
cookie, no `autocomplete` on the field, no hidden form. A Playwright test asserts both storage
areas are empty after an unlock. Owner: Task 5, Task 8.

---

## Data integrity

### I12 · In-place writes destroy safes · Sev C · OPEN→(design closes)
A crash, a full disk, or a killed helper part-way through a save leaves a truncated database
and no undo — the worst possible outcome for this program. **Mitigation:** write to
`<safe>.tmp-<pid>` in the same directory, `fsync` the file, `os.replace`, then `fsync` the
directory. Take a timestamped backup into a retention ring **before** the first mutation of a
session. A test kills the helper with `SIGKILL` between write and rename and asserts the
original is intact. Owner: Task 6.

### I13 · Lost updates against a desktop client · Sev H · OPEN→(design closes)
KeePass/KeePassXC use `<name>.kdbx.lock`; Password Safe uses `.plk`. Ignoring them means a
save silently discards whatever the desktop app wrote. **Mitigation:** honour and create the
lock file for the duration of a write; additionally record `(mtime_ns, size, sha256)` at
unlock and re-check immediately before writing — on mismatch, refuse and surface a
"changed on disk" conflict, never merge silently. Owner: Task 6.

### I14 · Plaintext in process memory, swap, and core dumps · Sev H · PARTIAL (inherent)
Python `str` is immutable and interned: a password read into a `str` **cannot** be wiped, and
`gcore` on the helper would yield the whole decrypted safe. **Mitigation (defence in depth,
not a fix):** read secrets into `bytearray` and zero them in `finally`; set `RLIMIT_CORE=0`
and `prctl(PR_SET_DUMPABLE, 0)` at start-up; best-effort `mlockall(MCL_CURRENT|MCL_FUTURE)`
and log when it fails rather than pretending it worked; keep the helper's lifetime to a single
operation so the window is milliseconds, not hours. **Residual risk stated in the docs:** a
root-equivalent attacker on this host can read helper memory. That is true of every password
manager on every machine and is not solved here. Owner: Task 2, Task 9.

### I15 · Secrets in logs, errors and tracebacks · Sev H · OPEN→(design closes)
An unhandled exception prints locals; `wg-admin`'s header already warns that this host's job
logs are group-readable. **Mitigation:** a single top-level exception barrier that emits
`{"error": "<class>: <safe message>"}` and never a traceback to stdout; an audit log that
records *verb, safe id, caller uid, outcome* and never a value; a redaction filter applied to
everything the helper writes; and `set -x` explicitly banned in any shell wrapper. Owner: Task 2.

### I16 · Unbounded unlock attempts · Sev M · OPEN→(design closes)
An unlock endpoint that never says no is an offline-strength guessing oracle with the KDF's
cost as the only brake. **Mitigation:** per-(uid, safe id) failure counter in a root-owned
state file with exponential backoff and a lockout threshold, plus a constant floor on the
failure path so a wrong password does not answer faster than a right one. Owner: Task 2.

### I17 · Clipboard leakage · Sev M · OPEN→(design closes)
A copied password stays in the clipboard indefinitely and any focused page can read it.
**Mitigation:** copy through `navigator.clipboard` on an explicit user gesture only, with a
visible countdown and automatic clear (default 15 s), and clear on page hide/unload. Document
honestly that the clipboard is a shared OS resource and clearing is best-effort. Owner: Task 5.

### I18 · An unlock agent is a permanently unlocked safe · Sev H · MITIGATED (two residuals named)
"Do not prompt every time" is exactly the property we are trying not to have. **Mitigation:**
the agent is **off by default** and must be enabled per-safe in the registry. When on: an
`AF_UNIX` socket in a 0700 per-user run dir, peer identity from `SO_PEERCRED`, a handle bound
to the uid that created it, a **hard** idle timeout (default 300 s) and absolute lifetime
(default 3600 s), automatic lock on screen-lock/logout, and a visible "unlocked, N s left"
banner. Prompting stays the default for every safe that does not opt out. Owner: Task 7.

**Status after the second build.** The agent ships, and `tests/integration/agent_cycle.py`
drives the real helper against the real daemon: agent off is proved to create no socket and
leave no state; agent on is proved to take a ticket, be visible to a SECOND helper process, be
revoked by `lock` with a bare safe id, and expire on its own deadline.

The mitigation went further than the design asked in one way and stops short in two others,
and all three are deliberate:

* **The agent holds a TICKET, not key material.** `secrets-admin` sends no `material` and the
  daemon's `put` makes it optional. So the agent cannot hand a later helper an unlocked safe,
  and the passphrase is still prompted on EVERY unlock — the agent buys visibility and
  revocation, not "do not ask me again". The material path exists and is tested because this
  hazard sanctions it as a per-safe opt-in, but nothing in the tree uses it and the helper
  strips a `material` key out of any reply at the door. docs/CONTRACT.md, "What the agent
  holds", is the authority.
* **RESIDUAL — the lock detection is a 10 s poll**, not a subscription to logind's `Lock`
  signal, so there is up to one poll interval between the screen locking and the ticket being
  dropped. Suspend is handled two other ways that are not polls: the deadlines run on
  `CLOCK_BOOTTIME` so they count suspended time, and a tick gap larger than tick+30 s drops
  everything.
* **RESIDUAL — the admin class separates operators by INSTANCE, not by peercred.** For an
  `access:"admin"` safe the helper is root, so `SO_PEERCRED` reports uid 0 for every operator.
  The separation is one agent per operator behind a 0700 run dir (`secrets-agent@<uid>`), which
  `install.sh` installs and deliberately does not enable. The correct fix is for the root
  helper to fork and setuid to the operator before connecting; that is not implemented.

### I19 · "Compliant" is a claim, not a test result · Sev H · OPEN→(design closes)
A reader and a writer that share a bug round-trip perfectly and interoperate with nothing.
**Mitigation:** compliance is measured **only** against foreign implementations — files we
write must open in `keepassxc-cli`, files it writes must open in ours, plus the published
Twofish/format test vectors and a committed real-`pwsafe`-GUI fixture for PWS3. Where an
oracle is unavailable (no packaged PWS3 CLI on this host), the docs say so instead of
implying coverage we do not have. Owner: Task 8, Task 9.

### I20 · KDBX3 has no authenticated encryption · Sev M · OPEN→(design closes)
KDBX 3.1 predates the KDBX4 HMAC block scheme: a tampered file decrypts to attacker-influenced
XML with nothing to detect it. **Mitigation:** open KDBX3 read-only, show a persistent banner
naming the risk, and offer an explicit operator-confirmed "upgrade to KDBX4" that writes a new
file rather than converting in place. Never upgrade silently. Owner: Task 3, Task 6.

### I21 · Attachment and export paths are an exfiltration channel · Sev M · OPEN→(design closes)
"Export database as CSV/XML" writes every secret in plaintext to disk, and an attachment
export names a destination path. **Mitigation:** exports are an `admin`-only verb, off unless
enabled in the registry, always written `0600` to an operator-configured directory (never a
client-supplied path), always audited by name, and always preceded by an explicit confirm
naming what is about to be written in the clear. Attachment downloads stream through the
Cockpit channel to the browser rather than landing on the server's disk. Owner: Task 6, Task 7.

**Status after the second build: MITIGATED, and proved as a pair.** `export` is refused for a
user-class safe even when the caller owns the file, refused when `export_allowed` is false,
refused without the per-safe confirm token `export-plaintext:<id>`, refused for a confirm
naming a DIFFERENT safe, and refused for an unknown `fmt` — and the SAME request then succeeds
inside `unshare --map-root-user`, where `os.geteuid()` really is 0. A refusal on its own proves
nothing; the pair is the evidence. Measured in `tests/integration/newverbs.py`: the file lands
0600 in a 0700 directory under `export_dir`, named `<safe id>-<UTC stamp>.<ext>` minted
helper-side, the content is absent from the response, and the audit line carries the file name
and the row count and no value. `validate.sh` additionally pins the one call site that creates
an export to `export_dir_for(entry)`, so a destination from the request cannot reappear as a
one-line change.

The sibling hazard — a page that phones out about the passwords it holds — is closed the same
way: `breach-check` reads an operator-supplied local corpus and there is no online fallback.
`validate.sh` bans every network-capable name from the helper, the backends and the agent, and
the verb is measured answering correctly inside a network namespace whose only interface is a
DOWN loopback, with a control proving that namespace really is deaf.

### I22 · Silent format/feature loss on save · Sev M · OPEN→(design closes)
Reading a KDBX4.1 database with a library that does not model every field and writing it back
**deletes** what it did not understand — custom icons, previous-parent-group, quality flags,
plugin data. **Mitigation:** before the first write to a safe, diff a parse→serialize→parse
round trip and refuse to save if any field would be dropped, naming the field. Prefer refusing
to save over quietly amputating a database. Owner: Task 3, Task 6.
