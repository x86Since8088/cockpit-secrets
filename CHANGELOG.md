# Changelog

Notable changes to cockpit-secrets. Versions are `MAJOR.MINOR.PATCH`; `VERSION`
carries the current one and `install.sh` prints it.

Two conventions worth knowing before reading an entry:

- Hazard ids (**I1**–**I35**) refer to [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md).
  A line that cites one is claiming that hazard is mitigated in this release, not
  that it was thought about.
- Some components are optional by design and can be absent from a build (the
  unlock agent above all). **`secrets-admin health` is the authority on what a
  given installation actually has** — not this file.

## 0.2.2 — 2026-09-04

**Documentation and verification only. No code changed** — `secrets-admin`, the
three backends, `secrets.js` and every other shipped file are byte-for-byte what
0.2.1 left. This entry exists because what is now *known* about that code changed,
and a version that reports 0.2.1 while the register says something different is
the kind of small lie this project keeps finding in itself.

An independent re-gate of the 0.2.1 remediation: every gate re-run from a clean
state, the package installed on this host for the first time, and the two places
the adversarial pass had left as "code-visible but unreproduced" re-attacked.

**The gates.** `./run_tests.sh` **17/17**, exit 0 — 1 188 independent assertions
plus 2 912 Twofish vector comparisons, zero failures. `./validate.sh` 47 PASS /
0 FAIL with 38 unit regressions. `./check.sh`, `gen_corpus.py --check` (67 cases),
`ban_os_write.py` and the Go oracle build all green. Nothing was weakened to get
there: no test, ban, budget or threshold was edited.

**Installed, at last.** 0.2.1 was never put on the host — the live Cockpit page
was still running the vulnerable 0.2.0 helper. `install.sh` now ran through the
`/srv/jobs` root runner (4 changes, 21 unchanged, 0 warnings) and served-versus-source
was verified by sha256 for **all eleven** installed artefacts, not only the four
that changed. `cockpit.socket` was never touched.

**Seven new hazards (I36–I42), of which two are defects the 0.2.1 remediation
reported as handled and had not handled.**

- **I41** is the attack pass's `CRYPTO-02`. I24 states in writing that the
  `_verify_own_output` fix *"also closes the latent half of the same latch on the
  PWS3 side"*. It does not: that method exists only in `backends/kdbx.py`, and
  `backends/psafe3.py` still latches its losslessness guard after the first save.
  Reproduced — a second save in one session wrote a Password Safe file the
  program's own reader then refused, reported `{"ok": true}`, and the reopen
  blamed the operator's passphrase. I24 now carries the correction and
  `COMPATIBILITY.md` §10.5 records it as a byte-level divergence.
- **I39** is the attack pass's `WEB-01`, which appeared in no remediation entry
  at all. The I16 lockout counter is a lost-update race: 50 concurrent wrong
  guesses produced 44 evaluated attempts and left the counter reading 43.
- **I40** — the admin-path lockout counter is keyed on euid, so every
  administrator shares one counter per admin safe. One administrator's single
  typo locked a second administrator out while they held the correct passphrase.
  Reproduced through the root runner; the browser lens had found it by reading
  and could not reach euid 0 to test it.
- **I36** — a downloaded attachment's blob URL outlives the Lock button by up to
  10 s, and script in the origin can re-trigger a download of the decrypted bytes.
  Measured in the live page. The read routes are closed by the CSP that I9
  refuses to relax, which is doing work here it was not designed for.
- **I37** — `clipboardClear()` announces success before the write resolves.
  **Not reproduced** by two independent lenses and reported as such.
- **I38** — the agent's `_note()` does not redact where the helper's does. No
  live escape; a hole in a last line of defence, same shape as I30.
- **I42** — the live suite's I11 storage check is a false statement on a live
  host: it attributes to this page a key Cockpit's own shell writes and rewrites.
  This is why the live walkthrough reports **129/130** rather than 140/140, twice.
  Deliberately not "fixed", because editing an oracle so a number comes out right
  is the failure this exercise exists to catch.

**Two hazards moved to MITIGATED with the evidence named**, not quietly closed.
I2 and I3 are now proved as pairs under a **real** Cockpit bridge — refused with
no prompt while administrative access is off, then opening a root-owned safe once
Cockpit's own control grants it. `COMPATIBILITY.md` §8a records the three rows
that moved out of "believed but not verified", with what moved them.

**New documents.** `docs/STRESS-REPORT.md` is the complete red-team record —
every attack across all six lenses with its command, its result and a
PASS/FAIL/NOT-ATTEMPTED verdict, weighted about four to one toward the attacks
that *bounced*, because an attack that failed is the only evidence a defence
exists. `docs/RESIDUAL-RISK.md` was rewritten as what an in-scope attacker can
still do, in plain language, with a section on what has never been tested at all:
no YubiKey has ever answered a challenge from this program, no KDBX 3.x + Twofish
file has ever been read, no foreign program has ever written a Twofish KDBX for
us to read, KDBX 4 + AES-KDF has never been read or written, no real Password
Safe GUI file has ever been opened, and the agent has never run as root.

## 0.2.1 — 2026-09-04

Fourteen defects found by adversarial review of 0.2.0 and confirmed by an
independent skeptic. Nothing in the verb table changed shape; two replies gained
fields and one gained a warning. Read [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md)
I23–I35 for the cause and the guard behind each line, and
[`docs/RESIDUAL-RISK.md`](docs/RESIDUAL-RISK.md) for the one that is argued
rather than fixed.

The uncomfortable part first: 0.2.0 passed `./run_tests.sh` 16/16,
`./validate.sh` 15/15, a live 10-item browser walkthrough 140/140 and a
233-check root-side verification. Every one of those tests was written by the
system that wrote the code, and a reader and a writer that share a bug agree
perfectly — which is I19's sentence about file formats, and turns out to be
just as true of a test suite.

### Fixed — data loss and availability

- **A save could write a database this program could never open again** (I23,
  I24). `attach_add` of an ordinary 8 MiB log file produced a 33 KB safe, `save()`
  answered `{"ok": true}`, and every later `unlock` refused it — while KeePassXC
  read the same file perfectly. Cause: a compression-RATIO guard set below what
  DEFLATE can physically produce, and a pre-write check that verified MACs
  without ever parsing what it was about to write. The ratio guard is replaced by
  structural caps on what the payload may CONTAIN, and `_verify_own_output` now
  re-opens the bytes through the same reader a later unlock uses, on every save.
  The same guard was refusing valid KDBX 3.1 databases written by
  `keepassxc-cli`.
- **A short write made a truncated backup generation the ring presented as a
  good one** (I26). `_ring_backup` advanced by the bytes it had READ. On a nearly
  full filesystem a 4661-byte safe produced a 4096-byte "generation" that was
  fsync'd, named, listed with a plausible size, and accepted by `restore-backup`
  — after which the safe did not open, and some of those saves had reported
  `"saved": true`. `backends/base.py write_all()` is now the only place in the
  program that calls `os.write()`, and `validate.sh` counts.
- **`restore-backup` installed a generation it had not checked** (I27). It
  bounded a generation from below only by "not empty" and then checked four bytes
  of magic. New `Backend.verify_structure()` walks the format's own framing with
  no credential; the ABC's default refuses rather than returning true.
- **A failed lock write wedged a safe permanently, and a directory at the lock
  path could not be cleared at all** (I28). Both fixed at the same call site;
  `override_stale` now reaches the case it was written for, and debris at the
  lock path is named as debris.

### Fixed — resource bounds

- **`Limits.MAX_ENTRIES` was enforced after the expensive parse** (I25). A 3.8 MB
  file carrying exactly `MAX_ENTRIES` protected values that fail to decode spent
  46 s at 100% CPU and 313 MB of RSS inside `PyKeePass(...)` — and was then
  accepted. The count clamps moved into the parse, and a new
  `Limits.parse_budget()` wraps it: unlike `kdf_budget`, which can only notice a
  C call's overrun afterwards, this one preempts the Python-level loop where the
  quadratic lives. Same file, same request: `invalid` at 20 s.

### Fixed — correctness and disclosure

- **Duplicate field names were resolved first-wins** (I29). KeePassXC refuses
  such a file outright; this package showed the first value, and `edit` reported a
  password rotation that had only touched one of the two copies. Refused now, on
  both formats, at the layer every read and write passes through.
- **A CSV export could carry a live spreadsheet formula** (I31). `QUOTE_ALL` is
  not a formula-injection defence. Cells beginning with `= + - @ TAB CR` are
  neutralised; the reply reports how many, because the neutralisation is a real
  loss of fidelity and is argued in `docs/RESIDUAL-RISK.md` §2.
- **`redact()` did not see a secret `json.dumps` had escaped** (I30). The blanket
  filter over `emit()` and `audit()` runs on the output of `json.dumps`, and a
  passphrase containing a double quote or a NUL matched none of its candidates.
  No live escape existed; the last line of defence had a hole in it, which is the
  whole point of a last line of defence.
- **Caller text still reached a pykeepass XPath** (I32). `docs/COMPATIBILITY.md`
  §7 fixed `reveal()` and warned that any other `find_*` call site had the same
  bug. `add()` was that call site: an entry titled `a"b` answered `internal`.
  Fixed, and the four pykeepass names are now banned from `backends/kdbx.py`
  outright rather than warned about in prose.
- **Two answers the helper gave were not true** (I33). A deeply nested request
  body answered `internal` — the code reserved for "we do not know what went
  wrong" — for input the helper does know is malformed. And every
  `restore-backup` reply said "this restore is itself undoable", which stops
  being true after `keep` of them; measured with keep=3, four saves and five
  restores left the operator's starting state in zero of three ring slots. The
  reply now carries `undo` (computed from the ring after the write) and
  `ring_full`.
- **Live-suite artefacts holding plaintext secrets were written under the umask**
  (I34). `page.screenshot()` and `download.saveAs()` have no mode option, so the
  screenshot of an unmasked password field and the decrypted attachment body were
  the two artefacts written group-readable, while the harmless console log was
  0600 — in a directory whose own `.gitignore` says the suite writes them 0600.

### Documented, not fixed

- **A hardware token's answer is a constant for the life of the file** (I35).
  KeePassXC rotates the KDF seed on every save and re-challenges the token, so a
  captured answer expires; here the challenge is a file constant. Rotating it
  needs a fresh token answer at save time, which the unlock protocol has no round
  for. The two available mechanisms were judged worse than the defect — the
  argument, the measurements and the conditions that would reverse it are in
  `docs/RESIDUAL-RISK.md` §1. `probe` and `unlock` now both warn.

### Added — the guards

- `tests/test_regressions.py` — 38 unit cases, one or more per finding, run by
  `validate.sh` on every gate (5 s). Every one was watched to FAIL with its fix
  reverted.
- `tests/integration/adversarial.py` — 67 checks at the layer only the real
  helper can reach: a request frame, a backup ring several processes have taken
  turns with, an export artefact read back off disk. Run by `run_tests.sh`.
- `tests/ban_os_write.py` and five new standing bans in `validate.sh`
  (DURABILITY-1, LEAKAGE-02, LEAKAGE-03, LEAKAGE-04 ×2, INPUT-2). Each was
  deliberately violated and watched to fail. The `os.write` ban parses rather
  than greps, because a first version matched its own explaining comments; and it
  does not exempt `backends/base.py`, because an earlier version did and passed
  with the bug put back.

### Changed — reply shapes

- `export` gains `neutralised` (int) and its `warning` explains the apostrophe
  when it is non-zero.
- `restore-backup` gains `undo` (string) and `ring_full` (bool). `note` is kept
  and now carries the same honest sentence.
- `probe` and `unlock` add a warning for a safe whose registry entry declares
  `yubikey_slot`.

## 0.2.0 — 2026-09-04

The second wave: ten more verbs, the optional unlock agent, and the integration
pass that made five parallel branches into one program. Everything in 0.1.0
still works; nothing in the original verb table changed shape.

### Added

- **Ten verbs**: `export`, `save-as`, `backups`, `restore-backup`, `history`,
  `history-restore`, `attach-add`, `attach-rm`, `strength`, `breach-check`.
  Every one is implemented on BOTH formats or refuses with the format's own
  reason named — `export` to Password Safe XML is `unsupported` because that is
  a GUI feature with a schema this project does not have, not a gap.
- **The unlock agent** (`agent/`, opt-in per safe, off by default, I18). It
  holds a **ticket, not key material**: a uid-bound record that a safe was
  unlocked, with a hard idle and a hard absolute deadline. The passphrase is
  therefore still prompted on every unlock — what the agent buys is that an
  unlocked safe is **visible** (`health.agent`, no handle and no passphrase
  needed) and **revocable** (`lock` with a bare safe id, across processes).
- **`export_dir` and `breach_corpus`** registry fields, both absolute,
  helper-side, and validated by `schema/safe-registry.schema.json`.
- **A Twofish KDBX 4.0 fixture** and the KDBX self-check that reads it.
- **Two integration suites** — `tests/integration/newverbs.py` (220 checks) and
  `tests/integration/agent_cycle.py` (45 checks) — plus the headless browser
  driver, all now stages of `run_tests.sh`.
- **Four standing bans** in `validate.sh`: an export may only be written to
  `export_dir_for(entry)`; no network-capable name anywhere in the helper,
  backends or agent; no verb may declare a filesystem path as a request field;
  no source file may contain a NUL byte. Each was verified to FAIL when
  deliberately violated.

### Fixed

- **`reveal` could not reach a custom field, on either format.** The contract
  spells one `custom:<name>`, and KDBX looked up a string field with that
  literal name. Every custom-field reveal in the program answered `not-found`,
  and the page was building buttons that sent exactly that. `totp` — published
  in the schema's own field menu — reached neither backend's name for the seed.
  Both fixed in the backends, where the mapping from a contract name to a
  storage key belongs. `custom:Password` is deliberately NOT a shortcut to the
  master password.
- **Entry history was ordered backwards in the UI.** The schema said index 0 was
  the most recently archived version; the data says it is the oldest, and the
  timestamps prove it. The page correctly believed the schema and sorted
  descending, so history displayed newest-first under an "oldest recorded
  version" label and attributed every change to the wrong version. Corrected in
  the descriptor, the sort and the browser fixture together.
- **`lock` reported `agent_dropped: true` when nothing was dropped.** The agent
  answers a drop for a safe it is not holding with `{"ok":true,"dropped":0}` — a
  satisfied request that revoked nothing. A Lock button that cannot lie is no
  use if its receipt can.
- **A duplicate attachment name was `conflict` on KDBX and `unsupported` on
  PWS3.** One operator mistake, two error codes, and only one of them named the
  fix. PWS3 now distinguishes "you already have one called that" (conflict, use
  `replace`) from "this format holds only one per record" (unsupported).
- **`breach-check` declared three response keys it correctly does not return**
  when no corpus is configured. Caught by conformance.py comparing the
  declaration against a real call.
- **`backend_health` reported a backend "available" when its module merely
  imported** — so a class that was abstract-incomplete read as working while
  every one of its verbs answered `internal`. It now also requires the class to
  be instantiable and names what is missing.
- **The agent daemon and the helper's agent client did not interoperate.** The
  daemon required `material` the helper does not send, indexed `drop` only by
  handle, and rejected the helper's own handle alphabet. `material` is now
  optional, `drop` accepts a safe id, and the token class is base64url — a
  superset of the hex it accepted before, so nothing was lost.
- **The integration harness rooted every run at one fixed path**, so two suites
  running at once deleted each other's registry mid-run. The root is now
  per-pid, overridable with `COCKPIT_SECRETS_TEST_ROOT`.
- **`secrets-admin` imported `backends.base._backup_dir_for`** — reaching past
  the package boundary for the single most important piece of agreement in the
  program. It is now public and re-exported, along with `validate_new_path`.
- **`install.sh`** now creates `/var/lib/cockpit-secrets/exports` 0700 and
  installs the agent's SYSTEM template to the system unit directory instead of
  letting a glob drop it into the per-user one, where `User=%i` cannot work.
- **`docs/HOST-FACTS.md` said `pwsafe --help` exits 0**; it exits **255** and
  writes to stderr. Measured twice, with and without a display.

### Known limitations unchanged

No YubiKey has ever answered a challenge; no registry owned by real root has
been tested; no `.psafe3` written by the real Password Safe GUI exists here.
`run_tests.sh` prints all four in its own summary.

## 0.1.0 — 2026-09-04

First release: unlock and fully manage KeePass (`.kdbx`) and Password Safe v3
(`.psafe3`) safes from a Cockpit page, with the passphrase prompted every time.

### Added

- **The Cockpit page** — `manifest.json`, `index.html`, `secrets.js`,
  `secrets.css`. Vanilla JS, no build step, no bundler, no framework, no CDN,
  no WASM. Every control, label, validation rule and enum is rendered from the
  helper's `schema` verb, so adding a field to the helper adds it to the UI with
  no JavaScript change.
- **`secrets-admin`** — one root helper, one verb per invocation, exactly one
  JSON object on stdout and nothing else, diagnostics on stderr, exit 0 for
  success. Requests arrive as one JSON object on **stdin**, capped at 1 MiB,
  because a request here carries secrets (I10).
- **Two format backends** on a common adapter interface: KDBX via `pykeepass`
  in-process, and Password Safe v3 implemented from `formatV3.txt` with Twofish
  from Botan 3.
- **The registry** — `/etc/cockpit-secrets/safes.d/*.json`, root-owned, validated
  against `schema/safe-registry.schema.json`. Verbs take an **id**; there is no
  verb that opens a caller-supplied path (I4). An entry that fails validation is
  dropped and logged, never partially applied (I1).
- **Two access classes, `admin` by default.** User-class safes are handled by an
  unescalated helper running as the logged-on user; admin-class safes require
  `euid == 0` and a real caller in the entry's `groups`. Both are re-derived from
  kernel-supplied identity inside **every** verb, never from the request body and
  never in the browser (I2, I3).
- **The backup ring** — every save copies the current file into
  `<safe>.bak.d/` (`0700`, generations `0600`, timestamp-ordered, pruned to
  `backup.keep`) before the first new byte exists. It is the only undo this
  program has.
- **`install.sh`** — root-only, `--uninstall`, `--with-agent`, `DESTDIR=`
  staging, `--help`. Validates the manifest, refuses one that relaxes the CSP,
  compiles the Python payload, runs the JavaScript gate and validates the seeded
  registry examples **before** writing anything. Seeds examples only where
  nothing exists, never touches an operator's registry entry or any safe file,
  and never restarts Cockpit. An uninstall keeps the registry, the safes, the
  audit log and the lockout counters.
- **`check.sh`** — the JavaScript syntax gate. A Cockpit package has no build
  step, so this is the only thing between a stray paren and a blank panel.
- **Documentation** — `README.md`, `docs/OPERATIONS.md` (registering, restoring,
  conflicts, rotation, the agent, the audit log, the lossless guard),
  `docs/CONTRACT.md`, `docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`,
  `docs/KNOWN_ISSUES.md`, `docs/UPSTREAM-REVIEW.md`, `etcdefaults/README.md`.

### Optional, and off unless deliberately enabled

- **The unlock agent** (I18) — `AF_UNIX` socket in a `0700` per-user run dir,
  peer identity from `SO_PEERCRED`, handle bound to the creating uid, hard idle
  **and** absolute timeouts neither of which a client can extend, a persistent
  "unlocked — N s remaining" banner. Off by default, opt-in per safe, installed
  only with `--with-agent`, and enabled only by the user in their own session.
  It was allowed to be dropped rather than shipped half-defended: ask `health`.
- **Export** (I21) — admin-only, off unless the registry enables it per safe,
  written `0600` to an operator-configured directory (never a path from the
  request), audited by name, and preceded by a confirmation that says in plain
  words what is about to be written in the clear.

### Security properties this release is built around

- The passphrase is prompted on **every** unlock by construction: one browser
  call runs one short-lived helper for one operation, and there is nowhere for a
  key to survive. Not a setting, not a timer.
- No secret on `argv`, in the environment, or in a temp file (I10). No secret in
  `localStorage`, `sessionStorage`, IndexedDB or a cookie (I11).
- Nothing decrypted leaves a backend before its MAC verifies; every MAC, key-hash
  and handle comparison is `hmac.compare_digest`. A wrong passphrase and a failed
  MAC return the same error with the same wording, with a constant time floor on
  the failure path, so unlock cannot be used as an oracle (I6, I16).
- KDF parameters are read from the file and therefore clamped before the KDF runs
  (I7); the decrypted inner XML is parsed with entities, DTDs and network access
  explicitly disabled (I8); every declared length is bounds-checked before
  anything is allocated.
- Safe files are opened `O_NOFOLLOW|O_CLOEXEC` and validated by `fstat` on the
  **fd**, never by a second `stat` of the path (I5).
- Saves are backup → temp file → `fsync` → `os.replace` → `fsync(dir)`, with a
  `(mtime_ns, size, sha256)` re-check immediately before (I12, I13). Desktop lock
  files (`.kdbx.lock`, `.plk`) are honoured; a foreign lock is a `conflict`
  naming the holder, never a forced write, and there is no stale-lock timeout.
- The manifest adds **no** CSP relaxation: no WASM, no `eval`, no inline
  `<script>`/`<style>` (I9). `install.sh` refuses a manifest that breaks this.
- The audit log records verb, safe, uid and outcome — never a value, never a
  traceback (I15). No `set -x` in any shell wrapper in this tree: the host's root
  job logs are group-readable.

### Known limitations — stated, not hidden

- **No master-passphrase rotation verb.** Rotation rewrites the whole database
  under a new key and a half-written rewrite is the outcome this program refuses
  to risk. `docs/OPERATIONS.md` §4 gives the procedure with a real client.
- **No "create a new safe" verb**, for the same reason.
- **The Password Safe v3 interop evidence is weaker than KDBX's.** Ubuntu ships
  no Password Safe CLI, so there is no scriptable foreign oracle: PWS3 is covered
  by published test vectors, a real-`pwsafe`-GUI fixture and a documented manual
  check instead. `docs/COMPATIBILITY.md` says which rows are verified and which
  are believed; do not read a believed row as a verified one (I19).
- **KDBX 3.x is read-only** (I20). It has no authenticated encryption, so a
  tampered file decrypts to attacker-influenced XML with nothing to detect it.
  Upgrading to KDBX4 is an explicit operator action that writes a new file.
- **A save is refused rather than allowed to drop a field** it did not model
  (I22). Three ways forward, no force flag: `docs/OPERATIONS.md` §7.
- **Root on this host can read the helper's memory**, and a Python `str` cannot
  be wiped. Mitigations (no core dumps, `PR_SET_DUMPABLE=0`, best-effort
  `mlockall` reported honestly, a process lifetime measured in milliseconds)
  raise the cost and do not change the conclusion. `docs/THREAT-MODEL.md`.
- **Clipboard clearing is best-effort.** The clipboard is a shared OS resource.

### Licence

GPL-3.0 (`LICENSE`), forced by linking `pykeepass`. Cockpit is LGPL-2.1+, which
is compatible for a Cockpit package. If the KDBX engine ever changes, the licence
question has to be re-answered before the tree is re-licensed.
