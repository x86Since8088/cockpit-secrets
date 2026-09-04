# Changelog

Notable changes to cockpit-secrets. Versions are `MAJOR.MINOR.PATCH`; `VERSION`
carries the current one and `install.sh` prints it.

Two conventions worth knowing before reading an entry:

- Hazard ids (**I1**–**I22**) refer to [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md).
  A line that cites one is claiming that hazard is mitigated in this release, not
  that it was thought about.
- Some components are optional by design and can be absent from a build (the
  unlock agent above all). **`secrets-admin health` is the authority on what a
  given installation actually has** — not this file.

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
