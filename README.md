# cockpit-secrets

A Cockpit page that lets the logged-on user type a passphrase to unlock and
fully manage a KeePass (`.kdbx`) or Password Safe v3 (`.psafe3`) safe on this
host — browse, reveal, copy, add, edit, move, delete, attach and save.
**It is licensed GPL-3.0** (`LICENSE`), and not by preference: the KDBX engine
is [`pykeepass`](https://github.com/libkeepass/pykeepass), which is GPL-3.0, and
linking it makes this program GPL-3.0 too. Cockpit itself is LGPL-2.1+, which is
compatible for a Cockpit package. Do not silently re-license this tree; if the
KDBX engine ever changes, the licence question has to be re-answered first.

Plain HTML, vanilla JS and CSS on the front, one Python 3 verb helper on the
back. **No build step, no bundler, no npm, no framework, no CDN, no WASM.** The
only script the page loads besides its own is Cockpit's `../base1/cockpit.js`.

### Where this actually stands — read this before you trust it

**Version 0.4.0.** It runs, it is installed on one host, and it has been
attacked. What that means, precisely:

- **0.4.0 is the release in which a browser request first writes into the
  registry** — this program's trust root, which decides which files are safes
  and what access class each one has. That is the most dangerous change the
  project has made, and it was treated that way: a red-team round against the
  first implementation of `safe-create` / `safe-import` / `safe-forget` /
  `safe-delete` found **twelve defects**, including a `safe-delete` that would
  shred any file a registry entry named and an `import-commit` that validated
  one read of the uploaded file and landed a different one. A thirteenth turned
  up while cleaning the host after the live walkthrough. All thirteen are fixed
  (I43–I55), each with a regression check watched going red with its fix
  reverted and a standing ban watched firing on a deliberate violation.

- Six adversarial lenses, an independent re-gate of the result, and a further
  red-team round against 0.4.0's registry-write feature have found **thirty-one
  defects** in this program and in its own test suite.
  **Thirty are fixed; one is argued and left standing with a runtime
  warning** (the hardware-token challenge does not rotate — I35, and the
  reasoning is in RESIDUAL-RISK §2.1). Three further low-severity items are
  open and tracked rather than closed: I36 (a decrypted attachment stays
  retrievable for ten seconds after Lock), I37 (a clipboard-clear failure the
  page would announce as success — **nobody has managed to make it fail**), and
  I38 (the optional agent's own notes are not redacted). The whole record,
  including the attacks that bounced off, is in
  [`docs/STRESS-REPORT.md`](docs/STRESS-REPORT.md); the hazard register with
  every id the code cites is [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md).
- **What is still true of an attacker on a good day** is in
  [`docs/RESIDUAL-RISK.md`](docs/RESIDUAL-RISK.md), which also has a part 3
  listing every path that exists, is expected to work, and **has never been run
  against the thing it names**. Read that part before promising anybody
  anything.
- **Compatibility is split into verified and believed**, deliberately, in
  [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) §8. Three things a reader
  might assume are in the believed column: no YubiKey has ever answered a
  challenge from this program, no Password Safe file written by the real
  Password Safe has ever been read, and KDBX 4 + AES-KDF has never been read or
  written.
- It has been driven end to end in a real browser against real Cockpit —
  ten items and 131 checks for the browse/edit/save surface, plus five more
  items and 57 checks for 0.4.0's create-and-adopt flows, in
  [`docs/LIVE-WALKTHROUGH.md`](docs/LIVE-WALKTHROUGH.md) — and at a real euid 0
  through this host's root job runner, where `keepassxc-cli` opens a safe this
  program created and reads back an entry this program saved into it.

It has **not** been reviewed by anybody outside the system that wrote it, and
it has run on exactly one machine.

---

## The one property everything else serves

> A decrypted value exists only inside one short-lived helper process, only
> after its MAC has verified, only for a caller the kernel says is entitled to
> it, and only for as long as one operation takes.

Everything below is downstream of that sentence. Where it cannot be achieved —
an unwipeable Python `str`, a root-equivalent attacker, a clipboard that is a
shared OS resource — it is written down in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
rather than papered over.

## What it does

- **Create** a new, empty safe — KDBX 4.1 (AES-256, Argon2id) or Password Safe
  v3 — from the page, and register it in one act. A key file can be generated as
  a second factor; it is shown **once** and stored nowhere. The passphrase
  strength estimate is advice on screen and never a gate.
- **Adopt** a safe you already have, by uploading it. **The encrypted file goes
  up first and the passphrase is asked for last**, deliberately: a large upload
  takes time, and collecting the passphrase in the file-picker step would hold
  it in the browser for the whole transfer. Before you type anything the page
  shows what the file's own header says — format, version, cipher, KDF and its
  cost — because a KDBX or PWS3 header is not secret and you are holding the
  file. That summary is labelled as what it is: **read from the header, not
  authenticated.** Nothing lands until the file has actually opened with the
  credential you gave.
- **Unregister** (`safe-forget` — the file stays exactly where it is) or
  **destroy** (`safe-delete` — the file and its backup ring, behind a
  confirmation token that names the safe). Both are offered side by side, with
  the reversible one first.
- **Unlock** a registered safe with a passphrase typed into the page, optionally
  with a registry-declared key file. KDBX 4.x and Password Safe v3 read/write;
  **KDBX 3.1 read-only**, behind a permanent banner, because that format has no
  integrity protection at all and a tampered file cannot be detected (I20). An
  explicit upgrade to KDBX 4 is offered instead.
- **Browse** groups and entries, search, page and sort. The entry table shows
  title, username, URL, tags, modified time and attachment count, and **never a
  password** — the helper does not send one.
- **Reveal** one field at a time, on an explicit click, for a countdown (15 s by
  default) after which the page re-masks it and drops the value. Copy goes
  through `navigator.clipboard` on a user gesture with the same countdown and a
  best-effort clear.
- **Edit** — add, edit, move, delete entries and groups, attachments, TOTP —
  all in memory, and nothing reaches disk until you press Save.
- **Save** as backup → temp file → `fsync` → atomic rename → `fsync` the
  directory, under the desktop clients' own lock files, refusing rather than
  merging if the file changed underneath you.

## What it deliberately does not do

- **It does not remember your passphrase.** There is no "remember me" checkbox,
  because there is nowhere to put the answer — see below.
- **It does not decrypt in the browser.** That would need WASM, which would need
  `wasm-unsafe-eval` in the package's Content-Security-Policy — a weaker policy
  on the one page that handles every password we own. It would also move access
  control into a browser `if`, which the sibling project `cockpit-guac-rdp`
  already learned is cosmetic.
- **It does not open a file you name.** Verbs take a registry id. There is no
  code path that opens a caller-supplied path.
- **It does not export by default.** "Export as CSV" writes every secret in the
  safe to disk in the clear. It is admin-only, off unless the registry enables
  it per safe, and audited by name.
- **It does not rotate a master passphrase.** `safe-create` makes a new safe and
  `save-as` copies an *open* database to a new name, but neither changes the
  passphrase of an existing safe. Use the desktop client —
  [`docs/OPERATIONS.md`](docs/OPERATIONS.md) has the procedure.
- **It does not create a safe that opens with no passphrase**, and it will not
  adopt one either. This program never registers a key-file *path*, so it cannot
  honestly describe such a safe in the registry — and a key file stored beside
  the safe it opens is worth nothing. A key file is accepted as a SECOND factor
  only. `import-commit` refuses a file that opens on a key file alone, with the
  reason.
- **It does not escrow or recover anything.** Lose the master passphrase and the
  safe is gone. That is the point of it.

---

## Install

`install.sh` must run as root, and refuses rather than half-installing.

**On this host there is no interactive `sudo`** — root work goes through the
`/srv/jobs` job runner, and `tests/root/submit.sh` is what this project uses:
`./tests/root/submit.sh 10-install.sh` installs, `20-verify-install.sh` then
audits the result from a *separate* root job, because an installer that checked
its own work would report the mode it intended in both places. The `sudo` forms
below are the portable spelling for a host that has it.

```bash
./check.sh                    # JavaScript syntax gate (no build step exists)
./validate.sh                 # standing invariants: syntax, JSON, the I9-I15 bans, unit tests
sudo ./install.sh             # install
sudo ./install.sh --with-agent    # ... and the opt-in unlock agent (you probably do not want this)
sudo ./install.sh --uninstall     # remove the software; keep registry, safes, audit log
sudo DESTDIR=/tmp/stage ./install.sh   # stage into a package build root
./install.sh --help
```

The installer validates `manifest.json` before copying anything — an invalid
manifest makes Cockpit drop the package *silently*, with no page, no menu entry
and no error where anyone will look — refuses a manifest that relaxes the CSP,
compiles the Python payload, runs the JavaScript gate, and validates the seeded
registry examples against the schema. Any of those failing means nothing is
written at all. It never restarts Cockpit; a page reload picks the package up,
and a logout/login picks up the menu entry.

### Installed layout

| Path | Mode | What |
|---|---|---|
| `/usr/share/cockpit/secrets/` | `0755 root:root`, files `0644` | `manifest.json`, `index.html`, `secrets.js`, `secrets.css` |
| `/usr/local/sbin/secrets-admin` | `0755 root:root` | the verb helper — the only thing that touches a safe |
| `/usr/local/lib/cockpit-secrets/backends/` | `0755`, files `0644` | the format adapters |
| `/usr/local/lib/cockpit-secrets/schema/` | `0755`, files `0644` | `safe-registry.schema.json` |
| `/etc/cockpit-secrets/safes.d/` | `0755 root:root`, entries `0644 root:root` | **the registry** — the only source of safes |
| `/etc/cockpit-secrets/safes/` | `0700 root:root` | admin-class safe files, `0600 root:root` |
| `/var/log/cockpit-secrets/` | `0700 root:root` | `audit.log` — metadata only, never a value |
| `/var/lib/cockpit-secrets/state/` | `0700 root:root` | `fail.<real uid>.<safe>.json` per-operator failure counters, and `safe.<safe>.json` per-safe rate windows. Both `0600`; the real uid, never the euid (I40) |
| `/var/lib/cockpit-secrets/exports/` | `0700 root:root` | where `export` writes, `0600` — an entire safe in plaintext |
| `/usr/local/lib/systemd/user/secrets-agent.*` | `0644` | `--with-agent` only, and never enabled by the installer |
| `/usr/local/lib/systemd/system/secrets-agent@.*` | `0644` | the admin-class template — installed, never enabled |

`secrets-admin` finds its Python packages in the directory holding the script
(the repo layout, where `backends/` and `schema/` sit beside it) and otherwise
in `/usr/local/lib/cockpit-secrets`. Both layouts work with no code change; the
installer smoke-tests the import and says so if it fails.

An uninstall removes the software and **keeps** the registry, the safes, the
audit log and the lockout counters. Removing a program must not silently change
who may open what, and uninstalling must not be a way to clear a lockout.

---

## The registry — the only source of safes

Nothing inside a `.kdbx` or `.psafe3` file records who may open it. "User safe"
and "admin safe" are *our* concepts, so they are imposed from outside the file
or they do not exist at all. That outside is
`/etc/cockpit-secrets/safes.d/*.json`, root-owned, one JSON object per file:

```json
{
  "id": "lab-dc",
  "label": "AD Lab domain accounts",
  "format": "kdbx",
  "path": "/etc/cockpit-secrets/safes/lab-dc.kdbx",
  "access": "admin",
  "groups": ["sudo"],
  "mode": "rw",
  "password_required": true,
  "keyfile": null,
  "yubikey_slot": null,
  "agent": { "enabled": false, "idle_seconds": 300, "max_seconds": 3600 },
  "export_allowed": false,
  "export_dir": null,
  "breach_corpus": null,
  "backup": { "keep": 10, "dir": null }
}
```

Every field, and what breaks when it is set wrong, is documented in the
`$comment` of [`schema/safe-registry.schema.json`](schema/safe-registry.schema.json).
Two working examples are installed as `*.json.example`, which the registry's
`*.json` glob does not match — copy one and edit the copy
([`etcdefaults/README.md`](etcdefaults/README.md) explains why they are seeded
disabled). `secrets-admin health` reports `registry_errors[]`, which is the
supported way to find out why a safe is missing from the list.

An entry that fails schema validation is **dropped and logged** — never
partially applied, and never defaulted to the permissive class.

An entry the page created or imported also carries `origin` (`created` /
`imported` / `manual`), `created_utc`, and — for an import — a `source` block
recording the unauthenticated header summary you were shown before you typed
your passphrase. None of the three grants anything: `safe-delete`'s gate is
**derived** from the id, not read from `origin`, precisely so that a
hand-edited provenance key cannot talk the helper into unlinking a file it did
not create.

### The second registry: `~/.config/cockpit-secrets/safes.d/`

Root owns `/etc/cockpit-secrets/safes.d/`, so an unprivileged user cannot write
there — which meant that before 0.4.0 they could not have a safe of their own
without an administrator hand-writing an entry for them. The **per-user
registry** is what lets `safe-create` and the import flow work for a normal
user, and it is the one trust-model change in this program's history. Five
rules, all enforced in the helper:

1. It is read **only** when the helper is running unescalated as that user. A
   root-mode helper does not even open it (`health` says so, and it is proved
   two ways in `docs/STRESS-REPORT.md`).
2. Every entry loaded from it is forced to `access: "user"`. One declaring
   `admin` is **dropped and reported**, never downgraded.
3. Its `path` must resolve to a file that user owns, 0600, with no
   group/other-writable parent — the same check `open_safe_fd` applies
   everywhere else.
4. The directory and its files must be owned by that user and not
   group/other-writable, or the whole per-user registry is refused.
5. A system entry and a per-user entry with the same id: **the system entry
   wins**, and the shadowed per-user entry is reported as an error.

**Why that is safe, in one sentence:** it grants the user no access they did not
already have, because the helper is running *as them* and they can read their
own files anyway. It is a convenience surface, not a privilege surface — and if
any of rules 1–4 is ever relaxed, that sentence stops being true.

### The two access classes, and `admin` is the default

|  | `access: "user"` | `access: "admin"` (**default**) |
|---|---|---|
| Helper euid | the logged-on user | `0`, or the verb is refused |
| Cockpit call | `cockpit.spawn([…])` | `cockpit.spawn([…], {superuser: "require"})` |
| Extra gate | the safe file must be owned by the caller | the real caller behind the escalation must be in one of `groups` (default: `sudo`/`wheel`) |
| Safe file | `0600`, in that user's own tree | `0600 root:root`, in `/etc/cockpit-secrets/safes/` |
| Blast radius of a helper bug | that one user's files | root |

**An entry that omits `access` is `admin`.** A hand-edit that loses a line
therefore makes a safe *harder* to reach, not easier. The opposite default would
turn a truncated write into a privilege grant.

The check runs **in the helper, inside every verb**, from an identity the kernel
supplies (`geteuid`, `getuid`, `getgroups`, and `SUDO_UID`/`PKEXEC_UID` behind
an escalation) — never from the request body, and never in the browser. The page
greys out what you cannot use so it is honest about what exists, but the greying
is decoration: the helper is what refuses.

---

## The security model, in plain words

**The passphrase is prompted every time, and that is a fact about the process
tree rather than a policy.** The browser runs one `cockpit.spawn` per verb. The
bridge forks a `secrets-admin`, writes one JSON request to its stdin, closes the
stream, reads one JSON object back, and reaps the child. A handle is a random
128-bit token bound to (uid, safe id, pid); when the process exits, the pid is
gone and so is every key derived inside it. Nothing is written to `/run` or
`/var/lib` that could outlive it. The next verb therefore starts from a locked
file. To break that you would have to change the process model, not flip a
setting. Two opt-in exceptions exist and both are visible: a single long-lived
helper for one multi-step editing session, and the per-safe agent (off by
default, hard idle and absolute timeouts, a persistent banner while it holds
anything).

The agent is a narrower exception than it sounds. It holds a **ticket, not a
key** — a uid-bound note that a safe was unlocked, with both deadlines running
and nothing in it that could reopen the safe — so even with it on, the
passphrase is prompted on every unlock. What it buys is that the unlock is
visible and revocable, not that you are asked less often.

**Guessing is bounded by a counter, not only by the KDF.** Five failures for one
operator against one safe trip an escalating backoff and then a five-minute
lockout; twenty credential attempts against one safe in sixty seconds, counting
every operator together, trip a fixed-window rate cap. The attempt is *reserved*
under an exclusive file lock **before** the key is derived, so fifty guesses
fired at once behave exactly like fifty guesses one at a time — that was not true
before 2026-09-04 and the defect is written up as I39. The counter is named after
the **real** caller behind an escalation, so one administrator's typo does not
refuse the safe to every other administrator (I40). A wrong passphrase also
cannot answer faster than a right one: there is a constant floor on the failure
path, measured.

**The passphrase never becomes an argument.** Not `argv`, not the environment,
not a temp file — `/proc/<pid>/cmdline` and `/proc/<pid>/environ` are readable by
the process owner and by root, and argv reaches shell history and audit trails.
Requests are one JSON object on the helper's stdin, capped at 1 MiB.

**Nothing about a safe is stored in the browser.** No `localStorage`, no
`sessionStorage`, no IndexedDB, no cookie, no hidden form field. The passphrase
lives in one function-scoped variable, is sent, and is overwritten. Anything
persisted there would be readable by any XSS anywhere in the Cockpit origin.

**Nothing decrypted leaves a backend before its MAC verifies.** Password Safe v3
puts its HMAC at the end of the file, so the format forces decrypt-then-
authenticate; KDBX4's inner XML is attacker-shaped until the block MACs check
out. Returning any value before that point turns a parser bug into a decryption
oracle. Every MAC, key hash and handle comparison is `hmac.compare_digest`, and
a wrong passphrase and a failed MAC return the **same** error with the same
wording — the distinction is in the audit log, not in the answer.

**Hostile files are treated as hostile.** KDF parameters come out of the file, so
they are clamped before the KDF runs (Argon2 `m` ≤ 1 GiB, `t` ≤ 32, `p` ≤ 8;
PWS3 `ITER` in [2048, 8388608]); the decrypted XML is parsed with entity
resolution, DTD loading and network access explicitly off; every declared length
is bounds-checked before anything is allocated.

**Files are opened by fd, not by name.** `O_NOFOLLOW|O_CLOEXEC`, then `fstat`
**the fd** — never a second `stat` of the path — checking regular file, expected
owner, no group or other permission bits, and no group- or other-writable
ancestor directory. Every later operation uses that same fd. That is what stops
a user-class safe path being swapped for a symlink to `/etc/shadow` between the
registry read and the open, on a helper that may be root.

**A save cannot destroy a safe.** Backup ring first, then a temp file in the same
directory, `fsync`, `os.replace`, `fsync` the directory. The target is never
opened for writing; the only thing that touches it is an atomic rename, so a
`SIGKILL` at any moment leaves either the whole old file or the whole new one.
The `(mtime_ns, size, sha256)` captured at unlock is re-checked immediately
before the write, and a mismatch is a refusal, never a silent merge.

**The audit log records the event, not the secret.** Timestamp, verb, safe id,
caller uid, outcome, duration — never a value, never an entry title, never a
path from the request, never a traceback.

## What this does not protect against

Stated here rather than buried, and in full in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md):

- **Root on this host.** Root can read the helper's memory, replace the helper,
  and read the registry. Disabling core dumps, `PR_SET_DUMPABLE=0`, best-effort
  `mlockall` and a process lifetime measured in milliseconds raise the cost;
  they do not change the conclusion. No password manager on any machine defends
  against this.
- **A compromised browser or endpoint.** If the machine typing the passphrase is
  owned, the passphrase is owned.
- **Python's own memory model.** A `str` is immutable and interned: the moment
  the JSON parser produces the passphrase, or `pykeepass` demands one, the
  interpreter holds a copy no code of ours can overwrite. Secrets live in
  `bytearray` and are zeroed in `finally` where that is possible; the two places
  it is not are named in `docs/ARCHITECTURE.md`.
- **The clipboard.** It is a shared OS resource. Clearing it is best-effort and
  the page says so where you copy.
- **Losing the master passphrase.** There is no escrow and no recovery. That is
  by design.

---

## This tree

| Path | What |
|---|---|
| `manifest.json`, `index.html`, `secrets.js`, `secrets.css` | the Cockpit package |
| `secrets-admin` | the verb helper: dispatch, identity, access class, audit |
| `backends/` | `base.py` (Secret, fd opening, atomic write, locks, limits) and one adapter per format |
| `schema/` | the registry schema — the machine-readable half of the contract |
| `etcdefaults/` | the two seeded registry examples |
| `agent/` | the optional unlock agent (I18), if it was built at all |
| `tests/` | unit, interop and browser suites |
| `docs/` | contract, architecture, threat model, hazard register, upstream review, operations |
| `check.sh` | JavaScript syntax gate |
| `validate.sh` | the fast standing gate: syntax, JSON, bad-practice bans, unit tests |
| `run_tests.sh` | everything that can run unprivileged and without Cockpit — 19 steps, including the integration suite, the format oracles and a headless browser driver |
| `tests/root/run-all.sh` | the eight-step root suite, submitted to `/srv/jobs`; the only place the admin class is tested against a genuinely root-owned registry |
| `tests/browser/run-live.sh` | the ten-item live walkthrough against real Cockpit; needs the package installed and a credentials directory |
| `install.sh` | root-only installer |

**Read before changing anything:**
[`docs/CONTRACT.md`](docs/CONTRACT.md) (the verb interface),
[`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md) (hazards **I1–I42** — the code
cites these ids by number, so a comment saying `(I13)` is a pointer into that
file),
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (what happens between a click and
a decrypted field), and
[`docs/UPSTREAM-REVIEW.md`](docs/UPSTREAM-REVIEW.md) (what was adopted from
KeePassXC and Password Safe, what was rejected and why, plus the 20-item
bad-practice table).

**Read before trusting it:**
[`docs/RESIDUAL-RISK.md`](docs/RESIDUAL-RISK.md) (what someone can still do, and
what has never been tested),
[`docs/STRESS-REPORT.md`](docs/STRESS-REPORT.md) (every attack, including the
ones that found nothing),
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) (verified versus believed), and
[`docs/LIVE-WALKTHROUGH.md`](docs/LIVE-WALKTHROUGH.md).

**Read before operating it:**
[`docs/OPERATIONS.md`](docs/OPERATIONS.md),
[`docs/HOST-FACTS.md`](docs/HOST-FACTS.md) (what is true of edt1 specifically)
and [`docs/ROOT-VERIFICATION.md`](docs/ROOT-VERIFICATION.md).
