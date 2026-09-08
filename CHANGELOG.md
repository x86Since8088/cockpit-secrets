## 0.5.2 - 2026-09-07

Install classification is now decided by LAYOUT, not by a development-root path
prefix, and this plugin was deployed to its real install path on edt1.

- `install.sh` decides dev vs deployed by asking whether its own directory is
  what a sibling `payload` symlink resolves to. The old test compared `$SRC`
  against a hardcoded development root and got a checkout sitting ANYWHERE ELSE
  wrong: such a checkout classified itself `deployed`, so it skipped the
  group-writable warning, wrote INSTALL_KIND=deployed for a host that was not
  self-sustaining, and dropped "the checkout is not touched" from
  `--uninstall`. Reproduced before the change and confirmed fixed after.
- Because that literal is gone, pre-flight check 9 now scans `install.sh`
  itself. The carve-out that exempted it is removed. Both of the check's own
  patterns are split so the scanner cannot match itself; the string it searches
  for is unchanged, so nothing is weakened.
- `owned_by_us` recognises a dev link by `$SRC` rather than by "anywhere
  under the development root", which is tighter: it no longer adopts a link
  belonging to a different checkout of the same project.
- The uninstall notice and the dev warning ask the LINK TARGET's layout, so
  they stay correct when the deployed installer tears down links a dev install
  made.
- Deployed to /opt/cockpit-secrets on edt1. The registry, safes, audit log and
  lockout state under /etc and /var were kept, not rewritten; the operator's
  pwsafe3 safe and registry entry and the three dummy-fake safes are unchanged,
  verified by hash before and after.
- Gate re-run after every change: check.sh OK, validate.sh OK, run_tests.sh OK
  with 20/20 groups and zero FAIL lines.
A recursive grep of the deployed tree for the development root or the retired
checkout path now returns nothing at all.

# Changelog

Notable changes to cockpit-secrets. Versions are `MAJOR.MINOR.PATCH`; `VERSION`
carries the current one and `install.sh` prints it.

Two conventions worth knowing before reading an entry:

- Hazard ids (**I1**–**I55**) refer to [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md).
  A line that cites one is claiming that hazard is mitigated in this release, not
  that it was thought about.
- Some components are optional by design and can be absent from a build (the
  unlock agent above all). **`secrets-admin health` is the authority on what a
  given installation actually has** — not this file.

## 0.5.1 — 2026-09-06

**The five things 0.5.0's own verification said were still wrong.** 0.5.0 shipped
the restyle and then said, in `docs/DESIGN.md` §18, exactly what it had not
delivered. This release closes that list and nothing else: R5, `theme.js`, the
cramped entries table, the three broken live specs, and the non-hermetic
integration suite. Each is a hazard in
[`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md) — **I56–I60** — with its evidence
and the check that goes red without it.

Every one was **reproduced before it was fixed** and every fix was **watched
failing with the fix reverted**.

### Fixed

- **R5 is delivered (I56).** `list` publishes `path`, resolved through
  `resolve_entry(entry, ctx.ident)` so there is no second source of truth and
  `%u` is expanded from kernel identity and never from the request. The page
  needed no change: `optColAvailable()` and the pane's `if (safe.path)` simply
  became true. The **Path column is off by default** and the path is **always in
  the details pane, in full, selectable and wrapping**.
  - **The design's own prescription was wrong, and that is recorded rather than
    quietly dropped.** §18.1 said to gate the new field on access class. Built
    that way it passed every offline gate and then failed live for the exact
    safe R5 was written about: `secrets.js` spawns `list` with no superuser
    option, always, so a class gate refuses every admin-class row at *both*
    access levels. What makes publishing it safe is a property of the loader,
    measured: a registry file the caller's euid cannot open never becomes a row,
    so every path shown came out of a file the caller could already read.
    `docs/CONTRACT.md` carries the correction and the four `path` rules.
- **`theme.js` is actually installed (I57).** It was in the page and not in
  `install.sh`'s `PLUGIN` array — which is the copy list *and* the sweep list —
  so the installer copied it and deleted it again on every run, and Chromium
  logged a MIME refusal on every page load. `PLUGIN` now names it, and a new
  **pre-flight gate** parses `index.html` with `html.parser` and refuses to
  install a page that references a package-local file the array does not ship.
  It refuses rather than warns, because a warning is what the previous round
  produced and nobody acted on.
- **The entries table is readable at the default docked width (I58).** The floor
  is 42rem → **60rem**, derived from the columns' own longest unbreakable tokens
  and written out in the sheet; `table.sec td` is `overflow-wrap: break-word`
  rather than `anywhere`, with `anywhere` re-applied to exactly the URL column
  and the safes table's `.mono` cells. Measured on the testbed's worst row:
  **26 lines → 9**, and `ada.lovelace` no longer breaks mid-word (96px → 176px).
- **A visually-hidden span no longer scrolls the whole page sideways (I59).**
  `.sec-scroll { position: relative }`. At a 380px frame the entries view really
  did scroll the document 318px; `clip: rect(0 0 0 0)` does not remove an
  absolutely-positioned element from the root's scrollable overflow, and nothing
  between the cell and the document was a containing block.
- **`tests/integration/` is hermetic again (I60).** `_env.py` exports
  `COCKPIT_SECRETS_HOME` beside the two seams it already set, and
  `assert_loaded` now refuses any id that was LOADED but not WRITTEN instead of
  counting. `./run_tests.sh` with **no environment override: 20/20, exit 0**
  (was 12/20 — eight stages aborted at build time because the caller's own
  per-user registry leaked into the "hermetic" one).

### Changed

- **All three live specs migrated to the pane idiom.** The restyle made an
  action two gestures — choose the row, then use the pane — and
  `.sec-safe … button:text-is("Unlock…")` matched nothing in any of them. Rows
  are `#sec-safes tbody tr.sec-safe` filtered on exact `.sec-safe-id`; the row's
  control is `button.sec-rowdoor`; Unlock is
  `#sec-pane-body .sec-safe-actions button.sec-btn.primary`, addressed by
  STRUCTURE so it survives a change of wording. Three assertions that no longer
  describe the product were **replaced with what does, each with its reason in
  the file** — never deleted, and never loosened.
- **`tests/root/20-verify-install.sh` derives the package payload from
  `install.sh`** instead of restating it. Its hard "holds exactly the payload"
  assertion carried its own four-name copy and therefore failed the release that
  legitimately grew the payload to five. A gate with its own copy of a list is a
  gate that fails the wrong thing.
- **`live-ui.spec.js` item 6's attachment step reads the helper's answer instead
  of assuming acceptance.** A Password Safe v3 database this program creates
  declares 0x030D and attachments need 0x030F, so the only PWS3 in the testbed
  cannot take one — by construction and on purpose
  (`docs/RESIDUAL-RISK.md` §4.11). The item used to assert "the upload was
  accepted" unconditionally and then throw, aborting the whole psafe3 half at
  that step the first time it was ever driven against a PWS3 this program had
  made. It now asserts the refusal is the FORMAT's own `unsupported`, carrying
  the version the file declares and the version attachments need, asserts the
  entry is not drawn as if it had an attachment, and continues. Any other
  refusal is still a failure.

### Added

- **`live-ui.spec.js` item 11 — R5 end to end**, the only committed test that
  drives R5 against the real helper. It runs last and in a session of its own,
  and escalates there through Cockpit's own header control, because R5 must be
  shown for a **system-registry** safe as well as a per-user one and items 1–10
  are written against a limited-access session. In one session it re-proves
  **R1 in both directions** (the admin row absent while access is off, present
  after), **R2**, **R3**, **R4**, all of **R5** (off by default; the published
  path string absent from the default table; the chooser offers it; both cells
  hold the helper's own value in full; it survives a sort in both directions;
  the pane's first section is Path, character-for-character, `user-select` not
  `none`, wrapping and not elided, with the correct location sentence), and
  **I11** across the chooser, the pane, the sort, the toggle and a full unlock
  against a baseline taken before any of it.

### Known issues

- **I61 (new, OPEN).** In a session that has *already* turned administrative
  access on, the details pane for an admin-class safe still reads "turn on
  Cockpit's Administrative access and try again". The sentence is the helper's
  and is correct for the caller that produced it — `list` is always spawned
  unescalated — but the page re-shows it after the operator has done the thing
  it asks for. The control works: `live-access.spec.js` item 9 opens that safe
  in that state. Advice that has gone stale, not a refusal.
- **Item 6 is a full pass for KDBX and a partial one for PWS3**, and says so in
  its own report: the attachment chain cannot be driven against a 0x030D file.
- **Chromium only**, in this round as in every previous one.
- The residual list for the 0.5.x page is
  [`docs/RESIDUAL-RISK.md`](docs/RESIDUAL-RISK.md) Part 5, and
  `docs/DESIGN.md` §18.11.

## 0.5.0 — 2026-09-06

**The page was restyled, and this is the first release where that restyle has
actually been installed and driven in a real browser.** 0.4.0's page was two
unrelated layouts — a card grid and a three-column split that, measured, could
never trigger inside Cockpit's iframe. It is now one workspace with one
right-docked details pane, one sortable table, and a theme that follows the
Cockpit shell instead of guessing from `prefers-color-scheme`.

`docs/DESIGN.md` is the specification and now carries an **"As built"** section
(§18) recording every place the implementation diverged from it. `docs/LIVE-WALKTHROUGH.md`
carries the 0.5.0 run: the commands, the measured numbers, and the failures.

### Added

- **`theme.js`** — resolves Cockpit's light/dark choice from the shell's own
  `<html>` and mirrors it onto ours, with a `MutationObserver` that follows a
  live change. It reads one class off a same-origin document and writes nothing
  anywhere: no storage API, no network. This fixes the two states a *deliberate*
  choice produces — shell Dark with the OS in light, and shell Light with the OS
  in dark — where `prefers-color-scheme` alone is measurably wrong.
  **See the Known issues entry below: `install.sh` does not ship this file yet.**
- A **column chooser** for the safes table, and a **details pane** with a real
  `<button>` toggle carrying `aria-expanded` / `aria-controls`.
- Skip links, including one to the details pane — R3 puts a long table between
  the top of the page and the pane, and one keystroke is what makes it reachable.

### Changed

- **The safe list is a real `<table>`** with `<th scope="col">`, a caption,
  `aria-sort` on the sorted column, and rows activated by Enter or Space. The
  card grid is gone.
- **Nothing in a row is an action any more.** Every action moved into the pane,
  so there is exactly one place a destructive control can live. This is the
  single change that breaks the live suites (below).
- **The details pane is docked right** at ≥ 60rem and un-docks below it. The old
  collapse point was 75rem, which the iframe can effectively never reach: at a
  1400px window the frame is 1160px.
- `.sec-safe.unreachable` no longer dims. Opacity is a colour-only carrier that
  lowers contrast; the "Unreachable" chip and the helper's own sentence say it
  instead.
- Focus is restored to the activated row after a re-render, rather than dropping
  to `<body>`.

### Fixed

- Contrast: every control boundary on the page. Measured from the rendered page,
  **21 fg/bg pairs in light and 23 in dark, zero below threshold** (lowest 4.97
  and 6.66). Disabled controls are exempt under WCAG 1.4.3 and are excluded.
- No horizontal page scroll at the WCAG 200% viewport (700 × 480), at 480px or
  at 360px; a wide table scrolls inside its own box instead.
- `prefers-reduced-motion: reduce` is honoured — zero animating and zero
  transitioning elements.

### Known issues introduced or confirmed by this release

> **All five of these were closed in 0.5.1** (`docs/KNOWN_ISSUES.md` I56–I60).
> They are left here as written, because the value of a release that lists what
> it did not deliver is destroyed by editing the list afterwards.

- **R5 (the Path column) is unreachable, and this release does not deliver it.**
  The `list` verb does not publish `path` — it is not in the verb's declared
  response and is absent live at every access level — and both the optional
  column and the pane's Path section are guarded on that field. The controls are
  written correctly and are dead code against this helper. **The fix is in the
  helper**: publish `path` from `list`, gated on access class.
- **`install.sh` does not ship `theme.js`.** `PLUGIN=(manifest.json index.html
  secrets.js secrets.css)` is both the copy list and the list the package
  directory is swept down to, so an installed `theme.js` is deleted on every run
  — while the same script's pre-flight syntax-checks it. `secrets.js` carries a
  guarded second copy of the resolver, so **the theme itself is unaffected**;
  the cost is that Cockpit answers the missing request with an HTML error page
  and the browser logs a script refusal on every page load. One line fixes it.
- **All three live browser specs need a selector migration**, not just
  `live-ui.spec.js`. `.sec-safe … button:text-is("Unlock…")` no longer matches,
  because Unlock moved into the pane. `run-live.sh` is **red**: `live-registry`
  13/15, `live-ui` 4/8, `live-access` 9/10.
- **`elevationChanged()` is unexercised.** Cockpit's shell reloads the plugin
  frame when superuser status changes, so R1's visible behaviour is delivered by
  that reload rather than by the listener. Not a security gap — a reload destroys
  the session outright — but not tested code either.
- **`tests/integration/_env.py` needs one line.** Its hermetic registry is
  contaminated by the caller's own per-user registry row, which made 8 of 20
  `run_tests.sh` items fail with `entries=10`. Setting `COCKPIT_SECRETS_HOME`
  alongside the existing `COCKPIT_SECRETS_ETC` isolates it: **20/20, exit 0**.

## 0.4.0 — 2026-09-04

**You can now create a safe and adopt an existing one.** Until this release a
safe existed only if root hand-wrote the file into `/etc/cockpit-secrets/safes/`
AND hand-wrote a registry entry into `/etc/cockpit-secrets/safes.d/`. A tool
that claims to fully manage safes has to be able to make one and to take one in,
and now it can — from the page, without an administrator for a user-class safe.

This is also the most dangerous change in the project, because it is the first
time a **browser request writes into the registry**, which is this program's
trust root. Everything else is downstream of the registry: it says which files
are safes, where they live, and what access class each one has. A red-team round
against the first implementation found **twelve defects**; all twelve are fixed
here, each with a regression check that was watched going red with its fix
reverted and a standing ban in `validate.sh` that was watched firing on a
deliberate violation.

### Added

- **`safe-create`** — mint a new, empty, valid KDBX 4.1 or Password Safe v3
  database and register it. The passphrase arrives on stdin like every other
  credential (I10); the strength estimate is shown as advice and never as a
  gate, because refusing an operator's chosen passphrase is not this program's
  decision to make. A key file can be generated as a SECOND factor, is returned
  **once**, and is stored nowhere.
- **`import-begin` / `-chunk` / `-inspect` / `-commit` / `-abort`** — adopt an
  existing safe. **The encrypted file is uploaded FIRST and the passphrase is
  asked for LAST**, and that ordering is a requirement rather than a
  preference: a large upload takes visible time, and collecting the passphrase
  up front means holding it in browser memory for the whole transfer, which is
  exactly the window I11 and I14 exist to shrink. Because a KDBX or PWS3 header
  is not secret — and the person uploading holds the file — `import-inspect`
  reports format, version, cipher, KDF and its parameters **with no credential
  at all**, so the operator can confirm they uploaded the file they meant to
  before typing anything. The UI labels that summary as what it is: read from
  the header, not authenticated. A KDF bomb is refused at that step, before
  anybody waits on a derivation. A wrong passphrase at commit does NOT destroy
  the staged bytes.
- **`safe-forget`** (remove the registry entry, leave the file exactly where it
  is — the default and the safe one) and **`safe-delete`** (forget it *and*
  destroy the file plus its derived backup ring, behind an exact confirmation
  token naming the id). Creating without removing would have built a trap.
- **A per-user registry** at `~/.config/cockpit-secrets/safes.d/`, which is the
  one trust-model change in this release. Root owns the system registry, so
  without this an unprivileged user could not have a safe of their own without
  an administrator. It is read **only** when the helper is running unescalated
  as that user; **a root-mode helper never opens it** (proved two ways — an
  instrumented-open shim with a positive control, and `strace` at a real euid 0
  through `/srv/jobs`); every entry loaded from it is forced to `access: "user"`
  and one declaring `admin` is dropped and reported; its `path` must pass
  `open_safe_fd`; and a system entry with the same id wins, with the shadowed
  per-user entry reported as an error rather than silently preferred. The safety
  argument, stated at the loader: this grants the user no access they did not
  already have, because the helper is running *as them*. It is a convenience
  surface, not a privilege surface.
- **Provenance in the registry** — `origin`, `created_utc` and `source`. A
  created or imported entry now records that this program made it, when, and
  (for an import) the unauthenticated header summary the operator was shown
  before they typed a passphrase.
- **Three new backend primitives**, all of which take BYTES and none of which
  takes a path, a filename or a directory: `Backend.create_new`,
  `Backend.validate_candidate` and `Backend.inspect_bytes`. `create_new` is
  concrete policy on the ABC standing on format hooks that refuse by default,
  so a third backend cannot half-implement creation into something that looks
  like it worked.

### Fixed — the twelve the red team found (I43–I54), and one this release found itself

- **I43 · `import-commit` proved one read of the staged file and landed a
  different one.** It addressed the blob by path twice with a full KDF
  derivation in between, so the bytes that were proven to open and the bytes
  that became a safe were never the same bytes — and the verb's whole security
  argument, that a file which does not open does not land, was false. Fixed
  structurally: `_open_candidate` no longer accepts a path, so there is nothing
  left to re-read.
- **I44 · a registry entry naming a FIFO hung every helper invocation,
  forever** — including `schema` and `health`, the two a stuck plugin needs to
  explain itself with. `open_safe_fd`'s "regular file, or refuse" check runs
  after the open, and `open(2)` on a FIFO blocks. One flag: `O_NONBLOCK`,
  cleared once `S_ISREG` passes.
- **I45 · a failed registry write left an orphan safe file and burned the id
  forever.** `_land_new_safe` now places the file and publishes the entry as one
  operation, and unlinks the file again if the entry cannot be written.
- **I46 · `_KNOWN_KEYS` omitted the three provenance keys**, so the three
  shipped `etcdefaults/` examples were accepted by jsonschema and silently
  DROPPED by the helper — an operator following the shipped documentation got a
  safe that did not appear in `list`. Both halves fixed in one change, and
  `tests/ban_registry_vocabulary.py` now compares the two vocabularies in both
  directions on every gate run.
- **I47 · `safe-delete` shredded any file a registry entry named**, without ever
  opening it through a backend, and swept any directory `backup.dir` named. The
  derived-path gate `docs/CONTRACT.md` already specified is now implemented, and
  the ring is derived from the minted path.
- **I48 · `safe-delete` destroyed the file BEFORE unregistering it** and then
  reported the whole thing `access-denied` — the operator was told nothing had
  happened after the safe and its entire backup ring were gone. The registry
  entry goes first now.
- **I49 · `safe-delete` checked `confirm` while its schema published
  `delete_confirm`**, so through the published interface the destructive verb
  could never succeed. Generalised into `tests/ban_undeclared_fields.py`, an AST
  + call-graph gate that refuses any verb reading a request field its own schema
  omits — which immediately found four more, all real: `backups`,
  `breach-check`, `restore-backup` and `export` all accept a session `handle`
  and none declared it. All four now do.
- **I50 · the pre-commit import steps ACCEPTED a credential and ignored it.**
  C5's ordering lived entirely in `secrets.js`. It is now enforced in the
  dispatcher, driven by each verb's own declared request, so a new verb gets the
  refusal without anybody adding a line.
- **I51 · `safe-forget` reported success while the safe stayed registered**,
  when two registry files declared one id. The loader carries every file that
  declared an id and forget refuses, naming them.
- **I52 · `safe-create` accepted bidi-override and zero-width characters in
  `label`** — the field the registry schema itself names as how a passphrase
  gets typed into the wrong prompt.
- **I53 · the start-up staging sweep followed a symlink named like a staging
  token** and unlinked `blob` / `meta.json` outside the staging root, on every
  helper invocation including at euid 0.
- **I54 · nothing bounded how many `import-inspect` / `import-commit` calls ran
  at once.** 32 simultaneous inspects of one 128 MiB staging measured **7.58 GiB**
  resident across 32 processes, every one euid 0 on the admin path. Bounded now
  by a non-blocking work slot that refuses rather than queues; the per-request
  cost also halved as a side effect of I43's single read (299 MiB -> 42 MiB peak
  on the same 128 MiB file).

- **I55 · a safe created at a reused id inherited the deleted one's lockout.**
  Found by cleaning the host after the live walkthrough, which was the first
  thing in this project's history to delete a safe and then reuse its id. The
  I16 counter is keyed on (real uid, safe id) and used to outlive the safe, so a
  brand-new safe was `locked-out` on its first unlock with the passphrase the
  operator had just chosen. Cleared in `_land_new_safe` and in `v_safe_delete`,
  so neither route can leave one armed.

### Changed

- `secrets-admin` builds a new KDBX through `KdbxBackend.create_new` instead of
  editing pykeepass's blank template itself. The old path inherited the
  template's **master seed, encryption IV and inner protected-stream key** into
  every safe it created — the last of those is the ChaCha20 key masking every
  protected value in the XML, and it was a published constant until the
  operator's first save. It also called `Secret.str_view()`, minting an
  unwipeable `str` of the new master passphrase. All of it is gone.
- `KDBX_MEMORY_MIN` / `_TIME_MIN` / `_PAR_MIN` are now `Limits`' own Argon2
  write floors (OWASP's m=19 MiB, t=2, p=1) rather than independent numbers.
  The helper used to publish a minimum of 8 MiB that the backend would then
  refuse — a published bound that is not the enforced bound is worse than none.
- `tests/integration/lockout.py` section A no longer asserts "exactly one of
  eight guesses was evaluated", which was true only while eight helper
  invocations fit inside the 2 s window the first failure opens. On a loaded
  machine they take 2.4 s, the eighth guess legitimately falls outside, and the
  test failed reporting a defect that was not there — it had been failing at
  HEAD for three separate agents. It now replays the escalating schedule
  (2 s, 4 s, 8 s …) against the observed timings from a **second implementation
  written from the published constants**, and a new section A0 MEASURES the
  first two windows against `LOCKOUT_BASE_SECONDS`. Strictly stronger and
  load-independent: a scratch build with the backoff zeroed passes the version
  that called the helper's own `_backoff_for` and fails this one with five red
  checks.
- `tests/integration/flow.py`'s class-gate sweep builds each request from that
  verb's own declared fields instead of sending `password` to all of them. 88
  checks -> 115, all green.
- **Four defects in this package's own test suite**, all of the same class — a
  check that could not fail. A `waitForFunction` with a string body is `eval`
  and the live CSP refuses it, so a swallowed rejection read a stale dialog; a
  predicate matched the create form's own help text and returned before the
  button was clicked; `Recorder.item()` defaulted a null state to `PASS`, so an
  item whose function threw reported green; and `input[type=checkbox]` caught
  the `make_keyfile` toggle as well as the confirmation gates. Three of the
  eight new `validate.sh` bans also failed to fire the first time they were
  tested against a deliberate violation, each because they grepped for a name
  that also appears in a definition. Every ban in this release was watched
  failing before it was kept.
- `install.sh` installs `etcdefaults/user-safes.d/` to
  `/usr/local/share/cockpit-secrets/examples/` as documentation and validates it
  against the schema; `validate.sh` checks its JSON. It is still never seeded
  into the system registry — a per-user entry there is an entry naming a home
  directory read by a root helper.

## 0.3.0 — 2026-09-04

**The three defects the re-gate found are closed, and so is the test defect it
declined to touch.** 0.2.2 was a documentation release that ended with I39, I40
and I41 recorded OPEN rather than rushed; this is the release that fixes them.
Two agents did the work, a third integrated it and **re-verified all three
without taking either report on trust** — which matters, because taking a
remediation report on trust is exactly how I41 survived 0.2.1.

### Fixed

- **I41 · a PWS3 save could destroy the safe and blame the passphrase.**
  `backends/psafe3.py`'s `save()` ran only the once-per-session losslessness
  guard, which latches after the first save. A second save in one session wrote
  a file the program's own reader then refused, reported `{"ok": true}`, and the
  next unlock answered `bad-credential` — sending the operator to guess more
  passphrases at a safe that was broken rather than locked.

  Three changes, and the first is the one that generalises. `Backend.verify_own_output()`
  in `backends/base.py` is now the **shared** policy — re-open the exact bytes
  through the reader a later `unlock` uses, diff against the database that was
  serialised, raise `Conflict` with the live file untouched — and it stands on
  two hooks that **refuse by default**, so a third backend that has not written
  them cannot save at all rather than saving unchecked bytes. `_emit_field` now
  calls `_check_field_length`, the READER's own bounds check with the same
  type-aware constants, so I23's *"this program cannot write a file its own
  reader refuses"* is true for PWS3 by construction. And a standing ban
  (`_unverified_writes`) fails any backend `save`/`save_as` that reaches
  `atomic_replace` without a verify call in the same body — no per-file
  exemption list, because an exemption list is how the second backend gets
  forgotten again.

  Separately, `_decode(own_output=True)` keeps a structural failure's real
  detail instead of flattening it to `BadCredential`. **I6's oracle is not
  reopened**: the flattening exists to deny a caller who supplies both a file
  and a passphrase guess any per-guess signal, and this path takes neither. The
  flag has exactly two callers, `unlock`/`parse_bytes`/`read_file` never pass it
  and cannot be made to from a request, and a wrong passphrase and a tampered
  file still return the identical `bad-credential` sentence.

  **The re-gate's reachability claim was wrong and is corrected rather than
  quietly dropped.** It recorded that only the 1 MiB request cap stood between
  this and the shipping `edit` verb. Field `0x0f`, the password history, is
  written by the helper rather than carried by the caller and grows one ordinary
  edit at a time; `password-history` is itself a published editable field name.
  Driven through the real helper, the largest frame needed was **65 680 bytes —
  six per cent of the cap**. The cap prevented nothing.

- **I39 · the unlock lockout did not survive concurrency.** Fifty guesses fired
  at once were 34 evaluated against a threshold of 5, and left the counter
  reading 3. **Three causes, all of which had to change.** Every counter access
  now goes through `_StateTxn` — `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`, `fstat`
  on the fd, `flock(LOCK_EX)` held across the read *and* the write. The attempt
  is **reserved before the KDF** rather than recorded after it, because the race
  window *was* the derivation and no amount of locking closes that; a wrong
  passphrase keeps the reservation, an error that never consumed a guess gives
  it back, a correct one clears it. And `lockout_reset()` zeroes in place instead
  of unlinking, because `flock` is held on an inode and unlinking hands the next
  arrival a different one.

  `flock` was chosen over an `O_EXCL` sidecar for **release on death**: this
  helper is spawned per verb by a browser channel that can vanish mid-derivation,
  and a killed process drops its `flock` with no reaper. The lock does not become
  the denial of service: nothing blocking happens while it is held, the wait is
  bounded by `LOCKOUT_LOCK_SECONDS` (5 s) and **fails closed**, and the counter is
  a different file per principal. Measured at a real euid 0 with a foreign process
  holding operator A's counter: A refused in 5.31 s naming the busy counter, B
  unaffected at 0.87 s, A admitted the moment the lock dropped.

- **I40 · every administrator shared one lockout counter per admin safe.** The
  counter was named after the **effective** uid, which is 0 for every operator on
  the admin path, so one clumsy operator's typo refused the safe to everybody else
  holding the correct passphrase. It is now named after `ident.real_uid`, the human
  behind the escalation — which is what I16 and `docs/ARCHITECTURE.md` step 6 both
  already said it was.

  **Keying on the real uid alone would have been theatre**, because an attacker at
  euid 0 can present a different `SUDO_UID` per attempt. Two things stop that. The
  class gate gets there first and mints no counter for a uid that is not in an
  administrative group — measured, so the fresh counters obtainable are one per
  *administrator of the host*, not one per integer. And a new per-SAFE cap that no
  identity resets: `LOCKOUT_SAFE_THRESHOLD` (20) attempts per `LOCKOUT_SAFE_WINDOW`
  (60 s) counting every principal together. It is deliberately a **fixed-window rate
  cap and not a second lockout** — giving it the per-principal escalation would let
  one bad actor deny a safe for fifteen minutes, which is worse than the hazard being
  closed.

- **I42 · the live suite's I11 storage check was a false statement** (a test
  defect, and the re-gate deliberately left it for somebody who was not also
  reporting on it). Item 4 treated *a key whose value changed length* as *a key
  this page added*, and Cockpit's own shell rewrites
  `sessionStorage["cockpit:page_status"]` while a run is in flight. The length
  comparison is replaced by an **in-page content probe** returning booleans —
  no storage value ever leaves the browser — and the exemption is bounded by
  **name and by content**: `HOST_SHELL_KEYS` is exactly `["cockpit:page_status"]`,
  documented in the source with the measurement, and being on it buys a key only
  the right to change length, never exemption from the probe. Strictly stronger,
  and proved so: of four scenarios the old check got **two wrong** — it fired on
  the shell's own key and it would have missed a same-length overwrite with the
  passphrase.

### Added

- `tests/integration/lockout.py` — 56 checks. A sequential control, 50 real
  helper **processes** fired at once, the reservation give-back, the per-safe cap
  against 25 synthetic principals, the wedge, and a reach sweep that reads the
  credential-bearing verbs **out of the `schema` verb**, so a verb added later
  that takes a passphrase is covered the day it is written. All 20 are covered.
- `tests/root/45-lockout-principals.sh` + `driver_lockout.py` — 35 checks at a
  real euid 0 through `/srv/jobs`, registered in `tests/root/run-all.sh`. It
  asserts B opens the safe while A is locked out **and in the same breath that A
  is still counted**, because "fix it by counting nobody" would pass the first
  check and destroy I16.
- `tests/browser/storage-check.selftest.js` — 6 checks, wired into
  `run_tests.sh`. It lifts item 4's storage oracle out of `live-ui.spec.js` by
  source extraction so it cannot drift, pins the four scenarios above, and fails
  if the tolerated-key list grows.
- New sections in `adversarial.py` (`crypto02_pws3`, the whole reachable sequence
  through the real helper) and in both backend self-checks.

### Verification

Every gate green against the final tree, and **every new test was watched failing
with its fix reverted.**

    ./check.sh              secrets.js syntax OK
    ./validate.sh           OK — 48 PASS / 0 FAIL, 38 unit tests
    ./run_tests.sh          OK — 19/19 PASS
    python3 backends/base.py            131 checks, 0 failure(s)
    python3 -m backends.psafe3          psafe3 self-check: OK
    python3 -m backends.kdbx            kdbx self-check: OK
    agent --selfcheck                    61 checks, 0 failure(s)
    gen_corpus.py --check                67 cases, 0 disagreed
    tests/oracle/build.sh                OK  (go1.26.0)
    integration: flow 86/0  conformance 83/0  properties 27/0  newverbs 220/0
                 agent_cycle 45/0  adversarial 87/0  lockout 56/0
                 corpus_vs_helper 67/0
    tests/root/run-all.sh   all 8 steps exit 0, 0 failures in every step
    run-live.sh             exit 0 — 131 checks held, 0 FAIL, all ten items

The independent re-verification is in `docs/STRESS-REPORT.md` §8. Its sharpest
result: with `verify_own_output` deleted from `Psafe3Backend.save` and nothing
else changed, a probe written for that pass watched the defect reproduce end to
end — `save() -> {'ok': True}`, the live file rewritten, and a fresh unlock
answering `bad-credential`.

**Nothing was weakened to get any of this green.** No test, ban, budget or
threshold was edited.

### Still open, deliberately

- `backends/kdbx.py` satisfies the new ban with its own private
  `_verify_own_output` rather than the shared policy. Both were measured and both
  hold; two implementations of one rule is nonetheless the shape that produced
  I41. Follow-up, `docs/RESIDUAL-RISK.md` §1.4.
- The ban is **static** — a backend that hid the write behind a helper method
  would pass it.
- The per-safe cap has never bitten on a real host: only three uids are in `sudo`
  here, so the per-principal backoff stops an identity-varying attacker at 3
  attempts, far short of 20.
- 20 / 60 s are a judgement, not a measurement. Nobody has attacked those numbers.
- I35, I36, I37 and I38 are unchanged and still open. So is everything in
  `docs/RESIDUAL-RISK.md` part 3 — no YubiKey, no foreign `.psafe3`, no
  KDBX 4 + AES-KDF, the agent has never run as root, real power loss untested.

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
