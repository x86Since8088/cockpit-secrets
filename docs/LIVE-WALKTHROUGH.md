# Driving the real plugin, in a real browser, against the live Cockpit

Every other test in this package stops short of the one thing an operator
actually does. `tests/integration/` drives `secrets-admin` and the helper does
not know the page exists. `tests/browser/ui.spec.js` drives the page and stubs
`cockpit.spawn` — its own README says the escalation path "is recorded but never
honoured". Between them sits the software as installed: Cockpit's bridge, the
Content-Security-Policy Cockpit really sends, `superuser: "require"` actually
being asked for and actually being refused, and a helper that re-derives who is
calling from the kernel.

This document is the record of driving that, on edt1, on 2026-09-04, and the
suite that does it lives in `tests/browser/`:

```
tests/browser/live-harness.js     login, navigation, CSP capture, artefacts
tests/browser/live-ui.spec.js     items 1-7 and 10
tests/browser/live-access.spec.js items 8 and 9
tests/browser/run-live.sh         the runner
tests/browser/artifacts/          screenshots and logs (git-ignored)
```

```
./tests/browser/run-live.sh
SECRETS_LIVE_HEADED=1 ./tests/browser/run-live.sh      # watch it happen
```

It needs a credentials **directory** — 0700, one 0600 file per name — because
I10 binds a test that checks I10 at least as tightly as it binds the helper:

```
<dir>/cptestadm.pass            the admin principal's Cockpit password
<dir>/cptest.pass               the non-admin principal's Cockpit password
<dir>/safe-<registry id>.pass   the master passphrase for that safe
```

Only the directory's path is ever in the environment. Nothing this suite runs
puts a password on a command line, and a credential it cannot read becomes a
NOT-ATTEMPTED naming the file it looked for — never a guess. Five wrong unlocks
lock a safe out (I16); a suite that guessed would leave the host worse than it
found it.

It never uses `sudo`, never submits a root job, and **never stops, starts or
reloads `cockpit.socket`.** Cockpit is a live system service on this host.

---

## The host, as measured

| | |
|---|---|
| Cockpit | 360-1 (`cockpit-ws`, `cockpit-bridge`), live at `https://localhost:9090` |
| Package | `/usr/share/cockpit/secrets`, installed 03:43 by the root task |
| Helper | `/usr/local/sbin/secrets-admin`, schema version 2, helper 1.0.0, 32 verbs |
| Principals | `cptestadm` (in `sudo`), `cptest` (uid 1005, **not** in `sudo`) |
| Browser | Playwright 1.62.1 chromium, headless, `ignoreHTTPSErrors` for the self-signed certificate and nothing else relaxed |

The policy the page ran under, read off the response headers for the package
page itself (`artifacts/01-csp-header.txt`):

```
default-src 'self'; connect-src wss://localhost:9090 'self'; form-action 'self';
base-uri 'self'; object-src 'none'; font-src 'self' data:; img-src 'self' data:;
block-all-mixed-content
```

No `unsafe-inline`, no `unsafe-eval`, no `wasm-unsafe-eval`. That is Cockpit's
default and this package adds nothing to it, which is what I9 asks for — and it
is why every rule and every line of code on the page is an external file.

---

## Results

| # | Item | Verdict |
|---|---|---|
| 1 | Loads under the real bridge, scripts run, zero CSP violations | **PASS** |
| 2 | Safe list: both classes, admin first, unreachable disabled with a reason | **PASS** (03:49 run) |
| 3 | Unlock end to end: wrong, right, entries, reveal, re-mask, copy, clear | **NOT-ATTEMPTED** |
| 4 | I11 — nothing left in the browser after an unlock | **NOT-ATTEMPTED** |
| 5 | Prompted every time: lock, then operate again | **NOT-ATTEMPTED** |
| 6 | Full management: add, edit, custom field, attach, download, history, save, reopen | **NOT-ATTEMPTED** |
| 7 | The conflict path is a decision, not an alert | **NOT-ATTEMPTED** |
| 8 | Non-admin refusal (I3), in the UI **and** from devtools | **PASS** |
| 9 | Escalation: Cockpit's own prompt, then the safe opens | **FAIL** → bug found and fixed; re-verification blocked |
| 10 | Accessibility: focus trap, 200% | **PARTIAL** — 200% PASS, keyboard half NOT-ATTEMPTED |

Everything marked NOT-ATTEMPTED has one cause, stated in full under
"[What is still not verified](#what-is-still-not-verified)". It is not a
shrug: it names the fixture that has to exist before those items can run.

**Read the verdicts above against `artifacts/run-0349-with-safes.log`, not
against the `live-*-result.json` files.** The registry on this host existed for
about six minutes: the root task seeded three throwaway safes at 03:45 and its
own `cs-90-cleanup` removed them at 03:50, twice over. Items 2 and 8 were driven
inside that window and passed there; every run after it re-listed an empty
registry and re-wrote the JSON with NOT-ATTEMPTED. The log is the record of the
run that had something to look at.

---

### 1 · The page loads under the real bridge · PASS

`artifacts/01-loaded.png`, `artifacts/01-console.log`, `artifacts/01-csp-header.txt`

```
PASS  secrets.js ran and the schema answered — #sec-sub reads "helper 1.0.0 · 32 verbs · reveal 15 s"
PASS  the footer carries 9 helper-published rules
PASS  secrets.css applied — the external stylesheet loaded under the real CSP
PASS  securitypolicyviolation events: 0
PASS  console CSP refusals: 0
PASS  page and console errors from the secrets package: 0
```

Both halves are load-bearing. `#sec-sub` reads `loading…` in the shipped
`index.html` and is only rewritten by `init()` after the `schema` verb answers,
so its contents prove the external script executed under the policy above AND
reached the helper through the bridge. The nine footer rules are rendered from
the schema, so a page whose `<script>` had been refused would show none.

CSP violations are counted twice over — from `securitypolicyviolation` events
collected in every frame, and from Chromium's console refusals — because one
detection path that quietly stopped working would read as a pass.

The console log records one error that is **not** this package's: Cockpit's own
shell probing `/cockpit/login` and getting a 401. It is reported as a note
against the shell rather than counted against the page.

### 2 · The safe list · PASS

`artifacts/02-safes-admin.png`, `artifacts/run-0349-with-safes.log`

Measured at 03:49, while the root task's throwaway registry was live (three
entries: two admin-class, one user-class):

```
....  class blocks in document order: ["Administrator safes","Your own safes"]
PASS  both access classes render, and Administrator safes comes first
PASS  “zz-throwaway-admin” shows its Unlock control disabled for cptestadm
PASS  the card states the reason: "this safe is administrator-class; turn on
      Cockpit's Administrative access and try again"
```

Admin first is not cosmetic: admin is the **default** access class (I1), and
the list reads in the order the registry defaults do.

The disabled card passed — and the reason it was disabled turned out to be the
bug in item 9. After the fix, the card that satisfies this half is the
user-class safe owned by somebody else (`this safe belongs to another user`),
which is a genuine refusal rather than an un-asked question.

### 3-7 · NOT-ATTEMPTED

No registered safe had a passphrase this suite could have. See
"[What is still not verified](#what-is-still-not-verified)".

### 8 · The non-admin refusal · PASS

`artifacts/08-nonadmin-list.png`, `artifacts/08-direct-calls.json`

The half that matters is the one that goes **around** the page. I3 exists
because a sibling project shipped an `if (t.admin && !isAdmin)` in JavaScript
and it was bypassable, so a refusal is only worth something if it survives
somebody opening devtools and calling `cockpit.spawn` themselves. That is
exactly what this does, from inside the plugin's own frame:

```
....  the page's bridge runs as: uid=1005(cptest) gid=1005(cptest)
      groups=1005(cptest),44(video),970(edy-rdp),990(render)
PASS  cptest is not in `sudo` — this is genuinely the non-admin principal
PASS  cockpit.spawn unlock WITHOUT escalation is refused
PASS  the helper answers "access-denied" — the refusal comes from the helper's
      own identity check (I3), not the page
PASS  the refusal is an operator sentence, not a traceback
PASS  cockpit.spawn unlock WITH superuser:"require" is refused too
      (channel problem: access-denied)
PASS  probe on the same safe is refused the same way, while `list` answered
      normally — the gate is the access class, not the helper being absent
PASS  a path in place of a registry id is refused ("invalid") — there is no
      verb that opens a path (I4)
```

Two independent gates, and it matters that both were seen. Cockpit's bridge
refuses `superuser: "require"` for an account that cannot escalate, before the
helper is reached at all; and the unescalated call reaches the helper, which
refuses on its own from `os.geteuid()`. The second is the one the design rests
on, because the first is a request and not a guarantee.

The `list` control is what makes the rest meaningful: the same principal, the
same bridge, a verb that answered normally a moment earlier. The refusal is
about the access class, not about anything being unreachable.

### 9 · Escalation · FAIL — and the bug it found

`artifacts/09-limited-access.png`

```
....  Cockpit's header reports: off
....  cockpit.permission({admin:true}).allowed === false
PASS  the page states the situation plainly instead of failing:
      "Administrative access is off in this Cockpit session, so admin-class
      safes cannot be opened yet. Turn it on with the “Administrative access”
      control in the Cockpit header — or just open one below and Cockpit will
      ask you for it."
PASS  it is a warning, not an error — nothing has failed yet
```

Then the run aborted, and the abort is the finding. The step is "open an admin
safe and let Cockpit ask" — and there was nothing on the card that could ask.
Playwright sat on a disabled control for thirty seconds:

```
locator resolved to <button disabled type="button" class="sec-btn primary"
  title="this safe is administrator-class; turn on Cockpit's Administrative
  access and try again">Unlock…</button>
- element is not enabled
```

**Root cause.** `secrets.js` called `list` deliberately without escalation —
correctly, because naming what exists is not opening anything. But
`v_list` in `secrets-admin` answers it by running the class gate against the
euid it actually has, and that gate raises for an `admin` entry whenever
`euid != 0`. So **every admin-class row comes back `usable:false` on every
list, for every caller, whatever Cockpit's administrative access is set to** —
an operator in `sudo` with escalation already on gets the identical row to a
stranger, because the process that asked was not root either way.

That is not a reading of the source, it is a measurement
(`artifacts/09-usable-is-euid.txt`). One hermetic registry with a single
admin-class entry, one helper binary, one request — the only variable is euid:

```
$ echo '{}' | COCKPIT_SECRETS_ETC=… secrets-admin list          # euid 1000 = eddie, who IS in `sudo`
  "usable": false,
  "reason": "this safe is administrator-class; turn on Cockpit's Administrative access and try again"

$ echo '{}' | unshare --map-root-user env COCKPIT_SECRETS_ETC=… secrets-admin list    # euid 0
  "usable": true,
  "reason": ""
```

An operator who is in the admin group gets `usable:false` — because the process
that asked was not root, which is the only thing the answer is about.

`safeReachable()` read that verdict as a refusal. Three consequences, and the
third is what makes it critical:

1. `Unlock…` was disabled on every admin-class safe, permanently.
2. `Check this safe` — the control whose entire purpose is to trigger
   Cockpit's prompt deliberately — was itself gated on `reachable`, so it was
   never drawn in the one situation it exists for.
3. Admin is the **default** access class (I1). A registry entry that omits
   `access` is admin. So the ordinary configuration of this program could not
   be opened from its own page at all, and the escalation banner's promise —
   "just open one below and Cockpit will ask you for it" — described something
   the page did not do.

**Fixed in `secrets.js`** (this is the whole of the change):

* `safeReachable()` no longer reads the list's verdict for an admin-class safe.
  It cannot: there is no state of the world in which an unescalated `list` says
  an admin safe is usable, so the answer carries no information. The escalated
  verb decides, and the helper re-checks the class inside it (I3) — a probe
  that comes back refused lands on the card as an error where an operator can
  see it.
* `Check this safe` is drawn whenever the safe is admin-class and this session
  has not escalated, with no reachability guard.
* The helper's sentence is now printed on **every** card that carries one, not
  only on unreachable ones. For an admin safe it is the instruction, and
  dropping it would leave an operator with an enabled button and no warning
  that Cockpit is about to ask for a password.
* `cockpit.permission`'s `changed` handler now probes the admin safes when
  access comes on. They are deliberately not probed while it is off — one
  Cockpit prompt per card on load is an interrogation, not a page — so this is
  the first moment they can be, and without it an operator who escalates from
  Cockpit's own header watches the cards stay blank until they think to press
  Refresh.

**Verified** against the same `index.html`/`secrets.js`/`secrets.css` under the
package's stub harness, with `cockpit.permission.allowed === false` and a
registry row shaped exactly as the live helper returns one:

```
PASS  the admin card is NOT marked unreachable just because we have not escalated
PASS  its Unlock control is ENABLED, so the escalation banner's promise is keepable
PASS  "Check this safe" is drawn — it used to be gated on reachability and so never appeared
PASS  the helper's own sentence is still on the card
PASS  a genuinely unreachable USER-class safe is still disabled with its reason
PASS  …and its Unlock control is still disabled
PASS  the escalation banner is shown while access is off
```

`tests/browser/ui.spec.js` still passes 134/134 with the change in.

**Not re-verified live**, and that is stated rather than glossed:
`/usr/share/cockpit/secrets/secrets.js` is root-owned, so the fixed file cannot
be installed by this task. The live host is still serving the pre-fix copy.
Re-running `run-live.sh` after the next `install.sh` is what closes item 9.

### 10 · Accessibility · PARTIAL

`artifacts/10-zoom-200.png`

```
PASS  no horizontal overflow at 200% (scrollWidth 700 vs clientWidth 700)
PASS  the topbar controls are still on screen at 200%
```

Browser zoom is a layout change, and the layout-equivalent of 200% at
1400×950 is a 700×475 CSS viewport, so that is what is emulated. The assertion
is the one that matters at any zoom and is the WCAG 1.4.10 failure when it does
not hold.

The keyboard half needs an unlock dialog to trap focus in, so it was not driven
live. `tests/browser/ui.spec.js` covers the same markup under the stub ("the
focus trap holds after 30 tabs", "Escape closes the dialog", "focus moves into
the dialog when it opens"), which is worth knowing and is **not** the same as
having been driven here.

---

## What is still not verified

**One missing fixture blocks items 3, 4, 5, 6, 7 and half of 10: there is no
registered safe whose passphrase an unprivileged operator can have.**

The root task's `cs-30-throwaway-safes` job builds exactly the right safes —
one admin-class, one read-only, one user-class owned by `cptest` — and then
generates their passphrase into `/run/cockpit-secrets-roottest/pw`, 0600 in a
0700 root-owned directory, destroyed by `cs-90-cleanup`. That is correct for
what it is for: those fixtures serve the helper-level suites, which run as root
through the job runner. A browser suite runs as the operator, in a browser, and
cannot read it. The safes were also removed again by the cleanup step, so by
the time the walkthrough re-ran the registry held nothing but the two
`*.json.example` files that `install.sh` seeds.

What would close it, and it is small: **one registry entry pointing at a
committed fixture whose passphrase is already published.**
`tests/fixtures/manifest.json` exists for this — its own header says "every
passphrase here is public on purpose; none of these safes holds a real
credential", and every fixture uses `fixture-pass-do-not-reuse`. Register one
of them as a **user-class** safe owned by the driving account:

```json
{ "id": "zz-live-user", "label": "THROWAWAY — live browser walkthrough",
  "format": "kdbx", "access": "user", "mode": "rw",
  "path": "/home/cptestadm/.local/share/cockpit-secrets/zz-live-user.kdbx",
  "owner": "cptestadm", "password_required": true }
```

and an admin-class entry beside it for items 8 and 9. Then

```
printf '%s' fixture-pass-do-not-reuse > "$SECRETS_LIVE_CREDS/safe-zz-live-user.pass"
chmod 600 "$SECRETS_LIVE_CREDS/safe-zz-live-user.pass"
./tests/browser/run-live.sh
```

runs all ten items. Nothing else about the suite changes: it discovers safes
from the live `list` and picks whichever one it has a passphrase for.

---

## Two other gaps, both in the helper rather than the page

Neither is a bug in `secrets.js`. The page renders what the schema declares,
which is the contract; in both cases the schema declares less than the backend
can do, so the capability exists and nothing can reach it. Reporting them
precisely is more useful than papering over them in the renderer, and inventing
data the helper did not send is exactly what this page must not do.

**A custom field cannot be created from the page.** `secrets-admin schema`
declares the `entry` and `changes` objects with sub-fields
`title, username, password, url, notes, tags, totp_uri, expires` — and no
custom-field control. The page therefore draws none. It does offer
"Reveal a custom field…", which READS one that already exists, so the asymmetry
is visible on screen: an operator can read a custom field and cannot make one.
The backend is not the limitation — `backends/kdbx.py:edit()` handles
`changes.custom` as `{name: {value, protected}}` and `None` deletes — so the
fix is to declare a `custom` sub-field on `entry` and `changes` in the helper's
field dictionary, after which the page draws it with no edit here.

**An attachment can be uploaded and not downloaded.** The `entries` row carries
`attachments` as a COUNT (`backends/kdbx.py:1796`, `len(entry.attachments)`;
`backends/base.py:1979` types it `int`, and docs/CONTRACT.md agrees), and the
helper publishes no verb that lists attachment names. `attach-get` takes a
name. So the page knows an entry has one attachment and cannot say which, and
it says so plainly — "Downloading one needs its name, and this helper publishes
no verb that lists them" — rather than guessing a filename. The backend already
computes the names: `backends/kdbx.py` `fields(uuid)` returns
`[{name, size}, …]`, and there is no `fields` verb in the schema. Publishing
that verb (or adding `attachment_names` to the `entries` row, which
`attachmentRows()` in `secrets.js` already reads) closes it with no page-side
change; `secrets.js` handles both shapes today.

---

## Two bugs in the suite itself, found by running it

Recorded because both are the kind that make a browser test lie quietly, and
the second one nearly did.

**Waiting for `#sec-safes` proved nothing.** That element is in the shipped
`index.html`, so it resolves before a single line of `secrets.js` has run.
Item 1 read `#sec-sub` as `loading…` and counted zero helper rules against a
page that was perfectly healthy a moment later — a false FAIL, which is the
better direction to fail in, but a false one all the same. `openPlugin()` now
waits for start-up to have SETTLED: either `#sec-sub` rewritten from the
schema, or the helper's error rendered into `#sec-safes`.

**Counting Cockpit's console as the page's.** A live shell logs a 401 from its
own `/cockpit/login` probe and an `ERR_ABORTED` for every iframe it swaps out.
Console traffic is now split by the URL it came from; the shell's is reported
as a note so it stays on the record without being counted against the page.

A third, caught before it ever ran live by exercising the suite's selectors
against the stub harness: `waitForSelector("#sec-clip[hidden]")` waits for a
hidden element to become *visible* and therefore waits for ever, and
`#sec-alerts` holds one alert at a time, so "wait until a `.sec-alert.ok`
exists" was satisfied instantly by the previous verb's result and read the
wrong sentence. Both are fixed; the save assertion now waits for the save's own
wording.

---

## Artefact index

`tests/browser/artifacts/` is git-ignored, and not only for tidiness: a
screenshot taken between "Reveal" and the countdown ending is a screenshot of a
password, and a live console log names this host's safes. The suite writes them
0600 for the same reason.

| File | What it shows |
|---|---|
| `01-loaded.png` | the page under Cockpit's shell, schema loaded, footer rules rendered |
| `01-console.log` | every console line of the run, with its source URL |
| `01-csp-header.txt` | the Content-Security-Policy Cockpit sent for the package page |
| `02-safes-admin.png` | the safe list as `cptestadm`, both access classes, admin first |
| `08-nonadmin-list.png` | the same registry as `cptest` |
| `08-direct-calls.json` | the four `cockpit.spawn` calls made around the UI, and the helper's answers |
| `09-limited-access.png` | the escalation banner with Cockpit's administrative access off |
| `09-usable-is-euid.txt` | the euid control: the same `list` answering `usable:false` at euid 1000 and `usable:true` at euid 0 |
| `10-zoom-200.png` | the page at the 200%-equivalent viewport |
| `run-0349-with-safes.log` | the full console of the 03:49 run, the one where the registry was live |
| `live-ui-result.json`, `live-access-result.json` | per-item verdicts, machine-readable — from the LAST run, against an empty registry |
| `probe-*.png` | both principals signed in to Cockpit, used to establish the login path before the package existed |
