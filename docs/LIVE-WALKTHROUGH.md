# Driving the real plugin, in a real browser, against the live Cockpit

Every other test in this package stops short of the one thing an operator
actually does. `tests/integration/` drives `secrets-admin` and the helper does
not know the page exists. `tests/browser/ui.spec.js` drives the page and stubs
`cockpit.spawn` — its own README says the escalation path "is recorded but never
honoured". Between them sits the software as installed: Cockpit's bridge, the
Content-Security-Policy Cockpit really sends, `superuser: "require"` actually
being asked for and actually being refused, and a helper that re-derives who is
calling from the kernel.

This document is the record of driving that, on edt1, on **2026-09-04**, and the
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

## The result

    ./tests/browser/run-live.sh   ->  exit 0
    live-ui      108/108 checks held   items 1, 2, 3, 4, 5, 6, 7, 10
    live-access   22/22  checks held   items 8, 9
    140 PASS, 0 FAIL, 0 NOT-ATTEMPTED

> **RE-RUN, 2026-09-04, after the close-out pass.** Same host, same installed package
> (`secrets.js` sha256 `7f03c81c…`, byte-identical — no browser-side code changed), rebuilt
> subjects, exit 0:
>
>     live-ui      109/109 checks held   items 1, 2, 3, 4, 5, 6, 7, 10
>     live-access   22/22  checks held   items 8, 9
>     131 checks held, 0 FAIL, 0 NOT-ATTEMPTED
>
> The check count moved because **item 4's I11 assertion was rewritten**, not because the page
> did. The version of item 4 that produced the 108 above treated *a key whose value changed
> length* as *a key this page added* — and Cockpit's own shell rewrites
> `sessionStorage["cockpit:page_status"]` while a run is in flight, so the assertion was a false
> statement that happened to be passing (KNOWN_ISSUES **I42**). It now asks, inside the page,
> whether a key's value contains the passphrase, a revealed password, the safe's id or this
> package's name, and returns a boolean; a named list of exactly one host-shell key
> (`cockpit:page_status`) may change LENGTH and nothing is ever exempt from the content probe.
> That is strictly stronger: the old check both fired on the shell's own key **and** would have
> missed a same-length overwrite with the passphrase.
>
> The same transition happened again during the re-run and now appears as the note it is:
>
>     ....  host-shell keys that changed and were tolerated by name:
>           ["session.cockpit:page_status 235 -> 223"]  (tolerated list: ["cockpit:page_status"])
>     PASS  the unlock added NOTHING to either storage area and wrote nothing of ours into
>           a key that was already there
>     PASS  no storage value in either area contains the passphrase, a revealed password,
>           the safe's id or this package's name — the tolerated keys included ([])
>
> `tests/browser/storage-check.selftest.js` pins that logic without needing a browser and runs in
> `run_tests.sh`, so the one negative assertion in this suite now has a guard that runs
> everywhere. The subjects were rebuilt from the committed fixtures for the re-run and destroyed
> again afterwards.

**All ten items pass.** Six of them had never run at all before this round —
items 3, 4, 5, 6, 7 and the keyboard half of 10 — and item 9 had run once and
failed. Getting there took one fix in `secrets.js` (the page promised an
escalation prompt that Cockpit does not raise) and seven fixes in the suite
itself, every one of which was a test asserting something that could not be
true. Both lists are below, with what was measured.

| # | Item | Verdict |
|---|---|---|
| 1 | Loads under the real bridge, scripts run, zero CSP violations | **PASS** |
| 2 | Safe list: both classes, admin first, unreachable disabled with a reason | **PASS** |
| 3 | Unlock end to end: wrong, right, entries, reveal, re-mask, copy, clear | **PASS** |
| 4 | I11 — nothing left in the browser after an unlock | **PASS** |
| 5 | Prompted every time: after a lock, after a reload, in a fresh tab | **PASS** |
| 6 | Full management, **both formats**: add, edit, custom field, attach, list, download, history, save, reopen | **PASS** |
| 7 | The conflict path is a decision, not an alert | **PASS** |
| 8 | Non-admin refusal (I3), in the UI **and** from devtools | **PASS** |
| 9 | Escalation: refused with no prompt while off, opens after Cockpit's own control grants it | **PASS** |
| 10 | Accessibility: focus trap, focus restore, keyboard-only unlock, 200% | **PASS** |

The record is `artifacts/run-0518-full-pass.log` — one run, start to finish, with
the registry live and every credential present.

---

## The host, as measured

| | |
|---|---|
| Cockpit | 360 (`cockpit-ws`, `cockpit-bridge`), live at `https://localhost:9090` |
| Package | `/usr/share/cockpit/secrets`, reinstalled 04:57 from the source tree; `secrets.js` sha256 `7f03c81c…` on the host **and** in the tree |
| Helper | `/usr/local/sbin/secrets-admin`, schema version 2, helper 1.0.0, **33 verbs** |
| Principals | `cptestadm` (uid 1007, in `sudo`), `cptest` (uid 1005, **not** in `sudo`) |
| Browser | Playwright 1.62.1 chromium, headless, `ignoreHTTPSErrors` for the self-signed certificate and nothing else relaxed |
| node | v22.22.1 |

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

### The fixture that made this possible

The previous round could not run items 3-7 for one reason: **no registered safe
had a passphrase an unprivileged operator could have.** The root suite's
throwaway safes generate their passphrase into a root-only tmpfs file and delete
the safes afterwards, which is right for the helper-level suites and useless to a
browser running as the operator.

This round registered three safes built from the **committed** fixtures, whose
passphrase (`fixture-pass-do-not-reuse`) is published in
`tests/fixtures/manifest.json` on purpose — that is what a fixture is for:

| Registry id | Class | Format | File | Owner / mode |
|---|---|---|---|---|
| `zz-throwaway-admin-kdbx` | admin | KDBX 4.1, AES-256/Argon2id | `/etc/cockpit-secrets/safes/zz-throwaway-admin-kdbx.kdbx` | `root:root` 0600 |
| `zz-throwaway-user-kdbx` | user | KDBX 4.0, AES-256/Argon2d | `/home/cptestadm/.local/share/cockpit-secrets/zz-throwaway-user-kdbx.kdbx` | `cptestadm` 0600 |
| `zz-throwaway-user-pws3` | user | Password Safe v3, Twofish-CBC | `/home/cptestadm/.local/share/cockpit-secrets/zz-throwaway-user-pws3.psafe3` | `cptestadm` 0600 |

Both classes and both formats, so item 6 could cover the parts of the program
that only exist in one of them. All three, and their registry entries, were
removed afterwards — see [What remains on the host](#what-remains-on-the-host).

### Running this again

The safes are gone, so a re-run has to recreate them. Two steps, and only the
first needs root:

**1 · Seed the safes and the registry** (through `/srv/jobs`; it never prints a
passphrase, and it must not):

```bash
FIX=<source>/tests/fixtures
install -d -o cptestadm -g cptestadm -m 0700 /home/cptestadm/.local/share/cockpit-secrets
install -o root      -g root      -m 0600 "$FIX/lab-kdbx41-aes256-argon2id.kdbx" \
        /etc/cockpit-secrets/safes/zz-throwaway-admin-kdbx.kdbx
install -o cptestadm -g cptestadm -m 0600 "$FIX/lab-kdbx40-aes256-argon2d.kdbx" \
        /home/cptestadm/.local/share/cockpit-secrets/zz-throwaway-user-kdbx.kdbx
install -o cptestadm -g cptestadm -m 0600 "$FIX/lab-pws3.psafe3" \
        /home/cptestadm/.local/share/cockpit-secrets/zz-throwaway-user-pws3.psafe3
```

then one 0644 root:root file per safe in `/etc/cockpit-secrets/safes.d/`, shaped
like `etcdefaults/*.json.example` — `access: "admin"` with `groups: ["sudo"]` for
the first, `access: "user"` with `owner: "cptestadm"` for the other two, all
`mode: "rw"`. Check it landed with `secrets-admin health`: `registry_errors` must
be empty.

The **ownership and the mode are load-bearing**, not tidiness. A user-class safe
the helper opens through `open_safe_fd` must be owned by the caller and carry no
group or other permission bits at all, and no ancestor directory may be
group/other-writable — get any of that wrong and every unlock is a correct
`access-denied` that reads like a bug.

**2 · The credentials directory**, as the driving account, no root:

```bash
CRED="${XDG_RUNTIME_DIR}/cockpit-secrets-live"
mkdir -p "$CRED" && chmod 700 "$CRED"
# the fixture passphrase is PUBLISHED in tests/fixtures/manifest.json on purpose;
# read it from there rather than typing it, and never put it on a command line
umask 077
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["fixtures"][0]["password"],end="")' \
        <source>/tests/fixtures/manifest.json > "$CRED/safe-zz-throwaway-user-kdbx.pass"
# …and the same for the other two ids, plus cptestadm.pass and cptest.pass
./tests/browser/run-live.sh
```

**Reset between runs.** This suite adds entries (item 6 adds one per format,
item 7 adds two more) and they persist, because the whole point of item 6 is that
they do. A second run is still valid — item 3 now chooses an entry that has a
password rather than taking the first row — but re-copying the three fixture
files back over the safes, and removing their `*.bak.d` backup rings, is what
makes a run start from the same place as this one did.

---

## The one page bug this round found

### Item 9 · the page promised an escalation prompt that Cockpit does not raise

The previous round left item 9 as FAIL with a fix that had never reached the
host. The fix was right as far as it went — an admin-class card must not be
permanently disabled because an unescalated `list` says `usable:false` — and
with it installed, item 9 got further and then failed on something else:

```
PASS  the card offers “Check this safe”
FAIL  Cockpit's escalation prompt did not appear within 30 s
```

`artifacts/09-refused-without-prompt.png` from the run before the fix shows what
happened instead: the card carried

> Administrative access is required and was not granted (access-denied).

**Measured, not inferred.** On Cockpit 360, a channel opened with
`superuser: "require"` from a session in limited access is refused immediately
and **no dialog is drawn anywhere.** Cockpit's escalation dialog belongs to the
shell: it is the component behind the header control, it calls
`cockpit.Superuser.Start()` itself and registers its `Prompt` listener around
that one call. Nothing a package page can reach makes it appear — the `superuser`
module the shipped Cockpit pages import is read-only (`allowed`, `configured`,
`reload_page_on_change`; verified in the installed `storaged` and `shell`
bundles), and a page that called `Start()` on its own would receive the Prompt
signal in its own frame and have to draw Cockpit's password dialog itself, which
is the one thing this program must never do.

So the bug was not that escalation was broken. It was that **the page said
something untrue about it**, in four places, and left an operator with a refusal
code and no route out of it:

* the escalation banner: *"— or just open one below and Cockpit will ask you for it"*;
* the access-denied message: the bare problem code, with no instruction;
* the "Administrator safes" class note: *"Cockpit asks for administrative access"*;
* the unlock dialog's intro: *"Cockpit will ask for administrative access if it is not already on"*.

**Fixed in `secrets.js`.** All four now name the control that really escalates —
Cockpit's own "Limited access" header control — and say plainly that opening an
admin safe while access is off is refused straight away, without a prompt, and
that nothing was sent. "Check this safe" is kept and reframed: it opens nothing
and asks for nothing, it reports what the helper says at the current privilege
level, and its `title` says which of the two it is doing. The section header in
`secrets.js` carries the measurement so the next reader does not re-derive it.

**Re-verified live**, and the whole of item 9 now runs end to end:

```
PASS  the admin-class card offers a “Check this safe” control while access is off
PASS  …and Unlock is NOT permanently disabled
PASS  asking for an admin-class safe while access is off produces an answer on the card
PASS  the answer is the bridge's refusal, delivered without any prompt
PASS  …and it names the control that DOES escalate
PASS  the page drew no password prompt of its own in response (0 password inputs in its frame)
PASS  Cockpit's header carries the “Limited access” control the page points at
PASS  Cockpit's own administrative prompt appeared in the SHELL, not in the plugin frame
PASS  administrative access is now on (cockpit.permission.allowed === true)
PASS  the page's escalation banner is gone now that there is nothing to warn about
PASS  with administrative access on, the ADMIN-CLASS safe opens through the page
PASS  …and its entries render — 6 row(s) out of a root-owned file that this
      account cannot read without escalating
```

`artifacts/09-escalation-prompt.png` is Cockpit's own "Switch to administrative
access" dialog — drawn by the shell, outside the plugin's frame, which is the
assertion. `artifacts/09-escalated.png` is the admin safe open afterwards.

---

## Seven bugs in the suite, every one of them a false statement

These matter as much as the page bug: each was a test that could not pass, or
one that passed without checking anything. They are recorded because a test that
lies is worse than no test.

**1 · Counting cards before the list arrived.** `openPlugin()` waits for the
SCHEMA to land; the safe list is a different verb answered by a different helper
process. Item 2 read *"cptest sees 0 safe(s) rendered unreachable"* off a page
still showing "Loading the safe registry…" (`02-safes-nonadmin.png` from that
run is the "Loading…" state). New `waitForSafeList()` waits for cards, an
explicit empty-registry line, or an error — all three are answers; "Loading…" is
not. Used in items 2 and 8. This is the same class of bug as the `#sec-safes`
one this document already recorded, in a second place.

**2 · The suite's own wrong passphrase locked out its right one (I16).** Item 3
makes exactly one wrong attempt on purpose. `lockout_fail()` then writes
`locked_until = now + 2 s`, so the correct passphrase typed a second later comes
back `locked-out` — which is the program working. The suite waited 120 s for a
browse view that was never coming and reported the walkthrough as aborted.
`unlockAndWaitOutBackoff()` now reads the wait out of the helper's **own**
sentence ("try again in N seconds") rather than copying a constant out of
`secrets-admin`, retries within a bounded budget, and returns any other refusal
immediately — a wrong passphrase must never be retried.

**3 · Add and Edit were clicking "Remove".** `runButton()` took the first
`.primary, .danger` button in the dialog. The custom-field row editor put a
`danger tiny` **Remove** button in the form above the action row, so from the
moment `custom` was published every Add and every Edit in this suite removed a
row instead: the dialog stayed open, nothing errored because nothing had gone
wrong, and thirty seconds later the assertion failed as "the entry never
appeared in the listing". Found with a probe that dumped the modal's buttons
before and after the click — three Show/Generate pairs before, two after, and no
Remove. `runButton()` now looks in `.sec-form-actions`, where `actionRow()` puts
the dialog's own buttons.

**4 · `localStorage.length === 0` is not a statement this page can make.** A
Cockpit package page is an iframe on the **same origin** as the shell, so the
web-storage areas are shared and Cockpit itself uses them. Measured, identical
from the frame and from the shell page, and present before this package is ever
opened:

```
local   ["superuser:cptestadm", "superuser-key", "standard-login"]
session ["cockpit:page_status", "cockpit:v2-machines.json"]
```

Item 4 asserted zero and failed on a page that had written nothing. What I11
actually says is that **this page** writes nothing there, so the check is now a
difference: a baseline is taken before any safe is opened, and the assertion is
that the unlock added no key and changed no value. It also asserts that no key
name belongs to this package and that no key or value anywhere holds the
passphrase. Item 5's reload and fresh-tab checks were rewritten the same way.

**5 · An assertion about attachments that read the whole detail pane.** Item 6
tested `/Attachments/ && !/^\s*None\.\s*$/m` against `#sec-detail.innerText`,
which matches a "None." belonging to any section. New
`attachmentsSectionText()` reads the run between the Attachments `<h4>` and the
next one, and the assertion is made twice: the section exists after the upload,
and once the listing has settled it does not read "None." for an entry that has
one.

**6 · The focus trap was never walked.** `locator.press()` **focuses** its
element before sending the key, so `.sec-modal.press("Tab")` put focus on the
dialog container every time and tabbed once from there. Forwards that looked
like a pass and checked nothing; backwards it was a FAIL, because Shift+Tab from
the container (`tabindex -1`, so not the `first` the handler compares against)
legitimately steps out — the assertion was asking the trap to catch a case it
does not exist for. Item 10 now focuses the first control and uses
`page.keyboard`, which is what a person pressing Tab does, and additionally
asserts that Shift+Tab lands on the **last** control, which is what makes the
trap a loop rather than a wall.

**7 · Revealing an entry that had no password.** Item 3 revealed the first row
in the listing. This suite ADDS entries — item 6 adds one per format, item 7 adds
two more with a title and nothing else, because a title is all a conflict needs
— and sorted into the listing those come first. On a second run item 3 read
*"Reveal shows a value (0 characters)"*: a true statement about that entry and a
useless test of the control. The entry is now chosen — walk the listing until one
has a password to show, and say so if none does.

---

## The items, and what each one measured

### 1 · The page loads under the real bridge · PASS

`artifacts/01-loaded.png`, `01-console.log`, `01-csp-header.txt`

```
PASS  secrets.js ran and the schema answered — #sec-sub reads "helper 1.0.0 · 33 verbs · reveal 15 s"
PASS  the footer carries 9 helper-published rules
PASS  secrets.css applied — the external stylesheet loaded under the real CSP
PASS  securitypolicyviolation events: 0
PASS  console CSP refusals: 0
PASS  page and console errors from the secrets package: 0
```

`#sec-sub` reads `loading…` in the shipped `index.html` and is only rewritten by
`init()` after the `schema` verb answers, so its contents prove the external
script executed under the policy above AND reached the helper through the
bridge. CSP violations are counted twice over — from `securitypolicyviolation`
events collected in every frame, and from Chromium's console refusals — because
one detection path that quietly stopped working would read as a pass.

The console log records one error that is **not** this package's: Cockpit's own
shell probing `/cockpit/login` and getting a 401. It is reported as a note
against the shell rather than counted against the page.

### 2 · The safe list · PASS

`artifacts/02-safes-admin.png`, `02-safes-nonadmin.png`

```
....  the registry offers 3 safe(s) to cptestadm
....  class blocks in document order: ["Administrator safes","Your own safes"]
PASS  both access classes render, and Administrator safes comes first
....  every registered safe is reachable by cptestadm (it is in `sudo`), so the
      disabled card is checked as cptest
PASS  cptest sees 2 safe(s) rendered unreachable
PASS  “zz-throwaway-user-kdbx” shows its Unlock control disabled for cptest
PASS  the card states the reason: "this safe belongs to another user"
```

Admin first is not cosmetic: admin is the **default** access class (I1), and the
list reads in the order the registry defaults do.

The disabled card is now a *genuine* refusal rather than an un-asked question:
a user-class safe owned by somebody else. That is the right case for this
assertion, and it is the case the escalation fix left standing — an admin-class
card is deliberately NOT disabled, because a session can escalate at any moment.

### 3 · Unlock end to end · PASS

`artifacts/03-unlock-prompt.png`, `03-bad-credential.png`, `03-entries.png`,
`03-revealed.png`, `03-remasked.png`, `03-copied.png`

```
PASS  the unlock prompt appears with a passphrase control
PASS  the passphrase control is autocomplete=off with no name attribute —
      {"autocomplete":"off","spellcheck":"false","name":null,"form":"no form"}
PASS  a wrong passphrase answers with the coarse code "bad-credential"
PASS  the detail is an operator sentence, not a traceback:
      "the passphrase, key file or file integrity check did not match this safe"
....  the helper is in its I16 backoff — waiting it out and trying again
....  waited 2 s of I16 backoff, armed by this item's own single wrong attempt
PASS  the correct passphrase unlocks and the browse view opens
PASS  entries render — 6 row(s)
PASS  the detail pane offers a Password reveal control and an entry with a
      password was found within the first 6 row(s)
PASS  Reveal shows a value (15 characters)
PASS  a countdown is running: "hides in 15 s"
PASS  the value re-masks when the countdown ends
PASS  the revealed value is GONE from the DOM, not merely hidden
PASS  Copy put the value on the clipboard
PASS  a clipboard countdown is shown: "clipboard clears in 15 s"
PASS  the clipboard no longer holds the value (it now reads "")
```

**One wrong passphrase, ever.** The lockout threshold is five (I16). The
assertion is about the WORDING of the refusal and one attempt shows it; the
suite then waits the backoff out rather than hammering the failure path.

"Re-masked" is checked as *gone from the DOM*, not merely hidden behind a CSS
rule (I17): `document.documentElement.innerHTML` is searched for the value that
was on screen a moment earlier.

### 4 · I11 — nothing is left in the browser · PASS

`artifacts/04-storage.png`

```
....  storage in the plugin frame: local ["superuser:cptestadm","superuser-key","standard-login"],
      session ["cockpit:page_status","cockpit:v2-machines.json"]
....  storage in Cockpit's shell page: (identical)
PASS  the plugin frame's storage IS Cockpit's — same origin, same keys
PASS  the unlock added NOTHING to either storage area ([] local, [] session,
      against the baseline taken before any safe was opened)
PASS  no storage key belongs to this package ([])
PASS  the plugin frame opened no IndexedDB database ([])
PASS  the passphrase string appears nowhere in the plugin frame's DOM
PASS  the passphrase is in neither storage area
PASS  the passphrase is in no cookie
PASS  no live input or textarea still holds the passphrase
PASS  every password input currently on the page reads empty
PASS  the passphrase is absent from Cockpit's shell page too — same origin, same risk
PASS  the now-detached passphrase input was WIPED, not just removed
```

The last one is the check that catches a "we removed the visible one"
regression: the element handle for the box the operator typed into is kept from
before the unlock, and its `.value` is read after it has been detached from the
document. `form.wipeSecrets()` blanks it before the request leaves, so a
detached node cannot be mined for it either.

The suite reads key **names and value lengths** only, never values — a helper
written for an I11 test that returned the values would put every one of them
into the suite's own memory and into any artefact that printed it.

### 5 · Prompted EVERY time · PASS

`artifacts/05-locked.png`, `05-prompted-again.png`, `05-prompted-after-reload.png`,
`05-prompted-fresh-tab.png`, `05-handle-replay.json`

**This is the central promise of the program and it had never been checked in a
browser.** It is now checked four ways.

```
PASS  Lock returns the page to the safe list
PASS  the next operation on that safe demands the passphrase again
PASS  the passphrase box comes up EMPTY — nothing was remembered

PASS  a handle from a previous helper process is refused by the next one
PASS  the helper answers "access-denied" for a handle that is no longer live

PASS  after a full page reload the safe is LOCKED again — the browse view is gone
PASS  the first operation after a reload demands the passphrase again
PASS  …and its box is EMPTY: a reload cannot restore what was never kept
PASS  nothing was carried across the reload — no storage key appeared or changed
      since before the first unlock, and the passphrase is not in either area
      or in any cookie

PASS  a fresh tab in the same Cockpit session opens on the safe list, not into a safe
PASS  the fresh tab demands the passphrase for the same safe
PASS  …and its box is EMPTY too — the first tab's unlock bought it nothing
PASS  the fresh tab sees no key this session added and neither its storage nor
      its DOM holds the passphrase
```

Three of those are different claims. The **lock** is a decision this page makes.
The **reload** is not: the whole of `secrets.js` is thrown away and rebuilt from
the file Cockpit serves, so anything that survived it survived in the *browser*,
which is the only place I11 says nothing may survive. The reload is deliberately
done from a safe that was left UNLOCKED, or it proves nothing — a page already
on the safe list would look identical. The **fresh tab** shares the origin and
the session cookie, so it genuinely could have read anything the first tab left
in `localStorage`; it found nothing to read.

The **handle replay** is the same claim made where it cannot be a rendering
choice. The page keeps its handle inside one closure, so there is nothing to
read out of it — which is itself the design. The equivalent statement is made
against the helper: mint a handle in one single-shot spawn, present it in a
second one, and watch it be refused. The default configuration is one helper
process per verb, so the handle died with the process that minted it, and
"prompted every time" is a property of the architecture and not a policy the
page applies. That is the same door an attacker would try from devtools.

### 6 · Full management, both formats · PASS

KDBX 4.0 (`zz-throwaway-user-kdbx`) and Password Safe v3
(`zz-throwaway-user-pws3`), the whole sequence against each.
`artifacts/06-kdbx-*.png`, `06-psafe3-*.png`.

Driving one format and reporting "management works" would be a claim about half
the program: a KDBX entry is a bag of named strings and a PWS3 record is a list
of TYPED fields, and the difference is visible in exactly the two capabilities
that arrived this round.

```
                                                       kdbx     psafe3
add an entry                                           PASS     PASS
edit it, and the change reads back from the helper     PASS     PASS
the dialog offers a control that CREATES a custom field PASS    PASS
control:"json" is drawn as a ROW EDITOR, not a textarea PASS    PASS
the custom field is written through the page           PASS       —
reveal field="custom:<name>" reads back what was written PASS     —
PWS3 refuses a custom field with `unsupported`            —     PASS
…and the refusal is the FORMAT's reason                   —     PASS
attachment upload accepted                             PASS     PASS
attach-list turns the count into a NAME, unprompted    PASS     PASS
the listed name is the one just uploaded               PASS     PASS
a “List attachments” control re-asks a stale list      PASS     PASS
that row offers Download                               PASS     PASS
downloaded through the Cockpit channel byte for byte   PASS     PASS
history                                                PASS     PASS
save, with the backup named (I12)                      PASS     PASS
lock, re-unlock, the entry persisted                   PASS     PASS
the attachment survived the save and is listed again   PASS     PASS
```

**The custom field.** The helper declares `custom` on `entry` and `changes` as a
keyed map — `control: "json"`, `type: "object"`, a separate `key` descriptor and
element `fields` — and `secrets.js` promotes that shape to a repeating row
editor rather than handing the operator a JSON textarea. Measured:

```
....  the custom-field control is a “Custom fields” row editor with 1 empty row(s)
      and a “Add a field” control — not a raw JSON textarea (no textarea)
```

The value is then read back through the only door that exists for it — `reveal`
with `field="custom:<name>"`, with its countdown and its audit line — not
through the bridge:

```
PASS  reveal with field="custom:walkthrough token" reads back exactly what the
      page wrote (20 characters)
```

**And PWS3 refuses it, correctly.** The descriptor is shared, so the control is
drawn for both formats and the FORMAT is what refuses:

```
PASS  Password Safe v3 refuses a custom field with `unsupported`, not with a
      wrong-field error: "unsupported"
PASS  …and the refusal is the FORMAT's reason, so an operator can tell it from a bug:
      "Password Safe v3 records carry typed fields, not named custom fields;
       there is nowhere to create this one. Use the notes field, or keep this
       entry in [a KDBX safe]"
```

**The attachment round trip closes the gap this document last recorded.** An
`entries` row sends `attachments` as a COUNT (measured directly against a
fixture: `attachments=2` for the Router entry, `0` for the rest) and
`attach-get` takes a NAME. The helper now publishes `attach-list`, and the page
asks it automatically the first time an entry with a bare count is drawn — so
the Download control appears with no operator action and no guessed filename.
The whole chain is asserted: count → `attach-list` → a name a person can see →
`attach-get` → the bytes in the browser, compared byte for byte against what was
uploaded (47 bytes for KDBX, 49 for PWS3).

**History differs by format, and the page says which.** KDBX listed three
previous versions after the edit and no row carried a password value. PWS3
listed none, and the assertion is that the page says so — *"No previous versions
are recorded for this entry"* — rather than showing an empty panel.

**Save named its backup**, which is I12's whole point:

```
PASS  Save wrote the safe: "Saved — 4501 bytes, previous copy kept at
      …/zz-throwaway-user-kdbx.kdbx.bak.d/zz-throwaway-user-kdbx.kdbx.20260904T101803.981334.1439054.bak."
PASS  the save names the backup it took before the first new byte existed (I12)
```

### 7 · The conflict path · PASS

`artifacts/07-session-b-saved.png`, `07-conflict.png`

Two Cockpit sessions racing each other, which is the real lost-update this
hazard is about (I13) — not a shell writing the file behind the helper's back.
Session A holds an unsaved entry; session B adds one and saves; A then saves.

```
....  session A holds an unsaved entry: conflict-A-…
PASS  session B's save landed
....  session B saved conflict-B-…, so the file on disk changed under A
PASS  the save was refused and the page opened a decision dialog
PASS  the dialog offers “Discard mine and reload”
PASS  the dialog offers “Keep my changes here”
PASS  the dialog offers a save-as route as well:
      ["Discard mine and reload","Save a copy","Keep my changes here"]
PASS  the dialog states that nothing was written
PASS  the dialog states that it refuses rather than merging
PASS  Escape does not dismiss it — a conflict is a decision the operator has to make
PASS  “Discard mine and reload” locks the safe so it can be re-read — and
      re-reading it means being asked for the passphrase again
```

Three named ways forward, an explanation that nothing was written, and no escape
hatch that would dismiss it by accident. The dialog is built with `noEscape` for
exactly that reason, and the Escape assertion is what holds it to it.

### 8 · The non-admin refusal · PASS

`artifacts/08-nonadmin-list.png`, `08-direct-calls.json`

The half that matters is the one that goes **around** the page. I3 exists
because a sibling project shipped an `if (t.admin && !isAdmin)` in JavaScript
and it was bypassable, so a refusal is only worth something if it survives
somebody opening devtools and calling `cockpit.spawn` themselves.

```
....  the page's bridge runs as: uid=1005(cptest) gid=1005(cptest) groups=…
PASS  cptest is not in `sudo` — this is genuinely the non-admin principal
PASS  the card tells the operator what stands in the way
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
same bridge, a verb that answered normally a moment earlier.

### 9 · Escalation · PASS

Covered in full under [the one page bug this round
found](#item-9--the-page-promised-an-escalation-prompt-that-cockpit-does-not-raise).

### 10 · Accessibility · PASS

`artifacts/10-zoom-200.png`, `10-keyboard-unlock.png`

```
PASS  no horizontal overflow at 200% (scrollWidth 700 vs clientWidth 700)
PASS  the topbar controls are still on screen at 200%
PASS  opening the dialog moves focus into it
PASS  Tab pressed 10 times from the first control never leaves the dialog — it
      wrapped instead (focus walked
      ["BUTTON:button","INPUT:file","INPUT:file","INPUT:number","BUTTON:button","BUTTON:button"]…)
PASS  Shift+Tab from the first control stays inside the dialog (landed on BUTTON:button)
PASS  …and it wrapped to the LAST control, which is what makes the trap a loop
      rather than a wall
PASS  Enter in the passphrase box submits the unlock — no pointer needed
PASS  Escape closes an ordinary dialog
PASS  closing the dialog puts focus back on the control that opened it
      (BUTTON “Generate password…”)
```

Browser zoom is a layout change, and the layout-equivalent of 200% at 1400×950
is a 700×475 CSS viewport, so that is what is emulated. The no-horizontal-scroll
assertion is the one that matters at any zoom and is the WCAG 1.4.10 failure
when it does not hold.

The keyboard half is new here and had never run live. The **focus restore** check
is new to the suite entirely: `modal()` remembers what was focused when it
opened and focuses it again on close, and without that, dismissing a dialog
drops a keyboard user at the top of the document with no idea where they were —
a WCAG 2.4.3 failure invisible to any test that only checks that the dialog went
away. The whole unlock in this item is done without touching the mouse.

---

## What is still not verified

Stated, not implied by silence.

**A real YubiKey.** No token has ever answered a challenge. `yubikey_slot` is
null on all three throwaway safes, so nothing here exercised the
challenge-response path; the arithmetic has unit vectors and that is all.

**A key file, live.** `tests/fixtures/` ships a password-and-keyfile safe and a
keyfile-only safe, and neither was registered. The unlock dialog's key-file
control was rendered (it is unconditional) but no key file was ever sent through
it in a browser.

**The agent (I18).** `agent.enabled` is false on all three entries and the agent
was never installed on this host (`install.sh --with-agent` has still never been
run at real root — `docs/ROOT-VERIFICATION.md` says so and it is still true), so
the agent banner and its countdown were never driven live.

**Export.** `export_allowed` is false on all three entries, so the export dialog
and its plaintext confirmation were not exercised in a browser. The verb itself
is covered at the helper level, and `docs/OPERATIONS.md` §8 records a real
export driven end to end through the helper.

**A second admin principal.** Item 9 escalated as `cptestadm`. `cpadmin` exists
and was not used, so "two admins cannot see each other's session" was not
checked here.

**Read-only mode.** All three entries are `rw`. A `mode: "ro"` safe's refusal of
the mutation verbs was not driven through the page; item 6 has the branch for it
and it was never taken.

**Browsers other than Chromium.** One engine, headless.

---

## One doc/implementation divergence, in a file this task did not own

`docs/CONTRACT.md` line 176 still declares

```
secrets-admin export     <stdin:{safe, credentials, fmt, confirm}>
```

The live schema does not. Measured from `secrets-admin schema` on the installed
helper:

```
export request: ['safe', 'password', 'keyfile_b64', 'yubikey_response',
                 'session', 'fmt', 'confirm']
```

There is no `credentials` field. CONTRACT.md's own preamble says the schema is
what the page reads and that a disagreement is a bug in that file, so the line
should be corrected there. This was reported in the previous round and is still
open; it is recorded here so it does not fall off the list again.

---

## What remains on the host

**The package is installed and left installed**, from the tree that produced
this document:

```
/usr/local/sbin/secrets-admin                 0755 root:root
/usr/share/cockpit/secrets/{index.html,manifest.json,secrets.js,secrets.css}
                                              0644 root:root
/usr/local/lib/cockpit-secrets/backends/*.py  0644 root:root
/usr/local/lib/cockpit-secrets/schema/*.json  0644 root:root
```

`secrets.js` on the host is byte-identical to the source copy —
sha256 `7f03c81c8919baf3260229a17c13e452707c0ec866fa9ecc2e4c397d1082db08` for
both, checked by the install job and again afterwards. That check is the point:
the previous round's escalation fix never reached the host, which is exactly how
item 9 came to be re-verified against the code it was fixing.

There is **no bytecode** anywhere under `/usr/local/lib/cockpit-secrets` — no
`__pycache__`, no `.pyc` — after the install and after the helper has been run
many times since.

**The three throwaway safes and their registry entries are gone**, together with
their backup rings and lockout counters. The registry holds only the two seeded
`*.json.example` files, which the registry's `*.json` glob does not match, so it
declares no safes.

The data locations `install.sh --uninstall` would keep are kept and empty of
anything this round created: `/etc/cockpit-secrets` (0755), `safes.d` (0755),
`safes` (0700, empty), `/var/log/cockpit-secrets` (0700, holding the audit log),
`/var/lib/cockpit-secrets/state` (0700, empty), `/var/lib/cockpit-secrets/exports`
(0700, **empty** — that directory is plaintext-bearing and was checked
deliberately, see `docs/OPERATIONS.md`).

**Two audit logs are deliberately KEPT.** The root one at
`/var/log/cockpit-secrets/audit.log`, and the user-class helper's own at
`/home/cptestadm/.local/state/cockpit-secrets/audit.log` — 510 lines, 0600,
327 of them naming a throwaway safe. An audit log is not a throwaway safe;
`install.sh --uninstall` keeps the root one for the same reason, and deleting the
record of what was done to a safe is exactly what a cleanup step must not do on
its own. It is the operator's to remove if they want it gone. The lockout
counters beside it — transient, per (uid, safe) — were dropped.

That log is also the last measurement of this round, and it is an I15 check on
real traffic rather than on a fixture: across all 510 lines written by a live
browser session doing every mutation in item 6, **no line carries a value** —
zero occurrences of `"password"`, `"value"`, `"b64"` or `"data_b64"` as a key.
One line verbatim, which is the whole shape:

```json
{"ts": "2026-09-04T10:24:55.899Z", "verb": "health", "safe": null, "uid": 1007,
 "euid": 1007, "outcome": "ok", "note": "", "duration_ms": 124, "pid": 1466971,
 "session": false, "artifact": null, "rows": null}
```

**`cockpit.socket` was never touched.** Its `ActiveEnterTimestamp` reads
`Tue 2026-09-01 01:59:08 CDT` before and after every job of this round, which is
the same value `docs/ROOT-VERIFICATION.md` records.

The credentials directory this suite reads is
`${XDG_RUNTIME_DIR}/cockpit-secrets-live` — tmpfs, 0700, five 0600 files. It is
the operator's to remove; nothing in it is a real credential (two throwaway
Cockpit test accounts and the published fixture passphrase), and it does not
survive a reboot.

---

## Artefact index

`tests/browser/artifacts/` is git-ignored, and not only for tidiness: **a
screenshot taken between "Reveal" and the countdown ending is a screenshot of a
password**, and a live console log names this host's safes. The suite writes them
0600 for the same reason.

| File | What it shows |
|---|---|
| `run-0518-full-pass.log` | the whole record run, 140 PASS / 0 FAIL, exit 0 |
| `01-loaded.png`, `01-console.log`, `01-csp-header.txt` | the page under Cockpit's shell; every console line with its source URL; the policy Cockpit really sent |
| `02-safes-admin.png`, `02-safes-nonadmin.png` | the same registry as `cptestadm` and as `cptest` |
| `03-unlock-prompt.png` … `03-copied.png` | the prompt, the coarse refusal, the entries, the reveal, the re-mask, the clipboard countdown |
| `04-storage.png` | the page after a successful unlock, for the I11 sweep |
| `05-locked.png`, `05-prompted-again.png`, `05-prompted-after-reload.png`, `05-prompted-fresh-tab.png` | the passphrase demanded again after a lock, after a reload, and in a fresh tab |
| `05-handle-replay.json` | a handle minted in one helper process and refused by the next |
| `06-kdbx-*.png`, `06-psafe3-*.png` | the full management sequence in both formats, including the row editor and PWS3's `unsupported` |
| `06-kdbx-downloaded-attachment.bin`, `06-psafe3-downloaded-attachment.bin` | the bytes that came back through the Cockpit channel |
| `07-session-b-saved.png`, `07-conflict.png` | the second session's save, and the decision dialog it caused |
| `08-nonadmin-list.png`, `08-direct-calls.json` | the registry as a non-admin, and the four `cockpit.spawn` calls made around the UI |
| `09-limited-access.png` | the escalation banner with administrative access off |
| `09-refused-without-prompt.png` | the refusal that arrives with no prompt — the finding this round fixed the wording for |
| `09-escalation-prompt.png` | Cockpit's own "Switch to administrative access" dialog, drawn by the shell |
| `09-escalated.png` | the admin-class safe open afterwards |
| `10-zoom-200.png`, `10-keyboard-unlock.png` | the page at the 200%-equivalent viewport; the unlock done from the keyboard alone |
| `live-ui-result.json`, `live-access-result.json` | per-item verdicts, machine-readable |

---

# 0.4.0 · The two new flows, and the foreign oracle on a safe this program made

`tests/browser/live-registry.spec.js` is the suite; `./tests/browser/run-live.sh`
runs it first, before `live-ui` and `live-access`, because it is the only spec
that WRITES to the host — into the signed-in account's own home, never `/etc` —
and it creates, uses and destroys everything it needs.

## What it drives, and against what

Real Cockpit 360 at `https://localhost:9090`, signed in as `cptestadm` with a
password read from a 0600 file in a credentials directory (never argv, never the
environment — the same rule the helper is held to). The INSTALLED package, the
INSTALLED helper, the real bridge, the real Content-Security-Policy. Nothing is
stubbed; `tests/browser/ui.spec.js` is the suite that stubs `cockpit.spawn`, and
it proves a different thing.

Five items:

| Item | What it establishes |
|---|---|
| **R1** | a new safe is created from the page and then opened by the page |
| **R2** | a committed fixture is uploaded, its header is shown BEFORE any passphrase, a wrong passphrase does not cost the transfer, and the adopted safe opens with the fixture's six entries |
| **R3** | `safe-forget` removes the registry entry and leaves the file byte-identical |
| **R4** | `safe-delete`'s token gate, and then the file is gone |
| **R5** | the host is left as it was found |

## Three defects in the SUITE, found by running it, worth recording

None of these was a product defect, and all three are the kind of thing that
makes a browser suite report green for work it did not do.

1. **A string predicate is `eval`, and the real CSP forbids it.**
   `frame.waitForFunction("...")` with a string body is refused by the page's
   own policy (`default-src 'self'`, no `unsafe-eval`) — which is exactly what
   `live-ui` item 1 exists to assert. The wait rejected, a `.catch(() => null)`
   swallowed the reason, and three checks silently read a stale dialog for two
   whole runs. Predicates are functions now, and a wait that gives up prints
   why.

2. **A predicate that was true before the button was clicked.** The first
   version waited for the modal's TEXT to match
   `created|invalid|refused|denied` — and the create form's own
   `breaks_when_wrong` help text already contains those words, so the wait
   returned instantly. `dialogSettled()` now watches the HEADING and the error
   node, neither of which the form says about itself before it is submitted.

3. **`input[type=checkbox]` is not "the confirmation boxes".** A `toggle` field
   in the form renders as a checkbox too, so ticking them all switched on
   `make_keyfile` and produced a safe that needed a key file the suite had
   thrown away. Confirmation gates carry `id^="sec-confirm"`.

A fourth, in the shared harness: `Recorder.item()` returned `state = null` for
an item whose function threw, and the report printed `state || "PASS"`. An
item that never finished is `INCOMPLETE` now, and it counts as a failure.

## I19 on a safe this program CREATED — the check that matters most

A safe only we can read is the I19 failure with a new name, so this is driven
against the foreign oracle rather than against our own reader. It runs through
`/srv/jobs` at a real euid 0, because a created safe is 0600 in somebody's home
and the browser suite never uses sudo. Job `cs-oracle-created`, 2026-09-04,
exit 0. The passphrase came from `/dev/urandom` into a shell variable and was
piped on stdin — this job's log is group-readable and never saw it.

```
== create a KDBX 4.1 / AES-256 / Argon2id safe as root, admin class ==
 helper: {"ok": true, "registry": "system", "bytes": 1173, "format": "kdbx",
          "kdf": {"memory_kib": 65536, "time": 8, "parallelism": 2}}
 -rw------- 1 root root 1173 .../etc/safes/oracle-new.kdbx

== the foreign oracle: keepassxc-cli 2.7.10 ==
 Name: Oracle check
 Cipher: AES 256-bit
 KDF: Argon2id (8 rounds, 65536 KB)
 Number of groups: 1
 Number of entries: 0
 --- ls ---
 [empty]
 --- version bytes at offset 8 (expect 01 00 04 00 = KDBX 4.1) ---
 00000008: 0100 0400                                ....

== a PWS3 created the same way, through the project's own oracle ==
 helper: {"ok": true, "bytes": 344, "format": "psafe3",
          "kdf": {"iterations": 262144}}
 hmac_ok: True  iter: 262144  records: 0   version: 0x030d

== round trip: unlock the CREATED kdbx, add an entry, save, read it foreign ==
 add: True
 ls: made-here
 password: entry-pass-oracle
```

Four things that are worth saying explicitly about that output:

* the **version bytes are `01 00 04 00`**, which is KDBX **4.1** — not the 4.0
  of the pykeepass template the old code inherited;
* the **database name is the operator's label**, so the name in the registry and
  the name a desktop client shows are the same;
* the safe is **empty** — one group, no entries. A template credential in a
  password manager is a thing operators leave behind, and one that looks real is
  a thing they later mistake for real;
* and the **round trip closes**: an entry added through this program and saved
  is read back by `keepassxc-cli show -a Password` with the value that was set.
  That is a foreign reader accepting our writer, which is the only form of I19
  evidence that counts.

The admin-class half is in the same job: the create ran at a real euid 0, landed
`0600 root:root`, and registered in the system registry. `/etc/cockpit-secrets`
was left exactly as it was found — the job worked in a private `/root` tree and
removed it.

## The rest of the walkthrough, re-run against a registry seeded BY THESE VERBS

`live-ui` items 2–7 and `live-access` items 8–9 need a registry with something in
it: an admin-class safe for a non-admin to be refused, and a user-class safe the
signed-in account can actually open. On a host whose registry ships empty they
correctly report NOT-ATTEMPTED with the reason, which is what the first run of
this suite after 0.4.0's install did.

Seeding it is root work and belongs to the operator, not to the suite — so it
was done through `/srv/jobs`, and it was done **with the verbs this release
adds**, which makes it evidence rather than setup:

```
# job cs-seed-walkthrough, at a real euid 0
 safe-create: {"ok": true, "registry": "system", "bytes": 1173, "format": "kdbx"}
 -rw------- 1 root root 1173 /etc/cockpit-secrets/safes/lab-dc.kdbx
 -rw-r--r-- 1 root root  508 /etc/cockpit-secrets/safes.d/lab-dc.json
   "access": "admin",  "origin": "created",
   "created_utc": "2026-09-05T00:21:31.022Z",
   "path": "/etc/cockpit-secrets/safes/lab-dc.kdbx"
 unlock: handle minted

# job cs-seed-user, as cptestadm through `runuser`, NO escalation
 identity: {"uid":1007,"euid":1007,"real_uid":1007,"real_user":"cptestadm",
            "escalated":false,"class_available":"user"}
 create user-kdbx  -> {"ok": true, "registry": "user", "bytes": 1173}
 create user-pws   -> {"ok": true, "registry": "user", "bytes": 344}

  lab-dc     kdbx    admin  registry=system origin=created usable=False manageable=False
  lab-pws    psafe3  admin  registry=system origin=created usable=False manageable=False
  user-kdbx  kdbx    user   registry=user   origin=created usable=True  manageable=True
  user-pws   psafe3  user   registry=user   origin=created usable=True  manageable=True

 /home/cptestadm/.config/cockpit-secrets/safes.d/:
  -rw------- 1 cptestadm cptestadm 550 user-kdbx.json
 /home/cptestadm/.local/share/cockpit-secrets/safes/:
  -rw------- 1 cptestadm cptestadm 1589 user-kdbx.kdbx
```

Three things in that output are the release's whole point, and they were not
possible before it:

* **an administrator made a safe without hand-writing two files**, and the entry
  it wrote records `origin: "created"` and when;
* **an unprivileged user made two safes of their own, with no administrator at
  all**, and the helper resolving their identity says `escalated: false`,
  `class_available: "user"`;
* the four safes list with the right class, the right registry and the right
  `usable` — `lab-dc` is `usable: False` and `manageable: False` to that user,
  because it is root's.

Everything the seeded registry made runnable is destroyed again at the end of
this document's "the host, afterwards" section, using `safe-delete` — which can
only remove them **because this program minted their paths** (I47). A
hand-registered safe would have had to be forgotten and removed by hand, which
is the intended asymmetry.

## Not attempted, and why

* **The admin class from the BROWSER.** R1 asserts that the page names the admin
  class as the default and says so before anything is typed, and it then chooses
  the user class deliberately. Driving an admin-class create from the page would
  write into `/etc/cockpit-secrets` from a test, and the escalation half of that
  path is already covered by `live-access.spec.js` item 9 against a real bridge.
* **A key-file create, end to end.** The generated key file is returned once and
  stored nowhere, so a suite that wanted to use it afterwards would have to keep
  it — which is the one thing the feature says it does not do. The page's
  "save this now" step is asserted to exist by `ui.spec.js`; the download itself
  has never been driven.
* **A 128 MiB upload through the browser.** The fixture is 4,661 bytes. The
  chunker's cap, its incremental enforcement and the memory cost of a 128 MiB
  staging are measured against the helper directly (I54), not through a page.

---

# 0.5.0 · Installing the restyle, and judging it in the real browser

> **SUPERSEDED IN PART BY THE 0.5.1 SECTION AT THE END OF THIS FILE.** Five
> findings in this section — R5 unreachable, `theme.js` not served, the cramped
> entries table, the three red live specs, and the non-hermetic integration
> suite — are closed. This section is deliberately **not edited to match**: it
> is the record of what was true when it was written, and a walkthrough that
> silently updates its own findings is a walkthrough nobody can check. Where a
> number below has moved, the 0.5.1 section gives the new one and says so.

The restyle described in `docs/DESIGN.md` was implemented against a stubbed
bridge and had **never been installed**. This round installed it on this host
and drove the installed page against the live Cockpit 360 at
`https://localhost:9090`. `cockpit.socket` was not stopped, started or reloaded.

The operator's `pwsafe3` was never listed to a verb, never selected, never
opened and never photographed. Its registry entry is byte-identical to the
value recorded before this work began — `mtime 1788641512`, `size 830`,
`sha256 fa0afcea4790f65425fd23fa2d3959660f7f298d9ebf2f647bf06d28dcde9fc8` —
and `grep -rl pwsafe3 tests/browser/artifacts/` returns nothing.

## The gates, before anything was installed

| gate | result |
|---|---|
| `./check.sh` | **exit 0** |
| `./validate.sh` | **exit 0** — every standing ban, 38 unit tests OK |
| `./run_tests.sh` | **exit 1**, 12 PASS / 8 FAIL as inherited … and then **exit 0, 20/20**, see below |

### The 8 inherited failures were environmental, and they ARE isolable

All eight failed identically:

```
hermetic registry did not load: entries=10 errors=[]
```

`tests/integration/_env.py` seeds 9 fixture safes and asserts `health` reports
9. It reports 10. The tenth is the caller's own per-user registry row — the
operator's `pwsafe3` — which `secrets-admin` resolves through
`pwd.getpwuid(euid).pw_dir`, a lookup `COCKPIT_SECRETS_ETC` does not touch.

The previous round concluded this **could not** be isolated. It can. The helper
already honours a `COCKPIT_SECRETS_HOME` override (`secrets-admin:1235`), which
`_env.py` does not set — it sets only `COCKPIT_SECRETS_ETC` and
`COCKPIT_SECRETS_VAR` (`_env.py:93`). Because `_env.py` builds its child
environment with `dict(os.environ)`, exporting the override is enough to prove
it:

```sh
$ echo '{}' | python3 secrets-admin health | ...      # registry_entries = 2
$ echo '{}' | COCKPIT_SECRETS_HOME=<empty dir> python3 secrets-admin health | ...
                                                       # registry_entries = 1
$ COCKPIT_SECRETS_HOME=<empty dir> ./run_tests.sh
  … 20 PASS, 0 FAIL, exit 0
```

**The whole suite is green with one line added to a file this task did not
own.** The fix belongs to `tests/integration/_env.py`:

```python
self.env["COCKPIT_SECRETS_HOME"] = self.root      # beside the ETC/VAR lines
```

No Python was changed to obtain this; `git diff --name-only HEAD` over `*.py`,
`secrets-admin`, `backends/` and `agent/` is empty. Nothing about the operator's
safe was used except a **count** returned by `health`.

## Installing

Through `/srv/jobs`, as root, with `install.sh` unmodified. Exit 0, 3 changes,
0 warnings, and `cockpit.socket` untouched. **Served bytes == source bytes** for
every payload file:

| file | sha256 (source == served) |
|---|---|
| `manifest.json` | `bb51d6b9956403a4cc03fb567a651a540e821d4be6acf74b2ceafb8a71561cd9` |
| `index.html` | `01899df1bdce6594978357f0335a945c0faa70c2fe05b669d86164e68b9d036c` |
| `secrets.js` | `1b7b6e4d7476c6ec8244c27230b4aa3b4ccbf34d8b53f1e0ad83564d5ee51ab0` |
| `secrets.css` | `733040173311740224bfaa563cb95ddcab5e8f6a7ba8d968498bee3fdbc280a7` |

### `theme.js` is NOT served, and the cost is not what the code comments claim

`install.sh:108` is `PLUGIN=(manifest.json index.html secrets.js secrets.css)`
and `:454-470` sweeps `$PKGDIR` down to exactly that list, so the installed
`theme.js` is deleted on every run. Measured after a real install:

```
$ ls /usr/share/cockpit/secrets/theme.js
ls: cannot access ...: No such file or directory
```

`install.sh` half-knows about the file: its pre-flight delegates to `check.sh`
(`install.sh:301`), which globs the JS and prints `theme.js  syntax OK` — so the
installer **gates** a file it then refuses to **ship**.

`index.html:17-20` says the missing request "404s silently". **It does not.**
Cockpit answers with an HTML error page, and Chromium refuses to execute it:

```
$ curl -sk -o /dev/null -w '%{http_code} %{content_type}\n' \
    https://localhost:9090/cockpit/@localhost/secrets/theme.js
401 text/html; charset=utf8              # 404 text/html inside a live session

Refused to execute script from '…/secrets/theme.js' because its MIME type
('text/html') is not executable, and strict MIME type checking is enabled.
```

That is **one console error on every single page load**, and it is what makes
`live-ui.spec.js` item 1 fail. The theme itself is fine — the guarded second
resolver in `secrets.js:151-181` runs and the page resolves correctly in both
directions (below) — so the defect is noise and a wasted request, not a broken
theme. One line in `install.sh` removes it, and the comment in `index.html`
should be corrected to say "answers with an HTML error page and logs a console
refusal" rather than "404s silently".

## R1–R5, driven against the real page

Every one of these was driven through the real shell. Nothing was stubbed.

### R1 · visibility follows elevation — **holds**, by a mechanism that is not the one claimed

* As **`cptest`** (uid 1005, not in `sudo`): the helper offers exactly one safe,
  `dummy-fake-safe`, access `admin`. The page draws **zero** rows and says
  *"Nothing is visible while access is limited · 1 administrator safe is
  hidden."* No admin-class row is drawn at all.
* As **`cptestadm`** unelevated: `dummy-fake-safe` is **absent** from the table
  while the helper still lists it — hiding is cosmetic, exactly as designed —
  and the count-only line reads *"1 administrator safe is hidden. Turn on
  Administrative access in the Cockpit header to see them."* It is **not**
  styled as an alert.
* Turning **Administrative access ON** in the real header makes the row appear.
* Turning it **OFF** again removes the row, clears the selection, and empties
  the pane back to *"No safe selected"* — verified with the admin safe selected
  first.

**But it is not the `changed` listener doing it.** The task asked for "without a
reload", so this was measured rather than assumed. Counting navigations of the
plugin document only (`cockpit/@localhost/secrets/index.html`) across an
escalation:

```
pluginDocNavsDuringEscalation: 1
stampSurvived: false          # window.__stamp set before, gone after
timeOriginChanged: true       # performance.timeOrigin moved
```

**Cockpit's shell reloads the plugin frame when superuser status changes.** The
operator-visible outcome R1 asks for is delivered — the safe appears with no
manual refresh — but `elevationChanged()` is not what delivers it in the
escalation direction, and it remains **unexercised**. This does not weaken the
security story: a frame reload destroys the page's session outright, which is a
stronger guarantee than the listener's lock-and-wipe, not a weaker one.

### R2 · the safes table — **holds**

`TABLE`; every header cell is a `TH` with `scope="col"`; body cells are `TD`;
the table carries a caption. Sorting moves `aria-sort` between columns
(`ascending` → `descending`) and the row order really reverses. A row is
activated by **Enter** and by **Space**, the selected row's door carries
`aria-current="true"` (meaning without colour), and — the defect the
implementer fixed — **focus is still on the same row button after the
re-render**, not dropped to `<body>`.

### R3 · the docked pane — **holds**, asserted as geometry

At the ordinary 1400px window the frame is 1160px and the workspace grid is
`728px 384px`. `pane.x = 760` is right of main's right edge (744), and the two
share a row (`y = 199.19` for both) — docked, not stacked. It is an `<aside>`
with `role="complementary"` and it **follows** `#sec-main` in the DOM, so
reading order and tab order are the same thing.

### R4 · the toggle — **holds**

A real `<button type="button">` with `aria-controls="sec-pane"` and the
accessible name *"Details pane"*. `aria-expanded` flips `true → false → true`.
Collapsed means **gone**: width and height both 0, the grid falls to one column,
and the table reclaims the space (728px → 1128px). Restoring returns the pane to
the same width.

### R5 · the Path column — **DOES NOT HOLD. It is unreachable.**

This is the one requirement the implementation does not deliver, and the
previous round reported it as landed.

The negative half is true: **`path` is not a column on first load**, no header
carries it, and no cell in the default table carries a filesystem path or a safe
filename. But the positive half cannot happen:

```
$ echo '{}' | python3 secrets-admin schema | …    # the `list` verb's response
"safes": "[{id,label,format,access,mode,locked,reason,usable,
            password_required,needs_keyfile,agent_enabled,
            export_allowed,registry,origin,manageable}]"
```

**`path` is not in it.** Live, every safe comes back with `path` absent, at both
access levels:

```
[{"id":"dummy-fake-safe","path":"(absent)"},
 {"id":"dummy-fake-user-kdbx","path":"(absent)"},
 {"id":"dummy-fake-user-psafe3","path":"(absent)"}]
```

Both halves of R5 are guarded on that field:

* `secrets.js:3660` — `optColAvailable()` offers the Path column only when
  `rows.some(s => !!s.path)`. It never can, so the checkbox is **never offered**.
  Measured, elevated and unelevated, the chooser offers only
  `["col-registry","col-kdf","col-id"]`.
* `secrets.js:4150` — the pane's Path section is behind `if (safe.path)`. It
  never renders. Selecting each safe in turn, the pane's only section heading is
  *"File header"*; there is no `Path` heading and no `code.sec-path` node.

Grepping the schema, the only verbs that publish a path are `safe-forget`,
`save-as` and `export` — a destructive verb and two that write files. **No
read-only verb tells the page where a safe lives**, so R5 cannot be satisfied by
the page alone. The column and the pane section are correctly written and are
dead code against this helper.

**The fix is in the helper, not the page**: add `path` to the `list` verb's
declared response and populate it (gated on access class, since a path names a
home directory and therefore an account — which is reason 1 of the three
`secrets.js:3906` gives for the column being off by default). The page then
works unchanged.

### The narrow viewport, and I11

Below the 60rem breakpoint the pane un-docks to a full-width panel below the
table, `aria-expanded` is `false`, and there is no horizontal page scroll at
480px or 360px. At 360px the table scrolls inside its own box
(`overflow-x: auto`, scroller 480px wide in a 326px box), which is the
`min-inline-size: 30rem` refinement doing its job.

After exercising the column chooser and the pane, **both storage areas are
byte-for-byte what they were before**: `localStorage` still
`{superuser:cptestadm, superuser-key, standard-login}` (all Cockpit's own),
`sessionStorage` still `{cockpit:page_status, cockpit:v2-machines.json}`, no
cookie set from the frame, and `indexedDB.databases()` empty. The session-only
trade holds.

## Judged, not just captured

### The theme follows the shell, live — with `theme.js` absent

Driven through the shell's own Session → Style control:

| shell setting | shell `<html>` | frame `<html>` |
|---|---|---|
| Light | `index-page` | `sec-light sec-theme-managed` |
| Dark | `index-page pf-v6-theme-dark` | `sec-theme-managed sec-dark` |

Both correct, with no reload, and with `theme.js` 404ing — so this is the
guarded fallback in `secrets.js` carrying the whole feature on an installed
host. The mitigation is real and it works.

### Contrast, computed from the rendered page in both themes

Every element with its own text was read out of the live DOM, its colour taken
against its first opaque ancestor background, and the WCAG ratio computed —
nothing was trusted from the plan.

| theme | pairs | below threshold |
|---|---|---|
| light | 21 | **0** |
| dark | 23 | **0** |

Lowest actual ratios: **4.97** (light, a `<summary>` at 14px) and **6.66**
(dark, the session chip at 12px). Both clear 4.5.

A first pass reported 2 failures per theme — `Save` at 2.25/3.33 and `Previous`
at 2.52/2.94. Both were measured again with the element's state read: they are
`disabled: true`, colour `rgb(112,112,112)`. **WCAG 1.4.3 exempts inactive user
interface components**, so they are not violations; the corrected measurement
excludes `disabled`, `[disabled]` ancestors and `aria-disabled="true"`. Recorded
because the first number was wrong and the reason it was wrong is the useful
part.

### Keyboard, zoom, motion

* **18 tab stops** inside the frame, in DOM order, ending at the footer
  disclosure. **Every one** is `:focus-visible` with a `2px solid` outline —
  one distinct outline width across all 18.
* **200% zoom** at the WCAG 1.4.10 viewport (700 × 480 CSS px):
  `scrollWidth === clientWidth === 700`, **zero** elements overflowing the frame
  outside their own scroller, and the pane un-docked to one column.
* **`prefers-reduced-motion: reduce`**, emulated for real: zero animating
  elements and zero transitioning elements on the whole page.
* **Target size**: one stop is under 24 CSS px in one dimension — the footer's
  `<summary>` at 960 × 21. Everything else clears 24 × 24.

### CSP

`securitypolicyviolation` events: **0**. The real policy on the package page is

```
default-src 'self'; connect-src wss://localhost:9090 'self'; form-action 'self';
base-uri 'self'; object-src 'none'; font-src 'self' data:; img-src 'self' data:;
block-all-mixed-content
```

The **one** console script refusal is the `theme.js` MIME refusal above, which
is the missing installer line and not a policy relaxation anywhere.

## The live suite, re-run: `exit 1`

`./tests/browser/run-live.sh`, against the installed page:

| spec | score | state |
|---|---|---|
| `live-registry.spec.js` | **13/15 checks** | R1 INCOMPLETE, R0 FAIL |
| `live-ui.spec.js` | **4/8 checks** | items 1, 2 FAIL; 3 aborted; 4, 5, 6, 7, 10 NOT-ATTEMPTED |
| `live-access.spec.js` | **9/10 checks** | item 8 PASS, item 9 FAIL |

**All three live specs are broken by the restyle, not just `live-ui.spec.js`.**
The previous round reported only `live-ui.spec.js` as needing migration; that is
incomplete. The single dominant cause is one selector:

```
locator('.sec-safe').filter({has: locator('.sec-safe-id:text-is("…")')})
       .locator('button:text-is("Unlock…")')
```

**Nothing in a row is an action any more** — `secrets.js:3969` says so
deliberately, and every action moved into the pane. So `Unlock…` is no longer
inside `.sec-safe`, and the click times out at 30s. That one timeout aborts
`live-ui.spec.js` after item 3, which is what turns five further items into
NOT-ATTEMPTED, and it aborts `live-access.spec.js` item 9.

The other three failures:

* `live-ui` item 1 — the `theme.js` MIME refusal (installer, above).
* `live-ui` item 2 — *"class blocks in document order: []"*. The card grid that
  grouped safes under class headings became one sortable table; there are no
  class blocks to be in document order.
* `live-access` item 9 — *"the admin-class card offers a 'Check this safe'
  control while access is off"*. This is R1's **disclosed** cost: the control
  exists only for an admin safe while access is off, and R1 hides the row that
  carries it in exactly that state. It is genuinely unreachable there.

None of these is a regression in what the page *does*; all are the suites
describing the old markup. They are real failures all the same, and the suite is
red until somebody who owns those files migrates them.

## What was NOT verified

* **`elevationChanged()`** — still unexercised, and in the escalation direction
  it appears unreachable in this shell, because Cockpit reloads the frame first.
  The de-escalation direction was observed to produce the right end state, but
  by the same reload.
* **Firefox and WebKit.** Chromium only.
* **`live-ui.spec.js` items 3–7 and 10** — aborted, not run. Item 3's unlock
  flow was driven by hand instead (below), but items 6 and 7 — full management
  in both formats, and the conflict path — were not exercised at all this round.
* **A real YubiKey, a real agent, a root-owned registry** — unchanged from 0.4.0.

## Screenshots

24 surfaces, light and dark, all `0600`, all in `tests/browser/artifacts/`, all
of the three throw-away `dummy-fake-*` safes. Every capture asserts `pwsafe3` is
absent from both the frame and the shell before the shutter opens.

| surface | light | dark |
|---|---|---|
| safe list | `restyle-light-01-safelist.png` | `restyle-dark-01-safelist.png` |
| pane, safe selected | `restyle-light-02-pane-safe-detail.png` | `restyle-dark-02-pane-safe-detail.png` |
| unlock modal | `restyle-light-03-unlock-modal.png` | `restyle-dark-03-unlock-modal.png` |
| unlock error | `restyle-light-04-unlock-error.png` | `restyle-dark-04-unlock-error.png` |
| entry list | `restyle-light-05-entry-list.png` | `restyle-dark-05-entry-list.png` |
| entry detail | `restyle-light-06-entry-detail.png` | `restyle-dark-06-entry-detail.png` |
| revealed, mid-countdown | `restyle-light-07-revealed-midcountdown.png` | `restyle-dark-07-revealed-midcountdown.png` |
| narrow, 480px | `restyle-light-08-narrow-480.png` | `restyle-dark-08-narrow-480.png` |
| strength meter, weak | `restyle-light-09-strength-weak.png` | `restyle-dark-09-strength-weak.png` |
| strength meter, strong | `restyle-light-10-strength-strong.png` | `restyle-dark-10-strength-strong.png` |
| delete confirm | `restyle-light-11-delete-confirm.png` | `restyle-dark-11-delete-confirm.png` |
| empty group | `restyle-light-12-empty-group.png` | `restyle-dark-12-empty-group.png` |
| locked out | `restyle-light-13-locked-out.png` | `restyle-dark-13-locked-out.png` |

Four more, light only, because they are not theme-dependent claims:
`restyle-light-14-cptest-nonadmin.png`,
`restyle-light-15-zoom200-700x480.png`,
`restyle-light-16-reduced-motion.png`,
`restyle-light-17-narrow-iframe-360.png`.

### One trap this round fell into, recorded because the README already warned about it

The first `04-unlock-error` pair was **byte-identical** to the `03-unlock-modal`
pair. The predicate waited for `/did not|wrong|failed/` in the modal's text —
and the modal's own explanatory copy contains those words, so it was true before
the button was ever pressed. That is trap #2 in `tests/browser/README.md`,
written down after the same mistake in `live-registry.spec.js`. The fix is to
count the **alert nodes** before submitting and wait for that count to go up.
The re-captured pair is distinct, and the alert reads *"the passphrase, key file
or file integrity check did not match this safe · bad-credential"*.

## Surfaces judged against what `docs/DESIGN.md` specified

* **The strength meter (§13)** — the segments are **single-hue**: at
  `password1`, one segment is lit in the same blue as all five at 289 bits.
  Meaning is carried by the count and by the sentence
  (*"15 bits of effective entropy (47 before its weaknesses) — Very weak: under
  28 effective bits…"*), never by red/amber/green. §13's hero-number DOM
  restructure was **not** done, as the implementer disclosed; the CSS half is
  there.
* **The empty state** — *"0 entries … No entries here."* with the header row and
  the pager still drawn. That is why `Previous`/`Next` are the page's only
  disabled controls, and why they were the two the first contrast pass tripped
  over.
* **The delete confirm** — two `id^="sec-confirm"` gates plus the safe's id
  typed, matching §7's ladder. Opened and **cancelled**; nothing was deleted.
* **Locked out** — reached deliberately on `dummy-fake-user-psafe3`:
  *"too many failed unlock attempts for this safe; try again in 1 seconds ·
  locked-out"*. Self-clearing, cap 900s.
* **The entries table is cramped**, and this is the one defect that only
  looking at a picture found. §5.5's scroll-in-its-own-box mechanism works
  (`min-inline-size: 42rem` = 672px inside a 504px host, `overflow-x: auto`, no
  page scroll) but 42rem is too small a floor for seven columns: every cell in
  the first row wraps to **five lines**, and `ada.lovelace` is broken mid-word
  in a 103px column. `docs/DESIGN.md` §18.9 has the measurements.
* **`.sec-safe.unreachable` no longer dims** — confirmed, and it is why
  `live-ui` item 2's "0 safes rendered unreachable" check fails. The chip and
  the helper's sentence carry the state instead, which is the better design and
  a real suite migration.

## What remains on the host

* The installed package at `/usr/share/cockpit/secrets/` — 4 files, **no
  `theme.js`** (swept by `install.sh`), version 0.5.0.
* The three `dummy-fake-*` testbed safes, **left in place as the operator asked**,
  unchanged in content.
* `/var/lib/cockpit-secrets/state/safe.dummy-fake-safe.json` and
  `fail.1007.dummy-fake-safe.json` (34–38 bytes each), plus the equivalent
  per-user counters in `~cptestadm`. These are ordinary self-expiring lockout and
  rate-cap bookkeeping written by the helper whenever anybody unlocks anything.
  **They were deliberately not deleted**: removing lockout state is tampering
  with a security control, and they expire on their own.
* 45 files in `tests/browser/artifacts/` (31 written this round), all `0600`, in
  a git-ignored directory. `grep -rl pwsafe3` over them returns nothing.
* Nothing else. No service was started, stopped or reloaded; no registry entry
  was created, edited or removed; no safe was created or deleted.

---

# 0.5.1 · Closing the five, and proving R5 on the live page

0.5.0 shipped the restyle and then said, in its own verification, exactly what it
had not delivered. This round closed that list — and nothing else — then
installed the result and drove it. `cockpit.socket` was **never** stopped,
started or reloaded; its `ActiveEnterTimestamp` reads
`Tue 2026-09-01 01:59:08 CDT` before and after every job.

The operator's `pwsafe3` was never listed to a verb, never selected, never
opened and never photographed. Its registry entry is byte-identical to the value
recorded before this work began — `mtime 1788641512`, `size 830`,
`sha256 fa0afcea4790f65425fd23fa2d3959660f7f298d9ebf2f647bf06d28dcde9fc8` —
re-checked after every root job, and `grep -rl pwsafe3 tests/browser/artifacts/`
returns nothing.

## The gates

`./check.sh` — exit 0 (`secrets.js`, `theme.js` syntax OK).
`./validate.sh` — `validate.sh: OK`, every standing ban PASS, 38 unit tests OK.
`python3 tests/corpus/gen_corpus.py --check` — `67 cases checked, 0 disagreed
with their sidecar`, exit 0.

`./run_tests.sh`, **with no environment override**, which is the point of I60:

```
  PASS  syntax and standing bans (validate.sh)             7s
  PASS  javascript syntax (check.sh)                       0s
  PASS  backends/base.py self-check                        1s
  PASS  backends/psafe3 self-check                         3s
  PASS  backends/kdbx self-check                           6s
  PASS  agent self-check                                   0s
  PASS  twofish ECB vectors, both providers                1s
  PASS  integration: contract flow, both formats          11s
  PASS  integration: cross-backend conformance             3s
  PASS  integration: load-bearing properties              18s
  PASS  integration: the second-wave verbs                14s
  PASS  integration: the unlock agent, end to end          7s
  PASS  integration: the lockout — concurrency, identity, reach    63s
  PASS  integration: the adversarial findings             15s
  PASS  integration: the registry write path              68s
  PASS  integration: corpus vs the helper                101s
  PASS  oracles: build and known-answer vectors            0s
  PASS  fixtures: verify against keepassxc-cli             3s
  PASS  ui: headless browser driver                       37s
  PASS  ui: item 4's storage oracle (I11, I42)             0s

run_tests.sh: OK
```

**20/20.** It was 12/20 before `_env.py` set `COCKPIT_SECRETS_HOME`, and the
eight that failed aborted at build time with `hermetic registry did not load:
entries=10 errors=[]` — the tenth entry being the operator's own safe, read
straight out of the caller's real home into what the suite called hermetic.

## Installing

Three root jobs through `/srv/jobs`, never `sudo`. A staged `DESTDIR` dry run
first (32 changes, 0 warnings, `theme.js` in the staged package), then the real
install, then a second run to prove the copy list and the sweep now agree:

```
=== 2. real install ===
  Summary
    1 change(s), 31 unchanged, 0 warning(s)

=== 3. idempotence ===
  index.html: 3 package-local reference(s), every one of them installed (theme.js, secrets.css, secrets.js)
  = unchanged /usr/share/cockpit/secrets/theme.js
  library root holds exactly the installed payload (no bytecode, no strays)
  0 change(s), 32 unchanged, 0 warning(s)
```

The first line of the idempotence run is the **new pre-flight gate** (I57): it
parses `index.html` and refuses an install where the page asks for a
package-local file `PLUGIN` does not ship.

**Served == source, by SHA-256, for every artefact the installer claims to
ship** — 5 package files, the helper, all 5 backends, the schema:

```
  OK    manifest.json              bb51d6b9956403a4
  OK    index.html                 2f11e92428ca7e14
  OK    secrets.js                 395a25ba4d6fbefe
  OK    secrets.css                1885f5ff6b63460f
  OK    theme.js                   e56b82e6f780dcec
  OK    secrets-admin              f5bb562beaf8f65d
  OK    base.py                    12ab9b664c9adf15
  OK    __init__.py                8eea9b00b4d3c0fb
  OK    kdbx.py                    b0bf7efbd49c0c82
  OK    psafe3.py                  0d5693e5e3026f5f
  OK    twofish_pure.py            f17e2cdb146bc7fc
  OK    safe-registry.schema.json  f7488cb582ba9f81
  mismatches: 0
```

All five package files `0644 root:root` in a `0755 root:root` directory. The
package directory now lists **five** files, and the second install run reports
`= unchanged` for `theme.js` rather than sweeping it — which is the actual proof
that I57 is closed, because the previous behaviour was a delete on every run.

## The browser console, on load

Item 1, on the installed page, through the real shell as `cptestadm`:

```
  PASS  securitypolicyviolation events: 0
  PASS  console CSP refusals: 0
  PASS  page and console errors from the secrets package: 0
  ....  Cockpit's own shell logged 1 error(s) in the same page:
        ["Failed to load resource: … 401 (Authentication failed) <…/cockpit/login>"]
```

Zero errors, zero CSP violations. The one error in the page is Cockpit's own
login probe, attributed by URL and not by assumption. The CSP the bridge really
sends is recorded in the item's own note and nothing about it was relaxed.

## R5, end to end — `live-ui.spec.js` item 11

This is the requirement 0.5.0 did not deliver, and the reason this round exists.
It runs **last and in a session of its own**, and escalates there through
Cockpit's own header control, because R5 must be shown for a system-registry
safe as well as a per-user one while items 1–10 are written against a
limited-access session.

Every line below is from the run, as `cptestadm`, against the installed helper:

```
R1 (access off): the helper lists 1 administrator safe(s) and the table draws
                 none of them — rows: ["dummy-fake-user-kdbx","dummy-fake-user-psafe3"]
administrative access is ON (cockpit.permission({admin:true}).allowed === true)
R1 (access on):  the same 1 administrator safe(s) are now drawn —
                 ["dummy-fake-safe","dummy-fake-user-kdbx","dummy-fake-user-psafe3"]
safes with a path: ["dummy-fake-safe/system","dummy-fake-user-kdbx/user",
                    "dummy-fake-user-psafe3/user"]

R2 still holds: a real <table>, every <th> scope=col — ["Safe","Class","Format","State"]
R2: 4 columns sort from a real <button> in the <th>

R5: Path is NOT a column on first load — headers ["Safe","Class","Format","State"]
R5: neither published path appears ANYWHERE in the default table ([])
    …and no home-directory path of any kind is on screen by default
the column chooser is a native <details>: ["col-path","col-registry","col-kdf","col-id"]
R5: the chooser OFFERS a Path checkbox
R5: every optional column is OFF by default, Path included
ticking the box adds a real <th>Path</th> immediately, with no Apply step
R5: the SYSTEM safe's cell holds the helper's own value in full:
    "/etc/cockpit-secrets/safes/dummy-fake-safe.kdbx"
R5: the PER-USER safe's cell holds the helper's own value in full:
    "/home/cptestadm/.local/share/cockpit-secrets/safes/dummy-fake-user-kdbx.kdbx"
R5: sorting by "Safe" keeps the Path column, in the same position (4)
    …and both cells still hold the full path after the re-render
    …and again with the sort reversed (aria-sort now "descending")

R3: choosing the system-registry row opens the pane on "dummy-fake-safe"
R5: the pane's FIRST section is Path (["Path","File header"])
R5: it is the whole path, character for character, not ~-abbreviated and not elided
R5: it is SELECTABLE — computed user-select is "auto"
R5: it WRAPS rather than truncating (overflow-wrap "anywhere",
    white-space "pre-wrap", scrollWidth 348 <= clientWidth 348)
    …and text-overflow is not an ellipsis, which is the other way a path lies
    …and the pane says what the LOCATION means for this class of safe ("admin")
(the same seven lines again for the PER-USER safe, ("user"))

R4: the pane toggle is a real <button> with aria-controls=sec-pane
R4: collapsing hides the pane and flips aria-expanded to false
R4: expanding brings it back

R5: unticking removes the column and the path string leaves the table with it
    …while the pane still shows it — that is what ALWAYS means (R5)
```

**I11 across all of it**, against a baseline taken immediately after escalation
and before the chooser was ever opened:

```
storage baseline: local ["superuser:cptestadm","superuser-key","standard-login"],
                  session ["cockpit:page_status","cockpit:v2-machines.json"]
a full unlock of "dummy-fake-user-kdbx" succeeds in this escalated session
host-shell keys that changed and were tolerated by name: none
I11: the column chooser, the details pane, the sort, the pane toggle and a full
     unlock added NOTHING to either storage area and overwrote nothing
     ([] local, [] session)
I11: no storage value anywhere holds the passphrase, a safe id, a safe PATH or
     this package's name — the tolerated keys included ([])
I11: no storage key belongs to this package ([])
the operator's own safe was never named in this frame, at either access level,
with the Path column on — which is the state that would have shown its file
```

The last line is the one worth reading twice: the Path column ON, in an
escalated session, is precisely the state in which the operator's own safe would
have disclosed its file, and it did not appear.

## The live suite, re-run: `exit 0`

`./tests/browser/run-live.sh`, against the installed page:

| spec | result | was, in 0.5.0 |
|---|---|---|
| `live-registry.spec.js` | **57 checks, 0 failures** — R1 R2 R3 R4 R5 all PASS | 13/15, R0 and R1 red |
| `live-ui.spec.js` | **185/185 checks held** — items 1, 2, 3, 4, 5, 6, 7, 10 **and the new 11** all PASS | 4/8 |
| `live-access.spec.js` | **22/22 checks held** — items 8 and 9 PASS | 9/10 |

**Item 6 drove BOTH formats this round**, which it had never done against this
testbed:

```
driving 2 safe(s), one per format: ["dummy-fake-user-kdbx (kdbx)",
                                    "dummy-fake-user-psafe3 (psafe3)"]
formats driven: ["kdbx","psafe3"]; formats present but not driven: []
```

`dummy-fake-user-psafe3` is registered `mode: "ro"` on purpose — it is the
fixture for the read-only and format-warning states — so it was flipped to `rw`
for the run using the one command `tests/browser/TESTBED.md` documents, and
**flipped back afterwards**; the helper's own `list` confirms `ro` again, with
`registry_errors: 0`.

Driving it found a real test defect, now fixed: item 6 asserted "the upload was
accepted" unconditionally and then threw, aborting the whole psafe3 half at the
attachment step. A Password Safe v3 database **this program creates** declares
0x030D and attachments need 0x030F, so the only PWS3 in the testbed cannot take
one, by construction (`docs/RESIDUAL-RISK.md` §4.11). The item now reads the
helper's answer instead of assuming it:

```
the upload was refused, and refused as a FORMAT LIMIT rather than as an error:
  code "unsupported"
…and the sentence names the version this file declares and the version
  attachments need: "this database declares format 0x030d; attachments need
  0x030f (PasswordSafe V3.68) or later"
the entry lists NO attachment, which is the correct reading of a file whose
  format cannot hold one
ATTACHMENT CHAIN NOT ATTEMPTED for psafe3 …
```

So **item 6 is a full pass for KDBX and a stated partial for PWS3** — add, edit,
custom field (refused as `unsupported` with the format's own reason), history,
save with the named backup, lock and reopen all held for both; attach-list,
attach-get and the byte-for-byte download are not claimed for a 0x030D file, and
the report says so rather than being silent.

## Screenshots for the operator

All `0600`, in `tests/browser/artifacts/`, all of the sanctioned `dummy-fake-*`
safes. `grep -rl pwsafe3` over the whole directory returns nothing.

| file | what it shows |
|---|---|
| `11-safes-path-on-light.png` | the safe list, **light**, Path column ON — three safes, full paths, and the pane showing the per-user safe's path with "Copy path" and the location sentence |
| `11-safes-path-off-light.png` | the same list, **light**, Path column OFF — the default, with no path anywhere in the table |
| `11-safes-path-on-dark.png` | the same, **dark** |
| `11-safes-path-off-dark.png` | the same, **dark**, default columns |
| `11-pane-path-light.png` / `11-pane-path-dark.png` | the details pane showing a path in full with the column OFF — R5's "always" |
| `11-pane-path-system.png` | the pane for the **system** safe: `/etc/cockpit-secrets/safes/dummy-fake-safe.kdbx` with the "owned by root" sentence |
| `11-pane-path-user.png` | the pane for the **per-user** safe, with the "a safe of your own" sentence |
| `11-path-column-on.png` | the moment after ticking the box, before any sort |
| `11-pane-collapsed.png` | R4 — the pane collapsed, `aria-expanded="false"`, the table reclaiming the width |
| `11-safes-360-path-on.png` | a **360px** frame with the Path column ON: the table scrolls in its own box and the page does not (asked it to scroll 4000px, it moved 0) |
| `10-entries-pane-open.png` | the entries table at its new 60rem floor in a 504px box — `ada.lovelace` on ONE line |
| `10-entries-pane-collapsed.png`, `10-entries-zoom-200.png`, `10-entries-360.png` | the same table at the other three widths |
| `02-pane-collapsed.png` | R4 from item 2's session |
| `06-psafe3-attach-refused.png` | the PWS3 format limit, refused with its own sentence |

## What is still not verified

* **Chromium only.** No Firefox, no WebKit, in this round or any previous one.
* **The attachment chain for PWS3.** It needs a 0x030F file, and this program
  does not create one; adopting a foreign Password Safe database is the route to
  that coverage, and there is no Password Safe CLI on this host to make one.
* **The `path`-less case** — a `%u` registry entry that cannot be resolved for
  the caller — is exercised only in a scratch registry under
  `unshare --map-root-user`, not by anything committed.
* **I61, new and open.** In a session that has *already* turned administrative
  access on, the pane for an admin-class safe still reads "turn on Cockpit's
  Administrative access and try again" — the helper's own sentence, correct for
  the unescalated `list` that produced it, re-shown after the operator has done
  the thing it asks. The control works: item 9 opens that safe in that state.
  `11-safes-path-off-dark.png` is the evidence.
* **`ui.spec.js` grew no source-level assertion on the CSS** — the natural one
  is that `table.sec td` must resolve `break-word` and the only `anywhere`
  inside a table must be the URL column and `#sec-safes .mono`.
* **Two files that SHIP are not in the repository.** `git status` reports
  `docs/DESIGN.md` and `theme.js` as untracked, and `git check-ignore` says
  nothing ignores them — they were written and never added. `theme.js` is a
  member of `install.sh`'s `PLUGIN` array and is served to every session, and
  `docs/DESIGN.md` is the specification §18 of this file keeps citing. A clone
  of this repository today gets neither: the installer's own pre-flight would
  refuse the install, which is the gate working, and §18 would be a dangling
  reference. This round did not run any `git` write command, so it is left for
  whoever commits — but it should be the first thing they do, not the last.

## What remains on the host

* The installed package at `/usr/share/cockpit/secrets/` — **five** files now,
  `theme.js` included, all `0644 root:root`, served == source by SHA-256,
  version 0.5.1.
* The three `dummy-fake-*` testbed safes, **left in place as the operator asked**.
  `dummy-fake-user-psafe3` is back to `mode: "ro"`, confirmed from the helper's
  own `list`. `dummy-fake-user-kdbx` and `dummy-fake-user-psafe3` carry the
  entries item 6 wrote into them, which is what a management test does; the
  testbed is rebuildable with the one command in `tests/browser/TESTBED.md`.
* `.bak.d` backup rings beside the two user-class safes, written by the saves
  item 6 made. They are the backup ring working (I12) and were not deleted.
* Lockout and rate-cap bookkeeping under `/var/lib/cockpit-secrets/state/` and
  the equivalent per-user counters in `~cptestadm`. **Deliberately not deleted**:
  removing lockout state is tampering with a security control, and it expires on
  its own.
* 192 files in `tests/browser/artifacts/`, all `0600` (the directory's
  `.gitignore` is the one exception, and holds nothing), in a git-ignored
  directory.
* Nothing else. No service was started, stopped or reloaded. `cockpit.socket`'s
  `ActiveEnterTimestamp` is unchanged. No registry entry was created or removed;
  one was edited twice — `dummy-fake-user-psafe3`'s `mode`, `ro` → `rw` → `ro` —
  and it is back where it started.
