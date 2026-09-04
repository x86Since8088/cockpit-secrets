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
