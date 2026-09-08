# tests/browser — the headless driver for `secrets.js`

```
node tests/browser/ui.spec.js
```

`secrets.js` is the one file in this package with no server-side test. The
integration suite under `tests/integration/` drives the real helper against real
fixtures, and the helper does not know the page exists. Everything the page is
supposed to guarantee is a claim about a browser:

* it renders nothing the schema did not describe, and everything it did;
* no secret reaches a storage area, a cookie, or a command line;
* an export cannot be reached without first reading what an export does;
* a safe held unlocked by the agent is never invisible.

Only a browser can check those, so this is a browser.

## What it runs against

**The real page.** There is no build step in this package: `install.sh` copies
`index.html`, `secrets.js` and `secrets.css` verbatim, and the static server in
`harness.js` serves those same three files. What the test loads is what the
operator loads.

**The real schema.** `harness.js` runs `secrets-admin schema` and hands the
output to the stub. A suite that checked the page against a schema copied into a
fixture would keep passing after the helper changed, which is precisely the
failure this exists to catch — the coverage assertions below are only worth
anything because the schema is live.

**A stub bridge.** `cockpit.spawn` is the page's entire interface to the world,
so it is the only thing faked: `/base1/cockpit.js` is served as a stub that
answers spawn from a per-test scenario and records every argv and every request
body. That recording is what makes I10 and I11 testable rather than assertable —
the driver checks what actually crossed the boundary, not what the page meant to
send.

No root, no Cockpit, no `cockpit.socket`, no network.

## The two coverage assertions

These are the ones that fail when somebody adds to the helper and forgets the
page.

**Every control type.** A synthetic verb is built declaring one field for each
entry in `enums.control`, the generic dialog is opened, and no field may carry
the renderer's own "this page does not know how to draw" warning. That warning
is the renderer being honest about a gap; this turns it into a failing test.

**Every verb.** `ROUTES` in `ui.spec.js` names, for each verb, how the page
reaches it: either the page calls it during the scripted walkthrough, or it
offers a control with a stated label. A verb with no route entry fails
immediately — so a helper that grows a verb this page does not handle is caught
before it ships a capability nobody can reach.

## What it does NOT cover

* **A real Cockpit bridge.** `superuser: "require"` is recorded but never
  honoured, so the escalation path has never run for real here. The access class
  is enforced in the helper and proved by `tests/integration/`, which drives it
  directly as a non-admin (I3).
* **A real YubiKey.** The challenge/response is scripted from the stub.
* **A real `secrets-agent`.** The banner is driven from the `agent` block on the
  unlock reply, which the stub supplies. No daemon is involved.
* **Anything the helper decides.** Every client-side check this suite exercises
  is FEEDBACK. The helper refuses, and the tests that prove it refuses live
  elsewhere.

## Dependencies

Playwright is not part of this package (`node_modules/` is git-ignored). The
harness resolves it from `$PLAYWRIGHT_PATH`, then the ordinary module path, then
`/opt/sc/edy-local/e2e/node_modules/playwright`. When it finds none, the suite
prints a SKIP banner naming what did not run and exits 0 — a missing tool is not
a passing test, and saying so is better than a green line that means nothing.

## `live-registry.spec.js` — 0.4.0's create-and-adopt flows, live

Runs FIRST in `run-live.sh`, because it is the only spec that writes to the host
(into the signed-in account's own home, never `/etc`) and it creates, uses and
destroys everything it needs. Five items, 57 checks:

| item | what it establishes |
|---|---|
| R1 | a new safe is created from the page and then opened by the page, empty |
| R2 | a committed fixture is uploaded, its header shown BEFORE any passphrase, a wrong passphrase does not cost the transfer, and the adopted safe opens with the fixture's six entries — with the landed file proved byte-identical to the one that was picked (I43) |
| R3 | `safe-forget` removes the entry and leaves the file byte-identical |
| R4 | `safe-delete`'s token gate — every box ticked and the id mistyped is still disabled — then the file is gone |
| R5 | the host is left as it was found |

It needs one credential the other live specs do not:
`<creds>/safe-live-created.pass`, the passphrase it will CREATE the safe with.
It is not invented, and that is deliberate: a passphrase the suite made up is
one nobody can use to check the file afterwards with `keepassxc-cli`. Absent,
every item is NOT-ATTEMPTED with the file name it looked for.

### Three traps this file records, because each one made a check meaningless

1. **`waitForFunction` with a STRING body is `eval`,** and the real Cockpit CSP
   is `default-src 'self'` with no `unsafe-eval` — so the predicate is refused
   by the browser, the wait rejects, and a `.catch(() => null)` turns that into
   "the assertion read a stale dialog". Predicates are functions; a wait that
   gives up prints why.
2. **A predicate can be true before the button is clicked.** Matching the
   modal's TEXT for `created|invalid|refused` returned instantly, because the
   create form's own help text contains those words. `dialogSettled()` watches
   the HEADING and the error node instead.
3. **`input[type=checkbox]` is not "the confirmation boxes".** A `toggle` FIELD
   renders as a checkbox too, so ticking them all switched on `make_keyfile`.
   Confirmation gates carry `id^="sec-confirm"`.

And one in `live-harness.js`: `Recorder.item()` left `state = null` for an item
whose function threw, and the report printed `state || "PASS"`. `done()` now
sets `finished`, and an item that never reached it is `INCOMPLETE` and counts as
a failure.

### What it does NOT do

It never uses `sudo` and never submits a root job, so the I19 check that a
**newly created** safe opens in `keepassxc-cli` is not here — the created file
is 0600 in a test principal's home. That runs through `/srv/jobs` and its output
is in `docs/LIVE-WALKTHROUGH.md`.
