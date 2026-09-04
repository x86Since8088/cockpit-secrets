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
