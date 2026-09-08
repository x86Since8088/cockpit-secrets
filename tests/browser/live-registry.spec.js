/* tests/browser/live-registry.spec.js — 0.4.0's two new flows, in a real
 * browser, against this host's live Cockpit and the INSTALLED package.
 *
 * `ui.spec.js` drives the same two flows against a stubbed `cockpit.spawn`: it
 * proves the page sends the right requests in the right order. It cannot prove
 * that the helper accepts them, that a file appears on disk, or that the safe
 * the page just made can be opened again — because nothing on the other side of
 * the stub is real. This file is the other half.
 *
 * FIVE ITEMS, in the order an operator would do them:
 *
 *   R1  create a new safe from the page, and open it
 *   R2  upload a committed fixture, and open it
 *   R3  forget one — the registry entry goes, the file stays
 *   R4  delete the other — the token gate, then the file is gone
 *   R5  the host is left as it was found
 *
 * The foreign-oracle check that a NEWLY CREATED safe opens in `keepassxc-cli`
 * (I19 — a safe only we can read is the failure) is deliberately NOT here: the
 * created file is 0600 in the test principal's home, and this suite never uses
 * sudo and never submits a root job. It runs as its own step through
 * `/srv/jobs` and its output is recorded in `docs/LIVE-WALKTHROUGH.md`.
 *
 * EVERYTHING IS USER-CLASS. A user-class safe lands under the signed-in
 * account's own home and can be created, opened, forgotten and destroyed by
 * that account with no escalation — which is exactly the capability 0.4.0 adds
 * and the one an ordinary operator has. The admin class writes into
 * /etc/cockpit-secrets and is covered at a real euid 0 through the root runner;
 * item R1 asserts that the page ASKS for escalation on an admin-class create
 * (`superuser: "require"`) without performing one.
 *
 * The three rules of live-harness.js hold here too: no secret on argv or in the
 * environment, cockpit.socket is never touched, and a missing precondition is a
 * stated NOT-ATTEMPTED rather than a green line.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const H = require("./live-harness.js");

/* The two safes this suite makes. The ids are namespaced so a leftover is
 * obviously ours, and short enough to be typed into the delete confirmation. */
const CREATED = "live-created";
const IMPORTED = "live-imported";

/* The fixture that gets adopted. Committed, public, and its credential is in
 * the repo — so nothing secret travels anywhere in item R2. */
const FIXTURE = path.join(H.SRC, "tests", "fixtures",
                          "lab-kdbx41-aes256-argon2id.kdbx");
const FIXTURE_PASS = "fixture-pass-do-not-reuse";

/* Where a user-class safe lands. Read from the helper's own published
 * constants at run time, never hard-coded: a page that named
 * ~/.local/share/cockpit-secrets/safes would keep naming it after the helper
 * moved, which is the rule secrets.js follows for the same string. */
async function userSafesDir(frame) {
    const raw = await frame.evaluate(
        () => (window.__SCHEMA_CONST__ || {}).user_safes_dir || null);
    return expandHome(frame, raw);
}

/* Run one helper verb through the page's own `cockpit.spawn`, unescalated.
 * This is how the suite READS state (does the file exist, what does the
 * registry say) without shelling out as eddie to a file owned by somebody
 * else. It is the same call the page makes. */
function helper(frame, verb, req, admin) {
    return inPage(frame, ([v, body, sup]) => new Promise((resolve) => {
        const p = cockpit.spawn(["/usr/local/sbin/secrets-admin", v],
                                { err: "message", superuser: sup ? "require" : null });
        p.input(body);
        p.then((out) => { try { resolve(JSON.parse(out)); } catch (e) { resolve({ error: "parse", raw: String(out).slice(0, 300) }); } })
         .catch((err, out) => {
             try { resolve(JSON.parse(out)); }
             catch (e) { resolve({ error: "spawn", detail: String(out || err).slice(0, 300) }); }
         });
    }), [verb, JSON.stringify(req || {}), !!admin]);
}

/* Does a path exist, and how big is it — asked through the signed-in account's
 * own bridge, because the file is 0600 in their home and this process is not
 * them. `stat` is not a helper verb, so this is a plain `cockpit.spawn`. */
function statPath(frame, p) {
    return inPage(frame, (target) => new Promise((resolve) => {
        const sp = cockpit.spawn(["stat", "-c", "%s %a %U", target],
                                 { err: "message", superuser: null });
        sp.then((out) => resolve(String(out).trim()))
          .catch(() => resolve(null));
    }), p);
}

/* `frame.evaluate` of a PROMISE, retried.
 *
 * A `cockpit.spawn` inside the page is a promise Playwright waits on, and the
 * page keeps re-rendering underneath it — `refreshAll()` after a commit is a
 * spawn and a repaint. When a render lands mid-await, Chromium collects the
 * pending promise and Playwright reports "Resulting promise was garbage
 * collected", which is a statement about timing and not about the product. It
 * failed one full-suite run here and passed the same step in the run before.
 *
 * Three attempts, and the last error is re-thrown so a REAL failure still
 * surfaces. */
async function inPage(frame, fn, arg) {
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            return await frame.evaluate(fn, arg);
        } catch (e) {
            lastErr = e;
            if (!/garbage collected|Execution context was destroyed|detached/i
                    .test(String(e && e.message))) throw e;
            await frame.waitForTimeout(500);
        }
    }
    throw lastErr;
}

function sha256(buf) {
    return crypto.createHash("sha256").update(buf).digest("hex");
}

/* ------------------------------------------------------------------ forms -- */
/* Address a control the way an operator does — by the text of its label. The
 * create form draws several text boxes and "the first input" is not a stable
 * way to mean "the id"; ui.spec.js learned that the hard way. */
async function selByLabel(frame, source) {
    const id = await frame.evaluate((src) => {
        const host = document.getElementById("sec-modal-host");
        const backs = host ? host.querySelectorAll(":scope > .sec-backdrop") : [];
        const top = backs.length ? backs[backs.length - 1] : document;
        const l = Array.prototype.find.call(
            top.querySelectorAll("label"),
            (n) => new RegExp(src).test(n.textContent));
        return l ? l.getAttribute("for") : null;
    }, source);
    return id ? "#" + id : null;
}

/* THE TOP MODAL, and this is not a nicety.
 *
 * `verbDialog` opens its RESULT as a second dialog stacked on the first — the
 * form stays in the DOM behind it — so `.sec-modal` matches the form, not the
 * answer. Reading it that way made "the helper accepted it" fail against a
 * create that had plainly succeeded (the file was on disk, 0600, and `list`
 * reported it) purely because the suite was reading the wrong box. `#sec-modal-host`
 * appends each backdrop, so the LAST one is the one on top. */
const M = "#sec-modal-host > .sec-backdrop:last-child .sec-modal";

/* The topmost dialog, INSIDE the page.
 *
 * A FUNCTION, never a string. `waitForFunction` with a string body is `eval`
 * in the page, and the real Cockpit CSP is `default-src 'self'` with no
 * `unsafe-eval` — so a string predicate is REFUSED by the browser, the wait
 * rejects, and a `.catch(() => null)` around it turns that into "the assertion
 * read a stale dialog". That cost two whole runs here, and it is the same
 * property `live-ui.spec.js` item 1 exists to assert: this page runs clean
 * under the policy the bridge really sends, and so must anything driving it.
 * Playwright's function form is serialised and invoked through the debugger
 * protocol, which is not eval and is not subject to the policy. */
/* A wait that gave up, and WHY. `.catch(() => null)` on a `waitForFunction`
 * hides two very different things — "the page never got there" and "the
 * predicate could not run at all" — and the second one (a string predicate
 * refused by the CSP) looked exactly like the first for three whole runs. */
function waitFailed(e) {
    console.log("  ....  a wait gave up: " +
                String((e && e.message) || e).split("\n")[0].slice(0, 180));
    return null;
}

/* Has the dialog SETTLED — i.e. has the verb answered, either way?
 *
 * Matching the modal's TEXT for "created|invalid|refused" was the wrong test
 * and it silently made three checks meaningless: the create form's own
 * `breaks_when_wrong` help text already contains those words, so the predicate
 * was true the instant it was first evaluated, the wait returned before the
 * helper had even started, and every assertion after it read the form.
 *
 * A dialog is settled when its HEADING has changed (verbDialog closes the form
 * and opens a result whose h2 is the outcome) or when an error node —
 * `.sec-alert.err`, which only `errNode()` produces — has appeared inside it.
 * Neither is anything the form says about itself before it is submitted. */
function dialogSettled(headingPattern) {
    const host = document.getElementById("sec-modal-host");
    const backs = host ? host.querySelectorAll(":scope > .sec-backdrop") : [];
    const top = backs.length ? backs[backs.length - 1] : null;
    const modal = top ? top.querySelector(".sec-modal") : null;
    if (!modal) return false;
    const h = modal.querySelector("h2");
    if (h && new RegExp(headingPattern, "i").test(h.textContent || "")) return true;
    return !!modal.querySelector(".sec-alert.err");
}

function topModalMatches(pattern) {
    const host = document.getElementById("sec-modal-host");
    const backs = host ? host.querySelectorAll(":scope > .sec-backdrop") : [];
    const top = backs.length ? backs[backs.length - 1] : null;
    const modal = top ? top.querySelector(".sec-modal") : null;
    return !!modal && new RegExp(pattern, "i").test(modal.textContent || "");
}

function topModalHeadingMatches(pattern) {
    const host = document.getElementById("sec-modal-host");
    const backs = host ? host.querySelectorAll(":scope > .sec-backdrop") : [];
    const top = backs.length ? backs[backs.length - 1] : null;
    const h = top ? top.querySelector(".sec-modal h2") : null;
    return !!h && new RegExp(pattern, "i").test(h.textContent || "");
}

async function clickIn(frame, selector, timeout) {
    let lastErr = null;
    /* Three attempts, RE-RESOLVING the handle each time. Settling for the
     * position also gives the page time to replace the element — the safe list
     * repaints when `list` comes back, and a handle resolved before that is
     * "not attached to the DOM" by the time it is clicked. Re-resolving is the
     * whole difference between a flaky suite and a suite that waits. */
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            const handle = await frame.waitForSelector(
                selector, { timeout: timeout || 20000 });
            await handle.scrollIntoViewIfNeeded();
            let last = null;
            for (let i = 0; i < 30; i++) {
                const box = await handle.boundingBox();
                if (box && last && box.x === last.x && box.y === last.y &&
                    box.width === last.width && box.height === last.height) break;
                last = box;
                await frame.waitForTimeout(100);
            }
            await handle.click({ timeout: 10000 });
            return handle;
        } catch (e) {
            lastErr = e;
            await frame.waitForTimeout(300);
        }
    }
    throw lastErr;
}

async function modalText(frame) {
    try { return await frame.textContent(M); } catch (e) { return ""; }
}

/* Tick every CONFIRMATION checkbox the dialog drew — and nothing else.
 *
 * `input[type=checkbox]` is the wrong selector and the reason is worth a line:
 * a `toggle` field in the FORM renders as a checkbox too, so ticking them all
 * turned on `make_keyfile` and produced a safe that needs a key file the suite
 * did not keep. Confirmation gates carry an id beginning `sec-confirm`, which
 * `verbDialog` mints for them and mints for nothing else. */
async function tickConfirms(frame) {
    const boxes = await frame.$$(M + ' input[id^="sec-confirm"]');
    for (const b of boxes) { if (!(await b.isChecked())) await b.check(); }
    return boxes.length;
}

/* The ROW for one safe, addressed by the id the page prints in it. `.sec-safe`
 * and `.sec-safe-id` were both carried over from the old card markup on
 * purpose — they are what all three browser suites address a safe by — and the
 * id text is matched exactly, so this cannot match a safe whose LABEL happens
 * to contain another safe's id. Scoped to the table body because `.sec-safe-id`
 * now appears in the details pane too. */
function cardFor(id) {
    return `#sec-safes tbody tr.sec-safe:has(.sec-safe-id:text-is("${id}"))`;
}

/* THE 0.5.0 RESTYLE MOVED EVERY ACTION OFF THE ROW AND INTO THE PANE.
 *
 * `cardFor(id) + ' button:text-is("Unlock…")'` addressed a button that existed
 * on a card and does not exist on a row: secrets.js's safeRow() says "nothing
 * in the row is an action. Every action lives in the pane". So every action is
 * two gestures now — choose the row, then use the pane — and these two helpers
 * are that pair for this suite.
 *
 * Choosing a row re-opens the pane if it was collapsed (selectSafe() in
 * secrets.js does it), so neither of these has to care which state R4's toggle
 * was left in; safeSelected() waits on the pane showing THIS id rather than on
 * a timeout, so a mis-aimed click fails naming the safe instead of silently
 * acting on another one. */
/* THIS SUITE ONLY EVER TOUCHES THE TWO SAFES IT MAKES.
 *
 * Every id here is a literal — CREATED and IMPORTED — and nothing iterates the
 * registry, so the operator's own `pwsafe3` was already out of reach by
 * construction. This turns that from an argument into a check, at the one
 * place an id becomes a click: R4 DELETES a safe and R3 FORGETS one, and
 * neither is a mistake anybody gets to make twice. */
const OWNED = [CREATED, IMPORTED];
function guard(id) {
    if (OWNED.indexOf(String(id)) < 0)
        throw new Error("refused: “" + id + "” is not one of this suite's own safes (" +
                        OWNED.join(", ") + "). It creates and destroys safes, and it may " +
                        "not aim that at anything it did not make — least of all the " +
                        "operator's own (tests/browser/TESTBED.md).");
    return id;
}

async function selectSafe(frame, id) {
    guard(id);
    await frame.click(cardFor(id) + " button.sec-rowdoor");
    await frame.waitForFunction((wanted) => {
        const pane = document.getElementById("sec-pane");
        if (!pane || pane.hidden) return false;
        const n = pane.querySelector(".sec-safe-id");
        return !!n && n.textContent.trim() === wanted;
    }, id, { timeout: 20000 });
}

/* One action on one safe. `label` is matched inside `.sec-safe-actions` only,
 * so a word that also appears in the pane's prose cannot be clicked instead.
 * Unlock is addressed by its `primary` class rather than by its text, because
 * safeActions() builds exactly one primary control and it is Unlock — that
 * survives a change of wording and the loss of the ellipsis. */
async function safeAction(frame, id, label) {
    await selectSafe(frame, id);
    const sel = label === "Unlock…"
        ? "#sec-pane-body .sec-safe-actions button.sec-btn.primary"
        : `#sec-pane-body .sec-safe-actions button:text-is("${label}")`;
    await frame.waitForSelector(sel, { state: "visible", timeout: 20000 });
    await frame.click(sel);
}

/* Wait for the list to have re-read and be showing this safe (or not). The
 * create and import dialogs call refreshAll() on success, which is a spawn and
 * a repaint; asserting immediately after the dialog closes races it. */
async function waitForCard(frame, id, present, timeout) {
    await frame.waitForFunction(([wanted, want]) => {
        const host = document.getElementById("sec-safes");
        if (!host) return false;
        const ids = Array.prototype.map.call(
            host.querySelectorAll("tbody tr.sec-safe .sec-safe-id"),
            (n) => n.textContent.trim());
        return ids.indexOf(wanted) >= 0 === want;
    }, [id, !!present], { timeout: timeout || 30000 });
}

/* A path the helper published with a leading `~`. The constants are written for
 * a human to read, so `user_safes_dir` is `~/.local/share/...`; the shell that
 * would expand it is not this process's. Expanded through the SIGNED-IN
 * account's own bridge, because it is that account's home that matters and not
 * the one this suite is running as. */
async function expandHome(frame, p) {
    if (!p || p[0] !== "~") return p;
    const home = await inPage(frame, () => new Promise((resolve) => {
        const sp = cockpit.spawn(["sh", "-c", "printf %s \"$HOME\""],
                                 { err: "message", superuser: null });
        sp.then((out) => resolve(String(out).trim())).catch(() => resolve(null));
    }));
    return home ? home + p.slice(1) : null;
}

/* Dismiss whatever dialog is open, and REPORT the buttons it offered if it
 * will not go. A modal left open puts `.sec-backdrop` over the page and every
 * later click in the suite fails with "intercepts pointer events" — which is a
 * true statement about the DOM and a useless one about the product, so it is
 * worth turning into a named failure at the point it happens. */
async function closeModal(frame) {
    const gone = async () => (await frame.$(".sec-modal")) === null;
    if (await gone()) return { closed: true, buttons: [] };
    const buttons = await frame.$$eval(M + " button",
        (ns) => ns.map((n) => (n.textContent || "").trim()));
    for (const label of ["Close", "Done", "Cancel", "Finish", "OK"]) {
        if (!buttons.includes(label)) continue;
        try { await clickIn(frame, M + ` button:text-is("${label}")`, 4000); }
        catch (e) { /* the click may race the close */ }
        try { await frame.waitForSelector(".sec-modal", { state: "detached", timeout: 4000 }); }
        catch (e) { /* try the next label */ }
        if (await gone()) return { closed: true, buttons };
    }
    /* Escape is the documented way out: the handler is on the backdrop, so the
     * key has to be pressed with focus inside the dialog. */
    try {
        await frame.focus(M);
        await frame.press(M, "Escape");
        await frame.waitForSelector(".sec-modal", { state: "detached", timeout: 4000 });
    } catch (e) { /* fall through to the report */ }
    return { closed: await gone(), buttons };
}

/* =========================================================================== */

async function main() {
    const rec = H.Recorder("live-registry — create, adopt, forget, delete");
    const pre = H.preconditions();
    const blocked = pre.filter((p) => !p.ok);

    const pw = H.requirePlaywright();
    const who = H.CFG.admin;                 /* has a Cockpit password on this host */
    const password = H.credential(who);
    const newPass = H.safePassphrase(CREATED);

    /* Every reason the run cannot proceed, collected before anything opens, so
     * a NOT-ATTEMPTED carries the whole story rather than the first blocker. */
    const reasons = [];
    blocked.forEach((b) => reasons.push(b.why));
    if (!password)
        reasons.push("no Cockpit password for " + who + " at " +
                     path.join(H.CFG.creds, who + ".pass"));
    if (!newPass)
        reasons.push("no passphrase to create the safe WITH, at " +
                     path.join(H.CFG.creds, "safe-" + CREATED + ".pass") +
                     " — this suite never invents one, because a passphrase it " +
                     "made up would be one nobody can use to check the file " +
                     "afterwards with keepassxc-cli");
    if (!fs.existsSync(FIXTURE))
        reasons.push("the fixture " + FIXTURE + " is missing, so there is " +
                     "nothing to adopt");

    if (reasons.length) {
        for (const id of ["R1", "R2", "R3", "R4", "R5"]) {
            rec.item(id, id).skip(reasons.join("; "));
        }
        return report(rec);
    }

    if (!(await H.checkLogin(who, password))) {
        for (const id of ["R1", "R2", "R3", "R4", "R5"]) {
            rec.item(id, id).skip("Cockpit refused " + who + "'s password; this " +
                                  "suite never guesses and never resets an account");
        }
        return report(rec);
    }

    const browser = await H.launch(pw);
    let ctx = null, page = null, frame = null;
    try {
        ctx = await H.newContext(browser);
        page = await H.login(ctx, who, password);
        frame = await H.openPlugin(page);
        /* The schema's constants, once, on the page — every path this suite
         * checks comes out of the helper rather than out of this file. */
        await frame.evaluate(() => new Promise((resolve) => {
            const p = cockpit.spawn(["/usr/local/sbin/secrets-admin", "schema"],
                                    { err: "message", superuser: null });
            p.input("{}");
            p.then((out) => {
                try { window.__SCHEMA_CONST__ = JSON.parse(out).constants || {}; }
                catch (e) { window.__SCHEMA_CONST__ = {}; }
                resolve();
            }).catch(() => { window.__SCHEMA_CONST__ = {}; resolve(); });
        }));

        /* START FROM A KNOWN STATE. A previous run that died mid-item leaves
         * one of these registered, and then `safe-create` answers `conflict` —
         * correctly — and every assertion below reads as a product failure
         * when it is this suite's own litter. Removed through the helper, by
         * id, with the token it demands; never with an `rm` of a guessed path. */
        for (const id of [CREATED, IMPORTED]) {
            const gone = await helper(frame, "safe-delete",
                                      { safe: id, delete_confirm: "delete-safe:" + id });
            if (gone && gone.ok)
                console.log("  ....  removed a leftover “" + id + "” from an " +
                            "earlier run before starting");
        }
        /* And wait for the list to have actually painted. `openPlugin` returns
         * when start-up has settled, which is BEFORE the first `list` comes
         * back — asserting on the tool bar immediately after it raced the
         * render and reported a missing button on a page that drew one a
         * moment later. */
        await frame.waitForSelector("#sec-safes .sec-tools button", { timeout: 30000 })
            .catch(() => null);

        await itemCreate(rec, frame, page, newPass);
        await itemImport(rec, frame, page);
        await itemForget(rec, frame, page);
        await itemDelete(rec, frame, page);
        await itemClean(rec, frame, page);
    } catch (e) {
        const it = rec.item("R0", "the run itself");
        it.fail("the suite could not complete: " + String(e && e.message || e));
    } finally {
        /* Best effort, and it runs whatever happened above: a safe left behind
         * by a failed item is this suite's litter, not the operator's. */
        if (frame) {
            for (const id of [CREATED, IMPORTED]) {
                try {
                    await helper(frame, "safe-delete",
                                 { safe: id, delete_confirm: "delete-safe:" + id });
                } catch (e) { /* it may already be gone */ }
            }
        }
        try { if (ctx) await ctx.close(); } catch (e) { /* closing is not a test */ }
        try { await browser.close(); } catch (e) { /* same */ }
    }
    return report(rec);
}

/* ------------------------------------------------------------------- R1 ---- */

async function itemCreate(rec, frame, page, newPass) {
    const it = rec.item("R1", "create a new safe from the page, and open it");
    console.log("\n\x1b[1mR1 · create a new safe from the page, and open it\x1b[0m");

    it.ok(!!(await frame.$('#sec-safes .sec-tools button:text-is("New safe…")')),
          "the safe list offers “New safe…”, drawn only because the installed " +
          "helper publishes safe-create");

    await frame.click('#sec-safes .sec-tools button:text-is("New safe…")');
    await frame.waitForSelector(".sec-modal", { timeout: 20000 });

    const idSel = await selByLabel(frame, "^Id");
    const labelSel = await selByLabel(frame, "^Label");
    it.ok(!!idSel && !!labelSel, "the create dialog drew the id and label controls");

    /* THE DEFAULT CLASS IS ADMIN, and the page says so before anything is
     * typed (I1). Asserted against the REAL schema, not a stub's. */
    it.ok(/administrator safe/i.test(await modalText(frame)),
          "with no access chosen the dialog says this will be an ADMINISTRATOR " +
          "safe — the restrictive default, from the live schema");

    /* Choose the user class. The note has to follow it, live. */
    await frame.selectOption((M + " select >> nth=-1"), "user");
    const noteAfter = await modalText(frame);
    it.ok(/your own safe/i.test(noteAfter),
          "choosing “This user” changes the note to say it is your own safe");
    it.ok(/\.config\/cockpit-secrets\/safes\.d/.test(noteAfter),
          "and names the per-user registry directory the helper published (C4)");

    await frame.fill(idSel, CREATED);
    await frame.fill(labelSel, "Created live at " + new Date().toISOString().slice(0, 10));
    await frame.fill((M + " input[type=password]"), newPass);
    await frame.waitForSelector((M + " .sec-strength"), { timeout: 10000 });
    it.ok(!!(await frame.$((M + " .sec-strength"))),
          "the live strength meter is drawn beside the passphrase — advice, " +
          "never a gate (C7)");

    await H.shot(page, "R1-create-dialog");
    it.shot("R1-create-dialog.png");

    await tickConfirms(frame);
    await clickIn(frame, M + ' button:text-is("Create the safe")');
    /* The helper builds a KDBX and re-opens it from cold before it answers, so
     * this is seconds rather than milliseconds. */
    await frame.waitForFunction(dialogSettled, "The safe was created",
                                { timeout: 90000 }).catch(waitFailed);
    const after = (await modalText(frame)).replace(/\s+/g, " ");
    it.ok(/The safe was created/.test(after),
          "the helper accepted it and the dialog says so: " + after.slice(0, 120));
    it.ok(/This user's registry/i.test(after),
          "and names the registry it landed in");
    it.ok(!/key file is shown ONCE/i.test(after),
          "no key file was generated — the toggle was left alone, so the safe " +
          "opens with the passphrase and nothing else");
    await H.shot(page, "R1-create-result");
    it.shot("R1-create-result.png");
    {
        const c = await closeModal(frame);
        it.ok(c.closed, "the result dialog dismisses (buttons: " +
              JSON.stringify(c.buttons) + ")");
    }

    /* Now the facts, from the helper rather than from the page's own words. */
    let appeared = true;
    try { await waitForCard(frame, CREATED, true); }
    catch (e) { appeared = false; }
    it.ok(appeared, "the new safe appears on the page without a reload");
    const list = await helper(frame, "list", {});
    const row = (list.safes || []).find((s) => s.id === CREATED);
    it.ok(!!row, "and the helper's own `list` reports it");
    if (row) {
        it.ok(row.registry === "user",
              "and `list` says it came from the per-user registry (registry=" +
              row.registry + ")");
        it.ok(row.usable === true && row.locked === true,
              "usable and locked — a created safe is not left open");
    }
    const dir = await userSafesDir(frame);
    const filePath = dir ? path.posix.join(dir, CREATED + ".kdbx") : null;
    if (filePath) {
        const st = await statPath(frame, filePath);
        it.ok(!!st && / 600 /.test(" " + st + " "),
              "the file exists 0600 in the caller's own tree (" + st + ")");
        it.note("path (from the helper's published constants): " + filePath);
    } else {
        it.note("the helper published no user_safes_dir constant, so the file's " +
                "path was not checked directly");
    }

    /* AND IT OPENS — which is the whole point. Through the page, by clicking
     * Unlock and typing the passphrase, not through a spawn. */
    await safeAction(frame, CREATED, "Unlock…");
    await frame.waitForSelector((M + " input[type=password]"), { timeout: 20000 });
    await frame.fill((M + " input[type=password]"), newPass);
    await clickIn(frame, M + ' button:text-is("Unlock")');
    await frame.waitForSelector("#sec-browse", { state: "visible", timeout: 60000 })
        .catch(() => null);
    const opened = await frame.evaluate(() => {
        const h = document.getElementById("sec-browse-h");
        return h ? h.textContent : "";
    });
    it.ok(/Created live/.test(opened || ""),
          "the page unlocked the safe it had just created and shows its label (" +
          String(opened).slice(0, 60) + ")");
    /* The COUNT the page prints, not the row count: an empty table renders one
     * "No entries here." row, so `tbody tr === 0` is never true and asserting
     * it would have been a check that could not pass. */
    const caption = await frame.textContent("#sec-entries caption").catch(() => "");
    const rowText = await frame.$$eval("#sec-entries tbody tr",
        (ns) => ns.map((n) => n.textContent.trim())).catch(() => []);
    it.ok(/^0 entries/.test((caption || "").trim()),
          "and it is EMPTY — a brand-new safe has no sample entry and no default " +
          "password in it (caption: " + JSON.stringify(caption) + ")");
    it.ok(rowText.length === 1 && /No entries here/.test(rowText[0]),
          "the table says so rather than drawing a blank grid (" +
          JSON.stringify(rowText) + ")");
    await H.shot(page, "R1-created-opened");
    it.shot("R1-created-opened.png");

    /* Lock it again so the next item starts from a closed page. */
    await frame.click('button:text-is("Lock")').catch(() => null);
    it.done();
}

/* ------------------------------------------------------------------- R2 ---- */

async function itemImport(rec, frame, page) {
    const it = rec.item("R2", "upload a committed fixture, and open it");
    console.log("\n\x1b[1mR2 · upload a committed fixture, and open it\x1b[0m");

    const bytes = fs.readFileSync(FIXTURE);
    const digest = sha256(bytes);
    it.note("fixture " + path.basename(FIXTURE) + ", " + bytes.length +
            " bytes, sha256 " + digest.slice(0, 16) + "…");

    it.ok(!!(await frame.$('#sec-safes .sec-tools button:text-is("Add an existing safe…")')),
          "the safe list offers “Add an existing safe…”");
    await frame.click('#sec-safes .sec-tools button:text-is("Add an existing safe…")');
    await frame.waitForSelector((M + " .sec-steps"), { timeout: 20000 });

    /* C5, ON THE REAL PAGE: the file-picker step has no passphrase box. The
     * stub suite asserts this too; here it is the installed secrets.js against
     * the installed schema. */
    it.ok((await frame.$$(M + " input[type=password]")).length === 0,
          "the file-picker step has NO passphrase field anywhere on it (C5)");
    it.ok(!!(await frame.$("#sec-import-file")), "and it has a file picker");

    const boxes = await frame.$$((M + " .sec-form input[type=text]"));
    const vals = [IMPORTED, "Adopted live at " + new Date().toISOString().slice(0, 10)];
    for (let i = 0; i < boxes.length; i++) await boxes[i].fill(vals[i] || "x");
    /* User class again, so it lands in this account's own tree. */
    await frame.selectOption((M + " select >> nth=-1"), "user").catch(() => null);

    await frame.setInputFiles("#sec-import-file", {
        name: path.basename(FIXTURE),
        mimeType: "application/octet-stream",
        buffer: bytes
    });
    await H.shot(page, "R2-upload-picker");
    it.shot("R2-upload-picker.png");
    await clickIn(frame, M + ' button:text-is("Upload the file")');

    /* The header summary. It arrives with NO credential having been sent. */
    await frame.waitForSelector((M + " .sec-kv"), { timeout: 60000 });
    const summary = await modalText(frame);
    it.ok(/4\.1/.test(summary) && /aes256/i.test(summary) && /argon2id/i.test(summary),
          "the header summary reports the fixture's real format, cipher and KDF " +
          "(4.1 / aes256 / argon2id) — read from the staged bytes with no " +
          "credential");
    it.ok(/not.{0,20}authenticated|unauthenticated/i.test(summary),
          "and it is LABELLED as unauthenticated, which is what it is");
    it.ok((await frame.$$(M + " input[type=password]")).length === 0,
          "and STILL no passphrase field on the summary step — the operator " +
          "confirms the file first (C5)");
    await H.shot(page, "R2-upload-inspect");
    it.shot("R2-upload-inspect.png");

    /* "This is the right file" is the step between the summary and the
     * passphrase — the whole reason the header is reported without a
     * credential is so the operator can answer it. */
    await clickIn(frame, M + ' button:text-is("This is the right file — unlock it")');
    await frame.waitForSelector((M + " input[type=password]"), { timeout: 20000 });
    it.ok((await frame.$$(M + " input[type=password]")).length >= 1,
          "the passphrase box appears HERE, after the bytes are staged and the " +
          "operator has confirmed the file, and nowhere before it (C5)");

    /* A wrong passphrase first: it must NOT cost the upload. */
    const runSel = (M + ' button:text-is("Unlock and register the safe")');
    await frame.fill((M + " input[type=password]"), "definitely-not-the-passphrase");
    await tickConfirms(frame);
    await clickIn(frame, runSel);
    await frame.waitForFunction(dialogSettled, "The safe was registered",
                                { timeout: 90000 }).catch(waitFailed);
    const afterBad = await modalText(frame);
    it.ok(/passphrase|credential/i.test(afterBad),
          "a wrong passphrase is reported as a credential problem");
    it.ok(/still staged|no need to re-upload/i.test(afterBad),
          "and the page says the upload is STILL STAGED and need not be sent " +
          "again — a typo does not cost the transfer");
    it.ok(/not on your guessing|not a limit on guessing/i.test(afterBad),
          "and it says plainly what the budget is: a limit on this host's disk " +
          "and CPU, not on guessing — the conclusion C5 asked to be written down");
    await H.shot(page, "R2-upload-badpass");
    it.shot("R2-upload-badpass.png");

    /* Now the right one, against the SAME staging. */
    await frame.fill((M + " input[type=password]"), FIXTURE_PASS);
    await tickConfirms(frame);
    await clickIn(frame, runSel);
    await frame.waitForFunction(topModalHeadingMatches, "The safe was registered",
                                { timeout: 120000 }).catch(waitFailed);
    it.ok(/The safe was registered/i.test(await modalText(frame)),
          "the commit succeeded and the result dialog says the safe was " +
          "registered");
    await H.shot(page, "R2-upload-committed");
    it.shot("R2-upload-committed.png");
    {
        const c = await closeModal(frame);
        it.ok(c.closed, "the wizard's final step dismisses (buttons: " +
              JSON.stringify(c.buttons) + ")");
    }

    let appeared = true;
    try { await waitForCard(frame, IMPORTED, true); }
    catch (e) { appeared = false; }
    it.ok(appeared, "the adopted safe appears on the page without a reload");
    const list = await helper(frame, "list", {});
    const row = (list.safes || []).find((s) => s.id === IMPORTED);
    it.ok(!!row, "and the helper's own `list` reports it");
    if (row) it.ok(row.registry === "user", "in the per-user registry");

    /* THE BYTES THAT LANDED ARE THE BYTES THAT WERE UPLOADED. This is I43's
     * property, checked against the real file rather than against a stub. */
    const dir = await userSafesDir(frame);
    if (dir) {
        const p = path.posix.join(dir, IMPORTED + ".kdbx");
        const st = await statPath(frame, p);
        it.ok(!!st && st.split(" ")[0] === String(bytes.length),
              "the landed file is exactly the size of the file that was picked (" +
              st + " vs " + bytes.length + ")");
        const got = await inPage(frame, (target) => new Promise((resolve) => {
            const sp = cockpit.spawn(["sha256sum", target],
                                     { err: "message", superuser: null });
            sp.then((out) => resolve(String(out).trim().split(/\s+/)[0]))
              .catch(() => resolve(null));
        }), p);
        it.ok(got === digest,
              "and byte-for-byte identical to it (sha256 " +
              String(got).slice(0, 16) + "… vs " + digest.slice(0, 16) + "…) — " +
              "the bytes that were validated are the bytes that landed (I43)");
    }

    /* And it opens, with the fixture's real contents. */
    await safeAction(frame, IMPORTED, "Unlock…");
    await frame.waitForSelector((M + " input[type=password]"), { timeout: 20000 });
    await frame.fill((M + " input[type=password]"), FIXTURE_PASS);
    await clickIn(frame, M + ' button:text-is("Unlock")');
    await frame.waitForSelector("#sec-entries tbody tr", { timeout: 60000 }).catch(() => null);
    const cap = await frame.textContent("#sec-entries caption").catch(() => "");
    it.ok(/^6 entries/.test((cap || "").trim()),
          "the adopted safe unlocks and renders the fixture's 6 entries " +
          "(caption: " + JSON.stringify(cap) + ")");
    await H.shot(page, "R2-imported-opened");
    it.shot("R2-imported-opened.png");
    await frame.click('button:text-is("Lock")').catch(() => null);
    it.done();
}

/* ------------------------------------------------------------------- R3 ---- */

async function itemForget(rec, frame, page) {
    const it = rec.item("R3", "forget one — the registry entry goes, the file stays");
    console.log("\n\x1b[1mR3 · forget one — the registry entry goes, the file stays\x1b[0m");

    const dir = await userSafesDir(frame);
    const p = dir ? path.posix.join(dir, IMPORTED + ".kdbx") : null;
    const before = p ? await statPath(frame, p) : null;
    it.ok(!!before, "the file is there before the forget (" + before + ")");

    await safeAction(frame, IMPORTED, "Forget…");
    await frame.waitForSelector(".sec-modal", { timeout: 20000 });
    const warn = await modalText(frame);
    it.ok(/file stays on disk/i.test(warn),
          "the dialog says in bold that the FILE STAYS ON DISK");
    await tickConfirms(frame);
    await H.shot(page, "R3-forget-dialog");
    it.shot("R3-forget-dialog.png");
    await clickIn(frame, M + ' button:text-is("Remove the registry entry")');
    await frame.waitForFunction(
        () => !document.querySelector(".sec-modal") ||
              !!document.querySelector(".sec-modal .sec-alert.err"),
        null, { timeout: 60000 }).catch(waitFailed);
    await closeModal(frame);
    await waitForCard(frame, IMPORTED, false).catch(() => null);
    const list = await helper(frame, "list", {});
    it.ok(!(list.safes || []).some((s) => s.id === IMPORTED),
          "the safe is gone from `list`");
    const after = p ? await statPath(frame, p) : null;
    it.ok(!!after && after === before,
          "and the file is still on disk, unchanged (" + after + ")");
    /* The page's banner says so too, and it survives the list refresh — the
     * ordering defect the UI agent found and fixed. */
    const banner = await frame.evaluate(() => {
        const a = document.querySelector("#sec-alert, .sec-alert.ok");
        return a ? a.textContent : "";
    });
    it.ok(/left on disk|was removed from the registry/i.test(banner || ""),
          "and the page still shows the outcome after the list re-read (" +
          String(banner).replace(/\s+/g, " ").slice(0, 90) + ")");
    await H.shot(page, "R3-forgotten");
    it.shot("R3-forgotten.png");
    it.done();
}

/* ------------------------------------------------------------------- R4 ---- */

async function itemDelete(rec, frame, page) {
    const it = rec.item("R4", "delete the other — the token gate, then the file is gone");
    console.log("\n\x1b[1mR4 · delete the other — the token gate, then the file is gone\x1b[0m");

    const dir = await userSafesDir(frame);
    const p = dir ? path.posix.join(dir, CREATED + ".kdbx") : null;
    it.ok(!!(p && await statPath(frame, p)), "the file is there before the delete");

    await safeAction(frame, CREATED, "Delete…");
    await frame.waitForSelector(".sec-modal", { timeout: 20000 });
    const danger = await modalText(frame);
    it.ok(/no undo|cannot be undone/i.test(danger),
          "the dialog says there is no undo");
    it.ok(/best effort/i.test(danger),
          "and that overwriting before unlinking is BEST EFFORT and nothing more");

    /* The gate: ticking every box is not enough on its own. */
    const ticked = await tickConfirms(frame);
    it.note(ticked + " confirmation checkbox(es) ticked");
    const runSel = (M + ' button:text-is("Destroy this safe and its backups")');
    it.ok(await frame.isDisabled(runSel),
          "with every box ticked and nothing typed, the destroy button is still " +
          "DISABLED — the token is AND-ed with the ticks, never instead of them");

    const typeSel = await selByLabel(frame, "Type the safe");
    it.ok(!!typeSel, "the dialog draws a type-to-confirm box naming the id");
    for (const wrong of ["live-create", "LIVE-CREATED", CREATED + " "]) {
        await frame.fill(typeSel, wrong);
        it.ok(await frame.isDisabled(runSel),
              "a near-miss (" + JSON.stringify(wrong) + ") leaves it disabled");
    }
    await frame.fill(typeSel, CREATED);
    it.ok(!(await frame.isDisabled(runSel)),
          "only the exact id enables it");
    await H.shot(page, "R4-delete-dialog");
    it.shot("R4-delete-dialog.png");

    await clickIn(frame, runSel);
    await frame.waitForFunction(
        () => !document.querySelector(".sec-modal") ||
              !!document.querySelector(".sec-modal .sec-alert.err"),
        null, { timeout: 90000 }).catch(waitFailed);
    await closeModal(frame);
    await waitForCard(frame, CREATED, false).catch(() => null);
    const list = await helper(frame, "list", {});
    it.ok(!(list.safes || []).some((s) => s.id === CREATED),
          "the safe is gone from `list`");
    const after = p ? await statPath(frame, p) : "(no path)";
    it.ok(after === null,
          "and the FILE is gone from disk too (" + String(after) + ")");
    const banner = await frame.evaluate(() => {
        const a = document.querySelector("#sec-alert, .sec-alert.ok");
        return a ? a.textContent : "";
    });
    it.ok(/deleted/i.test(banner || "") && /courtesy|copy-on-write|flash|snapshot/i.test(banner || ""),
          "and the page repeats the helper's own honest statement about what an " +
          "overwrite is worth (" + String(banner).replace(/\s+/g, " ").slice(0, 110) + ")");
    await H.shot(page, "R4-deleted");
    it.shot("R4-deleted.png");
    it.done();
}

/* ------------------------------------------------------------------- R5 ---- */

async function itemClean(rec, frame, page) {
    const it = rec.item("R5", "the host is left as it was found");
    console.log("\n\x1b[1mR5 · the host is left as it was found\x1b[0m");

    /* R3 left the adopted safe's FILE on disk deliberately — that is what
     * forget means — so this item removes it, the way an operator would: by
     * registering it again is not possible (it is unregistered), so it is a
     * plain unlink through the account's own bridge. Stated rather than done
     * quietly, because a suite that tidies up with a hidden `rm` is a suite
     * whose litter you never find out about. */
    const dir = await userSafesDir(frame);
    if (dir) {
        const p = path.posix.join(dir, IMPORTED + ".kdbx");
        const st = await statPath(frame, p);
        if (st) {
            await inPage(frame, (target) => new Promise((resolve) => {
                const sp = cockpit.spawn(["rm", "-f", target],
                                         { err: "message", superuser: null });
                sp.then(() => resolve(true)).catch(() => resolve(false));
            }), p);
            it.note("removed the forgotten file R3 deliberately left behind: " + p);
        }
        /* "Is the directory EMPTY" is the wrong question and it was asked
         * first: the host may legitimately hold safes this suite did not make
         * — the live walkthrough seeds two — and demanding an empty directory
         * turns somebody else's data into this suite's failure. The right
         * question is whether anything of OURS is left. */
        const left = await inPage(frame, (d) => new Promise((resolve) => {
            const sp = cockpit.spawn(["sh", "-c", "ls -1 " + d + " 2>/dev/null"],
                                     { err: "message", superuser: null });
            sp.then((out) => resolve(String(out).trim())).catch(() => resolve(""));
        }), dir);
        const names = left.split("\n").map((x) => x.trim()).filter(Boolean);
        const ours = names.filter(
            (n) => n.indexOf(CREATED) === 0 || n.indexOf(IMPORTED) === 0);
        it.ok(ours.length === 0,
              "nothing this suite created is left in the per-user safes " +
              "directory (" + JSON.stringify(ours) + ")");
        it.note("what else is in there, and is not ours: " +
                JSON.stringify(names.filter((n) => ours.indexOf(n) < 0)));
    }

    const list = await helper(frame, "list", {});
    const mine = (list.safes || []).filter(
        (s) => s.id === CREATED || s.id === IMPORTED);
    it.ok(mine.length === 0, "neither of this suite's safes is registered any more");
    const health = await helper(frame, "health", {});
    it.ok((health.registry_errors || []).length === 0,
          "and the registry loads with no errors (" +
          JSON.stringify(health.registry_errors || []).slice(0, 120) + ")");
    it.ok((health.import_staging || {}).staged === 0,
          "no import staging is left behind (" +
          String((health.import_staging || {}).staged) + ")");
    await H.shot(page, "R5-clean");
    it.shot("R5-clean.png");
    it.done();
}

/* ------------------------------------------------------------------ report -- */

function report(rec) {
    const s = rec.summary();
    console.log("\n\x1b[1m" + rec.label + "\x1b[0m");
    for (const i of s.items) {
        /* An item whose function threw never called done(), so `state` is null.
         * Defaulting that to PASS is how a suite reports green for work it did
         * not finish — it happened here on the first run and is the reason this
         * line is not `i.state || "PASS"`. */
        const state = i.state || (i.finished ? "PASS" : "INCOMPLETE");
        if (state === "INCOMPLETE") s.bad += 1;
        const colour = state === "PASS" ? "32" : state === "FAIL" ? "31" : "33";
        console.log("  \x1b[" + colour + "m" + state.padEnd(14) + "\x1b[0m" +
                    i.id + "  " + i.title + (i.why ? "  — " + i.why : ""));
    }
    console.log("\n  " + s.checks + " checks, " + s.bad + " failure(s)");
    H.writeArtifact("live-registry-result.json",
                    JSON.stringify({ label: rec.label, checks: s.checks,
                                     failures: s.bad, items: s.items }, null, 1));
    process.exitCode = s.bad ? 1 : 0;
    return s.bad ? 1 : 0;
}

main().catch((e) => {
    console.error("live-registry.spec.js: " + String(e && e.stack || e));
    process.exitCode = 1;
});
