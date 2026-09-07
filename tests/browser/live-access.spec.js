/* tests/browser/live-access.spec.js — the two items a stub can never do.
 *
 *   node tests/browser/live-access.spec.js      (or: ./tests/browser/run-live.sh)
 *
 * Item 8. THE NON-ADMIN REFUSAL (I3). `cptest` is not in `sudo`. The admin-class
 * safe must be refused, and refused twice over: once in the page, which is the
 * cosmetic half, and once when the verb is driven straight from the console
 * with `cockpit.spawn` — the same thing a person with devtools open would do.
 * The second half is the whole point. cockpit-guac-rdp shipped an
 * `if (t.admin && !isAdmin)` in JavaScript and it was bypassable; the register
 * says so in as many words. A refusal that only exists in the renderer is not a
 * refusal, and the only way to know which kind this is, is to go around the
 * renderer and look.
 *
 * Item 9. ESCALATION. With Cockpit's Administrative access OFF, an admin-class
 * safe must produce COCKPIT'S OWN prompt — the bridge's, drawn by the shell —
 * and not a bespoke error box invented by this page. With it on, the safe
 * opens. The stub suite records `superuser:"require"` and never honours it, so
 * this path has never run for real anywhere else in the tree.
 *
 * Both items need a session in a state the other suite has already left behind:
 * item 8 needs a different principal, item 9 needs one that has NOT escalated
 * yet. Hence a separate file rather than two more steps bolted onto a session
 * that is already root.
 */
"use strict";

const H = require("./live-harness.js");
const U = require("./live-ui.spec.js");
const path = require("path");

const REC = H.Recorder("live-access");

const ITEMS = {
    8: "The non-admin refusal (I3): refused in the UI AND when driven from devtools",
    9: "Escalation: refused with no prompt while access is off, then Cockpit's own header control grants it and the admin safe opens"
};
const ORDER = [8, 9];

function skipAll(why) {
    ORDER.forEach((k) => { const it = REC.item(k, ITEMS[k]); it.skip(why); it.done(); });
}

/* --------------------------------------------------------------- item 8 -- */
async function item8(browser) {
    const it = REC.item(8, ITEMS[8]);
    console.log("\n== 8. " + ITEMS[8] + " ==");

    const pass = H.credential(H.CFG.user);
    if (!pass) {
        it.skip("no credential file at " + path.join(H.CFG.creds, H.CFG.user + ".pass") +
                " — the non-admin principal cannot be signed in, and this suite will not " +
                "guess a password or reset an account.");
        it.done();
        return;
    }
    if (!(await H.checkLogin(H.CFG.user, pass))) {
        it.skip("Cockpit refused " + H.CFG.user + " with the credential in " + H.CFG.creds + ".");
        it.done();
        return;
    }

    const ctx = await H.newContext(browser);
    try {
        const page = await H.login(ctx, H.CFG.user, pass);
        const frame = await H.openPlugin(page);
        /* openPlugin() waits for the SCHEMA; the card comes from `list`, which is
         * a different spawn. Counting or reading cards without this reads a
         * page still saying "Loading the safe registry…". */
        await U.waitForSafeList(frame);

        /* Establish the principal really is the non-admin one, from the kernel's
         * point of view and not from a variable in this file. */
        const who = await frame.evaluate(() => new Promise((resolve) => {
            const p = cockpit.spawn(["id"], { err: "message" });
            p.then((o) => resolve(String(o).trim())).catch(() => resolve("(unreadable)"));
        }));
        it.note("the page's bridge runs as: " + who);
        it.ok(!/\(sudo\)/.test(who),
              H.CFG.user + " is not in `sudo` — this is genuinely the non-admin principal");

        const list = await H.liveList(frame);
        /* Never the operator's own safe, whatever the registry says — the
         * exclusion list lives in live-ui.spec.js so all three suites share
         * one answer (see the note beside EXCLUDED_SAFES there). */
        const admins = ((list && list.safes) || [])
            .filter((s) => U.classOf(s) === "admin" && !U.excluded(s.id));
        if (!admins.length) {
            it.skip("the registry declares no admin-class safe, so there is nothing for a " +
                    "non-admin to be refused. Seeding one is root work and belongs to the " +
                    "install task.");
            it.done();
            return;
        }
        const target = admins[0];
        it.note("target admin-class safe: " + target.id +
                " (list says usable=" + target.usable + ", reason=" +
                JSON.stringify(target.reason || "") + ")");

        /* --- half one: the page ----------------------------------------
         * Deliberately NOT the assertion this item turns on. The page's own
         * footer says it: "what is greyed out here is decoration", and an
         * admin-class card is drawn enabled on purpose, because an unescalated
         * `list` cannot tell an operator who may escalate from one who may not
         * and a permanently disabled control is how the default access class
         * became unopenable. What is checked here is that the helper's SENTENCE
         * reaches the operator either way. */
        const card = U.cardFor(frame, target.id);
        if (await card.count()) {
            /* 0.5.0: the row carries the state and the PANE carries the
             * control and the sentence, so the safe has to be chosen before
             * either can be read. */
            const cls = (await card.first().getAttribute("class")) || "";
            await U.selectSafeRow(frame, target.id);
            const disabled = await U.unlockButton(frame).isDisabled();
            it.note("the row is rendered " + (/unreachable/.test(cls) ? "unreachable" : "reachable") +
                    " with the pane's Unlock control " + (disabled ? "disabled" : "enabled"));
            const reason = (await frame.locator("#sec-pane-body").innerText()).trim();
            it.ok(/administrator-class|Administrative access/i.test(reason),
                  "the pane tells the operator what stands in the way: " +
                  JSON.stringify(reason.replace(/\s+/g, " ").slice(0, 200)));
        } else {
            /* R1 — and this is now the EXPECTED branch for a non-admin, not a
             * fallback. An administrator safe is not drawn at all while
             * Cockpit's administrative access is off, so the sentence an
             * unelevated operator gets is the count-only line, not a card. It
             * is asserted rather than merely noted, because "hiding is
             * permitted" must not become "the page said nothing at all".
             * live-ui.spec.js item 2 asserts the same panel in full. */
            const said = (await frame.locator("#sec-safes").innerText().catch(() => "")).trim()
                            .replace(/\s+/g, " ");
            it.note("the page draws no row for " + target.id + " for this principal — R1 hides " +
                    "administrator safes while administrative access is off. Hiding is " +
                    "permitted; refusing is what matters, and that is half two below.");
            it.ok(/hidden/i.test(said) && /Administrative access|Limited access/i.test(said),
                  "…and it still says so, with a count and the name of the control that " +
                  "would reveal them: " + JSON.stringify(said.slice(0, 200)));
            it.ok(!said.includes(target.id),
                  "…without naming the safe it is hiding — a count, never an inventory");
        }
        it.shot(await H.shot(page, "08-nonadmin-list"));

        /* --- half two: around the page ---------------------------------
         * Exactly what a person with the console open would type. If the only
         * thing standing between cptest and an admin safe were the disabled
         * attribute above, this is where it would open. */
        const direct = [];

        /* (a) unescalated, which is what a browser-side check cannot stop. */
        const a = await U.spawnVerb(frame, "unlock",
            { safe: target.id, password: "anything-at-all" }, null);
        const ao = U.parseMaybe(a.out);
        direct.push({ call: "unlock, superuser omitted", ok: a.ok, answer: ao, problem: a.problem });
        it.ok(!a.ok, "cockpit.spawn unlock WITHOUT escalation is refused");
        it.ok(ao && ao.error === "access-denied",
              "the helper answers " + JSON.stringify(ao && ao.error) +
              " — the refusal comes from the helper's own identity check (I3), not the page");
        if (ao) it.ok(!/traceback|File "/i.test(String(ao.detail || "")),
                      "the refusal is an operator sentence: " +
                      JSON.stringify(String(ao.detail || "").slice(0, 160)));

        /* (b) asking for escalation the account cannot have. Cockpit's bridge
         * refuses this one before the helper is even reached, which is the
         * second, independent gate — and the reason the helper's own check has
         * to exist anyway: a bridge that granted it would find the helper
         * refusing too. */
        const b = await U.spawnVerb(frame, "unlock",
            { safe: target.id, password: "anything-at-all" }, "require");
        const bo = U.parseMaybe(b.out);
        direct.push({ call: 'unlock, superuser:"require"', ok: b.ok, answer: bo, problem: b.problem });
        it.ok(!b.ok, 'cockpit.spawn unlock WITH superuser:"require" is refused too' +
                     (b.problem ? " (channel problem: " + b.problem + ")" : ""));

        /* (c) a read-only verb on the same safe, to show the refusal is about
         * the class and not about the helper being unreachable: `list` answered
         * for this principal a moment ago. */
        const c = await U.spawnVerb(frame, "probe", { safe: target.id }, null);
        const co = U.parseMaybe(c.out);
        direct.push({ call: "probe, superuser omitted", ok: c.ok, answer: co, problem: c.problem });
        it.ok(!c.ok && co && co.error === "access-denied",
              "probe on the same safe is refused the same way (" +
              JSON.stringify(co && co.error) + "), while `list` answered normally — " +
              "the gate is the access class, not the helper being absent");

        /* (d) and the hazard I4 exists for: naming a path instead of an id. */
        const d = await U.spawnVerb(frame, "unlock",
            { safe: "/etc/cockpit-secrets/safes/" + target.id + ".kdbx",
              password: "anything-at-all" }, null);
        const dobj = U.parseMaybe(d.out);
        direct.push({ call: "unlock with a PATH instead of an id", ok: d.ok, answer: dobj });
        it.ok(!d.ok && dobj && /invalid|not-found|access-denied/.test(String(dobj.error)),
              "a path in place of a registry id is refused (" +
              JSON.stringify(dobj && dobj.error) + ") — there is no verb that opens a path (I4)");

        H.writeArtifact("08-direct-calls.json", JSON.stringify(direct, null, 2) + "\n");
        it.note("every direct call recorded to artifacts/08-direct-calls.json");
    } finally {
        await ctx.close();
    }
    it.done();
}

/* --------------------------------------------------------------- item 9 -- */
async function item9(browser) {
    const it = REC.item(9, ITEMS[9]);
    console.log("\n== 9. " + ITEMS[9] + " ==");

    const pass = H.credential(H.CFG.admin);
    if (!pass) {
        it.skip("no credential file at " + path.join(H.CFG.creds, H.CFG.admin + ".pass") + ".");
        it.done();
        return;
    }

    const ctx = await H.newContext(browser);
    try {
        const page = await H.login(ctx, H.CFG.admin, pass);

        /* A fresh Cockpit session starts WITHOUT administrative access unless
         * the operator asked for it at the login screen. That un-escalated
         * state is the whole precondition for this item, so it is asserted
         * rather than assumed. */
        const state = await H.adminAccessState(page);
        it.note("Cockpit's header reports: " + state);
        let frame = await H.openPlugin(page);
        await U.waitForSafeList(frame);

        const perm = await frame.evaluate(() => new Promise((resolve) => {
            const p = cockpit.permission({ admin: true });
            /* `allowed` can be null until the bridge has answered once. */
            setTimeout(() => resolve(p.allowed), 500);
        }));
        it.note("cockpit.permission({admin:true}).allowed === " + JSON.stringify(perm));

        if (perm === true) {
            it.skip("this Cockpit session already has administrative access, so the " +
                    "escalation PROMPT cannot be observed. Cockpit grants it at login when " +
                    "the operator asks for it; forcing the session back to limited access " +
                    "is not something this suite may do to a live service.");
            it.shot(await H.shot(page, "09-already-escalated"));
            it.done();
            return;
        }

        /* --- the page's own words for the un-escalated state ---------------
         * A banner naming the control in Cockpit's header, NOT an error. */
        const banner = (await frame.locator("#sec-banners").innerText().catch(() => "")).trim();
        it.ok(/Administrative access is off/i.test(banner),
              "the page states the situation plainly instead of failing: " +
              JSON.stringify(banner.replace(/\s+/g, " ").slice(0, 200)));
        it.ok(!(await frame.locator("#sec-banners .sec-alert.err").count()),
              "it is a warning, not an error — nothing has failed yet");
        it.shot(await H.shot(page, "09-limited-access"));

        const list = await H.liveList(frame);
        /* Never the operator's own safe, whatever the registry says — the
         * exclusion list lives in live-ui.spec.js so all three suites share
         * one answer (see the note beside EXCLUDED_SAFES there). */
        const admins = ((list && list.safes) || [])
            .filter((s) => U.classOf(s) === "admin" && !U.excluded(s.id));
        if (!admins.length) {
            it.skip("the registry declares no admin-class safe, so escalation has nothing " +
                    "to be required for.");
            it.done();
            return;
        }
        const target = admins[0];

        /* --- WHAT A PACKAGE PAGE CAN AND CANNOT DO, MEASURED ---------------
         *
         * The previous revision of this item waited thirty seconds for
         * Cockpit's password dialog to appear after the page asked for
         * escalation, and failed. That failure was CORRECT and it was the
         * finding: on Cockpit 360 a channel opened with `superuser: "require"`
         * from a session in limited access is refused immediately with
         * `access-denied`, and no dialog is drawn anywhere. The dialog belongs
         * to the shell — it is the component behind the header control, which
         * calls cockpit.Superuser.Start() and listens for its Prompt signal
         * around that one call — and there is no API a package page can use to
         * summon it. The `superuser` module the shipped Cockpit pages import is
         * read-only (allowed / configured / reload_page_on_change).
         *
         * So the assertion is now the true one, in two halves: the page must
         * REPORT that plainly and point at the control that really escalates,
         * and the control that really escalates must then really open the safe.
         * Anything else would be this suite asserting a Cockpit feature that
         * does not exist and calling the page broken for not using it. */
        /* WHERE THIS ITEM'S FIRST HALF NOW LIVES, AND WHY IT HAD TO MOVE.
         *
         * It used to click the admin-class card's "Check this safe", read the
         * `access-denied` the bridge answered with off that card, and check the
         * card named the control that escalates. R1 removed the card: while
         * administrative access is off an administrator safe is NOT DRAWN, so
         * there is nothing to click and nothing to read. secrets.js records the
         * consequence beside the control itself — "while administrative access
         * is off, an admin-class safe is not listed at all, so this control
         * cannot be reached in the state it was built for. The count note and
         * the escalation banner are what an operator sees instead."
         *
         * The assertion is NOT dropped, because what it was really about is
         * still true and still checkable: asking for an admin-class safe from
         * this session is refused by the bridge, the refusal is `access-denied`,
         * no prompt is drawn anywhere by this page, and the operator is left
         * holding the name of the control that would work. The first of those
         * now comes from driving the verb the way the card's button drove it —
         * `probe` with superuser:"require", which is exactly what probeSafe()
         * sends — and the last two from the page's own banner and count line.
         *
         * If the row IS drawn (a Cockpit that lists it, or a future page that
         * shows admin safes greyed), the original gesture is driven instead, so
         * this reads the product rather than a snapshot of it. */
        const row = U.cardFor(frame, target.id).first();
        const rowDrawn = (await row.count()) > 0;
        let refusal = null;
        if (rowDrawn) {
            await U.selectSafeRow(frame, target.id);
            const check = U.paneActions(frame)
                .locator('button:text-is("Check this safe"), button:text-is("Check again")');
            it.ok(await check.count() > 0,
                  "the admin-class safe's pane offers a “Check this safe” control while " +
                  "access is off");
            it.ok(!(await U.unlockButton(frame).isDisabled()),
                  "…and Unlock is NOT permanently disabled — admin is the default class and a " +
                  "session can escalate at any moment");
            await check.first().click();
            refusal = await frame.waitForFunction(() => {
                const a = document.querySelector("#sec-pane-body .sec-alert.err");
                return a ? a.textContent.replace(/\s+/g, " ").trim().slice(0, 300) : null;
            }, null, { timeout: 30000 }).then((h) => h.jsonValue()).catch(() => null);
            it.ok(!!refusal,
                  "asking for it while access is off produces an answer in the pane rather " +
                  "than a silent nothing");
            it.ok(!!refusal && /access-denied/.test(refusal),
                  "the answer is the bridge's refusal, delivered without any prompt: " +
                  JSON.stringify(String(refusal).slice(0, 180)));
            it.ok(!!refusal && /Limited access|administrative access/i.test(refusal),
                  "…and it names the control that DOES escalate, so the operator is not left " +
                  "with a code and no route out of it");
        } else {
            it.note("R1: " + target.id + " is administrator-class and administrative access is " +
                    "off, so the page draws no row for it and the “Check this safe” control " +
                    "cannot be reached. The refusal is driven the way that control drives it " +
                    "instead, and the page's own words are asserted from the banner and the " +
                    "count line.");
            const probe = await U.spawnVerb(frame, "probe", { safe: target.id }, "require");
            const po = U.parseMaybe(probe.out);
            const answer = (probe.problem || "") + " " + String(probe.out || "") +
                           " " + JSON.stringify(po || {});
            it.ok(!probe.ok,
                  "asking for the admin-class safe with superuser:\"require\" while access is " +
                  "off is refused");
            it.ok(/access-denied/.test(answer),
                  "the answer is the bridge's own `access-denied`, delivered without any " +
                  "prompt: " + JSON.stringify(answer.replace(/\s+/g, " ").trim().slice(0, 180)));
            const words = ((await frame.locator("#sec-banners").innerText().catch(() => "")) +
                           " " + (await frame.locator("#sec-safes").innerText().catch(() => "")))
                          .replace(/\s+/g, " ").trim();
            it.ok(/Limited access|Administrative access/i.test(words),
                  "…and the page names the control that DOES escalate, so the operator is not " +
                  "left with a code and no route out of it: " +
                  JSON.stringify(words.slice(0, 200)));
            it.ok(/hidden/i.test(words) || /Nothing is visible/i.test(words),
                  "…and it accounts for what it is not showing rather than pretending the " +
                  "registry is empty");
            refusal = answer;
        }
        /* And no lookalike password box was drawn anywhere by this page. That
         * is the half a bespoke "escalation dialog" would fail. */
        const fakePrompt = await frame.evaluate(() =>
            document.querySelectorAll(".sec-modal input[type=password]").length);
        it.ok(fakePrompt === 0,
              "the page drew no password prompt of its own in response (" + fakePrompt +
              " password inputs in its frame) — Cockpit's prompt is Cockpit's");
        it.shot(await H.shot(page, "09-refused-without-prompt"));

        /* --- NOW THE ROUTE THAT WORKS: COCKPIT'S OWN HEADER CONTROL --------
         * This is the operator gesture the page's banner names. Everything
         * below happens in the SHELL page, outside the plugin's frame, which is
         * the assertion: the page did not draw this, Cockpit did. */
        const hdr = page.locator('button:has-text("Limited access"), a:has-text("Limited access")');
        it.ok(await hdr.count() > 0,
              "Cockpit's header carries the “Limited access” control the page points at");
        await hdr.first().click();

        const prompt = await page.waitForFunction(() => {
            const t = document.body ? document.body.innerText : "";
            const pw = document.querySelector("input[type=password]");
            return (/administrative access|switch to admin|password for|Limited access mode/i.test(t)
                    && !!pw)
                ? { text: t.slice(0, 300), hasPassword: true } : null;
        }, null, { timeout: 30000 }).then((h) => h.jsonValue()).catch(() => null);

        if (!prompt) {
            it.fail("Cockpit's own escalation dialog did not appear within 30 s of using its " +
                    "header control. That is a Cockpit-side failure, not a page one — the " +
                    "page's part (reporting the state and naming this control) held above.");
            it.shot(await H.shot(page, "09-no-prompt"));
            it.done();
            return;
        }
        it.ok(true, "Cockpit's own administrative prompt appeared in the SHELL, not in the " +
                    "plugin frame — the bespoke-error path was not taken");
        it.note("prompt text begins: " +
                JSON.stringify(String(prompt.text).replace(/\s+/g, " ").slice(0, 160)));
        it.shot(await H.shot(page, "09-escalation-prompt"));

        /* Answer it the way an operator does. */
        /* .first() rather than page.fill(): the shell can carry more than one
         * password control and a strict locator would rather say so than pick. */
        await page.locator("input[type=password]:visible").first().fill(pass);
        /* noWaitAfter, and the failure swallowed on purpose. Cockpit RELOADS the
         * whole page the moment its superuser state changes
         * (superuser.js: window.location.reload(true)), so the button this
         * click lands on is detached before the click can report success —
         * measured: `locator.click` waited its full 30 s for
         * button:text-is("Authenticate") on a dialog that had already done its
         * job and gone. What the click did is not asserted from the click; it
         * is asserted from cockpit.permission afterwards, which is the fact
         * that matters. */
        const auth = page.locator("button:visible")
                         .filter({ hasText: /^(Authenticate|Ok|Continue|Apply|Log in)$/i }).first();
        if (await auth.count())
            await auth.click({ noWaitAfter: true, timeout: 10000 }).catch(() => {});
        else
            await page.keyboard.press("Enter");

        /* Cockpit RELOADS the page when its superuser state changes
         * (superuser.js: window.location.reload(true) on the transition), so
         * the frame handle from before the prompt is stale by design. Re-open
         * the plugin rather than reaching through a detached frame. */
        await page.waitForLoadState("domcontentloaded").catch(() => {});
        await page.waitForFunction(() => {
            const t = document.body ? document.body.innerText : "";
            return /Administrative access/i.test(t) && !/Limited access/i.test(t);
        }, null, { timeout: 30000 }).catch(() => {});
        it.note("Cockpit's header now reports: " + (await H.adminAccessState(page)));
        frame = await H.openPlugin(page);
        await U.waitForSafeList(frame);

        const now = await frame.evaluate(() => new Promise((resolve) => {
            const p = cockpit.permission({ admin: true });
            setTimeout(() => resolve(p.allowed), 800);
        }));
        it.ok(now === true, "administrative access is now on (cockpit.permission.allowed === " +
                            JSON.stringify(now) + ")");
        it.ok(!(await frame.locator("#sec-banners .sec-alert.warn").count()),
              "the page's escalation banner is gone now that there is nothing to warn about");

        /* And the safe genuinely opens. A permission flag that flipped while the
         * verb still refused would be the interesting failure, so the check is
         * the verb, not the flag. */
        const safePass = H.safePassphrase(target.id);
        if (!safePass) {
            const probe = await U.spawnVerb(frame, "probe", { safe: target.id }, "require");
            const po = U.parseMaybe(probe.out);
            it.ok(probe.ok && po && !po.error,
                  "with access on, an escalated probe of the admin safe SUCCEEDS: " +
                  JSON.stringify(po && { format: po.format, version: po.version }));
            it.note("no passphrase file for " + target.id + ", so the unlock itself was not " +
                    "driven; the escalated verb answering is the half that escalation decides.");
        } else {
            await U.openUnlockDialog(frame, target.id);
            const opened = await U.unlockAndWaitOutBackoff(frame, safePass, it);
            it.ok(!!(opened && opened.ok),
                  "with administrative access on, the ADMIN-CLASS safe opens through the page" +
                  (opened && !opened.ok
                      ? " — got " + JSON.stringify(opened.code + ": " + opened.detail) : ""));
            if (opened && opened.ok) {
                await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 })
                           .catch(() => {});
                const rows = await frame.locator("#sec-entries table.sec tbody tr").count();
                it.ok(rows > 0,
                      "…and its entries render — " + rows + " row(s) out of a root-owned file " +
                      "that this account cannot read without escalating");
                /* Lock it again: leaving an admin safe open behind a suite that
                 * is about to close the browser is not this suite's to do. */
                await frame.locator('#sec-browse-tools button:text-is("Lock")').click()
                           .catch(() => {});
            }
        }
        it.shot(await H.shot(page, "09-escalated"));
    } finally {
        await ctx.close();
    }
    it.done();
}

/* ------------------------------------------------------------------ main -- */
async function main() {
    console.log("== cockpit-secrets · LIVE access control (items 8, 9) ==");
    console.log("   target " + H.CFG.url + "   credentials dir " + H.CFG.creds);

    const missing = H.preconditions().filter((p) => !p.ok);
    if (missing.length) {
        console.log("\n\x1b[33mPRECONDITION NOT MET\x1b[0m");
        missing.forEach((m) => console.log("   - " + m.why));
        skipAll(missing.map((m) => m.why).join("  "));
        return finish();
    }

    const browser = await H.launch(H.requirePlaywright());
    try {
        await item8(browser);
        await item9(browser);
    } catch (e) {
        console.log("\n\x1b[31mAborted:\x1b[0m " + String((e && e.stack) || e));
        ORDER.forEach((k) => {
            if (!REC.items.some((r) => String(r.id) === String(k))) {
                const it = REC.item(k, ITEMS[k]);
                it.skip("aborted before this item: " + String((e && e.message) || e));
                it.done();
            }
        });
    } finally {
        await browser.close();
    }
    return finish();
}

function finish() {
    const s = REC.summary();
    console.log("\n== live-access result ==");
    ORDER.forEach((k) => {
        const r = s.items.find((x) => String(x.id) === String(k));
        const st = r ? r.state : "NOT-ATTEMPTED";
        const c = st === "PASS" ? "\x1b[32m" : st === "FAIL" ? "\x1b[31m" : "\x1b[33m";
        console.log("  " + c + st + "\x1b[0m  " + k + ". " + ITEMS[k] +
                    (r && r.why ? "\n         reason: " + r.why : ""));
    });
    console.log("  " + (s.checks - s.bad) + "/" + s.checks + " checks held");
    H.writeArtifact("live-access-result.json", JSON.stringify(s.items, null, 2) + "\n");
    process.exitCode = s.bad ? 1 : 0;
}

if (require.main === module) main();
module.exports = { ITEMS };
