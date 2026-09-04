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
    9: "Escalation: Cockpit's own prompt when access is off, and the safe opens when it is on"
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
        const admins = ((list && list.safes) || []).filter((s) => U.classOf(s) === "admin");
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
            const cls = (await card.first().getAttribute("class")) || "";
            const disabled = await card.first().locator('button:text-is("Unlock…")').isDisabled();
            it.note("the card is rendered " + (/unreachable/.test(cls) ? "unreachable" : "reachable") +
                    " with its Unlock control " + (disabled ? "disabled" : "enabled"));
            const reason = (await card.first().innerText()).trim();
            it.ok(/administrator-class|Administrative access/i.test(reason),
                  "the card tells the operator what stands in the way: " +
                  JSON.stringify(reason.replace(/\s+/g, " ").slice(0, 200)));
        } else {
            it.note("the page does not render a card for " + target.id + " at all for this " +
                    "principal — hiding is permitted; refusing is what matters.");
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
        const frame = await H.openPlugin(page);

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

        /* The page's own words for the un-escalated state: a banner naming the
         * control in Cockpit's header, NOT an error. */
        const banner = (await frame.locator("#sec-banners").innerText().catch(() => "")).trim();
        it.ok(/Administrative access is off/i.test(banner),
              "the page states the situation plainly instead of failing: " +
              JSON.stringify(banner.replace(/\s+/g, " ").slice(0, 200)));
        it.ok(!(await frame.locator("#sec-banners .sec-alert.err").count()),
              "it is a warning, not an error — nothing has failed yet");
        it.shot(await H.shot(page, "09-limited-access"));

        const list = await H.liveList(frame);
        const admins = ((list && list.safes) || []).filter((s) => U.classOf(s) === "admin");
        if (!admins.length) {
            it.skip("the registry declares no admin-class safe, so escalation has nothing " +
                    "to be required for.");
            it.done();
            return;
        }
        const target = admins[0];

        /* Reaching for the safe is what asks. The card offers "Check this safe"
         * precisely so that the operator triggers COCKPIT's prompt deliberately
         * rather than meeting it as a failure. */
        const card = U.cardFor(frame, target.id).first();
        const check = card.locator('button:text-is("Check this safe")');
        const open = card.locator('button:text-is("Unlock…")');
        if (await check.count()) {
            it.ok(true, "the card offers “Check this safe” — the deliberate route to " +
                        "Cockpit's prompt, rather than meeting it as a failure");
            await check.click();
        } else if (!(await open.isDisabled())) {
            it.note("no “Check this safe” control; using Unlock, which asks the bridge for " +
                    "escalation on the same spawn.");
            await open.click();
        } else {
            /* Nothing on the card can ask. Say so instead of clicking a disabled
             * control and waiting out a 30 s timeout, which is how this read as
             * an abort the first time it ran. */
            it.fail("the admin-class card offers no way to ask for escalation: “Check this " +
                    "safe” is absent and Unlock is disabled. With administrative access off " +
                    "this card is a dead end, and the page's own banner promises otherwise.");
            it.shot(await H.shot(page, "09-dead-end"));
            it.done();
            return;
        }

        /* Cockpit's prompt lives in the SHELL page, outside the plugin's frame —
         * which is the assertion: the page did not draw this, the bridge did. */
        const prompt = await page.waitForFunction(() => {
            const t = document.body ? document.body.innerText : "";
            const pw = document.querySelector("input[type=password]");
            return (/administrative access|switch to admin|password for/i.test(t) && !!pw)
                ? { text: t.slice(0, 300), hasPassword: true } : null;
        }, null, { timeout: 30000 }).then((h) => h.jsonValue()).catch(() => null);

        if (!prompt) {
            const err = (await frame.locator("#sec-alerts, .sec-modal").innerText().catch(() => "")).trim();
            it.fail("Cockpit's escalation prompt did not appear within 30 s. The plugin frame " +
                    "shows: " + JSON.stringify(err.replace(/\s+/g, " ").slice(0, 240)));
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
        const buttons = await page.locator("button:visible").allInnerTexts();
        const label = buttons.find((t) => /^(authenticate|ok|continue|apply|log in)$/i.test(t.trim()));
        if (label) await page.locator(`button:text-is("${label}")`).first().click();
        else await page.keyboard.press("Enter");

        await page.waitForFunction(() => {
            const t = document.body ? document.body.innerText : "";
            return /Administrative access/i.test(t) && !/Limited access/i.test(t);
        }, null, { timeout: 30000 }).catch(() => {});

        const now = await frame.evaluate(() => new Promise((resolve) => {
            const p = cockpit.permission({ admin: true });
            setTimeout(() => resolve(p.allowed), 800);
        }));
        it.ok(now === true, "administrative access is now on (cockpit.permission.allowed === " +
                            JSON.stringify(now) + ")");

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
            await frame.locator("#sec-refresh").click();
            await U.openUnlockDialog(frame, target.id);
            await U.submitUnlock(frame, safePass);
            const opened = await frame.waitForSelector("#sec-browse-view:not([hidden])",
                                                       { timeout: 120000 })
                                      .then(() => true).catch(() => false);
            it.ok(opened, "with administrative access on, the admin-class safe opens");
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
