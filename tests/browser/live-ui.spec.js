/* tests/browser/live-ui.spec.js — the LIVE walkthrough, as an operator.
 *
 *   node tests/browser/live-ui.spec.js          (or: ./tests/browser/run-live.sh)
 *
 * Items 1-7 and 10 of the live-drive task, in the order an operator meets them:
 * the page loads under the real bridge, the list reads right, a safe is
 * unlocked, a value is revealed and copied, nothing is left in the browser, the
 * passphrase is demanded again after a lock, an entry is managed end to end, a
 * concurrent save is refused with a decision, and the whole thing works from a
 * keyboard at 200%.
 *
 * Items 8 and 9 — the non-admin refusal and the escalation prompt — need a
 * DIFFERENT principal and a session with administrative access still off, so
 * they live in live-access.spec.js rather than being bolted onto a session that
 * has already escalated.
 *
 * THE DIFFERENCE FROM ui.spec.js, WHICH IS THE POINT. That suite stubs
 * `cockpit.spawn` and says so plainly: `superuser:"require"` is "recorded but
 * never honoured". Here nothing is stubbed. Cockpit's own login form mints the
 * session, Cockpit's own shell loads the package under the CSP the bridge
 * really sends, and every refusal comes from the helper re-deriving the
 * caller's identity from the kernel. What a stub cannot prove is the only thing
 * this file tries to.
 *
 * WHAT IT WILL NOT DO. It never writes to /etc, never runs a root job, and
 * never touches cockpit.socket. Every safe it changes it changes through the
 * page. Every passphrase it uses comes out of a 0600 file in the credentials
 * directory — never argv, never the environment: I10 binds the test as tightly
 * as it binds the helper, and a suite that put a passphrase on a command line
 * to check that the helper does not would be self-refuting.
 *
 * ONE WRONG PASSPHRASE, EVER. The lockout threshold is five (I16). A suite that
 * hammered the failure path would leave the safe locked out for the next run
 * and for the operator. Item 3 makes exactly one wrong attempt, because the
 * assertion is about the WORDING of the refusal, and one attempt shows it.
 */
"use strict";

const H = require("./live-harness.js");
const fs = require("fs");
const os = require("os");
const path = require("path");

const REC = H.Recorder("live-ui");

/* The task's own numbering, so the report cannot drift from the brief. */
const ITEMS = {
    1: "The page loads under the real Cockpit bridge, scripts run, zero CSP violations",
    2: "The safe list renders both classes, admin first, unreachable disabled with a reason",
    3: "The unlock flow end to end: wrong, right, entries, reveal, re-mask, copy, clear",
    4: "I11 — nothing is left in the browser after a successful unlock",
    5: "The passphrase is demanded EVERY time: lock, then operate again",
    6: "Full management: add, edit, custom field, attach, download, history, save, reopen",
    7: "The conflict path surfaces a decision, not an alert",
    10: "Accessibility: keyboard-only unlock with a focus trap, and usable at 200%"
};
const ORDER = [1, 2, 3, 4, 5, 6, 7, 10];

/* --------------------------------------------------------------- helpers -- */

function classOf(s) { return (!s.access || s.access === "admin") ? "admin" : "user"; }
function reachable(s) {
    return s.usable === undefined ? !(s.locked && s.reason) : !!s.usable;
}

function pickSafe(list, want) {
    for (const s of ((list && list.safes) || [])) {
        if (want.cls && classOf(s) !== want.cls) continue;
        if (!reachable(s)) continue;
        if (want.rw && s.mode === "ro") continue;
        if (!H.safePassphrase(s.id)) continue;
        return s;
    }
    return null;
}

/* The card for one registry id. `.sec-safe-id` carries the id verbatim, which
 * is what makes a card addressable without depending on its label. */
function cardFor(frame, id) {
    return frame.locator(".sec-safe").filter({
        has: frame.locator(`.sec-safe-id:text-is("${id}")`)
    });
}

async function openUnlockDialog(frame, id) {
    await cardFor(frame, id).locator('button:text-is("Unlock…")').click();
    await frame.waitForSelector(".sec-modal input[type=password]", { timeout: 15000 });
}

/* Fill the passphrase and press Unlock. Deliberately returns nothing: a wrong
 * passphrase is a legitimate outcome here and must not be an exception. */
async function submitUnlock(frame, passphrase) {
    await frame.locator(".sec-modal input[type=password]").last().fill(passphrase);
    await frame.locator('.sec-modal button:text-is("Unlock")').last().click();
}

async function inBrowseView(frame) {
    return frame.evaluate(() => {
        const v = document.getElementById("sec-browse-view");
        return !!(v && !v.hidden);
    });
}

/* The id of the control whose LABEL is exactly `label`, inside the topmost open
 * dialog. The generic form mints its control ids per control, so there is no
 * stable selector; the label is the durable handle and it is the one an
 * operator uses. Only the label's own text nodes are compared — makeControl
 * appends an "(optional)" span and the helper's help text into the same
 * element, and matching on those would pick the wrong field. */
async function controlIdByLabel(frame, label) {
    return frame.evaluate((want) => {
        const backs = document.querySelectorAll(".sec-backdrop");
        const scope = backs.length ? backs[backs.length - 1] : document;
        const labels = scope.querySelectorAll("label[for]");
        for (const l of labels) {
            let t = "";
            for (const n of l.childNodes) if (n.nodeType === 3) t += n.textContent;
            t = t.trim();
            if (t.toLowerCase() === String(want).toLowerCase()) return l.getAttribute("for");
        }
        return null;
    }, label);
}

async function fillLabelled(frame, label, value) {
    const id = await controlIdByLabel(frame, label);
    if (!id) throw new Error("no control labelled “" + label + "” in the open dialog");
    await frame.locator("#" + id).fill(value);
    return id;
}

async function setLabelledFile(frame, label, file) {
    const id = await controlIdByLabel(frame, label);
    if (!id) throw new Error("no file control labelled “" + label + "” in the open dialog");
    await frame.locator("#" + id).setInputFiles(file);
    return id;
}

/* The dialog's run button. verbDialog builds it as `primary`, or `danger` for a
 * verb the helper marked destructive, so both have to be accepted. */
function runButton(frame) {
    return frame.locator(".sec-modal").last()
                .locator("button.primary, button.danger")
                .filter({ hasNotText: "Cancel" }).first();
}

/* Drive one verb the way devtools would: the page's own bridge, the page's own
 * argv, no UI in the way. Used to separate "the page cannot reach this" from
 * "the helper cannot do this" — the difference between a rendering bug and a
 * capability gap, which is the difference between a fix here and a fix there. */
async function spawnVerb(frame, verb, req, superuser) {
    return frame.evaluate(([v, r, su]) => new Promise((resolve) => {
        const opts = { err: "message" };
        if (su) opts.superuser = su;
        const p = cockpit.spawn(["/usr/local/sbin/secrets-admin", v], opts);
        p.input(JSON.stringify(r));
        p.then((out) => resolve({ ok: true, out: String(out) }))
         .catch((err, out) => resolve({ ok: false,
                                        problem: (err && err.problem) || "",
                                        out: String(out === undefined ? "" : out) }));
    }), [verb, req, superuser || null]);
}

function parseMaybe(text) {
    try { return JSON.parse(String(text || "").trim()); } catch (e) { return null; }
}

function skipAll(why) {
    ORDER.forEach((k) => { const it = REC.item(k, ITEMS[k]); it.skip(why); it.done(); });
}

/* ------------------------------------------------------------------ main -- */
async function main() {
    console.log("== cockpit-secrets · LIVE walkthrough (items 1-7, 10) ==");
    console.log("   target " + H.CFG.url + "   credentials dir " + H.CFG.creds);

    const missing = H.preconditions().filter((p) => !p.ok);
    if (missing.length) {
        console.log("\n\x1b[33mPRECONDITION NOT MET\x1b[0m");
        missing.forEach((m) => console.log("   - " + m.why));
        skipAll(missing.map((m) => m.why).join("  "));
        return finish();
    }

    const pw = H.requirePlaywright();
    const password = H.credential(H.CFG.admin);
    if (!password) {
        skipAll("no credential file at " + path.join(H.CFG.creds, H.CFG.admin + ".pass") +
                " — the admin principal cannot be signed in, and this suite will not guess " +
                "a password or reset an account.");
        return finish();
    }
    if (!(await H.checkLogin(H.CFG.admin, password))) {
        skipAll("Cockpit's own login endpoint refused " + H.CFG.admin +
                " with the credential in " + H.CFG.creds + ".");
        return finish();
    }

    const browser = await H.launch(pw);
    let ctx = null, page = null, frame = null, state = null;
    try {
        ctx = await H.newContext(browser);
        /* The clipboard is item 3's last assertion and the permission has to be
         * in place before the page loads. It is not a relaxation: it is the
         * same grant an operator makes by answering their browser's own
         * prompt, and nothing else about the context is loosened. */
        await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: H.CFG.url });

        page = await H.login(ctx, H.CFG.admin, password);
        frame = await H.openPlugin(page);

        await item1(page, frame);
        const list = await H.liveList(frame);
        H.writeArtifact("live-list.json", JSON.stringify(list, null, 2) + "\n");
        await item2(browser, page, frame, list);
        state = await item3(page, frame, list);
        await item4(page, frame, state);
        await item5(page, frame, state);
        await item6(page, frame, state);
        await item7(browser, page, frame, state, password);
        await item10(page, frame, state);
    } catch (e) {
        console.log("\n\x1b[31mThe walkthrough aborted:\x1b[0m " + String((e && e.stack) || e));
        if (page) await H.shot(page, "abort");
        ORDER.forEach((k) => {
            if (!REC.items.some((r) => String(r.id) === String(k))) {
                const it = REC.item(k, ITEMS[k]);
                it.skip("the walkthrough aborted before this item: " + String((e && e.message) || e));
                it.done();
            }
        });
    } finally {
        if (browser) await browser.close();
    }
    return finish();
}

/* ================================================================== item 1 */
async function item1(page, frame) {
    const it = REC.item(1, ITEMS[1]);
    console.log("\n== 1. " + ITEMS[1] + " ==");

    /* Scripts ran. #sec-sub reads "loading…" in the shipped index.html and is
     * only rewritten by init() once the schema verb has answered, so its
     * contents prove both that the external script executed under the real CSP
     * and that it reached the helper through the real bridge. */
    const sub = (await frame.locator("#sec-sub").innerText()).trim();
    it.ok(sub.length > 0 && !/^loading/i.test(sub),
          "secrets.js ran and the schema answered — #sec-sub reads " + JSON.stringify(sub));

    /* The helper's own rules, rendered into the footer from the schema. A page
     * whose <script> was refused has an empty footer here. */
    const rules = await frame.locator("#sec-rules li").count();
    it.ok(rules > 0, "the footer carries " + rules + " helper-published rules");

    /* The stylesheet is external for the same reason the script is: an inline
     * <style> would be refused by default-src 'self' (I9). If it loaded, the
     * topbar is the flex row secrets.css makes it. */
    const styled = await frame.evaluate(() => {
        const n = document.querySelector(".sec-topbar");
        return !!n && getComputedStyle(n).display === "flex";
    });
    it.ok(styled, "secrets.css applied — the external stylesheet loaded under the real CSP");

    /* Zero CSP violations, by two independent detectors, because a single
     * detection path that silently stopped working would read as a pass. */
    const evts = await H.cspFromEvents(page);
    const cons = H.cspFromConsole(page);
    it.ok(evts.length === 0, "securitypolicyviolation events: " + evts.length +
          (evts.length ? " — " + JSON.stringify(evts).slice(0, 500) : ""));
    it.ok(cons.length === 0, "console CSP refusals: " + cons.length +
          (cons.length ? " — " + JSON.stringify(cons.map((c) => c.text)).slice(0, 500) : ""));

    /* Scoped to the package's own resources. Cockpit's shell is a live page
     * with its own console traffic — a 401 from its /cockpit/login probe, an
     * ERR_ABORTED for every iframe it swaps out — and none of that is this
     * plugin speaking. What the shell said is recorded as a note, so it is on
     * the record without being counted against the page under test. */
    const errs = H.consoleFor(page, H.PKG_MARKER)
                  .filter((m) => m.type === "error" || m.type === "pageerror");
    it.ok(errs.length === 0, "page and console errors from the secrets package: " + errs.length +
          (errs.length ? " — " + JSON.stringify(errs.map((e) => e.text)).slice(0, 500) : ""));
    const shellNoise = H.consoleNotFor(page, H.PKG_MARKER)
                        .filter((m) => m.type === "error" || m.type === "pageerror");
    it.note("Cockpit's own shell logged " + shellNoise.length + " error(s) in the same page: " +
            JSON.stringify(shellNoise.map((m) => m.text + " <" + m.url + ">")).slice(0, 300));

    /* A clean console is a claim; the file is the receipt. */
    const logName = H.writeArtifact("01-console.log",
        (page.__console || []).map((m) =>
            `[${m.type}] ${m.text}${m.url ? "  <" + m.url + ">" : ""}`).join("\n") + "\n");
    it.note("console log captured to artifacts/" + logName);

    /* The policy header Cockpit really sent for the package page, on the record
     * rather than inferred. */
    const csp = await page.evaluate(async (url) => {
        try {
            const r = await fetch(url, { credentials: "same-origin" });
            return r.headers.get("content-security-policy") || "(no CSP header)";
        } catch (e) { return "(unreadable: " + String(e) + ")"; }
    }, frame.url());
    it.note("Content-Security-Policy on the package page: " + csp);
    H.writeArtifact("01-csp-header.txt", csp + "\n");

    it.shot(await H.shot(page, "01-loaded"));
    it.done();
}

/* ================================================================== item 2 */
async function item2(browser, page, frame, list) {
    const it = REC.item(2, ITEMS[2]);
    console.log("\n== 2. " + ITEMS[2] + " ==");

    const safes = (list && list.safes) || [];
    it.note("the registry offers " + safes.length + " safe(s) to " + H.CFG.admin);
    if (!safes.length) {
        it.skip("the live registry declares no safes, so there is no list to render. " +
                "Seeding /etc/cockpit-secrets/safes.d is root work and belongs to the " +
                "install task, not to this one.");
        it.done();
        return;
    }

    /* Admin FIRST, because admin is the default access class (I1) and the page
     * says so by putting it first. Read the headings in document order. */
    const heads = await frame.locator(".sec-class-block h3").allInnerTexts();
    it.note("class blocks in document order: " + JSON.stringify(heads));
    const iAdmin = heads.findIndex((h) => /Administrator safes/i.test(h));
    const iUser = heads.findIndex((h) => /Your own safes/i.test(h));
    const haveAdmin = safes.some((s) => classOf(s) === "admin");
    const haveUser = safes.some((s) => classOf(s) === "user");

    if (haveAdmin && haveUser) {
        it.ok(iAdmin >= 0 && iUser >= 0 && iAdmin < iUser,
              "both access classes render, and Administrator safes comes first");
    } else {
        it.note("only the " + (haveAdmin ? "admin" : "user") + " class is registered on " +
                "this host, so the ORDER of the two blocks cannot be observed from it.");
        it.ok((haveAdmin && iAdmin >= 0) || (haveUser && iUser >= 0),
              "the one registered class renders under its own heading");
    }

    /* A safe this caller cannot reach: control disabled, reason on the card.
     * The admin principal is in `sudo` and may legitimately reach everything,
     * so when nothing is unreachable HERE the check is made in a second session
     * as the non-admin principal. The case exists; it just does not exist for
     * this operator, and saying that is not the same as skipping it. */
    if (await frame.locator(".sec-safe.unreachable").count()) {
        await assertDisabledCard(frame, it, H.CFG.admin);
        it.shot(await H.shot(page, "02-safes-admin"));
    } else {
        it.note("every registered safe is reachable by " + H.CFG.admin + " (it is in " +
                "`sudo`), so the disabled card is checked as " + H.CFG.user + ".");
        it.shot(await H.shot(page, "02-safes-admin"));
        const upw = H.credential(H.CFG.user);
        if (!upw) {
            it.skip("no credential file for " + H.CFG.user + " at " +
                    path.join(H.CFG.creds, H.CFG.user + ".pass") + ", so an unreachable " +
                    "card could not be observed for any principal.");
            it.done();
            return;
        }
        const ctx2 = await H.newContext(browser);
        try {
            const p2 = await H.login(ctx2, H.CFG.user, upw);
            const f2 = await H.openPlugin(p2);
            const n = await f2.locator(".sec-safe.unreachable").count();
            it.ok(n > 0, H.CFG.user + " sees " + n + " safe(s) rendered unreachable");
            if (n > 0) await assertDisabledCard(f2, it, H.CFG.user);
            it.shot(await H.shot(p2, "02-safes-nonadmin"));
        } finally {
            await ctx2.close();
        }
    }
    it.done();
}

async function assertDisabledCard(frame, it, who) {
    const card = frame.locator(".sec-safe.unreachable").first();
    const id = (await card.locator(".sec-safe-id").innerText()).trim();
    const open = card.locator('button:text-is("Unlock…")');
    it.ok(await open.isDisabled(), "“" + id + "” shows its Unlock control disabled for " + who);
    /* The reason is carried twice on purpose — as the button's title and as a
     * line under it — so it reaches a pointer and a screen reader alike. */
    const title = (await open.getAttribute("title")) || "";
    const line = (await card.locator(".sec-subtle").last().innerText().catch(() => "")) || "";
    it.ok(!!title.trim() || !!line.trim(),
          "the card states the reason: " + JSON.stringify((line || title).trim().slice(0, 160)));
}

/* ================================================================== item 3 */
async function item3(page, frame, list) {
    const it = REC.item(3, ITEMS[3]);
    console.log("\n== 3. " + ITEMS[3] + " ==");

    const safe = pickSafe(list, { rw: true }) || pickSafe(list, {});
    if (!safe) {
        it.skip("no reachable registered safe has a passphrase file in " + H.CFG.creds +
                " (expected safe-<id>.pass, mode 0600). Without one there is nothing to " +
                "unlock, and this suite will not guess a passphrase: five wrong guesses " +
                "lock the safe out (I16).");
        it.done();
        return null;
    }
    const pass = H.safePassphrase(safe.id);
    it.note("driving safe “" + safe.id + "” — " + classOf(safe) + " class, " +
            safe.format + ", mode " + safe.mode);

    /* --- the prompt appears -------------------------------------------- */
    await openUnlockDialog(frame, safe.id);
    const pwBox = frame.locator(".sec-modal input[type=password]").last();
    it.ok(await pwBox.isVisible(), "the unlock prompt appears with a passphrase control");
    it.shot(await H.shot(page, "03-unlock-prompt"));

    /* The attributes that keep a browser, a password manager and a spell
     * checker away from a master passphrase, and the ABSENCE of a name
     * attribute, which is what autofill looks for (I11). */
    const attrs = await pwBox.evaluate((n) => ({
        autocomplete: n.getAttribute("autocomplete"),
        spellcheck: n.getAttribute("spellcheck"),
        name: n.getAttribute("name"),
        form: n.form ? "in a form" : "no form"
    }));
    it.ok(attrs.autocomplete === "off" && attrs.name === null,
          "the passphrase control is autocomplete=off with no name attribute — " +
          JSON.stringify(attrs));

    /* Hold on to the node itself. After the unlock it is detached from the
     * document, and item 4 reads its .value to prove it was WIPED rather than
     * merely removed. */
    const pwHandle = await pwBox.elementHandle();

    /* --- the wrong passphrase gives the coarse answer ------------------- */
    await submitUnlock(frame, "definitely-not-the-passphrase-" + Date.now());
    await frame.waitForSelector(".sec-modal .sec-alert.err", { timeout: 60000 });
    const code = (await frame.locator(".sec-modal .sec-alert.err .sec-code").last()
                             .innerText().catch(() => "")).trim();
    const detail = (await frame.locator(".sec-modal .sec-alert.err p").first().innerText()).trim();
    it.ok(code === "bad-credential",
          "a wrong passphrase answers with the coarse code " + JSON.stringify(code));
    it.ok(!/traceback|line \d+|File "/i.test(detail),
          "the detail is an operator sentence, not a traceback: " +
          JSON.stringify(detail.slice(0, 180)));
    it.shot(await H.shot(page, "03-bad-credential"));

    /* --- the right passphrase unlocks ----------------------------------- */
    await submitUnlock(frame, pass);
    await frame.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 });
    it.ok(await inBrowseView(frame), "the correct passphrase unlocks and the browse view opens");

    await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 });
    const rows = await frame.locator("#sec-entries table.sec tbody tr").count();
    const empty = await frame.locator("#sec-entries td.sec-empty").count();
    it.ok(rows > 0 && empty === 0, "entries render — " + rows + " row(s)");
    it.shot(await H.shot(page, "03-entries"));

    if (empty > 0 || rows === 0) {
        it.fail("the safe holds no entries, so reveal and copy cannot be driven against it");
        it.done();
        return { safe, pass, pwHandle, revealed: null };
    }

    /* --- reveal shows a value and re-masks on its countdown -------------- */
    await frame.locator("#sec-entries table.sec tbody tr").first()
               .locator("td button.sec-btn.link").click();
    await frame.waitForSelector("#sec-detail .sec-reveal", { timeout: 20000 });
    const widget = frame.locator("#sec-detail .sec-reveal").filter({
        has: frame.locator('.sec-reveal-label:text-is("Password")')
    }).first();
    it.ok((await widget.count()) > 0, "the detail pane offers a Password reveal control");

    const masked = (await widget.locator(".sec-value").innerText()).trim();
    await widget.locator('button:text-is("Reveal")').click();
    await widget.locator(".sec-value:not(.masked)").waitFor({ timeout: 30000 });
    const shown = await widget.locator(".sec-value").innerText();
    it.ok(shown.length > 0 && shown !== masked,
          "Reveal shows a value (" + shown.length + " characters)");
    const cd = (await widget.locator(".sec-countdown").innerText()).trim();
    it.ok(/hides in/.test(cd), "a countdown is running: " + JSON.stringify(cd));
    it.shot(await H.shot(page, "03-revealed"));

    /* The countdown is the helper's own expires_in — 15 s by the schema's
     * constants. Waiting it out IS the assertion; there is no shortcut that
     * would still be testing the thing. */
    await widget.locator(".sec-value.masked").waitFor({ timeout: 60000 });
    it.ok((await widget.locator(".sec-value").innerText()).trim() === masked,
          "the value re-masks when the countdown ends");
    /* "Re-masked" must not mean "still in the DOM behind a CSS rule" (I17). */
    const stillThere = await frame.evaluate((v) =>
        document.documentElement.innerHTML.indexOf(v) >= 0, shown);
    it.ok(!stillThere, "the revealed value is GONE from the DOM, not merely hidden");
    it.shot(await H.shot(page, "03-remasked"));

    /* --- copy puts it on the clipboard, and clears it -------------------- */
    await widget.locator('button:text-is("Copy")').click();
    await frame.waitForSelector("#sec-clip:not([hidden])", { timeout: 30000 });
    const clipped = await frame.evaluate(() => navigator.clipboard.readText());
    it.ok(clipped === shown, "Copy put the value on the clipboard");
    const clipMsg = (await frame.locator("#sec-clip").innerText()).trim();
    it.ok(/clipboard clears in/.test(clipMsg),
          "a clipboard countdown is shown: " + JSON.stringify(clipMsg));
    it.shot(await H.shot(page, "03-copied"));

    /* state:"hidden", not the default "visible": #sec-clip is hidden by the
     * `hidden` ATTRIBUTE, and a selector waiting for a hidden element to become
     * visible waits for ever. Caught by running this against the package's own
     * stub harness before the live host had the plugin on it. */
    await frame.waitForSelector("#sec-clip", { state: "hidden", timeout: 60000 });
    /* Clearing is best-effort by design: the page writes "" and falls back to a
     * single space. Either way the old value must not be what the clipboard
     * holds — which is the strongest claim the footer makes, and all it makes. */
    const after = await frame.evaluate(() => navigator.clipboard.readText());
    it.ok(after !== shown,
          "the clipboard no longer holds the value (it now reads " + JSON.stringify(after) + ")");

    it.done();
    return { safe, pass, pwHandle, revealed: shown };
}

/* ================================================================== item 4 */
async function item4(page, frame, state) {
    const it = REC.item(4, ITEMS[4]);
    console.log("\n== 4. " + ITEMS[4] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }

    /* Storage areas in the plugin's frame AND in Cockpit's shell page. The
     * areas are per-ORIGIN and the shell shares the origin, so a passphrase
     * that leaked into either is readable by any XSS anywhere in Cockpit (I11);
     * checking only the frame would miss half of the hazard. */
    const inFrame = await frame.evaluate(() => ({
        local: localStorage.length, session: sessionStorage.length, cookie: document.cookie
    }));
    const inShell = await page.evaluate(() => ({
        local: localStorage.length, session: sessionStorage.length
    }));
    it.ok(inFrame.local === 0, "plugin frame localStorage.length === 0 (read " + inFrame.local + ")");
    it.ok(inFrame.session === 0, "plugin frame sessionStorage.length === 0 (read " + inFrame.session + ")");
    it.note("Cockpit's own shell holds " + inShell.local + " localStorage and " +
            inShell.session + " sessionStorage key(s) — Cockpit's, not this page's");

    /* IndexedDB: the storage area a "we used no localStorage" claim forgets. */
    const idb = await frame.evaluate(async () => {
        if (!window.indexedDB || !indexedDB.databases) return "unavailable";
        try { return (await indexedDB.databases()).map((d) => d.name); }
        catch (e) { return "unreadable"; }
    });
    it.ok(!Array.isArray(idb) || idb.length === 0,
          "the plugin frame opened no IndexedDB database (" + JSON.stringify(idb) + ")");

    /* And the passphrase itself, nowhere: both storage areas serialized, the
     * whole DOM, every live input value, the cookie jar. */
    const hunt = await frame.evaluate((needle) => {
        const dump = (s) => {
            let o = "";
            for (let i = 0; i < s.length; i++) o += s.key(i) + "=" + s.getItem(s.key(i)) + "\n";
            return o;
        };
        const inputs = Array.prototype.map.call(
            document.querySelectorAll("input, textarea"), (n) => String(n.value || "")).join("\n");
        return {
            dom: document.documentElement.outerHTML.indexOf(needle) >= 0,
            local: dump(localStorage).indexOf(needle) >= 0,
            session: dump(sessionStorage).indexOf(needle) >= 0,
            cookie: document.cookie.indexOf(needle) >= 0,
            inputs: inputs.indexOf(needle) >= 0,
            allPwEmpty: Array.prototype.every.call(
                document.querySelectorAll("input[type=password]"),
                (n) => String(n.value || "") === "")
        };
    }, state.pass);
    it.ok(!hunt.dom, "the passphrase string appears nowhere in the plugin frame's DOM");
    it.ok(!hunt.local && !hunt.session, "the passphrase is in neither storage area");
    it.ok(!hunt.cookie, "the passphrase is in no cookie");
    it.ok(!hunt.inputs, "no live input or textarea still holds the passphrase");
    it.ok(hunt.allPwEmpty, "every password input currently on the page reads empty");

    const shell = await page.evaluate((needle) => {
        const dump = (s) => {
            let o = "";
            for (let i = 0; i < s.length; i++) o += s.key(i) + "=" + s.getItem(s.key(i)) + "\n";
            return o;
        };
        return { dom: document.documentElement.outerHTML.indexOf(needle) >= 0,
                 local: dump(localStorage).indexOf(needle) >= 0,
                 session: dump(sessionStorage).indexOf(needle) >= 0,
                 cookie: document.cookie.indexOf(needle) >= 0 };
    }, state.pass);
    it.ok(!shell.dom && !shell.local && !shell.session && !shell.cookie,
          "the passphrase is absent from Cockpit's shell page too — same origin, same risk");

    /* The control the operator actually typed into, now detached from the
     * document. form.wipeSecrets() blanks it before the request leaves, so a
     * detached node cannot be mined for it either. This is the check that
     * catches a "we removed the visible one" regression. */
    if (state.pwHandle) {
        const v = await state.pwHandle.evaluate((n) => String(n.value || ""));
        it.ok(v === "", "the now-detached passphrase input was WIPED, not just removed");
    }

    it.shot(await H.shot(page, "04-storage"));
    it.done();
}

/* ================================================================== item 5 */
async function item5(page, frame, state) {
    const it = REC.item(5, ITEMS[5]);
    console.log("\n== 5. " + ITEMS[5] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }
    const admin = classOf(state.safe) === "admin" ? "require" : null;

    /* Lock through the control an operator would use. */
    await frame.locator('#sec-browse-tools button:text-is("Lock")').click();
    const dirty = frame.locator('.sec-modal:has-text("Lock with unsaved changes?")');
    if (await dirty.count()) await dirty.locator('button:text-is("Discard and lock")').click();
    await frame.waitForSelector("#sec-safes-view:not([hidden])", { timeout: 30000 });
    it.ok(!(await inBrowseView(frame)), "Lock returns the page to the safe list");
    it.shot(await H.shot(page, "05-locked"));

    /* The next operation on that safe. It must ask again, and it must ask with
     * an EMPTY box: a remembered passphrase would be the thing this project
     * exists not to have. */
    await openUnlockDialog(frame, state.safe.id);
    const box = frame.locator(".sec-modal input[type=password]").last();
    it.ok(await box.isVisible(), "the next operation on that safe demands the passphrase again");
    it.ok((await box.inputValue()) === "", "the passphrase box comes up EMPTY — nothing was remembered");
    it.shot(await H.shot(page, "05-prompted-again"));
    await frame.locator('.sec-modal button:text-is("Cancel")').last().click();

    /* And the same claim made where it cannot be a rendering choice.
     *
     * The page keeps its handle inside one closure, so there is nothing to read
     * out of it — which is itself the design. The equivalent statement is made
     * against the HELPER instead: mint a handle in one single-shot spawn, then
     * present it in a SECOND one. The default configuration is one helper
     * process per verb, so the handle died with the process that minted it, and
     * "the passphrase is prompted every time" is a property of the architecture
     * rather than a policy the page applies. This is the same door an attacker
     * would try from devtools. */
    const u = await spawnVerb(frame, "unlock", { safe: state.safe.id, password: state.pass }, admin);
    const uo = parseMaybe(u.out);
    if (u.ok && uo && uo.handle) {
        const r = await spawnVerb(frame, "entries", { handle: uo.handle }, admin);
        const ro = parseMaybe(r.out);
        it.ok(!r.ok, "a handle from a previous helper process is refused by the next one");
        it.ok(ro && /access-denied|not-found|invalid/.test(String(ro.error)),
              "the helper answers " + JSON.stringify(ro && ro.error) +
              " for a handle that is no longer live");
        H.writeArtifact("05-handle-replay.json", JSON.stringify({ minted: !!uo.handle, replay: ro }, null, 2) + "\n");
    } else {
        it.note("the single-shot unlock used for the handle-replay control did not return a " +
                "handle (" + JSON.stringify(uo) + "); the UI half of this item stands alone.");
    }
    it.done();
}

/* ================================================================== item 6 */
async function item6(page, frame, state) {
    const it = REC.item(6, ITEMS[6]);
    console.log("\n== 6. " + ITEMS[6] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }
    if (state.safe.mode === "ro") {
        it.skip("safe “" + state.safe.id + "” is registered read-only, so nothing can be " +
                "added, edited, attached or saved through it.");
        it.done();
        return;
    }

    /* Unlock again. Because of item 5 this is a fresh passphrase prompt, which
     * is exactly what it should be. */
    await openUnlockDialog(frame, state.safe.id);
    await submitUnlock(frame, state.pass);
    await frame.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 });

    const title = "live-walkthrough-" + Date.now();
    state.title = title;

    /* --- add ------------------------------------------------------------ */
    await frame.locator('#sec-browse-tools button:text-is("Add entry…")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await fillLabelled(frame, "Title", title);
    await fillLabelled(frame, "Username", "walkthrough");
    await fillLabelled(frame, "Password", "first-value-" + Date.now());
    await runButton(frame).click();
    await frame.locator(".sec-modal").last().waitFor({ state: "detached", timeout: 60000 })
               .catch(() => {});
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`)
               .waitFor({ timeout: 30000 });
    it.ok(true, "an entry was added and appears in the listing: " + title);
    it.shot(await H.shot(page, "06-added"));

    /* --- edit ------------------------------------------------------------ */
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    await frame.locator('#sec-detail button:text-is("Edit entry")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await fillLabelled(frame, "URL", "https://edt1.invalid/walkthrough");
    await runButton(frame).click();
    await frame.locator(".sec-modal").last().waitFor({ state: "detached", timeout: 60000 })
               .catch(() => {});
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    const detailText = await frame.locator("#sec-detail").innerText();
    it.ok(/edt1\.invalid\/walkthrough/.test(detailText),
          "the edit took: the entry's URL now reads back from the helper");

    /* --- a custom field --------------------------------------------------
     * The page renders only what the schema declares. The helper's `entry` and
     * `changes` descriptors declare title/username/password/url/notes/tags/
     * totp_uri/expires and NO custom-field control, so there is nothing for
     * secrets.js to draw and no way to CREATE one from this page — only
     * "Reveal a custom field…", which READS one that already exists. Whether
     * that is a page bug or a helper bug is decided by driving the same verb
     * through the bridge, below. */
    const hasCustomControl = await frame.evaluate(() => {
        const back = document.querySelectorAll(".sec-backdrop");
        const scope = back.length ? back[back.length - 1] : document;
        return Array.prototype.some.call(scope.querySelectorAll("label"),
                                         (n) => /custom/i.test(n.textContent || ""));
    });
    it.ok(hasCustomControl, "the add/edit dialog offers a control that creates a custom field");
    if (!hasCustomControl) {
        const viaBridge = await spawnVerb(frame, "edit", {
            safe: state.safe.id, password: state.pass,
            uuid: await selectedUuid(frame, state),
            changes: { custom: { "live-walkthrough": { value: "set-through-the-bridge",
                                                       protected: true } } },
            autosave: true
        }, classOf(state.safe) === "admin" ? "require" : null);
        const vb = parseMaybe(viaBridge.out);
        it.note("the same edit verb, driven through cockpit.spawn with " +
                "changes.custom, answers " + JSON.stringify(vb) +
                " — so the BACKEND takes custom fields and the gap is in the schema " +
                "descriptor for `entry`/`changes` in secrets-admin, not in secrets.js.");
        it.shot(await H.shot(page, "06-no-custom-control"));
    }

    /* --- attachment: upload ---------------------------------------------- */
    const tmp = path.join(os.tmpdir(), "cockpit-secrets-live-attachment.txt");
    const attachBody = "live walkthrough attachment " + Date.now() + "\n";
    fs.writeFileSync(tmp, attachBody);
    const addAttach = frame.locator('#sec-detail button:text-is("Add an attachment…")');
    if (await addAttach.count()) {
        await addAttach.click();
        await frame.waitForSelector(".sec-modal", { timeout: 15000 });
        await fillLabelled(frame, "Name", "walkthrough.txt");
        await setLabelledFile(frame, "Attachment content", tmp);
        await runButton(frame).click();
        await frame.locator(".sec-modal").last().waitFor({ state: "detached", timeout: 60000 })
                   .catch(() => {});
        await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
        await frame.waitForSelector("#sec-detail h4", { timeout: 15000 });
        const txt = await frame.locator("#sec-detail").innerText();
        it.ok(/Attachments/.test(txt) && !/^\s*None\.\s*$/m.test(txt),
              "the attachment was added and the detail pane reports one");
        it.shot(await H.shot(page, "06-attached"));
    } else {
        it.fail("the detail pane offers no “Add an attachment…” control for a writable safe");
    }

    /* --- attachment: download -------------------------------------------- */
    /* The Download control only exists when the page knows the attachment's
     * NAME. `entries` sends `attachments` as a COUNT (backends/kdbx.py:1796 —
     * `len(entry.attachments)`) and the helper publishes no attach-list verb,
     * so the page correctly says it cannot name one rather than guessing. That
     * is a capability gap in secrets-admin, and the control below proves the
     * bytes themselves are reachable. */
    const dl = frame.locator('#sec-detail button:text-is("Download")');
    if (await dl.count()) {
        const [download] = await Promise.all([
            page.waitForEvent("download", { timeout: 30000 }),
            dl.first().click()
        ]);
        const to = path.join(H.artifactsDir(), "06-downloaded-attachment.bin");
        await download.saveAs(to);
        const got = fs.readFileSync(to, "utf8");
        it.ok(got === attachBody,
              "the attachment downloaded through the Cockpit channel byte for byte");
    } else {
        const said = await frame.locator("#sec-detail").innerText();
        const honest = /publishes no verb that lists them/.test(said);
        it.ok(false, "no Download control is offered for the attachment just added — " +
              "`entries` sends a COUNT, not names, and the helper publishes no " +
              "attach-list verb, so the page cannot name the file to fetch" +
              (honest ? " (the page says exactly that, rather than guessing a name)" : ""));
        const via = await spawnVerb(frame, "attach-get", {
            safe: state.safe.id, password: state.pass,
            uuid: await selectedUuid(frame, state), name: "walkthrough.txt"
        }, classOf(state.safe) === "admin" ? "require" : null);
        const vo = parseMaybe(via.out);
        it.note("attach-get for the same name, driven through cockpit.spawn, answers " +
                JSON.stringify(vo && (vo.error || { name: vo.name, size: vo.size })) +
                " — the bytes ARE reachable; only the NAME is unreachable from the page.");
    }

    /* --- history ---------------------------------------------------------- */
    const showHist = frame.locator('#sec-detail button:text-is("Show history")');
    if (await showHist.count()) {
        await showHist.click();
        await frame.waitForSelector("#sec-detail .sec-hist-row, #sec-detail .sec-alert.err",
                                    { timeout: 30000 }).catch(() => {});
        const nrows = await frame.locator("#sec-detail .sec-hist-row").count();
        it.ok(nrows > 0, "history lists " + nrows + " previous version(s) after the edit");
        if (nrows > 0) {
            /* Never a password: the helper does not send one and the page has
             * nothing to mask. A history row that contained the value would be
             * the single worst regression in this program. */
            const hist = await frame.locator("#sec-detail .sec-hist-row").allInnerTexts();
            const leaked = state.revealed && hist.some((h) => h.indexOf(state.revealed) >= 0);
            it.ok(!leaked, "no history row carries a password value");
        }
        it.shot(await H.shot(page, "06-history"));
    } else {
        it.fail("the detail pane offers no history control although the helper publishes the verb");
    }

    /* --- save --------------------------------------------------------------
     * #sec-alerts holds ONE alert at a time and every mutation above has
     * already written one into it, so waiting for ".sec-alert.ok" to exist
     * returns instantly on the PREVIOUS result and reads the wrong sentence.
     * Wait for the save's own wording instead. (Caught by running this spec's
     * selectors against the package's stub harness.) */
    await frame.locator("#sec-save").click();
    const confirm = frame.locator('.sec-modal:has-text("Write the safe to disk?")');
    if (await confirm.count()) await confirm.locator('button:text-is("Save")').click();
    const saveOutcome = await waitForSaveOutcome(frame);
    const saidSave = String((saveOutcome && saveOutcome.text) || "");
    it.ok(!!saveOutcome && saveOutcome.ok,
          "Save wrote the safe: " + JSON.stringify(saidSave.slice(0, 200)));
    it.ok(/previous copy kept at/.test(saidSave),
          "the save names the backup it took before the first new byte existed (I12)");
    it.shot(await H.shot(page, "06-saved"));

    /* --- reopen and confirm persistence ------------------------------------ */
    await frame.locator('#sec-browse-tools button:text-is("Lock")').click();
    const dirty2 = frame.locator('.sec-modal:has-text("Lock with unsaved changes?")');
    if (await dirty2.count()) await dirty2.locator('button:text-is("Discard and lock")').click();
    await frame.waitForSelector("#sec-safes-view:not([hidden])", { timeout: 30000 });
    await openUnlockDialog(frame, state.safe.id);
    await submitUnlock(frame, state.pass);
    await frame.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 });
    await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 });
    const back = await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).count();
    it.ok(back > 0, "after lock and a fresh unlock the entry is still there — it persisted to disk");
    it.shot(await H.shot(page, "06-reopened"));

    it.done();
}

/* The uuid of the entry the detail pane is showing.
 *
 * The page deliberately does not put a uuid in the markup — a row is addressed
 * by its title cell and the uuid lives in the closure — so the only honest way
 * to get one from outside is to ask the helper, which is what the two
 * bridge-driven controls in item 6 need it for anyway. That is a single-shot
 * `entries` call with the safe's own credentials: the same door, one more
 * passphrase prompt's worth of work, and no page internals reached into. */
async function selectedUuid(frame, state) {
    const title = (await frame.locator("#sec-detail h3").innerText().catch(() => "")).trim();
    if (!title) return null;
    const r = await spawnVerb(frame, "entries", {
        safe: state.safe.id, password: state.pass, query: title, limit: 50
    }, classOf(state.safe) === "admin" ? "require" : null);
    const o = parseMaybe(r.out);
    if (o && Array.isArray(o.entries)) {
        const hit = o.entries.find((e) => e.title === title);
        if (hit) return hit.uuid;
    }
    return null;
}

/* ================================================================== item 7 */
async function item7(browser, page, frame, state, accountPassword) {
    const it = REC.item(7, ITEMS[7]);
    console.log("\n== 7. " + ITEMS[7] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }
    if (state.safe.mode === "ro") {
        it.skip("safe “" + state.safe.id + "” is read-only, so no save can conflict.");
        it.done();
        return;
    }

    /* THE SAFE IS MODIFIED ON DISK BY A SECOND OPERATOR, THROUGH THE PAGE.
     *
     * Writing the file from the shell would need root for an admin-class safe
     * and would prove less: two Cockpit sessions racing each other is the real
     * lost-update this hazard is about (I13), it needs no privilege this suite
     * does not have, and every byte still goes through the helper's own atomic
     * write. Session A holds an unsaved change; session B saves; A then saves
     * and must be refused. */
    const ctxB = await H.newContext(browser);
    let refused = null;
    try {
        const pageB = await H.login(ctxB, H.CFG.admin, accountPassword);
        const frameB = await H.openPlugin(pageB);

        /* A: an unsaved change. */
        if (!(await inBrowseView(frame))) {
            await openUnlockDialog(frame, state.safe.id);
            await submitUnlock(frame, state.pass);
            await frame.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 });
        }
        const aTitle = "conflict-A-" + Date.now();
        await addEntry(frame, aTitle);
        it.note("session A holds an unsaved entry: " + aTitle);

        /* B: a change, saved — the file on disk moves under A. */
        await openUnlockDialog(frameB, state.safe.id);
        await submitUnlock(frameB, state.pass);
        await frameB.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 });
        const bTitle = "conflict-B-" + Date.now();
        await addEntry(frameB, bTitle);
        await frameB.locator("#sec-save").click();
        const cB = frameB.locator('.sec-modal:has-text("Write the safe to disk?")');
        if (await cB.count()) await cB.locator('button:text-is("Save")').click();
        const bSaved = await waitForSaveOutcome(frameB);
        it.ok(!!bSaved && bSaved.ok, "session B's save landed: " +
              JSON.stringify(String((bSaved && bSaved.text) || "").slice(0, 160)));
        it.note("session B saved " + bTitle + ", so the file on disk changed under A");
        it.shot(await H.shot(pageB, "07-session-b-saved"));

        /* A: save. The helper compares size, mtime and SHA-256 against what it
         * read at unlock and refuses (I13). */
        await frame.locator("#sec-save").click();
        const cA = frame.locator('.sec-modal:has-text("Write the safe to disk?")');
        if (await cA.count()) await cA.locator('button:text-is("Save")').click();

        refused = await frame.locator('.sec-modal:has-text("The safe changed on disk")')
                             .waitFor({ timeout: 60000 }).then(() => true).catch(() => false);
    } finally {
        await ctxB.close();
    }

    if (!refused) {
        const alerts = (await frame.locator("#sec-alerts").innerText().catch(() => "")).trim();
        it.fail("session A's save was NOT refused with a conflict. The page shows: " +
                JSON.stringify(alerts.slice(0, 240)));
        it.shot(await H.shot(page, "07-no-conflict"));
        it.done();
        return;
    }

    const dlg = frame.locator('.sec-modal:has-text("The safe changed on disk")').last();
    it.ok(true, "the save was refused and the page opened a decision dialog");

    /* A DECISION, NOT AN ALERT. Three named ways forward, an explanation that
     * nothing was written, and no Escape hatch that would dismiss it by
     * accident — the dialog is built with noEscape for that reason. */
    const choices = [];
    for (const label of ["Discard mine and reload", "Keep my changes here"]) {
        const n = await dlg.locator(`button:text-is("${label}")`).count();
        choices.push(label + "=" + n);
        it.ok(n > 0, "the dialog offers “" + label + "”");
    }
    const saveAs = await dlg.locator("button").allInnerTexts();
    it.ok(saveAs.some((t) => /save as|save a copy/i.test(t)),
          "the dialog offers a save-as route as well: " + JSON.stringify(saveAs));
    const body = await dlg.innerText();
    it.ok(/Nothing has been written/i.test(body),
          "the dialog states that nothing was written");
    it.ok(/never merge|refuses rather than merging|rather than merging/i.test(body),
          "the dialog states that it refuses rather than merging");

    /* Frame has no keyboard of its own; the input goes to the page that owns it,
     * and the focused element is inside this frame. */
    await frame.page().keyboard.press("Escape");
    it.ok(await dlg.isVisible(),
          "Escape does not dismiss it — a conflict is a decision the operator has to make");
    it.shot(await H.shot(page, "07-conflict"));

    /* Leave the safe as B wrote it: A's changes are the ones to drop, because B
     * is the write that actually landed. */
    await dlg.locator('button:text-is("Discard mine and reload")').click();
    await frame.waitForSelector("#sec-safes-view:not([hidden])", { timeout: 30000 });
    it.ok(true, "“Discard mine and reload” locks the safe so it can be re-read — " +
          "and re-reading it means being asked for the passphrase again");
    it.done();
}

/* The outcome of a save, read from the page's single alert slot.
 *
 * #sec-alerts holds exactly one alert: alertBox() clears the host before it
 * appends. Every mutation writes its own result there, so "wait until a .ok
 * alert exists" is satisfied by whatever was already on screen and reads the
 * previous verb's sentence. The save is identified by its OWN wording, which
 * secrets.js builds as "Saved — N bytes, previous copy kept at …". A conflict
 * never reaches here: doSaveNow() routes that to the conflict dialog instead of
 * an alert, which is item 7's whole subject. */
async function waitForSaveOutcome(frame, timeout) {
    const h = await frame.waitForFunction(() => {
        const n = document.querySelector("#sec-alerts .sec-alert");
        if (!n) return null;
        const t = (n.textContent || "").trim();
        if (/^Saved/.test(t)) return { ok: true, text: t };
        if (n.classList.contains("err")) return { ok: false, text: t };
        return null;
    }, null, { timeout: timeout || 60000 }).catch(() => null);
    return h ? h.jsonValue() : null;
}

async function addEntry(frame, title) {
    await frame.locator('#sec-browse-tools button:text-is("Add entry…")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await fillLabelled(frame, "Title", title);
    await runButton(frame).click();
    await frame.locator(".sec-modal").last().waitFor({ state: "detached", timeout: 60000 })
               .catch(() => {});
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`)
               .waitFor({ timeout: 30000 });
}

/* ================================================================= item 10 */
async function item10(page, frame, state) {
    const it = REC.item(10, ITEMS[10]);
    console.log("\n== 10. " + ITEMS[10] + " ==");

    /* The zoom half needs no safe and no unlock: it is a property of the page
     * as it stands, so it runs whatever else was reachable. Splitting the item
     * this way is the difference between "not attempted" and "half of it was
     * attempted and held" — and only one of those is true here. */
    await zoomHalf(page, frame, it);

    if (!state) {
        it.note("the keyboard half needs an unlock dialog, and item 3 never reached a " +
                "successful unlock, so the focus trap was NOT driven live. It is covered " +
                "against the same markup under the stub harness by tests/browser/ui.spec.js " +
                "(\"the focus trap holds after 30 tabs\"), which is a different thing from " +
                "having been driven here.");
        it.done();
        return;
    }

    /* Back to the safe list, then open the unlock dialog and never touch the
     * mouse again. */
    if (await inBrowseView(frame)) {
        await frame.locator('#sec-browse-tools button:text-is("Lock")').click();
        const d = frame.locator('.sec-modal:has-text("Lock with unsaved changes?")');
        if (await d.count()) await d.locator('button:text-is("Discard and lock")').click();
        await frame.waitForSelector("#sec-safes-view:not([hidden])", { timeout: 30000 });
    }
    await openUnlockDialog(frame, state.safe.id);

    /* Focus lands inside the dialog when it opens — modal() focuses the first
     * focusable rather than leaving the caret on the page behind. */
    const opened = await frame.evaluate(() =>
        !!(document.activeElement && document.activeElement.closest(".sec-modal")));
    it.ok(opened, "opening the dialog moves focus into it");

    /* The trap. Tab more times than there are focusable controls and focus must
     * still be inside: it wraps rather than walking out into the page behind. */
    const n = await frame.evaluate(() => {
        const m = document.querySelector(".sec-backdrop .sec-modal");
        return m ? m.querySelectorAll("a[href], button, input, select, textarea, [tabindex]").length : 0;
    });
    let escaped = null;
    for (let i = 0; i < n + 3; i++) {
        await frame.locator(".sec-modal").last().press("Tab");
        const inside = await frame.evaluate(() =>
            !!(document.activeElement && document.activeElement.closest(".sec-modal")));
        if (!inside) { escaped = i; break; }
    }
    it.ok(escaped === null,
          "Tab pressed " + (n + 3) + " times never leaves the dialog (focus trap holds)");

    /* And backwards: Shift+Tab off the first control wraps to the last. */
    await frame.evaluate(() => {
        const m = document.querySelector(".sec-backdrop .sec-modal");
        const f = m.querySelectorAll("a[href], button, input, select, textarea, [tabindex]");
        for (const n of f) if (!n.disabled && n.tabIndex !== -1 && n.offsetParent !== null) { n.focus(); return; }
    });
    await frame.locator(".sec-modal").last().press("Shift+Tab");
    const backWrapped = await frame.evaluate(() =>
        !!(document.activeElement && document.activeElement.closest(".sec-modal")));
    it.ok(backWrapped, "Shift+Tab from the first control wraps to the last, still inside");

    /* Keyboard-only unlock: tab to the passphrase box, type, press Enter. The
     * dialog has no <form>, so Enter is handled explicitly — which is exactly
     * the kind of thing that regresses unnoticed. */
    const pwId = await frame.evaluate(() => {
        const m = document.querySelector(".sec-backdrop .sec-modal");
        const i = m.querySelector("input[type=password]");
        return i ? i.id : null;
    });
    await frame.locator("#" + pwId).focus();
    await frame.page().keyboard.type(state.pass);
    await frame.page().keyboard.press("Enter");
    const unlocked = await frame.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 120000 })
                                .then(() => true).catch(() => false);
    it.ok(unlocked, "Enter in the passphrase box submits the unlock — no pointer needed");
    it.shot(await H.shot(page, "10-keyboard-unlock"));

    /* Escape closes an ordinary dialog. Checked on one that is allowed to be
     * dismissed — the conflict dialog is deliberately not, and item 7 checks
     * that side of it. */
    await frame.locator('#sec-browse-tools button:text-is("Generate password…")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await frame.locator(".sec-modal").last().press("Escape");
    const closed = await frame.locator(".sec-modal").count();
    it.ok(closed === 0, "Escape closes an ordinary dialog");

    it.done();
}

/* 200%, as a layout change rather than a screenshot filter.
 *
 * Browser zoom re-lays-out the page against a smaller CSS viewport; the
 * layout-equivalent of 200% at 1400x950 is 700x475. Emulating it that way keeps
 * the assertion the one that matters at any zoom and is the WCAG 1.4.10
 * failure when it does not hold: the page must not scroll sideways, and the
 * controls must still be on screen. */
async function zoomHalf(page, frame, it) {
    await page.setViewportSize({ width: 700, height: 480 });
    await page.waitForTimeout(500);
    const overflow = await frame.evaluate(() => {
        const d = document.documentElement;
        return { scrollW: d.scrollWidth, clientW: d.clientWidth };
    });
    it.ok(overflow.scrollW <= overflow.clientW + 2,
          "no horizontal overflow at 200% (scrollWidth " + overflow.scrollW +
          " vs clientWidth " + overflow.clientW + ")");
    it.ok(await frame.locator("#sec-refresh").isVisible(),
          "the topbar controls are still on screen at 200%");
    it.shot(await H.shot(page, "10-zoom-200"));
    await page.setViewportSize({ width: 1400, height: 950 });
    await page.waitForTimeout(300);
}

/* ---------------------------------------------------------------- report -- */
function finish() {
    const s = REC.summary();
    console.log("\n== live-ui result ==");
    ORDER.forEach((k) => {
        const r = s.items.find((x) => String(x.id) === String(k));
        const st = r ? r.state : "NOT-ATTEMPTED";
        const c = st === "PASS" ? "\x1b[32m" : st === "FAIL" ? "\x1b[31m" : "\x1b[33m";
        console.log("  " + c + st + "\x1b[0m  " + k + ". " + ITEMS[k] +
                    (r && r.why ? "\n         reason: " + r.why : ""));
    });
    console.log("  " + (s.checks - s.bad) + "/" + s.checks + " checks held");
    H.writeArtifact("live-ui-result.json", JSON.stringify(s.items, null, 2) + "\n");
    process.exitCode = s.bad ? 1 : 0;
}

if (require.main === module) main();
module.exports = { classOf, reachable, pickSafe, cardFor, openUnlockDialog, submitUnlock,
                   waitForSaveOutcome,
                   spawnVerb, parseMaybe, controlIdByLabel, fillLabelled, runButton, ITEMS };
