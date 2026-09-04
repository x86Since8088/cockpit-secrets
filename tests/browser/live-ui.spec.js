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
    5: "The passphrase is demanded EVERY time: after a lock, after a page reload, and in a fresh tab",
    6: "Full management in BOTH formats: add, edit, custom field, attach, list, download, history, save, reopen",
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

/* One writable, reachable, passphrase-bearing safe PER FORMAT.
 *
 * Item 6 says "both formats", and a KDBX file and a Password Safe v3 file do
 * not merely differ in their bytes: a PWS3 record is a list of TYPED fields, so
 * custom fields are `unsupported` and only one attachment can exist. Driving
 * one format and reporting "management works" would be a claim about half the
 * program. One safe per format is the smallest set that cannot say that. */
function pickPerFormat(list) {
    const out = [];
    const seen = {};
    for (const s of ((list && list.safes) || [])) {
        if (!reachable(s)) continue;
        if (s.mode === "ro") continue;
        if (!H.safePassphrase(s.id)) continue;
        const f = String(s.format || "?");
        if (seen[f]) continue;
        seen[f] = 1;
        out.push(s);
    }
    return out;
}

/* The card for one registry id. `.sec-safe-id` carries the id verbatim, which
 * is what makes a card addressable without depending on its label. */
function cardFor(frame, id) {
    return frame.locator(".sec-safe").filter({
        has: frame.locator(`.sec-safe-id:text-is("${id}")`)
    });
}

/* WAIT FOR THE LIST TO HAVE LANDED, not merely for the page to have started.
 *
 * `openPlugin()` returns as soon as init() has rewritten #sec-sub from the
 * schema — which is a DIFFERENT verb from `list`, answered by a different
 * helper process. Counting cards straight after it reads an empty #sec-safes
 * that still says "Loading the safe registry…", and an assertion about how many
 * safes are unreachable then passes or fails on which spawn won a race.
 *
 * Measured, not theorised: this is exactly how item 2 read "cptest sees 0
 * safe(s) rendered unreachable" against a page that a moment later showed two
 * (artifacts/02-safes-nonadmin.png from that run is the "Loading…" state).
 * A settled list is one with cards, an explicit empty-registry line, or an
 * error — all three are answers; "Loading…" is not. */
async function waitForSafeList(frame, timeout) {
    await frame.waitForFunction(() => {
        const host = document.getElementById("sec-safes");
        if (!host) return false;
        if (host.querySelector(".sec-safe")) return true;
        if (host.querySelector(".sec-alert")) return true;
        const t = (host.textContent || "").trim();
        return !!t && !/^Loading/i.test(t);
    }, null, { timeout: timeout || 30000 });
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

/* WHAT THE UNLOCK ACTUALLY DID — the browse view, or the helper's error code.
 *
 * `submit()` in secrets.js clears the dialog's error host and disables Unlock
 * before it spawns, so by the time this starts polling the PREVIOUS attempt's
 * alert is already gone and what it reads is this attempt's answer. */
async function unlockOutcome(frame, timeout) {
    const h = await frame.waitForFunction(() => {
        const v = document.getElementById("sec-browse-view");
        if (v && !v.hidden) return { ok: true, code: "", detail: "" };
        const modal = document.querySelector(".sec-backdrop .sec-modal");
        if (!modal) return null;
        const a = modal.querySelector(".sec-alert.err");
        if (!a) return null;
        const c = a.querySelector(".sec-code");
        return { ok: false,
                 code: String((c && c.textContent) || "").trim(),
                 detail: String(a.textContent || "").trim().slice(0, 240) };
    }, null, { timeout: timeout || 120000 }).catch(() => null);
    return h ? h.jsonValue() : null;
}

/* Unlock with the CORRECT passphrase, waiting out I16's backoff.
 *
 * ONE WRONG PASSPHRASE IS ENOUGH TO REFUSE THE RIGHT ONE, and that is the
 * program working. `lockout_fail()` writes locked_until = now + 2 s
 * (LOCKOUT_BASE_SECONDS) after a single failure, so item 3's correct attempt —
 * typed a second later, because a screenshot and four assertions happen in
 * between — comes back `locked-out`, not unlocked. Measured on the first live
 * run of this suite: "too many failed unlock attempts for this safe; try again
 * in 1 seconds", and the suite then sat on #sec-browse-view for its whole
 * 120 s timeout and reported the walkthrough as aborted.
 *
 * The wait is taken from the helper's OWN sentence rather than from a constant
 * copied out of secrets-admin: a suite that hard-coded 2 s would keep passing
 * after the backoff policy changed, which is the failure this file exists to
 * avoid. The retry budget is bounded, and a refusal that is not `locked-out` is
 * returned immediately — a wrong passphrase must never be retried. */
async function unlockAndWaitOutBackoff(frame, pass, it, budgetMs) {
    const deadline = Date.now() + (budgetMs || 180000);
    let waited = 0;
    for (;;) {
        await submitUnlock(frame, pass);
        const out = await unlockOutcome(frame);
        if (!out) return { ok: false, code: "timeout", detail: "", waited };
        if (out.ok || out.code !== "locked-out") return Object.assign(out, { waited });
        const m = /in (\d+) second/.exec(out.detail);
        const pause = (m ? Math.max(1, Number(m[1])) : 3) * 1000 + 750;
        if (Date.now() + pause > deadline) return Object.assign(out, { waited });
        if (it) it.note("the helper is in its I16 backoff (" +
                        JSON.stringify(out.detail.slice(0, 90)) +
                        ") — waiting it out and trying the correct passphrase again");
        waited += pause;
        await frame.page().waitForTimeout(pause);
    }
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
 * verb the helper marked destructive, so both have to be accepted — but it is
 * found by WHERE it is, not only by its class.
 *
 * THIS SELECTOR USED TO CLICK THE WRONG BUTTON, and the failure was silent.
 * It was `.sec-modal button.primary, button.danger` filtered on "not Cancel",
 * first match — which was fine until the custom-field row editor arrived and
 * put a `danger tiny` "Remove" button in the form ABOVE the action row. From
 * then on every Add and every Edit in this suite clicked Remove: the row
 * vanished, the dialog stayed open, no error was shown because nothing had gone
 * wrong, and the assertion failed thirty seconds later as "the entry never
 * appeared in the listing". Measured with a probe that dumped the modal's
 * buttons before and after the click — three Show/Generate pairs before, two
 * after, and no Remove.
 *
 * actionRow() puts the dialog's own buttons in `.sec-form-actions`, so that is
 * where the run button is looked for. The old selector is kept as a fallback
 * for a dialog built without an action row, but scoped to the LAST such button
 * so an in-form control cannot win it. */
function runButton(frame) {
    const modal = frame.locator(".sec-modal").last();
    const inActions = modal.locator(".sec-form-actions button.primary, .sec-form-actions button.danger")
                           .filter({ hasNotText: "Cancel" });
    return inActions.or(modal.locator("button.primary, button.danger")
                             .filter({ hasNotText: "Cancel" }).last()).first();
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
        await waitForSafeList(frame);
        /* THE BASELINE FOR I11, taken before a single safe has been opened.
         * The storage areas belong to Cockpit's origin and are not empty, so
         * the only honest form of "this page stored nothing" is a difference
         * against what was already there. Everything item 4 and item 5 assert
         * about storage is measured against this snapshot. */
        const storage0 = await readStorage(frame);
        console.log("   storage before any unlock: local " +
                    JSON.stringify(Object.keys(storage0.local)) + ", session " +
                    JSON.stringify(Object.keys(storage0.session)));
        const list = await H.liveList(frame);
        H.writeArtifact("live-list.json", JSON.stringify(list, null, 2) + "\n");
        await item2(browser, page, frame, list);
        state = await item3(page, frame, list);
        if (state) state.storage0 = storage0;
        await item4(page, frame, state);
        /* item 5 navigates: it reloads the page and opens a second tab, so the
         * frame handle it hands back is the live one and the old one is gone. */
        frame = (await item5(ctx, page, frame, state)) || frame;
        await item6(page, frame, state, list);
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
            /* openPlugin() returns when the SCHEMA has landed; the safe list is
             * a different verb and a different helper process. Counting cards
             * here without waiting read "0 unreachable" off a page still saying
             * "Loading the safe registry…" — a false FAIL that this suite has
             * now made twice, once for #sec-safes and once here. */
            await waitForSafeList(f2);
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

    /* --- the right passphrase unlocks -----------------------------------
     * Through unlockAndWaitOutBackoff, because the wrong attempt above has
     * just armed I16's backoff and the correct passphrase is legitimately
     * refused inside it. Waiting it out is not a workaround: the refusal IS
     * the feature, and the assertion that matters is that the correct
     * passphrase opens the safe once the window has passed. */
    const opened = await unlockAndWaitOutBackoff(frame, pass, it);
    if (opened && opened.waited)
        it.note("waited " + Math.round(opened.waited / 1000) + " s of I16 backoff, " +
                "armed by this item's own single wrong attempt");
    it.ok(!!(opened && opened.ok),
          "the correct passphrase unlocks and the browse view opens" +
          (opened && !opened.ok ? " — got " + JSON.stringify(opened.code + ": " + opened.detail) : ""));
    if (!(opened && opened.ok)) {
        it.done();
        return null;
    }

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

    /* --- reveal shows a value and re-masks on its countdown --------------
     *
     * NOT simply the first row. This suite ADDS entries — item 6 adds one per
     * format and item 7 adds two more to make its conflict — and item 7's are
     * created with a title and nothing else, because a title is all a conflict
     * needs. Sorted into the listing they come first, so a second run of this
     * suite revealed the Password of an entry that has none and read "Reveal
     * shows a value (0 characters)". That was a true statement about the entry
     * and a useless test of the control, so the entry is now CHOSEN: walk the
     * listing until one has a password to show, and say so if none does. */
    let widget = null, masked = null, shown = "";
    const consider = Math.min(rows, 6);
    for (let i = 0; i < consider; i++) {
        await frame.locator("#sec-entries table.sec tbody tr").nth(i)
                   .locator("td button.sec-btn.link").click();
        await frame.waitForSelector("#sec-detail .sec-reveal", { timeout: 20000 });
        const w = frame.locator("#sec-detail .sec-reveal").filter({
            has: frame.locator('.sec-reveal-label:text-is("Password")')
        }).first();
        if (!(await w.count())) continue;
        const m = (await w.locator(".sec-value").innerText()).trim();
        await w.locator('button:text-is("Reveal")').click();
        await w.locator(".sec-value:not(.masked)").waitFor({ timeout: 30000 });
        const v = await w.locator(".sec-value").innerText();
        if (v.length && v !== m) { widget = w; masked = m; shown = v; break; }
        it.note("entry " + (i + 1) + " of " + consider + " has an EMPTY password — the " +
                "reveal answered and there was nothing in the field; trying the next entry");
    }
    it.ok(widget !== null, "the detail pane offers a Password reveal control and an entry " +
          "with a password was found within the first " + consider + " row(s)");
    if (!widget) { it.done(); return null; }
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

/* Both web-storage areas as {key: valueLENGTH}, plus the cookie NAMES.
 *
 * Lengths and names only. A helper written for an I11 test that returned the
 * values would put every one of them into this suite's own memory and into any
 * artefact that printed it, which is the hazard rather than a check of it. */
async function readStorage(target) {
    return target.evaluate(() => {
        const dump = (s) => {
            const o = {};
            try {
                for (let i = 0; i < s.length; i++) {
                    const k = s.key(i);
                    o[k] = String(s.getItem(k) || "").length;
                }
            } catch (e) { /* a storage area the browser refuses is not a leak */ }
            return o;
        };
        return {
            local: dump(window.localStorage),
            session: dump(window.sessionStorage),
            cookies: String(document.cookie || "").split(";")
                        .map((c) => c.split("=")[0].trim()).filter(Boolean)
        };
    });
}

/* Which keys appeared between two readStorage() snapshots. A key whose VALUE
 * changed counts too: overwriting Cockpit's own key with a passphrase would
 * otherwise slip through a names-only comparison. */
function storageAdded(before, after) {
    const diff = (b, a) => Object.keys(a).filter(
        (k) => !Object.prototype.hasOwnProperty.call(b, k) || b[k] !== a[k]);
    return { local: diff(before.local, after.local),
             session: diff(before.session, after.session) };
}

function sameKeys(a, b) {
    const eq = (x, y) => {
        const kx = Object.keys(x).sort(), ky = Object.keys(y).sort();
        return kx.length === ky.length && kx.every((k, i) => k === ky[i]);
    };
    return eq(a.local, b.local) && eq(a.session, b.session);
}

/* ================================================================== item 4 */
async function item4(page, frame, state) {
    const it = REC.item(4, ITEMS[4]);
    console.log("\n== 4. " + ITEMS[4] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }

    /* THE STORAGE AREAS ARE THE ORIGIN'S, AND THE ORIGIN IS COCKPIT'S.
     *
     * This assertion used to read `localStorage.length === 0` in the plugin
     * frame, and it FAILED on a page that had written nothing. A Cockpit
     * package page is an iframe on the SAME origin as the shell
     * (https://localhost:9090), so localStorage and sessionStorage are one
     * shared area and Cockpit itself keeps things in it — measured on this
     * host: the same three local and two session keys are visible from the
     * shell page and from inside the plugin frame, and they are there before
     * this package is ever opened. There is no way for this page to make that
     * number zero and it was never this page's number to make.
     *
     * What I11 actually says is that THIS PAGE writes nothing there, so the
     * check is a DIFFERENCE and not an absolute: nothing appeared in either
     * area across the unlock, no key names this package, and no key or value
     * anywhere holds the passphrase. A page that stashed a passphrase would
     * fail the first of those, which is the one the old assertion was reaching
     * for and missing. The key names are printed so a reader can see whose
     * they are rather than taking "Cockpit's, not ours" on trust. */
    const inFrame = await readStorage(frame);
    const inShell = await readStorage(page);
    const added = state.storage0 ? storageAdded(state.storage0, inFrame) : null;
    it.note("storage in the plugin frame: local " + JSON.stringify(Object.keys(inFrame.local)) +
            ", session " + JSON.stringify(Object.keys(inFrame.session)));
    it.note("storage in Cockpit's shell page: local " + JSON.stringify(Object.keys(inShell.local)) +
            ", session " + JSON.stringify(Object.keys(inShell.session)));
    it.ok(sameKeys(inFrame, inShell),
          "the plugin frame's storage IS Cockpit's — same origin, same keys — so the " +
          "count can never be zero and the question is what THIS page added");
    if (added) {
        it.ok(!added.local.length && !added.session.length,
              "the unlock added NOTHING to either storage area (" +
              JSON.stringify(added.local) + " local, " + JSON.stringify(added.session) +
              " session, against the baseline taken before any safe was opened)");
    } else {
        it.note("no pre-unlock storage baseline was captured, so 'added nothing' could not " +
                "be checked as a difference; the ownership and passphrase checks below stand.");
    }
    const ours = Object.keys(inFrame.local).concat(Object.keys(inFrame.session))
                       .filter((k) => /secret|^sec[-_.:]/i.test(k));
    it.ok(!ours.length,
          "no storage key belongs to this package (" + JSON.stringify(ours) + ")");

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
async function item5(ctx, page, frame, state) {
    const it = REC.item(5, ITEMS[5]);
    console.log("\n== 5. " + ITEMS[5] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return frame; }
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

    /* ---- ACROSS A PAGE RELOAD ------------------------------------------
     * The lock above was a decision this page made. A reload is not: the whole
     * of secrets.js is thrown away and rebuilt from the file Cockpit serves,
     * and anything that survived it would have survived it in the BROWSER —
     * which is the only place I11 says nothing may survive. So the safe must
     * come back locked, and the next operation must ask again, with an empty
     * box. Do it after leaving a safe unlocked, or the reload proves nothing:
     * a page that was already on the safe list would look identical. */
    await openUnlockDialog(frame, state.safe.id);
    const reOpen = await unlockAndWaitOutBackoff(frame, state.pass, it);
    if (!(reOpen && reOpen.ok)) {
        it.fail("could not re-unlock the safe to set up the reload check: " +
                JSON.stringify(reOpen && (reOpen.code + ": " + reOpen.detail)));
        it.done();
        return frame;
    }
    it.note("the safe is unlocked and the browse view is open — now reloading the page");

    await page.reload({ waitUntil: "domcontentloaded" });
    frame = await H.openPlugin(page);
    await waitForSafeList(frame);
    it.ok(!(await inBrowseView(frame)),
          "after a full page reload the safe is LOCKED again — the browse view is gone");
    await openUnlockDialog(frame, state.safe.id);
    const boxR = frame.locator(".sec-modal input[type=password]").last();
    it.ok(await boxR.isVisible(),
          "the first operation after a reload demands the passphrase again");
    it.ok((await boxR.inputValue()) === "",
          "…and its box is EMPTY: a reload cannot restore what was never kept");
    /* And the storage areas, at the one moment a "we remembered it" bug would
     * have had to leave something behind to be able to skip this prompt. */
    const afterReload = await readStorage(frame);
    const addedR = state.storage0 ? storageAdded(state.storage0, afterReload)
                                  : { local: [], session: [] };
    const hitR = await frame.evaluate((needle) => {
        const dump = (s) => {
            let o = "";
            for (let i = 0; i < s.length; i++) o += s.key(i) + "=" + s.getItem(s.key(i)) + "\n";
            return o;
        };
        return dump(localStorage).indexOf(needle) >= 0 ||
               dump(sessionStorage).indexOf(needle) >= 0 ||
               document.cookie.indexOf(needle) >= 0;
    }, state.pass);
    /* Against the pre-unlock baseline, not against zero: the areas are
     * Cockpit's own and were never empty (see item 4). */
    it.ok(!addedR.local.length && !addedR.session.length && !hitR,
          "nothing was carried across the reload — no storage key appeared or changed " +
          "since before the first unlock (" + JSON.stringify(addedR.local) + " local, " +
          JSON.stringify(addedR.session) + " session) and the passphrase is not in either " +
          "area or in any cookie");
    it.shot(await H.shot(page, "05-prompted-after-reload"));
    await frame.locator('.sec-modal button:text-is("Cancel")').last().click();

    /* ---- IN A FRESH TAB -------------------------------------------------
     * Same Cockpit session, same cookie, same origin, a second page object —
     * which is what an operator does when they open the console again in
     * another tab. The storage areas are per-ORIGIN, so this is the check that
     * would fail if a passphrase had been parked somewhere a second tab could
     * read: the first tab's unlock must buy the second tab nothing. */
    const tab2 = await ctx.newPage();
    try {
        H.watchConsole(tab2);
        const f2 = await H.openPlugin(tab2);
        await waitForSafeList(f2);
        it.ok(!(await inBrowseView(f2)),
              "a fresh tab in the same Cockpit session opens on the safe list, not into a safe");
        await openUnlockDialog(f2, state.safe.id);
        const box2 = f2.locator(".sec-modal input[type=password]").last();
        it.ok(await box2.isVisible(),
              "the fresh tab demands the passphrase for the same safe");
        it.ok((await box2.inputValue()) === "",
              "…and its box is EMPTY too — the first tab's unlock bought it nothing");
        const s2 = await readStorage(f2);
        const added2 = state.storage0 ? storageAdded(state.storage0, s2)
                                      : { local: [], session: [] };
        const hit2 = await f2.evaluate((needle) => {
            const dump = (s) => {
                let o = "";
                for (let i = 0; i < s.length; i++) o += s.key(i) + "=" + s.getItem(s.key(i)) + "\n";
                return o;
            };
            return dump(localStorage).indexOf(needle) >= 0 ||
                   dump(sessionStorage).indexOf(needle) >= 0 ||
                   document.cookie.indexOf(needle) >= 0 ||
                   document.documentElement.outerHTML.indexOf(needle) >= 0;
        }, state.pass);
        /* sessionStorage is per-TAB, localStorage is per-origin — so this tab
         * genuinely could have read anything the first one left in the shared
         * area, and it found nothing to read. */
        it.ok(!added2.local.length && !added2.session.length && !hit2,
              "the fresh tab sees no key this session added (" + JSON.stringify(added2.local) +
              " local, " + JSON.stringify(added2.session) + " session) and neither its " +
              "storage nor its DOM holds the passphrase");
        it.shot(await H.shot(tab2, "05-prompted-fresh-tab"));
        await f2.locator('.sec-modal button:text-is("Cancel")').last().click();
    } finally {
        await tab2.close();
    }

    it.done();
    return frame;
}

/* ================================================================== item 6 */
/* FULL MANAGEMENT, ONCE PER FORMAT.
 *
 * This used to drive whichever safe item 3 happened to pick and report "full
 * management" from it. That is a claim about half the program: a KDBX entry is
 * a bag of named strings and a Password Safe v3 record is a list of TYPED
 * fields, and the difference is visible in exactly the two capabilities this
 * item exercises — custom fields do not exist in PWS3 at all, and a PWS3 record
 * has room for exactly one attachment because a field type appears at most
 * once. Both of those are answers the helper gives, and neither is observable
 * from the other format. So the walkthrough runs the whole sequence against one
 * writable safe of EACH registered format and reports per format.
 */
async function item6(page, frame, state, list) {
    const it = REC.item(6, ITEMS[6]);
    console.log("\n== 6. " + ITEMS[6] + " ==");
    if (!state) { it.skip("item 3 never reached a successful unlock"); it.done(); return; }

    const targets = pickPerFormat(list);
    if (!targets.length) {
        it.skip("no reachable, writable safe has a passphrase file in " + H.CFG.creds);
        it.done();
        return;
    }
    it.note("driving " + targets.length + " safe(s), one per format: " +
            JSON.stringify(targets.map((s) => s.id + " (" + s.format + ")")));

    for (const safe of targets) {
        const pass = H.safePassphrase(safe.id);
        console.log("\n   -- " + safe.id + " · " + safe.format + " --");
        it.note("=== " + safe.format + " · " + safe.id + " ===");
        try {
            await manageOne(page, frame, it, safe, pass, state);
        } catch (e) {
            it.fail("management of “" + safe.id + "” (" + safe.format + ") aborted: " +
                    String((e && e.message) || e));
            it.shot(await H.shot(page, "06-abort-" + safe.format));
            /* Get back to a known state so the NEXT format still runs: an
             * abort inside one safe must not silently take the other with it. */
            await backToSafeList(frame).catch(() => {});
        }
    }
    /* Leave the page on the safe list whatever happened, so item 7 starts from
     * a known state rather than inside whichever safe ran last. */
    await backToSafeList(frame).catch(() => {});
    it.done();
}

/* Return the page to the safe list from wherever it is, discarding anything
 * unsaved. Used between formats and after a failure. */
async function backToSafeList(frame) {
    for (let i = 0; i < 4; i++) {
        const m = frame.locator(".sec-modal").last();
        if (!(await frame.locator(".sec-modal").count())) break;
        const cancel = m.locator('button:text-is("Cancel"), button:text-is("Close")').first();
        if (await cancel.count()) await cancel.click().catch(() => {});
        else break;
    }
    if (await inBrowseView(frame)) {
        await frame.locator('#sec-browse-tools button:text-is("Lock")').click();
        const d = frame.locator('.sec-modal:has-text("Lock with unsaved changes?")');
        if (await d.count()) await d.locator('button:text-is("Discard and lock")').click();
    }
    await frame.waitForSelector("#sec-safes-view:not([hidden])", { timeout: 30000 });
    await waitForSafeList(frame);
}

/* The whole management sequence against ONE safe. Every assertion carries the
 * format, because "add worked" and "add worked for PWS3" are different facts
 * and a report that merges them is the report this item exists to replace. */
async function manageOne(page, frame, it, safe, pass, state) {
    const fmt = String(safe.format || "?");
    const tag = " [" + fmt + "]";
    const shotName = (n) => "06-" + fmt + "-" + n;
    const admin = classOf(safe) === "admin" ? "require" : null;

    if (safe.mode === "ro") {
        it.note("safe “" + safe.id + "” is registered read-only, so nothing can be added, " +
                "edited, attached or saved through it — skipped" + tag);
        return;
    }

    await backToSafeList(frame);
    await openUnlockDialog(frame, safe.id);
    const opened = await unlockAndWaitOutBackoff(frame, pass, it);
    if (!(opened && opened.ok))
        throw new Error("the safe would not unlock: " +
                        JSON.stringify(opened && (opened.code + ": " + opened.detail)));
    await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 });

    const title = "live-walkthrough-" + fmt + "-" + Date.now();
    if (safe.id === state.safe.id) state.title = title;

    /* --- add ------------------------------------------------------------ */
    await frame.locator('#sec-browse-tools button:text-is("Add entry…")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await fillLabelled(frame, "Title", title);
    await fillLabelled(frame, "Username", "walkthrough");
    await fillLabelled(frame, "Password", "first-value-" + Date.now());
    /* Read the dialog's OWN answer instead of waiting blindly for the listing
     * to grow. A refusal used to surface here as "timeout waiting for a row",
     * which names the symptom and hides the helper's sentence — the least
     * useful failure a suite can produce. */
    await runButton(frame).click();
    const addOut = await dialogOutcome(frame);
    if (!(addOut && addOut.ok)) {
        it.fail("Add entry was refused" + tag + ": " +
                JSON.stringify(addOut && (addOut.code + ": " + addOut.detail)));
        it.shot(await H.shot(page, shotName("add-refused")));
        throw new Error("add refused: " + JSON.stringify(addOut));
    }
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`)
               .waitFor({ timeout: 30000 });
    it.ok(true, "an entry was added and appears in the listing: " + title + tag);
    it.shot(await H.shot(page, shotName("added")));

    /* --- edit ------------------------------------------------------------ */
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    await frame.locator('#sec-detail button:text-is("Edit entry")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await fillLabelled(frame, "URL", "https://edt1.invalid/walkthrough");
    await runButton(frame).click();
    const editOut = await dialogOutcome(frame);
    it.ok(!!(editOut && editOut.ok), "the edit was accepted" +
          (editOut && !editOut.ok ? " — got " + JSON.stringify(editOut.code + ": " + editOut.detail) : "") + tag);
    if (!(editOut && editOut.ok)) throw new Error("edit refused: " + JSON.stringify(editOut));
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    const detailText = await frame.locator("#sec-detail").innerText();
    it.ok(/edt1\.invalid\/walkthrough/.test(detailText),
          "the edit took: the entry's URL now reads back from the helper" + tag);

    /* --- a custom field --------------------------------------------------
     * The helper now declares `custom` on `entry` and `changes` as a KEYED MAP
     * — control "json", type "object", a separate `key` descriptor and element
     * `fields` — and secrets.js promotes that shape to a repeating row editor.
     * The control is therefore a <fieldset>/<legend>, NOT a <label>: a group of
     * controls answering one question has to be announced as one group. The
     * old assertion here looked only at <label> and would have failed on a
     * page that draws the control correctly, which is the worst kind of test.
     *
     * PWS3 is where this gets interesting. The descriptor is shared, so the
     * control is drawn for both formats and the FORMAT is what refuses: a PWS3
     * record is a list of typed fields with no name-keyed space, and the helper
     * answers `unsupported` with that reason. Both outcomes are correct; which
     * one is correct depends on the safe, so both are asserted. */
    const cfName = "walkthrough token";
    const cfValue = "custom-" + Date.now();
    await frame.locator('#sec-detail button:text-is("Edit entry")').click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    const rowsHost = await customRowsHostId(frame);
    it.ok(!!rowsHost,
          "the add/edit dialog offers a control that CREATES a custom field" +
          (rowsHost ? "" : " — no fieldset or label naming one was drawn") + tag);
    if (rowsHost) {
        const drawn = await frame.evaluate((hid) => {
            const h = document.getElementById(hid);
            const fs = h && h.closest("fieldset");
            return {
                rows: h ? h.querySelectorAll(".sec-row").length : 0,
                legend: fs ? (fs.querySelector("legend") || {}).textContent || "" : "",
                addLabel: fs ? Array.prototype.map.call(fs.querySelectorAll(":scope > button"),
                                                        (b) => b.textContent).join("|") : "",
                json: !!(h && h.querySelector("textarea"))
            };
        }, rowsHost);
        it.note("the custom-field control is a “" + String(drawn.legend).trim() +
                "” row editor with " + drawn.rows + " empty row(s) and a “" +
                drawn.addLabel + "” control — not a raw JSON textarea (" +
                (drawn.json ? "a textarea IS present" : "no textarea") + ")" + tag);
        it.ok(!drawn.json,
              "control:\"json\" was promoted to a row editor, so the operator is not asked " +
              "to type the helper's map by hand" + tag);

        await fillRowField(frame, rowsHost, 0, "Field name", cfName);
        await fillRowField(frame, rowsHost, 0, "Value", cfValue);
        it.shot(await H.shot(page, shotName("custom-row")));
        await runButton(frame).click();

        const cfOutcome = await dialogOutcome(frame);
        if (fmt === "psafe3") {
            it.ok(cfOutcome && !cfOutcome.ok && cfOutcome.code === "unsupported",
                  "Password Safe v3 refuses a custom field with `unsupported`, not with a " +
                  "wrong-field error: " + JSON.stringify(cfOutcome && cfOutcome.code) + tag);
            it.ok(cfOutcome && /typed fields|name-keyed|Password Safe/i.test(cfOutcome.detail),
                  "…and the refusal is the FORMAT's reason, so an operator can tell it from " +
                  "a bug: " + JSON.stringify(String((cfOutcome || {}).detail).slice(0, 150)) + tag);
            it.shot(await H.shot(page, shotName("custom-unsupported")));
            const c = frame.locator('.sec-modal button:text-is("Cancel")').last();
            if (await c.count()) await c.click();
        } else {
            it.ok(!!(cfOutcome && cfOutcome.ok),
                  "the custom field was written through the page" +
                  (cfOutcome && !cfOutcome.ok
                      ? " — got " + JSON.stringify(cfOutcome.code + ": " + cfOutcome.detail) : "") + tag);
            if (cfOutcome && cfOutcome.ok) {
                /* READ IT BACK THROUGH THE PAGE, not through the bridge. The
                 * only door to a custom value is `reveal` with
                 * field="custom:<name>", and it is the door with the countdown
                 * and the audit line on it. */
                await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
                await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
                const opener = frame.locator('#sec-detail button:text-is("Reveal a custom field…")');
                it.ok(await opener.count() > 0,
                      "the detail pane offers “Reveal a custom field…”" + tag);
                await opener.click();
                await frame.waitForSelector('.sec-modal:has-text("Reveal a custom field")',
                                            { timeout: 15000 });
                await fillLabelled(frame, "Custom field name", cfName);
                await frame.locator('.sec-modal button:text-is("Reveal")').last().click();
                const w = frame.locator(".sec-modal .sec-reveal").last();
                await w.locator("button:text-is(\"Reveal\")").click().catch(() => {});
                await w.locator(".sec-value:not(.masked)").waitFor({ timeout: 30000 })
                       .catch(() => {});
                const got = (await w.locator(".sec-value").innerText().catch(() => "")).trim();
                it.ok(got === cfValue,
                      "reveal with field=\"custom:" + cfName + "\" reads back exactly what " +
                      "the page wrote (" + got.length + " characters)" + tag);
                it.shot(await H.shot(page, shotName("custom-revealed")));
                const close = frame.locator('.sec-modal button:text-is("Close")').last();
                if (await close.count()) await close.click();
            } else {
                const c = frame.locator('.sec-modal button:text-is("Cancel")').last();
                if (await c.count()) await c.click();
            }
        }
    } else {
        const c = frame.locator('.sec-modal button:text-is("Cancel")').last();
        if (await c.count()) await c.click();
    }

    /* --- attachment: upload ---------------------------------------------- */
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    const tmp = path.join(os.tmpdir(), "cockpit-secrets-live-attachment-" + fmt + ".txt");
    const attachName = "walkthrough.txt";
    const attachBody = "live walkthrough attachment " + fmt + " " + Date.now() + "\n";
    fs.writeFileSync(tmp, attachBody);
    const addAttach = frame.locator('#sec-detail button:text-is("Add an attachment…")');
    if (await addAttach.count()) {
        await addAttach.click();
        await frame.waitForSelector(".sec-modal", { timeout: 15000 });
        await fillLabelled(frame, "Name", attachName);
        await setLabelledFile(frame, "Attachment content", tmp);
        await runButton(frame).click();
        const attOut = await dialogOutcome(frame);
        it.ok(!!(attOut && attOut.ok), "the upload was accepted" +
              (attOut && !attOut.ok
                  ? " — got " + JSON.stringify(attOut.code + ": " + attOut.detail) : "") + tag);
        if (!(attOut && attOut.ok)) {
            it.shot(await H.shot(page, shotName("attach-refused")));
            throw new Error("attach-add refused: " + JSON.stringify(attOut));
        }
        await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
        await frame.waitForSelector("#sec-detail h4", { timeout: 15000 });
        /* Scoped to the Attachments SECTION. The old form read the whole detail
         * pane for the string "None." on its own line, which is written by more
         * than one section, and failed on an entry whose attachment was
         * present and listed a line later. An assertion about attachments has
         * to read the attachments. */
        it.ok(await frame.locator('#sec-detail h4:text-is("Attachments")').count() > 0,
              "the detail pane draws an Attachments section" + tag);
        it.note("the section reads: " +
                JSON.stringify((await attachmentsSectionText(frame)).replace(/\s+/g, " ")
                    .slice(0, 160)) + tag);
        it.shot(await H.shot(page, shotName("attached")));
    } else {
        it.fail("the detail pane offers no “Add an attachment…” control for a writable safe" + tag);
        return;
    }

    /* --- attachment: LIST, then download ---------------------------------
     * This is the half that did not exist before. `entries` sends `attachments`
     * as a COUNT, and attach-get takes a NAME; the helper now publishes
     * `attach-list`, and secrets.js asks it automatically the first time an
     * entry with a bare count is drawn. So the Download control should appear
     * on its own — no operator action, no guessed filename.
     *
     * The name is read off the SCREEN and handed straight to the download, so
     * what is asserted is the whole chain: count -> attach-list -> a name a
     * person can see -> attach-get -> the bytes in the browser. */
    const nameCell = frame.locator("#sec-detail .sec-file-row .sec-file-name");
    const listed = await nameCell.first().waitFor({ timeout: 30000 })
                                 .then(() => true).catch(() => false);
    it.ok(listed,
          "attach-list turned the count into a NAME on the card, with no operator action" + tag);
    if (listed) {
        const names = await nameCell.allInnerTexts();
        it.ok(names.map((s) => s.trim()).indexOf(attachName) >= 0,
              "the listed name is the one just uploaded: " + JSON.stringify(names) + tag);
        it.ok(await frame.locator('#sec-detail button:text-is("List attachments")').count() > 0,
              "a “List attachments” control is offered so a stale list can be re-asked" + tag);
        const dl = frame.locator("#sec-detail .sec-file-row").filter({
            has: frame.locator(`.sec-file-name:text-is("${attachName}")`)
        }).locator('button:text-is("Download")');
        it.ok(await dl.count() > 0, "…and that row offers Download" + tag);
        const [download] = await Promise.all([
            page.waitForEvent("download", { timeout: 30000 }),
            dl.first().click()
        ]);
        const to = path.join(H.artifactsDir(), "06-" + fmt + "-downloaded-attachment.bin");
        /* Through the harness, never the raw Playwright call: that one
         * creates the file under the process umask, and this file holds the
         * DECRYPTED attachment body. H.saveDownload chmods it 0600 — see
         * `lockDown` in live-harness.js. */
        await H.saveDownload(download, to);
        const got = fs.readFileSync(to, "utf8");
        it.ok(got === attachBody,
              "the attachment downloaded through the Cockpit channel byte for byte (" +
              Buffer.byteLength(attachBody) + " bytes)" + tag);
        const secText = await attachmentsSectionText(frame);
        it.ok(!/(^|\n)\s*None\.\s*(\n|$)/.test(secText),
              "the settled Attachments section does not read “None.” for an entry that has " +
              "one: " + JSON.stringify(secText.replace(/\s+/g, " ").slice(0, 140)) + tag);
        it.shot(await H.shot(page, shotName("downloaded")));
    }

    /* --- history ---------------------------------------------------------- */
    const showHist = frame.locator('#sec-detail button:text-is("Show history")');
    if (await showHist.count()) {
        await showHist.click();
        await frame.waitForSelector("#sec-detail .sec-hist-row, #sec-detail .sec-alert.err",
                                    { timeout: 30000 }).catch(() => {});
        const nrows = await frame.locator("#sec-detail .sec-hist-row").count();
        const said = await frame.locator("#sec-detail").innerText();
        if (nrows > 0) {
            it.ok(true, "history lists " + nrows + " previous version(s) after the edit" + tag);
            /* Never a password: the helper does not send one and the page has
             * nothing to mask. A history row that contained the value would be
             * the single worst regression in this program. */
            const hist = await frame.locator("#sec-detail .sec-hist-row").allInnerTexts();
            const leaked = state.revealed && hist.some((h) => h.indexOf(state.revealed) >= 0);
            it.ok(!leaked, "no history row carries a password value" + tag);
        } else {
            /* An empty history is an ANSWER for a format that keeps none, and
             * it is only acceptable when the page says which it is. */
            it.ok(/No previous versions are recorded|previous version/i.test(said),
                  "the history control answered, and says plainly that this entry has no " +
                  "recorded previous version rather than showing an empty panel" + tag);
            it.note("no history rows for this entry" + tag + " — the entry was created by this " +
                    "run, so whether one edit archives a version is the backend's decision.");
        }
        it.shot(await H.shot(page, shotName("history")));
    } else {
        it.fail("the detail pane offers no history control although the helper publishes the verb" + tag);
    }

    /* --- save --------------------------------------------------------------
     * #sec-alerts holds ONE alert at a time and every mutation above has
     * already written one into it, so waiting for ".sec-alert.ok" to exist
     * returns instantly on the PREVIOUS result and reads the wrong sentence.
     * Wait for the save's own wording instead. */
    await frame.locator("#sec-save").click();
    const confirm = frame.locator('.sec-modal:has-text("Write the safe to disk?")');
    if (await confirm.count()) await confirm.locator('button:text-is("Save")').click();
    const saveOutcome = await waitForSaveOutcome(frame);
    const saidSave = String((saveOutcome && saveOutcome.text) || "");
    it.ok(!!saveOutcome && saveOutcome.ok,
          "Save wrote the safe: " + JSON.stringify(saidSave.slice(0, 200)) + tag);
    it.ok(/previous copy kept at/.test(saidSave),
          "the save names the backup it took before the first new byte existed (I12)" + tag);
    it.shot(await H.shot(page, shotName("saved")));

    /* --- reopen and confirm persistence ------------------------------------ */
    await backToSafeList(frame);
    await openUnlockDialog(frame, safe.id);
    const reopened = await unlockAndWaitOutBackoff(frame, pass, it);
    if (!(reopened && reopened.ok))
        throw new Error("the safe would not re-open after the save: " +
                        JSON.stringify(reopened && (reopened.code + ": " + reopened.detail)));
    await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 });
    const back = await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).count();
    it.ok(back > 0,
          "after lock and a fresh unlock the entry is still there — it persisted to disk" + tag);

    /* And the two things that were WRITTEN into it, read back off the reopened
     * file rather than out of the page's memory. */
    await frame.locator(`#sec-entries td button.sec-btn.link:text-is("${title}")`).click();
    await frame.waitForSelector("#sec-detail h3", { timeout: 15000 });
    const reListed = await frame.locator("#sec-detail .sec-file-row .sec-file-name")
                                .first().waitFor({ timeout: 30000 })
                                .then(() => true).catch(() => false);
    it.ok(reListed, "the attachment survived the save and is listed again after reopening" + tag);
    it.shot(await H.shot(page, shotName("reopened")));
}

/* The text of the detail pane's Attachments SECTION — from its <h4> to the next
 * one. #sec-detail is a flat list of headings and blocks, so the section is the
 * run between them; reading the whole pane instead is how an assertion about
 * attachments ends up matching a sentence belonging to history or to tags. */
async function attachmentsSectionText(frame) {
    return frame.evaluate(() => {
        const host = document.getElementById("sec-detail");
        if (!host) return "";
        let on = false, out = "";
        for (const n of host.children) {
            if (n.tagName === "H4") { on = /attachment/i.test(n.textContent || ""); continue; }
            if (on) out += (n.innerText || n.textContent || "") + "\n";
        }
        return out.trim();
    });
}

/* The row editor's host element id, for whichever control in the open dialog is
 * the custom-field one.
 *
 * Found by SHAPE and by the legend text, in that order: a <fieldset class=
 * "sec-rows"> whose legend names custom fields. Deliberately not by control id
 * — the renderer mints those per control — and deliberately accepting a <label>
 * as well, so a future renderer that draws it as a labelled control still
 * satisfies "the dialog offers a way to create one". */
async function customRowsHostId(frame) {
    return frame.evaluate(() => {
        const backs = document.querySelectorAll(".sec-backdrop");
        const scope = backs.length ? backs[backs.length - 1] : document;
        for (const fs of scope.querySelectorAll("fieldset.sec-rows")) {
            const lg = fs.querySelector("legend");
            if (lg && /custom/i.test(lg.textContent || "")) {
                const host = fs.querySelector(".sec-rowlist");
                if (host && host.id) return host.id;
            }
        }
        /* A labelled control naming custom fields is also an answer. */
        for (const l of scope.querySelectorAll("label[for]")) {
            let t = "";
            for (const n of l.childNodes) if (n.nodeType === 3) t += n.textContent;
            if (/custom/i.test(t)) return l.getAttribute("for");
        }
        return null;
    });
}

/* Fill one field of one row of a row editor, by the label the row draws. */
async function fillRowField(frame, hostId, index, label, value) {
    const id = await frame.evaluate(([hid, ix, want]) => {
        const host = document.getElementById(hid);
        if (!host) return null;
        const row = host.querySelectorAll(".sec-row")[ix];
        if (!row) return null;
        for (const l of row.querySelectorAll("label[for]")) {
            let t = "";
            for (const n of l.childNodes) if (n.nodeType === 3) t += n.textContent;
            if (t.trim().toLowerCase() === String(want).toLowerCase())
                return l.getAttribute("for");
        }
        return null;
    }, [hostId, index, label]);
    if (!id) throw new Error("row " + index + " of “" + hostId + "” has no field labelled “" +
                             label + "”");
    await frame.locator("#" + id).fill(value);
    return id;
}

/* WHAT THE OPEN DIALOG'S RUN BUTTON DID: it closed (success), or the helper's
 * refusal is on it. Same shape as unlockOutcome and for the same reason — the
 * dialog clears its error host before it spawns, so what this reads is this
 * attempt's answer and not the last one's. */
async function dialogOutcome(frame, timeout) {
    const h = await frame.waitForFunction(() => {
        const back = document.querySelectorAll(".sec-backdrop");
        if (!back.length) return { ok: true, code: "", detail: "" };
        const modal = back[back.length - 1].querySelector(".sec-modal");
        if (!modal) return { ok: true, code: "", detail: "" };
        const a = modal.querySelector(".sec-alert.err");
        if (!a) return null;
        const c = a.querySelector(".sec-code");
        return { ok: false,
                 code: String((c && c.textContent) || "").trim(),
                 detail: String(a.textContent || "").trim().slice(0, 240) };
    }, null, { timeout: timeout || 60000 }).catch(() => null);
    return h ? h.jsonValue() : null;
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
            const a = await unlockAndWaitOutBackoff(frame, state.pass, it);
            if (!(a && a.ok))
                throw new Error("session A could not unlock the safe: " +
                                JSON.stringify(a && (a.code + ": " + a.detail)));
        }
        const aTitle = "conflict-A-" + Date.now();
        await addEntry(frame, aTitle);
        it.note("session A holds an unsaved entry: " + aTitle);

        /* B: a change, saved — the file on disk moves under A. */
        await openUnlockDialog(frameB, state.safe.id);
        const bOpen = await unlockAndWaitOutBackoff(frameB, state.pass, it);
        if (!(bOpen && bOpen.ok))
            throw new Error("session B could not unlock the safe: " +
                            JSON.stringify(bOpen && (bOpen.code + ": " + bOpen.detail)));
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
    /* Remember the control that opened it. modal() stashes document.activeElement
     * and focuses it again on close, and a dialog that drops focus back to the
     * top of the document is a keyboard user losing their place. */
    const opener = cardFor(frame, state.safe.id).locator('button:text-is("Unlock…")');
    await opener.focus();
    const openerId = await frame.evaluate(() => {
        const a = document.activeElement;
        if (!a) return null;
        a.setAttribute("data-live-opener", "1");
        return true;
    });
    await openUnlockDialog(frame, state.safe.id);

    /* Focus lands inside the dialog when it opens — modal() focuses the first
     * focusable rather than leaving the caret on the page behind. */
    const opened = await frame.evaluate(() =>
        !!(document.activeElement && document.activeElement.closest(".sec-modal")));
    it.ok(opened, "opening the dialog moves focus into it");

    /* THE TRAP, DRIVEN AS A KEYBOARD USER DRIVES IT.
     *
     * `locator.press()` FOCUSES the element before it sends the key, so
     * `.sec-modal.press("Tab")` put focus on the dialog container each time and
     * then tabbed once from there. Forwards that looked like a pass — every
     * press landed on the dialog's first control — and it never walked the
     * trap at all; backwards it was a FAIL, because Shift+Tab from the
     * container (tabindex -1, so not the `first` the handler compares against)
     * legitimately steps out of the dialog and the assertion was asking the
     * trap to catch a case it does not exist for. Measured on this host.
     *
     * page.keyboard sends to whatever is focused without touching focus, which
     * is what a person pressing Tab does, so that is what is used here. */
    const kb = frame.page().keyboard;
    const n = await frame.evaluate(() => {
        const m = document.querySelector(".sec-backdrop .sec-modal");
        return m ? m.querySelectorAll("a[href], button, input, select, textarea, [tabindex]").length : 0;
    });
    const focusFirst = () => frame.evaluate(() => {
        const m = document.querySelector(".sec-backdrop .sec-modal");
        const f = m.querySelectorAll("a[href], button, input, select, textarea, [tabindex]");
        for (const x of f)
            if (!x.disabled && x.tabIndex !== -1 && x.offsetParent !== null) { x.focus(); return x.tagName; }
        return null;
    });
    await focusFirst();
    let escaped = null;
    const seen = [];
    for (let i = 0; i < n + 3; i++) {
        await kb.press("Tab");
        const where = await frame.evaluate(() => {
            const a = document.activeElement;
            return { inside: !!(a && a.closest(".sec-modal")),
                     what: a ? (a.tagName + (a.type ? ":" + a.type : "")) : "(none)" };
        });
        seen.push(where.what);
        if (!where.inside) { escaped = i; break; }
    }
    it.ok(escaped === null,
          "Tab pressed " + (n + 3) + " times from the first control never leaves the dialog — " +
          "it wrapped instead (focus walked " + JSON.stringify(seen.slice(0, 6)) + "…)");

    /* And backwards: Shift+Tab off the first control wraps to the last. */
    await focusFirst();
    await kb.press("Shift+Tab");
    const backWrapped = await frame.evaluate(() => {
        const a = document.activeElement;
        const m = document.querySelector(".sec-backdrop .sec-modal");
        if (!a || !m || !a.closest(".sec-modal")) return { inside: false, last: false, what: a ? a.tagName : "(none)" };
        const f = Array.prototype.filter.call(
            m.querySelectorAll("a[href], button, input, select, textarea, [tabindex]"),
            (x) => !x.disabled && x.tabIndex !== -1 && x.offsetParent !== null);
        return { inside: true, last: f.length > 0 && f[f.length - 1] === a,
                 what: a.tagName + (a.type ? ":" + a.type : "") };
    });
    it.ok(backWrapped.inside,
          "Shift+Tab from the first control stays inside the dialog (landed on " +
          backWrapped.what + ")");
    it.ok(backWrapped.last,
          "…and it wrapped to the LAST control, which is what makes the trap a loop " +
          "rather than a wall");

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
    const gen = frame.locator('#sec-browse-tools button:text-is("Generate password…")');
    await gen.focus();
    await gen.click();
    await frame.waitForSelector(".sec-modal", { timeout: 15000 });
    await frame.page().keyboard.press("Escape");
    const closed = await frame.locator(".sec-modal").count();
    it.ok(closed === 0, "Escape closes an ordinary dialog");

    /* FOCUS RESTORE. modal() remembers what was focused when it opened and
     * focuses it again on close. Without that, dismissing a dialog drops a
     * keyboard user at the top of the document with no idea where they were —
     * which is a WCAG 2.4.3 failure and is invisible to every test that only
     * checks that the dialog went away. */
    const restored = await frame.evaluate(() => {
        const a = document.activeElement;
        return { tag: a ? a.tagName : "(none)",
                 text: a ? (a.textContent || "").trim().slice(0, 40) : "",
                 isBody: !a || a === document.body };
    });
    it.ok(!restored.isBody && /Generate password/.test(restored.text),
          "closing the dialog puts focus back on the control that opened it (" +
          JSON.stringify(restored.tag + " “" + restored.text + "”") + ")");

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
module.exports = { classOf, reachable, pickSafe, pickPerFormat, cardFor, openUnlockDialog,
                   submitUnlock, unlockOutcome, unlockAndWaitOutBackoff, waitForSafeList,
                   waitForSaveOutcome, inBrowseView,
                   spawnVerb, parseMaybe, controlIdByLabel, fillLabelled, runButton, ITEMS };
