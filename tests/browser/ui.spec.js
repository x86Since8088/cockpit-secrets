/* tests/browser/ui.spec.js — the headless driver for secrets.js.
 *
 *   node tests/browser/ui.spec.js
 *
 * What this is for. secrets.js is the one file in this package with no
 * server-side test at all: the integration suite drives the helper, and the
 * helper does not know the page exists. Everything the page is supposed to
 * guarantee — that it renders nothing the schema did not describe, that no
 * secret reaches a storage area or a command line, that an export cannot be
 * reached without reading what it does, that an unlocked safe is never
 * invisible — is a claim about the browser, and only a browser can check it.
 *
 * It runs against the REAL index.html, secrets.js and secrets.css (there is no
 * build step: the files served are the files installed) and the REAL schema
 * from `secrets-admin schema`. The only stub is the Cockpit bridge, which is
 * what makes it headless and rootless.
 *
 * Exit 0 = every assertion held. Exit 1 = at least one did not, and the failure
 * names which. Exit 0 with a SKIP banner = Playwright is not installed here,
 * which is stated rather than counted as a pass.
 */
"use strict";

const H = require("./harness.js");
const fs = require("fs");
const path = require("path");

let PASS = 0, FAIL = 0;
const FAILURES = [];

function ok(cond, what) {
    if (cond) { PASS++; console.log("  \x1b[32mPASS\x1b[0m  " + what); }
    else { FAIL++; FAILURES.push(what); console.log("  \x1b[31mFAIL\x1b[0m  " + what); }
}
function head(t) { console.log("\n== " + t + " =="); }

/* ------------------------------------------------------------- scenarios -- */
/* One safe of each shape the page has to draw differently. `export_allowed`
 * and `agent_enabled` are the two registry flags the UI gates on, so there is
 * a safe with each and a safe with neither. */
function baseSafes() {
    return [
        { id: "lab-dc", label: "AD Lab domain accounts", format: "kdbx",
          access: "admin", mode: "rw", locked: true, reason: "", usable: true,
          password_required: true, needs_keyfile: false,
          agent_enabled: false, export_allowed: true },
        { id: "mine", label: "My own safe", format: "psafe3",
          access: "user", mode: "rw", locked: true, reason: "", usable: true,
          password_required: true, needs_keyfile: false,
          agent_enabled: false, export_allowed: false }
    ];
}

const ENTRY = {
    uuid: "e1", title: "Domain administrator", username: "EDT1LAB\\Administrator",
    url: "https://edt1:9090", tags: ["lab"], has_totp: false,
    attachments: [{ name: "notes.txt", size: 1234 }],
    modified: "2026-09-01T10:00:00Z"
};

function baseResponses(over) {
    const r = {
        schema: null,                       /* filled with the live schema */
        list: { safes: baseSafes(), registry_errors: 0 },
        probe: { format: "kdbx", version: "4.1", kdf: "argon2id", iterations: 19,
                 needs_password: true, needs_keyfile: false, writable: true,
                 needs_challenge: false, challenge_b64: null, yubikey_slot: null,
                 warnings: [] },
        unlock: { handle: "h1", expires_in: 900, entries_total: 1, groups_total: 1,
                  warnings: [] },
        tree: { groups: [{ uuid: "g1", name: "Root", parent: "", count: 1 }] },
        entries: { total: 1, entries: [ENTRY] },
        reveal: { field: "password", value: "hunter2-not-real", expires_in: 15 },
        save: { ok: true, backup: "lab-dc.20260901.kdbx", bytes: 4096, conflict: false },
        lock: { ok: true },
        /* `health` is where the page learns what the agent is holding, so its
         * shape here is the helper's: a row per class socket, each either
         * absent, unreachable, or carrying the daemon's holdings. */
        health: { backends: {}, registry_errors: [],
                  agent: {
                      user: { socket: "/run/cockpit-secrets/1000/sock", present: false,
                              reachable: false, reason: "no socket", status: null },
                      admin: { socket: "/run/cockpit-secrets/admin/sock", present: false,
                               reachable: false, reason: "no socket", status: null } } }
    };
    return Object.assign(r, over || {});
}

/* --------------------------------------------------------------- helpers -- */
async function bootToSafes(browser, scenario) {
    const page = await H.openPage(browser, scenario);
    await page.goto(scenario.__url);
    await page.waitForSelector("#sec-safes .sec-safe, #sec-safes .sec-alert",
                               { timeout: 10000 });
    return page;
}

async function unlockFirst(page, safeId) {
    await page.click(`.sec-safe:has(.sec-safe-id:text-is("${safeId}")) button:text-is("Unlock…")`);
    await page.waitForSelector(".sec-modal input[type=password]");
    await page.fill(".sec-modal input[type=password]", "correct horse");
    await page.click('.sec-modal button:text-is("Unlock")');
    await page.waitForSelector("#sec-browse-view:not([hidden])", { timeout: 10000 });
}

/* ------------------------------------------------------------------ main -- */
async function main() {
    const pw = H.requirePlaywright();
    if (!pw) {
        console.log("\x1b[33mSKIP\x1b[0m  Playwright is not installed on this host.");
        console.log("      The UI driver DID NOT RUN; nothing about secrets.js was verified");
        console.log("      by this script. Set PLAYWRIGHT_PATH or install playwright.");
        process.exit(0);
    }

    const schema = H.liveSchema();
    const server = await H.startServer();
    const port = server.address().port;
    const url = `http://127.0.0.1:${port}/secrets/index.html`;
    const browser = await pw.chromium.launch({ headless: true });

    const scen = (over) => {
        const s = { admin: true, responses: baseResponses(over), __url: url };
        /* The live schema, with one addition: a one-second agent poll so the
         * "is it polling / has it stopped polling" assertions run in a test
         * rather than in fifteen-second increments. The page reads the interval
         * from constants like every other number it uses. */
        s.responses.schema = JSON.parse(JSON.stringify(schema));
        s.responses.schema.constants.agent_poll_seconds = 1;
        return s;
    };

    try {
        /* ============================================ source hygiene ====== */
        head("Source hygiene (no browser needed, but nothing else checks it)");
        for (const f of ["secrets.js", "secrets.css", "index.html"]) {
            const buf = fs.readFileSync(path.join(H.SRC, f));
            ok(!buf.includes(0x00), `${f} contains no raw NUL byte`);
        }
        const js = fs.readFileSync(path.join(H.SRC, "secrets.js"), "utf8");
        ok(!/\beval\s*\(|new Function\s*\(|WebAssembly\./.test(js),
           "secrets.js uses no eval, Function constructor or WebAssembly (I9)");
        ok(!/\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|document\.cookie/.test(js),
           "secrets.js names no browser storage API at all (I11)");
        const html = fs.readFileSync(path.join(H.SRC, "index.html"), "utf8");
        ok(!/<style[\s>]/.test(html) && !/<script(?![^>]*\bsrc=)/.test(html),
           "index.html has no inline <style> or <script> (I9)");

        /* ============================================ schema coverage ===== */
        head("Schema coverage — the page must draw everything the helper declares");

        /* Control types. For each control in enums.control, a synthetic verb is
         * added to the schema declaring a field that uses it; the page's
         * generic dialog is opened and the field must NOT carry the "this page
         * does not know how to draw" warning. That warning is the renderer
         * telling the truth about a gap, and this is the assertion that turns
         * it into a test failure. */
        {
            const controls = schema.enums.control;
            const probe = JSON.parse(JSON.stringify(schema));
            probe.fields = probe.fields.concat(controls.map((c, i) => ({
                id: "probe_" + i, label: "Probe " + c, control: c, type: "string",
                required: false, secret: false, default: null, min: null, max: null,
                maxlength: null,
                options: [{ value: "a", label: "A" }, { value: "b", label: "B" }],
                options_from: null, pattern: null, placeholder: "", help: "",
                breaks_when_wrong: null, unit: null, fields: null, partial: false
            })));
            probe.verbs = probe.verbs.concat([{
                id: "control-probe", group: "diagnostics", title: "Control probe",
                help: "", danger: false, mutates: false, needs: "none", stdin: true,
                session_only: false,
                request: controls.map((c, i) => "probe_" + i),
                response: {}, confirm: null, audited: false, access: "any",
                breaks_when_wrong: null
            }]);

            const s = scen();
            s.responses.schema = probe;
            s.responses["control-probe"] = { ok: true };
            const page = await bootToSafes(browser, s);
            await page.click('#sec-safes button:text-is("Control probe")');
            await page.waitForSelector(".sec-modal");
            const unknown = await page.$$eval(".sec-modal .sec-alert.warn",
                (ns) => ns.map((n) => n.textContent)
                          .filter((t) => /does not know how to draw/.test(t)));
            ok(unknown.length === 0,
               `every one of the ${controls.length} declared control types renders` +
               (unknown.length ? ` (unknown: ${unknown.join(" | ")})` : ""));
            /* And each one produced a real control, not an empty div. */
            const fieldCount = await page.$$eval(".sec-modal .sec-field", (n) => n.length);
            ok(fieldCount >= controls.length - 1,   /* `hidden` renders hidden */
               `each declared control produced a field (${fieldCount} for ${controls.length})`);
            await page.close();
        }

        /* Verbs. Every verb the helper declares must be REACHABLE from this
         * page, and the table below says HOW for each one — either the page
         * calls it during an ordinary walkthrough, or it offers a control whose
         * label is named here.
         *
         * The table is the point. A helper that grows a verb this page does not
         * handle fails the first assertion (no route declared) instead of
         * shipping a capability nobody can reach, which is the exact failure
         * "render everything the schema declares" exists to prevent — and the
         * one nobody notices, because a missing button looks like a feature
         * that was never asked for. */
        {
            const CALLED = "«called during the walkthrough»";
            const ROUTES = {
                "schema": CALLED, "list": CALLED, "probe": CALLED, "unlock": CALLED,
                "open": CALLED, "lock": CALLED, "tree": CALLED, "entries": CALLED,
                "history": CALLED, "backups": CALLED, "strength": CALLED,
                "breach-check": CALLED,
                "reveal": "Reveal",
                "totp": "Reveal",
                "attach-get": "Download",
                "add": "Add entry…",
                "edit": "Edit entry",
                "move": "Move entry",
                "rm": "Delete entry",
                "group-add": "Add group…",
                "group-rm": "Delete group",
                "group-mv": "Move group",
                "save": "Save",
                "history-restore": "Restore this version",
                "attach-add": "Add an attachment…",
                "attach-rm": "Remove",
                "save-as": "Save a copy",
                "restore-backup": "Restore…",
                "export": "Export…",
                "generate": "Generate password…",
                "health": "Backend health",
                "audit-tail": "Audit log"
            };

            const undeclared = schema.verbs.map((v) => v.id).filter((id) => !(id in ROUTES));
            ok(undeclared.length === 0,
               `every declared verb has a route through the UI` +
               (undeclared.length ? ` (no route for: ${undeclared.join(", ")})` : ""));

            const s = scen();
            for (const v of schema.verbs) if (!(v.id in s.responses))
                s.responses[v.id] = { ok: true };
            s.responses.list.safes[0].export_allowed = true;
            s.responses.entries = { total: 1, entries: [
                Object.assign({}, ENTRY, { has_totp: true })] };
            s.responses.totp = { code: "123456", seconds_remaining: 20 };
            s.responses.history = { uuid: "e1", total: 1, versions: [
                { index: 0, when: "2026-08-01T09:00:00Z", title: "Domain administrator",
                  username: "old", url: "", has_password: true, notes_len: 0 }] };
            s.responses.backups = { safe: "lab-dc", dir: "/var/backups", keep: 10, total: 1,
                backups: [{ name: "lab-dc.20260901-090000.kdbx",
                            when: "2026-09-01T09:00:00Z", size: 4096 }] };
            s.responses.strength = { entropy_bits: 30, effective_bits: 20,
                                     category: "weak", weaknesses: [] };
            s.responses["breach-check"] = { available: true, found: false, count: 0 };

            const page = await bootToSafes(browser, s);
            const labels = new Set();
            const grab = async () => {
                for (const t of await page.$$eval("button", (b) => b.map((x) => x.textContent.trim())))
                    labels.add(t);
            };
            await grab();                                   /* the safes view */

            await unlockFirst(page, "lab-dc");
            await grab();                                   /* the browse toolbar */

            /* A group must be SELECTED before the group verbs have a subject. */
            await page.click("#sec-tree ul li:nth-child(2) button");
            await page.waitForSelector("#sec-tree .sec-tools");
            await grab();

            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            await grab();                                   /* reveal, totp, files */

            await page.click('#sec-detail button:text-is("Show history")');
            await page.waitForSelector("#sec-detail .sec-hist-row");
            await grab();                                   /* history-restore */

            /* A password control is what makes the page ask about strength and
             * the breach corpus, so the add dialog is opened and typed into. */
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal input[type=password]");
            await page.fill(".sec-modal input[type=password]", "a-candidate");
            await page.waitForSelector(".sec-modal .sec-strength-text:not(:empty)",
                                       { timeout: 5000 });
            await grab();
            await page.click('.sec-modal button:text-is("Cancel")');
            await page.waitForSelector(".sec-modal", { state: "detached" });

            await page.click('#sec-browse-tools button:text-is("Backups…")');
            await page.waitForSelector(".sec-modal .sec-file-row");
            await grab();                                   /* restore-backup */
            await page.click('.sec-modal button:text-is("Close")');
            await page.waitForSelector(".sec-modal", { state: "detached" });

            await page.click("#sec-lock");
            const conf = await page.$('.sec-modal button:text-is("Discard and lock")');
            if (conf) await conf.click();
            await page.waitForSelector("#sec-safes-view:not([hidden])");

            const called = new Set(await page.evaluate(() =>
                window.__CALLS.map((c) => c.verb)
                    .concat(window.__BODIES.map((b) => b && b.verb).filter(Boolean))));

            const unreachable = [];
            for (const v of schema.verbs) {
                const route = ROUTES[v.id];
                if (route === undefined) continue;           /* already reported */
                if (route === CALLED) {
                    if (!called.has(v.id)) unreachable.push(`${v.id} (never called)`);
                } else if (!labels.has(route)) {
                    unreachable.push(`${v.id} (no control labelled "${route}")`);
                }
            }
            ok(unreachable.length === 0,
               `all ${schema.verbs.length} declared verbs are reachable` +
               (unreachable.length ? ` — ${unreachable.join("; ")}` : ""));
            await page.close();
        }

        /* ================================================ I11 / I10 ======= */
        head("Nothing is kept in the browser, and nothing is on a command line");
        {
            const page = await bootToSafes(browser, scen());
            await unlockFirst(page, "lab-dc");
            const stored = await page.evaluate(() => {
                const out = { local: -1, session: -1, cookie: "?", idb: "?" };
                try { out.local = window.localStorage.length; } catch (e) { out.local = -2; }
                try { out.session = window.sessionStorage.length; } catch (e) { out.session = -2; }
                try { out.cookie = document.cookie; } catch (e) { out.cookie = "?"; }
                return out;
            });
            ok(stored.local === 0, `localStorage is empty after an unlock (${stored.local})`);
            ok(stored.session === 0, `sessionStorage is empty after an unlock (${stored.session})`);
            ok(stored.cookie === "", "no cookie was set");

            const calls = await page.evaluate(() => window.__CALLS);
            const argvHasSecret = calls.some((c) =>
                c.argv.slice(2).some((a) => /correct horse/.test(String(a))));
            ok(!argvHasSecret, "the passphrase never appeared on argv (I10)");
            const bodies = await page.evaluate(() => window.__BODIES);
            ok(bodies.some((b) => b && b.password === "correct horse"),
               "the passphrase DID travel in a request body on stdin (I10)");

            /* The password input must be unnamed and un-autofillable. */
            await page.click("#sec-lock");
            await page.waitForSelector('.sec-modal, #sec-safes-view:not([hidden])');
            await page.close();
        }
        {
            const page = await bootToSafes(browser, scen());
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")');
            await page.waitForSelector(".sec-modal input[type=password]");
            const attrs = await page.$eval(".sec-modal input[type=password]", (n) => ({
                name: n.getAttribute("name"),
                autocomplete: n.getAttribute("autocomplete"),
                inForm: !!n.closest("form")
            }));
            ok(attrs.name === null, "the passphrase input has no name attribute (I11)");
            ok(attrs.autocomplete === "off", 'the passphrase input is autocomplete="off" (I11)');
            ok(attrs.inForm === false, "the passphrase input is not inside a <form> (I11)");
            await page.close();
        }

        /* The unlock dialog must NOT score the master passphrase. The claim in
         * secrets.js is that it opts out for two reasons — the answer is
         * useless and the cost is N more copies of the master passphrase in
         * flight — and a claim like that is worth a test, because turning the
         * meter on everywhere is the obvious "improvement" someone will make
         * later without noticing what it does here. */
        head("The strength meter is off where a passphrase is being TYPED, not chosen");
        {
            const s = scen();
            s.responses.strength = { entropy_bits: 30, effective_bits: 30,
                                     category: "weak", weaknesses: [] };
            const page = await bootToSafes(browser, s);
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")');
            await page.waitForSelector(".sec-modal input[type=password]");
            await page.fill(".sec-modal input[type=password]", "the master passphrase");
            await page.waitForTimeout(900);          /* well past the debounce */
            const asked = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "strength").length);
            ok(asked === 0,
               `the unlock dialog never sends the master passphrase to strength (${asked} calls)`);
            ok((await page.$$(".sec-modal .sec-strength")).length === 0,
               "and draws no meter there");
            /* While an add-entry dialog, where a password is being CHOSEN, does. */
            await page.close();
        }

        /* The two controls with no DOM property to read a value out of. */
        head("radio and readonly round-trip their values");
        {
            const probe = JSON.parse(JSON.stringify(schema));
            probe.fields = probe.fields.concat([
                { id: "pick", label: "Pick", control: "radio", type: "string",
                  required: false, secret: false, default: "b", min: null, max: null,
                  maxlength: null,
                  options: [{ value: "a", label: "Alpha" }, { value: "b", label: "Bravo" }],
                  options_from: null, pattern: null, placeholder: "", help: "",
                  breaks_when_wrong: null, unit: null, fields: null, partial: false },
                { id: "fixed", label: "Fixed", control: "readonly", type: "string",
                  required: false, secret: false, default: "cannot-change", min: null,
                  max: null, maxlength: null, options: null, options_from: null,
                  pattern: null, placeholder: "", help: "", breaks_when_wrong: null,
                  unit: null, fields: null, partial: false }
            ]);
            probe.verbs = probe.verbs.concat([{
                id: "rr-probe", group: "diagnostics", title: "RR probe", help: "",
                danger: false, mutates: false, needs: "none", stdin: true,
                session_only: false, request: ["pick", "fixed"], response: {},
                confirm: null, audited: false, access: "any", breaks_when_wrong: null
            }]);
            const s = scen();
            s.responses.schema = probe;
            s.responses["rr-probe"] = { ok: true };
            const page = await bootToSafes(browser, s);
            await page.click('#sec-safes button:text-is("RR probe")');
            await page.waitForSelector(".sec-modal");
            ok((await page.$$(".sec-modal fieldset.sec-radios legend")).length === 1,
               "a radio control is a fieldset with a legend, not orphaned options");
            const checked = await page.$eval(".sec-modal .sec-radiolist input:checked",
                                             (n) => n.value);
            ok(checked === "b", `the schema default is preselected (${checked})`);
            const names = await page.$$eval(".sec-modal .sec-radiolist input",
                (ns) => ns.map((n) => n.name));
            ok(names.length === 2 && names[0] === names[1] && !/password|user/i.test(names[0]),
               `the radios share a generated group name, not a field name (${names[0]})`);
            ok((await page.textContent(".sec-modal .sec-readonly")) === "cannot-change",
               "a readonly control shows its value");
            await page.click(".sec-modal .sec-radiolist input[value=a]");
            await page.click('.sec-modal button:text-is("Run")');
            await page.waitForSelector(".sec-modal", { state: "detached" }).catch(() => null);
            const sent = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.pick !== undefined).pop());
            ok(sent && sent.pick === "a",
               `the radio's chosen value is sent (${sent && sent.pick})`);
            ok(sent && sent.fixed === "cannot-change",
               `a readonly value still travels in the request (${sent && sent.fixed})`);
            await page.close();
        }

        /* ====================================================== export ==== */
        head("Export (I21)");
        {
            const s = scen();
            s.responses.export = { path: "/var/lib/cockpit-secrets/exports/lab-dc-20260904.csv",
                                   bytes: 8192, entries: 42, fmt: "csv", name: "lab-dc.csv",
                                   /* a helper that ALSO returned the content inline: */
                                   b64: "c2VjcmV0LWNvbnRlbnQtdGhhdC1tdXN0LW5vdC1yZW5kZXI=" };
            const page = await bootToSafes(browser, s);

            const onAllowed = await page.$$('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Export…")');
            const onDenied = await page.$$('.sec-safe:has(.sec-safe-id:text-is("mine")) button:text-is("Export…")');
            ok(onAllowed.length === 1, "Export is offered on the safe whose registry row allows it");
            ok(onDenied.length === 0, "Export is NOT offered on the safe whose row does not (I21)");

            await onAllowed[0].click();
            await page.waitForSelector(".sec-modal");
            const warn = await page.textContent(".sec-modal .sec-danger-block");
            ok(/This writes every password in this safe to disk in plain text/.test(warn),
               "the confirm states, in plain words, what an export writes");
            const shownPath = await page.textContent(".sec-modal .sec-danger-block .sec-path");
            ok(/\/var\/lib\/cockpit-secrets\/exports/.test(shownPath || ""),
               `the destination the helper published is shown before proceeding (${shownPath})`);

            const runDisabled = await page.$eval(
                '.sec-modal button:text-is("Write the plaintext export")', (b) => b.disabled);
            ok(runDisabled === true, "the run button is disabled until the warnings are ticked");

            const boxes = await page.$$(".sec-modal .sec-alert.warn input[type=checkbox]");
            ok(boxes.length >= 2,
               `both the helper's confirm and the page's are required (${boxes.length} boxes)`);
            for (const b of boxes) await b.check();
            const runEnabled = await page.$eval(
                '.sec-modal button:text-is("Write the plaintext export")', (b) => !b.disabled);
            ok(runEnabled, "ticking every confirm enables the run button");

            await page.selectOption(".sec-modal select", "csv");
            await page.click('.sec-modal button:text-is("Write the plaintext export")');
            await page.waitForSelector('.sec-modal h2:text-is("Export written")', { timeout: 5000 });
            const body = await page.textContent(".sec-modal");
            ok(/exports\/lab-dc-20260904\.csv/.test(body), "the result names the path written");
            ok(/8192 bytes/.test(body) || /8\.0 KiB/.test(body), "the result names the byte count");
            ok(!/secret-content-that-must-not-render/.test(body) &&
               !/c2VjcmV0LWNvbnRlbnQ/.test(body),
               "the exported content is NOT rendered in the browser, even when sent inline");
            ok(/b64/.test(body) && /does not render them/.test(body),
               "and the page says which key it withheld, rather than dropping it in silence");
            /* `entries` in an export reply is a ROW COUNT, not the rows. It must
             * be shown as the useful number it is, not withheld as a payload. */
            ok(/42/.test(body), "the exported row count is shown");
            ok(!/inline \(entries/.test(body) && !/entries, b64|b64, entries/.test(body),
               "a numeric row count is not mistaken for withheld content");

            const sent = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.fmt).pop());
            ok(sent && sent.confirm === "export-plaintext:lab-dc",
               `the helper's confirmation token was sent and names this safe (${sent && sent.confirm})`);
            await page.close();
        }
        {
            /* A registry entry may point one safe's exports somewhere other
             * than the host default, and `health` publishes that per safe. The
             * confirm has to name the REAL destination: telling an operator the
             * default while writing somewhere else is worse than saying
             * nothing, because they will go and look in the wrong place. */
            const s2 = scen();
            s2.responses.health = { backends: {}, registry_errors: [],
                agent: { user: null, admin: null },
                export: { default_dir: "/var/lib/cockpit-secrets/exports",
                          enabled_safes: [
                              { safe: "lab-dc", access: "admin",
                                dir: "/srv/audit/lab-dc-exports" }],
                          formats: ["csv", "xml", "json"],
                          confirm_prefix: "export-plaintext:" } };
            s2.responses.export = { path: "/srv/audit/lab-dc-exports/x.csv",
                                    bytes: 10, entries: 1, fmt: "csv" };
            const page = await bootToSafes(browser, s2);
            await page.waitForFunction(() =>
                window.__CALLS.some((c) => c.verb === "health"), null, { timeout: 5000 });
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Export…")');
            await page.waitForSelector(".sec-modal .sec-danger-block .sec-path");
            const shown = await page.textContent(".sec-modal .sec-danger-block .sec-path");
            ok(/\/srv\/audit\/lab-dc-exports/.test(shown),
               `the confirm names this safe's own export directory (${shown})`);
            ok(!/var\/lib\/cockpit-secrets\/exports/.test(shown),
               "and not the host default it overrides");
            await page.close();
        }

        /* ============================================ backups / restore === */
        head("Backups and restore");
        {
            const s = scen();
            s.responses.backups = { safe: "lab-dc", dir: "/var/lib/cockpit-secrets/backups",
                keep: 10, total: 2, backups: [
                { name: "lab-dc.20260903-231500.kdbx", when: "2026-09-03T23:15:00Z", size: 40960 },
                { name: "lab-dc.20260901-090000.kdbx", when: "2026-09-01T09:00:00Z", size: 4096 }] };
            s.responses["restore-backup"] = { ok: true, restored: "lab-dc.20260901-090000.kdbx",
                bytes: 4096, backup: "lab-dc.20260904-000000.kdbx", created: true };
            const page = await bootToSafes(browser, s);
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Backups…")');
            await page.waitForSelector(".sec-modal .sec-file-row");
            const rows = await page.$$eval(".sec-modal .sec-file-row",
                (ns) => ns.map((n) => n.textContent));
            ok(rows.length === 2, `both generations are listed (${rows.length})`);
            ok(rows.every((r) => /\d/.test(r)) && rows.some((r) => /KiB|bytes/.test(r)),
               "each backup shows a timestamp and a size");
            ok(rows.some((r) => /40960|40\.0 KiB/.test(r)), "the exact byte count is shown");

            await page.click('.sec-modal .sec-file-row:last-child button:text-is("Restore…")');
            await page.waitForSelector('.sec-modal h2:has-text("Restore")');
            const rWarn = await page.textContent(".sec-modal .sec-danger-block");
            ok(/overwrites the live safe/i.test(rWarn),
               "the restore confirm says the live safe will be overwritten");
            ok(/backup ring first|copied into the backup ring/i.test(rWarn),
               "the restore confirm says the current state is backed up first");
            await page.close();
        }

        /* =========================================== save-as takes a NAME = */
        head("Save-as takes a name, not a path");
        {
            const s = scen();
            s.responses["save-as"] = { ok: true, path: "/etc/cockpit-secrets/safes/copy.kdbx",
                                       bytes: 4096, name: "copy.kdbx" };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Save a copy")');
            await page.waitForSelector(".sec-modal");
            const hints = await page.$$eval(".sec-modal .hint", (n) => n.map((x) => x.textContent));
            ok(hints.some((h) => /A NAME, never a path/i.test(h)),
               "the helper's own 'a NAME, never a path' help is shown");
            ok(hints.some((h) => /A name, not a path/i.test(h)),
               "the page adds its own name-not-path advisory");
            const input = await page.$(".sec-modal input[type=text]");
            await input.fill("../../etc/shadow");
            await page.waitForFunction(() =>
                !!document.querySelector(".sec-modal .sec-field .err[aria-live]")?.textContent);
            const live = await page.textContent(".sec-modal .sec-field .err[aria-live]");
            ok(/path/i.test(live), `a path is flagged client-side as feedback (${live.trim()})`);
            await page.close();
        }

        /* ===================================================== history ==== */
        head("Entry history shows no password");
        {
            const s = scen();
            /* OLDEST FIRST, index ascending with time — which is what the real
             * helper returns, measured: an entry edited twice comes back with
             * index 0 carrying the ORIGINAL modification time. This stub used
             * to be the other way round because the schema's `index` help text
             * claimed 0 was "the most recently archived version". The text was
             * wrong, the page believed it and sorted descending, and history
             * displayed newest-first under an "oldest" label. Fixed in three
             * places together: the helper's descriptor, renderHistoryList's
             * sort, and this fixture. */
            s.responses.history = { uuid: "e1", total: 3, versions: [
                { index: 0, when: "2026-07-01T09:00:00Z", title: "Domain admin",
                  username: "EDT1LAB\\admin", url: "", has_password: false, notes_len: 0 },
                { index: 1, when: "2026-08-01T09:00:00Z", title: "Domain administrator",
                  username: "EDT1LAB\\admin", url: "https://edt1:9090",
                  has_password: true, notes_len: 0 },
                { index: 2, when: "2026-09-01T09:00:00Z", title: "Domain administrator",
                  username: "EDT1LAB\\Administrator", url: "https://edt1:9090",
                  has_password: true, notes_len: 40 }] };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            await page.click('#sec-detail button:text-is("Show history")');
            await page.waitForSelector("#sec-detail .sec-hist-row");
            const hrows = await page.$$eval("#sec-detail .sec-hist-row",
                (ns) => ns.map((n) => n.textContent));
            ok(hrows.length === 3, `every recorded version is listed (${hrows.length})`);
            ok(hrows.every((r) => /\d{4}|\d\d[:/]/.test(r)), "each version shows a timestamp");
            ok(hrows.some((r) => /Changed:/.test(r)), "the panel names what changed between versions");
            ok(hrows.some((r) => /username/.test(r)), "a changed username is named");
            /* ORDER. `index` counts FORWARDS through time — 0 is the oldest
             * recorded version — and the panel reads forwards too, so index
             * ascending and oldest first are the same thing. The assertion is
             * on BOTH, because the bug this replaced satisfied one of them:
             * the newest row was listed first AND labelled "the oldest
             * recorded version". */
            ok(/version 0/.test(hrows[0]) && /version 2/.test(hrows[2]),
               `versions read oldest-first, index ascending (${
                   hrows.map((r) => (r.match(/version \d/) || [""])[0]).join(" then ")})`);
            ok(/oldest recorded version/.test(hrows[0])
               && /2026|Jul/.test(hrows[0]),
               "and it is the genuinely oldest one that is labelled so");
            /* The 2026-07-01 row is the oldest; the change from it to
             * 2026-08-01 is a title change, and that is where it belongs. */
            ok(/Changed:.*title/.test(hrows[1]),
               `a change is attributed to the version it happened in (${
                   (hrows[1].match(/Changed:[^.]*/) || [""])[0]})`);
            const detail = await page.textContent("#sec-detail");
            ok(!/hunter2-not-real/.test(detail),
               "no password is anywhere in the history panel");
            ok(/had a password|no password/.test(hrows.join(" ")),
               "has_password is rendered as a boolean, not as a value");
            const restore = await page.$$('#sec-detail button:text-is("Restore this version")');
            ok(restore.length === 3, `every version offers a restore (${restore.length})`);
            await restore[2].click();
            await page.waitForSelector('.sec-modal h2:has-text("Restore a previous version")');
            const rtext = await page.textContent(".sec-modal");
            ok(/in the helper's memory only/i.test(rtext),
               "the restore confirm says it is in memory until save");
            ok(/not shown here/i.test(rtext),
               "the restore confirm says the value is revealed the normal way");
            await page.close();
        }

        /* ================================================= attachments ==== */
        head("Attachments");
        {
            const s = scen();
            s.responses["attach-get"] = { name: "notes.txt", size: 12,
                                          b64: Buffer.from("hello there\n").toString("base64") };
            s.responses["attach-add"] = { ok: true, name: "notes.txt", size: 12, saved: false };
            s.responses["attach-rm"] = { ok: true, name: "notes.txt", saved: false };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail .sec-file-row");
            const meta = await page.textContent("#sec-detail .sec-kv");
            ok(!/\[object Object\]/.test(meta),
               "an array of objects in the entry metadata is not printed as [object Object]");
            ok(/notes\.txt/.test(meta),
               "it is printed as what the objects call themselves");
            const arow = await page.textContent("#sec-detail .sec-file-row");
            ok(/notes\.txt/.test(arow), "the attachment is listed by name");
            ok(/1234 bytes|1\.2 KiB/.test(arow), `its size is shown (${arow.trim()})`);
            for (const label of ["Download", "Replace…", "Remove"])
                ok((await page.$$(`#sec-detail .sec-file-row button:text-is("${label}")`)).length === 1,
                   `the attachment offers ${label}`);
            ok((await page.$$('#sec-detail button:text-is("Add an attachment…")')).length === 1,
               "an upload control is offered");

            /* The size hint must quote the TRANSPORT cap, not the format cap:
             * the helper's own descriptor says the request cap is what bites. */
            const hint = await page.$$eval("#sec-detail .hint", (n) => n.map((x) => x.textContent).join(" "));
            ok(/per attachment/.test(hint), "an attachment size limit is shown");
            ok(!/32\.0 MiB per attachment/.test(hint),
               "the limit shown is the transport limit, not the larger format limit");

            /* A download must build a Blob in the page: no server-side file. */
            const dl = page.waitForEvent("download", { timeout: 5000 }).catch(() => null);
            await page.click('#sec-detail .sec-file-row button:text-is("Download")');
            const got = await dl;
            ok(!!got, "downloading streams through the channel to the browser (I21)");
            if (got) ok(got.suggestedFilename() === "notes.txt",
                        "the download keeps the attachment's name");

            await page.click('#sec-detail .sec-file-row button:text-is("Remove")');
            await page.waitForSelector('.sec-modal h2:has-text("Remove")');
            const rmText = await page.textContent(".sec-modal");
            ok(/backup ring/i.test(rmText), "removing an attachment names the way back");
            ok((await page.$$(".sec-modal .sec-alert.warn input[type=checkbox]")).length === 1,
               "attach-rm asks for the helper's confirm once, not twice");
            await page.close();
        }
        {
            /* After a mutation the DETAIL pane must show the entry as it now
             * is. It used to keep rendering the row from before, so an operator
             * who removed an attachment went on seeing it — the change looked
             * as though it had not happened, and the obvious next move is to
             * press Remove again. */
            const s = scen();
            s.responses["attach-rm"] = { ok: true, name: "notes.txt", saved: false };
            s.responses.entries = { __seq: [
                { total: 1, entries: [ENTRY] },
                { total: 1, entries: [Object.assign({}, ENTRY, { attachments: [] })] }
            ] };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail .sec-file-row");
            await page.click('#sec-detail .sec-file-row button:text-is("Remove")');
            await page.waitForSelector('.sec-modal h2:has-text("Remove")');
            await page.check(".sec-modal .sec-alert.warn input[type=checkbox]");
            await page.click('.sec-modal button:text-is("Remove the attachment")');
            await page.waitForSelector(".sec-modal", { state: "detached" });
            await page.waitForFunction(() =>
                !document.querySelector("#sec-detail .sec-file-row"), null, { timeout: 5000 })
                .then(() => ok(true, "the detail pane refreshes after a mutation"))
                .catch(() => ok(false, "the detail pane refreshes after a mutation"));
            const stillThere = await page.textContent("#sec-detail");
            ok(!/notes\.txt/.test(stillThere),
               "the removed attachment is gone from the pane, not just from the helper");
            ok(/unsaved change/.test(await page.textContent("#sec-dirty")),
               "and the mutation is counted as an unsaved change");
            await page.close();
        }

        /* ============================================ strength / breach === */
        head("Password strength and the breach corpus");
        {
            const s = scen();
            s.responses.strength = { entropy_bits: 48.5, effective_bits: 24.5,
                category: "very-weak", calculation: "48.5 - 14 - 10 = 24.5",
                weaknesses: [
                    { id: "dictionary-word", label: "contains a common word or a known-bad password",
                      cost_bits: 14 },
                    { id: "too-short", label: "fewer than 12 characters", cost_bits: 10 }] };
            s.responses["breach-check"] = { available: false,
                reason: "no corpus file is configured for this safe" };
            s.responses.add = { uuid: "e2" };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal input[type=password]");
            await page.fill(".sec-modal input[type=password]", "password1");
            await page.waitForSelector(".sec-modal .sec-strength-text:not(:empty)", { timeout: 5000 });
            const st = await page.textContent(".sec-modal .sec-strength-text");
            ok(/25 bits/.test(st),                       /* Math.round(24.5) === 25 */
               `effective entropy bits are shown (${st.trim().slice(0, 60)})`);
            ok(/48/.test(st), "raw entropy is shown alongside the effective figure");
            ok(/Very weak/.test(st), "the helper's category label is shown");
            ok(/under 28 effective bits/.test(st),
               "the helper's own threshold sentence for that category is shown");
            const weak = await page.$$eval(".sec-modal .sec-weak li", (n) => n.map((x) => x.textContent));
            ok(weak.length === 2, `both named weaknesses are listed (${weak.length})`);
            ok(weak.some((w) => /common word/.test(w)), "a weakness is named in the helper's words");
            ok(weak.some((w) => /−14 bits|-14 bits/.test(w)), "each weakness shows what it costs");
            const lit = await page.$$eval(".sec-modal .sec-strength-seg.bad", (n) => n.length);
            ok(lit === 1, `the bar is drawn on the helper's own five-category scale (${lit} lit)`);

            const breach = await page.textContent(".sec-modal .sec-breach");
            ok(/unavailable/.test(breach) && /no corpus file is configured/.test(breach),
               `an unavailable corpus shows the helper's reason, not silence (${breach.trim()})`);
            ok((await page.$$('.sec-modal .sec-breach button')).length === 0,
               "no live breach button is drawn while the corpus is unavailable");

            /* Nothing about the candidate may have gone to argv. */
            const calls = await page.evaluate(() => window.__CALLS);
            ok(!calls.some((c) => c.argv.slice(2).some((a) => /password1/.test(String(a)))),
               "the strength candidate never reached argv (I10)");
            await page.close();
        }
        {
            const s = scen();
            s.responses.strength = { entropy_bits: 90, effective_bits: 90, category: "strong",
                                     weaknesses: [] };
            s.responses["breach-check"] = { available: true, found: true, count: 7,
                prefix5: "5BAA6", method: "sha1-prefix", network: "none", offline_only: true };
            s.responses.add = { uuid: "e2" };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal input[type=password]");
            await page.fill(".sec-modal input[type=password]", "hunter2");
            await page.waitForSelector('.sec-modal .sec-breach button', { timeout: 5000 });
            await page.click(".sec-modal .sec-breach button");
            await page.waitForSelector(".sec-modal .sec-breach.hit", { timeout: 5000 });
            const hit = await page.textContent(".sec-modal .sec-breach");
            ok(/in the corpus/.test(hit), "a corpus hit is reported plainly");
            ok(/7 occurrence/.test(hit), "the occurrence count is shown");
            ok(/nothing left this host/.test(hit),
               "the page states the check was local and offline-only");
            await page.close();
        }

        /* ======================================================= agent ==== */
        head("The agent banner (I18)");
        {
            /* Agent off everywhere — the default. NOTHING may be drawn. */
            const page = await bootToSafes(browser, scen());
            await page.waitForTimeout(200);
            const banner = await page.$eval("#sec-agent-banner", (n) => n.textContent.trim());
            ok(banner === "", "with the agent off there is no banner and no placeholder");
            const visible = await page.$eval("#sec-agent-banner",
                (n) => window.getComputedStyle(n).display);
            ok(visible === "none", "the empty banner host collapses to nothing");
            /* And it costs almost nothing. `health` is fetched ONCE at load —
             * the export confirm needs its destination — but with the agent off
             * for every registry entry there is no daemon to watch, so it must
             * not be re-polled, least of all as root. The scenario shortens the
             * poll interval to a second so this is testable in a test. */
            const asked = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health").length);
            ok(asked === 1, `health is fetched once at load (${asked} calls)`);
            await page.waitForTimeout(2600);          /* several poll intervals */
            const again = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health").length);
            ok(again === 1,
               `with the agent off for every safe it is never re-polled (${again} calls)`);
            await page.close();
        }
        {
            /* And the converse: one entry opting in is enough to start it. */
            const s2 = scen();
            s2.responses.list.safes[1].agent_enabled = true;   /* the USER-class safe */
            const page = await bootToSafes(browser, s2);
            await page.waitForFunction(() =>
                window.__CALLS.filter((c) => c.verb === "health").length >= 3,
                null, { timeout: 8000 })
                .then(() => ok(true,
                    "one agent-enabled entry starts a repeating poll"))
                .catch(() => ok(false,
                    "one agent-enabled entry starts a repeating poll"));
            const esc = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health").map((c) => c.superuser));
            ok(esc.every((e) => e === null),
               `polling for a user-class safe is never escalated (${JSON.stringify(esc)})`);
            await page.close();
        }
        {
            /* The unlock reply reports the hold, and `health` confirms it. */
            const s2 = scen();
            s2.responses.list.safes[0].agent_enabled = true;
            s2.responses.unlock = { handle: "h1", expires_in: 900, entries_total: 1,
                groups_total: 1, warnings: [],
                agent: { held: true, expires_in: 3600, idle_seconds: 300,
                         max_seconds: 3600, socket: "/run/cockpit-secrets/1000/sock" } };
            s2.responses.health = { backends: {}, registry_errors: [], agent: {
                user: { socket: "/s", present: false, reachable: false, reason: "", status: null },
                admin: { socket: "/a", present: true, reachable: true, reason: "",
                         status: { holdings: [
                             { safe: "lab-dc", age: 12, expires_in: 3588,
                               idle_expires_in: 288 }] } } } };
            const page = await bootToSafes(browser, s2);
            await unlockFirst(page, "lab-dc");
            await page.waitForSelector(".sec-agent-banner");
            const text = await page.textContent(".sec-agent-banner");
            ok(/A safe is unlocked/.test(text), "a held safe is announced in the banner");
            ok(/AD Lab domain accounts/.test(text),
               "the banner names the safe by its registry label, not its id");
            ok(/locks in/.test(text),
               `the banner counts down (${text.replace(/\s+/g, " ").slice(0, 70)})`);
            /* The countdown must be the SOONER of the two timers. 288s idle
             * beats 3588s absolute; showing the larger would promise an
             * operator more time than the agent will actually give. */
            ok(/locks in 4:4\d|locks in 4:3\d/.test(text),
               `the countdown is the idle timer, the sooner of the two (${text.match(/locks in [\d:]+/)})`);
            ok((await page.$$('.sec-agent-banner button:text-is("Lock now")')).length === 1,
               "the banner offers a Lock button");
            await page.close();
        }
        {
            /* A hold this page did NOT create — the reload case. `health`
             * reports it with no handle and no passphrase, and the Lock button
             * must reach it with a bare safe id. */
            const s2 = scen();
            s2.responses.list.safes[0].agent_enabled = true;
            /* A SEQUENCE, because the banner is not the page's opinion: the
             * first health call reports the hold, and the one after the lock
             * reports none. The banner clears because the DAEMON stopped
             * holding it, not because this page decided the click worked. */
            const heldRow = { safe: "lab-dc", age: 400, expires_in: 3200,
                              idle_expires_in: 250 };
            const agentBlock = (holdings) => ({
                user: { socket: "/s", present: false, reachable: false, reason: "",
                        status: null },
                admin: { socket: "/a", present: true, reachable: true, reason: "",
                         status: { holdings: holdings } } });
            s2.responses.health = { __seq: [
                { backends: {}, registry_errors: [], agent: agentBlock([heldRow]) },
                { backends: {}, registry_errors: [], agent: agentBlock([]) }
            ] };
            s2.responses.lock = { ok: true, locked: 1, agent_dropped: true };
            const page = await bootToSafes(browser, s2);
            await page.waitForSelector(".sec-agent-banner", { timeout: 5000 });
            const t = await page.textContent(".sec-agent-banner");
            ok(/AD Lab domain accounts/.test(t),
               "a hold created before this page loaded is still shown (I18)");
            ok((await page.$$("#sec-browse-view:not([hidden])")).length === 0,
               "and it is shown from the safes view, not only from the safe's own page");

            await page.click('.sec-agent-banner button:text-is("Lock now")');
            await page.waitForFunction(() =>
                !document.querySelector(".sec-agent-banner"), null, { timeout: 5000 })
                .then(() => ok(true,
                    "the banner clears once the daemon stops reporting the hold"))
                .catch(() => ok(false,
                    "the banner clears once the daemon stops reporting the hold"));
            const lockReq = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.safe && !b.password &&
                    window.__CALLS.some((c) => c.verb === "lock")).pop());
            const lockCall = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "lock").length);
            ok(lockCall === 1, `the lock verb was called once (${lockCall})`);
            ok(lockReq && lockReq.safe === "lab-dc" && lockReq.handle === undefined,
               "it was locked by bare safe id, with no handle this page never had");
            await page.close();
        }
        {
            /* The converse, and the one that matters more. If the daemon goes
             * on reporting the hold, the banner must STAY UP even though the
             * lock verb answered ok — the page reports the agent's state, it
             * does not assert it. A banner that vanished on a click that did
             * not work would be the invisible unlocked safe, produced by the
             * very control meant to prevent it. */
            const s2 = scen();
            s2.responses.list.safes[0].agent_enabled = true;
            s2.responses.health = { backends: {}, registry_errors: [], agent: {
                user: { socket: "/s", present: false, reachable: false, reason: "", status: null },
                admin: { socket: "/a", present: true, reachable: true, reason: "",
                         status: { holdings: [
                             { safe: "lab-dc", age: 400, expires_in: 3200,
                               idle_expires_in: 250 }] } } } };
            s2.responses.lock = { ok: true, locked: 0 };
            const page = await bootToSafes(browser, s2);
            await page.waitForSelector(".sec-agent-banner", { timeout: 5000 });
            await page.click('.sec-agent-banner button:text-is("Lock now")');
            await page.waitForTimeout(500);
            ok((await page.$$(".sec-agent-banner")).length === 1,
               "a lock the daemon did not honour leaves the banner up");
            await page.close();
        }
        {
            /* A socket that is there but does not answer is a FAULT, and must
             * never render as "nothing is held". */
            const s2 = scen();
            s2.responses.list.safes[0].agent_enabled = true;
            s2.responses.health = { backends: {}, registry_errors: [], agent: {
                user: { socket: "/s", present: false, reachable: false, reason: "", status: null },
                admin: { socket: "/a", present: true, reachable: false,
                         reason: "connection refused", status: null } } };
            const page = await bootToSafes(browser, s2);
            await page.waitForSelector(".sec-agent-banner", { timeout: 5000 });
            const t = await page.textContent(".sec-agent-banner");
            ok(/could not be asked/.test(t),
               "an unreachable agent socket is reported, not read as 'nothing held'");
            ok(/connection refused/.test(t), "the helper's own reason is shown");
            ok(/Treat any safe with the agent enabled as open/.test(t),
               "and the operator is told what to assume meanwhile");
            await page.close();
        }

        /* ===================================================== yubikey ==== */
        head("YubiKey");
        {
            const s = scen();
            s.responses.probe = Object.assign({}, s.responses.probe, {
                needs_challenge: true, yubikey_slot: 2, challenge_b64: "Q0hBTExFTkdF" });
            const page = await bootToSafes(browser, s);
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")');
            await page.waitForSelector(".sec-modal");
            const t = await page.textContent(".sec-modal");
            ok(/needs a response from your YubiKey/.test(t), "the touch prompt is shown");
            ok(/slot 2/.test(t), "the slot the registry declared is named");
            ok(/Q0hBTExFTkdF/.test(t), "the challenge the probe handed over is shown in full");
            ok(/yubikey_response/.test(t),
               "the control that carries the response is named");
            await page.close();
        }
        {
            const s = scen();
            s.responses.probe = Object.assign({}, s.responses.probe, {
                needs_challenge: true, yubikey_slot: 1, yubikey: "unsupported" });
            s.responses.unlock = { error: "unsupported",
                detail: "this backend cannot do challenge-response" };
            const page = await bootToSafes(browser, s);
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")');
            await page.waitForSelector(".sec-modal");
            const t = await page.textContent(".sec-modal");
            ok(/answered .unsupported./.test(t),
               "an unsupported backend is reported as exactly that");
            ok(/will not paper over it|does not open without it/.test(t),
               "the page says it will not fall back to passphrase-only");

            await page.fill(".sec-modal input[type=password]", "correct horse");
            await page.click('.sec-modal button:text-is("Unlock")');
            /* NOT waitForSelector(".sec-alert.err"): the unsupported-probe
             * warning is already one of those, so that selector matches before
             * the reply has even been sent and the assertion races it. */
            const retried = await page.waitForSelector(
                '.sec-modal .sec-alert.err:has-text("No second attempt was made")',
                { timeout: 5000 }).catch(() => null);
            ok(!!retried, "an unsupported unlock says plainly that nothing was retried");
            const unlocks = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.verb === "unlock").length);
            ok(unlocks === 1, `exactly one unlock was attempted, never a silent retry (${unlocks})`);
            await page.close();
        }

        /* ==================================== hidden actually hides ======= */
        /* Every class in the stylesheet that sets an explicit display defeats
         * the browser's own `[hidden] { display: none }`, because an author
         * rule beats a UA rule at any specificity. secrets.js hides controls
         * two ways — the schema's `depends_on` and the `hidden` control kind —
         * and buildForm's values() skips a control it considers invisible. So
         * without the override this suite is checking for, a dependent field
         * stays ON SCREEN while its value is silently dropped from the request.
         * That is the worst shape a bug can take: visible to the operator,
         * invisible to the code. */
        head("The hidden attribute actually hides");
        {
            const page = await bootToSafes(browser, scen());
            const displays = await page.evaluate(() => {
                const out = {};
                ["sec-field", "sec-form", "sec-tools", "sec-checklist",
                 "sec-radiolist", "sec-agent-row", "sec-file-row", "sec-kv",
                 "sec-split", "sec-strength-track", "sec-safe-badges"].forEach((c) => {
                    const n = document.createElement("div");
                    n.className = c;
                    n.hidden = true;
                    document.body.appendChild(n);
                    out[c] = window.getComputedStyle(n).display;
                    n.remove();
                });
                return out;
            });
            const showing = Object.keys(displays).filter((k) => displays[k] !== "none");
            ok(showing.length === 0,
               `[hidden] wins over every layout class` +
               (showing.length ? ` (still shown: ${showing.join(", ")})` : ""));

            await page.close();
        }
        {
            /* End to end, on a verb that really does declare a hidden control
             * and a depends_on: the hidden one must occupy no space, and the
             * dependent one must be OFF SCREEN while its condition is false and
             * appear when it becomes true — the same condition values() uses to
             * decide whether to send it. */
            const probe = JSON.parse(JSON.stringify(schema));
            probe.fields = probe.fields.concat([
                { id: "invisible", label: "Invisible", control: "hidden", type: "string",
                  required: false, secret: false, default: "x", min: null, max: null,
                  maxlength: null, options: null, options_from: null, pattern: null,
                  placeholder: "", help: "", breaks_when_wrong: null, unit: null,
                  fields: null, partial: false },
                { id: "gate", label: "Gate", control: "toggle", type: "boolean",
                  required: false, secret: false, default: false, min: null, max: null,
                  maxlength: null, options: null, options_from: null, pattern: null,
                  placeholder: "", help: "", breaks_when_wrong: null, unit: null,
                  fields: null, partial: false },
                { id: "dependent", label: "Dependent", control: "text", type: "string",
                  required: false, secret: false, default: "sent-only-when-gated",
                  min: null, max: null, maxlength: null, options: null,
                  options_from: null, pattern: null, placeholder: "", help: "",
                  breaks_when_wrong: null, unit: null, fields: null, partial: false,
                  depends_on: { field: "gate", value: true } }
            ]);
            probe.verbs = probe.verbs.concat([{
                id: "hide-probe", group: "diagnostics", title: "Hide probe", help: "",
                danger: false, mutates: false, needs: "none", stdin: true,
                session_only: false, request: ["invisible", "gate", "dependent"],
                response: {}, confirm: null, audited: false, access: "any",
                breaks_when_wrong: null
            }]);
            const s2 = scen();
            s2.responses.schema = probe;
            s2.responses["hide-probe"] = { ok: true };
            const page = await bootToSafes(browser, s2);
            await page.click('#sec-safes button:text-is("Hide probe")');
            /* NOT `.sec-field` — the first one in this dialog is the hidden
             * control, and waiting for a VISIBLE match of that selector hangs
             * precisely because the fix works. */
            await page.waitForSelector(".sec-modal input[type=checkbox]");
            const heights = await page.$$eval(".sec-modal .sec-field[hidden]",
                (ns) => ns.map((n) => n.getBoundingClientRect().height));
            ok(heights.length >= 2 && heights.every((h) => h === 0),
               `hidden and not-yet-depended-on fields occupy no space (${JSON.stringify(heights)})`);

            /* Submit with the gate off: the dependent value must not be sent. */
            await page.click('.sec-modal button:text-is("Run")');
            await page.waitForSelector(".sec-modal", { state: "detached" });
            let sent = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.invisible !== undefined ||
                    (b && b.gate !== undefined)).pop());
            ok(sent && sent.dependent === undefined,
               "a field hidden by depends_on is not sent — and was not on screen either");

            /* Now with the gate on. */
            await page.click('#sec-safes button:text-is("Hide probe")');
            await page.waitForSelector(".sec-modal input[type=checkbox]");
            await page.check(".sec-modal input[type=checkbox]");
            const shown = await page.$$eval(".sec-modal .sec-field:not([hidden]) input[type=text]",
                (ns) => ns.length);
            ok(shown === 1, `the dependent field appears when its condition holds (${shown})`);
            await page.click('.sec-modal button:text-is("Run")');
            await page.waitForSelector(".sec-modal", { state: "detached" });
            sent = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.gate === true).pop());
            ok(sent && sent.dependent === "sent-only-when-gated",
               `and is then sent (${sent && sent.dependent})`);
            await page.close();
        }

        /* ============================================ accessibility ======= */
        head("Keyboard, focus and live regions");
        {
            const page = await bootToSafes(browser, scen());
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")');
            await page.waitForSelector(".sec-modal");
            const dlg = await page.$eval(".sec-modal", (n) => ({
                role: n.getAttribute("role"),
                modal: n.getAttribute("aria-modal"),
                labelled: !!n.getAttribute("aria-labelledby")
            }));
            ok(dlg.role === "dialog" && dlg.modal === "true" && dlg.labelled,
               "the dialog is a labelled aria-modal dialog");
            const inDialog = await page.evaluate(() =>
                !!document.activeElement.closest(".sec-modal"));
            ok(inDialog, "focus moves into the dialog when it opens");
            /* Tab from the last focusable must wrap to the first, not escape. */
            for (let i = 0; i < 30; i++) await page.keyboard.press("Tab");
            const stillIn = await page.evaluate(() =>
                !!document.activeElement.closest(".sec-modal"));
            ok(stillIn, "the focus trap holds after 30 tabs");
            await page.keyboard.press("Escape");
            await page.waitForSelector(".sec-modal", { state: "detached" });
            ok(true, "Escape closes the dialog");

            const live = await page.$eval("#sec-live", (n) => ({
                role: n.getAttribute("role"), live: n.getAttribute("aria-live") }));
            ok(live.role === "status" && live.live === "polite",
               "the status region is polite");
            const alerts = await page.$eval("#sec-alerts", (n) => n.getAttribute("aria-live"));
            ok(alerts === "assertive", "the error region is assertive");
            await page.close();
        }
        {
            /* 200% zoom: the page must reflow, never scroll sideways. */
            const page = await H.openPage(browser, scen());
            await page.setViewportSize({ width: 640, height: 720 });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe");
            const overflow = await page.evaluate(() =>
                document.documentElement.scrollWidth - document.documentElement.clientWidth);
            ok(overflow <= 1, `no horizontal overflow at a 640px viewport (${overflow}px)`);
            await page.close();
        }

        /* ================================================ console clean == */
        head("No page errors anywhere in the walkthrough");
        {
            const page = await bootToSafes(browser, scen());
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            ok(page.__errors.length === 0,
               "no uncaught page error or console error" +
               (page.__errors.length ? ": " + page.__errors.join(" | ") : ""));
            await page.close();
        }
    } finally {
        await browser.close();
        server.close();
    }

    console.log("\n" + (FAIL === 0 ? "\x1b[32m" : "\x1b[31m") +
        `${PASS} passed, ${FAIL} failed\x1b[0m`);
    if (FAIL) {
        console.log("\nFailures:");
        FAILURES.forEach((f) => console.log("  - " + f));
    }
    process.exit(FAIL ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
