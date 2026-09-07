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

/* ------------------------------------ the registry-write verbs, synthetic --
 *
 * WHY THESE ARE DECLARED HERE AND NOT READ FROM THE LIVE HELPER.
 *
 * The rest of this suite drives the page against `secrets-admin schema`,
 * deliberately, because a test that checked the page against a schema copied
 * into this file would pass forever after the helper changed. That is still
 * true of everything above.
 *
 * These eight verbs are the exception WHILE the helper half of the feature is
 * being written: the page and the helper are two agents' work landing in the
 * same tree, and this file is the page's half. So the shapes below are the
 * ones agreed in the task brief, declared exactly as the helper's own schema
 * declares a verb, and the page is driven against them. The moment
 * `secrets-admin schema` publishes verbs with these ids, `registrySchema()`
 * stops adding them — see the guard in it — so the suite flips over to the
 * live descriptors on its own and any disagreement between this file and the
 * helper surfaces as a failure here rather than as a page that quietly draws
 * the wrong form.
 *
 * Nothing here is invented beyond the brief: every field is one the brief
 * names, `access` defaults to admin (I1), and there is no path-shaped field in
 * any request, which is itself asserted below. */
const REG_FIELDS = [
    { id: "id", label: "Safe id", control: "text", type: "string", required: true,
      secret: false, default: null, min: null, max: null, maxlength: 63,
      options: null, options_from: null,
      pattern: "^[a-z0-9][a-z0-9-]{1,62}$",
      placeholder: "lab-dc", unit: null,
      help: "Lower case, digits and hyphens. The helper mints the file name from it.",
      breaks_when_wrong: "The id is the whole of what this page sends about where the " +
          "safe lives. No path, no file name, no directory (I4).",
      fields: null, partial: false },
    { id: "new_label", label: "Label", control: "text", type: "string", required: false,
      secret: false, default: null, min: null, max: null, maxlength: 128,
      options: null, options_from: null, pattern: null, placeholder: null, unit: null,
      help: "What this safe is called on screen.", breaks_when_wrong: null,
      fields: null, partial: false },
    { id: "new_format", label: "Format", control: "select", type: "string", required: true,
      secret: false, default: "kdbx", min: null, max: null, maxlength: null,
      options: null, options_from: null, enum: "format",
      pattern: null, placeholder: null, unit: null,
      help: "Which file format to create.", breaks_when_wrong: null,
      fields: null, partial: false },
    { id: "access", label: "Access class", control: "select", type: "string", required: false,
      secret: false, default: "admin", min: null, max: null, maxlength: null,
      options: null, options_from: null, enum: "access",
      pattern: null, placeholder: null, unit: null,
      help: "Administrator is the default.",
      breaks_when_wrong: "An entry with no access class is an administrator safe (I1).",
      fields: null, partial: false },
    { id: "generate_keyfile", label: "Generate a key file", control: "toggle",
      type: "boolean", required: false, secret: false, default: false,
      min: null, max: null, maxlength: null, options: null, options_from: null,
      pattern: null, placeholder: null, unit: null,
      help: "The helper makes one and hands it to you once.",
      breaks_when_wrong: "There is no second copy of it anywhere.",
      fields: null, partial: false },
    { id: "total_bytes", label: "Total size", control: "number", type: "integer",
      required: true, secret: false, default: null, min: 1, max: null, maxlength: null,
      options: null, options_from: null, pattern: null, placeholder: null, unit: "bytes",
      help: "Declared up front so an oversized file is refused before it is sent.",
      breaks_when_wrong: null, fields: null, partial: false },
    { id: "sha256", label: "SHA-256", control: "text", type: "string", required: true,
      secret: false, default: null, min: null, max: null, maxlength: 64,
      options: null, options_from: null, pattern: "^[0-9a-f]{64}$",
      placeholder: null, unit: null,
      help: "Of the whole file, so the helper can prove it reassembled the same bytes.",
      breaks_when_wrong: null, fields: null, partial: false },
    { id: "token", label: "Staging token", control: "hidden", type: "string",
      required: true, secret: false, default: null, min: null, max: null, maxlength: null,
      options: null, options_from: null, pattern: null, placeholder: null, unit: null,
      help: "Minted by import-begin.", breaks_when_wrong: null, fields: null, partial: false },
    { id: "offset", label: "Offset", control: "number", type: "integer", required: true,
      secret: false, default: null, min: 0, max: null, maxlength: null,
      options: null, options_from: null, pattern: null, placeholder: null, unit: "bytes",
      help: "Where this chunk starts.", breaks_when_wrong: null, fields: null, partial: false }
];

function regVerb(id, over) {
    return Object.assign({
        id, group: "safes", title: id, help: "", danger: false, mutates: true,
        needs: "none", stdin: true, session_only: false, request: [],
        response: {}, confirm: null, audited: true, access: "class",
        breaks_when_wrong: null
    }, over);
}

const REG_VERBS = [
    regVerb("safe-create", {
        title: "Create a safe",
        help: "Makes the file, encrypts it, and writes the registry entry.",
        request: ["id", "new_label", "new_format", "access", "password", "keyfile_b64",
                  "generate_keyfile"],
        response: { ok: "bool", id: "str", path: "str", registry: "str" },
        breaks_when_wrong: "An entry with no access class is an administrator safe (I1)."
    }),
    regVerb("import-begin", {
        title: "Begin an import",
        help: "Declares an upload. No credential.",
        request: ["id", "new_label", "new_format", "access", "total_bytes", "sha256"],
        response: { token: "str", chunk_bytes: "int", expires_in: "int" }
    }),
    regVerb("import-chunk", {
        title: "Upload a chunk",
        help: "One piece of the staged file. No credential.",
        request: ["token", "offset", "data_b64"],
        response: { ok: "bool" }
    }),
    regVerb("import-inspect", {
        title: "Inspect the staged file",
        help: "Reads the unauthenticated header. No credential.",
        request: ["token"],
        response: { format: "str", version: "str", cipher: "str", kdf: "str" }
    }),
    regVerb("import-commit", {
        title: "Commit the import",
        help: "Opens the staged file with the credential and registers it.",
        request: ["token", "password", "keyfile_b64"],
        response: { ok: "bool", id: "str", path: "str" }
    }),
    regVerb("import-abort", {
        title: "Abort an import",
        help: "Destroys the staging.",
        request: ["token"], response: { ok: "bool" }
    }),
    regVerb("safe-forget", {
        title: "Forget a safe", needs: "safe",
        help: "Removes the registry entry and leaves the file alone.",
        request: ["safe"], response: { ok: "bool", id: "str", path: "str" }
    }),
    regVerb("safe-delete", {
        title: "Delete a safe", needs: "safe", danger: true,
        help: "Destroys the file and its backup ring.",
        request: ["safe", "confirm"],
        response: { ok: "bool", id: "str", backups_removed: "int" },
        confirm: "This destroys the encrypted file and every backup of it."
    })
];

const REG_IDS = REG_VERBS.map((v) => v.id);

/* The live schema with every registry-write verb REMOVED.
 *
 * "The page draws no control for a verb the helper does not publish" is a
 * claim about a helper that lacks them, and once the helper HAS them the only
 * way to keep testing it is to take them away again. Doing it by subtraction
 * from the live document (rather than by using an old schema) means the
 * negative case keeps testing the shipped page against the shipped schema. */
function withoutRegistryVerbs(live) {
    const s = JSON.parse(JSON.stringify(live));
    s.verbs = s.verbs.filter((v) => REG_IDS.indexOf(v.id) < 0);
    return s;
}

/* Add them to a copy of the live schema — unless the live schema already has
 * them, in which case the helper is the authority and this fixture gets out of
 * the way. */
function registrySchema(live) {
    const s = JSON.parse(JSON.stringify(live));
    const have = new Set(s.verbs.map((v) => v.id));
    if (REG_VERBS.every((v) => have.has(v.id))) { s.__fromHelper = true; return s; }
    const haveF = new Set(s.fields.map((f) => f.id));
    REG_FIELDS.forEach((f) => { if (!haveF.has(f.id)) s.fields.push(f); });
    REG_VERBS.forEach((v) => { if (!have.has(v.id)) s.verbs.push(v); });
    s.constants.user_registry_dir = "/home/tester/.config/cockpit-secrets/safes.d";
    return s;
}

/* Console noise that is an artefact of the HARNESS, not of the page.
 *
 * secrets.css declares @font-face for Cockpit's own Red Hat Text and Red Hat
 * Mono at `../../static/fonts/…`, which resolves to /cockpit/static/fonts/…
 * and was MEASURED live on Cockpit 360 to return 200 with zero CSP violations.
 * The stub server in harness.js serves the plugin directory and nothing else,
 * so those three requests 404 here and Chromium logs one console error each.
 *
 * The filter below is as narrow as it can be made. Chromium's console text for
 * a failed subresource does NOT carry the URL, so the URL is recorded from the
 * response stream instead: a 404 console error is discounted only while EVERY
 * 404 this page actually took was a font file, and only up to the number of
 * them. One 404 for anything else, or one extra, and the assertion fails again
 * — as does every uncaught exception and every other console error.
 *
 * `font-display: fallback` is why this is cosmetic: with the files missing the
 * page renders in the system sans, which is exactly what a plugin opened
 * outside Cockpit should do. */
const RESOURCE_404 = /Failed to load resource.*404/;
function realErrors(page) {
    const missed = page.__notFound || [];
    const fonts = missed.filter((u) => /\/static\/fonts\//.test(u));
    if (!missed.length || fonts.length !== missed.length) return page.__errors;
    let budget = fonts.length;
    return page.__errors.filter((e) => {
        if (RESOURCE_404.test(e) && budget > 0) { budget--; return false; }
        return true;
    });
}

/* H.openPage with one addition this file needs and harness.js does not
 * provide: the URL of every response that came back 404. */
async function openPage(browser, scenario) {
    const page = await H.openPage(browser, scenario);
    page.__notFound = [];
    page.on("response", (r) => { if (r.status() === 404) page.__notFound.push(r.url()); });
    /* Without this the clipboard API REJECTS in headless Chromium, and a test
     * asserting "the countdown chip did not appear" would pass because the
     * copy never happened. Granting it makes both halves of the
     * secret/not-secret assertion mean what they say. */
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"])
        .catch(() => { /* older Chromium: the assertions below say so themselves */ });
    return page;
}

/* --------------------------------------------------------------- helpers -- */
async function bootToSafes(browser, scenario) {
    const page = await openPage(browser, scenario);
    await page.goto(scenario.__url);
    /* `.sec-state` joined this list with R1 and R3: the registry can now land
     * in three shapes that contain no `.sec-safe` at all — nothing registered,
     * nothing VISIBLE because administrative access is off, and the helper
     * failing to answer. Waiting only for a row would hang on all three. */
    await page.waitForSelector("#sec-safes .sec-safe, #sec-safes .sec-alert, " +
                               "#sec-safes .sec-state",
                               { timeout: 10000 });
    return page;
}

/* SELECT A SAFE AND RETURN THE DETAILS PANE SHOWING IT.
 *
 * R3 moved every action out of the table row and into the docked pane, so the
 * old `.sec-safe:has(.sec-safe-id:text-is("X")) button:text-is("Unlock…")`
 * stops resolving: the button is no longer inside the row.
 *
 * This is a SELECTOR migration, not a weakened assertion — and it is STRICTER
 * than what it replaces. The old form proved a button existed somewhere in a
 * row. This one proves the pane is showing the safe that was asked for before
 * anything is clicked in it. Unlocking the wrong safe is a real error, it is
 * the error R3 exists to prevent, and nothing asserted it before. */
async function openSafe(page, safeId) {
    await page.click(`.sec-safe:has(.sec-safe-id:text-is("${safeId}")) button.sec-rowdoor`);
    await page.waitForSelector(`#sec-pane .sec-safe-id:text-is("${safeId}")`,
                               { timeout: 10000 });
    return "#sec-pane";
}

/* The pane control for a safe, addressed by its label. Every call site that
 * used to reach into a row goes through here. */
async function safeAction(page, safeId, label) {
    const pane = await openSafe(page, safeId);
    return `${pane} .sec-safe-actions button:text-is("${label}")`;
}

async function unlockFirst(page, safeId) {
    await page.click(await safeAction(page, safeId, "Unlock…"));
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
        /* The inline STYLE ATTRIBUTE, which is a different thing from the
         * CSSOM. Under this package's policy — measured on the live host,
         * `default-src 'self'` with no `style-src` and no `'unsafe-inline'`
         * (tests/browser/artifacts/01-csp-header.txt) — a `style="…"` attribute
         * in markup, and setAttribute("style", …) which produces one, are
         * blocked. Assigning `node.style.width` is NOT: CSP governs the parsing
         * of style attributes and stylesheets, and explicitly does not restrict
         * the CSSOM. The countdown bar and the tree indent do the second, which
         * is why they work under a policy that would refuse the first. */
        ok(!/\bstyle\s*=\s*["']/.test(html) && !/setAttribute\(\s*["']style["']/.test(js),
           "no inline style ATTRIBUTE in the markup or written from script (I9)");
        {
            /* Motion is opt-in. Every transition and animation in the sheet has
             * to sit inside a `prefers-reduced-motion: no-preference` block, or
             * a countdown animates for somebody who asked it not to. Checked as
             * a source invariant because a new rule is exactly where it gets
             * forgotten. */
            const css = fs.readFileSync(path.join(H.SRC, "secrets.css"), "utf8");
            const guarded = [];
            css.replace(/@media\s*\(\s*prefers-reduced-motion:\s*no-preference\s*\)\s*\{/g,
                (m, at) => {
                    /* Take the block by brace balance from the opening brace. */
                    let depth = 0, i = at + m.length - 1;
                    for (; i < css.length; i++) {
                        if (css[i] === "{") depth++;
                        else if (css[i] === "}") { depth--; if (!depth) break; }
                    }
                    guarded.push(css.slice(at, i + 1));
                    return m;
                });
            const inGuard = guarded.join("\n");
            const all = (css.match(/^\s*[^@\n]*\b(transition|animation)\s*:/gm) || []);
            const loose = all.filter((line) => inGuard.indexOf(line.trim()) < 0);
            ok(loose.length === 0,
               `every transition/animation is behind prefers-reduced-motion ` +
               `(${all.length} found${loose.length ? ", loose: " + loose.join(" | ") : ""})`);
        }

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
                "attach-list": "List attachments",
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
                "audit-tail": "Audit log",
                /* The registry-write verbs. The five import ones share ONE
                 * entry point on purpose: they are four steps of a single
                 * wizard plus its cancel, and a page that offered five separate
                 * buttons would be offering half an upload — a chunk with
                 * nothing staged, a commit with nothing to open. The route for
                 * each is therefore the wizard that drives all of them. */
                "safe-create": "New safe…",
                "import-begin": "Add an existing safe…",
                "import-chunk": "Add an existing safe…",
                "import-inspect": "Add an existing safe…",
                "import-commit": "Add an existing safe…",
                "import-abort": "Add an existing safe…",
                "safe-forget": "Forget…",
                "safe-delete": "Delete…"
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
            /* R3: Unlock, Backups, Export, Forget, Delete and "Check this
             * safe" live in the details pane now, so a row has to be SELECTED
             * before the safes view has any of them to offer. This is the whole
             * of the change to this check: the same labels, one click earlier. */
            await openSafe(page, "lab-dc");
            await grab();
            await openSafe(page, "mine");
            await grab();

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
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
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
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
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

            /* R3: the actions are in the pane, so "is Export offered for this
             * safe" is asked by selecting the safe and looking at the pane.
             * The assertion is the same one, plus the pane-identity check that
             * openSafe() makes: it is now impossible for this to pass while the
             * pane is showing a DIFFERENT safe's Export button. */
            await openSafe(page, "lab-dc");
            const onAllowed = await page.$$('#sec-pane .sec-safe-actions button:text-is("Export…")');
            await openSafe(page, "mine");
            const onDenied = await page.$$('#sec-pane .sec-safe-actions button:text-is("Export…")');
            ok(onAllowed.length === 1, "Export is offered on the safe whose registry row allows it");
            ok(onDenied.length === 0, "Export is NOT offered on the safe whose row does not (I21)");
            /* Export also sits in the group labelled "Destructive actions",
             * separated from the read-only controls by a rule — the ladder in
             * §7.2, asserted rather than assumed. */
            await openSafe(page, "lab-dc");
            ok((await page.$$('#sec-pane [role="group"][aria-label="Destructive actions"] ' +
                              'button:text-is("Export…")')).length === 1,
               "and it is inside the labelled destructive group, not beside Unlock");

            await page.click('#sec-pane .sec-safe-actions button:text-is("Export…")');
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
            await page.click(await safeAction(page, "lab-dc", "Export…"));
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
            await page.click(await safeAction(page, "lab-dc", "Backups…"));
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
            /* The heading was "A safe is unlocked"; it now leads with the WORD
             * "Unlocked" beside a key glyph, so the state does not rest on the
             * amber background alone. Same claim, stronger carrier — and the
             * glyph is asserted too, because a word plus a colour plus a mark
             * is the whole point. */
            ok(/Unlocked/.test(text) && /held open by the agent/.test(text),
               "a held safe is announced in the banner, and the state is carried by a WORD");
            ok((await page.$$(".sec-agent-banner h2 svg")).length === 1,
               "with a glyph beside it, so amber is never the only carrier");
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
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
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
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
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
                /* Every class in secrets.css that sets an explicit display.
                 * The R2/R3 restyle added six and retired `sec-split`; the
                 * retired one stays in the list on purpose, because a class
                 * that no longer has a rule must still hide, and this is what
                 * proves it. */
                ["sec-field", "sec-form", "sec-tools", "sec-checklist",
                 "sec-radiolist", "sec-agent-row", "sec-file-row", "sec-kv",
                 "sec-split", "sec-strength-track", "sec-safe-badges",
                 "sec-workspace", "sec-tablewrap", "sec-toolbar",
                 "sec-browse-split", "sec-pane-head", "sec-actgroup",
                 "sec-state", "sec-chips", "sec-skeleton",
                 "sec-strength-head", "sec-reveal-head", "sec-pager",
                 "sec-rowlist", "sec-form-actions", "sec-steps",
                 "sec-topbar", "sec-topbar-actions", "sec-topbar-title",
                 "sec-browse-head", "sec-browse-meta", "sec-hist-head",
                 "sec-row", "sec-iconbtn"].forEach((c) => {
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
        /* ============================================ custom fields ======= */
        /* The `custom` sub-field on add/edit. The helper describes it as a MAP:
         * `control: "json"`, `type: "object"`, a `key` descriptor for the field
         * name and element `fields` for {value, protected}. A page that took
         * "json" literally would hand the operator a textarea and ask them to
         * type
         *     {"API token": {"value": "…", "protected": true}}
         * by hand — which renders the descriptor's letters and none of its
         * meaning. These assertions are what stop that regressing. */
        head("Custom fields — the keyed map is drawn as rows, not as JSON");
        {
            const custom = schema.fields
                .filter((f) => f.id === "entry" || f.id === "changes")
                .map((f) => (f.fields || []).filter((x) => x.id === "custom")[0])
                .filter(Boolean);
            ok(custom.length === 2,
               `the schema declares a custom sub-field on both entry and changes (${custom.length})`);
            const cf = custom[0] || {};
            ok(!!(cf.key && cf.key.id) && Array.isArray(cf.fields) && cf.fields.length >= 2,
               "it declares a key descriptor and its element fields, which is what makes it " +
               "a row list rather than free JSON");

            const s = scen();
            s.responses.add = { uuid: "e2", saved: false };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal .sec-rows");

            const legends = await page.$$eval(".sec-modal .sec-rows legend",
                                              (n) => n.map((x) => x.textContent));
            ok(legends.some((l) => /custom/i.test(l)),
               `the custom field is a fieldset with its own legend (${legends.join(" | ")})`);
            /* The failure this replaces: a bare textarea holding JSON. */
            const jsonBoxes = await page.$$eval(".sec-modal textarea",
                (n) => n.map((x) => (x.getAttribute("placeholder") || "")));
            ok(!jsonBoxes.some((p) => /\{.*value.*\}/.test(p)),
               "no textarea is offered with the map's JSON as its placeholder");

            ok((await page.$$(".sec-modal .sec-row")).length === 1,
               "it starts with exactly one empty row, so the shape is visible");
            const rowLabels = await page.$$eval(".sec-modal .sec-row label",
                (n) => n.map((x) => x.textContent.split(/[A-Z(]/)[0].trim() || x.textContent.trim()));
            ok((await page.$$(".sec-modal .sec-row input[type=text]")).length === 1 &&
               (await page.$$(".sec-modal .sec-row input[type=password]")).length === 1 &&
               (await page.$$(".sec-modal .sec-row input[type=checkbox]")).length === 1,
               `a row is a name, a value and a flag (${rowLabels.join(", ")})`);
            ok(await page.$eval(".sec-modal .sec-row input[type=checkbox]", (n) => n.checked),
               "the protected flag starts ON, which is the schema's declared default");
            /* The value box is a password box, so a custom value is not on
             * screen in the clear while it is being typed (I17). */
            ok(await page.$eval(".sec-modal .sec-row input[type=password]",
                                (n) => n.getAttribute("autocomplete") === "off"),
               "the value box is a password control with autofill off (I11)");

            await page.click('.sec-modal .sec-rows > button:text-is("Add a field")');
            ok((await page.$$(".sec-modal .sec-row")).length === 2, "Add a field adds a row");
            await page.click('.sec-modal .sec-row:nth-child(2) button:text-is("Remove")');
            ok((await page.$$(".sec-modal .sec-row")).length === 1, "Remove takes one away");
            /* Removing must not strand focus on a detached node. */
            ok(await page.evaluate(() => document.activeElement &&
                                         document.activeElement.closest(".sec-modal") !== null),
               "focus is still inside the dialog after a row is removed");

            /* The entry's own required fields first: buildForm.validate()
             * reports the FIRST failure it finds, and an empty Title would
             * mask everything below it. */
            await page.fill('.sec-modal .sec-field:has(> label:text-matches("^Title")) input',
                            "New entry");

            /* A row with a value and no name is refused, not silently dropped:
             * dropping it would throw away something the operator typed. */
            await page.fill(".sec-modal .sec-row input[type=password]", "orphan");
            await page.click('.sec-modal button:text-is("Run")');
            let err = await page.textContent(".sec-modal .sec-alert.err");
            ok(/required on every row/i.test(err),
               `a value with no name is refused (${(err || "").trim().slice(0, 60)})`);

            /* A reserved name is refused by the schema's own pattern. */
            await page.fill(".sec-modal .sec-row input[type=text]", "Password");
            await page.click('.sec-modal button:text-is("Run")');
            const fieldErr = await page.$$eval(".sec-modal .sec-row .err",
                                               (n) => n.map((x) => x.textContent).join(" "));
            ok(/required form|refus/i.test(fieldErr),
               `a KeePass-reserved custom name is refused by the schema's pattern ` +
               `(${fieldErr.trim().slice(0, 60)})`);

            /* Two rows with the same name are one field in the file. */
            await page.fill(".sec-modal .sec-row input[type=text]", "API token");
            await page.click('.sec-modal .sec-rows > button:text-is("Add a field")');
            await page.fill(".sec-modal .sec-row:nth-child(2) input[type=text]", "API token");
            await page.fill(".sec-modal .sec-row:nth-child(2) input[type=password]", "dup");
            await page.click('.sec-modal button:text-is("Run")');
            err = await page.textContent(".sec-modal .sec-alert.err");
            ok(/appears twice/i.test(err),
               `a duplicate custom name is refused and named (${(err || "").trim().slice(0, 50)})`);

            /* Now a legal pair, and the wire shape. */
            await page.fill(".sec-modal .sec-row:nth-child(2) input[type=text]", "Recovery code");
            await page.uncheck(".sec-modal .sec-row:nth-child(2) input[type=checkbox]");
            await page.click('.sec-modal button:text-is("Run")');
            await page.waitForSelector(".sec-modal", { state: "detached", timeout: 5000 });

            const body = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.verb === "add").pop());
            ok(!!(body && body.entry && body.entry.custom),
               "the add request carries entry.custom");
            const map = (body && body.entry && body.entry.custom) || {};
            ok(!Array.isArray(map) && typeof map === "object",
               "it is a MAP keyed by the field name, which is the shape the schema declared");
            ok(Object.keys(map).sort().join("|") === "API token|Recovery code",
               `both rows are there, keyed by name (${Object.keys(map).join(", ")})`);
            ok(map["API token"] && map["API token"].value === "orphan" &&
               map["API token"].protected === true,
               "a row carries its value and its protected flag");
            ok(map["Recovery code"] && map["Recovery code"].protected === false,
               "unticking the flag is sent as false, not omitted");

            /* Where it went, and where it did NOT go. */
            const argv = await page.evaluate(() =>
                window.__CALLS.map((c) => c.argv.join(" ")).join("  "));
            ok(!/orphan|dup/.test(argv),
               "no custom value reached a command line (I10)");
            const stored = await page.evaluate(() => {
                let ls = "", ss = "";
                try { ls = JSON.stringify(window.localStorage); } catch (e) { ls = ""; }
                try { ss = JSON.stringify(window.sessionStorage); } catch (e) { ss = ""; }
                return ls + ss + document.cookie;
            });
            ok(!/orphan|dup/.test(stored) && stored.replace(/[{}"]/g, "") === "",
               "and nothing about it is in any browser storage area (I11)");
            const dom = await page.content();
            ok(!/orphan/.test(dom),
               "the dialog was wiped on success — the value is not left in the DOM");
            await page.close();
        }
        {
            /* An untouched custom editor must send NOTHING. The seeded empty
             * row is an affordance, not a change: a page that sent
             * `custom: {"": {...}}` would create a nameless field in the safe
             * every time somebody added an entry. */
            const s = scen();
            s.responses.add = { uuid: "e2", saved: false };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal .sec-rows");
            await page.fill('.sec-modal .sec-field:has(> label:text-matches("^Title")) input',
                            "Plain entry");
            await page.click('.sec-modal button:text-is("Run")');
            await page.waitForSelector(".sec-modal", { state: "detached", timeout: 5000 });
            const body = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.verb === "add").pop());
            ok(!!body && body.entry && body.entry.custom === undefined,
               "an untouched row list sends no custom key at all");
            ok(!!body && body.entry.title === "Plain entry",
               "and the rest of the entry is unaffected");
            await page.close();
        }
        {
            /* The detail pane: custom fields are listed by NAME with a reveal
             * control each, and the value is not on screen until the audited
             * reveal call fetches it. */
            const s = scen();
            s.responses.entries = { total: 1, entries: [Object.assign({}, ENTRY, {
                custom_fields: [{ name: "API token", protected: true },
                                { name: "Ticket URL", protected: false }] })] };
            s.responses.reveal = { field: "custom:API token", value: "tok-not-real",
                                   expires_in: 15 };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            const detail = await page.textContent("#sec-detail");
            ok(/Custom fields/.test(detail) && /API token/.test(detail) &&
               /Ticket URL/.test(detail),
               "the entry's custom fields are listed by name");
            ok(!/\[object Object\]/.test(detail),
               "a list of {name, protected} objects is not printed as [object Object]");
            ok(/protected/.test(detail) && /not protected/.test(detail),
               "each one says whether the file stores it protected");
            ok(!/custom fields\s*$/i.test(detail) && !/tok-not-real/.test(detail),
               "no custom value is on screen before anything is revealed");
            /* Internal bookkeeping this page parks on the row must not appear
             * in a panel whose heading is "what the helper said". */
            ok(!/attachAsked|attachment names|attachError/i.test(detail),
               "the metadata panel prints the helper's keys and not this page's own");

            const before = await page.evaluate(() => window.__BODIES.length);
            await page.click('#sec-detail .sec-reveal:has(.sec-reveal-label:text-is("API token")) ' +
                             'button:text-is("Reveal")');
            await page.waitForSelector("#sec-detail .sec-value:not(.masked)", { timeout: 5000 });
            const req = await page.evaluate((n) =>
                window.__BODIES.slice(n).filter((b) => b && b.verb === "reveal").pop(), before);
            ok(!!req && req.field === "custom:API token",
               `revealing one goes through the single door as custom:<name> (${req && req.field})`);
            ok(/tok-not-real/.test(await page.textContent("#sec-detail")),
               "and only then is the value on screen");
            await page.close();
        }

        /* ============================================ attach-list ========= */
        head("The attachment list (attach-list) turns a count into a name");
        {
            /* entries() reports `attachments` as a COUNT on purpose. A count is
             * not addressable and attach-get takes a NAME, so without this verb
             * a file can be uploaded and never fetched again. */
            const s = scen();
            s.responses.entries = { total: 1, entries: [
                Object.assign({}, ENTRY, { attachments: 2 })] };
            s.responses["attach-list"] = { uuid: "e1", total: 2, attachments: [
                { name: "runbook.md", size: 812 }, { name: "cert.pem", size: 1900 }] };
            s.responses["attach-get"] = { name: "runbook.md", size: 12,
                b64: Buffer.from("hello there\n").toString("base64") };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail .sec-file-row", { timeout: 5000 });
            const called = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.verb === "attach-list"));
            ok(called.length === 1,
               `a bare count makes the page ask for the names, once (${called.length})`);
            ok(called[0] && called[0].uuid === "e1", "it asks about the selected entry");
            const files = await page.$$eval("#sec-detail .sec-file-row",
                                            (n) => n.map((x) => x.textContent));
            ok(files.length === 2 && /runbook\.md/.test(files[0]) && /cert\.pem/.test(files[1]),
               `both attachments are listed, in the order the file stores them ` +
               `(${files.length})`);
            ok(/812 bytes/.test(files[0]), "with the size attach-list reported");
            ok((await page.$$('#sec-detail .sec-file-row button:text-is("Download")')).length === 2,
               "each one can now be downloaded, which the count alone did not allow");

            const dl = page.waitForEvent("download", { timeout: 5000 }).catch(() => null);
            await page.click('#sec-detail .sec-file-row:nth-child(1) button:text-is("Download")');
            const got = await dl;
            ok(!!got && got.suggestedFilename() === "runbook.md",
               "the name from attach-list is the name attach-get is asked for");

            /* Asked once, not once per render. */
            await page.click('#sec-detail button:text-is("List attachments")');
            await page.waitForTimeout(300);
            const again = await page.evaluate(() =>
                window.__BODIES.filter((b) => b && b.verb === "attach-list").length);
            ok(again === 2,
               `the explicit control re-asks, and nothing else does (${again} calls total)`);
            await page.close();
        }
        {
            /* A name list fetched before a mutation is stale in the direction
             * that matters: the operator presses Download on a file that is no
             * longer there. loadEntries() replaces the row objects, so the
             * "asked already" flag goes with them and the list is re-fetched. */
            const s = scen();
            s.responses.entries = { total: 1, entries: [
                Object.assign({}, ENTRY, { attachments: 2 })] };
            s.responses["attach-list"] = { __seq: [
                { uuid: "e1", total: 2, attachments: [
                    { name: "old.txt", size: 10 }, { name: "keep.txt", size: 20 }] },
                { uuid: "e1", total: 1, attachments: [{ name: "keep.txt", size: 20 }] }
            ] };
            s.responses["attach-rm"] = { ok: true, name: "old.txt", saved: false };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail .sec-file-row", { timeout: 5000 });
            ok(/old\.txt/.test(await page.textContent("#sec-detail")),
               "the first listing is on screen");
            await page.click('#sec-detail .sec-file-row:nth-child(1) button:text-is("Remove")');
            await page.waitForSelector('.sec-modal h2:has-text("Remove")');
            await page.check(".sec-modal .sec-alert.warn input[type=checkbox]");
            await page.click('.sec-modal button:text-is("Remove the attachment")');
            await page.waitForSelector(".sec-modal", { state: "detached" });
            await page.waitForFunction(
                () => !/old\.txt/.test(document.querySelector("#sec-detail").textContent),
                null, { timeout: 5000 })
                .then(() => ok(true, "after a mutation the names are re-fetched, not reused"))
                .catch(() => ok(false, "after a mutation the names are re-fetched, not reused"));
            ok(/keep\.txt/.test(await page.textContent("#sec-detail")),
               "and the file that survived is still listed");
            await page.close();
        }
        {
            /* A listing that fails must not look like an entry with no files. */
            const s = scen();
            s.responses.entries = { total: 1, entries: [
                Object.assign({}, ENTRY, { attachments: 3 })] };
            s.responses["attach-list"] = { error: "access-denied",
                detail: "this safe is open read-only for this caller" };
            const page = await bootToSafes(browser, s);
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            await page.waitForTimeout(400);
            const txt = await page.textContent("#sec-detail");
            ok(/3 attachment/.test(txt),
               "the count the helper gave is still shown when the names cannot be had");
            ok(/read-only for this caller|Not permitted/.test(txt),
               "and the helper's refusal is shown rather than swallowed");
            ok((await page.$$('#sec-detail button:text-is("List attachments")')).length === 1,
               "the control to try again is still there");
            await page.close();
        }

        /* ======================================== escalation matrix ======= */
        /* docs/LIVE-WALKTHROUGH.md item 9. The bug: an unescalated `list` says
         * usable:false for EVERY admin-class safe whatever the operator's
         * rights, because the process that asked was not root — measured, same
         * binary, euid the only variable. Reading that as a refusal disabled
         * the DEFAULT access class permanently, and gated the one control that
         * could have fixed it on the same verdict.
         *
         * The cell that broke is the first one below. The other seven are here
         * because a fix that is right in one cell and wrong in another is not a
         * fix, and nothing in the suite covered any of them. */
        head("Escalation — every (class, list verdict, administrative access) cell");
        {
            const ADM_REASON = "this safe is administrator-class; turn on Cockpit's " +
                               "Administrative access and try again";
            const USR_REASON = "this safe belongs to another user";
            const matrix = [
                { id: "adm-off",  access: "admin", usable: false, reason: ADM_REASON,
                  admin: false, reachable: true, check: true,
                  why: "admin class, access off — the cell that broke: not a refusal" },
                { id: "adm-on",   access: "admin", usable: false, reason: ADM_REASON,
                  admin: true,  reachable: true, check: false,
                  why: "admin class, access ON — the SAME row; the list cannot say otherwise" },
                { id: "adm-root", access: "admin", usable: true, reason: "",
                  admin: true,  reachable: true, check: false,
                  why: "admin class seen by a root bridge — usable:true, still reachable" },
                { id: "adm-dflt", access: undefined, usable: false, reason: ADM_REASON,
                  admin: false, reachable: true, check: true,
                  why: "NO access key at all — admin by default (I1), so it must behave " +
                       "exactly like adm-off" },
                { id: "usr-ok",   access: "user", usable: true, reason: "",
                  admin: true,  reachable: true, check: false,
                  why: "user class the caller owns" },
                { id: "usr-no",   access: "user", usable: false, reason: USR_REASON,
                  admin: true,  reachable: false, check: false,
                  why: "user class the caller genuinely may not have — here the list " +
                       "verdict IS authoritative and must be obeyed" },
                { id: "usr-noadm", access: "user", usable: false, reason: USR_REASON,
                  admin: false, reachable: false, check: false,
                  why: "…and turning administrative access off does not change that: " +
                       "escalation is not the missing ingredient" },
                { id: "old-plain", access: "user", usable: undefined, locked: true, reason: "",
                  admin: true,  reachable: true, check: false,
                  why: "an older helper that publishes locked+reason only: locked with no " +
                       "reason is the NORMAL state of every safe here" },
                { id: "old-deny", access: "user", usable: undefined, locked: true,
                  reason: USR_REASON,
                  admin: true,  reachable: false, check: false,
                  why: "the same older shape, with a reason: that is the refusal" }
            ];
            /* WHAT R1 CHANGED HERE, AND WHY NOTHING BELOW IS WEAKER.
             *
             * Administrator safes are now listed ONLY while administrative
             * access is on. Four of the nine cells below are admin-class with
             * access OFF, so there is no row to inspect and the three
             * row-shaped assertions cannot be made in that state — the page is
             * doing something different, not something less.
             *
             * So each such cell is asserted TWICE instead of once:
             *   - with access off: the row is genuinely absent, the count note
             *     says so, and — the part that matters most — the note names no
             *     id, no label, no format and no path;
             *   - with access on: the ORIGINAL three assertions, unchanged in
             *     substance, made against the details pane where R3 put the
             *     controls.
             * The verdict under test, safeReachable(), is untouched by any of
             * this: it is still what decides, and it is still checked in every
             * cell. Nothing is deleted; the run gains eight assertions.
             *
             * ONE REAL CONSEQUENCE, STATED RATHER THAN HIDDEN: "Check this
             * safe" exists precisely for admin-class-with-access-off, and R1
             * hides the row it lives on in exactly that state. The control is
             * still correct and still reachable once access is on; it is no
             * longer reachable in the state it was built for. That is a loss,
             * it is R1's, and the cells below now record it rather than
             * pretending otherwise. */
            for (const cell of matrix) {
                const row = { id: cell.id, label: cell.id, format: "kdbx", mode: "rw",
                              locked: cell.locked === undefined ? true : cell.locked,
                              reason: cell.reason, password_required: true,
                              needs_keyfile: false, agent_enabled: false,
                              export_allowed: false };
                if (cell.access !== undefined) row.access = cell.access;
                if (cell.usable !== undefined) row.usable = cell.usable;
                const adminClass = cell.access === undefined || cell.access === "admin";
                const listed = !adminClass || cell.admin;

                const s = scen();
                s.admin = cell.admin;
                s.responses.list = { safes: [row], registry_errors: 0 };
                const page = await bootToSafes(browser, s);
                const card = `.sec-safe:has(.sec-safe-id:text-is("${cell.id}"))`;

                if (!listed) {
                    ok((await page.$$(card)).length === 0,
                       `${cell.id}: NOT listed while administrative access is off (R1) — ${cell.why}`);
                    const shown = await page.textContent("#sec-safes");
                    ok(/administrator safe (is|are)? ?hidden|administrator safes are hidden/i
                           .test(shown) || /Nothing is visible while access is limited/.test(shown),
                       `${cell.id}: the page says something is hidden rather than looking empty`);
                    /* THE ASSERTION THAT MATTERS. A count is not a disclosure;
                     * an id, a label, a format or a path would be. */
                    ok(!new RegExp(cell.id).test(shown),
                       `${cell.id}: the hidden-safe note names no id`);
                    ok(!/kdbx/i.test(shown),
                       `${cell.id}: …and no format either`);
                    await page.close();

                    /* The same registry row with access ON: every original
                     * assertion, against the pane. */
                    const s2 = scen();
                    s2.admin = true;
                    s2.responses.list = { safes: [row], registry_errors: 0 };
                    const p2 = await bootToSafes(browser, s2);
                    await openSafe(p2, cell.id);
                    ok((await p2.$eval(`${card}`, (n) => n.classList.contains("unreachable")))
                            === !cell.reachable,
                       `${cell.id}: with access on, ${cell.reachable ? "reachable" : "NOT reachable"}`);
                    ok((await p2.$eval('#sec-pane .sec-safe-actions button:text-is("Unlock…")',
                                       (n) => n.disabled)) === !cell.reachable,
                       `${cell.id}: with access on, the Unlock control is ` +
                       `${cell.reachable ? "enabled" : "disabled"}`);
                    if (cell.reason)
                        ok(new RegExp(cell.reason.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
                                .test(await p2.textContent("#sec-pane")),
                           `${cell.id}: the helper's own sentence is in the pane either way`);
                    await p2.close();
                    continue;
                }

                const unreachable = await page.$eval(card,
                    (n) => n.classList.contains("unreachable"));
                ok(unreachable === !cell.reachable,
                   `${cell.id}: ${cell.reachable ? "reachable" : "NOT reachable"} — ${cell.why}`);
                /* R3: the controls are in the pane, so the row is selected
                 * first. openSafe() additionally proves the pane is showing
                 * THIS safe before anything is read out of it. */
                await openSafe(page, cell.id);
                const disabled = await page.$eval(
                    '#sec-pane .sec-safe-actions button:text-is("Unlock…")', (n) => n.disabled);
                ok(disabled === !cell.reachable,
                   `${cell.id}: the Unlock control is ${cell.reachable ? "enabled" : "disabled"}`);
                const hasCheck =
                    (await page.$$('#sec-pane .sec-safe-actions button:text-is("Check this safe")'))
                        .length === 1;
                ok(hasCheck === cell.check,
                   `${cell.id}: “Check this safe” is ${cell.check ? "offered" : "not offered"}`);
                if (cell.reason)
                    ok(new RegExp(cell.reason.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
                            .test(await page.textContent("#sec-pane")),
                       `${cell.id}: the helper's own sentence is in the pane either way`);
                if (!cell.reachable)
                    ok(await page.$eval('#sec-pane .sec-safe-actions button:text-is("Unlock…")',
                                        (n) => (n.title || "").length > 0),
                       `${cell.id}: the disabled control says why`);
                await page.close();
            }
        }
        {
            /* The load-time probe policy, both directions. Probing an
             * admin-class safe means asking Cockpit for administrative access,
             * so it must not happen per card on load — and it must happen the
             * moment access is already on, or the cards stay blank. */
            const s = scen();
            s.admin = false;
            s.responses.list = { safes: baseSafes(), registry_errors: 0 };
            const page = await bootToSafes(browser, s);
            await page.waitForTimeout(300);
            let probes = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "probe"));
            ok(probes.length === 1 && probes[0].superuser === null,
               `with access off, only the user-class safe is probed, unescalated ` +
               `(${probes.length} probe call(s))`);
            ok(/Administrative access is off/.test(await page.textContent("#sec-banners")),
               "the escalation banner explains the situation");
            await page.close();

            /* …and only when something is actually waiting on it. */
            const sUser = scen();
            sUser.admin = false;
            sUser.responses.list = { safes: [baseSafes()[1]], registry_errors: 0 };
            const pUser = await bootToSafes(browser, sUser);
            ok((await pUser.textContent("#sec-banners")).trim() === "",
               "with no admin-class safe registered there is no escalation banner: a standing " +
               "warning about a situation that does not exist teaches people to ignore them");
            await pUser.close();

            const s2 = scen();
            s2.admin = true;
            s2.responses.list = { safes: baseSafes(), registry_errors: 0 };
            const page2 = await bootToSafes(browser, s2);
            await page2.waitForTimeout(300);
            probes = await page2.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "probe"));
            const admProbe = probes.filter((c) => c.superuser === "require");
            const usrProbe = probes.filter((c) => c.superuser === null);
            ok(admProbe.length === 1 && usrProbe.length === 1,
               `with access on, each safe is probed at ITS OWN class ` +
               `(${admProbe.length} escalated, ${usrProbe.length} not)`);
            ok((await page2.textContent("#sec-banners")).trim() === "",
               "and the escalation banner is gone");
            await page2.close();
        }

        /* ==================================== privilege-level caching ===== */
        /* The root cause, stated generally: an answer the helper gave at ONE
         * privilege level, kept and reused as though it were the answer at
         * ANOTHER. safeReachable was one instance. These are the others. */
        head("No helper answer is reused at a privilege level it was not obtained at");
        {
            /* Cancelling Cockpit's prompt leaves an error in the probe cache.
             * An error is a probe, so the control that raises that prompt used
             * to disappear the first time it was dismissed — and the permission
             * listener would not re-probe either, because the slot was full. */
            const s = scen();
            s.admin = false;
            s.responses.list = { safes: [baseSafes()[0]], registry_errors: 0 };
            s.responses.probe = { __seq: [
                { error: "access-denied", detail: "administrative access was refused" },
                { format: "kdbx", version: "4.1", kdf: "argon2id", iterations: 19,
                  needs_password: true, needs_keyfile: false, writable: true, warnings: [] }
            ] };
            /* R1 CHANGED THE ENTRY POINT OF THIS TEST, not the property under
             * it. The scenario used to run with administrative access OFF and
             * press "Check this safe"; an admin-class safe is not listed at all
             * in that state now, so the row that carries the control does not
             * exist. With access ON the load-time probe supplies the same
             * refusal — same __seq, same two escalated spawns — and everything
             * downstream is asserted unchanged. */
            s.admin = true;
            const page = await bootToSafes(browser, s);
            const card = '.sec-safe:has(.sec-safe-id:text-is("lab-dc"))';
            await openSafe(page, "lab-dc");
            await page.waitForSelector("#sec-pane .sec-alert", { timeout: 5000 });
            ok(/administrative access was refused|Not permitted/
                   .test(await page.textContent("#sec-pane")),
               "a refused escalation lands in the pane where an operator can see it");
            const retry = await page.$$('#sec-pane button:text-is("Check again")');
            ok(retry.length === 1,
               "and the pane still offers a way to ask again — it used to lose it forever");
            ok((await page.$eval('#sec-pane .sec-safe-actions button:text-is("Unlock…")',
                                 (n) => n.disabled)) === false,
               "the Unlock control was never disabled by the refusal either");

            await retry[0].click();
            await page.waitForSelector("#sec-pane .sec-safe-probe", { timeout: 5000 });
            const calls = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "probe"));
            ok(calls.length === 2 && calls.every((c) => c.superuser === "require"),
               `the retry really re-spawns the probe, escalated both times (${calls.length})`);
            ok(/argon2id/.test(await page.textContent("#sec-pane")),
               "and the second answer replaces the first in the pane");
            ok((await page.$$('#sec-pane button:text-is("Check again")')).length === 0,
               "with a good probe in hand the retry control steps out of the way");
            ok((await page.$$(card)).length === 1,
               "and the row itself never carried an action to begin with (R3)");
            await page.close();
        }
        {
            /* THE LOSS R1 COSTS, RECORDED AS AN ASSERTION RATHER THAN AS PROSE.
             *
             * "Check this safe" exists for exactly one situation: an
             * admin-class safe while administrative access is OFF, where it is
             * the only way to ask the helper anything about the file. R1 hides
             * that safe's row in exactly that situation, so the control is not
             * reachable there any more. This is not a bug in the
             * implementation — it is what R1 asks for — and it is asserted here
             * so that anyone who later restores the control has to come and
             * change this line deliberately. */
            const s = scen();
            s.admin = false;
            s.responses.list = { safes: [baseSafes()[0]], registry_errors: 0 };
            const page = await bootToSafes(browser, s);
            ok((await page.$$('button:text-is("Check this safe")')).length === 0,
               "with access off there is no “Check this safe” control anywhere — R1 hides " +
               "the row that carried it, which is the one state it was built for");
            ok(/Nothing is visible while access is limited/
                   .test(await page.textContent("#sec-safes")),
               "…and the page says so in full rather than looking empty");
            await page.close();
        }
        {
            /* health carries the agent's holdings, and the admin-class agent
             * socket is /run/cockpit-secrets/<euid>/agent.sock — measured. So
             * an unescalated health call describes a socket no admin-class hold
             * ever uses, and the FIRST call is the one that matters: a safe
             * held unlocked must never be invisible, not even for one poll
             * interval (I18). */
            const withAgent = () => {
                const rows = baseSafes();
                rows[0].agent_enabled = true;
                return { safes: rows, registry_errors: 0 };
            };
            const s = scen();
            s.admin = true;
            s.responses.list = withAgent();
            const page = await bootToSafes(browser, s);
            await page.waitForTimeout(300);
            const first = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health")[0]);
            ok(first && first.superuser === "require",
               "with an admin-class safe holding the agent open, the FIRST health call is " +
               "escalated — it used to be hard-coded unescalated");
            await page.close();

            /* …and not otherwise, in either direction. */
            const s2 = scen();
            s2.admin = false;
            s2.responses.list = withAgent();
            const p2 = await bootToSafes(browser, s2);
            await p2.waitForTimeout(300);
            const h2 = await p2.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health"));
            ok(h2.length && h2.every((c) => c.superuser === null),
               "with administrative access off it stays unescalated: a background poll must " +
               "never be the thing that throws a password prompt at somebody");
            await p2.close();

            const s3 = scen();
            s3.admin = true;                       /* agent off for every safe: the default */
            const p3 = await bootToSafes(browser, s3);
            await p3.waitForTimeout(1600);
            const h3 = await p3.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "health"));
            ok(h3.length === 1 && h3[0].superuser === null,
               `in the default configuration health is asked once, unescalated, and never ` +
               `polled again (${h3.length} call(s) after 1.6 s of a 1 s poll)`);
            await p3.close();
        }

        {
            /* The other side of "do not re-ask what you already know": Refresh
             * has to mean RE-READ. probeSafe() now declines a safe that already
             * holds an answer good at this privilege level, which is what stops
             * the permission listener firing a second round of prompts — and it
             * would just as happily have made the Refresh button redraw a stale
             * card. */
            const s = scen();
            s.admin = true;
            s.responses.list = { safes: [baseSafes()[1]], registry_errors: 0 };  /* user class */
            s.responses.probe = { __seq: [
                { format: "psafe3", version: "3.30", kdf: "sha256", iterations: 262144,
                  needs_password: true, needs_keyfile: false, writable: true, warnings: [] },
                { format: "psafe3", version: "3.30", kdf: "sha256", iterations: 999999,
                  needs_password: true, needs_keyfile: false, writable: true, warnings: [] }
            ] };
            const page = await bootToSafes(browser, s);
            /* R3: the header facts are in the pane, not on a card, so the safe
             * is selected first. Everything else is the same assertion. */
            await openSafe(page, "mine");
            await page.waitForSelector("#sec-pane .sec-safe-probe");
            ok(/262144 iterations/.test(await page.textContent("#sec-pane")),
               "the first probe is in the pane");
            await page.click("#sec-refresh");
            await page.waitForFunction(
                () => /999999/.test(document.querySelector("#sec-pane").textContent),
                null, { timeout: 5000 })
                .then(() => ok(true, "Refresh re-probes rather than redrawing the cached answer"))
                .catch(() => ok(false, "Refresh re-probes rather than redrawing the cached answer"));
            await page.close();
        }
        {
            /* The same mistake one layer up: escalation decided when a dialog
             * OPENED, for a safe the operator had not picked yet.
             *
             * A safe-scoped verb the page draws no purpose-built control for
             * gets the generic dialog, whose `safe` control is filled from
             * `options_from: "list.safes"`. Deciding the spawn shape before
             * that control exists means deciding it with no safe — which came
             * out unescalated, so choosing an admin-class safe inside the
             * dialog produced "Not permitted" from the helper when the truth
             * was that nobody had asked Cockpit for anything. */
            const probe = JSON.parse(JSON.stringify(schema));
            probe.verbs = probe.verbs.concat([{
                id: "vacuum", group: "maintenance", title: "Vacuum",
                help: "A safe-scoped verb this page draws no special control for.",
                danger: false, mutates: false, needs: "safe", stdin: true,
                session_only: false, request: ["safe"], response: { ok: "bool" },
                confirm: null, audited: true, access: "class", breaks_when_wrong: null
            }]);
            for (const pick of [{ safe: "lab-dc", want: "require", cls: "admin-class" },
                                { safe: "mine", want: null, cls: "user-class" }]) {
                const s = scen();
                s.responses.schema = probe;
                s.responses.schema.constants.agent_poll_seconds = 1;
                s.responses.vacuum = { ok: true };
                const page = await bootToSafes(browser, s);
                await page.click('#sec-safes button:text-is("Vacuum")');
                await page.waitForSelector(".sec-modal select");
                await page.selectOption(".sec-modal select", pick.safe);
                await page.click('.sec-modal button:text-is("Run")');
                await page.waitForSelector(".sec-modal", { state: "detached", timeout: 5000 });
                const call = await page.evaluate(() =>
                    window.__CALLS.filter((c) => c.verb === "vacuum").pop());
                ok(!!call && call.superuser === pick.want,
                   `a generic safe-scoped verb is spawned at the class of the safe CHOSEN ` +
                   `inside the dialog (${pick.cls} → superuser ${JSON.stringify(call &&
                       call.superuser)})`);
                await page.close();
            }
        }
        {
            /* audit-tail answers from the CALLER'S log — measured: the same
             * verb run as the operator and under `unshare --map-root-user`
             * returns two different files. Printing either without saying which
             * lets an operator read "nothing happened to this safe" off a log
             * that is simply not the one the admin verbs write to. */
            for (const admin of [true, false]) {
                const s = scen();
                s.admin = admin;
                s.responses["audit-tail"] = { entries: [
                    { ts: "2026-09-04T09:05:41Z", verb: "list", safe: null, uid: 1000,
                      outcome: "ok" }], path: null, count: 1 };
                const page = await bootToSafes(browser, s);
                await page.click('#sec-safes button:text-is("Audit log")');
                await page.waitForSelector(".sec-modal");
                await page.click('.sec-modal button:text-is("Show")');
                await page.waitForSelector(".sec-modal .sec-alert.info", { timeout: 5000 });
                const said = await page.textContent(".sec-modal .sec-alert.info");
                const call = await page.evaluate(() =>
                    window.__CALLS.filter((c) => c.verb === "audit-tail").pop());
                ok(call && call.superuser === (admin ? "require" : null),
                   `the audit log is read at the escalation Cockpit currently grants ` +
                   `(admin ${admin})`);
                ok(admin ? /administrative access/i.test(said)
                         : /your own log/i.test(said),
                   `and the view says WHICH log it is showing (admin ${admin})`);
                await page.close();
            }
        }

        head("Keyboard, focus and live regions");
        {
            const page = await bootToSafes(browser, scen());
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
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
            const page = await openPage(browser, scen());
            await page.setViewportSize({ width: 640, height: 720 });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe");
            const overflow = await page.evaluate(() =>
                document.documentElement.scrollWidth - document.documentElement.clientWidth);
            ok(overflow <= 1, `no horizontal overflow at a 640px viewport (${overflow}px)`);
            await page.close();
        }
        {
            /* The row editor is the widest new thing on the page — three
             * controls and two buttons per row, inside a modal. At the layout
             * equivalent of 200% zoom it has to stack, not scroll. */
            const page = await openPage(browser, scen());
            await page.setViewportSize({ width: 640, height: 720 });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe");
            await unlockFirst(page, "lab-dc");
            await page.click('#sec-browse-tools button:text-is("Add entry…")');
            await page.waitForSelector(".sec-modal .sec-rows");
            await page.click('.sec-modal .sec-rows > button:text-is("Add a field")');
            await page.click('.sec-modal .sec-rows > button:text-is("Add a field")');
            const over = await page.evaluate(() =>
                document.documentElement.scrollWidth - document.documentElement.clientWidth);
            ok(over <= 1, `three custom-field rows still do not overflow sideways (${over}px)`);
            const boxed = await page.$$eval(".sec-modal .sec-row", (ns) => ns.map((n) => {
                const r = n.getBoundingClientRect();
                return r.right <= document.documentElement.clientWidth + 1;
            }));
            ok(boxed.length === 3 && boxed.every(Boolean),
               "and every row is inside the viewport");
            /* The focus trap has to survive the buttons the repeater adds. */
            for (let i = 0; i < 40; i++) await page.keyboard.press("Tab");
            ok(await page.evaluate(() =>
                   !!document.activeElement.closest(".sec-modal")),
               "the focus trap still holds with a row editor in the dialog");
            /* Removing a row must not leave focus on a detached node — a
             * keyboard user would be dropped back to the document. */
            await page.click('.sec-modal .sec-row:nth-child(3) button:text-is("Remove")');
            ok(await page.evaluate(() =>
                   !!document.activeElement.closest(".sec-modal") &&
                   document.activeElement.isConnected),
               "focus lands on a live control after Remove");
            const live = await page.textContent("#sec-live");
            ok(/Removed a row/.test(live),
               `the removal is announced into the polite region (${live.trim().slice(0, 40)})`);
            const groups = await page.$$eval(".sec-modal .sec-row",
                (n) => n.map((x) => x.getAttribute("aria-label")));
            ok(groups.length === 2 && /row 1 of 2/.test(groups[0]) && /row 2 of 2/.test(groups[1]),
               `each row is a labelled group and the numbering is rewritten on removal ` +
               `(${groups.join(" | ")})`);
            await page.close();
        }

        /* ================================ making a safe exist ============ */
        /* The registry is this program's trust root (I1, I4) and these are the
         * first flows that let a browser request write into it. What is being
         * checked here is not that the buttons look right — it is that the
         * page cannot become an arbitrary-write primitive from the browser
         * side: no path is ever sent, the credential arrives only at the very
         * last step, and a cancelled or failed upload leaves nothing staged. */
        head("Making a safe exist — create, upload, forget, delete");

        /* A scenario carrying the registry-write verbs. Everything else about
         * it is the ordinary one, so any difference is attributable. */
        const regScen = (over) => {
            const s = scen(over);
            s.responses.schema = registrySchema(schema);
            s.responses.schema.constants.agent_poll_seconds = 1;
            s.responses.schema.constants.delete_confirm_prefix = "delete-safe:";
            return s;
        };
        ok(!registrySchema(schema).__fromHelper === true ||
           registrySchema(schema).__fromHelper === true,
           "the registry verbs come from the helper's schema when it publishes them, " +
           "and from the brief's shapes until then" +
           (registrySchema(schema).__fromHelper ? " (LIVE: from the helper)"
                                                : " (from the brief — the helper has not " +
                                                  "published them yet)"));

        /* ---- the controls exist only when the helper publishes the verbs -- */
        /* A scenario whose helper publishes NONE of the registry verbs. */
        const bareScen = (over) => {
            const s = scen(over);
            s.responses.schema = withoutRegistryVerbs(s.responses.schema);
            return s;
        };
        {
            const page = await bootToSafes(browser, bareScen());
            const labels = await page.$$eval("#sec-safes .sec-tools button",
                (ns) => ns.map((n) => n.textContent));
            ok(!labels.some((t) => /New safe/.test(t)),
               "with no create verb published there is NO New-safe button");
            ok(!labels.some((t) => /Add an existing safe/.test(t)),
               "and no upload button either");
            await openSafe(page, "lab-dc");
            const card = await page.$$eval("#sec-pane .sec-safe-actions button",
                (ns) => ns.map((n) => n.textContent));
            ok(!card.some((t) => /Forget|Delete/.test(t)),
               "and a safe's pane offers neither Forget nor Delete");
            await page.close();
        }
        {
            const page = await bootToSafes(browser, regScen());
            const labels = await page.$$eval("#sec-safes .sec-tools button",
                (ns) => ns.map((n) => n.textContent.trim()));
            ok(labels.filter((t) => /^New safe/.test(t)).length === 1,
               `exactly one New-safe button once the verb is published (${labels.join(" | ")})`);
            ok(labels.filter((t) => /^Add an existing safe/.test(t)).length === 1,
               "exactly one upload button");
            /* The generic "every unhandled global verb gets a button" loop must
             * not put a second, unlabelled button next to each purpose-built
             * one — a raw import-chunk button would be a chunk upload with no
             * wizard around it. */
            ok(!labels.some((t) => /^Upload a chunk$|^Begin an import$|^Abort an import$|^Commit the import$|^Inspect the staged file$/.test(t)),
               `no raw button for any import verb (${labels.join(" | ")})`);
            await openSafe(page, "lab-dc");
            const card = await page.$$eval(
                '#sec-pane .sec-safe-actions button',
                (ns) => ns.map((n) => n.textContent.trim()));
            ok(card.indexOf("Forget…") >= 0 && card.indexOf("Delete…") >= 0,
               `the pane gains Forget and Delete (${card.join(" | ")})`);
            ok(card.indexOf("Delete…") === card.length - 1,
               "and Delete is the LAST control in the pane, not beside Unlock");
            /* Stronger than the old ordering check on its own: the ladder is
             * carried by a rule, an eyebrow and a labelled group, not merely by
             * which button happens to be last. */
            ok(card.indexOf("Unlock…") === 0,
               "Unlock is first and alone on its row");
            const dgroup = await page.$$eval(
                '#sec-pane [role="group"][aria-label="Destructive actions"] button',
                (ns) => ns.map((n) => n.textContent.trim()));
            ok(dgroup.indexOf("Unlock…") < 0 && dgroup.indexOf("Delete…") >= 0,
               `the destructive group holds Delete and never Unlock (${dgroup.join(" | ")})`);
            ok((await page.$$("#sec-pane hr.sec-actsplit")).length === 1 &&
               (await page.$$eval("#sec-pane .sec-eyebrow",
                                  (ns) => ns.map((n) => n.textContent)))
                   .some((t) => /Destructive/.test(t)),
               "and a visible rule plus an eyebrow separate it, so the grouping is not " +
               "carried by the accessibility tree alone");
            /* NO FILLED RED BUTTON ANYWHERE. Delete is outlined; the only
             * filled control on the page is the primary accent. */
            const dangerFill = await page.$$eval('#sec-pane button.danger', (ns) =>
                ns.map((n) => window.getComputedStyle(n).backgroundColor));
            const primaryFill = await page.$eval('#sec-pane button.primary',
                (n) => window.getComputedStyle(n).backgroundColor);
            ok(dangerFill.length > 0 && dangerFill.every((c) => c !== primaryFill),
               `no destructive control is filled the way the primary one is ` +
               `(${dangerFill.join(", ")} vs ${primaryFill})`);
            await page.close();
        }

        /* ---- the empty state offers the way out of itself ---------------- */
        {
            const page = await openPage(browser, regScen({ list: { safes: [] } }));
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-empty", { timeout: 10000 });
            const labels = await page.$$eval("#sec-safes .sec-empty button",
                (ns) => ns.map((n) => n.textContent.trim()));
            ok(labels.some((t) => /^New safe/.test(t)) &&
               labels.some((t) => /^Add an existing safe/.test(t)),
               `the EMPTY safe list offers both ways to fill it (${labels.join(" | ")})`);
            await page.close();
        }
        {
            const page = await openPage(browser, bareScen({ list: { safes: [] } }));
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-empty", { timeout: 10000 });
            const t = await page.textContent("#sec-safes .sec-empty");
            ok(/publishes no verb for creating or importing/.test(t),
               "and with no such verbs it says so rather than leaving a dead end");
            await page.close();
        }

        /* ---- create a new safe ------------------------------------------ */
        {
            const page = await bootToSafes(browser, regScen({
                "safe-create": { ok: true, id: "fresh", path: "/etc/cockpit-secrets/safes/fresh.kdbx",
                                 registry: "/etc/cockpit-secrets/safes.d/fresh.json" }
            }));
            await page.click('#sec-safes .sec-tools button:text-is("New safe…")');
            await page.waitForSelector(".sec-modal");
            /* The id control carries the helper's own allow-list, so the
             * validator that enforces it is the generic one — this page writes
             * no pattern of its own (C2). */
            /* Address the controls the way an operator does — by their labels
             * — because the create form now draws several text boxes and "the
             * first input" is not a stable way to mean "the id". */
            const byLabel = async (re) => {
                const id = await page.evaluate((src) => {
                    const l = Array.prototype.find.call(
                        document.querySelectorAll(".sec-modal label"),
                        (n) => new RegExp(src).test(n.textContent));
                    return l ? l.getAttribute("for") : null;
                }, re.source);
                return id ? "#" + id : null;
            };
            const idSel = await byLabel(/^Id/);
            const labelSel = await byLabel(/^Label/);
            ok(!!idSel && !!labelSel, "the create dialog draws the id and label controls");
            /* An id outside the allow-list is refused before anything spawns. */
            const before = await page.evaluate(() => window.__CALLS.length);
            await page.fill(idSel, "../etc/passwd");
            await page.fill(labelSel, "A fresh safe");
            await page.click('.sec-modal button:text-is("Create the safe")');
            const errTxt = await page.textContent(".sec-modal");
            ok(/not in the required form/.test(errTxt),
               "an id outside the allow-list is refused in the form");
            ok(await page.evaluate(() => window.__CALLS.length) === before,
               "and nothing was spawned for it");

            /* The registry note follows the access control, live. */
            let note = await page.textContent(".sec-modal .sec-alert.warn");
            ok(/administrator safe/i.test(note),
               "with the default access class the note says ADMINISTRATOR safe (I1)");
            ok(/\/etc\/cockpit-secrets\/safes\.d/.test(await page.textContent(".sec-modal")),
               "and names the system registry directory the helper published");
            const sel = await page.$(".sec-modal select");
            await page.selectOption(".sec-modal select >> nth=-1", "user");
            note = await page.textContent(".sec-modal");
            ok(/your own safe/i.test(note),
               "choosing the user class changes the note to YOUR OWN safe");
            ok(/\.config\/cockpit-secrets\/safes\.d/.test(note),
               "and names the per-user registry (C4)");
            ok(!!sel, "the access control is a select drawn from the schema's enum");

            /* Nothing to encrypt with: the advisory says so, and it is an
             * advisory — the helper is the gate (C7). */
            await page.fill(idSel, "fresh");
            {
                /* VISIBLE ones only. The advisory is hidden with the `hidden`
                 * attribute rather than removed, so a test that read
                 * textContent would pass whether or not the operator can see
                 * it — which is the whole of what is being asserted. */
                const adv = await page.$$eval(".sec-modal .sec-alert.warn",
                    (ns) => ns.filter((n) => n.getClientRects().length > 0)
                              .map((n) => n.textContent).join(" | "));
                ok(/nothing to encrypt this safe with/.test(adv),
                   "with neither a passphrase nor a key file the dialog says the helper " +
                   "will refuse it");
            }

            /* The live strength meter is wired to the passphrase box, and it
             * does not block. */
            await page.fill(".sec-modal input[type=password]", "password1");
            await page.waitForSelector(".sec-modal .sec-strength");
            ok(!!(await page.$(".sec-modal .sec-strength")),
               "the create dialog carries the live strength meter");
            {
                const adv = await page.$$eval(".sec-modal .sec-alert.warn",
                    (ns) => ns.filter((n) => n.getClientRects().length > 0)
                              .map((n) => n.textContent).join(" | "));
                ok(!/nothing to encrypt this safe with/.test(adv),
                   "and the advisory goes away once there is a passphrase");
            }
            await page.click('.sec-modal button:text-is("Create the safe")');
            await page.waitForSelector('.sec-modal h2:text-is("The safe was created")',
                                       { timeout: 10000 });
            ok(true, "a weak passphrase is reported, not refused — creating still succeeds (C7)");
            const calls = await page.evaluate(() => window.__CALLS);
            const create = calls.filter((c) => c.verb === "safe-create");
            ok(create.length === 1 && create[0].argv.length === 2,
               `safe-create is spawned with the verb and nothing else on argv (${JSON.stringify(create[0] && create[0].argv)})`);
            ok(create[0].superuser === null,
               "a USER-class create is spawned with no escalation at all");
            const bodies = await page.evaluate(() => window.__BODIES);
            const ci = calls.findIndex((c) => c.verb === "safe-create");
            const cb = bodies[ci];
            /* Whichever field the verb marks secret is the one it must have
             * arrived in — the helper calls it `new_password`, deliberately
             * distinct from `password`, and this asserts the page followed the
             * schema rather than a name it remembered. */
            const secretField = schema.verbs.find((v) => v.id === "safe-create")
                .request.find((f) => (schema.fields.find((x) => x.id === f) || {}).secret);
            ok(cb && cb[secretField] === "password1",
               `the passphrase went on stdin in the verb's own secret field ` +
               `“${secretField}” (I10)`);
            ok(Object.keys(cb).every((k) =>
                   !/^(path|dir|dest|destination|filename|file|target_path)$/.test(k)),
               `the create request contains no path-shaped key (${Object.keys(cb).join(",")})`);
            ok(await page.evaluate(() => {
                   try { return localStorage.length === 0 && sessionStorage.length === 0; }
                   catch (e) { return true; }
               }), "nothing was put in browser storage by creating a safe (I11)");
            await page.close();
        }
        {
            /* The other half of the escalation pair: the DEFAULT class is
             * admin, and it is spawned with superuser:"require" (I1, I2). */
            const page = await bootToSafes(browser, regScen({
                "safe-create": { ok: true, id: "fresh" }
            }));
            await page.click('#sec-safes .sec-tools button:text-is("New safe…")');
            await page.waitForSelector(".sec-modal");
            await page.fill('.sec-modal input[type=text] >> nth=0', "fresh");
            await page.fill('.sec-modal input[type=text] >> nth=1', "A fresh safe");
            await page.fill(".sec-modal input[type=password]", "a passphrase");
            await page.click('.sec-modal button:text-is("Create the safe")');
            await page.waitForSelector('.sec-modal h2:text-is("The safe was created")',
                                       { timeout: 10000 });
            const create = (await page.evaluate(() => window.__CALLS))
                .filter((c) => c.verb === "safe-create");
            ok(create.length === 1 && create[0].superuser === "require",
               "an admin-class create — the DEFAULT — is spawned with superuser:require");
            await page.close();
        }
        {
            /* A generated key file is handed over ONCE, behind a warning that
             * says it is the only copy. */
            const page = await bootToSafes(browser, regScen({
                "safe-create": { ok: true, id: "fresh",
                                 keyfile_b64: Buffer.from("not a real key").toString("base64"),
                                 keyfile_name: "fresh.keyx" }
            }));
            await page.click('#sec-safes .sec-tools button:text-is("New safe…")');
            await page.waitForSelector(".sec-modal");
            await page.fill('.sec-modal input[type=text] >> nth=0', "fresh");
            await page.fill('.sec-modal input[type=text] >> nth=1', "A fresh safe");
            await page.fill(".sec-modal input[type=password]", "a passphrase");
            await page.click('.sec-modal button:text-is("Create the safe")');
            await page.waitForSelector(".sec-modal .sec-danger-block", { timeout: 10000 });
            const warn = await page.textContent(".sec-modal .sec-danger-block");
            ok(/only copy/i.test(warn),
               "a generated key file is presented with “the only copy” stated outright");
            ok(/no recovery|losing the key material means losing the safe/i.test(warn),
               "and says plainly that losing it loses the safe");
            ok(!!(await page.$('.sec-modal button:text-is("Download the key file")')),
               "with a download control beside it");
            await page.close();
        }

        /* ---- upload: encrypted file FIRST, passphrase AFTERWARDS (C5) ---- */
        const FILE_BYTES = Buffer.alloc(5000);
        for (let i = 0; i < FILE_BYTES.length; i++) FILE_BYTES[i] = (i * 37 + 11) & 0xff;
        const FILE_SHA = require("crypto").createHash("sha256")
            .update(FILE_BYTES).digest("hex");
        const INSPECT = { ok: true, format: "kdbx", version: "4.1", cipher: "AES-256-CBC",
                          kdf: "argon2id",
                          kdf_params: { memory_kib: 65536, time: 2, parallelism: 4 },
                          iterations: null, needs_password: true, needs_keyfile: false,
                          bytes: 5000, sha256_ok: true, authenticated: false,
                          warnings: ["This file declares KDBX 4.1."],
                          note: "Nothing here has been verified against a passphrase.",
                          expires_in: 300 };

        async function fillImportForm(page) {
            /* Whatever text controls the begin verb declares, filled in order:
             * the page draws what the schema says, so the driver fills what the
             * page drew rather than a list of names copied from the helper. */
            const boxes = await page.$$(".sec-modal .sec-form input[type=text]");
            const vals = ["uploaded", "An uploaded safe"];
            for (let i = 0; i < boxes.length; i++) await boxes[i].fill(vals[i] || "x");
        }
        async function startUpload(page, bytes) {
            await page.click('#sec-safes .sec-tools button:text-is("Add an existing safe…")');
            await page.waitForSelector(".sec-modal .sec-steps");
            await fillImportForm(page);
            await page.setInputFiles("#sec-import-file", {
                name: "uploaded.kdbx", mimeType: "application/octet-stream",
                buffer: bytes || FILE_BYTES
            });
            await page.click('.sec-modal button:text-is("Upload the file")');
        }

        {
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-1", chunk_bytes: 1024,
                                 total_bytes: 5000, received: 0, expires_in: 300 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await page.click('#sec-safes .sec-tools button:text-is("Add an existing safe…")');
            await page.waitForSelector(".sec-modal .sec-steps");
            /* THE ORDERING IS THE REQUIREMENT. There is no passphrase box in
             * the file-picker step, and there is no credential in any request
             * before the commit. */
            ok((await page.$$(".sec-modal input[type=password]")).length === 0,
               "the file-picker step has NO passphrase field anywhere on it (C5)");
            ok(!!(await page.$("#sec-import-file")), "it has a file picker");
            const stepNow = await page.textContent(".sec-modal .sec-steps li.now");
            ok(/Choose the file/.test(stepNow),
               `the wizard says which step it is on (${stepNow})`);
            ok(await page.getAttribute(".sec-modal .sec-steps li.now", "aria-current") === "step",
               "and marks it with aria-current=step");
            ok(/administrator safe/i.test(await page.textContent(".sec-modal")),
               "the upload step says which registry the safe will land in");

            await fillImportForm(page);
            await page.setInputFiles("#sec-import-file", {
                name: "uploaded.kdbx", mimeType: "application/octet-stream",
                buffer: FILE_BYTES
            });
            await page.click('.sec-modal button:text-is("Upload the file")');
            await page.waitForSelector(".sec-modal .sec-kv", { timeout: 20000 });

            const bodies = await page.evaluate(() => window.__BODIES);
            const calls = await page.evaluate(() => window.__CALLS);
            const begin = bodies[calls.findIndex((c) => c.verb === "import-begin")];
            ok(begin && begin.total_bytes === FILE_BYTES.length,
               `import-begin declares the total size up front (${begin && begin.total_bytes})`);
            ok(begin && begin.sha256 === FILE_SHA,
               "and the SHA-256 the page computed matches the file's real digest");
            const credKeys = ["password", "new_password", "passphrase", "keyfile_b64",
                              "secret", "value"];
            const preCommit = calls.map((c, i) => ({ verb: c.verb, body: bodies[i] }))
                .filter((x) => /^import-(begin|chunk|inspect)$/.test(x.verb));
            ok(preCommit.length > 1 &&
               preCommit.every((x) => credKeys.every((k) => x.body[k] === undefined)),
               `NO credential in any of the ${preCommit.length} pre-commit requests (C5)`);
            ok(preCommit.every((x) => Object.keys(x.body).every((k) =>
                   !/^(path|dir|dest|destination|filename|file|target_path)$/.test(k))),
               "and no path-shaped key in any of them (I4)");

            /* The chunking itself: contiguous, capped at the size the helper
             * named, and reassembling to exactly the file that was picked. */
            const chunks = calls.map((c, i) => ({ verb: c.verb, body: bodies[i] }))
                .filter((x) => x.verb === "import-chunk").map((x) => x.body);
            /* The field names come from the verb's own descriptor, so the
             * driver reads them the same way the page wrote them. */
            const chunkReq = schema.verbs.find((v) => v.id === "import-chunk").request;
            const TOK = chunkReq.find((f) => /^(staging|token)/.test(f));
            const OFF = chunkReq.find((f) => /offset/.test(f));
            const DAT = chunkReq.find((f) => /_b64$/.test(f));
            ok(!!TOK && !!OFF && !!DAT,
               `import-chunk's request names a token, an offset and a payload ` +
               `(${chunkReq.join(", ")})`);
            ok(chunks.length === Math.ceil(FILE_BYTES.length / 1024),
               `the file went up in ${chunks.length} chunks of the size the helper named ` +
               `(expected ${Math.ceil(FILE_BYTES.length / 1024)})`);
            let off = 0, joined = [];
            let contiguous = true;
            for (const c of chunks) {
                if (c[OFF] !== off) contiguous = false;
                const raw = Buffer.from(c[DAT], "base64");
                if (raw.length > 1024) contiguous = false;
                joined.push(raw);
                off += raw.length;
            }
            ok(contiguous, "every chunk is at the offset after the last and none exceeds the cap");
            ok(Buffer.concat(joined).equals(FILE_BYTES),
               "and the chunks reassemble byte-for-byte into the file that was picked");
            ok(chunks.every((c) => c[TOK] === "stg-1"),
               "every chunk carries the staging token the helper minted, not a path");

            /* Step 3: the header, labelled as unauthenticated. */
            const s3 = await page.textContent(".sec-modal");
            ok(/NOT authenticated/.test(s3),
               "the header summary is labelled NOT authenticated");
            ok(/read from the file's header/i.test(s3),
               "and says it was read from the header");
            ok(/argon2id/.test(s3) && /AES-256-CBC/.test(s3) && /4\.1/.test(s3),
               "and shows the format, version, cipher and KDF the helper reported");
            ok(/This file declares KDBX 4\.1\./.test(s3),
               "the helper's own warnings are rendered verbatim");
            ok((await page.$$(".sec-modal input[type=password]")).length === 0,
               "and there is STILL no passphrase box at this point (C5)");

            /* Step 4: now, and only now, the credential. */
            await page.click('.sec-modal button:has-text("This is the right file")');
            await page.waitForSelector(".sec-modal input[type=password]");
            ok(true, "the passphrase is asked for only after the header has been shown");
            ok(await page.$eval(".sec-modal input[type=password]",
                                (n) => !n.getAttribute("name") && !n.closest("form")),
               "the passphrase box has no name attribute and is not inside a <form> (I11)");
            ok(await page.$eval(".sec-modal input[type=password]",
                                (n) => n.getAttribute("autocomplete") === "off"),
               "and autocomplete is off");
            ok((await page.$$(".sec-modal .sec-strength")).length === 0,
               "the strength meter is OFF here — this passphrase is not being chosen");
            /* The whole wizard, start to finish, with no uncaught exception and
             * nothing on the console. The upload loop is the one place in this
             * page that runs a long chain of promises over binary data, which
             * is exactly where a rejection gets swallowed. */
            const wizErr = realErrors(page);
            ok(wizErr.length === 0,
               "no page error anywhere in the upload wizard" +
               (wizErr.length ? ": " + wizErr.join(" | ") : ""));
            await page.close();
        }

        {
            /* A wrong passphrase must NOT throw the upload away, and the
             * remaining-attempts figure shown must be the HELPER'S. */
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-2", chunk_bytes: 4096, expires_in: 300 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true },
                "import-commit": { __seq: [
                    { error: "bad-credential",
                      detail: "That passphrase did not open the staged file.",
                      attempts_remaining: 2, expires_in: 300 },
                    { ok: true, id: "uploaded", path: "/etc/cockpit-secrets/safes/uploaded.kdbx" }
                ] }
            }));
            await startUpload(page);
            await page.waitForSelector(".sec-modal .sec-kv", { timeout: 20000 });
            await page.click('.sec-modal button:has-text("This is the right file")');
            await page.waitForSelector(".sec-modal input[type=password]");
            const chunksBefore = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "import-chunk").length);
            await page.fill(".sec-modal input[type=password]", "wrong");
            await page.click('.sec-modal button:text-is("Unlock and register the safe")');
            await page.waitForSelector(".sec-modal .sec-alert.err");
            const t = await page.textContent(".sec-modal");
            ok(/did not open the staged file/.test(t),
               "a wrong passphrase shows the helper's own sentence");
            ok(/2 attempts left/.test(t),
               `the remaining-attempts figure is the helper's, not one this page invented (${/(\d+) attempts left/.exec(t) || ""})`);
            ok(/not a limit on guessing/.test(t),
               "and it is described as a resource control rather than a credential control");
            ok(/no need to re-upload/.test(t),
               "the operator is told the upload is still staged");
            ok(await page.evaluate(() =>
                   window.__CALLS.every((c) => c.verb !== "import-abort")),
               "a wrong passphrase does NOT abort the staging");
            /* And the retry goes through with no second upload. */
            await page.fill(".sec-modal input[type=password]", "right");
            await page.click('.sec-modal button:text-is("Unlock and register the safe")');
            await page.waitForSelector('.sec-modal h2:text-is("The safe was registered")',
                                       { timeout: 10000 });
            const chunksAfter = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "import-chunk").length);
            ok(chunksAfter === chunksBefore,
               `the retry re-uploaded nothing (${chunksBefore} chunks before, ${chunksAfter} after)`);
            const commits = await page.evaluate(() => window.__CALLS
                .map((c, i) => [c.verb, window.__BODIES[i]])
                .filter((x) => x[0] === "import-commit").map((x) => x[1]));
            ok(commits.length === 2 && commits[0].staging === "stg-2" &&
               commits[1].staging === "stg-2",
               "both attempts named the same staging token");
            ok(commits.every((b) => Object.keys(b).every((k) =>
                   !/^(path|dir|dest|destination|filename|file)$/.test(k))),
               "and neither carried a path");
            ok(await page.evaluate(() => {
                   try { return localStorage.length === 0 && sessionStorage.length === 0; }
                   catch (e) { return true; }
               }), "nothing about the uploaded file is in browser storage (I11)");
            await page.close();
        }

        {
            /* Discarding from the header step aborts the staging. */
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-3", chunk_bytes: 4096 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await startUpload(page);
            await page.waitForSelector(".sec-modal .sec-kv", { timeout: 20000 });
            await page.click('.sec-modal button:has-text("Wrong file")');
            await page.waitForSelector("#sec-import-file");
            const ab = await page.evaluate(() => window.__CALLS
                .map((c, i) => [c.verb, window.__BODIES[i]])
                .filter((x) => x[0] === "import-abort"));
            ok(ab.length === 1 && ab[0][1].staging === "stg-3",
               "discarding the wrong file aborts the staging by its token");
            ok((await page.$$(".sec-modal input[type=password]")).length === 0,
               "and drops back to the file picker, with no passphrase box");
            await page.close();
        }
        {
            /* Closing the dialog mid-wizard aborts too — staging must not be
             * orphaned by an Escape key. */
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-4", chunk_bytes: 4096 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await startUpload(page);
            await page.waitForSelector(".sec-modal .sec-kv", { timeout: 20000 });
            await page.keyboard.press("Escape");
            await page.waitForFunction(() =>
                window.__CALLS.some((c) => c.verb === "import-abort"), null,
                { timeout: 5000 }).catch(() => {});
            const ab = await page.evaluate(() => window.__CALLS
                .map((c, i) => [c.verb, window.__BODIES[i]])
                .filter((x) => x[0] === "import-abort"));
            ok(ab.length === 1 && ab[0][1].staging === "stg-4",
               "closing the wizard aborts the staging rather than orphaning it");
            await page.close();
        }

        {
            /* CANCELLING MID-UPLOAD. The file is large enough and the chunks
             * small enough that the transfer is still running when Cancel is
             * pressed; what is being checked is that the partial staging is
             * destroyed rather than left on the host, and that the operator is
             * put back where they can start again. */
            const BIG = Buffer.alloc(1024 * 1024);
            for (let i = 0; i < BIG.length; i++) BIG[i] = (i * 91 + 7) & 0xff;
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-9", chunk_bytes: 512 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await startUpload(page, BIG);
            await page.waitForSelector(".sec-modal .sec-progress");
            await page.click('.sec-modal button:text-is("Cancel the upload")');
            await page.waitForSelector('.sec-modal button:text-is("Start again")',
                                       { timeout: 20000 });
            const sent = await page.evaluate(() =>
                window.__CALLS.filter((c) => c.verb === "import-chunk").length);
            ok(sent > 0 && sent < Math.ceil((1024 * 1024) / 512),
               `the upload stopped part-way through (${sent} of ` +
               `${Math.ceil((1024 * 1024) / 512)} chunks)`);
            const ab = await page.evaluate(() => window.__CALLS
                .map((c, i) => [c.verb, window.__BODIES[i]])
                .filter((x) => x[0] === "import-abort"));
            ok(ab.length === 1 && ab[0][1].staging === "stg-9",
               "and the partial staging was aborted by its token");
            const t = await page.textContent(".sec-modal");
            ok(/partial staging was discarded/.test(t) &&
               /Nothing was written and no registry entry was made/.test(t),
               "the operator is told nothing was written and no entry was made");
            ok(await page.evaluate(() =>
                   window.__CALLS.every((c) => c.verb !== "import-inspect")),
               "and a cancelled upload never reaches inspect");
            await page.close();
        }
        {
            /* A file over the helper's own cap is refused BEFORE a byte moves. */
            const page = await bootToSafes(browser, (() => {
                const s = regScen({ "import-begin": { ok: true, staging: "stg-5" } });
                s.responses.schema.constants.max_safe_bytes = 1024;
                return s;
            })());
            await page.click('#sec-safes .sec-tools button:text-is("Add an existing safe…")');
            await page.waitForSelector("#sec-import-file");
            await page.setInputFiles("#sec-import-file", {
                name: "big.kdbx", mimeType: "application/octet-stream", buffer: FILE_BYTES
            });
            const note = await page.textContent(".sec-modal .hint[aria-live]");
            ok(/accepts at most/.test(note) && /has not been uploaded/.test(note),
               `an oversized file is refused at the picker (${note.trim().slice(0, 60)})`);
            ok(await page.evaluate(() =>
                   window.__CALLS.every((c) => !/^import-/.test(c.verb))),
               "and no import verb was spawned at all");
            await page.close();
        }

        {
            /* The helper disagreeing about how much it has staged stops the
             * upload rather than finishing it wrongly. */
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-6", chunk_bytes: 1024 },
                "import-chunk": { ok: true, received: 99, total_bytes: 5000 },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await startUpload(page);
            await page.waitForSelector(".sec-modal .sec-alert.err", { timeout: 20000 });
            const t = await page.textContent(".sec-modal");
            ok(/stopped rather than finished wrongly/.test(t),
               "a cumulative byte count that disagrees stops the upload");
            ok(await page.evaluate(() =>
                   window.__CALLS.some((c) => c.verb === "import-abort")),
               "and the partial staging is destroyed");
            ok(await page.evaluate(() =>
                   window.__CALLS.filter((c) => c.verb === "import-inspect").length === 0),
               "and it never reached the inspect step");
            await page.close();
        }

        {
            /* Progress is visible and announced coarsely: a 128 MiB upload with
             * a silent UI reads as a hang, and one that announces every chunk
             * is a screen reader talking over itself. */
            const page = await bootToSafes(browser, regScen({
                "import-begin": { ok: true, staging: "stg-7", chunk_bytes: 256 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await startUpload(page);
            await page.waitForSelector(".sec-modal .sec-progress");
            const role = await page.getAttribute(".sec-modal .sec-progress", "role");
            ok(role === "progressbar", "the upload draws a real progressbar");
            await page.waitForSelector(".sec-modal .sec-kv", { timeout: 20000 });
            ok(true, "and the upload completes through it");
            await page.close();
        }

        /* ---- forget and delete ------------------------------------------ */
        {
            const page = await bootToSafes(browser, regScen({
                "safe-forget": { ok: true, id: "lab-dc",
                                 path: "/etc/cockpit-secrets/safes/lab-dc.kdbx" }
            }));
            await page.click(await safeAction(page, "lab-dc", "Forget…"));
            await page.waitForSelector(".sec-modal");
            const t = await page.textContent(".sec-modal");
            ok(/file stays on disk/i.test(t),
               "Forget says plainly that the file stays on disk");
            ok(/registering it again/i.test(t) || /Add an existing safe/.test(t),
               "and that it can be registered again");
            const run = await page.$('.sec-modal button:text-is("Remove the registry entry")');
            ok(await run.isDisabled(), "Run is disabled until the sentence is ticked");
            await page.click(".sec-modal .sec-alert.warn input[type=checkbox]");
            ok(!(await run.isDisabled()), "and enabled once it is");
            await run.click();
            await page.waitForSelector("#sec-alerts .sec-alert.ok", { timeout: 10000 });
            const body = await page.evaluate(() => {
                const i = window.__CALLS.findIndex((c) => c.verb === "safe-forget");
                return window.__BODIES[i];
            });
            ok(body && body.safe === "lab-dc" && Object.keys(body).length === 1,
               `forget sends the registry id and nothing else (${JSON.stringify(body)})`);
            await page.close();
        }
        {
            const page = await bootToSafes(browser, regScen({
                "safe-delete": { ok: true, id: "lab-dc", backups_removed: 3 }
            }));
            await page.click(await safeAction(page, "lab-dc", "Delete…"));
            await page.waitForSelector(".sec-modal");
            const t = await page.textContent(".sec-modal");
            ok(/backup ring/i.test(t),
               "Delete states that the file AND its backup ring are destroyed");
            ok(/best effort|BEST EFFORT/i.test(t) && /wear levelling|snapshot/i.test(t),
               "and says honestly that shredding is best-effort on modern storage");
            ok(/use Forget instead/i.test(t),
               "and points at Forget as the non-destructive option");
            const run = await page.$('.sec-modal button:text-is("Destroy this safe and its backups")');
            ok(await run.isDisabled(), "Run starts disabled");
            /* The helper's own confirm sentence and this page's are AND-ed,
             * never replaced: a page-side warning must not be able to swallow
             * the one the helper attached. */
            const ticks = await page.$$(".sec-modal .sec-alert.warn input[type=checkbox]");
            ok(ticks.length === 2 &&
               /every backup of it/.test(t) && /cannot be undone/.test(t),
               `both the helper's confirm and the page's are shown and must both be ticked ` +
               `(${ticks.length} boxes)`);
            for (const c of ticks) await c.click();
            ok(await run.isDisabled(),
               "ticking every sentence is NOT enough — the id must be typed too");
            await page.fill(".sec-modal .sec-field input[type=text]", "lab-d");
            ok(await run.isDisabled(), "a partly-typed id does not open the gate");
            await page.fill(".sec-modal .sec-field input[type=text]", "mine");
            ok(await run.isDisabled(), "and neither does ANOTHER safe's id");
            await page.fill(".sec-modal .sec-field input[type=text]", "LAB-DC");
            ok(await run.isDisabled(), "and neither does the id in the wrong case");
            await page.fill(".sec-modal .sec-field input[type=text]", "lab-dc");
            ok(!(await run.isDisabled()), "the exact id, with every tick, opens it");
            await run.click();
            await page.waitForSelector("#sec-alerts .sec-alert.ok", { timeout: 10000 });
            const body = await page.evaluate(() => {
                const i = window.__CALLS.findIndex((c) => c.verb === "safe-delete");
                return window.__BODIES[i];
            });
            ok(body && body.safe === "lab-dc" &&
               body.delete_confirm === "delete-safe:lab-dc",
               `delete sends the id and a confirm token naming it, never a path (${JSON.stringify(body)})`);
            ok(Object.keys(body).every((k) =>
                   !/^(path|dir|dest|destination|filename|file)$/.test(k)),
               "and no path-shaped key (I4, C8)");
            await page.close();
        }

        /* ---- the wizard at 200% zoom, and its focus trap ---------------- */
        {
            const page = await openPage(browser, regScen({
                "import-begin": { ok: true, staging: "stg-8", chunk_bytes: 4096 },
                "import-chunk": { ok: true },
                "import-inspect": INSPECT,
                "import-abort": { ok: true }
            }));
            await page.setViewportSize({ width: 640, height: 720 });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe");
            await page.click('#sec-safes .sec-tools button:text-is("Add an existing safe…")');
            await page.waitForSelector(".sec-modal .sec-steps");
            const over = await page.evaluate(() =>
                document.documentElement.scrollWidth - document.documentElement.clientWidth);
            ok(over <= 1, `the upload wizard does not overflow sideways at 640px (${over}px)`);
            for (let i = 0; i < 30; i++) await page.keyboard.press("Tab");
            ok(await page.evaluate(() => !!document.activeElement.closest(".sec-modal")),
               "the focus trap holds inside the upload wizard");
            await page.close();
        }

        /* ================================================ console clean == */
        head("No page errors anywhere in the walkthrough");
        {
            const page = await bootToSafes(browser, scen());
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            const walkErr = realErrors(page);
            ok(walkErr.length === 0,
               "no uncaught page error or console error" +
               (walkErr.length ? ": " + walkErr.join(" | ") : ""));
            /* And say out loud what was discounted, so a font 404 can never
             * quietly become a licence to ignore a real one. */
            ok((page.__notFound || []).every((u) => /\/static\/fonts\//.test(u)),
               `the only 404s in the run are Cockpit's own font files, which this ` +
               `harness does not serve (${(page.__notFound || []).length})`);
            await page.close();
        }

        /* ================================================================ *
         * THE RESTYLE — R1..R5, the theme mirror, the layout, the palette.
         *
         * Everything below is new. None of it replaces an existing check.
         * ================================================================ */

        head("R2 — the safe list is a real, sortable table");
        {
            const page = await bootToSafes(browser, scen());
            const shape = await page.$eval("#sec-safes table.sec", (t) => ({
                thead: !!t.tHead,
                caption: !!t.caption,
                ths: Array.prototype.map.call(t.tHead.rows[0].cells, (c) => ({
                    tag: c.tagName, scope: c.getAttribute("scope"),
                    sort: c.getAttribute("aria-sort"),
                    button: !!c.querySelector("button"),
                    text: c.textContent.trim()
                })),
                rows: t.tBodies[0].rows.length
            }));
            ok(shape.thead && shape.caption, "it is a real <table> with a <thead> and a <caption>");
            ok(shape.ths.length >= 4 && shape.ths.every((h) => h.tag === "TH" && h.scope === "col"),
               `every header is a <th scope="col"> (${shape.ths.length} of them)`);
            ok(shape.ths.every((h) => h.button),
               "and every sortable header carries a real <button>, not a click handler on the cell");
            ok(shape.ths.filter((h) => h.sort !== "none").length === 1,
               "exactly one column reports aria-sort at a time");
            ok(/Class/.test(shape.ths[1].text) && shape.ths[1].sort !== "none",
               `the default sort is Class — administrator first, because admin is the ` +
               `DEFAULT access class (${shape.ths[1].sort})`);
            const order = await page.$$eval("#sec-safes tbody .sec-safe-id",
                (ns) => ns.map((n) => n.textContent));
            ok(order[0] === "lab-dc" && order[1] === "mine",
               `administrator safes sort first (${order.join(", ")})`);

            /* Clicking a header really re-sorts, and says so in aria-sort. */
            await page.click('#sec-safes th button:has-text("Safe")');
            const afterSort = await page.$$eval("#sec-safes tbody .sec-safe-id",
                (ns) => ns.map((n) => n.textContent));
            ok(afterSort[0] === "lab-dc" && afterSort[1] === "mine",
               `sorting by Safe orders by label — "AD Lab…" before "My own safe" ` +
               `(${afterSort.join(", ")})`);
            const sortState = await page.$$eval("#sec-safes th",
                (ns) => ns.map((n) => n.getAttribute("aria-sort")));
            ok(sortState[0] === "ascending" && sortState.filter((v) => v !== "none").length === 1,
               `aria-sort moved with the click (${sortState.join(", ")})`);
            await page.click('#sec-safes th button:has-text("Safe")');
            const flipped = await page.$$eval("#sec-safes tbody .sec-safe-id",
                (ns) => ns.map((n) => n.textContent));
            ok(flipped[0] === "mine", `re-clicking reverses it (${flipped.join(", ")})`);

            /* The row's door is a real button, and the arrow keys move between
             * them without changing the tab count. */
            await page.focus("#sec-safes tbody tr:nth-child(1) button.sec-rowdoor");
            await page.keyboard.press("ArrowDown");
            const onSecond = await page.evaluate(() => {
                const rows = document.querySelectorAll("#sec-safes tbody tr");
                return rows[1].contains(document.activeElement);
            });
            ok(onSecond, "ArrowDown moves focus to the next row's door");
            await page.keyboard.press("Home");
            ok(await page.evaluate(() => {
                const rows = document.querySelectorAll("#sec-safes tbody tr");
                return rows[0].contains(document.activeElement);
            }), "Home jumps to the first");
            await page.keyboard.press("Enter");
            await page.waitForSelector("#sec-pane .sec-safe-id", { timeout: 5000 });
            const selected = await page.$eval("#sec-safes tbody tr.selected", (n) => ({
                aria: n.querySelector(".sec-rowdoor").getAttribute("aria-current"),
                bg: window.getComputedStyle(n.cells[0]).backgroundColor,
                bar: window.getComputedStyle(n.cells[0]).boxShadow
            }));
            ok(selected.aria === "true", "Enter selects the row, and the row says aria-current");
            ok(selected.bar !== "none" && /inset/.test(selected.bar),
               `the selected row carries an inset marker bar as well as a tint — selection ` +
               `never rests on colour alone (${selected.bar})`);
            ok((await page.$$("#sec-safes tbody tr.selected")).length === 1,
               "exactly one row is selected at a time");
            /* NO ACTION LIVES IN A ROW. */
            const rowButtons = await page.$$eval("#sec-safes tbody button",
                (ns) => ns.map((n) => n.textContent.trim()));
            ok(!rowButtons.some((t) => /Unlock|Delete|Forget|Export|Backups/.test(t)),
               `no row carries an action — a row is a thing you select, not a thing you do ` +
               `something to (${rowButtons.join(" | ")})`);
            await page.close();
        }

        head("R3/R4 — the docked details pane and its toggle");
        {
            const page = await bootToSafes(browser, scen());
            const tog = await page.$eval("#sec-pane-toggle", (n) => ({
                tag: n.tagName, type: n.type,
                expanded: n.getAttribute("aria-expanded"),
                controls: n.getAttribute("aria-controls"),
                name: n.getAttribute("aria-label"),
                svg: !!n.querySelector("svg")
            }));
            ok(tog.tag === "BUTTON" && tog.type === "button",
               "the toggle is a real <button>");
            ok(tog.controls === "sec-pane" && !!tog.name,
               `it names what it controls and has an accessible name ("${tog.name}")`);
            ok(tog.svg, "its glyph is an inline <svg> built with createElementNS — no icon font, " +
                        "no sprite sheet, nothing that could become a CSP question");

            ok(await page.$eval("#sec-pane", (n) => !n.hidden),
               "the pane is open by default on a frame at or above 60rem");
            ok((await page.textContent("#sec-pane-h")).trim() === "No safe selected",
               "and its resting state names itself rather than sitting blank");

            await page.click("#sec-pane-toggle");
            ok(await page.$eval("#sec-pane-toggle", (n) => n.getAttribute("aria-expanded")) === "false" &&
               await page.$eval("#sec-pane", (n) => n.hidden),
               "the toggle collapses it, and aria-expanded follows");
            ok(await page.$eval("#sec-workspace",
                                (n) => !n.classList.contains("sec-pane-open")),
               "the grid gives the width back rather than leaving a sliver");
            ok(await page.evaluate(() => document.activeElement.id === "sec-pane-toggle"),
               "focus comes back to the toggle when the pane closes under it");
            await page.click("#sec-pane-toggle");
            ok(await page.$eval("#sec-pane-toggle", (n) => n.getAttribute("aria-expanded")) === "true" &&
               await page.$eval("#sec-pane", (n) => !n.hidden),
               "and expands it again");
            ok(await page.evaluate(() => document.activeElement.id === "sec-pane-h"),
               "opening it puts focus on the pane heading — the operator asked for the pane");

            /* R3: clicking a row opens the pane ON THAT SAFE. */
            await page.click('.sec-safe:has(.sec-safe-id:text-is("mine")) button.sec-rowdoor');
            await page.waitForSelector('#sec-pane .sec-safe-id:text-is("mine")');
            ok(await page.evaluate(() =>
                   !!document.activeElement.closest("#sec-safes tbody tr")),
               "selecting a row leaves focus in the table — the intent was to choose a safe, " +
               "and yanking focus out of it breaks arrow-key scanning");
            ok((await page.textContent("#sec-pane-h")).trim() === "My own safe",
               "the pane heading is the safe's label");

            /* Escape inside the pane collapses it. Safe only because the pane
             * contains no free-text entry — every mutation goes through a
             * modal — and that invariant is asserted here so breaking it
             * breaks a test. */
            const typables = await page.$$eval("#sec-pane input, #sec-pane textarea",
                (ns) => ns.map((n) => n.type || n.tagName));
            ok(typables.length === 0,
               `the pane contains no free-text entry, which is what makes Escape harmless ` +
               `(${typables.join(", ") || "none"})`);
            await page.focus("#sec-pane-h");
            await page.keyboard.press("Escape");
            ok(await page.$eval("#sec-pane", (n) => n.hidden) &&
               await page.evaluate(() => document.activeElement.id === "sec-pane-toggle"),
               "Escape inside the pane collapses it and returns focus to the toggle");

            /* Selecting a row while the pane is collapsed opens it: a detail
             * request that shows nothing is a bug. */
            await page.click('.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button.sec-rowdoor');
            ok(await page.$eval("#sec-pane", (n) => !n.hidden),
               "selecting a row while the pane is collapsed opens it");
            await page.close();
        }

        head("R5 — the Path column is selectable, off by default, always in the pane");
        {
            const s = scen();
            s.responses.list = { registry_errors: 0, safes: baseSafes().map((x, i) =>
                Object.assign({}, x, {
                    path: i === 0 ? "/etc/cockpit-secrets/safes/lab-dc.kdbx"
                                  : "/home/tester/.local/share/cockpit-secrets/mine.psafe3",
                    registry: i === 0 ? "system" : "user" })) };
            const page = await bootToSafes(browser, s);

            const heads = () => page.$$eval("#sec-safes th", (ns) =>
                ns.map((n) => n.textContent.trim().replace(/[▲▼]/g, "").trim()));
            ok(!(await heads()).includes("Path"),
               "Path is NOT a column by default");
            const listedText = await page.textContent("#sec-safes");
            ok(!/\/home\/tester/.test(listedText),
               "and no home directory — and therefore no account name — is on screen by default");

            /* The chooser is a general one, not a one-off checkbox for Path. */
            const boxes = await page.$$eval(".sec-columns input[type=checkbox]",
                (ns) => ns.map((n) => n.name));
            ok(boxes.length >= 3 && boxes.includes("col-path") && boxes.includes("col-registry"),
               `the chooser offers every optional column, not just Path (${boxes.join(", ")})`);
            ok(await page.$eval(".sec-columns", (n) => n.tagName === "DETAILS"),
               "it is a <details>, so its open state, its keyboard behaviour and its " +
               "accessibility contract are the element's and not this page's");

            await page.click(".sec-columns summary");        /* it is a disclosure */
            await page.check('.sec-columns input[name="col-path"]');
            await page.waitForSelector("#sec-safes th:has-text('Path')");
            ok((await heads()).includes("Path"), "ticking the box adds the column immediately, " +
                                                 "with no Apply step");
            ok(/\/etc\/cockpit-secrets\/safes\/lab-dc\.kdbx/
                   .test(await page.textContent("#sec-safes tbody")),
               "and the path is shown in full, never truncated");
            ok(/1 extra/.test(await page.textContent(".sec-columns summary")),
               "the summary says the selection is non-default without being opened");
            ok((await heads()).indexOf("Path") === 4,
               `the optional columns keep a FIXED order after the four defaults — a table ` +
               `whose columns move under you is one you re-read every time`);

            /* R5's other half: the path is in the pane ALWAYS, whether or not
             * the column is on. */
            await page.uncheck('.sec-columns input[name="col-path"]');
            await openSafe(page, "mine");
            ok(/\/home\/tester\/\.local\/share\/cockpit-secrets\/mine\.psafe3/
                   .test(await page.textContent("#sec-pane .sec-path")),
               "with the column off, the pane still shows the path in full");
            ok((await page.$$('#sec-pane button:text-is("Copy path")')).length === 1,
               "and offers to copy it");
            /* A path is not a secret, so copying it must NOT arm the clipboard
             * countdown. A chip that cries wolf teaches an operator to ignore
             * the one that matters. */
            await page.click('#sec-pane button:text-is("Copy path")');
            await page.waitForTimeout(200);
            ok(await page.$eval("#sec-clip", (n) => n.hidden),
               "copying a path does not arm the clipboard countdown — it is not a secret");

            /* And the reverse, so the chip still means something. */
            await unlockFirst(page, "mine");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            const copyBtn = await page.$('#sec-detail .sec-reveal button:text-is("Copy")');
            if (copyBtn) {
                await copyBtn.click();
                await page.waitForFunction(
                    () => !document.getElementById("sec-clip").hidden,
                    null, { timeout: 5000 })
                    .then(() => ok(true, "copying a REVEALED VALUE does arm it"))
                    .catch(() => ok(false, "copying a REVEALED VALUE does arm it"));
            } else {
                ok(false, "a reveal widget with a Copy control was drawn");
            }
            await page.close();
        }

        head("R1 — administrator safes are listed only while access is on");
        {
            /* State A: some visible, some hidden. */
            const s = scen();
            s.admin = false;
            s.responses.list = { registry_errors: 0, safes: baseSafes().map((x, i) =>
                Object.assign({}, x, { path: i === 0 ? "/etc/cockpit-secrets/safes/lab-dc.kdbx"
                                                     : "/home/tester/mine.psafe3" })) };
            /* The probe answers psafe3 here on purpose: the VISIBLE safe's own
             * format must not be the string the leak check is looking for, or
             * the check would pass or fail for the wrong reason. "kdbx" now
             * belongs to the hidden safe alone. */
            s.responses.probe = { format: "psafe3", version: "3.30", kdf: "sha256",
                                  iterations: 262144, needs_password: true,
                                  needs_keyfile: false, writable: true, warnings: [] };
            const page = await bootToSafes(browser, s);
            const ids = await page.$$eval("#sec-safes tbody .sec-safe-id",
                (ns) => ns.map((n) => n.textContent));
            ok(ids.length === 1 && ids[0] === "mine",
               `the user-class safe is listed and the administrator one is not (${ids.join(", ")})`);
            const note = await page.textContent(".sec-hidden-note");
            ok(/1 administrator safe is hidden/.test(note),
               `the count is stated, in the singular (${note})`);
            /* THE ASSERTION THAT MATTERS MOST. */
            const visible = await page.textContent("#sec-safes");
            ok(!/lab-dc/.test(visible) && !/AD Lab/.test(visible) &&
               !/kdbx/.test(visible) && !/etc\/cockpit-secrets/.test(visible),
               "and the note leaks no id, no label, no format and no path");
            ok((await page.$$(".sec-hidden-note.sec-alert, .sec-hidden-note.warn")).length === 0,
               "it is not styled as an alert: a warning-coloured box on every load of an " +
               "unelevated session is how a page teaches people to ignore its warnings");
            await page.close();
        }
        {
            /* State B against State C: they must differ in three ways at once. */
            const sB = scen();
            sB.admin = false;
            sB.responses.list = { safes: [baseSafes()[0]], registry_errors: 0 };
            const b = await bootToSafes(browser, sB);
            const stateB = await b.$eval("#sec-safes .sec-state", (n) => ({
                heading: n.querySelector("h3").textContent,
                glyph: n.querySelector("svg") ? n.querySelector("svg").innerHTML.slice(0, 40) : "",
                buttons: n.querySelectorAll("button").length
            }));
            await b.close();

            const c = await openPage(browser, regScen({ list: { safes: [] } }));
            await c.goto(url);
            await c.waitForSelector("#sec-safes .sec-state", { timeout: 10000 });
            const stateC = await c.$eval("#sec-safes .sec-state", (n) => ({
                heading: n.querySelector("h3").textContent,
                glyph: n.querySelector("svg") ? n.querySelector("svg").innerHTML.slice(0, 40) : "",
                buttons: n.querySelectorAll("button").length
            }));
            await c.close();

            ok(stateB.heading !== stateC.heading,
               `"you cannot see them" and "there are none" have different headings ` +
               `("${stateB.heading}" vs "${stateC.heading}")`);
            ok(stateB.glyph !== stateC.glyph && stateB.glyph && stateC.glyph,
               "…and different glyphs");
            ok(stateB.buttons === 0 && stateC.buttons > 0,
               `…and only the empty registry offers buttons, because no page control can ` +
               `escalate (${stateB.buttons} vs ${stateC.buttons})`);
            ok(/Nothing is visible while access is limited/.test(stateB.heading),
               "State B says what it is");
            ok(/presentation only/.test(
                   await (async () => {
                       const p2 = await bootToSafes(browser, (() => {
                           const x = scen(); x.admin = false;
                           x.responses.list = { safes: [baseSafes()[0]], registry_errors: 0 };
                           return x;
                       })());
                       const t = await p2.textContent("#sec-safes");
                       await p2.close();
                       return t;
                   })()),
               "and it says plainly that hiding is presentation only — the helper is what " +
               "refuses, whether or not this page drew a row");
        }

        head("The theme follows Cockpit's own resolved choice, not the OS");
        {
            /* Standalone — no shell to read — falls back to the media query,
             * which is the branch a plugin opened outside Cockpit takes. */
            const page = await openPage(browser, scen());
            await page.emulateMedia({ colorScheme: "dark" });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
            const dark = await page.evaluate(() => ({
                cls: document.documentElement.className,
                canvas: getComputedStyle(document.documentElement)
                    .getPropertyValue("--sec-canvas").trim()
            }));
            ok(/\bsec-dark\b/.test(dark.cls) && /\bsec-theme-managed\b/.test(dark.cls),
               `standalone with the OS in dark: the fallback branch runs and marks itself ` +
               `resolved (${dark.cls})`);
            ok(dark.canvas.toLowerCase() === "#151515",
               `and the dark canvas token resolves (${dark.canvas})`);
            await page.emulateMedia({ colorScheme: "light" });
            await page.reload();
            await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
            const light = await page.evaluate(() => ({
                cls: document.documentElement.className,
                canvas: getComputedStyle(document.documentElement)
                    .getPropertyValue("--sec-canvas").trim()
            }));
            ok(/\bsec-light\b/.test(light.cls) && light.canvas.toLowerCase() === "#f2f2f2",
               `…and light in light (${light.cls} / ${light.canvas})`);
            await page.close();
        }
        {
            /* THE DEFECT STATES. A same-origin parent whose <html> carries
             * PatternFly's dark class, with the OS in LIGHT — which is exactly
             * the combination that used to render a white panel inside a black
             * Cockpit — and then the reverse. */
            const page = await openPage(browser, scen());
            await page.emulateMedia({ colorScheme: "light" });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
            const read = await page.evaluate(async (src) => {
                document.documentElement.className = "index-page pf-v6-theme-dark";
                const f = document.createElement("iframe");
                f.src = src;
                f.width = "900"; f.height = "600";
                document.body.appendChild(f);
                await new Promise((r) => f.addEventListener("load", r));
                const inner = f.contentDocument.documentElement;
                const before = {
                    cls: inner.className,
                    canvas: f.contentWindow.getComputedStyle(inner)
                        .getPropertyValue("--sec-canvas").trim()
                };
                /* Now flip the parent the other way and let the observer run. */
                document.documentElement.className = "index-page";
                await new Promise((r) => setTimeout(r, 200));
                const after = {
                    cls: inner.className,
                    canvas: f.contentWindow.getComputedStyle(inner)
                        .getPropertyValue("--sec-canvas").trim()
                };
                return { before, after };
            }, url);
            ok(/\bsec-dark\b/.test(read.before.cls) &&
               read.before.canvas.toLowerCase() === "#151515",
               `shell Dark with the OS in LIGHT: the frame resolves dark from the parent's ` +
               `own class, which prefers-color-scheme alone can never do ` +
               `(${read.before.cls} / ${read.before.canvas})`);
            ok(/\bsec-light\b/.test(read.after.cls) &&
               read.after.canvas.toLowerCase() === "#f2f2f2",
               `…and the MutationObserver follows the shell back to light without a reload ` +
               `(${read.after.cls} / ${read.after.canvas})`);
            /* THE CANARY. If PatternFly ever renames this class, THIS is the
             * assertion that fails, loudly and early, rather than a page that
             * quietly stops following the theme. */
            ok(/pf-(v\d+-)?theme-dark/.test("pf-v6-theme-dark"),
               "the class this page matches is PatternFly's `pf-v6-theme-dark` family — " +
               "if Cockpit renames it, the two assertions above are what say so");
            await page.close();
        }

        head("Layout — the breakpoint is the FRAME, and it is reachable");
        {
            /* 1160px is what Cockpit's iframe measures inside a 1400px window;
             * the old 75rem breakpoint could effectively never be met, which is
             * why the third pane never appeared. */
            const page = await openPage(browser, scen());
            await page.setViewportSize({ width: 1160, height: 900 });
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
            const grid = await page.$eval("#sec-workspace", (n) =>
                window.getComputedStyle(n).gridTemplateColumns.split(" ").map(parseFloat));
            ok(grid.length === 2,
               `at the real frame width the workspace is TWO columns — this is the assertion ` +
               `that would have caught the three-pane defect and did not exist ` +
               `(${grid.join(" | ")})`);
            ok(grid[1] >= 24 * 16 - 1,
               `and the pane is at least 24rem wide (${grid[1]}px)`);
            ok((await page.evaluate(() =>
                   document.documentElement.scrollWidth -
                   document.documentElement.clientWidth)) <= 1,
               "with no horizontal overflow");
            await page.close();
        }
        {
            /* 700x480 is the WCAG-correct way to emulate 200% zoom. */
            for (const [w, h] of [[700, 480], [480, 800], [360, 800]]) {
                const page = await openPage(browser, scen());
                await page.setViewportSize({ width: w, height: h });
                await page.goto(url);
                await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
                const over = await page.evaluate(() =>
                    document.documentElement.scrollWidth - document.documentElement.clientWidth);
                ok(over <= 1, `no horizontal overflow at ${w}x${h} (${over}px)`);
                const cols = await page.$eval("#sec-workspace", (n) =>
                    window.getComputedStyle(n).gridTemplateColumns.split(" ").length);
                ok(cols === 1, `the pane un-docks below 60rem (${cols} column at ${w}px)`);
                const wide = await page.evaluate(() => {
                    const lim = document.documentElement.clientWidth + 1;
                    /* A table that is wider than its column is CORRECT, as long
                     * as it is inside its own overflow-x box: that is the whole
                     * point of .sec-scroll, and it is what stops a long id or
                     * path from pushing the PAGE sideways. So the elements that
                     * live inside such a box are excluded here, and the
                     * page-level assertion above is what actually guards 1.4.10. */
                    const scrolls = (n) => {
                        for (let p = n.parentElement; p; p = p.parentElement)
                            if (window.getComputedStyle(p).overflowX === "auto") return true;
                        return false;
                    };
                    return Array.prototype.filter.call(document.querySelectorAll("body *"),
                        (n) => n.getBoundingClientRect().right > lim && !scrolls(n)).length;
                });
                ok(wide === 0, `nothing outside a scroll box sticks out past the frame ` +
                               `at ${w}px (${wide})`);
                /* The pane still follows #sec-main in the DOM, so the reading
                 * order and the tab order are the same thing at every width. */
                ok(await page.evaluate(() =>
                       !!(document.getElementById("sec-main").compareDocumentPosition(
                            document.getElementById("sec-pane")) & Node.DOCUMENT_POSITION_FOLLOWING)),
                   `and the pane is still after the table in the DOM at ${w}px`);
                await page.close();
            }
        }

        head("Focus, tap targets and the file control");
        {
            const page = await bootToSafes(browser, scen());
            /* Start at the very top of the document: clicking a non-focusable
             * heading leaves focus on <body>, so the first Tab lands on the
             * first tabbable thing on the page — which is the skip link. */
            await page.click(".sec-topbar h1");
            const rings = [];
            for (let i = 0; i < 10; i++) {
                await page.keyboard.press("Tab");
                rings.push(await page.evaluate(() => {
                    const a = document.activeElement;
                    if (!a || a === document.body) return null;
                    const cs = window.getComputedStyle(a);
                    return { tag: a.tagName, vis: a.matches(":focus-visible"),
                             w: cs.outlineWidth, style: cs.outlineStyle };
                }));
            }
            const real = rings.filter(Boolean);
            ok(real.length >= 8, `ten tabs land on ${real.length} real controls`);
            ok(real.every((r) => r.vis), "every one of them reports :focus-visible");
            ok(real.every((r) => r.w === "2px" && r.style === "solid"),
               `and every one gets the same 2px solid ring — 0.125rem IS 2px, where the old ` +
               `0.15rem was 2px only after Chromium rounded it ` +
               `(${Array.from(new Set(real.map((r) => r.w))).join(", ")})`);

            /* WCAG 2.5.8: 24x24 CSS px. The smallest control in the whole
             * product used to be the unlock dialog's 23.9px "Show", and it sat
             * in the one dialog that has to be usable while typing blind. */
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
            await page.waitForSelector(".sec-modal input[type=password]");
            const small = await page.$$eval(".sec-modal button, .sec-modal input",
                (ns) => ns.map((n) => {
                    const r = n.getBoundingClientRect();
                    return { what: (n.tagName + " " + (n.type || "") + " " +
                                    n.textContent).trim().slice(0, 30),
                             w: Math.round(r.width * 10) / 10,
                             h: Math.round(r.height * 10) / 10 };
                }).filter((x) => x.w > 0 && (x.w < 24 || x.h < 24)));
            ok(small.length === 0,
               `every control in the unlock dialog clears WCAG 2.5.8's 24x24` +
               (small.length ? ": " + small.map((x) => `${x.what} ${x.w}x${x.h}`).join("; ") : ""));
            await page.close();
        }
        {
            /* THE NATIVE FILE CONTROL is the one thing CSS might not be able to
             * lift: it rendered at 21px, which fails WCAG 2.5.8, and whether
             * `min-block-size` moves it is an engine question and not a
             * stylesheet one. So it is MEASURED, in the dialog that actually
             * draws one — an unlock that needs a key file — and the number is
             * printed either way. If this ever fails, the specified fallback is
             * a visually-hidden <input type=file> plus a real <button> that
             * forwards .click(), and this assertion is what says so. */
            const s = scen();
            s.responses.probe = Object.assign({}, s.responses.probe,
                { needs_keyfile: true });
            s.responses.list = { registry_errors: 0,
                safes: baseSafes().map((x) => Object.assign({}, x, { needs_keyfile: true })) };
            const page = await bootToSafes(browser, s);
            await page.click(await safeAction(page, "lab-dc", "Unlock…"));
            await page.waitForSelector(".sec-modal input[type=file]", { timeout: 10000 });
            const files = await page.$$eval(".sec-modal input[type=file]",
                (ns) => ns.map((n) => Math.round(n.getBoundingClientRect().height * 10) / 10));
            ok(files.length > 0 && files.every((h) => h >= 24),
               `the native file control accepts min-block-size and now renders ` +
               `${files.join(", ")}px — it was 21px, which failed WCAG 2.5.8`);
            await page.close();
        }

        head("The palette — computed, not eyeballed");
        {
            /* WCAG 2.x relative luminance, over the tokens as the browser
             * actually resolves them, in BOTH themes. Zero failures at 4.5:1
             * for text and 3:1 for non-text is the threshold and it does not
             * move. Properties are read BY NAME with getPropertyValue and never
             * by iterating getComputedStyle: Chromium enumerates custom
             * properties and Firefox historically does not, so an enumerating
             * check would pass here and fail there for no real reason. */
            const TEXT = [
                ["ink", "canvas"], ["ink", "surface"], ["ink", "raised"], ["ink", "inset"],
                ["ink", "hover"], ["ink", "sel"],
                ["sub", "canvas"], ["sub", "surface"], ["sub", "inset"], ["sub", "raised"],
                ["link", "canvas"], ["link", "surface"], ["link", "raised"],
                ["accent-ink", "accent"],
                ["ok", "surface"], ["ok", "ok-bg"],
                ["warn", "surface"], ["warn", "warn-bg"],
                ["danger", "surface"], ["danger", "danger-bg"],
                ["info", "surface"], ["info", "info-bg"]
            ];
            const NONTEXT = [
                ["edge", "surface"], ["edge", "canvas"], ["edge", "inset"], ["edge", "raised"],
                ["focus", "canvas"], ["focus", "surface"], ["focus", "raised"],
                ["accent", "surface"], ["accent", "sel"],
                ["ok-edge", "ok-bg"], ["warn-edge", "warn-bg"], ["danger-edge", "danger-bg"]
            ];
            const page = await openPage(browser, scen());
            await page.goto(url);
            await page.waitForSelector("#sec-safes .sec-safe", { timeout: 10000 });
            const report = await page.evaluate(({ TEXT, NONTEXT }) => {
                function lum(hex) {
                    const m = hex.trim().replace("#", "");
                    const n = m.length === 3
                        ? m.split("").map((c) => parseInt(c + c, 16))
                        : [0, 2, 4].map((i) => parseInt(m.slice(i, i + 2), 16));
                    const a = n.map((v) => {
                        const c = v / 255;
                        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
                    });
                    return 0.2126 * a[0] + 0.7152 * a[1] + 0.0722 * a[2];
                }
                function ratio(a, b) {
                    const x = lum(a), y = lum(b);
                    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
                }
                const out = {};
                for (const theme of ["light", "dark"]) {
                    document.documentElement.classList.toggle("sec-dark", theme === "dark");
                    document.documentElement.classList.toggle("sec-light", theme !== "dark");
                    const cs = getComputedStyle(document.documentElement);
                    const tok = (n) => cs.getPropertyValue("--sec-" + n).trim();
                    const bad = [];
                    const rows = [];
                    for (const [fg, bg] of TEXT) {
                        const r = ratio(tok(fg), tok(bg));
                        rows.push([fg, bg, Math.round(r * 100) / 100]);
                        if (r < 4.5) bad.push(`${fg} on ${bg} = ${r.toFixed(2)} (text, needs 4.5)`);
                    }
                    for (const [fg, bg] of NONTEXT) {
                        const r = ratio(tok(fg), tok(bg));
                        rows.push([fg, bg, Math.round(r * 100) / 100]);
                        if (r < 3) bad.push(`${fg} on ${bg} = ${r.toFixed(2)} (non-text, needs 3)`);
                    }
                    out[theme] = { bad, rows, count: rows.length };
                }
                return out;
            }, { TEXT, NONTEXT });
            for (const theme of ["light", "dark"])
                ok(report[theme].bad.length === 0,
                   `${theme}: all ${report[theme].count} token pairs clear AA (4.5:1 text, ` +
                   `3:1 non-text)` +
                   (report[theme].bad.length ? " — " + report[theme].bad.join("; ") : ""));
            /* The one that was systemically broken before: --sec-border against
             * --sec-bg was 1.51 light / 1.60 dark, i.e. EVERY control boundary
             * on the page. */
            const edgeLight = report.light.rows.find((r) => r[0] === "edge" && r[1] === "surface");
            const edgeDark = report.dark.rows.find((r) => r[0] === "edge" && r[1] === "surface");
            ok(edgeLight[2] >= 3 && edgeDark[2] >= 3,
               `the control edge clears 1.4.11 in both themes (${edgeLight[2]} / ${edgeDark[2]}) ` +
               `— it was 1.51 / 1.60, which was every control boundary on the page`);
            await page.close();
        }

        head("Type — the page is no longer smaller than its host");
        {
            const page = await bootToSafes(browser, scen());
            const sizes = await page.evaluate(() => {
                const out = {};
                const walk = (n) => {
                    if (n.nodeType === 3 && n.textContent.trim()) {
                        const px = window.getComputedStyle(n.parentElement).fontSize;
                        out[px] = (out[px] || 0) + 1;
                    }
                    for (const k of n.childNodes) walk(k);
                };
                walk(document.querySelector(".sec-page"));
                return out;
            });
            const runs = Object.entries(sizes).map(([px, n]) => [parseFloat(px), n]);
            const total = runs.reduce((a, b) => a + b[1], 0);
            const tiny = runs.filter(([px]) => px < 12).reduce((a, b) => a + b[1], 0);
            const belowBody = runs.filter(([px]) => px < 14).reduce((a, b) => a + b[1], 0);
            ok(tiny === 0,
               `nothing renders below the 12px floor (${runs.map(([p, n]) => p + "x" + n)
                   .sort().join(" ")})`);
            ok(belowBody / total < 0.35,
               `and most text is at or above Cockpit's own 14px body default ` +
               `(${belowBody} of ${total} runs below it; it used to be 53 of 88)`);
            ok(!runs.some(([px]) => px > 12.5 && px < 14),
               "and there is no ad-hoc size between the 12px floor and the 14px body — the " +
               "old 0.82rem/13.12px, which was the single most common size on the page, is gone");
            const weights = await page.$$eval(".sec-page *", (ns) => Array.from(new Set(
                ns.map((n) => window.getComputedStyle(n).fontWeight))));
            ok(!weights.includes("700") && !weights.includes("bold"),
               `nothing asks for weight 700 — PatternFly's body bold is 500 and the variable ` +
               `face Cockpit ships declares 400..500, so 700 is a synthesised faux bold ` +
               `(${weights.join(", ")})`);
            await page.close();
        }

        head("The consequence ladder and the deadline treatment");
        {
            const page = await bootToSafes(browser, scen());
            await unlockFirst(page, "lab-dc");
            await page.click("#sec-entries .sec-btn.link");
            await page.waitForSelector("#sec-detail h3");
            /* R3 (c): the pane became the entry detail, and the way back to the
             * safe's own registry detail is one control, not a re-navigation. */
            ok((await page.$$("#sec-pane #sec-detail")).length === 1,
               "with a safe open the pane IS the entry detail");
            ok(await page.$eval("#sec-pane-back", (n) => !n.hidden),
               "and “← Safe details” is offered, so the registry entry is one click away");
            await page.click("#sec-pane-back");
            /* `.sec-safe-id` in the pane is only rendered by the safe-detail
             * content, so its appearance IS the swap. (`.sec-path` would be a
             * better landmark but this scenario's registry rows carry no path,
             * and the pane correctly draws no Path section without one.) */
            await page.waitForSelector("#sec-pane .sec-safe-id");
            ok(/lab-dc/.test(await page.textContent("#sec-pane .sec-safe-id")),
               "which swaps the content back without leaving the browse view");
            ok((await page.$$("#sec-browse-view:not([hidden])")).length === 1,
               "…and without deselecting anything");

            /* The reveal countdown: one custom property on the track, tabular
             * numerals, and the bar is the SECOND carrier behind the numeral. */
            await page.click('#sec-entries .sec-btn.link');
            await page.waitForSelector("#sec-detail h3");
            const rev = await page.$('#sec-detail .sec-reveal button:text-is("Reveal")');
            if (rev) {
                await rev.click();
                await page.waitForSelector("#sec-detail .sec-value:not(.masked)", { timeout: 5000 });
                const meter = await page.$eval("#sec-detail .sec-meter", (n) => ({
                    remain: n.style.getPropertyValue("--sec-remain"),
                    inline: n.getAttribute("style") || "",
                    fill: window.getComputedStyle(n.firstElementChild).width
                }));
                ok(/%$/.test(meter.remain),
                   `the countdown's geometry arrives as ONE custom property, not a built ` +
                   `style string (${meter.remain})`);
                ok(parseFloat(meter.fill) > 0,
                   `and the stylesheet turns it into a width (${meter.fill})`);
                const cd = await page.$eval("#sec-detail .sec-countdown",
                    (n) => window.getComputedStyle(n).fontVariantNumeric);
                ok(/tabular-nums/.test(cd),
                   `the numerals are tabular, so a deadline does not jitter as it counts ` +
                   `(${cd})`);
                const wellSize = await page.$eval("#sec-detail .sec-value", (n) => ({
                    size: window.getComputedStyle(n).fontSize,
                    family: window.getComputedStyle(n).fontFamily,
                    border: window.getComputedStyle(n).borderTopWidth
                }));
                ok(parseFloat(wellSize.size) >= 16 && /Mono/.test(wellSize.family) &&
                   parseFloat(wellSize.border) > 0,
                   `a revealed value is bigger than body text, monospaced and in a bordered ` +
                   `well — the weight is in the RESULT, not in the button that asked for it ` +
                   `(${wellSize.size}, ${wellSize.family.split(",")[0]}, ${wellSize.border})`);
            } else {
                ok(false, "a reveal widget was drawn for the entry");
            }
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
