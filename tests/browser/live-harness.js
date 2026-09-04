/* tests/browser/live-harness.js — the driver for the LIVE Cockpit suite.
 *
 * The sibling harness.js fakes `cockpit.spawn` so the page can be driven with
 * no root, no bridge and no service. This one fakes NOTHING. It signs a real
 * account in to the real Cockpit on https://localhost:9090, lets Cockpit's own
 * shell load the installed package, and drives the page inside the shell's
 * iframe. Everything the stub suite writes down as "recorded but never
 * honoured" — the CSP the bridge actually sends, `superuser:"require"`, the
 * escalation dialog, the helper's real refusals — is exercised here for real.
 *
 * Three rules this file keeps, because the program it tests keeps them:
 *
 *  * NO SECRET ON ARGV OR IN THE ENVIRONMENT (I10). Passwords are read out of
 *    files in a credentials DIRECTORY; only the directory's path travels in the
 *    environment. `ps` on a running suite shows which host is being driven and
 *    nothing else. The same rule the helper is held to is not one this suite
 *    gets to break in order to check it.
 *
 *  * NEVER TOUCH cockpit.socket. Cockpit is a live system service on this host.
 *    This file logs in and out; it does not start, stop, reload or reconfigure
 *    anything. A logout is a POST to the session endpoint, never a restart.
 *
 *  * A MISSING PRECONDITION IS NOT A FAILING TEST AND IT IS NOT A PASSING ONE.
 *    `require()` below returns a stated reason; the callers turn that into
 *    NOT-ATTEMPTED with the reason attached. A suite that cannot tell "the
 *    assertion did not hold" from "the thing was never installed" reports green
 *    for an empty host, which is the failure this whole task exists to avoid.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

const SRC = path.resolve(__dirname, "..", "..");
const ARTIFACTS = path.join(__dirname, "artifacts");

/* ------------------------------------------------------------ playwright -- */
/* Same resolution order as harness.js: this package does not depend on
 * Playwright and must not pretend to. */
const PW_CANDIDATES = [
    process.env.PLAYWRIGHT_PATH,
    "playwright",
    "/opt/sc/edy-local/e2e/node_modules/playwright",
    path.join(SRC, "node_modules", "playwright")
].filter(Boolean);

function requirePlaywright() {
    for (const c of PW_CANDIDATES) {
        try { return require(c); } catch (e) { /* try the next */ }
    }
    return null;
}

/* ----------------------------------------------------------------- config -- */
/* COCKPIT_URL only ever names a host. SECRETS_LIVE_CREDS names a DIRECTORY of
 * mode-0600 files, one per principal — never a password. */
const CFG = {
    url: process.env.COCKPIT_URL || "https://localhost:9090",
    creds: process.env.SECRETS_LIVE_CREDS ||
           path.join(process.env.XDG_RUNTIME_DIR || os.tmpdir(), "cockpit-secrets-live"),
    /* The two principals docs/HOST-FACTS.md names. cptest is deliberately NOT
     * in `sudo`: it is the whole of item 8. */
    admin: process.env.SECRETS_LIVE_ADMIN || "cptestadm",
    user: process.env.SECRETS_LIVE_USER || "cptest",
    headed: process.env.SECRETS_LIVE_HEADED === "1",
    slowMo: Number(process.env.SECRETS_LIVE_SLOWMO || 0)
};

/* A credential, by principal name. Returns null — never throws, never guesses —
 * so a caller can report NOT-ATTEMPTED with the path it looked at. */
function credential(who) {
    const f = path.join(CFG.creds, who + ".pass");
    try {
        const v = fs.readFileSync(f, "utf8").replace(/\r?\n$/, "");
        return v.length ? v : null;
    } catch (e) { return null; }
}

/* A safe's passphrase, by registry id. Same rule: a file, not an argument. */
function safePassphrase(id) {
    const f = path.join(CFG.creds, "safe-" + id + ".pass");
    try {
        const v = fs.readFileSync(f, "utf8").replace(/\r?\n$/, "");
        return v.length ? v : null;
    } catch (e) { return null; }
}

/* ----------------------------------------------------- host preconditions -- */
/* Everything this suite needs that is NOT in its own gift. Each answer is a
 * sentence, because each one becomes the reason on a NOT-ATTEMPTED line. */
function preconditions() {
    const out = [];
    const helper = "/usr/local/sbin/secrets-admin";
    const pkg = "/usr/share/cockpit/secrets";
    out.push({
        id: "helper",
        ok: fs.existsSync(helper),
        why: helper + " is not installed, so Cockpit's manifest condition " +
             "`path-exists` hides the package and there is no page to drive."
    });
    out.push({
        id: "package",
        ok: fs.existsSync(pkg),
        why: pkg + " does not exist, so Cockpit serves no `secrets` package."
    });
    out.push({
        id: "registry",
        ok: fs.existsSync("/etc/cockpit-secrets/safes.d"),
        why: "/etc/cockpit-secrets/safes.d does not exist, so the registry " +
             "declares no safes and the list has nothing to render."
    });
    out.push({
        id: "playwright",
        ok: !!requirePlaywright(),
        why: "Playwright is not resolvable from " + PW_CANDIDATES.join(", ") + "."
    });
    return out;
}

/* Does the live Cockpit accept this principal at all? A 200 from the login
 * endpoint is Cockpit's own PAM answer, and asking it before opening a browser
 * turns "the suite hung on a login form" into a stated reason. It is one
 * request over the loopback with Basic auth; nothing is stored. */
function checkLogin(who, password) {
    return new Promise((resolve) => {
        const u = new URL("/cockpit/login", CFG.url);
        const req = https.request({
            hostname: u.hostname,
            port: u.port || 443,
            path: u.pathname,
            method: "GET",
            rejectUnauthorized: false,          /* the host's self-signed cert */
            headers: {
                Authorization: "Basic " +
                    Buffer.from(who + ":" + password, "utf8").toString("base64")
            }
        }, (res) => {
            res.resume();
            resolve(res.statusCode === 200);
        });
        req.on("error", () => resolve(false));
        req.end();
    });
}

/* ---------------------------------------------------------------- results -- */
/* One record per numbered item in the task, so the report cannot quietly lose
 * one. `notAttempted` is a first-class outcome and carries its reason. */
function Recorder(label) {
    const items = [];
    let checks = 0, bad = 0;
    return {
        label,
        items,
        /* A named item of the task. `run` returns evidence strings. */
        item(id, title) {
            const rec = { id, title, state: null, why: "", evidence: [], shots: [] };
            items.push(rec);
            return {
                rec,
                ok(cond, what) {
                    checks++;
                    if (cond) { rec.evidence.push("PASS  " + what); }
                    else { bad++; rec.state = "FAIL"; rec.evidence.push("FAIL  " + what); }
                    console.log((cond ? "  \x1b[32mPASS\x1b[0m  " : "  \x1b[31mFAIL\x1b[0m  ") + what);
                    return cond;
                },
                note(what) { rec.evidence.push("note  " + what); console.log("  ....  " + what); },
                shot(name) { rec.shots.push(name); },
                skip(why) {
                    rec.state = "NOT-ATTEMPTED"; rec.why = why;
                    console.log("  \x1b[33mNOT-ATTEMPTED\x1b[0m  " + why);
                },
                fail(why) {
                    rec.state = "FAIL"; rec.why = why; bad++;
                    console.log("  \x1b[31mFAIL\x1b[0m  " + why);
                },
                done() { if (!rec.state) rec.state = "PASS"; return rec.state; }
            };
        },
        summary() { return { checks, bad, items }; }
    };
}

/* --------------------------------------------------------------- browser --- */
async function launch(pw) {
    /* ignoreHTTPSErrors, because this host's Cockpit carries the self-signed
     * certificate it generated for itself. Nothing else is relaxed: no
     * --disable-web-security, and above all no CSP flag — the whole of item 1
     * is that the page runs clean under the policy the bridge really sends. */
    return pw.chromium.launch({
        headless: !CFG.headed,
        slowMo: CFG.slowMo || undefined,
        args: ["--no-sandbox"]
    });
}

/* A context with the CSP recorder installed before any page script runs.
 * `securitypolicyviolation` fires in the frame that violated the policy, so the
 * listener has to be in every frame — addInitScript on the CONTEXT is. */
async function newContext(browser, opts) {
    const ctx = await browser.newContext(Object.assign({
        ignoreHTTPSErrors: true,
        viewport: { width: 1400, height: 950 }
    }, opts || {}));
    await ctx.addInitScript(() => {
        window.__CSP__ = [];
        document.addEventListener("securitypolicyviolation", (e) => {
            window.__CSP__.push({
                directive: e.effectiveDirective || e.violatedDirective,
                blocked: String(e.blockedURI || ""),
                file: String(e.sourceFile || ""),
                line: e.lineNumber || 0,
                sample: String(e.sample || "").slice(0, 120)
            });
        });
    });
    return ctx;
}

/* Console and page errors from EVERY frame, kept on the page object. Chromium
 * reports a CSP refusal as a console error, and the page's own
 * `securitypolicyviolation` events are collected separately: two independent
 * views of the same event, because item 1 treats a violation as a failure and a
 * single detection path that silently stopped working would read as a pass. */
function watchConsole(page) {
    const log = [];
    page.__console = log;
    page.on("console", (m) => {
        log.push({ type: m.type(), text: m.text(), url: (m.location() || {}).url || "" });
    });
    page.on("pageerror", (e) => log.push({ type: "pageerror", text: String(e), url: "" }));
    page.on("requestfailed", (r) => {
        const f = r.failure();
        log.push({ type: "requestfailed", text: (f && f.errorText) || "failed", url: r.url() });
    });
    return log;
}

const CSP_RE = /content security policy|refused to (load|execute|apply|connect|frame)/i;

/* Console traffic that belongs to THIS package, by the URL the message came
 * from. `page.on("console")` is per-page and Cockpit's shell is a busy page:
 * a live session logs a 401 from its own /cockpit/login probe, ERR_ABORTED for
 * every iframe it swaps out, and warnings from the Overview page. Counting
 * those as the plugin's errors made item 1 fail on a page that was faultless —
 * so the split is by origin path, and what the shell said is reported as a
 * note instead of as a verdict. A message with no location is kept: an
 * uncaught exception is worth more than the tidiness of dropping it. */
function consoleFor(page, marker) {
    return (page.__console || []).filter(
        (m) => !m.url || m.url.indexOf(marker) >= 0);
}
function consoleNotFor(page, marker) {
    return (page.__console || []).filter(
        (m) => m.url && m.url.indexOf(marker) < 0);
}

/* The path fragment that identifies this package's own resources in a Cockpit
 * URL: /cockpit/$<checksum>/secrets/… or /cockpit/@localhost/secrets/…. */
const PKG_MARKER = "/secrets/";

function cspFromConsole(page) {
    return consoleFor(page, PKG_MARKER).filter((m) => CSP_RE.test(m.text));
}

async function cspFromEvents(page) {
    /* Every frame in the page, because the plugin lives in one and the shell in
     * another and a violation in either is a violation. */
    const all = [];
    for (const f of page.frames()) {
        try {
            const v = await f.evaluate(() => window.__CSP__ || []);
            v.forEach((x) => all.push(Object.assign({ frame: f.url() }, x)));
        } catch (e) { /* a frame that navigated away mid-read */ }
    }
    return all;
}

/* ------------------------------------------------------------------ login -- */
/* Cockpit's own login form. Not an API call: the session cookie the shell needs
 * is minted by that form, and a suite that forged one would be testing a
 * different code path from the operator's. */
async function login(ctx, who, password) {
    const page = await ctx.newPage();
    watchConsole(page);
    await page.goto(CFG.url + "/", { waitUntil: "domcontentloaded" });
    await page.waitForSelector("#login-user-input", { timeout: 20000 });
    await page.fill("#login-user-input", who);
    await page.fill("#login-password-input", password);
    await Promise.all([
        page.waitForSelector("#login-user-input", { state: "detached", timeout: 30000 }),
        page.click("#login-button")
    ]);
    return page;
}

/* Navigate the SHELL to the plugin and hand back its frame. Going straight to
 * /cockpit/@localhost/secrets/index.html would load the page without the shell,
 * and the shell is what draws Cockpit's administrative-access prompt — item 9
 * would then have nothing to find. */
async function openPlugin(page, timeout) {
    await page.goto(CFG.url + "/secrets", { waitUntil: "domcontentloaded" });
    /* The shell creates this iframe for ANY /path it is pointed at, installed or
     * not — measured on this host with the package absent — so its presence is
     * not evidence that the package exists. #sec-safes is. */
    const sel = 'iframe[name="cockpit1:localhost/secrets"]';
    await page.waitForSelector(sel, { timeout: timeout || 30000 });
    const frame = await (await page.$(sel)).contentFrame();
    try {
        /* NOT "#sec-safes exists" — that div is in the shipped index.html and
         * resolves before a single line of secrets.js has run, so waiting for
         * it returned instantly and every later assertion raced the schema
         * call. (Measured: item 1 read #sec-sub as "loading…" and counted zero
         * helper rules against a page that was perfectly healthy a moment
         * later.) Wait for START-UP to have finished instead: init() either
         * rewrites #sec-sub from the schema, or clears it and renders the
         * helper's error into #sec-safes. Both are settled states; "loading…"
         * is not. */
        await frame.waitForFunction(() => {
            const sub = document.getElementById("sec-sub");
            const host = document.getElementById("sec-safes");
            if (!sub || !host) return false;
            const t = (sub.textContent || "").trim();
            if (t && !/^loading/i.test(t)) return true;      /* schema landed */
            return !!host.querySelector(".sec-alert");        /* or it failed */
        }, null, { timeout: timeout || 30000 });
    } catch (e) {
        /* Say what Cockpit actually served instead of "timeout waiting for a
         * selector", which is the least useful sentence in browser testing. */
        const url = (frame && frame.url()) || "(no frame)";
        let body = "";
        try { body = (await frame.evaluate(() => document.body ? document.body.innerText : ""))
                        .replace(/\s+/g, " ").slice(0, 200); } catch (e2) { body = "(unreadable)"; }
        let status = "?";
        try {
            status = await page.evaluate(async () => {
                const r = await fetch("/cockpit/@localhost/secrets/index.html",
                                      { credentials: "same-origin" });
                return String(r.status);
            });
        } catch (e2) { /* leave it */ }
        throw new Error("the secrets package did not load in Cockpit's shell. " +
                        "GET /cockpit/@localhost/secrets/index.html answered " + status +
                        "; the frame is at " + url + " and reads: " + JSON.stringify(body));
    }
    return frame;
}

/* Is the shell's Administrative access currently on? Cockpit puts the state in
 * the header and the label is the stable part across 3xx shells.
 *
 * "Limited access" is tested FIRST and it wins. The two strings can both be on
 * the page — the control that turns escalation ON is naturally worded with the
 * phrase "administrative access" — so a test that looked for the positive first
 * would report "on" for a session that is plainly limited. Measured on this
 * host at Cockpit 360: a fresh session reads "Limited access" in the header.
 * This is only a convenience for the report; the decisions are made from
 * cockpit.permission({admin:true}).allowed, which is the bridge's own answer. */
async function adminAccessState(page) {
    return page.evaluate(() => {
        const t = document.body ? document.body.innerText : "";
        if (/Limited access/i.test(t)) return "off";
        if (/Administrative access/i.test(t)) return "on";
        return "unknown";
    });
}

/* ------------------------------------------------------------- artefacts --- */
function artifactsDir() {
    fs.mkdirSync(ARTIFACTS, { recursive: true });
    return ARTIFACTS;
}

async function shot(pageOrFrame, name) {
    const dir = artifactsDir();
    const file = path.join(dir, name.replace(/[^A-Za-z0-9._-]/g, "_") + ".png");
    /* A frame cannot be screenshotted; its page can. */
    const page = pageOrFrame.page ? pageOrFrame.page() : pageOrFrame;
    try { await page.screenshot({ path: file, fullPage: false }); } catch (e) { return null; }
    return path.basename(file);
}

function writeArtifact(name, text) {
    const dir = artifactsDir();
    const file = path.join(dir, name.replace(/[^A-Za-z0-9._-]/g, "_"));
    fs.writeFileSync(file, text, { mode: 0o600 });
    return path.basename(file);
}

/* --------------------------------------------------------------- reading --- */
/* The live safe list, straight out of the page's own state. Reading it through
 * the DOM would couple every later test to the card markup; reading it through
 * `cockpit.spawn` inside the frame is the same call the page makes and is the
 * honest source for "which safes does THIS principal see". */
async function liveList(frame) {
    return frame.evaluate(() => new Promise((resolve) => {
        const p = cockpit.spawn(["/usr/local/sbin/secrets-admin", "list"],
                                { err: "message", superuser: null });
        p.input(JSON.stringify({}));
        p.then((out) => { try { resolve(JSON.parse(out)); } catch (e) { resolve({ error: "parse" }); } })
         .catch((err, out) => resolve({ error: "spawn", detail: String(out || err) }));
    }));
}

module.exports = {
    SRC, ARTIFACTS, CFG,
    requirePlaywright, preconditions, credential, safePassphrase, checkLogin,
    Recorder, launch, newContext, watchConsole, cspFromConsole, cspFromEvents,
    login, openPlugin, adminAccessState, shot, writeArtifact, artifactsDir,
    liveList, consoleFor, consoleNotFor, PKG_MARKER
};
