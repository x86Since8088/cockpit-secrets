/* tests/browser/harness.js — the fake Cockpit the UI driver runs against.
 *
 * secrets.js talks to exactly one thing: `cockpit.spawn`. So a headless test of
 * the page needs no Cockpit, no bridge and no root — it needs a stub that
 * answers spawn the way the real bridge does, and a static server that hands
 * the browser the REAL index.html, secrets.js and secrets.css, byte for byte.
 * There is no build step in this package, so what the test loads is what
 * install.sh copies.
 *
 * Two deliberate choices:
 *
 *  * THE SCHEMA IS THE LIVE ONE. `liveSchema()` runs the real
 *    `secrets-admin schema` and hands its output to the stub. A test that
 *    checked the page against a schema copied into this file would pass
 *    forever after the helper changed, which is the one failure this suite
 *    exists to catch.
 *
 *  * THE PASSPHRASE PATH IS NOT SIMULATED AWAY. The stub records every request
 *    body it is given, so the driver can assert what actually crossed the
 *    boundary — that a secret was on stdin and not on argv (I10), and that
 *    nothing was left in the browser afterwards (I11).
 *
 * Playwright is not part of this package (see .gitignore: node_modules/), so it
 * is resolved from wherever this host keeps it and the suite SKIPS with a
 * stated reason rather than failing when it is absent. A missing tool is not a
 * passing test and it is not a broken one either.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const SRC = path.resolve(__dirname, "..", "..");

/* ------------------------------------------------------------ playwright -- */
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

/* ---------------------------------------------------------- the schema ---- */
/* The real helper's own schema verb. COCKPIT_SECRETS_ETC=/nonexistent keeps it
 * off this host's actual registry: the schema does not depend on the registry,
 * and a test that read /etc would be a test whose result depends on which
 * machine it ran on. */
function liveSchema() {
    const out = execFileSync(path.join(SRC, "secrets-admin"), ["schema"], {
        cwd: SRC,
        env: Object.assign({}, process.env, { COCKPIT_SECRETS_ETC: "/nonexistent" }),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
    });
    return JSON.parse(out);
}

/* ------------------------------------------------------ the static server -- */
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

/* The stub bridge. It is served as /base1/cockpit.js because that is what
 * index.html asks for (`../base1/cockpit.js` from /secrets/index.html), so the
 * page under test is the shipped file with nothing rewritten in it. */
const COCKPIT_STUB = `
(function () {
    "use strict";
    var S = window.__SCENARIO || {};
    window.__CALLS = [];          /* every spawn: verb, argv, superuser */
    window.__BODIES = [];         /* every request body, as sent */

    function answerFor(verb, req) {
        var r = S.responses && S.responses[verb];
        if (r === undefined) return { error: "unsupported",
                                      detail: "the test scenario has no answer for " + verb };
        if (typeof r === "object" && r !== null && r.__seq) {
            var i = Math.min(r.__seq.length - 1, (r.__n = (r.__n || 0)) );
            r.__n++;
            return r.__seq[i];
        }
        return r;
    }

    function deferred() {
        var done = [], fail = [], streams = [], settled = null;
        var api = {
            then: function (cb) { done.push(cb); flush(); return api; },
            "catch": function (cb) { fail.push(cb); flush(); return api; },
            stream: function (cb) { streams.push(cb); return api; },
            close: function () { api.__closed = true; },
            __emit: function (chunk) { streams.forEach(function (f) { f(chunk); }); },
            __settle: function (kind, a, b) { settled = [kind, a, b]; flush(); }
        };
        function flush() {
            if (!settled) return;
            if (settled[0] === "ok" && done.length) {
                var list = done; done = [];
                list.forEach(function (f) { f(settled[1]); });
            } else if (settled[0] === "err" && fail.length) {
                var l2 = fail; fail = [];
                l2.forEach(function (f) { f(settled[1], settled[2]); });
            }
        }
        return api;
    }

    window.cockpit = {
        spawn: function (argv, opts) {
            var verb = argv[1];
            window.__CALLS.push({ verb: verb, argv: argv.slice(),
                                  superuser: (opts && opts.superuser) || null });
            var proc = deferred();
            var isSession = (verb === "open");

            if (isSession) {
                /* The open session: a banner frame, then one reply line per
                 * request line, exactly as docs/CONTRACT.md describes. */
                window.setTimeout(function () {
                    proc.__emit(JSON.stringify({ frame: "banner", session: true,
                        idle_seconds: 120, max_seconds: 900 }) + "\\n");
                }, 0);
                proc.input = function (data) {
                    String(data).split("\\n").forEach(function (line) {
                        if (!line.trim()) return;
                        var req = null;
                        try { req = JSON.parse(line); } catch (e) { return; }
                        window.__BODIES.push(req);
                        var v = req.verb || "unlock";
                        var ans = answerFor(v, req);
                        window.setTimeout(function () {
                            proc.__emit(JSON.stringify(ans) + "\\n");
                        }, 0);
                    });
                    return proc;
                };
                return proc;
            }

            proc.input = function (data) {
                var req = null;
                try { req = JSON.parse(String(data)); } catch (e) { req = String(data); }
                window.__BODIES.push(req);
                var ans = answerFor(verb, req);
                window.setTimeout(function () {
                    if (ans && ans.error) proc.__settle("err", { problem: "" },
                                                        JSON.stringify(ans));
                    else proc.__settle("ok", JSON.stringify(ans));
                }, 0);
                return proc;
            };
            return proc;
        },
        permission: function () {
            return {
                allowed: S.admin !== false,
                addEventListener: function () {}
            };
        }
    };
}());
`;

function startServer() {
    const server = http.createServer((req, res) => {
        let url = req.url.split("?")[0];
        if (url === "/base1/cockpit.js") {
            res.writeHead(200, { "content-type": "text/javascript" });
            res.end(COCKPIT_STUB);
            return;
        }
        if (url === "/" || url === "/secrets/") url = "/secrets/index.html";
        if (!url.startsWith("/secrets/")) { res.writeHead(404); res.end("no"); return; }
        const name = path.basename(url);          /* no traversal out of SRC */
        const file = path.join(SRC, name);
        fs.readFile(file, (err, buf) => {
            if (err) { res.writeHead(404); res.end("no"); return; }
            res.writeHead(200, { "content-type": MIME[path.extname(name)] || "text/plain" });
            res.end(buf);
        });
    });
    return new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve(server));
    });
}

/* ------------------------------------------------------------- the driver -- */
async function openPage(browser, scenario) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    /* Before ANY page script — including the stub — so the stub can read it. */
    await page.addInitScript(
        `window.__SCENARIO = ${JSON.stringify(scenario)};`);
    const errors = [];
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    page.__errors = errors;
    return page;
}

module.exports = { SRC, requirePlaywright, liveSchema, startServer, openPage };
