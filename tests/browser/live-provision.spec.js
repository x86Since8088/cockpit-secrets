/* tests/browser/live-provision.spec.js — BUILD THE DESIGN TESTBED, THROUGH
 * THE REAL UI.
 *
 *   node tests/browser/live-provision.spec.js
 *
 * This is the odd one out in tests/browser/. The other live specs ASSERT
 * things about a host that already has safes on it. This one MAKES the safes
 * the design work will be styled against, and it makes them the way an
 * operator would: a real Cockpit login, Cockpit's own Administrative-access
 * control, and the page's own "New safe…" form. It asserts as it goes,
 * because a testbed that was built wrong is worse than no testbed — but
 * building is the point, and the report says what exists at the end.
 *
 * WHAT IT LEAVES BEHIND (all three owned by `cptestadm`):
 *
 *   dummy-fake-safe          admin-class KDBX  — 15 groups, 31 entries, two
 *                                                attachments, one entry in
 *                                                the recycle bin
 *   dummy-fake-user-kdbx     user-class  KDBX  — 4 groups, 7 entries
 *   dummy-fake-user-psafe3   user-class  PWS3  — 3 groups, 5 entries, then
 *                                                marked READ-ONLY
 *
 * Their passphrases are 0600 files in the credentials directory, named
 * `safe-<id>.pass`. THEY ARE NOT INVENTED HERE. A passphrase this suite made
 * up would be one nobody could use to check the file afterwards with
 * `keepassxc-cli`, and it would be one nobody could type into the page by
 * hand — so a missing file is a stated NOT-ATTEMPTED naming the path, never
 * a guess. tests/browser/TESTBED.md carries the one command that generates
 * them and then runs this file.
 *
 * ===================== THE OPERATOR'S OWN SAFE ========================
 *
 * `pwsafe3` is a REAL, imported, user-class safe belonging to `eddie`, and
 * it holds live data. This file must never unlock it, open it, read it,
 * delete it, forget it, or put it in a screenshot.
 *
 * Three separate things keep that true, because one would be a promise:
 *
 *   1. Every id this file will act on is checked against OPERATOR_SAFES by
 *      `guard()` before the call is built. A verb that reaches the helper
 *      with that id is a bug this throws on rather than a bug somebody finds
 *      in the audit log.
 *   2. Nothing here iterates the registry. There is no "for every safe"
 *      loop to accidentally include it in — every id is a literal from
 *      `IDS`.
 *   3. The suite signs in as `cptestadm`, and `pwsafe3` lives in eddie's
 *      per-user registry, which cptestadm cannot read. Item P7 asserts that
 *      the page never rendered it, so the screenshots are provably clean
 *      rather than clean by argument.
 *
 * The registry FILE's mtime and sha256 are recorded outside this process,
 * before and after the run — that check belongs to whoever runs this, and
 * TESTBED.md gives the two commands.
 *
 * ========================= THE RULES IT KEEPS =========================
 *
 *   * NO SECRET ON ARGV OR IN THE ENVIRONMENT (I10). Passphrases are read
 *     from files in the credentials directory and travel exactly two ways:
 *     typed into the page's own password control, or inside the JSON body
 *     of a session frame written to the helper's stdin. `ps` on a running
 *     provision shows an `open` verb and nothing else. The one place a
 *     script reaches argv is the read-only flip in P5, and that script
 *     carries no secret — only a registry id and the word "ro".
 *   * NEVER TOUCH cockpit.socket. This signs in and out; it starts,
 *     reloads and reconfigures nothing.
 *   * A MISSING PRECONDITION IS NOT A FAILING TEST AND IT IS NOT A PASSING
 *     ONE. Every item can come back NOT-ATTEMPTED with the reason.
 *
 * ================= WHY THE CONTENT GOES IN BY SESSION =================
 *
 * The three safes are CREATED through the page's form — that is item 3 of
 * the task and it is the flow an operator actually performs. The ~43 entries
 * and 22 groups then go in through the page's own `open` SESSION: one
 * helper process, one unlock, a JSON frame per mutation, one `save`.
 *
 * That is not a shortcut around the UI. It is the same channel the page
 * itself uses for every edit (`openSession()` in secrets.js, which this
 * file's `installSession()` mirrors frame-for-frame, banner and closing
 * frame included) — the real bridge, the real CSP, the real
 * `superuser:"require"` on the admin-class safe, the real helper. What it
 * skips is re-typing the same modal 43 times, which would exercise nothing
 * the create flow and item P6 do not already cover and would take the run
 * from two minutes to most of an hour.
 *
 * The alternative — `autosave:true` on each mutation — would be forty-three
 * separate unlocks, i.e. forty-three Argon2 derivations, and it would also
 * be wrong: `HANDLES` in secrets-admin is a plain dict in the helper's own
 * address space and `find_session` compares `match.pid != ident.pid`, so a
 * handle from one `cockpit.spawn` is dead in the next. Sessions are not an
 * optimisation here, they are the only way to make more than one change to
 * one safe.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const H = require("./live-harness.js");
const D = require("./provision-data.js");

const HELPER = "/usr/local/sbin/secrets-admin";

/* ------------------------------------------------------------- the ids --- */
/* Literals, every one of them. Nothing in this file discovers an id. */
const IDS = {
    admin:  "dummy-fake-safe",
    kdbx:   "dummy-fake-user-kdbx",
    psafe3: "dummy-fake-user-psafe3"
};
const ALL_IDS = [IDS.admin, IDS.kdbx, IDS.psafe3];

/* THE GUARD. Not a comment — a throw. */
const OPERATOR_SAFES = ["pwsafe3"];

function guard(id) {
    if (OPERATOR_SAFES.indexOf(String(id)) >= 0)
        throw new Error("REFUSED: “" + id + "” is the operator's own registered safe. " +
                        "Nothing in this suite may name it.");
    if (ALL_IDS.indexOf(String(id)) < 0)
        throw new Error("REFUSED: “" + id + "” is not one of this suite's own ids (" +
                        ALL_IDS.join(", ") + "). This file acts on nothing it did not make.");
    return id;
}

const ITEMS = {
    P1: "Sign in as an admin principal and turn ON Cockpit's Administrative access",
    P2: "Create dummy-fake-safe (ADMIN class, KDBX) through the page's New-safe form",
    P3: "Populate dummy-fake-safe: a three-deep tree, ~31 entries, two attachments, a recycle bin",
    P4: "Create and populate dummy-fake-user-kdbx (USER class, KDBX)",
    P5: "Create and populate dummy-fake-user-psafe3 (USER class, PWS3), then mark it read-only",
    P6: "Every new safe unlocks in the page and renders its entries",
    P7: "The operator's own safe was never named, never opened and never rendered"
};
const ORDER = ["P1", "P2", "P3", "P4", "P5", "P6", "P7"];

const REC = H.Recorder("live-provision — build the design testbed");

/* ====================================================================== *
 * modal plumbing — the same three traps live-registry.spec.js records
 * ====================================================================== */

/* `verbDialog` stacks its RESULT on top of the form, so `.sec-modal` matches
 * the form and not the answer. `#sec-modal-host` appends each backdrop, so
 * the LAST one is the one on top. */
const M = "#sec-modal-host > .sec-backdrop:last-child .sec-modal";

/* A control addressed the way an operator addresses it: by the text of its
 * label. "The first input" is not a stable way to mean "the id". */
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

/* Tick every CONFIRMATION gate and nothing else. `input[type=checkbox]` is
 * the wrong selector: a `toggle` FIELD renders as a checkbox too, and
 * ticking them all switches on `make_keyfile` and produces a safe that needs
 * a key file nobody kept. Gates carry an id beginning `sec-confirm`. */
async function tickConfirms(frame) {
    const boxes = await frame.$$(M + ' input[id^="sec-confirm"]');
    for (const b of boxes) { if (!(await b.isChecked())) await b.check(); }
    return boxes.length;
}

/* Has the dialog SETTLED — has the verb answered, either way?
 *
 * A FUNCTION, never a string: `waitForFunction` with a string body is `eval`
 * in the page, the real Cockpit CSP has no `unsafe-eval`, and the refusal
 * looks exactly like "the page never got there".
 *
 * And it watches the HEADING plus the error node, never the modal's text:
 * the create form's own `breaks_when_wrong` help contains the words
 * "created", "invalid" and "refused", so a text predicate is true before the
 * button is even clicked. */
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

function waitFailed(e) {
    console.log("  ....  a wait gave up: " +
                String((e && e.message) || e).split("\n")[0].slice(0, 180));
    return null;
}

/* Re-RESOLVE the handle on every attempt. The safe list repaints when `list`
 * comes back and a handle resolved before that is detached by the time it is
 * clicked; settling for the bounding box is what turns a flaky click into a
 * wait. */
async function clickIn(frame, selector, timeout) {
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            const handle = await frame.waitForSelector(selector, { timeout: timeout || 20000 });
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

async function closeModal(frame) {
    const gone = async () => (await frame.$(".sec-modal")) === null;
    if (await gone()) return { closed: true, buttons: [] };
    const buttons = await frame.$$eval(M + " button",
        (ns) => ns.map((n) => (n.textContent || "").trim())).catch(() => []);
    for (const label of ["Close", "Done", "Cancel", "Finish", "OK"]) {
        if (!buttons.includes(label)) continue;
        try { await clickIn(frame, M + ` button:text-is("${label}")`, 4000); }
        catch (e) { /* the click may race the close */ }
        try { await frame.waitForSelector(".sec-modal", { state: "detached", timeout: 4000 }); }
        catch (e) { /* try the next label */ }
        if (await gone()) return { closed: true, buttons };
    }
    try {
        await frame.focus(M);
        await frame.press(M, "Escape");
        await frame.waitForSelector(".sec-modal", { state: "detached", timeout: 4000 });
    } catch (e) { /* fall through to the report */ }
    return { closed: await gone(), buttons };
}

function cardFor(id) {
    return `#sec-safes .sec-safe:has(.sec-safe-id:text-is("${id}"))`;
}

async function waitForCard(frame, id, present, timeout) {
    await frame.waitForFunction(([wanted, want]) => {
        const host = document.getElementById("sec-safes");
        if (!host) return false;
        const ids = Array.prototype.map.call(
            host.querySelectorAll(".sec-safe-id"), (n) => n.textContent.trim());
        return (ids.indexOf(wanted) >= 0) === want;
    }, [id, !!present], { timeout: timeout || 30000 });
}

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

/* `frame.evaluate` of a PROMISE, retried. A `cockpit.spawn` inside the page
 * is a promise Playwright waits on while the page keeps re-rendering
 * underneath it; when a render lands mid-await Chromium collects the pending
 * promise and Playwright reports "Resulting promise was garbage collected",
 * which is a statement about timing and not about the product. The last
 * error is re-thrown so a real failure still surfaces. */
async function inPage(frame, fn, arg) {
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
        try { return await frame.evaluate(fn, arg); }
        catch (e) {
            lastErr = e;
            if (!/garbage collected|Execution context was destroyed|detached/i
                    .test(String(e && e.message))) throw e;
            await frame.waitForTimeout(500);
        }
    }
    throw lastErr;
}

/* One one-shot verb through the page's own bridge — used to READ state and
 * to clean up, never to create the safes. Same call the page makes. */
function helper(frame, verb, req, admin) {
    return inPage(frame, ([v, body, sup, exe]) => new Promise((resolve) => {
        const p = cockpit.spawn([exe, v],
                                { err: "message", superuser: sup ? "require" : null });
        p.input(body);
        p.then((out) => {
            try { resolve(JSON.parse(out)); }
            catch (e) { resolve({ error: "parse", raw: String(out).slice(0, 300) }); }
        }).catch((err, out) => {
            try { resolve(JSON.parse(out)); }
            catch (e) { resolve({ error: "spawn", detail: String(out || err).slice(0, 300) }); }
        });
    }), [verb, JSON.stringify(req || {}), !!admin, HELPER]);
}

/* ====================================================================== *
 * the session driver — a mirror of openSession() in secrets.js
 * ====================================================================== */

/* Installs `window.__PROV` in the plugin's frame: ONE `open` process, a
 * newline-delimited JSON frame per verb, a FIFO of pending replies.
 *
 * The two unsolicited frames matter and are handled the way the page handles
 * them. The helper emits a `banner` when the session opens (carrying the
 * timeouts it will really enforce) and a `closed` frame naming why it ended.
 * Answering a queued request with one of those shifts every later reply by
 * one, and then every verb quietly receives the previous verb's answer —
 * which is the kind of bug that produces a testbed nobody can trust. They
 * are consumed by their `frame` tag and never dequeued. */
async function installSession(frame, safeId, admin) {
    guard(safeId);
    await frame.evaluate(([isAdmin, exe]) => {
        const opts = { err: "message" };
        if (isAdmin) opts.superuser = "require";
        const proc = cockpit.spawn([exe, "open"], opts);
        const st = { queue: [], buf: "", dead: null, handle: null,
                     banner: null, closed: null };

        function die(why) {
            if (st.dead) return;
            st.dead = why || "the helper session ended";
            while (st.queue.length) st.queue.shift().reject(new Error(st.dead));
        }
        function deliver(line) {
            let obj = null;
            try { obj = JSON.parse(line); } catch (e) { obj = null; }
            const tag = obj ? obj.frame : undefined;
            if (tag === "banner") { st.banner = obj; return; }
            if (tag === "closed") { st.closed = obj; return; }
            const w = st.queue.shift();
            if (!w) return;                       /* unsolicited — ignore */
            if (!obj) { w.reject(new Error("the helper sent a frame that is not JSON")); return; }
            w.resolve(obj);
        }
        function consume(chunk) {
            st.buf += String(chunk === undefined || chunk === null ? "" : chunk);
            let nl;
            while ((nl = st.buf.indexOf("\n")) >= 0) {
                const line = st.buf.slice(0, nl);
                st.buf = st.buf.slice(nl + 1);
                if (line.trim()) deliver(line);
            }
        }
        proc.stream(consume);
        proc.then(() => { if (st.buf.trim()) consume("\n"); die("the helper session closed"); })
            .catch((err, out) => {
                if (out) consume(String(out));
                die(String((err && err.message) || out || "the session could not be started"));
            });

        st.send = function (body) {
            if (st.dead) return Promise.reject(new Error(st.dead));
            return new Promise((resolve, reject) => {
                st.queue.push({ resolve, reject });
                try {
                    /* The second argument keeps stdin OPEN. This is the one
                     * place stdin is not closed after a write, because a
                     * session is one process for many verbs. */
                    proc.input(body + "\n", true);
                } catch (e) {
                    st.queue.pop();
                    reject(new Error("could not write to the helper session"));
                }
            });
        };
        st.stop = function () { try { proc.close("terminated"); } catch (e) { /* gone */ } };
        window.__PROV = st;
    }, [!!admin, HELPER]);
}

/* The unlock frame. The passphrase is put into the JSON body inside the page
 * and the body is dropped immediately afterwards; it never becomes an
 * argument to anything and never reaches storage. */
async function sessionUnlock(frame, safeId, passphrase) {
    guard(safeId);
    return inPage(frame, ([id, pass]) => {
        let body = JSON.stringify({ verb: "unlock", safe: id, password: pass });
        return window.__PROV.send(body).then((r) => {
            body = null;
            if (r && r.handle) window.__PROV.handle = r.handle;
            return r;
        }, (e) => { body = null; return { error: "session", detail: String(e && e.message || e) }; });
    }, [safeId, passphrase]);
}

/* Every other verb. `verb` and `handle` are the only keys added, exactly as
 * `s.call()` does in secrets.js — in particular NOT `safe`, because the
 * handle already names the safe and the helper rejects a key a verb did not
 * declare. */
async function call(frame, verb, args) {
    return inPage(frame, ([v, a]) => {
        const f = Object.assign({}, a || {});
        f.verb = v;
        if (window.__PROV.handle) f.handle = window.__PROV.handle;
        return window.__PROV.send(JSON.stringify(f))
            .catch((e) => ({ error: "session", detail: String(e && e.message || e) }));
    }, [verb, args || {}]);
}

async function sessionStop(frame) {
    await frame.evaluate(() => {
        if (window.__PROV) { window.__PROV.stop(); window.__PROV = null; }
    }).catch(() => null);
}

/* ====================================================================== *
 * the tree
 * ====================================================================== */

/* Group path -> group id, rebuilt from the helper's OWN `tree` after the
 * groups are added. `group-add` answers `{ok, saved}` and does not return the
 * new uuid, so the map cannot be accumulated as we go; and reconstructing
 * paths from `{uuid, name, parent}` is the honest way to get them even if it
 * did, because two groups may share a name at different depths.
 *
 * THE TWO FORMATS DO NOT HAVE THE SAME IDEA OF A GROUP, AND PRETENDING THEY
 * DO COST THIS FILE A WHOLE RUN.
 *
 *   KDBX  groups are objects with uuids and there is exactly ONE root group
 *         node — the database itself — which every path is relative to. Its
 *         `parent` is null, and it is the node the walk below stops at, so
 *         the root maps to "".
 *
 *   PWS3  gives groups no uuid at all. A group is a STRING on a record
 *         (backends/psafe3.py: "The group id IS the group path"), the root
 *         is the empty string and has no node, and a top-level group's
 *         `parent` is null — the same shape the KDBX root has. Walking it
 *         like a KDBX tree therefore reads every top-level group AS the
 *         root: an empty PWS3 answers `{"groups": []}`, the map comes back
 *         with no "" key at all, and every group-add is refused for having
 *         no parent. Measured — that is exactly how the first live run
 *         failed, with `["Legacy (no parent “”)", …]`.
 *
 * So the format is passed in and the two are handled as the two different
 * things they are, rather than inferred from the shape and got wrong.
 */
function pathMap(groups, format) {
    const byUuid = {};
    (groups || []).forEach((g) => { byUuid[g.uuid] = g; });

    /* AND THE SECOND HALF OF THE SAME LESSON: A PWS3 GROUP ID IS NOT A
     * SLASH PATH. Password Safe joins the hierarchy with DOTS, so
     * `group-add(parent:"Legacy", name:"Routers")` produces the id
     * `Legacy.Routers`, and a map keyed on the id it returns does not answer
     * to `provision-data.js`'s `"Legacy/Routers"`. The first fix here keyed
     * the map on `g.uuid` and the run then reported "missing
     * [Legacy/Routers, Legacy/Modems]" against groups that were sitting in
     * the file — a testbed loader failing on its own key format.
     *
     * So the KEY is always the "/"-joined path this suite writes, rebuilt
     * from the parent chain, and the VALUE is always whatever the format
     * calls the group — a uuid for KDBX, a dotted path for PWS3. Both are
     * then handed back to `group-add`/`add` verbatim. */
    const rootless = (format === "psafe3");
    const out = {};
    if (rootless) out[""] = "";                 /* the root has no node here */
    (groups || []).forEach((g) => {
        const parts = [];
        let cur = g, hops = 0;
        while (cur && hops++ < 32) {
            const parent = cur.parent ? byUuid[cur.parent] : null;
            if (!parent) {
                /* KDBX: `cur` IS the root, and contributes no path segment.
                 * PWS3: `cur` is a TOP-LEVEL group, and contributes its name. */
                if (rootless) parts.unshift(cur.name);
                break;
            }
            parts.unshift(cur.name);
            cur = parent;
        }
        out[parts.join("/")] = g.uuid;
    });
    return out;
}

/* ====================================================================== *
 * P1 — Cockpit's own Administrative access
 * ====================================================================== */

/* This is the whole reason the suite signs in as an account that is in
 * `sudo`. An admin-class safe is created and opened with
 * `superuser:"require"`, and MEASURED on Cockpit 360 (docs/LIVE-WALKTHROUGH.md
 * item 9): a channel opened with `superuser:"require"` from a session in
 * limited access is refused IMMEDIATELY with `access-denied` and NO DIALOG
 * IS DRAWN ANYWHERE. The escalation dialog belongs to the shell — it is the
 * component behind the header control, which calls
 * `cockpit.Superuser.Start()` and listens for its Prompt signal around that
 * one call — and there is no API a package page can use to summon it.
 *
 * So the only way in is the gesture an operator makes: click Cockpit's own
 * "Limited access" control in the header and answer its prompt. */
async function escalate(page, it, password) {
    const before = await H.adminAccessState(page);
    it.note("Cockpit's header reports: " + before);

    let frame = await H.openPlugin(page);
    await waitForSafeList(frame).catch(() => null);

    const perm0 = await frame.evaluate(() => new Promise((resolve) => {
        const p = cockpit.permission({ admin: true });
        setTimeout(() => resolve(p.allowed), 600);
    }));
    it.note("cockpit.permission({admin:true}).allowed === " + JSON.stringify(perm0));

    if (perm0 === true) {
        it.ok(true, "this session already has administrative access — nothing to escalate");
        return frame;
    }

    const hdr = page.locator('button:has-text("Limited access"), a:has-text("Limited access")');
    it.ok(await hdr.count() > 0,
          "Cockpit's header carries the “Limited access” control the page's banner names");
    await H.shot(page, "P1-limited-access");
    it.shot("P1-limited-access.png");
    await hdr.first().click();

    const prompt = await page.waitForFunction(() => {
        const t = document.body ? document.body.innerText : "";
        const pw = document.querySelector("input[type=password]");
        return (/administrative access|switch to admin|password for|Limited access mode/i.test(t) && !!pw)
            ? { text: t.slice(0, 200) } : null;
    }, null, { timeout: 30000 }).then((h) => h.jsonValue()).catch(() => null);

    if (!prompt) {
        it.fail("Cockpit's own escalation dialog did not appear within 30 s of using its " +
                "header control. Nothing below can create an admin-class safe.");
        await H.shot(page, "P1-no-prompt");
        return null;
    }
    it.ok(true, "Cockpit's own administrative prompt appeared in the SHELL, not in the " +
                "plugin frame — this suite drew no password box of its own");
    await H.shot(page, "P1-escalation-prompt");
    it.shot("P1-escalation-prompt.png");

    await page.locator("input[type=password]:visible").first().fill(password);
    /* noWaitAfter, and the failure swallowed on purpose: Cockpit RELOADS the
     * whole page the moment its superuser state changes
     * (superuser.js: window.location.reload(true)), so the button this click
     * lands on is detached before the click can report success. What the
     * click did is asserted from cockpit.permission afterwards, which is the
     * fact that matters. */
    const auth = page.locator("button:visible")
                     .filter({ hasText: /^(Authenticate|Ok|Continue|Apply|Log in)$/i }).first();
    if (await auth.count()) await auth.click({ noWaitAfter: true, timeout: 10000 }).catch(() => {});
    else await page.keyboard.press("Enter");

    await page.waitForLoadState("domcontentloaded").catch(() => {});
    await page.waitForFunction(() => {
        const t = document.body ? document.body.innerText : "";
        return /Administrative access/i.test(t) && !/Limited access/i.test(t);
    }, null, { timeout: 30000 }).catch(() => {});
    it.note("Cockpit's header now reports: " + (await H.adminAccessState(page)));

    /* The reload made the old frame stale by design. */
    frame = await H.openPlugin(page);
    await waitForSafeList(frame).catch(() => null);
    const now = await frame.evaluate(() => new Promise((resolve) => {
        const p = cockpit.permission({ admin: true });
        setTimeout(() => resolve(p.allowed), 800);
    }));
    it.ok(now === true,
          "administrative access is now ON (cockpit.permission.allowed === " +
          JSON.stringify(now) + ") — an admin-class create can be attempted");
    return now === true ? frame : null;
}

/* ====================================================================== *
 * creating a safe — through the page's own form
 * ====================================================================== */

async function createSafeViaForm(frame, page, it, spec) {
    guard(spec.id);

    it.ok(!!(await frame.$('#sec-safes .sec-tools button:text-is("New safe…")')),
          "the safe list offers “New safe…”, drawn only because the installed helper " +
          "publishes safe-create");
    await clickIn(frame, '#sec-safes .sec-tools button:text-is("New safe…")');
    await frame.waitForSelector(".sec-modal", { timeout: 20000 });

    const idSel = await selByLabel(frame, "^Id");
    const labelSel = await selByLabel(frame, "^Label");
    const fmtSel = await selByLabel(frame, "^Format");
    const accSel = await selByLabel(frame, "^Access class");
    it.ok(!!idSel && !!labelSel && !!fmtSel && !!accSel,
          "the create dialog drew Id, Label, Format and Access class");

    /* ADMIN IS THE DEFAULT AND THE PAGE SAYS SO BEFORE ANYTHING IS TYPED
     * (I1). Asserted against the live schema, not a fixture's. */
    it.ok(/administrator safe/i.test(await modalText(frame)),
          "with no access chosen the dialog says this will be an ADMINISTRATOR safe — " +
          "the restrictive default, from the live schema");

    await frame.fill(idSel, spec.id);
    await frame.fill(labelSel, spec.label);
    await frame.selectOption(fmtSel, spec.format);
    await frame.selectOption(accSel, spec.access);

    const note = await modalText(frame);
    if (spec.access === "user") {
        it.ok(/your own safe/i.test(note),
              "choosing “This user” changes the note to say it is your own safe");
        it.ok(/\.config\/cockpit-secrets\/safes\.d/.test(note),
              "…and names the per-user registry directory the helper published");
    } else {
        it.ok(/administrator safe/i.test(note),
              "the ADMIN class note is the one shown");
    }

    await frame.fill(M + " input[type=password]", spec.pass);
    await frame.waitForSelector(M + " .sec-strength", { timeout: 10000 }).catch(() => null);
    it.ok(!!(await frame.$(M + " .sec-strength")),
          "the live strength meter is drawn beside the passphrase — advice, never a gate");

    await H.shot(page, "create-" + spec.id + "-dialog");
    it.shot("create-" + spec.id + "-dialog.png");

    await tickConfirms(frame);
    await clickIn(frame, M + ' button:text-is("Create the safe")');
    /* The helper builds the file and re-opens it from cold before it
     * answers, so this is seconds rather than milliseconds. */
    await frame.waitForFunction(dialogSettled, "The safe was created", { timeout: 120000 })
               .catch(waitFailed);

    const after = (await modalText(frame)).replace(/\s+/g, " ");
    const made = /The safe was created/.test(after);
    it.ok(made, "the helper accepted it and the dialog says so: " + after.slice(0, 140));
    it.ok(!/key file is shown ONCE/i.test(after),
          "no key file was generated — the safe opens with the passphrase and nothing else");
    if (spec.format === "psafe3")
        it.note("creation warnings, verbatim from the helper: " +
                JSON.stringify(after.slice(0, 400)));

    await H.shot(page, "create-" + spec.id + "-result");
    it.shot("create-" + spec.id + "-result.png");
    const c = await closeModal(frame);
    it.ok(c.closed, "the result dialog dismisses (buttons: " + JSON.stringify(c.buttons) + ")");

    if (!made) return false;

    let appeared = true;
    try { await waitForCard(frame, spec.id, true); } catch (e) { appeared = false; }
    it.ok(appeared, "the new safe appears on the page without a reload");

    const list = await helper(frame, "list", {}, spec.access === "admin");
    const row = ((list && list.safes) || []).find((s) => s.id === spec.id);
    it.ok(!!row, "and the helper's own `list` reports it");
    if (row) {
        it.ok(row.registry === (spec.access === "admin" ? "system" : "user"),
              "…from the " + (spec.access === "admin" ? "system" : "per-user") +
              " registry (registry=" + row.registry + ")");
        it.ok(row.format === spec.format,
              "…declared format " + JSON.stringify(row.format));
        it.ok(row.locked === true,
              "…and locked: a created safe is not left open");
    }
    return true;
}

/* ====================================================================== *
 * populating a safe — through the page's own session
 * ====================================================================== */

async function populate(frame, it, spec) {
    guard(spec.id);

    await installSession(frame, spec.id, spec.access === "admin");
    const un = await sessionUnlock(frame, spec.id, spec.pass);
    if (!un || un.error || !un.handle) {
        it.fail("the session would not unlock " + spec.id + ": " +
                JSON.stringify(un && (un.error || un.detail || un)).slice(0, 200));
        await sessionStop(frame);
        return null;
    }
    it.ok(true, "an `open` session unlocked " + spec.id +
                " (entries_total=" + un.entries_total + ", groups_total=" + un.groups_total + ")");
    if (un.warnings && un.warnings.length)
        it.note("the helper's unlock warnings: " + JSON.stringify(un.warnings).slice(0, 300));

    /* --- groups, parents first ---------------------------------------- */
    let tree = await call(frame, "tree", {});
    let map = pathMap(tree && tree.groups, spec.format);
    const rootUuid = map[""];
    /* NOT `length > 0`: a PWS3 root IS the empty string, and asserting it is
     * non-empty would be asserting a KDBX detail against a format that does
     * not have it. What matters is that the root RESOLVES. */
    it.ok(typeof rootUuid === "string",
          "the root group resolves for this format (" + spec.format + ", root id " +
          JSON.stringify(rootUuid) + ")");

    const groupFail = [];
    for (const p of spec.groups) {
        const cut = p.lastIndexOf("/");
        const parentPath = cut < 0 ? "" : p.slice(0, cut);
        const name = cut < 0 ? p : p.slice(cut + 1);
        const parent = map[parentPath];
        if (parent === undefined) { groupFail.push(p + " (no parent “" + parentPath + "”)"); continue; }
        const r = await call(frame, "group-add", { parent: parent, name: name });
        if (!r || r.error) { groupFail.push(p + " -> " + JSON.stringify(r && (r.error || r)).slice(0, 90)); continue; }
        /* Re-read so the new group is addressable as a parent for the next
         * level. `group-add` does not answer with the uuid. */
        tree = await call(frame, "tree", {});
        map = pathMap(tree && tree.groups, spec.format);
    }
    const depth = Math.max.apply(null, spec.groups.map((p) => p.split("/").length));
    it.ok(groupFail.length === 0,
          spec.groups.length + " group(s) created, " + depth + " level(s) deep" +
          (groupFail.length ? " — FAILED: " + JSON.stringify(groupFail).slice(0, 300) : ""));

    const missing = spec.groups.filter((p) => map[p] === undefined);
    it.ok(missing.length === 0,
          "every group path resolves in the helper's own tree" +
          (missing.length ? " — missing " + JSON.stringify(missing) : ""));

    /* --- entries ------------------------------------------------------- */
    const uuids = {};                 /* title -> uuid, for the attachments */
    const entryFail = [];
    let n = 0;
    for (const e of spec.entries) {
        const body = { title: e.title };
        ["username", "password", "url", "notes", "expires", "totp_uri"].forEach((k) => {
            if (e[k] !== undefined) body[k] = e[k];
        });
        /* PWS3 refuses `tags` and `custom` — that is the FORMAT and not a
         * gap, so they are not sent rather than sent and refused. */
        if (spec.rich) {
            if (e.tags !== undefined) body.tags = e.tags;
            if (e.custom !== undefined) body.custom = e.custom;
        }
        const g = map[e.group === undefined ? "" : e.group];
        if (g === undefined) { entryFail.push(e.title.slice(0, 40) + " (no group)"); continue; }
        const r = await call(frame, "add", { group: g, entry: body });
        if (!r || r.error || !r.uuid) {
            entryFail.push(String(e.title).slice(0, 40) + " -> " +
                           JSON.stringify(r && (r.error || r.detail || r)).slice(0, 90));
            continue;
        }
        uuids[e.title] = r.uuid;
        n++;
        if (n % 10 === 0) it.note("…" + n + " entries in");
    }
    it.ok(entryFail.length === 0,
          n + " of " + spec.entries.length + " entries added" +
          (entryFail.length ? " — FAILED: " + JSON.stringify(entryFail).slice(0, 400) : ""));

    /* --- attachments --------------------------------------------------- */
    if (spec.attachments) {
        for (const e of spec.entries) {
            if (!e.attach) continue;
            const uuid = uuids[e.title];
            if (!uuid) { it.fail("no uuid for the entry that should carry the " + e.attach + " attachment"); continue; }
            const a = D.ATTACH[e.attach];
            /* Generated INSIDE the page: a 960 000-character base64 string is
             * not worth pushing across the debugger protocol, and building it
             * here keeps the frame's size a property of this file. */
            const r = await inPage(frame, ([id, name, text, chunk, size]) => {
                let s = text;
                if (size) { s = ""; while (s.length < size) s += chunk; s = s.slice(0, size); }
                const bytes = new Uint8Array(s.length);
                for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i) & 0xff;
                let bin = "";
                for (let i = 0; i < bytes.length; i += 8192)
                    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
                const f = { verb: "attach-add", uuid: id, name: name, data_b64: btoa(bin),
                            handle: window.__PROV.handle };
                return window.__PROV.send(JSON.stringify(f))
                    .catch((err) => ({ error: "session", detail: String(err && err.message || err) }));
            }, [uuid, a.name, a.text || "", a.chunk || "", a.bytes || 0]);
            it.ok(!!r && !r.error,
                  "attachment “" + a.name + "” (" + (r && r.size) + " bytes) added to " +
                  JSON.stringify(String(e.title).slice(0, 40)) +
                  (r && r.error ? " — " + JSON.stringify(r.error + ": " + (r.detail || "")) : ""));
        }
    }

    /* --- the recycle bin ----------------------------------------------- */
    if (spec.recycled) {
        const body = { title: spec.recycled.title };
        ["username", "password", "url", "notes", "expires"].forEach((k) => {
            if (spec.recycled[k] !== undefined) body[k] = spec.recycled[k];
        });
        if (spec.rich && spec.recycled.tags) body.tags = spec.recycled.tags;
        const add = await call(frame, "add", { group: map[""], entry: body });
        if (add && add.uuid) {
            /* `permanent` left FALSE: that is what makes it a recycle rather
             * than a delete. pykeepass creates the bin on first use. */
            const gone = await call(frame, "rm", { uuid: add.uuid, permanent: false });
            it.ok(!!gone && !gone.error && gone.recycled === true,
                  "one entry was deleted to the recycle bin (recycled=" +
                  JSON.stringify(gone && gone.recycled) + "), so the bin is not empty");
        } else {
            it.fail("the entry destined for the recycle bin could not be added: " +
                    JSON.stringify(add).slice(0, 150));
        }
    }

    /* --- one save ------------------------------------------------------ */
    const saved = await call(frame, "save", {});
    it.ok(!!saved && !saved.error && saved.ok === true,
          "the session wrote the safe to disk in one atomic save (" +
          JSON.stringify(saved && { bytes: saved.bytes, backup: !!saved.backup }) + ")" +
          (saved && saved.error ? " — " + JSON.stringify(saved.error + ": " + (saved.detail || "")) : ""));

    /* --- and read it back through the same session --------------------- */
    const back = await call(frame, "entries", { limit: 500 });
    const total = back && back.total;
    it.ok(typeof total === "number" && total >= spec.entries.length,
          "the helper reports " + total + " entries in the root listing scope");

    const finalTree = await call(frame, "tree", {});
    const finalMap = pathMap(finalTree && finalTree.groups, spec.format);
    it.ok(Object.keys(finalMap).length >= spec.groups.length + 1,
          Object.keys(finalMap).length + " group path(s) exist including the root" +
          (spec.recycled ? " and the recycle bin" : ""));

    await sessionStop(frame);
    return { total: total, groups: Object.keys(finalMap).length, uuids: uuids, map: finalMap };
}

/* ====================================================================== *
 * housekeeping
 * ====================================================================== */

/* Start from a known state. A previous run that died mid-item leaves a safe
 * registered, `safe-create` then answers `conflict` — correctly — and every
 * assertion below reads as a product failure when it is this suite's own
 * litter. Removed THROUGH THE HELPER, by id, with the token it demands;
 * never with an `rm` of a guessed path. */
async function removeOurs(frame, note) {
    /* A safe left read-only by a previous P5 refuses its own writes; the flip
     * back is done first so `safe-delete` is not fighting it. */
    await setMode(frame, IDS.psafe3, "rw").catch(() => null);
    for (const id of ALL_IDS) {
        guard(id);
        const admin = id === IDS.admin;
        const gone = await helper(frame, "safe-delete",
                                  { safe: id, delete_confirm: "delete-safe:" + id }, admin);
        if (gone && gone.ok && note) note("removed a leftover “" + id + "” from an earlier run");
    }
}

/* THE READ-ONLY FLIP, AND WHY IT IS NOT A UI FLOW.
 *
 * `mode` is a REGISTRY field ('ro' makes every write verb answer
 * access-denied before anything is serialized) and there is no verb that
 * edits a registry entry — by design: the registry is the thing the access
 * model is keyed on, and a verb that rewrote it would be a verb that could
 * re-class a safe. So the testbed sets it the way an operator would: by
 * editing the JSON file, in the account's OWN per-user registry directory,
 * with no escalation.
 *
 * The script carries no secret — an id and the word "ro" — so argv is the
 * right place for it (I10 is about credentials). Its first statement is the
 * guard: a path it did not build from a `dummy-fake-` id is refused, so this
 * cannot reach the operator's `pwsafe3.json` even if it were handed the id.
 * TESTBED.md records how to flip it back. */
const SET_MODE_PY = [
    "import json, os, sys, glob",
    "want, mode = sys.argv[1], sys.argv[2]",
    "assert want.startswith('dummy-fake-'), 'refused: not a testbed id'",
    "assert mode in ('rw', 'ro'), 'refused: not a mode'",
    "d = os.path.expanduser('~/.config/cockpit-secrets/safes.d')",
    "hits = []",
    "for f in sorted(glob.glob(os.path.join(d, '*.json'))):",
    "    try:",
    "        o = json.load(open(f))",
    "    except Exception:",
    "        continue",
    "    if o.get('id') != want:",
    "        continue",
    "    o['mode'] = mode",
    "    t = f + '.tmp'",
    "    fd = os.open(t, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)",
    "    with os.fdopen(fd, 'w') as h:",
    "        json.dump(o, h, indent=2, sort_keys=True)",
    "        h.write('\\n')",
    "    os.replace(t, f)",
    "    hits.append(os.path.basename(f))",
    "print(json.dumps({'changed': hits, 'mode': mode}))"
].join("\n");

async function setMode(frame, id, mode) {
    guard(id);
    return inPage(frame, ([script, want, m]) => new Promise((resolve) => {
        const p = cockpit.spawn(["python3", "-c", script, want, m], { err: "message" });
        p.then((out) => {
            try { resolve(JSON.parse(String(out).trim())); }
            catch (e) { resolve({ error: "parse", raw: String(out).slice(0, 200) }); }
        }).catch((err, out) => resolve({ error: "spawn", detail: String(out || err).slice(0, 200) }));
    }), [SET_MODE_PY, id, mode]);
}

/* ====================================================================== *
 * items
 * ====================================================================== */

/* IS THE PAGE IN THE BROWSE VIEW — asked the way live-ui.spec.js asks it.
 *
 * `waitForSelector("#sec-browse", {state:"visible"})` was the wrong question
 * and it cost a whole run: THERE IS NO `#sec-browse`. index.html has
 * `#sec-browse-view` (the section, which carries `hidden`), `#sec-browse-h`
 * (its heading) and `#sec-browse-tools`. So the wait timed out after two
 * minutes on a page that had unlocked the safe perfectly, the item was
 * recorded FAIL with an empty error string — because there was no error —
 * and then every LATER card's "Unlock…" button resolved to *hidden*, since
 * the page was sitting in the browse view this function had just decided it
 * was not in. One wrong id, three wrong verdicts, and the last two of them
 * looked like a product bug.
 *
 * `hidden` on the section is also the right property to watch rather than
 * CSS visibility: it is what `show()` in secrets.js toggles. */
function browseViewOpen() {
    const v = document.getElementById("sec-browse-view");
    return !!(v && !v.hidden);
}
function safesViewOpen() {
    const v = document.getElementById("sec-safes-view");
    return !!(v && !v.hidden);
}

/* Get back to the safe list whatever state the page is in, so the next card
 * is clickable. A browse view left open hides `#sec-safes-view` and every
 * later click fails with "resolved to hidden", which is a true statement
 * about the DOM and a useless one about the product. */
async function backToSafeList(frame) {
    if (await frame.evaluate(browseViewOpen).catch(() => false)) {
        await frame.click('button:text-is("Lock")').catch(() => null);
        await frame.waitForFunction(safesViewOpen, null, { timeout: 30000 }).catch(() => null);
    }
    await waitForSafeList(frame).catch(() => null);
}

async function itemUnlockInPage(frame, page, it, spec) {
    guard(spec.id);
    await backToSafeList(frame);
    await clickIn(frame, cardFor(spec.id) + ' button:text-is("Unlock…")');
    await frame.waitForSelector(M + " input[type=password]", { timeout: 20000 });
    await frame.fill(M + " input[type=password]", spec.pass);
    await clickIn(frame, M + ' button:text-is("Unlock")');
    const opened = await frame.waitForFunction(browseViewOpen, null, { timeout: 120000 })
                              .then(() => true).catch(() => false);
    it.ok(opened, "the page unlocked " + spec.id);
    if (!opened) {
        const err = await frame.textContent(M + " .sec-alert.err").catch(() => "");
        it.note("the dialog said: " + JSON.stringify(String(err).replace(/\s+/g, " ").slice(0, 200)));
        await closeModal(frame);
        await backToSafeList(frame);
        return;
    }
    const heading = (await frame.textContent("#sec-browse-h").catch(() => "") || "").trim();
    it.note("the browse heading reads " + JSON.stringify(heading.slice(0, 80)));
    await frame.waitForSelector("#sec-entries table.sec tbody tr", { timeout: 60000 }).catch(() => null);
    const caption = (await frame.textContent("#sec-entries caption").catch(() => "") || "").trim();
    const rows = await frame.locator("#sec-entries table.sec tbody tr").count();
    it.ok(rows > 0, "…and its entries render — " + rows + " row(s), caption " +
                    JSON.stringify(caption.slice(0, 60)));
    /* The group rail is `#sec-tree`, not `#sec-groups`. */
    const groups = await frame.locator("#sec-tree button, #sec-tree li").count().catch(() => 0);
    it.ok(groups > 0, "…and the group rail is populated — " + groups + " node(s)");
    if (spec.access === "user" && spec.format === "psafe3") {
        const warn = (await frame.textContent("#sec-browse-warnings").catch(() => "") || "")
                         .replace(/\s+/g, " ").trim();
        it.note("the browse view's warning strip reads " + JSON.stringify(warn.slice(0, 220)));
    }
    await H.shot(page, "open-" + spec.id);
    it.shot("open-" + spec.id + ".png");
    await backToSafeList(frame);
}

/* ====================================================================== *
 * main
 * ====================================================================== */

function skipAll(why) {
    ORDER.forEach((k) => { const it = REC.item(k, ITEMS[k]); it.skip(why); it.done(); });
}

async function main() {
    console.log("== cockpit-secrets · LIVE provisioning of the design testbed ==");
    console.log("   target " + H.CFG.url + "   credentials dir " + H.CFG.creds);
    console.log("   it will create: " + ALL_IDS.join(", "));
    console.log("   it will NEVER name: " + OPERATOR_SAFES.join(", ") +
                " (the operator's own safe)");

    const reasons = [];
    H.preconditions().filter((p) => !p.ok).forEach((p) => reasons.push(p.why));

    const who = H.CFG.admin;                       /* cptestadm — in `sudo` */
    const password = H.credential(who);
    if (!password)
        reasons.push("no Cockpit password for " + who + " at " +
                     path.join(H.CFG.creds, who + ".pass"));

    const passes = {};
    ALL_IDS.forEach((id) => {
        passes[id] = H.safePassphrase(id);
        if (!passes[id])
            reasons.push("no passphrase to create " + id + " WITH, at " +
                         path.join(H.CFG.creds, "safe-" + id + ".pass") + " — this suite " +
                         "never invents one, because a passphrase it made up is one " +
                         "nobody can use to check the file afterwards with keepassxc-cli. " +
                         "tests/browser/TESTBED.md has the command that writes it.");
    });

    if (reasons.length) { skipAll(reasons.join("; ")); return report(); }

    if (!(await H.checkLogin(who, password))) {
        skipAll("Cockpit refused " + who + "'s password; this suite never guesses and " +
                "never resets an account");
        return report();
    }

    const pw = H.requirePlaywright();
    const browser = await H.launch(pw);
    let ctx = null, page = null, frame = null;

    try {
        ctx = await H.newContext(browser);
        page = await H.login(ctx, who, password);

        /* ---------------------------------------------------------- P1 -- */
        const it1 = REC.item("P1", ITEMS.P1);
        console.log("\n\x1b[1mP1 · " + ITEMS.P1 + "\x1b[0m");
        frame = await escalate(page, it1, password);
        it1.done();
        if (!frame) {
            ["P2", "P3", "P4", "P5", "P6", "P7"].forEach((k) => {
                const it = REC.item(k, ITEMS[k]);
                it.skip("administrative access could not be turned on, so no admin-class " +
                        "safe can be created and the testbed would be incomplete");
                it.done();
            });
            return report();
        }

        /* Start clean — through the helper, by id, guarded. */
        console.log("\n  \x1b[2mclearing any leftover testbed from an earlier run\x1b[0m");
        await removeOurs(frame, (s) => console.log("  ....  " + s));
        await frame.waitForSelector("#sec-safes .sec-tools button", { timeout: 30000 })
                   .catch(() => null);

        const SPECS = {
            admin: {
                id: IDS.admin, label: "Dummy fake safe (admin, throw-away)",
                format: "kdbx", access: "admin", pass: passes[IDS.admin],
                groups: D.ADMIN_GROUPS, entries: D.adminEntries(),
                recycled: D.ADMIN_RECYCLED, attachments: true, rich: true
            },
            kdbx: {
                id: IDS.kdbx, label: "Dummy fake user safe (KDBX, throw-away)",
                format: "kdbx", access: "user", pass: passes[IDS.kdbx],
                groups: D.USER_KDBX_GROUPS, entries: D.userKdbxEntries(),
                recycled: null, attachments: false, rich: true
            },
            psafe3: {
                id: IDS.psafe3, label: "Dummy fake user safe (PWS3, throw-away)",
                format: "psafe3", access: "user", pass: passes[IDS.psafe3],
                groups: D.USER_PSAFE3_GROUPS, entries: D.userPsafe3Entries(),
                recycled: null, attachments: false, rich: false
            }
        };

        /* ---------------------------------------------------------- P2 -- */
        const it2 = REC.item("P2", ITEMS.P2);
        console.log("\n\x1b[1mP2 · " + ITEMS.P2 + "\x1b[0m");
        const madeAdmin = await createSafeViaForm(frame, page, it2, SPECS.admin);
        it2.done();

        /* ---------------------------------------------------------- P3 -- */
        const it3 = REC.item("P3", ITEMS.P3);
        console.log("\n\x1b[1mP3 · " + ITEMS.P3 + "\x1b[0m");
        if (!madeAdmin) it3.skip("dummy-fake-safe was not created, so there is nothing to fill");
        else {
            /* The awkward cases are a CHECKLIST, not a claim. */
            const present = D.adminEntries().map((e) => e.special).filter(Boolean);
            const absent = D.SPECIALS.filter((s) => present.indexOf(s) < 0);
            it3.ok(absent.length === 0,
                   D.SPECIALS.length + " named awkward cases are all present in the data set" +
                   (absent.length ? " — MISSING " + JSON.stringify(absent) : ""));
            it3.ok(D.url300().length === 300,
                   "the long URL is exactly " + D.url300().length + " characters");
            it3.ok(D.note40().split("\n").length === 40,
                   "the long note is exactly " + D.note40().split("\n").length + " lines");
            const eight = D.adminEntries().filter((e) => (e.tags || []).length === 8).length;
            const none = D.adminEntries().filter((e) => Array.isArray(e.tags) && e.tags.length === 0).length;
            it3.ok(eight >= 1 && none >= 1,
                   "one entry carries eight tags and " + none + " carr" +
                   (none === 1 ? "ies" : "y") + " none");
            it3.ok(D.PW.w1 === "password1" && D.PW.s4.length === 40,
                   "the password ladder runs from “password1” to " + D.PW.s4.length +
                   " characters of high entropy");

            const out = await populate(frame, it3, SPECS.admin);
            if (out) {
                it3.note("final: " + out.total + " entries reported, " + out.groups +
                         " group paths");
                const empty = out.map["Personal/Media"];
                it3.ok(typeof empty === "string",
                       "the deliberately EMPTY group Personal/Media exists");
            }
        }
        it3.done();

        /* ---------------------------------------------------------- P4 -- */
        const it4 = REC.item("P4", ITEMS.P4);
        console.log("\n\x1b[1mP4 · " + ITEMS.P4 + "\x1b[0m");
        const madeKdbx = await createSafeViaForm(frame, page, it4, SPECS.kdbx);
        if (madeKdbx) await populate(frame, it4, SPECS.kdbx);
        else it4.note("nothing to fill");
        it4.done();

        /* ---------------------------------------------------------- P5 -- */
        const it5 = REC.item("P5", ITEMS.P5);
        console.log("\n\x1b[1mP5 · " + ITEMS.P5 + "\x1b[0m");
        const madePws = await createSafeViaForm(frame, page, it5, SPECS.psafe3);
        if (madePws) {
            await populate(frame, it5, SPECS.psafe3);
            const flip = await setMode(frame, IDS.psafe3, "ro");
            it5.ok(!!flip && !flip.error && (flip.changed || []).length === 1,
                   "the PWS3 safe's registry entry is now mode=ro (" +
                   JSON.stringify(flip) + ") — the read-only state the design pass needs");
            /* And the page must SAY so. The reload is what makes the page
             * re-read the registry; the `catch` is because a frame that has
             * already begun navigating destroys its own execution context,
             * which Playwright reports as an error about a page that is doing
             * exactly what it was asked. */
            await frame.evaluate(() => location.reload()).catch(() => null);
            frame = await H.openPlugin(page);
            await waitForSafeList(frame);
            const card = (await frame.textContent(cardFor(IDS.psafe3)).catch(() => "") || "")
                             .replace(/\s+/g, " ");
            it5.ok(/read.?only/i.test(card),
                   "…and the safe list says so on the card: " + JSON.stringify(card.slice(0, 160)));
            await H.shot(page, "P5-readonly-card");
            it5.shot("P5-readonly-card.png");
        } else it5.note("nothing to fill");
        it5.done();

        /* ---------------------------------------------------------- P6 -- */
        const it6 = REC.item("P6", ITEMS.P6);
        console.log("\n\x1b[1mP6 · " + ITEMS.P6 + "\x1b[0m");
        await frame.evaluate(() => location.reload()).catch(() => null);
        frame = await H.openPlugin(page);
        await waitForSafeList(frame);
        await H.shot(page, "P6-safe-list");
        it6.shot("P6-safe-list.png");
        for (const key of ["admin", "kdbx", "psafe3"]) {
            const s = SPECS[key];
            const there = await frame.locator(cardFor(s.id)).count();
            if (!there) { it6.fail(s.id + " is not on the page"); continue; }
            await itemUnlockInPage(frame, page, it6, s);
        }
        it6.done();

        /* ---------------------------------------------------------- P7 -- */
        const it7 = REC.item("P7", ITEMS.P7);
        console.log("\n\x1b[1mP7 · " + ITEMS.P7 + "\x1b[0m");
        const rendered = await frame.$$eval("#sec-safes .sec-safe-id",
            (ns) => ns.map((n) => n.textContent.trim())).catch(() => []);
        it7.note("the page rendered: " + JSON.stringify(rendered));
        it7.ok(OPERATOR_SAFES.every((id) => rendered.indexOf(id) < 0),
               "no card for the operator's own safe was ever drawn, so no screenshot in " +
               "artifacts/ can contain it");
        const live = await H.liveList(frame);
        const listed = ((live && live.safes) || []).map((s) => s.id);
        it7.ok(OPERATOR_SAFES.every((id) => listed.indexOf(id) < 0),
               "…and the helper's own `list` for this principal does not return it either " +
               "(" + JSON.stringify(listed) + ")");
        let threw = false;
        try { guard("pwsafe3"); } catch (e) { threw = true; }
        it7.ok(threw, "the id guard throws on the operator's id, so no code path in this " +
                      "file can reach it even by mistake");
        it7.done();

    } catch (e) {
        const it = REC.item("P0", "the run itself");
        it.fail("the suite could not complete: " + String((e && e.stack) || e).slice(0, 600));
        it.done();
        try { if (page) await H.shot(page, "P0-crash"); } catch (e2) { /* nothing */ }
    } finally {
        /* NOTHING IS TORN DOWN. This suite's whole product is the three safes
         * it leaves behind — unlike live-registry.spec.js, which cleans up
         * because its safes are scaffolding. Removing them here would delete
         * the testbed the moment it was built. `removeOurs()` at the START is
         * what keeps re-runs idempotent. */
        try { if (frame) await sessionStop(frame); } catch (e) { /* nothing */ }
        try { if (ctx) await ctx.close(); } catch (e) { /* closing is not a test */ }
        try { await browser.close(); } catch (e) { /* same */ }
    }
    return report();
}

function report() {
    const s = REC.summary();
    console.log("\n\x1b[1m== live-provision · report ==\x1b[0m");
    ORDER.concat(["P0"]).forEach((k) => {
        const rec = s.items.find((i) => i.id === k);
        if (!rec) return;
        const state = rec.finished ? (rec.state || "PASS") : "INCOMPLETE";
        const colour = state === "PASS" ? "32" : (state === "NOT-ATTEMPTED" ? "33" : "31");
        console.log("  \x1b[" + colour + "m" + state.padEnd(14) + "\x1b[0m" + k + "  " + rec.title);
        if (rec.why) console.log("                " + rec.why);
    });
    console.log("  " + s.checks + " check(s), " + s.bad + " failed");
    console.log("\n  safes left behind: " + ALL_IDS.join(", "));
    console.log("  passphrases:       " + ALL_IDS.map((i) => path.join(H.CFG.creds, "safe-" + i + ".pass")).join("\n                     "));
    H.writeArtifact("live-provision-result.json", JSON.stringify(s.items, null, 2) + "\n");
    const incomplete = s.items.filter((i) => !i.finished).length;
    process.exitCode = (s.bad || incomplete) ? 1 : 0;
}

if (require.main === module) {
    main().catch((e) => {
        console.error("live-provision: " + String((e && e.stack) || e));
        process.exitCode = 1;
    });
}

module.exports = { IDS, ALL_IDS, OPERATOR_SAFES, guard, pathMap };
