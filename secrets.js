/* cockpit-secrets — the browser half: unlock, browse, reveal, manage.
 *
 * Vanilla JS in the idiom of cockpit-wireguard/source/wireguard.js and
 * cockpit-adlab/source/adlab.js. No framework, no bundler, no build step, no
 * CDN, no eval-family call, no WebAssembly — Cockpit's default policy is
 * default-src 'self' and this package adds no relaxation of it (I9).
 *
 * THE DESIGN RULE (cockpit-adlab's, and it is not negotiable here):
 * ================================================================
 *   THIS FILE RENDERS NOTHING IT INVENTED.
 *
 * Every control, label, enum, default, validation rule and help string comes
 * from `secrets-admin schema`, fetched once at load. Adding a field or a verb
 * to the helper must make it appear in this page with zero edits here. Where a
 * shape is pinned by docs/CONTRACT.md rather than by the schema (the eight
 * error codes, the keys of an `entries[]` row, which verbs carry a handle),
 * this file uses the contract as a FALLBACK and says so at the point of use —
 * contract-derived, never invented, and always overridable by the schema.
 *
 * WHERE THE PASSPHRASE LIVES, IN THIS FILE (docs/ARCHITECTURE.md, hop 2):
 * ======================================================================
 * In exactly one function-scoped variable inside submitUnlock(), for the length
 * of one cockpit.spawn call, and nowhere else. It is never assigned to a module
 * variable, a DOM property, a data attribute, a hidden field, a cookie or any
 * browser storage area (I11), and it never reaches argv or the environment —
 * the request is JSON written to the helper's stdin, which is then closed (I10).
 *
 * The honest limitation, stated here rather than papered over: a JavaScript
 * string is immutable, exactly like Python's. Overwriting the variable drops
 * the last reference so the collector can reclaim it; it does not scrub the
 * bytes. What this page can and does guarantee is that nothing retains a
 * reference, so an XSS that arrives one second later finds nothing to read.
 *
 * ACCESS CLASS (I3):
 * ==================
 * The page greys out a safe the caller cannot reach so that the list is honest
 * about what exists. THE GREYING IS DECORATION. The helper re-derives the
 * caller's identity from the kernel and re-checks the access class inside every
 * verb; that is what refuses. A sibling project (cockpit-guac-rdp, its I4)
 * shipped a browser-side check and had to tear it out when it turned out to be
 * bypassable by driving the backend directly.
 *
 * ------------------------------------------------------------------------
 * THE SCHEMA SHAPE THIS PAGE CONSUMES — `secrets-admin schema`, verified
 * against the helper itself rather than guessed at:
 *
 *   version        : int, the schema document's own version
 *   helper_version : string, shown in the header
 *   constants      : { reveal_seconds, session_idle_seconds,
 *                      session_max_seconds, lockout_threshold, ... }
 *   ui_rules       : [ sentence ]   — the helper's own rules for this page,
 *                                     rendered in the footer verbatim
 *   groups         : [ {id, title, order, help} ]
 *   enums          : { name: [ {value, label} ] }
 *   fields         : [ FIELD ]      — THE FIELD DICTIONARY, keyed by `id`.
 *                                     Verbs reference these by id.
 *   verbs          : [ {
 *       id, group, title, help, danger, mutates, confirm, audited,
 *       needs: "none"|"safe"|"handle",     — "handle" => run in the session
 *       access: "any"|"class",             — "class" => the safe's class
 *                                            decides which spawn shape
 *       stdin: bool,                       — false => the request goes on argv
 *       session_only: bool,                — only legal inside `open`
 *       request: [ field id, ... ],        — the form, by reference
 *       response: {...}, breaks_when_wrong } ]
 *
 *   FIELD = { id, label, control, type, required, secret, default, min, max,
 *             maxlength, options: [{value,label}]|null,
 *             options_from: "verb.path"|null,   — the option list comes from
 *                                                 a VERB, never from this file
 *             pattern, placeholder, help, breaks_when_wrong, unit,
 *             fields: [FIELD]|null,             — control "object": a subform
 *             partial: bool }                   — object: send only what changed
 *
 *   controls: the helper publishes the closed list as enums.control, and this
 *   page draws every one of them —
 *       text · password · password-reveal · number · toggle · select · radio ·
 *       textarea · tags · search · object · file-bytes · readonly · hidden
 *   plus the aliases a differently-shaped schema might use for the same thing.
 *
 * A control type this page does not know is drawn as text WITH A VISIBLE NOTE,
 * never dropped. Where the schema says nothing (the keys of an entries[] row,
 * for instance) the page falls back to what docs/CONTRACT.md pins and says so
 * at the point of use.
 *
 * ------------------------------------------------------------------------
 * THE SECOND WAVE OF CAPABILITIES, AND THE ONE RULE THEY ALL OBEY
 *
 * Export, save-as, the backup ring, entry history, attachment upload/replace/
 * removal, the strength meter, the breach check, the agent banner and the
 * YubiKey challenge are all rendered the same way everything else here is:
 * from the schema, or not at all. Each one is reached through verbFor(), which
 * asks the helper's own verb table for the name; when the helper does not
 * publish the verb, the control does not exist. There is no build of this page
 * that shows an Export button to a helper with no export verb.
 *
 * Three of them carry an extra gate beyond "the verb exists", because the verb
 * existing is not the same question as "may this safe do it":
 *
 *   EXPORT (I21)   also needs `export_allowed` on the safe's own `list` row,
 *                  and the row omitting the key means NO — the restrictive
 *                  default, the same way a registry entry with no `access` is
 *                  admin (I1). The confirm names the destination path in plain
 *                  words before the operator can proceed, and the result view
 *                  reports the path and the byte count and NOTHING ELSE: the
 *                  exported plaintext is never rendered in this browser.
 *
 *   BREACH         also needs the helper to say a corpus is configured. When it
 *                  answers available:false the page prints the REASON it gave;
 *                  the feature is never dropped silently, because "the button
 *                  is missing" and "there is no corpus" look identical from the
 *                  outside and only one of them is a configuration problem.
 *
 *   AGENT (I18)    is not a capability the page offers at all — it is a state
 *                  the page REPORTS. The banner exists only while the helper
 *                  says a safe is being held, it is above the view switch so it
 *                  survives navigating anywhere, and there is no placeholder
 *                  when nothing is held. An unlocked safe must never be
 *                  invisible; an agent that is off must not look like one that
 *                  is on and idle.
 * ------------------------------------------------------------------------
 */
(function () {
    "use strict";

    var HELPER = "/usr/local/sbin/secrets-admin";

    /* ------------------------------------------------------------------ *
     * Module state.
     *
     * Note what is NOT here: no passphrase, no revealed value, no key-file
     * bytes, no handle cache that outlives the session object. The handle
     * lives on the session because the session owns the process that owns it.
     * ------------------------------------------------------------------ */
    var SCHEMA = null;          // the helper's schema verb output
    var SAFES = [];             // the list verb output
    var PROBES = {};            // safe id -> probe result, or {_error: err}
    var PERM = null;            // cockpit.permission({admin:true})
    var SESSION = null;         // the one open unlock session, or null
    var BROWSE = null;          // the browse view's state for that session

    /* The agent's own state (I18). `rows` is what the helper last said it is
     * holding — never what this page decided; an empty array means the banner
     * is empty, which is the default because the agent is off by default.
     * Nothing in here is a handle: the page cannot use an agent's unlock, it
     * can only display it and ask for it to be locked. */
    var AGENT = { rows: [], timer: null, poll: null, said: "", failed: null,
                  polling: false };

    /* Breach-corpus availability, asked once per safe and cached for the page's
     * life. Per safe, not once globally, because the helper's breach verb is
     * `needs: "safe"` and `access: "class"` — whether a corpus is configured is
     * a question about a registry entry, and two safes need not answer it the
     * same way. Each entry is { state, reason, pending } where state is
     * "asking" | "yes" | "no" | "error". */
    var BREACH = {};

    /* The last `health` reply. It is the one verb that answers two questions
     * this page needs and cannot get anywhere else: what the unlock agent is
     * holding (I18), and where an export of a given safe would actually land
     * (I21) — the registry may override the default directory per entry, and
     * the confirm has to name the real destination, not a plausible one.
     * Fetched once at load, unescalated, and re-fetched only while there is an
     * agent to watch. */
    var HEALTH = null;

    /* Wipers: one function per rendered secret, so lock() scrubs the DOM
     * rather than merely navigating away from it (I17, task rule 7). */
    var WIPERS = [];

    var MASK_DEFAULT = "••••••••";

    /* Contract-derived fallbacks. Each one is overridden by the schema when the
     * schema says anything about the same thing. */
    var CONTRACT_SESSION_VERBS = {          // verbs that carry a handle
        "tree": 1, "entries": 1, "reveal": 1, "totp": 1, "attach-get": 1,
        "add": 1, "edit": 1, "move": 1, "rm": 1, "group-add": 1,
        "group-rm": 1, "group-mv": 1, "save": 1, "lock": 1
    };
    var CONTRACT_MUTATING = {               // success => unsaved changes on disk
        "add": 1, "edit": 1, "move": 1, "rm": 1,
        "group-add": 1, "group-rm": 1, "group-mv": 1
    };
    var CONTRACT_ENVELOPE = {               // args nest under this request key
        "add": "entry", "edit": "changes", "generate": "policy"
    };
    /* Verbs this page draws a purpose-built control for. Everything else the
     * helper offers is rendered automatically from its schema descriptor, which
     * is what makes "add a verb, get a button" true. */
    var HANDLED_VERBS = {
        "schema": 1, "list": 1, "probe": 1, "unlock": 1, "open": 1, "tree": 1,
        "entries": 1, "reveal": 1, "totp": 1, "attach-get": 1, "save": 1,
        "lock": 1, "add": 1, "edit": 1, "move": 1, "rm": 1, "group-add": 1,
        "group-rm": 1, "group-mv": 1, "generate": 1, "health": 1,
        "audit-tail": 1
    };
    /* Verb names docs/CONTRACT.md does NOT pin.
     *
     * The contract fixes the twenty-two verbs of the first build by name. The
     * capabilities added afterwards are fixed by SIGNATURE — the task brief
     * agreed `export_plain`, `save_as`, `history`, `history_restore`,
     * `attach_add`, `attach_rm` on the Backend ABC — but the helper is free to
     * spell the verb that carries each one however it likes.
     *
     * So this page does not hard-code a name; it asks the helper's verb table
     * for the first spelling it actually publishes. Each list below is ordered
     * most-likely-first and every entry is a name a reasonable helper might
     * choose for that signature. A helper that publishes none of them gets NO
     * control for that capability, which is the correct outcome: this page
     * renders nothing it invented, and a button that calls a verb the helper
     * does not have is exactly that.
     *
     * There is deliberately NO alias here for the agent. Its state does not
     * arrive through a verb of its own: `health` reports what the daemon is
     * holding, and `lock` accepts a bare safe id to release it. Both are
     * contract verbs with fixed names, so the agent banner needs no discovery
     * — see the agent section below. */
    var VERB_ALIASES = {
        "export":         ["export", "export-plain", "export-db", "export-database"],
        "saveAs":         ["save-as", "save_as", "saveas", "save-copy"],
        "backups":        ["backups", "backup-list", "backups-list", "backup-ls"],
        "restore":        ["restore", "backup-restore", "restore-backup"],
        "history":        ["history", "entry-history", "history-list"],
        "historyRestore": ["history-restore", "restore-history", "entry-restore"],
        "attachAdd":      ["attach-add", "attach-put", "attach-set"],
        "attachRm":       ["attach-rm", "attach-remove", "attach-del"],
        "attachList":     ["attach-list", "attachments", "attach-ls"],
        "strength":       ["strength", "password-strength", "strength-check"],
        "breach":         ["breach", "breach-check", "pwned", "hibp"],
        "yubikey":        ["yubikey-challenge", "yubikey", "challenge"]
    };

    /* The keys docs/CONTRACT.md pins for one entries[] row. Used only when the
     * schema declares no list columns. */
    var CONTRACT_LIST_COLUMNS = [
        { name: "title", label: "Title" },
        { name: "username", label: "Username" },
        { name: "url", label: "URL" },
        { name: "tags", label: "Tags" },
        { name: "has_totp", label: "TOTP" },
        { name: "attachments", label: "Attachments" },
        { name: "modified", label: "Modified" }
    ];

    /* ================================================================== *
     * Small DOM helpers — the house idiom. textContent everywhere, never
     * innerHTML: every string on this page came from a file an attacker may
     * control, and this page has no CSP relaxation to fall back on.
     * ================================================================== */
    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined && text !== null) n.textContent = String(text);
        return n;
    }
    function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
    function byId(id) { return document.getElementById(id); }
    function badge(text, kind) { return el("span", "sec-badge " + (kind || ""), text); }
    function show(n, yes) { if (n) n.hidden = !yes; }
    function btn(label, cls, onClick) {
        var b = el("button", "sec-btn " + (cls || ""), label);
        b.type = "button";
        if (onClick) b.addEventListener("click", onClick);
        return b;
    }
    function txt(v) {
        if (v === undefined || v === null) return "";
        if (Array.isArray(v))
            return v.map(function (x) {
                /* An array of OBJECTS — an attachment list is one, [{name,size}]
                 * — joined with the default toString gives "[object Object]",
                 * which is the least useful string in JavaScript and exactly
                 * what the entry metadata panel was printing. Prefer whatever
                 * the object calls itself; fall back to its JSON rather than to
                 * that. */
                if (x && typeof x === "object")
                    return String(x.name !== undefined ? x.name
                                : (x.label !== undefined ? x.label
                                : (x.id !== undefined ? x.id : JSON.stringify(x))));
                return String(x);
            }).join(", ");
        if (typeof v === "object") return JSON.stringify(v);
        return String(v);
    }
    function fmtSeconds(s) {
        s = Math.max(0, Math.round(Number(s) || 0));
        if (s < 60) return s + " s";
        var m = Math.floor(s / 60);
        var r = s % 60;
        return m + ":" + (r < 10 ? "0" : "") + r;
    }

    /* Byte counts, for backups, attachments and exports. Binary units because
     * that is what a file size is, and the exact figure in parentheses because
     * "1.4 MiB" is not enough to notice that yesterday's backup is a tenth of
     * the size of today's. */
    function fmtBytes(n) {
        var v = Number(n);
        if (!isFinite(v) || v < 0) return "";
        if (v < 1024) return v + " bytes";
        var units = ["KiB", "MiB", "GiB", "TiB"];
        var i = -1;
        var x = v;
        while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
        return x.toFixed(x < 10 ? 1 : 0) + " " + units[i] + " (" + v + " bytes)";
    }

    /* A timestamp from the helper, in the operator's own locale and zone.
     *
     * The helper writes UTC; the person reading the backup list is deciding
     * "is this the copy from before I broke it", and they think in local time.
     * Anything unparseable is printed verbatim rather than turned into
     * "Invalid Date" — the helper's string is more useful than our failure. */
    function fmtWhen(v) {
        if (v === undefined || v === null || v === "") return "";
        var d = (typeof v === "number") ? new Date(v * 1000) : new Date(String(v));
        if (!d || isNaN(d.getTime())) return String(v);
        try { return d.toLocaleString(); } catch (e) { return d.toISOString(); }
    }

    /* The polite live region: one sentence per state change. The visible
     * countdown digits are aria-hidden so a screen reader is not told the
     * number once a second. */
    function announce(text) {
        var n = byId("sec-live");
        if (n) n.textContent = text || "";
    }
    /* The assertive region: a failed unlock or a save conflict must interrupt. */
    function alertBox(node) {
        var host = byId("sec-alerts");
        clear(host);
        if (node) host.appendChild(node);
    }
    function alertText(msg, kind) {
        alertBox(el("div", "sec-alert " + (kind || "err"), msg));
    }

    /* ================================================================== *
     * Errors
     *
     * A helper error is one of the eight codes in docs/CONTRACT.md, arriving
     * as {"error": code, "detail": sentence} on stdout. A channel problem is
     * Cockpit's own and arrives as a rejection.
     *
     * `detail` is rendered VERBATIM. In particular bad-credential covers both
     * a wrong passphrase and a failed MAC, deliberately, and this page must not
     * add a distinction the helper refused to make — doing so would rebuild the
     * decryption oracle the coarse taxonomy exists to prevent (I6).
     * ================================================================== */
    var DENY_PROBLEMS = {
        "access-denied": 1, "authentication-failed": 1,
        "not-authorized": 1, "cancelled": 1
    };

    function mkErr(code, detail, extra) {
        var e = { code: String(code || "internal"), detail: String(detail || "") };
        if (extra && typeof extra === "object") {
            /* Carry through anything the helper attached for the UI to render,
             * e.g. the remaining lockout time on locked-out. Values are never
             * carried here — the helper does not put one in an error (I15). */
            if (extra.retry_after !== undefined) e.retry_after = extra.retry_after;
            if (extra.seconds_remaining !== undefined) e.seconds_remaining = extra.seconds_remaining;
            if (extra.locked_for !== undefined) e.locked_for = extra.locked_for;
        }
        return e;
    }
    function errCode(e) { return (e && e.code) || ""; }
    function errText(e) {
        if (!e) return "failed";
        if (e.detail) return e.detail;
        if (e.code) return e.code;
        return String(e.message || e);
    }
    /* The lockout countdown, if the helper attached one. */
    function errSeconds(e) {
        var v = e && (e.retry_after !== undefined ? e.retry_after
                    : e.seconds_remaining !== undefined ? e.seconds_remaining
                    : e.locked_for);
        v = Number(v);
        return isFinite(v) && v > 0 ? v : 0;
    }
    function errNode(e) {
        var box = el("div", "sec-alert err");
        box.appendChild(el("p", null, errText(e)));
        if (errCode(e)) {
            var p = el("p");
            p.appendChild(el("span", "sec-code", errCode(e)));
            if (errCode(e) === "locked-out" && errSeconds(e))
                p.appendChild(document.createTextNode(
                    " — try again in " + fmtSeconds(errSeconds(e)) + "."));
            box.appendChild(p);
        }
        return box;
    }
    /* Turn a Cockpit channel failure into the same eight-code shape. If the
     * helper managed to print its JSON before the non-zero exit, that wins. */
    function fromSpawnFailure(err, out) {
        var text = String(out === undefined || out === null ? "" : out).trim();
        if (text) {
            try {
                var obj = JSON.parse(text);
                if (obj && obj.error) return mkErr(obj.error, obj.detail, obj);
            } catch (e) { /* not JSON — fall through to the channel problem */ }
        }
        var problem = (err && err.problem) ? String(err.problem) : "";
        if (problem === "not-found")
            return mkErr("not-found", HELPER + " is not installed on this host.");
        if (DENY_PROBLEMS[problem])
            return mkErr("access-denied",
                "Administrative access is required and was not granted (" + problem + ").");
        return mkErr("internal", (err && (err.message || err.problem)) || "the helper failed");
    }

    /* ================================================================== *
     * Talking to the helper
     * ================================================================== */

    /* The user class runs the helper under the caller's own bridge with NO
     * escalation at all; the admin class asks Cockpit for its own standard
     * administrative prompt. We omit the key entirely on the user path rather
     * than passing superuser:null, so the two invocations in
     * docs/ARCHITECTURE.md are literally the two calls this page makes. */
    function spawnOpts(adminClass) {
        var o = { err: "message" };
        if (adminClass) o.superuser = "require";
        return o;
    }
    function isAdminClass(safe) {
        /* A registry entry that omits `access` is admin — the restrictive
         * default (I1). The helper resolves it the same way; this is only
         * deciding which of the two spawn shapes to use. */
        return !safe || !safe.access || safe.access === "admin";
    }

    function parseOneObject(out) {
        var text = String(out === undefined || out === null ? "" : out).trim();
        if (!text) throw mkErr("internal", "the helper produced no output");
        try { return JSON.parse(text); }
        catch (e) { throw mkErr("internal", "the helper did not produce one JSON object"); }
    }

    /* One verb, one process, request as JSON on stdin, stdin then CLOSED (I10).
     * `argvExtra` carries only non-secret arguments the schema marked on:"argv"
     * (audit-tail --n, for instance); addArgv() refuses to put a secret there. */
    function callOnce(verb, req, adminClass, argvExtra) {
        var argv = [HELPER, verb].concat(argvExtra || []);
        return new Promise(function (resolve, reject) {
            var proc = cockpit.spawn(argv, spawnOpts(adminClass));
            /* Always write a body, even an empty object: it is what closes the
             * child's stdin, and a helper that reads to EOF would otherwise
             * block forever on a bodyless verb. */
            proc.input(JSON.stringify(req === undefined || req === null ? {} : req));
            proc.then(function (out) {
                var obj;
                try { obj = parseOneObject(out); } catch (e) { reject(e); return; }
                if (obj && obj.error) reject(mkErr(obj.error, obj.detail, obj));
                else resolve(obj);
            }).catch(function (err, out) {
                reject(fromSpawnFailure(err, out));
            });
        });
    }

    /* --- the unlock session ------------------------------------------- *
     * A handle is bound to (uid, safe id, pid) and dies with the helper
     * process, so a browse-and-edit flow has to happen inside ONE invocation
     * held open on its stdin stream — docs/CONTRACT.md calls it the `open`
     * session, and docs/ARCHITECTURE.md explains why that shape IS the
     * prompt-every-time guarantee: closing this page closes the channel, which
     * kills the process, which ends the unlock. There is nowhere to put a
     * handle that outlives it, which is why there is no "remember" checkbox.
     *
     * Framing: one JSON request object per line on stdin, one JSON response
     * object per line on stdout, in order. The verb name travels in the frame
     * (default key "verb"); both the session verb and that key are overridable
     * from schema.ui.session so the helper stays the source of truth.
     */
    function sessionVerb() {
        var u = SCHEMA && SCHEMA.ui && SCHEMA.ui.session;
        return (u && u.verb) || "open";
    }
    function sessionRequestKey() {
        var u = SCHEMA && SCHEMA.ui && SCHEMA.ui.session;
        return (u && u.request_key) || "verb";
    }

    function openSession(safe) {
        var admin = isAdminClass(safe);
        var proc = cockpit.spawn([HELPER, sessionVerb()], spawnOpts(admin));
        var buf = "";
        var queue = [];
        var dead = null;

        var s = {
            safe: safe,
            admin: admin,
            handle: null,
            expiresAt: 0,
            closed: false,
            /* Filled in from the helper's opening banner: the timeouts it will
             * actually enforce, which the page shows rather than assumes. */
            idleSeconds: uiNum("session_idle_seconds", 0),
            maxSeconds: uiNum("session_max_seconds", 0),
            closeReason: "",
            onBanner: null
        };

        function die(e) {
            if (dead) return;
            dead = e || mkErr("internal", "the helper session ended");
            while (queue.length) queue.shift().reject(dead);
        }
        function deliver(line) {
            var obj = null;
            try { obj = JSON.parse(line); } catch (e) { obj = null; }
            /* The helper's session emits frames NOBODY asked for: a banner when
             * it opens, carrying the timeouts it will actually enforce, and a
             * closing frame naming why it ended. Answering a queued request
             * with one of those would shift every later reply by one and every
             * verb would get the previous verb's answer, so they are consumed
             * here and never dequeued.
             *
             * The helper tags them: an unsolicited frame carries a `frame` key
             * ("banner" or "closed") that no verb result ever sets. That tag is
             * the test. The shape test below it is the fallback for a helper
             * predating the tag, and it has to be exact — `session: true` on
             * its own is NOT it, because the unlock reply carries that flag too
             * to say it was issued inside a session, and treating that as a
             * banner silently loses the handle. */
            var tag = obj ? obj.frame : undefined;
            if (tag === "banner" ||
                (tag === undefined && obj && obj.session === true &&
                 obj.handle === undefined && obj.idle_seconds !== undefined &&
                 obj.max_seconds !== undefined)) {
                s.idleSeconds = Number(obj.idle_seconds) || s.idleSeconds;
                s.maxSeconds = Number(obj.max_seconds) || s.maxSeconds;
                if (s.onBanner) s.onBanner(obj);
                return;
            }
            if (tag === "closed" || (obj && obj.session_closed === true)) {
                s.closeReason = String(obj.reason || "");
                return;
            }
            var w = queue.shift();
            if (!w) return;                    /* unsolicited frame — ignore */
            if (!obj) { w.reject(mkErr("internal", "the helper sent a frame that is not JSON")); return; }
            if (obj.error) w.reject(mkErr(obj.error, obj.detail, obj));
            else w.resolve(obj);
        }
        function consume(chunk) {
            buf += String(chunk === undefined || chunk === null ? "" : chunk);
            var nl;
            while ((nl = buf.indexOf("\n")) >= 0) {
                var line = buf.slice(0, nl);
                buf = buf.slice(nl + 1);
                if (line.trim()) deliver(line);
            }
        }
        proc.stream(consume);
        proc.then(function () {
            if (buf.trim()) { consume("\n"); }
            die(mkErr("internal", "the helper session closed"));
        }).catch(function (err, out) {
            if (out) consume(String(out));
            die(fromSpawnFailure(err, out));
        });

        /* Send one frame. `body` may already be a serialized string — the
         * unlock path builds its own so the passphrase is never handed to a
         * generic serializer that might keep it somewhere. */
        s.send = function (body) {
            if (dead) return Promise.reject(dead);
            return new Promise(function (resolve, reject) {
                queue.push({ resolve: resolve, reject: reject });
                try {
                    /* The second argument keeps the stream open: this is the
                     * one place in the page where stdin is NOT closed after a
                     * write, because the session is exactly one process for
                     * several verbs. */
                    proc.input(body + "\n", true);
                } catch (e) {
                    queue.pop();
                    reject(mkErr("internal", "could not write to the helper session"));
                }
            });
        };
        s.call = function (verb, args) {
            var frame = {};
            Object.keys(args || {}).forEach(function (k) { frame[k] = args[k]; });
            frame[sessionRequestKey()] = verb;
            if (s.handle) frame.handle = s.handle;
            return s.send(JSON.stringify(frame));
        };
        /* True once the helper process is gone — which is also the moment every
         * key it derived is gone. The page uses this, and NOT an access-denied
         * from some individual verb, to decide the session is over: a
         * read-only safe answers access-denied to `edit` while the unlock is
         * perfectly alive, and locking on that would be wrong. */
        s.isDead = function () { return !!dead; };
        s.close = function () {
            if (s.closed) return;
            s.closed = true;
            die(mkErr("internal", "the session was closed"));
            try { proc.close("terminated"); } catch (e) { /* already gone */ }
        };
        return s;
    }

    /* ================================================================== *
     * Reading the schema
     * ================================================================== */
    /* A descriptor's identity: the helper calls it `id`; a dict-shaped schema
     * would call it `name`. Both are accepted, nothing else is invented. */
    function specName(spec) { return (spec && (spec.id || spec.name)) || ""; }

    function verbTable() {
        if (!SCHEMA) return {};
        var v = SCHEMA.verbs;
        if (!v) return {};
        if (Array.isArray(v)) {
            var out = {};
            v.forEach(function (spec) {
                var n = specName(spec);
                if (n) out[n] = spec;
            });
            return out;
        }
        return v;
    }

    /* The field dictionary: every request field of every verb, by id. */
    function fieldTable() {
        var out = {};
        if (!SCHEMA || !Array.isArray(SCHEMA.fields)) return out;
        SCHEMA.fields.forEach(function (f) {
            var n = specName(f);
            if (n) out[n] = f;
        });
        return out;
    }
    function fieldById(id) {
        var t = fieldTable();
        return Object.prototype.hasOwnProperty.call(t, id) ? t[id] : null;
    }
    function verbSpec(name) {
        var t = verbTable();
        return (name && Object.prototype.hasOwnProperty.call(t, name)) ? (t[name] || {}) : null;
    }
    function hasVerb(name) { return verbSpec(name) !== null; }
    /* First of several candidate names the helper actually offers. Used where
     * docs/CONTRACT.md leaves the name open (save-as, restore, history). */
    function findVerb(names) {
        for (var i = 0; i < names.length; i++)
            if (hasVerb(names[i])) return names[i];
        return null;
    }
    /* The name this helper actually publishes for one of the capabilities in
     * VERB_ALIASES, or null when it publishes none of them. Every second-wave
     * control on this page is behind one of these. */
    function verbFor(key) { return findVerb(VERB_ALIASES[key] || []); }

    /* Does this page already draw a purpose-built control for that verb?
     *
     * HANDLED_VERBS answers it for the twenty-two the contract names. The
     * second wave has to be resolved through the alias table instead, because
     * the name is the helper's choice — and the answer has to be right, or the
     * generic "every unhandled verb gets a button" loops below would put a
     * second, unlabelled Export button next to the purpose-built one that
     * carries the confirm. A generic button for `export` would be an export
     * with no warning attached, which is precisely the thing I21 forbids. */
    function isHandled(name) {
        if (HANDLED_VERBS[name]) return true;
        var keys = Object.keys(VERB_ALIASES);
        for (var i = 0; i < keys.length; i++)
            if (verbFor(keys[i]) === name) return true;
        return false;
    }
    /* A verb's form: its `request` list of field ids, resolved through the
     * field dictionary. A dict-shaped schema may inline `args` instead. */
    function verbArgs(name) {
        var spec = verbSpec(name);
        if (!spec) return [];
        if (Array.isArray(spec.args)) return spec.args;
        if (!Array.isArray(spec.request)) return [];
        var out = [];
        spec.request.forEach(function (id) {
            var f = fieldById(id);
            /* A request naming a field the dictionary does not define is a
             * schema bug. Draw a plain text control for it rather than
             * dropping the field silently — a missing control is the one
             * failure mode nobody notices. */
            out.push(f || { id: id, label: id, control: "text", type: "string",
                            required: false,
                            help: "This verb's request names “" + id + "”, which the " +
                                  "helper's field dictionary does not describe." });
        });
        return out;
    }
    function argNames(name) {
        var spec = verbSpec(name);
        if (spec && Array.isArray(spec.request)) return spec.request.slice();
        return verbArgs(name).map(specName);
    }
    function verbLabel(name) {
        var spec = verbSpec(name) || {};
        if (spec.title) return spec.title;
        if (spec.label) return spec.label;
        if (spec.help) return String(spec.help).replace(/\.$/, "");
        return name;
    }
    /* "needs": none | safe | handle. Only a handle verb has to run inside the
     * open session — everything else is one process, one operation. */
    function needsSession(name) {
        var spec = verbSpec(name) || {};
        if (spec.session_only) return true;
        if (spec.needs !== undefined) return spec.needs === "handle";
        if (spec.session !== undefined) return !!spec.session;
        if (argNames(name).indexOf("handle") >= 0) return true;
        return !!CONTRACT_SESSION_VERBS[name];
    }
    function mutates(name) {
        var spec = verbSpec(name) || {};
        if (spec.mutates !== undefined) return !!spec.mutates;
        return !!CONTRACT_MUTATING[name];
    }
    /* Does the request go on the child's stdin, or on argv? The helper says so
     * per verb. A field marked secret is NEVER allowed on argv whatever the
     * schema says — addArgv() refuses (I10). */
    function usesStdin(name) {
        var spec = verbSpec(name) || {};
        return spec.stdin === undefined ? true : !!spec.stdin;
    }
    /* An envelope is only needed when the helper did NOT describe the nesting
     * itself. The real schema does: `entry`, `changes` and `policy` are
     * request fields with control "object", so the generic form nests them
     * without any help from this table. */
    function envelopeFor(name) {
        var spec = verbSpec(name) || {};
        if (spec.envelope) return spec.envelope;
        if (verbArgs(name).length) return null;
        return CONTRACT_ENVELOPE[name] || null;
    }
    function verbScope(name) {
        var spec = verbSpec(name) || {};
        if (spec.scope) return spec.scope;
        var names = argNames(name);
        if (String(name).indexOf("group") === 0) return "group";
        if (names.indexOf("uuid") >= 0) return "entry";
        if (names.indexOf("group") >= 0) return "group";
        if (needsSession(name)) return "safe";
        return "global";
    }
    /* Numbers the page needs: the helper's `constants` first, then a `ui`
     * block if some other build of it publishes one, then the fallback. */
    function uiNum(key, fallback) {
        var c = SCHEMA && SCHEMA.constants ? Number(SCHEMA.constants[key]) : NaN;
        if (isFinite(c) && c > 0) return c;
        var v = SCHEMA && SCHEMA.ui ? Number(SCHEMA.ui[key]) : NaN;
        return (isFinite(v) && v > 0) ? v : fallback;
    }
    function maskString() {
        return (SCHEMA && SCHEMA.ui && SCHEMA.ui.mask) || MASK_DEFAULT;
    }
    /* Normalize an option list to [{value,label}], from `options` inline, from
     * `choices`, or by reference into schema.enums. `options_from` is resolved
     * separately because it names a VERB to ask. */
    function choicesFor(spec) {
        var raw = null;
        if (spec && Array.isArray(spec.options)) raw = spec.options;
        else if (spec && Array.isArray(spec.choices)) raw = spec.choices;
        else if (spec && spec["enum"] && SCHEMA && SCHEMA.enums) raw = SCHEMA.enums[spec["enum"]];
        if (!Array.isArray(raw)) return [];
        return raw.map(function (c) {
            if (c && typeof c === "object")
                return { value: c.value, label: c.label === undefined ? String(c.value) : String(c.label) };
            return { value: c, label: String(c) };
        });
    }
    /* `options_from: "list.safes"` / `"tree.groups"` — the option list comes
     * from a verb, never from this file (the helper's own ui_rules say so).
     * The two the helper uses today are already on screen, so they are served
     * from what the page last read rather than by spawning again. */
    function optionsFrom(spec) {
        var ref = spec && spec.options_from;
        if (!ref) return null;
        var parts = String(ref).split(".");
        var verb = parts[0], path = parts[1];
        var rows = null;
        if (verb === "list" && path === "safes") rows = SAFES;
        else if (verb === "tree" && path === "groups") rows = BROWSE ? BROWSE.groups : null;
        if (!Array.isArray(rows)) return null;
        return rows.map(function (r) {
            var value = r.uuid !== undefined ? r.uuid : r.id;
            var label = r.name !== undefined ? r.name : (r.label !== undefined ? r.label : value);
            return { value: value, label: String(label) };
        });
    }
    /* Which entry fields `reveal` will accept — straight out of the reveal
     * verb's own `field` descriptor, so adding a field to the helper adds a
     * reveal control here with no edit. */
    function revealFieldSpec() {
        /* The descriptor `reveal` actually uses for its `field` argument —
         * looked up through the verb rather than straight out of the field
         * dictionary, so it is found whether the schema references fields by
         * id or inlines them on the verb. */
        var args = verbArgs("reveal");
        for (var i = 0; i < args.length; i++)
            if (specName(args[i]) === "field") return args[i];
        return fieldById("field");
    }
    function revealFields() {
        var f = revealFieldSpec();
        var opts = choicesFor(f);
        if (opts.length) return opts;
        if (SCHEMA && SCHEMA.enums && Array.isArray(SCHEMA.enums.entry_field))
            return choicesFor({ options: SCHEMA.enums.entry_field });
        /* Nothing said: the field names docs/CONTRACT.md and both formats
         * guarantee. Contract-derived, not invented. */
        return [{ value: "password", label: "Password" },
                { value: "username", label: "Username" },
                { value: "url", label: "URL" },
                { value: "notes", label: "Notes" }];
    }
    function listColumns() {
        /* The helper's schema describes REQUEST fields, not the columns of an
         * entries[] row, so the columns come from the key set
         * docs/CONTRACT.md pins for that row. If a future schema publishes
         * `fields[].in_list`, that wins. */
        var declared = (SCHEMA && Array.isArray(SCHEMA.fields) ? SCHEMA.fields : [])
            .filter(function (f) { return f && f.in_list; });
        if (declared.length) {
            declared = declared.slice().sort(function (a, b) {
                return (Number(a.list_order) || 0) - (Number(b.list_order) || 0);
            });
            return declared.map(function (f) {
                return { name: specName(f), label: f.label || specName(f),
                         sortable: f.sortable !== false };
            });
        }
        return CONTRACT_LIST_COLUMNS.map(function (c) {
            return { name: c.name, label: c.label, sortable: true };
        });
    }

    /* ================================================================== *
     * Password strength, and the breach corpus
     *
     * Both are the helper's opinion, rendered. Neither is computed here, and
     * that is not laziness: a scorer written in this file would be a number
     * this page invented, and the whole design rule is that it does not invent
     * numbers. The helper owns the entropy model and the dictionary; this page
     * owns five rectangles and a sentence.
     *
     * THE COST, STATED PLAINLY. A live meter sends the candidate password to
     * the helper on every debounced keystroke, so the string leaves the browser
     * more than once instead of exactly once. It leaves the same way every
     * other secret does — as JSON on the helper's stdin, which is then closed;
     * never on argv, never in the environment (I10) — and no reference to it is
     * kept here between two calls. It is switched OFF for the unlock dialog,
     * where it would be both useless (the passphrase is whatever already opens
     * the file) and wasteful (N more copies of the master passphrase in flight
     * to answer a question nobody asked).
     * ================================================================== */

    /* Which request field a verb wants the candidate in. Read from the verb's
     * own descriptor — the first field it marks secret — so a helper that calls
     * it `candidate` or `value` instead of `password` works with no edit. */
    function secretArgName(verbName, fallback) {
        var args = verbArgs(verbName), i, n;
        for (i = 0; i < args.length; i++)
            if (isSecretSpec(args[i])) return specName(args[i]);
        /* No field is marked secret. Take the first that is not one of the
         * plumbing fields the caller supplies, rather than guessing a name. */
        for (i = 0; i < args.length; i++) {
            n = specName(args[i]);
            if (n && n !== "handle" && n !== "safe" && n !== "session") return n;
        }
        return fallback;
    }

    /* Send one candidate to one verb and drop our reference to it immediately.
     * Both call paths serialize the body synchronously — callOnce writes it
     * inside the Promise executor, and a session frame is stringified inside
     * send() — so by the time this returns, the value is on its way and the
     * object we built no longer needs to hold it. */
    function callWithCandidate(verbName, value, extra) {
        var field = secretArgName(verbName, "value");
        var inner = {};
        Object.keys(extra || {}).forEach(function (k) { inner[k] = extra[k]; });
        inner[field] = value;
        var env = envelopeFor(verbName);
        var body = inner;
        if (env) { body = {}; body[env] = inner; }
        var p = (needsSession(verbName) && SESSION)
            ? SESSION.call(verbName, body)
            : callOnce(verbName, body, adminForVerb(verbName));
        inner[field] = null;
        return p;
    }

    /* Availability of the breach corpus, asked once per safe.
     *
     * The helper's breach verb is `needs: "safe"`, and the question it answers
     * is "is a corpus configured for THIS registry entry" — so this asks with
     * the safe and no candidate. A helper with no corpus answers
     * {available:false, reason} and the reason is what gets printed; one that
     * has a corpus either says available:true or complains that the request is
     * missing its candidate, and both of those mean "the corpus is there, ask
     * properly".
     *
     * The outcome this refuses is a check that disappears in silence. "No
     * button" and "no corpus" look identical from the outside, and only one of
     * them is something an operator can go and fix — so an unavailable corpus
     * prints the helper's sentence where the button would have been.
     *
     * Note what is NOT sent here: no candidate. Asking whether the feature
     * exists must not cost a password.
     */
    function breachAvailability(safeId) {
        var key = safeId || "";
        var st = BREACH[key];
        if (st && st.pending) return st.pending;
        st = BREACH[key] = { state: "asking", reason: "", pending: null };
        var verb = verbFor("breach");
        if (!verb) {
            st.state = "no";
            st.pending = Promise.resolve(st);
            return st.pending;
        }
        var req = {};
        if (safeId) req.safe = safeId;
        st.pending = callOnce(verb, req, adminForVerb(verb, safeSpecById(safeId)))
        .then(function (res) {
            if (res && res.available === false) {
                st.state = "no";
                st.reason = String(res.reason || res.detail ||
                    "the helper reports no breach corpus is configured");
            } else {
                st.state = "yes";
                st.reason = "";
            }
            return st;
        }).catch(function (e) {
            /* "invalid" from a candidate-less request is the corpus saying it
             * is there and wants the real question. Anything else is reported
             * with the helper's own sentence rather than swallowed. */
            if (errCode(e) === "invalid") { st.state = "yes"; st.reason = ""; }
            else { st.state = "error"; st.reason = errText(e); }
            return st;
        });
        return st.pending;
    }

    /* The registry row for a safe id, for the escalation decision. */
    function safeSpecById(id) {
        if (!id) return null;
        for (var i = 0; i < SAFES.length; i++)
            if (SAFES[i] && SAFES[i].id === id) return SAFES[i];
        return null;
    }

    /* strengthWidget() -> { node, update(value), reset() }
     *
     * `update` is debounced; `reset` clears the readout and is what a control's
     * wipe() calls, so locking or clearing a form does not leave "18 bits,
     * found in 4 breaches" sitting under an emptied box. */
    function strengthWidget() {
        var verb = verbFor("strength");
        var breachVerb = verbFor("breach");
        var node = el("div", "sec-strength");
        var track = el("div", "sec-strength-track");
        var segs = [];
        var i;
        for (i = 0; i < 5; i++) {
            var sg = el("span", "sec-strength-seg");
            segs.push(sg);
            track.appendChild(sg);
        }
        track.hidden = true;
        track.setAttribute("aria-hidden", "true");   /* the text below IS the message */
        node.appendChild(track);

        /* One sentence per debounced answer, not one per keystroke: the region
         * is polite and atomic, and nothing writes to it while the operator is
         * still typing. */
        var text = el("div", "sec-strength-text");
        text.setAttribute("role", "status");
        text.setAttribute("aria-live", "polite");
        text.setAttribute("aria-atomic", "true");
        node.appendChild(text);
        var weak = el("ul", "sec-weak");
        weak.hidden = true;
        node.appendChild(weak);
        var breachLine = el("div", "sec-breach");
        node.appendChild(breachLine);

        var timer = null;
        var inFlight = 0;

        function paint(lit, total) {
            if (!isFinite(lit) || lit < 0 || !isFinite(total) || total <= 0) {
                /* No scale published, so no bar. Drawing five segments against
                 * a threshold this file made up would be this page inventing
                 * the verdict, which is the one thing it may not do. The
                 * entropy figure and the weaknesses below still say everything
                 * the helper actually said. */
                track.hidden = true;
                return;
            }
            track.hidden = false;
            /* The helper's five categories map one-for-one onto five segments
             * here. If it ever publishes a different number, the ratio still
             * holds and the bar still means what the helper said. */
            lit = Math.max(0, Math.min(segs.length, Math.round((lit / total) * segs.length)));
            var cls = lit <= 1 ? "bad" : (lit <= 3 ? "warn" : "on");
            segs.forEach(function (sg, ix) {
                sg.className = "sec-strength-seg" + (ix < lit ? " " + cls : "");
            });
        }

        function reset() {
            if (timer) { window.clearTimeout(timer); timer = null; }
            inFlight++;                       /* invalidate any answer in flight */
            text.textContent = "";
            clear(weak);
            weak.hidden = true;
            clear(breachLine);
            breachLine.className = "sec-breach";
            paint(NaN, NaN);
        }

        /* The helper publishes strength_category as an ORDERED list — very-weak,
         * weak, fair, strong, excellent — each with the effective-bit threshold
         * that defines it. THAT LIST IS THE SCALE, and it is the helper's,
         * which is the only reason this page is willing to draw a bar at all. A
         * helper that stops publishing it gets the text and no bar, rather than
         * five rectangles measured against a number invented here. */
        function categoryScale() {
            var e = SCHEMA && SCHEMA.enums && SCHEMA.enums.strength_category;
            return Array.isArray(e) ? e : [];
        }
        function categoryEntry(value) {
            var scale = categoryScale();
            for (var i = 0; i < scale.length; i++)
                if (String(scale[i].value) === String(value))
                    return { index: i, total: scale.length, spec: scale[i] };
            return null;
        }

        function render(res) {
            var bits = Number(res && res.entropy_bits);
            var eff = Number(res && res.effective_bits);
            var cat = categoryEntry(res && res.category);

            clear(text);
            /* effective_bits leads, because it is the figure the category is
             * derived from: raw entropy minus what each named weakness costs.
             * Both are shown when they differ, because the GAP is the finding —
             * "62 bits, 34 after its weaknesses" says more than either alone. */
            if (isFinite(eff)) {
                text.appendChild(el("span", "bits", Math.round(eff) + " bits"));
                text.appendChild(document.createTextNode(" of effective entropy"));
                if (isFinite(bits) && Math.round(bits) !== Math.round(eff))
                    text.appendChild(document.createTextNode(
                        " (" + Math.round(bits) + " before its weaknesses)"));
            } else if (isFinite(bits)) {
                text.appendChild(el("span", "bits", Math.round(bits) + " bits"));
                text.appendChild(document.createTextNode(" of entropy"));
            }
            if (cat) {
                text.appendChild(document.createTextNode(
                    (text.firstChild ? " — " : "") + String(cat.spec.label)));
                /* The threshold sentence the helper wrote for this category. It
                 * is the difference between being told "Fair" and knowing what
                 * fair buys you, and it is not this page's sentence to write. */
                if (cat.spec.help)
                    text.appendChild(el("span", "sec-subtle", ": " + String(cat.spec.help)));
            } else if (res && res.category) {
                text.appendChild(document.createTextNode(
                    (text.firstChild ? " — " : "") + String(res.category)));
            }
            if (!text.firstChild)
                text.appendChild(document.createTextNode(
                    "The helper answered, but named neither an entropy figure nor a category."));
            /* The arithmetic, when the helper shows its working. */
            if (res && res.calculation)
                text.appendChild(el("span", "sec-subtle", " " + String(res.calculation)));

            paint(cat ? cat.index + 1 : NaN, cat ? cat.total : NaN);

            clear(weak);
            var list = (res && (res.weaknesses || res.warnings || res.problems || res.issues));
            if (Array.isArray(list) && list.length) {
                list.forEach(function (w) {
                    /* The contract's weakness is {id, label, cost_bits}. The
                     * label names a CATEGORY of flaw and never quotes the text
                     * that triggered it — the helper is explicit that this is
                     * deliberate, because a response is a thing that gets
                     * screenshotted — so it is printed verbatim and nothing
                     * here tries to be more specific than the helper was. */
                    if (w && typeof w === "object") {
                        var li = el("li", null, String(w.label || w.id ||
                            w.detail || w.message || w.reason || ""));
                        if (w.cost_bits !== undefined)
                            li.appendChild(el("span", "sec-subtle",
                                "  −" + w.cost_bits + " bits"));
                        weak.appendChild(li);
                    } else {
                        weak.appendChild(el("li", null, String(w)));
                    }
                });
                weak.hidden = false;
            } else {
                weak.hidden = true;
            }
        }

        /* The breach control, drawn only after the helper has answered whether
         * a corpus exists. It is never automatic: a check sends the candidate
         * to whatever corpus the operator configured, and that is an explicit
         * act, not something a keystroke should trigger. */
        function drawBreach(getValue) {
            clear(breachLine);
            breachLine.className = "sec-breach";
            if (!breachVerb) return;
            /* The verb is per-safe, so the question and the check both carry
             * the safe currently open. Outside a session there is none, and
             * the helper answers for that. */
            var safeId = BROWSE ? BROWSE.safe.id : null;
            breachAvailability(safeId).then(function (b) {
                clear(breachLine);
                if (b.state === "no") {
                    breachLine.appendChild(el("span", "sec-subtle",
                        "Breach check unavailable — " +
                        (b.reason || "the helper did not say why") + "."));
                    return;
                }
                if (b.state === "error") {
                    breachLine.appendChild(el("span", "sec-subtle",
                        "Breach check could not be reached — " + b.reason));
                    return;
                }
                breachLine.appendChild(btn(verbLabel(breachVerb), "tiny", function () {
                    var v = getValue();
                    if (!v) {
                        clear(breachLine);
                        breachLine.appendChild(el("span", "sec-subtle",
                            "Type a password first."));
                        drawBreach(getValue);
                        return;
                    }
                    clear(breachLine);
                    breachLine.appendChild(el("span", "sec-subtle", "Checking…"));
                    callWithCandidate(breachVerb, v, safeId ? { safe: safeId } : null)
                    .then(function (res) {
                        v = null;
                        clear(breachLine);
                        if (res && res.available === false) {
                            breachLine.className = "sec-breach";
                            breachLine.appendChild(el("span", "sec-subtle",
                                "Breach check unavailable — " +
                                (res.reason || "the helper did not say why") + "."));
                            return;
                        }
                        var count = Number(res && (res.count !== undefined ? res.count : res.hits));
                        var found = res && (res.found === true || res.breached === true ||
                                            (isFinite(count) && count > 0));
                        breachLine.className = "sec-breach " + (found ? "hit" : "miss");
                        breachLine.appendChild(el("span", null, found
                            ? ("This password is in the corpus" +
                               (isFinite(count) && count > 0 ? " (" + count + " occurrence" +
                                   (count === 1 ? "" : "s") + ")" : "") +
                               ". Choose a different one.")
                            : "Not found in the configured corpus. That is not a guarantee " +
                              "it is unknown — only that this corpus has not seen it."));
                        /* The helper states, in its own contract, that this
                         * corpus is local and that there is no online
                         * fallback. Showing that is not decoration: the first
                         * question anyone sensible asks of a breach check is
                         * "did my password just leave this machine". */
                        if (res && (res.offline_only || res.network === "none"))
                            breachLine.appendChild(el("span", "sec-subtle",
                                " Checked against a local corpus only" +
                                (res.method ? " (" + res.method + ")" : "") +
                                "; nothing left this host."));
                        announce(found ? "This password was found in the breach corpus."
                                       : "This password was not found in the breach corpus.");
                    }).catch(function (e) {
                        v = null;
                        clear(breachLine);
                        breachLine.className = "sec-breach";
                        breachLine.appendChild(errNode(e));
                    });
                }));
            });
        }

        return {
            node: node,
            reset: reset,
            /* Called by the control's own change handler. `getValue` is a
             * function rather than a value so the candidate is read at the
             * moment it is sent, and this widget never holds one. */
            attach: function (getValue) {
                drawBreach(getValue);
                return function () {
                    var v = getValue();
                    if (timer) window.clearTimeout(timer);
                    if (!v) { reset(); drawBreach(getValue); return; }
                    if (!verb) return;
                    timer = window.setTimeout(function () {
                        var mine = ++inFlight;
                        var val = getValue();
                        if (!val) { reset(); drawBreach(getValue); return; }
                        callWithCandidate(verb, val).then(function (res) {
                            val = null;
                            if (mine !== inFlight) return;    /* a newer answer won */
                            render(res);
                        }).catch(function (e) {
                            val = null;
                            if (mine !== inFlight) return;
                            clear(text);
                            /* The meter failing must not look like a verdict. */
                            text.textContent = "Strength not available — " + errText(e);
                            clear(weak);
                            weak.hidden = true;
                            paint(NaN, NaN);
                        });
                    }, uiNum("strength_debounce_ms", 350));
                };
            }
        };
    }

    /* ================================================================== *
     * The generic control renderer — every input on this page comes from here
     * ================================================================== */
    var TYPE_ALIAS = {
        "str": "text", "string": "text", "text": "text", "path": "text",
        "url": "text", "email": "text", "uuid": "text", "search": "search",
        "password": "password", "secret": "password", "passphrase": "password",
        "password-stdin": "password", "protected": "password",
        /* The helper's own enums.control lists `password-reveal` as a distinct
         * control. It is the same input as `password` — the difference it names
         * is the Show/Hide affordance, which the password branch below already
         * draws for every password control, so mapping it here is not a
         * simplification that loses anything. Mapping it to `password` also
         * puts it on the right side of isSecretSpec(): a control that can show
         * a credential is treated as holding one whatever `secret` says. */
        "password-reveal": "password", "reveal": "password",
        "radio": "radio", "radiogroup": "radio",
        "readonly": "readonly", "static": "readonly", "display": "readonly",
        "textarea": "textarea", "multiline": "textarea", "notes": "textarea",
        "int": "int", "integer": "int", "number": "int",
        "float": "float", "double": "float",
        "bool": "bool", "boolean": "bool", "checkbox": "bool", "flag": "bool",
        "toggle": "bool", "switch": "bool",
        "enum": "enum", "select": "enum", "choice": "enum", "dropdown": "enum",
        "multi": "multi", "multienum": "multi", "flags": "multi", "set": "multi",
        "tags": "tags", "list": "tags", "strings": "tags", "array": "tags",
        "datetime": "datetime", "timestamp": "datetime", "expiry": "datetime",
        "date": "date",
        "file": "file", "file-b64": "file", "file-bytes": "file",
        "keyfile": "file", "attachment": "file",
        "object": "object", "subform": "object", "group": "object",
        "json": "json", "raw": "json",
        "info": "info", "note": "info",
        "hidden": "hidden"
    };
    /* `control` is what to DRAW; `type` is the JSON type it produces. The
     * helper publishes both, and the control wins — a "number" control whose
     * type is "integer" is still a number box. */
    function controlType(spec) {
        var c = spec && spec.control ? String(spec.control).toLowerCase() : "";
        var t = spec && spec.type ? String(spec.type).toLowerCase() : "";
        var kind = TYPE_ALIAS[c] || TYPE_ALIAS[t] || null;
        if (kind === "int" && (t === "float" || t === "number")) kind = "float";
        if (kind === "search") kind = "text";
        /* Two controls are refused for a field the helper marked secret, and
         * both refusals fail towards the password box rather than away from it.
         *
         *   radio     the only inputs on this page that carry a `name`, and a
         *             radio's value is visible on screen and in the a11y tree.
         *   readonly  prints its value as text; a credential printed with no
         *             countdown and no re-mask is the whole of what I17 exists
         *             to prevent.
         *
         * A schema that asked for either is a schema bug, but the failure mode
         * of complying is a plaintext credential on screen, so this page does
         * not comply. `spec.secret` is read directly rather than through
         * isSecretSpec(), which would call back into here. */
        if ((kind === "radio" || kind === "readonly") && spec && spec.secret === true)
            kind = "password";
        return kind;                          /* null => unknown, say so out loud */
    }
    function isSecretSpec(spec) {
        if (spec && spec.secret !== undefined) return !!spec.secret;
        return controlType(spec) === "password";
    }

    var CTRL_SEQ = 0;

    /* makeControl(spec, initial) -> {
     *     node, get(), set(v), focus(), wipe(), validate() -> string|null,
     *     spec, secret, setVisible(bool)
     * }
     * It renders what the descriptor asked for and nothing else. An unknown
     * type is rendered as text WITH A VISIBLE NOTE rather than dropped: a
     * silently missing control would break the design rule in the one direction
     * that cannot be noticed.
     */
    function makeControl(spec, initial) {
        var kind = controlType(spec);
        var unknown = null;
        if (!kind) { unknown = String(spec.control || spec.type); kind = "text"; }
        var fname = specName(spec);

        var id = "sec-c" + (++CTRL_SEQ);
        var wrap = el("div", "sec-field");
        /* `unit` qualifies a NUMBER ("900 seconds"). On a file picker it is
         * describing the max size, not the control, so it is not a suffix. */
        var showUnit = spec.unit && (kind === "int" || kind === "float");
        var label = el("label", null, (spec.label || fname) +
            (showUnit ? " (" + spec.unit + ")" : ""));
        label.setAttribute("for", id);
        if (spec.required === false) {
            var opt = el("span", "hint", " (optional)");
            label.appendChild(opt);
        }
        wrap.appendChild(label);
        if (spec.help) label.appendChild(el("span", "hint", spec.help));
        /* The helper says what goes wrong when this field is set wrong. That
         * sentence is the most useful thing on the form and it is not this
         * page's to write, so it is rendered verbatim. */
        if (spec.breaks_when_wrong)
            wrap.appendChild(el("div", "hint", String(spec.breaks_when_wrong)));
        if (unknown)
            wrap.appendChild(el("div", "sec-alert warn",
                "This helper declared the control “" + unknown +
                "”, which this page does not know how to draw. It is shown as " +
                "plain text so the field is not silently dropped."));

        var input = null, extra = null, fileBytes = null, sub = null;
        /* The two kinds whose value does not live in a DOM property: a
         * radiogroup with nothing checked, and a readonly display whose text is
         * a rendering of the value rather than the value itself (an array is
         * "a, b" on screen and must go back on the wire as an array). */
        var radioValue, readonlyValue;
        /* The strength/breach readout attached to a password control, so wipe()
         * can clear it: emptying the box must not leave the last verdict about
         * what used to be in it sitting underneath. */
        var strengthCtl = null;
        var errLine = el("div", "err");

        function attrs(n) {
            n.id = id;
            /* No name attribute anywhere in this page's inputs. A named field
             * is what autofill and a password manager look for, and this page
             * must never be autofilled with somebody's saved credential (I11). */
            if (spec.placeholder) n.setAttribute("placeholder", String(spec.placeholder));
            if (spec.maxlength) n.setAttribute("maxlength", String(spec.maxlength));
            return n;
        }

        switch (kind) {
        case "password":
            input = attrs(el("input"));
            input.type = "password";
            /* The four attributes that keep a browser, a password manager and a
             * spell checker away from a master passphrase (I11). */
            input.setAttribute("autocomplete", "off");
            input.setAttribute("spellcheck", "false");
            input.setAttribute("autocapitalize", "none");
            input.setAttribute("autocorrect", "off");
            wrap.appendChild(input);
            extra = el("div", "row");
            extra.appendChild(function () {
                var b = btn("Show", "tiny", function () {
                    var showing = input.type === "text";
                    input.type = showing ? "password" : "text";
                    b.textContent = showing ? "Show" : "Hide";
                    b.setAttribute("aria-pressed", showing ? "false" : "true");
                });
                b.setAttribute("aria-pressed", "false");
                return b;
            }());
            /* The generator is offered only when the helper offers the verb. */
            if (hasVerb("generate") && spec.generate !== false)
                extra.appendChild(btn("Generate…", "tiny", function () {
                    generateInto(input);
                }));
            wrap.appendChild(extra);
            /* The live meter and the breach control, when the helper offers the
             * verbs and the caller has not opted out. `spec.strength === false`
             * is set by exactly one caller — the unlock dialog — and its reason
             * is written there: scoring the passphrase that already opens a
             * file answers nothing and costs a copy of it in flight per
             * keystroke. */
            if (spec.strength !== false && (verbFor("strength") || verbFor("breach"))) {
                strengthCtl = strengthWidget();
                wrap.appendChild(strengthCtl.node);
                var onType = strengthCtl.attach(function () { return input.value; });
                input.addEventListener("input", onType);
                /* generateInto() dispatches this after writing a generated
                 * value, so the meter scores what the generator produced
                 * instead of going quiet the moment the box stops being typed
                 * into by hand. */
                input.addEventListener("change", onType);
            }
            break;
        case "textarea":
            input = attrs(el("textarea"));
            input.setAttribute("spellcheck", "false");
            wrap.appendChild(input);
            break;
        case "int":
        case "float":
            input = attrs(el("input"));
            input.type = "number";
            if (kind === "float") input.setAttribute("step", "any");
            if (spec.min !== undefined) input.setAttribute("min", String(spec.min));
            if (spec.max !== undefined) input.setAttribute("max", String(spec.max));
            wrap.appendChild(input);
            break;
        case "bool":
            clear(wrap);
            input = el("input");
            input.type = "checkbox";
            input.id = id;
            var lb = el("label", "sec-check");
            lb.setAttribute("for", id);
            lb.appendChild(input);
            lb.appendChild(el("span", null, spec.label || fname));
            wrap.appendChild(lb);
            if (spec.help) wrap.appendChild(el("div", "hint", spec.help));
            if (spec.breaks_when_wrong)
                wrap.appendChild(el("div", "hint", String(spec.breaks_when_wrong)));
            break;
        case "enum": {
            input = attrs(el("select"));
            if (!spec.required) input.appendChild(el("option", null, ""));
            /* Inline options first, then whatever verb `options_from` names.
             * The list is never written here (the helper's own ui_rules). */
            var opts = choicesFor(spec);
            if (!opts.length) opts = optionsFrom(spec) || [];
            opts.forEach(function (c) {
                var o = el("option", null, c.label);
                o.value = String(c.value);
                input.appendChild(o);
            });
            if (!opts.length && spec.options_from)
                wrap.appendChild(el("div", "hint",
                    "The option list for this control comes from the “" +
                    spec.options_from + "” verb, which has not been read yet."));
            wrap.appendChild(input);
            break;
        }
        case "radio": {
            /* A radiogroup is not a <select> with a different skin: it is a
             * group, and a group needs a <fieldset>/<legend> or a screen reader
             * reads five orphaned options with no idea what question they
             * answer. So the <label for> built above is discarded and rebuilt
             * as a legend.
             *
             * These are the only inputs on this page that carry a `name`, and
             * the reason is native behaviour: without a shared name the browser
             * does not treat them as one group, arrow keys stop working, and
             * more than one can be checked at a time. The name is this
             * control's own generated id ("sec-c17-radio"), not a field name —
             * nothing an autofill heuristic looks for — and radioSafe below
             * refuses the control outright for a secret field, so a credential
             * can never reach one. */
            clear(wrap);
            var fs = el("fieldset", "sec-radios");
            var lg = el("legend", null, spec.label || fname);
            fs.appendChild(lg);
            if (spec.help) fs.appendChild(el("div", "hint", spec.help));
            if (spec.breaks_when_wrong)
                fs.appendChild(el("div", "hint", String(spec.breaks_when_wrong)));
            input = el("div", "sec-radiolist");
            input.id = id;
            var ropts = choicesFor(spec);
            if (!ropts.length) ropts = optionsFrom(spec) || [];
            ropts.forEach(function (c, ix) {
                var rid = id + "-r" + ix;
                var rb = el("input");
                rb.type = "radio";
                rb.id = rid;
                rb.name = id + "-radio";
                rb.value = String(c.value);
                var rl = el("label", "sec-check");
                rl.setAttribute("for", rid);
                rl.appendChild(rb);
                rl.appendChild(el("span", null, c.label));
                input.appendChild(rl);
            });
            if (!ropts.length && spec.options_from)
                fs.appendChild(el("div", "hint",
                    "The option list for this control comes from the “" +
                    spec.options_from + "” verb, which has not been read yet."));
            fs.appendChild(input);
            wrap.appendChild(fs);
            break;
        }
        case "readonly":
            /* A value the helper fixed and the operator may not change, shown
             * so the request is not a black box. It still travels in the
             * request: hiding a value that is about to be sent is worse than
             * showing one that cannot be edited. */
            input = el("div", "sec-readonly");
            input.id = id;
            wrap.appendChild(input);
            break;
        case "multi":
            input = el("div", "sec-checklist");
            input.id = id;
            choicesFor(spec).forEach(function (c) {
                var cid = id + "-" + String(c.value).replace(/[^A-Za-z0-9_-]/g, "");
                var cb = el("input");
                cb.type = "checkbox";
                cb.id = cid;
                cb.value = String(c.value);
                var l = el("label", "sec-check");
                l.setAttribute("for", cid);
                l.appendChild(cb);
                l.appendChild(el("span", null, c.label));
                input.appendChild(l);
            });
            wrap.appendChild(input);
            break;
        case "tags":
            input = attrs(el("input"));
            input.type = "text";
            if (!spec.placeholder) input.setAttribute("placeholder", "comma separated");
            wrap.appendChild(input);
            break;
        case "datetime":
        case "date":
            input = attrs(el("input"));
            input.type = (kind === "date") ? "date" : "datetime-local";
            wrap.appendChild(input);
            break;
        case "file":
            input = el("input");
            input.type = "file";
            input.id = id;
            wrap.appendChild(input);
            var sizeNote = el("div", "hint");
            wrap.appendChild(sizeNote);
            input.addEventListener("change", function () {
                fileBytes = null;
                sizeNote.textContent = "";
                var f = input.files && input.files[0];
                if (!f) return;
                /* The helper publishes the cap: `max` on a file-bytes field,
                 * or max_bytes on a dict-shaped schema. But the cap that
                 * actually bites is usually the TRANSPORT: these bytes travel
                 * base64 inside the one JSON request, which the helper caps at
                 * constants.max_request_bytes, and base64 costs a third. A
                 * control that accepted 32 MiB because the format allows it
                 * would fail at a tenth of that with an error about request
                 * size, which is a bewildering way to learn the real limit.
                 * Both numbers are the helper's; neither is enforced here. */
                var declared = Number(spec.max_bytes) || Number(spec.max) || 0;
                var reqCap = Number((SCHEMA && SCHEMA.constants &&
                                     SCHEMA.constants.max_request_bytes) || 0);
                var transport = reqCap ? Math.floor((reqCap * 3 / 4) - 4096) : 0;
                var cap = (declared && transport) ? Math.min(declared, transport)
                                                  : (declared || transport || 0);
                if (cap && f.size > cap) {
                    sizeNote.textContent = "That file is " + fmtBytes(f.size) +
                        "; at most " + fmtBytes(cap) + " fits through the helper's request" +
                        (transport && cap === transport && declared > transport
                            ? " (the format itself allows " + fmtBytes(declared) +
                              ", but the request is capped below it)"
                            : "") + ".";
                    input.value = "";
                    return;
                }
                var r = new FileReader();
                r.onload = function () {
                    /* The bytes go into the JSON request on the helper's stdin
                     * and nowhere else — never a temp file on the server, never
                     * a browser storage area (I10, I11, I21). */
                    fileBytes = bytesToB64(new Uint8Array(r.result));
                    sizeNote.textContent = f.name + " — " + f.size + " bytes, sent inline.";
                };
                r.onerror = function () { sizeNote.textContent = "Could not read that file."; };
                r.readAsArrayBuffer(f);
            });
            break;
        case "object":
            /* A subform, described by the same FIELD shape one level down.
             * This is how `add` gets its entry, `edit` its changes and
             * `generate` its policy — the nesting is the helper's, declared in
             * the schema, not a table in this file. */
            sub = buildForm(Array.isArray(spec.fields) ? spec.fields : []);
            wrap.appendChild(sub.node);
            if (spec.partial)
                wrap.appendChild(el("div", "hint",
                    "Only the fields you fill in are sent; anything left blank " +
                    "is left as it is in the safe."));
            break;
        case "json":
            input = attrs(el("textarea"));
            input.setAttribute("spellcheck", "false");
            wrap.appendChild(input);
            break;
        case "info":
            clear(wrap);
            wrap.appendChild(el("div", "sec-alert info", spec.help || spec.label || ""));
            break;
        case "hidden":
            wrap.hidden = true;
            break;
        default:
            input = attrs(el("input"));
            input.type = "text";
            wrap.appendChild(input);
            break;
        }
        wrap.appendChild(errLine);

        function setValue(v) {
            if (kind === "object") {
                if (sub && v && typeof v === "object")
                    Object.keys(v).forEach(function (k) {
                        if (sub.byName[k]) sub.byName[k].set(v[k]);
                    });
                return;
            }
            if (!input) return;
            if (kind === "bool") { input.checked = !!v; return; }
            if (kind === "radio") {
                /* held separately: an unchecked radiogroup and a group whose
                 * value is the empty string are different answers, and the DOM
                 * cannot tell them apart once nothing is checked. */
                radioValue = (v === undefined || v === null) ? undefined : String(v);
                Array.prototype.forEach.call(input.querySelectorAll("input"), function (rb) {
                    rb.checked = (rb.value === radioValue);
                });
                return;
            }
            if (kind === "readonly") {
                readonlyValue = v;
                input.textContent = (v === undefined || v === null) ? "—" : txt(v);
                return;
            }
            if (kind === "multi") {
                var want = Array.isArray(v) ? v.map(String) : [];
                Array.prototype.forEach.call(input.querySelectorAll("input"), function (cb) {
                    cb.checked = want.indexOf(cb.value) >= 0;
                });
                return;
            }
            if (kind === "file") return;                 /* a file input cannot be set */
            if (kind === "tags") { input.value = Array.isArray(v) ? v.join(", ") : txt(v); return; }
            if (kind === "json") { input.value = (v === undefined || v === null) ? "" : JSON.stringify(v, null, 2); return; }
            input.value = (v === undefined || v === null) ? "" : String(v);
        }

        function getValue() {
            /* An object control returns the NON-SECRET half of its subform;
             * nested secrets are collected separately by applySecrets(), so
             * values() stays secret-free at every depth (I11). */
            if (kind === "object") {
                if (!sub) return undefined;
                var o = sub.values();
                if (spec.partial)
                    Object.keys(o).forEach(function (k) {
                        var val = o[k];
                        if (val === undefined || val === null || val === "" ||
                            (Array.isArray(val) && !val.length)) delete o[k];
                    });
                return o;
            }
            if (!input) return undefined;
            switch (kind) {
            case "bool": return !!input.checked;
            case "readonly": return readonlyValue;
            case "radio": {
                var picked = input.querySelector("input:checked");
                return picked ? picked.value : undefined;
            }
            case "multi":
                return Array.prototype.filter.call(input.querySelectorAll("input"), function (cb) {
                    return cb.checked;
                }).map(function (cb) { return cb.value; });
            case "file": return fileBytes;
            case "tags":
                return String(input.value).split(",").map(function (t) { return t.trim(); })
                    .filter(function (t) { return t.length; });
            case "int": {
                var s = String(input.value).trim();
                if (!s) return undefined;
                var n = parseInt(s, 10);
                return isFinite(n) ? n : undefined;
            }
            case "float": {
                var sf = String(input.value).trim();
                if (!sf) return undefined;
                var nf = parseFloat(sf);
                return isFinite(nf) ? nf : undefined;
            }
            case "json": {
                var sj = String(input.value).trim();
                if (!sj) return undefined;
                try { return JSON.parse(sj); } catch (e) { return undefined; }
            }
            case "datetime":
            case "date": {
                var sd = String(input.value).trim();
                return sd ? sd : undefined;
            }
            default: {
                var sv = String(input.value);
                return sv.length ? sv : undefined;
            }
            }
        }

        function validate() {
            if (kind === "object") return sub ? sub.validate() : null;
            var v = getValue();
            var empty = (v === undefined || v === null || v === "" ||
                         (Array.isArray(v) && !v.length));
            if (spec.required && empty)
                return (spec.label || fname) + " is required.";
            if (empty) return null;
            if (kind === "json" && String(input.value).trim() && v === undefined)
                return (spec.label || fname) + " is not valid JSON.";
            if ((kind === "int" || kind === "float")) {
                if (spec.min !== undefined && spec.min !== null && v < Number(spec.min))
                    return (spec.label || fname) + " must be at least " + spec.min + ".";
                if (spec.max !== undefined && spec.max !== null && v > Number(spec.max))
                    return (spec.label || fname) + " must be at most " + spec.max + ".";
            }
            if (typeof v === "string") {
                if (spec.minlength && v.length < Number(spec.minlength))
                    return (spec.label || fname) + " must be at least " + spec.minlength + " characters.";
                if (spec.maxlength && v.length > Number(spec.maxlength))
                    return (spec.label || fname) + " must be at most " + spec.maxlength + " characters.";
                if (spec.pattern) {
                    /* A RegExp built from a schema string. This is pattern
                     * compilation, not code execution — no eval-family call is
                     * used anywhere in this file (I9). */
                    var re = null;
                    try { re = new RegExp(String(spec.pattern)); } catch (e) { re = null; }
                    if (re && !re.test(v))
                        return spec.error || ((spec.label || fname) + " is not in the required form.");
                }
            }
            return null;
        }

        var ctrl = {
            spec: spec,
            kind: kind,
            node: wrap,
            sub: null,                        /* set below for control "object" */
            secret: isSecretSpec(spec),
            get: getValue,
            set: setValue,
            focus: function () {
                if (kind === "object") { if (sub) sub.focusFirst(); return; }
                if (kind === "readonly") return;     /* nothing to type into */
                /* A radiogroup and a checklist are <div>s holding the real
                 * inputs: a div has a .focus method and calling it does
                 * nothing, so focus the checked option, or the first one. */
                if (kind === "radio" || kind === "multi") {
                    var target = input && (input.querySelector("input:checked") ||
                                           input.querySelector("input"));
                    if (target) target.focus();
                    return;
                }
                if (input && input.focus) input.focus();
            },
            setVisible: function (yes) { wrap.hidden = !yes; },
            visible: function () { return !wrap.hidden; },
            onChange: function (fn) {
                if (kind === "object") {
                    if (sub) sub.controls.forEach(function (c) { c.onChange(fn); });
                    return;
                }
                if (!input) return;
                if (kind === "readonly") return;      /* nothing can change it */
                if (kind === "multi" || kind === "radio") {
                    Array.prototype.forEach.call(input.querySelectorAll("input"), function (cb) {
                        cb.addEventListener("change", fn);
                    });
                } else {
                    input.addEventListener("input", fn);
                    input.addEventListener("change", fn);
                }
            },
            validate: function () {
                var msg = wrap.hidden ? null : validate();
                errLine.textContent = msg || "";
                if (msg) wrap.classList.add("invalid"); else wrap.classList.remove("invalid");
                return msg;
            },
            /* Scrub whatever the control is holding. For a password control
             * this blanks the element's value, reassigns it, and blanks it
             * again — hygiene so the node does not carry the last string with
             * it when it is discarded. The browser owns that memory; this is
             * not a wipe and the page footer says so. */
            wipe: function () {
                fileBytes = null;
                if (strengthCtl) strengthCtl.reset();
                if (kind === "object") { if (sub) sub.wipeAll(); return; }
                if (!input) return;
                try {
                    if (kind === "bool") { input.checked = false; return; }
                    if (kind === "readonly") {
                        readonlyValue = null;
                        input.textContent = "";
                        return;
                    }
                    if (kind === "radio" || kind === "multi") {
                        radioValue = undefined;
                        Array.prototype.forEach.call(input.querySelectorAll("input"), function (cb) {
                            cb.checked = false;
                        });
                        return;
                    }
                    var n = String(input.value || "").length;
                    input.value = "";
                    if (n) input.value = new Array(n + 1).join("\u0000");
                    input.value = "";
                    if (input.setAttribute) input.setAttribute("value", "");
                } catch (e) { /* a detached node is fine to fail on */ }
            }
        };
        ctrl.sub = sub;
        if (initial !== undefined) setValue(initial);
        else if (spec["default"] !== undefined && spec["default"] !== null)
            setValue(spec["default"]);
        return ctrl;
    }

    /* buildForm(specs, opts) -> {
     *     node, controls, values(), readSecret(name), secretNames(),
     *     validate(), wipeSecrets(), focusFirst()
     * }
     *
     * NOTE the split: values() returns the NON-secret values only. A secret is
     * read one at a time, on demand, by readSecret(), so a caller can keep it
     * in exactly one function-scoped variable for exactly one call instead of
     * receiving it inside a bag of other values that outlives the request (I11).
     *
     * The container is a <div>, never a <form>. A form can be submitted by a
     * stray Enter and is what autofill looks for.
     */
    function buildForm(specs, opts) {
        opts = opts || {};
        var node = el("div", "sec-form");
        var controls = [];
        var byName = {};

        (specs || []).forEach(function (spec) {
            var fname = specName(spec);
            if (!spec || !fname) return;
            if (opts.omit && opts.omit.indexOf(fname) >= 0) return;
            var initial = (opts.values && opts.values[fname] !== undefined)
                ? opts.values[fname] : undefined;
            var c = makeControl(spec, initial);
            controls.push(c);
            byName[fname] = c;
            node.appendChild(c.node);
        });

        /* depends_on: a control is shown only while another control's value
         * matches. Declared by the schema, evaluated here. */
        function applyDeps() {
            controls.forEach(function (c) {
                var d = c.spec.depends_on;
                if (!d || !d.field) return;
                var other = byName[d.field];
                if (!other) return;
                var v = other.get();
                var ok;
                if (Array.isArray(d["in"])) ok = d["in"].map(String).indexOf(String(v)) >= 0;
                else if (d.value !== undefined) ok = String(v) === String(d.value);
                else ok = !(v === undefined || v === null || v === "" || v === false);
                c.setVisible(!!ok);
            });
        }
        controls.forEach(function (c) { c.onChange(applyDeps); });
        applyDeps();

        return {
            node: node,
            controls: controls,
            byName: byName,
            focusFirst: function () {
                for (var i = 0; i < controls.length; i++)
                    if (controls[i].visible()) { controls[i].focus(); return; }
            },
            validate: function () {
                var first = null;
                controls.forEach(function (c) {
                    var m = c.validate();
                    if (m && !first) first = m;
                });
                return first;
            },
            secretNames: function () {
                return controls.filter(function (c) { return c.secret; })
                    .map(function (c) { return specName(c.spec); });
            },
            /* Non-secret values only. */
            values: function () {
                var out = {};
                controls.forEach(function (c) {
                    if (c.secret || !c.visible()) return;
                    var v = c.get();
                    if (v !== undefined) out[specName(c.spec)] = v;
                });
                return out;
            },
            readSecret: function (name) {
                var c = byName[name];
                if (!c) return null;
                var v = c.get();
                return (v === undefined || v === null) ? null : v;
            },
            /* Write every secret this form is holding into `target`, including
             * the ones nested inside an object control, and hold none of them
             * afterwards. Called immediately before the request is serialized
             * so the window between reading a secret and sending it is a
             * couple of statements wide (I11). */
            applySecrets: function (target) {
                controls.forEach(function (c) {
                    if (!c.visible()) return;
                    var n = specName(c.spec);
                    if (c.secret) {
                        var v = c.get();
                        if (v !== undefined && v !== null && v !== "") target[n] = v;
                        v = null;
                        return;
                    }
                    if (c.kind === "object" && c.sub) {
                        var nested = target[n];
                        if (!nested || typeof nested !== "object") {
                            nested = {};
                            /* Only create the nesting if there is something to
                             * put in it — an untouched optional subform must
                             * not turn into an empty object in the request. */
                            var before = Object.keys(nested).length;
                            c.sub.applySecrets(nested);
                            if (Object.keys(nested).length > before) target[n] = nested;
                        } else {
                            c.sub.applySecrets(nested);
                        }
                    }
                });
            },
            wipeSecrets: function () {
                controls.forEach(function (c) {
                    if (c.secret) c.wipe();
                    else if (c.kind === "object" && c.sub) c.sub.wipeSecrets();
                });
            },
            wipeAll: function () { controls.forEach(function (c) { c.wipe(); }); }
        };
    }

    /* Null out every leaf of a request body we have already written, one level
     * of nesting included. Same honest caveat as everywhere else: this drops
     * references so the collector can reclaim them, it does not scrub bytes. */
    function dropDeep(obj) {
        Object.keys(obj || {}).forEach(function (k) {
            var v = obj[k];
            if (v && typeof v === "object" && !Array.isArray(v)) dropDeep(v);
            obj[k] = null;
        });
    }

    /* ================================================================== *
     * Modal with a focus trap and focus restore
     * ================================================================== */
    var MODAL_SEQ = 0;

    function modal(title, build, opts) {
        opts = opts || {};
        var host = byId("sec-modal-host");
        var restoreTo = document.activeElement;
        var back = el("div", "sec-backdrop");
        back.style.zIndex = String(50 + host.children.length * 2);
        var box = el("div", "sec-modal" + (opts.wide ? " wide" : ""));
        var hid = "sec-modal-h" + (++MODAL_SEQ);
        box.setAttribute("role", "dialog");
        box.setAttribute("aria-modal", "true");
        box.setAttribute("aria-labelledby", hid);
        var h = el("h2", null, title);
        h.id = hid;
        box.appendChild(h);
        if (opts.intro) box.appendChild(el("p", "sec-modal-intro", opts.intro));

        function focusables() {
            return Array.prototype.filter.call(
                box.querySelectorAll("a[href], button, input, select, textarea, [tabindex]"),
                function (n) {
                    return !n.disabled && n.tabIndex !== -1 && n.offsetParent !== null;
                });
        }
        function onKey(ev) {
            if (ev.key === "Escape" && !opts.noEscape) { ev.preventDefault(); api.close(); return; }
            if (ev.key !== "Tab") return;
            /* The trap: Tab from the last focusable wraps to the first and
             * Shift+Tab from the first wraps to the last, so keyboard focus
             * cannot walk out of an open dialog into the page behind it. */
            var f = focusables();
            if (!f.length) return;
            var first = f[0], last = f[f.length - 1];
            if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
            else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
        }
        back.addEventListener("keydown", onKey);
        back.addEventListener("click", function (ev) {
            if (ev.target === back && !opts.noEscape) api.close();
        });

        var api = {
            box: box,
            close: function () {
                if (!back.parentNode) return;
                if (opts.onClose) { try { opts.onClose(); } catch (e) { /* keep closing */ } }
                back.parentNode.removeChild(back);
                /* Focus restore: put the caret back where the user left it. */
                try { if (restoreTo && restoreTo.focus) restoreTo.focus(); } catch (e) { /* gone */ }
            }
        };
        back.appendChild(box);
        host.appendChild(back);
        build(box, api);
        var f = focusables();
        if (f.length) f[0].focus(); else box.focus();
        return api;
    }

    function actionRow(box, buttons) {
        var row = el("div", "sec-form-actions");
        buttons.forEach(function (b) { if (b) row.appendChild(b); });
        box.appendChild(row);
        return row;
    }

    /* ================================================================== *
     * base64 <-> bytes (attachments and key files, both directions)
     * ================================================================== */
    function bytesToB64(u8) {
        var chunk = 0x8000, out = [];
        for (var i = 0; i < u8.length; i += chunk)
            out.push(String.fromCharCode.apply(null, u8.subarray(i, i + chunk)));
        return btoa(out.join(""));
    }
    function b64ToBytes(b64) {
        var bin = atob(String(b64 || ""));
        var u8 = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return u8;
    }

    /* ================================================================== *
     * Clipboard (I17)
     *
     * Copy happens on an explicit user gesture, shows a countdown, and clears
     * on expiry, on page hide and on tab hide. Clearing is BEST EFFORT and the
     * page footer says so plainly: the clipboard is a shared operating-system
     * resource, another application may already have read it, and a clipboard
     * manager keeps its own history that no web page can reach.
     * ================================================================== */
    var CLIP = { armed: false, timer: null, deadline: 0 };

    function clipNode() { return byId("sec-clip"); }

    function clipboardTick() {
        var left = Math.ceil((CLIP.deadline - Date.now()) / 1000);
        var n = clipNode();
        if (left <= 0) { clipboardClear("the countdown ended"); return; }
        if (n) {
            n.hidden = false;
            n.textContent = "clipboard clears in " + fmtSeconds(left);
        }
    }
    function clipboardArm(seconds) {
        CLIP.armed = true;
        CLIP.deadline = Date.now() + seconds * 1000;
        if (CLIP.timer) window.clearInterval(CLIP.timer);
        CLIP.timer = window.setInterval(clipboardTick, 500);
        clipboardTick();
        announce("Copied. The clipboard will be cleared in " + fmtSeconds(seconds) +
                 ". Clearing is best-effort.");
    }
    function clipboardClear(why) {
        if (CLIP.timer) { window.clearInterval(CLIP.timer); CLIP.timer = null; }
        var n = clipNode();
        if (n) { n.hidden = true; n.textContent = ""; }
        if (!CLIP.armed) return;
        CLIP.armed = false;
        if (!navigator.clipboard || !navigator.clipboard.writeText) return;
        /* Overwrite with an empty string; some engines refuse an empty write,
         * so fall back to a single space. Either way the previous value is no
         * longer the clipboard's contents on this machine. */
        navigator.clipboard.writeText("").catch(function () {
            return navigator.clipboard.writeText(" ").catch(function () { /* best effort */ });
        });
        announce("Clipboard cleared because " + (why || "the countdown ended") + ".");
    }
    function copyValue(value) {
        if (!navigator.clipboard || !navigator.clipboard.writeText)
            return Promise.reject(mkErr("unsupported",
                "This browser does not offer the clipboard API to this page."));
        return navigator.clipboard.writeText(value).then(function () {
            clipboardArm(uiNum("clipboard_seconds", uiNum("reveal_seconds", 15)));
        });
    }

    /* ================================================================== *
     * Revealing a value (I17)
     *
     * reveal is the only door: the helper never puts a password or any other
     * protected value in an entries[] row, so there is nothing to un-hide
     * client-side and nothing cached to re-show. Each opening is one verb call,
     * one audit line in the helper, and one countdown here.
     * ================================================================== */
    function trackWiper(fn) { WIPERS.push(fn); return fn; }
    function wipeAllValues() {
        var list = WIPERS;
        WIPERS = [];
        list.forEach(function (f) { try { f(); } catch (e) { /* keep going */ } });
    }

    /* opts: { label, help, fetch() -> Promise({value, expires_in}), seconds } */
    function revealWidget(opts) {
        var seconds = Number(opts.seconds) || uiNum("reveal_seconds", 15);
        var shown = null;             /* the value, only while it is on screen */
        var timer = null;
        var deadline = 0;

        var wrap = el("div", "sec-reveal");
        var head = el("div", "sec-reveal-head");
        head.appendChild(el("span", "sec-reveal-label", opts.label));
        var acts = el("div", "sec-reveal-actions");
        head.appendChild(acts);
        wrap.appendChild(head);
        if (opts.help) wrap.appendChild(el("div", "sec-subtle", opts.help));

        var out = el("span", "sec-value masked", maskString());
        wrap.appendChild(out);
        var meter = el("div", "sec-meter");
        var bar = el("span");
        meter.appendChild(bar);
        meter.hidden = true;
        wrap.appendChild(meter);
        var cd = el("div", "sec-countdown");
        cd.setAttribute("aria-hidden", "true");     /* not once a second */
        wrap.appendChild(cd);
        var errHost = el("div");
        wrap.appendChild(errHost);

        function hideNow(why) {
            if (timer) { window.clearInterval(timer); timer = null; }
            var was = shown !== null;
            shown = null;
            /* Remove the text node and write the mask back. "Re-mask" must not
             * mean "the value is still in the DOM behind a CSS rule" — there
             * must be nothing left to read back out of the tree (I17). */
            clear(out);
            out.className = "sec-value masked";
            out.appendChild(document.createTextNode(maskString()));
            meter.hidden = true;
            cd.textContent = "";
            revealBtn.textContent = "Reveal";
            revealBtn.disabled = false;
            if (was) announce(opts.label + " hidden" + (why ? " — " + why : "") + ".");
        }

        function tick() {
            var left = (deadline - Date.now()) / 1000;
            if (left <= 0) { hideNow("the countdown ended"); return; }
            cd.textContent = "hides in " + fmtSeconds(left);
            bar.style.width = Math.max(0, Math.min(100, (left / seconds) * 100)) + "%";
        }

        function showValue(value, secs) {
            clear(errHost);
            shown = value;
            clear(out);
            out.className = "sec-value";
            out.appendChild(document.createTextNode(value));
            seconds = secs;
            deadline = Date.now() + secs * 1000;
            meter.hidden = false;
            bar.style.width = "100%";
            if (timer) window.clearInterval(timer);
            timer = window.setInterval(tick, 500);
            tick();
            revealBtn.textContent = "Hide";
            revealBtn.disabled = false;
            announce(opts.label + " is shown and hides itself in " + fmtSeconds(secs) + ".");
        }

        function fetchValue() {
            return opts.fetch().then(function (res) {
                var v = (res && res.value !== undefined && res.value !== null) ? String(res.value) : "";
                var s = Number(res && (res.expires_in !== undefined ? res.expires_in
                                                                    : res.seconds_remaining));
                return { value: v, seconds: (isFinite(s) && s > 0) ? s : seconds };
            });
        }

        var revealBtn = btn("Reveal", "tiny", function () {
            if (shown !== null) { hideNow("you hid it"); return; }
            revealBtn.disabled = true;
            clear(errHost);
            fetchValue().then(function (r) {
                showValue(r.value, r.seconds);
            }).catch(function (e) {
                revealBtn.disabled = false;
                errHost.appendChild(errNode(e));
                handleSessionError(e);
            });
        });
        acts.appendChild(revealBtn);

        acts.appendChild(btn("Copy", "tiny", function () {
            clear(errHost);
            /* Already on screen: copy the value we are holding, inside the
             * click itself, which is what the clipboard API wants. */
            if (shown !== null) {
                copyValue(shown).catch(function (e) { errHost.appendChild(errNode(e)); });
                return;
            }
            /* Not on screen: fetch, then write inside the promise chain this
             * click started. If the browser has already dropped the gesture the
             * write rejects and we say so rather than failing silently. */
            fetchValue().then(function (r) {
                return copyValue(r.value);
            }).catch(function (e) {
                errHost.appendChild(errNode(
                    errCode(e) ? e : mkErr("internal",
                        "The clipboard refused the write. Reveal the value first, then copy.")));
                handleSessionError(e);
            });
        }));

        wrap.secWipe = trackWiper(function () { hideNow(""); });
        return wrap;
    }

    /* ================================================================== *
     * Escalation (task rule 9)
     *
     * Cockpit owns the administrative prompt. This page asks for it by calling
     * spawn with superuser:"require" and lets the bridge put up its own dialog;
     * cockpit.permission tells us whether it is currently on so the list can
     * say so instead of only failing.
     * ================================================================== */
    function adminAllowed() { return !!(PERM && PERM.allowed); }

    /* Is this safe's "you cannot use it" nothing more than "we have not
     * escalated yet"?
     *
     * THIS IS THE DIFFERENCE BETWEEN A REFUSAL AND A NOT-YET, AND GETTING IT
     * WRONG MADE THE DEFAULT ACCESS CLASS UNOPENABLE. `list` is called with NO
     * escalation on purpose: it names what exists, and naming is not opening.
     * The helper answers it from the euid it actually has, so its class gate
     * fails for EVERY admin-class entry, for EVERY caller, on EVERY list — an
     * operator in `sudo` with administrative access already on gets exactly the
     * same `usable:false` as a stranger, because the process that asked was not
     * root either way. Reading that verdict as "unreachable" disabled the
     * Unlock control on every admin safe permanently, and admin is the DEFAULT
     * class (I1), so the ordinary configuration could not be opened at all —
     * including through "Check this safe", which was itself gated on
     * reachability and therefore never drawn in the one situation it exists
     * for. The escalation banner's own sentence, "just open one below and
     * Cockpit will ask you for it", described something the page did not do.
     *
     * Whether this operator may open it is decided by the ESCALATED verb, and
     * the helper re-checks the class inside it from kernel identity (I3). That
     * is the refusal that counts; this one is a statement about a spawn that
     * did not ask. */
    function pendingEscalation(safe) {
        return isAdminClass(safe) && !adminAllowed();
    }

    function escalationBanner() {
        if (adminAllowed()) return null;
        var box = el("div", "sec-alert warn");
        box.appendChild(el("p", null,
            "Administrative access is off in this Cockpit session, so admin-class safes " +
            "cannot be opened yet. Turn it on with the “Administrative access” " +
            "control in the Cockpit header — or just open one below and Cockpit will " +
            "ask you for it."));
        return box;
    }

    /* ================================================================== *
     * The safe list
     * ================================================================== */
    function refreshAll() {
        alertBox(null);
        var host = byId("sec-safes");
        clear(host);
        host.appendChild(el("p", "sec-subtle", "Loading the safe registry…"));
        /* `list` is a plain, unescalated call: it names what exists. Whether
         * the caller may OPEN any given safe is decided by the helper, per
         * verb, from the kernel's idea of who is calling (I3). */
        callOnce("list", {}, false).then(function (res) {
            SAFES = (res && res.safes) || [];
            renderSafes();
            /* Only now can health be asked usefully: whether to keep polling
             * it, and whether to ask escalated, are both decided from the
             * registry rows that have just arrived. The first call is
             * unconditional and unescalated — it is what makes the export
             * confirm name the right directory, and it reports any hold the
             * agent already has. */
            refreshHealth(false);
            SAFES.forEach(probeSafe);
        }).catch(function (e) {
            clear(host);
            host.appendChild(errNode(e));
        });
    }

    function safeReachable(safe) {
        /* `usable` is the helper's own answer to "could this caller open it",
         * and `reason` is its sentence for why not. `locked` means something
         * else entirely — "there is no live handle for it right now" — which
         * is the normal state of every safe in this program, so it must NOT be
         * read as unreachable. Older builds that publish only locked+reason
         * are handled by the second clause.
         *
         * THE DISABLING THAT FOLLOWS FROM THIS IS COSMETIC (I3): the helper
         * re-derives the caller's identity from the kernel and re-checks the
         * class inside every verb, and that is what refuses. The test suite
         * drives the helper directly as a non-admin to prove it. */
        if (!safe) return false;
        /* An ADMIN-class safe's usability cannot be read off this list AT ALL,
         * and not merely while escalation is off.
         *
         * `list` is spawned without escalation, always. The helper's class gate
         * raises for an admin entry before it checks anything else, so the row
         * comes back usable:false with the same sentence whoever asked and
         * whatever Cockpit's administrative access is currently set to. There
         * is no state of the world in which an unescalated list says an admin
         * safe IS usable, so the verdict carries no information and reading it
         * as a refusal is what disabled every admin card permanently. The
         * escalated verb is what decides, and a probe that comes back refused
         * lands on the card as an error where an operator can see it (I3).
         *
         * The helper's sentence is still shown, because it is the instruction:
         * this safe wants administrative access. It just is not a locked door. */
        if (isAdminClass(safe)) return true;
        if (safe.usable !== undefined) return !!safe.usable;
        return !(safe.locked && safe.reason);
    }

    function probeSafe(safe) {
        if (!safeReachable(safe)) return;
        if (isAdminClass(safe) && !adminAllowed()) return;   /* do not prompt N times on load */
        callOnce("probe", { safe: safe.id }, isAdminClass(safe)).then(function (res) {
            PROBES[safe.id] = res;
            renderSafes();
        }).catch(function (e) {
            PROBES[safe.id] = { _error: e };
            renderSafes();
        });
    }

    function renderSafes() {
        var host = byId("sec-safes");
        clear(host);
        var banner = byId("sec-banners");
        clear(banner);
        var esc = escalationBanner();
        if (esc) banner.appendChild(esc);

        if (!SAFES.length) {
            host.appendChild(el("p", "sec-empty",
                "The registry declares no safes. They are configured in " +
                "/etc/cockpit-secrets/safes.d/*.json; `secrets-admin health` reports why an " +
                "entry was dropped."));
            return;
        }

        /* Admin first, because admin is the DEFAULT access class (I1) and the
         * list should read in the same order the registry defaults do. */
        var classes = [
            { key: "admin", label: "Administrator safes",
              note: "The default class. Root-owned files; Cockpit asks for administrative " +
                    "access, and the helper refuses the verb unless it is running as root." },
            { key: "user", label: "Your own safes",
              note: "Opened by the helper running as you, with no escalation at all. The file " +
                    "must be owned by you." }
        ];
        var seen = {};
        classes.forEach(function (cls) {
            var rows = SAFES.filter(function (s) {
                var k = isAdminClass(s) ? "admin" : "user";
                if (k !== cls.key) return false;
                seen[s.id] = 1;
                return true;
            });
            if (!rows.length) return;
            var block = el("section", "sec-class-block");
            block.appendChild(el("h3", null, cls.label));
            block.appendChild(el("p", "sec-class-note sec-subtle", cls.note));
            var grid = el("div", "sec-safes");
            rows.forEach(function (s) { grid.appendChild(safeCard(s)); });
            block.appendChild(grid);
            host.appendChild(block);
        });

        var tools = el("div", "sec-tools");
        if (hasVerb("health"))
            tools.appendChild(btn("Backend health", "", function () {
                runAndShow("health", {}, false, "Backend health");
            }));
        if (hasVerb("audit-tail"))
            tools.appendChild(btn("Audit log", "", function () { auditDialog(); }));
        /* Every other global verb the helper offers, rendered from its own
         * descriptor. Add a verb to the helper and its button appears here. */
        Object.keys(verbTable()).sort().forEach(function (name) {
            if (isHandled(name)) return;
            if (verbScope(name) !== "global") return;
            tools.appendChild(btn(verbLabel(name), verbSpec(name).danger ? "danger" : "",
                function () { verbDialog(name, {}, null); }));
        });
        if (tools.childNodes.length) host.appendChild(tools);
    }

    function safeCard(safe) {
        var reachable = safeReachable(safe);
        var card = el("div", "sec-safe" + (reachable ? "" : " unreachable"));
        card.appendChild(el("h4", null, safe.label || safe.id));
        card.appendChild(el("div", "sec-safe-id", safe.id));

        var badges = el("div", "sec-safe-badges");
        badges.appendChild(badge(safe.format || "?", ""));
        badges.appendChild(badge(isAdminClass(safe) ? "admin" : "user",
                                 isAdminClass(safe) ? "warn" : ""));
        if (safe.mode === "ro") badges.appendChild(badge("read-only", "warn"));
        card.appendChild(badges);

        /* What the registry already told us in the list row, before any probe:
         * whether a passphrase is still demanded and whether a key is
         * registered. Both are facts about the entry, not about the file. */
        if (safe.password_required === false) badges.appendChild(badge("keyed", "warn"));
        if (safe.needs_keyfile) badges.appendChild(badge("key file", ""));
        if (safe.agent_enabled) badges.appendChild(badge("agent enabled", "warn"));

        var p = PROBES[safe.id];
        if (p && p._error) {
            card.appendChild(errNode(p._error));
        } else if (p) {
            if (p.version) badges.appendChild(badge(String(p.format || safe.format) + " " + p.version, ""));
            if (p.writable === false) badges.appendChild(badge("not writable", "warn"));
            var bits = [];
            if (p.kdf) bits.push("KDF " + p.kdf);
            if (p.iterations) bits.push(p.iterations + " iterations");
            if (p.needs_keyfile) bits.push("key file required");
            if (p.needs_password === false) bits.push("no passphrase required");
            if (bits.length) card.appendChild(el("div", "sec-safe-probe", bits.join(" · ")));
            /* Warnings are rendered VERBATIM from the helper. The KDBX3 "this
             * file is not authenticated" banner (I20) reaches the operator this
             * way, worded by the code that knows why. */
            (p.warnings || []).forEach(function (w) {
                card.appendChild(el("div", "sec-alert warn", String(w)));
            });
        }

        var acts = el("div", "sec-safe-actions");
        var open = btn("Unlock…", "primary", function () { unlockDialog(safe); });
        if (!reachable) {
            open.disabled = true;
            open.title = String(safe.reason || "");
        }
        acts.appendChild(open);
        /* The backup ring is readable without unlocking anything: it is a list
         * of files, not of secrets, and the moment an operator needs it is
         * usually the moment the safe will not open. */
        if (reachable && verbFor("backups"))
            acts.appendChild(btn("Backups…", "", function () { backupsDialog(safe); }));
        /* Export from the list, for the safes whose registry row allows it. The
         * dialog asks for the passphrase like every other single-shot verb —
         * being allowed to export is not being allowed to skip the unlock. */
        if (reachable && exportAllowed(safe))
            acts.appendChild(btn("Export…", "danger", function () { exportDialog(safe); }));
        /* NOT gated on `reachable`. It used to be, and that was the bug: the
         * only state this button exists for is the one in which an unescalated
         * list reports an admin safe unusable, so the guard removed it exactly
         * when it was needed. */
        if (!p && pendingEscalation(safe))
            acts.appendChild(btn("Check this safe", "", function () {
                /* Deliberately triggers Cockpit's own administrative prompt. */
                callOnce("probe", { safe: safe.id }, true).then(function (res) {
                    PROBES[safe.id] = res;
                    renderSafes();
                }).catch(function (e) {
                    PROBES[safe.id] = { _error: e };
                    renderSafes();
                });
            }));
        card.appendChild(acts);
        /* The helper's own sentence, whenever it sent one. For a safe this
         * caller genuinely cannot reach it is the refusal; for an admin-class
         * one it is the instruction — "turn on Cockpit's Administrative access
         * and try again" — and dropping it there would leave an operator with
         * an enabled button and no warning that Cockpit is about to ask them
         * for a password. It was previously printed only for unreachable
         * cards, which is why making admin cards reachable has to widen it. */
        if (safe.reason)
            card.appendChild(el("div", "sec-subtle", String(safe.reason)));
        return card;
    }

    /* ================================================================== *
     * Unlock — the centre of this project
     * ================================================================== */
    /* Does this safe still demand a passphrase? The probe knows for certain;
     * the list row carries the registry's answer when we have not probed. When
     * nothing says otherwise the answer is YES — asking is the restrictive
     * default and the point of the program. */
    function needsPassword(safe, probe) {
        if (probe && probe.needs_password !== undefined) return probe.needs_password !== false;
        if (safe && safe.password_required !== undefined) return !!safe.password_required;
        return true;
    }
    function needsKeyfile(safe, probe) {
        if (probe && probe.needs_keyfile !== undefined) return !!probe.needs_keyfile;
        return !!(safe && safe.needs_keyfile);
    }

    function unlockArgSpecs(safe, probe) {
        /* Schema first: whatever the helper says `unlock` takes is what is
         * drawn. Only the two things the probe knows about this particular file
         * are layered on top — whether the passphrase is required at all, and
         * whether a key file is wanted. */
        var specs = verbArgs("unlock").filter(function (a) {
            var n = specName(a);
            return n && n !== "safe" && n !== "handle" && n !== "session";
        });
        if (!specs.length) {
            /* The helper published no descriptor for unlock. Fall back to the
             * request shape docs/CONTRACT.md pins:
             *   {safe, password, keyfile_b64, session}
             * Contract-derived, not invented, and superseded the moment the
             * helper describes the verb itself. */
            specs = [
                { name: "password", label: "Passphrase", type: "password",
                  required: true,
                  help: "Typed every time. It is written to the helper's standard input and " +
                        "kept nowhere." },
                { name: "keyfile_b64", label: "Key file", type: "file", required: false,
                  help: "Only if this safe needs a key file that is not already registered " +
                        "on the host. Its bytes are sent inline; no copy is written to disk." }
            ];
        }
        specs = specs.map(function (a) {
            var copy = {};
            Object.keys(a).forEach(function (k) { copy[k] = a[k]; });
            /* No generator on this dialog. Generating a fresh random string is
             * the right answer when you are storing a new credential and the
             * wrong answer when you are being asked for the one that already
             * opens this file — offering it here only invites a mis-click into
             * a failed unlock and a lockout counter increment (I16). */
            copy.generate = false;
            /* No strength meter here either, for two reasons that both point
             * the same way. It answers nothing: the passphrase that opens this
             * file is whatever it is, and being told it is weak at the moment
             * you are typing it to READ the safe changes nothing you can act
             * on. And it costs: the meter sends its candidate to the helper on
             * every debounced keystroke, so scoring here would put a dozen
             * partial copies of the master passphrase in flight to answer a
             * question nobody asked. The meter belongs where a password is
             * being CHOSEN — add, edit, generate — and it is on by default
             * there. */
            copy.strength = false;
            if (controlType(copy) === "password" && isSecretSpec(copy)) {
                /* The schema marks `password` optional because SOME safe may be
                 * keyed. For THIS safe the registry has already answered, so
                 * the form asks for exactly what this file needs: required when
                 * a passphrase is still demanded (which is the default and the
                 * point of the program), optional only when the registry
                 * registered a key file or a hardware key for it — THE ONE
                 * EXEMPTION, and one nothing in the browser can grant. */
                if (needsPassword(safe, probe)) {
                    copy.required = true;
                } else {
                    copy.required = false;
                    copy.help = (copy.help ? copy.help + " " : "") +
                        "This safe is registered with a key, so a passphrase is optional for it.";
                }
            }
            return copy;
        });
        return specs;
    }

    /* ---- YubiKey (hardware challenge-response) ------------------------
     *
     * The challenge-response itself happens on the HOST, not here. A browser
     * cannot do HMAC-SHA1 challenge-response against a YubiKey slot — that is a
     * USB HID conversation, and reaching it from a web page would need a
     * capability this package deliberately does not have (I9: no CSP
     * relaxation, no WASM, nothing but default-src 'self'). What this page does
     * is what a browser can honestly do: tell the operator to touch the key,
     * ask the helper for the response, and put it in the unlock request.
     *
     * Two answers matter and they are opposites:
     *
     *   needs_challenge   the file wants a response and the operator must
     *                     touch the key. Prompt, then send it.
     *   unsupported       the backend cannot do challenge-response for this
     *                     format at all. SAY EXACTLY THAT. Do not offer to try
     *                     without it: a safe whose key file or hardware key is
     *                     part of its composite key does not open with the
     *                     passphrase alone, and quietly attempting one would
     *                     produce bad-credential — an answer that reads as
     *                     "you typed it wrong" for a problem that is nothing of
     *                     the sort, and one that walks the lockout counter
     *                     towards a lockout on the way (I16).
     */
    function yubikeyState(safe, probe) {
        var p = probe || {};
        var yk = p.yubikey;
        var out = { needed: false, unsupported: false, slot: null, detail: "",
                    challenge: null };
        out.slot = (p.yubikey_slot !== undefined && p.yubikey_slot !== null)
            ? p.yubikey_slot
            : ((safe && safe.yubikey_slot !== undefined) ? safe.yubikey_slot : null);
        if (typeof yk === "string") {
            if (yk === "needs_challenge") out.needed = true;
            if (yk === "unsupported") out.unsupported = true;
        } else if (yk && typeof yk === "object") {
            if (yk.needs_challenge) out.needed = true;
            if (yk.unsupported || yk.supported === false) out.unsupported = true;
            if (yk.slot !== undefined && yk.slot !== null) out.slot = yk.slot;
            if (yk.detail) out.detail = String(yk.detail);
        }
        if (p.needs_challenge === true) out.needed = true;
        if (p.yubikey_supported === false) out.unsupported = true;
        if (p.yubikey_detail) out.detail = String(p.yubikey_detail);
        /* The probe's own key for the challenge. It is present only when the
         * registry declares a slot for this safe, so its presence is itself the
         * signal that this file wants one. */
        if (p.challenge_b64) {
            out.challenge = String(p.challenge_b64);
            out.needed = true;
        }
        if (yk && typeof yk === "object" && yk.challenge_b64)
            out.challenge = String(yk.challenge_b64);
        /* A registry entry naming a slot means the operator configured one.
         * That is not on its own a challenge this file needs — the probe says
         * that — but it does mean the key is part of this safe's story and the
         * dialog should not be silent about it. */
        return out;
    }

    /* Which request field the unlock verb carries the response in. From the
     * verb's own descriptor, never a name written here. */
    function yubikeyField() {
        var names = argNames("unlock");
        for (var i = 0; i < names.length; i++)
            if (/yubi|challenge|hmac/i.test(names[i])) return names[i];
        return null;
    }

    function unlockDialog(safe) {
        var probe = PROBES[safe.id];
        if (probe && probe._error) probe = null;
        var admin = isAdminClass(safe);
        var yk = yubikeyState(safe, probe);
        var ykField = yubikeyField();
        var ykVerb = verbFor("yubikey");

        modal("Unlock " + (safe.label || safe.id), function (box, m) {
            var intro = el("p", "sec-modal-intro");
            intro.textContent = admin
                ? "Administrator safe. Cockpit will ask for administrative access if it is " +
                  "not already on, and the helper refuses this verb unless it is running as root."
                : "Your own safe. The helper runs as you, with no escalation.";
            box.appendChild(intro);

            if (needsKeyfile(safe, probe))
                box.appendChild(el("div", "sec-alert info",
                    "This safe is registered with a key file. The helper reads it on the host; " +
                    "its path never comes from this page."));
            (probe && probe.warnings ? probe.warnings : []).forEach(function (w) {
                box.appendChild(el("div", "sec-alert warn", String(w)));
            });

            /* ---- the hardware key, before the passphrase box ------------
             * It goes above the form because it changes what the operator is
             * about to do with their hands, and because the "unsupported" case
             * means the Unlock button below it is not going to work. */
            var ykResponse = null;      /* one variable, this dialog's scope only */
            var ykHost = el("div");
            box.appendChild(ykHost);

            if (yk.unsupported) {
                var ub = el("div", "sec-alert err");
                ub.appendChild(el("p", null,
                    "This backend answered “unsupported” for hardware challenge-response" +
                    (yk.slot !== null && yk.slot !== undefined
                        ? " on slot " + yk.slot : "") + "."));
                if (yk.detail) ub.appendChild(el("p", null, yk.detail));
                ub.appendChild(el("p", null,
                    "That is the answer, and this page will not paper over it by trying the " +
                    "passphrase on its own. A safe whose hardware key is part of its composite " +
                    "key does not open without it: the attempt would come back as " +
                    "“wrong passphrase”, which is not what happened, and it would count " +
                    "towards a lockout on the way (I16)."));
                ykHost.appendChild(ub);
            } else if (yk.needed) {
                var nb = el("div", "sec-alert warn");
                nb.appendChild(el("p", null,
                    "This safe needs a response from your YubiKey" +
                    (yk.slot !== null && yk.slot !== undefined
                        ? " on slot " + yk.slot : "") +
                    ". The key is read on the host, not in this browser."));
                if (yk.detail) nb.appendChild(el("p", null, yk.detail));

                if (ykVerb) {
                    /* The helper can run the challenge itself. Press, touch the
                     * key, and the response goes into the unlock request. */
                    var status = el("div", "sec-countdown");
                    status.setAttribute("aria-live", "polite");
                    var ask = btn("Challenge the key — touch it when it flashes", "primary",
                    function () {
                        ask.disabled = true;
                        status.textContent = "Waiting for the key. Touch it now.";
                        announce("Touch your YubiKey now.");
                        callOnce(ykVerb, { safe: safe.id }, admin).then(function (res) {
                            ask.disabled = false;
                            /* The response is a credential: it is held in this
                             * one variable, for this one unlock, and is never
                             * displayed, stored or logged. */
                            ykResponse = res && (res.response !== undefined
                                ? res.response
                                : (res.b64 !== undefined ? res.b64 : res.value));
                            if (ykResponse === undefined || ykResponse === null) {
                                status.textContent =
                                    "The key answered, but the helper named no response field.";
                                return;
                            }
                            status.textContent = "The key answered. Press Unlock.";
                            announce("The key answered. Press Unlock.");
                        }).catch(function (e) {
                            ask.disabled = false;
                            ykResponse = null;
                            clear(status);
                            status.textContent = "";
                            nb.appendChild(errNode(e));
                            if (errCode(e) === "unsupported")
                                nb.appendChild(el("p", null,
                                    "Unsupported. This page will not retry without the key."));
                        });
                    });
                    nb.appendChild(ask);
                    nb.appendChild(status);
                } else if (!ykField) {
                    /* The probe asks for a challenge and the helper publishes
                     * neither a verb to run it nor a field to carry it. Say so;
                     * do not offer an Unlock that cannot succeed without
                     * explaining why. */
                    nb.appendChild(el("p", null,
                        "This helper reports that a challenge is required but publishes " +
                        "neither a verb to perform it nor a request field to carry the " +
                        "response, so there is no way to supply one from this page."));
                } else {
                    /* The helper hands over the challenge itself, in
                     * probe.challenge_b64, and expects the response back in the
                     * request field the unlock verb declares. The challenge is
                     * NOT a secret — it is the input to the key, and the whole
                     * point of challenge-response is that knowing the challenge
                     * buys nothing — so it is shown in full and can be copied.
                     * The RESPONSE is a credential and is handled like one. */
                    if (yk.challenge) {
                        nb.appendChild(el("p", null,
                            "Take this challenge to the key, and put what it answers back " +
                            "in the “" + ykField + "” control below."));
                        nb.appendChild(el("code", "sec-path", yk.challenge));
                        nb.appendChild(btn("Copy the challenge", "tiny", function () {
                            /* The clipboard countdown exists for values that
                             * must not linger. A challenge is public, so it is
                             * copied plainly and no countdown is armed:
                             * pretending it needed one would teach the operator
                             * that the countdown means nothing. */
                            if (navigator.clipboard && navigator.clipboard.writeText)
                                navigator.clipboard.writeText(yk.challenge).then(function () {
                                    announce("Challenge copied.");
                                }).catch(function () { /* best effort */ });
                        }));
                    } else {
                        nb.appendChild(el("p", null,
                            "Supply the response in the “" + ykField + "” control below."));
                    }
                }
                ykHost.appendChild(nb);
            } else if (yk.slot !== null && yk.slot !== undefined) {
                ykHost.appendChild(el("div", "sec-alert info",
                    "This safe is registered with a hardware key on slot " + yk.slot +
                    ". The helper did not ask for a challenge for this file."));
            }

            var form = buildForm(unlockArgSpecs(safe, probe));
            box.appendChild(form.node);

            var errHost = el("div");
            box.appendChild(errHost);

            box.appendChild(el("p", "sec-subtle",
                "The passphrase is asked for every time. It goes into one variable, is written " +
                "to the helper's standard input, and is overwritten; it is never stored in this " +
                "browser and never appears on a command line."));

            var go = btn("Unlock", "primary", submit);
            var cancel = btn("Cancel", "", function () { m.close(); });
            actionRow(box, [go, cancel]);

            /* Enter submits, without a <form> to be submitted. */
            box.addEventListener("keydown", function (ev) {
                if (ev.key === "Enter" && ev.target && ev.target.tagName === "INPUT" &&
                    ev.target.type !== "button" && ev.target.type !== "checkbox") {
                    ev.preventDefault();
                    submit();
                }
            });

            function submit() {
                clear(errHost);
                var bad = form.validate();
                if (bad) { errHost.appendChild(el("div", "sec-alert err", bad)); return; }
                go.disabled = true;

                /* Non-secret values first: they are safe to hold in an object. */
                var req = form.values();
                req.safe = safe.id;
                req[sessionRequestKey()] = "unlock";

                /* ---- THE ONE VARIABLE ------------------------------------
                 * Every secret control on this dialog is read here, one at a
                 * time, straight into the JSON body, and released on the next
                 * statements. Nothing else in this file ever holds it. */
                var names = form.secretNames();
                var i, n, pw;
                for (i = 0; i < names.length; i++) {
                    n = names[i];
                    pw = form.readSecret(n);
                    if (pw !== null && pw !== "") req[n] = pw;
                    pw = "\0".repeat(pw ? pw.length : 0);
                    pw = null;
                }
                /* The challenge response, if the key was asked and answered. It
                 * is treated exactly like the passphrase: read once, put in the
                 * body, and the variable dropped on the next statements. It is
                 * sent under the field name the UNLOCK verb declares, so a
                 * helper that calls it something else works with no edit; when
                 * the verb declares no such field the response is not smuggled
                 * in under a name this page made up. */
                if (ykResponse !== null && ykResponse !== undefined && ykField)
                    req[ykField] = ykResponse;
                ykResponse = null;
                var body = JSON.stringify(req);
                /* Drop every reference we hold to the plaintext. A JavaScript
                 * string is immutable, so this releases rather than scrubs —
                 * docs/ARCHITECTURE.md hop 2 states the same limitation for
                 * Python's str and this page does not claim a stronger one.
                 * What it does guarantee is that nothing retains a reference
                 * once the request is on its way (I11). */
                names.forEach(function (nm) { req[nm] = null; });
                if (ykField) req[ykField] = null;
                req = null;
                form.wipeSecrets();

                var session = openSession(safe);
                session.send(body).then(function (res) {
                    body = null;
                    session.handle = res.handle || null;
                    m.close();
                    startSession(safe, session, res, probe);
                }).catch(function (e) {
                    body = null;
                    session.close();
                    go.disabled = false;
                    /* Rendered verbatim. bad-credential means "wrong passphrase
                     * OR failed MAC" and this page adds no distinction the
                     * helper deliberately refused to make (I6). */
                    clear(errHost);
                    errHost.appendChild(errNode(e));
                    if (errCode(e) === "locked-out" && errSeconds(e))
                        lockoutCountdown(errHost, errSeconds(e));
                    /* "unsupported" from an unlock is the backend saying it
                     * cannot do what this file needs — most often the hardware
                     * challenge. It is repeated in this page's own words so it
                     * cannot be mistaken for a typo, and NOTHING is retried:
                     * there is no passphrase-only fallback here, silent or
                     * otherwise. */
                    if (errCode(e) === "unsupported")
                        errHost.appendChild(el("div", "sec-alert err",
                            "Unsupported: the backend cannot open this safe the way it is " +
                            "configured. No second attempt was made — in particular, nothing " +
                            "was retried without the hardware key" +
                            (needsKeyfile(safe, probe) ? " or key file" : "") + "."));
                    form.focusFirst();
                });
            }
        }, { onClose: function () { /* nothing held to release */ } });
    }

    /* A live countdown for locked-out, using the helper's own number (I16). */
    function lockoutCountdown(host, seconds) {
        var line = el("div", "sec-countdown");
        host.appendChild(line);
        var deadline = Date.now() + seconds * 1000;
        var t = window.setInterval(function () {
            var left = Math.ceil((deadline - Date.now()) / 1000);
            if (left <= 0) {
                window.clearInterval(t);
                line.textContent = "You can try again now.";
                announce("The lockout has expired.");
                return;
            }
            line.textContent = "Locked out for another " + fmtSeconds(left) + ".";
        }, 500);
    }

    /* ================================================================== *
     * Session lifetime and locking
     * ================================================================== */
    var SESSION_TIMER = null;
    var HIDE_TIMER = null;

    function startSession(safe, session, unlockRes, probe) {
        SESSION = session;
        BROWSE = {
            safe: safe,
            probe: probe || {},
            unlock: unlockRes || {},
            format: (probe && probe.format) || safe.format || "",
            writable: !(safe.mode === "ro") && (!probe || probe.writable !== false),
            group: null,
            query: "",
            offset: 0,
            limit: uiNum("page_size", 100),
            sort: null,
            desc: false,
            rows: [],
            groups: [],
            total: 0,
            selected: null,
            dirty: 0
        };
        var secs = Number(unlockRes && unlockRes.expires_in);
        SESSION.expiresAt = (isFinite(secs) && secs > 0) ? Date.now() + secs * 1000 : 0;
        startSessionTicker();
        show(byId("sec-lock"), true);
        enterBrowse();
        announce("Unlocked " + (safe.label || safe.id) + ".");
        /* The unlock reply carries an `agent` block when, and only when, the
         * registry enabled the agent AND the daemon actually took the handle.
         * That reply is the moment the hold comes into existence, so it is the
         * moment the banner learns about it — no poll interval to wait out, and
         * no window in which a safe is held and not shown (I18). */
        agentNoted(safe, unlockRes);
    }

    function startSessionTicker() {
        if (SESSION_TIMER) window.clearInterval(SESSION_TIMER);
        var node = byId("sec-session");
        function tick() {
            if (!SESSION) { show(node, false); return; }
            if (!SESSION.expiresAt) {
                node.hidden = false;
                node.textContent = "unlocked";
                return;
            }
            var left = Math.ceil((SESSION.expiresAt - Date.now()) / 1000);
            if (left <= 0) {
                /* The handle has expired at the helper. Lock here too, so the
                 * page never shows a safe as open when it is not (I18's rule,
                 * applied to the plain session). */
                lockNow("the unlock expired");
                return;
            }
            node.hidden = false;
            node.textContent = "unlocked — " + fmtSeconds(left) + " left";
        }
        SESSION_TIMER = window.setInterval(tick, 500);
        tick();
    }

    /* Any verb can be the one that discovers the helper is gone. Only the
     * channel actually being dead counts: a per-verb access-denied is a normal
     * answer (a read-only safe refuses `edit` while the unlock is still live),
     * and treating it as an expiry would lock the user out of a working
     * session for asking a question the helper was entitled to say no to. */
    function handleSessionError(e) {
        if (!SESSION) return;
        if (SESSION.isDead()) lockNow("the helper session ended");
    }

    function lockNow(reason) {
        if (SESSION_TIMER) { window.clearInterval(SESSION_TIMER); SESSION_TIMER = null; }
        var hadDirty = BROWSE && BROWSE.dirty;
        var lockedSafeId = BROWSE ? BROWSE.safe.id : null;
        var s = SESSION;
        SESSION = null;
        if (s) {
            /* Ask politely first so the helper can zero its own buffers and
             * write its audit line, then close the channel, which kills the
             * process and with it every derived key. */
            try { s.call("lock", {}).catch(function () { /* closing anyway */ }); } catch (e) { /* ignore */ }
            window.setTimeout(function () { s.close(); }, 50);
        }
        BROWSE = null;
        /* Scrub every rendered value, then the panes that held them. Locking
         * clears the DOM, not just the view. */
        wipeAllValues();
        clear(byId("sec-tree"));
        clear(byId("sec-entries"));
        clear(byId("sec-detail"));
        clear(byId("sec-browse-tools"));
        clear(byId("sec-browse-warnings"));
        clear(byId("sec-browse-meta"));
        clipboardClear("the safe was locked");
        show(byId("sec-lock"), false);
        show(byId("sec-session"), false);
        setDirty(0);
        show(byId("sec-browse-view"), false);
        show(byId("sec-safes-view"), true);
        var msg = "Locked" + (reason ? " — " + reason : "") + ".";
        if (hadDirty) msg += " Unsaved changes were discarded; the safe on disk is unchanged.";
        alertText(msg, "info");
        announce(msg);
        /* This safe's own hold, if it had one, ends with the session. Any OTHER
         * safe the agent is holding is untouched and stays in the banner: the
         * one direction the banner must never go stale in is showing fewer
         * unlocked safes than there are. */
        if (lockedSafeId) agentDrop(lockedSafeId);
        refreshAgent();
    }

    function setDirty(n) {
        var node = byId("sec-dirty");
        if (BROWSE) BROWSE.dirty = n;
        if (!n) { show(node, false); node.textContent = ""; return; }
        node.hidden = false;
        node.textContent = n === 1 ? "1 unsaved change" : n + " unsaved changes";
    }
    function markDirty() {
        if (!BROWSE) return;
        setDirty((BROWSE.dirty || 0) + 1);
    }

    /* ================================================================== *
     * Browse
     * ================================================================== */
    function enterBrowse() {
        show(byId("sec-safes-view"), false);
        show(byId("sec-browse-view"), true);
        byId("sec-browse-h").textContent = BROWSE.safe.label || BROWSE.safe.id;

        var meta = byId("sec-browse-meta");
        clear(meta);
        var p = BROWSE.probe || {};
        meta.appendChild(badge((p.format || BROWSE.safe.format || "?") +
                               (p.version ? " " + p.version : ""), ""));
        meta.appendChild(badge(isAdminClass(BROWSE.safe) ? "admin" : "user",
                               isAdminClass(BROWSE.safe) ? "warn" : ""));
        if (!BROWSE.writable) meta.appendChild(badge("read-only", "warn"));
        if (BROWSE.unlock.entries_total !== undefined)
            meta.appendChild(el("span", "sec-subtle",
                BROWSE.unlock.entries_total + " entries, " +
                (BROWSE.unlock.groups_total || 0) + " groups"));

        var warn = byId("sec-browse-warnings");
        clear(warn);
        /* Both sets of warnings, verbatim from the helper: the KDBX3
         * "not authenticated" banner is one of these (I20). */
        (p.warnings || []).concat(BROWSE.unlock.warnings || []).forEach(function (w) {
            warn.appendChild(el("div", "sec-alert warn", String(w)));
        });
        if (!BROWSE.writable && BROWSE.safe.mode !== "ro")
            warn.appendChild(el("div", "sec-alert warn",
                "This safe is open read-only. The helper decides that — a KDBX3 file has " +
                "no authenticated encryption, and a safe whose round trip would drop a field " +
                "is refused write access rather than quietly amputated."));

        renderTools();
        loadTree();
        loadEntries();
    }

    function renderTools() {
        var host = byId("sec-browse-tools");
        clear(host);

        var search = el("input");
        search.type = "search";
        search.setAttribute("placeholder", "Search entries…");
        search.setAttribute("aria-label", "Search entries");
        search.setAttribute("spellcheck", "false");
        var deb = null;
        search.addEventListener("input", function () {
            if (deb) window.clearTimeout(deb);
            deb = window.setTimeout(function () {
                if (!BROWSE) return;
                BROWSE.query = search.value;
                BROWSE.offset = 0;
                loadEntries();
            }, 250);
        });
        host.appendChild(search);

        var sizes = (SCHEMA && SCHEMA.ui && Array.isArray(SCHEMA.ui.page_sizes))
            ? SCHEMA.ui.page_sizes : [25, 50, 100, 200];
        var sel = el("select");
        sel.setAttribute("aria-label", "Entries per page");
        sizes.forEach(function (n) {
            var o = el("option", null, n + " per page");
            o.value = String(n);
            sel.appendChild(o);
        });
        sel.value = String(BROWSE.limit);
        sel.addEventListener("change", function () {
            BROWSE.limit = parseInt(sel.value, 10) || 100;
            BROWSE.offset = 0;
            loadEntries();
        });
        host.appendChild(sel);

        host.appendChild(el("span", "sec-spacer"));

        if (hasVerb("add") && BROWSE.writable)
            host.appendChild(btn("Add entry…", "", function () {
                verbDialog("add", { group: BROWSE.group || undefined }, afterMutation);
            }));
        if (hasVerb("group-add") && BROWSE.writable)
            host.appendChild(btn("Add group…", "", function () {
                verbDialog("group-add", { parent: BROWSE.group || undefined }, afterMutation);
            }));
        if (hasVerb("generate"))
            host.appendChild(btn("Generate password…", "", function () {
                generateDialog(null);
            }));

        /* Save-as, the backup ring, and the export — each drawn only when the
         * helper publishes the verb, and the export only when this safe's own
         * registry row also permits it (I21). */
        if (verbFor("saveAs") && BROWSE.writable)
            host.appendChild(btn(verbLabel(verbFor("saveAs")), "", saveAsDialog));
        if (verbFor("backups"))
            host.appendChild(btn("Backups…", "", function () {
                backupsDialog(BROWSE.safe);
            }));
        if (exportAllowed(BROWSE.safe))
            host.appendChild(btn("Export in the clear…", "danger", function () {
                exportDialog(BROWSE.safe);
            }));
        else if (verbFor("export"))
            /* The verb exists and this safe is not allowed to use it. Saying so
             * is better than an absent button: "export is off for this safe" is
             * a registry decision an operator can look at and change, and a
             * missing control looks like a missing feature. */
            host.appendChild(el("span", "sec-subtle",
                "Export is not enabled for this safe in the registry."));

        /* Every other safe-scoped verb the helper offers — upgrade-to-kdbx4,
         * breach-check, whatever a later task adds. No edit here is needed to
         * make them appear. */
        Object.keys(verbTable()).sort().forEach(function (name) {
            if (isHandled(name)) return;
            if (verbScope(name) !== "safe") return;
            host.appendChild(btn(verbLabel(name), verbSpec(name).danger ? "danger" : "",
                function () { verbDialog(name, {}, afterMutation); }));
        });

        var save = btn("Save", "primary", doSave);
        save.id = "sec-save";
        save.disabled = true;
        if (!BROWSE.writable) save.title = "This safe is open read-only.";
        host.appendChild(save);
        host.appendChild(btn("Lock", "danger", function () { confirmLock(); }));
        updateSaveButton();
    }

    function updateSaveButton() {
        var b = byId("sec-save");
        if (!b) return;
        b.disabled = !(BROWSE && BROWSE.dirty && BROWSE.writable);
    }

    function afterMutation(res, verb) {
        if (mutates(verb)) markDirty();
        updateSaveButton();
        loadTree();
        loadEntries();
    }

    function confirmLock() {
        if (!BROWSE || !BROWSE.dirty) { lockNow("you locked it"); return; }
        modal("Lock with unsaved changes?", function (box, m) {
            box.appendChild(el("p", null,
                BROWSE.dirty + " change(s) have not been written to disk. Locking discards " +
                "them; the safe on disk is left exactly as it is."));
            actionRow(box, [
                btn("Save first", "primary", function () { m.close(); doSave(); }),
                btn("Discard and lock", "danger", function () { m.close(); lockNow("you locked it"); }),
                btn("Cancel", "", function () { m.close(); })
            ]);
        });
    }

    /* ---------------------------------------------------------- tree --- */
    function loadTree() {
        if (!SESSION) return;
        var host = byId("sec-tree");
        clear(host);
        host.appendChild(el("p", "sec-subtle", "Loading groups…"));
        SESSION.call("tree", {}).then(function (res) {
            clear(host);
            BROWSE.groups = (res && res.groups) || [];
            renderTree(host, BROWSE.groups);
        }).catch(function (e) {
            clear(host);
            host.appendChild(errNode(e));
            handleSessionError(e);
        });
    }

    function renderTree(host, groups) {
        var kids = {};
        var byUuid = {};
        groups.forEach(function (g) { byUuid[g.uuid] = g; });
        groups.forEach(function (g) {
            var parent = (g.parent === undefined || g.parent === null || g.parent === "") ? "" : g.parent;
            if (parent && !byUuid[parent]) parent = "";     /* orphan -> top level */
            (kids[parent] = kids[parent] || []).push(g);
        });

        var ul = el("ul");
        /* "All entries" clears the group filter. It is a control, not a group:
         * it sends no group at all, which is what the entries verb documents
         * as "every group". */
        var allLi = el("li");
        var allBtn = el("button", null, "All entries");
        allBtn.type = "button";
        allBtn.setAttribute("aria-current", BROWSE.group ? "false" : "true");
        allBtn.addEventListener("click", function () {
            BROWSE.group = null;
            BROWSE.offset = 0;
            loadTree();
            loadEntries();
        });
        allLi.appendChild(allBtn);
        ul.appendChild(allLi);

        function walk(parent, depth) {
            if (depth > 64) return;              /* matches the helper's depth cap */
            (kids[parent] || []).forEach(function (g) {
                var li = el("li");
                var b = el("button");
                b.type = "button";
                b.style.paddingLeft = (0.35 + depth * 0.75) + "rem";
                b.appendChild(document.createTextNode(g.name === undefined ? g.uuid : String(g.name)));
                if (g.count !== undefined) b.appendChild(el("span", "count", "(" + g.count + ")"));
                b.setAttribute("aria-current", BROWSE.group === g.uuid ? "true" : "false");
                b.addEventListener("click", function () {
                    BROWSE.group = g.uuid;
                    BROWSE.offset = 0;
                    loadTree();
                    loadEntries();
                });
                if (verbSpec("group-rm") || verbSpec("group-mv")) b.title = String(g.name || "");
                li.appendChild(b);
                ul.appendChild(li);
                walk(g.uuid, depth + 1);
            });
        }
        walk("", 0);
        host.appendChild(ul);

        if (BROWSE.group && BROWSE.writable) {
            var acts = el("div", "sec-tools");
            ["group-rm", "group-mv"].forEach(function (v) {
                if (!hasVerb(v)) return;
                acts.appendChild(btn(verbLabel(v), (verbSpec(v).danger ? "danger " : "") + "tiny",
                    function () { verbDialog(v, { uuid: BROWSE.group }, afterMutation); }));
            });
            /* Any other group-scoped verb the helper publishes. */
            Object.keys(verbTable()).sort().forEach(function (name) {
                if (isHandled(name)) return;
                if (verbScope(name) !== "group") return;
                acts.appendChild(btn(verbLabel(name), "tiny", function () {
                    verbDialog(name, { uuid: BROWSE.group, group: BROWSE.group }, afterMutation);
                }));
            });
            if (acts.childNodes.length) host.appendChild(acts);
        }
    }

    /* ------------------------------------------------------- entries --- */
    function serverSorts() { return argNames("entries").indexOf("sort") >= 0; }

    function loadEntries() {
        if (!SESSION) return;
        var host = byId("sec-entries");
        clear(host);
        host.appendChild(el("p", "sec-subtle", "Loading entries…"));
        var req = { offset: BROWSE.offset, limit: BROWSE.limit };
        if (BROWSE.group) req.group = BROWSE.group;
        if (BROWSE.query) req.query = BROWSE.query;
        if (serverSorts() && BROWSE.sort) {
            req.sort = BROWSE.sort;
            if (argNames("entries").indexOf("desc") >= 0) req.desc = BROWSE.desc;
            else if (argNames("entries").indexOf("order") >= 0) req.order = BROWSE.desc ? "desc" : "asc";
        }
        SESSION.call("entries", req).then(function (res) {
            BROWSE.rows = (res && res.entries) || [];
            BROWSE.total = Number(res && res.total) || BROWSE.rows.length;
            renderEntries();
        }).catch(function (e) {
            clear(host);
            host.appendChild(errNode(e));
            handleSessionError(e);
        });
    }

    function renderEntries() {
        var host = byId("sec-entries");
        clear(host);
        var cols = listColumns(BROWSE.format);
        var rows = BROWSE.rows.slice();

        if (!serverSorts() && BROWSE.sort) {
            rows.sort(function (a, b) {
                var x = txt(a[BROWSE.sort]).toLowerCase();
                var y = txt(b[BROWSE.sort]).toLowerCase();
                if (x < y) return BROWSE.desc ? 1 : -1;
                if (x > y) return BROWSE.desc ? -1 : 1;
                return 0;
            });
        }

        var wrap = el("div", "sec-scroll");
        var t = el("table", "sec");
        var cap = el("caption", "sec-subtle");
        cap.textContent = BROWSE.total + " entr" + (BROWSE.total === 1 ? "y" : "ies") +
            (BROWSE.query ? " matching “" + BROWSE.query + "”" : "") +
            (BROWSE.sort && !serverSorts()
                ? " — sorted within this page; the helper does not take a sort argument."
                : "");
        t.appendChild(cap);

        var thead = el("thead");
        var htr = el("tr");
        cols.forEach(function (c) {
            var th = el("th");
            th.scope = "col";
            if (c.sortable) {
                var b = el("button", null, c.label +
                    (BROWSE.sort === c.name ? (BROWSE.desc ? " ▾" : " ▴") : ""));
                b.type = "button";
                b.addEventListener("click", function () {
                    if (BROWSE.sort === c.name) BROWSE.desc = !BROWSE.desc;
                    else { BROWSE.sort = c.name; BROWSE.desc = false; }
                    if (serverSorts()) { BROWSE.offset = 0; loadEntries(); }
                    else renderEntries();
                });
                th.appendChild(b);
            } else {
                th.textContent = c.label;
            }
            htr.appendChild(th);
        });
        thead.appendChild(htr);
        t.appendChild(thead);

        var tb = el("tbody");
        if (!rows.length) {
            var tr0 = el("tr");
            var td0 = el("td", "sec-empty", "No entries here.");
            td0.colSpan = cols.length;
            tr0.appendChild(td0);
            tb.appendChild(tr0);
        }
        rows.forEach(function (r) {
            var tr = el("tr", "clickable" + (BROWSE.selected === r.uuid ? " selected" : ""));
            cols.forEach(function (c, idx) {
                var td = el("td");
                var v = r[c.name];
                if (idx === 0) {
                    /* The first column is the keyboard door into the entry. */
                    var b = el("button", "sec-btn link", txt(v) || "(untitled)");
                    b.type = "button";
                    b.addEventListener("click", function (ev) {
                        ev.stopPropagation();
                        selectEntry(r);
                    });
                    td.appendChild(b);
                } else if (typeof v === "boolean") {
                    td.appendChild(badge(v ? "yes" : "no", v ? "ok" : ""));
                } else {
                    /* Whatever the helper sent. It never sends a password or any
                     * other protected value in an entries[] row — reveal is the
                     * only door — so there is nothing here to mask. */
                    td.textContent = txt(v);
                }
                tr.appendChild(td);
            });
            tr.addEventListener("click", function () { selectEntry(r); });
            tb.appendChild(tr);
        });
        t.appendChild(tb);
        wrap.appendChild(t);
        host.appendChild(wrap);

        /* Keep the detail pane in step with the row it is showing. Adding or
         * removing an attachment, or restoring a version, changes the entry;
         * without this the pane keeps rendering the row from before the
         * mutation and an operator sees an attachment they have just deleted.
         * Only when the selected entry is on THIS page of results — a search
         * that filters it out should leave the pane alone rather than blank it. */
        if (BROWSE.selected) {
            var sel = null;
            rows.forEach(function (r) { if (r.uuid === BROWSE.selected) sel = r; });
            if (sel) renderDetail(sel);
        }

        var pager = el("div", "sec-pager");
        var from = BROWSE.total ? BROWSE.offset + 1 : 0;
        var to = Math.min(BROWSE.offset + BROWSE.rows.length, BROWSE.total);
        var prev = btn("Previous", "", function () {
            BROWSE.offset = Math.max(0, BROWSE.offset - BROWSE.limit);
            loadEntries();
        });
        prev.disabled = BROWSE.offset <= 0;
        var next = btn("Next", "", function () {
            BROWSE.offset = BROWSE.offset + BROWSE.limit;
            loadEntries();
        });
        next.disabled = to >= BROWSE.total;
        pager.appendChild(prev);
        pager.appendChild(el("span", "sec-subtle", from + "–" + to + " of " + BROWSE.total));
        pager.appendChild(next);
        host.appendChild(pager);
    }

    /* -------------------------------------------------------- detail --- */
    function selectEntry(row) {
        BROWSE.selected = row.uuid;
        renderEntries();
        renderDetail(row);
    }

    function renderDetail(row) {
        var host = byId("sec-detail");
        clear(host);
        host.appendChild(el("h3", null, txt(row.title) || "(untitled)"));

        /* Metadata the helper already sent. No value is in here by contract. */
        var dl = el("dl", "sec-kv");
        Object.keys(row).forEach(function (k) {
            if (k === "title" || k === "uuid") return;
            dl.appendChild(el("dt", null, k.replace(/_/g, " ")));
            var dd = el("dd");
            var v = row[k];
            if (typeof v === "boolean") dd.appendChild(badge(v ? "yes" : "no", v ? "ok" : ""));
            else dd.textContent = txt(v);
            dl.appendChild(dd);
        });
        host.appendChild(dl);

        /* --- values: one reveal control per field the schema declares ---
         * Every one of these is a separate `reveal` verb call, a separate audit
         * line in the helper, and a separate countdown here. There is no
         * "reveal everything" control and no cache to re-show from. */
        if (!hasVerb("reveal")) {
            host.appendChild(el("div", "sec-alert info",
                "This helper does not offer the reveal verb, so no value can be shown."));
        } else {
            /* The list of revealable fields is the `reveal` verb's own `field`
             * descriptor — its options, or the entry_field enum. Add a field
             * to the helper's enum and a control for it appears here with no
             * edit to this file. */
            var fieldSpec = revealFieldSpec() || {};
            host.appendChild(el("h4", null, "Fields"));
            revealFields().forEach(function (f) {
                var already = Object.prototype.hasOwnProperty.call(row, f.value);
                /* A field the listing already carries is metadata, printed
                 * above; it is not re-offered as a reveal unless the listing
                 * is silent about it. `password` is never in a listing, by
                 * contract, so it is always here. */
                if (already && f.value !== "password" && f.value !== "totp") return;
                host.appendChild(revealWidget({
                    label: f.label,
                    fetch: function () {
                        return SESSION.call("reveal", { uuid: row.uuid, field: f.value });
                    }
                }));
            });
            /* What the helper says about revealing, in its own words: what the
             * verb is for, and what it costs. Both are rendered — the second
             * one is the sentence explaining that this is the only door and
             * that each opening is an audit line. */
            if (fieldSpec.help) host.appendChild(el("div", "hint", String(fieldSpec.help)));
            if (fieldSpec.breaks_when_wrong)
                host.appendChild(el("div", "hint", String(fieldSpec.breaks_when_wrong)));

            /* Custom fields. The reveal pattern the helper publishes accepts
             * "custom:<name>", so a row that names its custom fields gets a
             * control each; one that does not gets an explicit way to ask. */
            var custom = row.custom_fields || row.custom || row.fields;
            if (Array.isArray(custom) && custom.length) {
                host.appendChild(el("h4", null, "Custom fields"));
                custom.forEach(function (cname) {
                    host.appendChild(revealWidget({
                        label: String(cname),
                        fetch: function () {
                            return SESSION.call("reveal",
                                { uuid: row.uuid, field: "custom:" + String(cname) });
                        }
                    }));
                });
            } else if (revealFields().length) {
                host.appendChild(btn("Reveal a custom field…", "tiny", function () {
                    customFieldDialog(row);
                }));
            }
        }

        /* --- TOTP: as sensitive as a password, so the same countdown --- */
        if (row.has_totp && hasVerb("totp")) {
            host.appendChild(el("h4", null, "One-time code"));
            host.appendChild(revealWidget({
                label: "TOTP",
                help: "The code changes on the authenticator's own schedule; the countdown " +
                      "here is the helper's seconds_remaining.",
                fetch: function () {
                    return SESSION.call("totp", { uuid: row.uuid }).then(function (r) {
                        return { value: r.code, expires_in: r.seconds_remaining };
                    });
                }
            }));
        }

        /* --- attachments --- */
        renderAttachments(host, row);

        /* --- history --- */
        renderHistory(host, row);

        /* --- actions: from the schema, so a new entry verb appears here --- */
        host.appendChild(el("h4", null, "Actions"));
        var acts = el("div", "sec-tools");
        ["edit", "move", "rm"].forEach(function (v) {
            if (!hasVerb(v)) return;
            var b = btn(verbLabel(v), (verbSpec(v).danger ? "danger " : "") + "tiny", function () {
                verbDialog(v, { uuid: row.uuid }, afterMutation, row);
            });
            if (!BROWSE.writable) { b.disabled = true; b.title = "This safe is open read-only."; }
            acts.appendChild(b);
        });
        Object.keys(verbTable()).sort().forEach(function (name) {
            if (isHandled(name)) return;
            if (verbScope(name) !== "entry") return;
            acts.appendChild(btn(verbLabel(name), "tiny", function () {
                verbDialog(name, { uuid: row.uuid }, afterMutation, row);
            }));
        });
        host.appendChild(acts);
    }

    /* A custom field is reached by name through the same single door: the
     * helper's `field` pattern accepts custom:<name>. Nothing is guessed —
     * the operator names the field they already know is there. */
    function customFieldDialog(row) {
        modal("Reveal a custom field", function (box, m) {
            var form = buildForm([{
                id: "custom", label: "Custom field name", control: "text",
                type: "string", required: true, maxlength: 128,
                help: "The name of the custom field inside this entry.",
                breaks_when_wrong: (revealFieldSpec() || {}).breaks_when_wrong || ""
            }]);
            box.appendChild(form.node);
            var out = el("div");
            box.appendChild(out);
            actionRow(box, [
                btn("Reveal", "primary", function () {
                    var bad = form.validate();
                    if (bad) { clear(out); out.appendChild(el("div", "sec-alert err", bad)); return; }
                    var nm = form.values().custom;
                    clear(out);
                    out.appendChild(revealWidget({
                        label: String(nm),
                        fetch: function () {
                            return SESSION.call("reveal",
                                { uuid: row.uuid, field: "custom:" + String(nm) });
                        }
                    }));
                }),
                btn("Close", "", function () { m.close(); })
            ]);
        });
    }

    /* ================================================================== *
     * Attachments
     *
     * Upload, replace, remove and download. Only the download is unusual, and
     * it is unusual in the direction that matters: the bytes come back through
     * the Cockpit channel as base64 in the verb's reply, are turned into a Blob
     * in this page, and are handed to the browser's own save mechanism. NOTHING
     * IS WRITTEN TO THE SERVER'S DISK ON THE WAY (I21). There is no temporary
     * file to forget to delete, because there is no temporary file.
     *
     * Uploads go the same road backwards: FileReader -> base64 -> the JSON
     * request on the helper's stdin, which is then closed (I10).
     * ================================================================== */

    /* Whatever the helper said about an entry's attachments, as
     * [{name, bytes|undefined}] plus a flag saying whether we actually know the
     * names or merely the count. Four shapes are accepted because the contract
     * pins `attachments` on an entries[] row without pinning which of them it
     * is; anything else yields `known:false`, which prints a count and says the
     * names are not available rather than inventing them. */
    function attachmentRows(row) {
        var raw = row.attachments;
        var named = Array.isArray(row.attachment_names) ? row.attachment_names : null;
        if (Array.isArray(raw)) named = raw;
        if (!named) {
            var n = Number(raw);
            return { known: false, count: isFinite(n) && n > 0 ? n : 0, rows: [] };
        }
        var out = named.map(function (a) {
            if (a && typeof a === "object")
                return { name: String(a.name === undefined ? a.filename : a.name),
                         bytes: (a.bytes !== undefined ? a.bytes : a.size) };
            return { name: String(a), bytes: undefined };
        }).filter(function (a) { return a.name && a.name !== "undefined"; });
        return { known: true, count: out.length, rows: out };
    }

    /* The cap the helper publishes for one attachment, read off whichever
     * file-bytes control its add verb declares. Client-side it is FEEDBACK —
     * makeControl already refuses an oversized file before it is even read —
     * and the helper's own refusal is the gate (backends/base.py Limits). */
    function attachmentCap() {
        var adder = verbFor("attachAdd");
        if (!adder) return { format: 0, effective: 0 };
        var format = 0;
        var args = verbArgs(adder);
        for (var i = 0; i < args.length; i++) {
            if (controlType(args[i]) !== "file") continue;
            format = Number(args[i].max_bytes) || Number(args[i].max) || 0;
            if (format) break;
        }
        /* THE CAP THAT ACTUALLY BITES IS THE TRANSPORT, NOT THE FORMAT.
         *
         * The helper's own descriptor says so: the format allows 32 MiB per
         * attachment, but the whole request is capped at max_request_bytes and
         * the bytes travel base64 inside it, which costs a third. So roughly
         * three quarters of the request cap is what fits, and telling an
         * operator "up to 32 MiB" would be a promise that fails at 800 KiB with
         * an error about the request size — a confusing way to find out.
         *
         * The margin leaves room for the rest of the JSON around it. Neither
         * number is enforced here; both are the helper's, and the helper is
         * what refuses. */
        var reqCap = Number((SCHEMA && SCHEMA.constants &&
                             SCHEMA.constants.max_request_bytes) || 0);
        var transport = reqCap ? Math.floor((reqCap * 3 / 4) - 4096) : 0;
        var effective = (format && transport) ? Math.min(format, transport)
                                              : (format || transport || 0);
        return { format: format, effective: effective };
    }

    function renderAttachments(host, row) {
        var info = attachmentRows(row);
        var adder = verbFor("attachAdd");
        var remover = verbFor("attachRm");
        var lister = verbFor("attachList");
        if (!info.count && !adder && !hasVerb("attach-get")) return;

        host.appendChild(el("h4", null, "Attachments"));

        if (!info.count && info.known) {
            host.appendChild(el("p", "sec-subtle", "None."));
        } else if (!info.known && info.count) {
            /* A count with no names. Ask the helper for the names if it offers
             * a verb for them; otherwise say plainly that a download needs a
             * name this helper does not provide, rather than guessing one. */
            host.appendChild(el("p", "sec-subtle",
                info.count + " attachment(s) on this entry."));
            if (lister) {
                host.appendChild(btn("List them", "tiny", function () {
                    SESSION.call(lister, { uuid: row.uuid }).then(function (res) {
                        row.attachment_names =
                            res.names || res.attachments || res.files || [];
                        renderDetail(row);
                    }).catch(function (e) {
                        alertBox(errNode(e));
                        handleSessionError(e);
                    });
                }));
            } else {
                host.appendChild(el("p", "sec-subtle",
                    "Downloading one needs its name, and this helper publishes no verb that " +
                    "lists them."));
            }
        } else if (info.rows.length) {
            var panel = el("div", "sec-panel");
            info.rows.forEach(function (a) {
                var line = el("div", "sec-file-row");
                line.appendChild(el("span", "sec-file-name", a.name));
                if (a.bytes !== undefined)
                    line.appendChild(el("span", "sec-file-size", fmtBytes(a.bytes)));
                line.appendChild(el("span", "sec-spacer"));
                if (hasVerb("attach-get"))
                    line.appendChild(btn("Download", "tiny", function () {
                        downloadAttachment(row.uuid, a.name);
                    }));
                if (adder && BROWSE.writable)
                    /* Replace is the add verb with the name fixed and the
                     * helper's own `replace` flag set, so there is one upload
                     * path and not two. Presetting both means neither control
                     * is drawn: the operator picked the file to overwrite by
                     * pressing the button beside it. */
                    line.appendChild(btn("Replace…", "tiny", function () {
                        attachUploadDialog(row, a.name);
                    }));
                if (remover && BROWSE.writable)
                    line.appendChild(btn("Remove", "danger tiny", function () {
                        attachRemoveDialog(remover, row, a);
                    }));
                panel.appendChild(line);
            });
            host.appendChild(panel);
        }

        if (adder && BROWSE.writable) {
            host.appendChild(btn("Add an attachment…", "tiny", function () {
                attachUploadDialog(row, null);
            }));
            var cap = attachmentCap();
            if (cap.effective) {
                host.appendChild(el("div", "hint",
                    "Up to about " + fmtBytes(cap.effective) + " per attachment. The file is " +
                    "read in this browser and sent inline to the helper; it never lands on " +
                    "the server as a temporary file."));
                if (cap.format && cap.format > cap.effective)
                    host.appendChild(el("div", "hint",
                        "The format itself allows " + fmtBytes(cap.format) + ", but the " +
                        "request the bytes travel in is capped below that, and base64 costs " +
                        "a third on the way. The smaller number is the one that applies."));
            }
        } else if (adder && !BROWSE.writable) {
            host.appendChild(el("p", "sec-subtle",
                "This safe is open read-only, so attachments cannot be changed."));
        }
    }

    /* One dialog for both add and replace. `existingName` non-null means
     * replace: the name is fixed and the helper's replace flag is preset, so
     * the operator is choosing a file and nothing else. */
    function attachUploadDialog(row, existingName) {
        var verb = verbFor("attachAdd");
        if (!verb) return;
        var presets = { uuid: row.uuid };
        var names = argNames(verb);
        if (existingName !== null && existingName !== undefined) {
            presets.name = existingName;
            /* Only set the flag the verb actually declares. A helper whose add
             * verb has no replace flag gets no invented field; it will refuse
             * the duplicate name, which is the correct outcome and a clearer
             * error than a silent overwrite. */
            ["replace", "overwrite", "force"].forEach(function (k) {
                if (names.indexOf(k) >= 0 && presets[k] === undefined) presets[k] = true;
            });
        }
        verbDialog(verb, presets, afterMutation, null, {
            title: existingName ? ("Replace “" + existingName + "”") : "Add an attachment",
            runLabel: existingName ? "Replace the file" : "Attach the file",
            intro: existingName
                ? "The bytes of the file you choose replace the ones stored under this name. " +
                  "Nothing reaches disk until you press Save."
                : "The file is read in this browser and sent inline to the helper. Nothing " +
                  "reaches disk until you press Save.",
            confirm: existingName
                ? "I understand the attachment stored under this name will be overwritten."
                : null
        });
    }

    function attachRemoveDialog(verb, row, a) {
        verbDialog(verb, { uuid: row.uuid, name: a.name }, afterMutation, null, {
            title: "Remove “" + a.name + "”",
            runLabel: "Remove the attachment",
            beforeForm: function (box) {
                box.appendChild(el("div", "sec-alert warn",
                    "Removes “" + a.name + "”" +
                    (a.bytes !== undefined ? " (" + fmtBytes(a.bytes) + ")" : "") +
                    " from this entry, in the helper's memory. It is written to disk when " +
                    "you press Save, and the copy of the safe from before that save is kept " +
                    "in the backup ring (I12) — which is the only way back."));
            }
            /* No `confirm` of this page's own here: attach-rm already declares
             * one, and stacking a second tick box on a small, in-memory,
             * still-undoable action is how operators learn to tick without
             * reading. The two places that DO stack are export and
             * restore-backup, where the action is neither small nor undoable. */
        });
    }

    function downloadAttachment(uuid, name) {
        SESSION.call("attach-get", { uuid: uuid, name: name }).then(function (res) {
            /* The bytes arrive through the Cockpit channel and are handed
             * straight to the browser. Nothing is written to the server's disk
             * on the way (I21). */
            var bytes;
            try { bytes = b64ToBytes(res.b64); }
            catch (e) {
                alertBox(errNode(mkErr("internal",
                    "The helper's reply for this attachment is not valid base64.")));
                return;
            }
            /* application/octet-stream on purpose. Handing the browser the
             * helper's idea of the type would let a file stored inside a safe
             * choose how this page's origin renders it, and "text/html" is a
             * perfectly ordinary thing to find in an attachment. */
            var blob = new Blob([bytes], { type: "application/octet-stream" });
            var url = URL.createObjectURL(blob);
            var a = el("a");
            a.href = url;
            a.download = String(res.name || name);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            /* Revoke on a timer rather than immediately: the click has started
             * a save the browser finishes on its own schedule, and revoking
             * under it truncates the file. */
            window.setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
            var sz = (res.size !== undefined) ? res.size : bytes.length;
            announce("Downloaded " + name + " — " + fmtBytes(sz) + ".");
            alertText("Downloaded “" + name + "” (" + fmtBytes(sz) +
                      ") straight to this browser; no copy was written on the server.", "ok");
        }).catch(function (e) {
            alertBox(errNode(e));
            handleSessionError(e);
        });
    }

    /* ================================================================== *
     * Entry history
     *
     * The helper's row for one version is
     *     {index, when, title, username, url, has_password, notes_len}
     * and what is NOT in it is the whole point: THERE IS NO PASSWORD IN A
     * HISTORY ROW. The helper does not send one, so this page has nothing to
     * mask, nothing to cache, and no countdown to run. `has_password` is a
     * boolean and it is drawn as one; `notes_len` is a length, which is why the
     * helper sends it instead of the notes.
     *
     * Seeing a value that a restore brought back is the ordinary `reveal` path,
     * with its ordinary fifteen-second countdown and its ordinary audit line
     * (I17). There is deliberately no shortcut from here to a value.
     * ================================================================== */

    /* Which of the metadata fields differ between two versions, using only the
     * keys the helper actually sent. A field the helper did not publish is not
     * compared, because "absent" and "changed to nothing" are different facts
     * and pretending otherwise would report edits that never happened. */
    var HISTORY_FIELDS = [
        { key: "title", label: "title" },
        { key: "username", label: "username" },
        { key: "url", label: "URL" },
        { key: "has_password", label: "password" },
        { key: "notes_len", label: "notes" }
    ];

    function historyChanges(older, newer) {
        var out = [];
        HISTORY_FIELDS.forEach(function (f) {
            var a = older ? older[f.key] : undefined;
            var b = newer ? newer[f.key] : undefined;
            if (a === undefined && b === undefined) return;
            if (txt(a) !== txt(b)) out.push(f.label);
        });
        return out;
    }

    /* The per-entry panel. It is loaded on demand rather than with the entry:
     * history is one verb call per entry, and paying it for every row an
     * operator merely clicks through would be a lot of audit lines for a
     * question nobody asked. */
    function renderHistory(host, row) {
        var verb = verbFor("history");
        if (!verb) return;
        host.appendChild(el("h4", null, "History"));
        var panel = el("div");
        host.appendChild(panel);

        var load = btn("Show history", "tiny", function () {
            clear(panel);
            panel.appendChild(el("p", "sec-subtle", "Loading…"));
            SESSION.call(verb, { uuid: row.uuid }).then(function (res) {
                clear(panel);
                var list = (res && (res.history || res.versions || res.entries)) || [];
                if (!Array.isArray(list) || !list.length) {
                    panel.appendChild(el("p", "sec-subtle",
                        "No previous versions are recorded for this entry."));
                    panel.appendChild(load);
                    return;
                }
                renderHistoryList(panel, row, list);
            }).catch(function (e) {
                clear(panel);
                panel.appendChild(errNode(e));
                panel.appendChild(load);
                handleSessionError(e);
            });
        });
        panel.appendChild(load);
    }

    function renderHistoryList(panel, row, list) {
        var restoreVerb = verbFor("historyRestore");

        /* OLDEST FIRST, so "what changed" reads forwards in time the way a
         * person reads it. `index` counts forwards too — 0 is the oldest
         * recorded version — so ascending is both.
         *
         * This sort was descending for a while because the helper's `index`
         * descriptor claimed 0 was "the most recently archived version". The
         * descriptor was wrong and the `when` timestamps say so: an entry
         * edited twice comes back with index 0 carrying the ORIGINAL
         * modification time. Both were corrected together; do not change one
         * of them alone.
         *
         * `index` itself is preserved on every row rather than recomputed from
         * this ordering, because it is what a restore is addressed by. */
        var rows = list.slice().sort(function (a, b) {
            return (Number(a.index) || 0) - (Number(b.index) || 0);
        });

        var box = el("div", "sec-panel");
        rows.forEach(function (v, ix) {
            var line = el("div", "sec-hist-row");

            var head = el("div", "sec-hist-head");
            var when = fmtWhen(v.when !== undefined ? v.when : v.modified);
            head.appendChild(el("span", "sec-hist-when",
                (when || "no timestamp recorded") +
                (v.index !== undefined ? "  ·  version " + v.index : "")));
            if (restoreVerb && BROWSE && BROWSE.writable)
                head.appendChild(btn("Restore this version", "tiny", function () {
                    historyRestoreConfirm(restoreVerb, row, v);
                }));
            line.appendChild(head);

            line.appendChild(el("div", "sec-hist-title",
                txt(v.title) || "(untitled in this version)"));

            /* The metadata this version carried. Never a value: a key that
             * looks like one is dropped and the drop is reported, so a helper
             * that starts sending passwords in history rows is noticed here
             * rather than quietly rendered. */
            var meta = [];
            var leaked = [];
            Object.keys(v).forEach(function (k) {
                if (k === "index" || k === "when" || k === "modified" || k === "title") return;
                if (k === "password" || k === "value" || k === "b64" || k === "secret") {
                    if (v[k] !== undefined && v[k] !== null) leaked.push(k);
                    return;
                }
                if (k === "has_password") {
                    meta.push(v[k] ? "had a password" : "no password");
                    return;
                }
                if (k === "notes_len") {
                    meta.push(Number(v[k]) ? (v[k] + " characters of notes") : "no notes");
                    return;
                }
                if (v[k] === undefined || v[k] === null || v[k] === "") return;
                meta.push(k.replace(/_/g, " ") + ": " + txt(v[k]));
            });
            if (meta.length) line.appendChild(el("div", "sec-hist-change", meta.join("  ·  ")));
            if (leaked.length)
                line.appendChild(el("div", "sec-alert warn",
                    "This helper put " + leaked.join(", ") + " in a history row. This page " +
                    "does not render it: a value belongs behind the reveal countdown, not in " +
                    "a list (I17)."));

            var changed = ix === 0 ? null : historyChanges(rows[ix - 1], v);
            var ch = el("div", "sec-hist-change");
            if (changed === null) {
                ch.textContent = "The oldest recorded version.";
            } else if (!changed.length) {
                ch.textContent = "No change in any field the helper reports.";
            } else {
                ch.appendChild(document.createTextNode("Changed: "));
                ch.appendChild(el("span", "changed", changed.join(", ")));
                ch.appendChild(document.createTextNode("."));
            }
            line.appendChild(ch);
            box.appendChild(line);
        });
        panel.appendChild(box);

        /* The live entry, so the newest history row can be read against what is
         * in the safe now rather than against nothing. */
        var last = rows[rows.length - 1];
        var vsNow = historyChanges(last, row);
        panel.appendChild(el("p", "sec-subtle", vsNow.length
            ? ("Since the newest recorded version, this entry's " + vsNow.join(", ") +
               " changed.")
            : "The entry as it stands matches the newest recorded version in every field " +
              "the helper reports."));
        if (!restoreVerb)
            panel.appendChild(el("p", "sec-subtle",
                "This helper lists history but offers no restore verb."));
    }

    /* Restoring is in the helper's MEMORY, not on disk. Saying so is the whole
     * job of this confirm: an operator who restores and then closes the tab has
     * changed nothing, and one who restores the wrong version can lock without
     * saving and lose only the restore. */
    function historyRestoreConfirm(verb, row, version) {
        var when = fmtWhen(version.when !== undefined ? version.when : version.modified);
        var presets = { uuid: row.uuid };
        var names = argNames(verb);
        var key = ["index", "version", "n"].filter(function (k) {
            return names.indexOf(k) >= 0;
        })[0] || "index";
        presets[key] = (version.index !== undefined) ? version.index : 0;

        verbDialog(verb, presets, afterMutation, null, {
            title: "Restore a previous version",
            runLabel: "Restore this version",
            beforeForm: function (box) {
                var w = el("div", "sec-alert warn");
                w.appendChild(el("p", null,
                    "This replaces the entry's current fields with the version recorded " +
                    (when ? "at " + when : "under that index") + ", including its password."));
                w.appendChild(el("p", null,
                    "It happens in the helper's memory only. Nothing reaches disk until you " +
                    "press Save, and locking without saving discards it — the safe on disk " +
                    "is left exactly as it is."));
                w.appendChild(el("p", null,
                    "The value it brings back is not shown here. Reveal it afterwards the " +
                    "usual way, with the usual countdown."));
                box.appendChild(w);
            },
            onResult: function (res) {
                var msg = "Restored version " +
                    (res && res.restored_from !== undefined ? res.restored_from : presets[key]) +
                    " into memory. Press Save to write it to disk.";
                alertText(msg, "ok");
                announce(msg);
                /* No reload here: `afterMutation` is this dialog's `done`
                 * callback and it already reloads the tree and the entries,
                 * which is what rebuilds the detail pane from the restored
                 * entry. Calling it twice would be two more verb round trips
                 * for the same screen. */
            }
        });
    }

    /* ================================================================== *
     * Generic verb dialog — this is what makes "add a verb, get a form" true
     * ================================================================== */
    function addArgv(argv, spec, value) {
        /* A secret must never be able to reach a command line (I10). If a
         * schema ever asked for that, refuse rather than comply. */
        if (isSecretSpec(spec))
            throw mkErr("invalid",
                "The helper's schema puts “" + specName(spec) + "” on the command line, but " +
                "it is a secret. This page will not put a secret on argv.");
        argv.push("--" + specName(spec), String(value));
    }

    /* Drop keys whose value is undefined, so "no group selected" means "draw
     * the group control", not "silently send nothing". */
    function defined(obj) {
        var out = {};
        Object.keys(obj || {}).forEach(function (k) {
            if (obj[k] !== undefined && obj[k] !== null) out[k] = obj[k];
        });
        return out;
    }

    /* Which of the two invocations in docs/ARCHITECTURE.md a verb uses. The
     * helper says `access: "any" | "class"`; "class" means the safe's own
     * class decides, and admin is the default class (I1). A verb reached from
     * the safe list with no safe open is called unescalated and the helper is
     * left to refuse if it disagrees — the browser never decides this (I3). */
    function adminForVerb(name, safe) {
        var spec = verbSpec(name) || {};
        if (spec.admin === true) return true;
        if (spec.access === "any") return false;
        /* `safe` is passed by the flows that run a verb against a safe which is
         * NOT the one currently open — export and restore are both reachable
         * from the safe list, with nothing unlocked. Without it those would be
         * spawned unescalated against an admin-class safe, and the helper's
         * refusal would read as "not permitted" when the truth is "you were
         * never asked for administrative access". */
        var s = safe || (BROWSE ? BROWSE.safe : null);
        return s ? isAdminClass(s) : false;
    }

    /* The fields the open session already supplies, so no form should ask for
     * them again: the handle, and everything the `unlock` request carries.
     *
     * This matters because most verbs can ALSO be run single-shot — the helper
     * lists `safe`, `password` and `keyfile_b64` on `add` and `edit` so one
     * process can unlock, change and save without an open session. Drawing
     * those inside an unlocked session would ask the operator to type the
     * master passphrase a second time to add an entry to a safe that is
     * already open in front of them, which is not prompting, it is nagging —
     * and it would put a second copy of the passphrase on screen. The set is
     * read from the schema's own unlock descriptor, not written here. */
    function sessionSuppliedFields() {
        var out = { "handle": 1 };
        argNames("unlock").forEach(function (n) { if (n) out[n] = 1; });
        return out;
    }

    /* presets: values supplied by the page (uuid, group, safe...) — they are
     * not drawn and not editable. `values` pre-fills drawn controls.
     *
     * `opts` is how the purpose-built flows below (export, save-as, restore)
     * reuse this dialog instead of growing their own copy of the submit path.
     * Everything that is delicate — the argv refusal for a secret, the envelope
     * nesting, reading secrets one at a time and dropping them immediately —
     * lives here once and nowhere else, so a new flow cannot get it subtly
     * wrong. What `opts` may change is the wording around the form, not the
     * handling of what the form collects:
     *
     *   title       heading, when the verb's own is too terse for the context
     *   intro       a sentence under the heading
     *   safe        the safe this runs against, when it is not the open one —
     *               decides escalation (see adminForVerb)
     *   beforeForm  a callback that may put anything above the controls; used
     *               for the export warning, which must be read before the
     *               format selector is even reached
     *   confirm     an EXTRA sentence the operator must tick, on top of any the
     *               helper attached. Both must be ticked; they are AND-ed,
     *               never replaced, so a page-side warning cannot swallow the
     *               helper's own
     *   runLabel    the primary button's text
     *   onResult    render the answer instead of the generic result view
     */
    function verbDialog(name, presets, done, values, opts) {
        var spec = verbSpec(name);
        if (!spec) return;
        opts = opts || {};
        presets = defined(presets);
        var onArgv = !usesStdin(name);
        var inSession = !!SESSION && needsSession(name);
        var supplied = inSession ? sessionSuppliedFields() : { "handle": 1 };
        var specs = verbArgs(name).filter(function (a) {
            var n = specName(a);
            if (!a || !n) return false;
            if (supplied[n]) return false;
            return !Object.prototype.hasOwnProperty.call(presets, n);
        });

        modal(opts.title || verbLabel(name), function (box, m) {
            if (spec.danger)
                box.appendChild(el("div", "sec-alert warn",
                    "This action is destructive. There is no undo except the backup ring the " +
                    "helper writes before a save."));
            if (opts.intro) box.appendChild(el("p", "sec-modal-intro", String(opts.intro)));
            if (spec.help) box.appendChild(el("p", "sec-modal-intro", spec.help));
            if (spec.breaks_when_wrong)
                box.appendChild(el("div", "sec-alert info", String(spec.breaks_when_wrong)));
            /* Anything that has to be READ before the form is reached — the
             * export warning naming the destination, the restore warning naming
             * what is about to be overwritten. Above the controls on purpose. */
            if (opts.beforeForm) opts.beforeForm(box);

            var form = buildForm(specs, { values: values || {} });
            box.appendChild(form.node);
            /* A caller that needs to reach the controls themselves — save-as
             * annotating whichever control turns out to carry the file name.
             * It gets the form object, not a DOM query into the modal host:
             * the second works right up until two dialogs are open. */
            if (opts.afterForm) opts.afterForm(form, box);

            /* The helper can demand an explicit confirmation, in its own
             * words, and a caller can demand one of its own. Run stays disabled
             * until EVERY one of them is ticked — the sentences are not
             * decoration, and a caller's warning never replaces the helper's. */
            var confirmBoxes = [];
            [spec.confirm, opts.confirm].forEach(function (sentence) {
                if (!sentence) return;
                var cid = "sec-confirm" + (++CTRL_SEQ);
                var cb = el("input");
                cb.type = "checkbox";
                cb.id = cid;
                var cl = el("label", "sec-check");
                cl.setAttribute("for", cid);
                cl.appendChild(cb);
                cl.appendChild(el("span", null, String(sentence)));
                var cw = el("div", "sec-alert warn");
                cw.appendChild(cl);
                box.appendChild(cw);
                confirmBoxes.push(cb);
                cb.addEventListener("change", function () {
                    go.disabled = confirmBoxes.some(function (x) { return !x.checked; });
                });
            });

            var errHost = el("div");
            box.appendChild(errHost);

            var go = btn(opts.runLabel || "Run", spec.danger ? "danger" : "primary", submit);
            if (confirmBoxes.length) go.disabled = true;
            actionRow(box, [go, btn("Cancel", "", function () { m.close(); })]);

            function submit() {
                clear(errHost);
                var bad = form.validate();
                if (bad) { errHost.appendChild(el("div", "sec-alert err", bad)); return; }
                go.disabled = true;

                var req = {};
                var argv = [];
                var env = envelopeFor(name);
                var bag = env ? {} : req;

                Object.keys(presets).forEach(function (k) {
                    if (presets[k] !== undefined) req[k] = presets[k];
                });
                var vals = form.values();
                var argvErr = null;
                form.controls.forEach(function (c) {
                    if (c.secret || !c.visible()) return;
                    var v = vals[specName(c.spec)];
                    if (v === undefined) return;
                    if (onArgv) {
                        try { addArgv(argv, c.spec, v); } catch (e) { argvErr = e; }
                    } else {
                        bag[specName(c.spec)] = v;
                    }
                });
                if (argvErr) {
                    go.disabled = false;
                    errHost.appendChild(errNode(argvErr));
                    return;
                }
                /* Secrets last and separately, including the ones nested inside
                 * an object control, so nothing carrying a value is ever part
                 * of the values() bag that the rest of this function handles. */
                form.applySecrets(bag);
                if (env) req[env] = bag;

                var p = needsSession(name)
                    ? (SESSION ? SESSION.call(name, req)
                               : Promise.reject(mkErr("access-denied", "The safe is locked.")))
                    : callOnce(name, req, adminForVerb(name, opts.safe), argv);

                p.then(function (res) {
                    /* Drop every reference to whatever we just sent. */
                    dropDeep(bag);
                    form.wipeAll();
                    m.close();
                    if (done) done(res, name);
                    if (opts.onResult) opts.onResult(res, name);
                    else showResult(verbLabel(name), res, mutates(name));
                }).catch(function (e) {
                    dropDeep(bag);
                    form.wipeSecrets();
                    go.disabled = false;
                    errHost.appendChild(errNode(e));
                    handleSessionError(e);
                });
            }
        });
    }

    /* A one-line summary of a result that carries no value: field names and
     * scalars only. `value` is excluded by name — a value belongs in a reveal
     * control with a countdown, never in a banner that stays on screen. */
    function summarize(res) {
        var parts = [];
        Object.keys(res || {}).forEach(function (k) {
            if (k === "ok" || k === "value" || k === "b64") return;
            var v = res[k];
            if (v === undefined || v === null) return;
            if (Array.isArray(v)) {
                if (v.every(function (x) { return x === null || typeof x !== "object"; }))
                    parts.push(k.replace(/_/g, " ") + ": " + v.join(", "));
                return;
            }
            if (typeof v !== "object") parts.push(k.replace(/_/g, " ") + ": " + v);
        });
        return parts.join(" · ");
    }

    /* A result view that is registered with the wipers, so locking scrubs it
     * even if a verb returned something sensitive.
     *
     * `quiet` is used for the mutation verbs: an add or an edit that worked
     * should leave a line in the page, not a dialog to dismiss before the Save
     * button can be reached. A result carrying a value is never quiet. */
    function showResult(title, res, quiet) {
        var trivial = !res || Object.keys(res).length === 0 ||
            (Object.keys(res).length === 1 && res.ok === true);
        var carriesValue = res && res.value !== undefined && res.value !== null;
        if (trivial || (quiet && !carriesValue)) {
            var line = title + ": done." + (trivial ? "" : " " + summarize(res));
            announce(line);
            alertText(line, "ok");
            return;
        }
        modal(title, function (box, m) {
            var host = el("div");
            box.appendChild(host);
            renderAnyResult(host, res);
            actionRow(box, [btn("Close", "", function () { m.close(); })]);
        }, { wide: true, onClose: function () { /* the wiper stays registered */ } });
    }

    /* Render an arbitrary helper response without pretending to know it. A
     * `value` key is treated as a secret and gets the reveal countdown rather
     * than being printed. */
    function renderAnyResult(host, res) {
        if (res && res.value !== undefined && typeof res.value === "string") {
            /* A verb returned a value. Treat it exactly like a revealed field:
             * countdown, masked by default, and the closure holding it is
             * released when the safe is locked rather than living as long as
             * the page does. */
            var v = res.value;
            res.value = null;
            var w = revealWidget({
                label: "value",
                seconds: uiNum("reveal_seconds", 15),
                fetch: function () { return Promise.resolve({ value: v === null ? "" : v }); }
            });
            trackWiper(function () { v = null; });
            host.appendChild(w);
            var rest = {};
            Object.keys(res).forEach(function (k) { if (k !== "value") rest[k] = res[k]; });
            if (Object.keys(rest).length) host.appendChild(kvList(rest));
            return;
        }
        var arrayKey = null;
        Object.keys(res || {}).forEach(function (k) {
            if (Array.isArray(res[k]) && res[k].length && typeof res[k][0] === "object") arrayKey = k;
        });
        if (arrayKey) {
            var rest2 = {};
            Object.keys(res).forEach(function (k) { if (k !== arrayKey) rest2[k] = res[k]; });
            if (Object.keys(rest2).length) host.appendChild(kvList(rest2));
            host.appendChild(resultTable(res[arrayKey], null));
            return;
        }
        host.appendChild(kvList(res));
    }

    function kvList(obj) {
        var dl = el("dl", "sec-kv");
        Object.keys(obj || {}).forEach(function (k) {
            dl.appendChild(el("dt", null, k.replace(/_/g, " ")));
            var dd = el("dd");
            var v = obj[k];
            if (typeof v === "boolean") dd.appendChild(badge(v ? "yes" : "no", v ? "ok" : ""));
            else if (v && typeof v === "object") dd.appendChild(el("pre", "sec-pre", JSON.stringify(v, null, 2)));
            else dd.textContent = txt(v);
            dl.appendChild(dd);
        });
        var node = el("div");
        node.appendChild(dl);
        trackWiper(function () { clear(dl); });
        return node;
    }

    function resultTable(list, actionFor) {
        var cols = [];
        list.forEach(function (r) {
            Object.keys(r || {}).forEach(function (k) {
                if (cols.indexOf(k) < 0) cols.push(k);
            });
        });
        var wrap = el("div", "sec-scroll");
        var t = el("table", "sec");
        var htr = el("tr");
        cols.forEach(function (c) {
            var th = el("th", null, c.replace(/_/g, " "));
            th.scope = "col";
            htr.appendChild(th);
        });
        if (actionFor) htr.appendChild(el("th", null, ""));
        t.appendChild(htr);
        list.forEach(function (r, i) {
            var tr = el("tr");
            cols.forEach(function (c) {
                var td = el("td");
                var v = r[c];
                if (typeof v === "boolean") td.appendChild(badge(v ? "yes" : "no", v ? "ok" : ""));
                else td.textContent = txt(v);
                tr.appendChild(td);
            });
            if (actionFor) {
                var td2 = el("td");
                var b = actionFor(r, i);
                if (b) td2.appendChild(b);
                tr.appendChild(td2);
            }
            t.appendChild(tr);
        });
        wrap.appendChild(t);
        trackWiper(function () { clear(t); });
        return wrap;
    }

    function runAndShow(verb, req, admin, title) {
        callOnce(verb, req, admin).then(function (res) {
            modal(title || verb, function (box, m) {
                var host = el("div");
                box.appendChild(host);
                renderAnyResult(host, res);
                actionRow(box, [btn("Close", "", function () { m.close(); })]);
            }, { wide: true });
        }).catch(function (e) { alertBox(errNode(e)); });
    }

    function auditDialog() {
        /* audit-tail is the one contract verb with an argv argument (--n). It
         * carries no secret, which is the only reason it may be there (I10). */
        modal("Audit log", function (box, m) {
            var form = buildForm(verbArgs("audit-tail").length
                ? verbArgs("audit-tail")
                : [{ name: "n", label: "Lines", type: "int", required: false, "default": 50,
                     on: "argv", min: 1, max: 1000 }]);
            box.appendChild(form.node);
            var out = el("div");
            box.appendChild(out);
            actionRow(box, [
                btn("Show", "primary", function () {
                    clear(out);
                    var vals = form.values();
                    var argv = [];
                    var req = {};
                    var bad = null;
                    form.controls.forEach(function (c) {
                        var v = vals[specName(c.spec)];
                        if (v === undefined) return;
                        if (!usesStdin("audit-tail") || specName(c.spec) === "n") {
                            try { addArgv(argv, c.spec, v); } catch (e) { bad = e; }
                        } else req[specName(c.spec)] = v;
                    });
                    if (bad) { out.appendChild(errNode(bad)); return; }
                    callOnce("audit-tail", req, adminAllowed(), argv).then(function (res) {
                        clear(out);
                        renderAnyResult(out, res);
                    }).catch(function (e) {
                        clear(out);
                        out.appendChild(errNode(e));
                    });
                }),
                btn("Close", "", function () { m.close(); })
            ]);
            box.appendChild(el("p", "sec-subtle",
                "The audit log records the verb, the safe, the caller's uid and the outcome. " +
                "It never records a value (I15)."));
        }, { wide: true });
    }

    /* ================================================================== *
     * Password generator — entirely schema-driven (the policy controls are
     * whatever the helper's `generate` verb declares)
     * ================================================================== */
    function generateDialog(onValue) {
        /* The generated value lives in ONE variable in this dialog's scope and
         * is dropped when the dialog closes — the same rule the passphrase
         * follows. Nothing keeps it afterwards. */
        var generated = null;
        modal(verbLabel("generate"), function (box, m) {
            var form = buildForm(verbArgs("generate"));
            box.appendChild(form.node);
            var out = el("div");
            box.appendChild(out);
            actionRow(box, [
                btn("Generate", "primary", function () {
                    clear(out);
                    var bad = form.validate();
                    if (bad) { out.appendChild(el("div", "sec-alert err", bad)); return; }
                    var env = envelopeFor("generate");
                    var vals = form.values();
                    var req = env ? {} : vals;
                    if (env) req[env] = vals;
                    callOnce("generate", req, false).then(function (res) {
                        clear(out);
                        if (res.entropy_bits !== undefined)
                            out.appendChild(el("div", "sec-alert ok",
                                res.entropy_bits + " bits of entropy, as computed by the helper."));
                        generated = String(res.value === undefined ? "" : res.value);
                        res.value = null;
                        out.appendChild(revealWidget({
                            label: "Generated value",
                            fetch: function () {
                                return Promise.resolve({ value: generated === null ? "" : generated });
                            }
                        }));
                        /* The generator's own entropy figure is the helper's
                         * arithmetic over the policy it was given. The strength
                         * verb is its opinion of the string that came out —
                         * a different question, and the one that catches a
                         * policy which happens to have produced something the
                         * dictionary knows. Both are shown when both exist. */
                        if (verbFor("strength") || verbFor("breach")) {
                            var sw = strengthWidget();
                            out.appendChild(sw.node);
                            sw.attach(function () { return generated || ""; })();
                        }
                        if (onValue)
                            out.appendChild(btn("Use this value", "primary", function () {
                                onValue(generated);
                                m.close();
                            }));
                    }).catch(function (e) {
                        clear(out);
                        out.appendChild(errNode(e));
                    });
                }),
                btn("Close", "", function () { m.close(); })
            ]);
        }, { onClose: function () { generated = null; } });
    }
    /* The little "Generate" button beside every password control. */
    function generateInto(input) {
        generateDialog(function (value) {
            input.value = value;
            value = null;
            /* Setting .value from script fires no event, so the strength meter
             * attached to this control would keep showing the verdict on
             * whatever was typed before. Dispatching `change` is what makes the
             * meter score the generated value — the requirement is a live meter
             * on the generator as well as on a typed field, and a meter that
             * goes stale exactly when the value changes is worse than none. */
            try { input.dispatchEvent(new Event("change")); }
            catch (e) { /* an engine without the Event constructor: no meter update */ }
        });
    }

    /* ================================================================== *
     * Save, and the conflict decision
     * ================================================================== */
    /* `save` is the only mutation that reaches disk, and the helper attaches a
     * confirm sentence to it. The Save button is purpose-built rather than
     * generated, so it has to honour that sentence explicitly — a confirm the
     * helper asked for must not be lost because the page drew its own button. */
    function doSave() {
        if (!SESSION || !BROWSE) return;
        var spec = verbSpec("save") || {};
        if (!spec.confirm) { doSaveNow(); return; }
        modal(verbLabel("save"), function (box, m) {
            box.appendChild(el("p", null, String(spec.confirm)));
            if (spec.help) box.appendChild(el("p", "sec-subtle", String(spec.help)));
            box.appendChild(el("p", "sec-subtle",
                "The helper copies the current file into the backup ring before the first new " +
                "byte exists, writes a temporary file beside it, and renames — so an " +
                "interrupted save leaves either the whole old file or the whole new one."));
            actionRow(box, [
                btn("Save", "primary", function () { m.close(); doSaveNow(); }),
                btn("Cancel", "", function () { m.close(); })
            ]);
        });
    }

    function doSaveNow() {
        if (!SESSION || !BROWSE) return;
        var b = byId("sec-save");
        if (b) b.disabled = true;
        SESSION.call("save", {}).then(function (res) {
            setDirty(0);
            updateSaveButton();
            var msg = "Saved" + (res && res.bytes ? " — " + res.bytes + " bytes" : "") +
                (res && res.backup ? ", previous copy kept at " + res.backup : "") + ".";
            alertText(msg, "ok");
            announce(msg);
        }).catch(function (e) {
            updateSaveButton();
            if (errCode(e) === "conflict") { conflictDialog(e); return; }
            alertBox(errNode(e));
            handleSessionError(e);
        });
    }

    /* A conflict is a decision, not an alert: the file on disk changed under
     * us, or a desktop client holds the lock. Nothing has been written (I13). */
    function conflictDialog(e) {
        var saveAs = verbFor("saveAs");
        modal("The safe changed on disk", function (box, m) {
            box.appendChild(errNode(e));
            box.appendChild(el("p", null,
                "Nothing has been written. The helper compares the file's size, modification " +
                "time and SHA-256 against what it read at unlock, and refuses rather than " +
                "merging — a silent merge is how a desktop client's changes disappear."));
            box.appendChild(el("p", null, "Choose one:"));

            var reload = btn("Discard mine and reload", "danger", function () {
                m.close();
                lockNow("you chose to reload the safe from disk");
                alertText("The safe was locked so it can be re-read from disk. Unlock it again " +
                          "— the passphrase is asked for every time, including this one.", "info");
            });
            var sa = btn(saveAs ? verbLabel(saveAs) : "Save as…", "", function () {
                m.close();
                /* The same save-as flow the toolbar uses, with its name
                 * advisory and its result line. A conflict is a bad moment to
                 * be given a second, subtly different dialog. */
                saveAsDialog();
            });
            if (!saveAs) {
                sa.disabled = true;
                sa.title = "This helper does not offer a save-as verb.";
            }
            var cancel = btn("Keep my changes here", "", function () { m.close(); });
            actionRow(box, [reload, sa, cancel]);
            box.appendChild(el("p", "sec-subtle",
                "“Keep my changes here” leaves them in the helper's memory only. They " +
                "are gone when this session ends, and the safe on disk stays as it is."));
        }, { noEscape: true });
    }

    /* ================================================================== *
     * The agent banner (I18)
     *
     * This is the one place in the program where a safe is unlocked while
     * nobody is looking at it. Everywhere else the unlock lives inside a helper
     * process the page is holding open, so closing the tab ends it; an agent
     * holds a key behind an AF_UNIX socket that outlives this page entirely.
     *
     * The rule that follows is short: AN UNLOCKED SAFE MUST NEVER BE INVISIBLE.
     * So the banner
     *   - lives above the view switch, in an element neither view clears, and
     *     is therefore on screen from the safe list, from inside a different
     *     safe, and from anywhere else this page can be;
     *   - is sticky, because scrolling is not permission to forget;
     *   - counts down to the lock the helper will actually perform, from the
     *     helper's own number;
     *   - carries a Lock button per held safe, so ending it is one click from
     *     wherever the operator is standing.
     *
     * And the other half of the rule, which is just as important: WHEN NOTHING
     * IS HELD THERE IS NO BANNER. Not a greyed-out one, not "no safes are
     * unlocked". The agent is off unless a registry entry opts in, and the
     * default configuration must not grow furniture implying that something is
     * being watched. An empty host collapses to nothing (`.sec-agent-host:empty`
     * in the stylesheet) and a helper with no agent verb at all is never even
     * polled.
     * ================================================================== */

    function agentPollSeconds() { return uiNum("agent_poll_seconds", 15); }

    /* WHERE THE PAGE LEARNS THAT A SAFE IS HELD.
     *
     * Two sources, and both matter.
     *
     *  1. THE UNLOCK REPLY, immediately. `unlock` answers with an `agent` block
     *     — {held, expires_in, idle_seconds, max_seconds, socket} — present only
     *     when the registry enabled the agent AND the daemon took the handle.
     *     That reply is the instant the hold begins, so the banner learns about
     *     it then rather than up to a poll interval later. There must be no
     *     window in which a safe is held and not shown.
     *
     *  2. THE `health` VERB, authoritatively. The helper probes both class
     *     sockets for this uid and returns what the daemon says it is holding —
     *     with no handle and no passphrase, which is the whole point: a page
     *     that has just been reloaded, or that never created the hold at all,
     *     can still see it. This is what makes "an unlocked safe must never be
     *     invisible" true across a page reload and not merely within one.
     *
     * The daemon's own status reply carries the handle; the helper strips it
     * before it reaches here, and nothing on this page wants it. Locking does
     * not need one: the `lock` verb takes a bare safe id for exactly this case,
     * because "once the helper that unlocked a safe has exited, the agent is
     * the only thing still saying it is unlocked, and a Lock button that could
     * not reach it would be a button that lies".
     */

    /* Pull the holdings out of a `health` reply. Shape:
     *   agent: { user: ROW, admin: ROW }
     *   ROW  : { socket, present, reachable, reason, status }
     *   status.holdings: [{safe, age, expires_in, idle_expires_in}]
     * A class whose socket is present but NOT reachable is a fault, not an
     * absence, and it is reported as one. */
    function agentRowsFromHealth(res) {
        var out = { rows: [], faults: [] };
        var blk = res && res.agent;
        if (!blk || typeof blk !== "object") return out;
        var now = Date.now();
        ["user", "admin"].forEach(function (cls) {
            var row = blk[cls];
            if (!row || typeof row !== "object") return;
            if (row.present && !row.reachable) {
                out.faults.push({ cls: cls,
                    reason: String(row.reason || "the agent socket did not answer") });
                return;
            }
            var held = row.status && row.status.holdings;
            if (!Array.isArray(held)) return;
            held.forEach(function (h) {
                if (!h || !h.safe) return;
                var known = safeSpecById(h.safe);
                /* The idle timeout usually fires long before the absolute one,
                 * so the number that matters is whichever comes first. Showing
                 * the larger would be a countdown that is wrong in the
                 * dangerous direction: it would say a safe stays open longer
                 * than it will, and an operator would stop watching. */
                var abs = Number(h.expires_in);
                var idle = Number(h.idle_expires_in);
                var secs = [abs, idle].filter(function (n) {
                    return isFinite(n) && n >= 0;
                }).sort(function (a, b) { return a - b; })[0];
                out.rows.push({
                    safe: h.safe,
                    label: (known && (known.label || known.id)) || h.safe,
                    cls: cls,
                    idle_expires_in: idle,
                    expires_in: abs,
                    _deadline: (secs !== undefined && secs > 0) ? now + secs * 1000 : 0
                });
            });
        });
        return out;
    }

    /* The immediate signal, straight off the unlock reply. */
    function agentNoted(safe, unlockRes) {
        var a = unlockRes && unlockRes.agent;
        if (!a || a.held === false) return;
        var secs = Number(a.expires_in !== undefined ? a.expires_in : a.max_seconds);
        AGENT.rows = AGENT.rows.filter(function (r) { return r.safe !== safe.id; });
        AGENT.rows.push({
            safe: safe.id,
            label: safe.label || safe.id,
            cls: isAdminClass(safe) ? "admin" : "user",
            idle_seconds: a.idle_seconds,
            max_seconds: a.max_seconds,
            _deadline: (isFinite(secs) && secs > 0) ? Date.now() + secs * 1000 : 0
        });
        renderAgentBanner();
        /* And confirm against the daemon, so the row this page just invented
         * from its own reply is replaced by the one the agent actually holds. */
        refreshAgent();
    }

    function agentDrop(safeId) {
        var before = AGENT.rows.length;
        AGENT.rows = AGENT.rows.filter(function (r) { return r.safe !== safeId; });
        if (AGENT.rows.length !== before) renderAgentBanner();
    }

    /* Ask the helper what the daemon is holding. `health` needs no handle, no
     * passphrase and no escalation to answer for the user-class socket; it is
     * run escalated only when administrative access is ALREADY on, so that the
     * admin-class socket is visible too without this poll being the thing that
     * throws a password prompt at somebody who left the page open. */
    /* Whether the agent is worth asking about at all.
     *
     * In the default configuration the agent is off for every safe, and in that
     * configuration this page must cost NOTHING: no poll, no spawn, and above
     * all no root helper process every fifteen seconds to interrogate a daemon
     * that is not running. The agent is opt-in per registry entry, so the poll
     * is too — it happens only when an entry has opted in, or when something is
     * currently held, which can only be true if one did. */
    function agentWatched() {
        if (AGENT.rows.length) return true;
        for (var i = 0; i < SAFES.length; i++)
            if (SAFES[i] && SAFES[i].agent_enabled === true) return true;
        return false;
    }

    /* Escalate the poll only when an ADMIN-class safe has opted in AND Cockpit
     * has already granted administrative access.
     *
     * Escalating otherwise spawns a root helper on every poll to look at a
     * socket that no admin-class safe uses; and escalating when access is NOT
     * already granted would turn a background poll into an administrative
     * password prompt that the operator did not ask for and cannot connect to
     * anything they did. The user-class socket is visible unescalated, which is
     * the case that matters for a safe the caller owns. */
    function agentPollAdmin() {
        if (!adminAllowed()) return false;
        for (var i = 0; i < SAFES.length; i++)
            if (SAFES[i] && SAFES[i].agent_enabled === true && isAdminClass(SAFES[i]))
                return true;
        return false;
    }

    /* One `health` call, cached, feeding both the agent banner and the export
     * destination. It carries no secret, needs no handle and needs no
     * escalation for the user-class view, which is why it can be a background
     * call at all. */
    function refreshHealth(escalate) {
        if (!hasVerb("health")) { renderAgentBanner(); return Promise.resolve(); }
        return callOnce("health", {}, !!escalate).then(function (res) {
            HEALTH = res || null;
            var got = agentRowsFromHealth(res);
            AGENT.failed = got.faults.length ? got.faults : null;
            /* The daemon's answer replaces this page's guesses outright. A row
             * this page added from an unlock reply that the agent turns out not
             * to be holding must disappear, not linger. */
            AGENT.rows = got.rows;
            renderAgentBanner();
        }).catch(function (e) {
            /* A health call that fails must not silently empty the banner:
             * "cannot tell" and "nothing is held" are different answers, and
             * showing the second when the first is true is exactly the
             * invisible unlocked safe this section exists to prevent. */
            AGENT.failed = [{ cls: "", reason: errText(e) }];
            renderAgentBanner();
        });
    }

    /* The periodic half. `health` is fetched ONCE at load whatever the registry
     * says, because the export confirm needs its destination; after that it is
     * re-fetched only while a registry entry has actually opted into the agent.
     * In the default configuration that means one call for the life of the
     * page, not one every fifteen seconds — and never a root one. */
    function refreshAgent() {
        if (!agentWatched()) { renderAgentBanner(); return Promise.resolve(); }
        return refreshHealth(agentPollAdmin());
    }

    function agentLock(r) {
        var nm = r.label || r.safe || "the safe";
        /* When the hold belongs to the session this page is browsing, end it
         * the ordinary way: lockNow() asks the helper politely first, so it can
         * zero its buffers and write its audit line, and it also tears down the
         * view. Going straight to the lock verb would leave this page showing
         * an unlocked safe that is not one. */
        if (SESSION && BROWSE && r.safe && BROWSE.safe.id === r.safe) {
            agentDrop(r.safe);
            lockNow("you locked it from the banner");
            return;
        }
        /* Otherwise: a bare safe id, no handle. The lock verb takes one for
         * precisely this case — the helper that unlocked this safe has exited
         * and the agent is the only thing still holding it. */
        var known = safeSpecById(r.safe);
        callOnce("lock", { safe: r.safe }, known ? isAdminClass(known) : true)
        .then(function (res) {
            agentDrop(r.safe);
            var msg = "Locked " + nm +
                (res && res.agent_dropped ? " and released the agent's ticket." : ".");
            alertText(msg, "ok");
            announce(msg);
            refreshAgent();
        }).catch(function (e) {
            alertBox(errNode(e));
            refreshAgent();
        });
    }

    function renderAgentBanner() {
        var host = byId("sec-agent-banner");
        if (!host) return;
        clear(host);

        if (AGENT.failed) {
            var fb = el("div", "sec-agent-banner");
            fb.appendChild(el("h2", null, "The unlock agent could not be asked"));
            fb.appendChild(el("p", null,
                "It may be holding a safe unlocked right now, and this page cannot tell:"));
            AGENT.failed.forEach(function (f) {
                fb.appendChild(el("p", null,
                    (f.cls ? f.cls + "-class socket: " : "") + f.reason));
            });
            fb.appendChild(el("p", null,
                "Treat any safe with the agent enabled as open until this clears."));
            host.appendChild(fb);
            /* Fall through: a fault on one class socket does not hide holdings
             * the other one reported. */
        }

        if (!AGENT.rows.length) {
            /* Nothing held. In the default configuration — the agent off for
             * every safe — nothing at all is drawn: no placeholder, no "0 safes
             * unlocked", no furniture implying this page is watching something.
             * The agent is opt-in per safe, and the page should look like it
             * does not exist until a registry entry opts in. */
            AGENT.said = "";
            return;
        }

        var box = el("div", "sec-agent-banner");
        box.appendChild(el("h2", null, AGENT.rows.length === 1
            ? "A safe is unlocked"
            : AGENT.rows.length + " safes are unlocked"));
        AGENT.rows.forEach(function (r) {
            var line = el("div", "sec-agent-row");
            line.appendChild(el("span", "sec-agent-name", String(r.label || r.safe || "safe")));
            /* aria-hidden: the digits change once a second, and the sentence a
             * screen reader needs is announced once, on change, into the polite
             * region instead. */
            var left = el("span", "sec-agent-left");
            left.setAttribute("aria-hidden", "true");
            line.appendChild(left);
            r._node = left;
            line.appendChild(el("span", "sec-spacer"));
            line.appendChild(btn("Lock now", "danger", function () { agentLock(r); }));
            box.appendChild(line);
        });
        box.appendChild(el("p", "sec-subtle",
            "Held by secrets-agent rather than by this page, so they outlive closing this " +
            "tab. They lock on the timeouts shown, which no client can extend (I18)."));
        host.appendChild(box);
        agentTick();

        /* One sentence to the polite region when the SET changes — not on every
         * tick, and not on a poll that returned the same thing. */
        var key = AGENT.rows.map(function (r) {
            return String(r.safe || r.label);
        }).sort().join(", ");
        if (key !== AGENT.said) {
            AGENT.said = key;
            announce("Held unlocked by the agent: " + key +
                     ". Each one has a Lock button in the banner at the top of the page.");
        }
    }

    function agentTick() {
        AGENT.rows.forEach(function (r) {
            if (!r._node) return;
            if (!r._deadline) { r._node.textContent = "no expiry published"; return; }
            var left = Math.ceil((r._deadline - Date.now()) / 1000);
            r._node.textContent = left > 0
                ? "locks in " + fmtSeconds(left)
                : "locking now…";
            if (left > 0) return;
            /* The deadline the helper gave has passed. Ask what is actually
             * true rather than deciding here that the safe is locked: this page
             * REPORTS the agent's state, it does not maintain it. The daemon
             * sweeps on its own schedule and its answer is the one that counts.
             *
             * The countdown is deliberately the SOONER of the idle and absolute
             * timers, so a row reaching zero and then being re-reported with
             * time left is normal — activity pushed the idle timer out — and
             * the poll simply corrects it. */
            if (AGENT.polling) return;
            AGENT.polling = true;
            window.setTimeout(function () {
                AGENT.polling = false;
                refreshAgent();
            }, 1000);
        });
    }

    /* Started once, after the schema. The ticker runs whenever there is a row
     * to tick. The poll asks `health`, which every helper publishes, so there
     * is no configuration in which a held safe goes unseen — but a helper with
     * no agent simply reports none, and nothing is drawn. */
    function startAgentWatch() {
        if (AGENT.timer) window.clearInterval(AGENT.timer);
        if (AGENT.poll) { window.clearInterval(AGENT.poll); AGENT.poll = null; }
        AGENT.timer = window.setInterval(agentTick, 500);
        /* The interval is armed unconditionally; refreshAgent() is what decides
         * each time whether there is anything to ask about. Arming it on the
         * registry instead would mean a safe whose entry gains agent.enabled
         * needs a page reload before it is ever watched. */
        AGENT.poll = window.setInterval(refreshAgent, agentPollSeconds() * 1000);
        /* No initial call here: SAFES has not loaded yet at this point, so the
         * decisions above would both be made against an empty registry. The
         * first poll is fired from refreshAll(), once the rows are in. */
    }

    /* ================================================================== *
     * Export (I21) — the most dangerous control on this page
     *
     * Everything else here is a value on screen for fifteen seconds. An export
     * is every value in the safe, unencrypted, in a file, indefinitely. There
     * is no countdown that re-hides a file and no lock that scrubs it, so the
     * defences are all in front of the action rather than behind it:
     *
     *   1. the helper must publish an export verb at all;
     *   2. the safe's own registry row must say export_allowed — and a row that
     *      does NOT carry the key means no, the same restrictive default that
     *      makes an entry with no `access` an admin entry (I1);
     *   3. the confirm names, in plain words and before the operator can reach
     *      the Run button, exactly what is about to be written and where;
     *   4. the result view reports the path and the byte count and refuses to
     *      render the content, whatever the helper sent back.
     *
     * Point 4 is not theoretical. A helper that answered with the export inline
     * would put every password in the safe into this page's DOM, where the lock
     * button cannot reach it and a screenshot can. The result renderer below
     * drops any content-bearing key by name and says that it did.
     * ================================================================== */

    /* May this caller export THIS safe? Both gates, and the row's silence is a
     * no. `list` publishes export_allowed per safe; when an older helper does
     * not, the answer is no rather than "probably fine". */
    function exportAllowed(safe) {
        if (!verbFor("export")) return false;
        return !!(safe && safe.export_allowed === true);
    }

    /* Where the file is going to land, as far as the helper has said.
     *
     * I21 puts the destination under the helper's control — never a path from
     * this page — so the page has to ASK rather than offer, and the answer may
     * simply not be published. Sources in order of specificity; the returned
     * `exact` distinguishes "this file" from "somewhere in this directory" so
     * the warning can be worded truthfully instead of implying a filename we
     * do not have. */
    function exportTarget(safe) {
        var spec = verbSpec(verbFor("export")) || {};
        var probe = PROBES[safe && safe.id] || {};
        var consts = (SCHEMA && SCHEMA.constants) || {};
        /* `health.export.enabled_safes` carries the directory THIS safe would be
         * written to, which is the accurate answer whenever a registry entry
         * overrides the host default. The constant is the fallback, not the
         * first choice: naming the default when the entry points somewhere else
         * would be a confirm that tells the operator the wrong place. */
        var perSafe = null;
        var eh = HEALTH && HEALTH["export"];
        if (eh && Array.isArray(eh.enabled_safes) && safe)
            eh.enabled_safes.forEach(function (r) {
                if (r && r.safe === safe.id && r.dir) perSafe = String(r.dir);
            });
        var exact = [spec.target, spec.path, safe && safe.export_path, probe.export_path];
        var dir = [perSafe, spec.directory, spec.dir, safe && safe.export_dir,
                   probe.export_dir, (eh && eh.default_dir),
                   consts.export_dir_default, consts.export_dir, consts.export_directory];
        var i;
        for (i = 0; i < exact.length; i++)
            if (exact[i]) return { path: String(exact[i]), exact: true };
        for (i = 0; i < dir.length; i++)
            if (dir[i]) return { path: String(dir[i]), exact: false };
        return { path: null, exact: false };
    }

    /* The sentence the operator must read. The wording is fixed deliberately:
     * "every password in this safe", "in plain text", and the destination. Not
     * "sensitive data may be written" — the whole failure mode of a warning is
     * that it is vague enough to skim. */
    function exportWarningNode(safe, dest) {
        var box = el("div", "sec-danger-block");
        var p = el("p");
        p.appendChild(el("strong", null,
            "This writes every password in this safe to disk in plain text"));
        if (dest.path) {
            p.appendChild(document.createTextNode(dest.exact ? " at:" : " into the directory:"));
            box.appendChild(p);
            box.appendChild(el("code", "sec-path", dest.path));
        } else {
            /* No destination published. Say that, rather than a reassuring
             * blank: an operator who cannot see where the file goes should
             * know that is what is happening. */
            p.appendChild(document.createTextNode(
                " at a path this helper does not publish in advance. The exact path is " +
                "reported the moment the file exists, and not before."));
            box.appendChild(p);
        }
        box.appendChild(el("p", null,
            "The file is not encrypted, nothing re-hides it after " +
            fmtSeconds(uiNum("reveal_seconds", 15)) + " the way a revealed value is, and " +
            "locking this safe does not remove it. Deleting it afterwards is yours to do."));
        box.appendChild(el("p", null,
            "The export is written by the helper and audited by name (I21). This page never " +
            "sees its contents and will not display them."));
        return box;
    }

    /* The confirmation TOKEN the helper refuses to export without.
     *
     * Its field help is unusually direct about the division of labour: the
     * token is "export-plaintext:" plus the safe's id, and "the UI MUST show
     * the operator, in full, what is about to be written in the clear and
     * where, and send this only after they agree". So the operator does not
     * TYPE it — making someone transcribe a token is a ritual, and a ritual is
     * something people learn to perform without reading. The page shows the
     * warning, the operator ticks the box that says they have read it, and the
     * token is sent. It names THIS safe, so an agreement given for a throwaway
     * safe cannot be replayed against the domain administrator one (I21).
     *
     * The prefix comes from the helper's constants, never from a literal here:
     * a page that hard-coded it would keep sending a token the helper had
     * stopped accepting, and the failure would look like a permissions bug. */
    function exportConfirmToken(safe) {
        var consts = (SCHEMA && SCHEMA.constants) || {};
        var prefix = consts.export_confirm_prefix;
        if (!prefix) return null;
        return String(prefix) + String(safe.id);
    }

    function exportDialog(safe) {
        var verb = verbFor("export");
        if (!verb) return;
        var dest = exportTarget(safe);
        /* Inside an open session the handle identifies the safe; outside one the
         * safe id has to be a preset, and the helper will ask for the passphrase
         * through the form exactly as it does for any other single-shot verb —
         * exporting is not a reason to stop prompting. */
        var presets = (SESSION && BROWSE && BROWSE.safe.id === safe.id && needsSession(verb))
            ? {} : { safe: safe.id };
        /* Preset, so the token control is not drawn: it is not a decision the
         * operator makes, it is the machine-readable half of the decision they
         * make by ticking the confirm below. Only set it when the verb declares
         * the field and the helper published the prefix — never a value this
         * page composed out of nothing. */
        var token = exportConfirmToken(safe);
        if (token && argNames(verb).indexOf("confirm") >= 0) presets.confirm = token;
        verbDialog(verb, presets, null, null, {
            title: "Export " + (safe.label || safe.id) + " in the clear",
            safe: safe,
            runLabel: "Write the plaintext export",
            beforeForm: function (box) { box.appendChild(exportWarningNode(safe, dest)); },
            confirm: "I understand this writes every password in this safe to disk in plain " +
                     "text, and that removing the file afterwards is my responsibility.",
            onResult: function (res) { exportResultDialog(res); }
        });
    }

    /* The result: where it went and how big it is. Nothing else.
     *
     * The content keys are dropped BY NAME and the drop is reported, because a
     * silent drop and a helper that sent nothing look the same, and one of them
     * means the operator is about to go looking for a file that is actually in
     * their browser. */
    var EXPORT_CONTENT_KEYS = { "b64": 1, "content": 1, "data": 1, "csv": 1,
                                "xml": 1, "json": 1, "body": 1, "text": 1,
                                "value": 1, "entries": 1 };

    /* A key from that list is only WITHHELD when its value is shaped like a
     * payload. The distinction is load-bearing: the helper's export reply
     * carries `entries` as a ROW COUNT, and treating the number 42 as "the
     * contents, withheld" would both hide a useful figure and print a warning
     * about a leak that did not happen. A number is a measurement; a non-empty
     * string or array is the thing itself. */
    function looksLikeContent(v) {
        if (typeof v === "string") return v.length > 0;
        if (Array.isArray(v)) return v.length > 0;
        return false;
    }

    function exportResultDialog(res) {
        modal("Export written", function (box, m) {
            var path = res && (res.path || res.file || res.target);
            if (path) {
                box.appendChild(el("p", null, "The plaintext export was written to:"));
                box.appendChild(el("code", "sec-path", String(path)));
            } else {
                box.appendChild(el("div", "sec-alert warn",
                    "The helper reported success but did not name the file it wrote. " +
                    "Its audit log records the export by name (I15, I21)."));
            }
            var meta = {};
            var withheld = [];
            Object.keys(res || {}).forEach(function (k) {
                if (EXPORT_CONTENT_KEYS[k] && looksLikeContent(res[k])) {
                    withheld.push(k);
                    return;
                }
                if (k === "path" || k === "file" || k === "target") return;
                meta[k] = res[k];
            });
            if (res && res.bytes !== undefined)
                box.appendChild(el("p", null, fmtBytes(res.bytes) + " on disk."));
            if (Object.keys(meta).length) box.appendChild(kvList(meta));
            if (withheld.length)
                box.appendChild(el("div", "sec-alert info",
                    "The helper also returned the export's contents inline (" +
                    withheld.join(", ") + "). This page does not render them: every password " +
                    "in the safe in the browser's DOM is not something the Lock button can " +
                    "take back."));
            box.appendChild(el("div", "sec-danger-block",
                "That file is plaintext and it is still there. Remove it when you are done " +
                "with it — nothing in this program will."));
            actionRow(box, [btn("Close", "", function () { m.close(); })]);
        }, { wide: true });
        announce("The plaintext export was written.");
    }

    /* ================================================================== *
     * Save-as, the backup ring, and restore
     *
     * Three operations that all touch files beside the safe, and one shared
     * honesty problem: the operator has to be told what is about to be
     * overwritten BEFORE it is, because none of it is undoable from this page.
     * ================================================================== */

    /* Save-as takes a NAME, not a path (I4: no verb accepts a caller-supplied
     * path, and that has not stopped being true because the file is new). This
     * advisory is CLIENT-SIDE FEEDBACK ONLY: it exists so the operator finds
     * out at the moment of typing rather than at the moment of refusal. The
     * helper is the gate. If this check and the helper ever disagree, the
     * helper is right and this is a bug in the hint. */
    function attachNameAdvisory(ctrl) {
        if (!ctrl || !ctrl.node) return;
        ctrl.node.appendChild(el("div", "hint",
            "A name, not a path. The helper chooses the directory the copy is written to \u2014 " +
            "there is no verb on this page that takes a path from the browser (I4)."));
        /* Polite, never assertive: this fires while the operator is still
         * typing, and interrupting a screen reader mid-word to say a half-typed
         * name is wrong is worse than saying nothing at all. */
        var live = el("div", "err");
        live.setAttribute("aria-live", "polite");
        ctrl.node.appendChild(live);
        ctrl.onChange(function () {
            var v = ctrl.get();
            v = (v === undefined || v === null) ? "" : String(v);
            var why = "";
            /* The rules the helper's own `name` descriptor states it refuses:
             * a slash, a backslash, a leading dot or a NUL. Repeating them here
             * buys the operator an answer while they type; the helper is what
             * actually refuses, and if these two ever disagree the helper is
             * right and this hint is the bug. */
            if (v.indexOf("/") >= 0)
                why = "That is a path. Give a name with no \u201c/\u201d in it.";
            else if (v.indexOf("\\") >= 0)
                why = "A backslash is refused. Give a name with no path separator in it.";
            else if (v === "." || v === "..")
                why = "\u201c" + v + "\u201d names a directory, not a file.";
            else if (v.indexOf("\u0000") >= 0)
                why = "That name contains a NUL byte and cannot be a filename.";
            else if (v.charAt(0) === ".")
                why = "A leading dot is refused by the helper. Start the name with a letter " +
                      "or a digit.";
            live.textContent = why;
        });
    }

    function saveAsDialog() {
        var verb = verbFor("saveAs");
        if (!verb || !SESSION || !BROWSE) return;
        verbDialog(verb, {}, null, null, {
            title: verbLabel(verb),
            safe: BROWSE.safe,
            runLabel: "Write the copy",
            intro: "Writes what is in memory — including changes not yet saved — to a NEW " +
                   "file. The safe this session opened is not touched, and its own unsaved " +
                   "changes stay unsaved.",
            beforeForm: function (box) {
                box.appendChild(el("div", "sec-alert info",
                    "The copy is a new file, so the changed-on-disk check that guards a " +
                    "normal save does not apply to it. If a file of that name is already " +
                    "there, the helper decides what happens — this page does not overwrite " +
                    "anything on its own."));
            },
            onResult: function (res) {
                var msg = "Copy written" +
                    (res && res.path ? " to " + res.path : "") +
                    (res && res.bytes !== undefined ? " — " + fmtBytes(res.bytes) : "") + ".";
                alertText(msg, "ok");
                announce(msg);
            },
            /* Which control carries the file name is the helper's choice, so
             * the advisory goes on every plain text control the verb declared
             * rather than on one this page picked by guessing at an id. There
             * is normally exactly one. */
            afterForm: function (form) {
                form.controls.forEach(function (c) {
                    if (c.kind === "text" && !c.secret) attachNameAdvisory(c);
                });
            }
        });
    }

    /* The backup ring (I12). The helper copies the current file into it before
     * the first new byte of a save exists, so this list is the undo that a
     * password safe is otherwise missing. Timestamps in local time and sizes in
     * bytes, because "which one was before I broke it" is answered by both. */
    function backupsDialog(safe) {
        var listVerb = verbFor("backups");
        if (!listVerb) return;
        var restoreVerb = verbFor("restore");
        var target = safe || (BROWSE ? BROWSE.safe : null);
        modal("Backups — " + ((target && (target.label || target.id)) || "this safe"),
        function (box, m) {
            var body = el("div");
            box.appendChild(body);
            body.appendChild(el("p", "sec-subtle", "Loading the backup ring…"));

            var req = {};
            if (target && !(SESSION && needsSession(listVerb))) req.safe = target.id;
            var p = (needsSession(listVerb) && SESSION)
                ? SESSION.call(listVerb, req)
                : callOnce(listVerb, req, adminForVerb(listVerb, target));

            p.then(function (res) {
                clear(body);
                var rows = (res && (res.backups || res.entries || res.files || res.ring)) || [];
                if (!Array.isArray(rows) || !rows.length) {
                    body.appendChild(el("p", "sec-empty",
                        "No backups yet. The helper writes one before the first mutation of " +
                        "a save, so this list fills up the first time this safe is saved."));
                    return;
                }
                if (res && res.keep !== undefined)
                    body.appendChild(el("p", "sec-subtle",
                        "The ring keeps " + res.keep + " generation(s); the oldest is pruned " +
                        "when a new one is written."));
                /* Where they are. An operator who needs a backup usually needs
                 * it from a shell, and the directory is the helper's to choose
                 * — this page has never named it and could not. */
                if (res && res.dir)
                    body.appendChild(el("code", "sec-path", String(res.dir)));
                var panel = el("div", "sec-panel");
                rows.forEach(function (r, ix) {
                    var line = el("div", "sec-file-row");
                    var nm = r.name || r.path || r.file || ("backup " + ix);
                    line.appendChild(el("span", "sec-file-name", String(nm)));
                    var when = fmtWhen(r.when !== undefined ? r.when
                                     : (r.modified !== undefined ? r.modified : r.mtime));
                    if (when) line.appendChild(el("span", "sec-file-size", when));
                    var sz = (r.bytes !== undefined ? r.bytes : r.size);
                    if (sz !== undefined) line.appendChild(el("span", "sec-file-size", fmtBytes(sz)));
                    line.appendChild(el("span", "sec-spacer"));
                    if (restoreVerb)
                        line.appendChild(btn("Restore…", "danger tiny", function () {
                            m.close();
                            restoreDialog(restoreVerb, target, r);
                        }));
                    panel.appendChild(line);
                });
                body.appendChild(panel);
                if (!restoreVerb)
                    body.appendChild(el("p", "sec-subtle",
                        "This helper lists backups but offers no restore verb, so they are " +
                        "recovered outside this page."));
            }).catch(function (e) {
                clear(body);
                body.appendChild(errNode(e));
                handleSessionError(e);
            });
            actionRow(box, [btn("Close", "", function () { m.close(); })]);
        }, { wide: true });
    }

    /* Restoring puts an old copy back over the live safe. The confirm has to
     * say both halves of that: what is about to be overwritten, and that the
     * thing being overwritten is itself copied into the ring first — an
     * operator who restores the wrong generation must be able to undo it, and
     * must be told so before they are frightened out of the decision. */
    function restoreDialog(verb, safe, item) {
        var nm = item && (item.name || item.path || item.file);
        var when = fmtWhen(item && (item.when !== undefined ? item.when : item.modified));
        var presets = {};
        if (safe && !(SESSION && needsSession(verb))) presets.safe = safe.id;
        if (nm) {
            /* Name whichever request field the verb declares for it, rather
             * than assuming "backup": the helper's descriptor is the authority
             * on its own request shape. */
            var names = argNames(verb);
            var key = ["backup", "name", "generation", "file", "index"].filter(function (k) {
                return names.indexOf(k) >= 0;
            })[0];
            if (key) presets[key] = (key === "index" && item.index !== undefined)
                ? item.index : nm;
        }
        verbDialog(verb, presets, null, null, {
            title: "Restore " + (nm ? String(nm) : "a backup"),
            safe: safe,
            runLabel: "Overwrite the safe with this backup",
            beforeForm: function (box) {
                var w = el("div", "sec-danger-block");
                w.appendChild(el("p", null,
                    "This overwrites the live safe" +
                    (safe ? " “" + (safe.label || safe.id) + "”" : "") +
                    " with the copy taken " + (when || "at the time shown") + "."));
                w.appendChild(el("p", null,
                    "Everything added or changed in the safe since then is gone from the " +
                    "file — including anything a desktop client wrote."));
                w.appendChild(el("p", null,
                    "The safe as it stands right now is copied into the backup ring first, " +
                    "so this is reversible by restoring the newest generation."));
                box.appendChild(w);
            },
            confirm: "I understand the safe on disk is about to be replaced by this backup.",
            onResult: function (res) {
                var msg = "Restored" + (nm ? " from " + nm : "") +
                    (res && res.backup ? "; the previous state was kept at " + res.backup : "") + ".";
                alertText(msg, "ok");
                announce(msg);
                /* The file underneath the open session is not the file that
                 * was unlocked any more. Continuing to browse it would show the
                 * operator the OLD contents out of the helper's memory while
                 * the disk holds something else, and the first save would
                 * either conflict or clobber. So lock, and say why.
                 *
                 * ONLY when it is the same safe. A restore is reachable from
                 * the safe list, so the safe being restored is not necessarily
                 * the one that happens to be open — and locking an unrelated
                 * session would throw away that session's unsaved changes for
                 * an action that had nothing to do with it. */
                var openId = BROWSE ? BROWSE.safe.id : null;
                if (SESSION && safe && openId === safe.id)
                    lockNow("the safe on disk was replaced by a backup");
                else if (!SESSION)
                    refreshAll();
            }
        });
    }

    /* ================================================================== *
     * Page lifetime: hide, unload, and the automatic lock
     * ================================================================== */
    function bindLifetime() {
        /* Leaving the page ends the unlock. The channel dying would kill the
         * helper anyway; asking first lets it write its audit line. */
        window.addEventListener("pagehide", function () {
            clipboardClear("the page was hidden");
            if (SESSION) lockNow("the page was closed");
        });

        document.addEventListener("visibilitychange", function () {
            if (document.visibilityState === "hidden") {
                clipboardClear("the tab was hidden");
                if (HIDE_TIMER) window.clearTimeout(HIDE_TIMER);
                if (!SESSION) return;
                var after = uiNum("hide_lock_seconds", 60);
                HIDE_TIMER = window.setTimeout(function () {
                    if (document.visibilityState === "hidden" && SESSION)
                        lockNow("this tab was hidden for " + fmtSeconds(after));
                }, after * 1000);
            } else {
                if (HIDE_TIMER) { window.clearTimeout(HIDE_TIMER); HIDE_TIMER = null; }
            }
        });
    }

    /* The helper publishes the rules this page is supposed to follow. They are
     * rendered verbatim, in the footer, so the page can be checked against
     * them by anyone reading it — a claim you can audit rather than a promise
     * buried in a source file. */
    function renderHelperRules() {
        var rules = SCHEMA && SCHEMA.ui_rules;
        if (!Array.isArray(rules) || !rules.length) return;
        var foot = document.querySelector(".sec-footer");
        if (!foot) return;
        var old = byId("sec-rules");
        if (old && old.parentNode) old.parentNode.removeChild(old);
        var box = el("details", null);
        box.id = "sec-rules";
        var sum = el("summary", null,
            "The " + rules.length + " rules this page follows, as stated by the helper");
        box.appendChild(sum);
        var ul = el("ul");
        rules.forEach(function (r) { ul.appendChild(el("li", null, String(r))); });
        box.appendChild(ul);
        foot.appendChild(box);
    }

    /* ================================================================== *
     * Start-up
     * ================================================================== */
    function init() {
        byId("sec-refresh").addEventListener("click", function () {
            if (SESSION) { loadTree(); loadEntries(); }
            else refreshAll();
            /* Whatever else Refresh means, it means "tell me the truth about
             * what is unlocked right now". */
            refreshAgent();
        });
        byId("sec-lock").addEventListener("click", function () { confirmLock(); });
        bindLifetime();

        PERM = cockpit.permission({ admin: true });
        PERM.addEventListener("changed", function () {
            if (SESSION) return;
            renderSafes();
            /* Administrative access has just come on. The admin-class safes
             * were deliberately not probed while it was off — one Cockpit
             * prompt per card on load is an interrogation, not a page — so this
             * is the first moment they can be, and without it an operator who
             * escalates from Cockpit's own header watches the cards stay blank
             * until they think to press Refresh. Only the ones not already
             * probed, because this event can fire more than once. */
            if (adminAllowed())
                SAFES.forEach(function (s) { if (!PROBES[s.id]) probeSafe(s); });
        });

        /* The schema is fetched first and everything else waits for it: this
         * page has nothing of its own to draw. */
        callOnce("schema", {}, false).then(function (res) {
            SCHEMA = res || {};
            var sub = byId("sec-sub");
            sub.textContent = "helper " +
                (SCHEMA.helper_version || SCHEMA.version || "?") + " · " +
                Object.keys(verbTable()).length + " verbs · reveal " +
                fmtSeconds(uiNum("reveal_seconds", 15));
            renderHelperRules();
            refreshAll();
            /* Started after the schema, because it is the schema that says
             * whether this helper has an agent at all. A helper without one is
             * never polled and never draws a banner (I18). */
            startAgentWatch();
        }).catch(function (e) {
            byId("sec-sub").textContent = "";
            var host = byId("sec-safes");
            clear(host);
            host.appendChild(errNode(e));
            host.appendChild(el("p", "sec-subtle",
                "This page renders only what " + HELPER + " describes through its schema verb, " +
                "so there is nothing to show until the helper answers. Install it with " +
                "install.sh from this package."));
        });
    }

    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", init);
    else
        init();
}());
