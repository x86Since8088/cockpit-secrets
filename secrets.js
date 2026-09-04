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
 *   controls seen: text · textarea · password · number · toggle · select ·
 *                  search · tags · file-bytes · object · hidden
 *
 * A control type this page does not know is drawn as text WITH A VISIBLE NOTE,
 * never dropped. Where the schema says nothing (the keys of an entries[] row,
 * for instance) the page falls back to what docs/CONTRACT.md pins and says so
 * at the point of use.
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
        if (Array.isArray(v)) return v.join(", ");
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
     * The generic control renderer — every input on this page comes from here
     * ================================================================== */
    var TYPE_ALIAS = {
        "str": "text", "string": "text", "text": "text", "path": "text",
        "url": "text", "email": "text", "uuid": "text", "search": "search",
        "password": "password", "secret": "password", "passphrase": "password",
        "password-stdin": "password", "protected": "password",
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
                 * or max_bytes on a dict-shaped schema. */
                var cap = Number(spec.max_bytes) || Number(spec.max) || 0;
                if (cap && f.size > cap) {
                    sizeNote.textContent = "That file is " + f.size + " bytes; the helper accepts " +
                        cap + " at most.";
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
                if (kind === "multi") {
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
                if (kind === "object") { if (sub) sub.wipeAll(); return; }
                if (!input) return;
                try {
                    if (kind === "bool") { input.checked = false; return; }
                    if (kind === "multi") {
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
            if (HANDLED_VERBS[name]) return;
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
        if (reachable && !p && isAdminClass(safe) && !adminAllowed())
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
        if (!reachable)
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

    function unlockDialog(safe) {
        var probe = PROBES[safe.id];
        if (probe && probe._error) probe = null;
        var admin = isAdminClass(safe);

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
                var body = JSON.stringify(req);
                /* Drop every reference we hold to the plaintext. A JavaScript
                 * string is immutable, so this releases rather than scrubs —
                 * docs/ARCHITECTURE.md hop 2 states the same limitation for
                 * Python's str and this page does not claim a stronger one.
                 * What it does guarantee is that nothing retains a reference
                 * once the request is on its way (I11). */
                names.forEach(function (nm) { req[nm] = null; });
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

        /* Every other safe-scoped verb the helper offers — upgrade-to-kdbx4,
         * export, restore-from-backup, breach-check, whatever Task 6 and 7 add
         * later. No edit here is needed to make them appear. */
        Object.keys(verbTable()).sort().forEach(function (name) {
            if (HANDLED_VERBS[name]) return;
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
                if (HANDLED_VERBS[name]) return;
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
        var histVerb = findVerb(["history", "entry-history", "history-list"]);
        if (histVerb) {
            host.appendChild(el("h4", null, "History"));
            host.appendChild(btn("Browse history…", "tiny", function () {
                historyDialog(histVerb, row);
            }));
        }

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
            if (HANDLED_VERBS[name]) return;
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

    function renderAttachments(host, row) {
        var count = row.attachments;
        var names = Array.isArray(count) ? count
                  : (Array.isArray(row.attachment_names) ? row.attachment_names : null);
        var n = names ? names.length : (Number(count) || 0);
        if (!n && !hasVerb("attach-get")) return;
        host.appendChild(el("h4", null, "Attachments"));
        if (!n) {
            host.appendChild(el("p", "sec-subtle", "None."));
        } else if (!names) {
            /* The helper sent a count, not names, and offers no verb that lists
             * them. Say so instead of inventing names. */
            var lister = findVerb(["attach-list", "attachments", "attach-ls"]);
            if (lister) {
                host.appendChild(btn("List " + n + " attachment(s)", "tiny", function () {
                    SESSION.call(lister, { uuid: row.uuid }).then(function (res) {
                        var list = res.names || res.attachments || [];
                        row.attachment_names = list;
                        renderDetail(row);
                    }).catch(function (e) { host.appendChild(errNode(e)); });
                }));
            } else {
                host.appendChild(el("p", "sec-subtle",
                    n + " attachment(s). This helper reports a count only — downloading one " +
                    "needs its name, which comes from a verb this helper does not offer."));
            }
        } else {
            names.forEach(function (name) {
                var rowEl = el("div", "sec-tools");
                rowEl.appendChild(el("span", null, String(name)));
                if (hasVerb("attach-get"))
                    rowEl.appendChild(btn("Download", "tiny", function () {
                        downloadAttachment(row.uuid, String(name));
                    }));
                host.appendChild(rowEl);
            });
        }
        /* Uploading is whatever verb the helper offers for it, rendered from
         * its own descriptor — the file control sends the bytes inline. */
        var adder = findVerb(["attach-add", "attach-put", "attach-set"]);
        if (adder && BROWSE.writable)
            host.appendChild(btn(verbLabel(adder), "tiny", function () {
                verbDialog(adder, { uuid: row.uuid }, afterMutation, row);
            }));
    }

    function downloadAttachment(uuid, name) {
        SESSION.call("attach-get", { uuid: uuid, name: name }).then(function (res) {
            /* The bytes arrive through the Cockpit channel and are handed
             * straight to the browser. Nothing is written to the server's disk
             * on the way (I21). */
            var bytes = b64ToBytes(res.b64);
            var blob = new Blob([bytes], { type: "application/octet-stream" });
            var url = URL.createObjectURL(blob);
            var a = el("a");
            a.href = url;
            a.download = String(res.name || name);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
            announce("Downloaded " + name + ".");
        }).catch(function (e) {
            alertBox(errNode(e));
            handleSessionError(e);
        });
    }

    function historyDialog(verb, row) {
        modal("History — " + (txt(row.title) || row.uuid), function (box, m) {
            var body = el("div");
            box.appendChild(body);
            body.appendChild(el("p", "sec-subtle", "Loading…"));
            var restore = findVerb(["history-restore", "restore-history", "entry-restore"]);
            SESSION.call(verb, { uuid: row.uuid }).then(function (res) {
                clear(body);
                var list = res.history || res.entries || res.versions || [];
                if (!list.length) { body.appendChild(el("p", "sec-empty", "No history.")); return; }
                body.appendChild(resultTable(list, restore ? function (item, idx) {
                    return btn("Restore", "tiny", function () {
                        m.close();
                        verbDialog(restore,
                            { uuid: row.uuid,
                              index: item.index !== undefined ? item.index : idx },
                            afterMutation, row);
                    });
                } : null));
            }).catch(function (e) {
                clear(body);
                body.appendChild(errNode(e));
                handleSessionError(e);
            });
            actionRow(box, [btn("Close", "", function () { m.close(); })]);
        }, { wide: true });
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
    function adminForVerb(name) {
        var spec = verbSpec(name) || {};
        if (spec.admin === true) return true;
        if (spec.access === "any") return false;
        return BROWSE ? isAdminClass(BROWSE.safe) : false;
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
     * not drawn and not editable. `values` pre-fills drawn controls. */
    function verbDialog(name, presets, done, values) {
        var spec = verbSpec(name);
        if (!spec) return;
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

        modal(verbLabel(name), function (box, m) {
            if (spec.danger)
                box.appendChild(el("div", "sec-alert warn",
                    "This action is destructive. There is no undo except the backup ring the " +
                    "helper writes before a save."));
            if (spec.help) box.appendChild(el("p", "sec-modal-intro", spec.help));
            if (spec.breaks_when_wrong)
                box.appendChild(el("div", "sec-alert info", String(spec.breaks_when_wrong)));

            var form = buildForm(specs, { values: values || {} });
            box.appendChild(form.node);

            /* The helper can demand an explicit confirmation, in its own
             * words. When it does, Run stays disabled until the box is
             * ticked — the sentence is not decoration. */
            var confirmBox = null;
            if (spec.confirm) {
                var cid = "sec-confirm" + (++CTRL_SEQ);
                confirmBox = el("input");
                confirmBox.type = "checkbox";
                confirmBox.id = cid;
                var cl = el("label", "sec-check");
                cl.setAttribute("for", cid);
                cl.appendChild(confirmBox);
                cl.appendChild(el("span", null, String(spec.confirm)));
                var cw = el("div", "sec-alert warn");
                cw.appendChild(cl);
                box.appendChild(cw);
                confirmBox.addEventListener("change", function () {
                    go.disabled = !confirmBox.checked;
                });
            }

            var errHost = el("div");
            box.appendChild(errHost);

            var go = btn("Run", spec.danger ? "danger" : "primary", submit);
            if (confirmBox) go.disabled = true;
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
                    : callOnce(name, req, adminForVerb(name), argv);

                p.then(function (res) {
                    /* Drop every reference to whatever we just sent. */
                    dropDeep(bag);
                    form.wipeAll();
                    m.close();
                    if (done) done(res, name);
                    showResult(verbLabel(name), res, mutates(name));
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
        var saveAs = findVerb(["save-as", "save_as", "saveas", "save-copy"]);
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
                verbDialog(saveAs, {}, function (res, v) {
                    setDirty(0);
                    updateSaveButton();
                    showResult(verbLabel(v), res);
                });
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
        });
        byId("sec-lock").addEventListener("click", function () { confirmLock(); });
        bindLifetime();

        PERM = cockpit.permission({ admin: true });
        PERM.addEventListener("changed", function () {
            if (!SESSION) renderSafes();
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
