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
 *   plus the aliases a differently-shaped schema might use for the same thing,
 *   plus ROWS: a repeating subform, N copies of the shape `fields` declares,
 *   with Add and Remove. A descriptor reaches it either by naming it (`custom`,
 *   `key-value`, `rows`, …) or by describing an `object` whose `type` is
 *   `array` — one subform where the request wants a list would silently drop
 *   every row but the first, which is the class of failure this page refuses.
 *   The custom string field both formats carry (name, value, protected) is the
 *   first request for it and not a special case in the renderer.
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
/* ---------------------------------------------------------------- theme ---
 * A SECOND COPY of theme.js's resolver, and it runs only if theme.js did not.
 *
 * theme.js is the primary path: it is loaded first in <head>, undeferred, so
 * the class lands before the stylesheet is requested and there is no flash by
 * construction.
 *
 * HISTORY, KEPT BECAUSE IT EXPLAINS WHY THIS COPY EXISTS. theme.js is a file
 * install.sh's PLUGIN array must name: that array is the list of files it
 * copies AND the list it sweeps the package directory down to, so for the whole
 * of 0.5.0 the installer copied theme.js and then swept it straight back off
 * the host on the same run. The installed page answered the request with
 * Cockpit's HTML error page and Chromium refused it on MIME type — a console
 * error on every single load, not the silent 404 the old comment here claimed.
 * Fixed in 0.5.1: `theme.js` is in PLUGIN, and install.sh now has a pre-flight
 * that parses index.html's own package-local references and REFUSES to install
 * a page that asks for a file the array does not ship, so the same omission
 * cannot recur.
 *
 * This guarded copy STAYS, and not out of caution: it is what kept the theme
 * correct through that outage (measured — with theme.js absent the frame still
 * resolved sec-light/sec-dark in both directions), and it is the only resolver
 * for a page loaded standalone or served by something that is not this
 * installer. What it cannot do is beat first paint: it is deferred behind
 * 476 KB, so on a cold cache or a slow link the frame paints unthemed inside
 * its window (161 ms paint vs a 3068 ms resolve, measured). Correctness here,
 * no-flash-by-construction in theme.js — the two are not substitutes.
 *
 * If `.sec-theme-managed` is already on <html>, theme.js ran and this does
 * nothing at all.
 *
 * The reasoning for reading the parent's class rather than shell:style is in
 * theme.js's header and is not repeated here.
 */
(function () {
    "use strict";
    var ROOT = document.documentElement;
    if (ROOT.classList.contains("sec-theme-managed")) return;   /* theme.js ran */
    var DARK_RE = /(^|\s)pf-(v\d+-)?theme-dark(\s|$)/;
    function shellRoot() {
        try {
            if (window.parent && window.parent !== window)
                return window.parent.document.documentElement;
        } catch (e) { /* cross-origin or blocked */ }
        return null;
    }
    function apply() {
        var host = shellRoot(), dark;
        if (host) dark = DARK_RE.test(host.className);
        else dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        ROOT.classList.toggle("sec-dark", !!dark);
        ROOT.classList.toggle("sec-light", !dark);
        ROOT.classList.add("sec-theme-managed");
    }
    apply();
    var host = shellRoot();
    if (host) {
        new MutationObserver(apply).observe(host,
            { attributes: true, attributeFilter: ["class"] });
    } else {
        var mq = window.matchMedia("(prefers-color-scheme: dark)");
        if (mq.addEventListener) mq.addEventListener("change", apply);
        else if (mq.addListener) mq.addListener(apply);
    }
}());

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

    /* ------------------------------------------------------------------ *
     * THE DETAILS PANE (R3/R4), THE SORT AND THE COLUMN SELECTION (R2/R5).
     *
     * All three live in ordinary variables for the life of the page and are
     * NOT persisted, deliberately. validate.sh bans all four browser-storage
     * identifiers as bare words anywhere in this package's JavaScript (I11) —
     * this comment cannot spell them, which is the ban working — and the live suite
     * additionally fails a run in which ANY storage key changes. That ban is
     * the mechanical guarantee that nothing about a safe is left behind in a
     * browser, and it is checkable by grep — a ban with one exception is a ban
     * an auditor has to read the code to trust. Remembering a pane position is
     * not worth spending it. If it is ever revisited the right answer is a
     * helper-side `ui-prefs` verb, so preferences live on the host under the
     * same access class and the same audit line as everything else.
     * ------------------------------------------------------------------ */
    var PANE = {
        open: true,          // recomputed from the frame width on first render
        userToggled: false,  // once the operator touches it, width stops deciding
        wide: null,          // last known answer to "is the frame >= 60rem"
        safeId: null,        // the selected registry row, or null
        mode: "safe"         // "safe" | "entry" — which content the stack shows
    };
    /* Optional columns (R5). Fixed ORDER lives in SAFE_OPT_COLS below; this is
     * only which of them are on. Path is off by default — see the three
     * reasons where the chooser is built. */
    var COLS = { path: false, registry: false, kdf: false, modified: false, id: false };
    /* Whether the chooser's disclosure is open, and which checkbox the operator
     * was standing on. Toggling a column re-renders the table, which destroys
     * both — so both are put back. A control that closes itself and drops your
     * focus every time you use it is a control nobody uses twice. */
    var COLS_OPEN = false;
    /* Default sort: Class (administrator first), then the safe's label. Admin
     * is the DEFAULT access class (I1), so the list reads in the order the
     * registry defaults do. */
    var SAFESORT = { key: "class", desc: false };

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
    /* The escalation the LAST health call was made at. `health` is one document
     * describing every safe, and part of it is euid-dependent — the admin-class
     * agent socket is /run/cockpit-secrets/<euid>/agent.sock — so "what was in
     * it" is not a complete answer without "who asked". */
    var HEALTH_ADMIN = false;

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
        "yubikey":        ["yubikey-challenge", "yubikey", "challenge"],
        /* --- making a safe exist, and making it stop existing -------------
         *
         * The registry is this program's trust root: it is what says which
         * files are safes, where they live and what access class each one has
         * (I1, I4). These eight capabilities are the first ones that WRITE to
         * it from a browser request, so every one of them is behind the same
         * "does the helper publish this verb" gate as everything else here —
         * a build of this page against a helper with no create verb has no
         * New-safe button, in the safe list or anywhere else.
         *
         * Note what is NOT in any of these lists and never will be: a name for
         * a verb that takes a path. The caller supplies an ID; the helper mints
         * the filename from it and from the managed directory for the access
         * class. There is no request field in this whole feature that is a
         * path, a filename, a directory or a component of one (C1, I4). */
        "safeCreate":     ["safe-create", "create-safe", "safe-new", "new-safe",
                           "safe-add", "add-safe"],
        "importBegin":    ["import-begin", "safe-import-begin", "import-start",
                           "upload-begin", "safe-upload-begin"],
        "importChunk":    ["import-chunk", "safe-import-chunk", "upload-chunk",
                           "import-part"],
        "importInspect":  ["import-inspect", "safe-import-inspect", "import-probe",
                           "upload-inspect"],
        "importCommit":   ["import-commit", "safe-import-commit", "import-finish",
                           "upload-commit"],
        "importAbort":    ["import-abort", "safe-import-abort", "import-cancel",
                           "upload-abort"],
        "safeForget":     ["safe-forget", "forget-safe", "registry-forget",
                           "safe-unregister", "unregister-safe"],
        "safeDelete":     ["safe-delete", "delete-safe", "safe-destroy",
                           "destroy-safe", "safe-rm"]
    };

    /* The shape of ONE row of a repeating subform, used only when the schema
     * declares a repeating field without describing its elements.
     *
     * The capability that forced the repeater to exist is the custom string
     * field both formats carry — KDBX calls them custom strings, PWS3 calls
     * them unknown fields, and both store a NAME, a VALUE and a flag saying
     * whether the value is protected. The helper's `reveal` verb already
     * publishes the addressing for them: its `field` pattern accepts
     * `custom:<name>`, which is this page's evidence that a custom field is a
     * (name, value, protected) triple and not something else.
     *
     * It is a FALLBACK and it says so on screen. The moment the schema
     * describes the element fields itself, its description is used instead and
     * this constant is not consulted — the same rule as every other CONTRACT_*
     * table in this file. */
    var CONTRACT_CUSTOM_ROW = [
        { id: "name", label: "Field name", control: "text", type: "string",
          required: true, secret: false, maxlength: 128,
          placeholder: "API token",
          help: "What the field is called inside the entry. `reveal` reaches it " +
                "afterwards as custom:<name>.",
          breaks_when_wrong: "Two custom fields with the same name are one field in " +
                "every format that stores them, so the second silently replaces the " +
                "first. This form refuses a duplicate rather than letting that happen." },
        { id: "value", label: "Value", control: "password", type: "string",
          required: false, secret: true, maxlength: 4096,
          /* Deliberately NOT scored. The strength meter answers "how hard is
           * this to guess as a password", and a custom string is very often
           * not one — a licence key, a recovery code, an account number. A
           * number computed as though it were would be this page inventing a
           * judgement about a field whose meaning it does not know, and it
           * would cost one helper call per keystroke per row to do it. */
          strength: false,
          help: "Travels on the helper's stdin inside the request object, like every " +
                "other secret on this page (I10). It is never put in browser storage (I11).",
          breaks_when_wrong: "Leave it empty and the field is created empty; there is no " +
                "way to tell that apart from a value that is genuinely the empty string." },
        { id: "protected", label: "Protected", control: "toggle", type: "boolean",
          required: false, secret: false, "default": true,
          help: "Store the value the way the format stores a password — encrypted in " +
                "memory and hidden in a listing.",
          breaks_when_wrong: "Unprotected, the value is visible in the entry listing of " +
                "other clients and is carried in the clear by an export. Protected is the " +
                "restrictive default here for the same reason admin is the default access " +
                "class (I1)." }
    ];
    var ROWS_FALLBACK_NOTE =
        "This helper declares the field as a list but does not describe what one row " +
        "contains, so the three parts docs/CONTRACT.md pins for a custom field are drawn: " +
        "a name, a value, and whether the value is protected. A schema that describes its " +
        "own rows replaces these entirely.";

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
            /* How many attempts a staged import has left, and how long the
             * staging survives without one. Both are COUNTS the helper owns —
             * a page that invented either would be telling the operator a
             * number it made up about somebody else's resource limit. Neither
             * is a value; a count of failures is exactly the sort of thing I15
             * permits in an error and a value is exactly what it does not. */
            ["attempts_remaining", "attempts_left", "remaining_attempts",
             "expires_in", "idle_seconds"].forEach(function (k) {
                if (extra[k] !== undefined) e[k] = extra[k];
            });
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
            /* Say what to DO about it. The bridge refuses a `superuser:"require"`
             * channel outright when this session is in limited access — no
             * dialog is drawn, here or anywhere — so an operator who read only
             * the problem code had a refusal with no route out of it. The route
             * is Cockpit's own header control and nothing on this page. */
            return mkErr("access-denied",
                "Administrative access is required and was not granted (" + problem + "). " +
                "Cockpit does not ask for it from inside a page: turn it on with the " +
                "“Limited access” control in the Cockpit header, then try again.");
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
    /* Which name a verb actually uses for one of its request fields.
     *
     * Same rule as VERB_ALIASES one level down: the page does not DICTATE what
     * the helper calls a field, it RECOGNISES the name out of an ordered list
     * of the ones a reasonable helper might pick, by asking the verb's own
     * `request` list. Everything in the create/import/forget feature goes
     * through this, so a helper that calls its staging token `staging_id`
     * instead of `token` works with no edit here.
     *
     * It returns null when the verb declares none of them, and every caller
     * treats null as "do not send this key" rather than inventing one — a page
     * that guessed a field name would be sending a request the helper never
     * described, which is the design rule at the top of this file inverted. */
    function requestFieldName(verbName, candidates, fallback) {
        var names = argNames(verbName);
        for (var i = 0; i < candidates.length; i++)
            if (names.indexOf(candidates[i]) >= 0) return candidates[i];
        return fallback === undefined ? null : fallback;
    }
    /* The mirror of the above for a RESPONSE: the first of these keys the
     * helper actually sent, or undefined. Used for the staging token, the
     * chunk size, the remaining-attempts figure and the staging expiry — all
     * of which this page must READ rather than compute, because every one of
     * them is a number only the helper knows. */
    function pickKey(obj, candidates) {
        if (!obj || typeof obj !== "object") return undefined;
        for (var i = 0; i < candidates.length; i++)
            if (obj[candidates[i]] !== undefined && obj[candidates[i]] !== null)
                return obj[candidates[i]];
        return undefined;
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
        var verb = verbFor("breach");
        /* The escalation this answer is being obtained at, recorded on the
         * cache entry. Asking about an admin-class safe's corpus without
         * administrative access is refused by the helper, and remembering that
         * refusal for the life of the page would leave "breach check could not
         * be reached" under every password box long after access came on.
         * dropStaleForEscalation() clears it; this stamp is what tells it
         * which entries to clear. */
        var admin = verb ? adminForVerb(verb, safeSpecById(safeId)) : false;
        st = BREACH[key] = { state: "asking", reason: "", pending: null, _admin: admin };
        if (!verb) {
            st.state = "no";
            st.pending = Promise.resolve(st);
            return st.pending;
        }
        var req = {};
        if (safeId) req.safe = safeId;
        st.pending = callOnce(verb, req, admin)
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
        /* A REPEATING subform: N rows of the same shape, with Add and Remove.
         *
         * Nothing here is about custom fields specifically. This is the
         * generic "array of objects" the field dictionary is now able to
         * describe — the element fields come from the descriptor, exactly the
         * way `object` takes its subform from one — and a verb that declares
         * any other repeating shape gets the same editor with no edit here.
         * The custom string field is simply the first request that needed it.
         *
         * The spellings below are the ones a reasonable schema might pick for
         * the same idea, in the same spirit as VERB_ALIASES: the page does not
         * dictate the name, it recognises it. */
        "rows": "rows", "row-list": "rows", "rowlist": "rows",
        "repeat": "rows", "repeating": "rows", "multi-object": "rows",
        "custom": "rows", "custom-field": "rows", "custom-fields": "rows",
        "custom_fields": "rows", "customfields": "rows",
        "custom-string": "rows", "custom-strings": "rows", "custom_strings": "rows",
        "kv": "rows", "key-value": "rows", "keyvalue": "rows", "key_value": "rows",
        "pairs": "rows", "name-value": "rows", "field-list": "rows",
        "fieldlist": "rows", "attributes": "rows",
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
        /* PROMOTIONS TO THE ROW LIST. Both are the schema saying "many of
         * these" in a way the control name alone did not.
         *
         *   object + type array   `object` describes ONE subform. The same
         *                         descriptor typed as an array says the
         *                         request carries a LIST of them, and drawing
         *                         a single subform would silently drop every
         *                         row after the first — a loss with no visible
         *                         symptom, which is the failure mode this file
         *                         refuses everywhere else.
         *
         *   tags + element fields `type: "array"` on its own is a list of
         *                         strings, which is the tags box. An array
         *                         whose ELEMENTS carry their own field list is
         *                         a list of objects, and a comma-separated
         *                         text box cannot carry one. */
        var repeats = !!(spec && (spec.repeat === true || spec.multiple === true ||
                                  spec.many === true)) || t === "array" || t === "list";
        var hasElementFields = !!(spec && Array.isArray(spec.fields) && spec.fields.length);
        var hasKeyField = !!(spec && spec.key && typeof spec.key === "object" &&
                             specName(spec.key));
        if (kind === "object" && repeats) kind = "rows";
        if (kind === "tags" && hasElementFields) kind = "rows";
        /* A descriptor that names its map KEY *and* describes its element
         * FIELDS is a map of objects, which is a row list whose first column
         * is the key. That combination cannot describe anything else, so the
         * promotion is safe whatever `control` said — and what `control` says
         * for the helper's `custom` field today is "json", which would put an
         * operator in front of a textarea and ask them to type
         *     {"API token": {"value": "…", "protected": true}}
         * by hand. The schema described a name, a value and a flag; drawing a
         * name, a value and a flag is rendering what it described, and a raw
         * JSON box is this page declining to. */
        if (hasKeyField && hasElementFields) kind = "rows";
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
        /* A ROW LIST IS SECRET WHOLESALE, whatever the container's own `secret`
         * key says — and the container's key will usually say false, because
         * the names in it are not secrets.
         *
         * The reason is where the values live. A row of a custom-field list
         * carries a name AND a value, and the value is a credential the moment
         * its `protected` flag is on. If the container were treated as
         * non-secret, buildForm().values() would collect the whole array —
         * values included — into the ordinary bag that the dialog's submit
         * path walks, and the promise this file makes in its header ("values()
         * returns the NON-secret values only", I11) would be false at one
         * level of nesting. Marking the container secret puts the entire array
         * on the applySecrets() path instead: read once, immediately before
         * the request is serialized, and dropped straight after.
         *
         * It also means addArgv() refuses it, which is the right refusal: a
         * custom field's value must never reach a command line (I10). */
        if (controlType(spec) === "rows") return true;
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
        /* Control "rows": the element descriptors, the live row forms, the host
         * they live in, and the change handlers a row created later has to be
         * wired into. */
        var rowSpecs = null, rowDrawSpecs = null, rowCtls = null;
        var rowHost = null, rowAdd = null;
        var rowWatchers = [];
        var ROW_SEQ = 0;
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
        case "rows": {
            /* A REPEATING SUBFORM — N rows of the shape the descriptor
             * declares, with Add and Remove.
             *
             * Like `object` above, the nesting is the helper's: the element
             * fields come from `spec.fields`, resolved one level down through
             * the same FIELD shape, and this file writes none of them. When the
             * descriptor declares a list but not what one row contains, the
             * three parts docs/CONTRACT.md pins for a custom field are drawn
             * and a visible note says that is what happened — the same
             * contract-as-fallback rule the rest of this page follows, never a
             * silent guess.
             *
             * It is a <fieldset>/<legend> rather than a <label for>, for the
             * same reason the radiogroup is: a group of controls that answer
             * one question needs to be announced as one group, or a screen
             * reader reads a run of orphaned name/value boxes with no idea
             * what they belong to. */
            clear(wrap);
            /* The element descriptors, in the order they are drawn. A map-shaped
             * field publishes its KEY separately from its element `fields` —
             * the helper's `custom` descriptor is exactly that: `key` is the
             * field name, `fields` is {value, protected} — so the key goes
             * first and becomes the row's identifying column. */
            rowSpecs = (Array.isArray(spec.fields) && spec.fields.length)
                ? spec.fields
                : (Array.isArray(spec.item_fields) && spec.item_fields.length
                    ? spec.item_fields
                    : (Array.isArray(spec.row_fields) && spec.row_fields.length
                        ? spec.row_fields : CONTRACT_CUSTOM_ROW));
            if (spec.key && typeof spec.key === "object" && specName(spec.key) &&
                rowSpecs !== CONTRACT_CUSTOM_ROW)
                rowSpecs = [spec.key].concat(rowSpecs);
            var rfs = el("fieldset", "sec-rows");
            var rlg = el("legend", null, spec.label || fname);
            rfs.appendChild(rlg);
            if (spec.help) rfs.appendChild(el("div", "hint", spec.help));
            if (spec.breaks_when_wrong)
                rfs.appendChild(el("div", "hint", String(spec.breaks_when_wrong)));
            if (rowSpecs === CONTRACT_CUSTOM_ROW)
                rfs.appendChild(el("div", "hint", ROWS_FALLBACK_NOTE));
            /* THE GUIDANCE IS HOISTED OUT OF THE ROWS, ONCE.
             *
             * Every other control on this page prints its descriptor's `help`
             * and `breaks_when_wrong` beside it, because that sentence is the
             * most useful thing on the form and is not this page's to write.
             * In a REPEATER that rule turns against itself: the helper's
             * custom-name field carries a hundred and ninety words about which
             * ten KeePass names are reserved and why, and three rows means
             * three identical copies of it, which is how a form becomes
             * unreadable and how people learn to skip the prose.
             *
             * So it is printed once, under the legend, labelled by field — the
             * same words, none dropped, said once instead of once per row. The
             * rows themselves are drawn from copies with those two keys
             * cleared. Nothing else about the descriptor is touched: pattern,
             * required, maxlength, secret and default all still come from the
             * helper, and validation still quotes its own message. */
            var guide = el("div", "sec-row-guide");
            rowSpecs.forEach(function (f) {
                if (!f.help && !f.breaks_when_wrong) return;
                var lead = (f.label || specName(f)) + " — ";
                if (f.help) {
                    var h = el("div", "hint");
                    h.appendChild(el("strong", null, lead));
                    h.appendChild(document.createTextNode(String(f.help)));
                    guide.appendChild(h);
                }
                if (f.breaks_when_wrong)
                    guide.appendChild(el("div", "hint",
                        (f.help ? "" : lead) + String(f.breaks_when_wrong)));
            });
            if (guide.childNodes.length) rfs.appendChild(guide);
            rowDrawSpecs = rowSpecs.map(function (f) {
                var c = {};
                Object.keys(f).forEach(function (k) { c[k] = f[k]; });
                c.help = null;
                c.breaks_when_wrong = null;
                return c;
            });
            rowHost = el("div", "sec-rowlist");
            rowHost.id = id;
            rfs.appendChild(rowHost);
            rowCtls = [];
            rowAdd = btn(spec.add_label ? String(spec.add_label) : "Add a field",
                         "tiny", function () {
                var rc = addRow();
                rc.form.focusFirst();
                announce("Added an empty row. It is row " + rowCtls.length + " of " +
                         rowCtls.length + ".");
            });
            rfs.appendChild(rowAdd);
            if (spec.partial)
                rfs.appendChild(el("div", "hint",
                    "Only the rows you fill in are sent; an empty row is not a change."));
            wrap.appendChild(rfs);
            break;
        }
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

        /* ---------------- control "rows": the repeater's machinery -------- */

        /* The first element field is the row's KEY — the custom field's name.
         * "First" is the schema's own ordering, not a name this file looks for:
         * a descriptor that puts the identifying field first is describing
         * which one it is, and a row whose key is empty is an empty row. */
        function rowKeyName() { return specName(rowSpecs[0]) || "name"; }

        /* One row's COMPLETE value, secrets included.
         *
         * values() is secret-free by construction, so the secret half is read
         * back through the row form's own applySecrets() — the same door every
         * other secret on this page goes through, one read, immediately before
         * the value is handed on. Nothing here keeps a reference afterwards:
         * the object is returned to rowsValue(), which is only ever called from
         * the parent form's applySecrets(). */
        function rowFull(rc) {
            var o = rc.form.values();
            rc.form.applySecrets(o);
            return o;
        }

        function rowIsEmpty(o) {
            var k = rowKeyName();
            var v = o[k];
            return (v === undefined || v === null || String(v).trim() === "");
        }

        /* Anything at all typed into a row, key or not — used to tell an
         * abandoned empty row (dropped in silence) from a row with a value and
         * no name (refused out loud, because dropping it would throw away
         * something the operator typed). */
        function rowHasAnything(o) {
            var k = rowKeyName();
            return Object.keys(o).some(function (n) {
                if (n === k) return false;
                var v = o[n];
                if (v === undefined || v === null || v === "" || v === false) return false;
                if (Array.isArray(v) && !v.length) return false;
                /* A boolean that is merely sitting at its declared default is
                 * not something the operator typed. */
                for (var i = 0; i < rowSpecs.length; i++)
                    if (specName(rowSpecs[i]) === n &&
                        rowSpecs[i]["default"] !== undefined &&
                        rowSpecs[i]["default"] === v) return false;
                return true;
            });
        }

        function renumberRows() {
            rowCtls.forEach(function (rc, ix) {
                rc.node.setAttribute("aria-label",
                    (spec.label || fname) + " row " + (ix + 1) + " of " + rowCtls.length);
            });
        }

        function removeRow(rc) {
            var ix = rowCtls.indexOf(rc);
            if (ix < 0) return;
            rc.form.wipeAll();                 /* scrub before detaching (I11) */
            rowCtls.splice(ix, 1);
            if (rc.node.parentNode) rc.node.parentNode.removeChild(rc.node);
            renumberRows();
            if (rowAdd) rowAdd.focus();
            announce("Removed a row. " + rowCtls.length + " left.");
            rowWatchers.forEach(function (fn) { fn(); });
        }

        function addRow(values) {
            var rc = { form: null, node: null };
            rc.node = el("div", "sec-row");
            rc.node.setAttribute("role", "group");
            rc.form = buildForm(rowDrawSpecs, { values: values || {} });
            rc.node.appendChild(rc.form.node);
            var rm = btn("Remove", "danger tiny", function () { removeRow(rc); });
            rm.setAttribute("aria-label", "Remove this row");
            /* On a PARTIAL list — the helper sends only the rows that are
             * filled in — taking a row out of this form is not the same as
             * taking the field out of the safe, and an operator who thinks it
             * is will believe they deleted something they did not. Say which
             * one it is, on the control itself. */
            if (spec.partial)
                rm.title = "Takes this row out of this form. The field already in the safe " +
                           "is left exactly as it is: only the rows you fill in are sent.";
            rc.node.appendChild(rm);
            rowHost.appendChild(rc.node);
            rowCtls.push(rc);
            renumberRows();
            /* A row created after the parent form wired its dependency handler
             * still has to report changes, or depends_on stops working for
             * everything downstream of this control. */
            rowWatchers.forEach(function (fn) {
                rc.form.controls.forEach(function (c) { c.onChange(fn); });
            });
            rowWatchers.forEach(function (fn) { fn(); });
            return rc;
        }

        /* The wire shape.
         *
         * An ARRAY of row objects, keyed by the element ids the schema
         * declared — that is what `type: "array"` asked for and it is the only
         * shape that can carry a per-row flag. A descriptor typed `object`
         * asks for a MAP instead, so the key field becomes the property name
         * and what is left of the row becomes its value: a bare scalar when
         * one field remains, the rest of the row when more than one does.
         *
         * Both are read off the descriptor. Nothing here picks a shape the
         * schema did not ask for, and the helper is what refuses one it did
         * not mean. */
        function rowsValue() {
            var out = [];
            rowCtls.forEach(function (rc) {
                var o = rowFull(rc);
                if (rowIsEmpty(o)) { dropDeep(o); return; }
                out.push(o);
            });
            if (!out.length) return undefined;
            if (String(spec.type || "").toLowerCase() !== "object") return out;
            var key = rowKeyName();
            var map = {};
            out.forEach(function (o) {
                var rest = {};
                var names = [];
                Object.keys(o).forEach(function (n) {
                    if (n === key) return;
                    rest[n] = o[n];
                    names.push(n);
                });
                map[String(o[key])] = (names.length === 1) ? rest[names[0]] : rest;
            });
            return map;
        }

        function setRows(v) {
            while (rowCtls.length) {
                var rc = rowCtls.pop();
                rc.form.wipeAll();
                if (rc.node.parentNode) rc.node.parentNode.removeChild(rc.node);
            }
            var key = rowKeyName();
            if (Array.isArray(v)) {
                v.forEach(function (r) {
                    if (r && typeof r === "object") { addRow(r); return; }
                    /* A bare list of NAMES — which is what a listing that
                     * reports custom fields without their values looks like. */
                    var one = {};
                    one[key] = String(r);
                    addRow(one);
                });
            } else if (v && typeof v === "object") {
                Object.keys(v).forEach(function (n) {
                    var row = {};
                    row[key] = n;
                    var val = v[n];
                    if (val && typeof val === "object" && !Array.isArray(val))
                        Object.keys(val).forEach(function (k2) { row[k2] = val[k2]; });
                    else if (rowSpecs.length > 1) row[specName(rowSpecs[1])] = val;
                    addRow(row);
                });
            }
            renumberRows();
        }

        function rowsValidate() {
            var first = null;
            var seen = {};
            var key = rowKeyName();
            rowCtls.forEach(function (rc) {
                var o = rowFull(rc);
                if (rowIsEmpty(o)) {
                    /* An untouched row is not an error — it is a row the
                     * operator added and did not use, and dropping it silently
                     * is right. A row with a VALUE and no name is different:
                     * dropping that would throw away something they typed. */
                    if (rowHasAnything(o) && !first)
                        first = (rowSpecs[0].label || key) + " is required on every row " +
                                "that has anything in it.";
                    dropDeep(o);
                    return;
                }
                var k = String(o[key]);
                if (Object.prototype.hasOwnProperty.call(seen, k)) {
                    if (!first) first = "“" + k + "” appears twice. Every row needs its " +
                        "own name: two rows with the same one are one field in the file, " +
                        "so the second would replace the first with nothing to show for it.";
                } else { seen[k] = 1; }
                dropDeep(o);
                var m = rc.form.validate();
                if (m && !first) first = m;
            });
            if (!first && spec.required && !rowCtls.length)
                first = (spec.label || fname) + " needs at least one row.";
            return first;
        }

        function setValue(v) {
            if (kind === "rows") { setRows(v); return; }
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
            /* A row list returns the WHOLE array, values included — and it is
             * only ever reached through applySecrets(), because isSecretSpec()
             * marks the control secret. values() never calls this. */
            if (kind === "rows") return rowsValue();
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
            if (kind === "rows") return rowsValidate();
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
                if (kind === "rows") {
                    if (rowCtls && rowCtls.length) { rowCtls[0].form.focusFirst(); return; }
                    if (rowAdd) rowAdd.focus();      /* an empty list: Add is the control */
                    return;
                }
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
                if (kind === "rows") {
                    /* Remembered as well as attached: a row added later has to
                     * be wired up too, or depends_on stops seeing this control
                     * change the moment the operator presses Add. */
                    rowWatchers.push(fn);
                    rowCtls.forEach(function (rc) {
                        rc.form.controls.forEach(function (c) { c.onChange(fn); });
                    });
                    return;
                }
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
                if (kind === "rows") {
                    /* Scrub every row's controls, then take the rows away. A
                     * detached node still holding a value is the one thing the
                     * Lock button could not reach (I11, I17). */
                    while (rowCtls.length) {
                        var rc = rowCtls.pop();
                        rc.form.wipeAll();
                        if (rc.node.parentNode) rc.node.parentNode.removeChild(rc.node);
                    }
                    return;
                }
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
        /* Scrub the CREDENTIAL and keep the structure.
         *
         * wipe() on a row list takes the rows away, which is what locking and a
         * successful submit want. An error path wants something narrower: the
         * dialog stays open with the helper's refusal on it, and taking the
         * operator's typed field NAMES away along with the values would punish
         * them for a failed request by making them retype the form. So the
         * values go and the rows stay. Everything that is not a row list has
         * one behaviour, and this is it. */
        ctrl.wipeSecret = function () {
            if (kind === "rows") {
                rowCtls.forEach(function (rc) { rc.form.wipeSecrets(); });
                return;
            }
            ctrl.wipe();
        };
        if (initial !== undefined) setValue(initial);
        else if (spec["default"] !== undefined && spec["default"] !== null)
            setValue(spec["default"]);
        /* An empty row list is a legend and a button, which reads as a feature
         * that is switched off. One empty row shows the shape of what can be
         * added; it carries no key, so rowsValue() drops it and an untouched
         * form sends nothing. */
        if (kind === "rows" && rowCtls && !rowCtls.length) addRow();
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
                    /* wipeSecret() is wipe() for everything except a row list,
                     * where it scrubs the values and leaves the rows standing
                     * — see the comment on it in makeControl. */
                    if (c.secret) { c.wipeSecret(); return; }
                    if (c.kind === "object" && c.sub) c.sub.wipeSecrets();
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
    /* THE CLIPBOARD COUNTDOWN IS ARMED FOR SECRETS ONLY.
     *
     * It used to be armed for everything this function was handed, including a
     * registry path — which is not secret, is on screen in full a centimetre
     * away, and is the sort of thing an operator copies into a shell. A chip
     * that cries wolf teaches an operator to ignore the one that matters, and
     * the countdown chip IS the page's statement that something dangerous is
     * on the clipboard.
     *
     * So the caller says. `secret: true` arms the countdown and clears the
     * clipboard on its deadline; the default is a plain copy with a one-shot
     * polite confirmation and no chip. There is no third behaviour: a value is
     * either worth clearing or it is not.
     *
     * opts: { secret: bool, what: string }  — `what` names the thing in the
     * announcement, and never contains the value itself. */
    function copyValue(value, opts) {
        opts = opts || {};
        if (!navigator.clipboard || !navigator.clipboard.writeText)
            return Promise.reject(mkErr("unsupported",
                "This browser does not offer the clipboard API to this page."));
        return navigator.clipboard.writeText(value).then(function () {
            if (opts.secret)
                clipboardArm(uiNum("clipboard_seconds", uiNum("reveal_seconds", 15)));
            else
                announce((opts.what || "Value") + " copied. It is not a secret, so the " +
                         "clipboard is not being counted down or cleared.");
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
            /* ONE custom property on the track, never a built style string.
             * The bar's whole geometry lives in secrets.css; this sets a
             * number. That is the CSP-safe form (I9) and it is also the only
             * thing that has to change if the bar is ever restyled. */
            meter.style.setProperty("--sec-remain",
                Math.max(0, Math.min(100, (left / seconds) * 100)) + "%");
            /* THE LAST FIVE SECONDS. The numerals go medium-weight and
             * danger-coloured and the bar follows — but the numeral itself is
             * still the text carrier, so colour is never alone. */
            var urgent = left <= 5;
            cd.className = "sec-countdown" + (urgent ? " urgent" : "");
            meter.className = "sec-meter" + (urgent ? " urgent" : "");
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
            meter.className = "sec-meter";
            cd.className = "sec-countdown";
            meter.style.setProperty("--sec-remain", "100%");
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
                copyValue(shown, { secret: true })
                    .catch(function (e) { errHost.appendChild(errNode(e)); });
                return;
            }
            /* Not on screen: fetch, then write inside the promise chain this
             * click started. If the browser has already dropped the gesture the
             * write rejects and we say so rather than failing silently. */
            fetchValue().then(function (r) {
                return copyValue(r.value, { secret: true });
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
     * COCKPIT OWNS THE ADMINISTRATIVE PROMPT, AND IT DOES NOT LEND IT OUT.
     * This page spawns admin-class verbs with superuser:"require"; when the
     * session already has administrative access that runs the helper as root,
     * and when it does not the bridge refuses the channel with `access-denied`
     * AND NO DIALOG IS SHOWN. Measured on Cockpit 360, in a real session, from
     * inside this frame — the dialog is the shell's own component behind the
     * header control, which calls cockpit.Superuser.Start() and listens for its
     * Prompt signal around that one call; nothing a package page can reach
     * makes it appear, and drawing a lookalike here would be a password box
     * this program did not write asking for a password it must never see.
     *
     * So the rule is: ask for escalation on every admin verb, report honestly
     * when it was not granted, and point at the control that grants it.
     * cockpit.permission tells us which of the two states we are in, so the
     * list can say so up front instead of only failing.
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
     * Cockpit will ask you for it", described something NOTHING does: it was
     * removed when the live run measured the bridge refusing that spawn with
     * `access-denied` and no prompt (see the section header above).
     *
     * Whether this operator may open it is decided by the ESCALATED verb, and
     * the helper re-checks the class inside it from kernel identity (I3). That
     * is the refusal that counts; this one is a statement about a spawn that
     * did not ask. */
    function pendingEscalation(safe) {
        return isAdminClass(safe) && !adminAllowed();
    }

    /* ------------------------------------------------------------------ *
     * PRIVILEGE-LEVEL STALENESS — the general form of the bug above.
     *
     * The escalation bug was not really about `safeReachable`. It was about a
     * page keeping an answer the helper gave at ONE privilege level and reusing
     * it as though it were the answer at ANOTHER. `list` runs unescalated,
     * always; its verdict on an admin-class safe is a fact about the euid that
     * asked and not about the operator, and reading it as a refusal disabled
     * the default access class permanently.
     *
     * Every other cached helper answer on this page has the same shape, so
     * every one of them is stamped with the escalation it was obtained at and
     * dropped when that stamp is lower than what the question now needs. The
     * three caches are PROBES (per safe), BREACH (per safe) and HEALTH (one
     * document). A stamp of `true` means "asked with superuser:require".
     *
     * The rule is one-directional on purpose: an answer obtained ESCALATED is
     * not invalidated when administrative access goes away. It is still a true
     * statement about the file — the KDF it uses, the warnings it carries —
     * and re-asking would be a Cockpit prompt the operator did not ask for.
     * What changes is that the verbs are refused again, and the helper is what
     * refuses them (I3).
     * ------------------------------------------------------------------ */

    /* What escalation a question about this safe has to be asked at. */
    function needsAdminFor(safe) { return isAdminClass(safe); }

    /* Was this cached answer obtained at a high enough privilege to be worth
     * anything? An entry with no stamp is from an older code path and is
     * treated as unescalated, which is the restrictive reading. */
    function staleForClass(entry, safe) {
        if (!entry) return false;                 /* nothing cached is not stale */
        return needsAdminFor(safe) && entry._admin !== true;
    }

    /* Throw away every cached answer that administrative access has just made
     * askable properly. Called from the permission listener, which is the only
     * moment the privilege level changes under a page that is already drawn. */
    function dropStaleForEscalation() {
        var dropped = 0;
        SAFES.forEach(function (s) {
            if (!needsAdminFor(s)) return;
            if (staleForClass(PROBES[s.id], s)) { delete PROBES[s.id]; dropped++; }
            var b = BREACH[s.id];
            if (b && b._admin !== true) { delete BREACH[s.id]; dropped++; }
        });
        /* The safe-less breach question — asked from a password control with
         * nothing open — is keyed on the empty string. It is asked
         * unescalated by construction, so it goes too rather than being the
         * one cache entry that outlives a privilege change. */
        if (BREACH[""] && BREACH[""]._admin !== true) { delete BREACH[""]; dropped++; }
        /* `health` is one document covering every safe, and its admin-class
         * agent socket path is euid-dependent — measured: the helper reports
         * /run/cockpit-secrets/<euid>/agent.sock, so an unescalated health call
         * describes a socket the admin-class agent does not use. Re-ask it
         * escalated the moment that is possible and there is an admin-class
         * agent to see. */
        if (agentPollAdmin() && HEALTH_ADMIN !== true) { HEALTH = null; dropped++; }
        return dropped;
    }

    function escalationBanner() {
        if (adminAllowed()) return null;
        /* …and only when there is actually something waiting on it. A registry
         * of nothing but user-class safes is a registry with no admin-class
         * safe to be unable to open, and a permanent warning about a situation
         * that does not exist is how a page teaches people to ignore its
         * warnings. */
        if (!SAFES.some(pendingEscalation)) return null;
        var box = el("div", "sec-alert warn");
        /* WHAT THIS SENTENCE USED TO SAY, AND WHY IT WAS WRONG.
         *
         * It ended "— or just open one below and Cockpit will ask you for it",
         * and that is not what happens. MEASURED on this host, Cockpit 360,
         * with a session in limited access: a channel opened with
         * `superuser: "require"` is refused IMMEDIATELY with `access-denied`
         * and no dialog is drawn anywhere. Cockpit's escalation dialog belongs
         * to the SHELL: it is the component behind the header control, it calls
         * `cockpit.Superuser.Start()` itself and listens for the `Prompt`
         * signal around that one call. There is no API by which a package page
         * can make it appear — `superuser` as the shipped pages import it is
         * read-only (`allowed`, `configured`, `reload_page_on_change`), and a
         * page that called `Start()` on its own would receive the Prompt signal
         * in its own frame and have to draw Cockpit's password dialog itself,
         * which is exactly the thing this page must never do.
         *
         * So the banner names the one control that really escalates, and does
         * not promise a second route that does not exist. An operator who
         * followed the old sentence got a bare "access-denied" on the card and
         * no way to tell a refusal from an un-asked question. */
        box.appendChild(el("p", null,
            "Administrative access is off in this Cockpit session, so admin-class safes " +
            "cannot be opened yet. Turn it on with the “Limited access” control in the " +
            "Cockpit header, then open the safe here."));
        box.appendChild(el("p", "sec-subtle",
            "Cockpit only asks for a password from that control. Opening an admin-class " +
            "safe from this page while access is off is refused straight away, without a " +
            "prompt — nothing is wrong when that happens, and nothing has been sent."));
        return box;
    }

    /* ================================================================== *
     * The safe list
     * ================================================================== */
    /* STATE 1 — LOADING. A skeleton, not a spinner, and it NEVER SHIMMERS —
     * for anyone, not only under reduced motion. A pulsing block behind a
     * security tool reads as activity that is not happening. A static tint at
     * the table's real row height says "a table is coming and it will be about
     * this big", which is the true statement and stops the layout jumping when
     * the rows arrive. */
    function skeletonTable(host) {
        var wrap = el("div", "sec-tablewrap");
        var sk = el("div", "sec-skeleton");
        sk.setAttribute("aria-hidden", "true");
        for (var i = 0; i < 3; i++) sk.appendChild(el("span"));
        wrap.appendChild(sk);
        host.appendChild(el("p", "sec-subtle", "Reading the safe registry…"));
        host.appendChild(wrap);
    }

    function refreshAll() {
        alertBox(null);
        var host = byId("sec-safes");
        clear(host);
        skeletonTable(host);
        /* `list` is a plain, unescalated call: it names what exists. Whether
         * the caller may OPEN any given safe is decided by the helper, per
         * verb, from the kernel's idea of who is calling (I3). */
        callOnce("list", {}, false).then(function (res) {
            SAFES = (res && res.safes) || [];
            /* REFRESH MEANS RE-READ. probeSafe() now declines to re-ask a safe
             * that already holds an answer good at the current privilege level
             * — which is what stops the permission listener from firing a
             * second round of probes — so the caches have to be emptied here or
             * pressing Refresh would redraw the same stale card. Nothing is
             * lost by it: an admin-class probe is only re-asked when
             * administrative access is already on, so this costs no extra
             * Cockpit prompt. */
            PROBES = {};
            BREACH = {};
            renderSafes();
            /* Only now can health be asked usefully: whether to keep polling
             * it, and whether to ask escalated, are both decided from the
             * registry rows that have just arrived. The call is UNCONDITIONAL
             * — it is what makes the export confirm name the right directory,
             * and it reports any hold the agent already has — but its
             * escalation is not.
             *
             * It used to be hard-coded to false, and that was the same
             * privilege-level mistake as the one above wearing different
             * clothes: the admin-class agent socket is
             * /run/cockpit-secrets/<euid>/agent.sock, so an unescalated health
             * call describes a socket that no admin-class hold ever uses. With
             * an admin safe holding a ticket, the banner stayed empty until the
             * next poll — up to fifteen seconds in which a safe was unlocked
             * and this page said nothing, which is exactly what I18's "an
             * unlocked safe must never be invisible" forbids.
             *
             * agentPollAdmin() is false unless an admin-class entry has opted
             * into the agent AND Cockpit has already granted access, so this
             * still never raises a prompt of its own. */
            refreshHealth(agentPollAdmin());
            SAFES.forEach(function (s) { probeSafe(s); });
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
        /* THE WHOLE MATRIX, because the bug was one cell of it and the fix has
         * to be right in all of them. `list` is spawned with no superuser
         * option, ALWAYS, so the euid column is "whoever the Cockpit bridge is
         * running as" and never "root because we escalated".
         *
         *  class  euid of list   admin access   list row      this returns
         *  -----  -------------  ------------   -----------   -------------------
         *  admin  the operator   off            usable:false  TRUE  — not a refusal:
         *  admin  the operator   ON             usable:false          the row says nothing
         *  admin  root (*)       either         usable:true   TRUE
         *  user   the operator   either         usable:true   TRUE
         *  user   the operator   either         usable:false  FALSE — authoritative
         *  user   root (*)       either         usable:false  FALSE — also authoritative:
         *                                                             the helper refuses a
         *                                                             user safe when it is
         *                                                             root, and this page
         *                                                             has no way to be
         *                                                             anything else
         *  (*) only when the logged-on Cockpit user IS root.
         *
         * The two admin rows in the middle are the finding: they are the same
         * row. Measured, same binary, same hermetic registry, same request,
         * euid the only variable — `usable:false` at euid 1000 for an operator
         * who IS in `sudo`, `usable:true` under `unshare --map-root-user`. The
         * user-class rows invert it exactly: a user safe is usable:false to a
         * root helper. In every case the verdict is a fact about the euid that
         * asked, and it is authoritative precisely when that euid is the one
         * the safe would actually be opened at — which is true for the user
         * class and false for the admin class.
         *
         * An ADMIN-class safe's usability therefore cannot be read off this
         * list AT ALL, and not merely while escalation is off.
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

    /* One probe, remembering the escalation it was asked at.
     *
     * `force` is the "Check this safe" button: it asks even while
     * administrative access is off, because triggering Cockpit's own prompt is
     * the entire point of that control. Everything else declines to probe an
     * admin-class safe unescalated — a prompt per card on load is an
     * interrogation, not a page. */
    function probeSafe(safe, force) {
        if (!safeReachable(safe)) return;
        var admin = isAdminClass(safe);
        if (admin && !adminAllowed() && !force) return;
        var already = PROBES[safe.id];
        if (already && !already._error && !staleForClass(already, safe) && !force) return;
        callOnce("probe", { safe: safe.id }, admin).then(function (res) {
            var out = res || {};
            out._admin = admin;
            PROBES[safe.id] = out;
            renderSafes();
        }).catch(function (e) {
            /* A refusal is remembered WITH the level it was refused at, so a
             * later escalation can tell "you were told no" from "you never
             * asked properly". Without that stamp the page kept a
             * cancelled-prompt error forever and hid the control that would
             * have retried it. */
            PROBES[safe.id] = { _error: e, _admin: admin };
            renderSafes();
        });
    }

    /* ================================================================== *
     * GLYPHS
     *
     * Every glyph on this page is either a real character in the text run with
     * a visually-hidden word beside it, or an inline <svg> built here with
     * createElementNS and painted with `currentColor`. No icon font, no sprite
     * sheet, no `content: url()`: no new asset, and nothing that could ever
     * become a CSP question (I9).
     * ================================================================== */
    var SVG_NS = "http://www.w3.org/2000/svg";
    /* Path data only — 16x16 viewBox, stroked, never filled with a colour of
     * its own. `class` is set by the caller so a state can tint it. */
    var GLYPHS = {
        /* A panel docked to the right: a rounded rectangle whose right-hand
         * third is divided off. This is the pane toggle. */
        "panel-right": ["M2 3h12v10H2z", "M10.5 3v10"],
        /* A key, for "held open" and for "hidden by elevation". */
        "key": ["M9.5 6.5a3 3 0 1 0-2.6 2.98L6 10.5v1.5H4.5V14H2v-2.5l4.9-4.9",
                "M11 4.5h.01"],
        /* A safe / box outline, for "no safes registered". */
        "box": ["M2 4.5h12v9H2z", "M2 4.5 8 2l6 2.5", "M8 8.5h3"],
        /* A warning triangle, for "the helper did not answer". */
        "warning": ["M8 2 15 14H1z", "M8 6.5v3.5", "M8 12h.01"],
        /* A closed padlock, for the lockout state (I16). */
        "lock": ["M3.5 7.5h9v6h-9z", "M5.5 7.5V5a2.5 2.5 0 0 1 5 0v2.5"]
    };
    function svgGlyph(name, cls) {
        var svg = document.createElementNS(SVG_NS, "svg");
        svg.setAttribute("viewBox", "0 0 16 16");
        svg.setAttribute("width", "16");
        svg.setAttribute("height", "16");
        svg.setAttribute("aria-hidden", "true");
        svg.setAttribute("focusable", "false");
        if (cls) svg.setAttribute("class", cls);
        (GLYPHS[name] || []).forEach(function (d) {
            var p = document.createElementNS(SVG_NS, "path");
            p.setAttribute("d", d);
            p.setAttribute("fill", "none");
            p.setAttribute("stroke", "currentColor");
            p.setAttribute("stroke-width", "1.5");
            p.setAttribute("stroke-linecap", "round");
            p.setAttribute("stroke-linejoin", "round");
            svg.appendChild(p);
        });
        return svg;
    }

    /* ================================================================== *
     * THE DETAILS PANE (R3) AND ITS TOGGLE (R4)
     *
     * One workspace, one pane, and the pane is where every action lives.
     *
     * WHY THE TOGGLE IS NOT A HAMBURGER, flagged so it can be overruled in one
     * line: the three bars mean NAVIGATION MENU everywhere they appear, and
     * this control docks and undocks a side panel. Using the menu glyph for it
     * would be the most confusing single choice on the page. R4's actual
     * requirement — a real <button>, with aria-expanded, with an accessible
     * name, that collapses and expands the pane — is met in full; only the
     * glyph differs. To revert: replace the svgGlyph("panel-right") call in
     * initPane() with document.createTextNode("☰") and leave everything
     * else exactly as it is.
     *
     * COLLAPSED MEANS GONE. There is no sliver. A sliver of a pane whose
     * content can include a revealed value is a half-open door, and it costs
     * horizontal space for no information. The affordance that the pane exists
     * is the toggle, which is always in the topbar and always carries
     * aria-expanded.
     * ================================================================== */
    function paneNode() { return byId("sec-pane"); }
    function paneBody() { return byId("sec-pane-body"); }
    function paneHeading() { return byId("sec-pane-h"); }
    function paneToggle() { return byId("sec-pane-toggle"); }

    /* MEASURED AGAINST THE FRAME, NOT THE WINDOW. Cockpit's sidebar eats the
     * width: the plugin iframe is 1160px inside a 1400px window and 760px
     * inside a 1000px one, so a media query in secrets.css evaluates against
     * 1160, not 1400. The old three-column browse layout collapsed at 75rem
     * (1200px) and therefore never happened at any ordinary desktop size —
     * which is why the entry detail rendered as a 208px strip below the fold.
     * 60rem is reachable where 75rem was not. */
    function frameIsWide() {
        return !!(window.matchMedia && window.matchMedia("(min-width: 60rem)").matches);
    }

    function setPaneOpen(open, opts) {
        opts = opts || {};
        var ws = byId("sec-workspace"), pane = paneNode(), tog = paneToggle();
        PANE.open = !!open;
        if (ws) {
            if (PANE.open) ws.classList.add("sec-pane-open");
            else ws.classList.remove("sec-pane-open");
        }
        if (pane) pane.hidden = !PANE.open;
        if (tog) tog.setAttribute("aria-expanded", PANE.open ? "true" : "false");
        /* The second skip link only exists while there is something to skip
         * to. A skip link pointing at a display:none target is a dead end. */
        var skip = byId("sec-skip-pane");
        if (skip) skip.hidden = !PANE.open;
        if (opts.announce) announce(PANE.open ? "Details pane shown." : "Details pane hidden.");
        if (opts.focus === "pane" && PANE.open && paneHeading()) paneHeading().focus();
        if (opts.focus === "toggle" && tog) tog.focus();
    }

    /* The default is recomputed only when the frame CROSSES 60rem, and only
     * while the operator has not touched the toggle. One boolean. */
    function syncPaneDefault() {
        var wide = frameIsWide();
        if (PANE.wide === wide) return;
        PANE.wide = wide;
        if (PANE.userToggled) return;
        setPaneOpen(wide);
    }

    function initPane() {
        var tog = paneToggle();
        if (tog) {
            tog.insertBefore(svgGlyph("panel-right"), tog.firstChild);
            tog.addEventListener("click", function () {
                PANE.userToggled = true;
                var opening = !PANE.open;
                setPaneOpen(opening, { announce: true,
                                       focus: opening ? "pane" : "toggle" });
            });
        }
        var back = byId("sec-pane-back");
        if (back) back.addEventListener("click", function () {
            /* Swaps the pane's CONTENT back to the safe's registry detail
             * without deselecting the entry, so the forward control returns to
             * exactly where the operator was. */
            PANE.mode = "safe";
            renderPane();
        });
        /* Escape inside the pane collapses it and returns focus to the toggle.
         * This is only safe because THE PANE CONTAINS NO FREE-TEXT ENTRY —
         * every mutation on this page goes through a modal. If that invariant
         * is ever broken this handler has to go with it. An open modal's own
         * handler runs first and swallows the key. */
        var pane = paneNode();
        if (pane) pane.addEventListener("keydown", function (ev) {
            if (ev.key !== "Escape") return;
            if (document.querySelector(".sec-modal")) return;
            PANE.userToggled = true;
            setPaneOpen(false, { announce: true, focus: "toggle" });
        });
        PANE.wide = frameIsWide();
        setPaneOpen(PANE.wide);
        if (window.matchMedia) {
            var mq = window.matchMedia("(min-width: 60rem)");
            var onCross = function () { syncPaneDefault(); syncTreeDisclosure(); };
            if (mq.addEventListener) mq.addEventListener("change", onCross);
            else if (mq.addListener) mq.addListener(onCross);
        }
        syncTreeDisclosure();
    }

    /* Selecting a row. The pane opens if it was collapsed — the operator asked
     * for detail, and a detail request that shows nothing is a bug. Focus
     * STAYS on the row button: the intent was to choose a safe, and yanking
     * focus out of the table breaks arrow-key scanning. */
    function selectSafe(id, opts) {
        opts = opts || {};
        PANE.safeId = id;
        PANE.mode = "safe";
        if (!PANE.open) setPaneOpen(true);
        renderPane();
        /* Re-rendering the table destroys the very node the operator is
         * standing on, so the door is put back under their finger. Without
         * this, clicking or Entering a row drops focus to <body> — which loses
         * their place entirely and is exactly what the arrow keys exist to
         * avoid. Focus is NOT moved into the pane: the intent was to choose a
         * safe, not to go and read about one. */
        var wasOnDoor = !!(document.activeElement &&
                           document.activeElement.classList &&
                           document.activeElement.classList.contains("sec-rowdoor"));
        if (!SESSION) renderSafes();
        if (wasOnDoor) {
            var back = document.querySelector(
                "#sec-safes tbody tr.selected button.sec-rowdoor");
            if (back) back.focus();
        }
        var safe = safeById(id);
        if (opts.announce !== false && safe)
            announce("Details for " + (safe.label || safe.id) +
                     " shown in the details pane.");
        /* Un-docked the pane is off-screen below the table, so "it appeared
         * somewhere further down" is not discoverable. Take the operator to it
         * — but only at that width, and never while it is docked beside them. */
        if (!frameIsWide() && paneNode()) {
            var reduce = window.matchMedia &&
                window.matchMedia("(prefers-reduced-motion: reduce)").matches;
            try {
                paneNode().scrollIntoView({ block: "start",
                                            behavior: reduce ? "auto" : "smooth" });
            } catch (e) { paneNode().scrollIntoView(); }
            if (paneHeading()) paneHeading().focus();
        }
    }

    function safeById(id) {
        var found = null;
        SAFES.forEach(function (s) { if (s.id === id) found = s; });
        return found;
    }

    /* ------------------------------------------------------------------ *
     * R1 — visibility follows elevation.
     *
     * User-class safes are always listed. Administrator-class safes are listed
     * only while cockpit.permission({admin:true}).allowed is true, and the list
     * reacts to the `changed` event, not only to page load.
     *
     * SAY PLAINLY THAT THIS IS COSMETIC. Hiding a row is presentation only:
     * the helper re-derives who is calling from the kernel and re-checks the
     * access class inside every verb, and that is what refuses a safe you may
     * not open — whether or not this page drew a row for it. A page that hides
     * rows and lets an operator infer that hiding IS the control is lying
     * about where the security boundary is.
     *
     * AND THE TRAP: admin is the DEFAULT access class (I1), so a typical
     * install is mostly admin safes and an unelevated administrator would
     * otherwise open this page, see nothing, and conclude the tool is broken.
     * Whenever this hides anything, the page says so — by COUNT ONLY, never an
     * id, a label, a format or a path.
     * ------------------------------------------------------------------ */
    /* WHAT HAPPENS WHEN ADMINISTRATIVE ACCESS CHANGES UNDER A DRAWN PAGE.
     *
     * Granted is easy: rows appear, the count note goes, focus does not move —
     * moving an operator's focus because a background condition IMPROVED is
     * hostile.
     *
     * Revoked while an admin safe is SELECTED is the case that has to be
     * specified, and the order below is the specification:
     *   1. if a session is open on that safe, LOCK IT. Not merely tidy: the
     *      helper will refuse the next verb anyway, and a page holding a live
     *      handle it can no longer use is a page showing stale,
     *      decrypted-looking content.
     *   2. wipe every revealed value in the DOM and cancel every countdown.
     *   3. clear the clipboard, with the reason.
     *   4. the pane STAYS OPEN and switches to its "nothing selected" content.
     *      It is not closed: collapsing a pane out from under a keyboard user
     *      moves focus somewhere they did not ask for, and the pane's empty
     *      state is where the explanation now needs to be.
     *   5. the toggle keeps whatever aria-expanded it had. The pane's CONTENT
     *      changed; its disposition did not, and the operator did not touch it.
     *   6. focus moves to #sec-main only if it was inside the pane or the row
     *      that is about to be removed. Never to a node about to be removed,
     *      and never allowed to fall to <body>.
     *   7. an ASSERTIVE alert, because this interrupts what they were doing.
     *      It names the safe's LABEL deliberately — they had it selected a
     *      moment ago, so this discloses nothing they were not already looking
     *      at, and an anonymous "a safe was locked" is useless.
     */
    function elevationChanged() {
        var hidden = hiddenSafeCount();
        var sel = PANE.safeId ? safeById(PANE.safeId) : null;
        var losing = sel && !safeIsVisible(sel);
        var openLosing = SESSION && !safeIsVisible(SESSION.safe);

        if (!losing && !openLosing) {
            if (adminAllowed())
                announce("Administrative access is on." +
                         (SAFES.length ? " " + visibleSafes().length + " safe" +
                          (visibleSafes().length === 1 ? " is" : "s are") + " listed." : ""));
            else if (hidden)
                announce(hiddenSentence(hidden));
            return;
        }

        var name = (openLosing ? SESSION.safe : sel);
        var label = String(name.label || name.id);

        /* Where focus is standing right now, decided BEFORE anything is
         * removed. */
        var inDoomed = false;
        var active = document.activeElement;
        if (active) {
            if (paneNode() && paneNode().contains(active)) inDoomed = true;
            var row = active.closest ? active.closest("tr.sec-safe") : null;
            if (row) inDoomed = true;
        }

        if (openLosing) lockNow("administrative access was turned off");
        wipeAllValues();
        clipboardClear("administrative access was turned off");

        PANE.safeId = null;
        PANE.mode = "safe";
        /* Note what is NOT done here: setPaneOpen() is not called. */
        renderPane();

        if (inDoomed && byId("sec-main")) byId("sec-main").focus();

        alertText("Administrative access was turned off. " + label + " was locked and " +
                  "everything shown from it was cleared. Administrator safes are hidden " +
                  "until access is on again.", "warn");
        announce(hiddenSentence(hiddenSafeCount()));
    }

    function safeIsVisible(safe) { return !isAdminClass(safe) || adminAllowed(); }
    function visibleSafes() { return SAFES.filter(safeIsVisible); }
    function hiddenSafeCount() { return SAFES.length - visibleSafes().length; }
    function hiddenSentence(n) {
        return n + " administrator safe" + (n === 1 ? " is" : "s are") + " hidden.";
    }

    /* ------------------------------------------------------------------ *
     * The State cell (R2, column 4).
     *
     * Every state an operator must not miss, as chips, in severity order. At
     * most two are drawn and the rest become "+N" — a row with six chips is a
     * row nobody reads, and the pane lists all of them in full.
     *
     * EVERY CHIP'S MEANING IS ITS WORD. Colour is a second carrier and never
     * the only one, which is also why there is no "Normal" chip: nothing to
     * say is an empty cell.
     * ------------------------------------------------------------------ */
    function safeStates(safe) {
        var p = PROBES[safe.id], out = [];
        /* Rank 1. safeReachable() is called, never re-derived: an
         * ADMIN-class safe is NEVER marked unreachable, because `list` is
         * always spawned unescalated and returns usable:false for every admin
         * entry for every caller in every session. Reading that verdict as a
         * refusal is what once disabled the default access class permanently. */
        if (!safeReachable(safe)) out.push({ label: "Unreachable", kind: "err" });
        if (p && !p._error && (p.warnings || []).length)
            out.push({ label: "Warnings (" + p.warnings.length + ")", kind: "warn" });
        if (p && !p._error && p.writable === false)
            out.push({ label: "Not writable", kind: "warn" });
        if (safe.mode === "ro") out.push({ label: "Read-only", kind: "warn" });
        if (safe.agent_enabled) out.push({ label: "Agent enabled", kind: "warn" });
        if (safe.needs_keyfile) out.push({ label: "Key file", kind: "" });
        if (safe.password_required === false) out.push({ label: "Keyed", kind: "" });
        return out;
    }

    function safeFormatText(safe) {
        var p = PROBES[safe.id];
        var fmt = (p && !p._error && p.format) || safe.format || "?";
        var ver = (p && !p._error && p.version) ? " " + p.version : "";
        return String(fmt) + ver;
    }
    function safeRegistryText(safe) {
        if (!safe.registry) return "";
        var label = safe.registry;
        var opts = (SCHEMA && SCHEMA.enums && SCHEMA.enums.registry_source) || [];
        opts.forEach(function (o) {
            if (o && String(o.value) === String(safe.registry)) label = o.label || label;
        });
        return String(label);
    }
    function safeKdfText(safe) {
        var p = PROBES[safe.id];
        if (!p || p._error) return "";
        var bits = [];
        if (p.kdf) bits.push(String(p.kdf));
        if (p.iterations) bits.push(p.iterations + " iterations");
        return bits.join(" · ");
    }
    function safeModifiedText(safe) {
        var p = PROBES[safe.id];
        var v = safe.modified !== undefined ? safe.modified
              : (p && !p._error ? p.modified : undefined);
        return v === undefined || v === null ? "" : fmtWhen(v);
    }
    function safeClassText(safe) { return isAdminClass(safe) ? "Administrator" : "Yours"; }

    /* The fixed order of the optional columns. It is fixed by design and NOT
     * by the order the operator ticked the boxes: a table whose columns move
     * under you is a table you have to re-read every time. */
    var SAFE_OPT_COLS = [
        { key: "path", label: "Path",
          hint: "Where each safe's file lives. Off by default.",
          value: function (s) { return s.path ? String(s.path) : ""; },
          mono: true },
        { key: "registry", label: "Registry",
          hint: "Who says this file is a safe — root-owned policy, or an entry you wrote.",
          value: safeRegistryText },
        { key: "kdf", label: "KDF",
          hint: "From the file header. Empty until the safe has been checked.",
          value: safeKdfText },
        { key: "modified", label: "Modified",
          hint: "When the file last changed.",
          value: safeModifiedText, num: true },
        { key: "id", label: "Id",
          hint: "The id on its own, so a large registry can be sorted by it.",
          value: function (s) { return String(s.id); }, mono: true }
    ];

    /* A column is OFFERED only when at least one currently visible row could
     * fill it. A helper that does not publish `modified` never shows a dead
     * checkbox, and nothing has to be special-cased for it. */
    function optColAvailable(col, rows) {
        if (col.key === "path") return rows.some(function (s) { return !!s.path; });
        if (col.key === "id") return rows.length > 0;
        return rows.some(function (s) { return !!col.value(s); });
    }

    function safeSortValue(safe, key) {
        switch (key) {
        case "class":  return isAdminClass(safe) ? "0" : "1";
        case "format": return safeFormatText(safe).toLowerCase();
        case "state":  {
            var st = safeStates(safe);
            /* Severity rank: the worst chip decides, and "nothing to say"
             * sorts last rather than first. */
            return st.length ? String(safeStates(safe).length ? 0 : 9) +
                               st[0].label.toLowerCase() : "9";
        }
        case "safe":   return String(safe.label || safe.id).toLowerCase();
        default: {
            var col = null;
            SAFE_OPT_COLS.forEach(function (c) { if (c.key === key) col = c; });
            return col ? String(col.value(safe)).toLowerCase() : "";
        }
        }
    }

    function sortSafes(rows) {
        var key = SAFESORT.key, desc = SAFESORT.desc;
        return rows.slice().sort(function (a, b) {
            var x = safeSortValue(a, key), y = safeSortValue(b, key);
            if (x !== y) return (x < y ? -1 : 1) * (desc ? -1 : 1);
            /* The stable tie-break is always the label, so two administrator
             * safes never swap places between renders. */
            var la = String(a.label || a.id).toLowerCase();
            var lb = String(b.label || b.id).toLowerCase();
            if (la === lb) return 0;
            return la < lb ? -1 : 1;
        });
    }

    /* ------------------------------------------------------------------ *
     * The empty / limited / broken states.
     *
     * One component so they read as a family; five instances, each
     * unmistakably itself. States 2 and 3 differ in THREE ways at once —
     * heading, glyph, and the presence or absence of buttons — because an
     * operator must never have to read carefully to tell "you cannot see them"
     * from "there are none".
     * ------------------------------------------------------------------ */
    function stateBlock(opts) {
        var box = el("div", "sec-state" + (opts.flush ? " flush" : ""));
        if (opts.glyph) box.appendChild(svgGlyph(opts.glyph, "glyph " + (opts.glyphKind || "")));
        if (opts.heading) box.appendChild(el("h3", null, opts.heading));
        (opts.body || []).forEach(function (p) {
            box.appendChild(typeof p === "string" ? el("p", null, p) : p);
        });
        return box;
    }

    /* ================================================================== *
     * The safes table (R2)
     * ================================================================== */
    function renderSafes() {
        var host = byId("sec-safes");
        clear(host);
        var banner = byId("sec-banners");
        clear(banner);
        var esc = escalationBanner();
        if (esc) banner.appendChild(esc);

        var rows = visibleSafes();
        var hidden = hiddenSafeCount();

        if (!SAFES.length) {
            /* STATE C — THE REGISTRY IS GENUINELY EMPTY, and the empty state
             * has to offer the way out of itself.
             *
             * This is the first thing a new operator sees, and until there was
             * a way to make a safe from the page it was a dead end with an
             * instruction to go and hand-write two files as root. The controls
             * that fix that belong HERE, above the explanation — an empty list
             * that hides the button for filling it is the worst place to hide
             * it. `.sec-empty` is kept as the wrapper: the suites select on it. */
            var empty = el("div", "sec-empty");
            var acts = el("div", "sec-tools");
            var offered = registryActions(acts);
            var where = registryDirs();
            var body = ["Make one, or register a safe file you already have."];
            var st = stateBlock({ glyph: "box", heading: "No safes are registered",
                                  body: body });
            if (offered) st.appendChild(acts);
            st.appendChild(el("p", "sec-subtle",
                "Safes are declared by the registry" +
                (where.system ? " in " + where.system : "") +
                "; `secrets-admin health` reports why an entry was dropped." +
                (offered ? "" :
                    " This helper publishes no verb for creating or importing one, so a " +
                    "safe still has to be registered on the host.")));
            empty.appendChild(st);
            host.appendChild(empty);
            renderPane();
            return;
        }

        if (!rows.length) {
            /* STATE B — NOTHING VISIBLE, BUT ADMIN SAFES EXIST. A full panel,
             * not a footnote: the region is otherwise empty and an empty region
             * needs an explanation.
             *
             * NO ACTION BUTTON. Measured on this host: a channel opened with
             * superuser:"require" is refused immediately with `access-denied`
             * and no dialog is drawn anywhere — Cockpit's escalation dialog
             * belongs to the shell and no package page can raise it. A button
             * that cannot work is worse than no button. */
            host.appendChild(stateBlock({
                glyph: "key", heading: "Nothing is visible while access is limited",
                body: [
                    hiddenSentence(hidden) +
                        " Turn on Administrative access with the “Limited access” " +
                        "control in the Cockpit header.",
                    "Hiding them is presentation only — the helper re-checks the access " +
                        "class on every operation, from the kernel's idea of who is calling."
                ]
            }));
            renderPane();
            return;
        }

        var wrap = el("div", "sec-tablewrap");
        var bar = el("div", "sec-toolbar");
        if (hidden) {
            /* STATE A — some visible, some hidden. ONE QUIET LINE. It is not
             * an alert and must not be styled as one: it is a true, unalarming
             * fact about a completely normal configuration, and a
             * warning-coloured box on every load of an unelevated session is
             * how a page teaches people to ignore its warnings. Count only. */
            bar.appendChild(el("p", "sec-hidden-note",
                hiddenSentence(hidden) +
                " Turn on Administrative access in the Cockpit header to see them."));
        } else {
            bar.appendChild(el("span", "sec-spacer"));
        }
        bar.appendChild(el("span", "sec-spacer"));
        columnChooser(bar, rows);
        wrap.appendChild(bar);

        var scroll = el("div", "sec-scroll");
        var t = el("table", "sec sec-safes-table");
        var cap = el("caption", null,
            rows.length + " safe" + (rows.length === 1 ? "" : "s"));
        t.appendChild(cap);

        var cols = [
            { key: "safe",   label: "Safe",   sortable: true },
            { key: "class",  label: "Class",  sortable: true },
            { key: "format", label: "Format", sortable: true },
            { key: "state",  label: "State",  sortable: true }
        ];
        SAFE_OPT_COLS.forEach(function (c) {
            if (COLS[c.key] && optColAvailable(c, rows)) cols.push(c);
        });

        var thead = el("thead"), htr = el("tr");
        cols.forEach(function (c) {
            var th = el("th");
            th.scope = "col";
            if (c.sortable === false) { th.textContent = c.label; htr.appendChild(th); return; }
            /* aria-sort is the ACCESSIBLE carrier and the glyph is the visual
             * one. Neither is colour. */
            th.setAttribute("aria-sort", SAFESORT.key === c.key
                ? (SAFESORT.desc ? "descending" : "ascending") : "none");
            var b = el("button", null, c.label);
            b.type = "button";
            if (SAFESORT.key === c.key) {
                var g = el("span", null, SAFESORT.desc ? " ▼" : " ▲");
                g.setAttribute("aria-hidden", "true");
                b.appendChild(g);
            }
            b.addEventListener("click", function () {
                if (SAFESORT.key === c.key) SAFESORT.desc = !SAFESORT.desc;
                else { SAFESORT.key = c.key; SAFESORT.desc = false; }
                renderSafes();
            });
            th.appendChild(b);
            htr.appendChild(th);
        });
        thead.appendChild(htr);
        t.appendChild(thead);

        var tb = el("tbody");
        sortSafes(rows).forEach(function (s) { tb.appendChild(safeRow(s, cols)); });
        t.appendChild(tb);
        scroll.appendChild(t);
        wrap.appendChild(scroll);
        host.appendChild(wrap);

        var tools = el("div", "sec-tools");
        /* Making a safe exist comes FIRST in this row, before the diagnostics.
         * It is the action an operator arrives wanting; health and the audit
         * log are what they reach for afterwards. */
        registryActions(tools);
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

        renderPane();
    }

    /* ------------------------------------------------------- the column chooser (R5) ---
     * A general chooser, not a one-off checkbox for Path — every optional
     * column is offered the same way and the mechanism does not care which one
     * anybody adds next.
     *
     * A <details> rather than a popup menu: it needs no focus trap, no
     * outside-click handler, no positioning maths and no aria-expanded
     * bookkeeping (the element carries all of that natively); it degrades
     * correctly with CSS off; and at 200% zoom it reflows instead of
     * overflowing a viewport. It pushes the table down when open, which is
     * honest and costs nothing.
     *
     * WHY PATH IS OFF BY DEFAULT — all three reasons, so nobody later "fixes" it:
     *   1. IT DISCLOSES. A path names a home directory and therefore an
     *      account, and it names the host's filesystem layout. This page gets
     *      screenshotted; the default view should not carry that.
     *   2. IT DOES NOT SCAN. It is by a wide margin the longest value in the
     *      row and the only one that must wrap. One Path column turns a
     *      four-line table into a twelve-line one.
     *   3. IT IS THE WRONG QUESTION AT THIS MOMENT. Choosing which safe to open
     *      is done by label, class and format. "Which file is this, exactly" is
     *      a question that arises when something is WRONG — which is exactly
     *      when the operator opens the details pane, where it always is.
     * And the counterweight, which is why it is not simply omitted: a safe you
     * cannot locate on disk is a safe you cannot back up, cannot repair and
     * cannot prove is the one you meant. It is ALWAYS in the pane, in full.
     */
    function columnChooser(host, rows) {
        var offered = SAFE_OPT_COLS.filter(function (c) { return optColAvailable(c, rows); });
        if (!offered.length) return;
        var on = offered.filter(function (c) { return COLS[c.key]; }).length;
        var d = el("details", "sec-columns");
        d.open = COLS_OPEN;
        d.addEventListener("toggle", function () { COLS_OPEN = d.open; });
        var sum = el("summary", null,
            "Columns" + (on ? " · " + on + " extra" : ""));
        d.appendChild(sum);
        /* Escape closes the disclosure and returns focus to the summary.
         * <details> does not do that natively and a keyboard user who opened it
         * would otherwise have to tab back out through every checkbox. */
        d.addEventListener("keydown", function (ev) {
            if (ev.key !== "Escape" || !d.open) return;
            ev.stopPropagation();
            d.open = false;
            sum.focus();
        });
        var fs = el("fieldset", "sec-radios");
        fs.appendChild(el("legend", null, "Optional columns"));
        var list = el("div", "sec-checklist");
        offered.forEach(function (c) {
            var lab = el("label", "sec-check");
            var cb = el("input");
            cb.type = "checkbox";
            cb.name = "col-" + c.key;
            cb.checked = !!COLS[c.key];
            cb.addEventListener("change", function () {
                COLS[c.key] = cb.checked;
                /* No Apply button: the table re-renders immediately, and the
                 * change is announced because a column appearing four rows
                 * below the control is not something a screen reader notices. */
                announce(c.label + " column " + (cb.checked ? "shown" : "hidden") + ".");
                renderSafes();
                var back = document.querySelector(
                    '.sec-columns input[name="col-' + c.key + '"]');
                if (back) back.focus();
            });
            lab.appendChild(cb);
            lab.appendChild(document.createTextNode(" " + c.label));
            if (c.hint) lab.appendChild(el("span", "hint", c.hint));
            list.appendChild(lab);
        });
        fs.appendChild(list);
        if (on) fs.appendChild(btn("Reset to defaults", "link", function () {
            SAFE_OPT_COLS.forEach(function (c) { COLS[c.key] = false; });
            announce("Optional columns reset.");
            renderSafes();
        }));
        d.appendChild(fs);
        host.appendChild(d);
    }

    /* One row. `.sec-safe` on the <tr> and `.sec-safe-id` on the id text are
     * kept from the old card markup on purpose: they are what the browser
     * suites address a safe by, in some fifty-five places, and they are a
     * better selector than anything that would replace them.
     *
     * NOTHING IN THE ROW IS AN ACTION. Every action lives in the pane, so
     * there is exactly one place a destructive control can be, exactly one
     * place its disabled/reason logic lives, and a row can never be a thing
     * you accidentally DO something to — a row is a thing you SELECT. */
    function safeRow(safe, cols) {
        var selected = PANE.safeId === safe.id;
        var tr = el("tr", "sec-safe clickable" +
                    (selected ? " selected" : "") +
                    (safeReachable(safe) ? "" : " unreachable"));
        cols.forEach(function (c, idx) {
            var td = el("td");
            if (idx === 0) {
                var b = el("button", "sec-rowdoor");
                b.type = "button";
                b.setAttribute("aria-current", selected ? "true" : "false");
                b.appendChild(el("span", "sec-safe-label", safe.label || safe.id));
                b.appendChild(el("span", "sec-safe-id", safe.id));
                b.addEventListener("click", function (ev) {
                    ev.stopPropagation();
                    selectSafe(safe.id);
                });
                /* Arrow keys move focus between rows; Home/End jump to the
                 * ends. This calls .focus() on a sibling — it does not change
                 * the tab count and it needs no roving tabindex, because a
                 * registry is a handful of rows and each one is an ordinary
                 * tab stop in DOM order. */
                b.addEventListener("keydown", rowArrowKeys);
                td.appendChild(b);
            } else if (c.key === "class") {
                td.appendChild(badge(safeClassText(safe), isAdminClass(safe) ? "warn" : ""));
            } else if (c.key === "format") {
                td.appendChild(badge(safeFormatText(safe), ""));
            } else if (c.key === "state") {
                var st = safeStates(safe);
                if (st.length) {
                    var chips = el("div", "sec-chips");
                    st.slice(0, 2).forEach(function (s) {
                        chips.appendChild(badge(s.label, s.kind));
                    });
                    if (st.length > 2)
                        chips.appendChild(btn("+" + (st.length - 2), "link tiny", function (ev) {
                            if (ev) ev.stopPropagation();
                            selectSafe(safe.id);
                        }));
                    td.appendChild(chips);
                }
                /* else: an EMPTY CELL, not a "Normal" chip. Nothing to say is
                 * not a state worth a word. */
            } else {
                var v = c.value ? c.value(safe) : "";
                if (c.num) td.className = "num";
                /* A class, not a style property. Anything that can be a class
                 * is a class: the stylesheet owns appearance and this file owns
                 * structure, and the only values that reach CSS from here are
                 * the two genuinely dynamic numbers (--sec-remain, --sec-depth). */
                if (c.mono && v) td.appendChild(el("span", "mono", v));
                else td.textContent = v;
            }
            tr.appendChild(td);
        });
        tr.addEventListener("click", function () { selectSafe(safe.id); });
        return tr;
    }

    /* Down/Up move focus to the next/previous row's door, Home/End to the
     * first/last. Enter and Space activate natively, because the door is a real
     * <button>. This calls .focus() on a sibling: it does not change the tab
     * count, so every row stays an ordinary tab stop in DOM order and no roving
     * tabindex is needed. */
    function rowArrowKeys(ev) { rowArrowKeysIn(ev, "tbody .sec-rowdoor"); }
    function entryArrowKeys(ev) {
        rowArrowKeysIn(ev, "tbody tr > td:first-child > button.sec-btn.link");
    }
    function rowArrowKeysIn(ev, sel) {
        var dirs = { ArrowDown: 1, ArrowUp: -1, Home: 0, End: 0 };
        if (!(ev.key in dirs)) return;
        var table = ev.currentTarget.closest("table");
        if (!table) return;
        var doors = Array.prototype.slice.call(table.querySelectorAll(sel));
        var i = doors.indexOf(ev.currentTarget);
        if (i < 0) return;
        var to;
        if (ev.key === "Home") to = 0;
        else if (ev.key === "End") to = doors.length - 1;
        else to = i + dirs[ev.key];
        if (to < 0 || to >= doors.length) return;
        ev.preventDefault();
        doors[to].focus();
    }

    /* ================================================================== *
     * The pane's four contents.
     * ================================================================== */
    function renderPane() {
        var body = paneBody(), head = paneHeading(), back = byId("sec-pane-back");
        if (!body || !head) return;
        clear(body);
        if (back) back.hidden = true;

        /* (c) A safe is OPEN. The pane becomes the entry detail, and the
         * safe's own identity lives in the compact strip above the entries
         * table. Two docked panes is not a design, it is a failure to choose:
         * with a safe open the thing an operator looks at over and over is the
         * entry, and it is the thing that most needs the width. The registry
         * detail stays one click away on #sec-pane-back. */
        if (SESSION && BROWSE) {
            if (back) back.hidden = (PANE.mode !== "entry");
            if (PANE.mode === "safe") {
                head.textContent = SESSION.safe.label || SESSION.safe.id;
                body.appendChild(paneSafeBody(SESSION.safe, { open: true }));
                return;
            }
            head.textContent = "Entry";
            var det = el("div", "sec-detail");
            det.id = "sec-detail";
            body.appendChild(det);
            /* Re-rendering the pane must not lose the entry that was in it —
             * this runs on an elevation change and on a view swap, neither of
             * which is a reason to blank what the operator was reading. */
            var sel = null;
            (BROWSE.rows || []).forEach(function (r) {
                if (r.uuid === BROWSE.selected) sel = r;
            });
            if (sel) renderDetail(sel);
            else det.appendChild(el("p", "sec-subtle",
                "Choose an entry from the table to see it here."));
            return;
        }

        var safe = PANE.safeId ? safeById(PANE.safeId) : null;
        if (safe && !safeIsVisible(safe)) safe = null;

        if (!safe) {
            /* (a) NOTHING SELECTED — the default on load. An empty pane that
             * teaches beats an empty pane that apologises, so the three facts
             * #sec-sub compresses into the topbar get a readable home here. */
            head.textContent = "No safe selected";
            var st = stateBlock({ flush: true, body: [
                "Choose a safe from the table to see its registry entry, its file header, " +
                "and what it will take to open it."
            ] });
            var dl = el("dl", "sec-kv");
            function kv(k, v) {
                dl.appendChild(el("dt", null, k));
                dl.appendChild(el("dd", null, v));
            }
            if (SCHEMA)
                kv("Helper", (SCHEMA.helper_version || SCHEMA.version || "?") + " · " +
                             Object.keys(verbTable()).length + " verbs");
            kv("Reveal window", fmtSeconds(uiNum("reveal_seconds", 15)));
            var where = registryDirs();
            var dirs = [];
            if (where.system) dirs.push(where.system);
            if (where.user) dirs.push(where.user);
            if (dirs.length) kv("Registry", dirs.join("  ·  "));
            st.appendChild(dl);
            body.appendChild(st);
            return;
        }

        head.textContent = safe.label || safe.id;
        body.appendChild(paneSafeBody(safe, {}));
    }

    /* (b) A safe is selected and locked — the normal state. And (d), the
     * unreachable one, which is the same content with the helper's own refusal
     * raised into an alert and the actions disabled. */
    function paneSafeBody(safe, opts) {
        opts = opts || {};
        var reachable = safeReachable(safe);
        var box = el("div");

        /* 1 · IDENTITY. The id in monospace beneath the label, then the two
         * chips that decide what an operation on this safe will need. */
        box.appendChild(el("div", "sec-safe-id", safe.id));
        var chips = el("div", "sec-safe-badges sec-chips");
        chips.appendChild(badge(safeClassText(safe), isAdminClass(safe) ? "warn" : ""));
        chips.appendChild(badge(safeFormatText(safe), ""));
        if (safeRegistryText(safe)) chips.appendChild(badge(safeRegistryText(safe), ""));
        safeStates(safe).forEach(function (s) { chips.appendChild(badge(s.label, s.kind)); });
        box.appendChild(chips);

        /* 2 · THE PATH — always, in full, wrapping, selectable, never
         * ~-abbreviated. A safe you cannot locate on disk is a safe you cannot
         * back up, cannot repair and cannot prove is the one you meant. */
        if (safe.path) {
            box.appendChild(el("h4", "sec-pane-section", "Path"));
            box.appendChild(el("code", "sec-path", String(safe.path)));
            var prow = el("div", "sec-actgroup");
            /* NOT a secret, so this must NOT arm the clipboard countdown —
             * see copyValue(). A chip that cries wolf teaches an operator to
             * ignore the one that matters. */
            prow.appendChild(btn("Copy path", "tiny", function (ev) {
                var b = ev && ev.currentTarget;
                copyValue(String(safe.path), { what: "The path" }).then(function () {
                    if (b) { b.textContent = "Copied"; window.setTimeout(function () {
                        b.textContent = "Copy path"; }, 2000); }
                }).catch(function (e) { alertBox(errNode(e)); });
            }));
            box.appendChild(prow);
            /* What the LOCATION means. THREE CASES, AND NEVER A GUESS: the
             * sentence is decided by the access class and the registry the
             * entry came from — the two facts that actually determine how the
             * helper opens the file — and not by pattern-matching a path.
             * Anything the helper has not told us about gets the path alone
             * and no editorial. */
            var kconst = (SCHEMA && SCHEMA.constants) || {};
            var sysSafes = kconst.safes_dir || kconst.system_safes_dir || null;
            var note = "";
            if (!isAdminClass(safe))
                note = "A safe of your own. The helper opens it running as you, with no " +
                       "escalation at all, and the file must be owned by you.";
            else if (String(safe.registry || "system") === "system" ||
                     (sysSafes && String(safe.path).indexOf(sysSafes) === 0))
                note = "Declared by the system registry and owned by root. Every operation " +
                       "on it is spawned with Cockpit's administrative access, and the " +
                       "helper refuses the verb unless it is running as root.";
            if (note) box.appendChild(el("p", "sec-subtle", note));
        }

        /* 3 · HEADER FACTS, from the probe. */
        var p = PROBES[safe.id];
        box.appendChild(el("h4", "sec-pane-section", "File header"));
        if (p && p._error) {
            box.appendChild(errNode(p._error));
        } else if (p) {
            var dl = el("dl", "sec-kv");
            function kv(k, v) {
                dl.appendChild(el("dt", null, k));
                dl.appendChild(el("dd", null, v));
            }
            kv("Format", safeFormatText(safe));
            if (p.kdf || p.iterations) {
                kv("KDF", safeKdfText(safe));
                /* The KDF value carries `.sec-safe-probe` — the class the
                 * browser suites wait on to know a probe has landed. It is on
                 * the value itself rather than on a second, duplicate summary
                 * line: the same facts printed twice, a centimetre apart, is
                 * how a panel stops being read. */
                dl.lastChild.className = "sec-safe-probe";
            }
            if (p.writable !== undefined) kv("Writable", p.writable === false ? "no" : "yes");
            if (p.needs_keyfile !== undefined)
                kv("Key file", p.needs_keyfile ? "required" : "not required");
            if (p.needs_password !== undefined)
                kv("Passphrase", p.needs_password === false ? "not required" : "required");
            box.appendChild(dl);
            /* 4 · WARNINGS, verbatim from the helper. The KDBX3 "this file is
             * not authenticated" banner (I20) reaches the operator this way,
             * worded by the code that knows why. */
            (p.warnings || []).forEach(function (w) {
                box.appendChild(el("div", "sec-alert warn", String(w)));
            });
        } else {
            box.appendChild(el("p", "sec-subtle", "The file header has not been read yet."));
        }

        /* (d) UNREACHABLE — the helper's own sentence as VISIBLE TEXT, not
         * only as a title. A title is invisible to touch, to most screen
         * readers in browse mode, and to anyone who does not hover. */
        if (safe.reason)
            box.appendChild(el("div", reachable ? "sec-subtle" : "sec-alert err",
                               String(safe.reason)));

        box.appendChild(safeActions(safe, opts));
        return box;
    }

    /* THE CONSEQUENCE LADDER, laid out (§7.2).
     *
     *   [ Unlock… ]                          primary, alone on its row
     *   [ Backups… ] [ Check this safe ]     rung 0
     *   ───────────────────────────────      a real rule
     *   Destructive                          an eyebrow
     *   [ Export… ] [ Forget… ] [ Delete… ]  role="group"
     *
     * Both carriers at once: a visible rule and eyebrow for sighted operators,
     * a labelled role="group" for assistive technology. Rung 2 and 3 controls
     * are never adjacent to rung 0 or 1 controls, and no filled red button
     * appears anywhere. */
    function safeActions(safe, opts) {
        var reachable = safeReachable(safe);
        var acts = el("div", "sec-safe-actions");

        var primary = el("div", "sec-actgroup");
        if (!opts.open) {
            var open = btn("Unlock…", "primary", function () { unlockDialog(safe); });
            if (!reachable) {
                open.disabled = true;
                open.title = String(safe.reason || "");
            }
            primary.appendChild(open);
        }
        acts.appendChild(primary);

        var read = el("div", "sec-actgroup");
        /* The backup ring is readable without unlocking anything: it is a list
         * of files, not of secrets, and the moment an operator needs it is
         * usually the moment the safe will not open. */
        if (reachable && verbFor("backups"))
            read.appendChild(btn("Backups…", "", function () { backupsDialog(safe); }));
        /* NOT gated on `reachable`, and not gated on there being no probe yet.
         * The only state this control exists for is the one in which an
         * unescalated list reports an admin safe unusable; gating it on either
         * removed it exactly when it was needed, and cancelling Cockpit's
         * prompt used to make it disappear forever because an error is a probe.
         *
         * NOTE, and it is a real consequence of R1: while administrative
         * access is off, an admin-class safe is not listed at all, so this
         * control cannot be reached in the state it was built for. The count
         * note and the escalation banner are what an operator sees instead. */
        var p = PROBES[safe.id];
        if (isAdminClass(safe) && (!p || p._error)) {
            var again = !!(p && p._error);
            var chk = btn(again ? "Check again" : "Check this safe", "", function () {
                probeSafe(safe, true);
            });
            chk.title = adminAllowed()
                ? "Opens nothing. Asks the helper, with this session's administrative " +
                  "access, whether the safe is readable and what is in its header."
                : "Opens nothing, and does not ask you for a password — Cockpit only does " +
                  "that from the “Limited access” control in its header. This reports what " +
                  "the helper says while administrative access is off.";
            read.appendChild(chk);
        }
        if (read.childNodes.length) acts.appendChild(read);

        /* The destructive group. Export is rung 2 (durable disclosure), Delete
         * is rung 3 (irreversible), and Forget is deliberately NOT on the
         * ladder at all — it is reversible, so it wears a default button. A
         * reversible action in the irreversible costume is how the costume
         * stops meaning anything. */
        var dgroup = el("div", "sec-actgroup destructive");
        dgroup.setAttribute("role", "group");
        dgroup.setAttribute("aria-label", "Destructive actions");
        if (reachable && exportAllowed(safe))
            dgroup.appendChild(btn("Export…", "danger", function () { exportDialog(safe); }));
        if (verbFor("safeForget"))
            dgroup.appendChild(btn("Forget…", "", function () { forgetDialog(safe); }));
        if (verbFor("safeDelete"))
            dgroup.appendChild(btn("Delete…", "danger", function () { deleteDialog(safe); }));
        if (dgroup.childNodes.length) {
            acts.appendChild(el("hr", "sec-actsplit"));
            acts.appendChild(el("p", "sec-eyebrow", "Destructive"));
            acts.appendChild(dgroup);
            if (verbFor("safeForget"))
                acts.appendChild(el("p", "sec-actnote",
                    "Forget removes the registry entry only. The file and its backups stay " +
                    "where they are, and registering it again brings it back."));
        }
        return acts;
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
        /* A refusal is not a description of the file, and neither is an answer
         * obtained below the privilege this safe's questions need. Both are
         * dropped here rather than shaping the form: needsPassword() and
         * needsKeyfile() fall back to the registry row, which says "yes, ask"
         * — the restrictive answer and the point of the program. */
        if (probe && (probe._error || staleForClass(probe, safe))) probe = null;
        var admin = isAdminClass(safe);
        var yk = yubikeyState(safe, probe);
        var ykField = yubikeyField();
        var ykVerb = verbFor("yubikey");

        modal("Unlock " + (safe.label || safe.id), function (box, m) {
            var intro = el("p", "sec-modal-intro");
            intro.textContent = admin
                ? (adminAllowed()
                    ? "Administrator safe. This session already has Cockpit's administrative " +
                      "access, so the unlock is spawned with it; the helper refuses this verb " +
                      "unless it is running as root."
                    : "Administrator safe, and administrative access is OFF in this Cockpit " +
                      "session. Turn it on with the “Limited access” control in the Cockpit " +
                      "header first — from here the unlock is refused straight away, without " +
                      "a prompt, and the helper refuses this verb unless it is running as root.")
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
    /* THE FOURTH DEADLINE, and it gets the same treatment as the other three
     * (reveal, clipboard, upload): tabular numerals as the text carrier, a
     * single-hue bar as the second carrier, the geometry set through ONE custom
     * property, and the last five seconds in the danger colour with the numeral
     * still saying it. Four deadlines that look like four different things is
     * four things to learn. */
    function lockoutCountdown(host, seconds) {
        var line = el("div", "sec-countdown");
        var meter = el("div", "sec-meter");
        meter.appendChild(el("span"));
        meter.setAttribute("aria-hidden", "true");
        host.appendChild(line);
        host.appendChild(meter);
        var total = Math.max(1, Number(seconds) || 1);
        var deadline = Date.now() + total * 1000;
        meter.style.setProperty("--sec-remain", "100%");
        var t = window.setInterval(function () {
            var left = Math.ceil((deadline - Date.now()) / 1000);
            if (left <= 0) {
                window.clearInterval(t);
                line.className = "sec-countdown";
                line.textContent = "You can try again now.";
                meter.hidden = true;
                /* It must not re-enable SILENTLY: the sentence is said once,
                 * politely, so an operator who looked away is told. */
                announce("The lockout has expired. You can try again now.");
                return;
            }
            meter.style.setProperty("--sec-remain",
                Math.max(0, Math.min(100, (left / total) * 100)) + "%");
            var urgent = left <= 5;
            line.className = "sec-countdown" + (urgent ? " urgent" : "");
            meter.className = "sec-meter" + (urgent ? " urgent" : "");
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
        /* The pane's content stack goes back to the safe it was showing. The
         * pane's DISPOSITION is untouched: the view changed under the operator
         * but they did not ask for the pane to move, and collapsing one out
         * from under a keyboard user sends focus somewhere they did not ask
         * for. */
        PANE.mode = "safe";
        PANE.safeId = lockedSafeId;
        renderSafes();
        /* The view changed under the operator, so land them at the top of the
         * new one rather than wherever the old one's DOM used to be. Never on
         * <body>: that loses their place entirely. */
        var door = document.querySelector("#sec-safes tbody .sec-rowdoor");
        if (door) door.focus();
        else if (byId("sec-main")) byId("sec-main").focus();
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

        /* The pane becomes the ENTRY detail from here on. The safe's own
         * registry detail is one click away on #sec-pane-back, which swaps the
         * content back WITHOUT deselecting the entry. */
        PANE.safeId = BROWSE.safe.id;
        PANE.mode = "entry";
        if (!PANE.open) setPaneOpen(true);
        renderPane();

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

    /* The groups tree is a column at >= 60rem and a disclosure below it. The
     * summary is hidden by CSS at the wide size, so `open` is forced there —
     * a hidden summary on a closed <details> would hide the tree entirely.
     * Below it, the summary names the group in play, because a collapsed
     * disclosure that does not say what it is filtering by is a filter an
     * operator forgets is on. */
    function syncTreeDisclosure() {
        var d = byId("sec-treewrap");
        if (!d) return;
        var wide = frameIsWide();
        if (wide) d.open = true;
        var sum = byId("sec-treewrap-sum");
        if (!sum) return;
        var name = "";
        if (BROWSE && BROWSE.group)
            (BROWSE.groups || []).forEach(function (g) {
                if (g.uuid === BROWSE.group) name = String(g.name || g.uuid);
            });
        sum.textContent = "Groups" + (name ? " · " + name : " · All entries");
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
            syncTreeDisclosure();
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
                /* ONE custom property, not a built style string. The STEP
                 * lives in secrets.css on the spacing scale
                 * (`calc(var(--sec-s-1) + var(--sec-depth) * var(--sec-s-2))`),
                 * so the geometry is in the stylesheet where it belongs and
                 * nothing here assembles CSS text. */
                b.style.setProperty("--sec-depth", String(depth));
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
    /* Is this entry past its expiry? The helper decides whenever it says so —
     * a boolean `expired` is taken verbatim. Otherwise a date-shaped `expires`
     * or `expiry` is compared with now, and anything unparseable is NOT
     * treated as expired: marking an entry expired because a field did not
     * parse would be this page inventing a fact, which is the one thing it may
     * not do. */
    function entryExpired(row) {
        if (!row) return false;
        if (typeof row.expired === "boolean") return row.expired;
        var v = row.expires !== undefined ? row.expires : row.expiry;
        if (v === undefined || v === null || v === "") return false;
        var t = Date.parse(String(v));
        if (isNaN(t)) return false;
        return t < Date.now();
    }

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
                    /* AN EXPIRED ENTRY — three carriers, never colour alone: a
                     * decorative glyph BEFORE the title, the WORD "Expired" in
                     * a chip after it, and the same word in the button's
                     * accessible name. Never strikethrough: struck-through text
                     * is unreadable at 14px and it reads as DELETED, which an
                     * expired entry is not.
                     *
                     * The glyph and the chip are in the CELL and not inside the
                     * button, deliberately: the live suite addresses an entry
                     * by `button.sec-btn.link:text-is("<title>")` in fourteen
                     * places, so the button's text content has to stay exactly
                     * the title. That constraint is also why this stays a
                     * `.sec-btn.link` rather than becoming a `.sec-rowdoor`. */
                    var expired = entryExpired(r);
                    if (expired) {
                        var g = el("span", null, "⚠ ");
                        g.setAttribute("aria-hidden", "true");
                        td.appendChild(g);
                    }
                    /* The keyboard door into the entry. */
                    var b = el("button", "sec-btn link", txt(v) || "(untitled)");
                    b.type = "button";
                    b.setAttribute("aria-current",
                                   BROWSE.selected === r.uuid ? "true" : "false");
                    if (expired)
                        b.setAttribute("aria-label", (txt(v) || "(untitled)") + ", expired");
                    b.addEventListener("click", function (ev) {
                        ev.stopPropagation();
                        selectEntry(r);
                    });
                    /* Arrow keys move between rows here exactly as they do in
                     * the safes table — one row idiom across both. */
                    b.addEventListener("keydown", entryArrowKeys);
                    td.appendChild(b);
                    if (expired) td.appendChild(badge("Expired", "warn"));
                } else if (typeof v === "boolean") {
                    /* A tick plus a hidden word for true, and AN EMPTY CELL for
                     * false. `badge("yes")`/`badge("no")` spent a whole chip on
                     * a boolean and filled the table with the word "no", which
                     * is the least informative thing a cell can contain. */
                    if (v) {
                        var tick = el("span", null, "✓");
                        tick.setAttribute("aria-hidden", "true");
                        td.appendChild(tick);
                        td.appendChild(el("span", "sec-visually-hidden", c.label));
                    }
                } else if (c.name === "username") {
                    /* JUDGEMENT CALL, stated: a username is COMPARED, not read.
                     * `admin1` beside `admin l` is a difference an operator has
                     * to be able to see at a glance, and a proportional face
                     * hides exactly that. It is not a secret: no well, no
                     * countdown, no mask. */
                    td.appendChild(el("span", "mono", txt(v)));
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
        if (BROWSE.selected && byId("sec-detail")) {
            /* …and only while the pane is actually SHOWING the entry detail.
             * If the operator has swapped it to the safe's registry entry with
             * "← Safe details", a background re-render must not drag them back
             * — that is the one thing that control exists to let them avoid.
             * byId("sec-detail") is the test: the host only exists in entry
             * mode. */
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
        /* The entry detail lives in the docked pane (R3). Selecting an entry
         * while the pane is showing the safe's registry detail swaps it back —
         * the operator asked to look at an entry. */
        PANE.mode = "entry";
        if (!PANE.open) setPaneOpen(true);
        renderEntries();
        renderDetail(row);
    }

    /* #sec-detail is the entry-detail host and it lives INSIDE #sec-pane-body,
     * created by renderPane(). It is addressed by id — and kept under that id —
     * because that is what the browser suites wait on, thirty-odd times, and a
     * rename would buy nothing. If the pane is currently showing something
     * else, asking for the host is what switches it. */
    function detailHost() {
        var h = byId("sec-detail");
        if (h) return h;
        PANE.mode = "entry";
        if (!PANE.open) setPaneOpen(true);
        renderPane();
        return byId("sec-detail");
    }

    function renderDetail(row) {
        var host = detailHost();
        if (!host) return;
        clear(host);
        host.appendChild(el("h3", null, txt(row.title) || "(untitled)"));

        /* Metadata the helper already sent. No value is in here by contract.
         *
         * The custom-field keys are skipped here and get their own section
         * below, and that is a defence as well as a layout choice. This loop
         * prints whatever the helper sent, and a row that carried
         * `[{name, value}]` would print the value as data — no mask, no
         * countdown, no re-hide, which is exactly what I17 exists to stop.
         * Below, the same list is drawn by NAME with a reveal control beside
         * each one, so the only way to see a custom value is still the audited
         * `reveal` call every other value goes through. */
        var dl = el("dl", "sec-kv");
        Object.keys(row).forEach(function (k) {
            if (k === "title" || k === "uuid") return;
            if (CUSTOM_ROW_KEYS[k]) return;
            /* This page's own bookkeeping, parked on the row object because
             * that is the thing loadEntries() replaces: the attach-list reply,
             * whether it has been asked for, and the last error. None of it
             * came from the helper, and this panel is "what the helper said". */
            if (k.charAt(0) === "_" || k === "attachment_names") return;
            dl.appendChild(el("dt", null, k.replace(/_/g, " ")));
            var dd = el("dd");
            var v = row[k];
            if (typeof v === "boolean") {
                /* A tick and a hidden word for true, nothing at all for false.
                 * `yes`/`no` chips spend a whole mark on a boolean and fill the
                 * panel with the word "no". */
                if (v) {
                    var tk = el("span", null, "✓");
                    tk.setAttribute("aria-hidden", "true");
                    dd.appendChild(tk);
                    dd.appendChild(el("span", "sec-visually-hidden", "yes"));
                } else {
                    dd.appendChild(el("span", "sec-visually-hidden", "no"));
                }
            } else if (k === "url" && txt(v)) {
                /* A URL INSIDE A SAFE IS ATTACKER-CONTROLLED DATA (threat model
                 * A3, "a malicious or corrupted safe file"). Rendering it as an
                 * anchor would let a safe's contents navigate the operator's
                 * browser on one mis-click, so it is presented as TEXT, in the
                 * code idiom, with a copy control — and the operator decides.
                 * This is a security decision wearing layout clothes. */
                dd.appendChild(el("code", "sec-path", txt(v)));
                dd.appendChild(btn("Copy", "tiny", function (ev) {
                    var b = ev && ev.currentTarget;
                    copyValue(txt(v), { what: "The URL" }).then(function () {
                        if (b) { b.textContent = "Copied"; window.setTimeout(function () {
                            b.textContent = "Copy"; }, 2000); }
                    }).catch(function () { /* best effort */ });
                }));
            } else if (txt(v).split("\n").length > 8) {
                /* A long multi-line value is CLAMPED, not scrolled. A scroll box
                 * inside a pane inside a page is three nested scrolls and the
                 * middle one is always the one the wheel does not reach.
                 *
                 * Note which values reach this branch: only ones the helper put
                 * in the entries[] row, which is metadata by contract. Anything
                 * in revealFields() is a protected value and goes through
                 * revealWidget with its own well and countdown; it never gets
                 * here and this clamp does not apply to it. */
                var lines = txt(v).split("\n");
                var pre = el("div", "sec-pre", lines.slice(0, 8).join("\n"));
                dd.appendChild(pre);
                dd.appendChild(btn("Show the whole " + k.replace(/_/g, " ") +
                                   " (" + lines.length + " lines)", "link",
                    function (ev) {
                        pre.textContent = txt(v);
                        if (ev && ev.currentTarget && ev.currentTarget.parentNode)
                            ev.currentTarget.parentNode.removeChild(ev.currentTarget);
                    }));
            } else {
                dd.textContent = txt(v);
            }
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
            var custom = customFieldRows(row);
            var saidUnprotected = false;
            if (custom.length) {
                host.appendChild(el("h4", null, "Custom fields"));
                custom.forEach(function (cf) {
                    var w = revealWidget({
                        label: cf.name,
                        fetch: function () {
                            return SESSION.call("reveal",
                                { uuid: row.uuid, field: "custom:" + cf.name });
                        }
                    });
                    /* Protected / not protected is a fact about how the FILE
                     * stores the value, and it is the difference between a
                     * field an export carries in the clear and one it does
                     * not. It is metadata, so it is shown; the value still is
                     * not. revealWidget() returns its node directly, so the
                     * badge goes into that node's own head row. */
                    var cfHead = w.querySelector(".sec-reveal-head");
                    var label = cfHead && cfHead.querySelector(".sec-reveal-label");
                    /* The chip QUALIFIES the name, so it reads BEFORE it, and it
                     * carries a filled or hollow dot as well as the word — the
                     * difference between an exported field that is in the clear
                     * and one that is not should not rest on a colour. */
                    if (cfHead && cf.protected === true) {
                        var okChip = badge("● protected", "ok");
                        cfHead.insertBefore(okChip, label || cfHead.firstChild);
                    } else if (cfHead && cf.protected === false) {
                        var noChip = badge("○ not protected", "warn");
                        cfHead.insertBefore(noChip, label || cfHead.firstChild);
                    }
                    host.appendChild(w);
                    /* ONCE PER ENTRY, under the first unprotected field — not
                     * once per field. Repeating a warning on every row is how a
                     * warning becomes wallpaper. */
                    if (cf.protected === false && !saidUnprotected) {
                        saidUnprotected = true;
                        host.appendChild(el("div", "hint",
                            "A field that is not protected is stored in the clear inside the " +
                            "file. Anyone holding the file can read it without the passphrase, " +
                            "and an export carries it as it stands."));
                    }
                });
            }
            if (revealFields().length)
                host.appendChild(btn("Reveal a custom field…", "tiny", function () {
                    customFieldDialog(row);
                }));
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
        /* THE SAME LADDER AS THE SAFE'S OWN ACTIONS. Rung 2 and 3 controls are
         * never adjacent to rung 0 controls: the destructive ones sit after a
         * visible rule, under an eyebrow, inside a labelled role="group", so
         * the separation is carried for sighted operators and for assistive
         * technology at once. */
        host.appendChild(el("h4", null, "Actions"));
        var acts = el("div", "sec-tools");
        var dangerActs = el("div", "sec-actgroup destructive");
        dangerActs.setAttribute("role", "group");
        dangerActs.setAttribute("aria-label", "Destructive actions");
        function entryBtn(name, into) {
            var spec = verbSpec(name) || {};
            var b = btn(verbLabel(name), (spec.danger ? "danger " : "") + "tiny", function () {
                verbDialog(name, { uuid: row.uuid }, afterMutation, row);
            });
            if (!BROWSE.writable) { b.disabled = true; b.title = "This safe is open read-only."; }
            into.appendChild(b);
        }
        ["edit", "move", "rm"].forEach(function (v) {
            if (!hasVerb(v)) return;
            entryBtn(v, (verbSpec(v) || {}).danger ? dangerActs : acts);
        });
        Object.keys(verbTable()).sort().forEach(function (name) {
            if (isHandled(name)) return;
            if (verbScope(name) !== "entry") return;
            entryBtn(name, (verbSpec(name) || {}).danger ? dangerActs : acts);
        });
        if (acts.childNodes.length) host.appendChild(acts);
        if (dangerActs.childNodes.length) {
            host.appendChild(el("hr", "sec-actsplit"));
            host.appendChild(el("p", "sec-eyebrow", "Destructive"));
            host.appendChild(dangerActs);
        }
    }

    /* The keys an entries[] row might use to name its custom fields.
     *
     * docs/CONTRACT.md pins the row's other keys but not this one, so — the
     * same rule as attachments — several spellings are accepted and none is
     * demanded. A row that uses none of them simply has no custom-field
     * section, and the "Reveal a custom field…" dialog is the way in.
     *
     * These keys are also excluded from the raw metadata dump in renderDetail:
     * see the comment there. */
    var CUSTOM_ROW_KEYS = {
        "custom": 1, "custom_fields": 1, "customFields": 1, "custom_strings": 1,
        "customStrings": 1, "custom_field_names": 1, "strings": 1, "attributes": 1
    };

    /* One entry's custom fields as [{name, protected}] — NEVER a value.
     *
     * `entries()` publishes names and never values, by contract, and this
     * function keeps that true whatever shape the helper chose: a bare list of
     * names, a list of {name, protected} objects, or a map. If a row ever did
     * arrive carrying values, the value is dropped HERE rather than rendered:
     * a custom value reaches the screen through `reveal`, with its countdown
     * and its audit line, or it does not reach the screen. */
    function customFieldRows(row) {
        var raw = null;
        Object.keys(CUSTOM_ROW_KEYS).forEach(function (k) {
            if (raw === null && row && row[k] !== undefined && row[k] !== null) raw = row[k];
        });
        if (raw === null) return [];
        var out = [];
        function push(name, prot) {
            var n = String(name === undefined || name === null ? "" : name);
            if (!n || n === "undefined") return;
            out.push({ name: n, protected: (prot === true || prot === false) ? prot : undefined });
        }
        if (Array.isArray(raw)) {
            raw.forEach(function (c) {
                if (c && typeof c === "object")
                    push(c.name !== undefined ? c.name : c.key,
                         c.protected !== undefined ? c.protected : c.is_protected);
                else push(c, undefined);
            });
        } else if (typeof raw === "object") {
            Object.keys(raw).forEach(function (n) {
                var v = raw[n];
                push(n, (v && typeof v === "object")
                        ? (v.protected !== undefined ? v.protected : v.is_protected)
                        : undefined);
            });
        }
        return out;
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
        /* `attachment_names` is where an attach-list reply is parked: the
         * listing row's own `attachments` is the helper's and is not
         * overwritten, so a re-listing that fails leaves the count intact. */
        var named = Array.isArray(row.attachment_names) ? row.attachment_names : null;
        if (!named && Array.isArray(raw)) named = raw;
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

    /* Whatever the attach-list verb answered, as [{name, size}].
     *
     * The Backend ABC pins the backend method's return — a list of
     * {name, size}, in the order the file stores them, and NO bytes — but the
     * verb is free to wrap it in whichever key it likes, so the wrappers a
     * reasonable helper might choose are all unwrapped and none is demanded.
     * A reply carrying bytes is not a shape this page renders: `b64` is
     * `attach-get`'s answer, and it is dropped here rather than passed on. */
    function attachListRows(res) {
        var raw = null;
        if (Array.isArray(res)) raw = res;
        else if (res && typeof res === "object")
            ["attachments", "names", "files", "rows", "entries", "list"]
                .forEach(function (k) {
                    if (raw === null && Array.isArray(res[k])) raw = res[k];
                });
        if (!Array.isArray(raw)) return null;
        return raw.map(function (a) {
            if (a && typeof a === "object")
                return { name: String(a.name === undefined ? a.filename : a.name),
                         size: (a.size !== undefined ? a.size : a.bytes) };
            return { name: String(a), size: undefined };
        }).filter(function (a) { return a.name && a.name !== "undefined"; });
    }

    /* Ask the helper for this entry's attachment names.
     *
     * `entries()` reports `attachments` as a COUNT on purpose — a listing must
     * show that an entry HAS attachments without shipping them — and
     * `attach-get` takes a NAME. Those two together leave a file that can be
     * uploaded and never fetched again, which is the gap this verb closes, so
     * the page asks for the names ONCE per selected entry rather than making
     * the operator find a button first. It is metadata: names and sizes, no
     * bytes, one audited call.
     *
     * `_attachAsked` is per ROW OBJECT, and loadEntries() replaces those
     * objects wholesale, so a refresh re-asks. That is deliberate: a cached
     * name list that survived an attach-add would be a list missing the file
     * that was just added. */
    function fetchAttachmentNames(row, onDone) {
        var lister = verbFor("attachList");
        if (!lister || !SESSION) { if (onDone) onDone(null); return; }
        SESSION.call(lister, { uuid: row.uuid }).then(function (res) {
            var rows = attachListRows(res);
            if (rows) row.attachment_names = rows;
            row._attachError = null;
            if (onDone) onDone(rows);
            /* Only redraw the pane if this entry is still the selected one:
             * an answer that arrives after the operator has moved on must not
             * yank the pane back to the previous entry. */
            if (BROWSE && BROWSE.selected === row.uuid) renderDetail(row);
        }).catch(function (e) {
            row._attachError = e;
            if (onDone) onDone(null);
            if (BROWSE && BROWSE.selected === row.uuid) renderDetail(row);
            handleSessionError(e);
        });
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
        if (!info.count && !adder && !lister && !hasVerb("attach-get")) return;

        host.appendChild(el("h4", null, "Attachments"));

        /* The last attempt at the listing, if it failed. Shown rather than
         * swallowed: "this entry has three attachments and here is why you
         * cannot see what they are called" is an operator's problem to solve,
         * and a silent empty list looks like an entry with no files. */
        if (row._attachError) host.appendChild(errNode(row._attachError));

        if (!info.count && info.known) {
            host.appendChild(el("p", "sec-subtle", "None."));
        } else if (!info.known && info.count) {
            /* A count with no names. The listing verb is what turns that into
             * something addressable — `attach-get` takes a NAME and a count is
             * not one — so it is asked automatically, once, the first time this
             * entry is drawn. Without it a file can be uploaded and never
             * fetched again from a page that never learned what it is called.
             *
             * When the helper publishes no such verb, say so plainly rather
             * than guessing a name. */
            host.appendChild(el("p", "sec-subtle",
                info.count + " attachment(s) on this entry."));
            if (lister) {
                if (!row._attachAsked && !row._attachError) {
                    row._attachAsked = true;
                    host.appendChild(el("p", "sec-subtle", "Asking the helper for their names…"));
                    fetchAttachmentNames(row);
                }
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

        /* The listing on demand, whatever state the section is in.
         *
         * It is drawn even when the names are already known, because "known"
         * only means "known as of the last entries call". An upload made from
         * another Cockpit tab, or a name list this page fetched before an
         * attach-rm, is stale in the direction that matters: the operator
         * presses Download on a file that is no longer there. One button, one
         * label, whether it is the first listing or the fourth. */
        if (lister) {
            host.appendChild(btn("List attachments", "tiny", function () {
                row._attachAsked = true;
                row._attachError = null;
                fetchAttachmentNames(row);
            }));
            host.appendChild(el("div", "hint",
                "Names and sizes only — the bytes come back one file at a time through " +
                "Download, which is a separate audited call."));
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

    /* The safe a request is actually about, as opposed to the one the page knew
     * about when it opened the dialog.
     *
     * Same family of bug as the escalation one: a decision taken at one moment
     * and reused at another where it is no longer the same question. A generic
     * dialog for a safe-scoped verb draws the `safe` control from
     * `options_from: "list.safes"` and the operator picks the safe INSIDE it —
     * so an escalation decided when the dialog opened was decided before there
     * was a safe to decide about. Deciding it from the request, at submit time,
     * is deciding it from the thing that is actually being asked.
     *
     * Getting it wrong costs an access-denied that reads as "you are not
     * allowed" when the truth is "you were never asked for administrative
     * access" — which is precisely the sentence the escalation bug put on every
     * admin card. */
    function safeForRequest(req, presets, opts) {
        if (opts && opts.safe) return opts.safe;
        var id = (req && req.safe) || (presets && presets.safe);
        var known = id ? safeSpecById(String(id)) : null;
        if (known) return known;
        /* An id the list does not know is still an id, and a registry entry
         * with no `access` key is admin (I1) — so an unknown one is treated as
         * admin rather than as user. Guessing the permissive class is the
         * mistake this file refuses everywhere. */
        if (id) return { id: String(id), access: "admin" };
        return null;
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
     *   typeToConfirm {expect, label, help} — a text box whose contents must
     *               equal `expect` before Run enables. AND-ed with every tick
     *               box, never instead of one. It exists for exactly one class
     *               of action: the ones where a mis-click destroys a file
     *               (safe-delete). A tick box is one gesture and a wrong tick
     *               is one gesture; typing an id is a gesture that cannot be
     *               made by accident against the WRONG safe, which is the
     *               failure this guards
     *   adminFrom   a callback (req) -> bool deciding the escalation from the
     *               REQUEST, for a verb whose class is not carried by a `safe`
     *               field at all. `safe-create` is the case: its access class
     *               is a value in its own request, and admin is the default
     *               when it is absent (I1), so the escalation has to be read
     *               from what was actually filled in
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
            /* Every gate is a function answering "may Run be pressed yet".
             * They are AND-ed and re-evaluated together, so adding a kind of
             * gate cannot accidentally replace an existing one. */
            var gates = [];
            function regate() {
                go.disabled = gates.some(function (g) { return !g(); });
            }
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
                gates.push(function () { return cb.checked; });
                cb.addEventListener("change", regate);
            });

            /* Type-the-name gate. The comparison is EXACT — no trimming, no
             * case folding — because the thing being typed is a registry id,
             * the ids are lower-case by construction, and a gate that accepts
             * “Lab-DC ” for “lab-dc” is a gate that accepts the operator not
             * having read what they typed. */
            if (opts.typeToConfirm && opts.typeToConfirm.expect) {
                var want = String(opts.typeToConfirm.expect);
                var tid = "sec-type" + (++CTRL_SEQ);
                var tw = el("div", "sec-field");
                var tl = el("label", null,
                    opts.typeToConfirm.label || ("Type “" + want + "” to confirm"));
                tl.setAttribute("for", tid);
                if (opts.typeToConfirm.help)
                    tl.appendChild(el("span", "hint", String(opts.typeToConfirm.help)));
                tw.appendChild(tl);
                var ti = el("input");
                ti.type = "text";
                ti.id = tid;
                /* Same four attributes as a passphrase box, for a different
                 * reason: an autofilled or autocorrected id would sail through
                 * a gate whose entire purpose is deliberate typing. No `name`
                 * anywhere on this page (I11). */
                ti.setAttribute("autocomplete", "off");
                ti.setAttribute("spellcheck", "false");
                ti.setAttribute("autocapitalize", "none");
                ti.setAttribute("autocorrect", "off");
                tw.appendChild(ti);
                var tmsg = el("div", "sec-countdown");
                tmsg.setAttribute("aria-live", "polite");
                tw.appendChild(tmsg);
                box.appendChild(tw);
                gates.push(function () { return ti.value === want; });
                ti.addEventListener("input", function () {
                    tmsg.textContent = ti.value === want
                        ? "That is the id. The action below is now available."
                        : (ti.value ? "That is not the id of the safe named above." : "");
                    regate();
                });
            }

            var errHost = el("div");
            box.appendChild(errHost);

            var go = btn(opts.runLabel || "Run", spec.danger ? "danger" : "primary", submit);
            if (gates.length) go.disabled = true;
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

                /* Escalation from the safe THIS REQUEST names — see
                 * safeForRequest(). opts.safe still wins when the caller named
                 * one, because export and restore are reached from the list
                 * with nothing open and know exactly which safe they mean. */
                /* `adminFrom` is for a verb whose access class lives in the
                 * request rather than in a registry row this page can look up
                 * — creating a safe that does not exist yet. It is read at
                 * SUBMIT time, from the request actually being sent, for the
                 * same reason safeForRequest() is: a decision taken when the
                 * dialog opened was taken before there was anything to decide
                 * about. */
                var admin = opts.adminFrom
                    ? !!opts.adminFrom(req)
                    : adminForVerb(name, safeForRequest(req, presets, opts));
                var p = needsSession(name)
                    ? (SESSION ? SESSION.call(name, req)
                               : Promise.reject(mkErr("access-denied", "The safe is locked.")))
                    : callOnce(name, req, admin, argv);

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
                    /* WHICH LOG THIS IS. Measured: audit-tail answers from the
                     * caller's own log, so the same verb run as the operator
                     * and as root returns two different files — and a page that
                     * printed either without saying which would let an operator
                     * conclude "nothing has been done to this safe" from a log
                     * that simply is not the one the admin verbs write to.
                     *
                     * The escalation is read at the moment of the call, never
                     * cached: adminAllowed() is Cockpit's current answer. */
                    var asRoot = adminAllowed();
                    callOnce("audit-tail", req, asRoot, argv).then(function (res) {
                        clear(out);
                        out.appendChild(el("div", "sec-alert info", asRoot
                            ? "Read with administrative access, so this is the log the " +
                              "root helper writes — the one admin-class safes are audited to."
                            : "Read as you, with no escalation, so this is your own log. " +
                              "Admin-class safes are audited by the root helper into a " +
                              "different one; turn on Cockpit's Administrative access to " +
                              "see that instead."));
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
            HEALTH_ADMIN = !!escalate;
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
        /* THE WORD "Unlocked" AND A KEY GLYPH, not amber alone. This is the one
         * state in the program where a safe is open while nobody is looking at
         * it, and a banner whose entire message is a background colour is a
         * banner that means nothing in greyscale, at a glance, or to a good
         * fraction of the people who will use this page. */
        var h = el("h2");
        h.appendChild(svgGlyph("key"));
        h.appendChild(el("span", null, "Unlocked"));
        h.appendChild(el("span", "sec-subtle", AGENT.rows.length === 1
            ? "— a safe is held open by the agent"
            : "— " + AGENT.rows.length + " safes are held open by the agent"));
        box.appendChild(h);
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
        /* A refusal is not a description of the file, and an answer obtained
         * below the privilege this safe needs is not one either. Either way
         * there is nothing in it to name a destination with, and the confirm
         * must name the real place or say it does not know — never a plausible
         * one (I21). */
        if (probe._error || staleForClass(probe, safe)) probe = {};
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
     * MAKING A SAFE EXIST — create, import, forget, delete
     *
     * THIS IS THE MOST DANGEROUS SURFACE IN THE PAGE, and the reason is one
     * sentence: the registry is this program's trust root. It is what says
     * which files are safes, where they live, and what access class each one
     * has (I1), and every other control here is downstream of it. These flows
     * are the first ones that let a BROWSER REQUEST write into it.
     *
     * What the page is responsible for, and what it is deliberately not:
     *
     *   THE HELPER MINTS THE PATH. The operator supplies an ID. Nothing in
     *   this whole section ever sends a path, a filename, a directory or a
     *   component of one — there is no control for one, no preset carrying
     *   one, and no response key read back as one except to DISPLAY where the
     *   helper decided to put the file (I4, C1). Search this section for
     *   `path`: every occurrence is a read of a helper's answer for display.
     *
     *   THE HELPER VALIDATES THE ID. The allow-list is published as the id
     *   field's own `pattern`, so makeControl's generic validator enforces it
     *   with no code here, and the helper enforces it again — which is the
     *   one that counts. A page-side check is feedback at the moment of
     *   typing, never a gate (I3).
     *
     *   ADMIN IS THE DEFAULT CLASS. The access control's default comes from
     *   the schema, and the schema's default is `admin` (I1). This page reads
     *   the chosen value to decide which of the two spawn shapes to use — and
     *   an ABSENT value is treated as admin, never as user, everywhere it is
     *   read here.
     *
     * ------------------------------------------------------------------
     * WHY THE ENCRYPTED FILE GOES FIRST AND THE PASSPHRASE SECOND (C5)
     *
     * The upload wizard collects the file, stages it, reports what its header
     * claims, and only THEN asks for the passphrase. That ordering is a
     * requirement, and it is also the better design for two reasons that are
     * worth writing down where the code lives:
     *
     *   1. A 128 MiB upload takes visible time. Collecting the passphrase in
     *      the file-picker step would mean holding it in browser memory for
     *      the whole transfer — which is precisely the window I11 and I14
     *      exist to shrink. Prompting after the bytes are staged means the
     *      passphrase exists for one request, exactly as it does for `unlock`.
     *
     *   2. The header of a KDBX or PWS3 file is NOT SECRET. Format, version,
     *      cipher, KDF and its parameters are readable from the bytes by
     *      anyone holding the file — and the person uploading it holds the
     *      file. So the helper can report all of that with no credential at
     *      all, and the operator can confirm they uploaded the file they meant
     *      to BEFORE they type anything. The page labels that summary as what
     *      it is: read from the header, and not authenticated.
     * ================================================================== */

    /* The one piece of import state that outlives a function: enough to abort
     * a staging the page walked away from, and nothing else. NO file bytes, NO
     * passphrase, NO key-file bytes — the token is a capability the helper
     * minted, in memory, exactly like a session handle, and it is dropped the
     * moment the import commits, aborts or fails. */
    var IMPORT = null;              /* { token, admin, verb } or null */

    /* Read a Blob as an ArrayBuffer. FileReader rather than Blob.arrayBuffer()
     * so this works on the same browsers the rest of the page does; the bytes
     * are the operator's own encrypted file, and they are dropped as soon as
     * the chunk they belong to is on its way. */
    function readBlob(blob) {
        return new Promise(function (resolve, reject) {
            var r = new FileReader();
            r.onload = function () { resolve(r.result); };
            r.onerror = function () {
                reject(mkErr("internal", "The browser could not read that file."));
            };
            r.readAsArrayBuffer(blob);
        });
    }

    /* SHA-256 of the whole file, computed IN THE PAGE and sent with
     * import-begin so the helper can prove the bytes it reassembled are the
     * bytes that were picked.
     *
     * `crypto.subtle` is a browser primitive, not WebAssembly and not an
     * eval-family call, so it does not touch I9 — this page still adds no CSP
     * relaxation of any kind. It is only available in a secure context;
     * Cockpit is HTTPS, and where it is genuinely absent the import control is
     * not offered at all rather than offered and then failing (see
     * importSupported). */
    function sha256Hex(buf) {
        return window.crypto.subtle.digest("SHA-256", buf).then(function (d) {
            var u = new Uint8Array(d), out = "", i;
            for (i = 0; i < u.length; i++)
                out += (u[i] < 16 ? "0" : "") + u[i].toString(16);
            return out;
        });
    }

    /* The four verbs the wizard needs, all present, plus the browser primitive
     * it cannot do without. Anything missing means no Upload control — the
     * page does not offer half a wizard. */
    function importVerbs() {
        var v = {
            begin: verbFor("importBegin"),
            chunk: verbFor("importChunk"),
            inspect: verbFor("importInspect"),
            commit: verbFor("importCommit"),
            abort: verbFor("importAbort")
        };
        return v;
    }
    function importSupported() {
        var v = importVerbs();
        if (!v.begin || !v.chunk || !v.inspect || !v.commit) return false;
        return !!(window.crypto && window.crypto.subtle && window.crypto.subtle.digest);
    }

    /* The largest safe the helper will accept, from its own constants. Used to
     * refuse a file BEFORE a single byte is uploaded, which is the point of
     * declaring the total size in import-begin. */
    function maxSafeBytes() {
        var c = (SCHEMA && SCHEMA.constants) || {};
        var n = Number(c.max_safe_bytes || c.max_safe_size || 0);
        return isFinite(n) && n > 0 ? n : 0;
    }

    /* How many raw bytes go in one chunk.
     *
     * The helper's own answer wins: import-begin may name it. Otherwise it is
     * derived from max_request_bytes the same way the attachment control
     * derives its cap — the chunk travels base64 inside one JSON request, and
     * base64 costs a third, so the raw payload that fits is three quarters of
     * what is left after the rest of the object. Neither number is this
     * page's; both are the helper's. */
    function importChunkBytes(beginRes) {
        var said = Number(pickKey(beginRes,
            ["chunk_bytes", "max_chunk_bytes", "chunk_size", "max_chunk"]));
        if (isFinite(said) && said > 0) return Math.floor(said);
        var c = (SCHEMA && SCHEMA.constants) || {};
        var konst = Number(c.import_chunk_bytes || 0);
        if (isFinite(konst) && konst > 0) return Math.floor(konst);
        var reqCap = Number(c.max_request_bytes || 0);
        if (reqCap > 65536) return Math.floor((reqCap - 8192) * 3 / 4);
        return 196608;                      /* 192 KiB — a last resort */
    }

    /* ------------------------------------------------------------------ *
     * Which registry an entry lands in, and what that means
     *
     * C4's per-user registry is the ONE trust-model change in this feature,
     * and the operator has to be able to see which of the two they are about
     * to write to before they write to it. The paths are printed only when the
     * helper published them in its constants: a page that hard-coded
     * /etc/cockpit-secrets/safes.d would keep naming it after the helper moved,
     * and a confirm that names the wrong place is worse than one that names no
     * place (the same rule exportTarget() follows for I21).
     * ------------------------------------------------------------------ */
    function registryDirs() {
        var c = (SCHEMA && SCHEMA.constants) || {};
        return {
            system: c.registry_dir || c.safes_dir || c.system_registry_dir || null,
            user: c.user_registry_dir || c.registry_dir_user ||
                  c.user_safes_dir || c.per_user_registry_dir || null
        };
    }
    /* An absent access value is ADMIN. Stated as a function so every caller in
     * this section resolves it the same way and none of them can drift into
     * treating "not set" as the permissive class (I1). */
    function accessIsAdmin(value) {
        return !(value === "user");
    }
    function registryNote(access) {
        var admin = accessIsAdmin(access);
        var dirs = registryDirs();
        var box = el("div", "sec-alert " + (admin ? "warn" : "info"));
        var p = el("p");
        p.appendChild(el("strong", null, admin
            ? "This will be an administrator safe."
            : "This will be your own safe."));
        p.appendChild(document.createTextNode(admin
            ? " Root owns the file and the registry entry, every administrator on this host " +
              "can open it with its passphrase, and creating it needs Cockpit's administrative " +
              "access to be on in this session."
            : " The file and its registry entry live under your own account, the helper runs " +
              "as you with no escalation at all, and no administrator has to be involved."));
        box.appendChild(p);
        var dir = admin ? dirs.system : dirs.user;
        if (dir) {
            box.appendChild(el("p", null, admin
                ? "Its registry entry is written by root into:"
                : "Its registry entry is written into your own registry at:"));
            box.appendChild(el("code", "sec-path", String(dir)));
        }
        box.appendChild(el("p", null,
            "The file's name and location are chosen by the helper from the id below. " +
            "This page never sends a path (I4)."));
        if (admin && !adminAllowed())
            box.appendChild(el("p", null,
                "Administrative access is OFF in this Cockpit session, so this will be " +
                "refused straight away. Turn it on with the “Limited access” control in the " +
                "Cockpit header first."));
        return box;
    }

    /* WHICH REGISTRY IT LANDED IN, from the helper's own answer.
     *
     * `registry` in a response is a registry SOURCE — the helper publishes the
     * closed set as `enums.registry_source`, with a label and a help sentence
     * for each — and NOT a path. Rendering "system" inside a <code> that says
     * "the registry entry is here" would present a word as a filename, which is
     * the sort of small lie that gets copied into a ticket. So the enum is
     * asked first, and only a value the enum does not know is treated as a path
     * the helper chose to name.
     *
     * The help text is the enum's own, verbatim: for the user registry it is
     * the sentence that states C4's safety argument, and it is worth more on
     * screen than anything this file could write about it. */
    function registrySourceNode(value) {
        var opts = (SCHEMA && SCHEMA.enums && SCHEMA.enums.registry_source) || [];
        var i;
        for (i = 0; i < opts.length; i++) {
            var o = opts[i];
            if (o && String(o.value) === String(value)) {
                var box = el("div", "sec-alert info");
                box.appendChild(el("p", null, "Registered in: " + String(o.label || o.value)));
                if (o.help) box.appendChild(el("p", null, String(o.help)));
                return box;
            }
        }
        /* Not one of the helper's registry sources, so it is whatever the
         * helper called it — shown as a path, unaltered. */
        var code = el("code", "sec-path", String(value));
        return code;
    }

    /* ------------------------------------------------------------------ *
     * A key file the helper generated: shown ONCE, downloaded ONCE
     *
     * A generated key file is half of a composite key and there is no copy of
     * it anywhere else — not on the host, not in the safe, not in this page
     * after the dialog closes. Losing it loses the safe, permanently and with
     * no recovery, which docs/THREAT-MODEL.md lists as explicitly out of scope
     * for this program. So the warning is a wall of red, not a hint, and the
     * bytes are dropped the moment the dialog goes away.
     * ------------------------------------------------------------------ */
    function keyfileHandoff(box, b64, name) {
        var bytes = null;
        try { bytes = b64ToBytes(b64); }
        catch (e) {
            box.appendChild(el("div", "sec-alert err",
                "The helper reported a generated key file, but its reply is not valid " +
                "base64, so there is nothing to hand you. Do not treat this safe as " +
                "usable — ask the helper's audit log what happened."));
            return;
        }
        var w = el("div", "sec-danger-block");
        w.appendChild(function () {
            var p = el("p");
            p.appendChild(el("strong", null, "This is the only copy of this key file."));
            return p;
        }());
        w.appendChild(el("p", null,
            "It is not stored on this host, it is not inside the safe, and it is gone from " +
            "this browser the moment you close this dialog. Download it now and put it " +
            "somewhere you will still have it in a year."));
        w.appendChild(el("p", null,
            "Without it the safe does not open. There is no recovery, no reset and no " +
            "escrow — losing the key material means losing the safe, by design."));
        var line = el("div", "sec-countdown");
        line.setAttribute("aria-live", "polite");
        var dl = btn("Download the key file", "primary", function () {
            if (!bytes) return;
            /* Straight to the browser through a Blob, exactly like an
             * attachment download: nothing is written on the server on the way
             * and nothing is put in a storage area (I11, I21).
             * application/octet-stream on purpose — the file's own idea of its
             * type must not decide how this origin renders it. */
            var blob = new Blob([bytes], { type: "application/octet-stream" });
            var url = URL.createObjectURL(blob);
            var a = el("a");
            a.href = url;
            a.download = String(name || "keyfile.keyx");
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
            line.textContent = "Saved as " + a.download + ". Check that you actually have " +
                "it before you close this dialog.";
            announce("The key file was downloaded. It is the only copy.");
        });
        w.appendChild(dl);
        w.appendChild(line);
        box.appendChild(w);
        /* Dropping the reference when the dialog closes. A JavaScript typed
         * array CAN be zeroed, unlike a string, so this one actually scrubs
         * rather than merely releasing — the honest caveat in this file's
         * header is about strings, and it does not apply here. */
        return function () {
            if (bytes) { bytes.fill(0); bytes = null; }
        };
    }

    /* ------------------------------------------------------------------ *
     * 1 · CREATE A NEW SAFE
     * ------------------------------------------------------------------ */
    function newSafeDialog() {
        var verb = verbFor("safeCreate");
        if (!verb) return;
        /* Which of this verb's request fields carry the decisions the page has
         * to react to. Every one is resolved from the verb's own descriptor;
         * a null simply means that control is not drawn and nothing keys off
         * it, never that the page invents one. */
        var accessField = requestFieldName(verb, ["access", "class", "access_class"]);
        var keyfileField = requestFieldName(verb,
            ["keyfile_b64", "keyfile", "key_file_b64", "keyfile_bytes"]);
        var genField = requestFieldName(verb,
            ["generate_keyfile", "new_keyfile", "make_keyfile", "keyfile_generate"]);
        var pwField = secretArgName(verb, "password");

        verbDialog(verb, {}, null, null, {
            title: "Create a new safe",
            runLabel: "Create the safe",
            /* THE ESCALATION IS READ FROM THE REQUEST, at submit time. A new
             * safe has no registry row to look the class up in — the class is
             * a value in the form — and an absent value is admin (I1). */
            adminFrom: function (req) {
                return accessIsAdmin(accessField ? req[accessField] : undefined);
            },
            beforeForm: function (box) {
                box.appendChild(el("p", "sec-modal-intro",
                    "The helper makes the file, encrypts it with the passphrase you choose " +
                    "here, and writes its registry entry. Nothing exists until all three " +
                    "have happened."));
            },
            afterForm: function (form, box) {
                /* Which registry this lands in, updated live as the access
                 * control changes. It is above the action row rather than
                 * inside the form, because it is a consequence of the form
                 * rather than another question. */
                var host = el("div");
                box.appendChild(host);
                /* The note is repainted whenever the access control changes, so
                 * it gets a container of its OWN. Clearing `host` instead would
                 * take the advisory below it with it — which it did, silently,
                 * the first time the operator switched class. */
                var noteHost = el("div");
                var ac = accessField ? form.byName[accessField] : null;
                /* And it goes DIRECTLY UNDER the control that decides it. This
                 * form is long — id, label, format, class, passphrase, key
                 * file, KDF costs — so a consequence parked at the bottom is a
                 * consequence half a screen away from its cause, and an
                 * operator switching to the user class would watch a paragraph
                 * change somewhere they are not looking. */
                if (ac && ac.node && ac.node.parentNode)
                    ac.node.parentNode.insertBefore(noteHost, ac.node.nextSibling);
                else host.appendChild(noteHost);
                function paint() {
                    clear(noteHost);
                    noteHost.appendChild(registryNote(ac ? ac.get() : undefined));
                }
                paint();
                if (ac) ac.onChange(paint);

                /* An empty passphrase with no key file is refused by the
                 * helper (C7). This is the same class of advisory as the
                 * save-as name check: CLIENT-SIDE FEEDBACK so the operator
                 * finds out while typing rather than at the moment of refusal.
                 * The helper is the gate; if the two ever disagree, the helper
                 * is right and this hint is the bug.
                 *
                 * It does NOT block, and the strength meter beside it does not
                 * block either. Telling an operator their passphrase is weak is
                 * this program's job; refusing the passphrase they chose is not
                 * (C7). */
                var pw = pwField ? form.byName[pwField] : null;
                var kf = keyfileField ? form.byName[keyfileField] : null;
                var gen = genField ? form.byName[genField] : null;
                if (!pw) return;
                var warn = el("div", "sec-alert warn");
                warn.hidden = true;
                warn.textContent =
                    "With no passphrase and no key file there is nothing to encrypt this " +
                    "safe with, and the helper refuses to create it. Type a passphrase, " +
                    "supply a key file, or ask for one to be generated.";
                host.appendChild(warn);
                function recheck() {
                    var hasPw = !!pw.get();
                    var hasKf = !!(kf && kf.get()) || !!(gen && gen.get());
                    warn.hidden = hasPw || hasKf;
                }
                pw.onChange(recheck);
                if (kf) kf.onChange(recheck);
                if (gen) gen.onChange(recheck);
                recheck();
            },
            onResult: function (res) { newSafeResultDialog(res); }
        });
    }

    /* The keys a registration result carries that this page renders itself,
     * so the leftovers can go into the generic list without being printed
     * twice — and so the KEY-FILE BYTES can never fall through into it. A
     * generated key file rendered as a row of a key/value table would be the
     * one credential on this page shown with no warning attached to it. */
    var REG_RESULT_HANDLED = {
        "ok": 1, "registry": 1, "safe": 1, "path": 1, "file": 1,
        "registry_path": 1, "registry_file": 1,
        "keyfile_b64": 1, "key_file_b64": 1, "keyfile_bytes": 1,
        "keyfile_name": 1, "keyfile_filename": 1, "key_file_name": 1,
        "keyfile_warning": 1, "strength": 1, "warnings": 1
    };

    /* Where the safe landed and what it is now, drawn the same way for a
     * created safe and an adopted one. `safe` is the registry row exactly as
     * `list` reports it, so the id comes out of it rather than out of a
     * separate key this page hoped would be there. */
    function registryResultBody(box, res) {
        var row = res && res.safe;
        var id = (row && typeof row === "object") ? row.id
               : pickKey(res, ["id", "safe", "safe_id"]);
        var reg = pickKey(res, ["registry", "registry_path", "registry_file"]);
        if (reg) box.appendChild(registrySourceNode(reg));
        /* A path only if the helper volunteered one. It was never sent by this
         * page and there is no control anywhere here that could have set one
         * (I4); it is displayed because an operator is entitled to know where
         * their safe is. */
        var path = pickKey(res, ["path", "file"]) ||
                   (row && typeof row === "object" ? row.path : undefined);
        if (path) {
            box.appendChild(el("p", null, "The helper minted this path for the file:"));
            box.appendChild(el("code", "sec-path", String(path)));
        }
        (Array.isArray(res && res.warnings) ? res.warnings : []).forEach(function (w) {
            box.appendChild(el("div", "sec-alert warn", String(w)));
        });
        var rest = {};
        Object.keys(res || {}).forEach(function (k) {
            if (REG_RESULT_HANDLED[k]) return;
            rest[k] = res[k];
        });
        if (rest.bytes !== undefined && rest.bytes !== null) {
            rest["file size"] = fmtBytes(rest.bytes);
            delete rest.bytes;
        }
        if (row && typeof row === "object") {
            if (row.format !== undefined) rest.format = row.format;
            if (row.access !== undefined) rest.access = row.access;
        }
        if (Object.keys(rest).length) box.appendChild(kvList(rest));
        return id;
    }

    /* The strength verdict on a passphrase the operator has just CHOSEN.
     * Reported, never enforced (C7): telling somebody their passphrase is weak
     * is this program's job, refusing the one they picked is not. The numbers
     * and the named weaknesses are the helper's; nothing is computed here. */
    function strengthVerdictNode(st) {
        if (!st || typeof st !== "object") return null;
        var bits = st.effective_bits !== undefined ? st.effective_bits : st.entropy_bits;
        var box = el("div", "sec-alert " +
            (String(st.category || "").indexOf("weak") >= 0 ? "warn" : "info"));
        box.appendChild(el("p", null,
            "The passphrase you chose: " +
            (st.category ? String(st.category) : "") +
            (bits !== undefined ? " — about " + bits + " effective bits" : "") + "."));
        var weak = Array.isArray(st.weaknesses) ? st.weaknesses : [];
        if (weak.length) {
            var ul = el("ul", "sec-weak");
            weak.forEach(function (w) {
                ul.appendChild(el("li", null, String((w && (w.label || w.id)) || w)));
            });
            box.appendChild(ul);
        }
        box.appendChild(el("p", null,
            "The safe was created with it either way — this is a report, not a refusal. " +
            "Changing it later means creating another safe and moving the entries across."));
        return box;
    }

    function newSafeResultDialog(res) {
        var kb = pickKey(res, ["keyfile_b64", "key_file_b64", "keyfile_bytes"]);
        var kn = pickKey(res, ["keyfile_name", "keyfile_filename", "key_file_name"]);
        var kw = pickKey(res, ["keyfile_warning"]);
        var drop = null;
        modal("The safe was created", function (box, m) {
            var lead = el("p");
            box.appendChild(lead);
            var id = registryResultBody(box, res);
            lead.textContent = "The helper created the file, encrypted it, and registered it" +
                (id ? " as “" + String(id) + "”" : "") + ".";
            var sv = strengthVerdictNode(res && res.strength);
            if (sv) box.appendChild(sv);
            if (kb) {
                /* The helper's own sentence about the key file, first and
                 * verbatim — it is written by the code that knows what it
                 * generated — then the handover. */
                if (kw) box.appendChild(el("div", "sec-alert warn", String(kw)));
                drop = keyfileHandoff(box, kb, kn);
            }
            box.appendChild(el("p", "sec-subtle",
                "The passphrase is not held anywhere. Opening this safe asks for it, the " +
                "same as every other safe on this page."));
            actionRow(box, [btn("Close", "primary", function () { m.close(); })]);
        }, { onClose: function () {
            if (drop) drop();
            refreshAll();
        } });
        announce("The safe was created.");
    }

    /* ------------------------------------------------------------------ *
     * 2 · UPLOAD AN EXISTING SAFE — file first, passphrase afterwards (C5)
     * ------------------------------------------------------------------ */

    /* Abort whatever staging this page is holding, best effort, and forget it.
     * Called on cancel, on every failure path, and on leaving the page — an
     * orphaned staging is the helper's to sweep on an idle timer, but leaving
     * one behind when we know it is dead is just littering. */
    function importAbortNow(why) {
        var st = IMPORT;
        IMPORT = null;
        if (!st || !st.token) return;
        var verb = verbFor("importAbort");
        /* A helper with no abort verb sweeps its own staging on the idle timer
         * instead. Nothing is retried and nothing is reported: this is
         * housekeeping, and there is nothing an operator would do with the
         * news that it could not be done early. */
        if (!verb) return;
        var field = requestFieldName(verb,
            ["staging", "token", "staging_id", "staging_token", "import_id", "upload_id"],
            "staging");
        var req = {};
        req[field] = st.token;
        /* Deliberately unawaited and deliberately silent: this is cleanup, and
         * a failure to clean up must never surface as an error on top of
         * whatever the operator was actually doing. */
        callOnce(verb, req, st.admin).catch(function () { /* the sweep gets it */ });
        if (why) announce("The staged upload was discarded: " + why + ".");
    }

    function importDialog() {
        var V = importVerbs();
        if (!importSupported()) return;

        /* The field names each verb actually uses, asked once.
         *
         * The candidate lists are deliberately SPECIFIC. An early draft had
         * `id` and `import` among the staging-token spellings, which would
         * have been a real hazard rather than untidiness: `id` is the field
         * carrying the SAFE'S OWN ID on import-begin, so a helper that spelled
         * both the same way would have had this page send a registry id where
         * a staging token belongs, or the reverse. Nothing generic enough to
         * mean two different things is in any of these lists. */
        var TOKEN_NAMES = ["staging", "token", "staging_id", "staging_token",
                           "import_id", "upload_id"];
        var tokenIn = {
            chunk: requestFieldName(V.chunk, TOKEN_NAMES, "staging"),
            inspect: requestFieldName(V.inspect, TOKEN_NAMES, "staging"),
            commit: requestFieldName(V.commit, TOKEN_NAMES, "staging")
        };
        var dataField = requestFieldName(V.chunk,
            ["chunk_b64", "data_b64", "bytes_b64", "chunk_data"], "chunk_b64");
        var offField = requestFieldName(V.chunk,
            ["chunk_offset", "offset", "byte_offset"]);
        var seqField = requestFieldName(V.chunk,
            ["seq", "sequence", "chunk_index", "chunk_seq"]);
        var sizeField = requestFieldName(V.begin,
            ["total_bytes", "size", "bytes", "total", "length"]);
        var hashField = requestFieldName(V.begin, ["sha256", "hash", "digest", "checksum"]);
        var accessField = requestFieldName(V.begin, ["access", "class", "access_class"]);

        /* The wizard's whole state. Function-scoped, dropped when the dialog
         * closes, and NOT in a global, a data attribute or any storage area
         * (I11). `file` is a browser handle to a file on the operator's own
         * disk, not its contents: chunks are sliced off it one at a time and
         * each slice is released as soon as it is on the wire. */
        var W = {
            file: null, token: null, admin: true, access: undefined,
            total: 0, chunkBytes: 0, cancelled: false,
            inspect: null, expiresAt: 0, expiryTimer: null, attempts: null
        };

        modal("Add an existing safe", function (box, m) {
            var steps = el("ol", "sec-steps");
            var STEP_LABELS = ["Choose the file", "Upload", "Check the header",
                               "Unlock it once"];
            var stepNodes = STEP_LABELS.map(function (t) {
                var li = el("li", null, t);
                steps.appendChild(li);
                return li;
            });
            box.appendChild(steps);
            function markStep(n) {
                stepNodes.forEach(function (li, i) {
                    li.className = i < n ? "done" : (i === n ? "now" : "");
                    if (i === n) li.setAttribute("aria-current", "step");
                    else li.removeAttribute("aria-current");
                });
            }

            var host = el("div");
            box.appendChild(host);
            var errHost = el("div");
            box.appendChild(errHost);
            var actions = el("div", "sec-form-actions");
            box.appendChild(actions);

            /* Enter submits the step that is on screen, without a <form> to be
             * submitted (I11). ONE listener for the whole wizard, re-pointed by
             * each step: attaching a fresh one per step would give the operator
             * two submits from one keypress the second time round a loop. */
            var enterSubmit = null;
            box.addEventListener("keydown", function (ev) {
                if (ev.key !== "Enter" || !enterSubmit) return;
                var t = ev.target;
                if (!t || t.tagName !== "INPUT") return;
                if (t.type === "button" || t.type === "checkbox" || t.type === "file") return;
                ev.preventDefault();
                enterSubmit();
            });

            function setActions(list) {
                clear(actions);
                list.forEach(function (b) { if (b) actions.appendChild(b); });
            }
            /* FOCUS FOLLOWS THE STEP, and it is not cosmetic.
             *
             * Each step replaces the panel AND the action row, so the button
             * the operator just pressed is detached — which drops focus to the
             * document, outside the dialog. A keyboard user is then stranded
             * (nothing is focused to Tab from) and, worse, Escape stops
             * closing the dialog, because the modal's key handler is bound to
             * the backdrop and a keypress on <body> never reaches it. An
             * upload wizard whose Escape does nothing is one that orphans a
             * staging on this host. */
            function focusStep() {
                var n = host.querySelector(
                    "input:not([type=hidden]), select, textarea, button, a[href]") ||
                    actions.querySelector("button");
                if (n && n.focus) { try { n.focus(); } catch (e) { /* detached */ } }
            }
            function fail(e) {
                clear(errHost);
                errHost.appendChild(errNode(e));
            }
            function cancelBtn(label) {
                return btn(label || "Cancel", "", function () { m.close(); });
            }

            /* ---- step 1: the file, the id, the label, the class ---------
             * NO CREDENTIAL. Not on this step, not on the next two. The
             * passphrase box does not exist yet and this is the requirement,
             * not a preference (C5). */
            function step1() {
                markStep(0);
                clear(host); clear(errHost);
                W.file = null;

                host.appendChild(el("p", "sec-modal-intro",
                    "Pick the encrypted safe file. It uploads first; the passphrase is asked " +
                    "for afterwards, once you have seen what the file says it is."));

                /* The file picker is drawn here rather than by the generic
                 * file-bytes control on purpose, and the reason is memory: that
                 * control reads the WHOLE file into one base64 string, which is
                 * right for a 700 KiB attachment and wrong for a 128 MiB safe.
                 * This one keeps the browser's File handle and slices it. */
                var pickWrap = el("div", "sec-field");
                var pickId = "sec-import-file";
                var pickLabel = el("label", null, "The safe file");
                pickLabel.setAttribute("for", pickId);
                pickLabel.appendChild(el("span", "hint",
                    "A KeePass (.kdbx) or Password Safe v3 (.psafe3) file. It is read from " +
                    "your disk in pieces and uploaded encrypted, exactly as it is on disk — " +
                    "nothing in this browser decrypts it."));
                pickWrap.appendChild(pickLabel);
                var pick = el("input");
                pick.type = "file";
                pick.id = pickId;
                pickWrap.appendChild(pick);
                var pickNote = el("div", "hint");
                pickNote.setAttribute("aria-live", "polite");
                pickWrap.appendChild(pickNote);
                host.appendChild(pickWrap);

                var cap = maxSafeBytes();
                pick.addEventListener("change", function () {
                    W.file = null;
                    pickNote.textContent = "";
                    var f = pick.files && pick.files[0];
                    if (!f) return;
                    /* The cap is the HELPER'S number and it is enforced before
                     * a single byte moves — that is the entire point of
                     * declaring the total size in import-begin (C5 step 1).
                     * The helper enforces it again, incrementally, as chunks
                     * arrive; this is the courtesy of not making somebody watch
                     * a 200 MiB upload fail at the end. */
                    if (cap && f.size > cap) {
                        pickNote.textContent = "That file is " + fmtBytes(f.size) +
                            " and the helper accepts at most " + fmtBytes(cap) +
                            ". It has not been uploaded.";
                        pick.value = "";
                        return;
                    }
                    W.file = f;
                    W.total = f.size;
                    pickNote.textContent = f.name + " — " + fmtBytes(f.size) +
                        ". Its SHA-256 is computed here and sent with the first request so " +
                        "the helper can prove it reassembled the same bytes.";
                });

                /* Everything else on this step is the helper's own form. */
                var specs = verbArgs(V.begin).filter(function (a) {
                    var n = specName(a);
                    /* The size and the digest are computed by this page from
                     * the file itself, so they are not questions to ask. */
                    return n && n !== sizeField && n !== hashField && !isSecretSpec(a);
                });
                var form = buildForm(specs);
                host.appendChild(form.node);

                var regHost = el("div");
                var ac = accessField ? form.byName[accessField] : null;
                /* Under the access control, for the reason given in
                 * newSafeDialog(): the consequence belongs beside its cause. */
                if (ac && ac.node && ac.node.parentNode)
                    ac.node.parentNode.insertBefore(regHost, ac.node.nextSibling);
                else host.appendChild(regHost);
                function paintReg() {
                    clear(regHost);
                    regHost.appendChild(registryNote(ac ? ac.get() : undefined));
                }
                paintReg();
                if (ac) ac.onChange(paintReg);

                function start() {
                    clear(errHost);
                    var bad = form.validate();
                    if (bad) { errHost.appendChild(el("div", "sec-alert err", bad)); return; }
                    if (!W.file) {
                        errHost.appendChild(el("div", "sec-alert err",
                            "Choose the safe file to upload."));
                        return;
                    }
                    go.disabled = true;
                    W.access = ac ? ac.get() : undefined;
                    W.admin = accessIsAdmin(W.access);
                    var begin = form.values();
                    begin[sizeField || "total_bytes"] = W.total;
                    step2(begin);
                }
                var go = btn("Upload the file", "primary", start);
                enterSubmit = start;
                setActions([go, cancelBtn()]);
                focusStep();
            }

            /* ---- step 2: hash, begin, and the chunked upload ------------ */
            function step2(begin) {
                markStep(1);
                enterSubmit = null;
                clear(host); clear(errHost);

                host.appendChild(el("p", "sec-modal-intro",
                    "Reading the file and uploading it. The passphrase is not asked for and " +
                    "is not sent with any part of this (C5)."));

                var bar = el("div", "sec-progress");
                bar.setAttribute("role", "progressbar");
                bar.setAttribute("aria-valuemin", "0");
                bar.setAttribute("aria-valuemax", "100");
                bar.setAttribute("aria-valuenow", "0");
                bar.setAttribute("aria-label", "Upload progress");
                var fill = el("span");
                bar.appendChild(fill);
                host.appendChild(bar);

                var line = el("div", "sec-countdown");
                host.appendChild(line);
                /* The polite region gets ONE sentence per decile, not one per
                 * chunk: a screen reader being told "3%… 4%… 5%…" a hundred
                 * and seventy times is a hang with extra steps. The visible
                 * text updates continuously; only the announcement is coarse. */
                var say = el("div", "sec-visually-hidden");
                say.setAttribute("role", "status");
                say.setAttribute("aria-live", "polite");
                host.appendChild(say);
                var lastDecile = -1;

                function paint(sent) {
                    var pct = W.total ? Math.floor((sent / W.total) * 100) : 0;
                    /* Same idiom as every other deadline on this page: one
                     * custom property on the track, geometry in the
                     * stylesheet, no style string anywhere. */
                    bar.style.setProperty("--sec-remain",
                        Math.max(0, Math.min(100, pct)) + "%");
                    bar.setAttribute("aria-valuenow", String(pct));
                    line.textContent = fmtBytes(sent) + " of " + fmtBytes(W.total) +
                        " — " + pct + "%";
                    var dec = Math.floor(pct / 10);
                    if (dec !== lastDecile) {
                        lastDecile = dec;
                        say.textContent = "Uploading, " + (dec * 10) + " percent.";
                    }
                }
                paint(0);

                var stop = btn("Cancel the upload", "", function () {
                    W.cancelled = true;
                    line.textContent = "Stopping…";
                });
                setActions([stop]);
                focusStep();

                line.textContent = "Reading the file and computing its SHA-256…";
                readBlob(W.file).then(function (buf) {
                    return sha256Hex(buf).then(function (hex) {
                        /* The whole-file buffer is needed for exactly one
                         * digest and is dropped here. Every later read is a
                         * SLICE off the File handle, so the page never holds
                         * more than one chunk at a time. */
                        buf = null;
                        return hex;
                    });
                }).then(function (hex) {
                    if (W.cancelled) throw mkErr("invalid", "The upload was cancelled.");
                    var req = {};
                    Object.keys(begin).forEach(function (k) { req[k] = begin[k]; });
                    if (hashField) req[hashField] = hex;
                    line.textContent = "Declaring the upload to the helper…";
                    return callOnce(V.begin, req, W.admin);
                }).then(function (res) {
                    W.token = pickKey(res,
                        ["staging", "token", "staging_id", "staging_token",
                         "import_id", "upload_id"]);
                    if (!W.token)
                        throw mkErr("internal",
                            "The helper accepted the upload but named no staging token, so " +
                            "there is no way to send it the bytes.");
                    IMPORT = { token: W.token, admin: W.admin };
                    W.chunkBytes = importChunkBytes(res);
                    noteExpiry(res);
                    return sendChunks(paint);
                }).then(function () {
                    return inspectWithRetry(paint);
                }).then(function (res) {
                    W.inspect = res || {};
                    noteExpiry(res);
                    step3();
                }).catch(function (e) {
                    /* EVERY failure path destroys the staging. A staged file
                     * with no wizard attached to it is a file on this host that
                     * nobody is going to commit and nobody is going to abort. */
                    importAbortNow("");
                    W.token = null;
                    markStep(0);
                    clear(host);
                    fail(e);
                    if (W.cancelled) {
                        clear(errHost);
                        errHost.appendChild(el("div", "sec-alert info",
                            "The upload was cancelled and the partial staging was discarded."));
                    }
                    host.appendChild(el("p", null,
                        "Nothing was written and no registry entry was made."));
                    setActions([btn("Start again", "primary", function () {
                        W.cancelled = false;
                        step1();
                    }), cancelBtn("Close")]);
                    focusStep();
                });
            }

            function inspectReq() {
                var r = {};
                r[tokenIn.inspect] = W.token;
                return r;
            }

            /* import-inspect, RETRIED on a `conflict` — because one of the two
             * things `conflict` means here is transient and the other is not,
             * and getting it wrong costs the operator their whole upload.
             *
             * The helper bounds how many inspects and commits may run at once
             * (constants.import_max_concurrent): each one reads a file that may
             * be 128 MiB or derives a key at the Argon2 ceiling, and nothing
             * else counted work in flight. The (N+1)th caller is REFUSED rather
             * than queued, because queueing would hold this Cockpit channel
             * open for the duration — so a plain `conflict` here can simply
             * mean "another operator is adopting a safe right now".
             *
             * The failure path below destroys the staging, which is right for
             * every permanent refusal and WRONG for that one. Re-uploading 128
             * MiB because two people clicked at the same moment is the same
             * class of bug as re-uploading it because of a typed passphrase,
             * and the helper deliberately keeps the staged bytes in both cases.
             * So a conflict is retried a few times with a short wait, and only
             * an exhausted retry (or any other code) falls through.
             *
             * Bounded and short: a retry loop with no ceiling is a page that
             * hangs, and the operator can always press the button again. */
            function inspectWithRetry(paint) {
                var tries = 0;
                function attempt() {
                    return callOnce(V.inspect, inspectReq(), W.admin)
                        .catch(function (e) {
                            var code = e && e.code;
                            if (code !== "conflict" || tries >= 4 || W.cancelled)
                                throw e;
                            tries += 1;
                            if (paint) paint("Another upload is being read on " +
                                             "this host; waiting for it (try " +
                                             tries + ")…");
                            return new Promise(function (resolve) {
                                window.setTimeout(resolve, 1200 + tries * 400);
                            }).then(attempt);
                        });
                }
                return attempt();
            }

            /* Sequential, never parallel. Order is the whole contract of a
             * chunked upload, and one request in flight at a time also bounds
             * how much of the operator's file this page is holding to exactly
             * one chunk. */
            function sendChunks(paint) {
                var off = 0, seq = 0;
                function next() {
                    if (W.cancelled) return Promise.reject(
                        mkErr("invalid", "The upload was cancelled."));
                    if (off >= W.total) return Promise.resolve();
                    var end = Math.min(W.total, off + W.chunkBytes);
                    var at = off;
                    return readBlob(W.file.slice(at, end)).then(function (buf) {
                        var b64 = bytesToB64(new Uint8Array(buf));
                        buf = null;
                        var req = {};
                        req[tokenIn.chunk] = W.token;
                        if (offField) req[offField] = at;
                        if (seqField) req[seqField] = seq;
                        req[dataField] = b64;
                        return callOnce(V.chunk, req, W.admin).then(function (res) {
                            /* Drop the chunk the moment it is on its way. */
                            req[dataField] = null;
                            b64 = null;
                            /* CROSS-CHECK what the helper says it has.
                             *
                             * `received` on its own is ambiguous — it could as
                             * easily mean "this chunk" as "so far" — and acting
                             * on the wrong reading would either stall the
                             * upload or skip a chunk. It is only read as a
                             * running total when the SAME reply also states a
                             * `total_bytes` equal to the file this page is
                             * sending, which pins it to the same frame of
                             * reference. The unambiguous spellings are always
                             * read. When the two disagree, stop: a silently
                             * mis-assembled safe is the failure with no
                             * symptom, and the sha256 check at inspect would
                             * catch it far later and say much less. */
                            var got = Number(pickKey(res,
                                ["total_received", "bytes_received", "received_total"]));
                            if (!isFinite(got) && Number(res && res.total_bytes) === W.total)
                                got = Number(pickKey(res, ["received"]));
                            if (isFinite(got) && got !== end)
                                throw mkErr("internal",
                                    "The helper has " + fmtBytes(got) + " staged but this " +
                                    "page has sent " + fmtBytes(end) + ". The upload was " +
                                    "stopped rather than finished wrongly.");
                            noteExpiry(res);
                            off = end;
                            seq++;
                            paint(off);
                            return next();
                        });
                    });
                }
                return next();
            }

            /* The staging's idle expiry, whenever the helper mentions it. It is
             * surfaced because a swept staging and a hung page look identical
             * from the operator's chair, and only one of them is worth waiting
             * for. */
            function noteExpiry(res) {
                var s = Number(pickKey(res, ["expires_in", "idle_seconds", "ttl"]));
                if (isFinite(s) && s > 0) W.expiresAt = Date.now() + s * 1000;
            }
            function expiryNode() {
                if (!W.expiresAt) return null;
                /* The node is LOCAL to this call and the ticker closes over
                 * that one, not over a shared variable: step 3 and step 4 each
                 * draw their own countdown, and a ticker still pointing at the
                 * previous step's detached node would write into nothing. */
                var line = el("div", "sec-countdown");
                line.setAttribute("aria-live", "polite");
                if (W.expiryTimer) window.clearInterval(W.expiryTimer);
                function tick() {
                    var left = Math.ceil((W.expiresAt - Date.now()) / 1000);
                    if (left <= 0) {
                        window.clearInterval(W.expiryTimer);
                        W.expiryTimer = null;
                        line.textContent =
                            "The staged upload has expired and the helper has discarded it. " +
                            "Start again to upload the file.";
                        return;
                    }
                    line.textContent =
                        "The staged file is discarded after " + fmtSeconds(left) +
                        " with nothing happening. That timer is a limit on this host's " +
                        "disk and CPU, not on your guessing.";
                }
                tick();
                W.expiryTimer = window.setInterval(tick, 1000);
                return line;
            }

            /* ---- step 3: what the header CLAIMS ------------------------- */
            function step3() {
                markStep(2);
                enterSubmit = null;
                clear(host); clear(errHost);
                var i = W.inspect || {};

                var banner = el("div", "sec-alert info");
                banner.appendChild(function () {
                    var p = el("p");
                    p.appendChild(el("strong", null, "Read from the file's header. "));
                    p.appendChild(document.createTextNode(
                        "NOT authenticated: no passphrase has been tried yet, nothing here " +
                        "has been checked against a MAC, and a file can put whatever it " +
                        "likes in its own header. It is here so you can confirm you " +
                        "uploaded the file you meant to, before you type anything."));
                    return p;
                }());
                host.appendChild(banner);

                var facts = {};
                ["format", "version", "cipher", "kdf", "iterations",
                 "compressed"].forEach(function (k) {
                    if (i[k] !== undefined && i[k] !== null) facts[k] = i[k];
                });
                /* A byte count is a SIZE, and "400000" is a number an operator
                 * has to stop and parse. Only the presentation changes; the
                 * figure is still the helper's. */
                if (i.bytes !== undefined && i.bytes !== null)
                    facts["file size"] = fmtBytes(i.bytes);
                if (i.kdf_params && typeof i.kdf_params === "object")
                    Object.keys(i.kdf_params).forEach(function (k) {
                        facts["kdf " + k] = i.kdf_params[k];
                    });
                if (i.needs_password !== undefined)
                    facts["passphrase required"] = i.needs_password !== false;
                if (i.needs_keyfile !== undefined)
                    facts["key file required"] = !!i.needs_keyfile;
                if (Object.keys(facts).length) host.appendChild(kvList(facts));
                else host.appendChild(el("p", "sec-subtle",
                    "The helper reported no header fields for this file."));

                /* The integrity check, which is a DIFFERENT claim from
                 * authentication and must not be allowed to read like it. The
                 * digest proves the bytes arrived intact; the caller supplied
                 * both the bytes and the digest, so it proves nothing about who
                 * the file belongs to or whether it opens. */
                if (i.sha256_ok !== undefined)
                    host.appendChild(el("div", "sec-alert " + (i.sha256_ok ? "ok" : "err"),
                        i.sha256_ok
                            ? "The reassembled upload matches the SHA-256 this browser " +
                              "computed before sending it, so the bytes arrived intact. " +
                              "That is an integrity check and nothing more — the digest " +
                              "came from the same place the file did."
                            : "The reassembled upload does NOT match the SHA-256 this " +
                              "browser computed. It is not the file that was picked."));
                /* The helper's own sentence about the file, verbatim. */
                if (i.note) host.appendChild(el("p", "sec-subtle", String(i.note)));

                /* Verbatim, like every other helper warning on this page. The
                 * KDBX3 "this file is not authenticated" banner (I20) reaches
                 * the operator through here. */
                (Array.isArray(i.warnings) ? i.warnings : []).forEach(function (w) {
                    host.appendChild(el("div", "sec-alert warn", String(w)));
                });

                var ex = expiryNode();
                if (ex) host.appendChild(ex);

                setActions([
                    btn("This is the right file — unlock it", "primary", function () {
                        step4();
                    }),
                    btn("Wrong file — discard it", "", function () {
                        importAbortNow("the operator said it was the wrong file");
                        W.token = null;
                        step1();
                    }),
                    cancelBtn()
                ]);
                focusStep();
            }

            /* ---- step 4: THE CREDENTIAL, for the first time -------------
             *
             * This is what stops the whole verb being an arbitrary-file-write
             * primitive: the only bytes that can ever land in the managed
             * directory are bytes that are demonstrably a safe the uploader can
             * already open. A file that does not open does not land.
             *
             * ON RATE-LIMITING THE RETRIES, since it is easy to mistake what
             * the bound here is for:
             *
             *   Rate-limiting the GUESS is theatre. The person retrying already
             *   possesses the file — they uploaded it — so they can guess
             *   against their own copy, offline, on their own hardware, as fast
             *   as they like. Nothing this host does changes that arithmetic by
             *   a single bit.
             *
             *   What is NOT theatre is that every attempt costs THIS HOST a
             *   full KDF derivation, which is deliberately expensive, and holds
             *   a staged file on its disk. So the attempt count and the idle
             *   expiry are RESOURCE CONTROLS. They protect the machine. They
             *   are not protecting the safe and this page does not describe
             *   them as though they were.
             *
             *   And a wrong passphrase must NOT destroy the staging. Making
             *   somebody re-upload 100 MiB because of a typo is a bug wearing
             *   a security control's clothes.
             *
             * The numbers shown are the HELPER'S. This page displays
             * `attempts_remaining` and the expiry it was told; it does not
             * count attempts itself, because a count the page invented would be
             * a promise about somebody else's limit. */
            function step4() {
                markStep(3);
                clear(host); clear(errHost);
                var i = W.inspect || {};

                host.appendChild(el("p", "sec-modal-intro",
                    "The passphrase for the file you just uploaded. The helper opens the " +
                    "staged file with it; a file that does not open is not registered and " +
                    "does not land anywhere."));
                if (i.needs_keyfile)
                    host.appendChild(el("div", "sec-alert info",
                        "This file's header says a key file is part of its key. Supply it " +
                        "below as well — it is sent with the passphrase, in the same request, " +
                        "and neither is kept afterwards."));
                /* The attempt budget, named before the first try rather than
                 * discovered on the last one. The number is the helper's; see
                 * the note above on what it is and is not protecting. */
                var budget = Number((SCHEMA && SCHEMA.constants &&
                                     SCHEMA.constants.import_max_attempts) || 0);
                if (W.attempts === null && isFinite(budget) && budget > 0)
                    host.appendChild(el("p", "sec-subtle",
                        "You get " + budget + " attempts against this staged file. Each one " +
                        "costs this host a full key derivation, which is what that limit is " +
                        "for — it is not protecting the safe, because you are holding the " +
                        "file and can try passphrases against your own copy offline."));

                /* The helper's own commit form, minus the plumbing. The
                 * passphrase and key-file controls come from the verb's
                 * descriptor; the strength meter is deliberately OFF, for the
                 * same reason it is off on the unlock dialog — scoring a
                 * passphrase that already exists answers nothing and costs a
                 * copy of it in flight per keystroke. */
                var specs = verbArgs(V.commit).filter(function (a) {
                    var n = specName(a);
                    return n && n !== tokenIn.commit;
                }).map(function (a) {
                    if (!isSecretSpec(a)) return a;
                    var copy = {};
                    Object.keys(a).forEach(function (k) { copy[k] = a[k]; });
                    copy.strength = false;
                    return copy;
                });
                var form = buildForm(specs);
                host.appendChild(form.node);

                var ex = expiryNode();
                if (ex) host.appendChild(ex);

                host.appendChild(el("p", "sec-subtle",
                    "It goes into one variable, is written to the helper's standard input, " +
                    "and is overwritten. It is not stored in this browser and never appears " +
                    "on a command line (I10, I11). A wrong passphrase does not throw the " +
                    "upload away — you can try again without re-uploading."));

                var go = btn("Unlock and register the safe", "primary", submit);
                setActions([go, btn("Discard the upload", "", function () {
                    importAbortNow("the operator discarded it");
                    W.token = null;
                    m.close();
                }), cancelBtn()]);

                enterSubmit = submit;
                focusStep();

                function submit() {
                    clear(errHost);
                    var bad = form.validate();
                    if (bad) { errHost.appendChild(el("div", "sec-alert err", bad)); return; }
                    go.disabled = true;

                    /* ---- THE ONE VARIABLE, exactly as unlockDialog does it.
                     * Every secret control is read here, one at a time,
                     * straight into the JSON body, and released on the next
                     * statements. Nothing else in this file ever holds it. */
                    var req = form.values();
                    req[tokenIn.commit] = W.token;
                    var names = form.secretNames();
                    var n, pw, k;
                    for (k = 0; k < names.length; k++) {
                        n = names[k];
                        pw = form.readSecret(n);
                        if (pw !== null && pw !== "") req[n] = pw;
                        pw = "\0".repeat(pw ? pw.length : 0);
                        pw = null;
                    }
                    var body = JSON.stringify(req);
                    names.forEach(function (nm) { req[nm] = null; });
                    req = null;
                    form.wipeSecrets();

                    callOnceBody(V.commit, body, W.admin).then(function (res) {
                        body = null;
                        /* Committed: the staging is the helper's problem now
                         * and there is nothing left to abort. */
                        IMPORT = null;
                        W.token = null;
                        form.wipeAll();
                        m.close();
                        importResultDialog(res);
                    }).catch(function (e) {
                        body = null;
                        go.disabled = false;
                        clear(errHost);
                        errHost.appendChild(errNode(e));
                        var left = pickKey(e,
                            ["attempts_remaining", "attempts_left", "remaining_attempts"]);
                        if (left !== undefined) {
                            W.attempts = Number(left);
                            errHost.appendChild(el("div", "sec-alert warn",
                                W.attempts > 0
                                    ? W.attempts + " attempt" + (W.attempts === 1 ? "" : "s") +
                                      " left against this upload before the helper discards " +
                                      "it. That is a limit on how much work this host will " +
                                      "do for one staged file, not a limit on guessing — " +
                                      "you have the file."
                                    : "No attempts left: the helper has discarded the staged " +
                                      "file. Upload it again to try another passphrase."));
                            if (W.attempts <= 0) { IMPORT = null; W.token = null; }
                        }
                        if (errCode(e) === "bad-credential")
                            errHost.appendChild(el("div", "sec-alert info",
                                "The upload is still staged. Try the passphrase again — " +
                                "there is no need to re-upload the file."));
                        if (errCode(e) === "locked-out" && errSeconds(e))
                            lockoutCountdown(errHost, errSeconds(e));
                        noteExpiry(e);
                        form.focusFirst();
                    });
                }
            }

            step1();
        }, { wide: true, onClose: function () {
            /* Cancel, Escape, the backdrop, and navigating away all land here.
             * A staging nobody is going to commit is aborted (C5 step 6). */
            W.file = null;
            if (W.expiryTimer) { window.clearInterval(W.expiryTimer); W.expiryTimer = null; }
            importAbortNow("");
        } });
    }

    /* callOnce, but with the body ALREADY serialized.
     *
     * The credential-bearing paths build their own JSON string so the
     * passphrase is never handed to a generic serializer that might keep it
     * somewhere — unlockDialog has done this since the first build, through
     * the session's send(). This is the same thing for a single-shot verb, and
     * it exists so the import commit does not have to be the one credential
     * path in this file that works differently from the others. */
    function callOnceBody(verb, body, adminClass) {
        return new Promise(function (resolve, reject) {
            var proc = cockpit.spawn([HELPER, verb], spawnOpts(adminClass));
            proc.input(body);                       /* stdin, then CLOSED (I10) */
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

    function importResultDialog(res) {
        modal("The safe was registered", function (box, m) {
            var lead = el("p");
            box.appendChild(lead);
            var id = registryResultBody(box, res);
            lead.textContent = "The uploaded file opened with the passphrase you gave, so it " +
                "was moved into place and registered" +
                (id ? " as “" + String(id) + "”" : "") + ".";
            box.appendChild(el("p", "sec-subtle",
                "Your original file is untouched where it was. Opening this safe asks for " +
                "the passphrase again, like every other safe on this page."));
            actionRow(box, [btn("Close", "primary", function () { m.close(); })]);
        }, { onClose: function () { refreshAll(); } });
        announce("The uploaded safe was registered.");
    }

    /* ------------------------------------------------------------------ *
     * 3 · FORGET AND DELETE
     *
     * Creating without removing means an operator can fill the registry and
     * never clean it, so both exist — but they are not the same act and the
     * page must not let them look like it.
     *
     *   FORGET is the ordinary one, and the safe one: the registry entry goes,
     *   the FILE STAYS EXACTLY WHERE IT IS. It is reversible by registering it
     *   again, which is what the upload wizard is for.
     *
     *   DELETE destroys the file and its whole backup ring. It is behind a
     *   typed id, it says plainly that shredding is best-effort on modern
     *   storage, and it is drawn last and in red so it is not the button next
     *   to the one you meant.
     * ------------------------------------------------------------------ */
    function forgetDialog(safe) {
        var verb = verbFor("safeForget");
        if (!verb) return;
        verbDialog(verb, { safe: safe.id }, null, null, {
            title: "Forget " + (safe.label || safe.id),
            safe: safe,
            runLabel: "Remove the registry entry",
            beforeForm: function (box) {
                var w = el("div", "sec-alert warn");
                w.appendChild(function () {
                    var p = el("p");
                    p.appendChild(el("strong", null, "The file stays on disk."));
                    p.appendChild(document.createTextNode(
                        " This removes the registry entry and nothing else: the safe " +
                        "disappears from this page, and the encrypted file, its backups and " +
                        "everything in it are exactly where they were."));
                    return p;
                }());
                w.appendChild(el("p", null,
                    "Nothing here can open it afterwards, because this page has no way to " +
                    "reach a file that is not in the registry (I4). Registering it again " +
                    "with “Add an existing safe” brings it back."));
                box.appendChild(w);
            },
            confirm: "I understand this removes the registry entry and leaves the file on disk.",
            onResult: function (res) {
                var msg = "“" + (safe.label || safe.id) + "” was removed from the registry; " +
                    "its file was left on disk" +
                    (pickKey(res, ["path", "file"])
                        ? " at " + String(pickKey(res, ["path", "file"])) : "") + ". " +
                    /* The helper's own sentence, appended verbatim. It is
                     * written by the code that did the unlinking and knows
                     * exactly what it did and did not touch. */
                    String(pickKey(res, ["warning"]) || "");
                /* The re-read FIRST, the banner SECOND. refreshAll() empties
                 * the alert region as its first statement, so saying it before
                 * asking would announce the outcome and then wipe it — the
                 * operator would watch the safe vanish with no word about why. */
                refreshAll();
                alertText(msg, "ok");
                announce(msg);
            }
        });
    }

    /* The confirm token safe-delete refuses to run without.
     *
     * Same division of labour as the export token (I21): the token is
     * machine-readable and names THIS safe, so an agreement given for a
     * throwaway safe cannot be replayed against the domain administrator one.
     * The prefix is the helper's, from its constants, never a literal here —
     * a page that hard-coded it would keep sending a token the helper had
     * stopped accepting and the failure would read as a permissions bug. When
     * the helper publishes no prefix, the token is the id itself, which is
     * still "an explicit token naming the id" and is the most this page can
     * honestly compose. */
    function safeDeleteToken(safe) {
        var c = (SCHEMA && SCHEMA.constants) || {};
        var prefix = c.delete_confirm_prefix || c.safe_delete_confirm_prefix ||
                     c.destroy_confirm_prefix;
        return prefix ? String(prefix) + String(safe.id) : String(safe.id);
    }

    function deleteDialog(safe) {
        var verb = verbFor("safeDelete");
        if (!verb) return;
        var presets = { safe: safe.id };
        /* Whichever field the verb declares for its token — the helper calls it
         * `delete_confirm` to keep it distinct from export's `confirm`, and a
         * page that hard-coded either name would silently send nothing. */
        var confirmField = requestFieldName(verb,
            ["delete_confirm", "confirm", "confirm_token", "token"]);
        if (confirmField) presets[confirmField] = safeDeleteToken(safe);
        verbDialog(verb, presets, null, null, {
            title: "Delete " + (safe.label || safe.id) + " and its file",
            safe: safe,
            runLabel: "Destroy this safe and its backups",
            beforeForm: function (box) {
                var w = el("div", "sec-danger-block");
                w.appendChild(function () {
                    var p = el("p");
                    p.appendChild(el("strong", null,
                        "This destroys the encrypted file and its whole backup ring."));
                    return p;
                }());
                w.appendChild(el("p", null,
                    "Every credential in “" + (safe.label || safe.id) + "” goes with it. " +
                    "There is no undo, no recycle bin and no escrow: this program has no " +
                    "copy of a safe it has deleted, and neither has the helper."));
                w.appendChild(el("p", null,
                    "Overwriting a file before unlinking it is BEST EFFORT and nothing more. " +
                    "On an SSD, on a copy-on-write filesystem, on anything with wear " +
                    "levelling, and on any snapshot or backup taken before now, the old " +
                    "bytes may well still be recoverable. Treat the passphrase as exposed " +
                    "rather than treating the file as gone."));
                w.appendChild(el("p", null,
                    "If you only want it off this page, use Forget instead — that leaves the " +
                    "file alone."));
                box.appendChild(w);
            },
            typeToConfirm: {
                expect: safe.id,
                label: "Type the safe's id, “" + safe.id + "”, to confirm",
                help: "Typed rather than ticked on purpose: a tick is one gesture and so is " +
                      "a mis-click, and this is the one action on this page that cannot be " +
                      "undone at all."
            },
            confirm: "I understand the encrypted file and every backup of it are destroyed, " +
                     "and that this cannot be undone.",
            onResult: function (res) {
                var msg = "“" + (safe.label || safe.id) + "” was deleted" +
                    (pickKey(res, ["backups_removed", "backups"]) !== undefined
                        ? ", with " + String(pickKey(res, ["backups_removed", "backups"])) +
                          " backup generation(s)" : "") + ". " +
                    /* Verbatim: this is the helper's own statement about what
                     * an overwrite is and is not worth on this storage, and it
                     * is more accurate than anything this page could add. */
                    String(pickKey(res, ["warning"]) || "");
                /* If it was the safe that happens to be open, that session is
                 * now pointing at a file that no longer exists. Lock it and say
                 * why rather than letting the first save find out. */
                var openId = BROWSE ? BROWSE.safe.id : null;
                if (SESSION && openId === safe.id) lockNow("the safe was deleted");
                else refreshAll();
                /* After the re-read, for the reason given in forgetDialog. */
                alertText(msg, "ok");
                announce(msg);
            }
        });
    }

    /* The two entry points, drawn wherever the safe list is. Both are behind
     * "does the helper publish the verb", like everything else here: a build
     * of this page against a helper that cannot create a safe has no New-safe
     * button, and one against a helper with no import verbs has no Upload
     * button — not a disabled one, not one that explains itself, none. */
    function registryActions(host) {
        var made = false;
        if (verbFor("safeCreate")) {
            host.appendChild(btn("New safe…", "primary", function () { newSafeDialog(); }));
            made = true;
        }
        if (importSupported()) {
            host.appendChild(btn("Add an existing safe…", "", function () { importDialog(); }));
            made = true;
        } else if (importVerbs().begin && importVerbs().commit) {
            /* The verbs are there and the browser primitive is not. Say which,
             * rather than leaving a gap that reads as "this helper cannot do
             * it": one of those is a configuration problem and the other is
             * not, and they look identical from the outside. */
            host.appendChild(el("p", "sec-subtle",
                "Uploading a safe needs the browser's SubtleCrypto digest to checksum the " +
                "file before it is sent, and this context does not provide it (it needs a " +
                "secure origin). The helper's import verbs are present."));
        }
        return made;
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
            /* A staged upload nobody is coming back to. The helper sweeps it on
             * its own idle timer anyway, but telling it now is the difference
             * between a file that is cleaned up in seconds and one that sits on
             * this host's disk until a timeout fires (C5 step 6). */
            importAbortNow("");
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
        /* The pane and its toggle (R3/R4) exist before anything is fetched, so
         * the page has its shape from the first frame and the layout does not
         * jump when the registry lands. */
        initPane();
        renderPane();
        bindLifetime();

        PERM = cockpit.permission({ admin: true });
        PERM.addEventListener("changed", function () {
            /* THE ONE MOMENT THE PRIVILEGE LEVEL CHANGES UNDER A DRAWN PAGE.
             *
             * Everything this page cached from the helper was cached at some
             * privilege level, and this event is where those levels stop
             * matching. So the stale ones go first and the re-asking happens
             * second — in that order, because probeSafe() declines to re-ask a
             * safe that already has an answer, and the whole failure this
             * closes was an answer that should not have counted as one.
             *
             * It runs even while a safe is open: SESSION only means the browse
             * view is on screen, and the safe list underneath it, the agent
             * banner above it and the breach control inside its dialogs are all
             * still reading these caches. Only the re-render of the list is
             * skipped while it is not the visible view. */
            var dropped = dropStaleForEscalation();
            /* R1 — VISIBILITY FOLLOWS ELEVATION, LIVE.
             *
             * Administrator safes are listed only while administrative access
             * is on, so this event is also the moment rows appear and
             * disappear. Everything that has to happen when they disappear is
             * in elevationChanged(), which runs BEFORE the re-render so that a
             * safe being locked and its values wiped is not racing the DOM that
             * is about to stop showing it. */
            elevationChanged();
            if (!SESSION) renderSafes();
            else renderPane();
            if (adminAllowed()) {
                /* Administrative access has just come on. The admin-class safes
                 * were deliberately not probed while it was off — one Cockpit
                 * prompt per card on load is an interrogation, not a page — so
                 * this is the first moment they can be, and without it an
                 * operator who escalates from Cockpit's own header watches the
                 * cards stay blank until they think to press Refresh.
                 * probeSafe() skips the ones that already hold an answer good
                 * at this level, so firing more than once is harmless. */
                SAFES.forEach(function (s) { probeSafe(s); });
                /* And the agent: an admin-class hold is only visible to an
                 * escalated health call (I18). */
                if (dropped || HEALTH === null) refreshAgent();
            }
        });

        /* The schema is fetched first and everything else waits for it: this
         * page has nothing of its own to draw. Retry re-runs THIS and nothing
         * else — re-running init() would bind every listener a second time and
         * open a second cockpit.permission. */
        loadSchema();
    }

    function loadSchema() {
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
            /* STATE 4 — THE HELPER DID NOT ANSWER. A different glyph, a
             * different heading and a Retry, so it can never be mistaken for
             * "there are no safes" or for "you cannot see them". */
            var host = byId("sec-safes");
            clear(host);
            var st = stateBlock({ glyph: "warning", glyphKind: "err",
                                  heading: "The helper did not answer" });
            st.appendChild(errNode(e));
            st.appendChild(el("p", null,
                "This page renders only what " + HELPER + " describes through its schema verb, " +
                "so there is nothing to show until the helper answers. Install it with " +
                "install.sh from this package."));
            var again = el("div", "actions");
            again.appendChild(btn("Retry", "primary", function () { loadSchema(); }));
            st.appendChild(again);
            host.appendChild(st);
            renderPane();
        });
    }

    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", init);
    else
        init();
}());
