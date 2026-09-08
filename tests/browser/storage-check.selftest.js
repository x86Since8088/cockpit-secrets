#!/usr/bin/env node
/* The oracle behind live-ui.spec.js item 4, tested without a browser.
 *
 * WHY THIS FILE EXISTS. Item 4 is the I11 assertion — "this page left nothing
 * in the browser" — and it is the one assertion in the package whose subject
 * is a NEGATIVE. A negative assertion that is quietly wrong looks exactly like
 * a negative assertion that is right, and that is what happened: the check
 * treated "a key's value changed LENGTH" as "a key was added", Cockpit's own
 * shell rewrites `cockpit:page_status` while a run is in flight, and the item
 * failed on a page that had written nothing (docs/KNOWN_ISSUES.md **I42**).
 *
 * The repair was to make the check CORRECT rather than lenient, and the danger
 * in any such repair is that it is really just leniency with a better comment.
 * So the repaired logic is pinned here, against four scenarios, and two of them
 * are there to fail if it ever becomes lenient:
 *
 *   1. the false positive that I42 was  -> must NOT be flagged
 *   2. a SAME-LENGTH overwrite of a tolerated key with the passphrase
 *                                       -> MUST be flagged   (the old check MISSED this)
 *   3. a brand-new key written by this package -> MUST be flagged
 *   4. a non-tolerated key that changed length -> MUST be flagged
 *
 * Scenario 2 is the one that makes the exemption safe: `HOST_SHELL_KEYS` waives
 * a NAME's right to change length and nothing else, so no key is ever exempt
 * from the content probes.
 *
 * The functions are lifted out of live-ui.spec.js by source extraction rather
 * than copied, so this exercises the SHIPPING logic and cannot drift from it.
 * It needs no browser, no Cockpit and no credentials, which is why it can run
 * in run_tests.sh while the live suite cannot.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const SPEC = path.join(__dirname, "live-ui.spec.js");

function extract(src, names) {
    let out = "";
    for (const n of names) {
        const re = new RegExp("(?:^const " + n + " =[\\s\\S]*?;$)|(?:^function " + n + "\\([\\s\\S]*?^})", "m");
        const m = src.match(re);
        if (!m) {
            console.error("storage-check.selftest: could not find `" + n + "` in " + SPEC +
                          "\n  item 4's storage oracle was renamed or removed; this guard is " +
                          "not optional, so fix the name here rather than deleting the check.");
            process.exit(2);
        }
        out += m[0] + "\n";
    }
    return new Function(out + "return {" + names.join(",") + "};")();
}

const M = extract(fs.readFileSync(SPEC, "utf8"),
                  ["HOST_SHELL_KEYS", "storageAdded", "storageProbeHits", "storageTolerated"]);

/* A snapshot entry as readStorage() builds it: a length, and the labels of the
 * probes whose text was found in the value. No value ever appears here either. */
const n = (len, hits) => ({ len: len, hits: hits || [] });

const BASE = { local:   { "cockpit:v2-machines.json": n(120), "superuser-key": n(44) },
               session: { "cockpit:page_status": n(235) } };

const CASES = [
    { name: "I42 itself: the shell rewrites its own page_status, 235 -> 223, nothing of ours in it",
      after: { local:   { "cockpit:v2-machines.json": n(120), "superuser-key": n(44) },
               session: { "cockpit:page_status": n(223) } },
      flag: false,
      why: "a named host-shell key changing length is the shell doing its job, not this page storing something" },

    { name: "a SAME-LENGTH overwrite of the tolerated key with the passphrase",
      after: { local:   { "cockpit:v2-machines.json": n(120), "superuser-key": n(44) },
               session: { "cockpit:page_status": n(235, ["the passphrase"]) } },
      flag: true,
      why: "the content probe has NO exemption; the length is identical, so nothing else could see this" },

    { name: "this package writes a key of its own",
      after: { local:   { "cockpit:v2-machines.json": n(120), "superuser-key": n(44) },
               session: { "cockpit:page_status": n(235),
                          "cockpit-secrets:pw": n(22, ["the passphrase", "this package's name"]) } },
      flag: true,
      why: "a key that was not in the baseline is reported whatever it is called" },

    { name: "a NON-tolerated key changes length",
      after: { local:   { "cockpit:v2-machines.json": n(999), "superuser-key": n(44) },
               session: { "cockpit:page_status": n(235) } },
      flag: true,
      why: "only the keys named in HOST_SHELL_KEYS may move; everything else changing is a finding" },
];

let fails = 0;
const ok = (cond, msg) => {
    if (!cond) fails++;
    console.log((cond ? "  \x1b[32mok\x1b[0m   " : "  \x1b[31mFAIL\x1b[0m ") + msg);
};

console.log("== item 4's storage oracle (I11, I42) ==");
console.log("   tolerated host-shell keys: " + JSON.stringify(M.HOST_SHELL_KEYS));
ok(M.HOST_SHELL_KEYS.length === 1 && M.HOST_SHELL_KEYS[0] === "cockpit:page_status",
   "the exemption list is exactly [\"cockpit:page_status\"] — it has not grown " +
   "(" + JSON.stringify(M.HOST_SHELL_KEYS) + ")");

for (const c of CASES) {
    const a = M.storageAdded(BASE, c.after);
    const hits = M.storageProbeHits(c.after);
    const flagged = !!(a.local.length || a.session.length || hits.length);
    ok(flagged === c.flag,
       (c.flag ? "FLAGGED: " : "not flagged: ") + c.name +
       "\n         " + c.why +
       "\n         (keys " + JSON.stringify(a.local.concat(a.session)) +
       ", probe hits " + JSON.stringify(hits) + ")");
}

/* And the note the suite prints on every run, so the waiver is never silent. */
const waived = M.storageTolerated(BASE, CASES[0].after);
ok(waived.length === 1 && waived[0].indexOf("cockpit:page_status") >= 0,
   "a tolerated change is REPORTED as a note rather than passing in silence (" +
   JSON.stringify(waived) + ")");

console.log("\n" + (fails ? fails + " failure(s)" : (CASES.length + 2) + " checks, 0 failure(s)"));
process.exit(fails ? 1 : 0);
