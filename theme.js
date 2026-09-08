/* theme.js — follow Cockpit's light/dark choice.  Forty lines, loaded first in
 * <head> and NOT deferred, so the class lands on <html> before the stylesheet
 * is even requested and there is no flash by construction.
 *
 * WHY THIS FILE REACHES OUTSIDE ITSELF, stated here because a reviewer who
 * sees `window.parent` in a security tool should find the justification
 * immediately:
 *
 *   Cockpit does NOT push its theme into a plugin iframe.  There is no
 *   attribute, no class, no postMessage and no cockpit.js API — measured,
 *   base1/cockpit.js contains the string "theme" zero times.  The shell writes
 *   the shell-style key into the browser's own key/value store, dispatches a
 *   `cockpit-style` CustomEvent on its OWN window only (measured: it never
 *   crosses the iframe boundary), resolves "auto" against
 *   prefers-color-scheme, and toggles `pf-v6-theme-dark` on its OWN <html>.
 *
 *   prefers-color-scheme alone is therefore wrong in exactly the two states a
 *   DELIBERATE choice produces — shell Dark with the OS in light, and shell
 *   Light with the OS in dark — which is how this page came to render a
 *   pure-white 1160px panel inside a black Cockpit.
 *
 *   The sibling plugins (wireguard, headscale) read that stored key back and
 *   re-derive "auto" themselves.  We do not, for two reasons.  validate.sh
 *   bans the four browser-storage identifiers in *.js LEXICALLY (I11) — this
 *   file cannot even NAME them, which is the ban working, and that lexical
 *   quality is exactly the point: an exception would make an auditor read the
 *   code to trust the claim.  And reading the parent's
 *   already-resolved class is strictly BETTER: no re-derivation of "auto", no
 *   possible disagreement with the shell, and it survives a browser with site
 *   data blocked, where getItem() throws.
 *
 * WHAT IT ACTUALLY DOES: reads one class name off a SAME-ORIGIN document that
 * Cockpit itself put us inside, observes one attribute on it, and writes
 * nothing anywhere.  No storage API, no network, no framework.
 *
 * LIMIT: if PatternFly ever inverts the convention — a `…-theme-light` class on
 * a dark default — this reads light.  The regex covers a version bump, not an
 * inversion.  The mitigation is the canary assertion in the live suite, not
 * more code here.
 */
(function () {
    "use strict";
    var ROOT = document.documentElement;
    /* Version-agnostic: PF5 used pf-theme-dark, PF6 uses pf-v6-theme-dark, PF7
       will use something else.  Match the family, not one release. */
    var DARK_RE = /(^|\s)pf-(v\d+-)?theme-dark(\s|$)/;

    function shellRoot() {
        /* Same-origin, measured: the plugin frame is a direct child of the
           shell (depth 1, parent === top).  Opened standalone there is no
           parent — window.parent === window — and the fallback branch below is
           taken, which is cleanly detectable and therefore testable. */
        try {
            if (window.parent && window.parent !== window)
                return window.parent.document.documentElement;
        } catch (e) { /* cross-origin or blocked: fall through to the media query */ }
        return null;
    }

    function apply() {
        var host = shellRoot(), dark;
        if (host) dark = DARK_RE.test(host.className);
        else dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        ROOT.classList.toggle("sec-dark", !!dark);
        ROOT.classList.toggle("sec-light", !dark);
        /* Tells the stylesheet that JS has resolved the REAL preference, so the
           prefers-color-scheme fallback must stop applying.  headscale.js's
           idea, and the right one: without it the fallback and the answer can
           disagree in precisely the two states this file exists to fix. */
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
        else if (mq.addListener) mq.addListener(apply);          /* older engines */
    }
}());
