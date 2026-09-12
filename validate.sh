#!/usr/bin/env bash
#
# validate.sh — the FAST gate the orchestrator runs after phase 4.
#
# The orchestrator kills a custom validator at 120 s, so this file may not run
# the Playwright suite or the fuzz corpus — those live in run_tests.sh and are
# driven by the phase prompt itself. What belongs here is everything that is
# cheap and everything that is a standing invariant: syntax, JSON validity,
# unit tests, and the grep-able bad-practice bans from docs/KNOWN_ISSUES.md.
#
# It is deliberately PROGRESSIVE: a check whose subject does not exist yet is
# skipped, not failed, so early tasks are not blocked by files later tasks
# create. Once a file exists, its checks are mandatory. Exit 0 = pass.
#
set -u
cd "$(dirname "$0")" || exit 1

rc=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; rc=1; }
skip() { printf '  \033[2mskip\033[0m  %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------- syntax ----
head_ "Syntax"

shopt -s nullglob
js=(*.js)
if ((${#js[@]})); then
    for f in "${js[@]}"; do
        # gjs parses the file inside a never-called wrapper: parse errors
        # surface, missing browser globals do not.
        python3 - "$f" <<'PY'
import sys, pathlib
f = sys.argv[1]
src = pathlib.Path(f).read_text()
pathlib.Path("/tmp/.syn-%s" % f).write_text(
    "function __never(cockpit, document, window, navigator){\n" + src + "\n}")
PY
        if gjs "/tmp/.syn-$f" 2>/tmp/.syn-err; then pass "js syntax $f"
        else fail "js syntax $f"; sed 's/^/        /' /tmp/.syn-err; fi
        rm -f "/tmp/.syn-$f" /tmp/.syn-err
    done
else
    skip "no *.js yet"
fi

# tests/integration/*.py is in this list but NOT in the unittest discovery
# below: those scripts drive the real helper against real fixtures and take
# about two minutes, which is more than this gate's whole budget. run_tests.sh
# runs them; this gate only checks they parse, because a syntax error there
# should not have to wait for the full suite to surface.
pys=(secrets-admin backends/*.py agent/*.py tests/*.py tests/integration/*.py)
found_py=0
for f in "${pys[@]}"; do
    [[ -f $f ]] || continue
    found_py=1
    if python3 -c "import ast,sys;ast.parse(open(sys.argv[1]).read())" "$f" 2>/tmp/.pyerr
    then pass "python syntax $f"
    else fail "python syntax $f"; sed 's/^/        /' /tmp/.pyerr; fi
done
((found_py)) || skip "no python sources yet"
rm -f /tmp/.pyerr

# `etcdefaults/*.json` does NOT descend, so the per-user registry example under
# `etcdefaults/user-safes.d/` was the one shipped registry entry no gate looked
# at. One extra glob puts it under the standing check, the same way install.sh's
# schema-validation loop now covers it.
for f in manifest.json etcdefaults/*.json etcdefaults/user-safes.d/*.json \
         tests/fixtures/*.json; do
    [[ -f $f ]] || continue
    if python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$f" 2>/dev/null
    then pass "json $f"; else fail "json $f is not valid JSON"; fi
done

# ------------------------------------------------- standing bans (I9-I15) ---
head_ "Bad-practice bans (docs/KNOWN_ISSUES.md)"

ban() {   # ban <regex> <glob...> -- <message>
    local pat="$1"; shift
    local msg="" files=() seen=0
    while (($#)); do [[ $1 == "--" ]] && { shift; msg="$*"; break; }; files+=("$1"); shift; done
    local hits=""
    for g in "${files[@]}"; do
        [[ -e $g ]] || continue
        seen=1
        local h; h=$(grep -REn "$pat" "$g" 2>/dev/null)
        [[ -n $h ]] && hits+="$h"$'\n'
    done
    if ((!seen)); then skip "$msg (nothing to scan)"
    elif [[ -n $hits ]]; then fail "$msg"; printf '%s' "$hits" | sed 's/^/        /' | head -8
    else pass "$msg"; fi
}

# I11 — nothing about a safe may be persisted in the browser.
ban '\b(localStorage|sessionStorage|indexedDB|document\.cookie)\b' *.js \
    -- "I11 no browser storage of secrets"
# I9 — no eval-family, no WASM, no CSP relaxation.
ban '\beval\(|new Function\(|WebAssembly\.' *.js \
    -- "I9 no eval/Function/WebAssembly in the plugin"
if [[ -f manifest.json ]]; then
    if python3 -c "
import json,sys
m=json.load(open('manifest.json'))
sys.exit(1 if any('content-security-policy'==k.lower() for k in m) else 0)"; then
        pass "I9 manifest declares no CSP relaxation"
    else fail "I9 manifest.json relaxes the Content-Security-Policy"; fi
else skip "I9 manifest.json not written yet"; fi
# I9 — Cockpit's default CSP forbids inline style/script.
ban '<script(?![^>]*\bsrc=)[^>]*>[[:space:]]*[^<[:space:]]|<style[^>]*>' index.html \
    -- "I9 no inline <script>/<style> in index.html"
# I15 — group-readable job logs; a traced shell prints every argument.
ban '^[[:space:]]*set[[:space:]]+-[a-z]*x' *.sh install.sh check.sh run_tests.sh \
    -- "I15 no 'set -x' in shell wrappers"
# I10 — a secret must never be able to reach argv.
ban 'add_argument\([^)]*(password|passphrase|secret|keyfile_b64)' secrets-admin agent/*.py \
    -- "I10 no secret accepted as a command-line argument"
ban 'os\.environ\[[^]]*(PASS|PASSPHRASE|SECRET)' secrets-admin backends/*.py agent/*.py \
    -- "I10 no secret read from the environment"
# I6 — MAC/hash comparison must be constant-time.
if compgen -G "backends/*.py" >/dev/null; then
    if grep -REn '\.digest\(\)[[:space:]]*[!=]=|hexdigest\(\)[[:space:]]*[!=]=' backends/ secrets-admin 2>/dev/null | grep -v compare_digest | grep -q .; then
        fail "I6 non-constant-time comparison of a digest"
        grep -REn '\.digest\(\)[[:space:]]*[!=]=|hexdigest\(\)[[:space:]]*[!=]=' backends/ secrets-admin 2>/dev/null | sed 's/^/        /' | head -5
    else pass "I6 digest comparisons are constant-time"; fi
    if grep -rq 'hmac' backends/ 2>/dev/null && ! grep -rq 'compare_digest' backends/ 2>/dev/null; then
        fail "I6 backends use hmac but never compare_digest"
    else pass "I6 compare_digest present where hmac is used"; fi
else skip "I6 no backends/ yet"; fi
# I8 — lxml must be constructed hardened, never with defaults.
if grep -rqs 'lxml' backends/ 2>/dev/null; then
    if grep -rqs 'resolve_entities[[:space:]]*=[[:space:]]*False' backends/; then
        pass "I8 lxml parser disables entity resolution"
    else fail "I8 lxml used without resolve_entities=False"; fi
else skip "I8 lxml not used yet"; fi
# I12 — saves must be atomic.
if compgen -G "backends/*.py" >/dev/null && grep -rqs 'def save' backends/; then
    if grep -rqs 'os\.replace' backends/; then pass "I12 save uses os.replace"
    else fail "I12 a save path exists with no os.replace (non-atomic write)"; fi
else skip "I12 no save path yet"; fi

# ---- bans added with the second wave of verbs -----------------------------

# I21 — AN EXPORT MAY NEVER LAND ON A PATH FROM THE REQUEST. `_write_export`
# is the one function that creates an export file; its destination must come
# from `export_dir_for(entry)`, which reads the REGISTRY. A call with any other
# first argument is the whole exfiltration hazard back in one line, so the call
# site is pinned rather than the intent described. `urllib.parse` is NOT in the
# network ban below for the same reason this is a call-site check and not a
# name check: it is what builds `otpauth://` URIs and opens nothing.
if [[ -f secrets-admin ]]; then
    if grep -n '_write_export(' secrets-admin \
        | grep -v '^[0-9]*:def _write_export(' \
        | grep -qv '_write_export(export_dir_for('; then
        fail "I21 an export is written to a directory that is not export_dir_for(entry)"
        grep -n '_write_export(' secrets-admin | sed 's/^/        /' | head -5
    else pass "I21 exports are written only to the registry's export_dir"; fi
else skip "I21 secrets-admin not written yet"; fi

# I21's sibling — THE HELPER HAS NO NETWORK CLIENT. `breach-check` answers from
# an operator-supplied local corpus or says it cannot; a Cockpit page that
# phones a third party about the passwords it is holding is precisely what this
# project must not become. The agent's AF_UNIX socket is not covered by these
# names, which is why they are the network-capable ones specifically rather
# than `socket` wholesale.
ban '\b(urllib\.request|urllib\.error|http\.client|httplib|requests\.(get|post|put)|socket\.create_connection|AF_INET|getaddrinfo|smtplib|ftplib|xmlrpc)\b' \
    secrets-admin backends backends/*.py agent/*.py \
    -- "I21 no network client anywhere in the helper, backends or agent"

# I18's keep-open relaxation — FOUR SPELLINGS, each of which IS the fix.
#
# `agent.allow_keep_open` lets an operator suspend one safe's IDLE timeout. The
# whole argument for shipping that rests on four properties, and every one of
# them is a line somebody could delete while the feature went on working:
#
#   1. THE DAEMON DECIDES. `_require_keep_open_allowed` reads the REGISTRY and
#      is called from both doors — `op_put`'s `keep_open` field and the
#      `keep-open` op. One def plus two calls; a caller-trusting version of
#      this feature is a version with fewer.
#   2. THE ABSOLUTE DEADLINE SURVIVES. `expires_in` drops the idle candidate
#      and returns the absolute one; a `keep_open` branch that returned
#      something larger, or `None`, would be an unlock with no end.
#   3. THE PRESENCE LOCKS ARE NOT TIMEOUTS. `sweep`, `drop_all`, the session
#      watcher and the freeze detector must not know this flag exists. A
#      `keep_open` anywhere in them is the "finish the job" mistake the
#      docstrings warn about, and it is the one that would actually be
#      dangerous.
#   4. AN UNLOCK DOES NOT START SUSPENDED. `agent_put` — the helper's call on
#      the unlock path — must never send `keep_open`. The operator asks for it
#      afterwards, explicitly, and it is audited when they do.
if [[ -f agent/secrets_agent.py ]]; then
    bad=""
    # One def, plus three call sites: `op_put`'s keep_open field, and the
    # keep-open op's two doors (by safe id and by handle), each of which has to
    # be gated on its own — a version that gated only one of them would refuse
    # the shape a test sends and admit the shape a client sends.
    n=$(grep -c '_require_keep_open_allowed(' agent/secrets_agent.py || true)
    (( n == 4 )) || bad+=" gate-appears-$n-times-(want 1 def + 3 calls)"
    sed -n '/    def op_put(/,/    def op_get(/p' agent/secrets_agent.py \
        | grep -q 'self._require_keep_open_allowed(safe, uid)' \
        || bad+=" put-does-not-gate"
    sed -n '/    def op_keep_open(/,/    def _holding_row(/p' agent/secrets_agent.py \
        | grep -q 'self._require_keep_open_allowed(' || bad+=" op-does-not-gate"
    # The gate must read the registry, not a request field.
    sed -n '/    def _require_keep_open_allowed(/,/    # -- operations/p' \
        agent/secrets_agent.py \
        | grep -q 'self.policy.allows_keep_open(safe)' || bad+=" gate-not-registry"
    sed -n '/    def expires_in(/,/    def idle_expires_in(/p' agent/secrets_agent.py \
        | grep -q '^            return absolute - at$' || bad+=" absolute-deadline-lost"
    # The BODY of each, strictly between its own def line and the next one at
    # the same indent. A sed range would include the terminating def line, and
    # the very next method after drop_all() is _require_keep_open_allowed —
    # whose NAME contains the string, which would make this check fail for the
    # one reason that is not a finding.
    for fn in 'def sweep(' 'def drop_all(' 'def _check_session(' 'def _check_freeze('; do
        if awk -v f="    $fn" 'index($0,f)==1{on=1;next} on && /^    def /{exit} on' \
               agent/secrets_agent.py | grep -q 'keep_open'; then
            bad+=" presence-lock-honours-keep_open:${fn}"
        fi
    done
    if [[ -f secrets-admin ]]; then
        sed -n '/^def agent_put(/,/^def agent_get(/p' secrets-admin \
            | grep -q 'keep_open' && bad+=" unlock-starts-suspended"
    fi
    # 5. THE GATE IS ON THE HOLDING'S OWN SAFE, NOT ON THE REQUEST'S. `op_put`
    #    finds an existing holding by HANDLE and may RELABEL it, so a gate
    #    keyed on `req["safe"]` and run only `if keep is True` was bypassable
    #    in three messages: take a handle on a denied safe, re-put it onto an
    #    allowed one with keep_open, re-put it back onto the denied one with
    #    no keep_open at all — "absent means leave it as it is" then carried
    #    the suspension onto the safe the registry refuses. The fix is the
    #    effective value, gated against the final label; these two spellings
    #    are what it looks like.
    sed -n '/    def op_put(/,/    def op_get(/p' agent/secrets_agent.py \
        | grep -q 'effective_keep = (keep if keep is not None' \
        || bad+=" put-gate-not-on-effective-value"
    sed -n '/    def op_put(/,/    def op_get(/p' agent/secrets_agent.py \
        | grep -q 'if keep is True:' && bad+=" put-gate-back-on-the-request"
    # 6. BOTH DIRECTIONS ARE GATED. `{"enabled": false}` was ungated and still
    #    ran touch(), which made it a handle-free, passphrase-free idle-timer
    #    reset that worked on safes the registry never opted in. An `if
    #    enabled:` in front of either gate in `op_keep_open` is that defect
    #    coming back.
    if awk 'index($0,"    def op_keep_open(")==1{on=1;next} on && /^    def /{exit} on' \
           agent/secrets_agent.py \
        | grep -B2 '_require_keep_open_allowed(' | grep -q 'if enabled:'; then
        bad+=" off-direction-ungated"
    fi
    # ...and the reset only ever happens for a holding that really WAS
    #    suspended. `if not enabled:` alone hands a free idle window to a
    #    message that carries no handle.
    awk 'index($0,"    def op_keep_open(")==1{on=1;next} on && /^    def /{exit} on' \
        agent/secrets_agent.py | grep -q 'if not enabled and was:' \
        || bad+=" off-direction-resets-what-it-did-not-resume"
    # 7. A WITHDRAWN OPT-IN REACHES A LIVE SUSPENSION. Without the reconcile
    #    the registry gate can only ever refuse the NEXT request, and a
    #    suspension already running keeps its permission for the rest of the
    #    holding's absolute lifetime — a permission that cannot be withdrawn.
    #    It must run before the expiry scan, and it must NOT touch().
    grep -q 'def reconcile_keep_open(' agent/secrets_agent.py \
        || bad+=" no-reconcile-so-revocation-cannot-reach-a-live-suspension"
    awk 'index($0,"    def refresh(")==1{on=1;next} on && /^    def /{exit} on' \
        agent/secrets_agent.py \
        | grep -q 'self.reconcile_keep_open(at, force=force)' \
        || bad+=" refresh-does-not-reconcile"
    awk 'index($0,"    def reconcile_keep_open(")==1{on=1;next} on && /^    def /{exit} on' \
        agent/secrets_agent.py | grep -q '\.touch()' \
        && bad+=" reconcile-hands-back-a-free-idle-window"
    if [[ -n $bad ]]; then
        fail "I18 the keep-open bound lost a guard:$bad"
    else pass "I18 keep-open is gated on the REGISTRY by the daemon at both doors and in both directions, on the holding's own safe after any relabel, keeps the absolute deadline, is unknown to every presence lock, never starts at unlock, and can be withdrawn while it is running"; fi
else skip "I18 agent/secrets_agent.py not written yet"; fi

# I18, THE HALF THAT IS THE FEATURE — KEEP-OPEN POINTS AT THE SESSION TIMER.
#
# The first implementation suspended the AGENT TICKET's idle timer. The agent
# holds a ticket and no key material, so that suspended nothing the operator
# could feel: what ends their working session is `SESSION_IDLE_SECONDS` in the
# helper's `run_session`. The toggle went on, the banner said they would not be
# locked out, and they were. Each grep below is one line of the fix, and each
# one could be deleted while the feature went on looking like it worked.
if [[ -f secrets-admin ]]; then
    bad=""
    grep -q '^class SessionWindow:' secrets-admin \
        || bad+=" no-SessionWindow-so-nothing-can-reach-the-session-timer"
    # The session waits on the window's own deadline, which drops the idle
    # candidate while suspended. A `min(now + idle, ...)` back in the loop is
    # the defect restored.
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q 'wake = window.deadline()' \
        || bad+=" run_session-does-not-wait-on-the-window"
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q 'if not window.keep_open:' \
        || bad+=" an-idle-wakeup-still-ends-a-suspended-session"
    # THE BOUND. The absolute deadline is counted from the session's start and
    # capped; a raise from anywhere but the registry, or one that is not
    # capped, is an unlock with no end.
    awk 'index($0,"    def grant(")==1{on=1;next} on && /^    def /{exit} on' \
        secrets-admin | grep -q 'min(int(registry_max), SESSION_KEEP_OPEN_CEILING)' \
        || bad+=" the-registry-raise-is-not-capped"
    awk 'index($0,"    def hard_deadline(")==1{on=1;next} on && /^    def /{exit} on' \
        secrets-admin | grep -q 'return self.started + self.lifetime' \
        || bad+=" the-absolute-deadline-stopped-counting-from-the-start"
    # A client that SHORTENED the lifetime may not get it back by clicking a
    # toggle.
    grep -q 'if self.client_shortened:' secrets-admin \
        || bad+=" a-client-can-shorten-then-raise-its-own-lifetime"
    # THE SUSPENSION DIES WITH THE SESSION, at the daemon, on every exit path.
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q 'keep_open_release(window, ctx, reason)' \
        || bad+=" the-suspension-can-outlive-the-session-that-asked-for-it"
    # ONE READER OF THE REGISTRY KEY. The helper asks the daemon; a helper-side
    # `allow_keep_open` read is the second reader and the second answer.
    grep -q "cfg.get(.allow_keep_open.)" secrets-admin \
        && bad+=" the-helper-reads-allow_keep_open-for-itself-again"
    # The verb may DESCRIBE the key in its docstring — it has to, that is where
    # the reasoning lives — but it must not READ it. Comment and docstring
    # lines are stripped first so the ban is about code.
    awk 'index($0,"def v_keep_open(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin \
        | grep -v '^\s*#' \
        | grep -E '(get|\[)\(?["'"'"']allow_keep_open' \
        && bad+=" the-verb-formed-its-own-opinion-again"
    # THE DIRECTION IS IN THE LOG. `audit()` drops any note outside the set.
    grep -q '"keep-open-on", "keep-open-off",' secrets-admin \
        || bad+=" the-audit-note-set-lost-the-direction"
    if [[ -n $bad ]]; then
        fail "I18 keep-open lost the timer it is supposed to suspend:$bad"
    else pass "I18 keep-open suspends the SESSION idle timer, keeps the absolute bound counted from the session's start and capped, dies with its session, reads the registry through the daemon only, and records its direction"; fi
else skip "I18 secrets-admin not written yet"; fi

# =============================================================================
# I18 — THE STANDING BAN: THE THING GATED AND THE THING AFFECTED ARE THE SAME
#       SCOPE.
# =============================================================================
#
# THIS MISTAKE HAS NOW BEEN MADE TWICE, WHICH IS WHY IT IS A BAN AND NOT A
# COMMENT.
#
#   1. `op_put` gated on the REQUEST's safe while acting on a holding found by
#      HANDLE, so the caller chose which safe the gate ran against.
#   2. `v_keep_open` gated on ONE safe (`_session_holds(entry["id"])`) while the
#      thing it switched off — `SESSION_IDLE_SECONDS` in `run_session` — is the
#      only idle protection EVERY safe that process has unlocked has. One
#      opted-in safe bought a suspension covering an opted-OUT one held beside
#      it, and the page drew no toggle for that safe, so the operator's only
#      signal said the opposite.
#
# The rule is one sentence: WHEREVER KEEP-OPEN IS GRANTED, THE SCOPE THE GATE
# WAS ASKED ABOUT MUST BE THE SCOPE THE GRANT AFFECTS. The grant affects the
# whole session, so the gate is asked about the whole session, and the greps
# below are what make a future divergence visible without understanding the
# program:
#
#   * `keep_open` is DERIVED. Exactly one line in the file assigns it, and it
#     is the one inside `SessionWindow._rescope` that compares the session's
#     held set against the daemon-affirmed set. Anything else assigning it is
#     a second opinion about the same fact — which is how (2) happened.
#   * the mutator takes the SCOPE, keyword-only and with no default, so a call
#     site cannot narrow it by forgetting an argument.
#   * every call site passes both halves.
#   * the scope is re-derived after every verb, because `unlock` is a verb.
if [[ -f secrets-admin ]]; then
    bad=""
    # ONE WRITER. Find the class body and require that every `.keep_open =`
    # assignment in the whole file lies inside it AND inside `_rescope`.
    python3 - <<'EOF' || bad+=" keep_open-is-assigned-outside-_rescope"
import re, sys
src = open("secrets-admin", encoding="utf-8").read().split("\n")
try:
    start = next(i for i, l in enumerate(src) if l == "class SessionWindow:")
except StopIteration:
    sys.exit(1)
end = next((i for i in range(start + 1, len(src))
            if src[i].startswith("class ") or src[i].startswith("def ")),
           len(src))
try:
    r0 = next(i for i in range(start, end)
              if src[i].strip().startswith("def _rescope(self"))
except StopIteration:
    sys.exit(1)
r1 = next((i for i in range(r0 + 1, end)
           if src[i].startswith("    def ")), end)
bad = [(i + 1, l.strip()) for i, l in enumerate(src)
       if re.search(r"(?<![\w.])(self|window|ctx\.window)\.keep_open\s*=(?!=)", l)
       and not (r0 <= i < r1)]
if bad:
    print(bad, file=sys.stderr)
    sys.exit(1)
EOF
    # THE SCOPE IS AN ARGUMENT, KEYWORD-ONLY AND WITHOUT A DEFAULT.
    grep -q 'def grant(self, safe_id, \*, held, allowed, registry_max=None):' \
        secrets-admin \
        || bad+=" the-grant-mutator-no-longer-demands-the-session-scope"
    # AND THE INVARIANT ITSELF: held must be a SUBSET of what the daemon
    # affirmed. `bool(self.granted) and set(held) <= self.allowed`.
    grep -q 'self.keep_open = bool(self.granted) and set(held) <= self.allowed' \
        secrets-admin \
        || bad+=" the-scope-invariant-was-rewritten-or-removed"
    # EVERY CALL SITE PASSES BOTH HALVES. A `.grant(` without `held=` is the
    # narrowing this ban exists to catch; it would also be a TypeError, and
    # both belts are cheap.
    # `grep -A3` because the call is wrapped: the scope is on a continuation
    # line, and a check that looked at one line would pass on a call that had
    # dropped the argument entirely.
    while IFS= read -r call; do
        [[ $call == *"held="* && $call == *"allowed="* ]] \
            || bad+=" a-grant-call-site-omits-the-scope"
    done < <(grep -A3 '\.grant(' secrets-admin | tr '\n' ' ' \
             | sed 's/--/\n/g' | grep 'grant(')
    # THE SCOPE COMES FROM ONE FUNCTION, and it is the one that looks at every
    # live handle this session owns.
    grep -q '^def session_held_safes(ctx):' secrets-admin \
        || bad+=" no-single-definition-of-the-session-scope"
    awk 'index($0,"def v_keep_open(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q 'held = session_held_safes(ctx)' \
        || bad+=" the-verb-gates-on-something-other-than-the-session-scope"
    # ...AND IT IS RE-DERIVED AFTER EVERY VERB, because `unlock` is a verb and
    # a scope checked only at the toggle can be walked around by unlocking
    # afterwards.
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q 'keep_open_rescope(window, ctx, verb)' \
        || bad+=" the-scope-is-not-re-derived-after-a-verb-changes-the-holdings"
    # THE RELEASE IS THE WHOLE GRANT, AND THE RECEIPT COUNTS. A release that
    # names one safe while the suspension covered several is the receipt that
    # overstates.
    grep -q 'gone = sorted(self.granted)' secrets-admin \
        || bad+=" the-release-no-longer-covers-the-whole-grant"
    # The teardown's own receipt, matched inside `keep_open_release` rather
    # than anywhere in the file: another function carries a similar sentence,
    # and a ban that matched it would pass with this one deleted.
    awk 'index($0,"def keep_open_release(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | tr -d '\n' \
        | grep -q 'all %d safe(s) it covered: %s' \
        || bad+=" the-teardown-receipt-stopped-counting-what-it-released"
    # THE PATH COCKPIT ACTUALLY TAKES. `proc.close("terminated")` signals the
    # process; with no handler the teardown never runs at all.
    grep -q 'def _session_signal_handler(' secrets-admin \
        || bad+=" a-SIGTERMed-session-dies-without-releasing-its-suspension"
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin | grep -q '_install_session_signals()' \
        || bad+=" run_session-does-not-install-the-teardown-signal-handler"
    # THE RE-ASK IS ON A CLOCK. In the `line is None` branch it is reached only
    # by a session that has gone silent — which is every session except the
    # ones keep-open is actually doing something for.
    grep -q 'window.last_recheck' secrets-admin \
        || bad+=" the-recheck-lost-its-clock-and-is-back-on-silence"
    awk 'index($0,"def run_session(")==1{on=1;next} on && /^def /{exit} on' \
        secrets-admin \
        | grep -q 'if window.keep_open and (time.monotonic() - window.last_recheck' \
        || bad+=" the-recheck-is-no-longer-at-the-top-of-the-loop"
    # THE RAISE IS CONTINGENT ON THE GRANT.
    grep -q 'self.lifetime = self.base_lifetime' secrets-admin \
        || bad+=" the-registry-raise-outlives-the-suspension-that-bought-it"
    if [[ -n $bad ]]; then
        fail "I18 the keep-open scope ban broke:$bad"
    else pass "I18 the thing gated and the thing affected are the same scope: keep_open is derived in one line from the session's whole held set, the mutator demands that scope keyword-only, every call site passes it, it is re-derived after every verb, the release covers the whole grant and counts what it released, SIGTERM reaches the teardown, the re-ask is on a clock, and the registry raise dies with the grant"; fi
else skip "I18 secrets-admin not written yet"; fi

# I18 — THE PAGE MAY NOT PROMISE MORE THAN THE HELPER CONFIRMED.
#
# `AGENT.rows[].keepOpen` is the DAEMON's ticket flag out of `health`. The
# banner's "they will NOT lock when you stop using them" is about the idle
# timeout of the helper SESSION holding the unlock — a different timer, in a
# process `health` does not describe. The banner made the whole promise from
# the ticket flag, so it said the most reassuring sentence on the page over
# holdings nothing had suspended a session timer for.
if [[ -f secrets.js ]]; then
    bad=""
    grep -q 'function keptConfirmed(' secrets.js \
        || bad+=" no-gate-between-the-ticket-flag-and-the-promise"
    grep -q 'function keptAdopt(' secrets.js \
        || bad+=" the-page-does-not-adopt-the-helper-published-scope"
    grep -q 'session_keep_open_safes' secrets.js \
        || bad+=" the-page-ignores-the-scope-the-helper-publishes"
    # The promise paragraph is drawn from `confirmed`, never from `suspended`.
    grep -q 'var confirmed = AGENT.rows.filter' secrets.js \
        && bad+=" confirmed-is-computed-from-rows-rather-than-from-suspended"
    grep -q 'if (confirmed.length) {' secrets.js \
        || bad+=" the-promise-paragraph-is-not-gated-on-a-confirmation"
    grep -q 'They will NOT lock when you stop using them' secrets.js \
        || bad+=" the-promise-sentence-moved-and-this-ban-cannot-see-it"
    # And the confirmation dies with the session that gave it.
    grep -q 'keptForget();' secrets.js \
        || bad+=" the-confirmation-outlives-the-session-that-gave-it"
    if [[ -n $bad ]]; then
        fail "I18 the page's promise gate broke:$bad"
    else pass "I18 the banner makes its promise only for safes the HELPER confirmed a session suspension for, adopts that scope from the helper rather than keeping its own, and forgets it when the session ends"; fi
else skip "I18 secrets.js not written yet"; fi

# I18 — THE PRESENCE LOCKS REACH A SUSPENDED HOLDING THIS PAGE DID NOT CREATE.
#
# `pagehide` and the hidden-tab timer used to run entirely inside `if
# (SESSION)`, so a holding suspended by another tab sailed through both while
# the banner promised otherwise. A suspended holding has no idle timer left to
# catch it; presence is all there is.
if [[ -f secrets.js ]]; then
    bad=""
    grep -q 'function agentPresenceLock(' secrets.js \
        || bad+=" no-agentPresenceLock"
    grep -q 'agentPresenceLock("you left the page")' secrets.js \
        || bad+=" pagehide-does-not-reach-a-suspended-holding"
    grep -q 'AGENT.rows.some(function (r) { return r.keepOpen; })' secrets.js \
        || bad+=" the-hidden-tab-timer-is-not-armed-for-a-suspended-holding"
    # The page ADOPTS the helper's deadline; it never computes one.
    grep -q 'function adoptSessionDeadline(' secrets.js \
        || bad+=" no-single-writer-for-the-lock-deadline"
    n=$(grep -c 'SESSION.expiresAt = ' secrets.js || true)
    (( n == 1 )) || bad+=" SESSION.expiresAt-written-in-$n-places-(want 1)"
    grep -q 'adoptSessionDeadline(res.session_expires_in)' secrets.js \
        || bad+=" the-page-does-not-adopt-the-deadline-keep-open-re-issued"
    # AND IT GOES DOWN THE SESSION'S CHANNEL. The timer being suspended lives in
    # the helper process holding the unlock; a `callOnce` spawns a second one,
    # which has no idle timer of its own and cannot reach the first's. Sent that
    # way the verb changes the agent's ticket and nothing the operator feels.
    grep -q 'SESSION.call("keep-open"' secrets.js \
        || bad+=" the-toggle-is-sent-out-of-session-and-reaches-no-timer"
    if [[ -n $bad ]]; then
        fail "I18 the page's half of keep-open lost a guard:$bad"
    else pass "I18 the page locks a suspended holding on every presence signal it promises, including ones it did not create, and adopts the helper's deadline through a single writer"; fi
else skip "I18 secrets.js not written yet"; fi

# I4 — NO VERB TAKES A FILESYSTEM PATH. `save-as` and `restore-backup` take a
# bare NAME; a field named `path`/`dir`/`dest` in a verb's request would be the
# I4 hazard re-entering through the schema, where it would look like a feature.
# Asked of the live schema rather than the source, because the schema is what
# the browser builds its forms from.
if [[ -x secrets-admin ]]; then
    if COCKPIT_SECRETS_ETC=/nonexistent ./secrets-admin schema 2>/dev/null \
       | python3 -c "
import json, sys
BAD = {'path', 'dir', 'dest', 'destination', 'target_path', 'filename', 'file'}
d = json.load(sys.stdin)
bad = [(v['id'], f) for v in d['verbs'] for f in v.get('request') or []
       if f in BAD]
if bad:
    print(bad, file=sys.stderr)
    sys.exit(1)
"; then pass "I4 no verb declares a filesystem path as a request field"
    else fail "I4 a verb declares a path-shaped request field"; fi
else skip "I4 secrets-admin not executable yet"; fi

# ---- bans added after the adversarial review ------------------------------
#
# Each of these five is a mistake that WAS made, survived every gate, and was
# found by an attacker rather than by a test. They are here because each one is
# cheap to grep for and expensive to find any other way.

# DURABILITY-1 — `os.write()` is allowed to write FEWER bytes than it was given.
# `_ring_backup` advanced by the bytes it had READ, so one short write on a
# nearly full filesystem produced a TRUNCATED backup generation that was
# fsync'd, named, listed by the `backups` verb with a plausible size, and
# accepted by `restore-backup` — which then wrote it over the live safe. Every
# other data-carrying write in the program looped correctly, which is exactly
# why nothing caught the one that did not.
#
# `backends/base.py` is NOT exempt — it is where the bug was. The rule is that
# the WHOLE PROGRAM contains exactly one code line calling os.write(), and it
# is the one inside write_all() that loops on the return value. A first version
# of this ban exempted base.py and passed with the bug put back, which is why
# the check counts rather than describes. tests/ban_os_write.py does the count.
if compgen -G "backends/*.py" >/dev/null; then
    if python3 tests/ban_os_write.py; then
        pass "DURABILITY-1 the only os.write() in the program is write_all()'s"
    else
        fail "DURABILITY-1 a bare os.write() outside write_all() (a short write is silent data loss)"
    fi
    # …and write_all must still be the thing that loops.
    if grep -q 'while written < total' backends/base.py; then
        pass "DURABILITY-1 write_all() loops on the return value"
    else
        fail "DURABILITY-1 write_all() no longer loops on os.write()'s return"
    fi
else skip "DURABILITY-1 no backends/ yet"; fi

# LEAKAGE-03 — RFC-4180 quoting is not a formula-injection defence. A spreadsheet
# parses a QUOTED cell beginning with = + - @ TAB or CR as a formula, so an
# attacker-controlled field value became `=WEBSERVICE(...)` in the one artefact
# that holds every credential in the safe at once. `base.CsvWriter` neutralises
# every cell; a raw `csv.writer` anywhere else is the hazard walking back in
# through a new export format.
ban 'csv\.writer\(' backends/kdbx.py backends/psafe3.py secrets-admin agent/*.py \
    -- "LEAKAGE-03 no raw csv.writer outside base.CsvWriter (formula injection)"

# LEAKAGE-04 — pykeepass formats caller-supplied text straight into an XPath
# predicate. docs/COMPATIBILITY.md §7 fixed `reveal()` and warned that "anyone
# else passing caller-supplied text to a pykeepass find_* / set_custom_property
# call has the same bug"; `add()` was that call site and was not hardened, so a
# legal entry title containing a double quote answered `internal`. Field access
# is done by comparing element text in Python, and these names must not come
# back.
ban '\.(find_entries|find_groups|find_attachments|set_custom_property)\(' \
    backends/kdbx.py \
    -- "LEAKAGE-04 no pykeepass find_*/set_custom_property (XPath injection)"
# The `add` call site specifically: the two positional strings after the
# destination group must be constants, because add_entry searches on them
# BEFORE it looks at force_creation.
if [[ -f backends/kdbx.py ]]; then
    if grep -q 'add_entry(' backends/kdbx.py \
       && ! grep -q 'dest, "", "", password' backends/kdbx.py; then
        fail "LEAKAGE-04 add_entry() is called with caller text as title/username"
        grep -n -A2 'add_entry(' backends/kdbx.py | sed 's/^/        /' | head -6
    else pass "LEAKAGE-04 add_entry() is called with constant title/username"; fi
else skip "LEAKAGE-04 backends/kdbx.py not written yet"; fi

# LEAKAGE-02 — `page.screenshot()` and `download.saveAs()` create their file
# under the process umask; Playwright offers no mode option on either. The two
# artefacts that hold ACTUAL secret material — a screenshot taken deliberately
# between Reveal and the countdown ending, and a decrypted attachment body —
# were therefore the two written group- and world-readable, while the harmless
# console log was 0600. Every writer goes through `lockDown()`, and the runner
# sets a private umask as the belt to that brace.
if [[ -f tests/browser/live-harness.js ]]; then
    ok=1
    grep -q 'function lockDown(' tests/browser/live-harness.js || ok=0
    grep -q 'umask 077' tests/browser/run-live.sh 2>/dev/null || ok=0
    grep -q 'download\.saveAs(' tests/browser/live-ui.spec.js 2>/dev/null && ok=0
    if ((ok)); then pass "LEAKAGE-02 live artefacts are chmod'ed 0600 as they are written"
    else fail "LEAKAGE-02 a live-suite artefact writer bypasses lockDown()/umask 077"; fi
else skip "LEAKAGE-02 no live browser harness yet"; fi

# INPUT-2 — `internal` is reserved for "we do not know what went wrong", and for
# a REQUEST FRAME we always do: the caller sent it. json.loads raises
# RecursionError (a RuntimeError, not a ValueError) on a deeply nested body, so
# 100 000 open brackets answered `internal`. The handler must stay.
if [[ -f secrets-admin ]]; then
    # The HANDLER line, not the word: the comment beside it explains why
    # RecursionError is not a ValueError, and a grep for the name alone
    # passed with the handler deleted and the comment left behind.
    if grep -A24 'def parse_request' secrets-admin \
       | grep -q '^ *except RecursionError:'; then
        pass 'INPUT-2 parse_request answers invalid for a body it cannot parse'
    else fail "INPUT-2 parse_request no longer catches RecursionError"; fi
else skip "INPUT-2 secrets-admin not written yet"; fi

# ------------------------------------------------ the registry write path ---
#
# Everything below closes a defect found in the 0.4.0 red-team round. Each one
# is here because the mistake is CHEAP TO GREP FOR: a ban that has to
# understand the program is a ban that will be wrong, and these are all "this
# exact spelling means the fix is gone".

# I43 — the candidate check must take BYTES. It used to take the staged file's
# PATH while import-commit separately re-read that path for the bytes it wrote,
# so the bytes that were proven to open and the bytes that landed as a safe
# were never the same bytes. The signature IS the fix: with bytes there is
# nothing left to re-read.
if [[ -f secrets-admin ]]; then
    bad=0
    grep -q 'def _open_candidate(fmt, data, password, keyfile, \*, mine):' \
        secrets-admin || bad=1
    grep -q 'def _header_facts(fmt, data):' secrets-admin || bad=1
    # And no second read of the staged blob inside the commit body: exactly one
    # `read_all` may appear there, and it is the one at the top.
    n=$(sed -n '/^def _commit_staged/,/^def /p' secrets-admin \
        | grep -c 'read_all(' || true)
    (( n <= 1 )) || bad=1
    if ((bad)); then
        fail "I43 the import candidate check takes a path again, or the commit re-reads the staged blob"
        grep -n 'def _open_candidate\|def _header_facts' secrets-admin | sed 's/^/        /'
    else pass "I43 the import candidate check takes bytes, read once"; fi
else skip "I43 secrets-admin not written yet"; fi

# I44 — open_safe_fd's S_ISREG refusal runs AFTER the open, and open(2) on a
# FIFO blocks forever, so the check could never run. One flag is the fix.
if [[ -f backends/base.py ]]; then
    if sed -n '/^def open_safe_fd/,/^def /p' backends/base.py \
       | grep -q 'flags |= os.O_NONBLOCK'; then
        pass "I44 open_safe_fd opens O_NONBLOCK so a FIFO cannot hang it"
    else fail "I44 open_safe_fd can block forever on a FIFO in the registry"; fi
else skip "I44 backends/base.py not written yet"; fi

# I45/I47/I48/I49/I50 — five properties of the two verbs that destroy or create.
if [[ -f secrets-admin ]]; then
    bad=""
    grep -q 'def _land_new_safe(' secrets-admin \
        || bad+=" I45:no-_land_new_safe"
    # No verb may place a safe and publish its entry as two independent steps:
    # `_place_new_safe` is called from exactly ONE place, and that place is
    # `_land_new_safe`, which unlinks the file again if the entry cannot be
    # published. A second call site is the orphan back.
    n=$(sed -n '/^def _land_new_safe/,/^def /p' secrets-admin \
        | grep -c '_place_new_safe(' || true)
    t=$(grep -c '_place_new_safe(' secrets-admin || true)   # 1 def + 1 call
    (( n == 1 && t == 2 )) || bad+=" I45:_place_new_safe-appears-$t-times-(want 1 def + 1 call in _land_new_safe)"
    grep -q 'path = _minted_path_or_refuse(entry, ctx)' secrets-admin \
        || bad+=" I47:no-derived-path-gate"
    # The ring must be derived from the minted path, never from the registry.
    sed -n '/^def _delete_ring/,/^def /p' secrets-admin \
        | grep -q 'backup_dir_for(safe_path, None)' || bad+=" I47:ring-not-derived"
    # safe-delete unregisters BEFORE it shreds: v_safe_forget must appear
    # before the first _shred in the verb body.
    body=$(sed -n '/^def v_safe_delete/,/^def /p' secrets-admin)
    f=$(printf '%s' "$body" | grep -n 'v_safe_forget(' | head -1 | cut -d: -f1)
    d=$(printf '%s' "$body" | grep -n '_shred(path)' | head -1 | cut -d: -f1)
    [[ -n $f && -n $d ]] && (( f < d )) || bad+=" I48:shred-before-unregister"
    grep -q 'confirm = req.get("delete_confirm")' secrets-admin \
        || bad+=" I49:delete-confirm-field"
    # The DEFINITION and the CALL, counted: grepping for the name alone passed
    # with the call replaced by `pass`, because the def line spells it the same
    # way. Two occurrences is one def plus one call site, and the call site is
    # checked to be inside run_verb.
    g=$(grep -c '_refuse_undeclared_credential(verb, req)' secrets-admin || true)
    (( g == 2 )) || bad+=" I50:credential-guard-appears-$g-times-(want def+call)"
    sed -n '/^def run_verb(/,/^# ===/p' secrets-admin \
        | grep -q '^        _refuse_undeclared_credential(verb, req)$' \
        || bad+=" I50:guard-not-called-from-run_verb"
    if [[ -n $bad ]]; then
        fail "the registry write path lost a guard:$bad"
    else pass "I45/I47/I48/I49/I50 create rolls back, delete is derived, unregisters first, reads its declared confirm, and refuses an undeclared credential"; fi
else skip "I45/I47/I48/I49/I50 secrets-admin not written yet"; fi

# I46 — the helper's own loader must accept the keys the helper writes. Both
# halves in one check, because either alone is the bug: writing a key the
# loader drops makes the operator's safe vanish from `list`, and `origin`,
# `created_utc` and `source` were declared in the schema and shipped in
# examples while `_KNOWN_KEYS` did not list them.
if [[ -f secrets-admin && -f schema/safe-registry.schema.json ]]; then
    if python3 tests/ban_registry_vocabulary.py >/tmp/.vocab 2>&1
    then pass "I46 _KNOWN_KEYS and safe-registry.schema.json declare the same keys"
    else fail "I46 the helper's registry vocabulary disagrees with its own schema file"
         sed 's/^/        /' /tmp/.vocab | head -8; fi
    rm -f /tmp/.vocab
else skip "I46 helper or schema not written yet"; fi

# I51/I52/I53/I54/I55 — the five smaller ones, each a single spelling.
if [[ -f secrets-admin ]]; then
    bad=""
    # The loader must RECORD every file that declared an id, and forget must
    # READ that list. Grepping for the key name alone passed with the recording
    # line replaced by `pass`, because the same key appears again in the
    # duplicate branch; and grepping forget for `raise Conflict(` passed with
    # `dupes` hard-coded empty, because the branch was still there and simply
    # never taken. Both are pinned to the line that does the work.
    grep -q '            entry\["registry_files"\] = \[name\]' secrets-admin \
        || bad+=" I51:loader-does-not-record-every-file"
    sed -n '/^def v_safe_forget/,/^def _shred/p' secrets-admin \
        | grep -q 'dupes = \[n for n in (entry.get("registry_files") or \[\])' \
        || bad+=" I51:forget-does-not-read-the-list"
    grep -q '_LABEL_SPOOF_CHARS' secrets-admin || bad+=" I52:label-constant"
    grep -q 'unicodedata.category(ch) == "Cf"' secrets-admin || bad+=" I52:Cf-sweep"
    sed -n '/^def _sweep_staging/,/^def /p' secrets-admin \
        | grep -q 'os.lstat(d)' || bad+=" I53:sweep-follows-symlinks"
    sed -n '/^def _staging_destroy/,/^def /p' secrets-admin \
        | grep -q 'dir_fd=dirfd' || bad+=" I53:destroy-unlinks-by-path"
    # BOTH expensive verbs, named individually: the slot on one of the two is
    # not a bound, and a whole-file grep passed with the inspect call site
    # removed because the commit one still matched.
    sed -n '/^def v_import_inspect/,/^def _inspect_staged/p' secrets-admin \
        | grep -q 'with _ImportWorkSlot(' || bad+=" I54:inspect-unbounded"
    sed -n '/^def v_import_commit/,/^def _commit_staged/p' secrets-admin \
        | grep -q 'with _ImportWorkSlot(' || bad+=" I54:commit-unbounded"
    # I55 — a safe that is destroyed takes its I16 counter with it, and a safe
    # created at a freed id starts clean. Both call sites, because the counter
    # can be inherited through either route (delete-then-create, or
    # forget-remove-create) and one of the two alone leaves the other open.
    sed -n '/^def _land_new_safe/,/^def /p' secrets-admin \
        | grep -q 'lockout_reset(ctx.ident, entry\["id"\])' \
        || bad+=" I55:create-inherits-a-stale-lockout"
    sed -n '/^def v_safe_delete/,/^def /p' secrets-admin \
        | grep -q 'lockout_reset(ctx.ident, entry\["id"\])' \
        || bad+=" I55:delete-leaves-its-lockout-armed"
    if [[ -n $bad ]]; then
        fail "the registry write path lost a smaller guard:$bad"
    else pass "I51/I52/I53/I54/I55 duplicate ids, spoofed labels, the staging sweep, import concurrency and the lockout of a reused id are all still guarded"; fi
else skip "I51/I52/I53/I54/I55 secrets-admin not written yet"; fi

# EVERY FIELD A VERB READS MUST BE A FIELD ITS SCHEMA DECLARES.
#
# This is I49 generalised, and it is the check that would have found it on its
# own: `safe-delete` read `confirm` while the schema published
# `delete_confirm`, so the destructive verb was unreachable through the
# published interface and destroyed on a field nobody was told about. An AST
# walk, not a grep, because `req.get("x")` has to be attributed to the verb
# function it appears in.
if [[ -f secrets-admin ]]; then
    if python3 tests/ban_undeclared_fields.py >/tmp/.undecl 2>&1
    then pass "I49 every field a verb reads is declared in its schema request"
    else fail "I49 a verb reads a request field its schema does not declare"
         sed 's/^/        /' /tmp/.undecl | head -12; fi
    rm -f /tmp/.undecl
else skip "I49 secrets-admin not written yet"; fi

# Not a KNOWN_ISSUES hazard, just a trap that cost real time: a stray NUL byte
# in a source file parses fine, passes both gates, and makes grep treat the
# file as binary — so every ban above it silently stops matching. A ban that
# can be switched off by a typo is not a ban.
#
# `-a` IS LOAD-BEARING. Without it grep detects the NUL, decides the file is
# binary, and skips it — so the check for the byte is disabled by the byte,
# which is the same failure one level down. Written out because it looks like
# a redundant flag and deleting it would leave a check that always passes.
if compgen -G "*.js" >/dev/null; then
    nul=$(grep -rlaP '\x00' --include='*.js' --include='*.py' --include='*.sh' \
              --include='*.json' --include='*.html' --include='*.css' \
              . 2>/dev/null | grep -v '^\./\.git' | head -5)
    if [[ -n $nul ]]; then
        fail "a source file contains a NUL byte (grep will treat it as binary)"
        printf '%s\n' "$nul" | sed 's/^/        /'
    else pass "no source file contains a NUL byte"; fi
else skip "no sources to scan for NUL bytes"; fi

# ---- keep-open: THE GATE AND THE THING IT GATES MUST BE THE SAME SCOPE ----
#
# Four defects in this feature were ONE mistake wearing four costumes: something
# checked at one scope and applied at another. Each was found by reproduction
# with a control, never by reading, which is why this is a ban and not a note:
#
#   1. `op_put` gated on the safe id IN THE REQUEST while acting on a holding
#      found BY HANDLE, so a re-put could relabel a holding to an allowed safe,
#      set keep_open, and relabel it back to a denied one.
#   2. The registry opt-in is PER SAFE; the suspension it granted was PER
#      SESSION — one timer over every safe the process held — so a denied safe
#      rode an allowed one's grant.
#   3. `v_list`'s live test had NO EXPIRY CHECK while the scope gate did, so a
#      safe whose handle had timed out both drew as unlocked and stopped
#      blocking the grant: wait the handle out and the gate lets you through.
#   4. The recheck-revocation path released the helper's window but never told
#      the DAEMON, so the agent-side half of the suspension outlived the
#      session that owned it.
#
# So the pairings below are what is pinned, not the spellings.
if [[ -f secrets-admin ]]; then
    bad=""
    # (2) the grant is computed over the SCOPE, never one safe.
    grep -q 'verdicts = keep_open_allowed_for(ctx, sorted(held | {entry\["id"\]}))' secrets-admin \
        || bad+=" grant-not-over-scope"
    # (3) `live` in v_list and `session_held_safes` must agree on what "held"
    #     means. Both test expiry, or neither does; one of each is defect 3.
    grep -q 'and s.expires_in() > 0' secrets-admin || bad+=" list-live-ignores-expiry"
    grep -q 'expires_in() > 0' secrets-admin || bad+=" scope-ignores-expiry"
    # (4) EVERY path that gives the window up tells the daemon. Three release
    #     sites; three notifications.
    r=$(grep -c 'window.release(' secrets-admin || true)
    t=$(grep -c 'keep_open_tell_agent_off(' secrets-admin || true)
    (( t >= 3 )) || bad+=" release-sites-$r-but-only-$t-notify"
    # (1)/F3 the OFF direction records a refusal instead of re-raising, so a
    #     withdrawn opt-in cannot strand a suspended timer.
    grep -q 'refusal = exc' secrets-admin || bad+=" off-direction-reraises"
    if [[ -n "$bad" ]]; then fail "keep-open scope pairings:$bad"
    else pass "keep-open: gate and grant share a scope, expiry agrees, every release notifies"; fi
fi

# ------------------------------------------- deployment bans (DEPLOY-CONTRACT) ---
head_ "Deployment bans (docs/DEPLOY-CONTRACT.md)"

# The declared payload, read from install.sh's manifest block - the same single
# source deploy.sh reads. If this file restated it the two could disagree, and a
# gate that scans a different list from the one that ships is a gate that passes
# the wrong files.
dc_manifest="$(sed -n '/^# BEGIN-MANIFEST/,/^# END-MANIFEST/p' install.sh)"
if [[ -z "$dc_manifest" ]]; then
    fail "install.sh has no BEGIN-MANIFEST block - deploy.sh and this gate both read it"
else
    eval "$dc_manifest"

    # The manifest block is read by THREE parsers: bash's eval here, deploy.ps1's
    # line-oriented reader, and this file. Only bash joins a continuation line, so
    # a multi-line array assignment silently handed the other two a truncated
    # STRING where an array was meant - REQUIRED_ENV came back as 64 characters
    # instead of 6 keys, and every check that iterated it quietly did nothing.
    # One line per assignment, enforced here so it cannot come back.
    if printf '%s\n' "$dc_manifest" | grep -qE '^[A-Z_]+=\([^)]*$'; then
        fail "a BEGIN-MANIFEST assignment does not close on one line - the non-bash parsers read it as a truncated string"
        printf '%s\n' "$dc_manifest" | grep -nE '^[A-Z_]+=\([^)]*$' | sed 's/^/        /'
    else
        pass "every BEGIN-MANIFEST assignment fits on one line (all three parsers agree)"
    fi

    # The dev root, split so this file's own mention cannot match itself and
    # turn the check below into a permanent self-inflicted failure.
    DC_DEV="/srv/smb/share/sc/ai-orchestrator""-group"

    dc_shipped=("${PAGE[@]}" "$ENVDEFAULT")
    for h in "${HELPERS[@]}"; do
        [[ -e "bin/$h" ]] && dc_shipped+=("bin/$h") || dc_shipped+=("$h")
    done
    for l in "${LIBS[@]}"; do
        [[ -d "$l" ]] && dc_shipped+=("$l") || dc_shipped+=("${l#lib/}")
    done
    [[ -d agent ]] && dc_shipped+=(agent)
    # Shipped docs land on production hosts like any other artifact.
    for d in README.md LICENSE; do [[ -f "$d" ]] && dc_shipped+=("$d"); done

    # THE STANDING BAN THE DEPLOYMENT WORK ADDS: no deployed artifact may
    # contain a dev-tree or retired path. install.sh is excluded because
    # section 3.1 REQUIRES it to carry the dev root as a literal - that is how
    # it classifies the install, and how --uninstall knows to tell an operator
    # that their checkout is not being touched. The ban is on artifacts that
    # would carry a dead path into production.
    #
    # Had this check existed in samba-ad-lab it would have caught all thirteen
    # occurrences there, including the two that are broken right now: a Cockpit
    # manifest condition naming a file that does not exist (which makes the
    # plugin SILENTLY ABSENT), and a SECRET_DIR that makes every build create an
    # empty secrets directory at a dead path.
    if hits=$(grep -RIn -e '/opt/sc/git' -e "$DC_DEV" -- "${dc_shipped[@]}" 2>/dev/null); then
        fail "a deployed artifact hardcodes a dev-tree or retired path - it belongs in .env"
        printf '%s\n' "$hits" | sed 's/^/        /' | head -8
    else
        pass "no deployed artifact names a dev-tree or retired path"
    fi

    # section 4.4 grep 1 - no shipped file names a source .env.
    if grep -RIn -e 'source/\.env' -- "${dc_shipped[@]}" 2>/dev/null | grep -q .; then
        fail "a shipped file names a source .env (that file is TEST-ONLY)"
    else pass "no shipped file names a source .env"; fi

    # section 4.4 grep 2 - nothing resolves .env relative to itself.
    if grep -RIn -e 'dirname.*\.env' -e '__file__.*\.env' -e 'BASH_SOURCE.*\.env' \
            -- "${dc_shipped[@]}" 2>/dev/null | grep -q .; then
        fail "a shipped file resolves .env relative to itself"
    else pass "nothing resolves .env relative to itself"; fi

    # section 4.4 grep 3 - a config reader goes through install.conf, or reads
    # nothing. secrets-admin takes the second branch: its data seams are its own
    # compiled constants, and install.sh's pre-flight 7b refuses when .env and
    # those constants disagree, so the two cannot silently diverge.
    dc_bad=""
    for h in "${HELPERS[@]}"; do
        hp="bin/$h"; [[ -e "$hp" ]] || hp="$h"
        grep -qE 'load_env|\.env\b' "$hp" 2>/dev/null || continue
        grep -q 'install\.conf' "$hp" || dc_bad+="$hp "
    done
    if [[ -n "$dc_bad" ]]; then fail "reads .env but never mentions install.conf: $dc_bad"
    else pass "every config reader goes through install.conf (or reads nothing)"; fi

    # section 4.1 - .envdefault must parse under the one grammar, and declare
    # every REQUIRED_ENV key.
    if [[ -f "$ENVDEFAULT" ]]; then
        if python3 - "$ENVDEFAULT" <<'PYGRAMMAR' 2>&1
import re, sys
path = sys.argv[1]
for n, raw in enumerate(open(path, encoding="utf-8"), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        sys.exit("%s:%d: not KEY=VALUE" % (path, n))
    k, v = (x.strip() for x in line.split("=", 1))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
        sys.exit("%s:%d: bad key %r" % (path, n, k))
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    if any(c in v for c in "$`"):
        sys.exit("%s:%d: %s contains $ or ` (no interpolation, section 4.1)" % (path, n, k))
PYGRAMMAR
        then pass "$ENVDEFAULT parses under the section 4.1 grammar"
        else fail "$ENVDEFAULT violates the section 4.1 grammar"; fi

        dc_missing=""
        for k in "${REQUIRED_ENV[@]}"; do
            grep -qE "^[[:space:]]*$k=" "$ENVDEFAULT" || dc_missing+="$k "
        done
        if [[ -n "$dc_missing" ]]; then fail "$ENVDEFAULT does not declare REQUIRED_ENV: $dc_missing"
        else pass "$ENVDEFAULT declares all ${#REQUIRED_ENV[@]} REQUIRED_ENV key(s)"; fi

        # section 4.2 - A DEPLOYED .env MUST NEVER CONTAIN A SECRET. This is
        # what makes mode 0644 safe rather than merely convenient, and in a
        # project whose entire job is passphrases it is the ban that matters
        # most. Checked on the committed default, because that is what a fresh
        # deploy copies.
        dc_leak=""
        while IFS='=' read -r k v; do
            [[ "$k" =~ (PASS|PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PASSPHRASE) ]] || continue
            [[ "$k" =~ _(FILE|PATH|DIR|NAME|ID)$ ]] && continue
            [[ -z "$v" ]] && continue
            dc_leak+="$k "
        done < <(grep -v '^[[:space:]]*#' "$ENVDEFAULT" | grep '=' || true)
        if [[ -n "$dc_leak" ]]; then fail "$ENVDEFAULT holds a secret-shaped VALUE: $dc_leak"
        else pass "$ENVDEFAULT holds no secret-shaped value"; fi
    else fail "$ENVDEFAULT is missing - section 5 requires one wherever etcdefaults/ exists"; fi

    # section 8.4 - a Cockpit condition may test only paths this project's own
    # install.sh creates. An unmet condition makes the package SILENTLY ABSENT:
    # no page, no menu entry, no error anywhere the operator will look. A
    # missing sibling must produce an in-page diagnosis naming the file and the
    # .env key, never a disappearance.
    if [[ -f manifest.json ]]; then
        if python3 - manifest.json "${HELPERS[@]}" <<'PYCOND'
import json, sys
m = json.load(open(sys.argv[1]))
allowed = {"/usr/local/sbin/%s" % h for h in sys.argv[2:]}
for c in m.get("conditions", []):
    p = c.get("path-exists") if isinstance(c, dict) else None
    if p and p not in allowed:
        sys.exit("condition tests %s, which install.sh does not create" % p)
PYCOND
        then pass "section 8.4 manifest conditions test only what install.sh creates"
        else fail "section 8.4 a manifest condition tests a path install.sh does not create"; fi
    fi

    # section 2.4 - the recursive-removal ban. rm -rf on a path that is a
    # symlink into the checkout, with one trailing slash, deletes the checkout.
    # install.sh must contain NO recursion at all; deploy.sh gets exactly two -
    # the $NEW.tmp staging dir it just created, and remove_old_payload, which
    # asserts three times against a $ROOT_REAL resolved once.
    # Heredoc bodies are TEXT PRINTED TO THE OPERATOR, not commands this script
    # runs, and install.sh's uninstall notice legitimately shows the operator
    # the `rm -rf` they would type by hand to remove their own data. Stripping
    # heredoc bodies before the scan makes this check MORE precise rather than
    # excusing a pattern - an exception list would have had to grow every time
    # the advice was reworded, and a check with an exception list is a check
    # with a blind spot.
    strip_heredocs() {
        awk '
            inhere { if ($0 == term || $0 == "\t" term) inhere = 0; next }
            {
                line = $0
                if (match(line, /<<-?[[:space:]]*'\''?"?[A-Za-z_][A-Za-z0-9_]*'\''?"?/)) {
                    t = substr(line, RSTART, RLENGTH)
                    gsub(/^<<-?[[:space:]]*/, "", t); gsub(/['\''"]/, "", t)
                    term = t; inhere = 1
                }
                print NR ":" line
            }
        ' "$1"
    }
    dc_off=""
    for sf in install.sh deploy.sh; do
        [[ -f "$sf" ]] || continue
        while IFS= read -r line; do dc_off+="$sf: $line"$'\n'; done \
            < <(strip_heredocs "$sf" \
                | grep -E 'rm[[:space:]]+-[a-zA-Z]*r|find[[:space:]].*-delete|rsync.*--delete' \
                | grep -vE '^[0-9]+:[[:space:]]*#' \
                | { if [[ "$sf" == deploy.sh ]]; then grep -vE 'rm -rf -- "\$NEW\.tmp"|rm -rf -- "\$real"'; else cat; fi; })
    done
    if [[ -n "$dc_off" ]]; then
        fail "a recursive removal outside remove_old_payload"
        printf '%s' "$dc_off" | sed 's/^/        /' | head -6
    else pass "no recursive removal outside remove_old_payload"; fi

    # section 6.1 - neither script may touch cockpit.socket (Cockpit is live on
    # this host), and install.sh may never enable or start a unit. Matched on a
    # COMMAND, not a comment: both scripts say in prose that they leave it
    # alone, and a check that cannot tell prose from a systemctl call is a check
    # that gets disabled.
    if grep -RIn 'cockpit\.socket' install.sh deploy.sh 2>/dev/null \
            | grep -E 'systemctl|service |systemd-run' | grep -q .; then
        fail "install.sh or deploy.sh acts on cockpit.socket"
    else pass "neither script touches cockpit.socket"; fi

    if grep -nE '^[^#]*systemctl( --user)? (enable|start|restart)' install.sh | grep -q .; then
        fail "install.sh enables or starts a unit - that is deploy.sh's, behind a flag"
    else pass "install.sh never enables or starts a unit"; fi

    # section 0 - install.sh LINKS the payload; it never copies it. A page file
    # arriving by `install` rather than `ln` is the old model coming back.
    if grep -nE '^[^#]*install .*-m 0644 .*\$SRC/\$f' install.sh | grep -q .; then
        fail "install.sh copies a page file instead of linking it"
    else pass "install.sh links the payload rather than copying it"; fi
fi

# ------------------------------------------------------------ unit tests ----
head_ "Unit tests"
if compgen -G "tests/test_*.py" >/dev/null; then
    if timeout 70 python3 -m unittest discover -s tests -p 'test_*.py' -q 2>&1 | tail -20
    then pass "unittest suite"; else fail "unittest suite"; fi
else
    skip "no tests/test_*.py yet"
fi

printf '\n'
((rc)) && printf '\033[31mvalidate.sh: FAILED\033[0m\n' || printf '\033[32mvalidate.sh: OK\033[0m\n'
exit $rc
