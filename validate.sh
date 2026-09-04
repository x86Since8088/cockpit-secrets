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

for f in manifest.json etcdefaults/*.json tests/fixtures/*.json; do
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
