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
