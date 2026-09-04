#!/usr/bin/env bash
#
# run_tests.sh — the FULL suite. `validate.sh` is the fast standing gate the
# orchestrator runs and kills at 120 s; this is the one a human runs before
# believing anything.
#
#   ./run_tests.sh              # everything that needs no network and no root
#   ./run_tests.sh --quick      # skip the corpus and the oracles (~90 s)
#   ./run_tests.sh --list       # print the stages and exit
#
# Deliberately NOT here, and why:
#
#   * anything needing root. The admin access class is only ever exercised from
#     the refusing side; euid 0 needs the /srv/jobs runner. Stated in the
#     summary rather than skipped silently.
#   * the Playwright browser drivers. They need a chromium and a node_modules
#     that are not part of this package; the summary says so.
#   * `tests/fixtures/gen_fixtures.sh --build --force`, which REWRITES the
#     committed fixtures. The verify-only form runs.
#
# No `set -x` anywhere: /srv/jobs logs are group-readable and a traced shell
# prints every argument (I15).
#
set -u
cd "$(dirname "$0")" || exit 1

QUICK=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --list)  sed -n 's/^run  *"\([^"]*\)".*/  \1/p' "$0"; exit 0 ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'run_tests.sh: unknown option %s\n' "$arg" >&2; exit 2 ;;
    esac
done

rc=0
declare -a NAMES=() RESULTS=() TIMES=()

run() {   # run <name> <timeout-seconds> <command...>
    local name="$1" limit="$2"; shift 2
    printf '\n\033[1m========== %s\033[0m\n' "$name"
    local t0 t1 status
    t0=$(date +%s)
    if timeout "$limit" "$@"; then status="PASS"; else status="FAIL"; rc=1; fi
    t1=$(date +%s)
    NAMES+=("$name"); RESULTS+=("$status"); TIMES+=("$((t1 - t0))s")
    printf '\033[%sm%s\033[0m  %s (%ss)\n' \
        "$([[ $status == PASS ]] && echo 32 || echo 31)" "$status" \
        "$name" "$((t1 - t0))"
}

skip() {
    printf '\n\033[2m========== %s — skipped: %s\033[0m\n' "$1" "$2"
    NAMES+=("$1"); RESULTS+=("skip"); TIMES+=("-")
}

# ------------------------------------------------------------ the gates ----
run "syntax and standing bans (validate.sh)"  180 ./validate.sh
run "javascript syntax (check.sh)"             60 ./check.sh

# ------------------------------------------------- the unit self-checks ----
run "backends/base.py self-check"             180 python3 backends/base.py
run "backends/psafe3 self-check"              180 python3 -m backends.psafe3
run "twofish ECB vectors, both providers"     180 python3 - <<'PY'
import binascii, json, sys
sys.path.insert(0, ".")
from backends import psafe3
v = json.load(open("tests/vectors/twofish_ecb.json"))
bad = 0
for provider in ("botan", "pure"):
    psafe3.set_twofish_provider(provider)
    n = 0
    for row in v["vectors"]:
        k = binascii.unhexlify(row["key"])
        pt = binascii.unhexlify(row["pt"])
        ct = binascii.unhexlify(row["ct"])
        n += psafe3._ecb_encrypt(k, pt) != ct
        n += psafe3._ecb_decrypt(k, ct) != pt
    print("  %-6s %d vectors, %d failure(s)" % (provider, v["count"], n))
    bad += n
psafe3.set_twofish_provider(None)
sys.exit(1 if bad else 0)
PY

# ------------------------------------------------------- the integration ---
# These drive the REAL helper against the REAL fixtures. See
# tests/integration/README.md for what each one covers and why.
run "integration: contract flow, both formats" 300 \
    python3 tests/integration/flow.py
run "integration: cross-backend conformance"   300 \
    python3 tests/integration/conformance.py
run "integration: load-bearing properties"     600 \
    python3 tests/integration/properties.py

if ((QUICK)); then
    skip "integration: corpus vs the helper" "--quick"
    skip "oracles: build and known-answer vectors" "--quick"
    skip "fixtures: verify against keepassxc-cli" "--quick"
else
    if [[ -f tests/corpus/files/index.json ]]; then
        run "integration: corpus vs the helper"  600 \
            python3 tests/integration/corpus_vs_helper.py
    else
        skip "integration: corpus vs the helper" \
             "no corpus built — tests/corpus/gen_corpus.py --build"
    fi
    if command -v go >/dev/null 2>&1; then
        run "oracles: build and known-answer vectors" 300 \
            bash tests/oracle/build.sh
    else
        skip "oracles: build and known-answer vectors" "go is not installed"
    fi
    if command -v keepassxc-cli >/dev/null 2>&1; then
        run "fixtures: verify against keepassxc-cli" 300 \
            bash tests/fixtures/gen_fixtures.sh
    else
        skip "fixtures: verify against keepassxc-cli" \
             "keepassxc-cli is not installed (it is the TEST-ONLY oracle; it "\
"must never appear in a runtime path)"
    fi
fi

# ------------------------------------------------------------- summary -----
printf '\n\033[1m========== summary\033[0m\n'
for i in "${!NAMES[@]}"; do
    case "${RESULTS[$i]}" in
        PASS) printf '  \033[32mPASS\033[0m  %-46s %6s\n' "${NAMES[$i]}" "${TIMES[$i]}" ;;
        FAIL) printf '  \033[31mFAIL\033[0m  %-46s %6s\n' "${NAMES[$i]}" "${TIMES[$i]}" ;;
        *)    printf '  \033[2mskip\033[0m  %-46s\n' "${NAMES[$i]}" ;;
    esac
done

cat <<'EOF'

Not covered by this script, and not claimed to be:
  * euid 0 / the admin access class from the ALLOWED side. Everything here runs
    unescalated, so `access: "admin"` is only ever proved to REFUSE. Use the
    /srv/jobs runner for the other half.
  * the page under a real Cockpit bridge. The browser drivers stub
    cockpit.spawn, so `superuser: "require"` has never been exercised for real.
  * a .psafe3 written by the actual Password Safe GUI. There is no Password
    Safe CLI packaged on this host, so I19 stays partially open for PWS3 —
    tests/fixtures/README.md has the table of what does and does not
    compensate.
EOF

((rc)) && printf '\n\033[31mrun_tests.sh: FAILED\033[0m\n' \
       || printf '\n\033[32mrun_tests.sh: OK\033[0m\n'
exit $rc
