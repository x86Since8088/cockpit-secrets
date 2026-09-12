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
#   * `tests/fixtures/gen_fixtures.sh --build --force`, which REWRITES the
#     committed fixtures. The verify-only form runs.
#
# The Playwright browser driver IS here now (`tests/browser/ui.spec.js`). It
# needs a chromium and a node_modules that are not part of this package, so it
# resolves them from the host and reports a SKIP with the reason when it cannot
# find them — the one stage that is allowed to decide for itself whether it can
# run.
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
        --list)  sed -n 's/^[[:space:]]*run  *"\([^"]*\)".*/  \1/p' "$0"; exit 0 ;;
        -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
run "backends/kdbx self-check"                180 python3 -m backends.kdbx
run "agent self-check"                        180 python3 agent/secrets_agent.py --selfcheck
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
run "integration: the second-wave verbs"       900 \
    python3 tests/integration/newverbs.py
# 300 s was the budget before this file measured the SESSION idle timer, which
# it can only do by being quiet for longer than one — and then quiet again for
# the absolute bound, and again for a registry revocation to be noticed. Nearly
# all of the added time is a deliberate sleep on an open pipe; shortening it
# would measure a different program, in the same way the lockout ladder below
# would.
run "integration: the unlock agent, end to end" 900 \
    python3 tests/integration/agent_cycle.py
# I16's counter under concurrency (I39) and across principals (I40). It spawns
# 50 helper processes at once and then waits out the real 2/4/8/16 s backoff
# ladder to open the hard window, so it is a minute of wall clock and almost
# all of that is sleeping on purpose: shortening the ladder would measure a
# different program.
run "integration: the lockout — concurrency, identity, reach" 600 \
    python3 tests/integration/lockout.py
# The confirmed adversarial findings, at the layer only the real helper can
# reach: a request frame, a backup ring several processes have taken turns
# with, an export artefact on disk. The per-cause guards for the same findings
# are unit tests in tests/test_regressions.py, which validate.sh runs.
run "integration: the adversarial findings"    600 \
    python3 tests/integration/adversarial.py
# The registry WRITE path: the twelve defects the 0.4.0 red-team round found in
# safe-create / safe-import / safe-forget / safe-delete, each one driven against
# the real helper with a per-user registry the caller can write. Every check in
# it goes red when its fix is reverted; the greppable half of the same guards is
# in validate.sh.
run "integration: the registry write path"     900 \
    python3 tests/integration/registry_writes.py

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
    # The page's own driver. It resolves Playwright from $PLAYWRIGHT_PATH, the
    # normal module path, or this host's shared copy, and SKIPS with a stated
    # reason if it finds none — so on a machine without one it reports that it
    # did not run rather than passing. That is why it is a `run` and not
    # guarded by a `command -v` here: the script itself is the better judge of
    # whether it can run, and it says so.
    if command -v node >/dev/null 2>&1; then
        run "ui: headless browser driver"       600 \
            node tests/browser/ui.spec.js
        # The ORACLE behind the live suite's I11 item, checked without a
        # browser. The live suite itself cannot run here (it needs Cockpit, an
        # account password and a registered safe), but the logic that decides
        # what counts as "this page stored something" can, and it is the piece
        # that was silently wrong once already (I42). It also asserts the
        # tolerated-key list has not grown.
        run "ui: item 4's storage oracle (I11, I42)"  60 \
            node tests/browser/storage-check.selftest.js
    else
        skip "ui: headless browser driver" "node is not installed"
        skip "ui: item 4's storage oracle (I11, I42)" "node is not installed"
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
  * the admin access class against a ROOT-OWNED registry. newverbs.py does run
    the export allow-path at a real euid 0, inside `unshare --map-root-user`,
    which exercises the euid-0 branch of gate() for real — but inside that
    namespace the caller's REAL uid is 0 too, so the SUDO_UID/group-membership
    branch is correctly skipped rather than tested. That half, and a registry
    genuinely owned by root, need the /srv/jobs runner.
  * the page under a real Cockpit bridge. The browser driver stubs
    cockpit.spawn, so `superuser: "require"` has never been exercised for real.
  * a real YubiKey. The challenge/response arithmetic has unit vectors; no
    token has ever answered one.
  * a .psafe3 written by the actual Password Safe GUI. There is no Password
    Safe CLI packaged on this host, so I19 stays partially open for PWS3 —
    tests/fixtures/README.md has the table of what does and does not
    compensate.
EOF

((rc)) && printf '\n\033[31mrun_tests.sh: FAILED\033[0m\n' \
       || printf '\n\033[32mrun_tests.sh: OK\033[0m\n'
exit $rc
