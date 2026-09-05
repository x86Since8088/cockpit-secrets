#!/usr/bin/env bash
#
# run-live.sh - drive the INSTALLED cockpit-secrets page in a real browser
#               against this host's live Cockpit.
#
#   ./tests/browser/run-live.sh
#   SECRETS_LIVE_CREDS=/run/user/1000/cs-live ./tests/browser/run-live.sh
#   SECRETS_LIVE_HEADED=1 ./tests/browser/run-live.sh      # watch it happen
#
# This is the only suite in the package that needs the software INSTALLED and
# Cockpit RUNNING. tests/browser/ui.spec.js stubs the bridge and needs neither;
# tests/integration/ drives the helper and never opens a browser. What is left
# over - the real Content-Security-Policy, superuser:"require" actually being
# honoured, Cockpit's own escalation dialog, and a refusal that survives being
# driven from the console - only exists here.
#
# WHAT IT WILL NOT DO, AND WHY EACH ONE MATTERS
#
#   - It never stops, starts, restarts or reloads cockpit.socket. Cockpit is a
#     live system service on this host and the operator may be logged in to it
#     while this runs.
#   - It never uses sudo and never submits a root job. Everything it needs from
#     root - the package, the helper, the registry - is a PRECONDITION it checks
#     and reports on, not something it installs for itself.
#   - It never puts a passphrase or an account password on a command line or in
#     the environment (I10). Credentials are 0600 files in a directory, and only
#     the DIRECTORY's path travels in the environment.
#   - It never guesses a password and never resets an account. A credential it
#     cannot read is a NOT-ATTEMPTED with the path it looked at, because five
#     wrong unlock attempts lock a safe out (I16) and a reset would destroy the
#     account another suite depends on.
#
# THE CREDENTIALS DIRECTORY. Mode 0700, one file per name, mode 0600:
#
#   <dir>/cptestadm.pass          the admin principal's Cockpit password
#   <dir>/cptest.pass             the non-admin principal's Cockpit password
#   <dir>/safe-<registry id>.pass the master passphrase for that safe
#
# Everything absent from it is reported NOT-ATTEMPTED with the file name that
# was missing, so the gap is a fact rather than a silence.
#
# EXIT STATUS. 0 when every attempted assertion held - including a run where
# nothing could be attempted, which prints its reasons. 1 when an assertion
# failed. A missing precondition is not a failure and is not a pass; it is a
# stated reason, and the console output is the report.
#
# There is no `set -x` in this tree (I15). A traced shell would put a
# credentials path and every argument it sees into whatever log caught it.
set -Eeuo pipefail

# EVERY FILE THIS SUITE CREATES IS PRIVATE BEFORE IT EXISTS.
#
# The artefacts include a screenshot taken deliberately between "Reveal" and
# the countdown ending — i.e. a picture of an unmasked password — and the
# decrypted body of a downloaded attachment. Those two were written by
# Playwright, which has no mode option on `page.screenshot()` or
# `download.saveAs()`, so they landed under this host's 0002 umask as
# -rw-rw-r-- on an SMB-exported tree while the harmless console log was 0600.
# live-harness.js now chmods each artefact as it is written; this line is the
# belt to that brace, and it is what covers a writer nobody remembered to route
# through the helper.
umask 077

HERE="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"
SRC="$(cd -- "$HERE/../.." && pwd)"
ART="$HERE/artifacts"

COCKPIT_URL="${COCKPIT_URL:-https://localhost:9090}"
SECRETS_LIVE_CREDS="${SECRETS_LIVE_CREDS:-${XDG_RUNTIME_DIR:-/tmp}/cockpit-secrets-live}"
export COCKPIT_URL SECRETS_LIVE_CREDS

note() { printf '  %s\n' "$*"; }
head() { printf '\n\033[1m%s\033[0m\n' "$*"; }

head "cockpit-secrets - live browser suite"
note "source      $SRC"
note "cockpit     $COCKPIT_URL"
note "credentials $SECRETS_LIVE_CREDS"
note "artifacts   $ART"

mkdir -p "$ART"

# ---------------------------------------------------------------- node ------
if ! command -v node >/dev/null 2>&1; then
    head "SKIPPED"
    note "node is not on PATH. docs/HOST-FACTS.md records node v22 on this host;"
    note "if it has moved, put it on PATH and run again."
    exit 0
fi
note "node        $(node --version)"

# ------------------------------------------------------- playwright ---------
# Resolved exactly the way the harness resolves it, so a SKIP here and a SKIP
# there cannot disagree about whether it is installed.
PW_FOUND="$(node -e '
const p=[process.env.PLAYWRIGHT_PATH,"playwright",
         "/opt/sc/edy-local/e2e/node_modules/playwright"].filter(Boolean);
for (const c of p) { try { require.resolve(c); console.log(c); process.exit(0); } catch(e){} }
process.exit(1)' 2>/dev/null || true)"
if [[ -z $PW_FOUND ]]; then
    head "SKIPPED"
    note "Playwright is not resolvable. It is deliberately not a dependency of this"
    note "package (node_modules/ is git-ignored); point PLAYWRIGHT_PATH at an install."
    exit 0
fi
note "playwright  $PW_FOUND"

# ------------------------------------------------------- preconditions ------
# Reported, never repaired. Installing is root work and belongs to whoever owns
# it; this suite's job is to say plainly that it has not happened.
MISSING=0
for p in /usr/local/sbin/secrets-admin /usr/share/cockpit/secrets /etc/cockpit-secrets/safes.d; do
    if [[ -e $p ]]; then note "present     $p"; else note "MISSING     $p"; MISSING=1; fi
done

if ! curl -sk -o /dev/null --max-time 10 "$COCKPIT_URL/" ; then
    head "SKIPPED"
    note "$COCKPIT_URL did not answer. Cockpit is a live system service here and this"
    note "suite will not start it - check it with 'systemctl status cockpit.socket'."
    exit 0
fi
note "cockpit     answering at $COCKPIT_URL"

if [[ -d $SECRETS_LIVE_CREDS ]]; then
    # Names only. Never a value, and never a size that would hint at one.
    note "credentials $(find "$SECRETS_LIVE_CREDS" -maxdepth 1 -name '*.pass' -printf '%f ' 2>/dev/null || true)"
else
    note "credentials directory does not exist - every item that needs one will be"
    note "            reported NOT-ATTEMPTED with the file name it looked for."
fi

if (( MISSING )); then
    head "PRECONDITION NOT MET"
    note "cockpit-secrets is not installed on this host, so there is no page to drive."
    note "The suites below still run: they report every item NOT-ATTEMPTED, with the"
    note "reason, which is the honest result and not a green line."
fi

# ------------------------------------------------------------- the run ------
rc=0
# live-registry.spec.js is FIRST on purpose: it creates the two safes it needs,
# uses them, and destroys them again, so it must not run against a page another
# spec has left mid-session. It is also the only spec that WRITES to the host —
# into the signed-in account's own home, never /etc — and running it first means
# a failure there is reported before two suites of unrelated output.
for spec in live-registry.spec.js live-ui.spec.js live-access.spec.js; do
    head "running $spec"
    if node "$HERE/$spec"; then :; else rc=1; fi
done

head "artifacts"
if compgen -G "$ART/*" >/dev/null; then
    ls -1 "$ART" | sed 's/^/  /'
else
    note "(none written)"
fi

head "done"
note "exit $rc"
exit "$rc"
