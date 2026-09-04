#!/usr/bin/env bash
#
# run-all.sh - submit the whole root verification suite, in order.
#
#   ./run-all.sh              # everything, 10 -> 90
#   ./run-all.sh 40 50        # just those steps
#
# Runs UNPRIVILEGED. Each step is a separate job, submitted with --wait, so the
# steps are serialised and each one's output.log is printed as it finishes.
#
# The steps are ORDERED and stateful: 30 mints the passphrase and builds the
# subjects, 40 and 50 use them, 60 uninstalls and reinstalls around them, 90
# destroys them. Running 40 without 30 is refused by 40's own preconditions
# rather than producing a page of misleading red.
#
# A failing step does NOT stop the run. Steps 10-50 are measurements; stopping
# at the first red would leave the host half-configured with the throwaway
# subjects still in the live registry, and 90-cleanup.sh is the thing that must
# always get to run.
#
set -u
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# step -> timeout, in seconds. 40 is long because the lockout backoff is real
# time: 2+4+8+16 seconds of waiting is the property being measured, and
# shortening it would measure a different program.
declare -A TIMEOUT=(
    [10-install.sh]=600
    [20-verify-install.sh]=300
    [30-throwaway-safes.sh]=300
    [40-admin-allow.sh]=900
    [45-lockout-principals.sh]=300
    [50-user-class.sh]=300
    [60-uninstall-reinstall.sh]=600
    [90-cleanup.sh]=300
)
ORDER=(10-install.sh 20-verify-install.sh 30-throwaway-safes.sh
       40-admin-allow.sh 45-lockout-principals.sh 50-user-class.sh
       60-uninstall-reinstall.sh 90-cleanup.sh)

steps=()
if (($#)); then
    for want in "$@"; do
        for s in "${ORDER[@]}"; do [[ $s == "$want"* ]] && steps+=("$s"); done
    done
    ((${#steps[@]})) || { echo "no step matched: $*" >&2; exit 1; }
else
    steps=("${ORDER[@]}")
fi

results=()
rc_all=0
for s in "${steps[@]}"; do
    printf '\n########################################################################\n'
    printf '# %s\n' "$s"
    printf '########################################################################\n'
    "$HERE/submit.sh" --timeout "${TIMEOUT[$s]:-600}" "$s"
    rc=$?
    results+=("$(printf '%-28s exit %d' "$s" "$rc")")
    ((rc)) && rc_all=1
done

printf '\n========================================================================\n'
printf 'root verification suite\n'
printf '========================================================================\n'
printf '  %s\n' "${results[@]}"
exit "$rc_all"
