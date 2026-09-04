#!/bin/bash
#
# 10-install.sh - install cockpit-secrets on the real host, as root.
#
# This is the first thing in this program that has ever run as root. It does
# exactly one privileged thing - run install.sh - and records the two facts the
# rest of the suite needs from it: the installer's own exit status, and proof
# that cockpit.socket was not disturbed.
#
# COCKPIT IS A LIVE SERVICE ON THIS HOST AND IS NEVER RESTARTED, reloaded or
# stopped by anything in this directory. Cockpit rescans /usr/share/cockpit on
# the next page load, so a restart would buy nothing and cost every open
# session on edt1.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "10 - install cockpit-secrets as root"
cs_note "euid=$(id -u) source=$CS_SRC"

# ---------------------------------------------------------------------------
# Cockpit's state BEFORE, recorded where job 20 can compare it. `systemctl
# show` reads; it does not act.
# ---------------------------------------------------------------------------
cs_rundir
systemctl show cockpit.socket -p ActiveEnterTimestamp -p InvocationID -p SubState \
    > "$CS_RUNDIR/cockpit-socket.before" 2>&1
chmod 0600 "$CS_RUNDIR/cockpit-socket.before"
cs_note "cockpit.socket before: $(tr '\n' ' ' < "$CS_RUNDIR/cockpit-socket.before")"

cs_sect "pre-flight"
[[ -x $CS_SRC/install.sh ]] && cs_ok "install.sh is present and executable" \
                            || cs_no "install.sh is present and executable"
cs_eq "running as root" "0" "$(id -u)"

# A re-run is legal: install.sh is idempotent and reports `unchanged`. Say which
# case this is, because "0 changes" reads like a failure if you expected a
# fresh install.
if [[ -e $CS_HELPER ]]; then
    cs_note "NOTE: $CS_HELPER already exists; this run is a re-install"
else
    cs_note "clean host: $CS_HELPER does not exist yet"
fi

# ---------------------------------------------------------------------------
# The install itself. Output is kept so the summary can be examined for the
# installer's own warnings; it contains paths and modes, never file contents -
# install.sh explicitly never prints the contents of anything.
# ---------------------------------------------------------------------------
cs_sect "install.sh"
log="$CS_RUNDIR/install.out"
"$CS_SRC/install.sh" > "$log" 2>&1
rc=$?
chmod 0600 "$log"
sed 's/^/     | /' "$log"

cs_eq "install.sh exit status" "0" "$rc"

# install.sh routes everything it wants an operator to act on through warn(),
# which prefixes '  ! '. On a clean host there should be none; one here is a
# real finding (a directory that is already too loose, a unit pointing at a
# missing binary) and must not scroll past.
warncount="$(grep -c '^  ! ' "$log" || true)"
cs_eq "install.sh raised no 'Action required' warnings" "0" "$warncount"
if ((warncount)); then grep '^  ! ' "$log" | sed 's/^/     /'; fi

cs_check "install.sh reported the smoke test" \
    grep -q 'secrets-admin health: one JSON object, exit 0' "$log"
cs_check "install.sh reported backends import from the runtime lib root" \
    grep -q "backends import from $CS_LIBDIR" "$log"

# ---------------------------------------------------------------------------
# Cockpit AFTER. Same two properties, compared immediately - job 20 compares
# them again after a gap, which is the more interesting of the two.
# ---------------------------------------------------------------------------
cs_sect "cockpit.socket was not disturbed"
systemctl show cockpit.socket -p ActiveEnterTimestamp -p InvocationID -p SubState \
    > "$CS_RUNDIR/cockpit-socket.after" 2>&1
chmod 0600 "$CS_RUNDIR/cockpit-socket.after"
if diff -q "$CS_RUNDIR/cockpit-socket.before" "$CS_RUNDIR/cockpit-socket.after" >/dev/null; then
    cs_ok "cockpit.socket ActiveEnterTimestamp/InvocationID unchanged across the install"
else
    cs_no "cockpit.socket changed across the install"
    diff "$CS_RUNDIR/cockpit-socket.before" "$CS_RUNDIR/cockpit-socket.after" | sed 's/^/     /'
fi

cs_finish
