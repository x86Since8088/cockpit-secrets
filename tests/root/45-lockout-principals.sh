#!/bin/bash
#
# 45-lockout-principals.sh - I40: two administrators, two lockout counters.
#
# A thin wrapper, the same shape as 40-admin-allow.sh. Everything interesting
# is in driver_lockout.py, because all of it is talking JSON to the helper as
# two different escalated operators and comparing structures.
#
# It is SEPARATE from 40 on purpose. 40 measures the backoff LADDER, which
# costs 2+4+8+16 seconds of real waiting and needs a counter it owns from the
# first check to the last; this measures which PRINCIPAL a counter belongs to,
# and starts by wiping that state. Interleaving the two would make each one's
# failures look like the other's.
#
# Preconditions are refused rather than worked around: a driver that ran with
# no passphrase file, or without the throwaway admin safe 30 builds, would
# produce a page of red that says nothing about the program.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "45 - preconditions"
cs_eq "running as root" "0" "$(id -u)"
[[ -x $CS_HELPER ]] && cs_ok "$CS_HELPER is installed" || cs_no "$CS_HELPER is installed"
[[ -f $CS_ADMIN_SAFE ]] && cs_ok "the throwaway admin safe exists" || cs_no "the throwaway admin safe exists"
[[ -d $CS_STATE ]] && cs_ok "$CS_STATE exists" || cs_no "$CS_STATE exists"

# Both operators must really be in an administrative group, or check 2 would
# pass for the wrong reason: a B who is refused by the CLASS GATE also fails to
# be locked out, and the report would read like a fix.
for uid in "$CS_UID_CPADMIN" "$CS_UID_CPTESTADM"; do
    user="$(getent passwd "$uid" | cut -d: -f1)"
    if [[ -n $user ]] && id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
        cs_ok "uid $uid ($user) is in sudo"
    else
        cs_no "uid $uid is in sudo" "${user:-no such account}"
    fi
done
# …and the control principal must really NOT be, for section 5.
user="$(getent passwd "$CS_UID_CPTEST" | cut -d: -f1)"
if [[ -n $user ]] && ! id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
    cs_ok "uid $CS_UID_CPTEST ($user) is NOT in sudo"
else
    cs_no "uid $CS_UID_CPTEST is not in sudo" "${user:-no such account}"
fi

cs_pw_require || { cs_no "the throwaway passphrase file is present and 0600"; cs_finish; exit 1; }
cs_ok "the throwaway passphrase file is present and 0600"
cs_finish || exit 1

# The driver owns its own report and exit status; this script's status is the
# driver's.
exec python3 "$JOBDIR/driver_lockout.py"
