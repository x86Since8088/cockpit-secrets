#!/bin/bash
#
# 40-admin-allow.sh - the ADMIN class from the ALLOWING side, as euid 0.
#
# A thin wrapper. Everything interesting is in driver_admin.py, because all of
# it is talking JSON to the helper and comparing structures, which shell is bad
# at and would do less carefully.
#
# What the wrapper itself is for: refusing to run at all unless the
# preconditions hold. A driver that ran with no passphrase file, or as the
# wrong uid, would produce a page of red that says nothing about the program.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "40 - preconditions"
cs_eq "running as root" "0" "$(id -u)"
[[ -x $CS_HELPER ]] && cs_ok "$CS_HELPER is installed" || cs_no "$CS_HELPER is installed"
[[ -f $CS_ADMIN_SAFE ]] && cs_ok "the throwaway admin safe exists" || cs_no "the throwaway admin safe exists"
cs_pw_require || { cs_no "the throwaway passphrase file is present and 0600"; cs_finish; exit 1; }
cs_ok "the throwaway passphrase file is present and 0600"
cs_finish || exit 1

# The driver owns its own report and exit status; this script's status is the
# driver's.
exec python3 "$JOBDIR/driver_admin.py"
