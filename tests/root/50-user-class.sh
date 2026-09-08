#!/bin/bash
#
# 50-user-class.sh - the USER class on the real host, driven as cptest.
#
# The job runs as root; the driver does not. `runuser` drops to cptest with no
# escalation available at all, which is what makes the refusals in
# driver_user.py mean something: they are the kernel's answers and the helper's
# own gate, not a browser hiding a button (I3).
#
# THE PASSPHRASE IS PIPED, NOT SHARED. Root reads the 0600 file and writes the
# value to the driver's stdin; cptest never gets a path to it and cannot even
# list the directory it lives in - which driver_user.py asserts rather than
# assumes. The value never reaches argv, an environment variable or a file
# cptest can open (I10).
#
# `cd /` before runuser is load-bearing: the job's working directory is its
# outbox folder, mode 0770 root:users, and cptest is not in `users`, so a child
# inheriting that cwd fails to start for a reason that has nothing to do with
# this program.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "50 - preconditions"
cs_eq "running as root (the driver will not be)" "0" "$(id -u)"
cs_eq "cptest exists with the expected uid" "$CS_UID_CPTEST" "$(id -u cptest 2>/dev/null)"
if id -nG cptest 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
    cs_no "cptest is NOT in the sudo group"
else
    cs_ok "cptest is NOT in the sudo group" "$(id -nG cptest | tr ' ' ',')"
fi
[[ -f $CS_USER_SAFE ]] && cs_ok "the throwaway user safe exists" || cs_no "the throwaway user safe exists"
cs_pw_require || { cs_no "the throwaway passphrase file is present and 0600"; cs_finish; exit 1; }
cs_ok "the throwaway passphrase file is present and 0600"

# The driver has to be readable and executable by cptest, and the job directory
# is not. A 0755 directory on tmpfs is the smallest thing that works; the
# passphrase stays in the 0700 one and is piped instead.
cs_pubdir
install -m 0644 "$JOBDIR/driver_user.py" "$CS_PUBDIR/driver_user.py"
install -m 0644 "$JOBDIR/checklib.py"    "$CS_PUBDIR/checklib.py"
cs_mode "$CS_PUBDIR" 755 root:root
cs_mode "$CS_PUBDIR/driver_user.py" 644 root:root
cs_finish || exit 1

# ---------------------------------------------------------------------------
# hand the passphrase to cptest on a PIPE and nothing else
# ---------------------------------------------------------------------------
cat "$CS_PWFILE" \
    | runuser -u cptest -- env -i \
        HOME=/home/cptest USER=cptest LOGNAME=cptest \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LANG=C.UTF-8 \
        python3 "$CS_PUBDIR/driver_user.py"
rc=${PIPESTATUS[1]}

rm -f "$CS_PUBDIR/driver_user.py" "$CS_PUBDIR/checklib.py"
rmdir "$CS_PUBDIR" 2>/dev/null

printf '\ndriver_user.py exited %d\n' "$rc"
exit "$rc"
