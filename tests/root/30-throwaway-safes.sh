#!/bin/bash
#
# 30-throwaway-safes.sh - create the throwaway safes and registry entries the
#                         rest of the suite exercises, under the REAL
#                         /etc/cockpit-secrets.
#
# Three registry entries, each of which exists to prove a different thing:
#
#   zz-throwaway-admin    OMITS the `access` key entirely. docs/KNOWN_ISSUES.md
#                         I1 says an entry with no `access` is ADMIN - the
#                         restrictive default - and the only honest way to test
#                         a default is to leave the key out. It also omits
#                         `groups`, so the gate falls back to the host's
#                         detected admin group, which is `sudo` here.
#   zz-throwaway-nogroup  the same file, admin class, with `groups` naming a
#                         group nobody is in. Proves the group gate is a real
#                         second condition and not decoration: euid 0 plus a
#                         real `sudo` member is still refused.
#   zz-throwaway-user     user class, owned by cptest, in cptest's own tree.
#
# EVERYTHING HERE IS THROWAWAY and 90-cleanup.sh removes it. The `zz-` prefix
# and the label are how an operator reading safes.d tells that at a glance,
# which matters because this is the live access-control policy directory.
#
# The passphrase is minted here into a 0600 file on tmpfs and is never printed;
# see rootlib.sh, "the passphrase".
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "30 - throwaway safes and registry entries"

[[ -x $CS_HELPER ]] || { echo "FATAL: $CS_HELPER is not installed; run 10-install.sh" >&2; exit 1; }

# ---------------------------------------------------------------------------
# the passphrase
# ---------------------------------------------------------------------------
cs_sect "passphrase"
cs_pw_new || exit 1
cs_pw_require || exit 1
cs_mode "$CS_RUNDIR" 700 root:root
cs_mode "$CS_PWFILE" 600 root:root
cs_note "a fresh passphrase was generated into $CS_PWFILE (tmpfs, 0600 in a 0700 root-owned dir)"
cs_note "it is never printed, never on argv, and 90-cleanup.sh destroys it"

# ---------------------------------------------------------------------------
# the admin-class safe: root-owned, 0600, inside the 0700 registry safes dir
# ---------------------------------------------------------------------------
cs_sect "admin-class safe"
rm -rf -- "$CS_ADMIN_SAFE" "$CS_ADMIN_SAFE.bak.d"
python3 "$JOBDIR/mkdb.py" "$CS_ADMIN_SAFE" "$CS_PWFILE" "$CS_ADMIN_ID" \
    || { cs_no "created $CS_ADMIN_SAFE"; cs_finish; exit 1; }
chown root:root "$CS_ADMIN_SAFE"
cs_mode "$CS_ADMIN_SAFE" 600 root:root

# ---------------------------------------------------------------------------
# the user-class safe: cptest's own file, in cptest's own tree
# ---------------------------------------------------------------------------
# Created by root and then chowned rather than created by cptest, so the
# passphrase file never has to be readable by cptest at all. The DIRECTORY is
# made cptest-owned and 0700 first: base.open_safe_fd walks the ancestry and
# refuses a safe under a group- or other-writable parent (I5), and a 0755 XDG
# directory would fail that check for a reason that has nothing to do with the
# safe itself.
cs_sect "user-class safe (cptest)"
udir="$(dirname -- "$CS_USER_SAFE")"
rm -rf -- "$CS_USER_SAFE" "$CS_USER_SAFE.bak.d"
install -d -o cptest -g cptest -m 0700 "$CS_USER_HOME/.local"
install -d -o cptest -g cptest -m 0700 "$CS_USER_HOME/.local/share"
install -d -o cptest -g cptest -m 0700 "$udir"
python3 "$JOBDIR/mkdb.py" "$CS_USER_SAFE" "$CS_PWFILE" "$CS_USER_ID" \
    || { cs_no "created $CS_USER_SAFE"; cs_finish; exit 1; }
chown cptest:cptest "$CS_USER_SAFE"
chmod 0600 "$CS_USER_SAFE"
cs_mode "$udir" 700 cptest:cptest
cs_mode "$CS_USER_SAFE" 600 cptest:cptest

# ---------------------------------------------------------------------------
# the registry entries
# ---------------------------------------------------------------------------
cs_sect "registry entries"
write_entry() {   # write_entry <file> <json>
    local dst="$1" body="$2"
    printf '%s\n' "$body" > "$dst"
    chown root:root "$dst"
    chmod 0644 "$dst"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$dst" \
        && cs_ok "wrote $dst" "$(stat -c '%a %U:%G' "$dst")" \
        || cs_no "wrote $dst" "not valid JSON"
}

# NOTE the missing "access": that omission IS the test (I1).
write_entry "$CS_SAFESD/90-$CS_ADMIN_ID.json" '{
 "id": "'"$CS_ADMIN_ID"'",
 "label": "THROWAWAY - tests/root admin class - delete me",
 "format": "kdbx",
 "path": "'"$CS_ADMIN_SAFE"'",
 "mode": "rw",
 "password_required": true,
 "backup": {"keep": 3, "dir": null}
}'

write_entry "$CS_SAFESD/91-$CS_ADMIN_NOGRP_ID.json" '{
 "id": "'"$CS_ADMIN_NOGRP_ID"'",
 "label": "THROWAWAY - tests/root admin class, unreachable group - delete me",
 "format": "kdbx",
 "path": "'"$CS_ADMIN_SAFE"'",
 "access": "admin",
 "groups": ["zzz-no-such-group"],
 "mode": "ro",
 "password_required": true
}'

write_entry "$CS_SAFESD/92-$CS_USER_ID.json" '{
 "id": "'"$CS_USER_ID"'",
 "label": "THROWAWAY - tests/root user class (cptest) - delete me",
 "format": "kdbx",
 "path": "'"$CS_USER_SAFE"'",
 "access": "user",
 "owner": "cptest",
 "mode": "rw",
 "password_required": true,
 "backup": {"keep": 3, "dir": null}
}'

# ---------------------------------------------------------------------------
# what the helper makes of them
# ---------------------------------------------------------------------------
cs_sect "the helper's view of the registry"
"$CS_HELPER" list > "$CS_RUNDIR/list.json" 2>/dev/null
rc=$?
chmod 0600 "$CS_RUNDIR/list.json"
cs_eq "secrets-admin list exit status" "0" "$rc"

python3 - "$CS_RUNDIR/list.json" "$CS_ADMIN_ID" "$CS_ADMIN_NOGRP_ID" "$CS_USER_ID" <<'CSLIST'
import json, sys
d = json.load(open(sys.argv[1]))
admin, nogrp, user = sys.argv[2], sys.argv[3], sys.argv[4]
by = {s["id"]: s for s in d.get("safes", [])}
bad = 0
def line(name, cond, extra=""):
    global bad
    print("  %-4s %s%s" % ("ok" if cond else "FAIL", name,
                           ("  -> " + str(extra)[:160]) if extra else ""))
    if not cond:
        bad = 1
line("registry_errors is 0", d.get("registry_errors") == 0, d.get("registry_errors"))
for sid in (admin, nogrp, user):
    line("%s is listed" % sid, sid in by)
# THE POINT OF THE MISSING KEY: an entry with no `access` must come back admin.
line("%s defaulted to access=admin with no `access` key (I1)" % admin,
     by.get(admin, {}).get("access") == "admin", by.get(admin, {}).get("access"))
line("%s is access=user" % user,
     by.get(user, {}).get("access") == "user", by.get(user, {}).get("access"))
line("%s is registered read-only" % nogrp,
     by.get(nogrp, {}).get("mode") == "ro", by.get(nogrp, {}).get("mode"))
line("every throwaway safe reports locked",
     all(by.get(s, {}).get("locked") is True for s in (admin, nogrp, user)))
sys.exit(bad)
CSLIST
if (($?)); then cs_no "registry list assertions"; else cs_ok "registry list assertions (7 sub-checks above)"; fi
rm -f "$CS_RUNDIR/list.json"

"$CS_HELPER" health 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
errs = d.get("registry_errors")
print("  %-4s health reports no registry errors  -> %s"
      % ("ok" if errs == [] else "FAIL", errs))
sys.exit(0 if errs == [] else 1)'
if (($?)); then cs_no "health registry_errors"; else cs_ok "health registry_errors"; fi

cs_finish
