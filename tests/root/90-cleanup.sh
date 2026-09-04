#!/bin/bash
#
# 90-cleanup.sh - remove everything this suite created, EXCEPT the package.
#
# What goes:
#   the three throwaway registry entries, the two throwaway safes and their
#   backup rings, cptest's state fallback directory, any lockout counter keyed
#   on a throwaway id, and the tmpfs passphrase.
#
# What stays, on purpose:
#   the installed package (the browser walkthrough needs it), the seeded
#   *.json.example files install.sh ships, and the audit log. The audit log
#   stays because it is the record of who opened what and install.sh's own
#   uninstall keeps it for that reason; it contains no value, and this script
#   ends by saying how many lines of it this run added.
#
# The removals are by exact path, never by glob into a shared directory. A
# wildcard in /etc/cockpit-secrets/safes.d is how you delete an operator's real
# access-control policy while cleaning up a test.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "90 - remove the throwaway subjects"


cs_sect "registry entries"
for f in "$CS_SAFESD/90-$CS_ADMIN_ID.json" \
         "$CS_SAFESD/91-$CS_ADMIN_NOGRP_ID.json" \
         "$CS_SAFESD/92-$CS_USER_ID.json"; do
    if [[ -e $f ]]; then rm -f -- "$f"; cs_ok "removed $f"
    else cs_skip "not present: $f"; fi
done

cs_sect "safe files and their backup rings"
for p in "$CS_ADMIN_SAFE" "$CS_USER_SAFE"; do
    if [[ -e $p ]]; then rm -f -- "$p"; cs_ok "removed $p"; else cs_skip "not present: $p"; fi
    if [[ -d $p.bak.d ]]; then
        n="$(find "$p.bak.d" -type f | wc -l)"
        rm -rf -- "$p.bak.d"; cs_ok "removed $p.bak.d" "$n backup generation(s)"
    else cs_skip "not present: $p.bak.d"; fi
done
# The lock files a save creates alongside the safe (I13), if a killed run left
# one behind.
shopt -s nullglob
for p in "$CS_ADMIN_SAFE".lock "$CS_USER_SAFE".lock "$CS_SAFES"/zz-throwaway*; do
    [[ -e $p ]] || continue      # the two .lock names are literals, not globs
    rm -rf -- "$p"; cs_ok "removed leftover $p"
done
shopt -u nullglob

cs_sect "cptest's own directories"
udir="$(dirname -- "$CS_USER_SAFE")"
if [[ -d $udir ]]; then rm -rf -- "$udir"; cs_ok "removed $udir"; else cs_skip "not present: $udir"; fi
# The helper falls back to the caller's own state directory when the root one
# is unreadable, so cptest accumulated a state dir and an audit log of their
# own during job 50. Both are this suite's litter, not the operator's data.
for d in "$CS_USER_HOME/.local/state/cockpit-secrets"; do
    if [[ -d $d ]]; then rm -rf -- "$d"; cs_ok "removed $d"; else cs_skip "not present: $d"; fi
done

cs_sect "lockout counters keyed on a throwaway safe"
shopt -s nullglob
# Two shapes since the I39/I40 fix: `fail.<real uid>.<safe>.json` is the
# per-principal counter (one per operator who mistyped) and
# `safe.<safe>.json` is the per-safe attempt window they share.
counters=("$CS_STATE"/fail.*.zz-throwaway-*.json "$CS_STATE"/safe.zz-throwaway-*.json)
shopt -u nullglob
if ((${#counters[@]})); then
    for c in "${counters[@]}"; do rm -f -- "$c"; cs_ok "removed $c"; done
else
    cs_ok "no lockout counter was left behind"
fi

cs_sect "the passphrase"
if [[ -e $CS_PWFILE ]]; then rm -f -- "$CS_PWFILE"; cs_ok "destroyed $CS_PWFILE (tmpfs)"
else cs_skip "not present: $CS_PWFILE"; fi
rm -rf -- "$CS_RUNDIR" "$CS_PUBDIR"
cs_absent "$CS_RUNDIR"
cs_absent "$CS_PUBDIR"

# ---------------------------------------------------------------------------
cs_sect "the registry is clean again"
# ---------------------------------------------------------------------------
"$CS_HELPER" list 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
ids = [s["id"] for s in d.get("safes", [])]
left = [i for i in ids if i.startswith("zz-throwaway")]
print("  %-4s no throwaway safe remains in the registry  -> %s"
      % ("ok" if not left else "FAIL", ids or "no safes registered"))
print("  %-4s registry_errors is 0  -> %s"
      % ("ok" if d.get("registry_errors") == 0 else "FAIL",
         d.get("registry_errors")))
sys.exit(0 if not left and d.get("registry_errors") == 0 else 1)'
if (($?)); then cs_no "registry is clean"; else cs_ok "registry is clean"; fi

# ---------------------------------------------------------------------------
cs_head "what remains on this host"
# ---------------------------------------------------------------------------
echo
echo "  INSTALLED, deliberately left in place for the browser walkthrough:"
for p in "$CS_PKGDIR" "$CS_HELPER" "$CS_LIBDIR" "$CS_ETC" "$CS_SAFESD" \
         "$CS_SAFES" "$CS_LOGDIR" "$CS_VAR" "$CS_STATE" "$CS_EXPORTS"; do
    [[ -e $p ]] && printf '    %s %-10s %s\n' "$(stat -c '%A' "$p")" "$(stat -c '%U:%G' "$p")" "$p"
done
echo
echo "  Files under those directories:"
find "$CS_PKGDIR" "$CS_LIBDIR" "$CS_ETC" "$CS_LOGDIR" "$CS_VAR" -type f 2>/dev/null \
    | sort | sed 's/^/    /'
echo
if [[ -f $CS_LOGDIR/audit.log ]]; then
    total="$(wc -l < "$CS_LOGDIR/audit.log")"
    mine="$(grep -c '"safe": "zz-throwaway' "$CS_LOGDIR/audit.log" || true)"
    printf '  audit.log: %s lines, %s of them naming a throwaway safe.\n' "$total" "$mine"
    printf '  KEPT: it records who opened what, it contains no value, and\n'
    printf '  install.sh --uninstall keeps it for the same reason.\n'
fi
echo
echo "  Cockpit was never stopped, restarted or reloaded by anything in tests/root."

cs_finish
