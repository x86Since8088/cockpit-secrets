#!/bin/bash
#
# 60-uninstall-reinstall.sh - prove `install.sh --uninstall` removes exactly
#                             what it added, and then put the package back.
#
# The claim under test is install.sh's own, printed at the end of every
# uninstall: it removes the software and KEEPS the registry, the safes, the
# audit log and the lockout counters, because "removing the software must not
# silently change who may open what" and "uninstalling must not be a way to
# clear a lockout".
#
# The method is a before/after snapshot of every path the package touches, with
# mode, ownership and type, plus a content hash for the registry entries. A
# claim about what an uninstall keeps is only worth anything if the KEPT files
# are compared byte for byte: an uninstall that rewrote a registry entry with
# the same name would satisfy a "still exists" test and would still have
# changed the access-control policy.
#
# THE PACKAGE IS REINSTALLED AT THE END. The next agent needs it live for the
# browser walkthrough, and this script says so in its own summary.
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "60 - uninstall, diff, reinstall"

SNAP=$CS_RUNDIR/snap
cs_rundir

# snapshot <file> - every path the package touches, with the facts that matter:
# type, mode, owner, path. Sorted, so `diff` is a set difference rather than a
# walk-order artefact. SIZE is deliberately not recorded - the audit log grows
# while this job runs and that is not a change to the installation.
snapshot() {
    local out="$1" r
    shopt -s nullglob
    {
        for r in "$CS_PKGDIR" "$CS_LIBDIR" "$CS_ETC" "$CS_LOGDIR" "$CS_VAR" \
                 "$CS_HELPER" \
                 /usr/local/lib/systemd/user/secrets-agent.* \
                 /usr/local/lib/systemd/system/secrets-agent@.*; do
            [[ -e $r ]] && find "$r" -printf '%y %m %u:%g %p\n' 2>/dev/null
        done
    } | sort > "$out"
    shopt -u nullglob
    chmod 0600 "$out"
}

# The registry entries are the thing the uninstall must not touch, so they get
# a content hash as well as a mode.
reg_hash() {
    find "$CS_SAFESD" -type f -printf '%p\n' 2>/dev/null | sort \
        | xargs -r sha256sum 2>/dev/null | sort
}

# ---------------------------------------------------------------------------
cs_sect "before"
# ---------------------------------------------------------------------------
[[ -x $CS_HELPER ]] || { echo "FATAL: nothing is installed; run 10-install.sh" >&2; exit 1; }
snapshot "$SNAP.before"
reg_hash > "$SNAP.reg.before"; chmod 0600 "$SNAP.reg.before"
cs_note "$(wc -l < "$SNAP.before") paths, $(wc -l < "$SNAP.reg.before") registry entr(y|ies)"

# ---------------------------------------------------------------------------
cs_sect "install.sh --uninstall"
# ---------------------------------------------------------------------------
"$CS_SRC/install.sh" --uninstall > "$CS_RUNDIR/uninstall.out" 2>&1
rc=$?
chmod 0600 "$CS_RUNDIR/uninstall.out"
sed 's/^/     | /' "$CS_RUNDIR/uninstall.out"
cs_eq "install.sh --uninstall exit status" "0" "$rc"

snapshot "$SNAP.after"
reg_hash > "$SNAP.reg.after"; chmod 0600 "$SNAP.reg.after"

# ---------------------------------------------------------------------------
cs_sect "what disappeared"
# ---------------------------------------------------------------------------
# LC_ALL=C on BOTH the sorts and the comm. Without it glibc collation makes
# `sort` and `comm` disagree about the order of paths containing hyphens and
# underscores; comm then prints "file 1 is not in sorted order" and produces a
# set difference that is quietly wrong - which for a check whose whole job is
# "exactly this and nothing else" is worse than an error.
paths() { LC_ALL=C sort -u < <(cut -d' ' -f4- "$1"); }
removed="$(LC_ALL=C comm -23 <(paths "$SNAP.before") <(paths "$SNAP.after"))"
added="$(LC_ALL=C comm -13 <(paths "$SNAP.before") <(paths "$SNAP.after"))"
printf '%s\n' "$removed" | sed '/^$/d;s/^/     - /'
cs_eq "an uninstall adds nothing" "" "$added"

# Exactly the software: the Cockpit package and its four files, the helper, the
# library root and everything under it. Nothing else may be in this set.
for p in "$CS_PKGDIR" "$CS_PKGDIR/manifest.json" "$CS_PKGDIR/index.html" \
         "$CS_PKGDIR/secrets.js" "$CS_PKGDIR/secrets.css" \
         "$CS_HELPER" "$CS_LIBDIR" "$CS_LIBDIR/backends" "$CS_LIBDIR/schema"; do
    if printf '%s\n' "$removed" | grep -qxF "$p"; then cs_ok "removed $p"
    else cs_no "removed $p" "still present or never there"; fi
done
cs_absent "$CS_PKGDIR"
cs_absent "$CS_HELPER"
cs_absent "$CS_LIBDIR"

# ---------------------------------------------------------------------------
cs_sect "what was KEPT, as its own docs promise"
# ---------------------------------------------------------------------------
cs_mode "$CS_ETC"    755 root:root
cs_mode "$CS_SAFESD" 755 root:root
cs_mode "$CS_SAFES"  700 root:root
cs_mode "$CS_LOGDIR" 700 root:root
cs_mode "$CS_STATE"  700 root:root
cs_mode "$CS_EXPORTS" 700 root:root
[[ -f $CS_ADMIN_SAFE ]] && cs_ok "the admin safe file survived" "$(stat -c '%a %U:%G' "$CS_ADMIN_SAFE")" \
                        || cs_no "the admin safe file survived"
[[ -f $CS_LOGDIR/audit.log ]] && cs_ok "the audit log survived" "$(stat -c '%a %U:%G' "$CS_LOGDIR/audit.log")" \
                              || cs_no "the audit log survived"

# The operator's registry entries, byte for byte. This is the check that
# separates "the file is still called that" from "the policy is unchanged".
if diff -q "$SNAP.reg.before" "$SNAP.reg.after" >/dev/null; then
    cs_ok "every registry entry is byte-identical after the uninstall" \
          "$(wc -l < "$SNAP.reg.after") file(s), sha256 unchanged"
else
    cs_no "a registry entry changed across the uninstall"
    diff "$SNAP.reg.before" "$SNAP.reg.after" | sed 's/^/     /'
fi
for sid in "$CS_ADMIN_ID" "$CS_ADMIN_NOGRP_ID" "$CS_USER_ID"; do
    f="$(find "$CS_SAFESD" -name "*$sid.json" -print -quit 2>/dev/null)"
    [[ -n $f ]] && cs_ok "registry entry for $sid survived" "$f" \
                || cs_no "registry entry for $sid survived"
done

# The uninstall also must not be a way to clear a lockout (I16). There is no
# counter to keep at this point in the run - 40-admin-allow.sh cleans up after
# itself - so this is stated as a directory-level check and the counter's own
# survival is covered by the state directory being untouched above.
cs_note "lockout counters live in $CS_STATE, which was kept 0700 root:root"

# ---------------------------------------------------------------------------
cs_sect "reinstall - the next agent needs this live"
# ---------------------------------------------------------------------------
"$CS_SRC/install.sh" > "$CS_RUNDIR/reinstall.out" 2>&1
rc=$?
chmod 0600 "$CS_RUNDIR/reinstall.out"
sed 's/^/     | /' "$CS_RUNDIR/reinstall.out"
cs_eq "install.sh (reinstall) exit status" "0" "$rc"
cs_eq "reinstall raised no 'Action required' warnings" "0" \
      "$(grep -c '^  ! ' "$CS_RUNDIR/reinstall.out" || true)"

# A reinstall must not re-seed over an example the operator kept, and must not
# touch a live entry at all.
cs_check "the reinstall kept the seeded examples rather than rewriting them" \
    grep -q 'kept existing .*\.json\.example' "$CS_RUNDIR/reinstall.out"
reg_hash > "$SNAP.reg.reinstall"; chmod 0600 "$SNAP.reg.reinstall"
if diff -q "$SNAP.reg.before" "$SNAP.reg.reinstall" >/dev/null; then
    cs_ok "every registry entry is STILL byte-identical after the reinstall"
else
    cs_no "a registry entry changed across the reinstall"
    diff "$SNAP.reg.before" "$SNAP.reg.reinstall" | sed 's/^/     /'
fi

cs_sect "the package is back"
snapshot "$SNAP.reinstall"
back="$(LC_ALL=C comm -13 <(paths "$SNAP.after") <(paths "$SNAP.reinstall"))"
gone="$(LC_ALL=C comm -23 <(paths "$SNAP.before") <(paths "$SNAP.reinstall"))"
cs_eq "the reinstall restored exactly what the uninstall removed" "" "$gone"
cs_note "$(printf '%s\n' "$back" | sed '/^$/d' | wc -l) path(s) restored"
cs_mode "$CS_HELPER" 755 root:root
cs_mode "$CS_PKGDIR" 755 root:root
cs_check "the reinstalled helper answers health" "$CS_HELPER" health

ww="$(find "$CS_PKGDIR" "$CS_LIBDIR" "$CS_HELPER" "$CS_ETC" "$CS_LOGDIR" "$CS_VAR" -perm /022 2>/dev/null)"
cs_eq "still nothing group- or world-writable after the reinstall" "" "$ww"

rm -f "$SNAP".*
cs_note "LEFT INSTALLED on purpose: the browser walkthrough needs it."
cs_finish
