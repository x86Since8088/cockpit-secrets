# rootlib.sh - shared plumbing for the tests/root job scripts. SOURCED, never
#              executed: it sets variables and defines the reporter, and every
#              numbered script begins by sourcing it.
#
# Every script in this directory runs AS ROOT, submitted to the /srv/jobs inbox
# runner (docs/HOST-FACTS.md, "Root"). Two consequences shape everything here:
#
#   1. `output.log` in /srv/jobs/outbox is group-readable by `users`. Nothing
#      that reaches stdout or stderr may be a passphrase, a safe's contents, a
#      revealed value or an export (I15). The reporter below prints a verdict
#      and a short, whitelisted `extra` - never a payload.
#   2. There is NO `set -x` in this tree, here included. A traced shell would
#      put every argument it sees into that log, which is the exact failure
#      docs/KNOWN_ISSUES.md I15 names.
#
# The job's working directory is its own outbox folder, `root:users` 0770.
# Accounts outside `users` - cptest is one - cannot chdir into it, so every
# script captures JOBDIR first, sources this file by absolute path, and then
# `cd /` before it runs anything through `runuser`.

# ---------------------------------------------------------------- config ---
# CS_SRC is written by tests/root/submit.sh into cs-config.sh at stage time, so
# nothing here hardcodes the checkout location. The fallback is the path on
# edt1 and exists only so a script hand-copied into a job still runs.
if [[ -r "${JOBDIR:-.}/cs-config.sh" ]]; then
    # shellcheck source=/dev/null
    . "${JOBDIR:-.}/cs-config.sh"
fi
: "${CS_SRC:=/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/cockpit-secrets/source}"

#: Where the package lands. Mirrors install.sh's own header; the verify job
#: reads these rather than a copy of the list, so a path that moves in the
#: installer moves here in one place.
CS_PKGDIR=/usr/share/cockpit/secrets
CS_HELPER=/usr/local/sbin/secrets-admin
CS_LIBDIR=/usr/local/lib/cockpit-secrets
CS_ETC=/etc/cockpit-secrets
CS_SAFESD=$CS_ETC/safes.d
CS_SAFES=$CS_ETC/safes
CS_LOGDIR=/var/log/cockpit-secrets
CS_VAR=/var/lib/cockpit-secrets
CS_STATE=$CS_VAR/state
CS_EXPORTS=$CS_VAR/exports

#: The throwaway subjects. `zz-` prefixed and labelled THROWAWAY in the
#: registry so an operator reading safes.d cannot mistake one for real policy,
#: and so 90-cleanup.sh can remove them by prefix rather than by a list that
#: could drift out of date.
CS_ADMIN_ID=zz-throwaway-admin
CS_ADMIN_NOGRP_ID=zz-throwaway-nogroup
CS_USER_ID=zz-throwaway-user
CS_ADMIN_SAFE=$CS_SAFES/$CS_ADMIN_ID.kdbx
CS_USER_HOME=/home/cptest
CS_USER_SAFE=$CS_USER_HOME/.local/share/cockpit-secrets/$CS_USER_ID.kdbx

#: Test principals. docs/HOST-FACTS.md fixes these; they are NOT created here.
CS_UID_CPTEST=1005        # not in `sudo` - the refusal principal
CS_UID_CPADMIN=1006       # in `sudo`   - the admission principal
CS_UID_CPTESTADM=1007     # in `sudo`   - the second admin principal

# -------------------------------------------------------- the passphrase ---
# THE ONE PLACE A SECRET EXISTS IN THIS SUITE.
#
# The throwaway safes get a freshly generated passphrase, written to a 0600
# file inside a 0700 root-owned directory on /run - which is tmpfs, so it never
# reaches persistent storage at all. It is created by 30-throwaway-safes.sh and
# destroyed by 90-cleanup.sh, and no script ever echoes it: the drivers read the
# file themselves and put the value on the helper's STDIN as JSON, which is the
# same rule the program itself lives by (I10).
#
# It is generated rather than taken from the committed fixture constant on
# purpose. The fixture passphrase would have to be copied into a job script
# under /srv/jobs, and that directory is group-readable by `users`; a value that
# exists only in tmpfs for the length of the run cannot leak that way.
CS_RUNDIR=/run/cockpit-secrets-roottest
CS_PWFILE=$CS_RUNDIR/pw
#: 0755, for the few files cptest must be able to read (its driver). NEVER the
#: passphrase - that lives in CS_RUNDIR, which cptest cannot even list.
CS_PUBDIR=/run/cockpit-secrets-roottest-pub

cs_rundir() {
    install -d -o root -g root -m 0700 "$CS_RUNDIR"
}

cs_pubdir() {
    install -d -o root -g root -m 0755 "$CS_PUBDIR"
}

# cs_pw_new - mint a fresh throwaway passphrase. Never printed, never on argv:
# python writes it straight to the fd it opened 0600.
cs_pw_new() {
    cs_rundir
    python3 - "$CS_PWFILE" <<'CSPWGEN'
import os, secrets, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
try:
    os.fchmod(fd, 0o600)
    os.write(fd, secrets.token_urlsafe(24).encode("ascii"))
finally:
    os.close(fd)
CSPWGEN
}

# cs_pw_require - refuse to run a job that needs the passphrase without one,
# and refuse one whose mode drifted. A 0644 passphrase file would make every
# "no secret leaked" claim in this suite false.
cs_pw_require() {
    [[ -f $CS_PWFILE ]] || { echo "FATAL: $CS_PWFILE is missing; run 30-throwaway-safes.sh first" >&2; return 1; }
    local m o
    m="$(stat -c '%a' "$CS_PWFILE")"; o="$(stat -c '%U:%G' "$CS_PWFILE")"
    [[ $m == 600 && $o == root:root ]] || { echo "FATAL: $CS_PWFILE is $m $o, expected 600 root:root" >&2; return 1; }
    m="$(stat -c '%a' "$CS_RUNDIR")"
    [[ $m == 700 ]] || { echo "FATAL: $CS_RUNDIR is mode 0$m, expected 0700" >&2; return 1; }
    return 0
}

# ------------------------------------------------------------- reporting ---
# The same shape tests/integration/_env.py Report prints, so a root run and a
# user run read alike: one line per check, a count at the end, exit 0 or 1.
CS_CHECKS=0
CS_FAILS=()

cs_head() { printf '\n== %s ==\n' "$*"; }
cs_sect() { printf '\n-- %s --\n' "$*"; }
cs_note() { printf '     %s\n' "$*"; }

# cs_check <name> <0|1 as shell truth> [extra]
cs_ok()   { CS_CHECKS=$((CS_CHECKS + 1)); printf '  %-4s %s%s\n' "ok"   "$1" "${2:+  -> $2}"; }
cs_no()   { CS_CHECKS=$((CS_CHECKS + 1)); CS_FAILS+=("$1"); printf '  %-4s %s%s\n' "FAIL" "$1" "${2:+  -> $2}"; }
cs_skip() { printf '  %-4s %s%s\n' "skip" "$1" "${2:+  -> $2}"; }

# cs_check <name> <command...> - runs the command, reports by its exit status.
cs_check() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then cs_ok "$name"; else cs_no "$name" "command exited $?"; fi
}

# cs_eq <name> <want> <got>
cs_eq() {
    if [[ "$2" == "$3" ]]; then cs_ok "$1" "$3"; else cs_no "$1" "want '$2', got '$3'"; fi
}

# cs_mode <path> <mode> <owner:group> - the check this suite makes most often.
# Reports the type too: a 0700 SYMLINK to somewhere else would satisfy a mode
# comparison and satisfy nothing else.
cs_mode() {
    local p="$1" want_mode="$2" want_own="$3"
    if [[ ! -e $p ]]; then cs_no "$p exists"; return; fi
    local got
    got="$(stat -c '%a %U:%G %F' "$p")"
    if [[ "$got" == "$want_mode $want_own regular file" || "$got" == "$want_mode $want_own directory" ]]
    then cs_ok "$p" "$got"
    else cs_no "$p" "want '$want_mode $want_own', got '$got'"; fi
}

cs_absent() {
    if [[ -e $1 ]]; then cs_no "absent: $1" "$(stat -c '%a %U:%G %F' "$1")"; else cs_ok "absent: $1"; fi
}

cs_finish() {
    printf '\n%d checks, %d failure(s)%s\n' \
        "$CS_CHECKS" "${#CS_FAILS[@]}" \
        "$( ((${#CS_FAILS[@]})) && printf ': %s' "${CS_FAILS[*]}" )"
    ((${#CS_FAILS[@]} == 0))
}
