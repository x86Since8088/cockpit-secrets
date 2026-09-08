#!/bin/bash
#
# 20-verify-install.sh - audit the installation from a SEPARATE job.
#
# Separate on purpose. install.sh reports what it believes it did; this job
# asks the filesystem. An installer that mis-set a mode would report the mode
# it intended in both places if the same run checked its own work.
#
# What it establishes, in the order the task asks for it:
#   * every path install.sh claims, with its mode, owner and type
#   * NOTHING from tests/ was installed - no fixture, no corpus file, no
#     directory component called `tests`
#   * no installed file is group- or world-writable, and none is setuid/setgid
#   * the helper actually resolves its library root to the installed one
#   * cockpit.socket is still exactly as it was before job 10 ran
#
set -u
JOBDIR="$PWD"
. "$JOBDIR/rootlib.sh"
cd /

cs_head "20 - verify the installation"

# ---------------------------------------------------------------------------
# 1. paths, modes, owners
# ---------------------------------------------------------------------------
cs_sect "paths and modes"
cs_mode "$CS_PKGDIR"        755 root:root
cs_mode "$CS_HELPER"        755 root:root
cs_mode "$CS_LIBDIR"        755 root:root
cs_mode "$CS_LIBDIR/backends" 755 root:root
cs_mode "$CS_LIBDIR/schema"   755 root:root
cs_mode "$CS_ETC"           755 root:root
cs_mode "$CS_SAFESD"        755 root:root
cs_mode "$CS_SAFES"         700 root:root
cs_mode "$CS_LOGDIR"        700 root:root
cs_mode "$CS_VAR"           700 root:root
cs_mode "$CS_STATE"         700 root:root
cs_mode "$CS_EXPORTS"       700 root:root

cs_sect "the Cockpit package payload"
# EXACTLY the files install.sh ships, and each 0644 root:root. An extra file
# here is served to every logged-in session.
#
# DERIVED FROM install.sh, NOT RESTATED. This line used to read
#     want_pkg="index.html manifest.json secrets.css secrets.js"
# and it was correct until 0.5.1, when `theme.js` was added to the page and to
# the installer's PLUGIN array. A hard gate that carries its own copy of a list
# fails the release that legitimately grows the list, and the failure looks like
# a defect in the installer rather than in the gate - which is exactly what
# happened here. install.sh's PLUGIN array is already the single source of the
# copy list, the stale-file sweep and the payload-present pre-flight; reading it
# here makes this check a fourth reader of that one line instead of a fifth
# opinion about it.
#
# The extraction is deliberately strict: it matches only the exact
# `PLUGIN=(...)` assignment on its own line, so a rename or a multi-line
# rewrite of the array yields an EMPTY want_pkg and the comparison below fails
# loudly rather than silently checking nothing.
want_pkg="$(cd "$CS_SRC" && sed -n 's/^PLUGIN=(\(.*\))$/\1/p' install.sh \
            | tr ' ' '\n' | grep -v '^$' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
if [[ -z $want_pkg ]]; then
    cs_no "install.sh still declares its payload as a one-line PLUGIN=(...) array" \
          "(extraction produced nothing - this gate cannot check the payload)"
fi
got_pkg="$(cd "$CS_PKGDIR" && ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
cs_eq "$CS_PKGDIR holds exactly the package payload" "$want_pkg" "$got_pkg"
for f in $want_pkg; do cs_mode "$CS_PKGDIR/$f" 644 root:root; done

cs_sect "the helper's library root"
# The installed backends must be exactly the source's *.py - no module a
# previous version left behind, and no compiled bytecode. install.sh sweeps for
# exactly that, with a comment saying why ("root-owned bytecode next to
# root-run source is a second thing to keep honest and buys nothing"); this is
# the independent confirmation of its own invariant.
want_be="$(cd "$CS_SRC/backends" && ls -A -- *.py | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
got_be="$(cd "$CS_LIBDIR/backends" && ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
cs_eq "$CS_LIBDIR/backends holds exactly the source's *.py" "$want_be" "$got_be"
want_sc="$(cd "$CS_SRC/schema" && ls -A -- *.json | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
got_sc="$(cd "$CS_LIBDIR/schema" && ls -A | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
cs_eq "$CS_LIBDIR/schema holds exactly the source's *.json" "$want_sc" "$got_sc"

# Bytecode gets its own check and its own diagnostic, because if it IS there
# the interesting question is who wrote it - the installer's sweep runs before
# the installer's smoke test, so a __pycache__ that reappears afterwards is
# created by the verification step rather than left over from a copy.
pyc="$(find "$CS_LIBDIR" -name '__pycache__' -o -name '*.pyc' 2>/dev/null)"
if [[ -z $pyc ]]; then
    cs_ok "the library root holds source only, no compiled bytecode"
else
    cs_no "the library root holds compiled bytecode" "$(printf '%s' "$pyc" | tr '\n' ' ')"
    printf '%s\n' "$pyc" | xargs -r stat -c '     %a %U:%G %n' 2>/dev/null
    # Attribution, measured rather than guessed: remove it and import the
    # package the way install.sh's own "Verifying" step does.
    rm -rf -- $pyc
    python3 -c "import sys; sys.path.insert(0, '$CS_LIBDIR'); import backends" >/dev/null 2>&1
    if [[ -n "$(find "$CS_LIBDIR" -name '__pycache__' 2>/dev/null)" ]]; then
        cs_note "DIAGNOSIS: it is recreated by importing backends as root -"
        cs_note "install.sh's own smoke test does that AFTER its stale-file sweep."
        cs_note "Fix: run that step with PYTHONDONTWRITEBYTECODE=1 (or python3 -B),"
        cs_note "or move the sweep after it. install.sh is not this task's file."
    else
        cs_note "it was NOT recreated by an import; it predates this install"
    fi
fi

# The agent was NOT requested (no --with-agent), so nothing of it may be here.
# I18's mitigation is "off by default"; an agent that appeared because the
# default install shipped it would be that mitigation quietly undone.
cs_sect "the optional agent was not installed (no --with-agent)"
cs_absent "$CS_LIBDIR/agent"
cs_absent "$CS_LIBDIR/secrets-agent"
shopt -s nullglob
stray_units=(/usr/local/lib/systemd/user/secrets-agent.* /usr/local/lib/systemd/system/secrets-agent@.*)
shopt -u nullglob
cs_eq "no secrets-agent systemd unit was installed" "0" "${#stray_units[@]}"

# ---------------------------------------------------------------------------
# 2. nothing from tests/ was installed
# ---------------------------------------------------------------------------
# Three independent angles, because each one alone has a hole: a path-component
# match misses a flattened copy, a content match misses a file the installer
# rewrote, and an extension match misses a test artefact that shares a name
# with a real one. Together they cover the ways a wildcard in an installer
# reaches one directory too far.
cs_sect "nothing from tests/ was installed"
ROOTS=("$CS_PKGDIR" "$CS_LIBDIR" "$CS_HELPER")

hits="$(find "${ROOTS[@]}" -path '*/tests/*' -o -name tests 2>/dev/null)"
cs_eq "no installed path has a 'tests' component" "" "$hits"

# By CONTENT, not by name. A basename comparison was tried first and reported
# `manifest.json`, which is a false positive twice over: tests/fixtures has a
# manifest and so does the Cockpit package, and they share nothing but the
# word. Hashing asks the question that was actually meant - "is any installed
# file one of the test files?" - and has no such collision.
# LC_ALL=C on both sides and on comm: `sort` and `comm` disagree about
# collation otherwise, and comm then warns and silently produces nonsense.
comm_out="$(LC_ALL=C comm -12 \
    <(find "$CS_SRC/tests" -type f -print0 2>/dev/null | xargs -0 -r sha256sum \
        | cut -d' ' -f1 | LC_ALL=C sort -u) \
    <(find "${ROOTS[@]}" -type f -print0 2>/dev/null | xargs -0 -r sha256sum \
        | cut -d' ' -f1 | LC_ALL=C sort -u))"
if [[ -z $comm_out ]]; then
    cs_ok "no installed file is byte-identical to anything under tests/"
else
    cs_no "an installed file is byte-identical to a file under tests/"
    for h in $comm_out; do
        find "${ROOTS[@]}" -type f -exec sha256sum {} + 2>/dev/null \
            | grep "^$h" | sed 's/^/     /'
    done
fi

ext_hits="$(find "${ROOTS[@]}" \( -name '*.kdbx' -o -name '*.psafe3' \
    -o -name '*.keyx' -o -name '*.expect.json' -o -name 'test_*' \
    -o -name '*.spec.js' \) 2>/dev/null)"
cs_eq "no safe, keyfile, corpus expectation or test artefact was installed" "" "$ext_hits"

# ---------------------------------------------------------------------------
# 3. permissions across everything the package owns
# ---------------------------------------------------------------------------
cs_sect "no installed path is group- or world-writable"
ALLROOTS=("$CS_PKGDIR" "$CS_LIBDIR" "$CS_HELPER" "$CS_ETC" "$CS_LOGDIR" "$CS_VAR")
ww="$(find "${ALLROOTS[@]}" -perm /022 2>/dev/null)"
cs_eq "find -perm /022 over every installed path is empty" "" "$ww"
[[ -n $ww ]] && printf '%s\n' "$ww" | xargs -r stat -c '     %a %U:%G %n' 2>/dev/null

sg="$(find "${ALLROOTS[@]}" -perm /6000 2>/dev/null)"
cs_eq "nothing installed is setuid or setgid" "" "$sg"

notroot="$(find "${ALLROOTS[@]}" \! -user root -o \! -group root 2>/dev/null)"
cs_eq "everything installed is owned root:root" "" "$notroot"

sym="$(find "${ALLROOTS[@]}" -type l 2>/dev/null)"
cs_eq "the installation contains no symlinks" "" "$sym"

# ---------------------------------------------------------------------------
# 4. the installed helper actually works, from its installed library root
# ---------------------------------------------------------------------------
cs_sect "the installed helper"
h="$("$CS_HELPER" health 2>"$CS_RUNDIR/health.err")"
rc=$?
cs_eq "$CS_HELPER health exit status" "0" "$rc"
# The development tree is group-writable over SMB, so the helper warns when it
# is run from there. Installed root-owned, that warning must be gone - it is
# the one-line difference between "trusted install" and "a dev checkout".
errtext="$(cat "$CS_RUNDIR/health.err" 2>/dev/null)"
cs_eq "the installed helper emits no warning on stderr" "" "$errtext"
rm -f "$CS_RUNDIR/health.err"

# The JSON goes to a file and the path goes on argv, because `python3 -` reads
# its PROGRAM from stdin: a heredoc and a pipe cannot both be stdin, and the
# pipe loses. `health` names safes and paths but no values, and the file is
# 0600 and removed below.
printf '%s' "$h" > "$CS_RUNDIR/health.json"
chmod 0600 "$CS_RUNDIR/health.json"
python3 - "$CS_RUNDIR/health.json" <<'CSHEALTH'
import json, sys
d = json.load(open(sys.argv[1]))
def line(name, cond, extra=""):
    print("  %-4s %s%s" % ("ok" if cond else "FAIL", name,
                           ("  -> " + str(extra)[:160]) if extra else ""))
    return 0 if cond else 1
bad = 0
bad |= line("health returns one JSON object", isinstance(d, dict))
bad |= line("library_root is the installed one",
            d.get("library_root") == "/usr/local/lib/cockpit-secrets",
            d.get("library_root"))
bad |= line("library_root_trusted is true",
            d.get("library_root_trusted") is True, d.get("library_root_trusted"))
bad |= line("registry_root is /etc/cockpit-secrets",
            d.get("registry_root") == "/etc/cockpit-secrets", d.get("registry_root"))
bad |= line("registry_errors is empty", d.get("registry_errors") == [],
            d.get("registry_errors"))
bad |= line("both backends are available",
            d.get("backends", {}).get("kdbx", {}).get("available") is True and
            d.get("backends", {}).get("psafe3", {}).get("available") is True,
            {k: v.get("available") for k, v in (d.get("backends") or {}).items()})
st = d.get("state") or {}
bad |= line("state_dir is the root-owned system one",
            st.get("state_dir") == "/var/lib/cockpit-secrets/state", st.get("state_dir"))
bad |= line("audit_log is the root-owned system one",
            st.get("audit_log") == "/var/log/cockpit-secrets/audit.log", st.get("audit_log"))
bad |= line("the agent is not running (nothing was enabled)",
            all(not (d.get("agent") or {}).get(k, {}).get("reachable")
                for k in ("user", "admin")), (d.get("agent") or {}).keys())
ident = d.get("identity") or {}
bad |= line("identity reports euid 0 and the admin class",
            ident.get("euid") == 0 and ident.get("class_available") == "admin",
            {k: ident.get(k) for k in ("uid", "euid", "real_uid", "escalated",
                                       "admin_group", "class_available")})
sys.exit(1 if bad else 0)
CSHEALTH
if (($?)); then cs_no "installed helper health assertions"; else cs_ok "installed helper health assertions (10 sub-checks above)"; fi
rm -f "$CS_RUNDIR/health.json"

# ---------------------------------------------------------------------------
# 5. cockpit.socket, again
# ---------------------------------------------------------------------------
cs_sect "cockpit.socket is still untouched"
if [[ -f $CS_RUNDIR/cockpit-socket.before ]]; then
    systemctl show cockpit.socket -p ActiveEnterTimestamp -p InvocationID -p SubState \
        > "$CS_RUNDIR/cockpit-socket.now" 2>&1
    chmod 0600 "$CS_RUNDIR/cockpit-socket.now"
    if diff -q "$CS_RUNDIR/cockpit-socket.before" "$CS_RUNDIR/cockpit-socket.now" >/dev/null; then
        cs_ok "cockpit.socket unchanged since before the install"
    else
        cs_no "cockpit.socket changed since before the install"
        diff "$CS_RUNDIR/cockpit-socket.before" "$CS_RUNDIR/cockpit-socket.now" | sed 's/^/     /'
    fi
else
    cs_skip "cockpit.socket comparison" "no baseline; run 10-install.sh first"
fi

cs_finish
