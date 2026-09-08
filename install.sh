#!/usr/bin/env bash
#
# install.sh - the IN-PLACE install, BY SYMLINK, of cockpit-secrets: the Cockpit
#              page, the secrets-admin verb helper, its backends and schema, the
#              registry directories, and - only when asked for by name - the
#              optional unlock agent's systemd units.
#
# IT DOES NOT COPY THE PAYLOAD. It links the files this directory ships into the
# places Cockpit, /usr/local/sbin and systemd look. Run it from a dev checkout
# and the page is symlinks into the checkout, so editing secrets.js changes what
# the browser loads on the next reload. Run the IDENTICAL script from
# /opt/cockpit-secrets/payload and the links point at a tree with no
# relationship to the share. The script is the same; only where it is run from
# differs. Nothing below branches on which of the two it is in order to decide
# WHAT to link - only to record which it did.
#
# MUST BE RUN AS ROOT. /usr/share/cockpit, /usr/local/sbin and /etc are
# root-owned, and every mode below is set explicitly rather than inherited from
# whatever umask happens to be in force. It refuses to run unescalated rather
# than half-installing a program that holds passphrases: a registry directory an
# unprivileged user can write is a registry that grants itself root (I1).
#
#   sudo ./install.sh                     # install
#   sudo ./install.sh --with-agent        # ... and the opt-in unlock agent (I18)
#   sudo ./install.sh --uninstall         # remove the software, KEEP registry + safes
#   sudo ./install.sh --env-file PATH     # override where .env is read from
#   sudo DESTDIR=/tmp/stage ./install.sh  # stage into a package build root
#   ./install.sh --help
#
# What it touches, and nothing else. This list is checked, not promised: the
# library root is asserted against it at the end of every run, and
# tests/root/20-verify-install.sh audits the whole set from outside, as a
# separate root job - a run that checked its own work would report the mode it
# intended in both places. Every location below comes from .env, and install.sh
# REFUSES if a value there disagrees with the constant compiled into
# secrets-admin.
#
#   /usr/share/cockpit/secrets/          a REAL directory of per-file symlinks
#   /usr/local/sbin/secrets-admin        -> payload/bin/secrets-admin
#   SECRETS_LIB_DIR/backends/*.py        -> payload/lib/backends/*.py
#   SECRETS_LIB_DIR/schema/*.json        -> payload/lib/schema/*.json
#   SECRETS_ETC_DIR/                     0755  the registry root
#   SECRETS_ETC_DIR/safes.d/             0755  the registry itself
#   SECRETS_ETC_DIR/safes/               0700  admin-class safe files
#   SECRETS_LOG_DIR/                     0700  audit.log
#   SECRETS_VAR_DIR/{state,exports}/     0700  lockout counters (I16), exports (I21)
#   SECRETS_EXAMPLE_DIR/user-safes.d/    0755  shipped documentation, not policy
#   /etc/cockpit-secrets/install.conf    0644  the machine's record of this install
#   SECRETS_UNIT_DIR/{user,system}/      --with-agent only, rendered, NOT enabled
#
# --uninstall removes every one of those EXCEPT the data locations it names on
# the way out: the registry and the safe files, the audit log, the lockout
# counters and the exports directory - which may hold PLAINTEXT exports.
#
# What it never does:
#
#   - copy the payload. It links. deploy.sh is the only thing that copies.
#   - restart, reload or otherwise disturb Cockpit. cockpit.socket is a live
#     service on this host and rescans its package directory on the next page
#     load anyway.
#   - enable, start or stop ANY unit. That is deploy.sh's, and ultimately the
#     operator's (I18).
#   - write .env. deploy.sh seeds it, missing-only. This script only reads it.
#   - write over any *.json already in safes.d/. An operator's registry entry is
#     the access-control policy for a safe; clobbering one would silently change
#     who can open what. Examples are seeded as *.json.example, which the
#     registry's *.json glob does not match, so a seeded example can never
#     become a live safe by accident.
#   - open, read, move or modify any safe file, backup or key file.
#   - print the contents of anything. Root work on this host goes through the
#     /srv/jobs runner and its output.log is group-readable.
#
# There is no `set -x` anywhere in this tree (I15). A traced shell would put
# every path and every argument it sees into that group-readable job log.
#
set -Eeuo pipefail

# ===========================================================================
# BEGIN-MANIFEST
#
# THE ONE DECLARATION (docs/DEPLOY-CONTRACT.md section 7.1). deploy.sh and
# validate.sh read this exact block out of this exact file rather than restating
# it. Two lists that can disagree is the failure being designed out; restating
# the payload in the deploy script is the obvious way to re-introduce it.
#
# This array is FOUR things at once: the link list, the stale-file sweep, the
# payload-present check, and what deploy.sh copies. They cannot disagree with
# each other because they are all reading these lines. What they CAN disagree
# EVERY ASSIGNMENT BELOW MUST FIT ON ONE LINE. bash's `eval` does not care, but
# deploy.ps1 and validate.sh read this block with a line-oriented parser, and a
# continuation line silently produced a 64-character STRING where an array was
# meant. The parsers now refuse a line they cannot read rather than guess - but
# the constraint is cheaper to obey than to detect.
#
# What they CAN disagree
# with is index.html, and for a release they did - `theme.js` was added to the
# page and not to the array, so the installer swept it back off the host on
# every single run. Pre-flight check 2 is what makes that impossible now.
# ---------------------------------------------------------------------------
PROJECT="cockpit-secrets"        # the repo dir, and the /opt/<project> name
NAME="secrets"                   # the Cockpit package, /usr/share/cockpit/<name>

PAGE=(manifest.json index.html secrets.js secrets.css theme.js)

# Verb helpers linked into /usr/local/sbin. secrets.js pins this one in a
# top-of-file literal constant, which is what lets pre-flight check 3 see it.
HELPERS=(secrets-admin)

# Python packages linked per-file into SECRETS_LIB_DIR. In the payload they are
# under lib/; in a dev checkout they sit at the repo root beside secrets-admin.
# That is JC-5's one tolerated asymmetry and src_lib() below is where it lives.
LIBS=(lib/backends lib/schema)

# Units for the base install: none. The agent's are opt-in and declared below.
UNITS=()

# Seed data for SECRETS_ETC_DIR. Managed CONTENT, not settings - zero or many
# registry entries, each a distinct object with a schema that the software
# validates and acts on. That is exactly the section 5 test for etcdefaults/
# rather than .envdefault, and this project has both.
SEEDS=(etcdefaults)

ENVDEFAULT=.envdefault

# --with-agent only (I18). USER units and the SYSTEM template are separate
# lists with separate destinations, and the separation is load-bearing: a
# single recursive glob would drop secrets-agent@.service into the user unit
# directory, where systemd reads User=%i and SocketUser=%i in a per-user
# manager that cannot honour either - silently wrong, and wrong about identity,
# which is the one thing this agent exists to get right.
AGENT_UNITS=(secrets-agent.socket secrets-agent.service)
AGENT_SYS_UNITS=(secrets-agent@.socket secrets-agent@.service)

# Keys .env must define, non-empty, or the install refuses (check 7).
REQUIRED_ENV=(SECRETS_ETC_DIR SECRETS_VAR_DIR SECRETS_LOG_DIR SECRETS_LIB_DIR SECRETS_EXAMPLE_DIR SECRETS_UNIT_DIR)
# END-MANIFEST
# ===========================================================================

# readlink -f FIRST, then dirname (section 3.1). Resolving the dirname of an
# unresolved $0 makes a script invoked through a symlink look for its payload in
# the LINK's directory, which is how an installer installs the wrong tree.
SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
SRC="$(cd -- "$(dirname -- "$SELF")" && pwd)"
SRC_REAL="$(readlink -f -- "$SRC")"
VERSION="$(cat "$SRC/VERSION" 2>/dev/null || echo 0.0.0)"

# The install root is the payload's parent: /opt/cockpit-secrets for
# /opt/cockpit-secrets/payload-0.5.1. .env is a SIBLING of the payload, never a
# child of it - the only way "seed .env in the install path" and "an upgrade
# never touches operator config" can both hold (section 1.3).
ROOT="$(cd -- "$SRC/.." && pwd)"
ROOT_REAL="$(readlink -f -- "$ROOT")"

# WHICH KIND OF INSTALL IS THIS? Decided by LAYOUT, never by a path prefix.
# Used ONLY to record and to warn (section 3.1) - never to decide what gets
# linked; dev and prod must not grow different link logic.
#
# deploy.sh writes <install path>/payload-<version>/ and points a sibling
# `payload` symlink at it; swapping that symlink IS an upgrade or rollback. So
# this is a DEPLOYED payload exactly when our own directory is what that
# symlink resolves to. A checkout has no such symlink.
#
# This replaces an older `$SRC == $DEV_ROOT/*` test that named the share
# literally and was WRONG for a checkout anywhere else: such a checkout called
# itself `deployed`, skipping the group-writable warning, recording
# INSTALL_KIND=deployed for a host that was not self-sustaining, and dropping
# "the checkout is not touched" from --uninstall. Layout cannot drift when a
# tree moves, and it leaves no dev-root literal here - which is why check 9
# now scans this installer too, with no carve-out.
# NB: computed from $SRC, never from $ROOT - in some of these installers ROOT
# is derived FROM KIND, so reading it here would be a use-before-assignment
# that silently classified every deployed payload as `dev`.
# Two ways to be a deployed payload. The first is the normal one: the `payload`
# alias points at us. The second covers a PREVIOUS payload being run directly -
# a rollback done without swapping the alias first - which is still a deployed
# tree, not a checkout, and must not be told to go and create a test .env.
if [[ "$(readlink -f -- "$SRC/../payload" 2>/dev/null)" == "$SRC" ]] \
   || { [[ "${SRC##*/}" == payload-* ]] && [[ -L "$SRC/../payload" ]]; }
then KIND=deployed
else KIND=dev
fi

# Modes are always given to `install` explicitly; this umask only covers the
# handful of shell redirections below, so nothing can land group-readable by
# accident.
umask 022
DESTDIR="${DESTDIR:-}"
ACTION="install"
WITH_AGENT=0
ENV_FILE=""

# install.conf is at a FIXED path, deliberately not under SECRETS_ETC_DIR: it is
# what tells a reader where SECRETS_ETC_DIR is, so deriving its own location
# from that key would be circular. It is `install.conf` and not `.env` because
# .env is the operator's and this is the machine's, and nothing good comes of
# one file being both.
INSTALL_CONF="$DESTDIR/etc/$PROJECT/install.conf"

usage() {
    sed -n '2,/^# There is no .set -x. anywhere/p' "$SELF" | sed '$d' | sed 's/^# \?//'
    exit "${1:-0}"
}

while (($#)); do
    case "$1" in
        --uninstall)  ACTION="uninstall"; shift ;;
        --with-agent) WITH_AGENT=1; shift ;;
        --env-file)   ENV_FILE="${2:?--env-file needs a path}"; shift 2 ;;
        -h|--help)    usage 0 ;;
        *) printf 'install.sh: unknown option: %s\n\n' "$1" >&2; usage 1 ;;
    esac
done

# --------------------------------------------------------------- reporting ---
# Every mutation is recorded so the run ends with an exact list of what changed,
# rather than a wall of scrolling output an operator reconstructs afterwards.
CHANGES=(); KEPT=(); WARNINGS=()
changed() { CHANGES+=("$*"); printf '  + %s\n' "$*"; }
kept()    { KEPT+=("$*");    printf '  = %s\n' "$*"; }
warn()    { WARNINGS+=("$*"); printf '  ! %s\n' "$*" >&2; }
note()    { printf '  %s\n' "$*"; }
die()     { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# Refuse before touching anything. Half an install of a program that holds
# passphrases is worse than none: the page would load and every verb would fail
# on a permission the operator cannot see.
if [[ -z "$DESTDIR" && $EUID -ne 0 ]]; then
    die "must be run as root (on this host: submit it to the /srv/jobs runner). Nothing was changed."
fi

# ===========================================================================
# .env - READ, never written. Only deploy.sh seeds it (section 4.2).
# ===========================================================================
# The section 4.1 grammar in awk: KEY=value, KEY="value", full-line comments
# only, no export, no interpolation. A strict subset of what sh, systemd's
# EnvironmentFile and Python all accept, which is why one file feeds all three.
env_get() {  # env_get <file> <key>  -> value on stdout, empty if absent
    [[ -f "$1" ]] || return 0
    awk -v want="$2" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            eq = index($0, "="); if (eq == 0) next;
            k = substr($0, 1, eq - 1); v = substr($0, eq + 1);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", k);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v);
            if (k != want) next;
            if (length(v) >= 2 && substr(v,1,1) == "\"" && substr(v,length(v),1) == "\"")
                v = substr(v, 2, length(v) - 2);
            val = v;
        }
        END { if (val != "") print val }
    ' "$1"
}

env_lint() {  # refuse anything outside the section 4.1 grammar
    local f=$1 n=0 line k v
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ "$line" == *=* ]] || die "$f:$n: not KEY=VALUE"
        k="${line%%=*}"; v="${line#*=}"
        k="${k#"${k%%[![:space:]]*}"}"; k="${k%"${k##*[![:space:]]}"}"
        v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
        [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] \
            || die "$f:$n: bad key '$k' (section 4.1: ^[A-Z][A-Z0-9_]*\$)"
        [[ "$v" == \"*\" ]] && v="${v:1:${#v}-2}"
        case "$v" in
            *'$'*|*'`'*) die "$f:$n: $k contains \$ or \` - interpolation is not supported (section 4.1). Write the value out in full, or let the consumer join the halves." ;;
        esac
    done < "$f"
}

# Resolution order (section 4.3), and there is no "look beside me" step:
#   --env-file, then ENV_FILE= recorded in install.conf, then the layout default.
# A deployed helper never gets a way to look relative to itself, because the
# same line that is right on a deployed host reads the TEST-ONLY .env in a dev
# checkout - which is the failure that indirection exists to prevent.
if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="$(env_get "$INSTALL_CONF" ENV_FILE)"
fi
if [[ -z "$ENV_FILE" ]]; then
    # Section 3.2's one sanctioned difference: it changes where config is READ,
    # never what is LINKED.
    if [[ "$KIND" == dev ]]; then ENV_FILE="$SRC/.env"; else ENV_FILE="$ROOT/.env"; fi
fi

# ===========================================================================
# the safe removal idiom (section 2.4) - copied verbatim, on purpose
# ===========================================================================
# rm -rf on a path that is a symlink to the dev checkout, with one trailing
# slash, deletes the dev checkout. `rm -rf -- "$PKGDIR"` is correct only while
# $PKGDIR is a real directory, which is exactly the assumption this design
# changes. Nothing in this file recurses and nothing follows a link.
remove_link() {
    local p=$1
    if [[ -L "$p" ]]; then
        rm -f -- "$p"          # removes the LINK. The target is untouched.
        changed "unlinked $p"
    elif [[ -e "$p" ]]; then
        warn "$p is not a symlink - left in place, remove it by hand if you meant to"
    fi
}

remove_link_or_file() {   # units are real files, not links
    local p=$1
    if [[ -L "$p" || -f "$p" ]]; then rm -f -- "$p"; changed "removed $p"; fi
}

remove_dir_if_empty() {
    local p=$1
    [[ -d "$p" && ! -L "$p" ]] || return 0
    if rmdir -- "$p" 2>/dev/null; then changed "removed empty $p"
    else note "kept $p (not empty - something else lives there)"; fi
}

# Is this destination ours to replace? (section 2.2)
# "Ours" = it resolves into this install root, or into this project's own dev
# checkout - deploying over a dev install of the SAME project is a normal
# upgrade. A link belonging to a DIFFERENT project is the collision this check
# exists to surface at install time, rather than as an intermittent wrong-verb
# error six months later. /usr/local/sbin is a shared namespace that eight
# helpers from six projects already occupy.
owned_by_us() {
    local link=$1 cur
    [[ -e "$link" || -L "$link" ]] || return 0
    [[ -L "$link" ]] || { warn "$link exists and is NOT a symlink"; return 1; }
    cur=$(readlink -f -- "$link") || return 1
    [[ "$cur" == "$ROOT_REAL"/* ]] && return 0
    # A dev install links into the checkout this script runs from, so $SRC is
    # necessary and sufficient - and tighter than "anywhere under the dev
    # root", which adopted links belonging to a DIFFERENT checkout.
    [[ "$cur" == "$SRC"/* ]] && return 0
    warn "$link -> $cur, which belongs to neither $ROOT_REAL nor $SRC"
    return 1
}

link_one() {
    local target=$1 link=$2 cur=""
    [[ -e "$target" ]] || die "refusing to link $link -> $target: the target does not exist"
    if [[ -L "$link" ]]; then
        cur="$(readlink -- "$link")"
        [[ "$cur" == "$target" ]] && { kept "unchanged $link -> $target"; return 0; }
    fi
    owned_by_us "$link" || die "refusing to take over $link (above). Nothing else was changed."
    ln -sfn -- "$target" "$link"
    if [[ -n "$cur" ]]; then changed "relinked $link -> $target (was $cur)"
    else changed "linked $link -> $target"; fi
}

# ensure_dir <path> <mode> <why-it-matters>
# Creates with an explicit mode, or leaves an existing directory alone and warns
# if its mode is looser than this program can defend. It never silently
# re-permissions a directory an operator already has: that could break a
# deliberate local policy, and a warning naming the exact chmod is more use than
# a surprise.
ensure_dir() {
    local d="$1" mode="$2" why="$3"
    [[ -L "$d" ]] && die "$d is a symlink. $why  Remove it by hand and re-run."
    if [[ -d $d ]]; then
        local have owner mask
        have="$(stat -c '%a' -- "$d")"; owner="$(stat -c '%U' -- "$d")"
        kept "kept $d (mode 0$have, owner $owner)"
        case "$mode" in
            0700) mask=$((8#077)) ;;   # nothing for group or other at all
            *)    mask=$((8#022)) ;;   # nobody but the owner may write
        esac
        (( 8#$have & mask )) && warn "$d is mode 0$have - $why  Fix: chmod $mode $d"
        if [[ -z $DESTDIR && $owner != root ]]; then
            warn "$d is owned by $owner, not root - $why  Fix: chown root:root $d"
        fi
    else
        # Create any missing parents at 0755 FIRST. `install -d -m 0700` applies
        # its mode to every component it has to create, which would leave a
        # staging root with a 0700 /var - correct for the leaf, wrong for
        # everything above it.
        local parent; parent="$(dirname -- "$d")"
        [[ -d $parent ]] || install -d -m 0755 -- "$parent"
        install -d -m "$mode" -- "$d"
        changed "created $d (mode $mode)"
    fi
}

# JC-5's one tolerated asymmetry, in the two functions that hold it. New
# projects put helpers and libs under bin/ and lib/ from the start; forcing the
# move across six repos, four of them public with their own clone-and-run
# instructions, would buy nothing an operator can see.
src_helper() { [[ -e "$SRC/bin/$1" ]] && printf '%s' "$SRC/bin/$1" || printf '%s' "$SRC/$1"; }
src_lib()    { [[ -d "$SRC/$1"     ]] && printf '%s' "$SRC/$1"     || printf '%s' "$SRC/${1#lib/}"; }

# ===========================================================================
# where everything goes - every location from .env, none of it guessed
# ===========================================================================
load_locations() {
    ETCROOT="$(env_get "$ENV_FILE" SECRETS_ETC_DIR)"
    VARROOT="$(env_get "$ENV_FILE" SECRETS_VAR_DIR)"
    LOGROOT="$(env_get "$ENV_FILE" SECRETS_LOG_DIR)"
    LIBROOT="$(env_get "$ENV_FILE" SECRETS_LIB_DIR)"
    EXROOT="$(env_get "$ENV_FILE" SECRETS_EXAMPLE_DIR)"
    UNITROOT="$(env_get "$ENV_FILE" SECRETS_UNIT_DIR)"
    # The runtime paths (what the helper will really use) and the staged paths
    # (what this script writes) are kept apart. A staging root is a build
    # artefact; nobody registers a safe in one.
    LIBDIR_RUNTIME="$LIBROOT"
    PKGDIR="$DESTDIR/usr/share/cockpit/$NAME"
    SBINDIR="$DESTDIR/usr/local/sbin"
    LIBDIR="$DESTDIR$LIBROOT"
    ETCDIR="$DESTDIR$ETCROOT"
    SAFESD="$ETCDIR/safes.d"
    SAFESDIR="$ETCDIR/safes"
    LOGDIR="$DESTDIR$LOGROOT"
    STATEDIR="$DESTDIR$VARROOT/state"
    EXPORTDIR="$DESTDIR$VARROOT/exports"
    EXAMPLEDIR="$DESTDIR$EXROOT"
    USERUNITDIR="$DESTDIR$UNITROOT/user"
    SYSUNITDIR="$DESTDIR$UNITROOT/system"
}

# ===========================================================================
# uninstall
# ===========================================================================
if [[ $ACTION == uninstall ]]; then
    echo "Uninstalling $PROJECT ($KIND install)"
    [[ -f "$ENV_FILE" ]] || die "no $ENV_FILE and no ENV_FILE= in $INSTALL_CONF, so this script cannot know where anything was installed. Point it with --env-file, or remove the links by hand."
    load_locations

    # The sentence the operator needs in order not to panic (section 2.4).
    # Ask the LINK TARGET's layout, not this script's: an operator may be
    # running the deployed installer to tear down links a dev install made.
    _t="$(readlink -f -- "$PKGDIR/index.html" 2>/dev/null || true)"
    if [[ -L "$PKGDIR/index.html" && -n "$_t" ]] \
       && [[ "$(readlink -f -- "${_t%/*}/../payload" 2>/dev/null)" != "${_t%/*}" ]]; then
        echo
        echo "  This is a DEV install: the Cockpit page is symlinks into"
        echo "  ${_t%/*}"
        echo "  ONLY THE SYMLINKS ARE REMOVED. The checkout is not touched."
        echo
    fi

    # Units first: stop and disable before the file goes, or systemd keeps a
    # removed unit around as failed. Failures are warnings, not aborts - an
    # uninstall that stops halfway leaves a worse host than one that finishes
    # noisily. Only units this package installs, by exact name: a wildcard in a
    # shared unit directory is how you delete someone else's service.
    for u in "${AGENT_SYS_UNITS[@]}"; do
        if [[ -z "$DESTDIR" ]]; then
            # A template needs its INSTANCES stopped too, and the socket before
            # the service, or systemd starts the service again on the next
            # connection.
            systemctl stop "${u%.*}@*.socket"  >/dev/null 2>&1 || true
            systemctl stop "${u%.*}@*.service" >/dev/null 2>&1 || true
            systemctl disable "$u"             >/dev/null 2>&1 || true
        fi
        remove_link_or_file "$SYSUNITDIR/$u"
    done
    for u in "${AGENT_UNITS[@]}"; do remove_link_or_file "$USERUNITDIR/$u"; done
    if [[ -z "$DESTDIR" ]]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed  >/dev/null 2>&1 || true
    fi

    for f in "${PAGE[@]}"; do remove_link "$PKGDIR/$f"; done
    remove_dir_if_empty "$PKGDIR"
    for h in "${HELPERS[@]}"; do remove_link "$SBINDIR/$h"; done

    shopt -s nullglob
    for l in "${LIBS[@]}"; do
        for existing in "$LIBDIR/$(basename -- "$l")"/*; do remove_link "$existing"; done
        remove_dir_if_empty "$LIBDIR/$(basename -- "$l")"
    done
    for existing in "$LIBDIR"/agent/*; do remove_link "$existing"; done
    shopt -u nullglob
    remove_dir_if_empty "$LIBDIR/agent"
    remove_link "$LIBDIR/secrets-agent"
    remove_dir_if_empty "$LIBDIR"

    remove_link_or_file "$INSTALL_CONF"
    remove_dir_if_empty "$(dirname -- "$INSTALL_CONF")"

    cat <<EOF

KEPT, deliberately - an uninstall removes the software, not your data:
  $ENV_FILE
      Your settings. A reinstall must not make you write them again, and this
      is not the verb that throws them away.
  $SAFESD/
      Your registry entries: the access-control policy for every safe.
      Removing the software must not silently change who may open what.
  $SAFESDIR/
      Safe files. This program never deletes a safe; the backup ring is the
      only undo it has, and neither is ours to throw away.
  $LOGDIR/
      The audit log: who opened what, and when. It outlives the tool.
  $STATEDIR/
      Lockout counters (I16). Uninstalling must not be a way to clear a lockout.
  $EXPORTDIR/
      The export destination. If anybody ever ran the export verb, a file here
      is AN ENTIRE SAFE IN PLAINTEXT (I21). Removing the software must not be
      the moment those quietly disappear - or quietly survive unnoticed.
      LOOK IN IT, then shred what is there:
        ls -l $EXPORTDIR/
        shred -u $EXPORTDIR/*        # not rm: see docs/OPERATIONS.md

To remove those too, after you have read them - and after you have shredded any
export, because rm -rf does not:
  rm -rf $ETCDIR $LOGDIR $DESTDIR$VARROOT

If anyone enabled the agent, they must turn it off in their OWN session - root
cannot reach another user's systemd instance:
  systemctl --user disable --now secrets-agent.socket

Cockpit was NOT restarted. The page disappears from the menu on the next login.
EOF
    printf '\n  %d change(s), %d warning(s)\n' "${#CHANGES[@]}" "${#WARNINGS[@]}"
    exit 0
fi

# ===========================================================================
# pre-flight - every check refuses, and NOTHING is written until all pass
# ===========================================================================
echo "Installing $PROJECT $VERSION"
note "kind: $KIND    (payload: $SRC)"
note "env:  $ENV_FILE"
note "to:   ${DESTDIR:-/}"
echo
echo "Pre-flight"

# --- 1. payload present ----------------------------------------------------
missing=()
for f in "${PAGE[@]}" "$ENVDEFAULT"; do [[ -e "$SRC/$f" ]] || missing+=("$f"); done
for h in "${HELPERS[@]}"; do [[ -f "$(src_helper "$h")" ]] || missing+=("bin/$h"); done
for l in "${LIBS[@]}";    do [[ -d "$(src_lib "$l")"    ]] || missing+=("$l"); done
[[ -f "$(src_lib lib/backends)/base.py" ]]                  || missing+=("lib/backends/base.py")
[[ -f "$(src_lib lib/schema)/safe-registry.schema.json" ]]  || missing+=("lib/schema/safe-registry.schema.json")
((${#missing[@]} == 0)) || die "the payload is incomplete - missing: ${missing[*]}. Nothing was changed."
note "1. payload complete (${#PAGE[@]} page files, ${#HELPERS[@]} helper, ${#LIBS[@]} lib dirs)"

# --- 1b. every backend the helper can be asked for is shipped --------------
# CHECK 3'S SHAPE, APPLIED TO THE LIBRARY. LIBS declares directories, so a
# backend module that silently vanished from the payload would install cleanly:
# the installer would link what it found, the stale-file sweep would tidy the
# old link away, and the result is a plugin where every KDBX safe is
# unopenable, reported to the operator as "the kdbx backend is not installed".
# That is the same defect as a page calling a helper nothing installs, and it
# gets the same refusal.
#
# secrets-admin drives itself from one literal tuple - `FORMATS = ("kdbx",
# "psafe3")` - and `open_backend` turns that data into an import. Reading that
# same tuple here is what keeps the two from disagreeing. It is a top-of-file
# literal for exactly the reason check 3's helper constants are.
formats=$(sed -n 's/^FORMATS *= *(\(.*\)).*/\1/p' "$(src_helper secrets-admin)" \
          | head -1 | tr -d '"'"'"' ' | tr ',' '\n' | grep -c . || true)
if ((formats == 0)); then
    warn "could not read FORMATS out of secrets-admin; backend completeness NOT checked"
else
    missing_be=()
    for fmt in $(sed -n 's/^FORMATS *= *(\(.*\)).*/\1/p' "$(src_helper secrets-admin)" \
                 | head -1 | tr -d '"'"'"' ' | tr ',' '\n' | grep .); do
        [[ -f "$(src_lib lib/backends)/$fmt.py" ]] || missing_be+=("$fmt")
    done
    ((${#missing_be[@]} == 0)) \
        || die "secrets-admin declares FORMATS=(${missing_be[*]} ...) but the payload ships no backends/<fmt>.py for: ${missing_be[*]}.
    Every safe of that format would be unopenable, reported only as 'the backend
    is not installed'. Ship the module, or remove the format from FORMATS."
    note "1b. every format in secrets-admin's FORMATS has a backend module ($formats)"
fi

# --- 2. the page asks for exactly what is shipped --------------------------
# The defect this exists to make impossible, by name: `theme.js` was added to
# index.html and not to PAGE, so the sweep deleted it from the installed host on
# every run. The cost was not the "404s silently" the page's comment claimed -
# Cockpit answers a missing package file with an HTML error page, and Chromium
# then logs a MIME-type refusal on EVERY page load, which is a permanent console
# error on the one page in this host that handles every passphrase we own.
#
# Parsed, not grepped: a regex over HTML is how you miss the one attribute that
# is spelled differently.
python3 - "$SRC/index.html" "${PAGE[@]}" <<'PY' \
    || die "index.html references a file this installer does not ship (above). Nothing was changed."
import html.parser, sys
path, ship = sys.argv[1], set(sys.argv[2:])
refs = []


class Refs(html.parser.HTMLParser):
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "img", "iframe", "audio", "video", "source",
                   "embed", "track") and a.get("src"):
            refs.append((tag, a["src"]))
        elif tag == "link" and a.get("href"):
            refs.append((tag, a["href"]))
        elif tag == "object" and a.get("data"):
            refs.append((tag, a["data"]))


try:
    Refs().feed(open(path, encoding="utf-8").read())
except Exception as e:
    sys.exit("index.html could not be parsed: %s" % type(e).__name__)

local, bad = [], []
for tag, raw in refs:
    u = raw.split("#")[0].split("?")[0].strip()
    if not u:
        continue
    low = u.lower()
    # A scheme, an authority, an absolute path or a parent segment all name
    # something outside this package directory. ../base1/cockpit.js is
    # Cockpit's own file and is deliberately not ours to install.
    if "://" in low or low.startswith(("//", "/", "data:", "mailto:", "../")):
        continue
    if "/" in u:
        bad.append("%s (<%s>: the package's page level is flat, so no PAGE "
                   "entry can satisfy this)" % (u, tag))
        continue
    local.append(u)
    if u not in ship:
        bad.append("%s (<%s>)" % (u, tag))
if bad:
    sys.exit("index.html references %s, which PAGE does not install - so the\n"
             "  stale-file sweep DELETES it from the installed package on every run\n"
             "  and Cockpit answers the browser with an HTML error page. Add it to\n"
             "  PAGE, or make the page stop asking for it." % ", ".join(sorted(set(bad))))
print("  2. index.html: %d package-local reference(s), every one installed (%s)"
      % (len(local), ", ".join(local)))
PY

# --- 2b. and what the JavaScript fetches at RUNTIME ------------------------
runtime=$(grep -ohE '(fetch|fetchJSON)\([[:space:]]*"[^"/]+\.[A-Za-z0-9]+"' \
              "${PAGE[@]/#/$SRC/}" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/' | sort -u || true)
for r in $runtime; do
    printf '%s\n' "${PAGE[@]}" | grep -qxF "$r" \
        || die "a shipped page file fetches \"$r\" at runtime, which PAGE does not install. Add it to PAGE, or stop fetching it."
done
note "2b. runtime fetch()es resolve to shipped page files ($(printf '%s' "$runtime" | grep -c . || true) found)"

# --- 3. every helper the page names is shipped and will be linked ----------
# THE wg-admin CATCH. wg-admin and hs-admin are installed on this host,
# byte-identical to source, and their own installers mention them ZERO times,
# while wgclient.js names /usr/local/sbin/wg-admin thirty times. A fresh clone
# of that public repo installs a UI whose backend is absent. This check is what
# makes that impossible here.
#
# Comments count. A false positive costs one word in an array; a false negative
# costs a UI with no backend. Bias to declaring.
#
# The corollary is a ban, because a grep can only see literals: a shipped page
# file must name each helper it calls in exactly ONE top-of-file constant, as a
# literal absolute path. secrets.js already does this.
named=$(grep -ohE '/usr/local/sbin/[A-Za-z0-9_.-]+' "${PAGE[@]/#/$SRC/}" 2>/dev/null \
        | sed 's#.*/##' | sort -u || true)
for h in $named; do
    printf '%s\n' "${HELPERS[@]}" | grep -qxF "$h" \
        || die "a shipped page file names /usr/local/sbin/$h, which HELPERS does not install. Add it to HELPERS, or stop the page calling it."
done
note "3. the page names $(printf '%s' "$named" | grep -c . || true) helper(s) under /usr/local/sbin; every one is declared"

# --- 4. the manifest -------------------------------------------------------
# An invalid manifest makes Cockpit drop the package SILENTLY: no page, no menu
# entry, no error anywhere the operator will look. The same check enforces I9:
# this package must run under Cockpit's default `default-src 'self'` and must
# not ship a relaxed policy. And section 8.4's rule: a Cockpit condition may
# test only paths THIS project's own install.sh creates, because an unmet
# condition makes the plugin silently absent.
python3 - "$SRC/manifest.json" "${HELPERS[@]}" <<'PY' || die "manifest.json rejected (see above). Nothing was changed."
import json, sys
path, helpers = sys.argv[1], sys.argv[2:]
try:
    m = json.load(open(path))
except Exception as e:
    sys.exit("manifest.json is not valid JSON: %s" % type(e).__name__)
if not isinstance(m, dict):
    sys.exit("manifest.json is not a JSON object")


def scan(node, where="manifest.json"):
    """Any content-security-policy key, at any depth, is a refusal (I9)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower().replace("_", "-") == "content-security-policy":
                sys.exit("%s declares a Content-Security-Policy at %s.%s - refused: "
                         "this package must run under Cockpit's default policy (I9)"
                         % (path, where, k))
            scan(v, "%s.%s" % (where, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            scan(v, "%s[%d]" % (where, i))


scan(m)
allowed = {"/usr/local/sbin/%s" % h for h in helpers}
for cond in m.get("conditions", []):
    p = cond.get("path-exists") if isinstance(cond, dict) else None
    if p and p not in allowed:
        sys.exit("manifest.json has a condition on %s, which this project's own\n"
                 "  install.sh does not create. An unmet Cockpit condition makes the\n"
                 "  package SILENTLY ABSENT - no page, no menu entry, no error anywhere\n"
                 "  the operator will look. Test only what install.sh creates (%s), and\n"
                 "  report a missing sibling at runtime, in the page, naming the file\n"
                 "  and the .env key. See DEPLOY-CONTRACT section 8.4." % (p, ", ".join(sorted(allowed))))
print("  4. manifest.json: valid, no CSP relaxation (I9), conditions test only what install.sh creates")
if "superuser" not in json.dumps(m):
    print("     note - no 'superuser' declaration; admin-class safes need Cockpit's "
          "Administrative access")
PY

# --- 5. python payload compiles -------------------------------------------
# compile() rather than py_compile: it proves the file parses without writing a
# __pycache__ into the source tree (or into DESTDIR, where it would then be
# installed, and where the library-root assertion would have to sweep it).
pyfiles=("$(src_helper secrets-admin)")
shopt -s nullglob
pyfiles+=("$(src_lib lib/backends)"/*.py "$SRC"/agent/*.py)
shopt -u nullglob
for f in "${pyfiles[@]}"; do
    python3 -c 'import sys; compile(open(sys.argv[1],"rb").read(), sys.argv[1], "exec")' "$f" \
        || die "does not compile: $f. Nothing was changed."
done
note "5. python payload compiles (${#pyfiles[@]} file(s))"

# --- 5b. the JavaScript gate ----------------------------------------------
# There is no build step; check.sh is the only thing between a stray paren and a
# blank panel in the browser. The payload deliberately does NOT ship check.sh -
# a production host has no business holding the dev gate - so its absence is a
# note in a deployed install and a warning in a checkout, which is the only
# place it should ever be missing.
if [[ -x "$SRC/check.sh" ]]; then
    if command -v gjs >/dev/null 2>&1; then
        "$SRC/check.sh" || die "check.sh found a JavaScript syntax error (above). Nothing was changed."
    else
        warn "gjs is not installed: the JavaScript syntax gate did not run"
    fi
elif [[ "$KIND" == dev ]]; then
    warn "check.sh missing or not executable in a CHECKOUT: JavaScript was not syntax-checked"
else
    note "5b. check.sh is not in the payload by design; deploy.sh ran it before copying"
fi

# --- 6. .envdefault parses, and declares every required key ----------------
env_lint "$SRC/$ENVDEFAULT"
for k in "${REQUIRED_ENV[@]}"; do
    grep -qE "^[[:space:]]*$k=" "$SRC/$ENVDEFAULT" \
        || die "$ENVDEFAULT does not declare REQUIRED_ENV key $k."
done
note "6. $ENVDEFAULT parses and declares all ${#REQUIRED_ENV[@]} required key(s)"

# --- 7. .env exists and defines every required key, non-empty --------------
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ "$KIND" == dev ]]; then
        die "no $ENV_FILE. A dev install reads the checkout's TEST-ONLY .env:
    cp $SRC/$ENVDEFAULT $SRC/.env   # then edit it
  Nothing was changed."
    fi
    die "no $ENV_FILE. Run deploy.sh, which seeds it from $ENVDEFAULT (missing-only). Nothing was changed."
fi
env_lint "$ENV_FILE"
for k in "${REQUIRED_ENV[@]}"; do
    [[ -n "$(env_get "$ENV_FILE" "$k")" ]] \
        || die "$ENV_FILE does not set $k (or sets it empty). See $SRC/$ENVDEFAULT for what it means. Nothing was changed."
done
load_locations
for v in "$ETCROOT" "$VARROOT" "$LOGROOT" "$LIBROOT" "$EXROOT" "$UNITROOT"; do
    [[ "$v" == /* ]] || die "$ENV_FILE holds a relative path: '$v'. Every location must be absolute."
done
note "7. $ENV_FILE defines all ${#REQUIRED_ENV[@]} required key(s), all absolute"

# --- 7b. .env agrees with what secrets-admin has compiled in --------------
# Two places that can hold a location is one place too many. If .env says the
# registry is somewhere the helper will never look, the page installs cleanly,
# every verb runs, and every safe is missing - with no error naming the cause.
# Refuse instead, and name both values.
HELPER_SRC="$(src_helper secrets-admin)"
check_const() {  # check_const <python-const> <env-key> <env-value>
    local const=$1 key=$2 want=$3 have
    have="$(sed -n "s/^$const *= *\"\\([^\"]*\\)\".*/\\1/p" "$HELPER_SRC" | head -1)"
    [[ -n "$have" ]] || { warn "could not read $const out of secrets-admin to cross-check $key"; return 0; }
    [[ "$have" == "$want" ]] || die "$key=$want in $ENV_FILE, but secrets-admin has $const=\"$have\" compiled in.
    The installer would create one and the helper would read the other, and
    every safe would be missing with nothing naming the cause. Make them agree."
}
check_const DEFAULT_ETC     SECRETS_ETC_DIR "$ETCROOT"
check_const DEFAULT_VAR     SECRETS_VAR_DIR "$VARROOT"
check_const DEFAULT_LOG_DIR SECRETS_LOG_DIR "$LOGROOT"
grep -qF "\"$LIBROOT\"" "$HELPER_SRC" \
    || die "SECRETS_LIB_DIR=$LIBROOT is not a library candidate in secrets-admin, so the helper would never import backends/ from where this script is about to link it. Make them agree."
note "7b. every location in .env matches the constant compiled into secrets-admin"

# --- 8. nothing declared collides with another project --------------------
for f in "${PAGE[@]}"; do
    owned_by_us "$PKGDIR/$f" || die "$PKGDIR/$f belongs to something else (above). Nothing was changed."
done
for h in "${HELPERS[@]}"; do
    owned_by_us "$SBINDIR/$h" || die "$SBINDIR/$h belongs to something else (above). Nothing was changed."
done
note "8. every destination is free, or is already ours"

# --- 9. no dev-tree and no retired path in anything being shipped ---------
# $SELF is scanned too, with NO carve-out. install.sh used to be excluded
# because section 3.1's classifier required a DEV_ROOT= literal; that
# classifier is layout-based now, so the only occurrence left in this file is
# the split pattern on the grep line below, which cannot match itself.
# Splitting a scanner's own pattern weakens nothing - the concatenation it
# searches for is unchanged and every other file is matched in full - it only
# stops the audit reporting itself, which is what let the carve-out exist.
# README.md and LICENSE are shipped too, so they are scanned too. A README
# that documents "how do I tell a dev install from a deployed one" is exactly
# the file most likely to name the dev root, and it lands on production hosts
# like any other artifact.
scan=("${PAGE[@]/#/$SRC/}" "$HELPER_SRC" "$SRC/$ENVDEFAULT" "$SELF")
for d in README.md LICENSE; do [[ -f "$SRC/$d" ]] && scan+=("$SRC/$d"); done
for l in "${LIBS[@]}"; do scan+=("$(src_lib "$l")"); done
[[ -d "$SRC/agent" ]] && scan+=("$SRC/agent")
if hits=$(grep -RIn -e "/opt/sc""/git" -e "/srv/smb/share/sc/ai-orchestrator""-group" -- "${scan[@]}" 2>/dev/null); then
    printf '%s\n' "$hits" | sed 's/^/        /' >&2
    die "a shipped file hardcodes a dev or retired path (above). It belongs in .env. Nothing was changed."
fi
note "9. no shipped artifact names a dev-tree or retired path"

# --- 10. the registry schema and the seeded examples ----------------------
# The examples ship as documentation, so they must be valid against the schema
# they document: a broken example teaches an operator a broken shape. The
# user-safes.d glob is SEPARATE and is not a tidy-up - `*.json` does not
# descend, so the per-user example was the one shipped registry entry no gate
# validated.
shopt -s nullglob
EXAMPLES=("$SRC"/etcdefaults/*.json "$SRC"/etcdefaults/user-safes.d/*.json)
shopt -u nullglob
python3 - "$(src_lib lib/schema)/safe-registry.schema.json" "${EXAMPLES[@]}" <<'PY' \
    || die "an etcdefaults example is not valid against the registry schema. Nothing was changed."
import json, sys
schema_path, examples = sys.argv[1], sys.argv[2:]
try:
    schema = json.load(open(schema_path))
except Exception as e:
    sys.exit("schema is not valid JSON: %s" % type(e).__name__)
try:
    from jsonschema import Draft7Validator
    validator = Draft7Validator(schema)
except Exception:
    validator = None
    print("  10. registry schema: valid JSON (python3-jsonschema absent, examples "
          "checked for JSON validity only)")
for path in examples:
    try:
        doc = json.load(open(path))
    except Exception as e:
        sys.exit("%s is not valid JSON: %s" % (path, type(e).__name__))
    if validator is not None:
        errs = sorted(validator.iter_errors(doc), key=str)
        if errs:
            sys.exit("%s is invalid: %s" % (path, errs[0].message))
if validator is not None:
    print("  10. registry schema + %d example(s): valid (jsonschema)" % len(examples))
PY

# --- 11. the agent, only if it was asked for ------------------------------
AGENT_PY=(); AGENT_BIN=""
if ((WITH_AGENT)); then
    [[ -d "$SRC/agent" ]] || die "--with-agent was given but $SRC/agent does not exist (the optional agent may have been dropped - see docs/KNOWN_ISSUES.md I18). Nothing was changed."
    for u in "${AGENT_UNITS[@]}"; do
        [[ -f "$SRC/agent/systemd/$u.in" || -f "$SRC/agent/systemd/$u" ]] \
            || die "--with-agent: missing user unit agent/systemd/$u(.in). Nothing was changed."
    done
    for u in "${AGENT_SYS_UNITS[@]}"; do
        [[ -f "$SRC/agent/systemd/system/$u.in" || -f "$SRC/agent/systemd/system/$u" ]] \
            || die "--with-agent: missing system unit agent/systemd/system/$u(.in). Nothing was changed."
    done
    shopt -s nullglob
    AGENT_PY=("$SRC"/agent/*.py)
    shopt -u nullglob
    [[ -f "$SRC/agent/secrets-agent" ]] && AGENT_BIN="$SRC/agent/secrets-agent"
    note "11. agent payload: ${#AGENT_UNITS[@]} user unit(s), ${#AGENT_SYS_UNITS[@]} system template(s), ${#AGENT_PY[@]} module(s)${AGENT_BIN:+, 1 executable}"
fi

# In a dev install the payload is the group-writable share, and from here on the
# ROOT-RUN HELPER imports its code from there. That is what a dev install is,
# and secrets-admin says so itself at runtime (_trusted_dir reports an untrusted
# library root on stderr) - but it must be said at install time too, to the
# person choosing to do it.
if [[ "$KIND" == dev ]]; then
    warn "DEV INSTALL: every link points into $SRC, which may be group-writable and vanishes if that tree is unmounted. The root-run helper will import backends/ from there. This is what a dev install IS; deploy.sh produces the self-sustaining kind."
fi

echo
echo "Installing"

# ===========================================================================
# 1. the Cockpit page - a REAL directory of per-file symlinks (section 2.1)
# ===========================================================================
# NOT one directory symlink at $SRC. This is the same script in a dev install,
# and there $SRC is the checkout: a directory symlink would point Cockpit's WEB
# ROOT at .git/, .claude/, tests/, docs/ and function-map/ and serve them over
# HTTPS to any authenticated Cockpit session. Handing a web root a symlink to a
# directory whose contents you do not enumerate is how repositories end up on
# the internet.
ensure_dir "$PKGDIR" 0755 "Cockpit serves this directory to every logged-in session."
for f in "${PAGE[@]}"; do link_one "$SRC/$f" "$PKGDIR/$f"; done

# Drop anything a previous version left behind: an old file that is no longer in
# the payload must not keep being served. Everything here is a symlink, so
# remove_link cannot recurse into the payload even if one points there.
shopt -s nullglob
for existing in "$PKGDIR"/*; do
    base="$(basename -- "$existing")"; keep=0
    for f in "${PAGE[@]}"; do [[ "$base" == "$f" ]] && keep=1; done
    ((keep)) || remove_link "$existing"
done
shopt -u nullglob

# ===========================================================================
# 2. the helper, its backends and the registry schema
# ===========================================================================
ensure_dir "$SBINDIR" 0755 "it holds a root-run helper."
for h in "${HELPERS[@]}"; do link_one "$(src_helper "$h")" "$SBINDIR/$h"; done

ensure_dir "$LIBDIR" 0755 "the helper imports code from here as root."
for l in "${LIBS[@]}"; do
    leaf="$(basename -- "$l")"
    ensure_dir "$LIBDIR/$leaf" 0755 "the helper imports from here as root."
    shopt -s nullglob
    case "$leaf" in
        backends) for f in "$(src_lib "$l")"/*.py;   do link_one "$f" "$LIBDIR/$leaf/$(basename -- "$f")"; done ;;
        schema)   for f in "$(src_lib "$l")"/*.json; do link_one "$f" "$LIBDIR/$leaf/$(basename -- "$f")"; done ;;
        *)        for f in "$(src_lib "$l")"/*;      do link_one "$f" "$LIBDIR/$leaf/$(basename -- "$f")"; done ;;
    esac
    shopt -u nullglob
done

# ===========================================================================
# 3. configuration, logs and state - OUTSIDE the payload, all of it
# ===========================================================================
# Nothing an upgrade replaces may hold state, and an upgrade replaces the
# payload wholesale. /etc, /var/lib and /var/log are used in preference to
# anything under the install path because backup policy, logrotate, SELinux
# labelling and restorecon already know those three trees.
ensure_dir "$ETCDIR"   0755 "it holds the registry that decides who may open which safe."
ensure_dir "$SAFESD"   0755 "the helper REFUSES a group- or other-writable registry directory (I1)."
ensure_dir "$SAFESDIR" 0700 "it holds admin-class safe files."
ensure_dir "$LOGDIR"   0700 "it holds the audit log."
ensure_dir "$DESTDIR$VARROOT" 0700 "it holds unlock-failure state."
ensure_dir "$STATEDIR" 0700 "it holds the per-(uid, safe) lockout counters (I16)."
# The helper creates this 0700 on first use anyway, so it is not load-bearing -
# but an operator who can SEE it the moment the package is installed can reason
# about it before an export lands in it, and a directory that appears the first
# time somebody dumps a safe in the clear is a directory nobody has looked at.
ensure_dir "$EXPORTDIR" 0700 "an export is AN ENTIRE SAFE IN PLAINTEXT (I21)."

# Seed the examples, and ONLY where nothing is there already. They are seeded
# with a .example suffix, which the registry's *.json glob does not match, for
# two reasons worth the ugly file name: a live example entry would appear in the
# safe list as a permanently broken row, which trains operators to ignore broken
# rows in a security UI; and worse, it would become a REAL safe with real access
# rules the moment anyone created a file at the example path. An access-control
# policy must never appear by accident.
shopt -s nullglob
for src in "$SRC"/etcdefaults/*.json; do
    dst="$SAFESD/$(basename -- "$src").example"
    if [[ -e $dst ]]; then kept "kept existing $dst (not overwritten)"
    else install -m 0644 -- "$src" "$dst"; changed "seeded $dst"; fi
done
shopt -u nullglob

# The PER-USER example goes where documentation goes, not where policy goes: a
# per-user entry in the system registry would be an entry naming a path in
# somebody's home directory, read by a root helper.
ensure_dir "$EXAMPLEDIR" 0755 "it holds shipped documentation, not policy."
ensure_dir "$EXAMPLEDIR/user-safes.d" 0755 "it holds the per-user registry example."
shopt -s nullglob
for src in "$SRC"/etcdefaults/user-safes.d/*; do
    [[ -f $src ]] || continue
    link_one "$src" "$EXAMPLEDIR/user-safes.d/$(basename -- "$src")"
done
live=("$SAFESD"/*.json)
shopt -u nullglob
((${#live[@]})) && note "left ${#live[@]} existing registry entry/entries in $SAFESD untouched"

# ===========================================================================
# 4. the optional unlock agent - RENDERED AND PLACED, never enabled (I18)
# ===========================================================================
UNIT_TMP="$(mktemp -d)"
cleanup_unit_tmp() { [[ -d "$UNIT_TMP" ]] || return 0
    rm -f -- "$UNIT_TMP"/*; rmdir -- "$UNIT_TMP" 2>/dev/null || true; }
trap cleanup_unit_tmp EXIT

render_unit() {  # render_unit <template-path> <outfile>
    local in=$1 out=$2
    [[ -f "$in" ]] || die "missing unit template $in"
    sed -e "s|@PAYLOAD@|$SRC|g" \
        -e "s|@INSTALL_PATH@|$ROOT|g" \
        -e "s|@ENV_FILE@|$ENV_FILE|g" \
        -e "s|@LIBDIR@|$LIBDIR_RUNTIME|g" \
        -e "s|@SBIN@|/usr/local/sbin|g" "$in" > "$out"
    # A placeholder that appears nowhere else cannot be silently no-op'ed. That
    # is the whole reason these are tokens and not literal old paths: sed
    # against a literal succeeds vacuously the moment the unit is edited, and
    # installs a working-looking unit naming a path nothing lives at.
    if grep -q '@[A-Z_]\+@' "$out"; then
        local left; left=$(grep -o '@[A-Z_]*@' "$out" | sort -u | tr '\n' ' ')
        rm -f -- "$out"; die "unrendered placeholder(s) in $(basename -- "$in"): $left"
    fi
}
place_unit() {  # place_unit <template-dir> <name> <dest-dir>
    local dir=$1 u=$2 dest=$3 in="$1/$2.in"
    [[ -f "$in" ]] || in="$dir/$u"
    render_unit "$in" "$UNIT_TMP/$u"
    while read -r word; do
        [[ "$word" == /* ]] || continue
        [[ -e "$DESTDIR$word" || -e "$word" ]] \
            || warn "$u runs $word, which is not installed"
    done < <(sed -n 's/^ExecStart=[-@+!]*//p' -- "$UNIT_TMP/$u" | tr ' ' '\n')
    if [[ -f "$dest/$u" ]] && cmp -s -- "$UNIT_TMP/$u" "$dest/$u"; then
        kept "unchanged $dest/$u"
    else
        install -m 0644 -- "$UNIT_TMP/$u" "$dest/$u"; changed "rendered $dest/$u"
    fi
}

if ((WITH_AGENT)); then
    ensure_dir "$LIBDIR/agent" 0755 "the agent imports code from here."
    for f in "${AGENT_PY[@]}"; do link_one "$f" "$LIBDIR/agent/$(basename -- "$f")"; done
    [[ -n $AGENT_BIN ]] && link_one "$AGENT_BIN" "$LIBDIR/secrets-agent"

    # A USER unit, not a system one, on purpose: the agent must run AS the user
    # whose safes it holds, so SO_PEERCRED on its socket is an identity and not
    # a broker authenticating on everyone's behalf (I18).
    ensure_dir "$USERUNITDIR" 0755 "systemd reads user units from here."
    for u in "${AGENT_UNITS[@]}"; do place_unit "$SRC/agent/systemd" "$u" "$USERUNITDIR"; done

    # The SYSTEM template, for the admin access class. Placed, NEVER enabled:
    # secrets-agent@<uid>.socket is one agent per operator behind a 0700 run
    # dir, and deciding that an administrator's safes may stay open is not an
    # installer's decision to make (I18).
    ensure_dir "$SYSUNITDIR" 0755 "systemd reads system units from here."
    for u in "${AGENT_SYS_UNITS[@]}"; do place_unit "$SRC/agent/systemd/system" "$u" "$SYSUNITDIR"; done
    note "agent units placed, NOT enabled and NOT started: see agent/README.md"
fi

# ===========================================================================
# 5. install.conf - the machine's record. .env is the operator's; this is not.
# ===========================================================================
ensure_dir "$(dirname -- "$INSTALL_CONF")" 0755 "it holds this install's record."
tmp_conf="$(mktemp)"
cat > "$tmp_conf" <<EOF
# Written by install.sh. Do not edit; re-run install.sh instead.
# This is the machine's record. Your settings are in ENV_FILE below.
INSTALL_KIND=$KIND
INSTALL_PATH=$ROOT
PAYLOAD=$SRC
ENV_FILE=$ENV_FILE
PKGDIR=${PKGDIR#"$DESTDIR"}
LIBDIR=$LIBROOT
UNITDIR=$UNITROOT
WITH_AGENT=$WITH_AGENT
VERSION=$VERSION
INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INSTALLED_BY=install.sh
EOF
if [[ -f "$INSTALL_CONF" ]] && diff -q <(grep -v '^INSTALLED_AT=' "$tmp_conf") \
        <(grep -v '^INSTALLED_AT=' "$INSTALL_CONF") >/dev/null 2>&1; then
    kept "unchanged $INSTALL_CONF"; rm -f -- "$tmp_conf"
else
    install -m 0644 -- "$tmp_conf" "$INSTALL_CONF"; rm -f -- "$tmp_conf"
    changed "wrote $INSTALL_CONF"
fi

# ===========================================================================
# 6. smoke test - only against a real installation, never a staging root
# ===========================================================================
# In a DESTDIR the helper is not at the path it will run from and its library
# root does not exist yet, so running it would prove nothing.
echo
echo "Verifying"
if [[ -z $DESTDIR ]]; then
    # `-B` IS LOAD-BEARING. Without it this probe is a WRITER: it imports a
    # package out of a root-owned directory as root, and CPython caches the
    # bytecode next to the source. That single line once put a __pycache__ back
    # into a directory the sweep had just cleaned, and the installer then
    # reported success against an invariant it had broken itself.
    if python3 -B -c "import sys; sys.path.insert(0, '$LIBDIR_RUNTIME'); import backends" 2>/dev/null; then
        note "backends import from $LIBDIR_RUNTIME"
    else
        warn "python3 cannot import backends from $LIBDIR_RUNTIME"
    fi
    # One JSON object on stdout and nothing else, exit 0 - the whole contract in
    # one call. Only the verdict is printed: health output names safes and
    # paths, and this runs in a group-readable job log (I15).
    #
    # Deliberately NOT run with PYTHONDONTWRITEBYTECODE=1, even though that
    # would also stop the bytecode: the helper has to be smoke-tested in the
    # environment it will really run in. It sets sys.dont_write_bytecode
    # itself, and the assertion below is what proves it.
    if out="$("$SBINDIR/secrets-admin" health 2>/dev/null)" \
       && printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d, dict) else 1)' 2>/dev/null; then
        note "secrets-admin health: one JSON object, exit 0"
    else
        warn "secrets-admin health did not return a JSON object - run '$SBINDIR/secrets-admin health' by hand"
    fi
else
    note "staged into $DESTDIR; smoke test skipped (the helper is not at its runtime path)"
fi

# ===========================================================================
# 6b. post-install assertion - what was PRODUCED, not what was intended
# ===========================================================================
# Separate from the pre-flight on purpose: a script that only checked its own
# intentions would report the mode it meant to set, in both places. Checked
# LAST - after the sweeps, after the smoke test, after anything else this
# script might grow. A future change that imports the package one more time, or
# a helper that starts writing bytecode again, cannot pass this quietly.
fail=0
shopt -s nullglob
found=("$PKGDIR"/*)
shopt -u nullglob
((${#found[@]} == ${#PAGE[@]})) \
    || { warn "$PKGDIR holds ${#found[@]} entries; PAGE declares ${#PAGE[@]}"; fail=1; }
for f in "${PAGE[@]}"; do
    l="$PKGDIR/$f"
    [[ -L "$l" ]] || { warn "$l is not a symlink"; fail=1; continue; }
    t="$(readlink -f -- "$l" 2>/dev/null || true)"
    [[ -n "$t" && -e "$t" ]] || { warn "$l is a DANGLING symlink"; fail=1; continue; }
    [[ "$t" == "$SRC_REAL"/* ]] || { warn "$l -> $t, outside the payload"; fail=1; }
done
for h in "${HELPERS[@]}"; do
    l="$SBINDIR/$h"
    [[ -L "$l" && -x "$(readlink -f -- "$l")" ]] \
        || { warn "$l is not a symlink to an executable"; fail=1; }
done

# The library root holds EXACTLY what was declared - no bytecode, no strays.
# The header claims a precise list; that claim was false for a release, and it
# is now checked rather than asserted in prose. It repairs and reports rather
# than dying: at this point the package is installed and working, and the defect
# would be in the installer, not the installation.
assert_library_root_clean() {
    [[ -d $LIBDIR ]] || return 0
    local stray=() existing base leaf
    shopt -s nullglob dotglob
    for existing in "$LIBDIR"/*; do
        base="$(basename -- "$existing")"
        case "$base" in backends|schema|agent|secrets-agent) continue ;; esac
        stray+=("$existing")
    done
    for l in "${LIBS[@]}"; do
        leaf="$(basename -- "$l")"
        for existing in "$LIBDIR/$leaf"/*; do
            base="$(basename -- "$existing")"
            [[ -L "$existing" && -e "$(src_lib "$l")/$base" ]] && continue
            stray+=("$existing")
        done
    done
    # agent/ only when it is installed. The agent names are allowed at the top
    # level unconditionally, NOT only under --with-agent: a plain reinstall on a
    # host where somebody installed the agent must not delete the code their
    # systemd units point at. Uninstall is where the agent goes away, by name.
    if [[ -d "$LIBDIR/agent" ]]; then
        for existing in "$LIBDIR"/agent/*; do
            base="$(basename -- "$existing")"
            [[ -L "$existing" && -e "$SRC/agent/$base" ]] && continue
            stray+=("$existing")
        done
    fi
    shopt -u nullglob dotglob
    if ((${#stray[@]} == 0)); then
        note "library root holds exactly the declared payload (all symlinks, no bytecode, no strays)"
        return 0
    fi
    for existing in "${stray[@]}"; do
        if [[ -L "$existing" ]]; then remove_link "$existing"
        elif [[ -f "$existing" ]]; then rm -f -- "$existing"; changed "removed unexpected $existing"
        else warn "unexpected DIRECTORY in the library root, left in place: $existing"; fi
    done
    warn "the library root contained ${#stray[@]} entry/entries this installer did not put there - see docs/ROOT-VERIFICATION.md F1: ${stray[*]}"
}
assert_library_root_clean

conf_payload="$(env_get "$INSTALL_CONF" PAYLOAD)"
[[ "$(readlink -f -- "$conf_payload")" == "$SRC_REAL" ]] \
    || { warn "install.conf PAYLOAD=$conf_payload does not resolve to $SRC"; fail=1; }
((fail)) || note "the package is exactly ${#PAGE[@]} symlink(s), every one resolving into $SRC"

# ===========================================================================
# 7. what changed, and what the operator does next
# ===========================================================================
echo
echo "Summary"
printf '  %d change(s), %d unchanged, %d warning(s)\n' \
    "${#CHANGES[@]}" "${#KEPT[@]}" "${#WARNINGS[@]}"
if ((${#WARNINGS[@]})); then
    echo
    echo "  Action required:"
    for w in "${WARNINGS[@]}"; do printf '    ! %s\n' "$w"; done
fi

# The instructions name the paths the operator will actually type, which are the
# runtime paths - a staging root is a build artefact, not somewhere anyone
# registers a safe.
cat <<EOF

Next steps
  1. Reload Cockpit in the browser (Ctrl-Shift-R). Log out and back in for the
     menu entry. Cockpit was NOT restarted and no service was touched.
  2. Which install is this?
       readlink -f /usr/share/cockpit/$NAME/index.html
       grep INSTALL_KIND ${INSTALL_CONF#"$DESTDIR"}
  3. Register a safe. Nothing is visible until you do - the registry is the only
     source of safes and it ships empty:
       cp $ETCROOT/safes.d/10-example-admin.json.example \\
          $ETCROOT/safes.d/10-lab-dc.json
       \$EDITOR $ETCROOT/safes.d/10-lab-dc.json   # id, label, path, access
       chmod 0644 $ETCROOT/safes.d/10-lab-dc.json
       secrets-admin health                    # registry_errors[] must be empty
     An entry that omits "access" is an ADMIN safe. That default is deliberate:
     a hand-edit that loses a line must fail closed (I1).
  4. Put admin-class safes in $ETCROOT/safes, mode 0600 root:root.
     A user-class safe lives in that user's own tree, mode 0600, owned by them.
  5. Read docs/OPERATIONS.md before the first save: the backup ring, the
     "changed on disk" conflict, and the lossless-save guard (I22) all behave in
     ways that are obvious afterwards and surprising the first time.

The agent stays off unless a registry entry sets agent.enabled - and it should
stay off. See docs/OPERATIONS.md, "The agent, and why you probably should not".
EOF
exit 0
