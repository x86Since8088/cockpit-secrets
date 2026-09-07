#!/usr/bin/env bash
#
# install.sh - install cockpit-secrets: the Cockpit page, the secrets-admin verb
#              helper and its backends, the registry directories, and - only when
#              asked for by name - the optional unlock agent's systemd USER unit.
#
# MUST BE RUN AS ROOT. /usr/share/cockpit, /usr/local/sbin and /etc are
# root-owned, and every mode and owner below is set explicitly rather than
# inherited from whatever umask happens to be in force. It refuses to run
# unescalated rather than half-installing a package Cockpit would then serve
# with the wrong permissions - a registry directory an unprivileged user can
# write is a registry that grants itself root (docs/KNOWN_ISSUES.md I1).
#
#   sudo ./install.sh                     # install
#   sudo ./install.sh --with-agent        # ... and the opt-in unlock agent (I18)
#   sudo ./install.sh --uninstall         # remove the software, KEEP registry + safes
#   sudo DESTDIR=/tmp/stage ./install.sh  # stage into a package build root
#   ./install.sh --help
#
# What it touches, and nothing else. This list is checked, not promised: the
# library root is asserted against it at the end of every run (section 5b
# below), and tests/root/20-verify-install.sh audits the whole set from outside,
# as a separate root job - a run that checked its own work would report the mode
# it intended in both places.
#
#   /usr/share/cockpit/secrets/                  0755 root:root, files 0644
#   /usr/local/sbin/                             0755 root:root   created if absent
#   /usr/local/sbin/secrets-admin                0755 root:root
#   /usr/local/lib/cockpit-secrets/              0755 root:root
#   /usr/local/lib/cockpit-secrets/backends/     0755, *.py 0644 and NOTHING else
#   /usr/local/lib/cockpit-secrets/schema/       0755, *.json 0644
#   /etc/cockpit-secrets/                        0755 root:root
#   /etc/cockpit-secrets/safes.d/                0755 root:root   the registry
#   /etc/cockpit-secrets/safes/                  0700 root:root   admin-class safe files
#   /var/log/cockpit-secrets/                    0700 root:root   audit.log
#   /var/lib/cockpit-secrets/                    0700 root:root
#   /var/lib/cockpit-secrets/state/              0700 root:root   lockout counters (I16)
#   /var/lib/cockpit-secrets/exports/            0700 root:root   export destination (I21)
#   /usr/local/lib/cockpit-secrets/agent/        --with-agent only
#   /usr/local/lib/cockpit-secrets/secrets-agent --with-agent only, if the source
#                                                tree ships one (0755; today it
#                                                ships modules and no executable)
#   /usr/local/lib/systemd/user/                 --with-agent only
#   /usr/local/lib/systemd/user/secrets-agent.*  --with-agent only
#   /usr/local/lib/systemd/system/               --with-agent only
#   /usr/local/lib/systemd/system/secrets-agent@.*  --with-agent only, NOT enabled
#
# --uninstall removes every one of those EXCEPT the data locations it names on
# the way out: /etc/cockpit-secrets (the registry and the safe files),
# /var/log/cockpit-secrets (the audit log), /var/lib/cockpit-secrets/state
# (lockout counters) and /var/lib/cockpit-secrets/exports (which may hold
# PLAINTEXT exports - see docs/OPERATIONS.md, "The exports directory").
#
# What it never does:
#
#   - restart, reload or otherwise disturb Cockpit. cockpit.socket is a live
#     service on this host and rescans its package directory on the next page
#     load anyway.
#   - write over any *.json already in safes.d/. An operator's registry entry is
#     the access-control policy for a safe; clobbering one would silently change
#     who can open what. Examples are seeded as *.json.example, which the
#     registry's *.json glob does not match, so a seeded example can never
#     become a live safe by accident.
#   - open, read, move or modify any safe file, backup or key file.
#   - print the contents of anything. Root work on this host goes through the
#     /srv/jobs runner and its output.log is group-readable.
#   - enable or start the agent. That is a per-user systemd decision and it is
#     the operator's to make, deliberately (I18).
#
# There is no `set -x` anywhere in this tree (I15). A traced shell would put
# every path and every argument it sees into that group-readable job log.
#
set -Eeuo pipefail

SRC="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"
NAME="secrets"
VERSION="$(cat "$SRC/VERSION" 2>/dev/null || echo 0.0.0)"

# Modes are always given to `install` explicitly; this umask only covers the
# handful of shell redirections below, so nothing can land group-readable by
# accident.
umask 022

DESTDIR="${DESTDIR:-}"

# The runtime location of the helper's Python packages. The helper resolves its
# library root as: the directory holding secrets-admin (the repo layout, where
# backends/ and schema/ sit beside it), else this path. Installed layout and
# repo layout therefore both work with no code change - see README.md,
# "Installed layout".
LIBDIR_RUNTIME="/usr/local/lib/cockpit-secrets"

PKGDIR="$DESTDIR/usr/share/cockpit/$NAME"
SBINDIR="$DESTDIR/usr/local/sbin"
HELPER_DST="$SBINDIR/secrets-admin"
LIBDIR="$DESTDIR$LIBDIR_RUNTIME"
ETCDIR="$DESTDIR/etc/cockpit-secrets"
SAFESD="$ETCDIR/safes.d"
SAFESDIR="$ETCDIR/safes"
LOGDIR="$DESTDIR/var/log/cockpit-secrets"
STATEDIR="$DESTDIR/var/lib/cockpit-secrets/state"
EXPORTDIR="$DESTDIR/var/lib/cockpit-secrets/exports"
EXAMPLEDIR="$DESTDIR/usr/local/share/cockpit-secrets/examples"
USERUNITDIR="$DESTDIR/usr/local/lib/systemd/user"
SYSUNITDIR="$DESTDIR/usr/local/lib/systemd/system"

# The Cockpit package payload, flat. This ONE array is three things at once: the
# copy list in section 1, the stale-file sweep immediately after it, and the
# payload-present check in the pre-flight. They cannot disagree with each other
# because they are all reading this line.
#
# What they CAN disagree with is index.html, and for a release they did.
# `theme.js` was added to the page and not to this array, so section 1 copied
# four files and then swept the fifth straight back off the installed host on
# every single run. The pre-flight below now reads the page's own <script> and
# <link> references and refuses an install where the page asks for a file this
# array does not ship.
PLUGIN=(manifest.json index.html secrets.js secrets.css theme.js)

ACTION="install"
WITH_AGENT=0

# --------------------------------------------------------------- reporting ---
# Every mutation is recorded so the run can end with an exact list of what
# changed, rather than a wall of scrolling `install` output an operator has to
# reconstruct after the fact.
CHANGES=()
KEPT=()
WARNINGS=()

changed() { CHANGES+=("$*"); printf '  + %s\n' "$*"; }
kept()    { KEPT+=("$*");    printf '  = %s\n' "$*"; }
warn()    { WARNINGS+=("$*"); printf '  ! %s\n' "$*" >&2; }
note()    { printf '  %s\n' "$*"; }
die()     { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# --help is the header block, from line 2 to the `set -x` note. Addressed by
# that note rather than by a line number: the header grew this round and a
# hard-coded `2,51p` silently truncated it mid-sentence, which is the failure
# mode where a usage message stops matching the program.
usage() {
    sed -n '2,/^# There is no .set -x. anywhere/p' "${BASH_SOURCE[0]}" \
        | sed '$d' | sed 's/^# \?//'
    exit "${1:-0}"
}

while (($#)); do
    case "$1" in
        --uninstall)  ACTION="uninstall"; shift ;;
        --with-agent) WITH_AGENT=1; shift ;;
        -h|--help)    usage 0 ;;
        *) printf 'install.sh: unknown option: %s\n\n' "$1" >&2; usage 1 ;;
    esac
done

# Refuse before touching anything. Half an install of a program that holds
# passphrases is worse than none: the page would load and every verb would fail
# on a permission the operator cannot see.
[[ $EUID -eq 0 ]] || die "must be run as root (on this host: submit it to the /srv/jobs runner). Nothing was changed."

# ======================================================================
# uninstall
# ======================================================================
if [[ $ACTION == uninstall ]]; then
    echo "Uninstalling cockpit-secrets"

    for target in "$PKGDIR" "$LIBDIR/backends" "$LIBDIR/schema" "$LIBDIR/agent"; do
        if [[ -d $target ]]; then rm -rf -- "$target"; changed "removed $target"
        else note "not present: $target"; fi
    done
    for target in "$HELPER_DST" "$LIBDIR/secrets-agent"; do
        if [[ -e $target ]]; then rm -f -- "$target"; changed "removed $target"
        else note "not present: $target"; fi
    done

    # Only ever remove units this package installs, by exact name prefix - a
    # wildcard in a shared unit directory is how you delete someone else's
    # service.
    #
    # BOTH directories, and the two globs differ. `secrets-agent.*` does not
    # match `secrets-agent@.service`, so the user glob alone left the system
    # template installed after an uninstall - software this package put there,
    # under "an uninstall removes the software", still on disk. The header's
    # list of what --with-agent touches now has a removal for every line in it.
    shopt -s nullglob
    for unit in "$USERUNITDIR"/secrets-agent.* "$SYSUNITDIR"/secrets-agent@.*; do
        rm -f -- "$unit"; changed "removed $unit"
    done
    shopt -u nullglob

    # rmdir, not rm -rf: it succeeds only if we left nothing behind and cannot
    # take a directory another package put files in.
    [[ -d $LIBDIR ]] && rmdir -- "$LIBDIR" 2>/dev/null && changed "removed $LIBDIR"

    echo
    echo "KEPT, deliberately - an uninstall removes the software, not your data:"
    echo "  $SAFESD/"
    echo "      Your registry entries: the access-control policy for every safe."
    echo "      Removing the software must not silently change who may open what."
    echo "  $SAFESDIR/"
    echo "      Safe files. This program never deletes a safe; the backup ring is"
    echo "      the only undo it has, and neither is ours to throw away."
    echo "  $LOGDIR/"
    echo "      The audit log: who opened what, and when. It outlives the tool."
    echo "  $STATEDIR/"
    echo "      Lockout counters (I16). Uninstalling must not be a way to clear a"
    echo "      lockout."
    echo "  $EXPORTDIR/"
    echo "      The export destination. If anybody ever ran the export verb, a"
    echo "      file here is an ENTIRE SAFE IN PLAINTEXT (I21). Removing the"
    echo "      software must not be the moment those quietly disappear - or"
    echo "      quietly survive unnoticed. LOOK IN IT, then shred what is there:"
    echo "        ls -l $EXPORTDIR/"
    echo "        shred -u $EXPORTDIR/*        # not rm: see docs/OPERATIONS.md"
    echo
    echo "To remove those too, after you have read them - and after you have"
    echo "shredded any export, because rm -rf does not:"
    echo "  rm -rf $ETCDIR $LOGDIR $DESTDIR/var/lib/cockpit-secrets"
    echo
    if ((${#CHANGES[@]})); then
        echo "Removed ${#CHANGES[@]} item(s). Cockpit was not restarted; the page"
        echo "disappears from the menu on the next login."
    else
        echo "Nothing was installed here. Nothing removed."
    fi
    echo
    echo "If anyone enabled the agent, they must turn it off in their OWN session -"
    echo "root cannot reach another user's systemd instance:"
    echo "  systemctl --user disable --now secrets-agent.socket"
    exit 0
fi

# ======================================================================
# pre-flight - everything that can refuse happens before anything is written
# ======================================================================
echo "Installing cockpit-secrets $VERSION"
note "from: $SRC"
note "to:   ${DESTDIR:-/} (Cockpit package, helper, registry, logs)"
echo
echo "Pre-flight"

# --- payload present -------------------------------------------------------
missing=()
for f in "${PLUGIN[@]}" secrets-admin; do
    [[ -f "$SRC/$f" ]] || missing+=("$f")
done
[[ -f "$SRC/backends/base.py" ]]                || missing+=("backends/base.py")
[[ -f "$SRC/schema/safe-registry.schema.json" ]] || missing+=("schema/safe-registry.schema.json")
((${#missing[@]} == 0)) || die "missing source file(s): ${missing[*]}. Nothing was changed."
note "payload complete (${#PLUGIN[@]} package files, helper, backends, schema)"

# --- the page asks for exactly what we ship --------------------------------
# The defect this exists to make impossible, by name. `theme.js` was added to
# index.html and not to PLUGIN; section 1 copies PLUGIN and then sweeps $PKGDIR
# down to PLUGIN, so the file was deleted from the installed host on every run
# and the page shipped a reference to a resource that was not there.
#
# The cost was NOT the "404s silently" the page's own comment claimed. Cockpit
# does not answer a missing package file with a bare 404: it serves an HTML
# error page, and Chromium then logs
#
#   Refused to execute script from '.../theme.js' because its MIME type
#   ('text/html') is not executable, and strict MIME type checking is enabled.
#
# on EVERY page load, which is a permanent console error on the one page in
# this host that handles every passphrase we own, and a live browser assertion
# that a clean console is what a clean CSP looks like.
#
# This REFUSES rather than warning. Nothing has been written at this point, the
# fix is one word in one array, and a warning is exactly what the last round
# produced - a true statement nobody acted on for a release.
#
# Only package-local references are considered. `../base1/cockpit.js` is
# Cockpit's own file, served from Cockpit's own directory, and is deliberately
# not ours to install.
python3 - "$SRC/index.html" "${PLUGIN[@]}" <<'PY' \
    || die "index.html references a file this installer does not ship (above). Nothing was changed."
import html.parser, sys

path, ship = sys.argv[1], set(sys.argv[2:])
refs = []


class Refs(html.parser.HTMLParser):
    """Every attribute that makes the browser fetch a second file from this
    package directory. Parsed, not grepped: a regex over HTML is how you miss
    the one attribute that is spelled differently."""

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
    # A scheme, an authority, an absolute path or a parent segment all name
    # something outside this package directory, which this installer neither
    # ships nor sweeps.
    low = u.lower()
    if "://" in low or low.startswith(("//", "/", "data:", "mailto:", "../")):
        continue
    if "/" in u:
        # The payload is FLAT - PLUGIN holds bare names and section 1 copies
        # them into one directory - so a subdirectory reference cannot be
        # shipped by this installer at all, however the array is edited.
        bad.append("%s (<%s>: the Cockpit payload is flat, so no PLUGIN entry "
                   "can ever satisfy this)" % (u, tag))
        continue
    local.append(u)
    if u not in ship:
        bad.append("%s (<%s>)" % (u, tag))

if bad:
    sys.exit("index.html references %s, which install.sh's PLUGIN array does not\n"
             "  install - so section 1's stale-file sweep DELETES it from the installed\n"
             "  package on every run and Cockpit answers the browser's request with an\n"
             "  HTML error page. Add it to PLUGIN in install.sh, or make the page\n"
             "  stop asking for it."
             % ", ".join(sorted(set(bad))))
print("  index.html: %d package-local reference(s), every one of them installed "
      "(%s)" % (len(local), ", ".join(local)))
PY

# --- the manifest ----------------------------------------------------------
# An invalid manifest makes Cockpit drop the package SILENTLY: no page, no menu
# entry, no error anywhere the operator will look. Refusing here is worth the
# three seconds. The same check enforces I9: this package must run under
# Cockpit's default `default-src 'self'` and must not ship a relaxed policy -
# adding wasm-unsafe-eval to the one page that handles every password we own is
# exactly the trade docs/UPSTREAM-REVIEW.md rejected.
python3 - "$SRC/manifest.json" <<'PY' || die "manifest.json rejected (see above). Nothing was changed."
import json, sys

path = sys.argv[1]
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
                sys.exit("%s declares a Content-Security-Policy at %s.%s - "
                         "refused: this package must run under Cockpit's default "
                         "policy (I9)" % (path, where, k))
            scan(v, "%s.%s" % (where, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            scan(v, "%s[%d]" % (where, i))

scan(m)
print("  manifest.json: valid JSON, no CSP relaxation (I9)")
if "superuser" not in json.dumps(m):
    print("  manifest.json: note - no 'superuser' declaration found; admin-class "
          "safes need Cockpit's Administrative access")
PY

# --- python payload compiles ----------------------------------------------
# compile() rather than py_compile: it proves the file parses without writing a
# __pycache__ into the source tree (or into DESTDIR, where it would then be
# installed).
pyfiles=("$SRC/secrets-admin")
shopt -s nullglob
pyfiles+=("$SRC"/backends/*.py "$SRC"/agent/*.py)
shopt -u nullglob
for f in "${pyfiles[@]}"; do
    python3 -c 'import sys; src=open(sys.argv[1],"rb").read(); compile(src, sys.argv[1], "exec")' "$f" \
        || die "does not compile: $f. Nothing was changed."
done
note "python payload compiles (${#pyfiles[@]} file(s))"

# --- the JavaScript gate ---------------------------------------------------
# There is no build step; check.sh is the only thing between a stray paren and a
# blank panel in the browser.
if [[ -x "$SRC/check.sh" ]]; then
    if command -v gjs >/dev/null 2>&1; then
        # Not redirected: when it fails, the parser's message and the line it
        # names are the whole point.
        "$SRC/check.sh" || die "check.sh found a JavaScript syntax error (above). Nothing was changed."
    else
        warn "gjs is not installed: the JavaScript syntax gate did not run"
    fi
else
    warn "check.sh missing or not executable: JavaScript was not syntax-checked"
fi

# --- the registry schema and the seeded examples ---------------------------
# The examples ship as documentation, so they must actually be valid against the
# schema they document. A broken example teaches an operator a broken shape.
# The `user-safes.d/` glob is SEPARATE and is not a tidy-up: `*.json` does not
# descend, so the per-user example was the one shipped registry entry that no
# gate validated. It is validated here and installed as DOCUMENTATION below —
# never seeded into the system registry, because a per-user entry there is an
# entry naming a path in somebody's home directory read by a root helper.
shopt -s nullglob
EXAMPLES=("$SRC"/etcdefaults/*.json "$SRC"/etcdefaults/user-safes.d/*.json)
shopt -u nullglob
python3 - "$SRC/schema/safe-registry.schema.json" "${EXAMPLES[@]}" <<'PY' \
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
    print("  registry schema: valid JSON (python3-jsonschema absent, examples "
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
    print("  registry schema + %d example(s): valid (jsonschema)" % len(examples))
PY

# --- the deployment contract the helper has to meet ------------------------
# Advisory, not fatal: the helper is another file's responsibility and the smoke
# test at the end is the real verdict. But saying it here turns "every verb
# returns internal" into one obvious line at install time.
if ! grep -qF "$LIBDIR_RUNTIME" "$SRC/secrets-admin"; then
    warn "secrets-admin does not mention $LIBDIR_RUNTIME; if it cannot import backends/ from there, the smoke test below will say so"
fi

# --- the agent, only if it was asked for -----------------------------------
AGENT_UNITS=()
AGENT_SYS_UNITS=()
AGENT_PY=()
AGENT_BIN=""
if ((WITH_AGENT)); then
    [[ -d "$SRC/agent" ]] || die "--with-agent was given but $SRC/agent does not exist (the optional agent may have been dropped - see docs/KNOWN_ISSUES.md I18). Nothing was changed."
    shopt -s nullglob
    # TWO GLOBS, TWO DESTINATIONS, and the separation is deliberate. The USER
    # units live directly under agent/systemd/; the SYSTEM template lives one
    # level down in agent/systemd/system/. A single recursive glob would drop
    # `secrets-agent@.service` into the user unit directory, where systemd
    # would read `User=%i` and `SocketUser=%i` in a per-user manager that
    # cannot honour either — silently wrong, and wrong about identity, which
    # is the one thing this agent exists to get right.
    AGENT_UNITS=("$SRC"/agent/systemd/*.socket "$SRC"/agent/systemd/*.service \
                 "$SRC"/agent/*.socket "$SRC"/agent/*.service)
    AGENT_SYS_UNITS=("$SRC"/agent/systemd/system/*.socket \
                     "$SRC"/agent/systemd/system/*.service)
    AGENT_PY=("$SRC"/agent/*.py)
    shopt -u nullglob
    [[ -f "$SRC/agent/secrets-agent" ]] && AGENT_BIN="$SRC/agent/secrets-agent"
    ((${#AGENT_UNITS[@]})) || die "--with-agent was given but no .socket/.service unit was found under $SRC/agent. Nothing was changed."
    note "agent payload: ${#AGENT_UNITS[@]} user unit(s), ${#AGENT_SYS_UNITS[@]} system template(s), ${#AGENT_PY[@]} module(s)${AGENT_BIN:+, 1 executable}"
fi

echo
echo "Installing"

# ======================================================================
# helpers that make "what changed" honest
# ======================================================================

# put <mode> <src> <dst> - copy only when the bytes differ, and say which of
# installed / updated / re-permissioned / unchanged happened. cmp is what makes
# the closing summary a real diff rather than a list of everything that was
# touched.
put() {
    local mode="$1" src="$2" dst="$3" verb="installed"
    if [[ -e $dst ]] && cmp -s -- "$src" "$dst"; then
        # Same bytes - but still re-assert mode and owner, because a helper that
        # drifted to group-writable is a real finding and is cheap to fix. Report
        # it only if it actually moved.
        local before after
        before="$(stat -c '%a %U:%G' -- "$dst")"
        install -o root -g root -m "$mode" -- "$src" "$dst"
        after="$(stat -c '%a %U:%G' -- "$dst")"
        if [[ $before == "$after" ]]; then kept "unchanged $dst"
        else changed "re-permissioned $dst ($before -> $after)"; fi
        return
    fi
    [[ -e $dst ]] && verb="updated"
    install -o root -g root -m "$mode" -- "$src" "$dst"
    changed "$verb $dst (mode $mode)"
}

# ensure_dir <path> <mode> <why-it-matters>
# Creates with an explicit mode, or leaves an existing directory alone and warns
# if its mode is looser than this program can defend. It never silently
# re-permissions a directory an operator already has: that could break a
# deliberate local policy, and a warning naming the exact chmod is more use than
# a surprise.
ensure_dir() {
    local d="$1" mode="$2" why="$3"
    if [[ -d $d ]]; then
        local have owner mask
        have="$(stat -c '%a' -- "$d")"
        owner="$(stat -c '%U' -- "$d")"
        kept "kept $d (mode 0$have, owner $owner)"
        case "$mode" in
            0700) mask=$((8#077)) ;;   # nothing for group or other at all
            *)    mask=$((8#022)) ;;   # nobody but the owner may write
        esac
        if (( 8#$have & mask )); then
            warn "$d is mode 0$have - $why  Fix: chmod $mode $d"
        fi
        if [[ -z $DESTDIR && $owner != root ]]; then
            warn "$d is owned by $owner, not root - $why  Fix: chown root:root $d"
        fi
    else
        # Create any missing parents at 0755 FIRST. `install -d -m 0700` applies
        # its mode to every component it has to create, which would leave a
        # staging root with a 0700 /var - correct for the leaf, wrong for
        # everything above it.
        local parent; parent="$(dirname -- "$d")"
        [[ -d $parent ]] || install -d -o root -g root -m 0755 -- "$parent"
        install -d -o root -g root -m "$mode" -- "$d"
        changed "created $d (mode $mode)"
    fi
}

# ======================================================================
# 1. the Cockpit package
# ======================================================================
ensure_dir "$PKGDIR" 0755 "Cockpit serves this directory to every logged-in session."
for f in "${PLUGIN[@]}"; do
    put 0644 "$SRC/$f" "$PKGDIR/$f"
done

# Drop anything a previous version left behind: an old file that is no longer in
# the source tree must not keep being served.
#
# This sweep is the WHOLE invariant for $PKGDIR, unlike the one in section 2.
# Nothing in this script writes into $PKGDIR after this loop - there is no
# import, no smoke test and no verification step that touches it - so there is
# nothing for section 5b to re-check here, which is why 5b is scoped to the
# library root and says so. What could put this directory out of step with the
# header is not a late writer but an edit to PLUGIN, and the pre-flight gate
# above is what catches that.
shopt -s nullglob
for existing in "$PKGDIR"/*; do
    base="$(basename -- "$existing")"
    keep=0
    for f in "${PLUGIN[@]}"; do [[ $base == "$f" ]] && keep=1; done
    if ((!keep)); then rm -rf -- "$existing"; changed "removed stale $existing"; fi
done
shopt -u nullglob

# ======================================================================
# 2. the helper, its backends and the registry schema
# ======================================================================
ensure_dir "$SBINDIR" 0755 "it holds a root-run helper."
put 0755 "$SRC/secrets-admin" "$HELPER_DST"

ensure_dir "$LIBDIR" 0755 "the helper imports code from here as root."
ensure_dir "$LIBDIR/backends" 0755 "the helper imports code from here as root."
shopt -s nullglob
for f in "$SRC"/backends/*.py; do
    put 0644 "$f" "$LIBDIR/backends/$(basename -- "$f")"
done
# Sweep anything that is not one of the .py files we just installed. That covers
# a module deleted upstream and a __pycache__ from a previous run - which is also
# why the loop above globs *.py explicitly instead of copying the directory:
# root-owned bytecode next to root-run source is a second thing to keep honest
# and buys nothing.
#
# THIS SWEEP IS NOT THE WHOLE STORY, and believing it was is what made the
# invariant false for a whole release. Anything that imports the package after
# this line puts the bytecode straight back, and section 5 below - this script's
# own verification - did exactly that. The three parts that make the claim true
# are: this sweep; `sys.dont_write_bytecode` in secrets-admin, so no root run of
# the helper ever writes any; and the assertion in section 5b, which re-checks
# the directory after everything else has run.
for existing in "$LIBDIR"/backends/*; do
    base="$(basename -- "$existing")"
    if [[ $base != *.py || ! -f "$SRC/backends/$base" ]]; then
        rm -rf -- "$existing"; changed "removed stale $existing"
    fi
done

ensure_dir "$LIBDIR/schema" 0755 "the helper validates every registry entry against it."
for f in "$SRC"/schema/*.json; do
    put 0644 "$f" "$LIBDIR/schema/$(basename -- "$f")"
done
shopt -u nullglob

# ======================================================================
# 3. configuration, logs and state
# ======================================================================
# /etc/cockpit-secrets/safes.d is the whole access-control policy: the helper
# refuses to trust it at all if it, or an entry in it, is group- or
# other-writable (I1).
ensure_dir "$ETCDIR"    0755 "it holds the registry that decides who may open which safe."
ensure_dir "$SAFESD"    0755 "the helper REFUSES a group- or other-writable registry directory (I1)."
# 0700: an admin-class safe is 0600 root:root and the directory holding it has no
# business being listable by anyone else.
ensure_dir "$SAFESDIR"  0700 "it holds admin-class safe files."
# The audit log names safes, verbs and uids. It never contains a value (I15), but
# it is still a map of who holds what.
ensure_dir "$LOGDIR"    0700 "it holds the audit log."
ensure_dir "$DESTDIR/var/lib/cockpit-secrets" 0700 "it holds unlock-failure state."
ensure_dir "$STATEDIR"  0700 "it holds the per-(uid, safe) lockout counters (I16)."
# The default export destination (I21). The helper creates it 0700 on first use
# anyway, so this is not load-bearing — but an operator who can SEE the
# directory the moment the package is installed can reason about it before an
# export lands in it, and a directory that appears the first time somebody dumps
# a safe in the clear is a directory nobody has ever looked at. Empty and 0700
# until `export_allowed` is turned on for some safe, which is off by default.
ensure_dir "$EXPORTDIR"  0700 "an export is an ENTIRE SAFE IN PLAINTEXT (I21)."

# Seed the examples, and ONLY where nothing is there already.
#
# They are seeded with a .example suffix, which the registry's *.json glob does
# not match, for two reasons that are worth the ugly file name:
#   - a live example entry would appear in the safe list as a permanently broken
#     row, which trains operators to ignore broken rows in a security UI;
#   - worse, it would become a REAL safe with real access rules the moment
#     anyone created a file at the example path. An access-control policy must
#     never appear by accident.
# The operator copies one to <nn>-<id>.json and edits it (see docs/OPERATIONS.md).
shopt -s nullglob
for src in "$SRC"/etcdefaults/*.json; do
    dst="$SAFESD/$(basename -- "$src").example"
    if [[ -e $dst ]]; then
        kept "kept existing $dst (not overwritten)"
    else
        install -o root -g root -m 0644 -- "$src" "$dst"
        changed "seeded $dst"
    fi
done
shopt -u nullglob

# The PER-USER example goes where documentation goes, not where policy goes.
# `etcdefaults/user-safes.d/README.md` tells the operator to copy it into a
# user's own `~/.config/cockpit-secrets/safes.d/`, and it has to exist somewhere
# on the installed host for that instruction to mean anything. It is NOT seeded
# into $SAFESD — see the comment above the loop.
ensure_dir "$EXAMPLEDIR" 0755 "it holds shipped documentation, not policy."
ensure_dir "$EXAMPLEDIR/user-safes.d" 0755 "it holds the per-user registry example."
shopt -s nullglob
for src in "$SRC"/etcdefaults/user-safes.d/*; do
    [[ -f $src ]] || continue
    put 0644 "$src" "$EXAMPLEDIR/user-safes.d/$(basename -- "$src")"
done
shopt -u nullglob

# Registry entries the operator wrote are never touched. Say so out loud, with a
# count, so the summary is checkable rather than a promise.
shopt -s nullglob
live=("$SAFESD"/*.json)
shopt -u nullglob
if ((${#live[@]})); then
    note "left ${#live[@]} existing registry entry/entries in $SAFESD untouched"
fi

# ======================================================================
# 4. the optional unlock agent (--with-agent only)
# ======================================================================
if ((WITH_AGENT)); then
    ensure_dir "$LIBDIR/agent" 0755 "the agent imports code from here."
    for f in "${AGENT_PY[@]}"; do
        put 0644 "$f" "$LIBDIR/agent/$(basename -- "$f")"
    done
    [[ -n $AGENT_BIN ]] && put 0755 "$AGENT_BIN" "$LIBDIR/secrets-agent"

    # A USER unit, not a system one, on purpose: the agent must run AS the user
    # whose safes it holds, so SO_PEERCRED on its socket is an identity and not a
    # broker authenticating on everyone's behalf (I18).
    ensure_dir "$USERUNITDIR" 0755 "systemd reads user units from here."
    for u in "${AGENT_UNITS[@]}"; do
        put 0644 "$u" "$USERUNITDIR/$(basename -- "$u")"
    done

    # The SYSTEM template, for the admin access class. Installed, never
    # enabled: `secrets-agent@<uid>.socket` is one agent per operator behind a
    # 0700 run dir, and deciding that an administrator's safes may stay open is
    # not an installer's decision to make (I18). agent/README.md has the
    # enable line and the argument against running it at all.
    if ((${#AGENT_SYS_UNITS[@]})); then
        ensure_dir "$SYSUNITDIR" 0755 "systemd reads system units from here."
        for u in "${AGENT_SYS_UNITS[@]}"; do
            put 0644 "$u" "$SYSUNITDIR/$(basename -- "$u")"
        done
        note "installed ${#AGENT_SYS_UNITS[@]} system template(s), NOT enabled: see agent/README.md"
    fi

    # Every ExecStart= in the units we just installed must point at something
    # that exists, or the operator finds out at first use instead of now.
    shopt -s nullglob
    for u in "$USERUNITDIR"/secrets-agent.* "$SYSUNITDIR"/secrets-agent@.*; do
        while read -r bin; do
            [[ -n $bin ]] || continue
            [[ -e "$DESTDIR$bin" ]] || warn "$(basename -- "$u") runs $bin, which is not installed"
        done < <(sed -n 's/^ExecStart=[-@+!]*\([^ ]*\).*/\1/p' -- "$u")
    done
    shopt -u nullglob
fi

# ======================================================================
# 5. smoke test - only against a real installation, never a staging root
# ======================================================================
# In a DESTDIR the helper is not at the path it will run from and its library
# root does not exist yet, so running it would prove nothing.
echo
echo "Verifying"
if [[ -z $DESTDIR ]]; then
    # Does the library root the helper depends on actually import? This isolates
    # a path problem from a helper problem.
    #
    # `-B` IS LOAD-BEARING. Without it this probe is a writer: it imports a
    # package out of a root-owned directory as root, and CPython caches the
    # bytecode next to the source - under this script's umask 022, so 0644.
    # That single line put a __pycache__ back into a directory the sweep above
    # had just cleaned, four files, and the installer then reported success
    # against an invariant it had broken itself.
    if python3 -B -c "import sys; sys.path.insert(0, '$LIBDIR_RUNTIME'); import backends" 2>/dev/null; then
        note "backends import from $LIBDIR_RUNTIME"
    else
        warn "python3 cannot import backends from $LIBDIR_RUNTIME"
    fi
    # One JSON object on stdout and nothing else, exit 0 - the whole contract in
    # one call. Only the verdict is printed: health output names safes and paths,
    # and this runs in a group-readable job log (I15).
    #
    # Deliberately NOT run with PYTHONDONTWRITEBYTECODE=1, even though that
    # would also stop the bytecode: the helper has to be smoke-tested in the
    # environment it will really run in. It sets `sys.dont_write_bytecode`
    # itself, and section 5b is what proves it - handing it the variable here
    # would test the variable instead of the helper.
    if out="$("$HELPER_DST" health 2>/dev/null)" \
       && printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d, dict) else 1)' 2>/dev/null; then
        note "secrets-admin health: one JSON object, exit 0"
    else
        warn "secrets-admin health did not return a JSON object - run '$HELPER_DST health' by hand"
    fi
else
    note "staged into $DESTDIR; smoke test skipped (the helper is not at its runtime path)"
fi

# ======================================================================
# 5b. the library root holds exactly what we installed - ASSERTED, LAST
# ======================================================================
# The header of this file claims a precise list of what the installation
# contains. That claim was false for a release: the sweep in section 2 removed
# the bytecode and section 5 imported the package again and recreated it, four
# root-owned .pyc files in two different modes from two different umasks
# (docs/ROOT-VERIFICATION.md F1). The comment saying why bytecode does not
# belong there was still sitting eight lines above the code that wrote it.
#
# So the invariant is now CHECKED here rather than asserted in prose, and it is
# checked LAST - after the sweep, after both verification steps, after anything
# else this script might grow. A future change that imports the package one more
# time, or a helper that starts writing bytecode again, cannot pass this
# quietly.
#
# It repairs and reports rather than dying: at this point the package is
# installed and working, and the defect is in the installer, not the
# installation. `warn` is not a quiet channel - it prints to stderr, it lists
# the file in the "Action required" block below, and tests/root/20-verify-
# install.sh fails an install that emits any such line. That is where this
# becomes a test failure.
assert_library_root_clean() {
    [[ -d $LIBDIR ]] || return 0
    local stray=() existing base

    shopt -s nullglob dotglob
    # Top level: the two package directories, plus the agent's two names. The
    # agent names are allowed unconditionally, NOT only under --with-agent: a
    # plain reinstall on a host where somebody installed the agent must not
    # delete the code their systemd units point at. Uninstall is where the agent
    # goes away, and it does so by name.
    for existing in "$LIBDIR"/*; do
        base="$(basename -- "$existing")"
        case "$base" in
            backends|schema|agent|secrets-agent) continue ;;
        esac
        stray+=("$existing")
    done
    # backends/ - exactly the source's *.py and nothing else. This is the
    # directory F1 was measured in.
    for existing in "$LIBDIR"/backends/*; do
        base="$(basename -- "$existing")"
        [[ $base == *.py && -f "$SRC/backends/$base" ]] && continue
        stray+=("$existing")
    done
    # schema/ - exactly the source's *.json.
    for existing in "$LIBDIR"/schema/*; do
        base="$(basename -- "$existing")"
        [[ $base == *.json && -f "$SRC/schema/$base" ]] && continue
        stray+=("$existing")
    done
    # agent/ only when it is installed. Same rule, same reason: it is a Python
    # package imported from a root-owned directory.
    if [[ -d "$LIBDIR/agent" ]]; then
        for existing in "$LIBDIR"/agent/*; do
            base="$(basename -- "$existing")"
            [[ $base == *.py && -f "$SRC/agent/$base" ]] && continue
            stray+=("$existing")
        done
    fi
    shopt -u nullglob dotglob

    if ((${#stray[@]} == 0)); then
        note "library root holds exactly the installed payload (no bytecode, no strays)"
        return 0
    fi
    for existing in "${stray[@]}"; do
        rm -rf -- "$existing"; changed "removed unexpected $existing"
    done
    warn "the library root contained ${#stray[@]} file(s)/directory(ies) this installer did not put there - removed, but something in THIS script or in secrets-admin wrote them after the stale-file sweep. See docs/ROOT-VERIFICATION.md F1: ${stray[*]}"
}
assert_library_root_clean

# ======================================================================
# 6. what changed, and what the operator does next
# ======================================================================
echo
echo "Summary"
printf '  %d change(s), %d unchanged, %d warning(s)\n' \
    "${#CHANGES[@]}" "${#KEPT[@]}" "${#WARNINGS[@]}"
if ((${#WARNINGS[@]})); then
    echo
    echo "  Action required:"
    for w in "${WARNINGS[@]}"; do printf '    ! %s\n' "$w"; done
fi

# The instructions below name the paths the operator will actually type, which
# are the runtime paths - a staging root is a build artefact, not somewhere
# anyone registers a safe.
R_SAFESD="${SAFESD#"$DESTDIR"}"
R_SAFESDIR="${SAFESDIR#"$DESTDIR"}"

cat <<EOF

Next steps
  1. Reload Cockpit in the browser (Ctrl-Shift-R). Log out and back in for the
     menu entry. Cockpit was NOT restarted and no service was touched.
  2. Register a safe. Nothing is visible until you do - the registry is the only
     source of safes and it ships empty:
       cp $R_SAFESD/10-example-admin.json.example \\
          $R_SAFESD/10-lab-dc.json
       \$EDITOR $R_SAFESD/10-lab-dc.json      # id, label, path, access
       chmod 0644 $R_SAFESD/10-lab-dc.json
       secrets-admin health                   # registry_errors[] must be empty
     An entry that omits "access" is an ADMIN safe. That default is deliberate:
     a hand-edit that loses a line must fail closed (I1).
  3. Put admin-class safes in $R_SAFESDIR, mode 0600 root:root.
     A user-class safe lives in that user's own tree, mode 0600, owned by them.
  4. Read docs/OPERATIONS.md before the first save: the backup ring, the
     "changed on disk" conflict, and the lossless-save guard (I22) all behave in
     ways that are obvious afterwards and surprising the first time.

The agent stays off unless a registry entry sets agent.enabled - and it should
stay off. See docs/OPERATIONS.md, "The agent, and why you probably should not".
EOF

exit 0
