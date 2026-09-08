#!/usr/bin/env bash
#
# check.sh - the JavaScript syntax gate.
#
# There is no build step for a Cockpit package: the files in this directory are
# the files the browser loads, byte for byte. A stray paren therefore ships
# straight to the browser, where it appears as a blank panel and a single line
# in the console - a miserable way to find a typo on the one page in this host
# that handles every passphrase we own. This gate catches it before install.sh
# copies anything.
#
#   ./check.sh          # from anywhere; it cds to its own directory
#
# Exit 0 = every .js file parsed (or there is no .js yet, which is not a
# failure while the tree is still being built). Exit 1 = a syntax error, with
# the parser's message.
#
# How it works, and why it is shaped like this:
#
#   gjs parses each file inside a wrapper function that is never called.
#   Parsing happens before execution, so a syntax error still surfaces, while
#   `cockpit`, `document`, `window` and `navigator` - none of which exist in
#   gjs - become harmless formal parameters instead of ReferenceErrors. The
#   wrapper signature is the same one source/validate.sh uses, deliberately: a
#   file must not be able to pass one gate and fail the other.
#
#   The wrapper header and the file's first line share a line, so gjs's line
#   numbers are the source file's own line numbers with no mental arithmetic.
#
#   Scratch files go in a private mktemp -d, not a predictable /tmp/<name>.
#   This is a multi-user host (docs/THREAT-MODEL.md A1): another local user can
#   pre-create a predictable path as a symlink and turn a developer running a
#   syntax check into a file-overwrite primitive. A 0700 directory nobody can
#   guess removes that race.
#
# There is no `set -x` in this tree (I15): the root job runner's output.log is
# group-readable and a traced shell prints every argument it is given.
set -u

cd "$(dirname "$(readlink -f "$0")")" || exit 1

tmp="$(mktemp -d "${TMPDIR:-/tmp}/cockpit-secrets-check.XXXXXXXX")" || {
    echo "check.sh: cannot create a scratch directory" >&2; exit 1; }
# Remove the scratch tree on every exit path, including a signal.
trap 'rm -rf -- "$tmp"' EXIT INT TERM

shopt -s nullglob
files=(*.js)

if ((${#files[@]} == 0)); then
    # Progressive, like validate.sh: a check whose subject does not exist yet is
    # reported, not failed, so an early task is not blocked by a later task's
    # files.
    echo "check.sh: no *.js in $PWD yet - nothing to parse (not a failure)"
    exit 0
fi

if ! command -v gjs >/dev/null 2>&1; then
    # Say plainly that nothing was verified rather than exiting 0 in silence.
    # A missing tool is not a passing test, and install.sh reports this skip
    # separately so it cannot be lost in the noise.
    echo "check.sh: gjs is not installed - the JavaScript syntax gate DID NOT RUN." >&2
    echo "check.sh: install it with: apt-get install gjs" >&2
    echo "check.sh: ${#files[@]} file(s) left UNVERIFIED: ${files[*]}" >&2
    exit 0
fi

rc=0
for f in "${files[@]}"; do
    # No trailing newline after the wrapper header: line 1 of the wrapper is
    # line 1 of the source, so reported line numbers need no adjustment.
    {
        printf 'function __never(cockpit, document, window, navigator){'
        cat -- "$f"
        printf '\n}\n'
    } >"$tmp/$f" || { printf '  %-20s CANNOT READ\n' "$f"; rc=1; continue; }

    if gjs "$tmp/$f" 2>"$tmp/.err"; then
        printf '  %-20s syntax OK\n' "$f"
    else
        printf '  %-20s SYNTAX ERROR\n' "$f"
        # The parser's own message, indented, with the scratch path rewritten
        # back to the real file so the line it names can be opened directly.
        sed -e "s#$tmp/##g" -e 's/^/      /' "$tmp/.err"
        rc=1
    fi
    rm -f -- "$tmp/$f" "$tmp/.err"
done

exit $rc
