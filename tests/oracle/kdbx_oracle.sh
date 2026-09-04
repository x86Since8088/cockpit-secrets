#!/usr/bin/env bash
#
# kdbx_oracle.sh — a thin, disciplined wrapper over the installed keepassxc-cli.
#
# WHY THIS EXISTS
# ---------------
# docs/KNOWN_ISSUES.md I19: compliance is measured only against a FOREIGN
# implementation. KeePassXC 2.7.10 is the most-audited KDBX implementation we
# can get on this host, and docs/UPSTREAM-REVIEW.md §2.2 adopts it as the KDBX
# interop oracle (and rejects it as the engine). This wrapper is that oracle,
# and it exists so the three rules below are enforced in ONE place instead of
# being re-typed, and eventually mistyped, in every test:
#
#   1. the passphrase is fed on STDIN, never on argv (I10). keepassxc-cli has
#      no --password option at all — that is upstream's own good design and we
#      copy it. /proc/<pid>/cmdline is world-readable.
#   2. every invocation gets -q, so keepassxc-cli never blocks on a human
#      prompt and never mixes prompt text into the output a test parses.
#   3. no `set -x` (I15 — this host's /srv/jobs logs are group-readable and a
#      traced shell prints every argument, including anything piped in view of
#      the trace).
#
# TEST-ONLY. `show --protected` and `export` print cleartext secrets on purpose:
# that is what an oracle does. Never run this from a /srv/jobs job.
#
# TWO IMPLEMENTATION DETAILS THAT ARE LOAD-BEARING, NOT STYLE:
#   - the passphrase is piped with the bash BUILTIN `printf`. A builtin forks
#     nothing, so the value never becomes another process's argv. `echo` may be
#     /bin/echo depending on how the script is invoked; `printf` as used here is
#     always the builtin.
#   - never `<<<"$pass"`. Bash implements here-strings and here-documents with a
#     TEMPORARY FILE, which is bad practice #3 in docs/UPSTREAM-REVIEW.md §4 and
#     is exactly the "no secret in a temp file" half of I10.
#
# Usage:  see usage() below, or `kdbx_oracle.sh help`.
# The passphrase for the database is read from THIS script's stdin, once.
#
set -u

readonly CLI="${KEEPASSXC_CLI:-keepassxc-cli}"
readonly SELF="${0##*/}"

die() { printf '%s: %s\n' "$SELF" "$*" >&2; exit 2; }

usage() {
    cat >&2 <<'USAGE'
kdbx_oracle.sh — foreign KDBX oracle (keepassxc-cli). Passphrase on stdin.

  create   --file F [--keyfile K] [--no-password] [--decryption-time MS]
  import   --file F --xml X [--keyfile K] [--no-password]
  info     --file F [--keyfile K] [--no-password]
  ls       --file F [--group G] [--recursive] [--flat]
  show     --file F --entry E [--protected] [--all] [--attachments] [--attr NAME]
  totp     --file F --entry E
  search   --file F --term T
  export   --file F [--format xml|csv|html]
  mkdir    --file F --group G
  add      --file F --entry E [--username U] [--url U] [--notes N] [--entry-password]
  edit     --file F --entry E [--title T] [--username U] [--url U] [--notes N] [--entry-password]
  mv       --file F --entry E --group G
  rm       --file F --entry E
  attach-import --file F --entry E --name N --path P
  attach-export --file F --entry E --name N --out P
  db-edit  --file F [--set-keyfile K] [--unset-password]
  merge    --file F --from G                       (same credentials for both)
  verify   --file F                                one JSON object, the read/verify shape
  version

Common: --keyfile K, --no-password (both apply to every verb that opens a db).
STDIN: line 1 is the database passphrase. `create`/`import` consume it twice
(keepassxc-cli asks to repeat); `--entry-password` consumes one more line for
the entry's own password.
USAGE
}

# ------------------------------------------------------------- arg parsing --

verb="${1:-}"
[ -n "$verb" ] || { usage; exit 64; }
shift || true

file=""; entry=""; group=""; xml=""; term=""; name=""; path=""; out=""
fromdb=""; fmt="xml"; keyfile=""; nopass=0; recursive=0; flat=0; protected=0
showall=0; attachments=0; entrypw=0; dectime=""; title=""; username=""
url=""; notes=""; attr=""; setkeyfile=""; unsetpass=0

while [ $# -gt 0 ]; do
    case "$1" in
        --file)            file="${2:-}"; shift 2 ;;
        --entry)           entry="${2:-}"; shift 2 ;;
        --group)           group="${2:-}"; shift 2 ;;
        --xml)             xml="${2:-}"; shift 2 ;;
        --term)            term="${2:-}"; shift 2 ;;
        --name)            name="${2:-}"; shift 2 ;;
        --path)            path="${2:-}"; shift 2 ;;
        --out)             out="${2:-}"; shift 2 ;;
        --from)            fromdb="${2:-}"; shift 2 ;;
        --format)          fmt="${2:-}"; shift 2 ;;
        --keyfile)         keyfile="${2:-}"; shift 2 ;;
        --decryption-time) dectime="${2:-}"; shift 2 ;;
        --title)           title="${2:-}"; shift 2 ;;
        --username)        username="${2:-}"; shift 2 ;;
        --url)             url="${2:-}"; shift 2 ;;
        --notes)           notes="${2:-}"; shift 2 ;;
        --attr)            attr="${2:-}"; shift 2 ;;
        --set-keyfile)     setkeyfile="${2:-}"; shift 2 ;;
        --unset-password)  unsetpass=1; shift ;;
        --no-password)     nopass=1; shift ;;
        --recursive)       recursive=1; shift ;;
        --flat)            flat=1; shift ;;
        --protected)       protected=1; shift ;;
        --all)             showall=1; shift ;;
        --attachments)     attachments=1; shift ;;
        --entry-password)  entrypw=1; shift ;;
        # There is deliberately no --password / --passphrase. If you find
        # yourself wanting one, that is I10 asking to be violated.
        -h|--help)         usage; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
done

command -v "$CLI" >/dev/null 2>&1 || die "$CLI is not installed (keepassxc-full)"

# ------------------------------------------------------- passphrase intake --
#
# Read at most two lines: the database passphrase, and (only when the verb
# needs one) the new entry's password. `read -r` puts them in shell variables,
# which live in this process's memory and are NOT exported — so they are absent
# from /proc/<pid>/environ of every child (I10). Nothing is written to disk.

pass=""
entry_pass=""
if [ "$nopass" -eq 0 ]; then
    IFS= read -r pass || pass=""
fi
if [ "$entrypw" -eq 1 ]; then
    IFS= read -r entry_pass || entry_pass=""
fi

# feed <n> — writes the database passphrase to stdout <n> times, then the entry
# password if one was collected. Built entirely from builtins.
feed() {
    local n="$1" i
    if [ "$nopass" -eq 0 ]; then
        for ((i = 0; i < n; i++)); do printf '%s\n' "$pass"; done
    fi
    if [ "$entrypw" -eq 1 ]; then printf '%s\n' "$entry_pass"; fi
}

# key_args — the open-a-database options shared by nearly every verb.
key_args=()
[ -n "$keyfile" ] && key_args+=(-k "$keyfile")
[ "$nopass" -eq 1 ] && key_args+=(--no-password)

# run <feed-count> <cli args...> — the ONLY place keepassxc-cli is invoked.
# -q is prepended here so no caller can forget it.
run() {
    local n="$1"; shift
    feed "$n" | "$CLI" "$@"
}

need() { [ -n "$2" ] || die "$verb needs $1"; }

# --------------------------------------------------------------- the verbs --

case "$verb" in
help) usage; exit 0 ;;

version)
    # One JSON object, house style.
    printf '{"oracle":"keepassxc-cli","version":"%s","wrapper":"kdbx_oracle.sh 1.0.0"}\n' \
        "$("$CLI" --version 2>/dev/null | tr -d '\r\n')"
    ;;

create)
    need --file "$file"
    args=(db-create -q)
    [ -n "$keyfile" ] && args+=(--set-key-file "$keyfile")
    [ "$nopass" -eq 0 ] && args+=(-p)
    [ -n "$dectime" ] && args+=(-t "$dectime")
    args+=("$file")
    # db-create asks for the password twice (enter + repeat).
    run 2 "${args[@]}"
    ;;

import)
    need --file "$file"; need --xml "$xml"
    args=(import -q)
    [ -n "$keyfile" ] && args+=(--set-key-file "$keyfile")
    [ "$nopass" -eq 0 ] && args+=(-p)
    args+=("$xml" "$file")
    run 2 "${args[@]}"
    ;;

info)
    need --file "$file"
    run 1 db-info -q "${key_args[@]+"${key_args[@]}"}" "$file"
    ;;

ls)
    need --file "$file"
    args=(ls -q "${key_args[@]+"${key_args[@]}"}")
    [ "$recursive" -eq 1 ] && args+=(-R)
    [ "$flat" -eq 1 ] && args+=(-f)
    args+=("$file")
    [ -n "$group" ] && args+=("$group")
    run 1 "${args[@]}"
    ;;

show)
    need --file "$file"; need --entry "$entry"
    args=(show -q "${key_args[@]+"${key_args[@]}"}")
    [ "$protected" -eq 1 ] && args+=(-s)
    [ "$showall" -eq 1 ] && args+=(--all)
    [ "$attachments" -eq 1 ] && args+=(--show-attachments)
    [ -n "$attr" ] && args+=(-a "$attr")
    args+=("$file" "$entry")
    run 1 "${args[@]}"
    ;;

totp)
    need --file "$file"; need --entry "$entry"
    run 1 show -q -t "${key_args[@]+"${key_args[@]}"}" "$file" "$entry"
    ;;

search)
    need --file "$file"; need --term "$term"
    run 1 search -q "${key_args[@]+"${key_args[@]}"}" "$file" "$term"
    ;;

export)
    need --file "$file"
    run 1 export -q -f "$fmt" "${key_args[@]+"${key_args[@]}"}" "$file"
    ;;

mkdir)
    need --file "$file"; need --group "$group"
    run 1 mkdir -q "${key_args[@]+"${key_args[@]}"}" "$file" "$group"
    ;;

add)
    need --file "$file"; need --entry "$entry"
    args=(add -q "${key_args[@]+"${key_args[@]}"}")
    [ -n "$username" ] && args+=(-u "$username")
    [ -n "$url" ] && args+=(--url "$url")
    [ -n "$notes" ] && args+=(--notes "$notes")
    # -p makes keepassxc-cli read the ENTRY's password from stdin too, which is
    # why the entry password is never a --password argument here either.
    [ "$entrypw" -eq 1 ] && args+=(-p)
    args+=("$file" "$entry")
    run 1 "${args[@]}"
    ;;

edit)
    need --file "$file"; need --entry "$entry"
    args=(edit -q "${key_args[@]+"${key_args[@]}"}")
    [ -n "$title" ] && args+=(-t "$title")
    [ -n "$username" ] && args+=(-u "$username")
    [ -n "$url" ] && args+=(--url "$url")
    [ -n "$notes" ] && args+=(--notes "$notes")
    [ "$entrypw" -eq 1 ] && args+=(-p)
    args+=("$file" "$entry")
    run 1 "${args[@]}"
    ;;

mv)
    need --file "$file"; need --entry "$entry"; need --group "$group"
    run 1 mv -q "${key_args[@]+"${key_args[@]}"}" "$file" "$entry" "$group"
    ;;

rm)
    need --file "$file"; need --entry "$entry"
    run 1 rm -q "${key_args[@]+"${key_args[@]}"}" "$file" "$entry"
    ;;

attach-import)
    need --file "$file"; need --entry "$entry"; need --name "$name"; need --path "$path"
    run 1 attachment-import -q -f "${key_args[@]+"${key_args[@]}"}" "$file" "$entry" "$name" "$path"
    ;;

attach-export)
    need --file "$file"; need --entry "$entry"; need --name "$name"; need --out "$out"
    run 1 attachment-export -q "${key_args[@]+"${key_args[@]}"}" "$file" "$entry" "$name" "$out"
    ;;

db-edit)
    # Change a database's credentials WITHOUT touching its cipher, KDF or
    # format version — verified on this host: db-edit round-trips a KDBX 4.1
    # Argon2id database unchanged. That is how the key-file fixtures are made
    # 4.1 rather than the 3.1 that db-create insists on.
    #   --set-keyfile K   add (and generate, if absent) a key file
    #   --unset-password  drop the passphrase, leaving key-file-only
    # There is no --set-password here on purpose: this wrapper reads exactly one
    # database passphrase from stdin, and a change-the-passphrase verb needs two
    # different ones. Changing a passphrase is not something an oracle is for.
    need --file "$file"
    args=(db-edit -q "${key_args[@]+"${key_args[@]}"}")
    [ -n "$setkeyfile" ] && args+=(--set-key-file "$setkeyfile")
    [ "$unsetpass" -eq 1 ] && args+=(--unset-password)
    args+=("$file")
    run 1 "${args[@]}"
    ;;

merge)
    need --file "$file"; need --from "$fromdb"
    # -s == --same-credentials: the source opens with the target's passphrase,
    # so exactly one passphrase crosses the pipe.
    run 1 merge -q -s "${key_args[@]+"${key_args[@]}"}" "$file" "$fromdb"
    ;;

verify)
    # The read/verify shape: ONE JSON object on stdout, nothing else, so a test
    # can diff this against secrets-admin's own `probe` + `tree` + `entries`.
    #
    # The format version is read from the file's own header bytes rather than
    # from db-info, which does not report it: bytes 8..9 are the minor version
    # and 10..11 the major, both little-endian (KDBX signature block).
    need --file "$file"
    [ -f "$file" ] || die "no such file: $file"

    ver="$(od -An -tx1 -j8 -N4 "$file" 2>/dev/null | tr -d ' \n')"
    case "$ver" in
        ????????) major=$((16#${ver:6:2}${ver:4:2})); minor=$((16#${ver:2:2}${ver:0:2})) ;;
        *) major=0; minor=0 ;;
    esac
    sig="$(od -An -tx1 -j0 -N8 "$file" 2>/dev/null | tr -d ' \n')"

    info_out="$(run 1 db-info -q "${key_args[@]+"${key_args[@]}"}" "$file" 2>&1)"
    info_rc=$?
    ls_out=""
    ls_rc=1
    if [ "$info_rc" -eq 0 ]; then
        ls_out="$(run 1 ls -q -R -f "${key_args[@]+"${key_args[@]}"}" "$file" 2>&1)"
        ls_rc=$?
    fi

    # jq is not a dependency of this project, so the JSON is assembled by python3
    # (which is a hard dependency anyway) rather than by string-mashing shell,
    # because a database name containing a quote would otherwise emit broken JSON.
    KDBXO_INFO="$info_out" KDBXO_LS="$ls_out" \
    KDBXO_FILE="$file" KDBXO_SIG="$sig" KDBXO_MAJOR="$major" KDBXO_MINOR="$minor" \
    KDBXO_INFO_RC="$info_rc" KDBXO_LS_RC="$ls_rc" \
    KDBXO_CLIVER="$("$CLI" --version 2>/dev/null | tr -d '\r\n')" \
    python3 - <<'PY'
# Only NON-secret material crosses in the environment here: a file path, the
# db-info summary and the list of entry paths. The passphrase never does (I10).
import json, os, re

info = os.environ["KDBXO_INFO"]
def grab(label):
    m = re.search(r"^%s:\s*(.*)$" % re.escape(label), info, re.M)
    return m.group(1).strip() if m else None
def num(label):
    m = re.search(r"^%s:\s*(\d+)\s*$" % re.escape(label), info, re.M)
    return int(m.group(1)) if m else None

paths = [p for p in os.environ["KDBXO_LS"].splitlines() if p.strip()]
ok = os.environ["KDBXO_INFO_RC"] == "0" and os.environ["KDBXO_LS_RC"] == "0"
out = {
    "oracle": "keepassxc-cli " + os.environ["KDBXO_CLIVER"],
    "file": os.environ["KDBXO_FILE"],
    "ok": ok,
    "signature": os.environ["KDBXO_SIG"],
    "format_version": "%s.%s" % (os.environ["KDBXO_MAJOR"], os.environ["KDBXO_MINOR"]),
    "uuid": grab("UUID"),
    "name": grab("Name"),
    "cipher": grab("Cipher"),
    "kdf": grab("KDF"),
    "groups": num("Number of groups"),
    "entries": num("Number of entries"),
    "paths": paths,
    # db-info's own text, so a failure is diagnosable without re-running.
    "raw": info if not ok else None,
}
print(json.dumps(out, indent=2, sort_keys=False))
raise SystemExit(0 if ok else 1)
PY
    ;;

*)
    usage
    die "unknown verb $verb"
    ;;
esac
