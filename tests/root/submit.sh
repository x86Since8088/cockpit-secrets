#!/usr/bin/env bash
#
# submit.sh - stage one tests/root job and hand it to the /srv/jobs runner.
#
#   ./submit.sh 10-install.sh              # submit and wait, print output.log
#   ./submit.sh --timeout 900 40-admin-allow.sh
#
# Runs UNPRIVILEGED, as the operator. It only stages files and calls
# submit-job.sh; the runner is what escalates. There is no `sudo` here and
# there must never be one: interactive sudo does not work on this host
# (docs/HOST-FACTS.md, "Root").
#
# Why it stages a DIRECTORY rather than piping a script on stdin: every job in
# this suite sources rootlib.sh and most run a Python driver, and the runner
# copies a job folder wholesale. Piping would force each script to be one
# self-contained wall of heredocs, which is how a shared reporter turns into
# six diverging copies of a shared reporter.
#
# It also compiles every Python driver it stages. A syntax error found here
# costs a second; found inside the job it costs a root run, an outbox entry and
# a confusing exit code.
#
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd -- "$HERE/../.." && pwd)"
SUBMIT="${SUBMIT_JOB:-/home/eddie/Documents/ClaudeSystem/submit-job.sh}"
TIMEOUT=600

usage() { sed -n '2,20p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

while (($#)); do
    case "$1" in
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        -*) echo "unknown option: $1" >&2; usage 1 ;;
        *) break ;;
    esac
done
(($#)) || { echo "which script? e.g. ./submit.sh 10-install.sh" >&2; usage 1; }

script="$1"; shift
[[ -f "$HERE/$script" ]] || { echo "no such job script: $HERE/$script" >&2; exit 1; }
[[ -x "$SUBMIT" ]] || { echo "submit-job.sh not found at $SUBMIT (set SUBMIT_JOB)" >&2; exit 1; }

# The job name the outbox will carry. Derived from the script so a run of the
# whole suite sorts in the outbox the way it ran.
name="cs-${script%.sh}"
name="${name//[^A-Za-z0-9._-]/-}"

stage="$(mktemp -d "${TMPDIR:-/tmp}/cs-root-job.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT

install -m 0755 "$HERE/$script" "$stage/run.sh"
install -m 0644 "$HERE/rootlib.sh" "$stage/rootlib.sh"
shopt -s nullglob
for py in "$HERE"/*.py; do
    python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$py" \
        || { echo "will not submit: $py does not parse" >&2; exit 1; }
    install -m 0644 "$py" "$stage/$(basename -- "$py")"
done
shopt -u nullglob

# The checkout location, discovered here and handed to the job, so no script in
# this directory hardcodes a share path.
printf 'CS_SRC=%q\n' "$SRC" > "$stage/cs-config.sh"
chmod 0644 "$stage/cs-config.sh"

exec "$SUBMIT" --wait --timeout "$TIMEOUT" "$name" "$stage"
