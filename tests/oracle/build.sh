#!/usr/bin/env bash
#
# build.sh — build the TEST-ONLY Password Safe v3 oracle.
#
# No `set -x` anywhere in this project's shell (docs/KNOWN_ISSUES.md I15: this
# host's /srv/jobs logs are group-readable and a traced shell prints every
# argument). `set -u` + explicit rc checks instead.
#
# The build is deliberately OFFLINE: golang.org/x/crypto@v0.48.0 is already in
# this host's module cache, so GOPROXY=off proves we are not silently pulling a
# different version of the one dependency that supplies the block cipher.
# Pass --net to allow the network if the cache is ever cold.
#
set -u

cd "$(dirname "$0")" || exit 1

proxy="off"
for a in "$@"; do
    case "$a" in
        --net) proxy="https://proxy.golang.org,direct" ;;
        -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
        *) printf 'build.sh: unknown argument %s\n' "$a" >&2; exit 64 ;;
    esac
done

command -v go >/dev/null 2>&1 || { printf 'build.sh: go is not installed\n' >&2; exit 1; }
printf 'build.sh: %s\n' "$(go version)"

export GOPROXY="$proxy"
export GOFLAGS=-mod=mod
# CGO buys nothing here and a static binary is easier to hand to a container
# test later.
export CGO_ENABLED=0

if ! go vet ./... ; then
    printf 'build.sh: go vet FAILED\n' >&2
    exit 1
fi

if ! go build -trimpath -o pws3_oracle . ; then
    printf 'build.sh: go build FAILED\n' >&2
    exit 1
fi

# The binary is worthless as an oracle if its Twofish is wrong, so the build is
# not finished until the published known-answer vectors pass. `vectors` exits
# non-zero when any KAT fails.
if ! ./pws3_oracle vectors >/dev/null ; then
    printf 'build.sh: Twofish/KDF known-answer tests FAILED — do not trust this build\n' >&2
    exit 1
fi

printf 'build.sh: OK  %s  (%s bytes)\n' "$PWD/pws3_oracle" "$(stat -c%s pws3_oracle)"
