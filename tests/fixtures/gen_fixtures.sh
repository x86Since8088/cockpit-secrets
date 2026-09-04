#!/usr/bin/env bash
#
# gen_fixtures.sh — build (and re-verify) the committed fixture corpus.
#
# READ THIS BEFORE RUNNING IT
# ---------------------------
# The .kdbx and .psafe3 files in this directory are COMMITTED. This script does
# not need to run for the test suite to work; it exists so the corpus can be
# rebuilt, audited and explained. It therefore REFUSES to overwrite an existing
# fixture unless you pass --force, so nobody churns the repository by reflex.
#
#   ./gen_fixtures.sh --verify        re-verify the committed corpus (default)
#   ./gen_fixtures.sh --build         build any fixture that is missing
#   ./gen_fixtures.sh --build --force rebuild everything from scratch
#
# PROVENANCE IS THE POINT (docs/KNOWN_ISSUES.md I19)
# --------------------------------------------------
# "A reader and a writer that share a bug round-trip perfectly and interoperate
# with nothing." So every KDBX file here is written by **keepassxc-cli 2.7.10**,
# a foreign implementation, and every one of them is then re-opened by
# keepassxc-cli before this script will call itself successful. The one thing
# keepassxc-cli cannot do is choose a cipher/KDF/format version — verified on
# this host, `db-create` always produces KDBX 3.1 + AES-KDF — so the 4.x
# variants get an empty header from kdbx_reformat.py and their CONTENT and
# their final bytes from `keepassxc-cli merge`. README.md states, per file,
# exactly which tool produced which bytes. Do not blur that.
#
# The .psafe3 fixture is written by tests/oracle/pws3_oracle, our independent
# Go implementation, because Ubuntu's `passwordsafe` package ships no CLI and
# `pwsafe --validate` cannot be driven headlessly (measured; see README.md).
# That is the closest thing to a foreign PWS3 writer available here, and
# README.md says so instead of implying an oracle we do not have.
#
# No `set -x` anywhere (I15: /srv/jobs logs are group-readable).
#
set -u

cd "$(dirname "$0")" || exit 1
readonly HERE="$PWD"
readonly ORACLE_DIR="$HERE/../oracle"
readonly KDBX="$ORACLE_DIR/kdbx_oracle.sh"
readonly PWS3="$ORACLE_DIR/pws3_oracle"
readonly REFORMAT="$HERE/kdbx_reformat.py"

# The one throwaway passphrase for every fixture in this directory. It is
# published in README.md on purpose: these safes are decoys and the tests need
# to open them. It is held in a shell variable and piped with the `printf`
# BUILTIN, so it never reaches any child's argv (I10) — the same discipline the
# real helper uses, practised here so nobody learns the wrong habit.
readonly FIXPASS='fixture-pass-do-not-reuse'

# Deterministic seed for the PWS3 writer, so regenerating the fixture produces
# byte-identical output and `git status` stays quiet. TEST-ONLY: pws3_oracle
# shouts about this on stderr, and it must never be used for a real safe.
readonly PWS3_SEED='cockpit-secrets-lab-pws3-v1'

mode="verify"
force=0
for a in "$@"; do
    case "$a" in
        --build)  mode="build" ;;
        --verify) mode="verify" ;;
        --force)  force=1 ;;
        -h|--help) sed -n '3,32p' "$0"; exit 0 ;;
        *) printf 'gen_fixtures.sh: unknown argument %s\n' "$a" >&2; exit 64 ;;
    esac
done

rc=0
pass_() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail_() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; rc=1; }
info_() { printf '  \033[2m....\033[0m  %s\n' "$*"; }
head_() { printf '\n== %s ==\n' "$*"; }

feedpass() { printf '%s\n' "$FIXPASS"; }   # builtin printf: never argv, never a temp file

# ------------------------------------------------------------ fixture names --
# Every name states version, cipher and KDF, so a test that opens the wrong one
# is obvious in the diff rather than mysterious in the failure.
readonly F_KDBX31='lab-kdbx31-aes256-aeskdf.kdbx'
readonly F_KDBX40='lab-kdbx40-aes256-argon2d.kdbx'
readonly F_KDBX41A='lab-kdbx41-aes256-argon2id.kdbx'
readonly F_KDBX41C='lab-kdbx41-chacha20-argon2d.kdbx'
readonly F_KF_ONLY='lab-kdbx41-keyfile-only.kdbx'
readonly F_KF_ONLY_KEY='lab-kdbx41-keyfile-only.keyx'
readonly F_PW_KF='lab-kdbx41-password-and-keyfile.kdbx'
readonly F_PW_KF_KEY='lab-kdbx41-password-and-keyfile.keyx'
readonly F_PWS3='lab-pws3.psafe3'
readonly ATT_TEXT='attachment-notes.txt'
readonly ATT_BIN='attachment-blob.bin'

readonly ALL_KDBX=("$F_KDBX31" "$F_KDBX40" "$F_KDBX41A" "$F_KDBX41C" "$F_KF_ONLY" "$F_PW_KF")
readonly ALL_FILES=("${ALL_KDBX[@]}" "$F_KF_ONLY_KEY" "$F_PW_KF_KEY" "$F_PWS3")

# The entry every fixture carries, and the sentinel it must hand back.
readonly SENTINEL_ENTRY='/Lab/Nested/Router'
readonly SENTINEL='SENTINEL-DO-NOT-LEAK-8f3a2b'

# ------------------------------------------------------------ prerequisites --

head_ "Prerequisites"
for tool in keepassxc-cli python3; do
    if command -v "$tool" >/dev/null 2>&1; then pass_ "$tool present"
    else fail_ "$tool is missing"; fi
done
[ -x "$KDBX" ] || fail_ "missing $KDBX"
if [ ! -x "$PWS3" ]; then
    info_ "building the PWS3 oracle"
    if (cd "$ORACLE_DIR" && ./build.sh >/dev/null 2>&1); then pass_ "pws3_oracle built"
    else fail_ "pws3_oracle failed to build (run tests/oracle/build.sh)"; fi
fi
if python3 -c 'import pykeepass' 2>/dev/null; then pass_ "python3-pykeepass present"
else fail_ "python3-pykeepass is missing (needed only for --build)"; fi
[ "$rc" -eq 0 ] || { printf '\ngen_fixtures.sh: prerequisites failed\n' >&2; exit 1; }

# ------------------------------------------------------------------- build --

build_all() {
    head_ "Build"

    # Refuse to clobber unless told to. The corpus is committed; silently
    # rewriting it would make every fixture-dependent test unreproducible.
    if [ "$force" -eq 0 ]; then
        for f in "${ALL_FILES[@]}"; do
            if [ -e "$f" ]; then
                info_ "$f exists, keeping it (pass --force to rebuild)"
            fi
        done
    else
        # .keyx files come out of keepassxc-cli mode 0400, so remove rather
        # than try to overwrite.
        rm -f "${ALL_FILES[@]}" manifest.json
        info_ "removed the previous corpus (--force)"
    fi

    # ---- attachment payloads ------------------------------------------
    # Committed alongside the safes so the fixtures are reproducible. The
    # binary one is bytes 0x00..0xFF, i.e. every byte value, which is what
    # makes it a real test of base64 round-tripping in `attach-get`.
    if [ ! -e "$ATT_TEXT" ]; then
        cat > "$ATT_TEXT" <<'ATT'
cockpit-secrets fixture attachment.
This file is throwaway test data and contains no credential.
It exists so the attachment code path has something to carry.
ATT
        pass_ "wrote $ATT_TEXT"
    fi
    if [ ! -e "$ATT_BIN" ]; then
        python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)))' > "$ATT_BIN"
        pass_ "wrote $ATT_BIN (all 256 byte values)"
    fi

    # ---- 1. the KDBX 3.1 base, straight from keepassxc-cli -------------
    # `import` parses kdbx-content.xml and writes the database itself, so the
    # bytes are KeePassXC's. This is also the KDBX 3.1 fixture: I20 wants a
    # database with no authenticated encryption to prove the read-only banner.
    if [ ! -e "$F_KDBX31" ]; then
        if feedpass | "$KDBX" import --file "$F_KDBX31" --xml kdbx-content.xml >/dev/null 2>&1; then
            pass_ "$F_KDBX31 imported"
        else
            fail_ "keepassxc-cli import failed"; return 1
        fi
        for spec in "$ATT_TEXT:notes.txt" "$ATT_BIN:blob.bin"; do
            src="${spec%%:*}"; nm="${spec##*:}"
            if feedpass | "$KDBX" attach-import --file "$F_KDBX31" \
                    --entry "$SENTINEL_ENTRY" --name "$nm" --path "$src" >/dev/null 2>&1; then
                pass_ "$F_KDBX31 attachment $nm"
            else
                fail_ "attachment-import $nm failed"; return 1
            fi
        done
    fi

    # ---- 2. the KDBX 4.x variants --------------------------------------
    # shell (empty, chosen cipher+KDF) -> keepassxc-cli merge (content, and the
    # final bytes) -> optional keepassxc-cli mv (which records
    # PreviousParentGroup, a 4.1-only element, so KeePassXC stamps the file 4.1).
    make_variant() {           # make_variant <file> <cipher> <kdf> <want41>
        local out="$1" cipher="$2" kdf="$3" want41="$4"
        [ -e "$out" ] && return 0
        if ! feedpass | python3 "$REFORMAT" --file "$out" --cipher "$cipher" --kdf "$kdf" \
                >/dev/null 2>&1; then
            fail_ "kdbx_reformat.py failed for $out"; return 1
        fi
        if ! feedpass | "$KDBX" merge --file "$out" --from "$F_KDBX31" >/dev/null 2>&1; then
            fail_ "keepassxc-cli merge failed for $out"; return 1
        fi
        if [ "$want41" -eq 1 ]; then
            # This is the ONLY thing that makes a 4.1 file 4.1: KeePassXC writes
            # the lowest format version that can express the database, so a
            # hand-set minor version would be overwritten on the next save.
            if ! feedpass | "$KDBX" mv --file "$out" \
                    --entry '/Staging/Moved Entry' --group '/Archive' >/dev/null 2>&1; then
                fail_ "keepassxc-cli mv failed for $out"; return 1
            fi
        fi
        pass_ "$out built"
    }

    make_variant "$F_KDBX40"  aes256   argon2   0 || return 1
    make_variant "$F_KDBX41A" aes256   argon2id 1 || return 1
    make_variant "$F_KDBX41C" chacha20 argon2   1 || return 1

    # ---- 3. the key-file variants --------------------------------------
    # Derived from the 4.1 AES/Argon2id fixture with `db-edit`, which changes
    # credentials and leaves cipher, KDF and format version alone (verified).
    # keepassxc-cli GENERATES the .keyx itself (a KeePassXC 2.0 XML key file),
    # so the key material is foreign too.
    if [ ! -e "$F_PW_KF" ]; then
        cp -- "$F_KDBX41A" "$F_PW_KF"
        rm -f "$F_PW_KF_KEY"
        if feedpass | "$KDBX" db-edit --file "$F_PW_KF" --set-keyfile "$F_PW_KF_KEY" >/dev/null 2>&1
        then pass_ "$F_PW_KF built (passphrase + key file)"
        else fail_ "db-edit --set-key-file failed"; return 1; fi
    fi
    if [ ! -e "$F_KF_ONLY" ]; then
        cp -- "$F_KDBX41A" "$F_KF_ONLY"
        rm -f "$F_KF_ONLY_KEY"
        if feedpass | "$KDBX" db-edit --file "$F_KF_ONLY" \
                --set-keyfile "$F_KF_ONLY_KEY" --unset-password >/dev/null 2>&1
        then pass_ "$F_KF_ONLY built (key file only, no passphrase)"
        else fail_ "db-edit --unset-password failed"; return 1; fi
    fi

    # ---- 4. the Password Safe v3 fixture -------------------------------
    if [ ! -e "$F_PWS3" ]; then
        if feedpass | "$PWS3" write --file "$F_PWS3" --json lab-pws3.spec.json \
                --seed "$PWS3_SEED" >/dev/null 2>&1
        then pass_ "$F_PWS3 written by pws3_oracle (deterministic)"
        else fail_ "pws3_oracle write failed"; return 1; fi
    fi

    chmod 0600 "${ALL_KDBX[@]}" "$F_PWS3" 2>/dev/null
    return 0
}

# ------------------------------------------------------------------ verify --
#
# Nothing counts until a FOREIGN implementation opens it. Every KDBX fixture is
# re-opened by keepassxc-cli, and the sentinel is read back out of it; the PWS3
# fixture is re-read by the Go oracle with its HMAC checked.

verify_all() {
    head_ "Verify (foreign oracles)"

    for f in "${ALL_KDBX[@]}"; do
        [ -e "$f" ] || { fail_ "$f is missing"; continue; }
        kargs=()
        case "$f" in
            "$F_KF_ONLY") kargs=(--keyfile "$F_KF_ONLY_KEY" --no-password) ;;
            "$F_PW_KF")   kargs=(--keyfile "$F_PW_KF_KEY") ;;
        esac
        if out="$(feedpass | "$KDBX" verify --file "$f" "${kargs[@]+"${kargs[@]}"}" 2>&1)"; then
            ver="$(printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("%s %s / %s" % (d["format_version"], d["cipher"], d["kdf"]))')"
            pass_ "$f opens in keepassxc-cli  [$ver]"
        else
            fail_ "$f does NOT open in keepassxc-cli"
            printf '%s\n' "$out" | sed 's/^/        /' | head -6
            continue
        fi

        # The sentinel must survive every re-encoding. `show --protected` is
        # the only way to get it, which is itself the reveal-is-the-only-door
        # rule the backends have to obey.
        got="$(feedpass | "$KDBX" show --file "$f" "${kargs[@]+"${kargs[@]}"}" \
                 --entry "$SENTINEL_ENTRY" --protected --attr Password 2>/dev/null)"
        if [ "$got" = "$SENTINEL" ]; then pass_ "$f carries the sentinel"
        else fail_ "$f lost the sentinel (got ${#got} bytes)"; fi

        # The attachments must survive the merge as well.
        atts="$(feedpass | "$KDBX" show --file "$f" "${kargs[@]+"${kargs[@]}"}" \
                  --entry "$SENTINEL_ENTRY" --attachments 2>/dev/null | grep -c -E 'notes\.txt|blob\.bin')"
        if [ "${atts:-0}" -eq 2 ]; then pass_ "$f carries both attachments"
        else fail_ "$f is missing an attachment (found ${atts:-0} of 2)"; fi

        # And the TOTP entry must still compute a code.
        code="$(feedpass | "$KDBX" totp --file "$f" "${kargs[@]+"${kargs[@]}"}" \
                  --entry '/TOTP Demo' 2>/dev/null | tr -d '\r\n')"
        case "$code" in
            [0-9][0-9][0-9][0-9][0-9][0-9]) pass_ "$f computes a 6-digit TOTP" ;;
            *) fail_ "$f TOTP did not produce 6 digits" ;;
        esac
    done

    # ---- PWS3 ----------------------------------------------------------
    if [ -e "$F_PWS3" ]; then
        if out="$(feedpass | "$PWS3" read --file "$F_PWS3" 2>/dev/null)"; then
            summary="$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
found = any(f.get("text") == "SENTINEL-DO-NOT-LEAK-8f3a2b"
            for r in d["records"] for f in r["fields"])
print("%s %s %s" % (d["hmac_ok"], d["counts"]["records"], found))')"
            set -- $summary
            [ "$1" = "True" ] && pass_ "$F_PWS3 HMAC verifies" || fail_ "$F_PWS3 HMAC does not verify"
            [ "$2" -ge 4 ] && pass_ "$F_PWS3 has $2 records" || fail_ "$F_PWS3 has only $2 records"
            [ "$3" = "True" ] && pass_ "$F_PWS3 carries the sentinel" || fail_ "$F_PWS3 lost the sentinel"
        else
            fail_ "$F_PWS3 does not read back"
        fi
        # A wrong passphrase must be refused with bad-credential and nothing else.
        if bad="$(printf 'definitely-not-the-passphrase\n' | "$PWS3" read --file "$F_PWS3" 2>/dev/null)"; then
            fail_ "$F_PWS3 opened with the WRONG passphrase"
        else
            code="$(printf '%s' "$bad" | python3 -c 'import json,sys; print(json.load(sys.stdin)["error"])' 2>/dev/null)"
            [ "$code" = "bad-credential" ] && pass_ "$F_PWS3 refuses a wrong passphrase (bad-credential)" \
                || fail_ "$F_PWS3 wrong-passphrase error was '$code', expected bad-credential"
        fi
    else
        fail_ "$F_PWS3 is missing"
    fi
}

# ---------------------------------------------------------------- manifest --
#
# A machine-readable index so a test never hardcodes a passphrase or a path, and
# so a changed fixture shows up as a changed digest instead of a mystery.

write_manifest() {
    head_ "Manifest"
    # The passphrase goes to gen_manifest.py on STDIN, like everywhere else in
    # this project — not on argv, and not in the environment. Prefixing the
    # command with FIXPASS=... would be both, and it is the habit that leaks
    # real passphrases in real code (I10).
    if feedpass | python3 "$HERE/gen_manifest.py"; then
        pass_ "manifest.json"
    else
        fail_ "manifest.json not written (or a fixture is missing)"
    fi
}

# -------------------------------------------------------------------- main --

if [ "$mode" = "build" ]; then
    build_all || rc=1
fi
verify_all
[ "$mode" = "build" ] && write_manifest

printf '\n'
if [ "$rc" -eq 0 ]; then
    printf '\033[32mgen_fixtures.sh: OK\033[0m\n'
else
    printf '\033[31mgen_fixtures.sh: FAILED\033[0m\n'
fi
exit "$rc"
