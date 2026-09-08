#!/usr/bin/env python3
"""gen_manifest.py — write manifest.json, the machine-readable fixture index.

TEST-ONLY. Called by gen_fixtures.sh.

The manifest exists so no test ever hardcodes a fixture name, a passphrase or a
digest. It records, per file: format, version, cipher, KDF, whether a passphrase
is needed, which key file goes with it, its size, its SHA-256, and — the part
that matters for docs/KNOWN_ISSUES.md I19 — **which tool actually produced its
bytes**. A fixture whose provenance is "our own writer" proves nothing about our
own writer, and the manifest is where that distinction is recorded rather than
assumed.

The corpus passphrase arrives on STDIN, not on argv and not in the environment.
That is theatre here — the passphrase is published in this very file's output
and in README.md, because these safes are decoys — but a fixture generator that
puts a passphrase on argv is how the habit gets learned wrong (I10, and item 1
of the bad-practice table in docs/UPSTREAM-REVIEW.md §4).
"""

import hashlib
import json
import os
import subprocess
import sys

SENTINEL = "SENTINEL-DO-NOT-LEAK-8f3a2b"
SENTINEL_ENTRY = "/Lab/Nested/Router"


def keepassxc_version():
    try:
        out = subprocess.run(["keepassxc-cli", "--version"],
                             capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or "unknown"
    except Exception:                                   # noqa: BLE001 - test tool
        return "unknown"


def build(passphrase):
    kxc = "keepassxc-cli " + keepassxc_version()
    pws3 = ("tests/oracle/pws3_oracle — our own independent Go implementation. "
            "There is NO foreign PWS3 writer on this host: Ubuntu's passwordsafe "
            "package ships only the GUI, and pwsafe --validate cannot be driven "
            "headlessly (see README.md). This fixture is therefore weaker "
            "evidence than the KDBX ones, and I19 says to state that rather "
            "than imply parity.")

    spec = [
        # file, format, version, cipher, kdf, needs_password, keyfile, provenance
        ("lab-kdbx31-aes256-aeskdf.kdbx", "kdbx", "3.1", "AES-256", "AES-KDF", True, None,
         kxc + " — `import` of kdbx-content.xml, then two `attachment-import` calls. "
               "Every byte written by KeePassXC."),
        ("lab-kdbx40-aes256-argon2d.kdbx", "kdbx", "4.0", "AES-256", "Argon2d", True, None,
         kxc + " — `merge` of the 3.1 fixture into an EMPTY header built by "
               "kdbx_reformat.py (pykeepass). KeePassXC wrote the final file."),
        ("lab-kdbx41-aes256-argon2id.kdbx", "kdbx", "4.1", "AES-256", "Argon2id", True, None,
         kxc + " — `merge` as above, then `mv` (which records PreviousParentGroup, "
               "a 4.1-only element, so KeePassXC stamps the file 4.1)."),
        ("lab-kdbx41-chacha20-argon2d.kdbx", "kdbx", "4.1", "ChaCha20", "Argon2d", True, None,
         kxc + " — `merge` + `mv` as above, into a ChaCha20/Argon2d header."),
        ("lab-kdbx41-password-and-keyfile.kdbx", "kdbx", "4.1", "AES-256", "Argon2id", True,
         "lab-kdbx41-password-and-keyfile.keyx",
         kxc + " — `db-edit --set-key-file` on the 4.1 AES/Argon2id fixture. "
               "KeePassXC generated the key file itself."),
        ("lab-kdbx41-keyfile-only.kdbx", "kdbx", "4.1", "AES-256", "Argon2id", False,
         "lab-kdbx41-keyfile-only.keyx",
         kxc + " — `db-edit --set-key-file --unset-password`. Opens with the key "
               "file alone; password_required is false."),
        ("lab-pws3.psafe3", "psafe3", "0x0311", "Twofish-CBC",
         "SHA-256 key stretch, ITER=262144", True, None, pws3),
    ]

    fixtures = []
    missing = []
    for name, fmt, ver, cipher, kdf, needs_pw, keyfile, prov in spec:
        if not os.path.exists(name):
            missing.append(name)
            continue
        with open(name, "rb") as fh:
            data = fh.read()
        entry = {
            "file": name,
            "format": fmt,
            "format_version": ver,
            "cipher": cipher,
            "kdf": kdf,
            "password_required": needs_pw,
            # Published on purpose: these are decoy safes and the tests must be
            # able to open them without a human. NEVER put a real passphrase in
            # a file that lives in a repository.
            "password": passphrase if needs_pw else None,
            "keyfile": keyfile,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "produced_by": prov,
        }
        if keyfile and os.path.exists(keyfile):
            with open(keyfile, "rb") as fh:
                kdata = fh.read()
            entry["keyfile_bytes"] = len(kdata)
            entry["keyfile_sha256"] = hashlib.sha256(kdata).hexdigest()
        fixtures.append(entry)

    return {
        "_comment": (
            "Index of the throwaway fixture corpus for cockpit-secrets. Every "
            "passphrase here is public on purpose; none of these safes holds a "
            "real credential. Tests should read this file instead of hardcoding "
            "names, passphrases or digests. Rebuild with "
            "./gen_fixtures.sh --build --force."),
        "sentinel": SENTINEL,
        "sentinel_entry": SENTINEL_ENTRY,
        "attachments": ["notes.txt", "blob.bin"],
        "totp_entry": "/TOTP Demo",
        "totp_seed": "JBSWY3DPEHPK3PXP",
        "unicode_entry": "/Ünïcødé — 日本語 🔐",
        "moved_entry_41": "/Archive/Moved Entry",
        "moved_entry_pre41": "/Staging/Moved Entry",
        "fixtures": fixtures,
    }, missing


def main():
    passphrase = sys.stdin.readline().rstrip("\n").rstrip("\r")
    if not passphrase:
        sys.stderr.write("gen_manifest.py: empty passphrase on stdin\n")
        return 64

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    manifest, missing = build(passphrase)
    for name in missing:
        sys.stderr.write("gen_manifest.py: %s is missing, not indexing it\n" % name)

    with open("manifest.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    sys.stderr.write("gen_manifest.py: manifest.json indexes %d fixtures\n"
                     % len(manifest["fixtures"]))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
