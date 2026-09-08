#!/usr/bin/env python3
"""kdbx_reformat.py — write an EMPTY KDBX 4 database with a chosen cipher and KDF.

TEST-ONLY. Called by gen_fixtures.sh; never installed, never imported by
`secrets-admin`, never on a runtime path.

WHY THIS EXISTS, AND WHY IT IS AS SMALL AS IT IS
------------------------------------------------
`keepassxc-cli db-create` has no switch for the format version, the cipher or the
KDF, and it is not a bug: verified on this host, every database it creates is
**KDBX 3.1 with AES-KDF**, whatever `--decryption-time` you give it. So the four
version/cipher/KDF fixtures docs/KNOWN_ISSUES.md I19 and I20 need cannot all come
straight out of the CLI.

The trick that keeps the fixtures foreign anyway: this script writes only an
**empty shell** — a database with the right header and no content — and
gen_fixtures.sh then runs `keepassxc-cli merge` to pour the real content in.
KeePassXC does that merge and rewrites the file itself, preserving the target's
cipher and KDF, so the committed fixture is a **KeePassXC-written database**
whose header parameters we chose. Only the initial empty header came from
pykeepass, and every result is then re-verified with `keepassxc-cli db-info`.
That is a materially stronger provenance claim than "pykeepass wrote it".

Two facts measured on this host that this script depends on (both re-checked by
gen_fixtures.sh, which fails loudly if they stop holding):

  1. `construct`'s RawCopy rebuilds from `.value` only when the container has no
     `.data`. pykeepass keeps the header bytes it parsed in `.data`, so mutating
     `header.value.*` and calling save() silently writes the ORIGINAL header
     while deriving the key from the NEW parameters — an inconsistent file that
     pykeepass itself will happily re-open and KeePassXC rejects. Popping
     `data` first is what makes the edit real.

  2. The Argon2id KDF UUID is 9e298b19-56db-4773-b23d-fc3ec6f0a1e6. It is easy
     to "remember" it as ...a1e3; a file carrying that UUID is rejected by
     KeePassXC 2.7.10 with "Unsupported key derivation function (KDF) or invalid
     parameters". Verified both ways on this host. We take the UUID from
     pykeepass's own table rather than typing it here, so there is one source.

The KDBX 4.1 stamp is NOT set here. KeePassXC writes the lowest format version
that can express the database, so a hand-set minor version is overwritten on its
next save. gen_fixtures.sh earns 4.1 honestly instead, by using
`keepassxc-cli mv`, which records PreviousParentGroup — a 4.1-only element.
"""

import argparse
import os
import sys

from pykeepass import PyKeePass, create_database
import pykeepass.kdbx_parsing.kdbx4 as kdbx4

# ChaCha20 has a 12-byte nonce; AES-256-CBC has a 16-byte IV. pykeepass's blank
# template is AES, so switching the cipher means resizing encryption_iv too or
# the build dies inside Cryptodome with "Nonce must be 8/12 bytes".
IV_LEN = {"aes256": 16, "chacha20": 12, "twofish": 16}


def build(path, password, keyfile, cipher, kdf, memory_kib, time_cost, parallelism):
    if os.path.exists(path):
        os.remove(path)

    # create_database() lays down pykeepass's blank KDBX 4.0 template.
    kp = create_database(path, password=password, keyfile=keyfile)
    kp.save()

    kp = PyKeePass(path, password=password, keyfile=keyfile)

    # See docstring fact (1): without this, every mutation below is a no-op on
    # disk and the file that comes out is internally inconsistent.
    kp.kdbx.header.pop("data", None)

    header = kp.kdbx.header.value
    dyn = header.dynamic_header
    dyn.cipher_id.data = cipher
    if len(dyn.encryption_iv.data) != IV_LEN[cipher]:
        dyn.encryption_iv.data = os.urandom(IV_LEN[cipher])

    params = dyn.kdf_parameters.data.dict
    params["$UUID"].value = kdbx4.kdf_uuids[kdf]   # docstring fact (2)
    # Deliberately modest costs. These are throwaway fixtures opened hundreds of
    # times by the test suite, and they must still sit inside the clamps in
    # backends/base.py Limits (ARGON2_MAX_MEMORY_KIB / _TIME / _PARALLELISM) so
    # that a fixture never trips the I7 guard it is not there to test.
    params["I"].value = time_cost
    params["M"].value = memory_kib * 1024          # the header carries BYTES
    params["P"].value = parallelism

    kp.save()
    return kp


def set_db_name(path, password, keyfile, name):
    """Name the database in Meta/DatabaseName.

    `keepassxc-cli merge` copies groups and entries but leaves the TARGET's
    metadata alone, so without this every merged fixture would report the blank
    template's name and the corpus would look inconsistent for no reason. There
    is no keepassxc-cli verb for this, so it happens here, before the merge.
    """
    kp = PyKeePass(path, password=password, keyfile=keyfile)
    for tag in ("DatabaseName", "DatabaseDescription"):
        node = kp.tree.find("Meta/%s" % tag)
        if node is not None:
            node.text = name if tag == "DatabaseName" else \
                "Throwaway test safe. Contains no real credential."
    kp.save()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="database to create")
    ap.add_argument("--cipher", required=True, choices=sorted(IV_LEN))
    ap.add_argument("--kdf", required=True, choices=("argon2", "argon2id", "aeskdf"))
    ap.add_argument("--memory-kib", type=int, default=32768)
    ap.add_argument("--time-cost", type=int, default=2)
    ap.add_argument("--parallelism", type=int, default=2)
    ap.add_argument("--keyfile", default=None)
    ap.add_argument("--db-name", default="cockpit-secrets fixture")
    # NOTE the absence of --password. The passphrase arrives on stdin, exactly
    # as it does everywhere else in this project (docs/KNOWN_ISSUES.md I10):
    # /proc/<pid>/cmdline is world-readable, and these fixtures share a
    # passphrase with nothing, but the habit is the point.
    args = ap.parse_args()

    if args.kdf == "aeskdf":
        sys.stderr.write(
            "kdbx_reformat.py: aeskdf is not offered here — a KDBX 3.1 + AES-KDF\n"
            "fixture comes straight from `keepassxc-cli db-create`, which is a\n"
            "better provenance than anything this script can produce.\n")
        return 64

    password = sys.stdin.readline().rstrip("\n").rstrip("\r")
    if not password:
        sys.stderr.write("kdbx_reformat.py: empty passphrase on stdin\n")
        return 64

    try:
        build(args.file, password, args.keyfile, args.cipher, args.kdf,
              args.memory_kib, args.time_cost, args.parallelism)
        set_db_name(args.file, password, args.keyfile, args.db_name)
    except Exception as exc:                      # noqa: BLE001 - test tool
        # Class + message only. Even in a test tool, a traceback prints locals,
        # and one of the locals here is the passphrase (I15).
        sys.stderr.write("kdbx_reformat.py: %s: %s\n" % (type(exc).__name__, exc))
        return 1
    finally:
        password = None

    sys.stderr.write("kdbx_reformat.py: wrote %s (%s + %s)\n"
                     % (args.file, args.cipher, args.kdf))
    return 0


if __name__ == "__main__":
    sys.exit(main())
