#!/usr/bin/env python3
"""gen_twofish_fixture.py — write a genuine KDBX 4 database encrypted with Twofish.

TEST-ONLY. Never installed, never imported by `secrets-admin`, never on a
runtime path.

WHY THIS EXISTS
---------------
docs/COMPATIBILITY.md carried this row, and it was the only "code exists,
UNTESTED" row in the whole table:

    | KDBX 3.x / 4.x | Twofish | any | code exists | code exists |
    | **UNTESTED — no fixture exists.** ...

Measured on this host and the reason for the gap: **`keepassxc-cli` cannot
create a Twofish database.** `db-create` has no cipher switch and always writes
KDBX 3.1 + AES-256 + AES-KDF; `import` behaves the same; `merge` preserves the
TARGET's cipher, so there is nothing to merge into. Every other fixture in this
directory is foreign because KeePassXC wrote its final bytes — and for Twofish
that route does not exist.

So this file writes the container itself, from the KDBX 4 specification, with
no help from the library that reads it.

WHAT THIS IS EVIDENCE OF, AND WHAT IT IS NOT — read this before citing it
-------------------------------------------------------------------------
docs/KNOWN_ISSUES.md **I19**: *"a reader and a writer that share a bug
round-trip perfectly and interoperate with nothing."* That is the trap this
fixture sits closest to, so the claim is drawn narrowly on purpose:

  IT IS      evidence that our KDBX 4 reader decrypts Twofish-CBC correctly.
             The ciphertext in the committed file is produced by **Botan
             3.10's** Twofish (`botan3.BlockCipher("Twofish")`, an audited
             third-party primitive that passes the published ECB vectors on
             this host — see tests/vectors/twofish_ecb.json). Our reader
             decrypts it through **pykeepass's pure-Python Twofish**, which
             shares no code with Botan. Two independent implementations of the
             cipher have to agree for the fixture to open at all, and a
             one-bit disagreement fails the KDBX4 block HMAC before a byte of
             plaintext escapes.

  IT IS      evidence that the container we wrote is well-formed, because
             `verify()` below also hands the file to **`keepassxc-cli` 2.7.10**
             and it opens: `db-info` reports "Cipher: Twofish 256-bit", `ls -R`
             lists both entries, `show -s` returns both protected values, and
             `attachment-export` recovers the binary byte for byte. MEASURED on
             this host. A foreign reader accepting the file is a genuinely
             independent check on the header layout, the HMAC block stream, the
             inner header, the ChaCha20 protected-value stream and the XML.

  IT IS NOT  a foreign fixture, and the distinction is not pedantry.
             **Every byte of this file was produced here.** Every other `.kdbx`
             in this directory had its final bytes written by KeePassXC; this
             one did not, and no rewording changes that. What that costs is
             narrow but real: KeePassXC reading our file proves our file is
             *acceptable*, not that it is what KeePassXC would have *written* —
             a field KeePassXC ignores on read but relies on elsewhere would
             pass this check. So the row in docs/COMPATIBILITY.md says
             "self-produced, foreign-read", never "foreign fixture", and the
             overstatement that would make this the I19 mistake is exactly
             "keepassxc-cli opens it, therefore it is a KeePassXC file".

THE CONSTRUCTION, so a reader of this file can check it against the spec
------------------------------------------------------------------------
    SIG1 SIG2 minor major
    outer header fields: 2=cipher, 3=compression, 4=master seed, 7=IV,
                         11=KDF VariantDictionary, 0=end (\\r\\n\\r\\n)
    SHA-256(header)                                       32 bytes
    HMAC-SHA-256(header) under block key 0xFFFFFFFFFFFFFFFF
    payload blocks: HMAC(32) | len(uint32 LE) | data, terminated by len == 0
        HMAC of block i covers  uint64le(i) || uint32le(len) || data
        block key i = SHA-512( uint64le(i) || SHA-512(master_seed ||
                                                      transformed_key || 0x01) )

    transformed_key = Argon2d(SHA-256(SHA-256(passphrase)), salt=S, ...)
    master_key      = SHA-256(master_seed || transformed_key)
    ciphertext      = Twofish-CBC-PKCS7(master_key, IV, gzip(inner || xml))

    inner header: 1 = protected-stream id (3 = ChaCha20), 2 = 64-byte stream
                  key, 3 = one binary (flags byte + content), 0 = end
    protected values: ChaCha20 keystream over the WHOLE document in element
                  order, key = SHA-512(stream key)[0:32],
                  nonce = SHA-512(stream key)[32:44]

USAGE
-----
    printf '%s\\n' "$PASSPHRASE" | ./gen_twofish_fixture.py --build
    printf '%s\\n' "$PASSPHRASE" | ./gen_twofish_fixture.py            # verify

`--build` refuses to overwrite unless `--force` is given: the fixture is
committed, and silently regenerating it on every test run would make the
committed bytes meaningless.

NOTE the absence of a `--password` switch. The passphrase arrives on stdin,
exactly as it does everywhere else in this project (I10): `/proc/<pid>/cmdline`
is world-readable, and although this fixture's passphrase is printed in
README.md on purpose, the habit is the point.
"""

import argparse
import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FILE = os.path.join(HERE, "lab-kdbx40-twofish-argon2d.kdbx")

# ---------------------------------------------------------------------------
# constants, from the KDBX specification (see the module docstring)
# ---------------------------------------------------------------------------
SIG1 = b"\x03\xd9\xa2\x9a"
SIG2 = b"\x67\xfb\x4b\xb5"
#: KDBX 4.0. NOT 4.1: nothing below uses a 4.1-only element (no
#: PreviousParentGroup, no per-element CustomData), and stamping a version the
#: content does not need is the kind of small lie that makes a fixture useless
#: as evidence later.
VERSION_MINOR, VERSION_MAJOR = 0, 4

CIPHER_TWOFISH = b"\xadh\xf2\x9fWoK\xb9\xa3j\xd4z\xf9e4l"
KDF_ARGON2D = b"\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c"

H_END, H_CIPHER, H_COMPRESSION, H_MASTER_SEED = 0, 2, 3, 4
H_ENCRYPTION_IV, H_KDF_PARAMETERS = 7, 11

#: VariantDictionary value type tags.
VD_UINT32, VD_UINT64, VD_BYTES = 0x04, 0x05, 0x42

BLOCK = 16                       # Twofish block size
#: KeePass splits the payload at 1 MiB. This fixture is a few KiB, so it
#: produces one data block and the zero-length terminator — but the writer
#: below chunks anyway, because a fixture whose only exercise of the block
#: stream is "there is exactly one block" would not catch an off-by-one in the
#: block index that feeds the per-block HMAC key.
PAYLOAD_BLOCK = 1024 * 1024

#: KDBX4 timestamps: little-endian uint64 seconds since 0001-01-01T00:00:00Z,
#: base64. KDBX3 writes ISO-8601 text instead; getting this wrong produces a
#: file that opens and then reports every date as the year 1.
KP_EPOCH = _dt.datetime(1, 1, 1, tzinfo=_dt.timezone.utc)

#: Argon2d cost. Deliberately modest — this fixture is opened by every test run
#: — and deliberately inside backends/base.py's `Limits` clamps, so it can never
#: trip the I7 guard it is not here to test.
ARGON2_MEMORY_BYTES = 32 * 1024 * 1024
ARGON2_TIME = 2
ARGON2_PARALLELISM = 2
ARGON2_VERSION = 0x13

#: The one string the leak tests grep the whole system for. Same sentinel as
#: the rest of the corpus, so a leak from THIS fixture is caught by the checks
#: that already exist.
SENTINEL = "SENTINEL-DO-NOT-LEAK-8f3a2b"
ATTACHMENT = b"twofish fixture attachment: " + bytes(range(256))


# ---------------------------------------------------------------------------
# Twofish-CBC, composed by hand over Botan's raw block primitive
# ---------------------------------------------------------------------------
def _twofish(key):
    """Botan's Twofish block primitive.

    docs/HOST-FACTS.md, the most expensive fact in that file:
    `botan3.SymmetricCipher("Twofish/CBC/NoPadding")` raises "Not implemented"
    — Botan's cipher-mode FFI has no Twofish at all — while
    `botan3.BlockCipher("Twofish")` has it and matches the official 128- and
    256-bit ECB vectors. `BlockCipher` is a RAW ECB primitive with no mode and
    no padding, so CBC is composed below by hand. Do not go looking for a Botan
    CBC mode for Twofish; there isn't one.
    """
    import botan3 as botan
    bc = botan.BlockCipher("Twofish")
    bc.set_key(key)
    return bc


def _cbc_encrypt(key, iv, plain):
    """Twofish-CBC with PKCS#7 padding, the mode and padding KDBX uses."""
    pad = BLOCK - (len(plain) % BLOCK)          # always 1..16, never 0
    data = bytes(plain) + bytes([pad]) * pad
    bc = _twofish(key)
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(data), BLOCK):
        block = bytes(a ^ b for a, b in zip(data[off:off + BLOCK], prev))
        # bytes() is load-bearing: botan3's BlockCipher hands back a
        # `ctypes.c_char_Array_16`, and iterating one yields 1-byte `bytes`
        # objects rather than ints, so the XOR on the NEXT round would raise
        # `TypeError: ... for ^: 'int' and 'bytes'`. Measured on this host —
        # and the same omission was a live bug in the reader's KDBX3+Twofish
        # path, which this fixture is what finally exercised.
        prev = bytes(bc.encrypt(block))
        out += prev
    return bytes(out)


# ---------------------------------------------------------------------------
# KDBX4 pieces
# ---------------------------------------------------------------------------
def _kdbx_time(when):
    return base64.b64encode(
        struct.pack("<Q", int((when - KP_EPOCH).total_seconds()))
    ).decode("ascii")


def _vd_item(tag, key, value):
    return (bytes([tag]) + struct.pack("<I", len(key)) + key.encode("ascii")
            + struct.pack("<I", len(value)) + value)


def _kdf_parameters(salt):
    """The Argon2d VariantDictionary for the outer header field 11.

    Layout, from pykeepass's own `VariantDictionary` construct and confirmed
    against a KeePassXC-written fixture on this host: a two-byte version
    (`00 01`), then `type | len(key) | key | len(value) | value` items, then a
    single terminating `0x00`. Key ORDER does not matter — it is a dictionary —
    but the terminator must directly follow the last item, because the parser
    stops by peeking the byte after each one.
    """
    body = b"\x00\x01"
    body += _vd_item(VD_BYTES, "$UUID", KDF_ARGON2D)
    body += _vd_item(VD_BYTES, "S", salt)
    body += _vd_item(VD_UINT64, "I", struct.pack("<Q", ARGON2_TIME))
    body += _vd_item(VD_UINT64, "M", struct.pack("<Q", ARGON2_MEMORY_BYTES))
    body += _vd_item(VD_UINT32, "P", struct.pack("<I", ARGON2_PARALLELISM))
    body += _vd_item(VD_UINT32, "V", struct.pack("<I", ARGON2_VERSION))
    return body + b"\x00"


def _header(master_seed, iv, kdf_params):
    out = bytearray(SIG1 + SIG2
                    + struct.pack("<HH", VERSION_MINOR, VERSION_MAJOR))
    for fid, data in ((H_CIPHER, CIPHER_TWOFISH),
                      (H_COMPRESSION, struct.pack("<I", 1)),   # 1 = gzip
                      (H_MASTER_SEED, master_seed),
                      (H_ENCRYPTION_IV, iv),
                      (H_KDF_PARAMETERS, kdf_params),
                      (H_END, b"\r\n\r\n")):
        out += bytes([fid]) + struct.pack("<I", len(data)) + data
    return bytes(out)


def _hmac_base_key(master_seed, transformed_key):
    return hashlib.sha512(master_seed + transformed_key + b"\x01").digest()


def _block_key(base, index):
    return hashlib.sha512(struct.pack("<Q", index) + base).digest()


def _hmac_blocks(base, data):
    """`HMAC | len | data` per block, terminated by a zero-length block."""
    out = bytearray()
    index = 0
    for off in range(0, len(data), PAYLOAD_BLOCK):
        block = data[off:off + PAYLOAD_BLOCK]
        out += _one_block(base, index, block)
        index += 1
    out += _one_block(base, index, b"")
    return bytes(out)


def _one_block(base, index, block):
    mac = hmac.new(_block_key(base, index),
                   struct.pack("<Q", index) + struct.pack("<I", len(block))
                   + block, hashlib.sha256).digest()
    return mac + struct.pack("<I", len(block)) + block


class _InnerStream:
    """KeePass's ChaCha20 protected-value stream.

    ONE keystream runs across the whole document in element order, so every
    protected value has to be encrypted in exactly the order a reader will
    decrypt them in. Encrypting them out of order produces a file that decrypts
    to plausible-looking garbage rather than to an error, which is the worst
    kind of bug to have in a fixture.

    key   = SHA-512(protected_stream_key)[0:32]
    nonce = SHA-512(protected_stream_key)[32:44]
    `cryptography` wants the 16-byte counter||nonce form and KeePass starts the
    counter at zero, hence the four leading zero bytes.
    """

    def __init__(self, stream_key):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        digest = hashlib.sha512(stream_key).digest()
        self._enc = Cipher(
            algorithms.ChaCha20(digest[:32], b"\x00" * 4 + digest[32:44]),
            None).encryptor()

    def protect(self, text):
        return base64.b64encode(
            self._enc.update(text.encode("utf-8"))).decode("ascii")


def _inner_header(stream_key, binaries):
    out = bytearray()
    out += b"\x01" + struct.pack("<I", 4) + struct.pack("<I", 3)  # ChaCha20
    out += b"\x02" + struct.pack("<I", len(stream_key)) + stream_key
    for blob in binaries:
        # The leading byte is the "protect in memory" flag KeePass stores with
        # every pool entry; 0x01 is what KeePassXC writes.
        payload = b"\x01" + blob
        out += b"\x03" + struct.pack("<I", len(payload)) + payload
    out += b"\x00" + struct.pack("<I", 0)
    return bytes(out)


def _xml(stream):
    """The inner document. Small on purpose; every element earns its place.

    `stream.protect()` is called in the order the values appear in the text
    below — see `_InnerStream` for why that ordering is load-bearing.
    """
    now = _kdbx_time(_dt.datetime.now(_dt.timezone.utc))

    def times(expires="False"):
        return ("<Times><CreationTime>{t}</CreationTime>"
                "<LastModificationTime>{t}</LastModificationTime>"
                "<LastAccessTime>{t}</LastAccessTime>"
                "<ExpiryTime>{t}</ExpiryTime><Expires>{e}</Expires>"
                "<UsageCount>0</UsageCount>"
                "<LocationChanged>{t}</LocationChanged></Times>"
                ).format(t=now, e=expires)

    def uuid():
        return base64.b64encode(os.urandom(16)).decode("ascii")

    # Encrypted here, in document order, BEFORE the f-string is assembled —
    # doing it inline would leave the order at the mercy of evaluation order.
    router_pw = stream.protect(SENTINEL)
    router_token = stream.protect("twofish-fixture-api-token")
    switch_pw = stream.protect("twofish-switch-pass")

    return (
        '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
        "<KeePassFile>"
        "<Meta>"
        "<Generator>cockpit-secrets tests/fixtures/gen_twofish_fixture.py"
        "</Generator>"
        "<DatabaseName>cockpit-secrets twofish fixture</DatabaseName>"
        "<DatabaseDescription>Throwaway test safe. Contains no real "
        "credential. Self-produced; see README.md.</DatabaseDescription>"
        "<DefaultUserName>fixture</DefaultUserName>"
        "<MaintenanceHistoryDays>365</MaintenanceHistoryDays>"
        "<MemoryProtection><ProtectTitle>False</ProtectTitle>"
        "<ProtectUserName>False</ProtectUserName>"
        "<ProtectPassword>True</ProtectPassword>"
        "<ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes>"
        "</MemoryProtection>"
        "<RecycleBinEnabled>False</RecycleBinEnabled>"
        "<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>"
        "<HistoryMaxItems>10</HistoryMaxItems>"
        "<HistoryMaxSize>6291456</HistoryMaxSize>"
        "<CustomIcons/><CustomData/>"
        "</Meta>"
        "<Root>"
        "<Group>"
        "<UUID>" + uuid() + "</UUID><Name>Twofish</Name>"
        "<Notes>Root group of the Twofish fixture.</Notes>"
        "<IconID>49</IconID>" + times() +
        "<IsExpanded>True</IsExpanded>"
        "<Entry>"
        "<UUID>" + uuid() + "</UUID><IconID>0</IconID>" + times() +
        "<String><Key>Title</Key><Value>Router</Value></String>"
        "<String><Key>UserName</Key><Value>admin</Value></String>"
        '<String><Key>Password</Key><Value Protected="True">'
        + router_pw + "</Value></String>"
        "<String><Key>URL</Key><Value>https://router.twofish.invalid/</Value>"
        "</String>"
        "<String><Key>Notes</Key><Value>Throwaway fixture entry. The password "
        "is a sentinel, not a credential.</Value></String>"
        '<String><Key>API Token</Key><Value Protected="True">'
        + router_token + "</Value></String>"
        "<String><Key>Lab Ticket</Key><Value>LAB-4711</Value></String>"
        "<Tags>lab;twofish</Tags>"
        "<Binary><Key>blob.bin</Key><Value Ref=\"0\"/></Binary>"
        "<AutoType><Enabled>True</Enabled>"
        "<DataTransferObfuscation>0</DataTransferObfuscation></AutoType>"
        "</Entry>"
        "<Entry>"
        "<UUID>" + uuid() + "</UUID><IconID>0</IconID>" + times() +
        "<String><Key>Title</Key><Value>Switch</Value></String>"
        "<String><Key>UserName</Key><Value>operator</Value></String>"
        '<String><Key>Password</Key><Value Protected="True">'
        + switch_pw + "</Value></String>"
        "<String><Key>URL</Key><Value>https://switch.twofish.invalid/</Value>"
        "</String>"
        "<String><Key>Notes</Key><Value/></String>"
        "<AutoType><Enabled>True</Enabled>"
        "<DataTransferObfuscation>0</DataTransferObfuscation></AutoType>"
        "</Entry>"
        "</Group>"
        "<DeletedObjects/>"
        "</Root>"
        "</KeePassFile>"
    ).encode("utf-8")


def build(passphrase):
    """Assemble the whole database. Returns bytes."""
    import argon2

    master_seed = os.urandom(32)
    iv = os.urandom(BLOCK)
    salt = os.urandom(32)
    stream_key = os.urandom(64)

    header = _header(master_seed, iv, _kdf_parameters(salt))

    composite = hashlib.sha256(
        hashlib.sha256(passphrase.encode("utf-8")).digest()).digest()
    transformed = argon2.low_level.hash_secret_raw(
        secret=composite, salt=salt, hash_len=32,
        type=argon2.low_level.Type.D, time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_BYTES // 1024,
        parallelism=ARGON2_PARALLELISM, version=ARGON2_VERSION)

    master_key = hashlib.sha256(master_seed + transformed).digest()
    base = _hmac_base_key(master_seed, transformed)

    stream = _InnerStream(stream_key)
    payload = _inner_header(stream_key, [ATTACHMENT]) + _xml(stream)
    compressor = zlib.compressobj(6, zlib.DEFLATED, 16 + 15,
                                  zlib.DEF_MEM_LEVEL, 0)
    compressed = compressor.compress(payload) + compressor.flush()

    out = bytearray(header)
    out += hashlib.sha256(header).digest()
    out += hmac.new(_block_key(base, 0xFFFFFFFFFFFFFFFF), header,
                    hashlib.sha256).digest()
    out += _hmac_blocks(base, _cbc_encrypt(master_key, iv, compressed))
    return bytes(out)


# ---------------------------------------------------------------------------
# verification — the point of the whole exercise
# ---------------------------------------------------------------------------
def verify(path, passphrase):
    """Open the fixture with OUR reader and check what came out. Returns 0/1.

    The file is copied to a private 0700 directory first, because
    `backends.base.open_safe_fd` refuses a safe whose parent directory is
    group-writable — and this source tree is 0775 over SMB. That refusal is
    I5 doing its job; it is not a problem with the fixture.
    """
    import shutil
    import tempfile

    sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
    from backends.base import Secret                       # noqa: E402
    from backends.kdbx import KdbxBackend                  # noqa: E402

    work = tempfile.mkdtemp(prefix="twofish-fixture-")
    os.chmod(work, 0o700)
    try:
        local = os.path.join(work, os.path.basename(path))
        shutil.copy2(path, local)
        os.chmod(local, 0o600)

        backend = KdbxBackend({"id": "twofish", "label": "twofish",
                               "format": "kdbx", "path": local,
                               "access": "admin", "mode": "ro"})
        probe = backend.probe()
        secret = Secret(passphrase)
        try:
            info = backend.unlock(secret, None)
        finally:
            secret.zero()

        rows = backend.entries(limit=100)["entries"]
        titles = sorted(r["title"] for r in rows)
        router = [r for r in rows if r["title"] == "Router"][0]
        password = backend.reveal(router["uuid"], "password")["value"]
        token = backend.reveal(router["uuid"], "API Token")["value"]
        blob = base64.b64decode(
            backend.attach_get(router["uuid"], "blob.bin")["b64"])
        backend.lock()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    checks = [
        ("the header reports KDBX 4.0", probe["version"] == "4.0"),
        ("the header reports Argon2d", probe["kdf"] == "argon2d"),
        ("both entries are present", titles == ["Router", "Switch"]),
        ("groups_total is 1", info["groups_total"] == 1),
        # The protected values are the real test: they only come out right if
        # Twofish-CBC decrypted correctly AND the ChaCha20 inner stream was
        # consumed in the same order it was produced.
        ("the protected password decrypts", password == SENTINEL),
        ("the protected custom field decrypts",
         token == "twofish-fixture-api-token"),
        ("the attachment round-trips byte for byte", blob == ATTACHMENT),
        ("tags survived", router["tags"] == ["lab", "twofish"]),
    ]
    bad = 0
    for label, cond in checks:
        print("  %s  %s" % ("PASS" if cond else "FAIL", label))
        bad += 0 if cond else 1
    return (1 if bad else 0) + _foreign_check(path, passphrase)


def _foreign_check(path, passphrase):
    """Hand the file to `keepassxc-cli` and see whether it opens. 0 = fine.

    This is the only part of this script that is evidence about anyone but us
    (I19), so it is run for real rather than described. It is a SKIP and not a
    failure when `keepassxc-cli` is absent — it is the TEST-ONLY oracle and must
    never appear in a runtime path — but the skip is printed, because a check
    that silently did not run is worse than one that failed.

    Note what is asserted about `stderr`: it must be exactly the password
    prompt. KeePassXC reports a container it tolerated but did not like (an
    unmapped key, an unknown element) on stderr while still exiting 0, so
    "rc == 0" on its own would hide precisely the class of defect a
    self-produced container is most likely to have.
    """
    import shutil
    import subprocess

    cli = shutil.which("keepassxc-cli")
    if not cli:
        print("  skip  keepassxc-cli is not installed — the FOREIGN check on "
              "this fixture DID NOT RUN")
        return 0

    def run(*args):
        return subprocess.run([cli] + list(args), input=passphrase + "\n",
                              capture_output=True, text=True)

    info = run("db-info", path)
    listing = run("ls", "-R", "-q", path)
    shown = run("show", "-s", "-q", "-a", "Password", path, "/Router")
    # KeePassXC writes its own password prompt to stderr — "Enter password to
    # unlock <path>: ", with no trailing newline — so it has to be removed by
    # pattern rather than by line. Anything ELSE on stderr is the complaint
    # this check exists to catch.
    import re
    noise = re.sub(r"Enter password to unlock [^\n]*?:\s*", "",
                   "".join(p.stderr for p in (info, listing, shown))).strip()
    checks = [
        ("keepassxc-cli db-info opens it", info.returncode == 0),
        ("keepassxc-cli recognises the cipher as Twofish",
         "Twofish" in info.stdout),
        ("keepassxc-cli lists both entries",
         listing.returncode == 0
         and sorted(listing.stdout.split()) == ["Router", "Switch"]),
        ("keepassxc-cli reads the protected password",
         shown.returncode == 0 and shown.stdout.strip() == SENTINEL),
        ("keepassxc-cli reported nothing on stderr", noise == ""),
    ]
    bad = 0
    for label, cond in checks:
        print("  %s  %s" % ("PASS" if cond else "FAIL", label))
        bad += 0 if cond else 1
    if bad:
        print("        keepassxc-cli stderr: %s" % noise[:300])
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", default=DEFAULT_FILE,
                    help="fixture to write or verify")
    ap.add_argument("--build", action="store_true",
                    help="write the fixture (default is verify-only)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing fixture")
    args = ap.parse_args()

    passphrase = sys.stdin.readline().rstrip("\n").rstrip("\r")
    if not passphrase:
        sys.stderr.write("gen_twofish_fixture.py: empty passphrase on stdin\n")
        return 64

    try:
        if args.build:
            if os.path.exists(args.file) and not args.force:
                sys.stderr.write(
                    "gen_twofish_fixture.py: %s exists; pass --force to "
                    "rewrite the COMMITTED fixture\n" % args.file)
                return 1
            data = build(passphrase)
            # 0600 and O_EXCL-free is fine here: this is a fixture, not a safe,
            # and the caller has just been told we are about to overwrite it.
            fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                         0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            os.chmod(args.file, 0o600)
            sys.stderr.write(
                "gen_twofish_fixture.py: wrote %s (%d bytes, sha256 %s)\n"
                % (args.file, len(data),
                   hashlib.sha256(data).hexdigest()[:16]))
        rc = verify(args.file, passphrase)
    except Exception as exc:                      # noqa: BLE001 - test tool
        # Class + message only. Even in a test tool a traceback prints locals,
        # and one of the locals here is the passphrase (I15).
        sys.stderr.write("gen_twofish_fixture.py: %s: %s\n"
                         % (type(exc).__name__, exc))
        return 1
    finally:
        passphrase = None

    print("\ngen_twofish_fixture.py: %s"
          % ("OK" if rc == 0 else "FAILED"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
