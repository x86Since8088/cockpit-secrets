"""psafe3 — Password Safe v3 (`.psafe3`), implemented from formatV3.txt.

WHY THIS IS HAND-WRITTEN AND NOT A DEPENDENCY
----------------------------------------------
docs/UPSTREAM-REVIEW.md §3 settles this and it is not reopened here:

  - The Ubuntu `passwordsafe` package ships `/usr/bin/pwsafe` — the wxWidgets
    GUI — and no CLI. "Shell out to the reference implementation" is available
    for KDBX and is NOT available for this format.
  - `ronys/pypwsafe` is GPLv2 Python **2**, unmaintained, and its own
    known-issues list records an unresolved doubt about the order in which
    preferences are serialised for HMAC validation. An acknowledged ambiguity
    in the *authentication tag computation* is disqualifying: it means the
    library may write files other implementations reject, or accept files it
    should not. Not vendored, not ported.

So: implemented from the specification. `docs/formatV3.txt` version 3.31 from
`pwsafe/pwsafe`, cross-read against `src/core/PWSfileV3.cpp` and
`src/core/Util.cpp` (`_writecbc1st`, `_writecbcRest`, `_readcbc`) so that the
three places the prose is ambiguous were settled by the reference code:

  1. **The KDF is NOT PBKDF2.** A well-ranked search result says it is. It is
     the iterated-hash key stretching of Kelsey/Schneier/Hall/Wagner §4.1:
     `X = SHA256(passphrase || salt)`, then `X = SHA256(X)` ITER times.
     Building on the PBKDF2 summary produces files no real Password Safe can
     open, and — worse — a reader that silently fails to open real ones.
  2. **The first block of every field carries up to 11 bytes of data.**
     `len(4, LE) | type(1) | data[0:11]`, then `ceil((len-11)/16)` more blocks.
     Not "a length block followed by ceil(len/16) data blocks".
  3. **The HMAC covers plaintext FIELD DATA only** — not the 4-byte length, not
     the type byte, not the random padding, not the EOF block.
     `PWSfileV3::WriteCBC` is one line: `m_hmac.Update(data, length)` and then
     the generic writer. Get this wrong and you produce a file that round-trips
     through your own bug and interoperates with nothing (bad practice #20).

VERIFY-BEFORE-USE IS *CONSTRAINED* BY THE FORMAT, NOT CHOSEN (I6)
------------------------------------------------------------------
The HMAC lives at the **end** of the file, after the ciphertext, and its key L
is itself wrapped in blocks that only the stretched key opens. There is no
ordering of operations in which this format can be authenticated before it is
decrypted. That is inherent to Password Safe v3 and cannot be fixed here.

What IS chosen, and what this module guarantees:

  - The whole file is decrypted and parsed into memory as **untrusted parser
    input**, with every length header bounds-checked in O(1) before a byte is
    allocated (I7).
  - The HMAC is verified with `hmac.compare_digest` before `parse_bytes`
    returns, so no decrypted value can escape to a caller — let alone to the
    browser, an error string or a log line — from a file that did not
    authenticate.
  - A wrong passphrase and a failed HMAC raise `BadCredential` with the **same
    detail string**. They are distinguishable in the audit log and nowhere
    else; making them distinguishable to the client turns unlock into a
    decryption oracle (I6, docs/CONTRACT.md error taxonomy).

    Honest caveat on timing: the format's `H(P')` check lets a wrong passphrase
    fail before the body is decrypted, so a wrong passphrase returns sooner
    than a right one. That is a property of the format. The constant floor that
    hides it (`Limits.FAIL_FLOOR_SECONDS`, I16) belongs to `secrets-admin`,
    which owns the failure path for every backend; this module does not sleep.

FORWARD COMPATIBILITY IS A CORRECTNESS REQUIREMENT (I22, spec §4.1)
--------------------------------------------------------------------
formatV3.txt §4.1: implementations "SHOULD NOT discard or report an error when
encountering a field of an unknown type. Rather, the field(s) type and data
should be read, and preserved when the database is saved."

This module models a database as **an ordered list of (type, bytes) fields**
and nothing else. Known types get accessors; unknown types get carried. There
is no "parse into a rich object and re-emit" step to lose anything in, which
is exactly the amputation I22 is about. `Psafe3Backend.save()` still runs the
round-trip guard before its first write, because "lossless by construction" is
a claim until something checks it.

Licence: GPL-3.0 — see ../LICENSE.
"""

import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import os
import secrets as _sysrandom
import sys
import time
import urllib.parse
import uuid as _uuid
from datetime import datetime, timezone

from .base import (
    AccessDenied, BadCredential, Conflict, Invalid, NotFound, SecretsError,
    Unsupported, Backend, CsvWriter, LockFile, Limits, Secret,
    atomic_replace, constant_time_eq, open_safe_fd, redact, register_backend,
    validate_new_path, VERSION,
)

__all__ = [
    "Psafe3Backend", "Pws3Db", "Field", "StretchedKey",
    "parse_bytes", "serialize", "read_file", "write_file",
    "parse_password_history", "build_password_history",
    "twofish_provider", "set_twofish_provider",
    "HEADER_FIELDS", "RECORD_FIELDS",
]


# ===========================================================================
# On-disk layout  (formatV3.txt §2)
# ===========================================================================
#
#   "PWS3" | SALT(32) | ITER(u32 LE) | H(P')(32) | B1 B2 B3 B4 (4x16) | IV(16)
#         | Twofish-CBC(K, HDR || R1..Rn) | "PWS3-EOFPWS3-EOF" | HMAC-SHA256(32)
#
TAG = b"PWS3"
EOF_BLOCK = b"PWS3-EOFPWS3-EOF"        # §2.10, exactly one block, UNENCRYPTED
BLOCK = 16                             # Twofish block size; the format's unit
SALT_LEN = 32
MAC_LEN = 32

#: Everything before the ciphertext: TAG+SALT+ITER+H(P')+B1..B4+IV.
PREFIX_LEN = len(TAG) + SALT_LEN + 4 + 32 + 64 + BLOCK      # 152
#: Everything after it: the EOF marker and the HMAC.
TAIL_LEN = len(EOF_BLOCK) + MAC_LEN                          # 48
#: A file smaller than this cannot hold even an empty header.
MIN_FILE_LEN = PREFIX_LEN + TAIL_LEN                         # 200

#: Field-count ceilings. `Limits` caps entries and bytes; these cap the third
#: axis a hostile file can inflate — fields per record — which is what turns
#: "100 000 legal records" into ten million allocations.
MAX_HEADER_FIELDS = 4096
MAX_FIELDS_PER_RECORD = 4096

#: Version we stamp into a database we CREATE. 0x030D is PasswordSafe V3.30 —
#: old enough that every maintained Password Safe reads it without a "newer
#: format" prompt, new enough to cover every field this module ever writes. A
#: database we OPENED keeps whatever version it declared: bumping a file's
#: format version because we saved it would be a claim about features we did
#: not add.
DEFAULT_NEW_VERSION = 0x030D

#: Format version that introduced the attachment fields 0x25..0x29 — §3.3 note
#: [30], "These parameters were introduced in version 0x030F (PasswordSafe
#: V3.68)". `attach_add` refuses below this rather than bumping the file's
#: declared version, for the reason stated on DEFAULT_NEW_VERSION: raising a
#: version is a claim about the file, and the operator is the one entitled to
#: make it.
ATTACHMENT_MIN_VERSION = 0x030F

# -- header field types (§3.2) ---------------------------------------------
HDR_VERSION = 0x00
HDR_UUID = 0x01
HDR_PREFS = 0x02
HDR_TREE_DISPLAY = 0x03
HDR_LAST_SAVE_TIME = 0x04
HDR_LAST_SAVE_WHO = 0x05          # deprecated by 0x07/0x08 since format 0x0302
HDR_LAST_SAVE_WHAT = 0x06
HDR_LAST_SAVE_USER = 0x07
HDR_LAST_SAVE_HOST = 0x08
HDR_DB_NAME = 0x09
HDR_DB_DESCRIPTION = 0x0A
HDR_FILTERS = 0x0B
HDR_RESERVED_0C = 0x0C
HDR_RESERVED_0D = 0x0D
HDR_RESERVED_0E = 0x0E
HDR_RECENTLY_USED = 0x0F
HDR_PASSWORD_POLICIES = 0x10
HDR_EMPTY_GROUP = 0x11            # repeatable — the ONE header field that is
HDR_YUBICO = 0x12
HDR_LAST_MASTER_PW_CHANGE = 0x13
FT_END = 0xFF                     # §3.2/§3.3, both tables

#: type -> (name, kind). `kind` drives rendering only; the raw bytes are always
#: what is stored and what is written back.
HEADER_FIELDS = {
    HDR_VERSION:               ("version", "u16"),
    HDR_UUID:                  ("uuid", "uuid"),
    HDR_PREFS:                 ("non-default-preferences", "text"),
    HDR_TREE_DISPLAY:          ("tree-display-status", "text"),
    HDR_LAST_SAVE_TIME:        ("last-save-time", "time"),
    HDR_LAST_SAVE_WHO:         ("last-save-who", "text"),
    HDR_LAST_SAVE_WHAT:        ("last-save-what", "text"),
    HDR_LAST_SAVE_USER:        ("last-save-user", "text"),
    HDR_LAST_SAVE_HOST:        ("last-save-host", "text"),
    HDR_DB_NAME:               ("db-name", "text"),
    HDR_DB_DESCRIPTION:        ("db-description", "text"),
    HDR_FILTERS:               ("db-filters", "text"),
    HDR_RESERVED_0C:           ("reserved-0c", "bytes"),
    HDR_RESERVED_0D:           ("reserved-0d", "bytes"),
    HDR_RESERVED_0E:           ("reserved-0e", "bytes"),
    HDR_RECENTLY_USED:         ("recently-used-entries", "text"),
    HDR_PASSWORD_POLICIES:     ("named-password-policies", "text"),
    HDR_EMPTY_GROUP:           ("empty-group", "text"),
    HDR_YUBICO:                ("yubico-secret", "bytes"),
    HDR_LAST_MASTER_PW_CHANGE: ("last-master-password-change", "time"),
}

# -- record field types (§3.3) ---------------------------------------------
REC_UUID = 0x01
REC_GROUP = 0x02
REC_TITLE = 0x03
REC_USERNAME = 0x04
REC_NOTES = 0x05
REC_PASSWORD = 0x06
REC_CREATE_TIME = 0x07
REC_PASSWORD_MOD_TIME = 0x08
REC_LAST_ACCESS_TIME = 0x09
REC_PASSWORD_EXPIRY_TIME = 0x0A
REC_RESERVED_0B = 0x0B
REC_LAST_MOD_TIME = 0x0C
REC_URL = 0x0D
REC_AUTOTYPE = 0x0E
REC_PASSWORD_HISTORY = 0x0F
REC_PASSWORD_POLICY = 0x10
REC_PASSWORD_EXPIRY_INTERVAL = 0x11
REC_RUN_COMMAND = 0x12
REC_DOUBLE_CLICK_ACTION = 0x13
REC_EMAIL = 0x14
REC_PROTECTED = 0x15
REC_OWN_SYMBOLS = 0x16
REC_SHIFT_DOUBLE_CLICK_ACTION = 0x17
REC_POLICY_NAME = 0x18
REC_KEYBOARD_SHORTCUT = 0x19
REC_RESERVED_1A = 0x1A
REC_TWO_FACTOR_KEY = 0x1B
REC_CC_NUMBER = 0x1C
REC_CC_EXPIRATION = 0x1D
REC_CC_VERIFICATION = 0x1E
REC_CC_PIN = 0x1F
REC_QR_CODE = 0x20
REC_TOTP_CONFIG = 0x21
REC_TOTP_LENGTH = 0x22
REC_TOTP_TIME_STEP = 0x23
REC_TOTP_START_TIME = 0x24
REC_ATT_TITLE = 0x25
REC_ATT_MEDIATYPE = 0x26
REC_ATT_FILENAME = 0x27
REC_ATT_MOD_TIME = 0x28
REC_ATT_CONTENT = 0x29
REC_PASSKEY_CREDENTIAL_ID = 0x2A
REC_PASSKEY_RP_ID = 0x2B
REC_PASSKEY_USER_HANDLE = 0x2C
REC_PASSKEY_ALGORITHM_ID = 0x2D
REC_PASSKEY_PRIVATE_KEY = 0x2E
REC_PASSKEY_SIGN_COUNT = 0x2F
REC_CUSTOM_TEXT_FIELD = 0x30
REC_UNKNOWN_TESTING = 0xDF

#: Every record field type in formatV3.txt §3.3, including the ones this
#: project never renders. They are listed so that `edit()` can refuse a name it
#: does not know rather than inventing a type byte, and so the UI schema has
#: one place to read the vocabulary from. Types absent from this table are
#: still parsed, carried and written back — see `Field` and I22.
RECORD_FIELDS = {
    REC_UUID:                      ("uuid", "uuid"),
    REC_GROUP:                     ("group", "text"),
    REC_TITLE:                     ("title", "text"),
    REC_USERNAME:                  ("username", "text"),
    REC_NOTES:                     ("notes", "text"),
    REC_PASSWORD:                  ("password", "text"),
    REC_CREATE_TIME:               ("create-time", "time"),
    REC_PASSWORD_MOD_TIME:         ("password-mod-time", "time"),
    REC_LAST_ACCESS_TIME:          ("last-access-time", "time"),
    REC_PASSWORD_EXPIRY_TIME:      ("password-expiry-time", "time"),
    REC_RESERVED_0B:               ("reserved-0b", "bytes"),
    REC_LAST_MOD_TIME:             ("last-mod-time", "time"),
    REC_URL:                       ("url", "text"),
    REC_AUTOTYPE:                  ("autotype", "text"),
    REC_PASSWORD_HISTORY:          ("password-history", "text"),
    REC_PASSWORD_POLICY:           ("password-policy", "text"),
    REC_PASSWORD_EXPIRY_INTERVAL:  ("password-expiry-interval", "u32"),
    REC_RUN_COMMAND:               ("run-command", "text"),
    REC_DOUBLE_CLICK_ACTION:       ("double-click-action", "u16"),
    REC_EMAIL:                     ("email", "text"),
    REC_PROTECTED:                 ("protected", "u8"),
    REC_OWN_SYMBOLS:               ("own-symbols", "text"),
    REC_SHIFT_DOUBLE_CLICK_ACTION: ("shift-double-click-action", "u16"),
    REC_POLICY_NAME:               ("password-policy-name", "text"),
    REC_KEYBOARD_SHORTCUT:         ("keyboard-shortcut", "bytes"),
    REC_RESERVED_1A:               ("reserved-1a", "uuid"),
    REC_TWO_FACTOR_KEY:            ("two-factor-key", "bytes"),
    REC_CC_NUMBER:                 ("credit-card-number", "text"),
    REC_CC_EXPIRATION:             ("credit-card-expiration", "text"),
    REC_CC_VERIFICATION:           ("credit-card-verification", "text"),
    REC_CC_PIN:                    ("credit-card-pin", "text"),
    REC_QR_CODE:                   ("qr-code", "text"),
    REC_TOTP_CONFIG:               ("totp-config", "u8"),
    REC_TOTP_LENGTH:               ("totp-length", "u8"),
    REC_TOTP_TIME_STEP:            ("totp-time-step", "u8"),
    REC_TOTP_START_TIME:           ("totp-start-time", "time"),
    REC_ATT_TITLE:                 ("attachment-title", "text"),
    REC_ATT_MEDIATYPE:             ("attachment-mediatype", "text"),
    REC_ATT_FILENAME:              ("attachment-filename", "text"),
    REC_ATT_MOD_TIME:              ("attachment-mod-time", "time"),
    REC_ATT_CONTENT:               ("attachment-content", "bytes"),
    REC_PASSKEY_CREDENTIAL_ID:     ("passkey-credential-id", "bytes"),
    REC_PASSKEY_RP_ID:             ("passkey-relying-party-id", "text"),
    REC_PASSKEY_USER_HANDLE:       ("passkey-user-handle", "bytes"),
    REC_PASSKEY_ALGORITHM_ID:      ("passkey-algorithm-id", "i32"),
    REC_PASSKEY_PRIVATE_KEY:       ("passkey-private-key", "bytes"),
    REC_PASSKEY_SIGN_COUNT:        ("passkey-sign-count", "u32"),
    REC_CUSTOM_TEXT_FIELD:         ("custom-text-field", "text"),
    REC_UNKNOWN_TESTING:           ("unknown-testing", "bytes"),
}

_RECORD_NAME_TO_TYPE = {name: t for t, (name, _k) in RECORD_FIELDS.items()}

#: Contract field name -> this format's own field name, for `reveal`. The
#: helper's vocabulary is deliberately format-neutral (docs/CONTRACT.md), so
#: the translation belongs on this side of the boundary; the alternative is a
#: table of per-format special cases in `secrets-admin`, which is precisely the
#: knowledge a backend exists to hold. Only names the helper actually publishes
#: appear here — this is not a general alias space.
_REVEAL_ALIASES = {
    "totp": "two-factor-key",
    "totp-seed": "two-factor-key",
}

#: Fields `entries()` must never carry — invariant 1 of the Backend ABC. This
#: is not "the password field": password history holds every PREVIOUS password
#: in cleartext, the two-factor key is a TOTP seed, and the credit-card and
#: passkey fields are exactly what an attacker came for. `reveal()` is the only
#: door for all of them.
SECRET_FIELDS = frozenset({
    "password", "notes", "password-history", "two-factor-key",
    "credit-card-number", "credit-card-expiration",
    "credit-card-verification", "credit-card-pin", "qr-code",
    "passkey-credential-id", "passkey-user-handle", "passkey-private-key",
    "attachment-content", "own-symbols",
})

#: Double-Click / Shift-Double-Click action values, spec §3.3 note [15]. Here
#: so the UI schema has a single source and does not invent labels.
DOUBLE_CLICK_ACTIONS = {
    0: "copy-password", 1: "view-edit", 2: "autotype", 3: "browse",
    4: "copy-notes", 5: "copy-username", 6: "copy-password-minimize",
    7: "browse-plus", 8: "run-command", 9: "send-email", 0xFF: "default",
}


# ===========================================================================
# Twofish provider — Botan first, pure Python as the fallback
# ===========================================================================

_PROVIDER = None            # "botan" | "pure", resolved on first use
_PROVIDER_FACTORY = None    # callable(key_bytes) -> object with encrypt/decrypt
_PROVIDER_FORCED = None     # set by set_twofish_provider() for the test suite


class _BotanTwofish:
    """Adapter over `botan3.BlockCipher("Twofish")` — raw ECB blocks only.

    `BlockCipher` and not `SymmetricCipher`, and the reason is measured rather
    than stylistic (docs/HOST-FACTS.md): `SymmetricCipher("Twofish/CBC/
    NoPadding")` raises "botan_cipher_init failed: -40 (Not implemented)" on
    Botan 3.10, and so does "Twofish/ECB/NoPadding" — Botan's cipher-mode FFI
    has no Twofish at all. There is no Botan CBC mode for this cipher to reach
    for. `BlockCipher` does have Twofish and matches the official ECB vectors.

    That suits this format anyway: `BlockCipher` is a raw block primitive with
    no mode and no padding, which is exactly what Password Safe v3 needs —
    fields are block-aligned by the format itself with random fill, so a
    library that quietly appended PKCS#7 would corrupt every file we wrote.
    Both providers therefore expose the same thing, one block in and one block
    out, and this module composes CBC itself.

    `bytes()` around every result is load-bearing: botan3 returns a
    `ctypes.c_char_Array_16`, and ITERATING one yields 1-byte `bytes` objects
    rather than ints, which turns the XOR in `_cbc_decrypt` into a TypeError.
    """

    __slots__ = ("_c",)

    def __init__(self, key):
        import botan3                       # imported lazily: a kdbx unlock
        self._c = botan3.BlockCipher("Twofish")   # must not drag in Botan
        self._c.set_key(bytes(key))

    def encrypt(self, data):
        return bytes(self._c.encrypt(bytes(data)))

    def decrypt(self, data):
        return bytes(self._c.decrypt(bytes(data)))

    def clear(self):
        try:
            self._c.clear()
        except Exception:
            pass


def _resolve_provider():
    """Pick the Twofish provider once, preferring Botan.

    Botan 3.10 is a maintained, audited C++ library and is the primary; the
    pure-Python fallback exists so a host without `python3-botan` degrades to
    "slower", not to "cannot open the safe". Both are checked against
    tests/vectors/twofish_ecb.json, which is what makes either of them
    trustworthy (I19).
    """
    global _PROVIDER, _PROVIDER_FACTORY
    if _PROVIDER_FACTORY is not None:
        return
    forced = _PROVIDER_FORCED
    if forced != "pure":
        try:
            import botan3                                   # noqa: F401
            probe = _BotanTwofish(b"\x00" * 16)
            # Prove the binding really exposes raw Twofish before committing to
            # it: a build without the Twofish module would otherwise fail at
            # unlock time, on a real safe, with a stranger error.
            if probe.encrypt(b"\x00" * BLOCK) != binascii.unhexlify(
                    b"9f589f5cf6122c32b6bfec2f2ae8c35a"):
                raise RuntimeError("Botan Twofish self-test mismatch")
            _PROVIDER, _PROVIDER_FACTORY = "botan", _BotanTwofish
            return
        except Exception:
            if forced == "botan":
                raise Unsupported("the Botan Twofish provider is unavailable")
    from .twofish_pure import Twofish as _PureTwofish
    _PROVIDER, _PROVIDER_FACTORY = "pure", _PureTwofish


def twofish_provider():
    """`"botan"` or `"pure"` — reported by `probe()` and the `health` verb.

    An operator who sees a slow save deserves to be able to tell whether it is
    the fallback cipher or something else.
    """
    _resolve_provider()
    return _PROVIDER


def set_twofish_provider(name):
    """Force a provider. **For the test suite only** — the vectors have to be
    able to exercise the fallback on a host where Botan is present."""
    global _PROVIDER, _PROVIDER_FACTORY, _PROVIDER_FORCED
    if name not in (None, "botan", "pure"):
        raise Invalid("unknown Twofish provider")
    _PROVIDER_FORCED = name
    _PROVIDER = _PROVIDER_FACTORY = None
    _resolve_provider()
    return _PROVIDER


def _cipher(key):
    _resolve_provider()
    return _PROVIDER_FACTORY(bytes(key))


def _ecb_decrypt(key, data):
    """§2.6/2.7: B1||B2 and B3||B4 are ECB, not CBC. Mixing them up yields a
    K that is wrong in its second block only — which decrypts the first record
    correctly and nothing after it."""
    c = _cipher(key)
    try:
        return c.decrypt(data)
    finally:
        c.clear()


def _ecb_encrypt(key, data):
    c = _cipher(key)
    try:
        return c.encrypt(data)
    finally:
        c.clear()


#: Chunk size for the bulk XOR below. Big enough that the per-chunk overhead
#: disappears, small enough that a 128 MiB safe (`Limits.MAX_SAFE_BYTES`) does
#: not turn into a 128 MiB Python integer three times over.
_XOR_CHUNK = 1 << 20


def _xor_into(dst, src_a, src_b):
    """`dst = src_a ^ src_b`, in 1 MiB bites, via big-integer XOR.

    A generator expression over `zip()` is the obvious spelling and is roughly
    an order of magnitude slower — which matters, because on a host without
    Botan this is the inner loop of every unlock.
    """
    for off in range(0, len(src_a), _XOR_CHUNK):
        end = min(off + _XOR_CHUNK, len(src_a))
        n = end - off
        a = int.from_bytes(src_a[off:end], "big")
        b = int.from_bytes(src_b[off:end], "big")
        dst[off:end] = (a ^ b).to_bytes(n, "big")


def _wipe(buf):
    """Overwrite a bytearray IN PLACE. Same idiom, and same caveat, as
    `Secret.zero()` in base.py: slice assignment writes over the actual
    allocation, whereas rebinding would hand the unwiped pages back to the
    allocator. A per-byte loop would also work and is ~100x slower on the
    128 MiB a safe is allowed to be."""
    n = len(buf)
    if n:
        buf[:] = b"\x00" * n


def _cbc_decrypt(key, iv, data):
    """CBC decryption — one bulk cipher call, then the chaining XOR.

    CBC *decryption* is parallelisable: block i's plaintext is
    `ECB-decrypt(c_i) XOR c_{i-1}`, and nothing depends on the previous
    plaintext. So the whole body goes through the cipher in ONE call — a single
    FFI crossing for Botan instead of one per 16 bytes — and the chaining is a
    single XOR against `IV || ciphertext[:-16]` afterwards. Encryption gets no
    such treatment below, because there it genuinely is serial.
    """
    data = bytes(data)
    if not data:
        return bytearray()
    c = _cipher(key)
    try:
        ecb = c.decrypt(data)
    finally:
        c.clear()
    out = bytearray(len(data))
    _xor_into(out, ecb, bytes(iv) + data[:-BLOCK])
    return out


def _cbc_encrypt(key, iv, data):
    """CBC encryption — irreducibly serial: block i needs block i-1's output."""
    c = _cipher(key)
    try:
        data = bytes(data)
        out = bytearray(len(data))
        prev = int.from_bytes(iv, "big")
        for off in range(0, len(data), BLOCK):
            block = int.from_bytes(data[off:off + BLOCK], "big") ^ prev
            enc = c.encrypt(block.to_bytes(BLOCK, "big"))
            out[off:off + BLOCK] = enc
            prev = int.from_bytes(enc, "big")
        return out
    finally:
        c.clear()


# ===========================================================================
# Key stretching  (§2.3, [KEYSTRETCH] §4.1)
# ===========================================================================

class StretchedKey:
    """`(SALT, ITER, P')` — everything needed to read or write one file.

    **This is what an unlocked backend holds instead of the passphrase.** The
    `Backend` ABC forbids keeping a reference to the caller's passphrase past
    `unlock()`, and it is right to: the passphrase may open other things, and
    the multi-verb `open` session keeps a process alive. `P'` is strictly less
    dangerous — it is bound to this file's salt and iteration count, the file
    already commits to it by storing `SHA-256(P')` in cleartext, and it opens
    nothing else. It is still key material and it still lives in a `Secret`
    that `zero()` wipes.
    """

    __slots__ = ("salt", "iterations", "_pprime")

    def __init__(self, salt, iterations, pprime):
        self.salt = bytes(salt)
        self.iterations = int(iterations)
        self._pprime = pprime            # Secret

    @classmethod
    def derive(cls, password, salt, iterations, *, for_write=False):
        """Stretch a passphrase into P'.

        `Limits.check_pws3_iter` runs FIRST and unconditionally (I7): ITER comes
        out of the file, so a hostile file gets to name how many SHA-256s this
        host performs, and on the admin path this host is root. `ITER=0x7fffffff`
        is a wall-clock DoS with no memory footprint for an RSS ceiling to
        catch, which is why the ceiling is a plain number checked up front.
        """
        Limits.check_pws3_iter(iterations, for_write=for_write)
        if len(salt) != SALT_LEN:
            raise Invalid("PWS3 salt is not 32 bytes")

        pw_bytes = password.bytes if isinstance(password, Secret) else password
        # [KEYSTRETCH] §4.1 with SHA-256:  X0 = H(P || S); X_i = H(X_{i-1}).
        # NOT PBKDF2 — see the module docstring. The passphrase is UTF-8 with
        # no terminator, matching pwsafe's ConvertPasskey().
        digest = hashlib.sha256(pw_bytes + salt).digest()
        with Limits.kdf_budget():
            for _ in range(iterations):
                digest = hashlib.sha256(digest).digest()
        pprime = Secret(digest)
        # `digest` is an immutable bytes the GC owns; documented in base.py's
        # Secret docstring as the copy we cannot wipe. Drop our reference and
        # keep the wipeable one.
        del digest
        return cls(salt, iterations, pprime)

    @property
    def pprime(self):
        return self._pprime.bytes

    def hash(self):
        """`H(P')` — §2.5, the passphrase check value stored in cleartext."""
        return hashlib.sha256(self._pprime.bytes).digest()

    def unwrap(self, b1b2, b3b4):
        """Recover `(K, L)` from B1..B4 — §2.6, §2.7. Twofish **ECB** under P'.

        K encrypts the records; L keys the HMAC. The spec's implementation note
        "K and L must NOT be related" is a rule for the writer, and `serialize`
        draws both from `secrets.token_bytes` independently.
        """
        key = Secret(_ecb_decrypt(self._pprime.bytes, b1b2))
        mac = Secret(_ecb_decrypt(self._pprime.bytes, b3b4))
        return key, mac

    def wrap(self, key, mac):
        return (_ecb_encrypt(self._pprime.bytes, key),
                _ecb_encrypt(self._pprime.bytes, mac))

    def zero(self):
        self._pprime.zero()

    def __repr__(self):
        return "<StretchedKey iter=%d %s>" % (
            self.iterations, "zeroed" if self._pprime.zeroed else "live")


# ===========================================================================
# Fields  (§3)
# ===========================================================================

class Field:
    """One typed field: a type byte and its data, verbatim.

    Deliberately dumb. Everything this module knows about a field's *meaning*
    lives in `HEADER_FIELDS`/`RECORD_FIELDS` and in the accessors; the field
    itself is bytes in, bytes out. That is what makes I22 hold: a field type we
    have never heard of survives a read/write cycle byte-for-byte because there
    is no richer representation for it to be flattened into.
    """

    __slots__ = ("type", "data")

    def __init__(self, ftype, data):
        self.type = int(ftype) & 0xFF
        self.data = bytes(data)

    def __eq__(self, other):
        return (isinstance(other, Field)
                and self.type == other.type and self.data == other.data)

    def __repr__(self):
        # Length only. A field's data may be a password (I15).
        return "<Field 0x%02x len=%d>" % (self.type, len(self.data))


def _check_field_length(declared, ftype, available):
    """O(1) bounds check on a field length header, before any allocation (I7).

    `Limits.check_length` is the shared checker and caps at
    `Limits.MAX_FIELD_BYTES` (4 MiB) — the right ceiling for a text field and
    the wrong one for exactly two record types. Attachment content is capped by
    `Limits.MAX_ATTACHMENT_BYTES` instead, because Password Safe genuinely
    stores files there and a 4 MiB refusal would make real databases
    unreadable. Either way the refusal is arithmetic: a declared length of
    0xFFFFFFFF fails here, not in the allocator (bad practice #7).
    """
    if ftype == REC_ATT_CONTENT:
        if declared > Limits.MAX_ATTACHMENT_BYTES:
            raise Invalid("attachment length %d exceeds the %d byte limit"
                          % (declared, Limits.MAX_ATTACHMENT_BYTES))
        if declared > available:
            raise Invalid("attachment length %d exceeds the %d bytes remaining"
                          % (declared, available))
        return
    Limits.check_length(declared, available, what="PWS3 field")


def _parse_field_stream(plain):
    """Split decrypted plaintext into `Field`s. §3, and `_readcbc` in Util.cpp.

    Layout, and the part a summary gets wrong: the FIRST block of a field is
    `len(4, LE) | type(1) | up to 11 bytes of data`, random-filled to 16. Only
    `len - 11` bytes spill into further blocks. A reader that expects a bare
    length block followed by `ceil(len/16)` data blocks desynchronises on the
    very first field of every real file.
    """
    fields = []
    pos = 0
    total = len(plain)
    while pos < total:
        if total - pos < BLOCK:
            raise Invalid("PWS3 field header is truncated")
        head = bytes(plain[pos:pos + BLOCK])
        declared = int.from_bytes(head[0:4], "little")
        ftype = head[4]
        pos += BLOCK
        # 11 bytes ride in the header block; the rest must fit in what remains.
        _check_field_length(declared, ftype, 11 + (total - pos))
        if declared <= 11:
            data = head[5:5 + declared]
        else:
            spill = declared - 11
            need = ((spill + BLOCK - 1) // BLOCK) * BLOCK
            if total - pos < need:
                raise Invalid("PWS3 field data is truncated")
            data = head[5:16] + bytes(plain[pos:pos + spill])
            pos += need
        fields.append(Field(ftype, data))
        if len(fields) > (Limits.MAX_ENTRIES * 8 + MAX_HEADER_FIELDS):
            raise Invalid("PWS3 file declares an implausible number of fields")
    return fields


def _emit_field(field, out, mac):
    """Serialise one field and fold its DATA — only its data — into the HMAC.

    §2.11 and `PWSfileV3::WriteCBC`: the MAC covers "all the data stored in all
    fields". Not the length, not the type byte, not the random padding, not the
    EOF block. This one line is the difference between a file real Password
    Safe opens and a file that only we can read.
    """
    data = field.data
    n = len(data)
    if n > 0xFFFFFFFF:
        raise Invalid("PWS3 field is too large to encode")
    # THE WRITE HALF OF THE READ LIMIT  (I23, I41).
    #
    # `_check_field_length` is the READER's bounds check, and until this line
    # existed nothing on the write side consulted it: `_emit_field` would
    # happily encode a 5 MiB text field that `_parse_field_stream` then refused
    # at 4 MiB, so a save produced a file this program could not open. The same
    # call, with the same constants and the same type-awareness (attachments
    # get `MAX_ATTACHMENT_BYTES`, everything else `MAX_FIELD_BYTES`), is what
    # makes I23's sentence true here — "the read and write limits are now the
    # same number and this program cannot write a file its own reader refuses."
    # `available=n` so only the CAP can fire; there is no file being consumed.
    #
    # This is a cause fix, not the guarantee. The guarantee is the round trip
    # in `Psafe3Backend.verify_own_output`, which catches the whole class —
    # record counts, field counts, and the next asymmetry nobody has thought of
    # — rather than the one member of it that is already known.
    _check_field_length(n, field.type, n)
    # Random fill first, then overwrite the header — the unused bytes of the
    # length block are random by design (§3), to deny a known-plaintext crib.
    head = bytearray(_sysrandom.token_bytes(BLOCK))
    head[0:4] = n.to_bytes(4, "little")
    head[4] = field.type
    inline = data[:11]
    head[5:5 + len(inline)] = inline
    out += head
    spill = data[11:]
    if spill:
        pad = (-len(spill)) % BLOCK
        out += spill + _sysrandom.token_bytes(pad)
    mac.update(data)


# ===========================================================================
# The database
# ===========================================================================

def _split_group(path):
    """`"a.b.c"` -> `["a","b","c"]`, honouring a backslash escape.

    §3.3 note [2] says groups are period-separated and that "dots entered by
    the user should be 'escaped' by the application" — with "escaped" in quotes
    and no convention named, because the format does not specify one.

    So the split is a DISPLAY projection and nothing more: the authoritative
    value is always the raw `group` field, which is what `move()` writes and
    what round-trips. If another implementation escapes differently, the tree
    renders differently and no data is harmed. That property is deliberate.
    """
    parts = []
    buf = []
    escaped = False
    for ch in path:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
            buf.append(ch)
        elif ch == ".":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    # A trailing lone backslash stays in `buf` and therefore in the last
    # component, which is what makes _join_group the exact inverse.
    parts.append("".join(buf))
    return parts


def _join_group(parts):
    """Exact inverse of `_split_group` for any list it produced."""
    return ".".join(parts)


def _render(kind, data):
    """Render a field's bytes for display. Never used to decide anything."""
    if kind == "text":
        return data.decode("utf-8", "replace")
    if kind == "uuid":
        # 32 lowercase hex, no dashes — the "uuidstr" form the format itself
        # uses for alias and shortcut references (§3.3 notes [3], [4]).
        return binascii.hexlify(data).decode("ascii")
    if kind == "time":
        return _render_time(data)
    if kind in ("u8", "u16", "u32"):
        return str(int.from_bytes(data, "little")) if data else ""
    if kind == "i32":
        return str(int.from_bytes(data, "little", signed=True)) if data else ""
    return binascii.hexlify(data).decode("ascii")


def _render_time(data):
    """§3.1.3 time_t, plus the two shapes real files actually contain.

    Nominally 32-bit little-endian seconds since the Unix epoch. Note [5] warns
    that before PasswordSafe 3.09 the field was written as an 8-byte hexadecimal
    ASCII string and that implementations SHOULD parse that too. TOTP Start Time
    (0x24) is specified as a 5-byte value. All three are accepted; anything else
    is rendered as hex rather than guessed at.
    """
    if not data:
        return ""
    try:
        if len(data) == 8:
            secs = int(data.decode("ascii"), 16)
        elif len(data) in (4, 5):
            secs = int.from_bytes(data, "little")
        else:
            return binascii.hexlify(data).decode("ascii")
        if secs == 0:
            return ""
        # One timestamp shape across BOTH backends. backends/kdbx.py's _iso()
        # renders "2026-09-04T05:20:57Z"; a bare .isoformat() here rendered
        # "2026-09-04T00:00:00+00:00" for the same contract key
        # (entries[].modified), so a caller sorting or parsing a mixed listing
        # met two encodings of the same thing. RFC 3339, seconds precision, Z
        # for UTC — chosen because that is what the audit log and the KDBX
        # backend already emit, so this is the smaller side of the drift.
        return (datetime.fromtimestamp(secs, timezone.utc)
                .isoformat(timespec="seconds").replace("+00:00", "Z"))
    except (ValueError, OverflowError, OSError):
        return binascii.hexlify(data).decode("ascii")


def _time_field(when=None):
    """A 4-byte little-endian time_t, the shape every current writer uses."""
    return int(when if when is not None else time.time()).to_bytes(
        4, "little", signed=False)


# ===========================================================================
# Password History  (§3.3 field 0x0f, note [12])
# ===========================================================================
#
# This is the only per-entry history Password Safe v3 has, and it is a STRING
# field, not a structure: the whole list is packed into one text value.
#
#     "fmmnnTLPTLP...TLP"
#       f   {0,1}  history off / on
#       mm  2 hex  maximum size of the list (so 255 is the ceiling)
#       nn  2 hex  current number of entries
#       T   8 hex  time_t the password was set (%08x)
#       L   4 hex  password length **in characters**, not bytes
#       P          the password itself
#
# "The list is sorted by T, with the oldest entry first. Newer entries are
# appended to the end of the list."
#
# Two properties of this format decide how the code below is written:
#
#   1. **L counts characters.** The field arrives as UTF-8 bytes; a length
#      taken over the encoded bytes desynchronises the parser on the first
#      non-ASCII password and then reads the rest of the list as garbage — or,
#      worse, as a plausible-looking shorter list. Everything here works on the
#      DECODED string.
#   2. **It is attacker-shaped.** The field's own bytes were verified by the
#      file HMAC before this code sees them (I6), so this is not a decryption
#      oracle — but a legitimately-authenticated file can still be malformed,
#      and every length below is bounds-checked before it is used as a slice.
#      `Invalid` is the answer, never a partial list: "recover what you can"
#      from a password history means showing an operator a password that was
#      never in the file.

#: 2 hex digits, so the format's own ceiling. Not a policy of ours.
PWH_MAX_ENTRIES = 255
#: 4 hex digits for the length of one password.
PWH_MAX_PASSWORD = 0xFFFF


def parse_password_history(text):
    """`"1050300000000..."` -> `(enabled, max_size, [(when, password), ...])`.

    Raises `Invalid` for anything that does not parse exactly. An absent field
    is the caller's business — the spec's preferred representation of "no
    history" is no field at all, and `"00000"` is the other legal spelling.
    """
    if text is None:
        return (False, 0, [])
    if len(text) < 5:
        raise Invalid("this entry's password history is malformed")
    if text[0] not in ("0", "1"):
        raise Invalid("this entry's password history has an invalid flag")
    try:
        enabled = text[0] == "1"
        max_size = int(text[1:3], 16)
        count = int(text[3:5], 16)
    except ValueError:
        raise Invalid("this entry's password history is malformed")

    items = []
    pos = 5
    for _ in range(count):
        # 8 hex time + 4 hex length is the smallest a record can be.
        if pos + 12 > len(text):
            raise Invalid("this entry's password history is truncated")
        try:
            when = int(text[pos:pos + 8], 16)
            length = int(text[pos + 8:pos + 12], 16)
        except ValueError:
            raise Invalid("this entry's password history is malformed")
        pos += 12
        if length > PWH_MAX_PASSWORD or pos + length > len(text):
            raise Invalid("this entry's password history is truncated")
        items.append((when, text[pos:pos + length]))
        pos += length
    # Trailing bytes are not "extra data we can ignore": either nn undercounts
    # the list (so we would silently drop history) or the field is corrupt.
    if pos != len(text):
        raise Invalid("this entry's password history has trailing data")
    return (enabled, max_size, items)


def build_password_history(enabled, max_size, items):
    """The inverse of `parse_password_history`. Returns the field's text.

    `max_size` and the entry count are both 2 hex digits, so both are clamped
    to 255 here rather than at the call site — a wider value would be written
    as more than two digits and every other implementation would then read the
    overflow as the start of a timestamp.
    """
    max_size = max(0, min(int(max_size), PWH_MAX_ENTRIES))
    items = list(items)[-PWH_MAX_ENTRIES:]
    out = ["%d%02x%02x" % (1 if enabled else 0, max_size, len(items))]
    for when, password in items:
        if len(password) > PWH_MAX_PASSWORD:
            raise Invalid("a password is too long to record in the history")
        # Lowercase %08x/%04x, matching pwsafe's own ostream formatting. A
        # reader that upper-cases is fine either way, but there is no reason to
        # be the implementation that finds out.
        out.append("%08x%04x%s" % (int(when) & 0xFFFFFFFF, len(password),
                                   password))
    return "".join(out)


class Pws3Db:
    """A parsed Password Safe v3 database: ordered fields, nothing more.

    `header` and `records` hold `Field` objects in FILE ORDER, with the `END`
    terminators omitted (they are structural, carry no data, and are re-emitted
    by `serialize`). Every field is present, known or not — see I22.
    """

    __slots__ = ("header", "records", "credential", "warnings")

    def __init__(self, header=None, records=None, credential=None):
        self.header = list(header or [])
        self.records = [list(r) for r in (records or [])]
        self.credential = credential          # StretchedKey, or None
        self.warnings = []

    # -- header helpers ----------------------------------------------------

    def header_get(self, ftype):
        for f in self.header:
            if f.type == ftype:
                return f.data
        return None

    def header_set(self, ftype, data):
        for f in self.header:
            if f.type == ftype:
                f.data = bytes(data)
                return
        # A new header field goes before END, i.e. at the end of the list. The
        # Version field must stay first (§2.9.1) and `serialize` re-checks that.
        self.header.append(Field(ftype, data))

    def version(self):
        raw = self.header_get(HDR_VERSION)
        if not raw or len(raw) < 2:
            return 0
        return int.from_bytes(raw[:2], "little")

    def version_string(self):
        v = self.version()
        return "%d.%02X" % (v >> 8, v & 0xFF) if v else "3"

    def empty_groups(self):
        return [f.data.decode("utf-8", "replace")
                for f in self.header if f.type == HDR_EMPTY_GROUP]

    # -- record helpers ----------------------------------------------------

    @staticmethod
    def _one(record, ftype):
        """Index of the ONE field of this type, or -1. Refuses a repeat.

        REFUSE A REPEATED FIELD TYPE RATHER THAN PICK ONE. formatV3.txt §3.3
        gives every record field type at most one occurrence — 0x11 (Empty
        Groups) is repeatable and is a HEADER field, reached through
        `header_get`, not this — so a record carrying two 0x06 (Password)
        fields is a file that is telling two different readers two different
        things.

        These three helpers used to answer with the FIRST match, and that is a
        parser differential of exactly the kind `_read_header` in the KDBX
        backend refuses one layer up ("Refuse rather than pick"). Measured on a
        record built with two 0x06 fields: `reveal` returned the first value,
        and — worse — `field_set` rewrote only the first, so an operator
        rotating a compromised password got `{"changed": ["password"]}` back
        while the second copy kept the old value. A rotation that silently did
        nothing is a worse outcome than a refusal an operator can see.

        Written once and used by all three accessors so a read and a write can
        never disagree about which copy is "the" field.
        """
        found = -1
        for i, f in enumerate(record):
            if f.type == ftype:
                if found >= 0:
                    raise Invalid(
                        "this record carries more than one 0x%02x field; "
                        "refusing to guess which one is meant" % ftype)
                found = i
        return found

    @staticmethod
    def field_get(record, ftype):
        i = Pws3Db._one(record, ftype)
        return record[i].data if i >= 0 else None

    @staticmethod
    def field_set(record, ftype, data):
        i = Pws3Db._one(record, ftype)
        if i >= 0:
            record[i].data = bytes(data)
            return
        record.append(Field(ftype, data))

    @staticmethod
    def field_del(record, ftype):
        i = Pws3Db._one(record, ftype)
        if i >= 0:
            del record[i]
            return True
        return False

    def record_id(self, index):
        """Addressing id for a record: its UUID as 32 lowercase hex.

        §3.3 makes UUID mandatory, but a malformed or hand-built file may omit
        it. Such a record gets a synthetic, session-local id rather than being
        dropped or repaired: repairing it would write a field the file never
        had, and dropping it would lose data (I22).
        """
        raw = self.field_get(self.records[index], REC_UUID)
        if raw and len(raw) == 16:
            return binascii.hexlify(raw).decode("ascii")
        return "noid:%d" % index

    def find(self, ident):
        """Index of the record with this id, or -1. Accepts the 32-hex form and
        the dashed RFC 4122 form."""
        want = (ident or "").strip().lower().replace("-", "")
        for i in range(len(self.records)):
            if self.record_id(i).lower().replace("-", "") == want:
                return i
        return -1

    def zero(self):
        """Drop the credential. The decrypted field data is ordinary Python
        bytes and cannot be wiped — base.py says so about `str`, and it is just
        as true here. The mitigation is that the helper lives for one
        operation (I14)."""
        if self.credential is not None:
            self.credential.zero()
        self.header = []
        self.records = []

    def __repr__(self):
        return "<Pws3Db v%s header=%d records=%d>" % (
            self.version_string(), len(self.header), len(self.records))


# ===========================================================================
# Parse
# ===========================================================================

def _split_prefix(data):
    """Structural checks on the envelope. No key material involved.

    Refuse, never salvage: a file with no EOF block is truncated, and
    docs/UPSTREAM-REVIEW.md §3.3 is explicit that "recover what you can" is the
    wrong answer for a format whose whole point is detecting truncation.
    """
    if len(data) < MIN_FILE_LEN:
        raise Invalid("file is too small to be a Password Safe v3 database")
    if not constant_time_eq(data[0:4], TAG):
        raise Invalid("file does not carry the PWS3 tag")
    body_len = len(data) - PREFIX_LEN - TAIL_LEN
    if body_len % BLOCK:
        raise Invalid("PWS3 ciphertext is not a whole number of blocks")
    eof_at = len(data) - TAIL_LEN
    if data[eof_at:eof_at + len(EOF_BLOCK)] != EOF_BLOCK:
        # §2.10: the EOF marker is unencrypted and is what says where the HMAC
        # starts. Its absence means truncated or tampered, full stop.
        raise Invalid("PWS3 end-of-file block is missing or misplaced")
    body = data[PREFIX_LEN:eof_at]
    if EOF_BLOCK in body:
        raise Invalid("PWS3 end-of-file block appears inside the ciphertext")
    return {
        "salt": bytes(data[4:36]),
        "iterations": int.from_bytes(data[36:40], "little"),
        "hpprime": bytes(data[40:72]),
        "b1b2": bytes(data[72:104]),
        "b3b4": bytes(data[104:136]),
        "iv": bytes(data[136:152]),
        "body": bytes(body),
        "mac": bytes(data[-MAC_LEN:]),
    }


#: The one detail returned for BOTH a wrong passphrase and a failed MAC. They
#: MUST NOT be distinguishable to the client (I6); the audit log carries the
#: difference. Sharing the literal is how that stays true after an edit.
_BAD_CREDENTIAL = "the passphrase did not open this safe"


def _decode(env, key, *, own_output=False):
    """Decrypt, parse, **verify the MAC**, and only then return a database.

    Order matters and is the whole of I6 for this format: nothing below returns
    a `Pws3Db` until `compare_digest` has said yes. Everything between the
    decrypt and that comparison is treated as attacker-shaped input, which is
    why every length is bounds-checked and every count is capped.

    `own_output=True` says the bytes were produced by `serialize()` in THIS
    process, from a database this process has already authenticated, under a
    credential it already holds — the pre-write round trip and nothing else.
    It does one thing: a STRUCTURAL failure keeps its real detail instead of
    being flattened into `BadCredential`.

    WHY THAT DOES NOT REOPEN I6's ORACLE, and this is the reasoning the fix
    turns on. The oracle I6 closes belongs to a caller who supplies BOTH a file
    and a passphrase guess: flattening is what denies them the ability to tell
    "your guess was wrong" from "your file is malformed", and so denies them a
    per-guess signal. This path takes neither — the caller supplies no file (we
    just built it) and no guess (the credential is the one that already opened
    the live safe). There is nothing for a distinction to be a distinction
    ABOUT. A hostile file and a wrong passphrase are still indistinguishable to
    a client, because `unlock()`, `parse_bytes()` and `read_file()` never pass
    this flag and cannot be made to from a request.

    What it buys is I41's other half. With the flag off, a file WE broke came
    back to the operator as "the passphrase did not open this safe" — the one
    answer that sends them to re-type a passphrase that was never wrong, and on
    into I39/I40's lockout, on a safe that is broken rather than locked. The
    difference between that file and a hostile one is that this file is one we
    wrote and can verify before we hand it over.
    """
    if not constant_time_eq(key.hash(), env["hpprime"]):
        # §2.5. Cheap, and the format's own design — but it is still only a
        # passphrase check, never an integrity check.
        if own_output:
            raise Invalid("the stretched-key check failed on a file we just "
                          "built; the write credential does not match it")
        raise BadCredential(_BAD_CREDENTIAL)

    record_key, mac_key = key.unwrap(env["b1b2"], env["b3b4"])
    plain = None
    try:
        plain = _cbc_decrypt(record_key.bytes, env["iv"], env["body"])
        try:
            return _decode_plaintext(plain, mac_key, env, key,
                                     own_output=own_output)
        except Invalid as exc:
            if own_output:
                raise
            # EVERY structural failure from here down is a failure on plaintext
            # that has NOT been authenticated yet, so telling the client which
            # one it was would distinguish "tampered file" from "wrong
            # passphrase" — the oracle the flattened taxonomy exists to close
            # (I6, docs/CONTRACT.md). The structural checks that CAN safely say
            # more are the ones in `_split_prefix`, which run before any key is
            # used and report only what anyone holding the file already knows.
            #
            # The operator still gets the real reason, on stderr, where the
            # contract puts diagnostics and where only the helper's own log can
            # see it. `redact()` because a length or a count is safe to print
            # and a field's contents never are (I15).
            sys.stderr.write("secrets-admin: psafe3: %s\n"
                             % redact(exc.detail))
            raise BadCredential(_BAD_CREDENTIAL) from None
    finally:
        record_key.zero()
        mac_key.zero()
        if plain is not None:
            # The decrypted database in a bytearray we own. Wipe it: the parsed
            # Field objects hold their own immutable copies, so this costs
            # nothing and removes one whole copy from the address space.
            _wipe(plain)


def _decode_plaintext(plain, mac_key, env, key, *, own_output=False):
    """Field walk and MAC verification over decrypted, still-UNTRUSTED bytes.

    Split out from `_decode` so that the one caller can convert every failure
    in here into the flat `BadCredential`, and so that "everything in this
    function is attacker-shaped" is a property of a whole function rather than
    a comment in the middle of one.

    `own_output` is `_decode`'s; see the reasoning there. It reaches this
    function for one line — the MAC gate — because on our own output a MAC
    mismatch is a bug in this program's writer and calling it a bad passphrase
    would be the same misattribution by a different route.
    """
    fields = _parse_field_stream(plain)
    mac = hmac.new(bytes(mac_key.bytes), digestmod=hashlib.sha256)

    # Header: fields up to the first END (§2.9.1).
    idx = 0
    header = []
    while True:
        if idx >= len(fields):
            raise Invalid("PWS3 header is not terminated")
        f = fields[idx]
        idx += 1
        # §2.11 / PWSfileV3::ReadCBC — the MAC takes the field DATA and nothing
        # else, in file order, header fields included, END fields included
        # (they are zero length, so they contribute nothing but the call).
        mac.update(f.data)
        if f.type == FT_END:
            break
        header.append(f)
        if len(header) > MAX_HEADER_FIELDS:
            raise Invalid("PWS3 header has an implausible number of fields")

    # Records: each terminated by END (§2.9.2).
    records = []
    current = []
    while idx < len(fields):
        f = fields[idx]
        idx += 1
        mac.update(f.data)
        if f.type == FT_END:
            records.append(current)
            current = []
            if len(records) > Limits.MAX_ENTRIES:
                raise Invalid("PWS3 file exceeds the %d record limit"
                              % Limits.MAX_ENTRIES)
        else:
            current.append(f)
            if len(current) > MAX_FIELDS_PER_RECORD:
                raise Invalid("a PWS3 record has too many fields")
    if current:
        raise Invalid("the last PWS3 record is not terminated")

    # THE GATE. Nothing above this line has been authenticated; nothing below
    # it is returned until this passes, and a failure here carries the SAME
    # detail as a wrong passphrase (I6).
    if not constant_time_eq(mac.digest(), env["mac"]):
        if own_output:
            raise Invalid("the HMAC of a file we just built does not verify")
        raise BadCredential(_BAD_CREDENTIAL)

    db = Pws3Db(header, records, credential=key)
    if not any(f.type == HDR_VERSION for f in header):
        # Mandatory per §2.9.1. Carry on rather than refusing an otherwise
        # authentic file, and say so.
        db.warnings.append("this database has no format-version header field")
    if key.iterations < Limits.PWS3_WRITE_MIN_ITER:
        db.warnings.append(
            "this database uses %d key-stretching iterations; the current "
            "format floor is %d and a save will raise it"
            % (key.iterations, Limits.PWS3_WRITE_MIN_ITER))
    return db


def parse_bytes(data, password):
    """Open a `.psafe3` image. `password` may be a `Secret`, bytes or str.

    Module-level and file-free ON PURPOSE: it is the seam the Go cross-check
    oracle and the fuzz corpus drive, and it has no opinion about where the
    bytes came from. The path guards (I4, I5) live in `read_file` and in
    `Psafe3Backend`, which are the only things `secrets-admin` calls.
    """
    env = _split_prefix(data)
    # Clamp BEFORE stretching. This is the whole of I7 for this format: the
    # iteration count is a number chosen by whoever wrote the file.
    Limits.check_pws3_iter(env["iterations"])
    owned = None
    try:
        if not isinstance(password, Secret):
            owned = Secret(password)
            password = owned
        key = StretchedKey.derive(password, env["salt"], env["iterations"])
    finally:
        if owned is not None:
            owned.zero()
    try:
        return _decode(env, key)
    except Exception:
        key.zero()
        raise


# ===========================================================================
# Serialise
# ===========================================================================

def _describe_field(where, field):
    """"header field last-save-time" / "entry field notes". A NAME, never a
    value — this string goes to the operator and I15 is not negotiable."""
    table = HEADER_FIELDS if where == "header" else RECORD_FIELDS
    name = table.get(field.type, ("type 0x%02x" % field.type,))[0]
    return "%s field %s" % (where, name)


def _diff_db(expect, probe):
    """What a read -> write -> read cycle LOST. A list of names; [] is clean.

    This is I22's comparison, and it is now one function because it has two
    callers that must not be allowed to disagree: `_ensure_lossless`, the early
    warning that runs before the first save, and `Psafe3Backend.read_back`'s
    partner `diff_read_back`, which runs on the ACTUAL bytes of EVERY save.
    Two copies of "did we lose anything" is how one of them ends up weaker than
    the other, which is the shape of I41 one level down.

    A `Pws3Db` IS its ordered list of (type, bytes) fields, so the comparison is
    exact: same header length, same fields in the same order, same record count,
    same field count per record, same bytes. There is no tolerance and no
    normalisation here — anything that legitimately changes on a save is
    resolved by `_final_header` BEFORE serialisation, so that by the time these
    two objects exist they are supposed to be identical.
    """
    lost = []
    if len(probe.header) != len(expect.header):
        lost.append("the header structure (%d fields written, %d read back)"
                    % (len(expect.header), len(probe.header)))
    for before, after in zip(expect.header, probe.header):
        if before != after:
            lost.append(_describe_field("header", before))
    if len(probe.records) != len(expect.records):
        lost.append("the record count (%d written, %d read back)"
                    % (len(expect.records), len(probe.records)))
    for rec_before, rec_after in zip(expect.records, probe.records):
        if len(rec_before) != len(rec_after):
            lost.append("a record's field count (%d written, %d read back)"
                        % (len(rec_before), len(rec_after)))
        for before, after in zip(rec_before, rec_after):
            if before != after:
                lost.append(_describe_field("entry", before))
    return lost


def _final_header(header, stamp):
    """The header `serialize` will actually write, given the one it is handed.

    Split out of `serialize` so a caller can know EXACTLY what it is about to
    write without writing it. That matters for the pre-write round trip (I41):
    the check compares the file it built against the database it meant to
    build, and two of the three things that happen here — the "last saved"
    stamp and the Version field's move to the front (§2.9.1) — are deliberate
    changes that a naive comparison against `db.header` would report as data
    loss. Calling this ONCE and serialising the result makes the expectation
    and the file the same object's worth of decisions, so the diff has nothing
    to be confused by. Calling it twice would not: `_stamped_header` reads the
    clock, and two calls a second apart do not agree.

    Everything else keeps its order exactly, because preserving order is how
    unknown fields come back out where they went in (I22, §4.1).
    """
    header = list(header)
    if stamp:
        header = _stamped_header(header)
    vidx = next((i for i, f in enumerate(header) if f.type == HDR_VERSION), -1)
    if vidx < 0:
        header.insert(0, Field(HDR_VERSION,
                               DEFAULT_NEW_VERSION.to_bytes(2, "little")))
    elif vidx > 0:
        header.insert(0, header.pop(vidx))
    return header


def serialize(db, credential=None, *, stamp=True):
    """Build a complete `.psafe3` image. Returns bytes.

    `credential` is a `StretchedKey`; it defaults to the one the database was
    opened with. K, L and the IV are drawn fresh from `secrets.token_bytes` on
    every call — §2.7's "K and L must NOT be related" is a rule for the writer,
    and re-using a record key across saves would leak which blocks changed.

    The SALT and ITER are the credential's, which means a save re-uses the
    salt the file was created with. That is what §2.2 describes ("generated at
    file creation time") and it is what lets an unlocked backend hold `P'`
    instead of the passphrase — see `StretchedKey`. A file whose ITER is below
    the current floor gets a NEW salt and a re-stretch at unlock time instead,
    so nothing this module writes is ever weaker than the reference
    implementation would write.

    `stamp=False` suppresses the "last saved" header updates; the losslessness
    guard and the round-trip tests need a byte-for-byte comparable structure.
    """
    if credential is None:
        credential = db.credential
    if credential is None:
        raise Invalid("no stretched key is available to write with")
    # The floor applies to what we WRITE, always (§2.4, I7).
    Limits.check_pws3_iter(credential.iterations, for_write=True)

    header = _final_header(db.header, stamp)

    key = Secret(_sysrandom.token_bytes(32))
    mac_key = Secret(_sysrandom.token_bytes(32))
    try:
        iv = _sysrandom.token_bytes(BLOCK)
        mac = hmac.new(bytes(mac_key.bytes), digestmod=hashlib.sha256)

        plain = bytearray()
        for f in header:
            if f.type == FT_END:
                continue          # structural; emitted once, below
            _emit_field(f, plain, mac)
        _emit_field(Field(FT_END, b""), plain, mac)
        for record in db.records:
            for f in record:
                if f.type == FT_END:
                    continue
                _emit_field(f, plain, mac)
            _emit_field(Field(FT_END, b""), plain, mac)

        b1b2, b3b4 = credential.wrap(key.bytes, mac_key.bytes)
        body = _cbc_encrypt(key.bytes, iv, plain)

        out = bytearray()
        out += TAG
        out += credential.salt
        out += credential.iterations.to_bytes(4, "little")
        out += credential.hash()
        out += b1b2
        out += b3b4
        out += iv
        out += body
        out += EOF_BLOCK
        out += mac.digest()

        if len(out) > Limits.MAX_SAFE_BYTES:
            raise Invalid("the serialised safe exceeds %d bytes"
                          % Limits.MAX_SAFE_BYTES)
        result = bytes(out)
        _wipe(plain)
        return result
    finally:
        key.zero()
        mac_key.zero()


def _stamped_header(header):
    """Update the "last saved" header fields — and only those.

    `0x04` (timestamp) and `0x06` (what performed the save) are set
    unconditionally: every real implementation writes them and an operator
    looking at a database wants to know that this program touched it.

    `0x07`/`0x08` (user, host) are updated ONLY if the file already carried
    them. Adding them would write the operator's login name and this machine's
    hostname into a database that had deliberately never recorded either —
    metadata disclosure by helpfulness, and not our call to make.
    """
    out = []
    seen_what = False
    for f in header:
        if f.type == HDR_LAST_SAVE_TIME:
            out.append(Field(f.type, _time_field()))
        elif f.type == HDR_LAST_SAVE_WHAT:
            seen_what = True
            out.append(Field(f.type,
                             ("cockpit-secrets %s" % VERSION).encode("utf-8")))
        elif f.type == HDR_LAST_SAVE_USER:
            out.append(Field(f.type, _local_user().encode("utf-8")))
        elif f.type == HDR_LAST_SAVE_HOST:
            out.append(Field(f.type, _local_host().encode("utf-8")))
        else:
            out.append(f)
    if not any(f.type == HDR_LAST_SAVE_TIME for f in out):
        out.append(Field(HDR_LAST_SAVE_TIME, _time_field()))
    if not seen_what:
        out.append(Field(HDR_LAST_SAVE_WHAT,
                         ("cockpit-secrets %s" % VERSION).encode("utf-8")))
    return out


def _local_user():
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return "unknown"


def _local_host():
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


# ===========================================================================
# File-level convenience — the seam the cross-check oracle drives
# ===========================================================================

def read_file(path, passphrase):
    """Open a `.psafe3` file. Returns a `Pws3Db` with its credential attached.

    Uses `open_safe_fd`, so the I4/I5 guards apply: absolute path, `O_NOFOLLOW`,
    `fstat` on the fd rather than a second `stat` of the path, owner and mode
    checked, size capped. This is a library entry point for tests and for the
    Go cross-check oracle — `secrets-admin` never calls it, because a verb that
    takes a path is the hazard I4 exists to describe.
    """
    with open_safe_fd(path) as sf:
        data = sf.read_all()
    return parse_bytes(data, passphrase)


def write_file(path, passphrase, db, *, iterations=None, backup_dir=None,
               keep=None, expect_fingerprint=None):
    """Write `db` to `path` durably. Returns the `atomic_replace` report.

    Derives a FRESH credential — new salt, iterations floored at the format's
    current minimum — from `passphrase`, so this is also the re-key path. The
    lock file (`<name>.plk`) is held for the write, and the write itself is
    backup -> temp -> fsync -> replace -> fsync(dir) (I12, I13).
    """
    want = iterations
    if want is None:
        want = db.credential.iterations if db.credential else \
            Limits.PWS3_WRITE_MIN_ITER
    want = max(int(want), Limits.PWS3_WRITE_MIN_ITER)

    owned = None
    credential = None
    try:
        if not isinstance(passphrase, Secret):
            owned = Secret(passphrase)
            passphrase = owned
        credential = StretchedKey.derive(
            passphrase, _sysrandom.token_bytes(SALT_LEN), want, for_write=True)
        header = _final_header(db.header, stamp=True)
        expect = Pws3Db(header, db.records, credential=credential)
        data = serialize(expect, stamp=False)
        # The same pre-write reader check `Psafe3Backend.save` runs (I24, I41),
        # here too because this function also puts bytes on a disk somebody
        # will later have to open. It is `Backend.verify_own_output`'s body
        # without the object: read the bytes back through the reader a later
        # unlock uses, compare against what we meant to write, and refuse
        # rather than write a file we cannot read. `own_output=True` for
        # `_decode`'s documented reason — these bytes are ours, so a structural
        # failure is ours and must not come back as a bad passphrase.
        try:
            echo = _decode(_split_prefix(data), credential, own_output=True)
        except SecretsError as exc:
            raise Conflict("the database we built cannot be read back, so it "
                           "was not written: %s" % exc.detail)
        lost = _diff_db(expect, echo)
        if lost:
            raise Conflict("this database cannot be written without losing "
                           "data: %s" % "; ".join(lost[:5]))
    finally:
        if owned is not None:
            owned.zero()

    try:
        with LockFile(path, fmt="psafe3"):
            return atomic_replace(path, data, backup_dir=backup_dir, keep=keep,
                                  expect_fingerprint=expect_fingerprint)
    finally:
        credential.zero()


# ===========================================================================
# TOTP  (§3.3 notes [23] and [29])
# ===========================================================================

def _iso_to_unix(value):
    """ISO-8601 (with or without a trailing Z) -> a 32-bit time_t.

    The published vocabulary carries timestamps as ISO-8601 UTC and §3.1.3
    stores them as a 4-byte little-endian time_t, so the range is the
    STORAGE's: a date outside it cannot be written and is refused here rather
    than silently wrapping into 1970 or 2038.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        secs = value
    else:
        try:
            when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise Invalid("expires is not a valid ISO-8601 timestamp")
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        secs = int(when.astimezone(timezone.utc).timestamp())
    if not 0 <= secs <= 0xFFFFFFFF:
        raise Invalid("that date cannot be stored in this format's 32-bit "
                      "time field")
    return secs


def _parse_otpauth(uri):
    """`otpauth://totp/...?secret=…` -> (seed bytes, digits, period).

    The published `entry`/`changes` vocabulary spells the OTP seed `totp_uri`
    and carries it as an `otpauth://` URI, because that is what a QR code
    decodes to and what every authenticator app emits. This format stores the
    same thing as four typed fields — Two Factor Key (0x1b) holds the RAW
    seed, not base32 — so the URI is taken apart here rather than stored
    verbatim. Storing the URI text in 0x1b would produce a field that reads
    back through `reveal` as base32-of-the-URI and generates codes that are
    always wrong, which is exactly the failure a "malformed URI is stored
    happily" note in the schema warns about.

    Refusals, all of them because the alternative is a silently wrong code:

      * `hotp://` — counter-based, and this format has no counter field.
      * an `algorithm` other than SHA1 — §3.3 note [29] defines only 0x00
        (SHA1) in TOTP Config, so there is nowhere to record another.
      * a secret that is not valid base32, or is empty.

    `urllib.parse` opens nothing; it is a string parser, which is why
    validate.sh's network ban names the network-capable modules specifically.
    """
    if not isinstance(uri, str) or not uri.strip():
        # The caller filters the empty case (it means "remove the seed"), so
        # reaching here with nothing is a caller bug, not an operator one.
        raise Invalid("a TOTP secret must be an otpauth:// URI")
    text = uri.strip()
    parts = urllib.parse.urlsplit(text)
    if parts.scheme.lower() != "otpauth":
        raise Invalid("a TOTP secret must be an otpauth:// URI")
    if (parts.netloc or "").lower() != "totp":
        raise Unsupported("Password Safe v3 stores time-based one-time "
                          "passwords only; there is no counter field for "
                          "otpauth://hotp")
    query = urllib.parse.parse_qs(parts.query)
    secret = (query.get("secret") or [""])[0].strip().replace(" ", "")
    if not secret:
        raise Invalid("the otpauth URI carries no secret")
    algorithm = (query.get("algorithm") or ["SHA1"])[0].strip().upper()
    if algorithm not in ("SHA1", ""):
        raise Unsupported("Password Safe v3's TOTP Config defines only SHA-1 "
                          "(note [29]); %s cannot be recorded" % algorithm)
    try:
        # base32 with the padding restored: authenticator apps almost always
        # strip it, and b32decode refuses an unpadded string outright.
        pad = "=" * (-len(secret) % 8)
        seed = base64.b32decode(secret.upper() + pad, casefold=True)
    except (binascii.Error, ValueError):
        raise Invalid("the otpauth URI's secret is not valid base32")
    if not seed:
        raise Invalid("the otpauth URI's secret is empty")

    def _int(name, default, low, high):
        raw = (query.get(name) or [""])[0].strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise Invalid("the otpauth URI's %s is not a number" % name)
        if not low <= value <= high:
            raise Invalid("the otpauth URI's %s is out of range" % name)
        return value

    # Both are single unsigned bytes in this format (0x22, 0x23), so the
    # ranges are the storage's and not a policy.
    digits = _int("digits", 6, 1, 10)
    period = _int("period", 30, 1, 255)
    # No T0 is returned because the otpauth URI has no parameter for one: RFC
    # 6238's T0 is fixed at the Unix epoch there. TOTP Start Time (0x24) is a
    # PWS3 extension, and the caller CLEARS it rather than leaving a stale one
    # behind — a leftover T0 from a previous seed shifts every code.
    return seed, digits, period


def _totp_code(seed, digits, step, t0, now=None):
    """RFC 6238, computed here rather than through `pyotp`.

    `python3-pyotp` is installed and would work, but its API takes the shared
    secret as a **base32 `str`** — which means base32-encoding the seed into an
    immutable, un-wipeable Python string on every request, for a value that is
    exactly as sensitive as the password (I14). Twelve lines of `hmac` avoid
    that, and they also model what PWS3 actually stores: an arbitrary time step,
    an arbitrary digit count, and a T0 the format writes as a 5-byte time_t.
    """
    now = int(time.time() if now is None else now)
    if step <= 0:
        raise Invalid("TOTP time step is not positive")
    counter = (now - t0) // step
    if counter < 0:
        raise Invalid("TOTP start time is in the future")
    mac = hmac.new(bytes(seed), counter.to_bytes(8, "big"), hashlib.sha1)
    digest = mac.digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    code = str(binary % (10 ** digits)).rjust(digits, "0")
    remaining = step - ((now - t0) % step)
    return code, remaining


# ===========================================================================
# The backend
# ===========================================================================

@register_backend("psafe3")
class Psafe3Backend(Backend):
    """`Backend` over one `.psafe3` file. One file, one process, one operation.

    Two things about this format shape everything below:

      - **It authenticates the whole file with one MAC at the end**, so there is
        no partial open and no streaming. `unlock()` reads, decrypts, verifies
        and parses in one go, or it fails; there is no state in between for a
        bug to leak from.
      - **It has no recycle bin, no entry history beyond the password-history
        field, and no per-entry ACL.** Where the ABC's vocabulary assumes a
        KDBX feature, this backend says so rather than emulating it — `rm()`
        always reports `recycled: false`, and that is the truth, not a stub.
    """

    def __init__(self, entry):
        super().__init__(entry)
        self._db = None
        self._lossless_checked = False
        self._provider = None

    # -- read side ---------------------------------------------------------

    def probe(self):
        """Header metadata only. No passphrase, nothing key-derived (§2.1-2.4).

        Everything returned here is readable by anyone who already holds the
        file, which is the test for whether a probe says too much. Note what is
        NOT here: the format sub-version (0x03xx) lives in the ENCRYPTED header
        (§3.2 field 0x00), so an unlocked probe honestly reports "3" rather than
        guessing.
        """
        with open_safe_fd(self.path) as sf:
            head = os.pread(sf.fd, PREFIX_LEN, 0)
            size = sf.st.st_size
            if size < MIN_FILE_LEN or len(head) < PREFIX_LEN:
                raise Invalid("file is too small to be a "
                              "Password Safe v3 database")
            if not constant_time_eq(head[0:4], TAG):
                raise Invalid("file does not carry the PWS3 tag")
            tail = os.pread(sf.fd, TAIL_LEN, size - TAIL_LEN)
            iterations = int.from_bytes(head[36:40], "little")

        warnings = list(self.warnings)
        ok_eof = tail[:len(EOF_BLOCK)] == EOF_BLOCK
        if not ok_eof:
            raise Invalid("PWS3 end-of-file block is missing or misplaced")
        if (size - PREFIX_LEN - TAIL_LEN) % BLOCK:
            raise Invalid("PWS3 ciphertext is not a whole number of blocks")
        if iterations < Limits.PWS3_MIN_ITER or \
                iterations > Limits.PWS3_MAX_ITER:
            # Reported, not raised: an operator is better served by "this file
            # is out of range" on the probe screen than by a bare error.
            warnings.append(
                "this file declares %d key-stretching iterations, outside the "
                "accepted range [%d, %d]; it cannot be opened"
                % (iterations, Limits.PWS3_MIN_ITER, Limits.PWS3_MAX_ITER))
        elif iterations < Limits.PWS3_WRITE_MIN_ITER:
            warnings.append(
                "this database uses %d key-stretching iterations; saving will "
                "raise it to the format floor of %d"
                % (iterations, Limits.PWS3_WRITE_MIN_ITER))
        warnings.append("Twofish provider: %s" % twofish_provider())

        return {
            "format": "psafe3",
            "version": "3",
            "kdf": "pws3-sha256",
            "iterations": iterations,
            "needs_password": True,
            # §2 has no key-file or hardware-key concept at all. Saying "false"
            # here is a fact about the format, not a policy of ours.
            "needs_keyfile": False,
            "writable": not self.readonly,
            "warnings": warnings,
        }

    @staticmethod
    def verify_structure(data):
        """See `Backend.verify_structure`. `_split_prefix` already IS this.

        PWS3 is the easier of the two formats to prove complete without a key:
        §2.10 puts an UNENCRYPTED `PWS3-EOFPWS3-EOF` block immediately before
        the 32-byte HMAC, so a truncated file is one whose last 48 bytes do not
        end that way. `_split_prefix` checks that, the tag, the minimum length
        and the cipher-block alignment, and it needs no credential to do any of
        it — which is exactly the contract here.
        """
        _split_prefix(data)

    def unlock(self, password, keyfile=None, session=None, *,
               yubikey_response=None):
        """Derive, verify, parse — in that order, and nothing escapes early.

        `keyfile` and `yubikey_response` are both REFUSED rather than ignored,
        for the same reason: accepting a second factor and then not using it
        leaves an operator believing they have protection they do not have.

        On the hardware-token refusal specifically, because the reason is not
        "Password Safe has no YubiKey support" — it does. formatV3.txt §3.2
        field 0x12 ("Yubico", 20 bytes, note [18]) stores *the YubiKey's secret
        key*, "saved so that it can be used to initialize additional YubiKeys".
        That is a provisioning aid, not a challenge-response construction: the
        format does not specify how a token's answer combines with the
        passphrase to open the file, because in Password Safe that combination
        is application behaviour rather than file format. Guessing it would
        produce a stretched key no real Password Safe agrees with, and the
        symptom would be `bad-credential` on a correct passphrase.
        """
        if keyfile is not None and len(keyfile) > 0:
            raise Unsupported("Password Safe v3 has no key-file support")
        if yubikey_response is not None:
            raise Unsupported(
                "Password Safe v3 does not specify how a hardware token's "
                "response combines with the passphrase; its 0x12 header field "
                "stores a YubiKey secret for provisioning, not a "
                "challenge-response key derivation")
        if password is None:
            raise Invalid("this format requires a passphrase")

        with open_safe_fd(self.path) as sf:
            data = sf.read_all()
            # Fingerprint from THIS fd, before anything else touches the path
            # (I13). Re-stat'ing the path later would race a desktop client.
            fingerprint = sf.fingerprint()

        env = _split_prefix(data)
        Limits.check_pws3_iter(env["iterations"])          # BEFORE the KDF (I7)
        key = StretchedKey.derive(password, env["salt"], env["iterations"])
        db = None
        try:
            db = _decode(env, key)
        except Exception:
            key.zero()
            raise

        # Refuse a repeated record field type HERE as well as in `_one`, so the
        # operator learns at open time rather than at the first `reveal` of the
        # one field that happens to be doubled. `_one` is the enforcement point
        # no path can be added around; this is the one that gives a useful
        # answer. Only types the format defines are scanned: an unknown
        # repeated type is a field we do not read, and refusing it would invent
        # a rule about data we deliberately preserve unchanged (I22).
        try:
            for record in db.records:
                seen = set()
                for f in record:
                    if f.type in RECORD_FIELDS:
                        if f.type in seen:
                            raise Invalid(
                                "a record in this database carries more than "
                                "one 0x%02x field; refusing to guess which one "
                                "is meant" % f.type)
                        seen.add(f.type)
        except Exception:
            key.zero()
            raise

        # A legacy file below the write floor cannot be saved under its own
        # parameters, and we deliberately do not keep the passphrase to
        # re-stretch later. So do it now, while the caller still owns it: a
        # fresh salt at the format's current minimum becomes the WRITE
        # credential, and the read credential is discarded.
        if key.iterations < Limits.PWS3_WRITE_MIN_ITER and not self.readonly:
            upgraded = StretchedKey.derive(
                password, _sysrandom.token_bytes(SALT_LEN),
                Limits.PWS3_WRITE_MIN_ITER, for_write=True)
            key.zero()
            db.credential = upgraded

        self._db = db
        self.fingerprint = fingerprint
        self.warnings = list(self.warnings) + db.warnings
        self._provider = twofish_provider()
        self.handle = _sysrandom.token_hex(16)      # 128 bits, per CONTRACT.md
        self.unlocked = True

        return {
            "handle": self.handle,
            # 0 means "no timed expiry": in the default configuration this
            # handle dies with the helper process, which is what makes
            # "prompt every time" true by construction rather than by policy.
            "expires_in": int(
                (self.entry.get("agent") or {}).get("idle_seconds", 0)
                if (self.entry.get("agent") or {}).get("enabled") else 0),
            "entries_total": len(db.records),
            "groups_total": len(self._group_paths()),
            "warnings": list(self.warnings),
        }

    # -- groups ------------------------------------------------------------

    def _group_paths(self):
        """Every group path in the database, including implied ancestors.

        PWS3 has no group objects: a group exists because a record names it, or
        because the header carries an Empty Groups field (§3.2 field 0x11). So
        the tree is derived, and `Limits.MAX_GROUPS` / `MAX_GROUP_DEPTH` are
        enforced here because a file can name 10 000-deep paths and a recursive
        walker dies on them.
        """
        paths = set()
        sources = []
        for record in self._db.records:
            g = Pws3Db.field_get(record, REC_GROUP)
            if g:
                sources.append(g.decode("utf-8", "replace"))
        sources.extend(self._db.empty_groups())
        for path in sources:
            if not path:
                continue
            parts = _split_group(path)
            if len(parts) > Limits.MAX_GROUP_DEPTH:
                raise Invalid("group nesting exceeds %d levels"
                              % Limits.MAX_GROUP_DEPTH)
            for i in range(1, len(parts) + 1):
                paths.add(_join_group(parts[:i]))
                if len(paths) > Limits.MAX_GROUPS:
                    raise Invalid("this database declares more than %d groups"
                                  % Limits.MAX_GROUPS)
        return sorted(paths)

    def tree(self):
        """`{"groups": [...]}`. The group id IS the group path.

        PWS3 gives groups no UUID — a group is a string on a record — so
        inventing an opaque id would mean carrying a lookup table that has to
        stay consistent across a save, for no gain. The path is the identity
        the format itself uses, and `move()`/`group_mv()` take the same string.
        """
        self.require_unlocked()
        counts = {}
        for record in self._db.records:
            g = Pws3Db.field_get(record, REC_GROUP)
            name = g.decode("utf-8", "replace") if g else ""
            counts[name] = counts.get(name, 0) + 1
        groups = []
        for path in self._group_paths():
            parts = _split_group(path)
            groups.append({
                "uuid": path,
                "name": parts[-1],
                "parent": _join_group(parts[:-1]) if len(parts) > 1 else None,
                # Direct members only: a folder view that counted descendants
                # would disagree with the list the user then sees.
                "count": counts.get(path, 0),
            })
        return {"groups": groups}

    # -- entries -----------------------------------------------------------

    def _entry_meta(self, index):
        record = self._db.records[index]
        get = Pws3Db.field_get
        title = get(record, REC_TITLE) or b""
        username = get(record, REC_USERNAME) or b""
        url = get(record, REC_URL) or b""
        modified = get(record, REC_LAST_MOD_TIME) or get(record,
                                                         REC_CREATE_TIME)
        return {
            "uuid": self._db.record_id(index),
            "title": title.decode("utf-8", "replace"),
            "username": username.decode("utf-8", "replace"),
            "url": url.decode("utf-8", "replace"),
            # Password Safe v3 has no tag field (§3.3 lists none). An empty
            # list is the honest answer; synthesising tags from the group path
            # would invent data the file does not contain.
            "tags": [],
            "has_totp": get(record, REC_TWO_FACTOR_KEY) is not None,
            "attachments": 1 if get(record, REC_ATT_MEDIATYPE) else 0,
            "modified": _render_time(modified) if modified else "",
        }

    def entries(self, group=None, query=None, offset=0, limit=100):
        """Metadata only — invariant 1 of the `Backend` ABC.

        Note what this cannot return even by accident: it builds its result from
        exactly six fields, none of which is in `SECRET_FIELDS`. There is no
        "all fields" path here for a future edit to widen.
        """
        self.require_unlocked()
        offset = max(0, int(offset or 0))
        # Clamped, because an unbounded limit ships the whole database to the
        # browser in one response.
        limit = max(1, min(int(limit or 100), 1000))
        needle = (query or "").strip().lower()

        matched = []
        for i in range(len(self._db.records)):
            meta = self._entry_meta(i)
            if group is not None:
                g = Pws3Db.field_get(self._db.records[i], REC_GROUP)
                name = g.decode("utf-8", "replace") if g else ""
                if name != group:
                    continue
            if needle:
                hay = " ".join([meta["title"], meta["username"],
                                meta["url"]]).lower()
                if needle not in hay:
                    continue
            matched.append(meta)

        return {"total": len(matched),
                "entries": matched[offset:offset + limit]}

    def reveal(self, uuid, field):
        """The only door. One named field of one named entry (I17, I15).

        Refuses a field name it does not know rather than guessing a type byte:
        a typo must not silently return the wrong secret.

        Two names from the helper's published vocabulary need translating here,
        because that vocabulary was written for a format with named fields:

          * `totp` is the seed. formatV3.txt calls it Two Factor Key (0x1b),
            and `reveal` renders it as unpadded base32 — the form a phone's
            authenticator app will accept.
          * `custom:<name>` cannot be answered at all. A PWS3 record is a list
            of TYPED fields and a type appears at most once, so there is no
            name-keyed custom string space to look a name up in. 0xdf
            ("custom-text-field") is one such type, not a dictionary. Refusing
            with `unsupported` and naming the reason is the honest answer; a
            not-found would read as "this entry happens not to have it".
        """
        self.require_unlocked()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        if isinstance(field, str) and field.startswith("custom:"):
            raise Unsupported(
                "Password Safe v3 records carry typed fields, not named "
                "custom fields; there is nothing to look this name up in")
        ftype = _RECORD_NAME_TO_TYPE.get(_REVEAL_ALIASES.get(field, field))
        if ftype is None:
            raise NotFound("no such field")
        raw = Pws3Db.field_get(record, ftype)
        if raw is None:
            raise NotFound("this entry has no such field")

        name, kind = RECORD_FIELDS[ftype]
        if name == "two-factor-key":
            # Base32 without padding: the form every authenticator app and QR
            # generator expects. The raw bytes are what the file stores.
            value = base64.b32encode(raw).decode("ascii").rstrip("=")
        elif name == "attachment-content":
            raise Unsupported("use attach-get for attachment content")
        else:
            value = _render(kind, raw)
        return {"field": name, "value": value,
                "expires_in": Limits.REVEAL_SECONDS}

    def totp(self, uuid):
        """A current code from the Two-Factor Key field (§3.3 notes 23, 29)."""
        self.require_unlocked()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        seed = Pws3Db.field_get(record, REC_TWO_FACTOR_KEY)
        if not seed:
            raise Unsupported("this entry has no two-factor key")

        cfg = Pws3Db.field_get(record, REC_TOTP_CONFIG)
        if cfg and (cfg[0] & 0x03) != 0:
            # Note [29]: bits 0-1 select the HMAC hash and only 0x00 (SHA1) is
            # defined. Refuse the reserved values instead of quietly computing
            # a SHA-1 code and calling it right.
            raise Unsupported("this entry uses a reserved TOTP hash algorithm")
        digits = Pws3Db.field_get(record, REC_TOTP_LENGTH)
        step = Pws3Db.field_get(record, REC_TOTP_TIME_STEP)
        start = Pws3Db.field_get(record, REC_TOTP_START_TIME)
        digits = digits[0] if digits else 6
        step = step[0] if step else 30
        t0 = int.from_bytes(start, "little") if start else 0
        if not 1 <= digits <= 10:
            raise Invalid("TOTP digit count is out of range")

        code, remaining = _totp_code(seed, digits, step, t0)
        return {"code": code, "seconds_remaining": int(remaining)}

    def attach_list(self, uuid):
        """Attachment NAMES and sizes for one record. No bytes (see the ABC).

        **Password Safe v3 does have attachments, and this backend writes
        them** — §3.3 note [30], fields 0x25..0x29, introduced in format
        version 0x030F (PasswordSafe V3.68). So this returns a real list rather
        than `Unsupported`; claiming the format cannot do it would be a lie
        about a file `attach_add` has already written.

        Two limits are the format's own and are reported by SHAPE rather than
        explained in a sentence nobody reads:

          * **At most one attachment per record.** A record is a list of typed
            fields and a type appears at most once in it, so there is nowhere
            to put a second Att Content. The list is therefore empty or one
            element long, always — a page that renders it as a list is right,
            and a page that assumes several is only ever wrong on this format.
          * **MediaType is what says an attachment exists** (note [30]:
            "if an entry contains an attachment the field Att MediaType must be
            present and non-empty"), so `_attachment_name` is the single place
            that decides, shared with `attach_get` and `attach_rm`. A record
            with an Att Content and no MediaType is not an attachment here, and
            listing one would name something `attach_get` then refuses.

        A database older than 0x030F simply has no such fields and lists
        nothing; it is `attach_add` that refuses with the version, because a
        version is a reason not to WRITE, not a reason to lie about what is
        already in the file.
        """
        self.require_unlocked()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        have = self._attachment_name(record)
        if not have:
            return []
        # "Absence of [Att Content] implies a zero-sized attachment" — note
        # [30]. A row with size 0 is therefore a legal answer and not a bug.
        content = Pws3Db.field_get(record, REC_ATT_CONTENT) or b""
        return [{"name": have, "size": len(content)}]

    def attach_get(self, uuid, name):
        """One attachment, base64, through the Cockpit channel (§3.3 note 30).

        Never lands on this host's disk — an attachment written to a
        server-side path is the exfiltration channel I21 is about.
        """
        self.require_unlocked()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        media = Pws3Db.field_get(record, REC_ATT_MEDIATYPE)
        if not media:
            raise NotFound("this entry has no attachment")
        # PWS3 carries at most one attachment per record, named by Att FileName
        # with Att Title as the fallback.
        fname = Pws3Db.field_get(record, REC_ATT_FILENAME) or b""
        title = Pws3Db.field_get(record, REC_ATT_TITLE) or b""
        have = fname.decode("utf-8", "replace") or title.decode("utf-8",
                                                                "replace")
        if name and name != have:
            raise NotFound("this entry has no such attachment")
        content = Pws3Db.field_get(record, REC_ATT_CONTENT) or b""
        if len(content) > Limits.MAX_ATTACHMENT_BYTES:
            raise Invalid("attachment exceeds %d bytes"
                          % Limits.MAX_ATTACHMENT_BYTES)
        return {"name": have, "size": len(content),
                "b64": base64.b64encode(content).decode("ascii")}

    @staticmethod
    def _attachment_name(record):
        """The name `attach_get`/`attach_rm` address, or `""` if there is none.

        §3.3 note [30]: "If an entry contains an attachment the field Att
        MediaType must be present and non-empty" — so MediaType, not FileName,
        is what decides whether an attachment exists at all. FileName is the
        preferred display name because it carries the extension the note says
        applications need; Att Title is the fallback.
        """
        if not Pws3Db.field_get(record, REC_ATT_MEDIATYPE):
            return ""
        fname = Pws3Db.field_get(record, REC_ATT_FILENAME) or b""
        title = Pws3Db.field_get(record, REC_ATT_TITLE) or b""
        return (fname.decode("utf-8", "replace")
                or title.decode("utf-8", "replace"))

    def history(self, uuid):
        """The entry's password history, metadata only. **Never a password.**

        This format has no per-entry version history in the KDBX sense: there
        is no archived copy of the whole record anywhere in a `.psafe3` file.
        What it has is field 0x0f, a list of *(time, password)* pairs — and
        that is what this reports, rather than an empty list. An empty list
        would say "this entry has no history", which is a different and untrue
        statement about a record that has ten old passwords in it.

        The consequence for the agreed shape, stated rather than papered over:
        `title`, `username` and `url` are **always `""`** and `notes_len` is
        always 0, because the format stores none of them per history item.
        Filling them in from the entry's CURRENT values would render a history
        row that looks like a snapshot and is not one — the UI would show a
        title that may have changed since, next to a password that definitely
        did. A caller that wants the entry's metadata already has it from
        `entries()`.

        Oldest first, which is both the agreed order and the format's own:
        "The list is sorted by T, with the oldest entry first."
        """
        self.require_unlocked()
        idx = self._require_record(uuid)
        raw = Pws3Db.field_get(self._db.records[idx], REC_PASSWORD_HISTORY)
        if raw is None:
            return []
        _enabled, _max_size, items = parse_password_history(
            raw.decode("utf-8", "replace"))
        return [{
            "index": i,
            "when": _render_time(_time_field(when)),
            "title": "",
            "username": "",
            "url": "",
            "has_password": bool(password),
            "notes_len": 0,
        } for i, (when, password) in enumerate(items)]

    # -- mutation: in memory only ------------------------------------------

    def _require_record(self, uuid):
        idx = self._db.find(uuid)
        if idx < 0:
            raise NotFound("no such entry")
        return idx

    @staticmethod
    def _require_unprotected(record):
        """§3.3 note [17]: a non-zero Protected field means the entry cannot be
        changed or deleted. Honour it — it is the file's own instruction, and
        overriding it silently is exactly the "amputate rather than refuse"
        behaviour I22 rejects."""
        flag = Pws3Db.field_get(record, REC_PROTECTED)
        if flag and any(flag):
            raise AccessDenied("this entry is marked protected in the safe")

    def add(self, group, entry):
        """Create an entry. §2.9.2 makes UUID, Title and Password mandatory."""
        self.require_writable()
        if len(self._db.records) >= Limits.MAX_ENTRIES:
            raise Invalid("this database already holds %d entries"
                          % Limits.MAX_ENTRIES)
        entry = dict(entry or {})
        if not entry.get("title"):
            raise Invalid("an entry needs a title")

        now = _time_field()
        record = [
            Field(REC_UUID, _uuid.uuid4().bytes),
            Field(REC_TITLE, str(entry.pop("title")).encode("utf-8")),
            Field(REC_PASSWORD, str(entry.pop("password", "")).encode("utf-8")),
            Field(REC_CREATE_TIME, now),
            Field(REC_PASSWORD_MOD_TIME, now),
            Field(REC_LAST_MOD_TIME, now),
        ]
        if group:
            record.insert(1, Field(REC_GROUP, str(group).encode("utf-8")))
        self._db.records.append(record)
        idx = len(self._db.records) - 1
        if entry:
            # Everything else goes through the same validated path as `edit`,
            # so there is one place that maps a name to a type byte.
            self._apply_changes(idx, entry)
        self._forget_empty_group(group)
        return {"uuid": self._db.record_id(idx)}

    def edit(self, uuid, changes):
        """Apply named changes. Returns the NAMES that changed, never values."""
        self.require_writable()
        idx = self._require_record(uuid)
        self._require_unprotected(self._db.records[idx])
        changed = self._apply_changes(idx, changes or {})
        return {"uuid": self._db.record_id(idx), "changed": changed}

    @staticmethod
    def _push_password_history(record, old_password, when=None):
        """Archive `old_password` into field 0x0f, obeying the record's policy.

        Password Safe records the history POLICY in the field itself — an
        on/off flag and a maximum size — so this honours the file rather than
        imposing anything:

          * **no 0x0f field at all** -> nothing is recorded and none is
            created. Note [12] calls the absent field the *preferred*
            representation of "keep no history"; manufacturing one would turn
            a deliberate setting off and start accumulating old passwords in
            cleartext in a database whose owner had switched that off.
          * **flag 0** -> history is disabled. The existing list is left
            exactly as it is, because note [12] says a disabled-but-populated
            list ("0aabb, where bb <= aa") is a legal state that the format
            expects to survive.
          * **flag 1** -> append, then trim from the FRONT to `max_size`,
            which is where the oldest entries live.

        An empty old password is not recorded: there is nothing to restore to
        and a zero-length entry in the list would occupy one of the at most 255
        slots the format allows.
        """
        raw = Pws3Db.field_get(record, REC_PASSWORD_HISTORY)
        if raw is None or not old_password:
            return False
        enabled, max_size, items = parse_password_history(
            raw.decode("utf-8", "replace"))
        if not enabled:
            return False
        items.append((int(when if when is not None else time.time()),
                      old_password))
        if max_size > 0:
            items = items[-max_size:]
        Pws3Db.field_set(
            record, REC_PASSWORD_HISTORY,
            build_password_history(enabled, max_size, items).encode("utf-8"))
        return True

    def _apply_changes(self, idx, changes):
        record = self._db.records[idx]
        # Captured BEFORE anything is written: once the new password is in the
        # field there is nothing left to archive, and a password change that
        # silently drops the previous value is the data loss the history field
        # exists to prevent. Real Password Safe does this on every change.
        old_password = None
        old_password_when = None
        if "password" in changes:
            raw = Pws3Db.field_get(record, REC_PASSWORD)
            old_password = raw.decode("utf-8", "replace") if raw else ""
            # The timestamp that belongs on the ARCHIVED password is when THAT
            # password was set — the current Password Modification Time — and
            # it has to be read now, because the block below overwrites it with
            # the time of this change.
            stamp = Pws3Db.field_get(record, REC_PASSWORD_MOD_TIME)
            if stamp and len(stamp) >= 4:
                old_password_when = int.from_bytes(stamp[:4], "little")
        changed = []
        for name, value in changes.items():
            if not value and name in ("custom", "tags"):
                # An EMPTY custom map or tag list asks for nothing, and a form
                # built from the schema sends both keys on every `add` whether
                # the operator filled them in or not. Refusing "write no tags"
                # would make every add from the page fail on this format for a
                # request that wanted nothing written.
                continue
            if name == "custom" or (isinstance(name, str)
                                    and name.startswith("custom:")):
                # The write half of `reveal`'s refusal, in the same words and
                # for the same reason. A PWS3 record is a list of TYPED fields
                # and a type appears at most once, so there is no name-keyed
                # string space to create a field IN. 0xdf ("custom-text-field")
                # is one such type, not a dictionary.
                #
                # `unsupported`, not `invalid`: the request is well formed and
                # would be honoured on the other backend, so the operator needs
                # to be told the FORMAT cannot do this — not that they typed
                # something wrong. The alternatives were both worse than
                # refusing: writing it into Notes invents a convention no other
                # Password Safe implementation reads, and squatting on 0xdf
                # gives every entry exactly one custom field whose name is not
                # stored anywhere.
                raise Unsupported(
                    "Password Safe v3 records carry typed fields, not named "
                    "custom fields; there is nowhere to create this one. Use "
                    "the notes field, or keep this entry in a KDBX safe")
            if name in ("totp_uri", "expires", "tags"):
                # The three remaining names in the helper's published
                # `entry`/`changes` vocabulary that this format does not spell
                # the same way. Before this they all fell through to "unknown
                # field name", which is `invalid` — the code that tells an
                # operator they typed something wrong, for a request a
                # schema-driven form generated correctly.
                changed.extend(self._apply_published_name(record, name, value))
                continue
            ftype = _RECORD_NAME_TO_TYPE.get(name)
            if ftype is None:
                raise Invalid("unknown field name")
            if ftype in (REC_UUID,):
                # Rewriting a UUID breaks every alias/shortcut that points at
                # this record (§3.3 notes [3], [4]).
                raise Invalid("an entry's uuid cannot be changed")
            if value is None:
                if Pws3Db.field_del(record, ftype):
                    changed.append(name)
                continue
            _name, kind = RECORD_FIELDS[ftype]
            Pws3Db.field_set(record, ftype, self._encode_value(kind, value))
            changed.append(name)
        if changed:
            now = _time_field()
            Pws3Db.field_set(record, REC_LAST_MOD_TIME, now)
            if "password" in changed:
                Pws3Db.field_set(record, REC_PASSWORD_MOD_TIME, now)
                self._push_password_history(record, old_password,
                                            old_password_when)
        return changed

    @staticmethod
    def _apply_published_name(record, name, value):
        """Three names the helper publishes that §3.3 spells differently — or
        does not have at all. Returns the list of names actually changed.

        Each one is either mapped to the field the format really has, or
        refused with `unsupported` naming the format's limit. What none of them
        does any more is answer `invalid: unknown field name`, which read as
        "you typed that wrong" for a request a schema-driven form built exactly
        as the schema told it to.

          `expires`   -> Password Expiry Time (0x0a). PWS3 has one expiry per
                        record and calls it the password's; KDBX has one and
                        calls it the entry's. They are the same operator
                        intention and there is no second field to disagree
                        with. Empty/None DELETES it, which is this format's
                        "never" — note [11] treats an absent 0x0a as no expiry
                        and a zero value is NOT the same statement.
          `totp_uri`  -> Two Factor Key (0x1b) plus TOTP Length (0x22) and
                        Time Step (0x23), through `_parse_otpauth`. The raw
                        seed is stored, never the URI text.
          `tags`      -> refused. §3.3 lists no tag field, `_entry_meta`
                        returns `[]` for exactly that reason, and inventing one
                        out of the group path would write data the file does
                        not contain and no other implementation would read.
        """
        if name == "tags":
            raise Unsupported(
                "Password Safe v3 has no tag field (§3.3 lists none), so "
                "there is nothing to write tags into; this format's grouping "
                "is the record's Group path")
        if name == "expires":
            if value is None or (isinstance(value, str) and not value.strip()):
                removed = Pws3Db.field_del(record, REC_PASSWORD_EXPIRY_TIME)
                return ["expires"] if removed else []
            if isinstance(value, bool):
                # A bare true has no date in it and this format stores only a
                # date. Refusing beats inventing one.
                raise Invalid("expires needs an ISO-8601 timestamp on this "
                              "format, or null for never")
            Pws3Db.field_set(record, REC_PASSWORD_EXPIRY_TIME,
                             _time_field(_iso_to_unix(value)))
            return ["expires"]
        # totp_uri
        if value is None or (isinstance(value, str) and not value.strip()):
            removed = False
            for ftype in (REC_TWO_FACTOR_KEY, REC_TOTP_CONFIG,
                          REC_TOTP_LENGTH, REC_TOTP_TIME_STEP,
                          REC_TOTP_START_TIME):
                removed = Pws3Db.field_del(record, ftype) or removed
            return ["totp_uri"] if removed else []
        seed, digits, period = _parse_otpauth(value)
        Pws3Db.field_set(record, REC_TWO_FACTOR_KEY, seed)
        # Note [29]: bits 0-1 select the hash and only 0x00 (SHA-1) is defined.
        # It is written explicitly rather than left absent so a reader does not
        # have to infer the algorithm from a missing field.
        Pws3Db.field_set(record, REC_TOTP_CONFIG, b"\x00")
        Pws3Db.field_set(record, REC_TOTP_LENGTH, bytes((digits,)))
        Pws3Db.field_set(record, REC_TOTP_TIME_STEP, bytes((period,)))
        # An otpauth URI carries no T0, so any Start Time already on the record
        # belonged to the seed being replaced. Leaving it would shift every
        # code this seed produces, silently and by a constant.
        Pws3Db.field_del(record, REC_TOTP_START_TIME)
        return ["totp_uri"]

    @staticmethod
    def _encode_value(kind, value):
        """Name/kind -> bytes. Refuses rather than coerces: a field written in
        the wrong shape is a field another implementation will misread."""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if kind == "text":
            return str(value).encode("utf-8")
        if kind == "time":
            if isinstance(value, str) and value.isdigit():
                value = int(value)
            if not isinstance(value, int):
                raise Invalid("a time field needs a Unix timestamp")
            return _time_field(value)
        if kind in ("u8", "u16", "u32", "i32"):
            width = {"u8": 1, "u16": 2, "u32": 4, "i32": 4}[kind]
            signed = kind == "i32"
            if isinstance(value, str) and (value.lstrip("-").isdigit()):
                value = int(value)
            if not isinstance(value, int):
                raise Invalid("this field needs an integer")
            try:
                return value.to_bytes(width, "little", signed=signed)
            except OverflowError:
                raise Invalid("this field's value is out of range")
        if kind == "uuid":
            try:
                return _uuid.UUID(str(value)).bytes
            except ValueError:
                raise Invalid("this field needs a uuid")
        if kind == "bytes":
            try:
                return base64.b64decode(str(value), validate=True)
            except (binascii.Error, ValueError):
                raise Invalid("this field needs base64 content")
        raise Invalid("this field cannot be set")

    def move(self, uuid, group):
        """Re-file an entry. The group is written verbatim (§3.3 note [2])."""
        self.require_writable()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        self._require_unprotected(record)
        if group:
            parts = _split_group(str(group))
            if len(parts) > Limits.MAX_GROUP_DEPTH:
                raise Invalid("group nesting exceeds %d levels"
                              % Limits.MAX_GROUP_DEPTH)
            Pws3Db.field_set(record, REC_GROUP, str(group).encode("utf-8"))
            self._forget_empty_group(str(group))
        else:
            Pws3Db.field_del(record, REC_GROUP)
        Pws3Db.field_set(record, REC_LAST_MOD_TIME, _time_field())
        return {"ok": True}

    def rm(self, uuid, permanent=False):
        """Delete an entry.

        `recycled` is always False and that is not a stub: Password Safe v3 has
        no recycle bin, so `permanent` cannot change the outcome. The backup
        ring taken by `atomic_replace` is the only undo, which is why the UI
        must confirm this.
        """
        self.require_writable()
        idx = self._require_record(uuid)
        self._require_unprotected(self._db.records[idx])
        del self._db.records[idx]
        return {"ok": True, "recycled": False}

    def group_add(self, parent, name):
        """Create a group.

        A group with no members exists only as a header Empty Groups field
        (§3.2 field 0x11) — the one header field the spec allows to repeat.
        """
        self.require_writable()
        if not name:
            raise Invalid("a group needs a name")
        parts = (_split_group(parent) if parent else []) + [str(name)]
        if len(parts) > Limits.MAX_GROUP_DEPTH:
            raise Invalid("group nesting exceeds %d levels"
                          % Limits.MAX_GROUP_DEPTH)
        path = _join_group(parts)
        if path in self._group_paths():
            raise Conflict("that group already exists")
        self._db.header.append(Field(HDR_EMPTY_GROUP, path.encode("utf-8")))
        return {"ok": True}

    def group_rm(self, uuid, permanent=False):
        """Delete a group. Refuses a non-empty group unless `permanent`."""
        self.require_writable()
        path = str(uuid or "")
        if not path:
            raise Invalid("the root group cannot be removed")
        members = [i for i in range(len(self._db.records))
                   if self._in_group(self._db.records[i], path)]
        if members and not permanent:
            raise Conflict("this group still holds %d entries" % len(members))
        for i in reversed(members):
            self._require_unprotected(self._db.records[i])
            del self._db.records[i]
        self._db.header = [f for f in self._db.header
                           if not (f.type == HDR_EMPTY_GROUP
                                   and self._path_covers(
                                       path, f.data.decode("utf-8", "replace")))]
        return {"ok": True}

    def group_mv(self, uuid, parent):
        """Re-parent a group, rewriting every member's Group field."""
        self.require_writable()
        path = str(uuid or "")
        if not path:
            raise Invalid("the root group cannot be moved")
        parts = _split_group(path)
        new_parts = (_split_group(parent) if parent else []) + [parts[-1]]
        new_path = _join_group(new_parts)
        if new_path == path:
            return {"ok": True}
        # A group moved into its own descendant produces a cycle the tree
        # walker will not survive.
        if self._path_covers(path, new_path):
            raise Invalid("a group cannot be moved inside itself")
        if len(new_parts) > Limits.MAX_GROUP_DEPTH:
            raise Invalid("group nesting exceeds %d levels"
                          % Limits.MAX_GROUP_DEPTH)

        for record in self._db.records:
            g = Pws3Db.field_get(record, REC_GROUP)
            if g is None:
                continue
            old = g.decode("utf-8", "replace")
            if self._path_covers(path, old):
                tail = _split_group(old)[len(parts):]
                Pws3Db.field_set(record, REC_GROUP,
                                 _join_group(new_parts + tail).encode("utf-8"))
                Pws3Db.field_set(record, REC_LAST_MOD_TIME, _time_field())
        for f in self._db.header:
            if f.type == HDR_EMPTY_GROUP:
                old = f.data.decode("utf-8", "replace")
                if self._path_covers(path, old):
                    tail = _split_group(old)[len(parts):]
                    f.data = _join_group(new_parts + tail).encode("utf-8")
        return {"ok": True}

    @staticmethod
    def _path_covers(ancestor, path):
        """True when `path` is `ancestor` or lives under it. Compares whole
        components, so "Fin" does not match "Finance"."""
        if path == ancestor:
            return True
        a = _split_group(ancestor)
        p = _split_group(path)
        return len(p) > len(a) and p[:len(a)] == a

    def _forget_empty_group(self, path):
        """Drop the Empty Groups header for a group that just gained a member.

        §3.2 note [16]: the field "contains the name of an empty group that
        cannot be constructed from entries within the database". Once an entry
        names the group, the group IS constructible from the entries and the
        header field is stale. Leaving it would not corrupt anything, but it
        would mean this program writes a database describing a state that is no
        longer true — and every unknown field in the file is preserved on the
        promise that we only touch what we understand.
        """
        if not path:
            return
        self._db.header = [
            f for f in self._db.header
            if not (f.type == HDR_EMPTY_GROUP
                    and f.data.decode("utf-8", "replace") == path)]

    def _in_group(self, record, path):
        g = Pws3Db.field_get(record, REC_GROUP)
        return g is not None and self._path_covers(
            path, g.decode("utf-8", "replace"))

    def history_restore(self, uuid, index):
        """Make one archived password current again. In memory only.

        The current password is pushed onto the history first — subject to the
        record's own policy, see `_push_password_history` — so a restore is
        itself undoable wherever the file allows history at all. Where the file
        has history switched off, the restore still happens and the previous
        password is NOT recorded, because recording it would be this program
        overriding a setting the operator chose in another application.

        `index` addresses `history()`'s list, oldest first. Negative indices
        are `NotFound`, not Python end-relative lookups: `history()` publishes
        0..n-1, so `-1` is a caller that got its arithmetic wrong, and quietly
        restoring the newest archived password instead of refusing would put a
        credential the operator did not choose into the live field.
        """
        self.require_writable()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        self._require_unprotected(record)

        raw = Pws3Db.field_get(record, REC_PASSWORD_HISTORY)
        if raw is None:
            raise NotFound("this entry has no password history")
        _enabled, _max_size, items = parse_password_history(
            raw.decode("utf-8", "replace"))
        try:
            index = int(index)
        except (TypeError, ValueError):
            raise NotFound("no such history version")
        if index < 0 or index >= len(items):
            raise NotFound("no such history version")
        # Captured BEFORE the archive step: pushing the current password can
        # trim the list from the front, which would renumber every index.
        target = items[index][1]

        current = Pws3Db.field_get(record, REC_PASSWORD)
        stamp = Pws3Db.field_get(record, REC_PASSWORD_MOD_TIME)
        self._push_password_history(
            record, current.decode("utf-8", "replace") if current else "",
            int.from_bytes(stamp[:4], "little")
            if stamp and len(stamp) >= 4 else None)

        now = _time_field()
        Pws3Db.field_set(record, REC_PASSWORD, target.encode("utf-8"))
        Pws3Db.field_set(record, REC_PASSWORD_MOD_TIME, now)
        Pws3Db.field_set(record, REC_LAST_MOD_TIME, now)
        return {"uuid": self._db.record_id(idx), "restored_from": index}

    def attach_add(self, uuid, name, data, *, replace=False):
        """Attach BYTES to an entry — §3.3 fields 0x25..0x29, note [30].

        **This is the format's own attachment mechanism, not a custom field.**
        Worth stating plainly because the fields are recent and easy to miss:
        note [30] defines Att Title / MediaType / FileName / Modification Time
        / Content, and says "if an entry contains an attachment the field Att
        MediaType must be present and non-empty". `attach_get` already reads
        exactly these; this is the write half.

        Two things the format genuinely cannot do, both refused with the reason
        named rather than worked around:

          * **One attachment per record.** A record is a list of fields and a
            field type appears at most once in it, so there is nowhere to put a
            second Att Content. Adding one under a custom text field would
            invent a convention no other implementation reads. A second name is
            `Unsupported`; `replace=True` replaces the one that is there.
          * **Format version 0x030F or later.** Note [30]: the attachment
            fields "were introduced in version 0x030F (PasswordSafe V3.68)".
            Writing them into a database that declares an older version means
            writing fields the file's own version says do not exist. We do not
            silently raise the declared version to make room — that is a claim
            about the file, and it is the operator's to make (see
            DEFAULT_NEW_VERSION).

        The media type is derived from the name's extension, defaulting to
        `application/octet-stream`. The format requires a non-empty MediaType
        and Python's `mimetypes` will not always produce one, so the default is
        the RFC 2046 catch-all rather than a guess.
        """
        self.require_writable()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        self._require_unprotected(record)

        version = self._db.version()
        if version and version < ATTACHMENT_MIN_VERSION:
            raise Unsupported(
                "this database declares format 0x%04x; attachments need "
                "0x%04x (PasswordSafe V3.68) or later"
                % (version, ATTACHMENT_MIN_VERSION))
        if not isinstance(name, str) or not name:
            raise Invalid("an attachment needs a name")
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise Invalid("the attachment content must be bytes")
        if len(data) > Limits.MAX_ATTACHMENT_BYTES:
            raise Invalid("the attachment is larger than the %d byte limit"
                          % Limits.MAX_ATTACHMENT_BYTES)

        existing = self._attachment_name(record)
        if existing and not replace:
            # TWO DIFFERENT REFUSALS, and telling them apart is the point.
            # Re-adding the SAME name is a `conflict`: the format can hold an
            # attachment by that name — it already does — and `replace=True`
            # is the answer. That is also what KDBX answers for the identical
            # request, and two backends that give one request two different
            # error codes is precisely the drift `conformance.py` exists to
            # catch. Only a SECOND, DIFFERENTLY NAMED attachment is
            # `unsupported`, because a record is a list of fields and a field
            # type appears at most once, so there is genuinely nowhere to put
            # it. "You cannot do this" and "you have already done this" are
            # different sentences and an operator acts on them differently.
            if existing == name:
                raise Conflict(
                    "this entry already has an attachment called %s"
                    % name[:64])
            raise Unsupported(
                "Password Safe v3 stores at most one attachment per entry and "
                "this entry already has %s; replace it or remove it first"
                % existing[:64])

        import mimetypes
        media = mimetypes.guess_type(name)[0] or "application/octet-stream"
        now = _time_field()
        Pws3Db.field_set(record, REC_ATT_TITLE, name.encode("utf-8"))
        Pws3Db.field_set(record, REC_ATT_FILENAME, name.encode("utf-8"))
        Pws3Db.field_set(record, REC_ATT_MEDIATYPE, media.encode("utf-8"))
        Pws3Db.field_set(record, REC_ATT_MOD_TIME, now)
        Pws3Db.field_set(record, REC_ATT_CONTENT, data)
        Pws3Db.field_set(record, REC_LAST_MOD_TIME, now)
        return {"ok": True, "name": name, "size": len(data)}

    def attach_rm(self, uuid, name):
        """Remove the entry's attachment — all five 0x25..0x29 fields.

        All five, and in particular Att MediaType: note [30] makes MediaType
        the field that says an attachment exists, so leaving it behind would
        leave a record that claims a zero-sized attachment ("absence of [Att
        Content] implies a zero-sized attachment") rather than none.
        """
        self.require_writable()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        self._require_unprotected(record)

        have = self._attachment_name(record)
        if not have:
            raise NotFound("this entry has no attachment")
        if name and name != have:
            raise NotFound("this entry has no such attachment")
        for ftype in (REC_ATT_TITLE, REC_ATT_MEDIATYPE, REC_ATT_FILENAME,
                      REC_ATT_MOD_TIME, REC_ATT_CONTENT):
            Pws3Db.field_del(record, ftype)
        Pws3Db.field_set(record, REC_LAST_MOD_TIME, _time_field())
        return {"ok": True}

    # -- persistence -------------------------------------------------------

    def _ensure_lossless(self):
        """I22's EARLY warning: refuse the first save if a field would be lost.

        The claim this backend makes is that a field type it has never heard of
        survives a save byte-for-byte, because a database IS its ordered list of
        (type, bytes) fields. That claim is cheap to check: serialise, parse the
        result back with the same credential, and compare every field of every
        record. If anything differs, refuse the save and NAME the field —
        refusing to save beats amputating a database.

        `stamp=False` on both halves: the "last saved" fields are meant to
        change, and comparing them would make the guard fail on the one thing it
        is supposed to allow.

        **THIS IS NOT THE PRE-WRITE CHECK, and believing it was is I41.** It
        latches on `self._lossless_checked` and runs once per session, so the
        second save of a session — the one carrying a mutation made after the
        latch closed — went to disk with nothing having looked at it. The
        per-save guarantee is `verify_own_output()` below, which runs on the
        actual bytes of every save and cannot be latched. This stays because an
        EARLY refusal, before the operator has done any work, is worth having;
        it is no longer the thing standing between a mutation and the disk.
        """
        if self._lossless_checked:
            return
        try:
            probe = serialize(self._db, stamp=False)
            echo = _decode(_split_prefix(probe), self._db.credential,
                           own_output=True)
        except Conflict:
            raise
        except SecretsError as exc:
            # `own_output=True` is why there is a real reason to print here at
            # all; see `_decode`. Without it this line said "the passphrase did
            # not open this safe" about a database the operator had just
            # successfully unlocked.
            raise Conflict("this database cannot be written: %s" % exc.detail)
        lost = _diff_db(self._db, echo)
        if lost:
            raise Conflict("a save would not preserve %s; refusing to write"
                           % "; ".join(lost[:5]))
        self._lossless_checked = True

    # -- the pre-write reader check  (I24, I41) ----------------------------

    def read_back(self, data):
        """`Backend.read_back` for PWS3: the reader `unlock()` uses, exactly.

        `_split_prefix` -> `_decode`, which is the same pair `parse_bytes` runs
        and therefore the same envelope checks, the same `_parse_field_stream`,
        the same `_check_field_length` caps, the same `MAX_ENTRIES` and
        `MAX_FIELDS_PER_RECORD` refusals and the same MAC gate. Not a re-run of
        the MAC: I41 was a file whose MAC was perfect and whose FIELD LENGTH the
        reader refused, so a check that stops at the MAC is exactly the check
        that missed it.

        The one difference from `unlock()` is `own_output=True`, and it is not a
        weakening — `_decode`'s docstring carries the argument in full. In one
        line: the flattening exists to deny a guesser a per-guess signal, and
        there is no guesser here, only bytes we made ourselves half a
        millisecond ago with a credential we already hold.

        No KDF: the credential is the `StretchedKey` the database is already
        open under, so the cost is one Twofish-CBC decrypt and one field walk.
        """
        self.require_unlocked()
        return _decode(_split_prefix(data), self._db.credential,
                       own_output=True)

    def diff_read_back(self, probe, expect=None):
        """`Backend.diff_read_back` for PWS3. Names, never values (I15).

        `expect` is the database `_serialize_for_write` actually built — header
        stamped, Version field already in front — so the comparison is exact and
        needs no tolerances. Falling back to `self._db` would make every save
        report the "last saved" stamp as data loss.
        """
        return _diff_db(expect if expect is not None else self._db, probe)

    def _serialize_for_write(self):
        """The bytes to write, and the database they are supposed to contain.

        Returns `(data, expect)`. `_final_header` is called ONCE and the result
        is what gets serialised, so `expect` is not an approximation of the file
        — it is the same decisions, and any difference the round trip finds is a
        real difference.

        A serialisation refusal becomes a `Conflict`: `Invalid` is the code for
        "the caller sent something malformed", and nobody sent anything here.
        `Conflict` is already what I22 answers for "this database cannot be
        written", it is the code the UI knows leaves the live file untouched,
        and the detail still names what was wrong.
        """
        self.require_unlocked()
        header = _final_header(self._db.header, stamp=True)
        expect = Pws3Db(header, self._db.records,
                        credential=self._db.credential)
        try:
            data = serialize(expect, stamp=False)
        except Conflict:
            raise
        except SecretsError as exc:
            raise Conflict("this database cannot be written: %s" % exc.detail)
        return data, expect

    def save(self, *, override_stale=False):
        """Serialise and write durably. The only method that writes (I12, I13).

        Sequence, with no shortcuts: access class (the caller's job) ->
        `require_writable` -> the I22 early warning -> `.plk` lock -> serialise
        -> **verify what we are about to write** -> `atomic_replace` with the
        fingerprint captured at unlock -> update the fingerprint.

        The verify step is I41. It runs inside the lock, on the exact bytes, on
        EVERY save, and a failure leaves the live file byte-for-byte as it was.
        """
        self.require_writable()
        self._ensure_lossless()

        backup = self.entry.get("backup") or {}
        # The `.plk` name is Password Safe's own convention (`base.LockFile`
        # knows it); holding it for the write is what stops a save from
        # silently discarding what the desktop app wrote (I13).
        # override_stale is the operator's explicit answer to the Conflict
        # LockFile raises; it is never inferred from an age or a pid (I13).
        with LockFile(self.path, fmt="psafe3", override_stale=override_stale):
            data, expect = self._serialize_for_write()
            # Verify before the bytes replace a database that currently works.
            # Cheap (no KDF) and it is the difference between "the save failed"
            # and "the safe is gone, and we told you it was your passphrase".
            self.verify_own_output(data, expect)
            report = atomic_replace(
                self.path, data,
                backup_dir=backup.get("dir"),
                keep=backup.get("keep"),
                expect_fingerprint=self.fingerprint)
        self.fingerprint = report["fingerprint"]
        return {"ok": True, "backup": report["backup"],
                "bytes": report["bytes"], "conflict": False}

    def save_as(self, target_path, *, override_stale=False):
        """Write this database to a NEW path. The original is not touched.

        Enforced by construction rather than by care, exactly as in the KDBX
        backend: `validate_new_path` has just proved the destination does not
        exist, so `atomic_replace` with `expect_fingerprint=None` never opens
        the original, never re-fingerprints it and finds nothing to back up;
        the `.plk` taken is the TARGET's, so the desktop client is not blocked
        on the original for the duration of a copy; and `self.fingerprint` is
        left describing the original, so a later `save()` still re-checks
        against the right file (I13).

        The copy carries the SAME credential — `serialize` uses the database's
        `StretchedKey`, i.e. the same salt and iteration count — so it opens
        with the passphrase the original opened with. K, L and the IV are drawn
        fresh, as they are on every serialise, so the two files share no
        keystream.

        `require_writable()` is deliberately not called; see the KDBX backend's
        `save_as` for why the registry's `mode: "ro"` is a statement about that
        file rather than about the operator.

        `verify_own_output` runs here for a sharper reason than in `save()`:
        there is no live file to be spared, so the copy IS the artefact, and
        nothing else will ever check it before the operator relies on it.
        """
        self.require_unlocked()
        self._ensure_lossless()
        validate_new_path(target_path)
        with LockFile(target_path, fmt="psafe3",
                      override_stale=override_stale):
            data, expect = self._serialize_for_write()
            self.verify_own_output(data, expect)
            report = atomic_replace(target_path, data,
                                    expect_fingerprint=None)
        return {"path": target_path, "bytes": report["bytes"]}

    # -- plaintext export  (I21) ------------------------------------------

    def export_plain(self, *, fmt):
        """**The single most dangerous method in this codebase.** See the ABC.

        One call returns every password, note, TOTP seed, credit-card field and
        passkey private key in the safe, in the clear, plus every archived
        password in every entry's history — which `reveal()` cannot reach at
        all. It exists because credentials an operator cannot get out are
        credentials they will not trust the tool with; it is gated because it
        is the shape of every exfiltration incident there has ever been (I21).

        Two formats, and one deliberate refusal:

          csv   a stable core of columns, plus any other KNOWN field that some
                record actually carries, in field-type order. Unknown field
                types are named (not dropped) in an `unknown-fields` column so
                a migrator can see that something was left behind.
          json  every field of every record, rendered per its declared type,
                with the raw bytes of unknown types in base64 so nothing is
                lost at all.
          xml   `Unsupported`. Password Safe's GUI does have an XML export, but
                it is an application feature governed by its own schema
                (`pwsafe.xsd`) — it is not part of formatV3.txt, and that
                schema is not available on this host. Emitting an
                approximation would produce a file that CLAIMS to be Password
                Safe XML and has never been read by Password Safe: precisely
                the compliance-by-assertion I19 exists to stop.

        Attachment CONTENT is excluded and the attachment's name, media type
        and size are listed — an export is for migrating credentials, and
        `attach_get` is the audited way to move one file at a time.
        """
        self.require_unlocked()
        if fmt == "csv":
            return self._export_csv()
        if fmt == "json":
            return self._export_json()
        if fmt == "xml":
            raise Unsupported(
                "Password Safe v3's XML export is a GUI feature with its own "
                "schema, not part of the file format; this backend will not "
                "emit a file claiming to be it")
        raise Unsupported("%s is not an export format this backend writes"
                          % str(fmt)[:16])

    #: Always present, in this order, whether or not any record uses them. A
    #: stable prefix is what lets a migrator write one column mapping and reuse
    #: it against every database. These are §3.3 field names and are read
    #: straight out of the record by `_export_value`.
    _CSV_CORE_FIELDS = ("group", "title", "username", "password", "url",
                        "email", "notes", "create-time", "password-mod-time",
                        "last-mod-time", "password-expiry-time",
                        "password-history", "two-factor-key")
    #: Also always present, but DERIVED rather than read from a single field:
    #: the three attachment columns fold five §3.3 fields into a name, a media
    #: type and a size (the content itself is excluded), and `unknown-fields`
    #: names the type bytes this export could not label. Kept as its own tuple
    #: so that adding a core column cannot silently shift the boundary between
    #: "look this up by name" and "compute it".
    _CSV_CORE_DERIVED = ("attachment", "attachment-mediatype",
                         "attachment-bytes", "unknown-fields")
    #: The five attachment fields never become extra columns: the content is
    #: excluded outright and the other four are folded into the three
    #: `attachment*` columns above.
    _CSV_ATTACHMENT = frozenset(("attachment-content", "attachment-title",
                                 "attachment-filename", "attachment-mediatype",
                                 "attachment-mod-time"))

    def _export_csv(self):
        if len(self._db.records) > Limits.MAX_ENTRIES:
            raise Invalid("this database holds more than %d entries"
                          % Limits.MAX_ENTRIES)
        # Which extra known fields any record actually carries. Emitting all 48
        # of §3.3 would give a migrator a wall of empty columns; emitting none
        # would silently drop credit-card numbers and passkey material. The set
        # is derived from the data and the order is the field-type order, so
        # the result is deterministic for a given database.
        skip = self._CSV_ATTACHMENT.union(self._CSV_CORE_FIELDS)
        present = set()
        for record in self._db.records:
            for f in record:
                name = RECORD_FIELDS.get(f.type, (None,))[0]
                if name and name not in skip:
                    present.add(f.type)
        extra = [RECORD_FIELDS[t][0] for t in sorted(present)]

        buf = io.StringIO()
        # QUOTE_ALL and CRLF: RFC 4180, and the only setting under which a
        # password containing a comma, a quote or a newline reads back as the
        # value we wrote. It is NOT a formula-injection defence — a spreadsheet
        # parses a quoted cell beginning with `=` as a formula just the same —
        # so the writer is `CsvWriter`, which neutralises those. See
        # base.csv_cell for the hazard and for what the neutralisation costs.
        writer = CsvWriter(buf)
        writer.writerow(list(self._CSV_CORE_FIELDS)
                        + list(self._CSV_CORE_DERIVED) + extra)
        for record in self._db.records:
            row = [self._export_value(record, name)
                   for name in self._CSV_CORE_FIELDS]
            content = Pws3Db.field_get(record, REC_ATT_CONTENT) or b""
            media = Pws3Db.field_get(record, REC_ATT_MEDIATYPE) or b""
            row += [
                self._attachment_name(record),
                media.decode("utf-8", "replace"),
                str(len(content)) if media else "",
                " ".join("0x%02x" % f.type for f in record
                         if f.type not in RECORD_FIELDS),
            ]
            row += [self._export_value(record, name) for name in extra]
            writer.writerow(row)
        # Read by the `export` verb so the operator is told rather than
        # surprised. Same contract as the KDBX backend's.
        self.last_export_neutralised = writer.neutralised
        return buf.getvalue().encode("utf-8")

    def _export_value(self, record, name):
        """One named field, rendered for a text cell. `""` when absent."""
        ftype = _RECORD_NAME_TO_TYPE.get(name)
        if ftype is None:
            return ""
        raw = Pws3Db.field_get(record, ftype)
        if raw is None:
            return ""
        if name == "two-factor-key":
            # Base32, unpadded — what every authenticator and QR generator
            # expects, and what `reveal` already hands back for this field.
            return base64.b32encode(raw).decode("ascii").rstrip("=")
        return _render(RECORD_FIELDS[ftype][1], raw)

    def _export_json(self):
        entries = []
        for i, record in enumerate(self._db.records):
            known = {}
            unknown = []
            for f in record:
                if f.type in RECORD_FIELDS:
                    name, kind = RECORD_FIELDS[f.type]
                    if name == "attachment-content":
                        continue                # bytes excluded; see the ABC
                    if name == "two-factor-key":
                        known[name] = base64.b32encode(
                            f.data).decode("ascii").rstrip("=")
                    else:
                        known[name] = _render(kind, f.data)
                else:
                    # Carried, not dropped. §4.1 says an unknown field must
                    # survive a save, and an export that silently omitted it
                    # would be the one place the guarantee stopped holding.
                    unknown.append({
                        "type": "0x%02x" % f.type,
                        "bytes": len(f.data),
                        "b64": base64.b64encode(f.data).decode("ascii"),
                    })
            content = Pws3Db.field_get(record, REC_ATT_CONTENT) or b""
            media = Pws3Db.field_get(record, REC_ATT_MEDIATYPE) or b""
            row = {
                "uuid": self._db.record_id(i),
                "fields": known,
                "unknown_fields": unknown,
                "attachment": ({"name": self._attachment_name(record),
                                "mediatype": media.decode("utf-8", "replace"),
                                "size": len(content)} if media else None),
                "password_history": self._export_history_json(record),
            }
            entries.append(row)

        header = {}
        header_unknown = []
        for f in self._db.header:
            if f.type in HEADER_FIELDS:
                name, kind = HEADER_FIELDS[f.type]
                # Empty Groups is the one repeatable header field (§3.2 [16]),
                # so a dict keyed by name would keep only the last one.
                if f.type == HDR_EMPTY_GROUP:
                    header.setdefault("empty-groups", []).append(
                        _render(kind, f.data))
                else:
                    header[name] = _render(kind, f.data)
            else:
                header_unknown.append({
                    "type": "0x%02x" % f.type,
                    "bytes": len(f.data),
                    "b64": base64.b64encode(f.data).decode("ascii"),
                })

        document = {
            "format": "psafe3",
            "version": self._db.version_string(),
            "generator": "cockpit-secrets %s" % VERSION,
            "exported": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds").replace("+00:00", "Z"),
            "header": header,
            "header_unknown": header_unknown,
            "entries": entries,
        }
        return json.dumps(document, ensure_ascii=False,
                          indent=1).encode("utf-8")

    @staticmethod
    def _export_history_json(record):
        """The password history WITH its passwords — this is a plain export.

        `history()` refuses to return these and this method returns them, and
        the difference is the whole point of the I21 gate: browsing history is
        an everyday read, and taking every password an entry has ever had out
        of the safe in one object is not.
        """
        raw = Pws3Db.field_get(record, REC_PASSWORD_HISTORY)
        if raw is None:
            return None
        try:
            enabled, max_size, items = parse_password_history(
                raw.decode("utf-8", "replace"))
        except Invalid:
            # One malformed history must not fail an export of a thousand
            # entries. Say so in the output rather than dropping the field.
            return {"malformed": True,
                    "raw": raw.decode("utf-8", "replace")}
        return {
            "enabled": enabled,
            "max_size": max_size,
            "entries": [{"when": _render_time(_time_field(when)),
                         "password": password} for when, password in items],
        }

    def lock(self):
        """Drop the database and every key derived from it. Idempotent."""
        if self._db is not None:
            self._db.zero()
            self._db = None
        self.handle = None
        self.unlocked = False
        self._lossless_checked = False
        return {"ok": True}


# ===========================================================================
# self-check — runnable proof, in the shape base.py set
# ===========================================================================

def _selfcheck():                                       # noqa: C901
    """`python3 -m backends.psafe3` — build a safe, break it, prove the refusals.

    No real secret is involved: the passphrase below is a literal in a test, and
    the file is written to a private temporary directory that is removed again.
    """
    import shutil
    import tempfile

    failures = []

    def ok(label, cond):
        print("  %s  %s" % ("PASS" if cond else "FAIL", label))
        if not cond:
            failures.append(label)

    def raises(label, exc_type, fn):
        try:
            fn()
        except exc_type:
            ok(label, True)
            return
        except Exception as exc:                        # noqa: BLE001
            ok("%s (got %s)" % (label, type(exc).__name__), False)
            return
        ok("%s (no error raised)" % label, False)

    print("== twofish providers ==")
    for want in ("botan", "pure"):
        try:
            got = set_twofish_provider(want)
        except Unsupported:
            print("  skip  %s is unavailable" % want)
            continue
        kat = _ecb_encrypt(b"\x00" * 16, b"\x00" * 16)
        ok("%s passes the 128-bit ECB known-answer vector" % got,
           binascii.hexlify(kat) == b"9f589f5cf6122c32b6bfec2f2ae8c35a")
    set_twofish_provider(None)

    tmp = tempfile.mkdtemp(prefix="psafe3-selfcheck-")
    os.chmod(tmp, 0o700)
    path = os.path.join(tmp, "selfcheck.psafe3")
    pw = "correct horse battery staple"
    try:
        print("== round trip ==")
        db = Pws3Db()
        db.header.append(Field(HDR_VERSION,
                               DEFAULT_NEW_VERSION.to_bytes(2, "little")))
        db.header.append(Field(HDR_UUID, _uuid.uuid4().bytes))
        # An unknown header type and an unknown record type, to prove §4.1.
        db.header.append(Field(0xC7, b"unknown-header-payload"))
        db.records.append([
            Field(REC_UUID, _uuid.uuid4().bytes),
            Field(REC_GROUP, b"Finance.bank"),
            Field(REC_TITLE, b"example"),
            Field(REC_USERNAME, b"alice"),
            Field(REC_PASSWORD, b"s3cret-value"),
            Field(REC_LAST_MOD_TIME, _time_field(1700000000)),
            Field(0xE7, b"implementation-specific bytes that must survive"),
        ])
        write_file(path, pw, db, iterations=Limits.PWS3_WRITE_MIN_ITER)
        back = read_file(path, pw)
        # A save stamps "last saved at / by what", so the header GAINS two
        # fields. Everything that was there before must still be there,
        # unchanged and in order.
        ok("every original header field survives, in order",
           [f.type for f in db.header]
           == [f.type for f in back.header[:len(db.header)]]
           and all(a == b for a, b in zip(db.header, back.header)))
        ok("save stamped the last-saved fields",
           back.header_get(HDR_LAST_SAVE_TIME) is not None
           and back.header_get(HDR_LAST_SAVE_WHAT) is not None)
        ok("unknown header field preserved byte-for-byte",
           back.header_get(0xC7) == b"unknown-header-payload")
        ok("unknown record field preserved byte-for-byte",
           Pws3Db.field_get(back.records[0], 0xE7)
           == b"implementation-specific bytes that must survive")
        ok("password preserved",
           Pws3Db.field_get(back.records[0], REC_PASSWORD) == b"s3cret-value")
        ok("iterations at the write floor",
           back.credential.iterations == Limits.PWS3_WRITE_MIN_ITER)

        # The property that matters for I22: with the "last saved" stamp off,
        # a read -> write -> read cycle is EXACTLY field-stable. The file bytes
        # differ every time — the padding is random by design (§3) and K, L and
        # the IV are freshly drawn — so field identity, not byte identity, is
        # the right thing to assert.
        again = _decode(_split_prefix(serialize(back, stamp=False)),
                        back.credential)
        ok("read -> write -> read is field-stable (header)",
           again.header == back.header)
        ok("read -> write -> read is field-stable (records)",
           again.records == back.records)
        back.zero()

        print("== refusals ==")
        raw = open(path, "rb").read()
        raises("wrong passphrase -> BadCredential", BadCredential,
               lambda: parse_bytes(raw, "not the passphrase"))
        flipped = bytearray(raw)
        flipped[PREFIX_LEN + 3] ^= 0x01
        raises("flipped ciphertext byte -> BadCredential or Invalid",
               (BadCredential, Invalid),
               lambda: parse_bytes(bytes(flipped), pw))
        raises("truncated file -> Invalid", Invalid,
               lambda: parse_bytes(raw[:-64], pw))
        no_eof = bytearray(raw)
        no_eof[-TAIL_LEN] ^= 0xFF
        raises("missing EOF block -> Invalid", Invalid,
               lambda: parse_bytes(bytes(no_eof), pw))
        zero_iter = bytearray(raw)
        zero_iter[36:40] = (0).to_bytes(4, "little")
        raises("ITER=0 -> Invalid", Invalid,
               lambda: parse_bytes(bytes(zero_iter), pw))
        big_iter = bytearray(raw)
        big_iter[36:40] = (2 ** 31).to_bytes(4, "little")
        raises("ITER=2^31 -> Invalid", Invalid,
               lambda: parse_bytes(bytes(big_iter), pw))

        print("== the pre-write reader check  (I24, I41) ==")
        # The PWS3 twin of kdbx's
        # `test_crypto01_save_refuses_output_it_cannot_read_back`. Its absence
        # is why I24's written claim that this was already fixed here survived
        # review for a whole remediation cycle.
        live = os.path.join(tmp, "guarded.psafe3")
        db2 = Pws3Db()
        db2.header.append(Field(HDR_VERSION,
                                DEFAULT_NEW_VERSION.to_bytes(2, "little")))
        db2.records.append([
            Field(REC_UUID, _uuid.uuid4().bytes),
            Field(REC_TITLE, b"guarded"),
            Field(REC_PASSWORD, b"s3cret-value"),
        ])
        write_file(live, pw, db2, iterations=Limits.PWS3_WRITE_MIN_ITER)
        os.chmod(live, 0o600)
        entry = {"id": "guarded", "label": "guarded", "format": "psafe3",
                 "path": live, "access": "user", "mode": "rw",
                 "backup": {"keep": 2, "dir": None}}
        b = Psafe3Backend(entry)
        b.unlock(Secret(pw))
        uuid0 = b.entries(limit=1)["entries"][0]["uuid"]
        b.edit(uuid0, {"notes": "first edit"})
        ok("save 1 succeeds", b.save().get("ok") is True)
        # I41 IN ONE ASSERTION: the I22 guard has now latched, and the
        # per-save check must not have latched with it.
        ok("the I22 early guard has latched after save 1",
           b._lossless_checked is True)

        before = open(live, "rb").read()
        b.edit(uuid0, {"notes": "second edit, made AFTER the latch closed"})
        # Make the READER stricter than the writer for the duration of ONE
        # save. MAX_ENTRIES is a read-side cap that `serialize` does not
        # consult, so this is a genuine writer/reader asymmetry rather than a
        # patched-out guard — the same shape as the drift that produced I41,
        # induced on purpose. With the check removed, this save SUCCEEDS and
        # writes a file no later `unlock` can open.
        keep_entries = Limits.MAX_ENTRIES
        Limits.MAX_ENTRIES = 0
        try:
            b.save()
            ok("a save whose output the reader refuses is REFUSED", False)
            caught = None
        except SecretsError as exc:
            caught = exc
            ok("a save whose output the reader refuses is REFUSED", True)
        finally:
            Limits.MAX_ENTRIES = keep_entries
        if caught is not None:
            ok("...as a Conflict (the live file is untouched)",
               caught.code == "conflict")
            ok("...naming what the reader objected to",
               "record limit" in caught.detail)
            # THE MISATTRIBUTION, which is the half of I41 that costs the
            # operator their next move: a file WE broke must never come back as
            # a statement about their passphrase.
            ok("...and NOT as bad-credential",
               caught.code != "bad-credential"
               and _BAD_CREDENTIAL not in caught.detail)
        ok("the live file is byte-for-byte unchanged",
           open(live, "rb").read() == before)
        # The positive control, so "refuses everything" cannot pass this.
        ok("...and an ordinary save 2 still succeeds",
           b.save().get("ok") is True)
        after = read_file(live, pw)
        ok("...and what it wrote still opens, with the second edit in it",
           Pws3Db.field_get(after.records[0], REC_NOTES)
           == b"second edit, made AFTER the latch closed")
        after.zero()

        # I6 IS NOT WEAKENED BY THE ABOVE. `own_output=True` reaches exactly
        # one caller — the pre-write check — and the client-facing answers stay
        # flat: a hostile file and a wrong passphrase are the same sentence.
        raw2 = open(live, "rb").read()
        hostile = bytearray(raw2)
        hostile[PREFIX_LEN + 17] ^= 0x40
        wrong = tampered = None
        try:
            parse_bytes(raw2, "not the passphrase")
        except SecretsError as exc:
            wrong = exc
        try:
            parse_bytes(bytes(hostile), pw)
        except SecretsError as exc:
            tampered = exc
        ok("a wrong passphrase is still bad-credential",
           wrong is not None and wrong.code == "bad-credential")
        ok("a tampered file is still bad-credential",
           tampered is not None and tampered.code == "bad-credential")
        ok("...and the two are indistinguishable to a client",
           wrong is not None and tampered is not None
           and (wrong.code, wrong.detail) == (tampered.code, tampered.detail))
        b.lock()

        print("== the write half of the read limit  (I23, I41) ==")
        # `_emit_field` must refuse exactly what `_parse_field_stream` refuses,
        # by calling the same checker with the same constants.
        raises("a field over MAX_FIELD_BYTES cannot be WRITTEN", Invalid,
               lambda: _emit_field(Field(REC_NOTES,
                                         b"x" * (Limits.MAX_FIELD_BYTES + 1)),
                                   bytearray(),
                                   hmac.new(b"k", digestmod=hashlib.sha256)))
        raises("...and the reader refuses the same size", Invalid,
               lambda: _check_field_length(Limits.MAX_FIELD_BYTES + 1,
                                           REC_NOTES,
                                           Limits.MAX_FIELD_BYTES + 1))
        big_att = bytearray()
        _emit_field(Field(REC_ATT_CONTENT, b"x" * (Limits.MAX_FIELD_BYTES + 1)),
                    big_att, hmac.new(b"k", digestmod=hashlib.sha256))
        ok("an ATTACHMENT of that size is still written (its cap is 32 MiB)",
           len(big_att) > Limits.MAX_FIELD_BYTES)

        print("== hostile field length ==")
        started = time.monotonic()
        raises("declared field length 0xFFFFFFFF -> Invalid", Invalid,
               lambda: _parse_field_stream(
                   b"\xff\xff\xff\xff\x03" + b"\x00" * 11))
        ok("...and refused in O(1) (%.4fs)" % (time.monotonic() - started),
           time.monotonic() - started < 0.5)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print("psafe3 self-check: %d FAILURE(S)" % len(failures))
        return 1
    print("psafe3 self-check: OK")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selfcheck())
