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
import hashlib
import hmac
import os
import secrets as _sysrandom
import sys
import time
import uuid as _uuid
from datetime import datetime, timezone

from .base import (
    AccessDenied, BadCredential, Conflict, Invalid, NotFound, Unsupported,
    Backend, LockFile, Limits, Secret,
    atomic_replace, constant_time_eq, open_safe_fd, redact, register_backend,
    VERSION,
)

__all__ = [
    "Psafe3Backend", "Pws3Db", "Field", "StretchedKey",
    "parse_bytes", "serialize", "read_file", "write_file",
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

    Botan's `SymmetricCipher` would offer "Twofish/CBC", but its CBC comes with
    a padding scheme and Password Safe v3 has none: fields are block-aligned by
    the format itself, with random fill, and a library that quietly appended
    PKCS#7 would corrupt every file we wrote. So both providers expose the same
    thing — one block in, one block out — and this module drives CBC itself.
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
    def field_get(record, ftype):
        for f in record:
            if f.type == ftype:
                return f.data
        return None

    @staticmethod
    def field_set(record, ftype, data):
        for f in record:
            if f.type == ftype:
                f.data = bytes(data)
                return
        record.append(Field(ftype, data))

    @staticmethod
    def field_del(record, ftype):
        for i, f in enumerate(record):
            if f.type == ftype:
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


def _decode(env, key):
    """Decrypt, parse, **verify the MAC**, and only then return a database.

    Order matters and is the whole of I6 for this format: nothing below returns
    a `Pws3Db` until `compare_digest` has said yes. Everything between the
    decrypt and that comparison is treated as attacker-shaped input, which is
    why every length is bounds-checked and every count is capped.
    """
    if not constant_time_eq(key.hash(), env["hpprime"]):
        # §2.5. Cheap, and the format's own design — but it is still only a
        # passphrase check, never an integrity check.
        raise BadCredential(_BAD_CREDENTIAL)

    record_key, mac_key = key.unwrap(env["b1b2"], env["b3b4"])
    plain = None
    try:
        plain = _cbc_decrypt(record_key.bytes, env["iv"], env["body"])
        try:
            return _decode_plaintext(plain, mac_key, env, key)
        except Invalid as exc:
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


def _decode_plaintext(plain, mac_key, env, key):
    """Field walk and MAC verification over decrypted, still-UNTRUSTED bytes.

    Split out from `_decode` so that the one caller can convert every failure
    in here into the flat `BadCredential`, and so that "everything in this
    function is attacker-shaped" is a property of a whole function rather than
    a comment in the middle of one.
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

    header = list(db.header)
    if stamp:
        header = _stamped_header(header)

    # §2.9.1: the header begins with the Version field. Order is otherwise
    # preserved exactly, because preserving order is how unknown fields come
    # back out in the same place they went in.
    vidx = next((i for i, f in enumerate(header) if f.type == HDR_VERSION), -1)
    if vidx < 0:
        header.insert(0, Field(HDR_VERSION,
                               DEFAULT_NEW_VERSION.to_bytes(2, "little")))
    elif vidx > 0:
        header.insert(0, header.pop(vidx))

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
        data = serialize(db, credential)
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

    def unlock(self, password, keyfile=None, session=None):
        """Derive, verify, parse — in that order, and nothing escapes early.

        `keyfile` is refused rather than ignored: Password Safe v3 has no key
        file, and accepting one silently would let an operator believe a second
        factor was in play when it was not.
        """
        if keyfile is not None and len(keyfile) > 0:
            raise Unsupported("Password Safe v3 has no key-file support")
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
        """
        self.require_unlocked()
        idx = self._require_record(uuid)
        record = self._db.records[idx]
        ftype = _RECORD_NAME_TO_TYPE.get(field)
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

    def _apply_changes(self, idx, changes):
        record = self._db.records[idx]
        changed = []
        for name, value in changes.items():
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
        return changed

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

    # -- persistence -------------------------------------------------------

    def _ensure_lossless(self):
        """I22, and it runs for real rather than being asserted.

        The claim this backend makes is that a field type it has never heard of
        survives a save byte-for-byte, because a database IS its ordered list of
        (type, bytes) fields. That claim is cheap to check: serialise, parse the
        result back with the same credential, and compare every field of every
        record. If anything differs, refuse the save and NAME the field —
        refusing to save beats amputating a database.

        `stamp=False` on both halves: the "last saved" fields are meant to
        change, and comparing them would make the guard fail on the one thing it
        is supposed to allow.
        """
        if self._lossless_checked:
            return
        probe = serialize(self._db, stamp=False)
        echo = _decode(_split_prefix(probe), self._db.credential)

        def describe(where, field):
            table = HEADER_FIELDS if where == "header" else RECORD_FIELDS
            name = table.get(field.type, ("type 0x%02x" % field.type,))[0]
            return "%s field %s" % (where, name)

        if len(echo.header) != len(self._db.header):
            raise Conflict("a save would change this database's header "
                           "structure; refusing to write")
        for before, after in zip(self._db.header, echo.header):
            if before != after:
                raise Conflict("a save would not preserve the %s; "
                               "refusing to write" % describe("header", before))
        if len(echo.records) != len(self._db.records):
            raise Conflict("a save would change this database's record count; "
                           "refusing to write")
        for rec_before, rec_after in zip(self._db.records, echo.records):
            if len(rec_before) != len(rec_after):
                raise Conflict("a save would change a record's field count; "
                               "refusing to write")
            for before, after in zip(rec_before, rec_after):
                if before != after:
                    raise Conflict("a save would not preserve the %s; "
                                   "refusing to write"
                                   % describe("entry", before))
        self._lossless_checked = True

    def save(self, *, override_stale=False):
        """Serialise and write durably. The only method that writes (I12, I13).

        Sequence, with no shortcuts: access class (the caller's job) ->
        `require_writable` -> losslessness guard -> `.plk` lock -> serialise ->
        `atomic_replace` with the fingerprint captured at unlock -> update the
        fingerprint.
        """
        self.require_writable()
        self._ensure_lossless()

        backup = self.entry.get("backup") or {}
        data = serialize(self._db)
        # The `.plk` name is Password Safe's own convention (`base.LockFile`
        # knows it); holding it for the write is what stops a save from
        # silently discarding what the desktop app wrote (I13).
        # override_stale is the operator's explicit answer to the Conflict
        # LockFile raises; it is never inferred from an age or a pid (I13).
        with LockFile(self.path, fmt="psafe3", override_stale=override_stale):
            report = atomic_replace(
                self.path, data,
                backup_dir=backup.get("dir"),
                keep=backup.get("keep"),
                expect_fingerprint=self.fingerprint)
        self.fingerprint = report["fingerprint"]
        return {"ok": True, "backup": report["backup"],
                "bytes": report["bytes"], "conflict": False}

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
