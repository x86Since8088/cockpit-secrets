#!/usr/bin/env python3
"""backends/kdbx.py — the KeePass KDBX 3.x / 4.x adapter, engine `pykeepass`.

Same house contract as the rest of the tree (docs/CONTRACT.md, and
cockpit-wireguard/docs/CONTRACT.md for the shape): this module is a library, it
never prints, it never touches argv, and every failure is one of the eight typed
errors from `backends.base`. `secrets-admin` is the only thing that talks to a
browser.

In-process only. `keepassxc-cli` is the interop ORACLE for the test suite
(docs/UPSTREAM-REVIEW.md §2.2) and must never appear in a runtime code path:
driving it means either a pty or piping the master passphrase into a child on
every operation, which adds a process boundary the secret has to cross for no
gain over a library that is already in this address space.

WHAT THIS MODULE DOES THAT pykeepass DOES NOT, and why each one is here
----------------------------------------------------------------------

1. **It parses the KDBX header itself, before pykeepass is allowed near the
   file (I7).** `PyKeePass(...)` derives the key inside its constructor, so by
   the time you hold a `PyKeePass` object the Argon2 parameters a hostile file
   asked for have already been honoured — `m=4 GiB` has already been allocated.
   A clamp that runs after that is decoration. `_read_header()` is a raw,
   allocation-free reader over the bytes we already have in memory, and
   `Limits.check_argon2` / `Limits.check_aeskdf_rounds` run against its output
   *before* a single round of derivation.

2. **It verifies the MAC itself, with `hmac.compare_digest` (I6).** pykeepass
   authenticates through `construct.Checksum`, whose `_parse` compares with
   `!=` and whose exception message carries the computed digest in hex. We
   therefore verify the KDBX4 header HMAC and every payload block HMAC
   ourselves, constant-time, and only hand the bytes to pykeepass once they
   have passed. A wrong passphrase and a failed MAC raise `BadCredential` with
   the SAME detail string, because distinguishing them turns `unlock` into a
   decryption oracle.

3. **It never gives pykeepass the passphrase.** We compute the composite key
   from `Secret.bytes` — the wipeable `bytearray` — derive the transformed key,
   and open the database with `transformed_key=` alone. `Secret.str_view()` is
   never called in this file. That closes hop 7 of the passphrase table in
   docs/ARCHITECTURE.md for KDBX: the master passphrase never becomes an
   unwipeable Python `str` inside this process.

   **The honest remainder (I14):** every decrypted *value* pykeepass hands back
   — passwords, notes, protected custom fields — IS an immutable `str` on the
   GC heap, and so are the `str`s lxml builds for every XML text node. Those
   cannot be wiped, and `lock()` cannot make them go away. The mitigation is
   the process model, not this module: one helper process per operation, whose
   whole address space returns to the kernel in milliseconds. `harden_process()`
   (RLIMIT_CORE=0, PR_SET_DUMPABLE=0, best-effort mlockall) narrows the window
   further. A root-equivalent attacker still wins, and docs/THREAT-MODEL.md
   says so rather than pretending otherwise.

4. **It hardens the XML parser by interposition (I8).** pykeepass builds its own
   `lxml` parser with library defaults, inside `construct` adapters we do not
   own. Defaults are not a mitigation — they change between releases, and the
   one that matters here (internal entity expansion) is still ON in lxml 6.0.2.
   `_install_xml_hardening()` replaces the `etree` and `zlib` names *inside*
   pykeepass's parsing module with proxies that force
   `resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False`,
   refuse any document carrying a DOCTYPE or an unexpanded entity reference,
   and bound decompression. It proves itself with a canary at install time and
   raises `Internal` — fail closed — if the canary is not refused.

5. **KDBX3 is read-only (I20)** and says why in `warnings`. KDBX 3.1 has no
   authenticated encryption: its "credential check" is a known-plaintext
   comparison against `stream_start_bytes` and its per-block digests are
   unkeyed SHA-256, so anyone who can write the file can also rewrite those.
   `upgrade_to_kdbx4()` exists, writes a NEW file at a path the operator names,
   and is never automatic.

6. **It refuses to save a database it cannot round-trip (I22).** Before the
   first mutation, `_assert_lossless()` does parse -> serialize -> parse in
   memory and diffs the two XML trees. Any element, attribute or custom field
   that would be dropped turns writes off and NAMES the field. Refusing to save
   beats silently amputating a database.

7. **It reseeds on save.** pykeepass rewrites a database with the master seed,
   the encryption IV and the inner protected-stream key it read, so two
   consecutive saves of a database that differ by one late entry share a key
   AND an IV — identical CBC/stream prefixes, which is a free diff for anyone
   holding both files. Real KeePass regenerates. We regenerate the three
   values that do not require re-running the KDF (the KDF salt is left alone
   precisely because changing it would need the passphrase we deliberately no
   longer hold).

Licence: GPL-3.0 — forced by linking pykeepass. See ../LICENSE.
"""

import base64
import binascii
import datetime as _dt
import hashlib
import hmac
import io
import os
import re
import secrets as _sysrandom
import struct
import time
import zlib
from copy import deepcopy

from lxml import etree

from .base import (
    BadCredential,
    Conflict,
    Internal,
    Invalid,
    Limits,
    NotFound,
    Secret,
    Unsupported,
    Backend,
    atomic_replace,
    constant_time_eq,
    open_safe_fd,
    register_backend,
    LockFile,
)

# pykeepass and its parsing internals. The import is at module scope on
# purpose: `secrets-admin` imports backends lazily (a psafe3 unlock must not
# drag in the KDBX XML stack), so reaching this line already means a KDBX safe
# is in play. A missing pykeepass raises ImportError here and the helper reports
# the format as `unsupported` — never a traceback (backends/__init__.py).
import pykeepass
from pykeepass import PyKeePass
from pykeepass.kdbx_parsing import common as _pk_common
from pykeepass import pykeepass as _pk_top

VERSION = "1.0.0"

# ===========================================================================
# format constants — from the KDBX specification, not from a summary
#   https://keepass.info/help/kb/kdbx.html · .../kdbx_4.html
# ===========================================================================

KDBX_SIG1 = b"\x03\xd9\xa2\x9a"
KDBX_SIG2 = b"\x67\xfb\x4b\xb5"

#: Outer-header field ids. 3.x and 4.x share the low numbers; 4.x replaced the
#: 3.x transform/protected-stream fields with a single KDF VariantDictionary.
_H_END = 0
_H_COMMENT = 1
_H_CIPHER_ID = 2
_H_COMPRESSION = 3
_H_MASTER_SEED = 4
_H_TRANSFORM_SEED = 5          # 3.x only
_H_TRANSFORM_ROUNDS = 6        # 3.x only
_H_ENCRYPTION_IV = 7
_H_PROTECTED_STREAM_KEY = 8    # 3.x only
_H_STREAM_START_BYTES = 9      # 3.x only
_H_PROTECTED_STREAM_ID = 10    # 3.x only
_H_KDF_PARAMETERS = 11         # 4.x only
_H_PUBLIC_CUSTOM_DATA = 12     # 4.x only

#: Cipher UUIDs, same table pykeepass uses (KeePass2.cpp).
_CIPHERS = {
    b"1\xc1\xf2\xe6\xbfqCP\xbeX\x05!j\xfcZ\xff": "aes256",
    b"\xadh\xf2\x9fWoK\xb9\xa3j\xd4z\xf9e4l": "twofish",
    b"\xd6\x03\x8a+\x8boL\xb5\xa5$3\x9a1\xdb\xb5\x9a": "chacha20",
}

#: KDF UUIDs. argon2d and argon2id are distinct algorithms, not a flag.
_KDF_ARGON2D = b"\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c"
_KDF_ARGON2ID = b"\x9e)\x8b\x19V\xdbGs\xb2=\xfc>\xc6\xf0\xa1\xe6"
_KDF_AESKDF = b"\xc9\xd9\xf3\x9ab\x8aD`\xbft\r\x08\xc1\x8aO\xea"

#: VariantDictionary value types (KDBX4 KDF parameters).
_VD_UINT32 = 0x04
_VD_UINT64 = 0x05
_VD_BOOL = 0x08
_VD_INT32 = 0x0C
_VD_INT64 = 0x0D
_VD_STRING = 0x18
_VD_BYTES = 0x42

#: The KeePass epoch for KDBX4 timestamps: seconds since 0001-01-01T00:00:00Z,
#: little-endian uint64, base64. KDBX3 writes ISO-8601 text instead, which is
#: why `upgrade_to_kdbx4()` has to rewrite every Times element.
_KP_EPOCH = _dt.datetime(1, 1, 1, tzinfo=_dt.timezone.utc)

#: Entry string fields KeePass reserves. A "custom field" is anything else.
_RESERVED_FIELDS = frozenset(
    ("Title", "UserName", "Password", "URL", "Notes", "Tags", "IconID",
     "Times", "History", "otp")
)

#: reveal() field name -> KDBX string key, for the built-in fields. Anything not
#: in here is looked up as a custom string field.
_BUILTIN_FIELDS = {
    "title": "Title",
    "username": "UserName",
    "password": "Password",
    "url": "URL",
    "notes": "Notes",
    "otp": "otp",
    "totp-seed": "otp",
}

#: KeePass 2.x (not KeePassXC) stores OTP configuration in these custom fields.
_TIMEOTP_SECRET_FIELDS = ("TimeOtp-Secret-Base32", "TimeOtp-Secret-Hex",
                          "TimeOtp-Secret-Base64", "TimeOtp-Secret")
_HMACOTP_SECRET_FIELDS = ("HmacOtp-Secret-Base32", "HmacOtp-Secret-Hex",
                          "HmacOtp-Secret-Base64", "HmacOtp-Secret")

#: The same sentence for a wrong passphrase and for a failed MAC. Having ONE
#: constant is how the rule survives editing: two call sites that each write
#: their own message drift, and the drift is the oracle (I6).
_BAD_CRED = ("the passphrase, key file or file integrity check did not match "
             "this safe")

#: Ratio guard floor. `Limits.MAX_DECOMPRESS_RATIO` is meaningless on a small
#: payload — a 700-byte gzip of a blank database legitimately expands past 200x
#: relative to nothing much. A real compression bomb is large by construction,
#: so the ratio test only starts once the output is big enough for the ratio to
#: mean something. The absolute `MAX_INNER_BYTES` cap applies at every size.
_RATIO_FLOOR_BYTES = 1024 * 1024


# ===========================================================================
# 1. XML and decompression hardening, by interposition  (I8)
# ===========================================================================
#
# The decrypted inner payload is XML and the key file may be XML. Both are
# attacker-shaped: the inner XML is only "ours" AFTER the MAC verifies, and the
# key file arrives from the request. pykeepass parses both with
# `etree.XMLParser(remove_blank_text=True)` / `etree.fromstring()` — library
# defaults — from inside `construct` adapters we do not own and must not edit.
#
# Measured on this host (lxml 6.0.2 / libxml2 2.15.2), the default parser DOES
# expand internal entities: a five-level "billion laughs" comes back as 3000
# characters of payload from 400 bytes of source. libxml2's own amplification
# limit catches the *large* case today; that is a library default, it has moved
# between releases, and docs/KNOWN_ISSUES.md I8 says in as many words not to
# rely on one. So we interpose.

def _hardened_parser(**kwargs):
    """An `lxml` parser with every hostile-XML feature explicitly OFF (I8).

    Every flag is named even where it matches today's default, because the
    point of I8 is that a default is not a decision. `resolve_entities=False`
    is the one that actually stops billion-laughs; the DTD/network flags stop
    XXE and SSRF; `huge_tree=False` keeps libxml2's own depth and amplification
    limits switched on.
    """
    kwargs.pop("resolve_entities", None)
    kwargs.pop("no_network", None)
    kwargs.pop("load_dtd", None)
    kwargs.pop("huge_tree", None)
    kwargs.pop("dtd_validation", None)
    kwargs.pop("recover", None)
    return etree.XMLParser(
        resolve_entities=False,   # billion laughs / quadratic blowup (I8)
        no_network=True,          # no SSRF out of a parsed document
        load_dtd=False,           # no external subset, no default attributes
        dtd_validation=False,
        huge_tree=False,          # keep libxml2's depth + amplification limits
        recover=False,            # a malformed document is an error, not a guess
        **kwargs
    )


def _reject_hostile_xml(root, what):
    """Refuse a parsed document that carries a DTD or any entity reference.

    `resolve_entities=False` stops the *expansion*; it leaves the entity
    references in the tree as `_Entity` nodes, so a document that tried is still
    a document that tried. Neither a KDBX inner payload nor a KeePass key file
    has any legitimate use for a DOCTYPE, so the presence of one is by itself
    sufficient grounds — and refusing on structure means our refusal does not
    depend on whichever amplification limit libxml2 ships this month.

    Raises `Invalid`, never `BadCredential`: the file authenticated, it is the
    *shape* we are rejecting, and saying so leaks nothing about the passphrase.
    """
    tree = root.getroottree() if hasattr(root, "getroottree") else root
    docinfo = getattr(tree, "docinfo", None)
    if docinfo is not None:
        if docinfo.internalDTD is not None or docinfo.externalDTD is not None:
            raise Invalid("%s declares a DTD; refused (I8)" % what)
    # An entity reference survives as an entity node under
    # `resolve_entities=False`. The test is `node.tag is etree.Entity` — the
    # PUBLIC factory object lxml stamps on those nodes — rather than
    # `isinstance(node, etree._Entity)`, because a private class name is
    # exactly the kind of thing that gets renamed and would turn this refusal
    # into an AttributeError at the worst possible moment. iter() over the
    # whole tree is bounded by huge_tree=False.
    entity_tag = getattr(etree, "Entity", None)
    for node in tree.iter():
        if entity_tag is not None and node.tag is entity_tag:
            raise Invalid("%s contains an XML entity reference; refused (I8)"
                          % what)
    return root


def _parse_xml_hardened(data, what="XML document"):
    """Parse bytes with the hardened parser and the structural refusal.

    Returns an `lxml` ElementTree (what `etree.parse` returns), because that is
    what pykeepass stores as the payload and later calls `.xpath()` on.
    """
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise Invalid("%s is not bytes" % what)
    # The inner payload is already bounded by _bounded_decompress and by
    # MAX_SAFE_BYTES; this catches the uncompressed case (I7).
    if len(data) > Limits.MAX_INNER_BYTES:
        raise Invalid("%s is %d bytes, over the %d byte limit"
                      % (what, len(data), Limits.MAX_INNER_BYTES))
    try:
        tree = etree.parse(io.BytesIO(data), _hardened_parser(
            remove_blank_text=True))
    except etree.XMLSyntaxError as exc:
        # lxml's message can quote the offending document. Do not pass it on —
        # after decryption that document is the safe's contents (I15).
        raise Invalid("%s is not well-formed XML (line %s)"
                      % (what, getattr(exc, "lineno", "?")))
    _reject_hostile_xml(tree.getroot(), what)
    return tree


def _bounded_decompress(data, wbits):
    """gzip/zlib inflate with an absolute cap and a ratio guard (I7, I8).

    pykeepass calls `zlib.decompress(data, 16 + 15)`, which has no upper bound:
    a few KiB of crafted gzip expands until the allocator gives up, and on the
    admin path the allocator belongs to root. `decompressobj(...).decompress(
    data, max_length)` stops at the cap and leaves the rest in
    `unconsumed_tail`, so "too big" is detected instead of attempted.
    """
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    obj = zlib.decompressobj(wbits)
    try:
        out = obj.decompress(data, Limits.MAX_INNER_BYTES)
        if obj.unconsumed_tail or not obj.eof:
            raise Invalid("compressed payload expands past the %d byte limit"
                          % Limits.MAX_INNER_BYTES)
        out += obj.flush()
    except zlib.error:
        raise Invalid("the compressed payload is corrupt")
    if len(out) > Limits.MAX_INNER_BYTES:
        raise Invalid("compressed payload expands past the %d byte limit"
                      % Limits.MAX_INNER_BYTES)
    if (len(out) > _RATIO_FLOOR_BYTES
            and len(out) > Limits.MAX_DECOMPRESS_RATIO * max(1, len(data))):
        raise Invalid("compressed payload expansion ratio %d:1 is over the "
                      "%d:1 limit" % (len(out) // max(1, len(data)),
                                      Limits.MAX_DECOMPRESS_RATIO))
    return out


class _HardenedEtree:
    """A module-shaped proxy for `lxml.etree`, installed inside pykeepass.

    Only the three entry points that turn *bytes we did not write* into a tree
    are overridden — `XMLParser`, `parse`, `fromstring`. Everything else
    (`tostring`, `Element`, `XMLSyntaxError`, ...) is the real module, reached
    through `__getattr__`, so pykeepass's serialisation and its `except
    etree.XMLSyntaxError` clauses keep working unchanged.
    """

    __slots__ = ("_etree",)

    def __init__(self, real):
        self._etree = real

    def __getattr__(self, name):
        return getattr(self._etree, name)

    def __repr__(self):
        return "<hardened lxml.etree proxy (cockpit-secrets I8)>"

    def XMLParser(self, **kwargs):                          # noqa: N802
        """Hand back OUR parser whatever flags the caller asked for."""
        return _hardened_parser(**kwargs)

    def parse(self, source, parser=None, base_url=None):
        """pykeepass calls this on the decrypted inner payload."""
        if hasattr(source, "read"):
            data = source.read()
        elif isinstance(source, (bytes, bytearray, memoryview)):
            data = bytes(source)
        else:
            # A filename would mean something is reading a path we did not
            # validate. Nothing in our call graph does that; refuse rather than
            # quietly open it (I4).
            raise Invalid("hardened XML parser refuses to open a path")
        return _parse_xml_hardened(data, "the decrypted inner payload")

    def fromstring(self, text, parser=None, base_url=None):
        """pykeepass calls this on key-file bytes. Returns the ROOT element."""
        if isinstance(text, str):
            text = text.encode("utf-8", "surrogatepass")
        return _parse_xml_hardened(bytes(text), "the key file").getroot()


class _BoundedZlib:
    """A module-shaped proxy for `zlib` that bounds `decompress` (I7)."""

    __slots__ = ("_zlib",)

    def __init__(self, real):
        self._zlib = real

    def __getattr__(self, name):
        return getattr(self._zlib, name)

    def __repr__(self):
        return "<bounded zlib proxy (cockpit-secrets I7)>"

    def decompress(self, data, wbits=zlib.MAX_WBITS, bufsize=None):
        return _bounded_decompress(data, wbits)


#: One-shot install flag. The canary below is what makes it meaningful.
_HARDENED = False

#: A document a DEFAULT lxml parser expands happily (measured: 3000 characters
#: out of 400 bytes in) and a hardened one must refuse. Small enough to sit far
#: below libxml2's own amplification limit, so if this is refused it is refused
#: by US.
_CANARY = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE d [\n'
    b' <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">\n'
    b' <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
    b' <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
    b']>\n<d>&c;</d>'
)


def _install_xml_hardening():
    """Interpose the hardened parser and bounded inflate inside pykeepass.

    Idempotent. FAIL CLOSED: if the proxies cannot be installed, or the canary
    is NOT refused after installing them, this raises `Internal` and the caller
    never gets as far as parsing an attacker's XML with a default parser.

    Why interposition rather than "pass a parser": pykeepass constructs its
    parser inside `construct` Adapter subclasses instantiated at import time,
    several layers below any argument we control. Rebinding the module-global
    name those adapters resolve is the only hook that reaches every parse point
    — the inner payload in `kdbx_parsing.common.XML._decode`, the key file in
    `kdbx_parsing.common.compute_key_composite`, and the KDBX3 attachment
    inflate in `pykeepass.pykeepass.binaries`.
    """
    global _HARDENED
    if _HARDENED:
        return
    try:
        if not isinstance(_pk_common.etree, _HardenedEtree):
            _pk_common.etree = _HardenedEtree(_pk_common.etree)
        if not isinstance(_pk_common.zlib, _BoundedZlib):
            _pk_common.zlib = _BoundedZlib(_pk_common.zlib)
        # KDBX3 keeps attachments as base64 gzip in Meta/Binaries and inflates
        # them in the top-level module, which imports its own `zlib`.
        if not isinstance(_pk_top.zlib, _BoundedZlib):
            _pk_top.zlib = _BoundedZlib(_pk_top.zlib)
    except Exception:
        raise Internal("the XML hardening could not be installed")

    # The canary: prove the thing we just installed actually refuses. An
    # assertion that the flag is set would only prove we set a flag.
    try:
        _pk_common.etree.parse(io.BytesIO(_CANARY))
    except Invalid:
        _HARDENED = True
        return
    except Exception:
        raise Internal("the XML hardening self-check failed unexpectedly")
    raise Internal("the XML hardening self-check did not refuse a hostile "
                   "document; refusing to parse untrusted XML")


# Installed at import. Reaching this line means a KDBX safe is in play, and no
# parse can precede it, so there is no window in which the default parser is
# live. A failure here fails the import, which `secrets-admin` reports as an
# unsupported format rather than silently proceeding unhardened.
_install_xml_hardening()


# ===========================================================================
# 2. the raw KDBX header reader  (I7)
# ===========================================================================
#
# This exists because `PyKeePass(...)` derives the key in its constructor. Any
# parameter clamp that runs on a PyKeePass object runs after the damage. So we
# read the header ourselves, from bytes already in memory, with no allocation
# driven by a declared length, and clamp before anything expensive happens.

class KdbxHeader:
    """Everything the outer header says, and nothing derived from a key."""

    __slots__ = ("major", "minor", "fields", "raw", "end", "cipher",
                 "compressed", "kdf", "kdf_params", "master_seed",
                 "encryption_iv")

    def __init__(self):
        self.major = 0
        self.minor = 0
        self.fields = {}
        self.raw = b""          # header bytes, exactly as the HMAC covers them
        self.end = 0            # offset of the first byte after the header
        self.cipher = "unknown"
        self.compressed = False
        self.kdf = "unknown"    # "argon2d" | "argon2id" | "aes-kdf"
        self.kdf_params = {}
        self.master_seed = b""
        self.encryption_iv = b""

    @property
    def version(self):
        return "%d.%d" % (self.major, self.minor)

    @property
    def iterations(self):
        """The cost figure an operator recognises: Argon2 `t`, or AES rounds."""
        if self.kdf == "aes-kdf":
            return int(self.kdf_params.get("rounds", 0))
        return int(self.kdf_params.get("time", 0))


def _u16(data, off):
    if off + 2 > len(data):
        raise Invalid("the KDBX header is truncated")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off + 4 > len(data):
        raise Invalid("the KDBX header is truncated")
    return struct.unpack_from("<I", data, off)[0]


def _variant_dict(blob):
    """Parse a KDBX4 VariantDictionary (the KDF parameter block).

    Every length is bounds-checked against what actually remains before it is
    used as a slice bound — a declared 0xFFFFFFFF must cost O(1) to refuse, not
    an allocation attempt (bad practice #7, I7).
    """
    if len(blob) < 3:
        raise Invalid("the KDF parameter block is truncated")
    off = 2                                     # skip the version word
    out = {}
    while True:
        if off >= len(blob):
            raise Invalid("the KDF parameter block is truncated")
        vtype = blob[off]
        off += 1
        if vtype == 0x00:
            break
        klen = _u32(blob, off)
        off += 4
        Limits.check_length(klen, len(blob) - off, "KDF parameter name")
        key = blob[off:off + klen].decode("utf-8", "replace")
        off += klen
        vlen = _u32(blob, off)
        off += 4
        Limits.check_length(vlen, len(blob) - off, "KDF parameter value")
        raw = blob[off:off + vlen]
        off += vlen
        try:
            if vtype == _VD_UINT32:
                value = struct.unpack("<I", raw)[0]
            elif vtype == _VD_UINT64:
                value = struct.unpack("<Q", raw)[0]
            elif vtype == _VD_INT32:
                value = struct.unpack("<i", raw)[0]
            elif vtype == _VD_INT64:
                value = struct.unpack("<q", raw)[0]
            elif vtype == _VD_BOOL:
                value = bool(raw and raw[0])
            elif vtype == _VD_STRING:
                value = raw.decode("utf-8", "replace")
            else:
                value = raw
        except struct.error:
            raise Invalid("a KDF parameter has the wrong width for its type")
        if key in out:
            # Same reasoning as the duplicate header field: two values for `M`
            # and two implementations that disagree about which one counts.
            raise Invalid("the KDF parameter block repeats a key")
        out[key] = value
        if len(out) > 64:
            raise Invalid("the KDF parameter block has too many entries")
    return out


def _read_header(data):
    """Parse the outer header without deriving anything. Raises `Invalid`.

    `Invalid` and never `BadCredential`: a malformed header is a property of
    the file that anyone holding the file can already see, so naming it leaks
    nothing about the passphrase (docs/CONTRACT.md error taxonomy).
    """
    if len(data) < 12:
        raise Invalid("the file is too short to be a KDBX database")
    if not (constant_time_eq(data[0:4], KDBX_SIG1)
            and constant_time_eq(data[4:8], KDBX_SIG2)):
        raise Invalid("this file is not a KeePass database")
    hdr = KdbxHeader()
    hdr.minor, hdr.major = struct.unpack_from("<HH", data, 8)
    if hdr.major not in (3, 4):
        raise Unsupported("KDBX major version %d is not supported"
                          % hdr.major)

    # KDBX3 length prefixes are uint16, KDBX4 widened them to uint32.
    off = 12
    seen = 0
    while True:
        if off >= len(data):
            raise Invalid("the KDBX header is truncated")
        fid = data[off]
        off += 1
        if hdr.major >= 4:
            flen = _u32(data, off)
            off += 4
        else:
            flen = _u16(data, off)
            off += 2
        Limits.check_length(flen, len(data) - off, "KDBX header field")
        if fid in hdr.fields:
            # A duplicated header field is a parser differential waiting to
            # happen: we would take one copy and KeePass the other, from bytes
            # that produce the SAME header HMAC. Refuse rather than pick.
            raise Invalid("the KDBX header repeats field %d" % fid)
        hdr.fields[fid] = data[off:off + flen]
        off += flen
        seen += 1
        if fid == _H_END:
            break
        if seen > 32:
            raise Invalid("the KDBX header has too many fields")
    hdr.end = off
    hdr.raw = data[:off]

    cipher_uuid = hdr.fields.get(_H_CIPHER_ID, b"")
    hdr.cipher = _CIPHERS.get(bytes(cipher_uuid), "unknown")
    if hdr.cipher == "unknown":
        raise Unsupported("this database uses an unrecognised cipher")

    comp = hdr.fields.get(_H_COMPRESSION, b"\x00\x00\x00\x00")
    if len(comp) < 4:
        raise Invalid("the compression flag field is malformed")
    hdr.compressed = struct.unpack("<I", bytes(comp[:4]))[0] != 0

    hdr.master_seed = bytes(hdr.fields.get(_H_MASTER_SEED, b""))
    if len(hdr.master_seed) != 32:
        raise Invalid("the master seed field is malformed")
    hdr.encryption_iv = bytes(hdr.fields.get(_H_ENCRYPTION_IV, b""))
    if not hdr.encryption_iv:
        raise Invalid("the encryption IV field is missing")

    if hdr.major >= 4:
        vd = _variant_dict(hdr.fields.get(_H_KDF_PARAMETERS, b""))
        uuid = bytes(vd.get("$UUID", b""))
        if constant_time_eq(uuid, _KDF_ARGON2ID):
            hdr.kdf = "argon2id"
        elif constant_time_eq(uuid, _KDF_ARGON2D):
            hdr.kdf = "argon2d"
        elif constant_time_eq(uuid, _KDF_AESKDF):
            hdr.kdf = "aes-kdf"
        else:
            raise Unsupported("this database uses an unrecognised key "
                              "derivation function")
        if hdr.kdf.startswith("argon2"):
            hdr.kdf_params = {
                "salt": bytes(vd.get("S", b"")),
                "time": vd.get("I"),
                "memory_kib": (vd.get("M") // 1024
                               if isinstance(vd.get("M"), int) else None),
                "parallelism": vd.get("P"),
                "argon_version": vd.get("V", 0x13),
            }
        else:
            hdr.kdf_params = {"salt": bytes(vd.get("S", b"")),
                              "rounds": vd.get("R")}
    else:
        # KDBX 3.x always AES-KDF, with the seed and round count as their own
        # header fields.
        hdr.kdf = "aes-kdf"
        rounds = hdr.fields.get(_H_TRANSFORM_ROUNDS, b"")
        if len(rounds) != 8:
            raise Invalid("the transform-rounds field is malformed")
        hdr.kdf_params = {
            "salt": bytes(hdr.fields.get(_H_TRANSFORM_SEED, b"")),
            "rounds": struct.unpack("<Q", bytes(rounds))[0],
        }
        for need, what in ((_H_STREAM_START_BYTES, "stream start bytes"),
                           (_H_PROTECTED_STREAM_KEY, "protected stream key")):
            if need not in hdr.fields:
                raise Invalid("the %s field is missing" % what)
    return hdr


def _clamp_kdf(hdr):
    """Range-check the file's KDF request BEFORE any derivation runs (I7).

    This is the whole point of `_read_header`: a file that asks for
    `m=4 GiB, t=1000000` gets refused here, in microseconds, instead of being
    honoured by argon2-cffi inside `PyKeePass.__init__`.
    """
    p = hdr.kdf_params
    if hdr.kdf.startswith("argon2"):
        if len(p.get("salt") or b"") not in range(8, 65):
            raise Invalid("the Argon2 salt has an implausible length")
        Limits.check_argon2(p.get("memory_kib"), p.get("time"),
                            p.get("parallelism"))
        if p.get("argon_version") not in (0x10, 0x13):
            raise Invalid("unsupported Argon2 version in the header")
    else:
        if len(p.get("salt") or b"") != 32:
            raise Invalid("the AES-KDF transform seed has the wrong length")
        Limits.check_aeskdf_rounds(p.get("rounds"))


# ===========================================================================
# 3. credentials — composite key and key derivation
# ===========================================================================

def _keyfile_composite(keyfile):
    """The 32-byte contribution a KeePass key file makes to the composite key.

    Handles both KeePass 2.x forms and the raw fallbacks, in the order KeePass
    itself uses:

      * XML key file, `<Meta><Version>1.0`  — base64 in `Key/Data`
      * XML key file, `<Meta><Version>2.0`  — hex in `Key/Data`, with the first
        four bytes of its SHA-256 in the `Hash` attribute
      * exactly 32 raw bytes                — used as the key directly
      * exactly 64 hex characters           — decoded to 32 bytes
      * anything else                       — SHA-256 of the whole file

    The v2.0 hash is compared with `constant_time_eq`. pykeepass compares it
    with `assert hash == hash_computed`, which is a plain `==` AND vanishes
    under `python3 -O`; we never reach that code because we hand pykeepass a
    transformed key rather than a key file, but the check still has to happen,
    so it happens here.
    """
    raw = bytes(keyfile.bytes)
    if len(raw) > Limits.MAX_KEYFILE_BYTES:
        raise Invalid("the key file is larger than the %d byte limit"
                      % Limits.MAX_KEYFILE_BYTES)
    if not raw:
        raise Invalid("the key file is empty")

    # Try the XML forms first, exactly as KeePass does. The parse goes through
    # the hardened parser: a key file is caller-supplied bytes and is every bit
    # as hostile as the inner payload (I8).
    try:
        root = _parse_xml_hardened(raw, "the key file").getroot()
    except Invalid:
        root = None
    if root is not None and root.tag == "KeyFile":
        version = (root.findtext("Meta/Version") or "").strip()
        data_el = root.find("Key/Data")
        if data_el is None or data_el.text is None:
            raise Invalid("the XML key file has no Key/Data element")
        text = data_el.text
        if version.startswith("1.0"):
            try:
                composite = base64.b64decode(text.strip(), validate=True)
            except (binascii.Error, ValueError):
                raise Invalid("the XML key file's data is not valid base64")
            if len(composite) != 32:
                raise Invalid("the XML key file's data is not 32 bytes")
            return composite
        if version.startswith("2.0"):
            hexed = re.sub(r"\s+", "", text)
            try:
                composite = bytes.fromhex(hexed)
            except ValueError:
                raise Invalid("the XML key file's data is not valid hex")
            want = (data_el.attrib.get("Hash") or "").strip()
            try:
                want_bytes = bytes.fromhex(want)
            except ValueError:
                raise Invalid("the XML key file's Hash attribute is not hex")
            got = hashlib.sha256(composite).digest()[:4]
            if not constant_time_eq(want_bytes, got):     # I6
                raise Invalid("the XML key file failed its own integrity check")
            return composite
        raise Unsupported("XML key file version %s is not supported"
                          % (version[:8] or "?"))

    # Not XML: the historical raw forms.
    if len(raw) == 32:
        return raw
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
    return hashlib.sha256(raw).digest()


def _composite_key(password, keyfile):
    """SHA-256(SHA-256(passphrase) || keyfile_composite) — KeePass's rule.

    `password` is a `Secret`, so this reads the wipeable `bytearray` directly.
    `Secret.str_view()` is deliberately never called anywhere in this module:
    KDBX needs the passphrase only as UTF-8 bytes to hash, so there is no
    reason to mint an unwipeable `str` from it (I14).
    """
    parts = b""
    if password is not None:
        if password.zeroed:
            raise Internal("the passphrase buffer was already zeroed")
        parts += hashlib.sha256(bytes(password.bytes)).digest()
    if keyfile is not None:
        if keyfile.zeroed:
            raise Internal("the key file buffer was already zeroed")
        parts += _keyfile_composite(keyfile)
    if not parts:
        raise BadCredential(_BAD_CRED)
    return hashlib.sha256(parts).digest()


def _aes_kdf(seed, rounds, composite):
    """KeePass's AES-KDF: `rounds` ECB passes over the composite, then SHA-256.

    Sequential by construction — each round's output is the next round's input —
    so there is no way to make this cheaper than the round count, which is
    exactly why `Limits.check_aeskdf_rounds` has to have run first. A KDBX3
    written by keepassxc-cli on this host asks for 12 000 000 rounds and takes
    about eight seconds; `AESKDF_MAX_ROUNDS` (1e8) is the point past which we
    refuse rather than let a file park a helper.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    encryptor = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    buf = bytes(composite)
    for _ in range(rounds):
        buf = encryptor.update(buf)
    return hashlib.sha256(buf).digest()


def _derive(hdr, composite):
    """Run the file's KDF, clamped and time-budgeted. Returns 32 bytes.

    `Limits.kdf_budget()` cannot interrupt the C call — base.py says so and it
    is true — so this is the backstop that turns "the channel hung" into a typed
    error. The prevention is `_clamp_kdf`, which has already run.
    """
    import argon2
    p = hdr.kdf_params
    with Limits.kdf_budget():
        if hdr.kdf.startswith("argon2"):
            try:
                return argon2.low_level.hash_secret_raw(
                    secret=composite,
                    salt=p["salt"],
                    hash_len=32,
                    type=(argon2.low_level.Type.ID if hdr.kdf == "argon2id"
                          else argon2.low_level.Type.D),
                    time_cost=p["time"],
                    memory_cost=p["memory_kib"],
                    parallelism=p["parallelism"],
                    version=p["argon_version"],
                )
            except argon2.exceptions.Argon2Error:
                # argon2-cffi's message can quote the parameters; it never sees
                # the passphrase, but there is no reason to forward it (I15).
                raise Invalid("the Argon2 parameters in this file were "
                              "rejected by the key derivation function")
        return _aes_kdf(p["salt"], p["rounds"], composite)


# ===========================================================================
# 4. MAC verification — nothing decrypted escapes before this passes  (I6)
# ===========================================================================

def _hmac_base_key(master_seed, transformed_key):
    """SHA-512(master_seed || transformed_key || 0x01) — the KDBX4 HMAC root."""
    return hashlib.sha512(master_seed + transformed_key + b"\x01").digest()


def _block_hmac_key(base, index):
    """Per-block key: SHA-512(index_LE64 || base). Index 0xFFFFFFFFFFFFFFFF is
    the header's."""
    return hashlib.sha512(struct.pack("<Q", index) + base).digest()


def _verify_kdbx4(data, hdr, transformed_key):
    """Authenticate a KDBX4 file end to end. Returns the number of payload bytes.

    Order matters and is the order KeePass specifies:

      1. SHA-256 over the header — `Invalid`, because it is credential-
         independent: it fails identically for every passphrase, so reporting
         it separately is not an oracle.
      2. HMAC-SHA-256 over the header under the derived key — `BadCredential`.
         This is the first check a wrong passphrase fails.
      3. HMAC-SHA-256 over every payload block, BEFORE any of it is decrypted —
         `BadCredential`. This is what makes "verify before use" real for
         KDBX4: a flipped ciphertext byte is caught here, with no plaintext
         anywhere.

    Every comparison is `constant_time_eq` (`hmac.compare_digest`).
    """
    end = hdr.end
    if len(data) < end + 64:
        raise Invalid("the KDBX file is truncated before its header hashes")
    stored_sha = data[end:end + 32]
    stored_hmac = data[end + 32:end + 64]

    if not constant_time_eq(hashlib.sha256(hdr.raw).digest(), stored_sha):
        raise Invalid("the KDBX header hash does not match the header")

    base = _hmac_base_key(hdr.master_seed, transformed_key)
    header_key = _block_hmac_key(base, 0xFFFFFFFFFFFFFFFF)
    calc = hmac.new(header_key, hdr.raw, hashlib.sha256).digest()
    if not constant_time_eq(calc, stored_hmac):
        raise BadCredential(_BAD_CRED)

    # Payload blocks: hmac(32) | length(uint32 LE) | data. A zero-length block
    # terminates the stream. Everything is bounds-checked before it is sliced.
    off = end + 64
    index = 0
    total = 0
    while True:
        if off + 36 > len(data):
            raise Invalid("the KDBX payload is truncated")
        block_mac = data[off:off + 32]
        blen = struct.unpack_from("<I", data, off + 32)[0]
        Limits.check_length(blen, len(data) - (off + 36), "KDBX payload block")
        block = data[off + 36:off + 36 + blen]
        key = _block_hmac_key(base, index)
        calc = hmac.new(
            key,
            struct.pack("<Q", index) + struct.pack("<I", blen) + block,
            hashlib.sha256).digest()
        if not constant_time_eq(calc, block_mac):
            raise BadCredential(_BAD_CRED)
        off += 36 + blen
        total += blen
        index += 1
        if blen == 0:
            break
        if index > 1 + (Limits.MAX_SAFE_BYTES // 1024):
            raise Invalid("the KDBX payload has an implausible block count")
    return total


def _decrypt_prefix(hdr, master_key, blob, nbytes):
    """Decrypt the first `nbytes` of a KDBX3 payload — for the credential check.

    KDBX3 has no MAC (that is I20 in one sentence), so the only thing that says
    "this passphrase is right" is the 32 known plaintext bytes the header calls
    `stream_start_bytes`. We decrypt exactly those and compare them constant-
    time, rather than letting `construct.Checksum`'s `!=` be the deciding
    comparison.
    """
    want = ((nbytes + 15) // 16) * 16
    chunk = bytes(blob[:want])
    if len(chunk) < want:
        raise Invalid("the KDBX3 payload is truncated")
    if hdr.cipher == "aes256":
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        dec = Cipher(algorithms.AES(master_key),
                     modes.CBC(hdr.encryption_iv)).decryptor()
        return dec.update(chunk)[:nbytes]
    if hdr.cipher == "chacha20":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        # KeePass names a 12-byte nonce and starts the block counter at zero;
        # `cryptography` wants the 16-byte counter||nonce form.
        dec = Cipher(algorithms.ChaCha20(master_key,
                                         b"\x00" * 4 + hdr.encryption_iv),
                     None).decryptor()
        return dec.update(chunk)[:nbytes]
    if hdr.cipher == "twofish":
        # Lazily imported so a KDBX unlock does not drag in Botan for the 99%
        # of databases that are AES or ChaCha20 (backends/__init__.py).
        # HOST-FACTS.md: Botan's SymmetricCipher has no Twofish; BlockCipher
        # does, as a raw ECB primitive, so CBC is composed here by hand.
        try:
            import botan3 as botan
        except ImportError:
            raise Unsupported("KDBX3 databases encrypted with Twofish need "
                              "python3-botan")
        bc = botan.BlockCipher("Twofish")
        bc.set_key(master_key)
        out = bytearray()
        prev = hdr.encryption_iv
        for i in range(0, want, 16):
            ct = chunk[i:i + 16]
            pt = bc.decrypt(ct)
            out += bytes(a ^ b for a, b in zip(pt, prev))
            prev = ct
        return bytes(out[:nbytes])
    raise Unsupported("this database uses an unrecognised cipher")


def _verify_kdbx3(data, hdr, transformed_key):
    """The KDBX3 credential check: decrypt 32 bytes, compare constant-time.

    This is NOT authentication and this module never claims it is. It proves
    the passphrase; it proves nothing about whether the rest of the file was
    tampered with, because KDBX 3.1's per-block digests are unkeyed SHA-256
    that any writer can recompute. That is exactly why KDBX3 opens read-only
    with a banner (I20).
    """
    master_key = hashlib.sha256(hdr.master_seed + transformed_key).digest()
    start = bytes(hdr.fields.get(_H_STREAM_START_BYTES, b""))
    if len(start) != 32:
        raise Invalid("the stream-start-bytes field is malformed")
    got = _decrypt_prefix(hdr, master_key, data[hdr.end:], 32)
    if not constant_time_eq(got, start):
        raise BadCredential(_BAD_CRED)


# ===========================================================================
# 5. small helpers
# ===========================================================================

def _iso(value):
    """A datetime as ISO-8601 UTC, or None. Never raises on a broken time."""
    if value is None:
        return None
    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    except (AttributeError, ValueError, OverflowError):
        return None


def _parse_iso(text, what="time"):
    """ISO-8601 (with or without a trailing Z) to an aware UTC datetime."""
    if isinstance(text, _dt.datetime):
        value = text
    else:
        try:
            value = _dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise Invalid("%s is not a valid ISO-8601 timestamp" % what)
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def _check_text(value, what):
    """Bound one field's size before it is stored (I7)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise Invalid("%s must be a string" % what)
    if len(value.encode("utf-8", "surrogatepass")) > Limits.MAX_FIELD_BYTES:
        raise Invalid("%s is larger than the %d byte limit"
                      % (what, Limits.MAX_FIELD_BYTES))
    return value


def _entry_field_keys(entry):
    """Every String/Key name on an entry, in document order.

    Read straight off the element rather than through
    `Entry.custom_properties`, which silently drops the reserved names — we
    need the built-ins listed too, by NAME, so the UI can offer `reveal` on
    them without `entries()` ever carrying a value.
    """
    names = []
    for string_el in entry._element.findall("String"):
        key_el = string_el.find("Key")
        if key_el is not None and key_el.text is not None:
            names.append(key_el.text)
    return names


def _field_element(entry, key):
    """The `<String>` element whose `<Key>` text is exactly `key`, or None.

    THIS IS A SECURITY FIX, not a style preference. pykeepass's
    `Entry._get_string_field()` builds its query by formatting the name into
    `String/Key[text()="{}"]/../Value` and handing it to `lxml`'s XPath engine.
    `reveal(uuid, field)` takes that name straight from the request, so a field
    name containing a double quote closes the literal and the remainder is
    XPath — measured on this host, `reveal(uuid, 'zzz"]/../Value | //Value[
    @Protected="True')` returned another field's protected value, and a merely
    malformed name raised `XPathEvalError` straight out of a verb, which is an
    untyped exception the taxonomy exists to prevent.

    Comparing element text in Python has neither problem, needs no escaping
    scheme to get right, and cannot be re-broken by a future edit.
    """
    for string_el in entry._element.findall("String"):
        key_el = string_el.find("Key")
        if key_el is not None and key_el.text == key:
            return string_el
    return None


def _field_value(entry, key):
    """One string field's text, or None when the field is absent."""
    string_el = _field_element(entry, key)
    if string_el is None:
        return None
    value_el = string_el.find("Value")
    if value_el is None:
        return None
    # KeePass writes an empty field as <Value/>, whose .text is None. "present
    # but empty" and "absent" are different answers to reveal().
    return value_el.text if value_el.text is not None else ""


def _field_protected(entry, key):
    """Whether a string field is marked protected. False when it is absent."""
    string_el = _field_element(entry, key)
    if string_el is None:
        return False
    value_el = string_el.find("Value")
    if value_el is None:
        return False
    # `Protected="True"` exactly: that literal is what pykeepass's stream
    # cipher adapter matches on when it re-encrypts protected values at build
    # time, so anything else means the value goes to disk in the clear.
    return value_el.get("Protected") == "True"


def _set_field(entry, key, value, protect):
    """Create or replace one string field, keeping the document tidy.

    Position matters enough to bother with: KeePass's own schema is a sequence
    of `String` elements followed by `History`, and appending to the end of the
    entry would gradually shuffle new fields past the history block. Readers on
    this host do not care, but writing XML that only lenient readers accept is
    how a file stops being portable one small step at a time.
    """
    string_el = etree.Element("String")
    key_el = etree.SubElement(string_el, "Key")
    key_el.text = key
    value_el = etree.SubElement(string_el, "Value")
    value_el.text = value if value is not None else ""
    if protect:
        value_el.set("Protected", "True")

    old = _field_element(entry, key)
    if old is not None:
        old.addprevious(string_el)          # replace in place
        entry._element.remove(old)
        return
    existing = entry._element.findall("String")
    if existing:
        existing[-1].addnext(string_el)
        return
    history = entry._element.find("History")
    if history is not None:
        history.addprevious(string_el)
    else:
        entry._element.append(string_el)


def _del_field(entry, key):
    """Remove one string field. Returns True when there was one."""
    old = _field_element(entry, key)
    if old is None:
        return False
    entry._element.remove(old)
    return True


def _attachment_bytes(attachment, strict=True):
    """One attachment's bytes, tolerating a dangling pool reference.

    An entry's `Binary/Value/@Ref` is an index into a shared pool, and a
    hostile — or merely mangled — file can point one at a slot that is not
    there. pykeepass answers that with an `IndexError`, which would leave a
    verb raising an untyped exception; `strict=False` is for the listing paths,
    where one broken reference must not make the whole entry unreadable.
    """
    try:
        return attachment.binary or b""
    except (IndexError, KeyError, TypeError, ValueError):
        if strict:
            raise Invalid("this attachment points at a binary that is not in "
                          "the database")
        return b""


def _otp_config(entry):
    """What OTP configuration an entry carries, or None. NEVER the seed.

    Two dialects have to be understood because both are in the wild:

      * KeePassXC writes a single `otp` string — either a full `otpauth://`
        URI or the legacy `key=SEED&step=30&size=6` form.
      * KeePass 2.x writes `TimeOtp-*` / `HmacOtp-*` custom fields.

    The return value carries the *kind* only; `totp()` re-reads the secret at
    the moment it needs it, so nothing here can accidentally end up in
    `entries()` output.
    """
    if _field_value(entry, "otp"):
        return "otp"
    for name in _TIMEOTP_SECRET_FIELDS:
        if _field_value(entry, name):
            return "timeotp"
    for name in _HMACOTP_SECRET_FIELDS:
        if _field_value(entry, name):
            return "hmacotp"
    return None


def _b32(secret_text, encoding):
    """Normalise an OTP seed to base32, which is what pyotp wants."""
    text = re.sub(r"\s+", "", secret_text or "")
    if encoding == "base32":
        pad = "=" * (-len(text) % 8)
        try:
            base64.b32decode(text.upper() + pad, casefold=True)
        except (binascii.Error, ValueError):
            raise Invalid("the stored OTP secret is not valid base32")
        return text.upper() + pad
    if encoding == "hex":
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise Invalid("the stored OTP secret is not valid hex")
    elif encoding == "base64":
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raise Invalid("the stored OTP secret is not valid base64")
    else:
        raw = text.encode("utf-8", "surrogatepass")
    return base64.b32encode(raw).decode("ascii")


# ===========================================================================
# 6. the adapter
# ===========================================================================

@register_backend("kdbx")
class KdbxBackend(Backend):
    """One KDBX safe, one short-lived process. See `backends.base.Backend`.

    Lifecycle, and the order is the contract:

        b = KdbxBackend(entry)          # entry is a VALIDATED registry entry
        b.probe()                       # header only, no credential
        b.unlock(pw, keyfile)           # clamp -> derive -> verify -> open
        ... reads and in-memory mutations ...
        b.save()                        # the only method that writes
        b.lock()
    """

    __slots__ = ("_kp", "_tk", "_header", "_data", "_index", "_group_index",
                 "_lossless", "_lossless_detail", "_dirty", "_format_ro")

    def __init__(self, entry):
        super().__init__(entry)
        self._kp = None              # the open PyKeePass, or None
        self._tk = None              # Secret: transformed key — see lock()
        self._header = None          # KdbxHeader from the last read
        self._data = None            # the file bytes read at unlock
        self._index = {}             # uuid str -> Entry
        self._group_index = {}       # uuid str -> Group
        self._lossless = None        # None = not yet checked (I22)
        self._lossless_detail = ""
        self._dirty = False
        self._format_ro = False      # True for KDBX3 (I20)

    # -- file access -------------------------------------------------------

    def _open(self, want_write=False):
        """Open the registry path under the I4/I5 guard.

        `expect_uid=None` means `os.geteuid()`, and that is right for BOTH
        access classes by construction: an admin safe is root-owned and the
        helper is euid 0, a user safe is owned by the caller and the helper is
        the caller. The helper has already refused the verb if those do not
        line up (docs/ARCHITECTURE.md, "Access classes, concretely").
        """
        return open_safe_fd(self.path, want_write=want_write)

    def _read(self, fingerprint=True):
        """Read the whole file and fingerprint it from the SAME fd (I5, I13).

        `fingerprint=False` for `probe()`: the fingerprint costs a SHA-256 over
        the whole file and exists only to be re-checked at save time, so a verb
        that will never write should not pay it on a 128 MiB safe.
        """
        with self._open() as sf:
            data = sf.read_all()
            fp = sf.fingerprint() if fingerprint else None
        return data, fp

    # -- probe -------------------------------------------------------------

    def probe(self):
        """Header metadata only. No credential, nothing key-derived (I6)."""
        data, _fp = self._read(fingerprint=False)
        hdr = _read_header(data)
        warnings = []
        writable = not self.readonly
        if hdr.major < 4:
            writable = False
            warnings.append(_KDBX3_WARNING)
        if hdr.major == 4 and hdr.minor > 1:
            warnings.append(
                "this database is KDBX %s, newer than the 4.1 this backend "
                "was written against; it is opened read-only until the "
                "round-trip check passes" % hdr.version)
        return {
            "format": "kdbx",
            "version": hdr.version,
            "kdf": hdr.kdf,
            "iterations": hdr.iterations,
            # The file cannot say whether a passphrase is required — nothing in
            # KDBX records that — so this is the REGISTRY's answer, which is the
            # only authority we have (I1).
            "needs_password": bool(self.entry.get("password_required", True)),
            "needs_keyfile": bool(self.entry.get("keyfile")),
            "writable": writable,
            "warnings": warnings,
        }

    # -- unlock ------------------------------------------------------------

    def unlock(self, password, keyfile=None, session=None):
        """Clamp, derive, verify, and only then open. Never zeroes `password`.

        The sequence below is the one docs/CONTRACT.md and the ABC both spell
        out, and every step is here because skipping it has a name:

          read -> header parse -> CLAMP (I7) -> composite -> derive (budgeted)
               -> VERIFY MAC constant-time (I6) -> open with the transformed
               key -> fingerprint from the same fd (I13) -> unlocked = True
        """
        _install_xml_hardening()                     # idempotent; fail closed
        if self.entry.get("yubikey_slot"):
            # Challenge-response needs a physical token on the host and a
            # different composite-key construction. Refusing loudly beats
            # opening the safe with a key that silently ignores the token.
            raise Unsupported("YubiKey challenge-response is not implemented; "
                              "clear yubikey_slot in the registry entry to "
                              "open this safe with a passphrase or key file")
        if password is None and self.entry.get("password_required", True):
            # The schema permits password_required:false only alongside a key
            # file, but a schema is not an enforcement point (I1).
            raise BadCredential(_BAD_CRED)

        data, fp = self._read()
        hdr = _read_header(data)
        _clamp_kdf(hdr)                              # I7 — BEFORE deriving

        composite = _composite_key(password, keyfile)
        try:
            transformed = _derive(hdr, composite)
        finally:
            # The composite is a key, not a passphrase, but it is still key
            # material this frame owns; do not leave it for the GC.
            composite = b"\x00" * 32

        warnings = []
        if hdr.major >= 4:
            _verify_kdbx4(data, hdr, transformed)    # I6 — MAC before use
        else:
            _verify_kdbx3(data, hdr, transformed)    # credential check only
            warnings.append(_KDBX3_WARNING)
            self._format_ro = True
        if hdr.major == 4 and hdr.minor > 1:
            warnings.append(
                "this database is KDBX %s; writes stay off until the "
                "round-trip check confirms nothing would be lost"
                % hdr.version)

        # Only now is it safe to let a parser near the plaintext. pykeepass
        # gets the transformed key and NOT the passphrase, so the master
        # passphrase never becomes an unwipeable `str` in this process (I14).
        try:
            kp = PyKeePass(io.BytesIO(data), transformed_key=transformed)
        except (Invalid, Unsupported):
            raise
        except Exception as exc:
            raise self._map_pykeepass_error(exc)

        self._kp = kp
        # Our retained copy of the transformed key lives in a Secret so that
        # `lock()` can actually overwrite it. See lock() for what that does and
        # does not buy (I14).
        self._tk = Secret(transformed)
        self._header = hdr
        self._data = data
        self.fingerprint = fp
        self._reindex()
        # Over-size is refused here rather than earlier because the counts are
        # only knowable once the payload is parsed. `lock()` — not a bare
        # `self._kp = None` — is what drops the transformed key with it: an
        # unlock that ends in a refusal must not leave key material behind.
        if len(self._index) > Limits.MAX_ENTRIES:
            self.lock()
            raise Invalid("this database declares more than %d entries"
                          % Limits.MAX_ENTRIES)
        if len(self._group_index) > Limits.MAX_GROUPS:
            self.lock()
            raise Invalid("this database declares more than %d groups"
                          % Limits.MAX_GROUPS)

        self.warnings = warnings
        self.handle = _sysrandom.token_hex(16)       # 128 bits, opaque
        self.unlocked = True
        return {
            "handle": self.handle,
            # In the default configuration the handle dies with this process,
            # so there is no clock to report: 0 means "as long as this
            # operation" (docs/ARCHITECTURE.md). A session or the opt-in agent
            # is the only thing that gives it a lifetime.
            # `or {}` and not a default: the schema allows "agent": null, and
            # `.get("agent", {})` returns None for that, not the default.
            "expires_in": int((self.entry.get("agent") or {}).get(
                "idle_seconds", 0)
                if (self.entry.get("agent") or {}).get("enabled") else 0),
            "entries_total": len(self._index),
            "groups_total": len(self._group_index),
            "warnings": list(self.warnings),
        }

    def _map_pykeepass_error(self, exc):
        """Turn a pykeepass/construct exception into our taxonomy, no traceback.

        Deliberately coarse. `construct.ChecksumError`'s message carries the
        computed digest in hex and a decrypted-payload path; none of that may
        reach a client (I15), so nothing from `exc` is forwarded — only its
        class decides the code.
        """
        name = type(exc).__name__
        if name in ("CredentialsError", "PayloadChecksumError", "ChecksumError"):
            return BadCredential(_BAD_CRED)
        if name in ("HeaderChecksumError", "CheckError", "StreamError",
                    "ConstructError", "RangeError", "MappingError",
                    "FormatFieldError", "StringError", "TerminatedError"):
            return Invalid("this database is malformed or truncated")
        if isinstance(exc, MemoryError):
            return Invalid("this database asked for more memory than the "
                           "helper is allowed")
        # The byte-level shapes. A truncated KDBX3 payload reaches PyCryptodome
        # as `ValueError("Data must be padded to 16 byte boundary in CBC
        # mode")`; struct/binascii raise their own on short or malformed input.
        # None of these means "our code is broken" — they mean "these bytes are
        # not a database", which is `invalid`. Reaching this function at all
        # means we are already inside a parse of a caller-supplied FILE, so
        # `internal` is reserved for classes we genuinely do not recognise.
        # MEASURED: without this, corpus case kdbx31-trunc-last-byte answered
        # {"error":"internal"}, which is outside the sidecar's taxonomy and
        # tells an operator nothing.
        if isinstance(exc, (ValueError, OverflowError, IndexError,
                            UnicodeDecodeError, struct.error, binascii.Error)):
            return Invalid("this database is malformed or truncated")
        return Internal("the KDBX engine could not open this database")

    # -- indexing ----------------------------------------------------------

    def _reindex(self):
        """Rebuild uuid -> object maps, bounded by `Limits`.

        We index rather than using `find_entries(uuid=...)` because the uuid
        xpath is a base64 string comparison built by string formatting; a map
        built once from `kp.entries` is both faster and has no formatting in
        the path a caller controls.
        """
        self._index = {}
        self._group_index = {}
        for entry in self._kp.entries:
            try:
                key = str(entry.uuid)
            except Exception:
                continue                    # an entry with no/broken UUID
            # A uuid IS the identity that reveal, edit, move and rm all address.
            # Two entries sharing one makes every one of those verbs ambiguous:
            # a dict silently keeps the last, so `rm <uuid>` deletes a row the
            # operator did not mean and `reveal <uuid>` hands back a different
            # entry's password. Refuse the database rather than pick a winner,
            # and do NOT de-duplicate — rewriting uuids on open is the I22 data
            # loss this project exists to avoid.
            # MEASURED: pykeepass opens tests/corpus/files/
            # kdbx41-xml-duplicate-uuid.kdbx without complaint, and
            # keepassxc-cli 2.7.10 hangs on it for over a minute, so there is no
            # foreign backstop for this one at all.
            if key in self._index:
                raise Invalid("two entries in this database share the uuid "
                              "that every edit and delete addresses; refusing "
                              "to open it")
            self._index[key] = entry
            if len(self._index) > Limits.MAX_ENTRIES:
                break
        for group in self._kp.groups:
            try:
                key = str(group.uuid)
            except Exception:
                continue
            if key in self._group_index:
                raise Invalid("two groups in this database share the uuid "
                              "that every move addresses; refusing to open it")
            self._group_index[key] = group
            if len(self._group_index) > Limits.MAX_GROUPS:
                break

    def _entry(self, uuid):
        self.require_unlocked()
        if not isinstance(uuid, str):
            raise NotFound("no such entry")
        found = self._index.get(uuid)
        if found is None:
            raise NotFound("no such entry")
        return found

    def _group(self, uuid):
        self.require_unlocked()
        if uuid in (None, "", "/"):
            return self._kp.root_group
        if not isinstance(uuid, str):
            raise NotFound("no such group")
        found = self._group_index.get(uuid)
        if found is None:
            raise NotFound("no such group")
        return found

    # -- read side ---------------------------------------------------------

    def tree(self):
        """The group hierarchy, depth- and count-capped (`Limits`)."""
        self.require_unlocked()
        root = self._kp.root_group
        groups = []
        # Iterative walk. A 10 000-deep nesting is in the malformed corpus
        # precisely because it blows a recursive walker's stack.
        stack = [(root, None, 0)]
        while stack:
            group, parent, depth = stack.pop()
            if depth > Limits.MAX_GROUP_DEPTH:
                raise Invalid("the group tree is nested deeper than %d levels"
                              % Limits.MAX_GROUP_DEPTH)
            try:
                uuid = str(group.uuid)
            except Exception:
                continue
            groups.append({
                "uuid": uuid,
                "name": group.name,
                "parent": parent,
                "count": len(group.entries),
            })
            if len(groups) > Limits.MAX_GROUPS:
                raise Invalid("this database has more than %d groups"
                              % Limits.MAX_GROUPS)
            for sub in reversed(group.subgroups):
                stack.append((sub, uuid, depth + 1))
        return {"groups": groups}

    def entries(self, group=None, query=None, offset=0, limit=100):
        """Entry METADATA only. Invariant 1: no password, no protected value.

        The dict below is built key by key from a fixed list on purpose. A
        comprehension over "all the fields" is how a password ends up in a list
        view, and a list view is exactly what must never carry one — reveal()
        is the only door.
        """
        self.require_unlocked()
        try:
            offset = max(0, int(offset))
            limit = int(limit)
        except (TypeError, ValueError):
            raise Invalid("offset and limit must be integers")
        limit = max(1, min(limit, 500))          # an unbounded limit ships the
                                                 # whole database to a browser
        if query is not None and not isinstance(query, str):
            raise Invalid("query must be a string")
        if query is not None and len(query) > 512:
            raise Invalid("query is too long")
        needle = query.casefold() if query else None

        if group in (None, ""):
            candidates = list(self._index.values())
        else:
            grp = self._group(group)
            candidates = list(grp.entries)

        rows = []
        for entry in candidates:
            title = entry.title or ""
            username = entry.username or ""
            url = entry.url or ""
            tags = entry.tags or []
            if needle:
                hay = " ".join([title, username, url, " ".join(tags)]).casefold()
                if needle not in hay:
                    continue
            try:
                uuid = str(entry.uuid)
            except Exception:
                continue
            rows.append({
                "uuid": uuid,
                "title": title,
                "username": username,
                "url": url,
                "tags": list(tags),
                # A boolean and a count: the PRESENCE of a secret, never the
                # secret. This is why the ABC specifies these two shapes.
                "has_totp": _otp_config(entry) is not None,
                "attachments": len(entry.attachments),
                "modified": _iso(entry.mtime),
            })
        rows.sort(key=lambda r: (r["title"].casefold(), r["uuid"]))
        return {"total": len(rows), "entries": rows[offset:offset + limit]}

    def fields(self, uuid):
        """Entry detail WITHOUT values — the index `reveal()` is called from.

        Not in the ABC: `entries()` has a fixed shape that carries no field
        names, so the UI would have no way to know a protected custom field
        called "API token" exists without either widening `entries()` (which is
        how a list view starts carrying secrets) or a separate call that
        returns names only. This is that call.
        """
        entry = self._entry(uuid)
        names = []
        for key in _entry_field_keys(entry):
            if key in ("Title", "UserName", "URL", "Notes", "Password", "otp"):
                builtin = True
            else:
                builtin = False
            value = _field_value(entry, key)
            names.append({
                "name": key,
                "builtin": builtin,
                "protected": _field_protected(entry, key),
                # Whether there is anything there at all. NOT the value, and
                # not its length — a length is a hint (I6).
                "has_value": bool(value),
            })
        custom_icon = entry._element.findtext("CustomIconUUID")
        return {
            "uuid": uuid,
            "fields": names,
            "attachments": [{"name": a.filename,
                             "size": len(_attachment_bytes(a, strict=False))}
                            for a in entry.attachments],
            "tags": list(entry.tags or []),
            "icon": entry.icon,
            "custom_icon": custom_icon,
            "has_totp": _otp_config(entry) is not None,
            "history": len(entry.history),
            "expires": bool(entry.expires),
            "times": {
                "created": _iso(entry.ctime),
                "modified": _iso(entry.mtime),
                "accessed": _iso(entry.atime),
                "expires": _iso(entry.expiry_time),
            },
        }

    def meta(self):
        """Database-level facts. No values, no key material."""
        self.require_unlocked()
        recycle = None
        try:
            bin_group = self._kp.recyclebin_group
            recycle = str(bin_group.uuid) if bin_group is not None else None
        except Exception:
            recycle = None
        icons = self._kp._xpath("/KeePassFile/Meta/CustomIcons/Icon")
        return {
            "name": self._kp.database_name,
            "description": self._kp.database_description,
            "default_username": self._kp.default_username,
            "version": self._header.version,
            "cipher": self._header.cipher,
            "kdf": self._header.kdf,
            "iterations": self._header.iterations,
            "recyclebin": recycle,
            "custom_icons": len(icons or []),
            # All three causes of "you cannot write this", in one boolean for
            # the UI. The distinct ERROR CODES are what tell an operator which
            # one it was; this is only for greying out a button.
            "readonly": bool(self.readonly or self._format_ro
                             or self._lossless is False),
            "warnings": list(self.warnings),
        }

    def reveal(self, uuid, field):
        """The ONLY door a secret leaves through. One field, once, audited.

        Field references (`{REF:P@I:...}`) are dereferenced, because handing a
        caller the literal reference text would be a reveal that reveals
        nothing and would push them to ask for the target entry instead.
        """
        entry = self._entry(uuid)
        if not isinstance(field, str) or not field:
            raise NotFound("no such field")
        key = _BUILTIN_FIELDS.get(field.casefold(), field)
        value = _field_value(entry, key)
        if value is None:
            raise NotFound("no such field")
        try:
            value = self._kp.deref(value)
        except Exception:
            pass                        # a broken reference reveals as itself
        return {
            "field": key,
            "value": value,
            "expires_in": Limits.REVEAL_SECONDS,
        }

    def totp(self, uuid):
        """A current OTP code. As sensitive as a password; same treatment.

        KeePassXC's `otp` string and KeePass 2.x's `TimeOtp-*` custom fields are
        both understood. HOTP (`HmacOtp-*`) is computed at the counter STORED IN
        THE FILE and the counter is not advanced: advancing it is a mutation,
        and a read verb that quietly dirties the database would be a save
        waiting to surprise someone. Stated here rather than papered over.
        """
        import pyotp
        entry = self._entry(uuid)
        kind = _otp_config(entry)
        if kind is None:
            raise Unsupported("this entry has no OTP configuration")

        if kind == "otp":
            raw = _field_value(entry, "otp") or ""
            if raw.startswith("otpauth://"):
                try:
                    otp = pyotp.parse_uri(raw)
                except Exception:
                    raise Invalid("the stored otpauth URI is malformed")
                if isinstance(otp, pyotp.TOTP):
                    return {"code": otp.now(),
                            "seconds_remaining": _totp_remaining(otp)}
                return {"code": otp.at(0), "seconds_remaining": 0}
            # The legacy KeePassXC form: key=SEED&step=30&size=6
            params = {}
            for part in raw.split("&"):
                if "=" in part:
                    name, _, val = part.partition("=")
                    params[name.strip().casefold()] = val.strip()
            seed = params.get("key")
            if not seed:
                raise Invalid("the stored OTP configuration has no key")
            otp = pyotp.TOTP(_b32(seed, "base32"),
                             interval=int(params.get("step") or 30),
                             digits=int(params.get("size") or 6))
            return {"code": otp.now(), "seconds_remaining": _totp_remaining(otp)}

        if kind == "timeotp":
            seed, encoding = _read_otp_secret(entry, _TIMEOTP_SECRET_FIELDS)
            period = int(_field_value(entry, "TimeOtp-Period") or 30)
            digits = int(_field_value(entry, "TimeOtp-Length") or 6)
            algo = (_field_value(entry, "TimeOtp-Algorithm") or "").upper()
            digest = {"HMAC-SHA-256": hashlib.sha256,
                      "HMAC-SHA-512": hashlib.sha512}.get(algo, hashlib.sha1)
            otp = pyotp.TOTP(_b32(seed, encoding), interval=period,
                             digits=digits, digest=digest)
            return {"code": otp.now(), "seconds_remaining": _totp_remaining(otp)}

        seed, encoding = _read_otp_secret(entry, _HMACOTP_SECRET_FIELDS)
        counter = int(_field_value(entry, "HmacOtp-Counter") or 0)
        otp = pyotp.HOTP(_b32(seed, encoding))
        return {"code": otp.at(counter), "seconds_remaining": 0}

    def attach_get(self, uuid, name):
        """One attachment's bytes, base64, for streaming to the browser.

        It goes out through the Cockpit channel and never lands on this host's
        disk — an attachment written to a server-side path is precisely the
        exfiltration channel I21 is about.
        """
        entry = self._entry(uuid)
        if not isinstance(name, str):
            raise NotFound("no such attachment")
        for att in entry.attachments:
            if att.filename == name:
                data = _attachment_bytes(att)
                if len(data) > Limits.MAX_ATTACHMENT_BYTES:
                    raise Invalid("this attachment is larger than the %d byte "
                                  "limit" % Limits.MAX_ATTACHMENT_BYTES)
                return {"name": name, "size": len(data),
                        "b64": base64.b64encode(data).decode("ascii")}
        raise NotFound("no such attachment")

    def history(self, uuid):
        """Entry history, metadata only. Same rule as `entries()`: no values."""
        entry = self._entry(uuid)
        versions = []
        for index, old in enumerate(entry.history):
            versions.append({
                "index": index,
                "title": old.title or "",
                "username": old.username or "",
                "url": old.url or "",
                "modified": _iso(old.mtime),
                "has_totp": _otp_config(old) is not None,
                "attachments": len(old.attachments),
            })
        return {"uuid": uuid, "total": len(versions), "versions": versions}

    # -- mutation: in memory only; nothing reaches disk until save() -------

    def _mutable(self):
        """Every mutating method starts here. Three refusals, three codes.

        `require_writable()` raises AccessDenied for a registry `mode: "ro"`;
        KDBX3 raises Unsupported because the FORMAT cannot be written safely
        (I20); a failed round-trip raises Conflict because the DATABASE has
        something we would drop (I22). An operator acts on each differently,
        which is why they are not flattened into one code.
        """
        self.require_writable()
        if self._format_ro:
            raise Unsupported(
                "KDBX 3.x has no authenticated encryption, so this backend "
                "opens it read-only; use upgrade_to_kdbx4 to convert it")
        self._assert_lossless()
        self._dirty = True

    def add(self, group, entry):
        """Create an entry. In memory only."""
        self._mutable()
        if not isinstance(entry, dict):
            raise Invalid("the entry must be an object")
        dest = self._group(group)
        title = _check_text(entry.get("title") or "", "title")
        username = _check_text(entry.get("username") or "", "username")
        password = _check_text(entry.get("password") or "", "password")
        url = _check_text(entry.get("url"), "url")
        notes = _check_text(entry.get("notes"), "notes")
        otp = _check_text(entry.get("otp"), "otp")
        tags = entry.get("tags") or None
        if tags is not None and not isinstance(tags, list):
            raise Invalid("tags must be a list of strings")
        expiry = (_parse_iso(entry["expiry_time"], "expiry_time")
                  if entry.get("expiry_time") else None)
        try:
            new = self._kp.add_entry(
                dest, title, username, password, url=url, notes=notes,
                expiry_time=expiry, tags=tags, otp=otp,
                icon=entry.get("icon") or None,
                # KeePass itself permits two entries with the same title in one
                # group; pykeepass refuses by default with a bare Exception.
                # Enforcing uniqueness we do not have would be inventing a rule.
                force_creation=True)
        except Exception as exc:
            raise self._map_pykeepass_error(exc)
        for name, spec in (entry.get("custom") or {}).items():
            self._set_custom(new, name, spec)
        if entry.get("expires") is not None:
            new.expires = bool(entry["expires"])
        uuid = str(new.uuid)
        self._index[uuid] = new
        return {"uuid": uuid}

    def edit(self, uuid, changes):
        """Apply changes to one entry. Returns field NAMES, never values (I15).

        The previous version is pushed onto the entry's History first, which is
        what KeePass does and what makes "restore" mean anything.
        """
        self._mutable()
        entry = self._entry(uuid)
        if not isinstance(changes, dict) or not changes:
            raise Invalid("changes must be a non-empty object")
        entry.save_history()
        changed = []
        for name, value in changes.items():
            low = str(name).casefold()
            if low in ("title", "username", "password", "url", "notes", "otp"):
                # None means "clear it". It has to become "" here: lxml's
                # element builder raises a bare TypeError on a None child, and
                # an untyped exception out of a verb is exactly what the error
                # taxonomy exists to prevent.
                setattr(entry, low, _check_text(value, low) or "")
                changed.append(low)
            elif low == "tags":
                if value is not None and not isinstance(value, list):
                    raise Invalid("tags must be a list of strings")
                # `None` means "no tags". pykeepass's setter joins the value,
                # and joining [None] is a TypeError out of a verb.
                tags = [_check_text(t, "tag") or "" for t in (value or [])]
                entry.tags = tags
                changed.append("tags")
            elif low == "icon":
                entry.icon = str(value) if value is not None else None
                changed.append("icon")
            elif low == "expires":
                entry.expires = bool(value)
                changed.append("expires")
            elif low == "expiry_time":
                entry.expiry_time = _parse_iso(value, "expiry_time")
                entry.expires = True
                changed.append("expiry_time")
            elif low == "custom":
                if not isinstance(value, dict):
                    raise Invalid("custom must be an object")
                for cname, spec in value.items():
                    self._set_custom(entry, cname, spec)
                    changed.append("custom:%s" % cname)
            else:
                raise Invalid("%s is not an editable field"
                              % str(name)[:40])
        entry.touch(modify=True)
        return {"uuid": uuid, "changed": changed}

    def _set_custom(self, entry, name, spec):
        """Create/replace one custom string field. `None` deletes it."""
        if not isinstance(name, str) or not name:
            raise Invalid("a custom field needs a name")
        if name in _RESERVED_FIELDS:
            # pykeepass guards this with `assert`, which vanishes under -O.
            raise Invalid("%s is a reserved KeePass field name" % name)
        if spec is None:
            if not _del_field(entry, name):
                raise NotFound("no such custom field")
            return
        if isinstance(spec, dict):
            value = spec.get("value")
            protect = bool(spec.get("protected", True))
        else:
            value, protect = spec, True
        _set_field(entry, name, _check_text(value, "custom field"), protect)

    def custom_set(self, uuid, name, value, protect=True):
        """Custom-field CRUD as its own verb, for a schema-driven UI."""
        self._mutable()
        entry = self._entry(uuid)
        entry.save_history()
        self._set_custom(entry, name, {"value": value, "protected": protect})
        entry.touch(modify=True)
        return {"uuid": uuid, "changed": [name]}

    def custom_rm(self, uuid, name):
        self._mutable()
        entry = self._entry(uuid)
        entry.save_history()
        self._set_custom(entry, name, None)
        entry.touch(modify=True)
        return {"uuid": uuid, "changed": [name]}

    def move(self, uuid, group):
        self._mutable()
        entry = self._entry(uuid)
        dest = self._group(group)
        self._kp.move_entry(entry, dest)
        entry.touch(modify=True)
        return {"ok": True}

    def rm(self, uuid, permanent=False):
        """Recycle-bin aware. `permanent` bypasses it and is unrecoverable
        except from the backup ring, so the UI must confirm it explicitly."""
        self._mutable()
        entry = self._entry(uuid)
        if permanent:
            self._kp.delete_entry(entry)
            self._index.pop(uuid, None)
            return {"ok": True, "recycled": False}
        try:
            self._kp.trash_entry(entry)
            return {"ok": True, "recycled": True}
        except Exception:
            # No recycle bin, or the entry is already in it: fall through to a
            # real delete rather than leaving the caller thinking it worked.
            self._kp.delete_entry(entry)
            self._index.pop(uuid, None)
            return {"ok": True, "recycled": False}

    def group_add(self, parent, name):
        self._mutable()
        dest = self._group(parent)
        if not isinstance(name, str) or not name.strip():
            # A None name reaches lxml's element builder as a None child and
            # comes back as a bare TypeError; refuse it with a code instead.
            raise Invalid("a group needs a name")
        new = self._kp.add_group(dest, _check_text(name, "group name"))
        self._group_index[str(new.uuid)] = new
        return {"ok": True, "uuid": str(new.uuid)}

    def group_rm(self, uuid, permanent=False):
        self._mutable()
        group = self._group(uuid)
        if group == self._kp.root_group:
            raise Invalid("the root group cannot be deleted")
        if permanent:
            self._kp.delete_group(group)
        else:
            try:
                # trash_group refuses a non-empty group; emptying it into the
                # bin one item at a time is not the same thing as deleting it,
                # so move the whole subtree instead.
                self._kp.trash_group(group)
            except Exception:
                self._kp.delete_group(group)
        # Rebuild rather than prune: a recycled group still EXISTS (it moved
        # into the bin) and must stay addressable, while a permanent delete
        # took its entries with it. Only a re-walk knows which happened.
        self._reindex()
        return {"ok": True}

    def group_mv(self, uuid, parent):
        """Re-parent a group, refusing a move into its own descendant.

        Without this check the tree walker meets a cycle and never comes back —
        `tree()`'s depth cap would eventually raise, but only after building a
        list bounded by MAX_GROUPS first.
        """
        self._mutable()
        group = self._group(uuid)
        dest = self._group(parent)
        if group == self._kp.root_group:
            raise Invalid("the root group cannot be moved")
        walk = dest
        while walk is not None:
            if walk == group:
                raise Invalid("a group cannot be moved into its own subtree")
            walk = walk.parentgroup
        self._kp.move_group(group, dest)
        return {"ok": True}

    def attach_add(self, uuid, name, b64, replace=False):
        """Attach bytes to an entry. The bytes arrive base64 in the request —
        never as a path (I4), and never through a temp file (I10)."""
        self._mutable()
        entry = self._entry(uuid)
        if not isinstance(name, str) or not name:
            raise Invalid("an attachment needs a name")
        try:
            data = base64.b64decode(b64 or "", validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise Invalid("the attachment content is not valid base64")
        if len(data) > Limits.MAX_ATTACHMENT_BYTES:
            raise Invalid("the attachment is larger than the %d byte limit"
                          % Limits.MAX_ATTACHMENT_BYTES)
        existing = [a for a in entry.attachments if a.filename == name]
        if existing and not replace:
            raise Conflict("this entry already has an attachment called %s"
                           % name[:64])
        # Archive FIRST: the history copy takes over the old reference, so the
        # detach below sees the binary is still needed and leaves the pool
        # entry alone. Doing it the other way round loses the old attachment
        # from every historical version of the entry.
        entry.save_history()
        if existing:
            self._detach(entry, name)
        binary_id = self._kp.add_binary(data)
        entry.add_attachment(binary_id, name)
        entry.touch(modify=True)
        return {"ok": True, "name": name, "size": len(data)}

    def attach_rm(self, uuid, name):
        self._mutable()
        entry = self._entry(uuid)
        if not any(a.filename == name for a in entry.attachments):
            raise NotFound("no such attachment")
        entry.save_history()
        self._detach(entry, name)
        entry.touch(modify=True)
        return {"ok": True}

    def _detach(self, entry, name):
        """Drop the named Binary element from ONE entry, then collect garbage.

        The binary pool is shared across the whole database, history included,
        so removing an attachment from an entry is not the same act as removing
        its bytes. Freeing the pool slot while a history version still points at
        it is what produces the dangling `Binary/Value/@Ref` that KeePassXC
        reports as "Unmapped keys left." — measured against `keepassxc-cli`
        on a file written this way (I19: the oracle, not our own round trip, is
        what says whether a file is right).
        """
        freed = []
        for el in list(entry._element.findall("Binary")):
            if el.findtext("Key") != name:
                continue
            value = el.find("Value")
            entry._element.remove(el)
            try:
                freed.append(int(value.get("Ref")))
            except (AttributeError, TypeError, ValueError):
                continue
        for binary_id in sorted(set(freed), reverse=True):
            self._gc_binary(binary_id)
        return freed

    def _gc_binary(self, binary_id):
        """Remove a pool binary only when NOTHING still references it."""
        root = self._kp.tree.getroot()
        for el in root.iter("Binary"):
            value = el.find("Value")
            if value is not None and value.get("Ref") == str(binary_id):
                return False                    # a history version needs it
        self._delete_binary(binary_id)
        return True

    def _delete_binary(self, binary_id):
        """Remove one binary from the pool and renumber EVERY reference.

        pykeepass's own `delete_binary()` renumbers with
        `find_attachments()`, which does not descend into `History` elements,
        so references inside archived versions are left pointing one slot too
        high — silently at somebody else's bytes. Walking the whole tree is the
        only correct version of this operation.
        """
        try:
            self._kp.payload.inner_header.binary.pop(binary_id)
        except (AttributeError, IndexError, KeyError, ValueError):
            # KDBX3 keeps the pool in Meta/Binaries, and KDBX3 is read-only
            # here (I20), so there is nothing to do and nothing to guess at.
            raise Invalid("this database's attachment pool cannot be edited")
        root = self._kp.tree.getroot()
        for el in list(root.iter("Binary")):
            value = el.find("Value")
            if value is None:
                continue                     # a KDBX3 Meta/Binaries element
            try:
                ref = int(value.get("Ref"))
            except (TypeError, ValueError):
                continue
            if ref == binary_id:
                el.getparent().remove(el)
            elif ref > binary_id:
                value.set("Ref", str(ref - 1))

    def history_restore(self, uuid, index):
        """Restore an entry to one of its historical versions.

        The CURRENT version is pushed onto the history first, so restoring is
        itself undoable — a restore that discards what you had is a data-loss
        bug wearing a feature's clothes.
        """
        self._mutable()
        entry = self._entry(uuid)
        versions = entry.history
        try:
            index = int(index)
            old = versions[index]
        except (TypeError, ValueError, IndexError):
            raise NotFound("no such history version")
        entry.save_history()
        archived = deepcopy(old._element)
        hist = archived.find("History")
        if hist is not None:
            archived.remove(hist)
        parent = entry._element
        # Replace every child except History with the archived version's, and
        # put them BEFORE the history block: KeePass's schema is strings then
        # History, and an entry whose History drifted to the front is valid to
        # every reader on this host and invalid to a strict one.
        history_el = parent.find("History")
        for child in list(parent):
            if child is not history_el:
                parent.remove(child)
        for child in list(archived):
            if history_el is not None:
                history_el.addprevious(child)
            else:
                parent.append(child)
        entry.touch(modify=True)
        return {"uuid": uuid, "restored": index}

    def history_rm(self, uuid, index=None, all=False):      # noqa: A002
        self._mutable()
        entry = self._entry(uuid)
        versions = entry.history
        if all:
            if versions:
                entry.delete_history(all=True)
            return {"ok": True, "removed": len(versions)}
        try:
            old = versions[int(index)]
        except (TypeError, ValueError, IndexError):
            raise NotFound("no such history version")
        entry.delete_history(history_entry=old)
        return {"ok": True, "removed": 1}

    # -- the losslessness guard  (I22) ------------------------------------

    def _assert_lossless(self):
        """parse -> serialize -> parse, and refuse writes if anything is lost.

        Reading a KDBX 4.1 database with a library that does not model every
        field and writing it back DELETES what it did not understand. The check
        is cheap here because we already hold the transformed key, so the round
        trip costs a symmetric encrypt and decrypt rather than another KDF run.

        It runs once, lazily, at the top of the first mutating call — which is
        still before the first mutation, because `_mutable()` calls it before
        the caller's change is applied. On failure it turns writes off AND
        names the field, because "refused to save" without a reason is a bug
        report nobody can act on.
        """
        if self._lossless is True:
            return
        if self._lossless is False:
            raise Conflict("this database cannot be written without losing "
                           "data: %s" % self._lossless_detail)
        try:
            probe_bytes = self._serialize(reseed=False)
            probe = PyKeePass(io.BytesIO(probe_bytes),
                              transformed_key=self._tk.bytes)
            lost = _diff_xml(self._kp.tree.getroot(), probe.tree.getroot())
        except (Invalid, Unsupported, Conflict):
            raise
        except Exception:
            self._fail_lossless("the database could not be re-read after a "
                                "trial serialisation")
        if lost:
            self._fail_lossless("; ".join(lost[:5]), lost[0])
        self._lossless = True

    def _fail_lossless(self, detail, first=None):
        """Latch the I22 refusal and raise `Conflict` — always `Conflict`.

        Note what this does NOT do: set `self.readonly`. Flipping that flag
        would make every later attempt come back as `AccessDenied`, which is
        the code for "the REGISTRY says read-only". Three causes, three codes
        (base.py's ERROR-CODE CONVENTION), and an operator fixes each one
        differently — a registry edit, a format upgrade, or a bug report about
        the field we are refusing to drop.
        """
        self._lossless = False
        self._lossless_detail = detail
        banner = ("writes are disabled: a save would drop %s"
                  % (first or detail))
        if banner not in self.warnings:
            self.warnings.append(banner)
        raise Conflict("this database cannot be written without losing "
                       "data: %s" % detail)

    # -- persistence -------------------------------------------------------

    def _serialize(self, reseed=True):
        """Build the whole database into bytes. Touches no disk.

        `reseed=True` regenerates the master seed, the encryption IV and the
        inner protected-stream key. pykeepass re-uses whatever it read, so two
        saves of a database that differs by one entry would share a key AND an
        IV — identical CBC/keystream prefixes, i.e. a free diff for anyone
        holding both generations. Real KeePass regenerates on every save.

        The KDF salt is deliberately NOT regenerated: changing it invalidates
        the transformed key, and re-deriving needs the passphrase, which this
        object no longer has (and not having it is the point — see the module
        docstring). The three values we do rotate are the ones that make the
        encryption key and IV fresh without another KDF run.

        `reseed=False` is for the I22 round-trip probe, which has to compare
        like with like.
        """
        kp = self._kp
        if reseed:
            dh = kp.kdbx.header.value.dynamic_header
            dh.master_seed.data = os.urandom(32)
            dh.encryption_iv.data = os.urandom(len(self._header.encryption_iv))
            try:
                kp.kdbx.body.payload.inner_header.protected_stream_key.data = \
                    os.urandom(64)
            except (AttributeError, KeyError):
                pass                       # KDBX3 keeps it in the outer header
            # The header is a construct RawCopy: when `data` is present the
            # builder replays those exact bytes and ignores `value`. Dropping
            # it is what makes the edited header actually get written — without
            # this the file would carry the OLD seed and a body encrypted under
            # the NEW one, which is a database nobody can open.
            try:
                del kp.kdbx.header["data"]
            except (KeyError, AttributeError):
                pass
        buf = io.BytesIO()
        try:
            kp.save(buf, transformed_key=self._tk.bytes)
        except Exception as exc:
            raise self._map_pykeepass_error(exc)
        return buf.getvalue()

    def save(self, *, override_stale=False):
        """Serialize and write durably. The only method that touches disk.

        The sequence is base.py's, and there are no shortcuts (I12, I13):
        require_writable -> LockFile -> serialize -> verify what we are about
        to write -> atomic_replace with the unlock fingerprint -> re-fingerprint.
        """
        self.require_writable()
        if self._format_ro:
            raise Unsupported(
                "KDBX 3.x has no authenticated encryption, so this backend "
                "opens it read-only; use upgrade_to_kdbx4 to convert it")
        self._assert_lossless()

        backup = self.entry.get("backup") or {}
        # override_stale is the operator's explicit answer to the Conflict
        # LockFile raises; it is never inferred from an age or a pid (I13).
        with LockFile(self.path, fmt="kdbx", override_stale=override_stale):
            data = self._serialize(reseed=True)
            # Verify what we are about to write, with our own constant-time
            # check, before it replaces a database that currently works. This
            # is cheap (no KDF — the transformed key is in hand) and it is the
            # difference between "the save failed" and "the safe is gone".
            self._verify_own_output(data)
            result = atomic_replace(
                self.path, data,
                backup_dir=backup.get("dir"),
                keep=backup.get("keep"),
                expect_fingerprint=self.fingerprint,
            )
        self.fingerprint = result["fingerprint"]
        self._data = data
        self._header = _read_header(data)
        self._dirty = False
        return {"ok": True, "backup": result["backup"],
                "bytes": result["bytes"], "conflict": False}

    def _verify_own_output(self, data):
        """Re-run the full MAC verification over bytes we just built.

        A writer and a reader that share a bug round-trip perfectly (I19), so
        this is not evidence of compliance — the interop oracle is. What it IS
        evidence of is that the bytes about to replace a working database are
        internally consistent, which is the failure this catches: a truncated
        build, a mismatched seed, a construct edge case.
        """
        hdr = _read_header(data)
        if hdr.major >= 4:
            _verify_kdbx4(data, hdr, self._tk.bytes)
        else:
            _verify_kdbx3(data, hdr, self._tk.bytes)

    def lock(self):
        """Drop the decrypted database and every key derived from it.

        Honest about exactly how far this goes (I14). OUR copy of the
        transformed key is a `Secret`, so it is a `bytearray` and this
        overwrites it. What it does NOT reach: the immutable `bytes` object
        argon2-cffi returned when the key was derived, the copies `construct`
        made of it while parsing, and every decrypted value pykeepass
        materialised as a Python `str`. None of those can be overwritten by any
        code we could write. Dropping the references lets the GC reclaim them,
        which is not the same thing as erasing them, and pretending otherwise
        would be worse than saying so. What actually ends them is the process
        exiting — milliseconds away in the default configuration, and the
        single largest mitigation in the program. Idempotent.
        """
        if self._tk is not None:
            self._tk.zero()
            self._tk = None
        self._kp = None
        self._data = None
        self._header = None
        self._index = {}
        self._group_index = {}
        self.handle = None
        self.unlocked = False
        return {"ok": True}

    # -- KDBX3 -> KDBX4  (I20) --------------------------------------------

    def upgrade_to_kdbx4(self, dest_path, password, keyfile=None):
        """Write a NEW KDBX4 database at an operator-named path. Never in place.

        This is the explicit, confirmed action I20 asks for. It is never
        automatic, it never touches the source file, and it refuses to overwrite
        anything: converting a database in place would mean the moment before
        `os.replace` there is exactly one copy of the operator's passwords and
        it is the one we are half-way through re-encrypting.

        `password` is a `Secret` and has to be supplied again because this
        object deliberately did not keep one: a KDBX4 file needs a key derived
        under a NEW Argon2 salt, and there is no way to get one from a
        transformed key. As with `unlock()`, the CALLER zeroes it.

        The new file inherits the KDF cost of pykeepass's blank KDBX4 template
        (Argon2d, t=14, m=64 MiB, p=2) rather than the KDBX3 original's AES-KDF
        round count, because the two are not comparable numbers and silently
        picking one would be inventing a security level.

        Faithfulness work this does that a naive tree copy would get wrong:
          * KDBX3 stores timestamps as ISO-8601 text and KDBX4 as base64
            little-endian seconds since year 1. Every Times element is
            converted; a copied ISO string would make the new file unreadable.
          * KDBX3 keeps attachments as base64 gzip in `Meta/Binaries`, KDBX4 in
            the inner header. The binaries are re-added in index order so the
            `Binary/Value/@Ref` numbers on entries stay correct, and the old
            `Meta/Binaries` element is dropped.
          * `Meta/HeaderHash` belongs to the KDBX3 header and is meaningless in
            KDBX4; it is removed rather than copied as a stale value.
        """
        self.require_unlocked()
        if not isinstance(dest_path, str) or not dest_path.startswith("/"):
            raise Invalid("the destination must be an absolute path")
        if dest_path != os.path.normpath(dest_path):
            # No "..", no doubled slashes, no trailing slash. The refusals
            # below are all textual, and a path that does not equal its own
            # normal form can walk straight past every one of them.
            raise Invalid("the destination path must be in normal form")
        if dest_path.startswith("/tmp/") or dest_path.startswith("/var/tmp/"):
            raise Invalid("refusing to write a database under /tmp")
        if os.path.lexists(dest_path):
            raise Conflict("the destination already exists; "
                           "this never overwrites")
        if self._header.major >= 4:
            raise Invalid("this database is already KDBX 4")
        if password is None:
            raise BadCredential(_BAD_CRED)

        # The blank KDBX4 template ships inside the pykeepass package. This is
        # a fixed, package-owned constant, not a caller-supplied path, so I4
        # does not apply to it — I4 is about a path the browser can name.
        blank_path = os.path.join(os.path.dirname(pykeepass.__file__),
                                  "blank_database.kdbx")
        with open(blank_path, "rb") as fh:
            blank = fh.read()
        new = PyKeePass(io.BytesIO(blank), password="password")

        # Move the whole KeePassFile document across, then fix the two things
        # that are version-specific.
        src_root = self._kp.tree.getroot()
        dst_tree = new.tree
        dst_root = dst_tree.getroot()
        for tag in ("Meta", "Root"):
            old_el = dst_root.find(tag)
            if old_el is not None:
                dst_root.remove(old_el)
            src_el = src_root.find(tag)
            if src_el is not None:
                dst_root.append(deepcopy(src_el))

        meta = dst_root.find("Meta")
        for stale in ("HeaderHash", "Binaries"):
            el = meta.find(stale) if meta is not None else None
            if el is not None:
                meta.remove(el)
        _convert_times_to_kdbx4(dst_root)

        # Re-add the attachments in their original index order so that every
        # Binary/Value/@Ref an entry carries still points at the right bytes.
        for blob in self._kp.binaries:
            new.add_binary(blob)

        # A fresh KDF salt and a fresh master seed, then one derivation.
        template = _read_header(blank)
        dh = new.kdbx.header.value.dynamic_header
        kdfp = dh.kdf_parameters.data.dict
        kdfp["S"].value = os.urandom(32)
        dh.master_seed.data = os.urandom(32)
        dh.encryption_iv.data = os.urandom(len(template.encryption_iv))
        try:
            new.kdbx.body.payload.inner_header.protected_stream_key.data = \
                os.urandom(64)
        except (AttributeError, KeyError):
            pass
        del new.kdbx.header["data"]

        template.kdf_params["salt"] = bytes(kdfp["S"].value)
        _clamp_kdf(template)                         # I7, even on our own file
        composite = _composite_key(password, keyfile)
        try:
            transformed = Secret(_derive(template, composite))
        finally:
            composite = b"\x00" * 32

        try:
            buf = io.BytesIO()
            try:
                new.save(buf, transformed_key=transformed.bytes)
            except Exception as exc:
                raise self._map_pykeepass_error(exc)
            data = buf.getvalue()

            # Prove the file we are about to create authenticates under the key
            # we just derived, before it exists on disk at all.
            out_hdr = _read_header(data)
            _verify_kdbx4(data, out_hdr, transformed.bytes)
            PyKeePass(io.BytesIO(data), transformed_key=transformed.bytes)
        finally:
            # This key belongs to the NEW file and nothing here keeps it.
            transformed.zero()

        result = atomic_replace(dest_path, data, expect_fingerprint=None)
        return {"ok": True, "path": dest_path, "bytes": result["bytes"],
                "version": out_hdr.version}


#: The banner I20 asks for, in one place so probe() and unlock() cannot drift.
_KDBX3_WARNING = (
    "this is a KDBX 3.x database: the format has no authenticated encryption, "
    "so a tampered file decrypts to attacker-influenced data with nothing to "
    "detect it. It is open read-only. Use the KDBX 4 upgrade to write to it.")


def _totp_remaining(otp):
    """Seconds until the current TOTP window rolls over."""
    interval = getattr(otp, "interval", 30) or 30
    return int(interval - (int(time.time()) % interval))


def _read_otp_secret(entry, candidates):
    """(seed_text, encoding) from the first KeePass 2.x OTP field present."""
    for name in candidates:
        value = _field_value(entry, name)
        if value:
            if name.endswith("-Base32"):
                return value, "base32"
            if name.endswith("-Hex"):
                return value, "hex"
            if name.endswith("-Base64"):
                return value, "base64"
            return value, "base32"
    raise Unsupported("this entry has no OTP configuration")


# ===========================================================================
# 7. the losslessness diff  (I22)
# ===========================================================================

#: Elements whose text legitimately differs across a round trip. Keep this list
#: SHORT and justified — every entry is a field the guard stops protecting.
_VOLATILE_TAGS = frozenset((
    # KDBX3 only: a digest of the outer header, which the writer recomputes.
    "HeaderHash",
))


def _norm(text):
    return (text or "").strip()


def _diff_xml(a, b, path="", depth=0, found=None):
    """Name what a parse -> serialize -> parse round trip would drop.

    Returns a list of human-readable field paths, empty when the trip is
    lossless. Bounded in both depth and result count: this runs on an
    attacker-shaped document and must not become the denial of service it is
    meant to prevent.
    """
    if found is None:
        found = []
    if len(found) >= 25 or depth > Limits.MAX_GROUP_DEPTH * 4:
        return found

    here = "%s/%s" % (path, a.tag)
    if a.tag != b.tag:
        found.append("%s (element renamed to %s)" % (here, b.tag))
        return found
    if a.tag in _VOLATILE_TAGS:
        return found

    for name, value in a.attrib.items():
        if name not in b.attrib:
            found.append("%s/@%s (attribute dropped)" % (here, name))
        elif b.attrib[name] != value:
            found.append("%s/@%s (attribute changed)" % (here, name))
    for name in b.attrib:
        if name not in a.attrib:
            found.append("%s/@%s (attribute added)" % (here, name))

    if _norm(a.text) != _norm(b.text):
        # The VALUE is never reported — this is a password field as often as
        # not (I15). Only the path is.
        found.append("%s (text changed)" % here)

    ac = [c for c in a if isinstance(c.tag, str)]
    bc = [c for c in b if isinstance(c.tag, str)]
    if len(ac) != len(bc):
        found.append("%s (%d child elements became %d)"
                     % (here, len(ac), len(bc)))
        return found
    for child_a, child_b in zip(ac, bc):
        _diff_xml(child_a, child_b, here, depth + 1, found)
        if len(found) >= 25:
            break
    return found


def _convert_times_to_kdbx4(root):
    """Rewrite every ISO-8601 timestamp as a KDBX4 base64 int64. Used by the
    3.x -> 4.x upgrade; a copied ISO string makes the new file unreadable."""
    time_tags = ("CreationTime", "LastModificationTime", "LastAccessTime",
                 "ExpiryTime", "LocationChanged", "MasterKeyChanged",
                 "RecycleBinChanged", "EntryTemplatesGroupChanged",
                 "SettingsChanged")
    for el in root.iter():
        if el.tag not in time_tags or not el.text:
            continue
        text = el.text.strip()
        if not text:
            continue
        try:
            when = _parse_iso(text, el.tag)
        except Invalid:
            continue                       # already base64, or unparseable
        seconds = int((when - _KP_EPOCH).total_seconds())
        el.text = base64.b64encode(struct.pack("<Q", seconds)).decode("ascii")


__all__ = ["KdbxBackend", "VERSION"]
