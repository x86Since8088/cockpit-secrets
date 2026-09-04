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
import csv
import datetime as _dt
import hashlib
import hmac
import io
import json
import os
import re
import secrets as _sysrandom
import struct
import time
import urllib.parse
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
    SecretsError,
    Unsupported,
    Backend,
    CsvWriter,
    atomic_replace,
    constant_time_eq,
    open_safe_fd,
    register_backend,
    validate_new_path,
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
    # The helper's published vocabulary (docs/CONTRACT.md, `_FIELD_RE`, and the
    # schema's `field` select whose label is "TOTP secret") spells the seed
    # `totp`. Without this row that option resolved to a string field literally
    # named "totp", which no KeePass writer produces, so the UI's own menu item
    # answered not-found on every database.
    "totp": "otp",
}

#: The prefix the helper's `field` vocabulary uses to address a non-reserved
#: string field: `custom:<name>`. It is stripped here rather than in the helper
#: because the mapping from a contract field name to a storage key is exactly
#: what a backend is for — psafe3 answers the same spelling from a typed field
#: table that has no named custom fields at all.
_CUSTOM_PREFIX = "custom:"

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

#: THE MAXIMUM EXPANSION A SINGLE DEFLATE MEMBER CAN PHYSICALLY PRODUCE.
#:
#: This number is why the ratio guard is no longer a bomb defence. DEFLATE's
#: best case is one 258-byte match per few output bits, which caps expansion at
#: 1032:1; measured on this host with zlib 1.3, `zlib.compress(b"\0" * n, 9)`
#: tops out at 1028:1 for every n from 1 MiB to 256 MiB. A gzip stream therefore
#: cannot expand further than this no matter who wrote it, and a threshold below
#: it does not separate a bomb from ordinary compressible content — it only
#: decides how compressible a legitimate attachment is allowed to be.
#:
#: It decided wrong. An 8 MiB log file — one repeated line, well under
#: `Limits.MAX_ATTACHMENT_BYTES` — compresses at 258:1 inside the inner payload,
#: so `attach_add` + `save()` answered `{"ok": true}` and wrote a database that
#: every later `unlock` refused with "expansion ratio 258:1 is over the 200:1
#: limit", while KeePassXC read the same file perfectly. The same guard refused
#: valid KDBX 3.1 databases written by keepassxc-cli, whose attachments are
#: gzipped one by one in the binary pool.
#:
#: What replaces it, and why each piece is sound where a ratio is not:
#:
#:   * the ABSOLUTE cap (`Limits.MAX_INNER_BYTES`), enforced INCREMENTALLY by
#:     `decompressobj().decompress(data, max_length)` — memory never exceeds the
#:     cap, whatever the ratio, so "expands until the allocator gives up" is
#:     impossible by construction rather than by threshold;
#:   * the STRUCTURAL caps in `_reject_hostile_xml` — a `<Value>` over
#:     `Limits.MAX_FIELD_BYTES`, a pooled binary over
#:     `Limits.MAX_ATTACHMENT_BYTES`, more than `Limits.MAX_ENTRIES` entries or
#:     `Limits.MAX_GROUPS` groups. These describe what the CONTENT is, which a
#:     ratio never could: they refuse the corpus's 64 MiB single-value bomb and
#:     admit a 32 MiB attachment, and those two are byte-identical to a ratio;
#:   * `Limits.parse_budget()`, which bounds the wall clock of everything
#:     downstream of the inflate.
#:
#: The check below is kept because it still asserts something true — a stream
#: that expands past what DEFLATE can produce is not a DEFLATE stream, so it is
#: a corruption or library-behaviour check now, not a security control, and the
#: comment says so rather than letting a future reader mistake it for one.
_DEFLATE_MAX_RATIO = 1032


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


def _reject_hostile_xml(root, what, structural=False):
    """Refuse a parsed document that carries a DTD or any entity reference.

    `resolve_entities=False` stops the *expansion*; it leaves the entity
    references in the tree as `_Entity` nodes, so a document that tried is still
    a document that tried. Neither a KDBX inner payload nor a KeePass key file
    has any legitimate use for a DOCTYPE, so the presence of one is by itself
    sufficient grounds — and refusing on structure means our refusal does not
    depend on whichever amplification limit libxml2 ships this month.

    Raises `Invalid`, never `BadCredential`: the file authenticated, it is the
    *shape* we are rejecting, and saying so leaks nothing about the passphrase.

    `structural=True` additionally enforces the SIZE AND COUNT clamps in
    `Limits` against the document itself — see `_assert_structural_limits`. It
    is set only for the decrypted inner payload, because those clamps describe
    a KeePass database and mean nothing for a key file.
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
    #
    # The structural clamps ride along in the SAME walk. Not for speed — the
    # walk is cheap — but so that "we looked at every node" is one loop with one
    # exit rather than two passes that can drift apart.
    entity_tag = getattr(etree, "Entity", None)
    entries = groups = 0
    max_field = Limits.MAX_FIELD_BYTES
    # A pooled binary is base64 in the XML, which is 4 bytes of text per 3 bytes
    # of attachment. Comparing text length against the raw-byte limit would
    # refuse a legal attachment a third under it.
    max_binary = Limits.MAX_ATTACHMENT_BYTES * 4 // 3 + 8
    for node in tree.iter():
        tag = node.tag
        if entity_tag is not None and tag is entity_tag:
            raise Invalid("%s contains an XML entity reference; refused (I8)"
                          % what)
        if not structural or not isinstance(tag, str):
            continue
        if tag == "Entry":
            entries += 1
            if entries > Limits.MAX_ENTRIES:
                raise Invalid("this database declares more than %d entries"
                              % Limits.MAX_ENTRIES)
        elif tag == "Group":
            groups += 1
            if groups > Limits.MAX_GROUPS:
                raise Invalid("this database declares more than %d groups"
                              % Limits.MAX_GROUPS)
        elif tag in ("Value", "Binary"):
            text = node.text
            if text is None:
                continue
            if tag == "Binary":
                # KDBX 3.1 keeps attachment bodies as base64 text directly on
                # `Meta/Binaries/Binary`. (KDBX 4 moved them to the inner
                # header, where MAX_INNER_BYTES is the bound.) An entry's own
                # `<Binary><Key/><Value Ref="0"/></Binary>` carries no text and
                # falls out at the `text is None` test above.
                if len(text) > max_binary:
                    raise Invalid(
                        "this database carries an attachment of %d bytes, over "
                        "the %d byte limit" % (len(text), max_binary))
                continue
            # `Binary/Value` is an attachment reference or, in KDBX 3.1, the
            # base64 body itself; `String/Value` is a field. Two different
            # limits, told apart by the parent, because a 32 MiB attachment and
            # a 32 MiB "password" are not the same claim about a database.
            parent = node.getparent()
            ptag = parent.tag if parent is not None else None
            limit, kind = ((max_binary, "attachment")
                           if ptag == "Binary"
                           else (max_field, "field value"))
            if len(text) > limit:
                raise Invalid(
                    "this database carries a %s of %d bytes, over the %d byte "
                    "limit" % (kind, len(text), limit))
    return root


def _parse_xml_hardened(data, what="XML document", structural=False):
    """Parse bytes with the hardened parser and the structural refusal.

    Returns an `lxml` ElementTree (what `etree.parse` returns), because that is
    what pykeepass stores as the payload and later calls `.xpath()` on.

    `structural=True` is set by the one caller that is parsing a KeePass
    database rather than a key file. It is what makes `Limits.MAX_ENTRIES` mean
    what its docstring in base.py claims — "stops a file that claims 10^9
    records and makes the helper build the list before anything notices". The
    count used to be checked only in `unlock()`, AFTER `PyKeePass(...)` had
    parsed the whole payload AND run its protected-value pass over it, which is
    the expensive part and the part an attacker controls the size of.
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
    _reject_hostile_xml(tree.getroot(), what, structural=structural)
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
    # See `_DEFLATE_MAX_RATIO`: this is a "these bytes are not a deflate
    # stream" assertion, not the bomb defence. The bomb defence is the
    # incremental cap above plus the structural caps in `_reject_hostile_xml`.
    ratio_limit = max(Limits.MAX_DECOMPRESS_RATIO, _DEFLATE_MAX_RATIO)
    if (len(out) > _RATIO_FLOOR_BYTES
            and len(out) > ratio_limit * max(1, len(data))):
        raise Invalid("compressed payload expansion ratio %d:1 is over the "
                      "%d:1 limit" % (len(out) // max(1, len(data)),
                                      ratio_limit))
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
        return _parse_xml_hardened(data, "the decrypted inner payload",
                                   structural=True)

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


def _composite_key(password, keyfile, challenge_result=None):
    """SHA-256(SHA-256(passphrase) || keyfile_composite || CR) — KeePass's rule.

    `password` is a `Secret`, so this reads the wipeable `bytearray` directly.
    `Secret.str_view()` is deliberately never called anywhere in this module:
    KDBX needs the passphrase only as UTF-8 bytes to hash, so there is no
    reason to mint an unwipeable `str` from it (I14).

    `challenge_result` is the challenge-response component and is appended LAST,
    which is the order KeePassXC's `CompositeKey::rawKey(transformSeed)` hashes
    in: every static key first, then the challenge-response hash. Order is not a
    detail here — a different order produces a different composite key, which
    produces a different transformed key, which fails the header HMAC with the
    same `bad-credential` a wrong passphrase gives, and no amount of staring at
    the error tells you which of the two it was. `_yubikey_component()` is what
    builds this value; nothing else may pass it.
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
    if challenge_result is not None:
        parts += bytes(challenge_result)
    if not parts:
        raise BadCredential(_BAD_CRED)
    return hashlib.sha256(parts).digest()


# -- YubiKey HMAC-SHA1 challenge-response  (KeePassXC-compatible) -----------
#
# Read from KeePassXC 2.7.10's own source rather than from a description of it,
# because every constant below is one that silently produces the WRONG key
# rather than an error when it is wrong:
#
#   src/keys/CompositeKey.cpp  `transform()`  — for anything that is not the
#     legacy KDBX3 AES-KDF, the challenge is `kdf.seed()`: the KDF salt out of
#     the KDBX4 header, NOT the master seed and NOT the encryption IV.
#   src/keys/CompositeKey.cpp  `challenge()`  — the component folded into the
#     composite key is SHA-256 over each challenge-response key's raw answer,
#     i.e. SHA-256(response) for a single token. The raw 20 bytes are NOT what
#     gets hashed into the composite.
#   src/keys/drivers/YubiKeyInterfaceUSB.cpp  `performChallenge()` — the
#     challenge is PKCS#7-padded to exactly 64 bytes before it goes to the
#     token ("for compatibility with all configurations"), and the answer is
#     truncated to the 20 bytes of an HMAC-SHA1.
#
#: An HMAC-SHA1 answer. Fixed, because a response of any other length means the
#: helper decoded something that is not a slot answer, and folding it in anyway
#: would produce a key that fails with the same error as a wrong passphrase.
_YUBIKEY_RESPONSE_LEN = 20
#: The wire size the token expects. KeePassXC pads to this and so must we, or
#: the token HMACs different bytes and every answer is wrong.
_YUBIKEY_CHALLENGE_LEN = 64


def _pkcs7_to(data, size):
    """Pad `data` to `size` bytes, PKCS#7 — the padding KeePassXC sends."""
    if len(data) > size:
        raise Invalid("the challenge is longer than the %d bytes a hardware "
                      "token accepts" % size)
    pad = size - len(data)
    return bytes(data) + bytes([pad]) * pad if pad else bytes(data)


def _challenge_bytes(hdr):
    """The exact bytes to send to the token for this database.

    KDBX4 only, and the refusal is not a shrug. KeePassXC folds the response
    into the FINAL key for a legacy KDBX3 AES-KDF database
    (`SHA-256(master_seed || SHA-256(response) || transformed_key)`) rather than
    into the composite key, so it is a genuinely different construction — and
    KDBX 3.x is opened read-only here anyway because it has no authenticated
    encryption (I20). Implementing a second, untestable construction for a
    format we will not write is how a bug gets shipped with nothing to catch it.
    """
    if hdr.major < 4:
        raise Unsupported(
            "challenge-response is implemented for KDBX 4 only: KeePassXC "
            "folds the token's answer into the final key rather than the "
            "composite key for KDBX 3.x, which is a different construction")
    seed = hdr.kdf_params.get("salt") or b""
    if not seed:
        raise Invalid("this database's header carries no KDF seed to "
                      "challenge the token with")
    return _pkcs7_to(seed, _YUBIKEY_CHALLENGE_LEN)


def _yubikey_component(response):
    """SHA-256 over the token's raw answer — the composite-key contribution."""
    raw = bytes(response.bytes) if isinstance(response, Secret) \
        else bytes(response)
    if len(raw) != _YUBIKEY_RESPONSE_LEN:
        raise Invalid("a hardware-token response is %d bytes; this one is %d"
                      % (_YUBIKEY_RESPONSE_LEN, len(raw)))
    return hashlib.sha256(raw).digest()


def challenge_for(entry):
    """What `probe` publishes so the caller can drive the hardware token.

    Takes a **validated registry entry** — the same object a backend is built
    from — because the challenge is a property of the FILE, and the registry is
    the only thing allowed to say which file (I4).

    Returns::

        {"slot": 1|2, "algorithm": "hmac-sha1", "challenge_b64": str,
         "challenge_bytes": 64, "source": "kdf-seed"}

    None of that is secret: the KDF seed is in the outer header, in cleartext,
    for anyone who already holds the file. That is the test a probe result has
    to pass, and this passes it — the value that IS secret is the token's
    answer, which never comes near this function.

    Raises `Unsupported` when the entry declares no `yubikey_slot`, or when the
    database is KDBX 3.x (see `_challenge_bytes`).
    """
    slot = entry.get("yubikey_slot")
    if not slot:
        raise Unsupported("this safe's registry entry declares no yubikey_slot")
    with open_safe_fd(entry.get("path", "")) as sf:
        data = sf.read_all()
    challenge = _challenge_bytes(_read_header(data))
    return {
        "slot": int(slot),
        "algorithm": "hmac-sha1",
        "challenge_b64": base64.b64encode(challenge).decode("ascii"),
        "challenge_bytes": len(challenge),
        "source": "kdf-seed",
    }


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
            # bytes() is load-bearing, not tidiness: botan3's BlockCipher
            # returns a `ctypes.c_char_Array_16`, and ITERATING one yields
            # 1-byte `bytes` objects rather than ints — so `a ^ b` below raised
            # `TypeError: unsupported operand type(s) for ^: 'bytes' and 'int'`
            # and the whole KDBX3+Twofish path answered `internal`. MEASURED on
            # this host while building tests/fixtures/gen_twofish_fixture.py;
            # it had never been reachable before, because no Twofish fixture
            # existed for it to run against (docs/COMPATIBILITY.md's one
            # "UNTESTED" row, and exactly the kind of bug that row was warning
            # about).
            pt = bytes(bc.decrypt(ct))
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
    # REFUSE A REPEATED KEY RATHER THAN PICK ONE.
    #
    # `_read_header` already applies this rule one layer up, with the reason
    # written out there: "A duplicated header field is a parser differential
    # waiting to happen ... Refuse rather than pick." The same hazard is
    # sharper down here, because down here the differing values are
    # CREDENTIALS. Measured on a database with two `<String><Key>Password`
    # elements: this function's first-match answer showed the FIRST value while
    # keepassxc-cli 2.7.10 refused the file outright ("Duplicate custom
    # attribute found"), so a safe supplied by A3 displayed a password no
    # reference implementation would ever show. The write path was worse:
    # `edit` rewrote the first copy and reported `{"changed": ["password"]}`
    # while the second copy — the one another reader might use — kept the old
    # value, i.e. a credential rotation that silently did nothing.
    #
    # The refusal lives HERE, not only in a scan at unlock, because every read
    # and every write of a string field goes through this function. A check
    # placed anywhere else is a check some future path can be added around.
    found = None
    for string_el in entry._element.findall("String"):
        key_el = string_el.find("Key")
        if key_el is not None and key_el.text == key:
            if found is not None:
                raise Invalid(
                    "this entry carries more than one field with the same "
                    "name; refusing to guess which one is meant")
            found = string_el
    return found


def _assert_unique_fields(entry):
    """Refuse an entry carrying two `<String>` elements with the same `<Key>`.

    `_field_element` already refuses when a duplicated key is READ, and that is
    the enforcement point no path can be added around. This is the one that
    catches the case where nothing reads the duplicated key at all: `edit` sets
    the six core fields through pykeepass's own property setters (so that the
    OTP and tag semantics stay pykeepass's rather than ours), and those setters
    do their own first-match update. Without this scan, rotating a password on
    an entry with two `<String><Key>Password` elements rewrote the first copy,
    answered `{"changed": ["password"]}`, and left the second — the one another
    reader might use — holding the old value.

    Called from `_entry()`, which every uuid-addressed verb goes through, so
    "no verb operates on an entry whose fields are ambiguous" is a property of
    one function rather than a rule each verb has to remember.
    """
    seen = set()
    for string_el in entry._element.findall("String"):
        key_el = string_el.find("Key")
        if key_el is None:
            continue
        if key_el.text in seen:
            raise Invalid("this entry carries more than one field with the "
                          "same name; refusing to guess which one is meant")
        seen.add(key_el.text)


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

    `SecretsError` is in the tolerant list, and that omission was a real bug:
    reading a KDBX 3.1 attachment INFLATES it, so `_bounded_decompress` can
    refuse from inside this call. Catching only the four builtin types meant an
    `Invalid` flew straight out of `attach_list()` and `fields()` — the two
    paths whose whole contract is "one broken attachment must not make the
    entry unreadable" — and took the entry's name and every other field with it.
    """
    try:
        return attachment.binary or b""
    except (IndexError, KeyError, TypeError, ValueError):
        if strict:
            raise Invalid("this attachment points at a binary that is not in "
                          "the database")
        return b""
    except SecretsError:
        if strict:
            raise
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

        # The hardware-token challenge, when the registry says one is in play.
        # It is published from `probe` — the verb that runs with no credential
        # — because the caller has to hold the challenge BEFORE it can ask the
        # operator to touch the token, and the challenge is header cleartext.
        # An Unsupported here becomes a warning rather than an error: a KDBX3
        # safe with a stale `yubikey_slot` should still probe and tell the
        # operator why the token cannot be used, not fail the whole verb.
        yubikey = None
        if self.entry.get("yubikey_slot"):
            try:
                yubikey = challenge_for(self.entry)
                warnings.append(_YUBIKEY_CONSTANT_CHALLENGE_WARNING)
            except Unsupported as exc:
                warnings.append("hardware key unavailable: %s" % exc.detail)

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
            "yubikey": yubikey,
            "warnings": warnings,
        }

    # -- unlock ------------------------------------------------------------

    def unlock(self, password, keyfile=None, session=None, *,
               yubikey_response=None):
        """Clamp, derive, verify, and only then open. Never zeroes `password`.

        The sequence below is the one docs/CONTRACT.md and the ABC both spell
        out, and every step is here because skipping it has a name:

          read -> header parse -> CLAMP (I7) -> composite (+ hardware token)
               -> derive (budgeted) -> VERIFY MAC constant-time (I6) -> open
               with the transformed key -> fingerprint from the same fd (I13)
               -> unlocked = True
        """
        _install_xml_hardening()                     # idempotent; fail closed
        if password is None and self.entry.get("password_required", True):
            # The schema permits password_required:false only alongside a key
            # file, but a schema is not an enforcement point (I1).
            raise BadCredential(_BAD_CRED)

        data, fp = self._read()
        hdr = _read_header(data)
        _clamp_kdf(hdr)                              # I7 — BEFORE deriving

        composite = _composite_key(password, keyfile,
                                   self._challenge_component(hdr,
                                                             yubikey_response))
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
        if self.entry.get("yubikey_slot") and hdr.major >= 4:
            # Said at unlock as well as at probe: the probe warning is shown
            # before the token is touched, and a caller that goes straight to
            # `unlock` (the agent, a script, the integration suite) never sees
            # it. A property this important should not depend on which door was
            # used. See `_YUBIKEY_CONSTANT_CHALLENGE_WARNING`.
            warnings.append(_YUBIKEY_CONSTANT_CHALLENGE_WARNING)

        # Only now is it safe to let a parser near the plaintext. pykeepass
        # gets the transformed key and NOT the passphrase, so the master
        # passphrase never becomes an unwipeable `str` in this process (I14).
        try:
            # The MAC has verified, so these bytes are "ours" in the I6 sense —
            # but a file the operator can open is still a file an attacker may
            # have shaped (A3), and everything from here to `_reindex()` is
            # iteration over structure the attacker chose. The budget is the
            # only bound on that stretch: the KDF clamps are spent, the size
            # caps are spent, and `MAX_ENTRIES` bounds the COUNT but not the
            # per-entry cost. Measured before it existed: 100 000 entries whose
            # protected values fail to decode took 46 s at 100% CPU and were
            # then accepted.
            with Limits.parse_budget(what="opening this database"):
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

    def _challenge_component(self, hdr, yubikey_response):
        """Turn a token answer into its composite-key contribution, or None.

        Four cases, and each answer is deliberate:

          slot set, no answer     -> `BadCredential`. A credential the registry
                                     says is required was not supplied; that is
                                     the same class of event as a missing
                                     passphrase and it gets the same code, so
                                     the failure path cannot be used to
                                     enumerate which factor was missing (I6).
          slot set, answer given  -> the SHA-256 component.
          no slot, answer given   -> `Invalid`. Folding an unexpected key
                                     component in would change the composite
                                     key on the say-so of the request rather
                                     than the registry, and the registry is the
                                     only authority for what opens a safe (I1).
          neither                 -> None; the composite key is unchanged, so
                                     every existing database opens exactly as
                                     it did before this parameter existed.
        """
        slot = self.entry.get("yubikey_slot")
        if yubikey_response is None:
            if slot:
                raise BadCredential(_BAD_CRED)
            return None
        if not slot:
            raise Invalid("this safe's registry entry declares no "
                          "yubikey_slot, so a token response cannot be used")
        _challenge_bytes(hdr)      # KDBX3 refusal, before any key material
        return _yubikey_component(yubikey_response)

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
        # An lxml XPath error is never a statement about the FILE — it is a
        # statement about a query we built, i.e. about the request. Belt to the
        # brace in `add()`, which no longer puts caller text in a query at all:
        # if some future call site reintroduces one, the caller learns their
        # input was rejected instead of being told, falsely, that their database
        # will not open. `XPathError` is the base of `XPathEvalError` and of
        # `XPathSyntaxError`, and it is a `LookupError` subclass, so it must be
        # tested before any broad builtin class above it — it is not, today,
        # because none of those catch it.
        xpath_error = getattr(etree, "XPathError", None)
        if xpath_error is not None and isinstance(exc, xpath_error):
            return Invalid("that name cannot be used here")
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
        _assert_unique_fields(found)
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

        `custom:<name>` addresses a non-reserved string field. The prefix is
        REQUIRED for one and stripped for the other on purpose: a bare name is
        looked up through `_BUILTIN_FIELDS` first, so without a distinct
        namespace `reveal("Password")` and `reveal("password")` would be two
        spellings of one door, and `custom:Password` would be a third that
        reached the master password while the audit line said "custom field".
        A prefixed name is therefore looked up ONLY among the custom fields,
        and a reserved key behind the prefix is not-found, not a shortcut.
        """
        entry = self._entry(uuid)
        if not isinstance(field, str) or not field:
            raise NotFound("no such field")
        if field.startswith(_CUSTOM_PREFIX):
            key = field[len(_CUSTOM_PREFIX):]
            if not key or key in _RESERVED_FIELDS:
                raise NotFound("no such field")
        else:
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

    def attach_list(self, uuid):
        """Attachment NAMES and sizes for one entry. No bytes (see the ABC).

        `fields()` has carried this list since the first build, but nothing
        published it: `entries()` sends `attachments` as a COUNT and there was
        no verb that turned a count into a name, so a file could be uploaded
        and never fetched again. This is the same list under its own method so
        `attach-list` can be one narrow verb rather than a page reading it out
        of a fatter response that also enumerates every field name.

        The size is the DECLARED length of the stored bytes and is reported
        even when it exceeds `Limits.MAX_ATTACHMENT_BYTES` — `attach_get` is
        where that cap refuses, with a sentence naming the number. Hiding the
        row here would make an oversized attachment look like no attachment.

        `strict=False` matches `fields()`: a binary whose pool reference is
        dangling is worth reporting as a zero-length row rather than making the
        whole listing raise, because the operator's next move is to remove it
        and they cannot remove a row they cannot see.
        """
        entry = self._entry(uuid)
        return [{"name": a.filename,
                 "size": len(_attachment_bytes(a, strict=False))}
                for a in entry.attachments]

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
        """Entry history, metadata only. Same rule as `entries()`: no values.

        Oldest first, because that is the order KeePass stores `History/Entry`
        in and `index` therefore addresses the same version here, in
        `history_restore`, and in the file. Re-sorting by timestamp would look
        tidier and would break that identity the first time a database carried
        two versions with the same second-precision mtime.
        """
        entry = self._entry(uuid)
        versions = []
        for index, old in enumerate(entry.history):
            versions.append({
                "index": index,
                "when": _iso(old.mtime),
                "title": old.title or "",
                "username": old.username or "",
                "url": old.url or "",
                # A boolean and a length. Not the password, not the notes —
                # a history list is browsed to decide which version to restore,
                # and restoring is the audited mutation that makes an old value
                # reachable at all.
                "has_password": bool(old.password),
                "notes_len": len(old.notes or ""),
                # Beyond the agreed shape, and useful for the same reason
                # `entries()` carries them: presence without value.
                "has_totp": _otp_config(old) is not None,
                "attachments": len(old.attachments),
            })
        return versions

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

    def _meta_int(self, name, default):
        """One `Meta/<name>` as an int, or `default`. Never raises."""
        try:
            text = self._kp.tree.getroot().findtext("Meta/%s" % name)
            return int(text) if text is not None and text.strip() else default
        except (AttributeError, TypeError, ValueError):
            return default

    def _archive_entry(self, entry):
        """Push the current version onto History, then prune it to policy.

        Every mutation in this module that used to call `entry.save_history()`
        directly now comes through here, because `save_history()` on its own is
        an unbounded append: pykeepass does not read `Meta/HistoryMaxItems` or
        `Meta/HistoryMaxSize` at all, so a database edited through this backend
        would grow a history KeePass itself would have trimmed — and grow it
        with plaintext old passwords, which is the wrong thing to accumulate
        without limit in a file whose whole risk model is "how much is in here".

        KeePass's own rules, and the sign convention matters: **-1 means
        unlimited and 0 means keep nothing**, so a bare `if max_items:` test
        would treat "unlimited" as "keep none". Defaults are KeePass's (10
        items, 6 MiB) for a database whose Meta does not say.

        The oldest versions go first, which is the order KeePass drops them in
        and the order `History/Entry` is stored in.

        What this deliberately does NOT do: garbage-collect binaries a pruned
        version was the last referrer to. Renumbering the pool is a whole-tree
        rewrite (`_delete_binary`) and doing it as a side effect of an edit is
        how a `Binary/Value/@Ref` ends up pointing at somebody else's bytes.
        An orphaned pool entry is wasted space in a file, not corruption, and
        KeePass likewise only collects those on an explicit maintenance action.
        """
        entry.save_history()
        hist = entry._element.find("History")
        if hist is None:
            return
        items = hist.findall("Entry")

        max_items = self._meta_int("HistoryMaxItems", 10)
        if max_items >= 0:
            while len(items) > max_items:
                hist.remove(items.pop(0))

        max_size = self._meta_int("HistoryMaxSize", 6 * 1024 * 1024)
        if max_size >= 0 and items:
            # Serialised length is an approximation of KeePass's own size
            # accounting — it counts XML rather than the value bytes KeePass
            # sums — and it is an approximation in the SAFE direction: it
            # over-counts, so we prune at or before the point KeePass would.
            sizes = [len(etree.tostring(el)) for el in items]
            total = sum(sizes)
            while items and total > max_size:
                total -= sizes.pop(0)
                hist.remove(items.pop(0))

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
        # `totp_uri` is the name the schema and docs/CONTRACT.md publish; `otp`
        # is this backend's storage key. `edit` accepts both for the same
        # reason: a form built from the schema sends the schema's spelling.
        otp = _check_text(entry.get("totp_uri") or entry.get("otp"), "otp")
        tags = entry.get("tags") or None
        if tags is not None and not isinstance(tags, list):
            raise Invalid("tags must be a list of strings")
        # `expires` is an ISO-8601 timestamp in the published vocabulary and a
        # bool in the KDBX file. A string sets the DATE (and the flag below); a
        # bool is the flag alone. `expiry_time` stays accepted as the storage
        # spelling, and wins if both are sent, so nothing that worked before
        # changed meaning.
        want_expiry = entry.get("expiry_time")
        if not want_expiry and isinstance(entry.get("expires"), str) \
                and entry["expires"].strip():
            want_expiry = entry["expires"]
        expiry = (_parse_iso(want_expiry, "expires")
                  if want_expiry else None)
        try:
            # THE TWO EMPTY STRINGS ARE THE FIX, not a tidy-up.
            #
            # `PyKeePass.add_entry` opens by calling `find_entries(title=...,
            # username=...)` — unconditionally, before it even looks at
            # `force_creation` — and `_find` formats those caller-supplied
            # strings straight into an XPath predicate. That is the second half
            # of the defect docs/COMPATIBILITY.md §7 documents for `reveal()`
            # and then warns about in general: "Anyone else passing
            # caller-supplied text to a pykeepass find_* / set_custom_property
            # call has the same bug." `add` was that call site and was never
            # hardened. Measured: an entry titled `a"b` — a perfectly legal
            # KeePass title — answered {"error": "internal", "detail": "the
            # KDBX engine could not open this database"}, which is both a verb
            # the caller cannot use and a sentence that is not true.
            #
            # Passing a CONSTANT removes the caller's text from the query
            # altogether, which is better than any escaping scheme because
            # there is nothing left to get right. (`None` would skip the filter
            # entirely, which is tidier still, but pykeepass then hands `None`
            # to `E.Value()` and lxml refuses it — so the constant is the empty
            # string, and the two fields are written immediately afterwards by
            # `_set_field`, which compares element text in Python. That is the
            # same technique §7 used to fix `reveal()`.)
            new = self._kp.add_entry(
                dest, "", "", password, url=url, notes=notes,
                expiry_time=expiry, tags=tags, otp=otp,
                icon=entry.get("icon") or None,
                # KeePass itself permits two entries with the same title in one
                # group; pykeepass refuses by default with a bare Exception.
                # Enforcing uniqueness we do not have would be inventing a rule.
                force_creation=True)
        except Exception as exc:
            raise self._map_pykeepass_error(exc)
        _set_field(new, "Title", title, False)
        _set_field(new, "UserName", username, False)
        # Same shape and the same validator as `edit`'s `changes.custom`, so a
        # custom field can be created WITH the entry rather than only bolted on
        # by a second verb afterwards. The isinstance check is not decoration:
        # without it a `custom` that arrived as a string reached `.items()` and
        # left the verb as an AttributeError, which the error barrier reports
        # as `internal` — the one code that tells an operator nothing about
        # what they got wrong.
        custom = entry.get("custom")
        if custom is not None and not isinstance(custom, dict):
            raise Invalid("custom must be an object of "
                          "{name: {value, protected}}")
        for name, spec in (custom or {}).items():
            self._set_custom(new, name, spec)
        if entry.get("expires") is not None:
            # A timestamp was already turned into `expiry_time` above; here it
            # only has to mean "yes, this expires". A bool still means exactly
            # what it says, and an empty string means never.
            value = entry["expires"]
            new.expires = (bool(value.strip()) if isinstance(value, str)
                           else bool(value))
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
        self._archive_entry(entry)
        changed = []
        for name, value in changes.items():
            low = str(name).casefold()
            # The helper's published vocabulary spells the OTP seed `totp_uri`
            # (schema field, docs/CONTRACT.md) and this backend's own storage
            # key is `otp`. Without this row the schema declared a control
            # whose only effect was `invalid: totp_uri is not an editable
            # field` — a form box that could never work, which is the same
            # defect as a missing one and harder to see.
            if low == "totp_uri":
                low = "otp"
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
                # The schema publishes `expires` as "ISO-8601 UTC timestamp,
                # or empty for never", and this used to be a bare bool()  — so
                # a page that sent the timestamp the schema asked for set the
                # FLAG and left the DATE untouched, and the verb answered
                # `changed: ["expires"]`. A wrong answer that reports success
                # is worse than a refusal, and this is the one field on the
                # form where the wrong answer is "this credential never
                # expires".
                #
                # All three spellings are honoured because all three are things
                # a caller reasonably means: a timestamp sets the date AND the
                # flag; false/null/"" clears the flag; true without a date is
                # the flag alone, which is what the KDBX field itself is.
                if isinstance(value, str) and value.strip():
                    entry.expiry_time = _parse_iso(value, "expires")
                    entry.expires = True
                    changed.append("expiry_time")
                else:
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
        self._archive_entry(entry)
        self._set_custom(entry, name, {"value": value, "protected": protect})
        entry.touch(modify=True)
        return {"uuid": uuid, "changed": [name]}

    def custom_rm(self, uuid, name):
        self._mutable()
        entry = self._entry(uuid)
        self._archive_entry(entry)
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

    def attach_add(self, uuid, name, data, *, replace=False):
        """Attach BYTES to an entry — never a path (I4), never a temp file (I10).

        `data` is bytes and not base64: base64 is how the content crosses the
        helper's stdin, and decoding it is the helper's job. A backend that
        also accepted base64 would have two entry points for the same operation
        and one of them would eventually get the length check wrong.
        """
        self._mutable()
        entry = self._entry(uuid)
        if not isinstance(name, str) or not name:
            raise Invalid("an attachment needs a name")
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise Invalid("the attachment content must be bytes")
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
        self._archive_entry(entry)
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
        self._archive_entry(entry)
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

        `index` addresses `history()`'s list, oldest first. A NEGATIVE index is
        `NotFound` and not a Python end-relative lookup: `history()` publishes
        0..n-1, so `-1` is a caller that got its arithmetic wrong, and quietly
        restoring the newest version instead of refusing would overwrite the
        entry with something the operator never picked.

        The version to restore is captured BEFORE the archive step on purpose.
        `_archive_entry` prunes to the database's history policy and can drop
        the very element being restored; the lxml element is already held here,
        with its own subtree, so the restore still does what was asked.
        """
        self._mutable()
        entry = self._entry(uuid)
        versions = entry.history
        try:
            index = int(index)
        except (TypeError, ValueError):
            raise NotFound("no such history version")
        if index < 0 or index >= len(versions):
            raise NotFound("no such history version")
        old = versions[index]
        self._archive_entry(entry)
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
        return {"uuid": uuid, "restored_from": index}

    def history_rm(self, uuid, index=None, all=False):      # noqa: A002
        self._mutable()
        entry = self._entry(uuid)
        versions = entry.history
        if all:
            if versions:
                entry.delete_history(all=True)
            return {"ok": True, "removed": len(versions)}
        try:
            index = int(index)
        except (TypeError, ValueError):
            raise NotFound("no such history version")
        # Same reasoning as history_restore: `history()` publishes 0..n-1, so a
        # negative index is a caller mistake and must not silently delete the
        # newest version instead.
        if index < 0:
            raise NotFound("no such history version")
        try:
            old = versions[index]
        except IndexError:
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

    def save_as(self, target_path, *, override_stale=False):
        """Write this database to a NEW path. The original is not touched.

        "Not touched" is enforced by construction rather than by care:

          * `atomic_replace` is called with `expect_fingerprint=None` against a
            path that `validate_new_path` has just proved does not exist, so it
            never opens the original, never re-fingerprints it, and its backup
            step finds nothing to back up. The original's `.bak.d` ring is not
            entered at all.
          * the `LockFile` taken is the TARGET's. Taking the original's would
            be both pointless (we are not writing it) and harmful (it would
            block the desktop client for the duration of a copy). That is also
            what `override_stale` refers to here: two concurrent copies to the
            same destination.
          * `self.fingerprint` is deliberately NOT updated. It still describes
            the file this object was unlocked from, so a later `save()` still
            performs its changed-on-disk re-check against the right file (I13).

        The refusals are `save()`'s, for `save()`'s reasons: KDBX 3.x is not
        written at all (I20 — a new name does not give the format authenticated
        encryption), and a database that would drop a field on serialisation
        drops it into a copy just as thoroughly (I22).

        `require_writable()` is deliberately NOT called. The registry's
        `mode: "ro"` is a statement about THAT file — "do not modify this safe"
        — and a copy modifies nothing. Whether the operator may write a
        decrypted-then-re-encrypted database somewhere else at all is I21, and
        that gate belongs to the helper, which owns `export_allowed` and the
        destination directory.
        """
        self.require_unlocked()
        if self._format_ro:
            raise Unsupported(
                "KDBX 3.x has no authenticated encryption, so this backend "
                "never writes it; use upgrade_to_kdbx4 to convert it")
        self._assert_lossless()
        validate_new_path(target_path)

        with LockFile(target_path, fmt="kdbx", override_stale=override_stale):
            data = self._serialize(reseed=True)
            # Same check `save()` runs, and for the sharper reason: this file
            # is about to be the only copy of something an operator intends to
            # rely on, and nothing else will ever have verified it.
            self._verify_own_output(data)
            result = atomic_replace(target_path, data,
                                    expect_fingerprint=None)
        return {"path": target_path, "bytes": result["bytes"]}

    # -- plaintext export  (I21) ------------------------------------------

    def export_plain(self, *, fmt):
        """**The single most dangerous method in this codebase.** See the ABC.

        One call returns every password, note, TOTP seed and protected custom
        field in the safe, decrypted, in the clear — including every archived
        password in every history version, which not even `reveal()` can reach.
        It exists because an operator who cannot get their credentials out of a
        tool does not trust the tool; it is gated because it is the shape of
        every credential-exfiltration incident there has ever been (I21).

        Three formats, all of which a foreign tool can actually read:

          csv   KeePassXC's own ten export columns, in its order, so the file
                imports into KeePassXC's CSV importer unchanged — then five
                more of ours (tags, expiry, attachment NAMES, custom fields as
                JSON) that KeePassXC's own CSV silently drops. Extra trailing
                columns are ignored by a column-mapped importer.
          xml   KeePass 2 XML in the dialect `keepassxc-cli export --format
                xml` emits: protected values in the clear under
                `ProtectInMemory="True"` rather than `Protected="True"`, which
                is what tells a reader the value is NOT stream-encrypted. That
                one attribute is the whole difference between a file KeePass
                imports and a file it decodes into mojibake.
          json  everything the other two cannot say — history, per-field
                protection flags, icons, times, group tree — in this project's
                own shape. No other tool reads it; it is the format for a
                migration you are going to script.

        Attachment CONTENT is excluded from all three and attachment NAMES are
        listed. `keepassxc-cli export --format xml` does the same thing (it
        writes `Ref="0"` for every binary), so this matches the reference tool
        rather than inventing a rule.
        """
        self.require_unlocked()
        if fmt == "csv":
            return self._export_csv()
        if fmt == "xml":
            return self._export_xml()
        if fmt == "json":
            return self._export_json()
        raise Unsupported("%s is not an export format this backend writes"
                          % str(fmt)[:16])

    #: KeePassXC 2.7.10's `export --format csv` header, verbatim and in order,
    #: measured on this host. Ours are appended AFTER these so a column-mapped
    #: importer that only knows KeePassXC's set still lines up.
    _CSV_KEEPASSXC = ("Group", "Title", "Username", "Password", "URL", "Notes",
                      "TOTP", "Icon", "Last Modified", "Created")
    _CSV_EXTRA = ("Tags", "Expires", "Expiry Time", "Attachments",
                  "Custom Fields")

    def _export_csv(self):
        buf = io.StringIO()
        # QUOTE_ALL and CRLF are what KeePassXC writes and what RFC 4180 asks
        # for. A password can contain a comma, a quote, a newline and a NUL-
        # adjacent control character; quoting everything is the only setting
        # under which the file a migrator reads back is the file we meant.
        #
        # RFC-4180 quoting is NOT a formula-injection defence — a spreadsheet
        # parses a quoted cell that begins with `=` as a formula just the same.
        # `CsvWriter` is `csv.writer` with `csv_cell` applied to every field;
        # see its docstring for the hazard and the fidelity cost.
        writer = CsvWriter(buf)
        writer.writerow(self._CSV_KEEPASSXC + self._CSV_EXTRA)
        for entry in self._export_entries():
            custom = {name: value for name, value, _p in
                      self._custom_fields(entry)}
            writer.writerow([
                _group_path(entry.group),
                entry.title or "",
                entry.username or "",
                entry.password or "",
                entry.url or "",
                entry.notes or "",
                _totp_uri(entry),
                str(entry.icon or ""),
                _iso(entry.mtime),
                _iso(entry.ctime),
                ";".join(entry.tags or []),
                "True" if entry.expires else "False",
                _iso(entry.expiry_time) if entry.expires else "",
                "; ".join(a.filename for a in entry.attachments),
                json.dumps(custom, ensure_ascii=False, sort_keys=True)
                if custom else "",
            ])
        # Read by the `export` verb so the operator is TOLD that cells were
        # changed rather than discovering an apostrophe later. See
        # base.CsvWriter / base.csv_cell for why the change is made at all.
        self.last_export_neutralised = writer.neutralised
        return buf.getvalue().encode("utf-8")

    def _export_xml(self):
        """KeePass 2 XML, protected values in the clear, no attachment bytes."""
        root = deepcopy(self._kp.tree.getroot())
        # Protected="True" is the marker pykeepass's stream adapter matches on
        # when it RE-ENCRYPTS a value at build time; a plaintext export that
        # kept it would be read back as base64 ciphertext by anything that
        # believed it. KeePassXC's own export renames it, and so do we.
        for value in root.iter("Value"):
            if (value.get("Protected") or "").strip() == "True":
                del value.attrib["Protected"]
                value.set("ProtectInMemory", "True")
        # KDBX3 keeps attachment BYTES here as base64 gzip. KDBX4 keeps them in
        # the inner header, which is not part of this tree at all, so this loop
        # is the KDBX3 case and the one place bytes could leak into an export
        # that promised only names.
        meta = root.find("Meta")
        if meta is not None:
            binaries = meta.find("Binaries")
            if binaries is not None:
                meta.remove(binaries)
        return etree.tostring(root, pretty_print=True, encoding="UTF-8",
                              xml_declaration=True, standalone=True)

    def _export_json(self):
        groups = []
        stack = [(self._kp.root_group, None, 0)]
        while stack:
            group, parent, depth = stack.pop()
            if depth > Limits.MAX_GROUP_DEPTH:
                raise Invalid("the group tree is nested deeper than %d levels"
                              % Limits.MAX_GROUP_DEPTH)
            uuid = str(group.uuid)
            groups.append({"uuid": uuid, "name": group.name, "parent": parent,
                           "path": _group_path(group),
                           "notes": group.notes or ""})
            for sub in reversed(group.subgroups):
                stack.append((sub, uuid, depth + 1))

        document = {
            "format": "kdbx",
            "version": self._header.version,
            "generator": "cockpit-secrets %s" % VERSION,
            "exported": _iso(_dt.datetime.now(_dt.timezone.utc)),
            "database": {
                "name": self._kp.database_name,
                "description": self._kp.database_description,
                "default_username": self._kp.default_username,
            },
            "groups": groups,
            "entries": [self._export_entry_json(e, history=True)
                        for e in self._export_entries()],
        }
        return json.dumps(document, ensure_ascii=False, indent=1,
                          sort_keys=False).encode("utf-8")

    def _export_entries(self):
        """The entries an export covers, in the order `entries()` lists them.

        Built from `self._index`, which `_reindex` already proved has no
        duplicate uuid — so an export cannot silently carry two rows that a
        later import would collapse into one.
        """
        return sorted(self._index.values(),
                      key=lambda e: ((e.title or "").casefold(), str(e.uuid)))

    @staticmethod
    def _custom_fields(entry):
        """`[(name, value, protected)]` for every non-reserved string field."""
        out = []
        for key in _entry_field_keys(entry):
            if key in _RESERVED_FIELDS:
                continue
            out.append((key, _field_value(entry, key) or "",
                        _field_protected(entry, key)))
        return sorted(out)

    def _export_entry_json(self, entry, history=False):
        row = {
            "uuid": str(entry.uuid),
            "group": _group_path(entry.group) if entry.group is not None
            else "",
            "title": entry.title or "",
            "username": entry.username or "",
            "password": entry.password or "",
            "url": entry.url or "",
            "notes": entry.notes or "",
            "tags": list(entry.tags or []),
            "icon": entry.icon,
            "custom_icon": entry._element.findtext("CustomIconUUID"),
            "totp_uri": _totp_uri(entry),
            "custom_fields": [{"name": n, "value": v, "protected": p}
                              for n, v, p in self._custom_fields(entry)],
            # Names and sizes. The bytes are what `attach_get` is for — see the
            # method docstring for why an export does not carry them.
            "attachments": [{"name": a.filename,
                             "size": len(_attachment_bytes(a, strict=False))}
                            for a in entry.attachments],
            "expires": bool(entry.expires),
            "times": {
                "created": _iso(entry.ctime),
                "modified": _iso(entry.mtime),
                "accessed": _iso(entry.atime),
                "expires": _iso(entry.expiry_time),
            },
        }
        if history:
            # One level only. A history version's own History element is
            # stripped by KeePass when it archives, so there is nothing below
            # this — and recursing on a file that DID nest them would be an
            # unbounded walk over attacker-shaped XML.
            row["history"] = [self._export_entry_json(old, history=False)
                              for old in entry.history]
        return row

    @staticmethod
    def verify_structure(data):
        """See `Backend.verify_structure`. Walks the file, decrypts nothing.

        KDBX4 is fully checkable without a key: the outer header ends with a
        SHA-256 and an HMAC, and the payload is a chain of
        `hmac(32) | length(u32 LE) | bytes` blocks ending in a zero-length one.
        Walking those lengths proves the file is whole, and none of it needs
        the transformed key — the MACs are simply not compared.

        KDBX 3.x has no block framing (the whole payload is one CBC stream), so
        the strongest key-free statement available is that the ciphertext is
        present and a whole number of cipher blocks. That is weaker, and saying
        so here is better than implying a check we cannot make.
        """
        hdr = _read_header(data)          # raises Invalid on a short header
        if hdr.major < 4:
            body = len(data) - hdr.end
            if body <= 0:
                raise Invalid("this file has a KDBX header and no payload")
            if body % 16:
                raise Invalid("this KDBX 3.x payload is not a whole number of "
                              "cipher blocks; the file is truncated")
            return
        end = hdr.end
        if len(data) < end + 64:
            raise Invalid("this file is truncated before its header hashes")
        off = end + 64
        index = 0
        while True:
            if off + 36 > len(data):
                raise Invalid("this KDBX payload is truncated")
            blen = struct.unpack_from("<I", data, off + 32)[0]
            Limits.check_length(blen, len(data) - (off + 36),
                                "KDBX payload block")
            off += 36 + blen
            index += 1
            if blen == 0:
                break
            if index > 1 + (Limits.MAX_SAFE_BYTES // 1024):
                raise Invalid("this KDBX payload has an implausible block "
                              "count")
        if off != len(data):
            # Trailing bytes after the terminator mean the file is not the
            # thing it claims to be — a concatenation, or a partially
            # overwritten generation.
            raise Invalid("this KDBX file carries %d bytes after the end of "
                          "its payload" % (len(data) - off))

    def _verify_own_output(self, data):
        """Prove we can READ what we are about to write, before we write it.

        A writer and a reader that share a bug round-trip perfectly (I19), so
        this is not evidence of compliance — the interop oracle is. What it IS
        evidence of is that the bytes about to replace a working database are
        ones THIS PROGRAM can open again, which is a promise the operator is
        entitled to and which this method used not to keep.

        It used to run only `_verify_kdbx4`/`_verify_kdbx3` — header hash and
        per-block HMAC. Those never decompress and never parse, so every
        refusal that lives downstream of them was invisible here. Measured: one
        `attach_add` of an ordinary 8 MiB log file (well inside
        `Limits.MAX_ATTACHMENT_BYTES`) produced a 33 KB database that passed
        every MAC, was written over the live safe with `{"ok": true}`, and was
        then refused by our own `unlock` at every later attempt. The round-trip
        guard that would have caught it — `_assert_lossless` — had latched
        `self._lossless = True` before the attachment existed and short-circuits
        on every later call, so it never looked at the mutated database at all.
        That latch is right for its own job (an EARLY warning that this file
        cannot be written at all) and wrong as a pre-write check, so the
        pre-write check now stands on its own and runs EVERY time:

          1. the MACs, as before — a truncated build or a mismatched seed;
          2. a full re-open through the SAME reader path a later `unlock` uses,
             including `_bounded_decompress` and the hardened XML parser, so any
             read-side refusal is a save that fails rather than a safe that is
             gone;
          3. `_diff_xml` against the tree we are serialising, so I22's "a save
             must not silently drop a field" holds for THESE bytes rather than
             for the state the database happened to be in at the first mutation.

        The cost is one symmetric decrypt and one parse per save, with no KDF —
        the same price `_assert_lossless` already pays once, now paid each time
        a database is written. A save is not a hot path, and the alternative is
        the failure above.
        """
        hdr = _read_header(data)
        if hdr.major >= 4:
            _verify_kdbx4(data, hdr, self._tk.bytes)
        else:
            _verify_kdbx3(data, hdr, self._tk.bytes)
        try:
            with Limits.parse_budget(what="verifying the database we built"):
                probe = PyKeePass(io.BytesIO(data),
                                  transformed_key=self._tk.bytes)
        except SecretsError as exc:
            # The reader refused our own output. Conflict, not Internal: this
            # is the same class of "this database cannot be written" answer
            # `_fail_lossless` gives, the live file is untouched, and the detail
            # names what the reader objected to so the operator can undo the
            # change that caused it.
            raise Conflict("the database we built cannot be read back, so it "
                           "was not written: %s" % exc.detail)
        except Exception as exc:
            raise Conflict("the database we built cannot be read back, so it "
                           "was not written: %s"
                           % self._map_pykeepass_error(exc).detail)
        lost = _diff_xml(self._kp.tree.getroot(), probe.tree.getroot())
        if lost:
            self._fail_lossless("; ".join(lost[:5]), lost[0])

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
        # The absolute / normal-form / not-under-/tmp / does-not-already-exist
        # rules used to be spelled out here and are now `validate_new_path` in
        # base.py, shared with `save_as`. Two copies of a refusal list is how
        # one of them quietly loses a case: this is the only other operation
        # that creates a database at a path the registry does not name, and it
        # must refuse exactly what that one refuses.
        validate_new_path(dest_path)
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

#: Said at every unlock of a safe whose registry entry declares a hardware
#: token, because the operator's mental model of a second factor ("the token has
#: to be present each time") is not what this file actually gives them.
#:
#: The challenge IS the KDF seed (see `_challenge_bytes`), and `_serialize`
#: deliberately does not rotate the KDF seed — it cannot, because a new seed is
#: a new challenge and computing the answer to it needs the token again at SAVE
#: time, which this protocol has no round for. KeePassXC's `Kdbx4Writer` calls
#: `Kdf::randomizeSeed()` on every save and re-challenges the token, so under
#: KeePassXC a captured 20-byte answer stops working at the operator's next
#: save; here it keeps working for as long as the file exists.
#:
#: docs/RESIDUAL-RISK.md carries the argument for why the two available
#: mechanical fixes — a second challenge round in the unlock protocol, or
#: holding the composite key and paying a full KDF on every save — were judged
#: worse than saying this out loud. Saying nothing was not one of the options.
_YUBIKEY_CONSTANT_CHALLENGE_WARNING = (
    "this safe's hardware-token challenge is its KDF seed, and this program "
    "does not rotate that seed when it saves: the token's answer for this file "
    "is the same value every time, so anyone who observes it once can open the "
    "file until the file is re-keyed elsewhere. KeePassXC rotates the seed on "
    "every save and retires the previous answer.")


def _totp_remaining(otp):
    """Seconds until the current TOTP window rolls over."""
    interval = getattr(otp, "interval", 30) or 30
    return int(interval - (int(time.time()) % interval))


def _group_path(group):
    """`"Root/Lab/Nested"` — the slash form `keepassxc-cli export` writes.

    Built by walking `parentgroup` rather than by using pykeepass's own `path`,
    because that property renders the root as an empty component and an export
    column that starts with a bare "/" for every top-level entry is one a
    migrator has to clean up by hand. The depth cap is here and not only in
    `tree()`: a cyclic parent chain in a hand-built file would otherwise spin
    forever inside an export, which is the one operation that has no other
    bound on its work.
    """
    parts = []
    walk = group
    while walk is not None:
        if len(parts) > Limits.MAX_GROUP_DEPTH:
            raise Invalid("the group tree is nested deeper than %d levels"
                          % Limits.MAX_GROUP_DEPTH)
        parts.append(walk.name or "")
        walk = walk.parentgroup
    return "/".join(reversed(parts))


def _totp_uri(entry):
    """The entry's OTP configuration as an `otpauth://` URI, or `""`.

    An export has to carry the SEED, not a code: a code is valid for thirty
    seconds and a migration is not. `otpauth://` is the one encoding every
    authenticator, KeePassXC and KeePass 2.x all accept, so both stored
    dialects are normalised into it here rather than exported as whichever
    private form the database happened to use.

    Returns `""` — never raises — for an entry whose OTP configuration is
    malformed. An export must not fail on one bad row out of a thousand; the
    other 999 credentials are why the operator ran it.
    """
    kind = _otp_config(entry)
    if kind is None:
        return ""
    label = urllib.parse.quote(entry.title or "OTP", safe="")
    account = urllib.parse.quote(entry.username or "", safe="")
    path = "%s:%s" % (label, account) if account else label
    try:
        if kind == "otp":
            raw = _field_value(entry, "otp") or ""
            if raw.startswith("otpauth://"):
                return raw                    # already the portable form
            params = {}
            for part in raw.split("&"):
                if "=" in part:
                    name, _, value = part.partition("=")
                    params[name.strip().casefold()] = value.strip()
            seed = params.get("key")
            if not seed:
                return ""
            query = {"secret": _b32(seed, "base32"),
                     "period": params.get("step") or "30",
                     "digits": params.get("size") or "6"}
            return "otpauth://totp/%s?%s" % (
                path, urllib.parse.urlencode(query))
        if kind == "timeotp":
            seed, encoding = _read_otp_secret(entry, _TIMEOTP_SECRET_FIELDS)
            algo = (_field_value(entry, "TimeOtp-Algorithm") or "").upper()
            query = {
                "secret": _b32(seed, encoding),
                "period": _field_value(entry, "TimeOtp-Period") or "30",
                "digits": _field_value(entry, "TimeOtp-Length") or "6",
                "algorithm": {"HMAC-SHA-256": "SHA256",
                              "HMAC-SHA-512": "SHA512"}.get(algo, "SHA1"),
            }
            return "otpauth://totp/%s?%s" % (
                path, urllib.parse.urlencode(query))
        seed, encoding = _read_otp_secret(entry, _HMACOTP_SECRET_FIELDS)
        query = {"secret": _b32(seed, encoding),
                 "counter": _field_value(entry, "HmacOtp-Counter") or "0"}
        return "otpauth://hotp/%s?%s" % (path, urllib.parse.urlencode(query))
    except (Invalid, Unsupported):
        return ""


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


# ===========================================================================
# self-check — runnable proof, in the shape base.py and psafe3.py set
# ===========================================================================

def _selfcheck():                                       # noqa: C901
    """`python3 -m backends.kdbx` — prove the parts nothing else can reach.

    This exists because two things in this module have no other test:

      * **the challenge-response key composition.** There is no YubiKey on this
        host, so the end-to-end path cannot run at all. What CAN be checked is
        the arithmetic — that the response is hashed before it joins the
        composite, that it joins LAST, and that the challenge is PKCS#7-padded
        to 64 bytes — and each of those is a value that produces a wrong key
        silently rather than an error when it is wrong.
      * **Twofish-CBC decryption.** The committed Twofish fixture is KDBX4, so
        it exercises the pykeepass payload path; `_decrypt_prefix`'s Twofish
        branch is KDBX3-only and no KDBX3+Twofish fixture exists. It is checked
        here directly against ciphertext Botan produced.

    Honest about what the vectors below are (I19): the composite-key digests
    are **regression** vectors, not interop vectors. Nobody but us has ever
    computed them. They pin the construction against a restatement of
    KeePassXC's `CompositeKey::rawKey(transformSeed)` written beside them, so
    an edit that reorders the concatenation or forgets the SHA-256 fails —
    which is their whole job. They do NOT show that a real YubiKey and a real
    KeePassXC would agree with us, and nothing on this host can.
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

    print("== hardware-token challenge and key composition ==")
    seed = bytes(range(32))
    ok("a 32-byte challenge is PKCS#7-padded to 64",
       _pkcs7_to(seed, 64) == seed + b"\x20" * 32)
    ok("an already-64-byte challenge is unchanged",
       _pkcs7_to(bytes(64), 64) == bytes(64))
    raises("an over-long challenge -> Invalid", Invalid,
           lambda: _pkcs7_to(bytes(65), 64))

    response = bytes(range(20))
    ok("the component is SHA-256 OF the response, not the response",
       _yubikey_component(response) == hashlib.sha256(response).digest())
    raises("a 19-byte response -> Invalid", Invalid,
           lambda: _yubikey_component(bytes(19)))
    raises("a 32-byte response -> Invalid", Invalid,
           lambda: _yubikey_component(bytes(32)))

    pw = Secret("correct horse battery staple")
    keyfile = Secret(bytes(range(32)))          # 32 raw bytes: used verbatim
    try:
        # The restatement, written from CompositeKey.cpp rather than from the
        # implementation: hash every static key first, then the SHA-256 of the
        # challenge-response answer, then SHA-256 the lot.
        want_pw_cr = hashlib.sha256(
            hashlib.sha256(bytes(pw.bytes)).digest()
            + hashlib.sha256(response).digest()).digest()
        want_all = hashlib.sha256(
            hashlib.sha256(bytes(pw.bytes)).digest()
            + bytes(keyfile.bytes)
            + hashlib.sha256(response).digest()).digest()
        got_pw_cr = _composite_key(pw, None, _yubikey_component(response))
        got_all = _composite_key(pw, keyfile, _yubikey_component(response))

        ok("passphrase + token matches the restatement",
           constant_time_eq(got_pw_cr, want_pw_cr))
        ok("passphrase + key file + token matches the restatement",
           constant_time_eq(got_all, want_all))
        # Frozen so that editing the code AND the restatement together still
        # fails. Computed here, by us, once — see the docstring.
        ok("passphrase + token matches the frozen regression vector",
           binascii.hexlify(got_pw_cr) == b"2ec9767e4a9bbeefd0294073f04bc2bf"
                                          b"7eaf8202119af35eb92be2e007f16b72")
        ok("passphrase + key file + token matches the frozen vector",
           binascii.hexlify(got_all) == b"7c99602d2ea8f4da6878cf0d38033b23"
                                        b"4a8141f084558ee8802c74afcb9cc553")
        # The ORDER is the thing a refactor breaks silently.
        ok("the token component is appended LAST, not prepended",
           not constant_time_eq(
               got_pw_cr,
               hashlib.sha256(hashlib.sha256(response).digest()
                              + hashlib.sha256(bytes(pw.bytes)).digest()
                              ).digest()))
        ok("no token means the composite is unchanged from before",
           constant_time_eq(
               _composite_key(pw, None),
               hashlib.sha256(hashlib.sha256(bytes(pw.bytes)).digest()
                              ).digest()))
    finally:
        pw.zero()
        keyfile.zero()

    print("\n== Twofish-CBC decryption (the KDBX3 branch) ==")
    try:
        import botan3 as botan
    except ImportError:
        print("  skip  python3-botan is not installed — the Twofish branch "
              "DID NOT RUN")
    else:
        key = hashlib.sha256(b"twofish selfcheck key").digest()
        iv = bytes(range(16))
        plain = b"KDBX3 stream start bytes, exactly 32 bytes here!"[:32]
        bc = botan.BlockCipher("Twofish")
        bc.set_key(key)
        cipher = bytearray()
        prev = iv
        for off in range(0, len(plain), 16):
            block = bytes(a ^ b for a, b in zip(plain[off:off + 16], prev))
            prev = bytes(bc.encrypt(block))
            cipher += prev
        hdr = KdbxHeader()
        hdr.cipher = "twofish"
        hdr.encryption_iv = iv
        ok("Botan-encrypted Twofish-CBC decrypts back to the plaintext",
           _decrypt_prefix(hdr, key, bytes(cipher), 32) == plain)

    print("\n== the committed Twofish fixture ==")
    fixture = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "tests", "fixtures",
        "lab-kdbx40-twofish-argon2d.kdbx")
    if not os.path.exists(fixture):
        print("  skip  %s is not present" % os.path.basename(fixture))
    else:
        # NOT /tmp. `save_as` refuses a destination there (world-writable, and
        # a decrypted-then-re-encrypted database landing in it is a
        # disclosure), so a scratch directory under /tmp would fail the very
        # check it is hosting. The XDG runtime directory is private, on this
        # host's own filesystem, and cleaned up by the session — the same
        # choice tests/integration/_env.py made for the same reason.
        base = os.environ.get("XDG_RUNTIME_DIR") or os.path.expanduser(
            "~/.cache")
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            base = None
        tmp = tempfile.mkdtemp(prefix="kdbx-selfcheck-", dir=base)
        os.chmod(tmp, 0o700)
        can_write_here = not tmp.startswith(("/tmp/", "/var/tmp/"))
        try:
            # Copied because open_safe_fd refuses a safe whose parent directory
            # is group-writable, and this source tree is 0775 over SMB. That
            # refusal is I5 working, not a problem with the fixture.
            local = os.path.join(tmp, "twofish.kdbx")
            shutil.copy2(fixture, local)
            os.chmod(local, 0o600)
            before = hashlib.sha256(open(local, "rb").read()).hexdigest()

            backend = KdbxBackend({"id": "tf", "label": "tf", "format": "kdbx",
                                   "path": local, "access": "admin",
                                   "mode": "rw"})
            secret = Secret("fixture-pass-do-not-reuse")
            try:
                backend.unlock(secret, None)
            finally:
                secret.zero()
            rows = backend.entries(limit=50)["entries"]
            router = [r for r in rows if r["title"] == "Router"][0]
            ok("the Twofish fixture opens and lists both entries",
               sorted(r["title"] for r in rows) == ["Router", "Switch"])
            ok("its protected password decrypts",
               backend.reveal(router["uuid"], "password")["value"]
               == "SENTINEL-DO-NOT-LEAK-8f3a2b")
            ok("history() on an entry with none is an empty list",
               backend.history(router["uuid"]) == [])

            for fmt, needle in (("csv", b"SENTINEL-DO-NOT-LEAK-8f3a2b"),
                                ("xml", b'ProtectInMemory="True"'),
                                ("json", b'"totp_uri"')):
                blob = backend.export_plain(fmt=fmt)
                ok("the %s export is produced and holds what it claims" % fmt,
                   isinstance(blob, bytes) and needle in blob)
            raises("an unknown export format -> Unsupported", Unsupported,
                   lambda: backend.export_plain(fmt="sqlite"))
            ok("no export carries attachment bytes",
               b"twofish fixture attachment"
               not in backend.export_plain(fmt="json"))

            copy = os.path.join(tmp, "copy.kdbx")
            raises("save_as under /tmp -> Invalid", Invalid,
                   lambda: backend.save_as("/tmp/never-written.kdbx"))
            raises("save_as to a relative path -> Invalid", Invalid,
                   lambda: backend.save_as("copy.kdbx"))
            if not can_write_here:
                print("  skip  no scratch directory outside /tmp is "
                      "available — the save_as checks DID NOT RUN")
            else:
                result = backend.save_as(copy)
                ok("save_as wrote the copy", os.path.exists(copy)
                   and result["bytes"] > 0)
                after = hashlib.sha256(open(local, "rb").read()).hexdigest()
                # constant_time_eq and not `==`: this is a digest comparison,
                # and every digest comparison in this tree goes through the one
                # helper so that the standing ban in validate.sh can be a plain
                # grep rather than a judgement call about which ones matter.
                ok("save_as left the original byte-for-byte identical",
                   constant_time_eq(after, before))
                ok("save_as took no backup of the original",
                   not os.path.exists(local + ".bak.d"))
                ok("save_as left no lock file beside the original",
                   not os.path.exists(local + ".lock"))
                raises("save_as onto an existing path -> Conflict", Conflict,
                       lambda: backend.save_as(copy))
            backend.lock()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print("kdbx self-check: %d FAILURE(S)" % len(failures))
        return 1
    print("kdbx self-check: OK")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selfcheck())


__all__ = ["KdbxBackend", "challenge_for", "VERSION"]
