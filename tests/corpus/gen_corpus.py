#!/usr/bin/env python3
"""gen_corpus.py — build the malformed-input corpus, one file per hazard.

TEST-ONLY. Nothing here is installed and nothing imports it at runtime.

WHAT THIS IS FOR
----------------
`docs/THREAT-MODEL.md` A3 is "a malicious or corrupted safe file", with full
control of the bytes — KDF parameters, field lengths, inner XML. Every file this
script writes is that adversary, made concrete and repeatable, and every one
comes with a sidecar `<name>.expect.json` stating:

    error           the taxonomy code from docs/CONTRACT.md the helper MUST
                    return (or null, when the correct behaviour is to ACCEPT
                    the file — see the zero-length-field and non-UTF-8 cases)
    error_acceptable  the codes a reviewer will accept, when the taxonomy
                    genuinely admits more than one right answer
    max_seconds     the wall clock the refusal must fit inside. This is the
                    half that catches the real bugs: "it eventually said no"
                    is not a defence against a KDF bomb (I7), and "it said no
                    after allocating 4 GiB" is not a defence at all.
    must_not_leak   strings that must appear NOWHERE in stdout, stderr or the
                    audit log for this case (I15).

WHY THE TIME BUDGET IS THE POINT
--------------------------------
Half these files are refused correctly by almost any implementation *eventually*.
The Argon2 m=4 GiB case is only mitigated if the parameters are clamped BEFORE
the KDF runs; a reader that derives first and validates second passes a
correctness test and still hands an unauthenticated file the ability to OOM the
helper — and on the admin path, root. So those cases carry a 2 second budget,
which no implementation can meet by accident.

HOW THE FILES ARE MADE
----------------------
Three techniques, deliberately, so that a bug in one does not silently disable
the whole corpus:

  1. BYTE SURGERY on a committed fixture — truncation, bit flips, and the
     KDF-parameter bombs. No crypto involved, so nothing here can be wrong in
     an interesting way.
  2. `tests/oracle/pws3_oracle forge` — for hazards that need a real Twofish
     body and a real HMAC over hostile plaintext. The Go oracle does the
     crypto; this script only decides what the plaintext says.
  3. pykeepass with `XML._encode` HOOKED (see raw_inner_xml) — for hazards that
     live in the decrypted KDBX inner XML: billion laughs, an external entity,
     10 000-deep nesting, duplicate UUIDs, non-UTF-8 in every string field, and
     the compression bombs. Hooking that one method lets arbitrary bytes take
     the place of the serialised tree, which is the only way to produce inner
     XML that no XML library would ever emit.

Run:  ./gen_corpus.py --build        (writes ./files/)
      ./gen_corpus.py --list         (prints the case table, builds nothing)
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.normpath(os.path.join(HERE, "..", "fixtures"))
ORACLE = os.path.normpath(os.path.join(HERE, "..", "oracle"))
PWS3_ORACLE = os.path.join(ORACLE, "pws3_oracle")
OUT_DEFAULT = os.path.join(HERE, "files")

# The two strings that must never come back out of a corpus file. Both live in
# the fixtures the corpus is derived from, so a parser that leaks decrypted
# material before the MAC verifies (I6) will show up as one of these appearing
# in a helper's output for a file that should have been refused outright.
SENTINELS = ["SENTINEL-DO-NOT-LEAK-8f3a2b", "tok-protected-do-not-leak-4c9d1e"]

# Budgets. A refusal that needs longer than this is a finding, not a slow test.
FAST = 2.0        # must be refused before any expensive work happens
NORMAL = 5.0      # one real KDF run plus the I16 constant-time failure floor
SLOW = 15.0       # decompression bombs and 10 000-deep trees

cases = []


# --------------------------------------------------------------- utilities --

def load_manifest():
    path = os.path.join(FIXTURES, "manifest.json")
    if not os.path.exists(path):
        sys.exit("gen_corpus.py: %s is missing — run tests/fixtures/gen_fixtures.sh "
                 "--build first" % path)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fixture(manifest, name):
    for f in manifest["fixtures"]:
        if f["file"] == name:
            return f
    sys.exit("gen_corpus.py: fixture %s is not in the manifest" % name)


def emit(outdir, name, data, *, fmt, base, hazard, ids, password, error,
         acceptable=None, seconds=FAST, notes="", keyfile=None,
         extra_no_leak=()):
    """Write one corpus file and its sidecar."""
    path = os.path.join(outdir, name)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)   # base.open_safe_fd refuses group/other bits

    if acceptable is None:
        acceptable = [error]
    expect = {
        "file": name,
        "format": fmt,
        "base": base,
        "hazard": hazard,
        "known_issues": ids,
        "password": password,
        "keyfile": keyfile,
        "error": error,
        "error_acceptable": acceptable,
        "max_seconds": seconds,
        "must_not_leak": SENTINELS + list(extra_no_leak),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "notes": notes,
    }
    with open(path + ".expect.json", "w", encoding="utf-8") as fh:
        json.dump(expect, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    cases.append(expect)
    return expect


# ------------------------------------------------------------ KDBX surgery --

def kdbx_layout(raw):
    """Walk the KDBX outer header without decrypting anything.

    KDBX3 header items are id(1) len(uint16 LE) data; KDBX4 uses uint32. Both
    terminate on id 0. Returns the offsets the truncation cases need. This is a
    dozen lines rather than a pykeepass call on purpose: the corpus must still
    be buildable when the thing it is testing is broken.
    """
    if raw[0:4] != b"\x03\xd9\xa2\x9a" or raw[4:8] != b"\x67\xfb\x4b\xb5":
        raise ValueError("not a KDBX file")
    minor, major = struct.unpack_from("<HH", raw, 8)
    lensize = 4 if major >= 4 else 2
    off = 12
    items = {}
    while True:
        tid = raw[off]
        ln = int.from_bytes(raw[off + 1:off + 1 + lensize], "little")
        data_off = off + 1 + lensize
        items.setdefault(tid, (data_off, ln))
        off = data_off + ln
        if tid == 0:
            break
    return {
        "major": major, "minor": minor, "items": items,
        "header_end": off,
        # KDBX4 only: SHA-256 of the header, then HMAC-SHA256 of the header,
        # then the HMAC'd block stream.
        "sha_end": off + 32,
        "hmac_end": off + 64,
    }


def flip(raw, offset):
    """Flip the low bit of one byte. One bit, so the change is unambiguous."""
    b = bytearray(raw)
    b[offset] ^= 0x01
    return bytes(b)


def patch_variant_dict(raw, off, length, updates):
    """Rewrite values inside the kdf_parameters VariantDictionary IN PLACE.

    Format: version(2) then items of type(1) keylen(4) key vallen(4) value,
    terminated by type 0. Only same-width replacements are made, so no length
    field anywhere in the file has to move — which keeps these cases pure
    "hostile parameters" and not accidentally "malformed container" as well.
    """
    b = bytearray(raw)
    p = off + 2
    end = off + length
    seen = {}
    while p < end:
        vtype = b[p]
        if vtype == 0:
            break
        klen = int.from_bytes(b[p + 1:p + 5], "little")
        key = bytes(b[p + 5:p + 5 + klen]).decode("ascii", "replace")
        vp = p + 5 + klen
        vlen = int.from_bytes(b[vp:vp + 4], "little")
        vstart = vp + 4
        seen[key] = (vtype, vstart, vlen)
        if key in updates:
            value = updates[key]
            if vlen == 8:
                b[vstart:vstart + 8] = struct.pack("<Q", value)
            elif vlen == 4:
                b[vstart:vstart + 4] = struct.pack("<I", value)
            else:
                raise ValueError("unexpected width %d for %s" % (vlen, key))
        p = vstart + vlen
    for key in updates:
        if key not in seen:
            raise ValueError("kdf parameter %s not present" % key)
    return bytes(b)


# -------------------------------------------- KDBX inner-XML construction ---

def raw_inner_xml(base_path, out_path, password, xml_bytes, keyfile=None):
    """Rebuild `base_path` with `xml_bytes` as its decrypted inner XML.

    pykeepass's XML adapter serialises an lxml tree with `etree.tostring`, so
    there is no legitimate way to make it emit bytes that are not well-formed
    XML — and "not well-formed" is exactly what several of these hazards are.
    Hooking `XML._encode` for the duration of one save substitutes our bytes
    for the serialised tree. Everything downstream of it stays real: the
    payload is compressed, encrypted, split into blocks and HMAC'd by
    pykeepass, so the resulting file is a genuine KDBX whose *contents* are
    hostile — which is the only kind of file worth testing with.

    This is corpus-generation surgery on a test dependency. It is not a pattern
    to copy anywhere near the helper.
    """
    from pykeepass import PyKeePass
    import pykeepass.kdbx_parsing.common as common

    shutil.copyfile(base_path, out_path)
    os.chmod(out_path, 0o600)
    kp = PyKeePass(out_path, password=password, keyfile=keyfile)

    original = common.XML._encode
    try:
        common.XML._encode = lambda self, tree, con, path: xml_bytes
        kp.save()
    finally:
        common.XML._encode = original

    with open(out_path, "rb") as fh:
        return fh.read()


def inner_xml_of(base_path, password, keyfile=None):
    """The decrypted, unprotected inner XML of a fixture, as bytes."""
    from lxml import etree
    from pykeepass import PyKeePass
    kp = PyKeePass(base_path, password=password, keyfile=keyfile)
    return etree.tostring(kp.kdbx.body.payload.xml)


# ----------------------------------------------------------- PWS3 building --

def pws3_forge(spec, out_path, password, seed="cockpit-secrets-corpus-v1"):
    """Run `pws3_oracle forge`. The passphrase goes on stdin, never argv (I10)."""
    if not os.path.exists(PWS3_ORACLE):
        sys.exit("gen_corpus.py: %s is missing — run tests/oracle/build.sh"
                 % PWS3_ORACLE)
    spec_path = out_path + ".forge.json"
    with open(spec_path, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2)
    try:
        proc = subprocess.run(
            [PWS3_ORACLE, "forge", "--file", out_path, "--json", spec_path,
             "--seed", seed],
            input=(password + "\n").encode(), capture_output=True, timeout=120)
        if proc.returncode != 0:
            sys.exit("gen_corpus.py: forge failed for %s: %s"
                     % (out_path, proc.stdout.decode("utf-8", "replace")))
    finally:
        os.remove(spec_path)
    with open(out_path, "rb") as fh:
        return fh.read()


def pws3_field(ftype, data, declared=None):
    """Encode one PWS3 field, optionally LYING about its length.

    formatV3.txt section 3: len(4 LE) | type(1) | up to 11 data bytes | random
    pad, then 16 bytes of data per further block. `declared` overrides the
    length that goes in the file without changing how many bytes follow — which
    is the whole hazard for the 0xFFFFFFFF and 2 GiB cases.
    """
    real = len(data)
    if declared is None:
        declared = real
    blocks = 1 + (0 if real <= 11 else (real - 11 + 15) // 16)
    buf = bytearray(b"\x00" * (blocks * 16))
    struct.pack_into("<I", buf, 0, declared & 0xFFFFFFFF)
    buf[4] = ftype
    buf[5:5 + min(real, 11)] = data[:11]
    if real > 11:
        buf[16:16 + (real - 11)] = data[11:]
    return bytes(buf)


# --------------------------------------------------------------- the cases --

def build_kdbx_structural(outdir, manifest):
    """Truncation and bit flips on the committed 4.1 and 3.1 fixtures."""
    for fixname in ("lab-kdbx41-aes256-argon2id.kdbx", "lab-kdbx31-aes256-aeskdf.kdbx"):
        meta = fixture(manifest, fixname)
        pw = meta["password"]
        tag = "kdbx41" if "41" in fixname else "kdbx31"
        with open(os.path.join(FIXTURES, fixname), "rb") as fh:
            raw = fh.read()
        lay = kdbx_layout(raw)

        # ---- truncation at every structural boundary -------------------
        points = [
            (4, "mid-signature", "half of the 8-byte KDBX signature"),
            (8, "after-signature", "signature complete, version missing"),
            (12, "after-version", "version complete, dynamic header missing"),
            (lay["header_end"] - 1, "mid-header", "inside the last header item"),
            (lay["header_end"], "after-header", "dynamic header complete, nothing after it"),
        ]
        if lay["major"] >= 4:
            points += [
                (lay["sha_end"], "after-header-sha256",
                 "header SHA-256 present, header HMAC missing"),
                (lay["hmac_end"], "after-header-hmac",
                 "header verified, block stream missing"),
                (lay["hmac_end"] + 16, "mid-block-hmac",
                 "inside the first payload block's HMAC"),
                (lay["hmac_end"] + 40, "mid-block-data",
                 "inside the first payload block's data"),
            ]
        else:
            points += [
                (lay["header_end"] + 16, "mid-payload",
                 "inside the encrypted payload; KDBX3 has no MAC to notice (I20)"),
            ]
        points.append((len(raw) - 1, "last-byte", "one byte short of complete"))

        for offset, label, why in points:
            if offset <= 0 or offset >= len(raw):
                continue
            # Truncation before the credentials are ever used is a structural
            # fault -> invalid. Truncation inside the ciphertext cannot be told
            # from a wrong passphrase without an oracle, so bad-credential is
            # also a correct answer there (I6).
            structural = offset <= lay["header_end"] or (
                lay["major"] >= 4 and offset <= lay["hmac_end"])
            err = "invalid"
            acc = ["invalid"] if structural else ["invalid", "bad-credential"]
            emit(outdir, "%s-trunc-%s.kdbx" % (tag, label), raw[:offset],
                 fmt="kdbx", base=fixname,
                 hazard="truncated at %d bytes (%s)" % (offset, why),
                 ids=["I6"], password=pw, error=err, acceptable=acc,
                 seconds=FAST if structural else NORMAL,
                 notes="A truncated safe must be refused whole. Never 'recover "
                       "what you can' — a partial parse of an unauthenticated "
                       "file is the decryption oracle I6 exists to prevent.")

        # ---- a flipped bit in the header --------------------------------
        seed_off, seed_len = lay["items"][4]          # master seed
        emit(outdir, "%s-flip-header.kdbx" % tag, flip(raw, seed_off),
             fmt="kdbx", base=fixname,
             hazard="one bit flipped in the master seed header item",
             ids=["I6"], password=pw,
             error="invalid" if lay["major"] >= 4 else "bad-credential",
             acceptable=["invalid", "bad-credential"],
             seconds=NORMAL,
             notes=("KDBX4 carries TWO integrity values over its header: an "
                    "UNKEYED SHA-256 and an HMAC-SHA-256 under the derived key. "
                    "The SHA-256 is checked first and is credential-independent "
                    "— it fails identically for every passphrase, and anyone "
                    "holding the file can compute it — so a mismatch is "
                    "`invalid`, not an oracle. `bad-credential` is the answer "
                    "only when a reader skips the unkeyed hash and lets the "
                    "header HMAC catch it; both are accepted. KDBX3 has neither "
                    "(I20) — it simply derives the wrong key, which is why KDBX3 "
                    "is opened read-only with a banner. The constant-time floor "
                    "in secrets-admin is what makes the two indistinguishable by "
                    "a stopwatch (MEASURED: 0.90 s either way)."))

        # ---- a flipped bit in the ciphertext ----------------------------
        ct_off = (lay["hmac_end"] + 36) if lay["major"] >= 4 else (lay["header_end"] + 8)
        if ct_off < len(raw):
            emit(outdir, "%s-flip-ciphertext.kdbx" % tag, flip(raw, ct_off),
                 fmt="kdbx", base=fixname,
                 hazard="one bit flipped inside the encrypted payload",
                 ids=["I6"], password=pw, error="bad-credential",
                 acceptable=["bad-credential", "invalid"], seconds=NORMAL,
                 notes="Must be indistinguishable from a wrong passphrase in what "
                       "the client is told (I6). The distinction belongs in the "
                       "audit log, not in the response.")

        # ---- a flipped bit in the MAC -----------------------------------
        if lay["major"] >= 4:
            emit(outdir, "%s-flip-header-hmac.kdbx" % tag,
                 flip(raw, lay["header_end"] + 32),
                 fmt="kdbx", base=fixname,
                 hazard="one bit flipped in the header HMAC",
                 ids=["I6"], password=pw, error="bad-credential",
                 seconds=NORMAL,
                 notes="The header HMAC is the first thing KDBX4 can check. "
                       "Nothing may be decrypted before it verifies.")
            emit(outdir, "%s-flip-block-hmac.kdbx" % tag,
                 flip(raw, lay["hmac_end"] + 4),
                 fmt="kdbx", base=fixname,
                 hazard="one bit flipped in the first payload block's HMAC",
                 ids=["I6"], password=pw, error="bad-credential",
                 seconds=NORMAL,
                 notes="KDBX4 authenticates per block; a block whose tag fails "
                       "must abort the whole read, not skip the block.")

            # ---- a hostile block length ---------------------------------
            b = bytearray(raw)
            struct.pack_into("<I", b, lay["hmac_end"] + 32, 0xFFFFFFFF)
            emit(outdir, "%s-blocklen-ffffffff.kdbx" % tag, bytes(b),
                 fmt="kdbx", base=fixname,
                 hazard="first payload block declares 0xFFFFFFFF bytes",
                 ids=["I6", "I7"], password=pw, error="invalid",
                 acceptable=["invalid", "bad-credential"], seconds=FAST,
                 notes="4 GiB declared by an unauthenticated length field. The "
                       "budget is the assertion: refusing after allocating it is "
                       "not refusing.")
            b = bytearray(raw)
            struct.pack_into("<I", b, lay["hmac_end"] + 32, 0)
            emit(outdir, "%s-blocklen-zero.kdbx" % tag, bytes(b),
                 fmt="kdbx", base=fixname,
                 hazard="first payload block declares 0 bytes",
                 ids=["I6"], password=pw, error="bad-credential",
                 acceptable=["invalid", "bad-credential"], seconds=NORMAL,
                 notes="A zero-length block is the end-of-stream marker, so this "
                       "is an empty payload with a bad HMAC. A reader that loops "
                       "on it instead of terminating is the bug being hunted.")


def build_kdbx_kdf(outdir, manifest):
    """Attacker-chosen KDF parameters (I7). These must be refused BEFORE the KDF."""
    fixname = "lab-kdbx41-aes256-argon2id.kdbx"
    meta = fixture(manifest, fixname)
    pw = meta["password"]
    with open(os.path.join(FIXTURES, fixname), "rb") as fh:
        raw = fh.read()
    lay = kdbx_layout(raw)
    kdf_off, kdf_len = lay["items"][11]        # kdf_parameters

    bombs = [
        ("argon2-m-4gib", {"M": 4 * 1024 ** 3},
         "Argon2 memory = 4 GiB",
         "Limits.ARGON2_MAX_MEMORY_KIB is 1 GiB. Deriving first and validating "
         "second turns a hostile file into a remote OOM of the helper — and on "
         "the admin path, of root."),
        ("argon2-t-1000000", {"I": 1000000},
         "Argon2 time cost = 1 000 000",
         "Limits.ARGON2_MAX_TIME is 32. At the fixture's 32 MiB this would run "
         "for days."),
        ("argon2-p-255", {"P": 255},
         "Argon2 parallelism = 255",
         "Limits.ARGON2_MAX_PARALLELISM is 8. Parallelism multiplies the memory "
         "the KDF actually touches."),
        ("argon2-all-max", {"M": 4 * 1024 ** 3, "I": 1000000, "P": 255},
         "Argon2 m=4 GiB, t=1 000 000, p=255 together",
         "All three at once, in case a reader checks them one at a time and "
         "stops at the first."),
    ]
    for name, updates, hazard, note in bombs:
        data = patch_variant_dict(raw, kdf_off, kdf_len, updates)
        emit(outdir, "kdbx41-%s.kdbx" % name, data,
             fmt="kdbx", base=fixname, hazard=hazard, ids=["I7"],
             password=pw, error="invalid", seconds=FAST,
             notes=note + " The 2 s budget is the real assertion: a reader that "
                          "clamps AFTER deriving cannot meet it.")

    # AES-KDF rounds on the KDBX 3.1 fixture: same hazard, different knob.
    fixname3 = "lab-kdbx31-aes256-aeskdf.kdbx"
    meta3 = fixture(manifest, fixname3)
    with open(os.path.join(FIXTURES, fixname3), "rb") as fh:
        raw3 = fh.read()
    lay3 = kdbx_layout(raw3)
    rounds_off, rounds_len = lay3["items"][6]   # transform_rounds, uint64 LE
    b = bytearray(raw3)
    struct.pack_into("<Q", b, rounds_off, 1000000000)
    emit(outdir, "kdbx31-aeskdf-rounds-1e9.kdbx", bytes(b),
         fmt="kdbx", base=fixname3,
         hazard="AES-KDF transform rounds = 1 000 000 000",
         ids=["I7", "I20"], password=meta3["password"], error="invalid",
         seconds=FAST,
         notes="Limits.AESKDF_MAX_ROUNDS is 100 000 000. KDBX3 carries the round "
               "count in an UNAUTHENTICATED header (I20), so this cannot even be "
               "detected as tampering — only clamped.")


def build_kdbx_inner(outdir, manifest):
    """Hazards that live in the decrypted inner XML."""
    fixname = "lab-kdbx41-aes256-argon2id.kdbx"
    meta = fixture(manifest, fixname)
    pw = meta["password"]
    base_path = os.path.join(FIXTURES, fixname)
    good = inner_xml_of(base_path, pw)
    body = good.split(b"?>", 1)[-1] if good.startswith(b"<?xml") else good

    def set_db_name(xml, payload):
        """Replace the DatabaseName element's content, whatever shape it has.

        The naive `replace(b"<DatabaseName/>", ...)` silently does nothing on a
        fixture that already has a name — and a hazard file that quietly lost
        its hazard is worse than no hazard file at all.
        """
        new = b"<DatabaseName>" + payload + b"</DatabaseName>"
        out, n = re.subn(rb"<DatabaseName\s*(?:/>|>.*?</DatabaseName>)", new, xml, count=1,
                         flags=re.S)
        if n != 1:
            raise RuntimeError("could not place the payload in DatabaseName")
        return out

    def build(name, xml_bytes, hazard, ids, error, acceptable=None,
              seconds=SLOW, notes="", extra_no_leak=()):
        path = os.path.join(outdir, name)
        data = raw_inner_xml(base_path, path, pw, xml_bytes)
        emit(outdir, name, data, fmt="kdbx", base=fixname, hazard=hazard,
             ids=ids, password=pw, error=error, acceptable=acceptable,
             seconds=seconds, notes=notes, extra_no_leak=extra_no_leak)

    # ---- billion laughs -----------------------------------------------
    laughs = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
              b'<!DOCTYPE KeePassFile [\n'
              b'  <!ENTITY a "aaaaaaaaaa">\n'
              b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
              b'  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
              b'  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">\n'
              b'  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">\n'
              b'  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">\n'
              b'  <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">\n'
              b'  <!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">\n'
              b'  <!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;">\n'
              b'  <!ENTITY j "&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;">\n'
              b']>\n') + set_db_name(body, b"&j;")
    build("kdbx41-xml-billion-laughs.kdbx", laughs,
          "billion laughs: ten nested entity levels, 10^10 characters",
          ["I8"], "invalid", ["invalid", "bad-credential"],
          notes="The inner XML is only 'ours' AFTER the MAC verifies, and even "
                "then it is attacker-shaped. lxml must be constructed with "
                "resolve_entities=False, load_dtd=False, no_network=True, "
                "huge_tree=False — never trusted to default that way.")

    # ---- external entity ----------------------------------------------
    # Three entities on purpose:
    #   shadow   the real target — only readable when the helper is euid 0, i.e.
    #            on the admin path, which is exactly where it would hurt most
    #   hostname world-readable, so entity resolution is DETECTABLE even when
    #            the test runs unprivileged. Without this the case silently
    #            passes as a non-root user whether or not the parser is safe.
    #   ssrf     no_network=True has to be set too; a parser that fetches this
    #            has turned a safe file into a request from the host
    xxe = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
           b'<!DOCTYPE KeePassFile [\n'
           b'  <!ENTITY shadow SYSTEM "file:///etc/shadow">\n'
           b'  <!ENTITY hostname SYSTEM "file:///etc/hostname">\n'
           b'  <!ENTITY ssrf SYSTEM "http://127.0.0.1:9090/">\n'
           b']>\n') + set_db_name(body, b"&shadow;|&hostname;|&ssrf;")
    with open("/etc/hostname", "rb") as fh:
        hostname_marker = fh.read().decode("utf-8", "replace").strip()
    build("kdbx41-xml-external-entity.kdbx", xxe,
          "external entities: file:///etc/shadow, file:///etc/hostname and a "
          "loopback HTTP URL",
          ["I8"], "invalid", ["invalid", "bad-credential"],
          extra_no_leak=[hostname_marker, "root:x:", "root:!"],
          notes="If this file's contents ever contain the host's name, a root: "
                "line, or an HTTP response, the parser resolved entities and "
                "this is file disclosure and SSRF, not a parsing bug. The "
                "hostname entity is the one that makes the case meaningful when "
                "the test runs as a non-root user, since /etc/shadow would come "
                "back empty for them anyway. MEASURED: keepassxc-cli 2.7.10 OPENS this file, so no foreign oracle catches this one — the cap in backends/base.py Limits is the only defence. Construct lxml with "
                "resolve_entities=False, load_dtd=False, no_network=True and "
                "huge_tree=False (I8) — measured here, libxml2's own "
                "amplification guard happens to fire today, and I8 says "
                "explicitly not to rely on a default that can change.")

    # ---- 10 000-deep group nesting ------------------------------------
    depth = 10000
    deep = io.BytesIO()
    deep.write(b'<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Meta>'
               b'<DatabaseName>deep</DatabaseName></Meta><Root>')
    for n in range(depth):
        deep.write(b"<Group><Name>g%d</Name>" % n)
    deep.write(b"</Group>" * depth)
    deep.write(b"</Root></KeePassFile>")
    build("kdbx41-xml-deep-nesting.kdbx", deep.getvalue(),
          "%d nested groups" % depth, ["I8"], "invalid",
          ["invalid", "bad-credential"],
          notes="Limits.MAX_GROUP_DEPTH is 64. A recursive tree walk over this "
                "raises RecursionError, and an unhandled RecursionError prints "
                "locals — which is I15 as well as I8. Refuse on depth, do not "
                "rely on the interpreter's own limit. MEASURED: keepassxc-cli 2.7.10 OPENS this file, so no foreign oracle catches this one — the cap in backends/base.py Limits is the only defence.")

    # ---- duplicate UUID ------------------------------------------------
    dup = body
    marker = b"<UUID>"
    first = dup.find(marker)
    if first >= 0:
        end = dup.find(b"</UUID>", first)
        value = dup[first + len(marker):end]
        # Replace EVERY entry/group UUID with the first one.
        parts = dup.split(marker)
        rebuilt = [parts[0]]
        for chunk in parts[1:]:
            stop = chunk.find(b"</UUID>")
            rebuilt.append(value + chunk[stop:])
        dup = marker.join(rebuilt)
    build("kdbx41-xml-duplicate-uuid.kdbx",
          b'<?xml version="1.0" encoding="UTF-8"?>' + dup,
          "every entry and group shares one UUID", ["I22"], "invalid",
          ["invalid", "conflict"], seconds=NORMAL,
          notes="UUIDs are the identity a move, an edit and a delete all address. "
                "If two entries share one, `edit <uuid>` is ambiguous and `rm` "
                "may delete the wrong row. Refuse the database; do not "
                "de-duplicate silently, which would be a I22 data loss. MEASURED: this file HANGS keepassxc-cli 2.7.10 for over a minute, so the foreign oracle cannot even refuse it.")

    # ---- non-UTF-8 in every string field -------------------------------
    # 0xFF 0xFE 0xFD is invalid UTF-8 in any position. XML declares UTF-8, so
    # this document is not well-formed — which is the hazard: the failure has
    # to be a clean refusal, not a UnicodeDecodeError traceback.
    bad = body
    for tag in (b"Key", b"Value", b"Name", b"Notes", b"DatabaseName"):
        bad = bad.replace(b"<%s>" % tag, b"<%s>\xff\xfe\xfd" % tag)
    build("kdbx41-xml-non-utf8.kdbx",
          b'<?xml version="1.0" encoding="UTF-8"?>' + bad,
          "invalid UTF-8 injected into every string element", ["I8", "I15"],
          "invalid", ["invalid", "bad-credential"], seconds=NORMAL,
          notes="Must be a taxonomy error, never a UnicodeDecodeError reaching "
                "stdout. A traceback prints locals and the locals here include "
                "the decrypted database (I15).")

    # ---- compression bombs ---------------------------------------------
    # The payload is gzipped AFTER XML._encode, so a big, boring string becomes
    # a small file that expands enormously. Two cases: one that only the
    # decompression RATIO guard can catch (under the 256 MiB inner cap), and
    # one that exceeds the cap outright.
    for label, mib, ids, note in (
        ("ratio", 64, ["I8"],
         "64 MiB of one repeated byte: about 1000:1, comfortably inside "
         "Limits.MAX_INNER_BYTES, so ONLY Limits.MAX_DECOMPRESS_RATIO (200) can "
         "catch it. Decompress incrementally with a running cap — never "
         "zlib.decompress() on the whole stream. MEASURED: keepassxc-cli 2.7.10 OPENS this file, so no foreign oracle catches this one — the cap in backends/base.py Limits is the only defence."),
        ("size", 300, ["I8"],
         "300 MiB decompressed, past Limits.MAX_INNER_BYTES (256 MiB)."
         "MEASURED: keepassxc-cli 2.7.10 OPENS this file, so no foreign oracle catches this one — the cap in backends/base.py Limits is the only defence."),
    ):
        payload = (b'<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Meta>'
                   b'<DatabaseName>bomb</DatabaseName></Meta><Root><Group>'
                   b'<Name>b</Name><Entry><String><Key>Notes</Key><Value>'
                   + b"A" * (mib * 1024 * 1024) +
                   b'</Value></String></Entry></Group></Root></KeePassFile>')
        build("kdbx41-compression-bomb-%s.kdbx" % label, payload,
              "inner stream decompresses to %d MiB" % mib, ids,
              "invalid", ["invalid"], seconds=SLOW, notes=note)
        del payload


def build_pws3(outdir, manifest):
    """Password Safe v3 hazards."""
    meta = fixture(manifest, "lab-pws3.psafe3")
    pw = meta["password"]
    src = os.path.join(FIXTURES, "lab-pws3.psafe3")
    with open(src, "rb") as fh:
        raw = fh.read()

    # Fixed offsets from formatV3.txt section 2. Nothing is variable-length
    # before the body, which is what makes byte surgery safe here.
    O_SALT, O_ITER, O_HP, O_B1, O_IV, O_BODY = 4, 36, 40, 72, 136, 152

    # ---- ITER: attacker-controlled, and a CPU bomb ---------------------
    for value, label in ((0, "0"), (1, "1"), (2 ** 31 - 1, "2147483647"),
                         (2047, "2047-just-below-min"), (2 ** 32 - 1, "4294967295")):
        b = bytearray(raw)
        struct.pack_into("<I", b, O_ITER, value)
        emit(outdir, "pws3-iter-%s.psafe3" % label, bytes(b),
             fmt="psafe3", base="lab-pws3.psafe3",
             hazard="ITER = %d" % value, ids=["I7"], password=pw,
             error="invalid", seconds=FAST,
             notes="formatV3.txt section 2.4: ITER is a 32-bit LE value read "
                   "straight out of the file. The permitted range is "
                   "[2048, 8388608] and the check must happen BEFORE the "
                   "SHA-256 stretch loop — 2^31-1 iterations is roughly three "
                   "weeks of CPU. The 2 s budget is the assertion.")

    # ---- truncation at every structural boundary -----------------------
    points = [
        (2, "mid-tag", "half of the PWS3 tag"),
        (O_SALT, "after-tag", "tag only"),
        (O_ITER, "after-salt", "salt complete, ITER missing"),
        (O_HP, "after-iter", "ITER complete, H(P') missing"),
        (O_B1, "after-hp", "H(P') complete, B1..B4 missing"),
        (O_IV, "after-b1b4", "key blocks complete, IV missing"),
        (O_BODY, "after-iv", "preamble complete, no body and no EOF"),
        (O_BODY + 16, "mid-body", "one body block, no EOF"),
        (len(raw) - 48, "at-eof-block", "body complete, EOF block missing"),
        (len(raw) - 32, "after-eof-block", "EOF block present, HMAC missing"),
        (len(raw) - 1, "mid-hmac", "one byte short of the HMAC"),
    ]
    for offset, label, why in points:
        emit(outdir, "pws3-trunc-%s.psafe3" % label, raw[:offset],
             fmt="psafe3", base="lab-pws3.psafe3",
             hazard="truncated at %d bytes (%s)" % (offset, why),
             ids=["I6"], password=pw, error="invalid", seconds=FAST,
             notes="formatV3.txt section 2.10: the unencrypted EOF block is what "
                   "says where the HMAC starts. A file without it is truncated — "
                   "refuse it, never 'recover what you can'.")

    # ---- bit flips ------------------------------------------------------
    for offset, label, hazard, err, note in (
        (O_SALT + 3, "salt", "one bit flipped in the salt", "bad-credential",
         "Changes P', so H(P') no longer matches. Indistinguishable from a wrong "
         "passphrase, and it must stay that way (I6)."),
        (O_HP + 3, "hp", "one bit flipped in the stored H(P')", "bad-credential",
         "The passphrase check value itself. Compare it with compare_digest, "
         "never ==."),
        (O_B1 + 3, "b1", "one bit flipped in B1 (the record key blob)",
         "bad-credential",
         "K decrypts to garbage, so the body decrypts to garbage and the HMAC "
         "fails. Nothing may escape before that."),
        (O_IV + 3, "iv", "one bit flipped in the CBC IV", "bad-credential",
         "Corrupts only the first plaintext block, which is a field header — a "
         "hostile length arrives by accident. The HMAC still has to be the "
         "gate."),
        (O_BODY + 20, "ciphertext", "one bit flipped in the encrypted body",
         "bad-credential",
         "CBC error propagation gives the attacker one controlled plaintext "
         "block. Verify the MAC before believing any of it."),
        (len(raw) - 1, "hmac", "one bit flipped in the trailing HMAC",
         "bad-credential",
         "The MAC is the last 32 bytes (section 2.11). Same error and the SAME "
         "detail string as a wrong passphrase, or unlock is an oracle."),
    ):
        emit(outdir, "pws3-flip-%s.psafe3" % label, flip(raw, offset),
             fmt="psafe3", base="lab-pws3.psafe3", hazard=hazard,
             ids=["I6"], password=pw, error=err,
             acceptable=["bad-credential"], seconds=NORMAL, notes=note)

    # ---- tag ------------------------------------------------------------
    emit(outdir, "pws3-bad-tag.psafe3", b"PWS2" + raw[4:],
         fmt="psafe3", base="lab-pws3.psafe3", hazard='the tag is "PWS2"',
         ids=["I6"], password=pw, error="invalid", seconds=FAST,
         notes="section 2.1: the tag has no cryptographic value, but a file that "
               "is not a PWS3 database must be refused on sight rather than "
               "decrypted hopefully.")

    # ---- forged bodies --------------------------------------------------
    # A real Twofish body and a real HMAC over deliberately hostile plaintext.
    hdr = pws3_field(0x00, struct.pack("<H", 0x0311)) + pws3_field(0xFF, b"")

    # field length 0xFFFFFFFF
    body = hdr + pws3_field(0x03, b"Title", declared=0xFFFFFFFF) + pws3_field(0xFF, b"")
    data = pws3_forge({"body_hex": body.hex(), "hmac_data_hex": ""},
                      os.path.join(outdir, "pws3-fieldlen-ffffffff.psafe3"), pw)
    emit(outdir, "pws3-fieldlen-ffffffff.psafe3", data,
         fmt="psafe3", base="forged", hazard="a field declares 0xFFFFFFFF bytes",
         ids=["I6", "I7"], password=pw, error="bad-credential",
         acceptable=["bad-credential", "invalid"], seconds=NORMAL,
         notes="4 GiB from an unauthenticated length field (section 3). It must "
               "be bounds-checked against the bytes actually remaining, in "
               "uint64 so nothing wraps, BEFORE anything is allocated. The "
               "answer is bad-credential rather than a descriptive error "
               "because at this point the body has not been authenticated and "
               "saying how far the parse got is an oracle (I6).")

    # 2 GiB declared attachment (Att Content, type 0x29)
    body = hdr + pws3_field(0x29, b"\x00" * 16, declared=2 * 1024 ** 3) + pws3_field(0xFF, b"")
    data = pws3_forge({"body_hex": body.hex(), "hmac_data_hex": ""},
                      os.path.join(outdir, "pws3-attachment-2gib.psafe3"), pw)
    emit(outdir, "pws3-attachment-2gib.psafe3", data,
         fmt="psafe3", base="forged",
         hazard="Att Content (0x29) declares 2 GiB", ids=["I7", "I21"],
         password=pw, error="bad-credential",
         acceptable=["bad-credential", "invalid"], seconds=NORMAL,
         notes="Limits.MAX_ATTACHMENT_BYTES is 32 MiB. section 3.3[29] allows an "
               "attachment up to 4 GiB, so a compliant-looking file can ask for "
               "more memory than the host has. The declared size must be "
               "checked against MAX_ATTACHMENT_BYTES and against the bytes that "
               "actually remain.")

    # zero-length fields: legal, and a non-termination trap
    zeros = hdr[:-16] + pws3_field(0xFF, b"")     # header: Version + END
    rec = b"".join(pws3_field(0xC0 + (n % 16), b"") for n in range(2048))
    rec += pws3_field(0x01, b"\x11" * 16) + pws3_field(0x03, b"z") \
        + pws3_field(0x06, b"z") + pws3_field(0xFF, b"")
    body = zeros + rec
    data = pws3_forge({"body_hex": body.hex()},
                      os.path.join(outdir, "pws3-fieldlen-zero.psafe3"), pw)
    emit(outdir, "pws3-fieldlen-zero.psafe3", data,
         fmt="psafe3", base="forged",
         hazard="2048 zero-length fields in one record", ids=["I6"],
         password=pw, error=None, acceptable=[None], seconds=NORMAL,
         notes="THE ONE CASE THAT MUST SUCCEED. section 2.9.2 says a "
               "non-mandatory field may be absent OR zero length, so this file "
               "is valid and must open. The hazard is a reader that computes "
               "blocks = ceil(len/16), gets 0 for a zero-length field, advances "
               "by 0 bytes and loops forever — which is why this case has a time "
               "budget and not an error code.")

    # no EOF block
    body = hdr + pws3_field(0x01, b"\x22" * 16) + pws3_field(0x03, b"t") \
        + pws3_field(0x06, b"p") + pws3_field(0xFF, b"")
    data = pws3_forge({"body_hex": body.hex(), "omit_eof": True},
                      os.path.join(outdir, "pws3-no-eof.psafe3"), pw)
    emit(outdir, "pws3-no-eof.psafe3", data,
         fmt="psafe3", base="forged", hazard="no PWS3-EOF block", ids=["I6"],
         password=pw, error="invalid", seconds=FAST,
         notes="section 2.10. Without the EOF block there is no way to know "
               "where the body stops and the HMAC starts, so the last 32 bytes "
               "of ciphertext would be read as the MAC. Refuse.")

    # non-UTF-8 in every string field
    fields = [pws3_field(0x01, b"\x33" * 16)]
    for ftype in (0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E, 0x12, 0x14):
        fields.append(pws3_field(ftype, b"\xff\xfe\xfd\x80\x81 not utf-8"))
    fields.append(pws3_field(0xFF, b""))
    body = hdr + b"".join(fields)
    data = pws3_forge({"body_hex": body.hex()},
                      os.path.join(outdir, "pws3-non-utf8.psafe3"), pw)
    emit(outdir, "pws3-non-utf8.psafe3", data,
         fmt="psafe3", base="forged",
         hazard="invalid UTF-8 in every text field", ids=["I15"],
         password=pw, error=None, acceptable=[None, "invalid"], seconds=NORMAL,
         notes="section 3.1.2 says text fields are UTF-8, and this file breaks "
               "that in nine of them. Either answer is defensible — refuse the "
               "record, or decode with errors='replace' and say so — but a "
               "UnicodeDecodeError traceback on stdout is neither, and it "
               "prints locals (I15).")

    # a header with no END field
    body = pws3_field(0x00, struct.pack("<H", 0x0311)) + pws3_field(0x09, b"no end")
    data = pws3_forge({"body_hex": body.hex()},
                      os.path.join(outdir, "pws3-header-no-end.psafe3"), pw)
    emit(outdir, "pws3-header-no-end.psafe3", data,
         fmt="psafe3", base="forged",
         hazard="the header is never terminated by an END field", ids=["I6"],
         password=pw, error="invalid", acceptable=["invalid", "bad-credential"],
         seconds=NORMAL,
         notes="section 2.9.1 makes the Version and END fields mandatory. A "
               "reader that treats the first record as more header, or the "
               "header as a record, is confused about where trust starts.")

    # an HMAC computed over the wrong bytes: the classic PWS3 implementation bug
    body = hdr + pws3_field(0x01, b"\x44" * 16) + pws3_field(0x03, b"whole-block") \
        + pws3_field(0x06, b"p") + pws3_field(0xFF, b"")
    data = pws3_forge({"body_hex": body.hex(), "hmac_data_hex": body.hex()},
                      os.path.join(outdir, "pws3-hmac-over-blocks.psafe3"), pw)
    emit(outdir, "pws3-hmac-over-blocks.psafe3", data,
         fmt="psafe3", base="forged",
         hazard="HMAC computed over whole blocks instead of field data",
         ids=["I6", "I19"], password=pw, error="bad-credential", seconds=NORMAL,
         notes="section 2.11: the HMAC covers the field DATA only — not the "
               "4-byte length, not the type byte, not the random padding. This "
               "file's MAC covers the whole padded blocks, which is the single "
               "most common way to write a PWS3 file that round-trips through "
               "your own code and opens in nothing else. A reader that ACCEPTS "
               "this file has the same bug and I19 has caught it.")



# ------------------------------------------------------------------ check ----

def check_corpus(outdir):
    """Re-test every case against a FOREIGN reader, and report the agreement.

    What this proves and what it does not:

      * For the .psafe3 cases it runs `tests/oracle/pws3_oracle`, an independent
        Go implementation written from formatV3.txt. That oracle uses the same
        eight-code taxonomy as docs/CONTRACT.md, so its answer can be compared
        with `error` / `error_acceptable` directly. Agreement is real evidence
        that the sidecar names an achievable answer and not a wish.
      * For the .kdbx cases it runs `keepassxc-cli db-info`, which has its own
        vocabulary and only ever exits 0 or 1. So the only thing compared is
        REFUSED vs OPENED, and a handful of cases are EXPECTED to open in
        KeePassXC — the compression bombs, the 10 000-deep tree and the
        duplicate UUIDs are all *valid* KDBX files whose contents are hostile.
        That is the finding, not a failure: KeePassXC has no decompression cap,
        no depth cap and no UUID-uniqueness check, so those three hazards are
        ours alone to catch.

    This does NOT test secrets-admin. It tests that the corpus is well-formed
    and that its expectations are met by something other than the code under
    test (docs/KNOWN_ISSUES.md I19).
    """
    import time

    index_path = os.path.join(outdir, "index.json")
    if not os.path.exists(index_path):
        sys.exit("gen_corpus.py: %s is missing — run --build first" % index_path)
    with open(index_path, encoding="utf-8") as fh:
        index = json.load(fh)

    # KDBX files that are STRUCTURALLY valid and hostile only in their content.
    # Measured: KeePassXC 2.7.10 opens all of these, and it is not wrong to —
    # it simply has no cap for what they do. Every one of them is therefore a
    # hazard only OUR caps can catch, which is exactly why they are in the
    # corpus. Do not "fix" this set to make the check tidier.
    #
    #   compression-bomb-*   no decompression size or ratio cap
    #   xml-deep-nesting     no group-depth cap (libxml2's own 256-deep guard
    #                        fires for pykeepass, but KeePassXC reads it fine)
    #   xml-duplicate-uuid   no UUID-uniqueness check; measured to HANG
    #                        keepassxc-cli for over a minute
    #   xml-external-entity  the DOCTYPE's entities are left unresolved (good)
    #                        and the undefined references are then dropped, so
    #                        the document parses and the database opens
    kxc_opens = {
        "kdbx41-compression-bomb-ratio.kdbx",
        "kdbx41-compression-bomb-size.kdbx",
        "kdbx41-xml-deep-nesting.kdbx",
        "kdbx41-xml-duplicate-uuid.kdbx",
        "kdbx41-xml-external-entity.kdbx",
    }

    bad = 0
    for case in index["cases"]:
        path = os.path.join(outdir, case["file"])
        started = time.monotonic()
        if case["format"] == "psafe3":
            proc = subprocess.run(
                [PWS3_ORACLE, "read", "--file", path],
                input=(case["password"] + "\n").encode(),
                capture_output=True, timeout=120)
            if proc.returncode == 0:
                got = None
            else:
                try:
                    got = json.loads(proc.stdout.decode())["error"]
                except Exception:                        # noqa: BLE001
                    got = "UNPARSEABLE"
            ok = got in case["error_acceptable"]
            shown = got or "(opened)"
        else:
            # 25 s, not 90: four of these cases hang keepassxc-cli
            # indefinitely (measured — the Argon2 t=10^6 and m=4 GiB bombs, the
            # AES-KDF 10^9 bomb and the duplicate-UUID database), and a timeout
            # IS the result for them. Waiting longer only makes the check slow.
            try:
                proc = subprocess.run(
                    ["keepassxc-cli", "db-info", "-q", path],
                    input=(case["password"] + "\n").encode(),
                    capture_output=True, timeout=25)
                opened = proc.returncode == 0
            except subprocess.TimeoutExpired:
                opened = None
            if opened is None:
                # A timeout is neither "opened" nor "refused" — it is the
                # oracle being taken out by the file, which is a result in its
                # own right and never a corpus defect. Four cases do this today.
                shown = "(timed out — the oracle hung)"
                ok = True
            elif opened:
                shown = "(opened)"
                ok = case["file"] in kxc_opens
            else:
                shown = "(refused)"
                ok = case["file"] not in kxc_opens
        elapsed = time.monotonic() - started

        # The sentinels must not appear in the corpus file's own bytes either.
        # A truncated or forged file that still carries readable plaintext would
        # make every leak test pass for the wrong reason.
        with open(path, "rb") as fh:
            blob = fh.read()
        leaked = [s for s in case["must_not_leak"]
                  if s and s.encode("utf-8", "replace") in blob]
        if leaked:
            ok = False
            shown += " LEAKS:" + ",".join(leaked)

        if not ok:
            bad += 1
        sys.stdout.write("  %-4s %-42s %-22s %6.2fs\n"
                         % ("ok" if ok else "BAD", case["file"], shown, elapsed))

    sys.stdout.write("\n%d cases checked, %d disagreed with their sidecar\n"
                     % (len(index["cases"]), bad))
    return 1 if bad else 0


# ------------------------------------------------------------------- main ----

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=OUT_DEFAULT)
    ap.add_argument("--build", action="store_true", help="write the corpus")
    ap.add_argument("--list", action="store_true",
                    help="print the case table without writing anything")
    ap.add_argument("--clean", action="store_true",
                    help="remove the output directory first")
    ap.add_argument("--check", action="store_true",
                    help="re-test the built corpus against the foreign oracles")
    args = ap.parse_args()

    manifest = load_manifest()

    if args.clean and os.path.isdir(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out, exist_ok=True)

    if args.check and not args.build:
        return check_corpus(args.out)

    if not args.build and not args.list:
        ap.error("give --build, --list or --check")

    build_kdbx_structural(args.out, manifest)
    build_kdbx_kdf(args.out, manifest)
    build_kdbx_inner(args.out, manifest)
    build_pws3(args.out, manifest)

    index = {
        "_comment": ("Malformed-input corpus for cockpit-secrets. Every entry "
                     "names the docs/CONTRACT.md error code the helper must "
                     "return and the wall clock the refusal must fit inside. "
                     "Rebuild with ./gen_corpus.py --build --clean."),
        "generated_from": "tests/fixtures/manifest.json",
        "budgets": {"fast": FAST, "normal": NORMAL, "slow": SLOW},
        "must_not_leak": SENTINELS,
        "count": len(cases),
        "cases": cases,
    }
    with open(os.path.join(args.out, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    by_fmt = {}
    for c in cases:
        by_fmt[c["format"]] = by_fmt.get(c["format"], 0) + 1
    for c in cases:
        sys.stdout.write("%-42s %-8s %-14s %5.1fs  %s\n" % (
            c["file"], c["format"], c["error"] or "(must open)",
            c["max_seconds"], ",".join(c["known_issues"])))
    sys.stdout.write("\n%d cases: %s\n" % (
        len(cases), ", ".join("%s=%d" % kv for kv in sorted(by_fmt.items()))))
    sys.stdout.write("index: %s\n" % os.path.join(args.out, "index.json"))
    if args.check:
        sys.stdout.write("\n== checking against the foreign oracles ==\n")
        return check_corpus(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
