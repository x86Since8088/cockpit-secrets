#!/usr/bin/env python3
"""tests/test_regressions.py — one test per confirmed adversarial finding.

Every test in this file FAILED before the fix it guards, and was watched to
fail: the procedure for each was to revert the fix, run the test, see red, put
the fix back, see green. The finding id is in the test name so a future
regression names the report it came from rather than a line number.

Why these are unittest cases and not another integration script: `validate.sh`
discovers `tests/test_*.py` and runs it on every gate, which is 70 s of budget
and no fixtures to build. Everything here is therefore either pure-function or
one temp-directory copy of a committed fixture. The cases that genuinely need
the helper process — a request frame, a restore, an export artefact — live in
`tests/integration/adversarial.py`, which `run_tests.sh` runs.

THE FINDINGS, and what guards each:

  CRYPTO-01   a save that writes a database the reader refuses
              test_crypto01_*  (four: the ratio guard, the round trip, the
              pre-write read-back, the tolerant attachment path)
  CRYPTO-03   the KDF seed never rotates, so a token's answer is a constant
              test_crypto03_constant_challenge_is_stated
  CRYPTO-04   duplicate field types resolved first-wins
              test_crypto04_kdbx_*, test_crypto04_pws3_*
  INPUT-1     MAX_ENTRIES enforced only after the parse
              test_input1_*
  INPUT-2     a deeply nested request answers `internal`
              (tests/integration/adversarial.py — it needs the real frame)
  LEAKAGE-01  redact() misses a secret json.dumps has escaped
              test_leakage01_*
  LEAKAGE-02  live-harness artefacts written under the umask
              test_leakage02_*
  LEAKAGE-03  CSV formula injection
              test_leakage03_*
  LEAKAGE-04  caller text reaching a pykeepass XPath through `add`
              test_leakage04_*
  DURABILITY-1 a short write makes a truncated backup generation
              test_durability1_*
  DURABILITY-2 an orphan lock file after a failed write
              test_durability2_*
  DURABILITY-4 a truncated generation is restorable
              test_durability4_*
  DURABILITY-5 a directory at the lock path is unrecoverable
              test_durability5_*
  DURABILITY-3 `restore-backup` over-claims "itself undoable"
              (tests/integration/adversarial.py — it needs the ring)
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from backends import base                                       # noqa: E402
from backends.base import (                                     # noqa: E402
    Conflict, Internal, Invalid, Limits, LockFile, Secret,
    csv_cell, CsvWriter, redact, write_all,
)

PW = b"fixture-pass-do-not-reuse"
KDBX41 = os.path.join(FIXTURES, "lab-kdbx41-aes256-argon2id.kdbx")
KDBX31 = os.path.join(FIXTURES, "lab-kdbx31-aes256-aeskdf.kdbx")
PWS3 = os.path.join(FIXTURES, "lab-pws3.psafe3")


def _read(path):
    """Read a text file and close it. `open(p).read()` leaks a descriptor and
    the ResourceWarning it prints buries the test output it appears in."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _workdir():
    """A private directory the safe guards will accept.

    NOT /tmp: `atomic_replace` refuses a backup ring under /tmp or /var/tmp,
    and `open_safe_fd` refuses a group-writable parent — both correctly, and
    both would read like a test bug (tests/integration/_env.py says the same).
    """
    base_dir = os.environ.get("XDG_RUNTIME_DIR") or os.path.expanduser("~/.cache")
    d = tempfile.mkdtemp(prefix="cs-regress-", dir=base_dir)
    os.chmod(d, 0o700)
    return d


def _copy(fixture, into, name=None):
    dst = os.path.join(into, name or os.path.basename(fixture))
    shutil.copy(fixture, dst)
    os.chmod(dst, 0o600)
    return dst


def _entry(path, fmt="kdbx", **over):
    e = {"id": "t", "label": "t", "path": path, "format": fmt,
         "access": "user", "mode": "rw"}
    e.update(over)
    return e


def _open_kdbx(path, **over):
    from backends import kdbx
    b = kdbx.KdbxBackend(_entry(path, **over))
    b.unlock(Secret(bytearray(PW)))
    return b


class TempSafe(unittest.TestCase):
    """Base class: one throwaway directory per test, removed afterwards."""

    def setUp(self):
        self.dir = _workdir()
        self.addCleanup(shutil.rmtree, self.dir, True)


# ===========================================================================
# CRYPTO-01 — save() could write a database the plugin could never reopen
# ===========================================================================

class Crypto01(TempSafe):

    #: One repeated log line. This is the ordinary content that used to be
    #: refused: 8 MiB of it compresses at about 258:1, and the guard's limit
    #: was 200:1.
    @staticmethod
    def _log(size=8 * 1024 * 1024):
        line = (b"2026-09-04T10:00:00Z INFO worker=3 request completed "
                b"status=200 bytes=1234\n")
        return (line * (size // len(line) + 1))[:size]

    def test_crypto01_ordinary_compressible_payload_is_not_a_bomb(self):
        """A ratio a real log file reaches must not be a refusal.

        Before the fix: Invalid("expansion ratio 258:1 is over the 200:1
        limit"). The absolute cap and the structural caps are the bomb
        controls now; see backends/kdbx.py `_DEFLATE_MAX_RATIO`.
        """
        import zlib
        from backends.kdbx import _bounded_decompress
        raw = self._log()
        packed = zlib.compress(raw, 6)
        self.assertGreater(len(raw) // len(packed), Limits.MAX_DECOMPRESS_RATIO,
                           "this fixture is supposed to exceed the old limit")
        self.assertEqual(_bounded_decompress(packed, zlib.MAX_WBITS), raw)

    def test_crypto01_attach_then_save_then_reopen(self):
        """attach_add -> save -> unlock. The whole finding, end to end.

        Before the fix this save answered {"ok": true} and every later unlock
        answered invalid, while KeePassXC read the same file perfectly.
        """
        path = _copy(KDBX41, self.dir)
        b = _open_kdbx(path)
        uuid = next(iter(b._index))
        b.attach_add(uuid, "app.log", self._log(), replace=True)
        self.assertTrue(b.save()["ok"])
        b.lock()

        b2 = _open_kdbx(path)
        self.addCleanup(b2.lock)
        self.assertEqual([a["name"] for a in b2.attach_list(uuid)], ["app.log"])
        import base64
        got = b2.attach_get(uuid, "app.log")
        self.assertEqual(got["size"], len(self._log()))
        self.assertEqual(base64.b64decode(got["b64"]), self._log(),
                         "the attachment did not survive the round trip")

    def test_crypto01_save_refuses_output_it_cannot_read_back(self):
        """The pre-write check must PARSE, not just re-MAC.

        The mechanism is exercised by making the reader stricter than the
        writer for the duration of one save — which is exactly the shape of
        the original bug, where a decompression guard the writer did not
        consult refused the writer's own output. A save that produces bytes
        this process cannot re-open must fail, and must leave the live file
        exactly as it found it.

        Before the fix `_verify_own_output` only re-ran the MACs, so the
        unreadable file was written and the live safe was lost.
        """
        path = _copy(KDBX41, self.dir)
        before = _read_bytes(path)
        b = _open_kdbx(path)
        uuid = next(iter(b._index))
        b.edit(uuid, {"notes": "x" * 4096})

        original = Limits.MAX_ENTRIES
        Limits.MAX_ENTRIES = 0               # the READER now refuses our output
        try:
            with self.assertRaises(Conflict) as caught:
                b.save()
        finally:
            Limits.MAX_ENTRIES = original
        self.assertIn("cannot be read back", caught.exception.detail)
        self.assertEqual(_read_bytes(path), before,
                         "the live safe must be untouched by a refused save")

    def test_crypto01_tolerant_attachment_path_tolerates_invalid(self):
        """`_attachment_bytes(strict=False)` must swallow a typed refusal.

        It caught only (IndexError, KeyError, TypeError, ValueError), so an
        `Invalid` raised while INFLATING a KDBX 3.1 attachment flew out of
        `attach_list()` and `fields()` — the two paths documented as tolerant.
        """
        from backends.kdbx import _attachment_bytes

        class Exploding:
            @property
            def binary(self):
                raise Invalid("a decompression guard said no")

        self.assertEqual(_attachment_bytes(Exploding(), strict=False), b"")
        with self.assertRaises(Invalid):
            _attachment_bytes(Exploding(), strict=True)


# ===========================================================================
# INPUT-1 — the entry cap was enforced after the expensive parse
# ===========================================================================

class Input1(TempSafe):

    @staticmethod
    def _xml(entries=1, groups=1, value="v", tag="String"):
        body = "".join(
            "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>"
            "<%s><Key>Password</Key><Value>%s</Value></%s></Entry>"
            % (tag, value, tag) for _ in range(entries))
        return ('<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Meta>'
                '<DatabaseName>t</DatabaseName></Meta><Root>'
                + "".join("<Group><Name>g</Name>%s</Group>"
                          % (body if i == 0 else "")
                          for i in range(groups))
                + '</Root></KeePassFile>').encode()

    def test_input1_entry_count_is_refused_before_the_decode(self):
        """MAX_ENTRIES must bite in the parse, not after it.

        The check used to live in `unlock()`, after `PyKeePass(...)` had
        already run its protected-value pass — the part whose cost the attacker
        chooses. `_parse_xml_hardened(structural=True)` is the parse, so a
        refusal from it is a refusal before the decode.
        """
        from backends.kdbx import _parse_xml_hardened
        original = Limits.MAX_ENTRIES
        Limits.MAX_ENTRIES = 4
        try:
            _parse_xml_hardened(self._xml(entries=4), "t", structural=True)
            with self.assertRaises(Invalid) as caught:
                _parse_xml_hardened(self._xml(entries=5), "t", structural=True)
        finally:
            Limits.MAX_ENTRIES = original
        self.assertIn("more than 4 entries", caught.exception.detail)

    def test_input1_group_count_is_refused_in_the_parse(self):
        from backends.kdbx import _parse_xml_hardened
        original = Limits.MAX_GROUPS
        Limits.MAX_GROUPS = 3
        try:
            with self.assertRaises(Invalid) as caught:
                _parse_xml_hardened(self._xml(groups=4), "t", structural=True)
        finally:
            Limits.MAX_GROUPS = original
        self.assertIn("more than 3 groups", caught.exception.detail)

    def test_input1_oversize_field_value_is_refused_structurally(self):
        """The bomb control that replaced the compression ratio.

        A 64 MiB single `<Value>` and a 32 MiB attachment are byte-identical to
        a ratio test and completely different as a claim about a database. This
        is the check that tells them apart, and it is what keeps the corpus's
        `kdbx41-compression-bomb-ratio.kdbx` refused now that the ratio no
        longer fires on ordinary compressible content.
        """
        from backends.kdbx import _parse_xml_hardened
        original = Limits.MAX_FIELD_BYTES
        Limits.MAX_FIELD_BYTES = 32
        try:
            with self.assertRaises(Invalid) as caught:
                _parse_xml_hardened(self._xml(value="A" * 64), "t",
                                    structural=True)
        finally:
            Limits.MAX_FIELD_BYTES = original
        self.assertIn("field value", caught.exception.detail)

    def test_input1_attachment_text_gets_the_attachment_limit(self):
        """…and a pooled binary is measured against MAX_ATTACHMENT_BYTES.

        Same node name, different parent, different limit. Getting this wrong
        in the other direction would refuse every legal KDBX 3.1 attachment,
        which is the read-side half of CRYPTO-01.
        """
        from backends.kdbx import _parse_xml_hardened
        allowed = Limits.MAX_ATTACHMENT_BYTES * 4 // 3
        xml = ('<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Meta>'
               '<Binaries><Binary ID="0">%s</Binary></Binaries></Meta>'
               '<Root/></KeePassFile>' % ("A" * 4096)).encode()
        # 4 KiB of base64 is nowhere near the limit: it must pass.
        _parse_xml_hardened(xml, "t", structural=True)
        self.assertGreater(allowed, Limits.MAX_FIELD_BYTES,
                           "an attachment is allowed to be bigger than a field")

    def test_input1_parse_budget_stops_a_python_loop(self):
        """The budget must PREEMPT, not merely notice afterwards.

        `kdf_budget` cannot interrupt a C call and says so; this one has to
        interrupt a Python-level loop, because that is where the quadratic
        lives. A budget that only reported an overrun would still have let the
        measured 46-second unlock run to completion.
        """
        started = time.monotonic()
        # Bounded rather than `while True`: without the preemption this test
        # must FAIL, not hang. Three seconds of work against a quarter-second
        # budget is a wide enough gap that the assertion below cannot be a
        # timing flake on a loaded machine.
        with self.assertRaises(Invalid) as caught:
            with Limits.parse_budget(seconds=0.25, what="spinning"):
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    _ = sum(range(1000))
        elapsed = time.monotonic() - started
        self.assertIn("budget", caught.exception.detail)
        self.assertLess(elapsed, 1.5,
                        "the budget did not interrupt the loop; it only "
                        "reported the overrun after %.1fs" % elapsed)

    def test_input1_parse_budget_is_invisible_when_it_is_not_hit(self):
        with Limits.parse_budget(seconds=30.0):
            value = 1 + 1
        self.assertEqual(value, 2)


# ===========================================================================
# CRYPTO-04 — duplicate field types were resolved first-wins
# ===========================================================================

class Crypto04(TempSafe):

    def _dup_kdbx(self):
        """A KDBX with two <String><Key>Password</Key></String> in one entry.

        keepassxc-cli 2.7.10 refuses this file outright ("Duplicate custom
        attribute found"), which is the reference behaviour this matches.
        """
        import copy
        from pykeepass import create_database
        path = os.path.join(self.dir, "dup.kdbx")
        kp = create_database(path, password="pw")
        entry = kp.add_entry(kp.root_group, "Router", "admin", "DECOY-first")
        for string_el in entry._element.findall("String"):
            if string_el.find("Key").text == "Password":
                clone = copy.deepcopy(string_el)
                clone.find("Value").text = "REAL-second"
                entry._element.append(clone)
                break
        kp.save()
        os.chmod(path, 0o600)
        return path

    def test_crypto04_kdbx_duplicate_field_is_refused_not_picked(self):
        from backends import kdbx
        path = self._dup_kdbx()
        b = kdbx.KdbxBackend(_entry(path))
        b.unlock(Secret(bytearray(b"pw")))
        self.addCleanup(b.lock)
        uuid = next(iter(b._index))
        with self.assertRaises(Invalid) as caught:
            b.reveal(uuid, "password")
        self.assertIn("more than one field", caught.exception.detail)

    def test_crypto04_kdbx_duplicate_is_refused_on_the_write_path_too(self):
        """The sharper half: a rotation that appeared to succeed.

        `edit` rewrote the FIRST copy and answered {"changed": ["password"]}
        while the second copy kept the old value.
        """
        from backends import kdbx
        path = self._dup_kdbx()
        b = kdbx.KdbxBackend(_entry(path))
        b.unlock(Secret(bytearray(b"pw")))
        self.addCleanup(b.lock)
        uuid = next(iter(b._index))
        with self.assertRaises(Invalid):
            b.edit(uuid, {"password": "ROTATED"})

    def test_crypto04_pws3_duplicate_field_type_is_refused(self):
        """The same rule for Password Safe, built with the project's own writer.

        formatV3.txt §3.3 gives a record field type at most one occurrence
        (0x11 repeats, and is a HEADER field), so two 0x06 fields is a file
        telling two readers two different things.
        """
        from backends import psafe3
        from backends.psafe3 import Field, Pws3Db, REC_PASSWORD

        path = _copy(PWS3, self.dir)
        b = psafe3.Psafe3Backend(_entry(path, fmt="psafe3"))
        b.unlock(Secret(bytearray(PW)))
        record = b._db.records[0]
        Pws3Db.field_set(record, REC_PASSWORD, b"DECOY-first")
        record.append(Field(REC_PASSWORD, b"REAL-last"))

        with self.assertRaises(Invalid) as caught:
            Pws3Db.field_get(record, REC_PASSWORD)
        self.assertIn("more than one", caught.exception.detail)
        with self.assertRaises(Invalid):
            Pws3Db.field_set(record, REC_PASSWORD, b"ROTATED")
        with self.assertRaises(Invalid):
            Pws3Db.field_del(record, REC_PASSWORD)
        b.lock()

    def test_crypto04_pws3_duplicate_is_refused_at_unlock(self):
        """…and the whole file is refused when it is opened, not on first read."""
        from backends import psafe3
        from backends.psafe3 import Field, Pws3Db, REC_PASSWORD

        path = _copy(PWS3, self.dir)
        b = psafe3.Psafe3Backend(_entry(path, fmt="psafe3"))
        b.unlock(Secret(bytearray(PW)))
        b._db.records[0].append(Field(REC_PASSWORD, b"REAL-last"))
        b.save()
        b.lock()

        b2 = psafe3.Psafe3Backend(_entry(path, fmt="psafe3"))
        with self.assertRaises(Invalid) as caught:
            b2.unlock(Secret(bytearray(PW)))
        self.assertIn("more than one", caught.exception.detail)


# ===========================================================================
# LEAKAGE-01 — redact() did not see what json.dumps had escaped
# ===========================================================================

class Leakage01(unittest.TestCase):

    #: The two escapes `json.dumps(..., ensure_ascii=False)` still emits, and
    #: which `repr()` renders differently — so no candidate matched them.
    CASES = ('SENTINEL-with-"-quote', "SENTINEL-with-\x00-nul",
             "SENTINEL-with-\\-slash", "SENTINEL-plain-000",
             "SENTINEL-with-é-accent")

    def test_leakage01_redact_covers_the_json_escaped_form(self):
        for raw in self.CASES:
            for ensure_ascii in (False, True):
                secret = Secret(raw.encode("utf-8", "surrogatepass"))
                try:
                    line = json.dumps({"echo": raw}, ensure_ascii=ensure_ascii)
                    cleaned = redact(line, live=[secret])
                    self.assertNotIn(json.dumps(raw, ensure_ascii=ensure_ascii)[1:-1],
                                     cleaned,
                                     "leaked %r at ensure_ascii=%s"
                                     % (raw, ensure_ascii))
                    self.assertNotIn(raw, cleaned)
                finally:
                    secret.zero()

    def test_leakage01_the_plain_form_is_still_covered(self):
        secret = Secret(b'SENTINEL-with-"-quote')
        try:
            self.assertNotIn('SENTINEL-with-"-quote',
                             redact('got SENTINEL-with-"-quote', live=[secret]))
        finally:
            secret.zero()


# ===========================================================================
# LEAKAGE-03 — CSV formula injection
# ===========================================================================

class Leakage03(unittest.TestCase):

    def test_leakage03_every_formula_lead_is_neutralised(self):
        for lead in base.CSV_FORMULA_LEAD:
            cell = lead + "cmd|' /C calc'!A0"
            self.assertTrue(csv_cell(cell).startswith(base.CSV_TEXT_PREFIX),
                            "a cell beginning %r reaches a spreadsheet as a "
                            "formula" % lead)

    def test_leakage03_ordinary_values_are_untouched(self):
        for cell in ("hunter2", "", "https://example.invalid/", "a=b",
                     "Ünïcødé — 日本語 🔐"):
            self.assertEqual(csv_cell(cell), cell)

    def test_leakage03_the_writer_neutralises_and_counts(self):
        buf = io.StringIO()
        writer = CsvWriter(buf)
        writer.writerow(["Title", "URL"])
        writer.writerow(["Nasty", "=cmd|' /C calc'!A0"])
        writer.writerow(["Fine", "https://example.invalid/"])
        text = buf.getvalue()
        self.assertEqual(writer.neutralised, 1)
        self.assertIn('"\'=cmd', text)
        self.assertNotIn('"=cmd', text)

    def test_leakage03_both_backends_use_the_neutralising_writer(self):
        """A grep, deliberately: the hazard is a future export format that
        reaches for `csv.writer` because that is what the others looked like.
        `validate.sh` carries the same ban as a standing gate."""
        for name in ("backends/kdbx.py", "backends/psafe3.py"):
            text = _read(os.path.join(SRC, name))
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("*"):
                    continue
                self.assertNotIn("csv.writer(", line,
                                 "%s builds a raw csv.writer" % name)


# ===========================================================================
# LEAKAGE-04 — caller text reached a pykeepass XPath through `add`
# ===========================================================================

class Leakage04(TempSafe):

    def test_leakage04_a_quote_in_a_title_is_a_legal_entry(self):
        """Before the fix these two answered internal / "could not open this
        database" — a sentence that was not even true, since the database was
        open."""
        path = _copy(KDBX41, self.dir)
        b = _open_kdbx(path)
        self.addCleanup(b.lock)
        from backends.kdbx import _field_value
        for title, username in (('a"b', "u"), ('=WEBSERVICE("x")', 'u"v'),
                                ("plain", "plain")):
            uuid = b.add(None, {"title": title, "username": username,
                                "password": "p"})["uuid"]
            entry = b._index[uuid]
            self.assertEqual(_field_value(entry, "Title"), title)
            self.assertEqual(_field_value(entry, "UserName"), username)

    def test_leakage04_the_documented_reveal_injection_still_answers_notfound(self):
        """The §7 hardening this finding said had not been applied to `add`
        must not have been undone by applying it to `add`."""
        from backends.base import NotFound
        path = _copy(KDBX41, self.dir)
        b = _open_kdbx(path)
        self.addCleanup(b.lock)
        uuid = next(iter(b._index))
        payload = 'custom:x"]/../Value|//String[Key="Password"]/Value["'
        with self.assertRaises(NotFound):
            b.reveal(uuid, payload)

    def test_leakage04_an_xpath_error_is_invalid_not_internal(self):
        """Belt to the brace: `internal` means "we do not know what went
        wrong", and a query we built is never that."""
        from lxml import etree
        from backends import kdbx
        backend = kdbx.KdbxBackend(_entry(os.path.join(self.dir, "none.kdbx")))
        mapped = backend._map_pykeepass_error(etree.XPathEvalError("Invalid "
                                                                   "predicate"))
        self.assertEqual(mapped.code, "invalid")


# ===========================================================================
# DURABILITY-1 — a short write produced a truncated backup generation
# ===========================================================================

class ShortWrite:
    """Context manager: make the FIRST os.write on any fd short, exactly once.

    A short write is legal, rare and almost never seen in a test — which is the
    whole reason the bug survived. Forcing one is the only honest way to test
    for it without filling a real filesystem.
    """

    def __init__(self, first_n=100):
        self.first_n = first_n
        self.fired = False
        self._real = os.write

    def __enter__(self):
        def patched(fd, data):
            if not self.fired and len(data) > self.first_n:
                self.fired = True
                return self._real(fd, data[:self.first_n])
            return self._real(fd, data)
        os.write = patched
        return self

    def __exit__(self, *exc):
        os.write = self._real
        return False


class Durability1(TempSafe):

    def test_durability1_write_all_loops_on_a_short_write(self):
        path = os.path.join(self.dir, "w")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with ShortWrite(first_n=7) as shim:
                written = write_all(fd, b"A" * 4096)
            self.assertTrue(shim.fired, "the shim did not force a short write")
            self.assertEqual(written, 4096)
        finally:
            os.close(fd)
        self.assertEqual(os.path.getsize(path), 4096)

    def test_durability1_a_short_backup_write_is_refused_and_removed(self):
        """The finding itself: the ring must never hold a partial generation.

        Before the fix `_ring_backup` advanced by the bytes READ, so this
        produced a 100-byte "generation" of a 4661-byte safe, fsync'd it, named
        it, and `backups` listed it with a plausible size.
        """
        path = _copy(KDBX41, self.dir)
        data = _read_bytes(path)
        ring = path + ".bak.d"
        with ShortWrite(first_n=100) as shim:
            base.atomic_replace(path, data, keep=3)
        self.assertTrue(shim.fired, "the shim did not force a short write")
        generations = os.listdir(ring)
        self.assertEqual(len(generations), 1)
        got = _read_bytes(os.path.join(ring, generations[0]))
        self.assertEqual(got, data,
                         "the ring holds a %d-byte generation of a %d-byte "
                         "safe" % (len(got), len(data)))

    def test_durability1_a_good_backup_is_still_taken(self):
        path = _copy(KDBX41, self.dir)
        data = _read_bytes(path)
        base.atomic_replace(path, data, keep=3)
        ring = path + ".bak.d"
        generations = os.listdir(ring)
        self.assertEqual(len(generations), 1)
        self.assertEqual(os.path.getsize(os.path.join(ring, generations[0])),
                         len(data))


# ===========================================================================
# DURABILITY-2 / DURABILITY-5 — the lock file
# ===========================================================================

class LockFileRegressions(TempSafe):

    def test_durability2_a_failed_payload_write_leaves_no_lock(self):
        """A completely full filesystem used to wedge the safe forever.

        `acquire()` creates the lock with O_CREAT|O_EXCL and then writes the
        payload. When that write failed the exception left `__enter__`, so
        Python never called `__exit__` and nothing ever removed the file. Every
        later save then answered `conflict / locked by an unnamed process` —
        long after the disk was free — and `override_stale` was the only way
        out, which is exactly the habit I13 needs operators not to acquire.
        """
        path = os.path.join(self.dir, "s.kdbx")
        open(path, "wb").close()
        os.chmod(path, 0o600)
        lock = LockFile.lock_path_for(path, "kdbx")

        real = os.write

        def explode(fd, data):
            raise OSError(28, "No space left on device")     # ENOSPC

        os.write = explode
        try:
            with self.assertRaises(Internal):
                with LockFile(path, fmt="kdbx"):
                    pass
        finally:
            os.write = real
        self.assertFalse(os.path.exists(lock),
                         "an orphan lock file survived a failed write")

        # …and the safe is savable again immediately, with no override.
        with LockFile(path, fmt="kdbx"):
            pass
        self.assertFalse(os.path.exists(lock))

    def test_durability5_a_directory_at_the_lock_path_is_a_conflict(self):
        """Not `internal / IsADirectoryError`, and not unreachable.

        `_read_holder` did `os.read` on a descriptor that `os.open` had happily
        given it for a DIRECTORY. The IsADirectoryError was raised inside the
        `except FileExistsError` handler, where the sibling `except OSError` of
        the same statement cannot catch it, so it escaped BEFORE the
        `override_stale` branch was consulted — the documented escape hatch
        could not be used at all.
        """
        path = os.path.join(self.dir, "s.kdbx")
        open(path, "wb").close()
        os.chmod(path, 0o600)
        os.mkdir(LockFile.lock_path_for(path, "kdbx"))

        for override in (False, True):
            with self.assertRaises(Conflict) as caught:
                with LockFile(path, fmt="kdbx", override_stale=override):
                    pass
            self.assertIn("not a lock file", caught.exception.detail)

    def test_durability5_an_ordinary_stale_lock_still_overrides(self):
        """The control: the escape hatch must still work where it should."""
        path = os.path.join(self.dir, "s.kdbx")
        open(path, "wb").close()
        os.chmod(path, 0o600)
        lock = LockFile.lock_path_for(path, "kdbx")
        with open(lock, "w") as fh:
            fh.write("[Lock]\nUserName=someone\n")
        os.chmod(lock, 0o600)
        with self.assertRaises(Conflict):
            with LockFile(path, fmt="kdbx"):
                pass
        with LockFile(path, fmt="kdbx", override_stale=True):
            pass


# ===========================================================================
# DURABILITY-4 — a truncated generation was restorable
# ===========================================================================

class Durability4(unittest.TestCase):

    def test_durability4_kdbx_truncation_is_detected_without_a_key(self):
        from backends.kdbx import KdbxBackend
        good = _read_bytes(KDBX41)
        self.assertIsNone(KdbxBackend.verify_structure(good))
        for cut in (100, 4096, len(good) - 1):
            with self.assertRaises(Invalid, msg="accepted a %d-byte prefix"
                                                % cut):
                KdbxBackend.verify_structure(good[:cut])
        # …and the magic alone is not the check: every prefix above keeps it.
        self.assertTrue(good[:100].startswith(b"\x03\xd9\xa2\x9a"))

    def test_durability4_kdbx3_truncation_is_detected(self):
        from backends.kdbx import KdbxBackend
        good = _read_bytes(KDBX31)
        self.assertIsNone(KdbxBackend.verify_structure(good))
        with self.assertRaises(Invalid):
            KdbxBackend.verify_structure(good[:4096])

    def test_durability4_trailing_bytes_are_detected(self):
        from backends.kdbx import KdbxBackend
        with self.assertRaises(Invalid):
            KdbxBackend.verify_structure(_read_bytes(KDBX41) + b"junk")

    def test_durability4_pws3_truncation_is_detected(self):
        from backends.psafe3 import Psafe3Backend
        good = _read_bytes(PWS3)
        self.assertIsNone(Psafe3Backend.verify_structure(good))
        for cut in (200, len(good) // 2, len(good) - 1):
            with self.assertRaises(Invalid):
                Psafe3Backend.verify_structure(good[:cut])

    def test_durability4_the_default_refuses_rather_than_passing(self):
        """A format with no completeness check must not read as verified."""
        from backends.base import Backend, Unsupported
        with self.assertRaises(Unsupported):
            Backend.verify_structure(b"anything")


# ===========================================================================
# CRYPTO-03 — the constant hardware-token challenge
# ===========================================================================

class Crypto03(TempSafe):

    def test_crypto03_constant_challenge_is_stated(self):
        """The mechanism is not fixed — see docs/RESIDUAL-RISK.md for the
        argument — so what is guarded is that the operator is TOLD. A silent
        deviation from KeePassXC on a second factor is the finding.
        """
        from backends import kdbx
        path = _copy(KDBX41, self.dir)
        entry = _entry(path, yubikey_slot=2)

        probe = kdbx.KdbxBackend(entry).probe()
        self.assertTrue(any("does not rotate that seed" in w
                            for w in probe["warnings"]),
                        "probe says nothing about the constant challenge: %r"
                        % probe["warnings"])

        # The committed fixture is not keyed with a token, so a real response
        # cannot pass the MAC. What is under test is that the warning is keyed
        # on the REGISTRY declaring a slot, so the component is neutralised for
        # the duration of one unlock and everything else stays real.
        backend = kdbx.KdbxBackend(entry)
        original = kdbx.KdbxBackend._challenge_component
        kdbx.KdbxBackend._challenge_component = lambda self, hdr, resp: None
        try:
            result = backend.unlock(Secret(bytearray(PW)))
        finally:
            kdbx.KdbxBackend._challenge_component = original
        self.addCleanup(backend.lock)
        self.assertTrue(any("does not rotate that seed" in w
                            for w in result["warnings"]),
                        "unlock says nothing about it either: %r"
                        % result["warnings"])

    def test_crypto03_the_challenge_is_still_the_kdf_seed(self):
        """If a later change DOES rotate the seed, this test is the reminder
        that the warning above has to go with it."""
        from backends import kdbx
        path = _copy(KDBX41, self.dir)
        entry = _entry(path, yubikey_slot=2)
        first = kdbx.challenge_for(entry)["challenge_b64"]
        backend = _open_kdbx(path)
        backend.edit(next(iter(backend._index)), {"notes": "touch"})
        backend.save()
        backend.lock()
        self.assertEqual(kdbx.challenge_for(entry)["challenge_b64"], first)


# ===========================================================================
# LEAKAGE-02 — the live browser harness wrote secrets under the umask
# ===========================================================================

class Leakage02(unittest.TestCase):

    HARNESS = os.path.join(HERE, "browser", "live-harness.js")
    SPEC = os.path.join(HERE, "browser", "live-ui.spec.js")
    RUNNER = os.path.join(HERE, "browser", "run-live.sh")

    def test_leakage02_every_artifact_writer_locks_the_file_down(self):
        """`page.screenshot()` and `download.saveAs()` have no mode option, so
        the two artefacts that contain ACTUAL secret material — a screenshot of
        an unmasked password field, and a decrypted attachment body — were the
        two written -rw-rw-r--, while the harmless console log was 0600."""
        harness = _read(self.HARNESS)
        self.assertIn("function lockDown(", harness)
        for writer in ("page.screenshot({ path: file", "await download.saveAs("):
            self.assertIn(writer, harness,
                          "a raw writer moved out of the harness: %r" % writer)
        self.assertNotIn("download.saveAs(", _read(self.SPEC),
                         "a spec calls download.saveAs() directly again; it "
                         "must go through H.saveDownload")

    def test_leakage02_the_runner_sets_a_private_umask(self):
        self.assertIn("umask 077", _read(self.RUNNER))


if __name__ == "__main__":
    unittest.main(verbosity=2)
