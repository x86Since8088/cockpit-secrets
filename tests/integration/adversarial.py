#!/usr/bin/env python3
"""The confirmed adversarial findings that only the REAL HELPER can prove.

`tests/test_regressions.py` guards the causes — a decompression guard, a write
loop, a lock file, a CSV cell — at the layer they live in, and `validate.sh`
runs it on every gate. What cannot be reached from there is the shape of a
REQUEST FRAME, the contents of a backup ring after several helper processes
have taken turns with it, and the bytes of an export artefact on disk. Those
are here, and each one is a full round trip through `secrets-admin`.

  INPUT-2      a deeply nested request answered `internal`, the code reserved
               for "we do not know what went wrong", for input the helper does
               know is malformed.
  DURABILITY-1 a short write on the backup fd produced a TRUNCATED generation
               that the ring presented as a good one. Reproduced here the way
               it happens in the field — one short `os.write` injected through
               a sitecustomize on PYTHONPATH, nothing in the package touched.
  DURABILITY-4 `restore-backup` installed a generation it had not checked was
               a complete database.
  DURABILITY-3 every restore reply said "this restore is itself undoable",
               which stops being true after `keep` of them.
  LEAKAGE-03   a CSV export wrote an attacker-supplied formula verbatim.
  LEAKAGE-04   an entry title containing a double quote answered `internal`.
  CRYPTO-01    the READ half: a database written entirely by keepassxc-cli, with
               an ordinary compressible attachment, was refused at every verb
               that touched the attachment. Needs the foreign oracle, so it
               cannot be a unit test.

Run it directly, or through `run_tests.sh`.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Report, PW, HELPER, SRC        # noqa: E402


# ---------------------------------------------------------------- INPUT-2 ---

def input2(env, r):
    r.section("INPUT-2 — a malformed request frame is `invalid`, never `internal`")
    cases = [
        ("100 000 open brackets", b"[" * 100000 + b"]" * 100000),
        ("100 000 nested objects", b'{"a":' * 100000 + b"1" + b"}" * 100000),
    ]
    for label, body in cases:
        p = subprocess.run([sys.executable, HELPER, "unlock"], cwd=SRC,
                           env=env.env, input=body, capture_output=True,
                           timeout=120)
        try:
            out = json.loads(p.stdout)
        except Exception:
            out = {"_unparseable": p.stdout[:200].decode("utf-8", "replace")}
        r.check("%s -> invalid" % label, out.get("error") == "invalid", out)
        r.check("%s: the detail says what was wrong" % label,
                "deeply" in (out.get("detail") or ""), out.get("detail"))
        r.check("%s: no traceback reached stdout" % label,
                "Traceback" not in p.stdout.decode("utf-8", "replace"))
    # The controls, so a blanket "everything is invalid" cannot pass this.
    for label, body, want in (
            ("not json at all", b"not json", "the request is not valid JSON"),
            ("a JSON array", b"[1,2,3]", "a single JSON object")):
        p = subprocess.run([sys.executable, HELPER, "unlock"], cwd=SRC,
                           env=env.env, input=body, capture_output=True,
                           timeout=120)
        out = json.loads(p.stdout)
        r.check("control: %s still says so" % label,
                out.get("error") == "invalid" and want in out.get("detail", ""),
                out)


# ----------------------------------------------------------- DURABILITY-1 ---

_SHIM = '''\
"""Injected on PYTHONPATH for ONE helper run. Makes the FIRST write to a file
whose name ends in `.bak` short, exactly once — the failure a nearly full
filesystem produces, without needing one."""
import os

_real_write = os.write
_state = {"fired": False}


def _is_backup(fd):
    try:
        return os.readlink("/proc/self/fd/%d" % fd).endswith(".bak")
    except OSError:
        return False


def _write(fd, data):
    if not _state["fired"] and len(data) > 100 and _is_backup(fd):
        _state["fired"] = True
        return _real_write(fd, data[:100])
    return _real_write(fd, data)


os.write = _write
'''


def durability1(env, r, shimdir):
    r.section("DURABILITY-1 — a short write must never make a ring generation")
    env.reset_safes()
    safe = "lab-kdbx41"
    path = os.path.join(env.safes, "lab-kdbx41-aes256-argon2id.kdbx")
    good = open(path, "rb").read()

    out, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                         "limit": 1})
    uuid = out["entries"][0]["uuid"]

    shim_env = dict(env.env)
    shim_env["PYTHONPATH"] = shimdir + os.pathsep + shim_env.get("PYTHONPATH", "")
    out, _rc, _err = env.run(
        "edit", {"safe": safe, "password": PW, "uuid": uuid,
                 "changes": {"notes": "short-write probe"}, "autosave": True},
        extra_env={"PYTHONPATH": shim_env["PYTHONPATH"]})
    r.check("the save still succeeds — a short write is not an error",
            out.get("saved") is True, out)

    bdir = path + ".bak.d"
    gens = sorted(os.listdir(bdir)) if os.path.isdir(bdir) else []
    r.check("exactly one generation was taken", len(gens) == 1, gens)
    if gens:
        blob = open(os.path.join(bdir, gens[0]), "rb").read()
        r.check("…and it is the WHOLE file, not the first short write",
                blob == good, "%d bytes of %d" % (len(blob), len(good)))

    # The ring is listed and restorable, and what comes back opens.
    listing, _rc, _err = env.run("backups", {"safe": safe})
    r.check("`backups` lists it", listing.get("total") == 1, listing)
    if gens:
        res, rc, _err = env.run("restore-backup", {"safe": safe,
                                                   "name": gens[0]})
        r.check("restore-backup accepts a COMPLETE generation",
                res.get("ok") is True, res)
        after, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                               "limit": 1})
        r.check("…and the restored safe opens", "entries" in after, after)


# ----------------------------------------------------------- DURABILITY-4 ---

def durability4(env, r):
    r.section("DURABILITY-4 — a truncated generation is not restorable")
    env.reset_safes()
    safe = "lab-kdbx41"
    path = os.path.join(env.safes, "lab-kdbx41-aes256-argon2id.kdbx")

    # One real save, to create the ring the way the program does.
    out, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                         "limit": 1})
    uuid = out["entries"][0]["uuid"]
    env.run("edit", {"safe": safe, "password": PW, "uuid": uuid,
                     "changes": {"notes": "one"}, "autosave": True})
    bdir = path + ".bak.d"
    gens = sorted(os.listdir(bdir))
    if not r.check("the ring holds a generation", len(gens) == 1, gens):
        return

    # Truncate it the way a short write did, keeping the format magic.
    victim = os.path.join(bdir, gens[0])
    with open(victim, "r+b") as fh:
        fh.truncate(4096)
    r.check("the truncated generation still carries the KDBX magic",
            open(victim, "rb").read(4) == b"\x03\xd9\xa2\x9a")

    listing, _rc, _err = env.run("backups", {"safe": safe})
    r.check("`backups` still lists it — the listing is metadata only",
            listing.get("total") == 1, listing)

    live_before = open(path, "rb").read()
    res, rc, _err = env.run("restore-backup", {"safe": safe, "name": gens[0]})
    r.check("restore-backup REFUSES it", res.get("error") == "invalid", res)
    r.check("…and says it is not complete",
            "complete" in (res.get("detail") or ""), res.get("detail"))
    r.check("…and the live safe is byte-for-byte what it was",
            open(path, "rb").read() == live_before,
            "%d bytes now, %d before" % (os.path.getsize(path),
                                         len(live_before)))
    after, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                           "limit": 1})
    r.check("…and it still opens", "entries" in after, after)


# ----------------------------------------------------------- DURABILITY-3 ---

def durability3(env, r):
    r.section("DURABILITY-3 — `restore-backup` tells the truth about undo")
    env.reset_safes()
    safe = "lab-kdbx41"
    path = os.path.join(env.safes, "lab-kdbx41-aes256-argon2id.kdbx")
    keep = 3

    out, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                         "limit": 1})
    uuid = out["entries"][0]["uuid"]
    for n in range(4):
        env.run("edit", {"safe": safe, "password": PW, "uuid": uuid,
                         "changes": {"notes": "legitimate-revision-%d" % n},
                         "autosave": True})
    target = hashlib.sha256(open(path, "rb").read()).hexdigest()

    def ring_hashes():
        bdir = path + ".bak.d"
        return {n: hashlib.sha256(
            open(os.path.join(bdir, n), "rb").read()).hexdigest()
            for n in sorted(os.listdir(bdir))}

    saw_full_warning = False
    for step in range(1, keep + 3):
        listing, _rc, _err = env.run("backups", {"safe": safe})
        hashes = ring_hashes()
        pick = next((row["name"] for row in listing["backups"]
                     if hashes.get(row["name"]) != target),
                    listing["backups"][0]["name"])
        res, _rc, _err = env.run("restore-backup", {"safe": safe,
                                                    "name": pick})
        if not r.check("restore %d succeeded" % step, res.get("ok") is True,
                       res):
            return
        r.check("restore %d carries an `undo` sentence" % step,
                isinstance(res.get("undo"), str) and res["undo"], res.get("undo"))
        r.check("restore %d no longer claims to be unconditionally undoable"
                % step,
                "is itself undoable" not in res.get("undo", ""), res.get("undo"))
        if res.get("ring_full"):
            saw_full_warning = True
            r.check("…and when the ring is FULL it says the oldest generation "
                    "is about to be discarded",
                    "discards the oldest" in res["undo"], res["undo"])
        recoverable = sum(1 for h in ring_hashes().values() if h == target)
        r.check("restore %d: ring_full=%s matches the ring (%d of %d slots, "
                "%d still hold the operator's state)"
                % (step, res.get("ring_full"), len(ring_hashes()), keep,
                   recoverable),
                res.get("ring_full") == (len(ring_hashes()) >= keep))
    r.check("the operator was warned before the ring started discarding",
            saw_full_warning)


# ------------------------------------------------------------- LEAKAGE-03 ---

def leakage03(env, r):
    r.section("LEAKAGE-03 — a CSV export cannot carry a live formula")
    env.reset_safes()
    # `export` is an administrator-class verb, so this runs at a real euid 0
    # inside `unshare --map-root-user` — the same shape tests/integration/
    # newverbs.py uses for the export allow-path.
    safe = "lab-admin"
    exports = os.path.join(env.var, "exports")
    os.makedirs(exports, exist_ok=True)
    os.chmod(exports, 0o700)

    for name in os.listdir(env.safes_d):
        p = os.path.join(env.safes_d, name)
        entry = json.load(open(p))
        if entry["id"] == safe:
            entry["export_allowed"] = True
            entry["export_dir"] = exports
            json.dump(entry, open(p, "w"), indent=1)
            os.chmod(p, 0o644)
            break

    def as_root(verb, req):
        p = subprocess.run(["unshare", "--map-root-user", "--",
                            sys.executable, HELPER, verb],
                           cwd=SRC, env=env.env, input=json.dumps(req),
                           text=True, capture_output=True, timeout=300)
        try:
            return json.loads(p.stdout)
        except Exception:
            return {"_unparseable": p.stdout[:300], "_stderr": p.stderr[-300:]}

    payload = "=cmd|' /C calc'!A0"
    add = as_root("add", {"safe": safe, "password": PW, "group": None,
                          "entry": {"title": "Nasty", "username": "n",
                                    "password": "pw1", "url": payload},
                          "autosave": True})
    if not r.check("the hostile entry was added", "uuid" in add, add):
        return

    out = as_root("export", {"safe": safe, "password": PW, "fmt": "csv",
                             "confirm": "export-plaintext:" + safe})
    if not r.check("the export was written", "path" in out, out):
        return
    r.check("the reply says how many cells were neutralised",
            out.get("neutralised", 0) >= 1, out.get("neutralised"))
    r.check("…and the warning explains the apostrophe",
            "apostrophe" in out.get("warning", ""), out.get("warning"))

    text = open(out["path"], encoding="utf-8").read()
    r.check("the payload is present as TEXT, prefixed", '"\'=cmd' in text)
    r.check("…and never as a live formula", '"=cmd' not in text)
    r.check("an ordinary value is untouched", '"Nasty"' in text)
    os.unlink(out["path"])


# ------------------------------------------------------------- LEAKAGE-04 ---

def leakage04(env, r):
    r.section("LEAKAGE-04 — a double quote in a title is a legal entry")
    env.reset_safes()
    safe = "lab-kdbx41"
    for title in ("plain2", 'a"b', "a&b", "a<b", "a'b", '=WEBSERVICE("x")'):
        out, _rc, _err = env.run(
            "add", {"safe": safe, "password": PW, "group": None,
                    "entry": {"title": title, "username": 'u"v',
                              "password": "p"},
                    "autosave": True})
        r.check("add(%r) succeeds" % title, "uuid" in out, out)
        r.check("add(%r) is never `internal`" % title,
                out.get("error") != "internal", out)
    listing, _rc, _err = env.run("entries", {"safe": safe, "password": PW,
                                             "limit": 200})
    titles = {row["title"] for row in listing.get("entries", [])}
    r.check("every title round-tripped exactly",
            {'a"b', '=WEBSERVICE("x")'} <= titles,
            sorted(t for t in titles if '"' in t))


# ---------------------------------------------------------------- CRYPTO-01 ---

def crypto01_foreign(env, r):
    """The READ half of I23, against the foreign oracle rather than ourselves.

    The write half is a unit test (attach_add -> save -> unlock). This is the
    half a unit test cannot honestly cover: a database written ENTIRELY by
    `keepassxc-cli`, whose KDBX 3.1 binary pool gzips each attachment on its
    own, so an ordinary 8 MiB log file becomes a ~2 KB database. Before the fix
    that file unlocked and then answered `invalid: compressed payload expansion
    ratio 293:1 is over the 200:1 limit` at `fields`, `attach_list`,
    `attach_get` and `export_plain` — while keepassxc-cli exported the same
    attachment byte for byte.

    Skipped, loudly, where the oracle is not installed: keepassxc-cli is the
    TEST-ONLY oracle and must never appear in a runtime path.
    """
    r.section("CRYPTO-01 (read half) — a foreign database with a compressible "
              "attachment")
    if not shutil.which("keepassxc-cli"):
        r.check("keepassxc-cli is installed (the oracle)", False,
                "skipped: no oracle on this host")
        return
    work = os.path.join(env.root, "foreign")
    os.makedirs(work, exist_ok=True)
    os.chmod(work, 0o700)
    db = os.path.join(work, "f.kdbx")
    blob = os.path.join(work, "app.log")
    line = (b"2026-09-04T10:00:00Z INFO worker=3 request completed "
            b"status=200 bytes=1234\n")
    body = (line * (8 * 1024 * 1024 // len(line)))[:8 * 1024 * 1024]
    with open(blob, "wb") as fh:
        fh.write(body)

    def kpxc(args, stdin):
        return subprocess.run(["keepassxc-cli"] + args, input=stdin, text=True,
                              capture_output=True, timeout=300)

    kpxc(["db-create", "-q", "-p", db], "kpxc-pass\nkpxc-pass\n")
    kpxc(["add", "-q", "-u", "user", "-p", db, "/Item"],
         "kpxc-pass\nitem-pass\nitem-pass\n")
    kpxc(["attachment-import", "-q", db, "/Item", "app.log", blob],
         "kpxc-pass\n")
    if not r.check("the oracle built a database with the attachment",
                   os.path.exists(db) and os.path.getsize(db) > 0,
                   "%d bytes" % (os.path.getsize(db) if os.path.exists(db)
                                 else 0)):
        return
    os.chmod(db, 0o600)
    back = os.path.join(work, "out.log")
    kpxc(["attachment-export", "-q", db, "/Item", "app.log", back],
         "kpxc-pass\n")
    r.check("…and reads its own attachment back byte for byte",
            os.path.exists(back) and open(back, "rb").read() == body)

    entry = {"id": "foreign", "label": "foreign", "format": "kdbx",
             "path": db, "access": "user", "owner": "%u", "mode": "ro",
             "password_required": True, "backup": {"keep": 3, "dir": None}}
    reg = os.path.join(env.safes_d, "91-foreign.json")
    with open(reg, "w") as fh:
        json.dump(entry, fh)
    os.chmod(reg, 0o644)
    try:
        out, _rc, _err = env.run("entries", {"safe": "foreign",
                                             "password": "kpxc-pass"})
        if not r.check("cockpit-secrets opens it", "entries" in out, out):
            return
        uuid = out["entries"][0]["uuid"]
        listed, _rc, _err = env.run("attach-list", {"safe": "foreign",
                                                    "password": "kpxc-pass",
                                                    "uuid": uuid})
        r.check("attach-list names the attachment",
                [a["name"] for a in listed.get("attachments", [])] == ["app.log"],
                listed)
        r.check("…with its true size",
                listed.get("attachments", [{}])[0].get("size") == len(body),
                listed)
        got, _rc, _err = env.run("attach-get", {"safe": "foreign",
                                                "password": "kpxc-pass",
                                                "uuid": uuid,
                                                "name": "app.log"})
        r.check("attach-get returns it", got.get("size") == len(body), got)
    finally:
        os.unlink(reg)


def main():
    env = Env().build()
    r = Report("adversarial findings, against the real helper")
    shimdir = os.path.join(env.root, "shim")
    os.makedirs(shimdir, exist_ok=True)
    with open(os.path.join(shimdir, "sitecustomize.py"), "w") as fh:
        fh.write(_SHIM)
    try:
        input2(env, r)
        durability1(env, r, shimdir)
        durability4(env, r)
        durability3(env, r)
        leakage03(env, r)
        leakage04(env, r)
        crypto01_foreign(env, r)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
