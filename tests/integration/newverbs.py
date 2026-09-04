#!/usr/bin/env python3
"""Every verb added after the first build, driven end to end on BOTH formats.

The first build's suite (flow / conformance / properties / corpus) covers the
original verb table. This one covers the ten that came after — export, save-as,
backups, restore-backup, history, history-restore, attach-add, attach-rm,
strength, breach-check — against the REAL helper and the REAL fixtures in a
hermetic `COCKPIT_SECRETS_ETC`. Nothing is stubbed.

Two things here are not just "call it and see":

  * **The export gate is proved as a PAIR.** A refusal on its own proves
    nothing — a verb that always fails also always refuses. So the same
    request that is refused as uid 1000 is re-sent inside `unshare -r`, where
    `os.geteuid()` really is 0 and the admin branch of `gate()` really runs,
    and it succeeds. One without the other is not evidence.

  * **A traversal refusal is only interesting if the safe name is not.** Every
    bad `save-as` name below is sent through the same code path that accepted
    `copy.kdbx` a few lines earlier, so a green result cannot come from the
    verb being broken for everyone.

`unshare -r` is a real euid 0 and a real admin branch. It is NOT a real root
registry: inside the namespace the caller's real uid is also 0, so the
SUDO_UID/group-membership branch of `gate()` is correctly skipped rather than
exercised. That half needs the /srv/jobs runner and is stated, not claimed.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, HELPER, SRC, PW, SENTINEL   # noqa: E402

#: A string that must never appear in an audit log or a helper response. Not
#: the fixture sentinel: this one is written BY this script, so finding it
#: anywhere proves that this run leaked it, not that a fixture contains it.
CANARY = "NEWVERBS-CANARY-9c41ae"

#: Two HIBP-shaped corpus rows. The format is `<SHA1 upper hex>:<count>`, and
#: the file must be sorted by hash for the binary-search path to be sound —
#: which is why it is built here rather than hand-written in the wrong order.
CORPUS_PASSWORDS = [("hunter2", 41), ("correct horse battery staple", 3)]

#: The control for the "no network" proof. Cockpit is live on 9090 on this
#: host, so a connection to it succeeds outside a namespace and must fail
#: inside one — which is what turns "breach-check answered" into evidence that
#: it did not need a socket, rather than evidence that unshare did nothing.
NET_PROBE = (
    "import socket, sys\n"
    "try:\n"
    "    socket.create_connection(('127.0.0.1', 9090), 3).close()\n"
    "    sys.exit(0)\n"
    "except OSError:\n"
    "    sys.exit(7)\n"
)


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _strings(obj, out=None):
    """Every string anywhere in a response, keys included."""
    out = set() if out is None else out
    if isinstance(obj, str):
        out.add(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            _strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _strings(v, out)
    return out


def build_corpus(path):
    rows = sorted((hashlib.sha1(p.encode()).hexdigest().upper(), n)
                  for p, n in CORPUS_PASSWORDS)
    with open(path, "w") as fh:
        for h, n in rows:
            fh.write("%s:%d\n" % (h, n))
    os.chmod(path, 0o600)
    return path


def add_safe(env, sid, fixture, **over):
    """Register one more view of a fixture. `Env.build()` writes a fixed set;
    the export and agent cases need entries it does not have, and copying its
    whole table here would make a fixture rename break two files."""
    entry = {"id": sid, "label": sid,
             "format": over.pop("format", "kdbx"),
             "path": os.path.join(env.safes, fixture),
             "access": over.pop("access", "user"),
             "mode": "rw", "password_required": True,
             "backup": {"keep": 3, "dir": None}}
    if entry["access"] == "user":
        entry["owner"] = "%u"
    entry.update(over)
    p = os.path.join(env.safes_d, "90-%s.json" % sid)
    with open(p, "w") as fh:
        json.dump(entry, fh, indent=1)
    os.chmod(p, 0o644)
    dst = os.path.join(env.safes, fixture)
    if not os.path.exists(dst):
        shutil.copy(os.path.join(SRC, "tests", "fixtures", fixture), dst)
        os.chmod(dst, 0o600)
    return entry


def run_as_root(env, verb, req):
    """The same single-shot call `Env.run` makes, inside a user namespace where
    `os.geteuid()` is 0. `--map-root-user` maps only the caller, so the files
    stay ours and only the identity the helper reads changes."""
    p = subprocess.run(
        ["unshare", "--map-root-user", "--", sys.executable, HELPER, verb],
        cwd=SRC, env=env.env, input=json.dumps(req),
        text=True, capture_output=True, timeout=300)
    try:
        return json.loads(p.stdout), p.returncode
    except Exception:
        return {"_unparseable": (p.stdout or p.stderr)[:400]}, p.returncode


# ------------------------------------------------------------ history ------

def history_both(env, r):
    r.section("history / history-restore — both formats, no password in a row")
    for safe in ("lab-kdbx41", "lab-pws3"):
        s = Session(env)
        try:
            h = s.call("unlock", safe=safe, password=PW)["handle"]
            uuid = s.call("entries", handle=h, limit=1)["entries"][0]["uuid"]
            first = s.call("reveal", handle=h, uuid=uuid,
                           field="password")["value"]
            if safe == "lab-pws3":
                # PWS3 records history POLICY in the record, and formatV3.txt
                # note [12] calls an ABSENT 0x0f field the preferred way to
                # say "keep none" — so nothing in this program manufactures
                # one, and a fixture record without it must genuinely have no
                # history. Assert that first, then turn the policy on the way
                # Password Safe does: `1` = enabled, `03` = keep three, `00`
                # = the list is currently empty.
                empty = s.call("history", handle=h, uuid=uuid)
                r.check("lab-pws3: a record with no 0x0f field has no history",
                        empty.get("total") == 0, empty)
                r.check("lab-pws3: ...and restoring from it is not-found",
                        s.call("history-restore", handle=h, uuid=uuid,
                               index=0).get("error") == "not-found")
                s.call("edit", handle=h, uuid=uuid,
                       changes={"password-history": "10300"})
            # Two edits, so there are two archived versions and an ORDER to
            # get wrong. `index` counts FORWARDS through time: 0 is oldest.
            s.call("edit", handle=h, uuid=uuid,
                   changes={"password": CANARY + "-1"})
            s.call("edit", handle=h, uuid=uuid,
                   changes={"password": CANARY + "-2"})
            out = s.call("history", handle=h, uuid=uuid)
            rows = out.get("versions") or []
            r.check("%s: two edits leave two versions" % safe,
                    len(rows) == 2, out.get("total"))
            r.check("%s: no row carries a password" % safe,
                    CANARY not in json.dumps(rows)
                    and not any("password" in k and k != "has_password"
                                for row in rows for k in row))
            r.check("%s: a row says a password EXISTS without giving it" % safe,
                    all(row.get("has_password") is True for row in rows), rows)
            r.check("%s: every row carries the documented keys" % safe,
                    all({"index", "when", "title", "username", "url",
                         "has_password", "notes_len"} <= set(row)
                        for row in rows))
            r.check("%s: indexes are 0..n-1 in listing order" % safe,
                    [row["index"] for row in rows] == list(range(len(rows))))
            # THE ORDERING CHECK. `index` counted backwards in the schema's
            # help text and forwards in the data, and secrets.js believed the
            # text — so history displayed newest-first under an "oldest"
            # label. index 0 must restore the ORIGINAL password.
            back = s.call("history-restore", handle=h, uuid=uuid, index=0)
            r.check("%s: history-restore names where it came from" % safe,
                    back.get("restored_from") == 0, back)
            now = s.call("reveal", handle=h, uuid=uuid, field="password")
            r.check("%s: index 0 is the OLDEST version, not the newest" % safe,
                    now.get("value") == first, now.get("value"))
            r.check("%s: a negative index is refused" % safe,
                    s.call("history-restore", handle=h, uuid=uuid,
                           index=-1).get("error") in ("not-found", "invalid"))
            r.check("%s: an index past the end is refused" % safe,
                    s.call("history-restore", handle=h, uuid=uuid,
                           index=999).get("error") in ("not-found", "invalid"))
        finally:
            s.close()
    env.reset_safes()


def reveal_vocabulary(env, r):
    """`reveal`'s published field names must all reach something.

    Two of them did not. `custom:<name>` was passed through to the backend
    verbatim, so KDBX looked up a string field literally called
    `custom:Lab Ticket` and answered not-found for every custom field in every
    database — while secrets.js was building buttons that sent exactly that.
    `totp` (labelled "TOTP secret" in the schema's own select) reached neither
    backend's name for the seed. Both are one-line mappings and both are the
    kind of thing only an end-to-end check catches, because each half was
    individually correct.
    """
    r.section("reveal — every published field name reaches a value")
    for safe, custom in (("lab-kdbx41", True), ("lab-pws3", False)):
        s = Session(env)
        try:
            h = s.call("unlock", safe=safe, password=PW)["handle"]
            rows = s.call("entries", handle=h, limit=50)["entries"]
            uuid = rows[0]["uuid"]
            for f in ("password", "username", "url", "notes", "title"):
                got = s.call("reveal", handle=h, uuid=uuid, field=f)
                r.check("%s: reveal %s answers" % (safe, f),
                        "value" in got, got)
                r.check("%s: reveal %s echoes the REQUESTED name" % (safe, f),
                        got.get("field") == f, got.get("field"))
            totp_uuid = next((x["uuid"] for x in rows if x.get("has_totp")),
                             None)
            if totp_uuid:
                got = s.call("reveal", handle=h, uuid=totp_uuid, field="totp")
                r.check("%s: reveal totp reaches the seed" % safe,
                        "value" in got and got["value"], got)
            if custom:
                s.call("edit", handle=h, uuid=uuid,
                       changes={"custom": {"Lab Ticket": CANARY}})
                got = s.call("reveal", handle=h, uuid=uuid,
                             field="custom:Lab Ticket")
                r.check("%s: custom:<name> reaches the custom field" % safe,
                        got.get("value") == CANARY, got)
                r.check("%s: ...and reports the storage key it resolved to"
                        % safe, got.get("resolved_field") == "Lab Ticket", got)
                # `custom:` must not be a second door to a reserved field:
                # one that answered would put the master password behind an
                # audit line that said "custom field".
                r.check("%s: custom:Password is NOT a shortcut" % safe,
                        s.call("reveal", handle=h, uuid=uuid,
                               field="custom:Password"
                               ).get("error") == "not-found")
            else:
                got = s.call("reveal", handle=h, uuid=uuid,
                             field="custom:anything")
                r.check("%s: custom:<name> is unsupported, with a reason"
                        % safe,
                        got.get("error") == "unsupported" and got.get("detail"),
                        got.get("detail"))
        finally:
            s.close()
    env.reset_safes()


# --------------------------------------------------------- attachments -----

def attachments_both(env, r):
    r.section("attach-add / attach-rm — both formats")
    payload = b"\x00\x01\x02" + CANARY.encode() + b"\xff" * 64
    b64 = base64.b64encode(payload).decode()
    for safe in ("lab-kdbx41", "lab-pws3"):
        s = Session(env)
        try:
            h = s.call("unlock", safe=safe, password=PW)["handle"]
            uuid = s.call("entries", handle=h, limit=1)["entries"][0]["uuid"]
            add = s.call("attach-add", handle=h, uuid=uuid,
                         name="evidence.bin", data_b64=b64)
            r.check("%s: attach-add reports the DECODED size" % safe,
                    add.get("size") == len(payload), add)
            got = s.call("attach-get", handle=h, uuid=uuid, name="evidence.bin")
            r.check("%s: the bytes round-trip exactly" % safe,
                    base64.b64decode(got.get("b64", "")) == payload)
            dup = s.call("attach-add", handle=h, uuid=uuid,
                         name="evidence.bin", data_b64=b64)
            r.check("%s: a duplicate name is a conflict" % safe,
                    dup.get("error") == "conflict", dup)
            rep = s.call("attach-add", handle=h, uuid=uuid,
                         name="evidence.bin", data_b64=b64, replace=True)
            r.check("%s: replace=true is accepted" % safe,
                    rep.get("ok") is True, rep)
            r.check("%s: non-base64 is refused" % safe,
                    s.call("attach-add", handle=h, uuid=uuid, name="x.bin",
                           data_b64="not base64!!").get("error") == "invalid")
            rm = s.call("attach-rm", handle=h, uuid=uuid, name="evidence.bin")
            r.check("%s: attach-rm succeeds" % safe, rm.get("ok") is True, rm)
            r.check("%s: and it is gone" % safe,
                    s.call("attach-get", handle=h, uuid=uuid,
                           name="evidence.bin").get("error") == "not-found")
            r.check("%s: removing it twice is not-found" % safe,
                    s.call("attach-rm", handle=h, uuid=uuid,
                           name="evidence.bin").get("error") == "not-found")
            # THE CEILING THAT ACTUALLY BITES IS THE TRANSPORT, not the
            # format. `data_b64`'s declared max is 32 MiB, but the whole
            # request is one JSON object capped at MAX_REQUEST_BYTES and
            # base64 costs a third, so ~760 KiB fits. This is deliberately the
            # LAST thing done on this session: an over-long line cannot be
            # resynchronised, so the helper answers `invalid`, emits a closing
            # frame and shuts the stream down — correct, and fatal to the
            # session, which is why the single-shot form is used below.
            over = s.call_may_close("attach-add", handle=h, uuid=uuid,
                                    name="big.bin",
                                    data_b64="A" * (2 * 1024 * 1024))
            r.check("%s: an oversize frame is answered, not just dropped"
                    % safe, over.get("error") == "invalid",
                    over.get("detail"))
        finally:
            s.close()
    r.section("attach-add — the request cap, on the single-shot transport")
    huge = base64.b64encode(b"A" * (2 * 1024 * 1024)).decode()
    for safe in ("lab-kdbx41", "lab-pws3"):
        got, rc, _e = env.run("attach-add",
                              {"safe": safe, "password": PW, "uuid": "x",
                               "name": "big.bin", "data_b64": huge})
        r.check("%s: an oversize request is refused" % safe,
                got.get("error") == "invalid" and rc != 0, got.get("detail"))
        r.check("%s: ...by the REQUEST limit, before any decode" % safe,
                "request" in (got.get("detail") or ""), got.get("detail"))
    env.reset_safes()


# ------------------------------------------------- save-as and backups -----

#: Every shape of "this is not a bare file name" worth naming. `..` and a
#: leading dot are separate rules from the slash rule, and NUL is separate
#: again because everything below Python's string layer is C.
BAD_NAMES = ["../escape.kdbx", "../../etc/passwd", "/etc/cockpit-secrets/x",
             "sub/dir.kdbx", "..", ".", ".hidden", "a\x00b.kdbx",
             "back\\slash.kdbx", "", "  ", "x" * 300]


def save_as_and_backups(env, r):
    r.section("save-as — a NAME, never a path (I4)")
    for safe, fixture in (("lab-kdbx41", "lab-kdbx41-aes256-argon2id.kdbx"),
                          ("lab-pws3", "lab-pws3.psafe3")):
        orig = os.path.join(env.safes, fixture)
        before = sha(orig)
        s = Session(env)
        try:
            h = s.call("unlock", safe=safe, password=PW)["handle"]
            good = "copy-%s.out" % safe
            out = s.call("save-as", handle=h, name=good)
            r.check("%s: save-as writes a new file" % safe,
                    out.get("ok") is True and os.path.exists(out.get("path", "")),
                    out)
            r.check("%s: the ORIGINAL is byte-identical afterwards" % safe,
                    sha(orig) == before)
            r.check("%s: the copy is 0600" % safe,
                    os.stat(out["path"]).st_mode & 0o777 == 0o600)
            r.check("%s: the byte count matches the file" % safe,
                    out.get("bytes") == os.path.getsize(out["path"]))
            r.check("%s: no .bak.d appeared beside the original" % safe,
                    not os.path.exists(orig + ".bak.d"))
            for bad in BAD_NAMES:
                got = s.call("save-as", handle=h, name=bad)
                r.check("%s: save-as refuses %r" % (safe, bad),
                        got.get("error") == "invalid", got.get("detail"))
            r.check("%s: an existing target is a conflict" % safe,
                    s.call("save-as", handle=h,
                           name=good).get("error") == "conflict")
        finally:
            s.close()
        # A read-only registry entry must refuse even a NEW file: `mode:"ro"`
        # is a statement about this safe, not about this inode.
        if safe == "lab-kdbx41":
            s = Session(env)
            try:
                h = s.call("unlock", safe="lab-ro", password=PW)["handle"]
                got = s.call("save-as", handle=h, name="ro-copy.kdbx")
                r.check("a mode:ro safe refuses save-as",
                        got.get("error") == "access-denied", got)
            finally:
                s.close()

    r.section("backups / restore-backup — membership, not sanitising")
    for safe, fixture in (("lab-kdbx41", "lab-kdbx41-aes256-argon2id.kdbx"),
                          ("lab-pws3", "lab-pws3.psafe3")):
        orig = os.path.join(env.safes, fixture)
        pristine = sha(orig)
        s = Session(env)
        try:
            h = s.call("unlock", safe=safe, password=PW)["handle"]
            uuid = s.call("entries", handle=h, limit=1)["entries"][0]["uuid"]
            s.call("edit", handle=h, uuid=uuid, changes={"notes": CANARY})
            saved = s.call("save", handle=h)
            r.check("%s: save succeeded" % safe, saved.get("ok") is True, saved)
        finally:
            s.close()
        r.check("%s: the file really changed" % safe, sha(orig) != pristine)

        listing, _rc, _e = env.run("backups", {"safe": safe})
        names = [b["name"] for b in listing.get("backups") or []]
        r.check("%s: the save left one generation" % safe,
                len(names) == 1, listing.get("total"))
        r.check("%s: every generation carries name/when/size" % safe,
                all({"name", "when", "size"} <= set(b)
                    for b in listing.get("backups") or []))
        for bad in ["../../etc/passwd", "/etc/passwd", "nope.bak", "", ".",
                    "..", names[0] + "x"]:
            got, _rc, _e = env.run("restore-backup",
                                   {"safe": safe, "name": bad})
            r.check("%s: restore-backup refuses %r" % (safe, bad),
                    got.get("error") in ("not-found", "invalid"),
                    got.get("detail"))
        got, _rc, _e = env.run("restore-backup",
                               {"safe": safe, "name": names[0]})
        r.check("%s: restore-backup accepts a listed generation" % safe,
                got.get("ok") is True, got)
        r.check("%s: the pristine bytes are back" % safe, sha(orig) == pristine)
        r.check("%s: created is false — the safe was there" % safe,
                got.get("created") is False, got.get("created"))
        # The restore is itself undoable: `atomic_replace` copies the CURRENT
        # file into the ring before writing, so the ring goes 1 -> 2 and the
        # generation just replaced is the newest one in the listing.
        after = env.run("backups", {"safe": safe})[0].get("backups") or []
        r.check("%s: the restore took its own backup first" % safe,
                len(after) == 2, [b["name"] for b in after])
        r.check("%s: ...and it is the newest generation" % safe,
                after[0]["name"] == os.path.basename(got.get("backup") or ""),
                (after[0]["name"], got.get("backup")))
    env.reset_safes()


# ------------------------------------------------------------- export ------

def export_gate(env, r):
    r.section("export — refused four ways, then allowed at euid 0 (I21)")
    exp_dir = os.path.join(env.var, "exports")
    add_safe(env, "exp-user", "lab-kdbx41-aes256-argon2id.kdbx",
             access="user", export_allowed=True)
    add_safe(env, "exp-admin", "lab-kdbx41-aes256-argon2id.kdbx",
             access="admin", export_allowed=True, export_dir=exp_dir)
    add_safe(env, "exp-off", "lab-kdbx41-aes256-argon2id.kdbx",
             access="admin", export_allowed=False)
    add_safe(env, "exp-pws3", "lab-pws3.psafe3", format="psafe3",
             access="admin", export_allowed=True, export_dir=exp_dir)

    # The schema now knows export_dir and breach_corpus, so the helper's
    # drift accommodation must have nothing to report.
    h, _rc, _e = env.run("health")
    r.check("the registry accepted every entry",
            not h.get("registry_errors"), h.get("registry_errors"))
    r.check("export_dir/breach_corpus need no schema-drift accommodation",
            not h.get("registry_drift"), h.get("registry_drift"))

    ok_req = {"password": PW, "fmt": "csv"}

    def call(sid, **kw):
        req = dict(ok_req, safe=sid,
                   confirm="export-plaintext:" + kw.pop("confirm_for", sid))
        req.update(kw)
        return env.run("export", req)[0]

    # 1. the class gate — a user-class safe, export_allowed AND a valid confirm
    got = call("exp-user")
    r.check("refused for a user-class safe even with export_allowed",
            got.get("error") == "access-denied", got.get("detail"))
    # 2. an admin-class safe, but this caller is not euid 0
    got = call("exp-admin")
    r.check("refused for a non-root caller on an admin safe",
            got.get("error") == "access-denied", got.get("detail"))
    # 3. the registry switch, checked even at euid 0
    got, _rc = run_as_root(env, "export",
                           dict(ok_req, safe="exp-off",
                                confirm="export-plaintext:exp-off"))
    r.check("refused at euid 0 when export_allowed is false",
            got.get("error") == "access-denied", got.get("detail"))
    # 4. the confirm — missing, and belonging to a DIFFERENT safe
    got, _rc = run_as_root(env, "export", dict(ok_req, safe="exp-admin"))
    r.check("refused at euid 0 with no confirm",
            got.get("error") == "access-denied", got.get("detail"))
    got, _rc = run_as_root(env, "export",
                           dict(ok_req, safe="exp-admin",
                                confirm="export-plaintext:exp-off"))
    r.check("a confirm naming ANOTHER safe is refused",
            got.get("error") == "access-denied", got.get("detail"))
    got, _rc = run_as_root(env, "export",
                           dict(safe="exp-admin", password=PW, fmt="pdf",
                                confirm="export-plaintext:exp-admin"))
    r.check("an unknown fmt is refused", got.get("error") == "invalid", got)

    # ...and now the allowed path, which is what makes the refusals evidence.
    for sid, fmt, expect in (("exp-admin", "csv", "ok"),
                             ("exp-admin", "xml", "ok"),
                             ("exp-admin", "json", "ok"),
                             ("exp-pws3", "csv", "ok"),
                             ("exp-pws3", "xml", "unsupported")):
        got, _rc = run_as_root(env, "export",
                               {"safe": sid, "password": PW, "fmt": fmt,
                                "confirm": "export-plaintext:" + sid})
        if expect == "unsupported":
            r.check("%s %s answers unsupported with a reason" % (sid, fmt),
                    got.get("error") == "unsupported" and got.get("detail"),
                    got.get("detail"))
            continue
        if not r.check("%s %s exports at euid 0" % (sid, fmt),
                       got.get("ok", True) and "path" in got, got):
            continue
        path = got["path"]
        r.check("%s %s: the file is 0600" % (sid, fmt),
                os.stat(path).st_mode & 0o777 == 0o600)
        r.check("%s %s: its directory is 0700" % (sid, fmt),
                os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700)
        r.check("%s %s: bytes match the file" % (sid, fmt),
                got.get("bytes") == os.path.getsize(path))
        r.check("%s %s: the name is helper-minted, not caller-supplied" % (sid, fmt),
                os.path.basename(path).startswith(sid + "-")
                and os.path.basename(path).endswith("." + fmt))
        r.check("%s %s: the CONTENT is not in the response" % (sid, fmt),
                SENTINEL not in json.dumps(got))
        with open(path, "rb") as fh:
            blob = fh.read()
        r.check("%s %s: the export really contains the safe" % (sid, fmt),
                SENTINEL.encode() in blob, len(blob))

    # I21's "always audited by name", and I15's "never a value".
    tail, _rc, _e = env.run("audit-tail", argv=["--n", "200"])
    lines = tail.get("entries") or []
    exports = [ln for ln in lines if ln.get("verb") == "export"]
    r.check("every export attempt is audited", len(exports) >= 9, len(exports))
    r.check("a successful export is audited BY FILE NAME",
            all(ln.get("artifact") for ln in exports
                if ln.get("outcome") == "ok"),
            [ln.get("artifact") for ln in exports])
    r.check("a refusal is audited with artifact null",
            all(ln.get("artifact") is None for ln in exports
                if ln.get("outcome") != "ok"))
    r.check("no exported secret reached the audit log",
            SENTINEL not in json.dumps(lines) and PW not in json.dumps(lines))
    return exp_dir


# ------------------------------------------------- strength / breach -------

def strength_and_breach(env, r):
    r.section("strength — never echoes the candidate")
    schema, _rc, _e = env.run("schema")

    def values(enum):
        """An enum entry is `{value,label,…}`; a bare string is also accepted
        so this does not become the reason a schema tidy-up breaks the tests."""
        return {o["value"] if isinstance(o, dict) else o
                for o in schema["enums"][enum]}

    cats = values("strength_category")
    weak_ids = values("strength_weakness")
    # THE FIXED PROSE a strength answer may carry: everything the SCHEMA
    # publishes for this verb (every weakness label and help string), plus a
    # whole answer for a candidate that shares nothing with the ones under
    # test. Anything below that quotes a candidate and is NOT in this set is a
    # genuine echo.
    #
    # The set is needed because "the candidate never appears anywhere" is not
    # actually the property wanted, and asserting it fails honestly the first
    # time someone tests the candidate `password` — which is a substring of the
    # permanent label "contains a common word or a known-bad password". The
    # schema is the right source for the exemption list precisely because it is
    # the list of strings the helper promised in advance, before it saw any
    # candidate.
    boiler, _rc, _e = env.run("strength", {"value": "Zq7#mW2!xR9tLp4v"})
    FIXED = _strings(boiler) | _strings(schema["enums"]["strength_weakness"]) \
        | _strings(schema["enums"]["strength_category"])

    cases = [("hunter2", "very-weak"), ("password", "very-weak"),
             ("aaaaaaaaaaaaaaaaaaaaaaaa", None),
             ("8Kq#vT2m!Zr4wLx9Pn6B", "excellent"), ("a" * 4096, "very-weak")]
    seen = []
    for value, expect in cases:
        out, _rc, _e = env.run("strength", {"value": value})
        seen.append(out)
        r.check("strength(%r) returns no value key" % value[:14],
                "value" not in out, sorted(out))
        echoes = [s for s in _strings(out) if value in s and s not in FIXED]
        r.check("strength(%r) never quotes the candidate" % value[:14],
                not echoes, echoes)
        r.check("strength(%r) category is from the published enum" % value[:14],
                out.get("category") in cats, out.get("category"))
        r.check("strength(%r) weakness ids are published" % value[:14],
                all(w["id"] in weak_ids for w in out.get("weaknesses") or []))
        if expect:
            r.check("strength(%r) is %s" % (value[:14], expect),
                    out.get("category") == expect, out.get("category"))
    long_run = [o for (v, _), o in zip(cases, seen) if v == "a" * 4096][0]
    r.check("4096 repeated characters is NOT called strong",
            long_run["effective_bits"] < 30, long_run["effective_bits"])
    r.check("...and the naive figure is still reported for comparison",
            long_run["entropy_bits"] > 1000, long_run["entropy_bits"])

    tail, _rc, _e = env.run("audit-tail", argv=["--n", "200"])
    blob = json.dumps(tail)
    r.check("no strength candidate reached the audit log",
            all(v not in blob for v, _ in cases))
    r.check("but the strength verb IS audited",
            any(ln.get("verb") == "strength"
                for ln in tail.get("entries") or []))

    r.section("breach-check — offline, and it says so on every branch")
    out, _rc, _e = env.run("breach-check",
                           {"safe": "lab-kdbx41", "value": "hunter2"})
    r.check("with no corpus: available false",
            out.get("available") is False, out)
    r.check("with no corpus: still says network none / offline only",
            out.get("network") == "none" and out.get("offline_only") is True)
    r.check("with no corpus: the reason rules out an online fallback",
            "no online fallback" in (out.get("reason") or ""),
            out.get("reason"))

    corpus = build_corpus(os.path.join(env.root, "corpus.txt"))
    add_safe(env, "brch", "lab-kdbx41-aes256-argon2id.kdbx",
             access="user", breach_corpus=corpus)
    hit, _rc, _e = env.run("breach-check", {"safe": "brch", "value": "hunter2"})
    r.check("a corpus hit is found", hit.get("found") is True, hit)
    r.check("...with the occurrence count from the file",
            hit.get("occurrences") == 41 or hit.get("count") == 41, hit)
    r.check("...and still says network none", hit.get("network") == "none")
    miss, _rc, _e = env.run("breach-check",
                            {"safe": "brch", "value": CANARY})
    r.check("a miss is found:false", miss.get("found") is False, miss)
    r.check("at most FIVE hex characters are echoed",
            len(hit.get("prefix5") or "") <= 5
            and len(miss.get("prefix5") or "") <= 5)
    full = hashlib.sha1(b"hunter2").hexdigest().upper()
    r.check("the full SHA-1 is never echoed", full not in json.dumps(hit))
    pref, _rc, _e = env.run("breach-check",
                            {"safe": "brch", "sha1_prefix": full[:5]})
    r.check("a 5-char prefix answers found:null, never false",
            pref.get("found") is None, pref)
    r.check("...with an exact count for the prefix",
            isinstance(pref.get("count"), int) and pref["count"] >= 1, pref)

    # THE CLAIM THAT MATTERS: no socket is opened. Run it in a network
    # namespace whose only interface is a DOWN loopback, so a network call
    # cannot succeed even by accident. `--map-current-user`, NOT `-r`: the
    # safe is user-class and the helper correctly refuses to open one as a
    # root helper, so mapping to uid 0 would prove the class gate rather than
    # the absence of a socket.
    p = subprocess.run(
        ["unshare", "--user", "--map-current-user", "-n", "--",
         sys.executable, HELPER, "breach-check"],
        cwd=SRC, env=env.env,
        input=json.dumps({"safe": "brch", "value": "hunter2"}),
        text=True, capture_output=True, timeout=120)
    try:
        iso = json.loads(p.stdout)
    except Exception:
        iso = {"_unparseable": (p.stdout or p.stderr)[:200]}
    r.check("breach-check answers correctly with NO network at all",
            iso.get("found") is True, iso)
    # ...and the control: the namespace really is deaf. Without this, a green
    # result above could just mean unshare did nothing.
    probe = subprocess.run(
        ["unshare", "--user", "--map-current-user", "-n", "--",
         sys.executable, "-c", NET_PROBE],
        capture_output=True, text=True, timeout=60)
    r.check("...and that namespace genuinely cannot reach the network",
            probe.returncode == 7, probe.returncode)

    blob = json.dumps(env.run("audit-tail", argv=["--n", "200"])[0])
    r.check("no breach candidate reached the audit log",
            "hunter2" not in blob and CANARY not in blob)


def main():
    env = Env().build()
    r = Report("verbs added after the first build")
    try:
        history_both(env, r)
        reveal_vocabulary(env, r)
        attachments_both(env, r)
        save_as_and_backups(env, r)
        export_gate(env, r)
        strength_and_breach(env, r)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
