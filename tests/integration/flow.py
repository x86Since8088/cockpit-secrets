#!/usr/bin/env python3
"""The whole contract flow against the real helper and real fixtures, for BOTH
formats: probe -> unlock -> tree -> entries -> reveal -> totp -> add -> edit ->
save -> lock, plus an `open` session doing several mutations under ONE unlock,
plus the three distinct read-only refusals.

This is the script that answers "does it actually run". Everything it asserts
crosses a module boundary that no single agent owned.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, SENTINEL, PW      # noqa: E402


def flow(env, r, safe, fmt):
    r.section("%s (%s)" % (safe, fmt))
    env.reset_safes()

    probe, rc, _ = env.run("probe", {"safe": safe})
    r.check("probe names the format", probe.get("format") == fmt, probe)
    r.check("probe reports a KDF and an iteration count",
            bool(probe.get("kdf")) and isinstance(probe.get("iterations"), int),
            "%s/%s" % (probe.get("kdf"), probe.get("iterations")))

    s = Session(env)
    r.check("the banner is tagged and carries no handle",
            s.banner.get("frame") == "banner" and "handle" not in s.banner,
            json.dumps(s.banner)[:120])

    u = s.call("unlock", safe=safe, password=PW)
    if not r.check("unlock returns a handle", "handle" in u, u):
        s.close()
        return
    h = u["handle"]

    t = s.call("tree", handle=h)
    r.check("tree rows carry exactly {uuid,name,parent,count}",
            all(sorted(g) == ["count", "name", "parent", "uuid"]
                for g in t.get("groups", [])),
            sorted(t["groups"][0]) if t.get("groups") else None)

    e = s.call("entries", handle=h, limit=200)
    r.check("entries returns rows", e.get("total", 0) > 0, e.get("total"))
    r.check("entries carries NO sentinel value (contract invariant 1)",
            SENTINEL not in json.dumps(e))
    r.check("entries[].modified is RFC 3339 UTC on both backends",
            all((not row["modified"]) or row["modified"].endswith("Z")
                for row in e["entries"]),
            sorted({row["modified"] for row in e["entries"]}))

    router = next((x for x in e["entries"] if x["title"] == "Router"), None)
    if r.check("the sentinel entry is listed", router is not None):
        v = s.call("reveal", handle=h, uuid=router["uuid"], field="password")
        r.check("reveal is the only door, and it opens", v.get("value") == SENTINEL)
        r.check("reveal echoes the field that was ASKED for",
                v.get("field") == "password", v.get("field"))

    otp = next((x for x in e["entries"] if x["has_totp"]), None)
    if r.check("a TOTP entry is listed", otp is not None):
        c = s.call("totp", handle=h, uuid=otp["uuid"])
        r.check("totp is a 6-digit code with a countdown",
                isinstance(c.get("code"), str) and c["code"].isdigit()
                and isinstance(c.get("seconds_remaining"), int), c)

    # several mutations under ONE unlock, then one save
    root = t["groups"][0]["uuid"] if fmt == "kdbx" else ""
    a1 = s.call("add", handle=h, group=root,
                entry={"title": "FlowOne", "username": "u1",
                       "password": "flow-pw-1"})
    a2 = s.call("add", handle=h, group=root,
                entry={"title": "FlowTwo", "password": "flow-pw-2"})
    r.check("two adds under one unlock", "uuid" in a1 and "uuid" in a2,
            "%s %s" % (a1.get("uuid"), a2.get("uuid")))
    r.check("a mutation is in memory until save (saved:false)",
            a1.get("saved") is False and a2.get("saved") is False)
    ed = s.call("edit", handle=h, uuid=a1["uuid"], changes={"username": "u1b"})
    r.check("edit reports field NAMES, never values",
            ed.get("changed") == ["username"] and "u1b" not in json.dumps(ed), ed)
    mv = s.call("move", handle=h, uuid=a2["uuid"], group=root)
    r.check("move into the root group is accepted on both formats",
            mv.get("ok") is True, mv)

    sv = s.call("save", handle=h)
    r.check("save is atomic and reports its backup",
            sv.get("ok") is True and sv.get("conflict") is False
            and sv.get("bytes", 0) > 0, sv)
    r.check("the backup landed in the ring",
            bool(sv.get("backup")) and os.path.exists(sv["backup"]),
            sv.get("backup"))

    after = s.call("entries", handle=h, limit=300)
    titles = [x["title"] for x in after["entries"]]
    r.check("both adds survived the save",
            "FlowOne" in titles and "FlowTwo" in titles)

    lk = s.call("lock", handle=h)
    r.check("lock is acknowledged", lk.get("ok") is True, lk)
    tail = s.call("lock", handle=h)       # the session ends with the last handle
    r.check("dropping the last handle closes the session",
            tail.get("frame") == "closed" and tail.get("reason") == "locked", tail)
    _rest, _err, rc = s.close()
    r.check("the helper exits 0", rc == 0, "rc=%d" % rc)

    # a fresh process must see what the save wrote — the proof it reached disk
    again, _rc, _err = env.run("unlock", {"safe": safe, "password": PW})
    r.check("a NEW helper process reopens the saved file",
            "handle" in again, json.dumps(again)[:160])
    r.check("and counts the two new entries",
            again.get("entries_total") == e["total"] + 2,
            "%s vs %s+2" % (again.get("entries_total"), e["total"]))


def main():
    env = Env().build()
    r = Report("integration flow")
    try:
        flow(env, r, "lab-kdbx41", "kdbx")
        flow(env, r, "lab-pws3", "psafe3")

        r.section("the three distinct read-only causes")
        env.reset_safes()
        mut = {"password": PW, "group": None, "autosave": True,
               "entry": {"title": "x", "password": "y"}}
        out, _rc, _e = env.run("add", dict(mut, safe="lab-ro"))
        r.check("registry mode:'ro' is access-denied",
                out.get("error") == "access-denied", out)
        out, _rc, _e = env.run("add", dict(mut, safe="lab-kdbx31"))
        r.check("KDBX 3.x is unsupported, not access-denied (I20)",
                out.get("error") == "unsupported", out)
        out, _rc, _e = env.run("unlock", {"safe": "lab-kdbx31", "password": PW})
        r.check("...and KDBX 3.x still READS, with the I20 banner",
                "handle" in out and out.get("warnings"),
                (out.get("warnings") or [""])[0][:60])

        r.section("credentials that are not a passphrase")
        out, _rc, _e = env.run("unlock", {"safe": "lab-kdbx-kf"})
        r.check("a key-file-only safe opens with NO password",
                "handle" in out, json.dumps(out)[:120])
        out, _rc, _e = env.run("unlock", {"safe": "lab-kdbx-pwkf",
                                          "password": PW})
        r.check("a password+key-file safe opens with both",
                "handle" in out, json.dumps(out)[:120])

        r.section("access class, enforced in the helper (I1, I2, I3)")
        for verb in ("probe", "unlock", "entries"):
            out, rc, _e = env.run(verb, {"safe": "lab-admin", "password": PW})
            r.check("an admin safe is access-denied to a non-root helper (%s)"
                    % verb,
                    out.get("error") == "access-denied" and rc != 0, out)
        out, _rc, _e = env.run("probe", {"safe": "no-such-safe"})
        r.check("an unregistered id is not-found",
                out.get("error") == "not-found", out)
        out, _rc, _e = env.run("probe", {"safe": "../../etc/shadow"})
        r.check("a traversal-shaped id is refused by SHAPE, before it is a path",
                out.get("error") == "invalid", out)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
