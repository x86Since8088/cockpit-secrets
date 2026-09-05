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
        # EVERY class-gated verb, taken from the schema rather than a list
        # written here — so a verb added later is covered the day it appears
        # instead of the day somebody remembers this file. I3's whole point is
        # that the check is server-side and applies to the WHOLE surface; a
        # gate proved on three verbs out of twenty is a gate with seventeen
        # holes in it.
        schema, _rc, _e = env.run("schema")
        # `save` is excluded and it is the only exclusion: it has no
        # single-shot form at all — it takes a handle from an open session and
        # nothing else — so there is no request that reaches its gate from
        # here. Its gate is `unlock`'s: an admin safe hands a non-root helper
        # no handle, so there is no path to `save` to defend. That is checked
        # one line below rather than assumed.
        gated = [v["id"] for v in schema["verbs"]
                 if v.get("access") == "class"
                 and v.get("needs") in ("safe", "handle")
                 and v["id"] != "save"]
        r.check("the schema declares a class-gated verb surface to check",
                len(gated) >= 10, gated)
        # EVERY REQUEST BELOW IS BUILT FROM THE VERB'S OWN DECLARED REQUEST.
        #
        # It used to send `password` to all of them, which was harmless while
        # the helper ignored a field it had no use for. It is not harmless any
        # more: the dispatcher now REFUSES a credential sent to a verb whose
        # schema declares none (I48, C5's ordering enforced server-side), so a
        # blanket `password` made seven of these answer `invalid` — argument
        # validation — instead of reaching the class gate at all. That would
        # have been the test quietly stopping to test anything.
        #
        # Filtering to the declared fields is the stronger version of the same
        # check, not a weaker one: the verbs are now called the way a
        # conforming client calls them, and the assertion is unchanged.
        declared = {v["id"]: set(v.get("request") or []) for v in schema["verbs"]}
        for verb in sorted(gated):
            # `autosave` is what makes a single-shot MUTATION a well-formed
            # request: without it the helper answers `invalid` before it looks
            # at the safe at all, and the gate is never reached. A refusal that
            # comes from argument validation is not evidence about access
            # control, so every request here is built to be well-formed and to
            # fail for exactly one reason.
            req = {"safe": "lab-admin", "password": PW, "autosave": True}
            # A few verbs need one more field for the same reason.
            req.update({"reveal": {"uuid": "x", "field": "password"},
                        "totp": {"uuid": "x"},
                        "attach-get": {"uuid": "x", "name": "n"},
                        "attach-add": {"uuid": "x", "name": "n",
                                       "data_b64": "eA=="},
                        "attach-rm": {"uuid": "x", "name": "n"},
                        "history": {"uuid": "x"},
                        "history-restore": {"uuid": "x", "index": 0},
                        "add": {"entry": {"title": "t"}},
                        "edit": {"uuid": "x", "changes": {"username": "u"}},
                        "move": {"uuid": "x", "group": None},
                        "rm": {"uuid": "x"},
                        "group-add": {"name": "g"},
                        "group-rm": {"uuid": "x"},
                        "group-mv": {"uuid": "x", "parent": None},
                        "save-as": {"name": "copy.out"},
                        "restore-backup": {"name": "nope"},
                        "export": {"fmt": "csv",
                                   "confirm": "export-plaintext:lab-admin"},
                        "breach-check": {"value": "x"},
                        }.get(verb, {}))
            req = {k: v for k, v in req.items() if k in declared[verb]}
            r.check("  %s's request is buildable from its own schema" % verb,
                    "safe" in req or "handle" in req, sorted(req))
            out, rc, _e = env.run(verb, req)
            r.check("an admin safe is access-denied to a non-root helper (%s)"
                    % verb,
                    out.get("error") == "access-denied" and rc != 0, out)

        # `save`'s gate, the only way it can be reached: no handle, no save.
        sess = Session(env)
        try:
            u = sess.call("unlock", safe="lab-admin", password=PW)
            r.check("a session cannot unlock an admin safe either",
                    u.get("error") == "access-denied", u)
            r.check("...so `save` has no handle to be reached with",
                    sess.call("save", handle=u.get("handle") or "x"
                              ).get("error") == "access-denied")
        finally:
            sess.close()

        # ...and the request-shape refusal that runs BEFORE the gate must not
        # be an oracle. `save` without a handle answers the same `invalid` for
        # a safe you own, a safe you may not touch, and a safe that does not
        # exist — so a caller who provokes it learns nothing about the
        # registry. If these three ever diverge, the cheapest verb in the
        # program becomes a way to enumerate safe ids.
        shapes = [env.run("save", {"safe": sid, "password": PW})[0]
                  for sid in ("lab-kdbx41", "lab-admin", "no-such-safe")]
        r.check("a pre-gate argument refusal is identical for a safe you own, "
                "one you may not, and one that does not exist",
                len({json.dumps(x, sort_keys=True) for x in shapes}) == 1,
                shapes)

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
