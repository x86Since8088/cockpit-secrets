#!/usr/bin/env python3
"""Cross-backend drift detector.

Runs every verb on BOTH formats and compares the response SHAPES — to each
other, and to what the `schema` verb declares. The two backends were written by
authors who never saw each other's code, against the same prose contract, so
this is where a key that quietly means two different things shows up.

Two divergences are legitimate and are asserted as such rather than ignored:
`reveal.resolved_field` appears only when the backend's own name for a field
differs from the requested one, and `group-add` returns a `uuid` on KDBX because
KeePass groups have one and PWS3 groups do not. Both are supersets of the
contract shape. Anything else that differs is drift.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, SENTINEL, PW      # noqa: E402

#: keys one backend may carry that the other need not — each with the reason.
ALLOWED_EXTRA = {
    ("reveal", "resolved_field"):
        "KDBX resolves 'password' to the KeePass field name 'Password'; PWS3's "
        "own name already IS 'password', so it has nothing extra to report.",
    ("group-add", "uuid"):
        "KeePass groups have a uuid; a PWS3 group IS its '.'-delimited path, so "
        "there is no second identifier to return.",
}

SHAPES = {}


def record(fmt, verb, out):
    SHAPES.setdefault(verb, {})[fmt] = sorted(out.keys())


def exercise(env, r, safe, fmt):
    r.section("%s (%s)" % (safe, fmt))
    env.reset_safes()
    s = Session(env)
    u = s.call("unlock", safe=safe, password=PW)
    record(fmt, "unlock", u)
    if not r.check("unlock", "handle" in u, u):
        s.close()
        return
    h = u["handle"]

    t = s.call("tree", handle=h)
    record(fmt, "tree", t)
    e = s.call("entries", handle=h, limit=200)
    record(fmt, "entries", e)
    r.check("entries carries no sentinel", SENTINEL not in json.dumps(e))

    router = next((x for x in e["entries"] if x["title"] == "Router"), None)
    if router:
        record(fmt, "reveal",
               s.call("reveal", handle=h, uuid=router["uuid"],
                      field="password"))
        bad = s.call("reveal", handle=h, uuid=router["uuid"], field="nope!!")
        r.check("a malformed field name is `invalid` on both backends",
                bad.get("error") == "invalid", bad)
        gone = s.call("reveal", handle=h, field="password",
                      uuid="00000000000000000000000000000000")
        r.check("an unknown uuid is `not-found` on both backends",
                gone.get("error") == "not-found", gone)
    otp = next((x for x in e["entries"] if x["has_totp"]), None)
    if otp:
        record(fmt, "totp", s.call("totp", handle=h, uuid=otp["uuid"]))

    root = t["groups"][0]["uuid"] if fmt == "kdbx" else ""
    record(fmt, "group-add",
           s.call("group-add", handle=h, parent=None, name="ConformGroup"))
    t2 = s.call("tree", handle=h)
    newg = next((g for g in t2["groups"] if g["name"] == "ConformGroup"), None)
    r.check("the new group is in the tree", newg is not None)

    a = s.call("add", handle=h, group=(newg or {}).get("uuid"),
               entry={"title": "ConformEntry", "username": "cu",
                      "password": "conform-pw"})
    record(fmt, "add", a)
    record(fmt, "edit",
           s.call("edit", handle=h, uuid=a["uuid"], changes={"username": "c2"}))
    record(fmt, "move", s.call("move", handle=h, uuid=a["uuid"], group=root))
    record(fmt, "group-mv",
           s.call("group-mv", handle=h, uuid=(newg or {}).get("uuid"),
                  parent=root or None))
    record(fmt, "rm", s.call("rm", handle=h, uuid=a["uuid"], permanent=True))
    record(fmt, "save", s.call("save", handle=h))
    record(fmt, "lock", s.call("lock", handle=h))
    _rest, _err, rc = s.close()
    r.check("the session exits 0", rc == 0, "rc=%d" % rc)


def main():
    env = Env().build()
    r = Report("cross-backend conformance")
    try:
        exercise(env, r, "lab-kdbx41", "kdbx")
        exercise(env, r, "lab-pws3", "psafe3")

        schema, _rc, _e = env.run("schema")
        by_id = {v["id"]: v for v in schema["verbs"]}

        r.section("the same verb answers the same shape on both backends")
        for verb in sorted(SHAPES):
            got = SHAPES[verb]
            if len(got) != 2:
                r.check("%s ran on both backends" % verb, False, list(got))
                continue
            a, b = set(got["kdbx"]), set(got["psafe3"])
            extra = {(verb, k) for k in (a ^ b)}
            unexplained = sorted(k for (_v, k) in extra
                                 if (verb, k) not in ALLOWED_EXTRA)
            r.check("%-11s %s" % (verb, "identical" if a == b
                                  else "differs only by %s"
                                  % sorted(k for (_v, k) in extra)),
                    not unexplained,
                    "unexplained: %s" % unexplained if unexplained else "")

        r.section("every key the schema declares is actually returned")
        for verb in sorted(SHAPES):
            declared = {k for k in by_id.get(verb, {}).get("response", {})
                        # a declaration may name an optional key explicitly
                        if "absent" not in str(
                            by_id[verb]["response"][k]).lower()}
            for fmt, keys in SHAPES[verb].items():
                missing = sorted(declared - set(keys))
                r.check("%-11s %-7s returns everything it declares"
                        % (verb, fmt), not missing, "missing %s" % missing)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
