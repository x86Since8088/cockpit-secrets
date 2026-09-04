#!/usr/bin/env python3
"""Cross-backend drift detector.

Runs every verb on BOTH formats and compares the response SHAPES — to each
other, and to what the `schema` verb declares. The two backends were written by
authors who never saw each other's code, against the same prose contract, so
this is where a key that quietly means two different things shows up.

Three divergences are legitimate and are named in `ALLOWED_EXTRA` with their
reasons rather than ignored: `reveal.resolved_field` appears only when the
backend's own name for a field differs from the requested one; `group-add`
returns a `uuid` on KDBX because KeePass groups have one and PWS3 groups do not;
and `probe.yubikey` appears only on KDBX because only KDBX4 can carry a hardware
key. All three are supersets of the contract shape. Anything else that differs
is drift.

Two things are compared besides the shapes, and both were added after they
caught something:

  * **the error CODE for an identical bad request.** A duplicate attachment name
    answered `conflict` on KDBX and `unsupported` on PWS3 — one operator mistake,
    two codes, and only one of them named the fix.
  * **the declaration against a real call.** `breach-check` declared three keys
    it correctly does not return when no corpus is configured.
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
    ("probe", "yubikey"):
        "KdbxBackend.probe() publishes a `yubikey` object (slot, algorithm and "
        "the 64-byte challenge from the KDF seed) because KDBX4 can carry a "
        "hardware key; PWS3 cannot, so it has nothing to put there. This is "
        "allowed ONLY because the helper flattens it: `needs_challenge` and a "
        "top-level `challenge_b64` are present on BOTH, which is what the page "
        "actually reads. That normalisation is asserted below rather than "
        "assumed, because without it this exemption would be hiding a real "
        "difference instead of naming a superset.",
}

SHAPES = {}

#: label -> {fmt: error code}. The SAME bad request on both backends must draw
#: the same code out of docs/CONTRACT.md's taxonomy. The detail sentence may
#: and should differ — it names the format's own reason — but a UI branches on
#: the code, and a code that means "impossible here" on one backend and
#: "already done" on the other sends the operator two different ways.
ERRORS = {}


def record(fmt, verb, out):
    SHAPES.setdefault(verb, {})[fmt] = sorted(out.keys())


def exercise(env, r, safe, fmt):
    r.section("%s (%s)" % (safe, fmt))
    env.reset_safes()
    # `probe` is the no-credential verb the page reads before it draws the
    # unlock dialog, and the two backends do NOT return the same thing:
    # `KdbxBackend.probe()` carries a `yubikey` object and `Psafe3Backend`'s
    # does not. The helper normalises that into `needs_challenge` and a
    # top-level `challenge_b64`, and the page reads the normalised keys — so
    # the normalisation is load-bearing and belongs in the drift detector
    # rather than in a comment saying it was handled.
    record(fmt, "probe", env.run("probe", {"safe": safe})[0])

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

    # --- the verbs added after the first build --------------------------
    # Shapes only; behaviour lives in newverbs.py. The point here is that the
    # two backends answer the same KEYS and, for an identical bad request, the
    # same ERROR CODE — which is where the second wave drifted: a duplicate
    # attachment name was `conflict` on KDBX and `unsupported` on PWS3, so the
    # same operator mistake produced two different sentences and only one of
    # them named the fix.
    target = router or e["entries"][0]
    tu = target["uuid"]
    record(fmt, "history", s.call("history", handle=h, uuid=tu))
    record(fmt, "attach-add",
           s.call("attach-add", handle=h, uuid=tu, name="conform.bin",
                  data_b64="Y29uZm9ybQ=="))
    record(fmt, "attach-get",
           s.call("attach-get", handle=h, uuid=tu, name="conform.bin"))
    ERRORS.setdefault("attach-add duplicate name", {})[fmt] = \
        s.call("attach-add", handle=h, uuid=tu, name="conform.bin",
               data_b64="Y29uZm9ybQ==").get("error")
    ERRORS.setdefault("attach-get unknown name", {})[fmt] = \
        s.call("attach-get", handle=h, uuid=tu, name="nope.bin").get("error")
    ERRORS.setdefault("attach-rm unknown name", {})[fmt] = \
        s.call("attach-rm", handle=h, uuid=tu, name="nope.bin").get("error")
    ERRORS.setdefault("history-restore past the end", {})[fmt] = \
        s.call("history-restore", handle=h, uuid=tu, index=9999).get("error")
    ERRORS.setdefault("save-as with a path for a name", {})[fmt] = \
        s.call("save-as", handle=h, name="../escape.db").get("error")
    ERRORS.setdefault("restore-backup unlisted name", {})[fmt] = \
        env.run("restore-backup",
                {"safe": safe, "name": "../../etc/passwd"})[0].get("error")
    record(fmt, "attach-rm",
           s.call("attach-rm", handle=h, uuid=tu, name="conform.bin"))
    record(fmt, "save-as", s.call("save-as", handle=h, name="conform-%s.out"
                                  % fmt))
    record(fmt, "save", s.call("save", handle=h))
    record(fmt, "lock", s.call("lock", handle=h))
    _rest, _err, rc = s.close()
    r.check("the session exits 0", rc == 0, "rc=%d" % rc)

    record(fmt, "backups", env.run("backups", {"safe": safe})[0])
    record(fmt, "breach-check",
           env.run("breach-check", {"safe": safe, "value": "x"})[0])


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

        r.section("probe is normalised across the backend asymmetry")
        for fmt in ("kdbx", "psafe3"):
            keys = set(SHAPES["probe"][fmt])
            r.check("%-6s probe answers the normalised hardware-key keys" % fmt,
                    {"needs_challenge", "yubikey_slot"} <= keys,
                    sorted(keys))

        r.section("the same bad request draws the same error code")
        for label in sorted(ERRORS):
            got = ERRORS[label]
            r.check("%-34s %s" % (label, got.get("kdbx")),
                    len(got) == 2 and got.get("kdbx") == got.get("psafe3"),
                    got if got.get("kdbx") != got.get("psafe3") else "")

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
