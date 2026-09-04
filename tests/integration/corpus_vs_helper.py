#!/usr/bin/env python3
"""Drive the WHOLE malformed corpus through the REAL helper.

This is the check the corpus was built for and that nothing else performs.
`tests/corpus/gen_corpus.py --check` re-runs the corpus against the Go oracle
and keepassxc-cli — foreign implementations, which is what makes the expected
codes credible — but it never touches the code under test. The backend authors
tested hostile input of their own devising. Neither exercise puts the committed
corpus in front of `secrets-admin`.

Three assertions per case, and the second one is the interesting one:

  * the taxonomy code matches the sidecar's `error` / `error_acceptable`;
  * the wall clock fits `max_seconds` — which is precisely what separates
    "clamped the KDF parameters BEFORE deriving" from "clamped them after",
    and several cases are meaningful only because of it;
  * nothing in `must_not_leak` appears in stdout, stderr OR the audit log.

Plus one the sidecars do not state: no case may answer `internal`. `internal`
means "we do not know what went wrong", and for a file the caller handed us we
always do — it is either malformed (`invalid`) or it failed a MAC
(`bad-credential`).

Takes about a minute: most of it is the I16 constant-time floor, 0.9 s per
failing case, which is the point.
"""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Report, HELPER, SRC, CORPUS, FIXTURES     # noqa: E402


def register(env, case, path):
    """One registry entry, replaced per case, always mode:'ro' — the corpus is
    about opening files, never about writing them."""
    entry = {"id": "corpus", "label": case["file"], "format": case["format"],
             "path": path, "access": "user", "owner": "%u", "mode": "ro",
             "password_required": bool(case.get("password"))}
    if case.get("keyfile"):
        name = os.path.basename(case["keyfile"])
        kf = os.path.join(env.safes, name)
        if not os.path.exists(kf):
            shutil.copy(os.path.join(FIXTURES, name), kf)
            os.chmod(kf, 0o600)
        entry["keyfile"] = kf
    reg = os.path.join(env.safes_d, "00-corpus.json")
    with open(reg, "w") as fh:
        json.dump(entry, fh)
    os.chmod(reg, 0o644)


def main():
    index_path = os.path.join(CORPUS, "index.json")
    if not os.path.exists(index_path):
        print("no corpus built; run tests/corpus/gen_corpus.py --build "
              "(about 3.5 s) first")
        return 0
    index = json.load(open(index_path))
    global_leak = index.get("must_not_leak", [])

    env = Env()
    env.build()
    # The corpus wants ONE registry entry, rewritten per case, not the standard
    # fixture set — so clear it out and re-assert the count each time.
    for name in os.listdir(env.safes_d):
        os.unlink(os.path.join(env.safes_d, name))

    r = Report("corpus vs the real helper (%d cases)" % len(index["cases"]))
    audit = os.path.join(env.var, "log", "audit.log")
    rows = []
    try:
        for case in index["cases"]:
            src = os.path.join(CORPUS, case["file"])
            if not os.path.exists(src):
                r.check("%s: corpus file present" % case["file"], False)
                continue
            dst = os.path.join(env.safes, case["file"])
            shutil.copy(src, dst)
            os.chmod(dst, 0o600)
            register(env, case, dst)
            env.assert_loaded(1)       # a setup failure must never look like a
            env.clear_lockout()        # taxonomy disagreement

            req = {"safe": "corpus"}
            if case.get("password"):
                req["password"] = case["password"]
            budget = float(case.get("max_seconds") or 15.0)
            t0 = time.monotonic()
            try:
                p = subprocess.run(
                    [sys.executable, HELPER, "unlock"], cwd=SRC, env=env.env,
                    input=json.dumps(req), text=True, capture_output=True,
                    timeout=budget + 45)
                dt = time.monotonic() - t0
                out, err = p.stdout, p.stderr
            except subprocess.TimeoutExpired:
                dt = time.monotonic() - t0
                out, err = "", ""

            try:
                obj = json.loads(out)
            except Exception:
                obj = None
            got = obj.get("error") if isinstance(obj, dict) else "<not JSON>"
            if isinstance(obj, dict) and "handle" in obj:
                got = None                          # it opened, legitimately

            accept = set(case.get("error_acceptable") or [])
            if case.get("error") is not None:
                accept.add(case["error"])
            ok_code = (got in accept) if accept else (got is None)

            audit_text = (open(audit, errors="replace").read()
                          if os.path.exists(audit) else "")
            leaked = [n for n in
                      list(case.get("must_not_leak") or []) + global_leak
                      if n and (n in out or n in err or n in audit_text)]

            rows.append((case["file"], case.get("error"), got, dt, budget))
            label = "%-38s %-14s -> %-14s %5.2fs/%.1fs" % (
                case["file"], case.get("error") or "(open)",
                got or "(open)", dt, budget)
            r.check(label, ok_code and dt <= budget and not leaked
                    and got != "internal" and obj is not None,
                    ("code %r not in %s; " % (got, sorted(accept))
                     if not ok_code else "")
                    + ("over budget; " if dt > budget else "")
                    + ("LEAKED %s; " % leaked if leaked else "")
                    + ("fell through to internal; " if got == "internal" else "")
                    + ("stdout was not one JSON object" if obj is None else ""))
            os.unlink(dst)
    finally:
        env.destroy()

    slow = max(rows, key=lambda x: x[3]) if rows else None
    if slow:
        print("\nslowest refusal: %s at %.2fs (budget %.1fs)"
              % (slow[0], slow[3], slow[4]))
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
