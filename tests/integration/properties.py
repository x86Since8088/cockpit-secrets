#!/usr/bin/env python3
"""The load-bearing properties, measured rather than asserted.

  I10  /proc/<pid>/cmdline and /proc/<pid>/environ of a LIVE helper holding an
       unlocked safe carry no passphrase — with a control proving the reader
       works, so a green result cannot come from a broken test.
  I12  SIGKILL between the temp write and the rename leaves the original safe
       byte-identical, on both formats.
  I13  a stale lock file is refused by default and overridable only explicitly.
  I16  the wrong-passphrase path is not measurably faster than the right one,
       and every failure meets the constant-time floor.

The I12 test needs to stop the process at one exact instruction. It does that
with a `sitecustomize.py` on PYTHONPATH (imported by `site` before any project
code runs) that replaces `os.replace` with a SIGKILL. Nothing in the project
tree is modified or conditionally compiled to make the test possible.
"""
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, HELPER, SRC, PW      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DECOY = "DECOY-ENV-VALUE-CANARY-4417"


# ---------------------------------------------------------------- I10 ------

def proc_leak(env, r):
    r.section("I10 — no secret on argv or in the environment")
    e = dict(env.env)
    e["CS_DECOY"] = DECOY
    p = subprocess.Popen([sys.executable, HELPER, "open"], cwd=SRC, env=e,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        p.stdout.readline()                                   # banner
        p.stdin.write(json.dumps({"verb": "unlock", "safe": "lab-kdbx41",
                                  "password": PW}) + "\n")
        p.stdin.flush()
        reply = json.loads(p.stdout.readline())
        if not r.check("the helper under test is live and holds an unlocked "
                       "safe", "handle" in reply, reply):
            return

        def read(name):
            try:
                with open("/proc/%d/%s" % (p.pid, name), "rb") as fh:
                    return fh.read().decode("utf-8", "replace"), None
            except OSError as exc:
                return None, "%s (errno %d)" % (exc.strerror, exc.errno)

        frags = [PW, PW[:12], PW[-12:], "fixture-pass", "do-not-reuse"]

        cmdline, err = read("cmdline")
        r.check("cmdline is readable (so this check is not vacuous)",
                cmdline is not None, err)
        if cmdline is not None:
            argv = [x for x in cmdline.split("\0") if x]
            r.check("argv is [python, helper, verb] and nothing after the verb",
                    len(argv) == 3 and argv[2] == "open", argv)
            r.check("no fragment of the passphrase is on argv",
                    not any(f in cmdline for f in frags))

        environ, err = read("environ")
        if environ is None:
            # PR_SET_DUMPABLE=0 reparents /proc/<pid>/* to root, so even the
            # same uid cannot read it. Stronger than "the value is absent".
            r.check("environ is UNREADABLE even to the helper's own uid "
                    "(PR_SET_DUMPABLE=0, I14)", True, err)
        else:
            r.check("no fragment of the passphrase is in the environment",
                    not any(f in environ for f in frags))
    finally:
        try:
            p.stdin.close()
        except Exception:
            pass
        p.wait(timeout=30)

    # the control: an ordinary child of ours IS readable, with the decoy in it
    q = subprocess.Popen(["sleep", "5"], env=e)
    try:
        time.sleep(0.3)
        with open("/proc/%d/environ" % q.pid, "rb") as fh:
            seen = DECOY in fh.read().decode("utf-8", "replace")
        r.check("CONTROL: a plain child's environ IS readable and does carry "
                "the decoy", seen)
    finally:
        q.kill()
        q.wait(timeout=10)


# ---------------------------------------------------------------- I12 ------

def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def atomic_kill(env, r):
    r.section("I12 — SIGKILL between the temp write and the rename")
    shim = os.path.join(env.root, "shim")
    os.makedirs(shim, exist_ok=True)
    shutil.copy(os.path.join(HERE, "killshim_sitecustomize.py"),
                os.path.join(shim, "sitecustomize.py"))

    for safe, fixture in (("lab-kdbx41", "lab-kdbx41-aes256-argon2id.kdbx"),
                          ("lab-pws3", "lab-pws3.psafe3")):
        env.reset_safes()
        path = os.path.join(env.safes, fixture)
        before, size = sha(path), os.path.getsize(path)
        witness = os.path.join(env.root, "witness.txt")
        if os.path.exists(witness):
            os.unlink(witness)

        out, rc, _err = None, None, None
        p = subprocess.run(
            [sys.executable, HELPER, "add"], cwd=SRC,
            env=dict(env.env, PYTHONPATH=shim, CS_KILL_AT_REPLACE="1",
                     CS_KILL_WITNESS=witness),
            input=json.dumps({"safe": safe, "password": PW, "group": None,
                              "autosave": True,
                              "entry": {"title": "NeverLands",
                                        "password": "never-lands"}}),
            text=True, capture_output=True, timeout=300)
        rc = p.returncode

        if not r.check("%s: the helper was killed AT os.replace" % safe,
                       rc == -9, "rc=%s stdout=%s" % (rc, p.stdout[:120])):
            continue
        if r.check("%s: ...with the temp file already written and fsynced"
                   % safe, os.path.exists(witness)):
            src, dst, nbytes = open(witness).read().split("\n")[:3]
            r.check("%s: the rename that never happened targeted the safe"
                    % safe, dst == path,
                    "%s bytes were staged in %s"
                    % (nbytes, os.path.basename(src)))
        r.check("%s: the original safe is BYTE-IDENTICAL" % safe,
                sha(path) == before,
                "%d bytes, sha %s" % (size, before[:24]))

        debris = sorted(n for n in os.listdir(env.safes)
                        if n.startswith(fixture) and n != fixture
                        and (".tmp-" in n or n.endswith(".lock")))
        # A SIGKILL cannot run a cleanup handler. Stating what it leaves is the
        # honest result; the property under test is that the ORIGINAL is intact.
        print("       (debris a SIGKILL could not unlink: %s)"
              % (debris or "none"))
        for n in debris:
            os.unlink(os.path.join(env.safes, n))
        again, _rc, _e = env.run("unlock", {"safe": safe, "password": PW})
        r.check("%s: the safe still opens, with the killed write absent" % safe,
                "handle" in again, json.dumps(again)[:140])


# ---------------------------------------------------------------- I13 ------

def stale_lock(env, r):
    r.section("I13 — a stale lock file is refused, and overridable only "
              "explicitly")
    for safe, lock in (("lab-kdbx41",
                        "lab-kdbx41-aes256-argon2id.kdbx.lock"),
                       ("lab-pws3", "lab-pws3.plk")):
        env.reset_safes()
        lp = os.path.join(env.safes, lock)
        with open(lp, "w") as fh:
            fh.write("someone-else\n99999\n")
        os.chmod(lp, 0o600)
        req = {"safe": safe, "password": PW, "group": None, "autosave": True,
               "entry": {"title": "LockTest", "password": "x"}}
        out, _rc, _e = env.run("add", req)
        r.check("%s: a foreign lock is a conflict NAMING the holder" % safe,
                out.get("error") == "conflict" and "someone-else" in
                (out.get("detail") or ""), out)
        out, _rc, _e = env.run("add", dict(req, override_stale=True))
        r.check("%s: an explicit override takes it and the save completes"
                % safe, out.get("saved") is True, json.dumps(out)[:160])
        r.check("%s: ...and the override released its own lock afterwards"
                % safe, not os.path.exists(lp))


# ---------------------------------------------------------------- I16 ------

def fail_timing(env, r, n=5):
    r.section("I16 — the wrong passphrase is not faster than the right one")
    wrong = PW[:-1] + "X"            # same length, one byte different

    def once(safe, password):
        env.clear_lockout()
        t0 = time.monotonic()
        out, _rc, _e = env.run("unlock", {"safe": safe, "password": password})
        return time.monotonic() - t0, out

    for safe in ("lab-kdbx41", "lab-pws3"):
        good, bad = [], []
        for _ in range(n):
            dt, out = once(safe, PW)
            if "handle" not in out:
                r.check("%s: the right passphrase opens it" % safe, False, out)
                return
            good.append(dt)
            dt, out = once(safe, wrong)
            if out.get("error") != "bad-credential":
                r.check("%s: the wrong passphrase is bad-credential" % safe,
                        False, out)
                return
            bad.append(dt)
        gm, bm = statistics.median(good), statistics.median(bad)
        r.check("%s: wrong (%.3fs) is NOT faster than right (%.3fs)"
                % (safe, bm, gm), bm >= gm, "delta %+.3fs" % (bm - gm))
        r.check("%s: every failure met the %.2fs floor (min %.3fs)"
                % (safe, 0.75, min(bad)), min(bad) >= 0.75)

    # A file that is not a safe at all must be floored too, or "not a safe" is
    # distinguishable from "wrong passphrase" with a stopwatch.
    junk = os.path.join(env.safes, "junk.kdbx")
    with open(junk, "wb") as fh:
        fh.write(b"this is not a kdbx file" * 40)
    os.chmod(junk, 0o600)
    reg = os.path.join(env.safes_d, "99-junk.json")
    with open(reg, "w") as fh:
        json.dump({"id": "lab-junk", "label": "junk", "format": "kdbx",
                   "path": junk, "access": "user", "owner": "%u",
                   "password_required": True}, fh)
    os.chmod(reg, 0o644)
    try:
        dt, out = once("lab-junk", PW)
        r.check("a structurally broken file is floored like every other "
                "failure (%.3fs)" % dt, dt >= 0.75, out)
    finally:
        os.unlink(reg)
        os.unlink(junk)
        env.clear_lockout()


def main():
    env = Env().build()
    r = Report("load-bearing properties")
    try:
        proc_leak(env, r)
        atomic_kill(env, r)
        stale_lock(env, r)
        fail_timing(env, r)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
