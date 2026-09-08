#!/usr/bin/env python3
"""The unlock agent, end to end: the REAL helper against the REAL daemon (I18).

`agent/secrets_agent.py --selfcheck` proves the daemon's own rules and the
helper has its own client, but until this script existed the two had never
spoken to each other — they were written in parallel against the same prose and
did not agree about `put`, about `drop`, or about the token alphabet. So the
assertions here are all about the SEAM.

Two halves, and the first one matters more:

  * **AGENT OFF, WHICH IS THE DEFAULT.** No socket is created, `unlock` gains
    no agent key, and nothing survives the helper process. This is the state
    every safe on this host is in unless somebody deliberately changed it, and
    it is the state non-negotiable 9 depends on.
  * **AGENT ON.** unlock -> the daemon takes a TICKET -> a SECOND helper
    process can see it (which is what makes an unlock visible after a page
    reload) -> `lock` with a bare safe id revokes it across processes ->
    the idle deadline expires it on its own.

What the agent holds is a ticket, not key material: see docs/CONTRACT.md,
"What the agent holds". The reattach proved below is therefore a ticket lookup
and NOT a second process opening a safe without a prompt — that is the point,
not a shortcoming, and there is an explicit check that no material crosses.
"""
import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, HELPER, SRC, PW      # noqa: E402

AGENT = os.path.join(SRC, "agent", "secrets_agent.py")


class Daemon:
    """The real agent, self-bound in a private run directory.

    `XDG_RUNTIME_DIR` is redirected at both processes so the helper's
    `agent_socket_path()` lands on this daemon and never on a real one that
    might be running for this user — a test that could be answered by somebody
    else's agent is not a test.
    """

    def __init__(self, run_root, idle=300, lifetime=3600):
        self.run_root = run_root
        self.dir = os.path.join(run_root, "cockpit-secrets")
        self.sock = os.path.join(self.dir, "agent.sock")
        self.p = subprocess.Popen(
            [sys.executable, AGENT, "--run-dir", self.dir,
             "--idle-seconds", str(idle), "--max-seconds", str(lifetime),
             # logind is polled by shelling out to `loginctl`; a test must not
             # depend on whether the developer's screen happens to be locked.
             "--no-session-watch", "--session-poll-seconds", "1"],
            cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if os.path.exists(self.sock):
                return True
            if self.p.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    def ask(self, req):
        """One protocol round trip, straight at the socket — the control that
        proves an assertion about the helper is about the HELPER."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(self.sock)
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf.split(b"\n")[0] or b"{}")
        finally:
            s.close()

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(timeout=10)
        return self.p.communicate()


def enable_agent(env, sid, idle=300, lifetime=3600):
    """Turn the agent on for one registry entry, in place."""
    for name in sorted(os.listdir(env.safes_d)):
        p = os.path.join(env.safes_d, name)
        with open(p) as fh:
            entry = json.load(fh)
        if entry.get("id") != sid:
            continue
        entry["agent"] = {"enabled": True, "idle_seconds": idle,
                          "max_seconds": lifetime}
        with open(p, "w") as fh:
            json.dump(entry, fh, indent=1)
        os.chmod(p, 0o644)
        return p
    raise SystemExit("no registry entry %r to enable the agent on" % sid)


# ------------------------------------------------------------- agent off ---

def agent_off(env, r, run_root):
    r.section("agent OFF — the default, and what I18 depends on")
    sock_dir = os.path.join(run_root, "cockpit-secrets")

    s = Session(env)
    try:
        u = s.call("unlock", safe="lab-kdbx41", password=PW)
        r.check("unlock succeeds", "handle" in u, u)
        r.check("the response carries NO agent key", "agent" not in u,
                sorted(u))
        r.check("...and no agent warning either",
                not any("agent" in str(w).lower()
                        for w in (u.get("warnings") or [])),
                u.get("warnings"))
        handle = u["handle"]
    finally:
        s.close()

    r.check("the helper created no run directory",
            not os.path.exists(sock_dir), sock_dir)
    r.check("...and no socket anywhere under it",
            not os.path.exists(os.path.join(sock_dir, "agent.sock")))

    h, _rc, _e = env.run("health")
    agent = h.get("agent") or {}
    r.check("health still REPORTS on the agent rather than hiding it",
            bool(agent), agent)
    r.check("health says no socket is reachable",
            not any((agent.get(k) or {}).get("reachable")
                    for k in ("user", "admin")), agent)

    # THE PROPERTY THAT MATTERS: a handle minted by a helper that has exited
    # is dead, and presenting it is access-denied — never not-found, which
    # would say which handles once existed.
    got, _rc, _e = env.run("entries", {"handle": handle})
    r.check("a handle does not survive the helper process",
            got.get("error") == "access-denied", got)
    got, _rc, _e = env.run("entries", {"handle": "TotallyMadeUpHandle1234"})
    r.check("...and an invented handle is the SAME error",
            got.get("error") == "access-denied", got)

    # And nothing is left on disk for a later process to pick up.
    leftovers = []
    for base in (run_root, env.var):
        for root, _dirs, files in os.walk(base):
            leftovers += [os.path.join(root, f) for f in files
                          if "agent" in f or "handle" in f or "sock" in f]
    r.check("no agent state was written anywhere", not leftovers, leftovers)


# -------------------------------------------------------------- agent on ---

def agent_on(env, r, run_root):
    r.section("agent ON — unlock, reattach, revoke")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600)
    d = Daemon(run_root)
    try:
        if not r.check("the daemon bound its socket", d.wait(),
                       d.p.stderr.read() if d.p.poll() is not None else ""):
            return
        r.check("the run dir is 0700",
                os.stat(d.dir).st_mode & 0o777 == 0o700)
        r.check("the socket is 0600",
                os.stat(d.sock).st_mode & 0o777 == 0o600)
        r.check("nothing is held before the first unlock",
                d.ask({"op": "status"}).get("holdings_total") == 0)

        # -- unlock: the helper hands the daemon a ticket -------------------
        s = Session(env)
        try:
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            handle = u.get("handle")
            block = u.get("agent") or {}
            r.check("unlock's response NOW carries an agent block",
                    bool(block), sorted(u))
            r.check("...saying the daemon took it", block.get("held") is True,
                    block)
            r.check("...with the registry's own window",
                    block.get("idle_seconds") == 300
                    and block.get("max_seconds") == 3600, block)
            r.check("...and a countdown the helper did not invent",
                    0 < int(block.get("expires_in") or 0) <= 3600, block)
            r.check("...naming the socket it spoke to",
                    block.get("socket") == d.sock, block.get("socket"))
        finally:
            s.close()

        # -- what the daemon actually holds --------------------------------
        raw = d.ask({"op": "status"})
        held = raw.get("holdings") or []
        r.check("the daemon holds exactly one thing", len(held) == 1, raw)
        r.check("...for the right safe",
                held and held[0].get("safe") == "lab-kdbx41", held)
        # NON-NEGOTIABLE 9. The daemon was asked directly, not through the
        # helper's scrubber, so this is what the daemon really has.
        direct = d.ask({"op": "get", "handle": handle})
        r.check("the ticket carries NO key material",
                direct.get("ok") is True
                and direct.get("material_held") is False
                and "material" not in direct, direct)
        r.check("...so the passphrase is still needed to read anything",
                env.run("entries", {"handle": handle})[0].get("error")
                == "access-denied")

        # -- REATTACH: a SECOND helper process sees the live unlock ---------
        # This is the half of I18 that is about visibility: the process that
        # minted the handle has exited, and the hold is still on screen.
        h2, _rc, _e = env.run("health")
        rows = (((h2.get("agent") or {}).get("user") or {})
                .get("status") or {}).get("holdings") or []
        r.check("a second helper process SEES the hold", len(rows) == 1, rows)
        r.check("...and it names the safe",
                rows and rows[0].get("safe") == "lab-kdbx41", rows)
        r.check("...with a live countdown",
                rows and 0 < int(rows[0].get("expires_in") or 0) <= 3600, rows)
        r.check("the helper STRIPS the handle out of what it reports",
                "handle" not in json.dumps(rows), rows)
        r.check("...and any material with it",
                "material" not in json.dumps(h2.get("agent")))

        # -- REVOKE: `lock` with a bare safe id, no handle -----------------
        # A Lock button has a safe id and nothing else; the helper that minted
        # the handle is long gone.
        out, _rc, _e = env.run("lock", {"safe": "lab-kdbx41"})
        r.check("lock accepts a bare safe id", out.get("ok") is True, out)
        r.check("...and says it revoked the agent ticket",
                out.get("agent_dropped") is True, out)
        r.check("the daemon really let go",
                d.ask({"op": "status"}).get("holdings_total") == 0)
        h3, _rc, _e = env.run("health")
        rows = (((h3.get("agent") or {}).get("user") or {})
                .get("status") or {}).get("holdings") or []
        r.check("...so the banner would now be empty", rows == [], rows)
        out, _rc, _e = env.run("lock", {"safe": "lab-kdbx41"})
        # THE RECEIPT MUST NOT LIE. The daemon answers a drop for a safe it
        # is not holding with {"ok":true,"dropped":0} — a satisfied request
        # that revoked nothing — and the helper read that as "dropped" until
        # this check existed.
        r.check("locking an unheld safe is ok but claims NOTHING was dropped",
                out.get("ok") is True and out.get("agent_dropped") is False,
                out)
    finally:
        d.stop()

    r.check("the socket is unlinked when the daemon exits",
            not os.path.exists(d.sock))


def agent_expiry(env, r, run_root):
    r.section("agent ON — the idle deadline fires on its own")
    # The registry's floor for `idle_seconds` is 30 s and stays there: it is
    # the window in which a stolen session reads the safe without knowing the
    # passphrase, and lowering it to make a test faster would be moving a
    # security bound for the convenience of the thing measuring it. The DAEMON
    # is given the short window instead, which exercises the real rule — the
    # effective window is min(agent's, client's), so the agent's own argv is
    # the hard bound and a registry asking for 30 gets 2 here.
    enable_agent(env, "lab-kdbx41", idle=30, lifetime=60)
    d = Daemon(run_root, idle=2, lifetime=60)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            block = u.get("agent") or {}
            r.check("the agent block is present", block.get("held") is True,
                    block)
            r.check("the effective window is the SHORTER of the two",
                    int(block.get("expires_in") or 99) <= 2, block)
        finally:
            s.close()
        r.check("held immediately after the unlock",
                d.ask({"op": "status"}).get("holdings_total") == 1)
        r.check("...and it is a ticket, not a key",
                d.ask({"op": "status"})["holdings"][0].get("expires_in") <= 2)
        # The daemon's tick is 5 s, so an expiry can fire up to a tick late.
        # Waiting past that measures the deadline rather than the tick.
        deadline = time.time() + 25
        while time.time() < deadline:
            if d.ask({"op": "status"}).get("holdings_total") == 0:
                break
            time.sleep(0.5)
        r.check("the idle deadline dropped it with no client involved",
                d.ask({"op": "status"}).get("holdings_total") == 0)
        h, _rc, _e = env.run("health")
        rows = (((h.get("agent") or {}).get("user") or {})
                .get("status") or {}).get("holdings") or []
        r.check("...and the UI would see it gone", rows == [], rows)
    finally:
        _out, err = d.stop()
    r.check("the expiry is audited as an expiry, by reason",
            '"op": "expire"' in err or '"op":"expire"' in err,
            [ln for ln in err.splitlines() if "expire" in ln][:2])


def hostile_socket(env, r, run_root):
    """A socket the helper must refuse to speak to at all (A1)."""
    r.section("agent ON — a socket that fails validation is not spoken to")
    enable_agent(env, "lab-kdbx41")
    d = os.path.join(run_root, "cockpit-secrets")
    os.makedirs(d, exist_ok=True)

    os.chmod(d, 0o755)                      # not 0700: another user could plant
    s = Session(env)
    try:
        u = s.call("unlock", safe="lab-kdbx41", password=PW)
        r.check("a group-readable run dir means no agent block",
                "agent" not in u, sorted(u))
    finally:
        s.close()

    os.chmod(d, 0o700)
    with open(os.path.join(d, "agent.sock"), "w") as fh:
        fh.write("not a socket")            # right name, wrong kind of file
    s = Session(env)
    try:
        u = s.call("unlock", safe="lab-kdbx41", password=PW)
        r.check("a regular file on the socket path means no agent block",
                "agent" not in u, sorted(u))
    finally:
        s.close()
    h, _rc, _e = env.run("health")
    reason = ((h.get("agent") or {}).get("user") or {}).get("reason") or ""
    r.check("...and health says WHY rather than just 'no'",
            "socket" in reason.lower(), reason)
    os.unlink(os.path.join(d, "agent.sock"))
    os.rmdir(d)


def main():
    env = Env().build()
    run_root = os.path.join(env.root, "run")
    os.makedirs(run_root, exist_ok=True)
    os.chmod(run_root, 0o700)
    env.env["XDG_RUNTIME_DIR"] = run_root
    r = Report("the unlock agent, helper against daemon")
    try:
        agent_off(env, r, run_root)
        agent_on(env, r, run_root)
        agent_expiry(env, r, run_root)
        hostile_socket(env, r, run_root)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
