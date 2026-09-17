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
import re
import select
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Session, Report, HELPER, SRC, PW      # noqa: E402

AGENT = os.path.join(SRC, "agent", "secrets_agent.py")

#: `SESSION_KEEP_OPEN_RECHECK_SECONDS` in the helper: how long a suspended
#: session may go before it re-asks the daemon whether it may still be
#: suspended. Read from the helper rather than copied, so a change there does
#: not quietly turn the revocation test into a test of nothing.
SESSION_RECHECK = int(re.search(
    r"^SESSION_KEEP_OPEN_RECHECK_SECONDS = (\d+)",
    open(HELPER, encoding="utf-8").read(), re.M).group(1))


class Daemon:
    """The real agent, self-bound in a private run directory.

    `XDG_RUNTIME_DIR` is redirected at both processes so the helper's
    `agent_socket_path()` lands on this daemon and never on a real one that
    might be running for this user — a test that could be answered by somebody
    else's agent is not a test.
    """

    def __init__(self, run_root, idle=300, lifetime=3600, registry=None,
                 tick=None, keep_open=True):
        self.run_root = run_root
        self.dir = os.path.join(run_root, "cockpit-secrets")
        self.sock = os.path.join(self.dir, "agent.sock")
        argv = [sys.executable, AGENT, "--run-dir", self.dir,
                "--idle-seconds", str(idle), "--max-seconds", str(lifetime),
                # logind is polled by shelling out to `loginctl`; a test must
                # not depend on whether the developer's screen happens to be
                # locked.
                "--no-session-watch", "--session-poll-seconds", "1"]
        # THE REGISTRY THE DAEMON READS FOR ITSELF. Named explicitly rather
        # than left to the default, for the same reason `_env` redirects both
        # of the helper's registries: a daemon that consulted the operator's
        # REAL /etc while the helper consulted a hermetic one would answer
        # questions about somebody's actual safes. It also happens to be the
        # first proof in this file that the daemon has a registry at all —
        # without this flag it correctly refuses everything below.
        if registry:
            argv += ["--registry-dir", registry]
        if tick is not None:
            argv += ["--tick-seconds", str(tick)]
        if not keep_open:
            argv += ["--no-keep-open"]
        self.p = subprocess.Popen(
            argv, cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

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


def enable_agent(env, sid, idle=300, lifetime=3600, allow_keep_open=False):
    """Turn the agent on for one registry entry, in place."""
    for name in sorted(os.listdir(env.safes_d)):
        p = os.path.join(env.safes_d, name)
        with open(p) as fh:
            entry = json.load(fh)
        if entry.get("id") != sid:
            continue
        entry["agent"] = {"enabled": True, "idle_seconds": idle,
                          "max_seconds": lifetime,
                          "allow_keep_open": bool(allow_keep_open)}
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


def keep_open_refused(env, r, run_root):
    """THE DEFAULT, AND THE PROOF THAT THE DAEMON IS THE AUTHORITY.

    `allow_keep_open` is false, so nothing may suspend the idle timer — and the
    refusal is measured twice, at two different layers, because only the second
    one is load-bearing:

      * through the HELPER, which is what the page reaches, and
      * straight at the SOCKET, bypassing the helper entirely, which is what a
        compromised or simply wrong client would do. If only the helper
        refused, `allow_keep_open` would be a UI preference with a security
        comment attached.
    """
    r.section("keep-open — allow_keep_open FALSE: the daemon refuses")
    enable_agent(env, "lab-kdbx41", idle=30, lifetime=600,
                 allow_keep_open=False)
    d = Daemon(run_root, idle=30, lifetime=600, registry=env.safes_d)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        out, _rc, _e = env.run("list")
        row = [x for x in out["safes"] if x["id"] == "lab-kdbx41"][0]
        r.check("the list row says the toggle may NOT be drawn",
                row.get("agent_keep_open_allowed") is False, row)

        s = Session(env)
        try:
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            handle = u["handle"]
            r.check("the unlock still works", bool(handle))
        finally:
            s.close()

        out, _rc, _e = env.run("keep-open", {"safe": "lab-kdbx41",
                                             "enabled": True})
        r.check("the helper refuses keep-open with access-denied",
                out.get("error") == "access-denied", out)

        # THE ONE THAT MATTERS. No helper in the path at all: this is the raw
        # protocol, the shape a client that had been talked into asking would
        # send. The daemon reads the registry itself and says no.
        direct = d.ask({"op": "keep-open", "safe": "lab-kdbx41",
                        "enabled": True})
        r.check("...and so does the DAEMON, asked directly over the socket",
                direct.get("error") == "access-denied", direct)
        r.check("...for a reason that names the registry key, not a path",
                "allow_keep_open" in str(direct.get("detail") or "")
                and "/" not in str(direct.get("detail") or ""), direct)
        direct = d.ask({"op": "put", "safe": "lab-kdbx41",
                        "handle": handle, "keep_open": True})
        r.check("a put that asks for keep_open is refused the same way",
                direct.get("error") == "access-denied", direct)

        held = d.ask({"op": "status"}).get("holdings") or []
        r.check("nothing is suspended",
                held and held[0].get("keep_open") is False, held)
        r.check("...and the idle deadline is still running on it",
                held and isinstance(held[0].get("idle_expires_in"), int), held)
    finally:
        _out, err = d.stop()
    r.check("the refusal is audited, with the safe and the uid and no value",
            any('"op":"keep-open"' in ln and '"outcome":"denied"' in ln
                and '"safe":"lab-kdbx41"' in ln for ln in err.splitlines()),
            [ln for ln in err.splitlines() if "keep-open" in ln][:3])


def keep_open_allowed(env, r, run_root):
    """`allow_keep_open` TRUE: the idle timer stops, the absolute one does not.

    Both halves are measured against the clock rather than asserted from a
    reply: a holding is kept past several multiples of its idle window, and
    then the absolute deadline is allowed to fire while a client does
    everything it can to push it out.
    """
    r.section("keep-open — allow_keep_open TRUE: the idle timer suspends")
    # The registry's floor for idle_seconds is 30 s and stays there — it is a
    # security bound, not a test parameter. The DAEMON is given the short
    # window instead, exactly as the expiry section above does.
    enable_agent(env, "lab-kdbx41", idle=30, lifetime=600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=2, lifetime=600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        out, _rc, _e = env.run("list")
        row = [x for x in out["safes"] if x["id"] == "lab-kdbx41"][0]
        r.check("the list row now says the toggle MAY be drawn",
                row.get("agent_keep_open_allowed") is True, row)

        s = Session(env)
        try:
            s.call("unlock", safe="lab-kdbx41", password=PW)
        finally:
            s.close()
        held = (d.ask({"op": "status"}).get("holdings") or [{}])[0]
        r.check("an unlock does NOT start suspended",
                held.get("keep_open") is False, held)

        out, _rc, _e = env.run("keep-open", {"safe": "lab-kdbx41",
                                             "enabled": True})
        r.check("the helper accepts keep-open by bare safe id",
                out.get("ok") is True and out.get("keep_open") is True, out)
        r.check("...and reports the holding it changed",
                out.get("affected") == 1 and out.get("changed") == 1, out)
        r.check("...with no idle deadline left to report",
                out.get("idle_expires_in") is None, out)
        # A ONE-SHOT VERB HAS NO SESSION IDLE TIMEOUT TO SUSPEND, and the
        # reply now says so instead of claiming a suspension it did not make.
        # This assertion used to read the other way round — it accepted "this
        # safe's idle timeout is suspended" from a helper process that was
        # about to exit — and that is the sentence the operator was shown while
        # being locked out two minutes later. See `keep_open_session` below for
        # the measurement of the timer that actually matters.
        r.check("...and says plainly that there was no SESSION to keep open",
                out.get("session") is False
                and any("no session idle timeout to suspend" in str(w)
                        for w in (out.get("warnings") or [])),
                out.get("warnings"))

        held = (d.ask({"op": "status"}).get("holdings") or [{}])[0]
        r.check("the daemon says the holding is suspended",
                held.get("keep_open") is True, held)
        r.check("...and publishes no idle countdown for it",
                held.get("idle_expires_in") is None, held)
        r.check("status says keep-open is available and counts the suspended",
                d.ask({"op": "status"})["keep_open"]["suspended"] == 1)

        # THE MEASUREMENT. Six times the daemon's 2 s idle window, with no use
        # at all in between: without the suspension the sweep would have taken
        # this holding several times over.
        time.sleep(12)
        r.check("the holding is still there twelve seconds into a two-second "
                "idle window", d.ask({"op": "status"})
                .get("holdings_total") == 1)
        h2, _rc, _e = env.run("health")
        rows = (((h2.get("agent") or {}).get("user") or {})
                .get("status") or {}).get("holdings") or []
        r.check("...and a second helper process sees it as suspended",
                len(rows) == 1 and rows[0].get("keep_open") is True, rows)

        # Turning it OFF hands the idle timer back, and the holding then dies
        # on it like any other.
        out, _rc, _e = env.run("keep-open", {"safe": "lab-kdbx41",
                                             "enabled": False})
        r.check("turning it off is accepted", out.get("ok") is True
                and out.get("keep_open") is False, out)
        r.check("...and an idle deadline is running again",
                isinstance(out.get("idle_expires_in"), int), out)
        deadline = time.time() + 20
        while time.time() < deadline:
            if d.ask({"op": "status"}).get("holdings_total") == 0:
                break
            time.sleep(0.5)
        r.check("the resumed idle timer drops it with no client involved",
                d.ask({"op": "status"}).get("holdings_total") == 0)
    finally:
        _out, err = d.stop()
    r.check("switching it on is audited as a keep-open, by safe and uid",
            any('"op":"keep-open"' in ln and '"outcome":"ok"' in ln
                and '"detail":"enabled"' in ln for ln in err.splitlines()),
            [ln for ln in err.splitlines() if "keep-open" in ln][:4])
    r.check("...and no audit line carries a value or a path",
            all(("/" not in ln and PW not in ln)
                for ln in err.splitlines() if ln.startswith("{")),
            [ln for ln in err.splitlines()
             if ln.startswith("{") and "/" in ln][:2])


def keep_open_absolute(env, r, run_root):
    """THE BOUND. The absolute deadline fires on time under keep-open, and no
    client can move it — not by re-putting with a bigger number, not by using
    the holding, and not by toggling keep-open at it."""
    r.section("keep-open — the ABSOLUTE deadline still fires, and cannot be "
              "extended")
    enable_agent(env, "lab-kdbx41", idle=30, lifetime=600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=2, lifetime=10, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            handle = u["handle"]
        finally:
            s.close()
        started = time.time()
        out, _rc, _e = env.run("keep-open", {"safe": "lab-kdbx41",
                                             "enabled": True})
        r.check("keep-open is on", out.get("keep_open") is True, out)
        r.check("...and expires_in is the ABSOLUTE remainder, not the idle one",
                0 < int(out.get("expires_in") or 0) <= 10, out)

        # A LIVE RE-PUT ASKING FOR A DAY. The window may only ever be
        # SHORTENED, so this must come back no larger than it went in.
        before = d.ask({"op": "get", "handle": handle}).get("expires_in")
        d.ask({"op": "put", "safe": "lab-kdbx41", "handle": handle,
               "keep_open": True, "max_seconds": 86400, "idle_seconds": 3600})
        after = d.ask({"op": "get", "handle": handle}).get("expires_in")
        r.check("a re-put asking for a day does not lengthen the window",
                isinstance(after, int) and after <= before, (before, after))

        # Then everything else a client can do to stay alive, in a loop, for
        # longer than the absolute lifetime. None of it is allowed to matter.
        # `put` is deliberately NOT in this loop: once the deadline has fired
        # and the holding is gone, a put mints a BRAND NEW ticket with its own
        # fresh lifetime, which is not an extension of anything — it is the
        # same thing an unlock does, and it is checked as such below rather
        # than left in here to look like a bypass.
        attempts, oldest = 0, 0
        while time.time() - started < 12:
            d.ask({"op": "get", "handle": handle})
            d.ask({"op": "keep-open", "safe": "lab-kdbx41", "enabled": True})
            for h in (d.ask({"op": "status"}).get("holdings") or []):
                oldest = max(oldest, int(h.get("age") or 0))
            attempts += 1
            time.sleep(0.5)
        r.check("the absolute deadline fired anyway, after %d rounds of a "
                "client using and re-toggling it" % attempts,
                d.ask({"op": "status"}).get("holdings_total") == 0)
        r.check("...and no holding was ever older than its 10 s lifetime "
                "plus a tick (oldest seen: %d s)" % oldest, oldest <= 11)
        r.check("...within a few seconds of its time, not late",
                time.time() - started < 20)

        # AND THE HONEST FOOTNOTE. A `put` after the expiry is a NEW holding
        # with a NEW deadline, because that is what a ticket is: a record that
        # a safe was unlocked at a time. It carries nothing forward from the
        # one that died, which is what stops it being a way round the cap.
        d.ask({"op": "put", "safe": "lab-kdbx41", "handle": handle,
               "keep_open": True, "max_seconds": 86400})
        fresh = (d.ask({"op": "status"}).get("holdings") or [{}])[0]
        # `or 99` would be wrong here: age 0 is falsy and is also the RIGHT
        # answer, so the default has to come from .get() and not from `or`.
        r.check("a put after the expiry mints a NEW ticket, from zero",
                int(fresh.get("age", 99)) <= 1, fresh)
        r.check("...still capped at the daemon's own lifetime, not the day "
                "the client asked for",
                0 < int(fresh.get("expires_in") or 0) <= 10, fresh)
        r.check("...and it may be suspended again only because the registry "
                "was re-read and still says yes",
                fresh.get("keep_open") is True, fresh)
    finally:
        _out, err = d.stop()
    r.check("the expiry is audited as ABSOLUTE, not idle",
            any('"op":"expire"' in ln and '"absolute"' in ln
                for ln in err.splitlines()),
            [ln for ln in err.splitlines() if "expire" in ln][:3])


def keep_open_presence(env, r, run_root):
    """THE PRESENCE LOCKS ARE NOT SUSPENDED. keep-open turns off a TIMEOUT;
    "nobody is here" is not one, so `lock` — which is what the page's Lock
    button, its pagehide handler and its hidden-tab timer all reach — still
    ends a suspended unlock immediately."""
    r.section("keep-open — Lock still ends a suspended unlock at once")
    enable_agent(env, "lab-kdbx41", idle=30, lifetime=600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            s.call("unlock", safe="lab-kdbx41", password=PW)
        finally:
            s.close()
        env.run("keep-open", {"safe": "lab-kdbx41", "enabled": True})
        r.check("a suspended holding exists",
                d.ask({"op": "status"})["keep_open"]["suspended"] == 1)
        out, _rc, _e = env.run("lock", {"safe": "lab-kdbx41"})
        r.check("lock by bare safe id still revokes it",
                out.get("ok") is True and out.get("agent_dropped") is True, out)
        r.check("the daemon let go immediately, with no timer involved",
                d.ask({"op": "status"}).get("holdings_total") == 0)
        r.check("...and SIGTERM would have too (the daemon holds nothing now)",
                d.ask({"op": "status"})["keep_open"]["suspended"] == 0)

        # And the same for the agent-wide ceiling: an operator who does not
        # want this feature on this host turns it off at the daemon, and no
        # registry entry can lift it.
    finally:
        d.stop()

    r.section("keep-open — --no-keep-open is a ceiling no registry can lift")
    d = Daemon(run_root, idle=300, lifetime=600, registry=env.safes_d,
               keep_open=False)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            s.call("unlock", safe="lab-kdbx41", password=PW)
        finally:
            s.close()
        r.check("status says the daemon does not offer keep-open",
                d.ask({"op": "status"})["keep_open"]["available"] is False)
        out, _rc, _e = env.run("keep-open", {"safe": "lab-kdbx41",
                                             "enabled": True})
        r.check("...and an opted-in safe is still refused",
                out.get("error") == "access-denied", out)
        r.check("...by the daemon, asked directly",
                d.ask({"op": "keep-open", "safe": "lab-kdbx41",
                       "enabled": True}).get("error") == "access-denied")
    finally:
        d.stop()


def wait_for_close(s, timeout):
    """Read `s`'s reply stream until the helper's closing frame, or `timeout`.

    **IT DOES NOT CLOSE STDIN**, and that is the whole reason it exists. The
    obvious way to wait for a session to end is to close the write end and read
    to EOF — but the helper treats a closed channel as the operator leaving the
    page and shuts down at once, so a test written that way passes whether or
    not the deadline it claims to be measuring exists. Silence on an OPEN
    channel is the only thing that measures an idle or absolute deadline.
    """
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([s.p.stdout], [], [],
                                    max(0.0, end - time.time()))
        if not ready:
            break
        line = s.p.stdout.readline()
        if not line:
            return {"frame": "closed", "reason": "eof"}
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("frame") == "closed":
            return obj
    return None


def keep_open_session(env, r, run_root):
    """THE FEATURE, MEASURED: the operator is not locked out mid-work.

    ========================================================================
    WHAT THE FIRST IMPLEMENTATION GOT WRONG, AND WHAT THIS MEASURES.
    ========================================================================

    It suspended the AGENT TICKET's idle timer. The agent holds a ticket and no
    key material, so that suspended nothing the operator could feel: the thing
    that ended their session was `SESSION_IDLE_SECONDS` in the helper's
    `run_session` — the channel goes quiet, the process exits, the unlock goes
    with it — and the toggle never touched it. The banner said they would not
    be locked out. They were.

    So this runs a REAL session, over a real pipe, against a real daemon, and
    measures the only thing that settles it: after the toggle is on, the
    session is left silent for several times its own idle window and then asked
    to do something that needs the unlock. Before the fix that call gets no
    reply at all, because the helper exited on schedule.

    The bound is measured in the same session: `SESSION_MAX_SECONDS` still
    fires, on time, with the toggle on and no client able to move it.
    """
    r.section("keep-open — the SESSION idle timer, measured over a real pipe")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return

        # SESSION_IDLE_MIN is 10 s and is a security bound, not a test knob —
        # so the session is shortened to exactly it and the measurement is made
        # against that, rather than the bound being lowered to suit the test.
        s = Session(env)
        try:
            s.call("session", idle_seconds=10, max_seconds=60)
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            r.check("unlocked inside the session", bool(u.get("handle")), u)
            r.check("...and the deadline it published is the SESSION's, not a "
                    "longer one the helper does not believe",
                    0 < int(u.get("expires_in") or 0) <= 60, u)

            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("keep-open inside a session reports a SESSION suspension",
                    out.get("ok") is True
                    and out.get("session") is True
                    and out.get("session_keep_open") is True, out)
            r.check("...with no session idle deadline left to count down",
                    out.get("session_idle_expires_in") is None, out)
            r.check("...and re-issues the deadline for the page to adopt",
                    0 < int(out.get("session_expires_in") or 0) <= 60, out)
            r.check("...and the daemon's ticket was suspended too",
                    out.get("affected") == 1 and out.get("keep_open") is True,
                    out)

            # THE MEASUREMENT. 25 s of complete silence on a 10 s idle window:
            # two and a half windows, on a session that would otherwise have
            # been gone after the first.
            start = time.time()
            time.sleep(25)
            # The failure this measures is the helper having EXITED, so the
            # call raises (EPIPE, or no reply at all) rather than answering
            # badly. Caught and reported as a failed check: a traceback is a
            # crashed test, and this is a finding.
            try:
                still = s.call("list")
            except Exception as exc:                           # noqa: BLE001
                still = {"_gone": "%s: %s" % (type(exc).__name__, exc)}
            waited = time.time() - start
            r.check("the session is ALIVE %.0f s into a 10 s idle window, and "
                    "still answering" % waited,
                    isinstance(still, dict) and still.get("safes") is not None,
                    still.get("_gone") or sorted(still)[:6])

            # ...and the safe is still unlocked in it, which is the operator's
            # actual complaint: not "the pipe is open" but "my work is still
            # there".
            try:
                ent = s.call("entries", handle=u["handle"])
            except Exception as exc:                           # noqa: BLE001
                ent = {"error": "%s: %s" % (type(exc).__name__, exc)}
            r.check("...and the unlock is still live in it: entries answers "
                    "without a new passphrase",
                    ent.get("error") is None, sorted(ent)[:6])

            # THE BOUND. 60 s absolute from the session's start; ~35 s of it
            # are already spent. It must close ON ITS OWN, with the toggle on
            # and the channel still open — see `wait_for_close`.
            closed = wait_for_close(s, 60)
            elapsed = time.time() - start
            r.check("the ABSOLUTE bound still ends the suspended session",
                    closed is not None
                    and closed.get("reason") == "max-lifetime", closed)
            r.check("...on time, not late: %.0f s after the unlock" % elapsed,
                    closed is not None and elapsed < 75, elapsed)
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass

        # AND THE SUSPENSION DID NOT OUTLIVE THE SESSION. The ticket the daemon
        # holds must not still be flagged keep-open once the session that asked
        # for it has gone — that flag is what the page's banner draws, and a
        # banner promising protection for a session that ended is the defect
        # this closes.
        end = time.time() + 10
        rows = None
        while time.time() < end:
            rows = d.ask({"op": "status"}).get("holdings") or []
            if not rows or rows[0].get("keep_open") is False:
                break
            time.sleep(0.5)
        r.check("the suspension did not outlive the session that asked for it",
                not rows or rows[0].get("keep_open") is False, rows)
    finally:
        _out, err = d.stop()
    # THE DIRECTION, IN THE OPERATOR'S OWN LOG. `ctx.note` was set to
    # "keep-open-on"/"keep-open-off" and `audit()` drops any note outside
    # `_AUDIT_NOTES`, which did not list either — so every keep-open line read
    # `"note": ""` and the log could not tell switching the timer OFF from
    # switching it back ON.
    tail, _rc, _e = env.run("audit-tail", {"n": 400})
    lines = [x for x in (tail.get("entries") or [])
             if str(x.get("verb")) == "keep-open"]
    r.check("the audit line says WHICH DIRECTION the toggle went",
            any(x.get("note") == "keep-open-on" for x in lines)
            and any(x.get("note") == "keep-open-off" for x in lines),
            [x.get("note") for x in lines][:6])
    r.check("...and still carries no value and no path",
            all("/" not in json.dumps(x) and PW not in json.dumps(x)
                for x in lines), lines[:2])


def keep_open_registry_raise(env, r, run_root):
    """THE ONE INPUT THAT MAY RAISE THE BOUND, AND THE TWO THAT MAY NOT.

    `SESSION_MAX_SECONDS` is the bound a suspended session still dies on. A
    registry entry MAY raise it, because that file is the operator's policy and
    not a client — capped at the built-in ceiling, counted from the session's
    start, idempotent under re-sending, and refused outright once a client has
    shortened the lifetime itself. All four are measured here, and so is the
    thing that made the raise a lie the first time it was written: the HANDLE
    carries its own absolute deadline, and a raise that moved only the session
    would leave the page alive with every verb answering "unlock again".
    """
    r.section("keep-open — the registry may raise the bound; a client may not")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            # NO max_seconds here: the client shortens only the idle window, so
            # the registry's raise is allowed to apply.
            s.call("session", idle_seconds=10)
            u = s.call("unlock", safe="lab-kdbx41", password=PW)
            base = int(u.get("expires_in") or 0)
            r.check("before the toggle the session's bound is the built-in one",
                    0 < base <= 900, base)
            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            raised = int(out.get("session_expires_in") or 0)
            r.check("the registry's agent.max_seconds raises the session bound",
                    raised > 900, out)
            r.check("...and it is capped at the built-in ceiling",
                    raised <= 3600, raised)
            r.check("...and the raise is announced in the reply, with the "
                    "ceiling in it",
                    any("ceiling" in str(w) for w in (out.get("warnings") or [])),
                    out.get("warnings"))
            again = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("...and re-sending the toggle cannot ratchet it",
                    int(again.get("session_expires_in") or 0) <= raised, again)
            # THE HANDLE WENT WITH IT. Without that, the session outlives its
            # own handle and every verb answers "unlock again".
            ent = s.call("entries", handle=u["handle"])
            r.check("the handle is still valid under the raised bound",
                    ent.get("error") is None, sorted(ent)[:4])

            # ==============================================================
            # F4 — THE RAISE IS CONTINGENT ON THE SUSPENSION.
            # ==============================================================
            # It used to survive both OFF and revocation, so a client could
            # click the toggle on, take the hour, and click it off: an
            # extension bought with two clicks, which is precisely the
            # manoeuvre `client_shortened` exists to stop one door along. Off
            # gives it back, and the reply re-publishes the lowered number in
            # the same breath so the page is never ahead of the helper.
            #
            # Delete the `base_lifetime` restore in `SessionWindow.release`
            # and this fails: session_max_seconds stays at 3600.
            off = s.call("keep-open", safe="lab-kdbx41", enabled=False)
            r.check("switching it OFF gives the registry's raise back",
                    int(off.get("session_max_seconds") or 0) <= 900, off)
            r.check("...and re-publishes the LOWERED deadline in the same "
                    "reply, so the page cannot stay ahead of the helper",
                    0 < int(off.get("session_expires_in") or 0) <= 900, off)
            r.check("...and the scope it publishes is empty again",
                    off.get("session_keep_open_safes") == [], off)
        finally:
            s.close()

        # ==================================================================
        # F5 — `unlock`'s OWN max_seconds COUNTS AS SHORTENING.
        # ==================================================================
        # `client_shortened` was set only by a `session` frame, and `unlock`
        # takes a `max_seconds` of its own. So a client could shorten the
        # HANDLE there, toggle keep-open, and have `_raise_session_handles`
        # hand the lifetime straight back — the same manoeuvre the `session`
        # frame is refused, through a door nobody had guarded.
        #
        # Remove the `ctx.window.client_shortened = True` in `v_unlock` and
        # this fails: the 60 s handle comes back as 3599.
        s = Session(env)
        try:
            s.call("session", idle_seconds=10)         # NO max_seconds here
            u = s.call("unlock", safe="lab-kdbx41", password=PW,
                       max_seconds=60)
            r.check("the unlock shortened its own handle",
                    0 < int(u.get("expires_in") or 0) <= 60, u)
            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("a client that shortened through UNLOCK gets no raise "
                    "either",
                    0 < int(out.get("session_expires_in") or 0) <= 60, out)
            r.check("...and no ceiling note, because nothing was raised",
                    not any("ceiling" in str(w)
                            for w in (out.get("warnings") or [])),
                    out.get("warnings"))
        finally:
            s.close()

        # AND A CLIENT CANNOT GET IT BY SHORTENING FIRST. A `session` frame may
        # only ever shorten; a client that could shorten the bound and then
        # have a toggle hand it back would have found the extension the frame
        # is not allowed to ask for.
        s = Session(env)
        try:
            s.call("session", idle_seconds=10, max_seconds=60)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("a client that SHORTENED the lifetime gets no raise from "
                    "the registry",
                    0 < int(out.get("session_expires_in") or 0) <= 60, out)
        finally:
            s.close()
    finally:
        d.stop()


def keep_open_revocation(env, r, run_root):
    """REVOKING THE OPT-IN REACHES A LIVE SUSPENSION — both halves of it.

    The daemon's own reconciliation is proved in `--selfcheck`; what is proved
    here is that the SESSION finds out too. A session that had been granted the
    suspension goes on being granted it only for as long as the daemon keeps
    saying yes, and it re-asks; the registry is edited underneath it and the
    session loses the suspension and then dies on the idle timer that came
    back.
    """
    r.section("keep-open — the operator can take it back while it is running")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        alive_after_revoke = None
        try:
            s.call("session", idle_seconds=10, max_seconds=300)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("the session is suspended",
                    out.get("session_keep_open") is True, out)

            # The operator edits their registry. Nothing is restarted, nothing
            # is signalled, and the session is in the middle of its silence.
            enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                         allow_keep_open=False)

            # The session rechecks on its own timer, so this waits for the
            # recheck AND for the idle window it hands back. The channel stays
            # OPEN throughout: closing it would end the session for a reason
            # that has nothing to do with the revocation.
            closed = wait_for_close(s, SESSION_RECHECK + 40)
            alive_after_revoke = closed.get("reason") if closed else None
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass
        r.check("a withdrawn opt-in ends the session it was keeping open, "
                "without anything being restarted and without the channel "
                "being closed under it",
                alive_after_revoke in ("idle", "max-lifetime",
                                       "agent-released"),
                alive_after_revoke)
    finally:
        d.stop()
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)


def keep_open_scope(env, r, run_root):
    """F1 — THE GRANT IS BOUNDED BY THE WEAKEST SAFE THE SESSION HOLDS.

    ========================================================================
    THE DEFECT, AND WHY IT IS THE STRUCTURAL ONE.
    ========================================================================

    The daemon's gate is asked about ONE safe. The thing it was allowed to
    switch off — `SESSION_IDLE_SECONDS` in the helper's `run_session` — is the
    only idle protection EVERY safe that process has unlocked has. So one
    opted-in safe bought a suspension that covered an opted-OUT one sitting
    beside it: `allow_keep_open: false` protected nothing whenever any other
    safe in the same process was opted in, and the page drew no toggle for it,
    so the operator's only signal said the opposite.

    Measured with a CONTROL, because "the session is still alive" only means
    something against a session that would otherwise be dead: the same script,
    the same silence, no toggle.

    Revert the `held <= allowed` test in `SessionWindow._rescope` — or let
    `grant` take a single safe again — and the first half of this fails: the
    opted-out safe answers 26 s into a 10 s idle window.
    """
    r.section("keep-open — the grant is bounded by the WEAKEST safe held (F1)")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    enable_agent(env, "lab-kdbx40", idle=300, lifetime=3600,
                 allow_keep_open=False)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            s.call("session", idle_seconds=10, max_seconds=300)
            u40 = s.call("unlock", safe="lab-kdbx40", password=PW)
            u41 = s.call("unlock", safe="lab-kdbx41", password=PW)
            r.check("one session holds both safes",
                    bool(u40.get("handle")) and bool(u41.get("handle")))

            denied, _rc, _e = None, None, None
            out40 = s.call("keep-open", safe="lab-kdbx40", enabled=True)
            r.check("the registry refuses the opted-OUT safe outright",
                    out40.get("error") == "access-denied", out40)

            out41 = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("and the opted-IN safe does not get the session suspended "
                    "either, because the suspension would cover the other one",
                    out41.get("ok") is True
                    and out41.get("session_keep_open") is False, out41)
            r.check("...and the reply NAMES the safe that blocked it",
                    any("lab-kdbx40" in str(w)
                        for w in (out41.get("warnings") or [])),
                    out41.get("warnings"))
            r.check("...and publishes an EMPTY scope, so a page cannot promise "
                    "over it",
                    out41.get("session_keep_open_safes") == [], out41)

            # THE MEASUREMENT. 26 s of silence on a 10 s idle window.
            time.sleep(26)
            try:
                ent = s.call("entries", handle=u40["handle"])
            except Exception as exc:                           # noqa: BLE001
                ent = {"_gone": "%s: %s" % (type(exc).__name__, exc)}
            r.check("26 s later the opted-OUT safe is NOT still open: the "
                    "session died on the idle timer nothing was allowed to "
                    "suspend",
                    isinstance(ent, dict) and ent.get("_gone") is not None,
                    ent)
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass

        # THE CONTROL. Same script, same silence, no toggle — so the death
        # above is known to be the idle timer and not something else.
        s = Session(env)
        try:
            s.call("session", idle_seconds=10, max_seconds=300)
            u40 = s.call("unlock", safe="lab-kdbx40", password=PW)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            time.sleep(26)
            try:
                ent = s.call("entries", handle=u40["handle"])
            except Exception as exc:                           # noqa: BLE001
                ent = {"_gone": str(type(exc).__name__)}
            r.check("control: with NO toggle at all the same session dies the "
                    "same way, so the check above measures the timer",
                    isinstance(ent, dict) and ent.get("_gone") is not None, ent)
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass

        # AND THE OTHER DIRECTION: a suspension that is running when a safe the
        # agent will not let this session suspend is opened ends THERE AND THEN.
        s = Session(env)
        try:
            s.call("session", idle_seconds=10, max_seconds=300)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            on = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("alone, the opted-in safe DOES suspend the session",
                    on.get("session_keep_open") is True, on)
            r.check("...and the scope it publishes is exactly that safe",
                    on.get("session_keep_open_safes") == ["lab-kdbx41"], on)
            u40 = s.call("unlock", safe="lab-kdbx40", password=PW)
            r.check("unlocking the opted-OUT safe into the suspended session "
                    "ends the suspension in the unlock's own reply",
                    u40.get("session_keep_open") is False
                    and u40.get("session_keep_open_safes") == [], u40)
            time.sleep(26)
            try:
                ent = s.call("entries", handle=u40["handle"])
            except Exception as exc:                           # noqa: BLE001
                ent = {"_gone": str(type(exc).__name__)}
            r.check("...and the session then dies on the idle timer that came "
                    "back", isinstance(ent, dict) and ent.get("_gone")
                    is not None, ent)
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass
    finally:
        d.stop()
    enable_agent(env, "lab-kdbx40", idle=300, lifetime=3600,
                 allow_keep_open=False)


def keep_open_recheck_while_talking(env, r, run_root):
    """F2 — THE RE-ASK IS ON A CLOCK, NOT ON SILENCE.

    The recheck used to live in the idle-timeout branch, so it was reached only
    by a session that had gone quiet. A session that keeps talking — the normal
    state of a page whose operator is working, and the only state in which
    keep-open is doing anything at all — never re-asked. So a withdrawn opt-in
    and every presence signal that lands at the DAEMON (the screen locking, the
    machine suspending, another tab's Lock) reached exactly the sessions that
    were about to end anyway.

    Measured with the presence half, because it is the sharper one: the daemon
    lets go of the holding, and the session must end within the recheck
    interval WHILE IT IS STILL SENDING FRAMES.

    Move the recheck back into the `line is None` branch and this fails: the
    session talks straight through the interval.
    """
    r.section("keep-open — a TALKING session finds out too (F2)")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        ended, waited = None, 0.0
        try:
            # The idle window is 300 s and the absolute one 600 s, so NOTHING
            # here can end this session except the recheck.
            s.call("session", idle_seconds=300, max_seconds=600)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("the session is suspended",
                    out.get("session_keep_open") is True, out)
            # PRESENCE: the daemon drops the holding, which is what a screen
            # lock, a suspend or a SIGTERM does over there.
            d.ask({"op": "drop", "all": True})
            t0 = time.time()
            while time.time() - t0 < SESSION_RECHECK + 20:
                try:
                    s.call("list")
                except Exception as exc:                       # noqa: BLE001
                    ended = type(exc).__name__
                    break
                time.sleep(2)
            waited = time.time() - t0
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass
        r.check("a session that never stops talking still ends within the "
                "recheck interval of the daemon letting go (%.0f s, interval "
                "%d s)" % (waited, SESSION_RECHECK),
                ended is not None and waited <= SESSION_RECHECK + 15,
                ended or "still alive and still holding the unlock")
    finally:
        d.stop()


def keep_open_off_after_revocation(env, r, run_root):
    """F3 — THE OPERATOR CAN ALWAYS SWITCH IT BACK OFF.

    The daemon gates OFF exactly as it gates ON, and it must: its OFF resets
    the holding's idle timer, so an ungated OFF is a keepalive. But it
    therefore refuses OFF for a safe whose opt-in has just been WITHDRAWN, and
    the helper relayed that refusal — so the operator whose registry had
    changed under them could not turn the toggle off at all, and the control
    they were left with read "Keeping open".

    The fix is in the HELPER and does not weaken the daemon's gate by one line:
    the daemon still refuses, still resets nothing, and the helper resumes its
    OWN idle timer regardless, which is strictly more protective.

    Re-raise the daemon's refusal for the off direction in `v_keep_open` and
    this fails with access-denied.
    """
    r.section("keep-open — OFF still works after the opt-in is withdrawn (F3)")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return
        s = Session(env)
        try:
            s.call("session", idle_seconds=300, max_seconds=600)
            s.call("unlock", safe="lab-kdbx41", password=PW)
            on = s.call("keep-open", safe="lab-kdbx41", enabled=True)
            r.check("the session is suspended",
                    on.get("session_keep_open") is True, on)
            enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                         allow_keep_open=False)
            # Silence long enough for the recheck to revoke it.
            time.sleep(SESSION_RECHECK + 5)
            off = s.call("keep-open", safe="lab-kdbx41", enabled=False)
            r.check("the operator can still switch keep-open OFF after the "
                    "opt-in was withdrawn under them",
                    off.get("ok") is True
                    and off.get("session_keep_open") is False, off)
            r.check("...and the reply SAYS the daemon refused its half rather "
                    "than pretending it did not",
                    any("refused" in str(w)
                        for w in (off.get("warnings") or [])),
                    off.get("warnings"))
        finally:
            try:
                s.close()
            except Exception:                                  # noqa: BLE001
                pass
    finally:
        d.stop()
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)


def keep_open_teardown(env, r, run_root):
    """B AND THE RECEIPT — a clean teardown releases EVERY safe it suspended,
    and a SIGTERM is a clean teardown.

    ========================================================================
    TWO DEFECTS, ONE FUNCTION.
    ========================================================================

    B. `run_session`'s release ran on the loop's own ways out — EOF, idle,
    lifetime, `lock`. The way the browser actually ends a session is none of
    them: the page calls `proc.close("terminated")` and cockpit's spawn channel
    SIGNALS the process. With no handler that is the kernel's default, so the
    release never ran on the path Cockpit actually takes, and the daemon was
    left holding a ticket still flagged `keep_open` for a session that had
    gone. The page draws the daemon's state, so that ticket IS a banner still
    promising a suspension over nothing.

    THE RECEIPT. The release named `window.safe` — the last safe toggled —
    released that one, and printed "its keep-open suspension went with it". A
    session that had suspended two left one suspended at the daemon and told
    the operator it had not. A receipt that overstates is the same defect as a
    banner that overstates.

    Remove the SIGTERM handler and the first half fails; put `window.safe`
    back in place of `window.granted` and the second half fails.
    """
    r.section("keep-open — the teardown releases ALL of it, on the path "
              "Cockpit actually takes (B)")
    enable_agent(env, "lab-kdbx41", idle=300, lifetime=3600,
                 allow_keep_open=True)
    enable_agent(env, "lab-kdbx40", idle=300, lifetime=3600,
                 allow_keep_open=True)
    d = Daemon(run_root, idle=300, lifetime=3600, registry=env.safes_d, tick=1)
    try:
        if not r.check("the daemon bound its socket", d.wait()):
            return

        # ---- B: SIGTERM, which is what proc.close("terminated") sends -----
        s = Session(env)
        s.call("session", idle_seconds=300, max_seconds=600)
        s.call("unlock", safe="lab-kdbx41", password=PW)
        s.call("keep-open", safe="lab-kdbx41", enabled=True)
        rows = d.ask({"op": "status"}).get("holdings") or []
        r.check("the ticket is suspended before the signal",
                any(x.get("keep_open") for x in rows), rows)
        s.p.send_signal(signal.SIGTERM)
        try:
            s.p.wait(timeout=15)
        except Exception:                                      # noqa: BLE001
            pass
        end = time.time() + 10
        while time.time() < end:
            rows = d.ask({"op": "status"}).get("holdings") or []
            if not any(x.get("keep_open") for x in rows):
                break
            time.sleep(0.5)
        r.check("a SIGTERMed session releases its suspension rather than "
                "dying where it stands",
                not any(x.get("keep_open") for x in rows), rows)
        err = s.p.stderr.read() or ""
        r.check("...and says so on stderr, naming the reason it ended",
                "terminated" in err and "keep-open suspension went with it"
                in err, err[-160:])
        d.ask({"op": "drop", "all": True})

        # ---- the receipt: TWO safes suspended, one clean close ------------
        s = Session(env)
        s.call("session", idle_seconds=300, max_seconds=600)
        s.call("unlock", safe="lab-kdbx40", password=PW)
        s.call("unlock", safe="lab-kdbx41", password=PW)
        s.call("keep-open", safe="lab-kdbx40", enabled=True)
        out = s.call("keep-open", safe="lab-kdbx41", enabled=True)
        r.check("with BOTH safes opted in the session suspends, and the scope "
                "it publishes names both",
                out.get("session_keep_open") is True
                and out.get("session_keep_open_safes")
                == ["lab-kdbx40", "lab-kdbx41"], out)
        rows = d.ask({"op": "status"}).get("holdings") or []
        r.check("two tickets are suspended at the daemon",
                sum(1 for x in rows if x.get("keep_open")) == 2, rows)
        _rest, err, _rc = s.close()
        end = time.time() + 10
        while time.time() < end:
            rows = d.ask({"op": "status"}).get("holdings") or []
            if not any(x.get("keep_open") for x in rows):
                break
            time.sleep(0.5)
        r.check("a clean teardown releases EVERY safe it suspended, not the "
                "last one toggled",
                not any(x.get("keep_open") for x in rows), rows)
        r.check("...and the receipt says how many and which, rather than "
                "claiming it released them all while releasing one",
                "all 2 safe(s)" in err and "lab-kdbx40" in err
                and "lab-kdbx41" in err,
                [ln for ln in err.splitlines() if "suspension" in ln])
    finally:
        d.stop()
    enable_agent(env, "lab-kdbx40", idle=300, lifetime=3600,
                 allow_keep_open=False)


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
        keep_open_refused(env, r, run_root)
        keep_open_allowed(env, r, run_root)
        keep_open_absolute(env, r, run_root)
        keep_open_presence(env, r, run_root)
        keep_open_session(env, r, run_root)
        keep_open_registry_raise(env, r, run_root)
        keep_open_revocation(env, r, run_root)
        keep_open_scope(env, r, run_root)
        keep_open_recheck_while_talking(env, r, run_root)
        keep_open_off_after_revocation(env, r, run_root)
        keep_open_teardown(env, r, run_root)
        hostile_socket(env, r, run_root)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
