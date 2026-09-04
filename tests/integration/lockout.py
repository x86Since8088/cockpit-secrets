#!/usr/bin/env python3
"""I16's counter, at the layer that broke it: concurrency, identity and reach.

The attack pass's `WEB-01` (docs/KNOWN_ISSUES.md **I39**) and the browser
lens's **I40**. Both were reproduced on 2026-09-04; this file is what stops
them coming back, and every check in it was watched to FAIL against the
committed pre-fix helper before the fix went in.

WHAT EACH SECTION PROVES, and why it needs the real helper

  A  the sequential control. Eight wrong guesses one at a time. Nothing here
     is a regression guard — it is the REFERENCE the concurrent run is
     compared against, because "50 concurrent behaved" means nothing without
     "and this is what one at a time does".

  B  I39, the lost-update race. N helper PROCESSES, spawned together, all with
     a wrong passphrase. Two assertions, and the second is the one with teeth:
     the counter on disk must equal the number of attempts that were actually
     evaluated, exactly — no lost increments — and the outcome distribution
     must match section A's. Before the fix, 50 concurrent guesses were 34
     evaluated against a threshold of 5 and left the counter reading 3.

     Threads, not asyncio: each unit of work is a separate `secrets-admin`
     PROCESS with its own file descriptors, which is the only arrangement in
     which a file lock is being tested rather than a Python one.

  C  the reservation is given back when no guess was consumed. The counter is
     now incremented BEFORE the derivation, so a request that fails without
     ever reaching the KDF — no passphrase at all — must leave both counters
     where it found them. If it did not, anyone entitled to try could burn the
     per-safe cap with empty requests and deny the safe to everybody else.

  D  the per-safe rate cap, driven at the module boundary. It exists for an
     attacker who can vary `SUDO_UID` and collect a fresh per-principal
     counter each time (see I40's fix note), and proving it end to end would
     need twenty real administrators on the host. So it is proved against the
     real `lockout_begin`/`lockout_settle` with synthetic identities, and the
     END-TO-END bound on identity variation — the class gate — is measured in
     `tests/root/driver_lockout.py` where euid 0 is real.

  F  the wedge. `flock` is the mechanism, so "hold that file open" is the way
     to try to switch the mechanism off. A foreign process takes the lock and
     a CORRECT passphrase is refused — fail closed — inside a bounded wait,
     because an unbounded one is the other way a lock becomes a denial of
     service. That a wedge does not stall a DIFFERENT principal needs two real
     uids at euid 0 and is `tests/root/driver_lockout.py` section 7.

  E  reach. The red team asked whether the counter is on every
     credential-consuming path or only `unlock`, and it was never answered.
     It is answered here by measurement, and the list of verbs is read out of
     the `schema` verb rather than written down here, so a verb added later
     that accepts a passphrase is covered the day it exists.

     THIS SECTION PASSED BEFORE THE FIX TOO, and that is the finding: the
     reach was already correct — everything routes through `need_backend` ->
     `do_unlock` — and nobody had ever demonstrated it. It is a guard on an
     answer, not on a defect. Sections B and D are the ones that were red.

Run it directly, or through `run_tests.sh`.
"""
import collections
import concurrent.futures as cf
import fcntl
import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Env, Report, PW, SRC                  # noqa: E402

#: The safe every section guesses at. User-class, so no escalation is needed
#: and the whole file runs unprivileged.
SAFE = "lab-kdbx41"

#: Enough concurrency to lose an increment. The finding was reproduced at 25
#: and 50; 50 costs about a second and a half here.
CONCURRENCY = 50

#: A short floor, so a section that makes fifty failed attempts is not fifty
#: times 0.75 s. This is a TEST SEAM the helper offers on purpose and refuses
#: on the production admin path — `fail_floor_seconds()` ignores it at euid 0
#: against the real registry. The floor itself is measured in
#: docs/STRESS-REPORT.md, not here.
FAST_FLOOR = {"COCKPIT_SECRETS_FAIL_FLOOR": "0.01"}


def _load_helper_module():
    """Import `secrets-admin` as a module. It has no `.py` extension and is a
    program, not a package, so this is the only way to reach the counter's own
    functions — which section D needs, because a per-safe cap keyed on twenty
    distinct principals cannot be built out of one unprivileged uid."""
    loader = importlib.machinery.SourceFileLoader(
        "secrets_admin_under_test", os.path.join(SRC, "secrets-admin"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _state_dir(env):
    return os.path.join(env.var, "state")


def _counter(env, uid=None, safe=SAFE):
    """The per-principal counter document, or {}."""
    uid = os.getuid() if uid is None else uid
    path = os.path.join(_state_dir(env), "fail.%d.%s.json" % (uid, safe))
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _window(env, safe=SAFE):
    """The per-safe rate-cap document, or {}."""
    path = os.path.join(_state_dir(env), "safe.%s.json" % safe)
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _files(env):
    d = _state_dir(env)
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def _guess(env, i):
    """ONE wrong passphrase, in its own helper process."""
    out, _rc, _err = env.run("unlock",
                             {"safe": SAFE, "password": "wrong-%d" % i},
                             extra_env=FAST_FLOOR)
    return out.get("error") or ("ok" if out.get("handle") else "unexpected")


# ------------------------------------------------------------ A: control ---

def control(env, r):
    r.section("A — the sequential control: eight wrong guesses, one at a time")
    env.clear_lockout()
    outcomes = [_guess(env, i) for i in range(8)]
    counts = collections.Counter(outcomes)
    r.check("the first guess is evaluated (bad-credential)",
            outcomes[0] == "bad-credential", outcomes[0])
    r.check("exactly one guess was evaluated",
            counts.get("bad-credential") == 1, dict(counts))
    r.check("the other seven were refused by the open window",
            counts.get("locked-out") == 7, dict(counts))
    doc = _counter(env)
    r.check("the counter records exactly the one evaluated attempt",
            doc.get("failures") == 1, doc)
    return dict(counts)


# ------------------------------------------------- B: I39, the real race ---

def concurrency(env, r, reference):
    r.section("B — I39: %d helper PROCESSES fired at once" % CONCURRENCY)
    env.clear_lockout()
    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        outcomes = list(pool.map(lambda i: _guess(env, i),
                                 range(CONCURRENCY)))
    counts = collections.Counter(outcomes)
    evaluated = counts.get("bad-credential", 0)
    doc = _counter(env)

    r.check("every helper answered with a taxonomy code",
            set(counts) <= {"bad-credential", "locked-out"}, dict(counts))
    # THE ASSERTION THIS FILE EXISTS FOR. Not "the counter is small" and not
    # "few got through" — the counter must equal the number of attempts that
    # were actually evaluated, exactly. A lost update makes these two numbers
    # differ and nothing else does.
    r.check("the counter is EXACT: failures == attempts evaluated",
            doc.get("failures") == evaluated,
            "failures=%s evaluated=%d  %s"
            % (doc.get("failures"), evaluated, dict(counts)))
    r.check("concurrent is indistinguishable from sequential",
            evaluated == reference.get("bad-credential"),
            "concurrent evaluated %d, sequential evaluated %s"
            % (evaluated, reference.get("bad-credential")))
    r.check("the threshold held: no more attempts than the sequential control",
            evaluated <= reference.get("bad-credential", 0), evaluated)
    win = _window(env)
    r.check("the per-safe window counted the same attempts",
            win.get("window_count") == evaluated,
            "window=%s evaluated=%d" % (win.get("window_count"), evaluated))
    r.check("one counter file per principal, one window file per safe",
            _files(env) == ["fail.%d.%s.json" % (os.getuid(), SAFE),
                            "safe.%s.json" % SAFE], _files(env))


# ------------------------------------------------------- C: the give-back ---

def give_back(env, r):
    r.section("C — an attempt that consumed no guess is given back")
    env.clear_lockout()
    # No `password` key at all: refused by `_password_secret` before any
    # backend is constructed, so no derivation happens and no guess is spent.
    codes = []
    for _ in range(25):
        out, _rc, _err = env.run("unlock", {"safe": SAFE},
                                 extra_env=FAST_FLOOR)
        codes.append(out.get("error"))
    counts = collections.Counter(codes)
    r.check("all 25 credential-free requests answer invalid",
            counts.get("invalid") == 25, dict(counts))
    doc, win = _counter(env), _window(env)
    r.check("the per-principal counter did not move",
            doc.get("failures", 0) == 0, doc)
    r.check("the per-safe window did not move",
            win.get("window_count", 0) == 0, win)
    # …and the safe still opens, which is the point: 25 empty requests must
    # not be a way to deny a safe to the operator who owns it.
    out, _rc, _err = env.run("unlock", {"safe": SAFE, "password": PW},
                             extra_env=FAST_FLOOR)
    r.check("the correct passphrase still opens the safe afterwards",
            bool(out.get("handle")),
            {k: v for k, v in out.items() if k != "handle"})


# ------------------------------------------------------- D: the safe cap ---

def safe_cap(env, r):
    r.section("D — the per-safe rate cap, against %d synthetic principals"
              % 25)
    mod = _load_helper_module()
    # Named explicitly rather than assumed. Run against a helper that predates
    # this fix, the section has to REPORT that the mechanism is absent — a
    # traceback here would take sections D and E down with it and the run would
    # say less about the defect than it does now.
    for name in ("lockout_begin", "lockout_settle", "lockout_reset",
                 "LOCKOUT_SAFE_THRESHOLD", "LOCKOUT_SAFE_WINDOW"):
        if not hasattr(mod, name):
            r.check("the helper has a per-safe attempt cap (%s)" % name,
                    False, "absent from this build of secrets-admin")
            return
    root = tempfile.mkdtemp(prefix="cs-lockout-cap-")
    try:
        os.chmod(root, 0o700)
        os.environ["COCKPIT_SECRETS_VAR"] = root
        # init_state is memoised; this module was just imported fresh, so it
        # resolves against the directory above and nothing else on the host.
        ident = mod.Identity()
        report = mod.init_state(ident)
        r.check("the synthetic state directory resolved",
                report["state_persisted"], report["state_dir"])

        def as_uid(uid):
            who = mod.Identity()
            who.real_uid = uid
            return who

        allowed, refused = 0, 0
        for i in range(25):
            try:
                mod.lockout_begin(as_uid(9000 + i), "zz-cap-probe")
                allowed += 1
            except mod.LockedOut:
                refused += 1
        r.check("the cap admitted exactly LOCKOUT_SAFE_THRESHOLD attempts",
                allowed == mod.LOCKOUT_SAFE_THRESHOLD,
                "allowed=%d refused=%d threshold=%d"
                % (allowed, refused, mod.LOCKOUT_SAFE_THRESHOLD))
        r.check("a fresh identity does NOT get a fresh allowance past the cap",
                refused == 25 - mod.LOCKOUT_SAFE_THRESHOLD,
                "refused=%d" % refused)
        # I40's property, stated as a count: TWENTY-FIVE separate counter
        # files, one per principal, nobody sharing. The five the cap turned
        # away are there too and read zero, because a reservation that was
        # refused is given back rather than charged.
        names = sorted(os.listdir(os.path.join(root, "state")))
        fails = [n for n in names if n.startswith("fail.")]
        live = 0
        for name in fails:
            with open(os.path.join(root, "state", name), encoding="utf-8") as fh:
                live += 1 if (json.load(fh).get("failures") or 0) > 0 else 0
        r.check("every principal got its OWN counter file — none shared (I40)",
                len(fails) == 25, "%d counter files for 25 principals"
                % len(fails))
        r.check("exactly the admitted attempts are recorded as live failures",
                live == allowed, "%d live of %d files" % (live, len(fails)))
        r.check("and there is exactly one per-safe window file",
                names.count("safe.zz-cap-probe.json") == 1, names)

        # The denial the cap can cause is bounded by ONE window, which is what
        # makes it safe to have at all. Rewinding the window start is the same
        # arithmetic the helper does when the window expires.
        path = os.path.join(root, "state", "safe.zz-cap-probe.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["window_start"] = time.time() - mod.LOCKOUT_SAFE_WINDOW - 1
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        try:
            mod.lockout_begin(as_uid(9999), "zz-cap-probe")
            lifted = True
        except mod.LockedOut:
            lifted = False
        r.check("the cap lifts when the window expires (bounded denial)",
                lifted, "window is %.0f s" % mod.LOCKOUT_SAFE_WINDOW)
    finally:
        os.environ.pop("COCKPIT_SECRETS_VAR", None)
        shutil.rmtree(root, ignore_errors=True)


# ----------------------------------------------------------- E: the reach ---

#: The extra fields each credential-bearing verb needs before it will look at
#: a credential at all. Several validate their own arguments first, which is
#: correct — an argument check costs no KDF — but it means a sweep sent bare
#: `{safe, password}` would measure argument validation and call it a lockout.
#: The values are deliberately nonsense: a locked-out verb must never get far
#: enough to mind.
VERB_ARGS = {
    "reveal": {"uuid": "0" * 32, "field": "password"},
    "totp": {"uuid": "0" * 32},
    "attach-list": {"uuid": "0" * 32},
    "attach-get": {"uuid": "0" * 32, "name": "x"},
    "add": {"entry": {"title": "x"}, "autosave": True},
    "edit": {"uuid": "0" * 32, "changes": {"title": "x"}, "autosave": True},
    "move": {"uuid": "0" * 32, "group": "0" * 32, "autosave": True},
    "rm": {"uuid": "0" * 32, "autosave": True},
    "group-add": {"name": "g", "autosave": True},
    "group-rm": {"uuid": "0" * 32, "autosave": True},
    "group-mv": {"uuid": "0" * 32, "parent": "0" * 32, "autosave": True},
    "history": {"uuid": "0" * 32},
    "history-restore": {"uuid": "0" * 32, "index": 0, "autosave": True},
    "attach-add": {"uuid": "0" * 32, "name": "x", "data_b64": "eA==",
                   "autosave": True},
    "attach-rm": {"uuid": "0" * 32, "name": "x", "autosave": True},
    "save-as": {"name": "copy.kdbx"},
    "export": {"fmt": "csv", "confirm": "EXPORT-PLAINTEXT"},
}

#: Verbs that consume no credential. They must NOT be refused: the lockout is a
#: brake on guessing, and a `probe` or a `backups` listing is not a guess.
CREDENTIAL_FREE_VERBS = (
    ("probe", {"safe": SAFE}),
    ("backups", {"safe": SAFE}),
    ("restore-backup", {"safe": SAFE, "name": "nope"}),
    ("list", {}),
    ("health", {}),
    ("audit-tail", {"n": 1}),
)


def _arm_hard_window(env, r):
    """Open the HARD (300 s) window the honest way: LOCKOUT_THRESHOLD real
    failed unlocks, waiting out each escalating window in between.

    No state file is edited by hand. A sweep of twenty verbs cannot fit inside
    the 2 s window one failure opens, and forging a longer one on disk would
    make this section a test of a document rather than of the mechanism.
    """
    env.clear_lockout()
    for i, wait in enumerate((2, 4, 8, 16, 0)):
        out, _rc, _err = env.run("unlock",
                                 {"safe": SAFE, "password": "arm-%d" % i},
                                 extra_env=FAST_FLOOR)
        if out.get("error") != "bad-credential":
            r.check("arming failure %d was evaluated" % (i + 1), False, out)
            return False
        if wait:
            time.sleep(wait + 0.7)
    doc = _counter(env)
    return r.check("five real failures opened the hard window",
                   doc.get("failures") == 5
                   and doc.get("locked_until", 0) - time.time() > 250,
                   "failures=%s remaining=%.0fs"
                   % (doc.get("failures"),
                      doc.get("locked_until", 0) - time.time()))


def reach(env, r):
    r.section("E — the counter is on EVERY credential-consuming verb")
    if not _arm_hard_window(env, r):
        return

    # THE LIST COMES FROM THE SCHEMA, not from a list in this file. `schema` is
    # the single source of truth for the UI, so a verb added later that accepts
    # a passphrase appears here the day it is written — which is the only way
    # this answer stays true. The red team's question was "unlock, or all of
    # them?"; the answer is every verb the schema says takes a `password`.
    doc, _rc, _err = env.run("schema")
    credential = [v["id"] for v in doc.get("verbs", [])
                  if "password" in (v.get("request") or [])]
    r.check("the schema declares %d credential-bearing verbs"
            % len(credential), len(credential) >= 19, credential)

    for verb in credential:
        req = {"safe": SAFE, "password": PW}
        req.update(VERB_ARGS.get(verb, {}))
        out, _rc, _err = env.run(verb, req, extra_env=FAST_FLOOR)
        if verb == "export":
            # Admin-class, so on a user-class safe it is refused one gate
            # EARLIER than the counter and cannot be measured here. That it
            # never reaches a credential is the point; its lockout is the same
            # `need_backend` line every other verb uses, and it is measured at
            # a real euid 0 in tests/root/driver_lockout.py.
            r.check("`export` never reaches a credential on a user-class safe",
                    out.get("error") == "access-denied", out.get("error"))
            continue
        r.check("`%s` with a credential is refused: locked-out" % verb,
                out.get("error") == "locked-out",
                {k: out.get(k) for k in ("error", "detail")})

    for verb, req in CREDENTIAL_FREE_VERBS:
        out, _rc, _err = env.run(verb, dict(req), extra_env=FAST_FLOOR)
        r.check("`%s` consumes no credential and is NOT refused" % verb,
                out.get("error") != "locked-out", out.get("error"))

    after = _counter(env)
    r.check("none of those refusals moved the counter (no self-extension)",
            after.get("failures") == 5, after)


# ------------------------------------------------------- F: the wedge ------

def wedge(env, r):
    r.section("F — a held lock fails CLOSED, in bounded time")
    env.clear_lockout()
    # One real failure, to bring both state files into existence.
    env.run("unlock", {"safe": SAFE, "password": "prime"}, extra_env=FAST_FLOOR)
    path = os.path.join(_state_dir(env),
                        "fail.%d.%s.json" % (os.getuid(), SAFE))
    r.check("the counter file exists to be held", os.path.isfile(path), path)

    # A FOREIGN process holding the counter. This is the failure mode the fix
    # has to answer for: `flock` is the mechanism, so "somebody is holding it"
    # is the way to switch the mechanism off, and the answer must not be
    # "then the guess goes through".
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        started = time.monotonic()
        out, _rc, _err = env.run("unlock", {"safe": SAFE, "password": PW},
                                 extra_env=FAST_FLOOR, timeout=120)
        held = time.monotonic() - started
        r.check("a CORRECT passphrase is refused while the counter is held",
                out.get("error") == "locked-out", out)
        r.check("…and the refusal says so, rather than blaming the passphrase",
                "busy" in (out.get("detail") or ""), out.get("detail"))
        # LOCKOUT_LOCK_SECONDS is 5; the rest is process start-up. The bound is
        # the property — an unbounded wait would be a hang, which is the other
        # way a lock becomes a denial of service.
        r.check("the wait is BOUNDED, not indefinite", held < 20.0,
                "%.2f s" % held)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    out, _rc, _err = env.run("unlock", {"safe": SAFE, "password": PW},
                             extra_env=FAST_FLOOR)
    r.check("the lock is released and the safe opens immediately",
            bool(out.get("handle")),
            {k: v for k, v in out.items() if k != "handle"})
    # The other half of this property — a wedge must not stall a DIFFERENT
    # principal — needs two real uids at euid 0 and lives in the root suite.
    # Asserted as a real check rather than left as a comment, because a
    # sentence pointing at a test that has been deleted is worse than no
    # sentence: it reads like coverage.
    root = os.path.join(SRC, "tests", "root", "driver_lockout.py")
    try:
        with open(root, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        body = ""
    r.check("the two-principal wedge is covered in the root suite",
            "7 · a wedged counter" in body,
            "tests/root/driver_lockout.py section 7")


def main():
    env = Env().build()
    r = Report("I16's lockout: concurrency (I39), identity (I40), reach")
    try:
        reference = control(env, r)
        concurrency(env, r, reference)
        give_back(env, r)
        safe_cap(env, r)
        wedge(env, r)
        reach(env, r)
    finally:
        env.destroy()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
