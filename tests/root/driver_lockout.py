"""I40 — two administrators, two lockout counters, at a REAL euid 0.

docs/KNOWN_ISSUES.md I40. `_lockout_path()` built its file name from
`os.geteuid()`, and on the admin path every escalated operator is euid 0, so
one counter served every administrator of an admin-class safe. Operator A
mistyped once and operator B was then refused WITH THE CORRECT PASSPHRASE.

This is the only place that defect can be measured. Reaching euid 0 with a
DIFFERENT real caller behind it needs sudo/pkexec semantics: `unshare -r` gives
a real euid 0 but makes the real uid 0 as well, and cptest cannot escalate at
all. So the two-principal proof lives here, in the /srv/jobs root runner, where
`SUDO_UID` is believed because euid really is 0 and the class gate really runs.

WHAT IS MEASURED, in order:

  1. the counter's FILE NAME carries the real uid, not the euid. This is the
     defect stated as a fact about the filesystem.
  2. A mistypes, B offers the CORRECT passphrase and gets in. This is the
     defect stated as behaviour, and it is the check that was red before.
  3. A is still counted. Fixing "B is not locked out" by not counting anybody
     would pass check 2 and destroy I16, so A's own window is asserted to be
     open in the same breath.
  4. the per-safe cap exists and is shared, which is what stops an attacker at
     euid 0 handing the helper a fresh SUDO_UID for every guess.
  5. what actually bounds identity variation end to end: the CLASS GATE. A
     `SUDO_UID` that is not in an administrative group is refused before the
     counter is consulted at all, so the fresh counters an attacker can mint
     are limited to the administrators of this host — measured, not asserted.
  6. `export`, the one credential-bearing verb that is admin-class and
     therefore cannot be reached from the unprivileged suite, is refused
     `locked-out` while the window is open.
  7. a counter held open by a foreign process fails CLOSED, in bounded time,
     and does not stall a DIFFERENT principal. That last clause is the one
     that needs two real uids, and it is why the per-principal counter being a
     separate FILE per principal is a property and not an implementation
     detail.

Nothing here prints a value; `output.log` is group-readable (I15). The
passphrase is read from its 0600 tmpfs file and goes on the helper's stdin.
"""
import fcntl
import json
import os
import time
import secrets as pysecrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checklib                                       # noqa: E402
from checklib import base_env, brief, run             # noqa: E402

ADMIN_ID = "zz-throwaway-admin"
STATE_DIR = "/var/lib/cockpit-secrets/state"
PWFILE = "/run/cockpit-secrets-roottest/pw"

#: docs/HOST-FACTS.md fixes these. cpadmin and cptestadm are both in `sudo`;
#: cptest is not, and is the control for check 5.
UID_A = 1006          # cpadmin      — operator A, who mistypes
UID_B = 1007          # cptestadm    — operator B, who does not
UID_OUTSIDER = 1005   # cptest       — in no administrative group

#: `export` refuses without this, and it refuses BEFORE it looks at a
#: credential — so a section that sent the wrong token would measure argument
#: validation and call it a lockout. It is per-safe on purpose
#: (secrets-admin, EXPORT_CONFIRM_PREFIX): a confirmation the operator can
#: paste from one safe into another is not a confirmation.
CONFIRM = "export-plaintext:" + ADMIN_ID


def counter_path(uid, safe=ADMIN_ID):
    return os.path.join(STATE_DIR, "fail.%d.%s.json" % (uid, safe))


def window_path(safe=ADMIN_ID):
    return os.path.join(STATE_DIR, "safe.%s.json" % safe)


def doc_at(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _mode(path):
    """"0<mode> <uid>:<gid>" for a path, or None if it is not there. Never
    raises: a driver that aborts on a missing file cannot report what a
    pre-fix helper did instead of creating it."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return "0%o %d:%d" % (st.st_mode & 0o777, st.st_uid, st.st_gid)


def state_files(safe=ADMIN_ID):
    try:
        return sorted(n for n in os.listdir(STATE_DIR) if safe in n)
    except OSError:
        return []


def wipe(safe=ADMIN_ID):
    """Start from no counter at all. Root owns this directory; this is the
    operator's own lift-the-lockout action, and 90-cleanup.sh does the same."""
    for name in state_files(safe):
        try:
            os.unlink(os.path.join(STATE_DIR, name))
        except OSError:
            pass


def export_allowed(env, safe=ADMIN_ID):
    """What the helper says about this safe's export policy. `list` carries it;
    `probe` does not, which cost a root run to find out."""
    out, _rc, _e = run("list", env=env)
    for row in out.get("safes") or []:
        if row.get("id") == safe:
            return row.get("export_allowed")
    return None


def registry_entry_path(safe=ADMIN_ID):
    """The throwaway safe's registry file. Found by listing, not by the
    numeric prefix 30-throwaway-safes.sh happens to use today."""
    d = "/etc/cockpit-secrets/safes.d"
    try:
        names = sorted(n for n in os.listdir(d)
                       if n.endswith(".json") and safe in n)
    except OSError:
        return None
    return os.path.join(d, names[0]) if names else None


def write_registry(path, doc):
    """Replace a registry entry atomically, 0644 root:root. The helper refuses
    the WHOLE registry if a file in it is group-writable (I1), so the mode is
    set on the fd before the rename rather than after."""
    tmp = path + ".tmp-45"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                 0o644)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
    finally:
        pass
    os.replace(tmp, path)


def as_operator(uid, **extra):
    """The environment sudo/pkexec would hand the helper for that operator."""
    return base_env(SUDO_UID=uid, SUDO_GID=uid, **extra)


def body(rep):
    pw = checklib.read_passphrase(PWFILE)

    # =====================================================================
    rep.section("preconditions")
    # =====================================================================
    rep.check("running at a real euid 0", os.geteuid() == 0, os.geteuid())
    h, _rc, _e = run("health", env=as_operator(UID_A))
    ident = h.get("identity") or {}
    rep.check("the helper sees euid 0 with a DIFFERENT real caller behind it",
              ident.get("euid") == 0 and ident.get("real_uid") == UID_A
              and ident.get("escalated") is True, brief(ident))
    rep.check("the state directory is the root-owned one",
              (h.get("state") or {}).get("state_dir") == STATE_DIR,
              brief(h.get("state")))
    wipe()
    rep.check("no counter for this safe exists to start with",
              state_files() == [], state_files())

    # =====================================================================
    rep.section("1 · the counter is keyed on the REAL uid, not the euid")
    # =====================================================================
    out, _rc, _e = run("unlock",
                       {"safe": ADMIN_ID,
                        "password": "wrong-" + pysecrets.token_hex(4)},
                       env=as_operator(UID_A))
    rep.check("operator A's wrong passphrase is evaluated",
              out.get("error") == "bad-credential", brief(out))
    rep.check("the counter file names A's REAL uid (%d), not euid 0" % UID_A,
              os.path.exists(counter_path(UID_A)), counter_path(UID_A))
    rep.check("there is NO euid-keyed counter (the I40 file name)",
              not os.path.exists(counter_path(0)), counter_path(0))
    # `os.stat` on the file check 1 just said might not be there would abort
    # the driver, and sections 2 and 3 are the ones that show the DEFECT
    # rather than its file name. Against a pre-fix helper this reports and
    # carries on, which is what "watched it fail" needs it to do.
    mode_of = _mode(counter_path(UID_A))
    rep.check("A's counter is 0600 root-owned", mode_of == "0600 0:0",
              mode_of or "no such file")

    # =====================================================================
    rep.section("2 · A's typo does not lock B out — THE I40 CHECK")
    # =====================================================================
    out, rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                      env=as_operator(UID_B))
    opened = bool(out.get("handle"))
    rep.check("operator B, who has typed nothing, opens the safe with the "
              "correct passphrase",
              opened and rc == 0,
              brief({k: v for k, v in out.items() if k != "handle"}))
    rep.check("B's success did not need A's counter to be cleared",
              os.path.exists(counter_path(UID_A)), state_files())

    # =====================================================================
    rep.section("3 · …and A IS still counted (the fix is not 'count nobody')")
    # =====================================================================
    out, _rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                       env=as_operator(UID_A))
    rep.check("A is still inside their own backoff window, correct "
              "passphrase and all",
              out.get("error") == "locked-out", brief(out))
    doc = doc_at(counter_path(UID_A))
    rep.check("A's counter records exactly the one failure A made",
              (doc or {}).get("failures") == 1, brief(doc))
    rep.check("B has a counter of their own, and it is clear",
              (doc_at(counter_path(UID_B)) or {}).get("failures") in (0, None),
              brief(doc_at(counter_path(UID_B))))

    # =====================================================================
    rep.section("4 · the per-safe cap is SHARED, and counts both operators")
    # =====================================================================
    # The counter that no identity resets. It is what stops an attacker at
    # euid 0 handing the helper a fresh SUDO_UID for every guess, and the only
    # way to show it is shared is to move it from two different principals.
    wipe()
    counts = []
    for who in (UID_A, UID_B):
        run("unlock",
            {"safe": ADMIN_ID, "password": "wrong-" + pysecrets.token_hex(4)},
            env=as_operator(who))
        counts.append((doc_at(window_path()) or {}).get("window_count"))
    rep.check("A's failure opened a per-safe window at 1", counts[0] == 1,
              counts)
    rep.check("B's failure moved THE SAME window to 2 — it is shared",
              counts[1] == 2, counts)
    rep.check("…while A and B still have separate per-principal counters",
              (doc_at(counter_path(UID_A)) or {}).get("failures") == 1
              and (doc_at(counter_path(UID_B)) or {}).get("failures") == 1,
              brief([doc_at(counter_path(UID_A)),
                     doc_at(counter_path(UID_B))]))
    mode_of = _mode(window_path())
    rep.check("the shared window file is 0600 root-owned",
              mode_of == "0600 0:0", mode_of or "no such file")
    rep.note("The cap is a FIXED-WINDOW rate limit (%d attempts / %.0f s), "
             "not a second lockout: the longest denial anyone can cause with "
             "it is one window. A successful unlock clears it — somebody just "
             "proved they hold the key (I16)."
             % ((h.get("policy") or {}).get("lockout_safe_threshold", -1),
                (h.get("policy") or {}).get("lockout_safe_window_seconds", -1)))

    # =====================================================================
    rep.section("5 · what bounds identity variation: the class gate")
    # =====================================================================
    # The reason a per-real-uid counter is not simply "a counter an attacker
    # resets by changing one number": the number has to name somebody the
    # class gate will admit. Measured against a uid that exists and is not in
    # an administrative group, and against one that does not exist at all.
    before = set(state_files())
    for label, uid in (("cptest (exists, NOT in sudo)", UID_OUTSIDER),
                       ("a uid with no account at all", 4242)):
        out, _rc, _e = run("unlock",
                           {"safe": ADMIN_ID,
                            "password": "wrong-" + pysecrets.token_hex(4)},
                           env=as_operator(uid))
        rep.check("SUDO_UID=%s is refused BEFORE the counter: access-denied"
                  % label, out.get("error") == "access-denied", brief(out))
        rep.check("…and minted no counter file of its own",
                  not os.path.exists(counter_path(uid)),
                  _mode(counter_path(uid)) or "no such file")
    rep.check("the class gate added no state at all",
              set(state_files()) == before,
              sorted(set(state_files()) - before))
    rep.note("So the fresh counters an attacker at euid 0 can mint are one "
             "per ADMINISTRATOR of this host, not one per integer. The "
             "per-safe cap in section 4 is what bounds the rest.")

    # =====================================================================
    rep.section("6 · `export` — the admin-class credential verb")
    # =====================================================================
    # Every other credential-bearing verb is swept by
    # tests/integration/lockout.py section E. `export` is admin-class, so on
    # the user-class fixture safe it is refused one gate earlier and cannot be
    # measured there. Here it can — but only after the registry says this safe
    # may be exported at all, which is a SECOND operator decision `export`
    # checks before it ever looks at a credential. The entry is edited for the
    # length of this section and restored byte for byte in the `finally`,
    # because a throwaway safe left export-enabled is a throwaway safe whose
    # every credential can be written out in the clear by the next job.
    reg = registry_entry_path()
    original = None
    try:
        if reg is None:
            rep.check("the throwaway admin registry entry was found", False,
                      "no *zz-throwaway-admin*.json under the registry dir")
        else:
            with open(reg, "rb") as fh:
                original = fh.read()
            doc = json.loads(original.decode("utf-8"))
            doc["export_allowed"] = True
            write_registry(reg, doc)
            rep.check("the safe is temporarily export-enabled",
                      export_allowed(as_operator(UID_A)) is True,
                      "list -> export_allowed=%s"
                      % export_allowed(as_operator(UID_A)))

            wipe()
            out, _rc, _e = run(
                "unlock",
                {"safe": ADMIN_ID,
                 "password": "wrong-" + pysecrets.token_hex(4)},
                env=as_operator(UID_A))
            rep.check("one wrong guess opens A's window",
                      out.get("error") == "bad-credential", brief(out))
            out, _rc, _e = run("export",
                               {"safe": ADMIN_ID, "password": pw,
                                "fmt": "csv", "confirm": CONFIRM},
                               env=as_operator(UID_A))
            rep.check("`export` with the CORRECT passphrase is refused: "
                      "locked-out", out.get("error") == "locked-out",
                      brief(out))
            out, _rc, _e = run("export",
                               {"safe": ADMIN_ID, "password": pw,
                                "fmt": "csv", "confirm": CONFIRM},
                               env=as_operator(UID_B))
            rep.check("…and B, who did not mistype, may still export",
                      out.get("error") is None, brief(out))
    finally:
        if original is not None:
            with open(reg, "wb") as fh:
                fh.write(original)
            os.chmod(reg, 0o644)
            rep.check("the registry entry is restored: export is refused again",
                      export_allowed(as_operator(UID_A)) is False,
                      "list -> export_allowed=%s"
                      % export_allowed(as_operator(UID_A)))

    # =====================================================================
    rep.section("7 · a wedged counter must not lock every other principal out")
    # =====================================================================
    # `flock` is the mechanism the I39 fix rests on, so "hold that file open"
    # is the way to try to switch it off, and there are two ways that could go
    # wrong. It could fail OPEN — the guess goes through because the counter
    # was busy — which would make the lockout optional. Or it could fail
    # BROADLY — one stuck helper freezing every operator — which is the denial
    # of service a shared lock invites. Neither, measured:
    wipe()
    run("unlock", {"safe": ADMIN_ID, "password": "prime-" + pysecrets.token_hex(4)},
        env=as_operator(UID_A))
    path = counter_path(UID_A)
    rep.check("A's counter exists to be held", os.path.isfile(path), path)
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        t0 = time.monotonic()
        out, _rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                           env=as_operator(UID_A))
        held = time.monotonic() - t0
        rep.check("A is refused with the CORRECT passphrase — fail closed",
                  out.get("error") == "locked-out", brief(out))
        rep.check("…and the detail says the counter was busy, not that the "
                  "passphrase was wrong",
                  "busy" in (out.get("detail") or ""),
                  (out.get("detail") or "")[:90])
        rep.check("the wait is bounded, not a hang", held < 20.0,
                  "%.2f s" % held)

        t0 = time.monotonic()
        out, _rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                           env=as_operator(UID_B))
        other = time.monotonic() - t0
        rep.check("operator B is UNAFFECTED by the wedge on A's counter",
                  bool(out.get("handle")),
                  brief({k: v for k, v in out.items() if k != "handle"}))
        rep.check("…and was not even slowed by it", other < held / 2.0,
                  "B %.2f s vs A %.2f s" % (other, held))
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    out, _rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                       env=as_operator(UID_A))
    rep.check("the lock is released and A gets in again",
              bool(out.get("handle")),
              brief({k: v for k, v in out.items() if k != "handle"}))

    # =====================================================================
    rep.section("cleanup")
    # =====================================================================
    # The exports this section wrote hold every credential in the throwaway
    # safe in plaintext. They are removed here rather than left for
    # 90-cleanup.sh: an artefact like that must not outlive the check that
    # made it, even by one job.
    removed = 0
    expdir = "/var/lib/cockpit-secrets/exports"
    for name in sorted(os.listdir(expdir)) if os.path.isdir(expdir) else []:
        if ADMIN_ID in name:
            try:
                os.unlink(os.path.join(expdir, name))
                removed += 1
            except OSError:
                pass
    rep.note("removed %d export artefact(s) from %s" % (removed, expdir))
    wipe()
    rep.check("the lockout state this job created is gone",
              state_files() == [], state_files())


if __name__ == "__main__":
    checklib.main_guard(body)("45 · I40 — two administrators, two counters")
