"""The USER access class on the real host, run as cptest, unescalated.

The mirror of driver_admin.py. cptest is uid 1005 and is deliberately NOT in
`sudo` (docs/HOST-FACTS.md), so this process is the adversary of
docs/THREAT-MODEL.md A1/A2 with a legitimate safe of its own: it must be able
to do everything the user class promises and nothing the admin class holds.

The passphrase arrives on THIS PROCESS'S STDIN, piped in by the root job that
ran `runuser`. It is never a file cptest can read, never an argument and never
an environment variable — the 0600 passphrase file lives in a 0700 root-owned
directory cptest cannot even list, and that is checked below rather than
assumed. Reading it from a pipe is the same discipline the program itself
keeps for the browser -> helper hop (I10).

Nothing here prints a value. `output.log` is group-readable (I15).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checklib                                      # noqa: E402
from checklib import Session, base_env, brief, run    # noqa: E402

ADMIN_ID = "zz-throwaway-admin"
NOGRP_ID = "zz-throwaway-nogroup"
USER_ID = "zz-throwaway-user"

ADMIN_SAFE = "/etc/cockpit-secrets/safes/%s.kdbx" % ADMIN_ID
SAFES_DIR = "/etc/cockpit-secrets/safes"
SAFES_D = "/etc/cockpit-secrets/safes.d"
STATE_DIR = "/var/lib/cockpit-secrets/state"
LOG_DIR = "/var/log/cockpit-secrets"
AUDIT = os.path.join(LOG_DIR, "audit.log")
PW_RUNDIR = "/run/cockpit-secrets-roottest"

UID_CPTEST = 1005
UID_CPADMIN = 1006


def refused(rep, name, fn):
    """Assert `fn()` fails with a permission error from the KERNEL.

    A FileNotFoundError would pass a naive "it raised" test and would mean the
    opposite of what is being claimed, so the exception type is checked and
    reported. EACCES and EPERM both count; ENOENT explicitly does not.
    """
    try:
        fn()
    except PermissionError as exc:
        rep.check(name, True, "%s: %s" % (type(exc).__name__, exc.strerror))
        return
    except OSError as exc:
        rep.check(name, False,
                  "wrong error: %s %s" % (type(exc).__name__, exc.strerror))
        return
    rep.check(name, False, "the operation SUCCEEDED")


def body(rep):
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        raise SystemExit("no passphrase arrived on stdin")

    # =====================================================================
    rep.section("A · identity, unescalated")
    # =====================================================================
    out, rc, err = run("health", env=base_env())
    ident = out.get("identity") or {}
    state = out.get("state") or {}
    rep.check("health exits 0 for an unprivileged caller", rc == 0, rc)
    rep.check("euid is cptest", ident.get("euid") == UID_CPTEST, ident.get("euid"))
    rep.check("real_uid is cptest", ident.get("real_uid") == UID_CPTEST,
              ident.get("real_uid"))
    rep.check("escalated is false", ident.get("escalated") is False,
              ident.get("escalated"))
    rep.check("class_available is user, not admin",
              ident.get("class_available") == "user",
              ident.get("class_available"))
    # The root state directory is 0700, so an unprivileged helper cannot use
    # it and falls back to the caller's own. That is the design, and health
    # says so out loud rather than silently losing the audit trail.
    rep.check("state falls back to cptest's own directory",
              isinstance(state.get("state_dir"), str)
              and state.get("state_dir", "").startswith("/home/cptest"),
              brief({"state_dir": state.get("state_dir"),
                     "reason": state.get("reason")}))
    rep.check("cptest's audit log is not the root one",
              state.get("audit_log") != AUDIT, state.get("audit_log"))
    # stderr is expected to carry the mlockall note for a non-root helper —
    # that is I14 being reported honestly rather than pretended about.
    rep.note("helper stderr: %s" % (err.strip()[:160] or "(silent)"))

    # =====================================================================
    rep.section("B · cptest opens THEIR OWN safe, unescalated")
    # =====================================================================
    out, rc, _e = run("list", env=base_env())
    by = {s["id"]: s for s in (out.get("safes") or [])}
    # An admin safe is LISTED to cptest and marked unusable with a reason. That
    # is deliberate: the page is more honest saying "there is a safe here you
    # cannot open" than pretending it does not exist — and it is also the I3
    # test, because being listed is exactly what a browser-side check would
    # have been tempted to treat as permission.
    rep.check("the user-class safe is listed and usable",
              by.get(USER_ID, {}).get("usable") is True,
              brief(by.get(USER_ID)))
    rep.check("the admin-class safe is listed but NOT usable, with a reason",
              by.get(ADMIN_ID, {}).get("usable") is False
              and bool(by.get(ADMIN_ID, {}).get("reason")),
              brief(by.get(ADMIN_ID)))

    out, rc, _e = run("probe", {"safe": USER_ID}, env=base_env())
    rep.check("probe of the user-class safe succeeds",
              rc == 0 and out.get("format") == "kdbx", brief(out))

    ses = Session(env=base_env())
    u = ses.call("unlock", safe=USER_ID, password=pw)
    handle = u.get("handle")
    rep.check("cptest UNLOCKS their own safe with no escalation", bool(handle),
              brief({k: v for k, v in u.items() if k != "handle"}))

    rows = (ses.call("entries", handle=handle, limit=50).get("entries") or [])
    seed = next((r for r in rows if r.get("title") == "seed-entry"), None)
    rep.check("entries lists the seeded entry", seed is not None,
              brief({"rows": len(rows)}))
    if seed:
        rev = ses.call("reveal", handle=handle, uuid=seed["uuid"],
                       field="password")
        rep.check("reveal returns a non-empty password (compared, not printed)",
                  isinstance(rev.get("value"), str) and rev.get("value") != "",
                  brief({k: v for k, v in rev.items() if k != "value"}))
        add = ses.call("add", handle=handle, group=None,
                       entry={"title": "user-class-write", "username": "cptest",
                              "password": "not-a-real-secret"})
        rep.check("cptest may ADD to their own safe", bool(add.get("uuid")),
                  brief(add))
        saved = ses.call("save", handle=handle)
        rep.check("cptest may SAVE their own safe", saved.get("ok") is True,
                  brief(saved))
    ses.call("lock", handle=handle)
    ses.close()

    st = os.stat("/home/cptest/.local/share/cockpit-secrets/%s.kdbx" % USER_ID)
    rep.check("the saved safe is still 0600 and owned by cptest",
              (st.st_mode & 0o777) == 0o600 and st.st_uid == UID_CPTEST,
              "0%o %d:%d" % (st.st_mode & 0o777, st.st_uid, st.st_gid))

    # =====================================================================
    rep.section("C · cptest cannot reach the admin class through the helper")
    # =====================================================================
    for verb, req in (("probe", {"safe": ADMIN_ID}),
                      ("unlock", {"safe": ADMIN_ID, "password": pw}),
                      ("probe", {"safe": NOGRP_ID}),
                      ("unlock", {"safe": NOGRP_ID, "password": pw})):
        out, rc, _e = run(verb, req, env=base_env())
        rep.check("%s %s is refused" % (verb, req["safe"]),
                  rc != 0 and out.get("error") == "access-denied", brief(out))

    # The taxonomy is deliberately coarse (I6): a refusal must not double as an
    # oracle telling the caller whether the safe or the passphrase was the
    # problem. Both wrong-safe and wrong-passphrase answer access-denied here
    # because the class gate runs first.
    out, rc, _e = run("unlock", {"safe": ADMIN_ID, "password": "definitely-wrong"},
                      env=base_env())
    rep.check("a wrong passphrase for an admin safe is the SAME refusal",
              out.get("error") == "access-denied", brief(out))

    # =====================================================================
    rep.section("D · SUDO_UID is not a group membership (I3)")
    # =====================================================================
    # The single most important row in this file. An unprivileged caller can
    # set any environment variable they like; the helper reads SUDO_UID ONLY
    # when euid is already 0, so setting it here must change nothing at all.
    env = base_env(SUDO_UID=UID_CPADMIN, PKEXEC_UID=UID_CPADMIN,
                   SUDO_USER="cpadmin")
    out, rc, _e = run("health", env=env)
    ident = out.get("identity") or {}
    rep.check("SUDO_UID=cpadmin does NOT change the real caller below euid 0",
              ident.get("real_uid") == UID_CPTEST and ident.get("escalated") is False,
              brief({"real_uid": ident.get("real_uid"),
                     "escalated": ident.get("escalated"),
                     "euid": ident.get("euid")}))
    out, rc, _e = run("probe", {"safe": ADMIN_ID}, env=env)
    rep.check("...and the admin safe is still refused",
              rc != 0 and out.get("error") == "access-denied", brief(out))

    # =====================================================================
    rep.section("E · cptest cannot reach the files behind the helper either")
    # =====================================================================
    # The helper's refusals would be worth nothing if the same bytes were
    # readable directly. These are the kernel's answers, not the program's.
    refused(rep, "cannot read the admin safe file",
            lambda: open(ADMIN_SAFE, "rb").read(16))
    refused(rep, "cannot list %s (0700 root)" % SAFES_DIR,
            lambda: os.listdir(SAFES_DIR))
    refused(rep, "cannot read the root audit log",
            lambda: open(AUDIT, "rb").read(16))
    refused(rep, "cannot list %s (0700 root)" % LOG_DIR,
            lambda: os.listdir(LOG_DIR))
    refused(rep, "cannot list the root state directory",
            lambda: os.listdir(STATE_DIR))
    refused(rep, "cannot list the passphrase directory",
            lambda: os.listdir(PW_RUNDIR))
    refused(rep, "cannot read the throwaway passphrase file",
            lambda: open(os.path.join(PW_RUNDIR, "pw"), "rb").read())
    # safes.d is 0755 so it is READABLE - the registry is not a secret, it is a
    # policy. What matters is that it is not WRITABLE: an entry cptest could
    # write is an access-control policy cptest could grant themselves.
    rep.check("the registry directory is readable (it is policy, not a secret)",
              isinstance(os.listdir(SAFES_D), list))
    refused(rep, "cannot write a registry entry",
            lambda: open(os.path.join(SAFES_D, "99-zz-forged.json"), "w"))
    refused(rep, "cannot replace the installed helper",
            lambda: open("/usr/local/sbin/secrets-admin", "ab"))
    refused(rep, "cannot write into the helper's library root",
            lambda: open("/usr/local/lib/cockpit-secrets/backends/evil.py", "w"))


if __name__ == "__main__":
    checklib.main_guard(body)("50 · the USER class on the real host, as cptest")
