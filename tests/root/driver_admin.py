"""The ADMIN access class, proved from the ALLOWING side, as euid 0.

Everything before this ran unescalated and measured refusals. A refusal on its
own proves nothing — a helper that refused every verb would pass every one of
those tests. This driver is the other half: root opens an admin-class safe,
reads it, changes it, saves it, and the change is still there when a second
process opens the file again.

It runs as root, inside a /srv/jobs job whose `output.log` is group-readable,
so it prints verdicts and shapes and never a value (I15). The canary password
it writes into the safe is generated at run time precisely so that grepping the
audit log for it means something: a constant committed in this file would be a
canary an old log could satisfy.

Sections, in the order they run:

    A  identity, as direct root
    B  unlock -> read -> mutate -> save -> lock, in one open session
    C  the root-owned state and audit directories
    D  SUDO_UID / PKEXEC_UID: which real caller the helper believes
    E  the registry's `groups` gate, which is a SECOND condition
    F  the user class is refused AT euid 0, from the other direction
    G  the lockout counter (I16), including who can clear it
"""
import json
import os
import re
import secrets as pysecrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checklib                                      # noqa: E402
from checklib import Session, base_env, brief, run    # noqa: E402

ADMIN_ID = "zz-throwaway-admin"
NOGRP_ID = "zz-throwaway-nogroup"
USER_ID = "zz-throwaway-user"
PWFILE = "/run/cockpit-secrets-roottest/pw"

STATE_DIR = "/var/lib/cockpit-secrets/state"
LOG_DIR = "/var/log/cockpit-secrets"
AUDIT = os.path.join(LOG_DIR, "audit.log")
ADMIN_SAFE = "/etc/cockpit-secrets/safes/%s.kdbx" % ADMIN_ID

UID_CPTEST = 1005       # not in `sudo`
UID_CPADMIN = 1006      # in `sudo`
UID_CPTESTADM = 1007    # in `sudo`

#: docs/CONTRACT.md fixes this set. The audit line is built from it, so a line
#: with an extra key is a line carrying something the taxonomy never sanctioned.
AUDIT_KEYS = {"ts", "verb", "safe", "uid", "euid", "outcome", "note",
              "duration_ms", "pid", "session", "artifact", "rows"}


def mode_of(path):
    st = os.stat(path)
    return "0%o %d:%d" % (st.st_mode & 0o777, st.st_uid, st.st_gid)


def as_cptest(argv):
    """Run argv as cptest and return (rc, combined output).

    `cd /` is already done by the job script: the job's working directory is
    its outbox folder, `root:users`, and cptest is not in `users`, so a child
    that inherited that cwd would fail to start for the wrong reason.
    """
    p = subprocess.run(["runuser", "-u", "cptest", "--"] + list(argv),
                       capture_output=True, text=True, cwd="/", timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


def lock_path():
    return os.path.join(STATE_DIR, "fail.0.%s.json" % ADMIN_ID)


def lock_doc():
    try:
        with open(lock_path()) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def seconds_from_detail(detail):
    m = re.search(r"(\d+) seconds", str(detail or ""))
    return int(m.group(1)) if m else -1


def body(rep):
    pw = checklib.read_passphrase(PWFILE)
    canary = "canary-" + pysecrets.token_hex(8)
    title = "root-verification-" + pysecrets.token_hex(4)

    # =====================================================================
    rep.section("A · identity, as direct root")
    # =====================================================================
    out, rc, err = run("health", env=base_env())
    ident = out.get("identity") or {}
    rep.check("health exits 0", rc == 0, rc)
    rep.check("stderr is silent for a root helper on an installed tree",
              err.strip() == "", err.strip()[:160])
    rep.check("euid is 0", ident.get("euid") == 0, ident.get("euid"))
    rep.check("real_uid is 0 with no escalation hint set",
              ident.get("real_uid") == 0, ident.get("real_uid"))
    rep.check("escalated is false for direct root",
              ident.get("escalated") is False, ident.get("escalated"))
    rep.check("the detected admin group is `sudo` (this host has no `wheel`)",
              ident.get("admin_group") == "sudo", ident.get("admin_group"))
    rep.check("class_available is admin",
              ident.get("class_available") == "admin",
              ident.get("class_available"))

    # =====================================================================
    rep.section("B · unlock, read, mutate, save — one open session as root")
    # =====================================================================
    st_before = os.stat(ADMIN_SAFE)
    audit_before = os.path.getsize(AUDIT) if os.path.exists(AUDIT) else 0

    ses = Session(env=base_env())
    rep.check("the session opens with a banner frame",
              ses.banner.get("frame") == "banner", brief(ses.banner))

    u = ses.call("unlock", safe=ADMIN_ID, password=pw)
    handle = u.get("handle")
    rep.check("root UNLOCKS the admin-class safe", bool(handle),
              brief({k: v for k, v in u.items() if k != "handle"}))
    # Counted, not hardcoded: this driver ADDS an entry and saves, so a second
    # run would meet a safe with one more entry in it. The assertion that
    # matters is the DELTA after the save, which is checked below.
    entries_before = u.get("entries_total")
    rep.check("the unlock reports the safe's contents",
              isinstance(entries_before, int) and entries_before >= 1
              and u.get("groups_total") == 2,
              brief({"entries_total": entries_before,
                     "groups_total": u.get("groups_total")}))

    tree = ses.call("tree", handle=handle)
    groups = tree.get("groups") or []
    target = next((g for g in groups if g.get("name") == "Throwaway"), None)
    rep.check("tree returns the seeded group", target is not None,
              [g.get("name") for g in groups])

    ent = ses.call("entries", handle=handle, limit=50)
    rows = ent.get("entries") or []
    rep.check("entries lists the seed entry",
              any(r.get("title") == "seed-entry" for r in rows),
              brief({"total": ent.get("total")}))
    # docs/CONTRACT.md: the listing carries NO passwords. Asserted here rather
    # than trusted, because this is the listing a root helper just produced.
    rep.check("no listing row carries a password field",
              all("password" not in r for r in rows),
              sorted({k for r in rows for k in r}))

    add = ses.call("add", handle=handle, group=(target or {}).get("uuid"),
                   entry={"title": title, "username": "root-verification",
                          "password": canary,
                          "url": "https://root-verification.invalid"})
    uuid = add.get("uuid")
    rep.check("root ADDS an entry", bool(uuid), brief(add))
    rep.check("the add is in memory only until save (saved is false)",
              add.get("saved") is False, add.get("saved"))

    edited = ses.call("edit", handle=handle, uuid=uuid,
                      changes={"notes": "written by tests/root as euid 0"})
    rep.check("root EDITS the entry", edited.get("changed") == ["notes"],
              brief(edited))

    rev = ses.call("reveal", handle=handle, uuid=uuid, field="password")
    # The comparison is the check. The value is never printed — not even a
    # prefix of it — because this log is group-readable.
    rep.check("reveal returns exactly the password that was written",
              rev.get("value") == canary,
              brief({k: v for k, v in rev.items() if k != "value"}))

    saved = ses.call("save", handle=handle)
    rep.check("root SAVES the safe", saved.get("ok") is True, brief(saved))
    rep.check("the save reports no conflict", saved.get("conflict") is False,
              saved.get("conflict"))
    backup = saved.get("backup")
    rep.check("the save took a backup first (I12)",
              bool(backup) and os.path.exists(backup or ""), backup)
    if backup and os.path.exists(backup):
        bst = os.stat(backup)
        rep.check("the backup is 0600 root-owned",
                  (bst.st_mode & 0o777) == 0o600 and bst.st_uid == 0,
                  mode_of(backup))

    locked = ses.call("lock", handle=handle)
    rep.check("lock drops the handle", locked.get("ok") is True, brief(locked))
    rest, serr, src = ses.close()
    rep.check("the session closes cleanly", src == 0,
              brief({"rc": src, "last": rest.strip()[:120]}))
    rep.check("the session wrote nothing to stderr", serr.strip() == "",
              serr.strip()[:160])

    st_after = os.stat(ADMIN_SAFE)
    rep.check("the safe on disk actually changed",
              st_after.st_mtime_ns != st_before.st_mtime_ns,
              "%d -> %d bytes" % (st_before.st_size, st_after.st_size))
    rep.check("the safe is still 0600 root:root after a root save",
              (st_after.st_mode & 0o777) == 0o600 and st_after.st_uid == 0,
              mode_of(ADMIN_SAFE))

    # A handle is single-process and dies with the helper (docs/CONTRACT.md).
    # Presenting the dead one from a NEW process is the check that the
    # "prompted every time" default is structural and not a policy.
    out, rc, _err = run("entries", {"handle": handle}, env=base_env())
    rep.check("the handle is dead in a new process",
              out.get("error") in ("access-denied", "not-found") and rc != 0,
              brief(out))

    # The real proof of the save: a SECOND helper process opens the file again.
    ses2 = Session(env=base_env())
    u2 = ses2.call("unlock", safe=ADMIN_ID, password=pw)
    h2 = u2.get("handle")
    rep.check("a second process re-unlocks the saved safe", bool(h2),
              brief({k: v for k, v in u2.items() if k != "handle"}))
    rep.check("the safe now holds exactly one more entry than before the save",
              u2.get("entries_total") == entries_before + 1,
              "%s -> %s" % (entries_before, u2.get("entries_total")))
    rows2 = (ses2.call("entries", handle=h2, limit=50).get("entries") or [])
    match = next((r for r in rows2 if r.get("title") == title), None)
    rep.check("the added entry survived the save", match is not None,
              brief({"titles": len(rows2)}))
    if match:
        rv2 = ses2.call("reveal", handle=h2, uuid=match["uuid"], field="password")
        rep.check("its password reads back byte-identical after the round trip",
                  rv2.get("value") == canary, "compared, not printed")
    ses2.call("lock", handle=h2)
    ses2.close()

    # =====================================================================
    rep.section("C · the root-owned state and audit directories")
    # =====================================================================
    for path, want in ((STATE_DIR, 0o700), (LOG_DIR, 0o700)):
        st = os.stat(path)
        rep.check("%s is 0%o root-owned" % (path, want),
                  (st.st_mode & 0o777) == want and st.st_uid == 0 and st.st_gid == 0,
                  mode_of(path))
    rep.check("the audit log exists", os.path.exists(AUDIT), AUDIT)
    ast = os.stat(AUDIT)
    rep.check("the audit log is 0600 root:root",
              (ast.st_mode & 0o777) == 0o600 and ast.st_uid == 0 and ast.st_gid == 0,
              mode_of(AUDIT))
    rep.check("the root path actually appended to it",
              ast.st_size > audit_before,
              "%d -> %d bytes" % (audit_before, ast.st_size))

    with open(AUDIT, "r", errors="replace") as fh:
        raw = fh.read()
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    parsed, badkeys = [], []
    for ln in lines:
        try:
            doc = json.loads(ln)
        except ValueError:
            badkeys.append("unparseable")
            continue
        parsed.append(doc)
        if set(doc) != AUDIT_KEYS:
            badkeys.append(sorted(set(doc) ^ AUDIT_KEYS))
    rep.check("every audit line is one JSON object with exactly the fixed keys",
              not badkeys, badkeys[:3])
    rep.check("the audit log contains no traceback",
              "Traceback" not in raw and "File \"" not in raw)
    # The two canaries. Neither is a real secret; both are values, and a value
    # in this file would be I15 failing.
    rep.check("the passphrase does not appear in the audit log", pw not in raw)
    rep.check("the canary password does not appear in the audit log",
              canary not in raw)
    rep.check("the entry title does not appear in the audit log",
              title not in raw)
    rep.check("no audit line carries a value-shaped key",
              not any(k in doc for doc in parsed
                      for k in ("value", "password", "title", "detail",
                                "traceback")))
    save_lines = [d for d in parsed
                  if d.get("verb") == "save" and d.get("safe") == ADMIN_ID]
    rep.check("the root save is recorded with uid 0 and euid 0",
              any(d.get("uid") == 0 and d.get("euid") == 0
                  and d.get("outcome") == "ok" for d in save_lines),
              brief(save_lines[-1]) if save_lines else "no save line")

    out, rc, _err = run("audit-tail", argv=["--n", "5"], env=base_env())
    tail = out.get("entries") or []
    rep.check("audit-tail returns metadata only",
              rc == 0 and tail and all(set(e) <= AUDIT_KEYS for e in tail),
              brief({"n": len(tail)}))

    # =====================================================================
    rep.section("D · SUDO_UID / PKEXEC_UID — which real caller is believed")
    # =====================================================================
    # Every row runs at euid 0 against the SAME admin safe with `probe`, which
    # gates but needs no credential, so a row can neither be explained by a
    # wrong password nor move the lockout counter.
    #
    # The helper reads SUDO_UID first and stops at the first usable value
    # (secrets-admin, class Identity), so the two mixed rows are the ones that
    # pin the ORDER rather than merely the effect.
    matrix = [
        ("no escalation hint at all", {}, 0, True),
        ("SUDO_UID=cpadmin (in sudo)", {"SUDO_UID": UID_CPADMIN},
         UID_CPADMIN, True),
        ("SUDO_UID=cptestadm (in sudo)", {"SUDO_UID": UID_CPTESTADM},
         UID_CPTESTADM, True),
        ("SUDO_UID=cptest (NOT in sudo) — refused at euid 0",
         {"SUDO_UID": UID_CPTEST}, UID_CPTEST, False),
        ("PKEXEC_UID=cpadmin (in sudo)", {"PKEXEC_UID": UID_CPADMIN},
         UID_CPADMIN, True),
        ("PKEXEC_UID=cptest (NOT in sudo)", {"PKEXEC_UID": UID_CPTEST},
         UID_CPTEST, False),
        ("SUDO_UID=cpadmin + PKEXEC_UID=cptest — SUDO_UID wins",
         {"SUDO_UID": UID_CPADMIN, "PKEXEC_UID": UID_CPTEST},
         UID_CPADMIN, True),
        ("SUDO_UID=cptest + PKEXEC_UID=cpadmin — SUDO_UID wins",
         {"SUDO_UID": UID_CPTEST, "PKEXEC_UID": UID_CPADMIN},
         UID_CPTEST, False),
        ("SUDO_UID is not a number — ignored, caller stays root",
         {"SUDO_UID": "not-a-number"}, 0, True),
        ("SUDO_UID=0 — ignored, caller stays root", {"SUDO_UID": "0"}, 0, True),
        ("SUDO_UID names a uid with no account — refused",
         {"SUDO_UID": "424242"}, 424242, False),
    ]
    for name, over, want_uid, want_allow in matrix:
        env = base_env(**over)
        h, _rc, _e = run("health", env=env)
        got_uid = (h.get("identity") or {}).get("real_uid")
        rep.check("real caller for [%s]" % name, got_uid == want_uid,
                  "real_uid=%s escalated=%s"
                  % (got_uid, (h.get("identity") or {}).get("escalated")))
        out, rc, _e = run("probe", {"safe": ADMIN_ID}, env=env)
        if want_allow:
            rep.check("ADMITTED: %s" % name,
                      rc == 0 and out.get("format") == "kdbx", brief(out))
        else:
            rep.check("REFUSED: %s" % name,
                      rc != 0 and out.get("error") == "access-denied", brief(out))

    # The allowing side, end to end, for an ESCALATED caller rather than direct
    # root: cpadmin's uid behind the escalation genuinely opens the safe.
    env = base_env(SUDO_UID=UID_CPADMIN)
    ses3 = Session(env=env)
    u3 = ses3.call("unlock", safe=ADMIN_ID, password=pw)
    rep.check("an escalated `sudo` member (cpadmin) really unlocks the safe",
              bool(u3.get("handle")),
              brief({k: v for k, v in u3.items() if k != "handle"}))
    if u3.get("handle"):
        ses3.call("lock", handle=u3["handle"])
    ses3.close()

    # ... and the refusal it is paired with is recorded against the RIGHT uid.
    with open(AUDIT, "r", errors="replace") as fh:
        recent = [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]
    denied = [d for d in recent
              if d.get("safe") == ADMIN_ID and d.get("outcome") == "access-denied"
              and d.get("uid") == UID_CPTEST]
    rep.check("the refusal is audited against the REAL caller (uid 1005, euid 0)",
              bool(denied) and denied[-1].get("euid") == 0,
              brief(denied[-1]) if denied else "no matching audit line")

    # =====================================================================
    rep.section("E · the registry `groups` gate is a second condition")
    # =====================================================================
    out, rc, _e = run("probe", {"safe": NOGRP_ID}, env=base_env())
    rep.check("direct root opens a safe whose `groups` names nobody — BY DESIGN",
              rc == 0 and out.get("format") == "kdbx", brief(out))
    rep.note("gate() treats uid 0 with no escalation behind it as "
             "administrative by definition; asking /etc/group whether uid 0 is "
             "in `sudo` would answer no on a normal host.")
    out, rc, _e = run("probe", {"safe": NOGRP_ID},
                      env=base_env(SUDO_UID=UID_CPADMIN))
    rep.check("an escalated `sudo` member is REFUSED that safe (wrong group)",
              rc != 0 and out.get("error") == "access-denied", brief(out))

    # =====================================================================
    rep.section("F · the user class is refused AT euid 0")
    # =====================================================================
    out, rc, _e = run("probe", {"safe": USER_ID}, env=base_env())
    rep.check("root may not probe a user-class safe",
              rc != 0 and out.get("error") == "access-denied", brief(out))
    out, rc, _e = run("unlock", {"safe": USER_ID, "password": pw},
                      env=base_env())
    rep.check("root may not unlock a user-class safe even with the passphrase",
              rc != 0 and out.get("error") == "access-denied", brief(out))
    rep.note("I2/I5: a root helper opening a file inside a directory the user "
             "controls is the symlink race, so the user class is served "
             "unescalated or not at all.")

    # =====================================================================
    rep.section("G · the lockout counter (I16)")
    # =====================================================================
    try:
        os.unlink(lock_path())
    except OSError:
        pass
    rep.check("the counter starts absent", not os.path.exists(lock_path()),
              lock_path())

    delays = [2, 4, 8, 16]
    for attempt in range(1, 6):
        out, rc, _e = run("unlock",
                          {"safe": ADMIN_ID, "password": "wrong-" + pysecrets.token_hex(4)},
                          env=base_env())
        rep.check("failed unlock %d answers bad-credential" % attempt,
                  out.get("error") == "bad-credential", brief(out))
        doc = lock_doc()
        rep.check("the counter records %d failure(s)" % attempt,
                  (doc or {}).get("failures") == attempt,
                  brief({"failures": (doc or {}).get("failures")}))
        if attempt == 1:
            st = os.stat(lock_path())
            rep.check("the counter file is 0600 root-owned",
                      (st.st_mode & 0o777) == 0o600 and st.st_uid == 0,
                      mode_of(lock_path()))
        # The window is open right now, and it is checked BEFORE the KDF, so a
        # correct passphrase is refused too. That is the property: the brake is
        # on the endpoint, not on the guess.
        out, rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                          env=base_env())
        rep.check("during the backoff even the CORRECT passphrase is refused",
                  out.get("error") == "locked-out", brief(out))
        if attempt < 5:
            time.sleep(delays[attempt - 1] + 0.6)

    out, _rc, _e = run("unlock", {"safe": ADMIN_ID, "password": pw},
                       env=base_env())
    remaining = seconds_from_detail(out.get("detail"))
    rep.check("at the threshold the lockout is the hard one (>= 250s left)",
              out.get("error") == "locked-out" and remaining >= 250,
              "remaining=%ss" % remaining)

    rc_, txt = as_cptest(["rm", "-f", lock_path()])
    rep.check("cptest CANNOT delete the counter", rc_ != 0, txt[:160])
    rep.check("the counter file is still there", os.path.exists(lock_path()))
    rc_, txt = as_cptest(["ls", "-a", STATE_DIR])
    rep.check("cptest cannot even list %s" % STATE_DIR, rc_ != 0, txt[:160])
    rc_, txt = as_cptest(["cat", lock_path()])
    rep.check("cptest cannot read the counter", rc_ != 0, txt[:160])

    # Only root can lift it, and lifting it restores service — which is what
    # makes the lockout a brake rather than a way to destroy access.
    os.unlink(lock_path())
    rep.check("root removed the counter and it is gone before the next unlock",
              not os.path.exists(lock_path()), lock_path())
    ses4 = Session(env=base_env())
    u4 = ses4.call("unlock", safe=ADMIN_ID, password=pw)
    rep.check("root cleared the counter and the safe opens again",
              bool(u4.get("handle")),
              brief({k: v for k, v in u4.items() if k != "handle"}))
    if u4.get("handle"):
        ses4.call("lock", handle=u4["handle"])
    ses4.close()

    # The property is "the counter no longer bites", not "the file is gone".
    # lockout_reset() unlinks and falls back to writing zeros if the unlink
    # raises - and ENOENT raises, so a successful unlock with no counter
    # present CREATES one holding {failures: 0, locked_until: 0}. That is
    # harmless (it is 0600, it carries no value, and lockout_check returns
    # immediately on it) but it is not what the docstring's "clears the
    # counter" leads you to expect, so it is measured and reported rather than
    # asserted away in either direction.
    doc = lock_doc()
    cleared = (doc is None
               or (doc.get("failures") in (0, None)
                   and float(doc.get("locked_until") or 0) <= time.time()))
    rep.check("a successful unlock leaves no live counter", cleared,
              brief({"exists": os.path.exists(lock_path()), "doc": doc}))
    if doc is not None:
        st = os.stat(lock_path())
        rep.check("the zeroed counter it wrote is still 0600 root-owned",
                  (st.st_mode & 0o777) == 0o600 and st.st_uid == 0,
                  mode_of(lock_path()))
        rep.note("NOTE: lockout_reset() re-created this file. os.unlink raised "
                 "ENOENT (nothing to clear) and the except branch writes a "
                 "zero counter regardless, so every first successful unlock "
                 "leaves one small 0600 JSON file per (uid, safe) in the "
                 "state directory. Harmless; recorded in "
                 "docs/ROOT-VERIFICATION.md.")
        os.unlink(lock_path())


if __name__ == "__main__":
    checklib.main_guard(body)("40 · the ADMIN class from the allowing side")
