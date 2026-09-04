# Root verification — cockpit-secrets installed and proved on edt1

Everything before this ran unescalated and measured **refusals**. A refusal on
its own proves nothing: a helper that refused every verb would have passed all
of it. This is the record of the other half — the package installed on the real
host by root, and the admin access class exercised from the **allowing** side.

Run on **edt1, 2026-09-04**, by `tests/root/`, through the `/srv/jobs` inbox
runner. Every command below was actually executed and every output is real.
Anything that was not run is listed in **[Not attempted](#not-attempted)**, not
implied by silence.

    233 checks, 2 failures — both the same finding (F1), severity low.

| Step | Job in `/srv/jobs/outbox` | Checks | Verdict |
|---|---|---:|---|
| 1 · install as root | `cs-10-install.20260904-034310.956443` | 7 | **PASS** |
| 2 · audit the installation | `cs-20-verify-install.20260904-035016.988952` | 34 | **FAIL ×2** (F1) |
| 3 · throwaway safes + registry | `cs-30-throwaway-safes.20260904-034457.964863` | 11 | **PASS** |
| 4 · the ADMIN class, allowing side | `cs-40-admin-allow.20260904-034805.977465` | 98 | **PASS** |
| 5 · the USER class as `cptest` | `cs-50-user-class.20260904-034905.981843` | 34 | **PASS** |
| 6 · uninstall, diff, reinstall | `cs-60-uninstall-reinstall.20260904-034955.987517` | 35 | **PASS** |
| 7 · cleanup | `cs-90-cleanup.20260904-035026.989627` | 14 | **PASS** |

**The package is left INSTALLED.** The next agent needs it live for the browser
walkthrough. The throwaway safes and registry entries are gone; see
[What remains on the host](#what-remains-on-the-host).

**Reproducible.** The table above is the per-step run whose output is quoted
below. The whole suite was then run again end to end as one command
(`tests/root/run-all.sh`) and produced identical counts — 7 / 34 / 11 / 98 / 34
/ 35 / 14, with the same two F1 failures and nothing else — in jobs
`cs-*.20260904-0355*` through `cs-90-cleanup.20260904-035652.1026412`. The
suite is therefore re-runnable against a host it has already installed on: step
1 reports a re-install rather than a fresh one, and step 4's assertions are
deltas (`the safe now holds exactly one more entry than before the save`)
rather than absolute counts, which is what makes a second run mean the same
thing as the first.

---

## How this was run, and where the passphrase lived

Interactive `sudo` does not work on edt1 (`docs/HOST-FACTS.md`, "Root"), so
every privileged step is a job folder handed to the root-owned inbox runner:

    cd tests/root
    ./submit.sh --timeout 600 10-install.sh
    ./submit.sh --timeout 300 20-verify-install.sh
    ./submit.sh --timeout 300 30-throwaway-safes.sh
    ./submit.sh --timeout 900 40-admin-allow.sh
    ./submit.sh --timeout 300 50-user-class.sh
    ./submit.sh --timeout 600 60-uninstall-reinstall.sh
    ./submit.sh --timeout 300 90-cleanup.sh

(`tests/root/run-all.sh` does the same in one command.)

**The runner's `output.log` is group-readable by `users`**, so nothing in this
suite prints a passphrase, a safe's contents, a revealed value or an export
(I15). `checklib.scrub()` runs over everything the Python drivers print, and
every value assertion compares rather than displays — the reveal check reads
`reveal returns exactly the password that was written`, and the value itself
never appears.

**Which passphrase mechanism was used: a mode-0600 file, on tmpfs.**
`30-throwaway-safes.sh` generates a fresh passphrase with
`secrets.token_urlsafe(24)` written straight into a descriptor opened
`O_CREAT|O_EXCL, 0600` inside a `0700` root-owned directory under **`/run`**,
which is tmpfs — so it never touches persistent storage at all — and
`90-cleanup.sh` destroys it. Measured:

    ok   /run/cockpit-secrets-roottest       -> 700 root:root directory
    ok   /run/cockpit-secrets-roottest/pw    -> 600 root:root regular file

It was **generated rather than borrowed from the committed fixture constant**
(`tests/integration/_env.py`, `PW = "fixture-pass-do-not-reuse"`). Using that
one would have meant copying it into a job script staged under `/srv/jobs`,
which is group-readable — a value that exists only in tmpfs for the length of
the run cannot leak that way. Step 5 needs the passphrase **as `cptest`**, who
must not be able to read that file; root pipes the value into the driver's
stdin instead, and `driver_user.py` then asserts that cptest can neither list
the directory nor open the file.

`cockpit.socket` was never stopped, restarted or reloaded. Steps 1 and 2 record
`ActiveEnterTimestamp` and `InvocationID` before and after and compare them;
independently, after the whole run:

    $ systemctl show cockpit.socket -p ActiveEnterTimestamp -p InvocationID
    ActiveEnterTimestamp=Tue 2026-09-01 01:59:08 CDT
    InvocationID=f81f1b1cbb0e4d15aa444073f68cbdf3

Three days before any of this work started.

---

## 1 · Install — PASS

`install.sh` as root, on a host where nothing of this package existed:
`/usr/share/cockpit/secrets`, `/usr/local/sbin/secrets-admin`,
`/usr/local/lib/cockpit-secrets`, `/etc/cockpit-secrets`,
`/var/log/cockpit-secrets` and `/var/lib/cockpit-secrets` were all absent
beforehand (checked from an unprivileged shell; `ls` returned "No such file or
directory" for each).

    Pre-flight
      payload complete (4 package files, helper, backends, schema)
      manifest.json: valid JSON, no CSP relaxation (I9)
      python payload compiles (7 file(s))
      secrets.js           syntax OK
      registry schema + 2 example(s): valid (jsonschema)
    Installing
      + created /usr/share/cockpit/secrets (mode 0755)
      ... 24 changes ...
      + created /etc/cockpit-secrets/safes (mode 0700)
      + created /var/log/cockpit-secrets (mode 0700)
      + created /var/lib/cockpit-secrets/state (mode 0700)
      + created /var/lib/cockpit-secrets/exports (mode 0700)
      + seeded /etc/cockpit-secrets/safes.d/10-example-admin.json.example
      + seeded /etc/cockpit-secrets/safes.d/20-example-user.json.example
    Verifying
      backends import from /usr/local/lib/cockpit-secrets
      secrets-admin health: one JSON object, exit 0
    Summary
      24 change(s), 1 unchanged, 0 warning(s)

| Check | Result |
|---|---|
| `install.sh` exit status 0 | PASS |
| no `Action required` warnings (`  ! ` lines) | PASS — 0 |
| it reported its own smoke test | PASS |
| it reported `backends import from /usr/local/lib/cockpit-secrets` | PASS |
| `cockpit.socket` unchanged across the install | PASS |

## 2 · Audit of the installation — 32 PASS, 2 FAIL (F1)

Run as a **separate job**, deliberately: `install.sh` reports what it believes
it did, and a run that checked its own work would report the mode it intended
in both places.

### Paths, modes, owners — all PASS

    ok   /usr/share/cockpit/secrets           -> 755 root:root directory
    ok   /usr/local/sbin/secrets-admin        -> 755 root:root regular file
    ok   /usr/local/lib/cockpit-secrets       -> 755 root:root directory
    ok   /usr/local/lib/cockpit-secrets/backends -> 755 root:root directory
    ok   /usr/local/lib/cockpit-secrets/schema   -> 755 root:root directory
    ok   /etc/cockpit-secrets                 -> 755 root:root directory
    ok   /etc/cockpit-secrets/safes.d         -> 755 root:root directory
    ok   /etc/cockpit-secrets/safes           -> 700 root:root directory
    ok   /var/log/cockpit-secrets             -> 700 root:root directory
    ok   /var/lib/cockpit-secrets             -> 700 root:root directory
    ok   /var/lib/cockpit-secrets/state       -> 700 root:root directory
    ok   /var/lib/cockpit-secrets/exports     -> 700 root:root directory
    ok   /usr/share/cockpit/secrets holds exactly the package payload
         -> index.html manifest.json secrets.css secrets.js
    ok   ... each of the four is 644 root:root
    ok   /usr/local/lib/cockpit-secrets/schema holds exactly the source's *.json

### Nothing from `tests/` was installed — PASS

Three independent angles, because each alone has a hole:

    ok   no installed path has a 'tests' component
    ok   no installed file is byte-identical to anything under tests/
    ok   no safe, keyfile, corpus expectation or test artefact was installed

The middle check is by **SHA-256**, not by name. A basename comparison was
tried first and reported `manifest.json` — a false positive twice over, since
`tests/fixtures/manifest.json` and the Cockpit package manifest share nothing
but the word. Hashing asks the question that was meant.

### Permissions — all PASS

    ok   find -perm /022 over every installed path is empty
    ok   nothing installed is setuid or setgid
    ok   everything installed is owned root:root
    ok   the installation contains no symlinks

Roots scanned: `/usr/share/cockpit/secrets`, `/usr/local/lib/cockpit-secrets`,
`/usr/local/sbin/secrets-admin`, `/etc/cockpit-secrets`,
`/var/log/cockpit-secrets`, `/var/lib/cockpit-secrets`.

### The agent was not installed — PASS

`--with-agent` was not given, and I18's mitigation is "off by default", so its
absence is checked rather than assumed:

    ok   absent: /usr/local/lib/cockpit-secrets/agent
    ok   absent: /usr/local/lib/cockpit-secrets/secrets-agent
    ok   no secrets-agent systemd unit was installed  -> 0

### The installed helper resolves its installed library root — PASS

    ok   /usr/local/sbin/secrets-admin health exit status  -> 0
    ok   the installed helper emits no warning on stderr
    ok   library_root is the installed one   -> /usr/local/lib/cockpit-secrets
    ok   library_root_trusted is true        -> True
    ok   registry_root is /etc/cockpit-secrets
    ok   registry_errors is empty
    ok   both backends are available   -> {'kdbx': True, 'psafe3': True}
    ok   state_dir is /var/lib/cockpit-secrets/state
    ok   audit_log is /var/log/cockpit-secrets/audit.log
    ok   the agent is not running (nothing was enabled)
    ok   identity reports euid 0 and the admin class
         -> {'uid': 0, 'euid': 0, 'real_uid': 0, 'escalated': False,
             'admin_group': 'sudo', 'class_available': 'admin'}

The silent stderr is worth its own line: run from the development checkout the
helper warns that its directory is group-writable over SMB. Installed
root-owned, that warning is gone — which is the one-line difference between a
trusted install and a dev tree.

### FAIL — F1, see [Findings](#findings)

    FAIL /usr/local/lib/cockpit-secrets/backends holds exactly the source's *.py
         -> want '__init__.py base.py kdbx.py psafe3.py twofish_pure.py',
             got '__init__.py __pycache__ base.py kdbx.py psafe3.py twofish_pure.py'
    FAIL the library root holds compiled bytecode

## 3 · Throwaway safes and registry entries — PASS

Created under the **real** `/etc/cockpit-secrets`, all named `zz-throwaway-*`
and labelled `THROWAWAY … delete me`, so an operator reading the live
access-control directory cannot mistake one for policy.

| Registry entry | Why it exists |
|---|---|
| `zz-throwaway-admin` | **omits `access` entirely** — I1 says a missing `access` is `admin`, and the only honest way to test a default is to leave the key out. Also omits `groups`, so the gate falls back to the host's detected admin group |
| `zz-throwaway-nogroup` | the same file, `access: "admin"`, `groups: ["zzz-no-such-group"]` — proves the group gate is a real second condition |
| `zz-throwaway-user` | `access: "user"`, `owner: "cptest"`, in cptest's own tree |

The KDBX files were built by `tests/root/mkdb.py` with `pykeepass` **directly**,
not through a backend: a subject this program wrote itself would be the
round-trip fallacy I19 warns about, one level down.

    created /etc/cockpit-secrets/safes/zz-throwaway-admin.kdbx
            (1589 bytes, mode 0600, 1 entries, 2 groups)
    created /home/cptest/.local/share/cockpit-secrets/zz-throwaway-user.kdbx
            (1573 bytes, mode 0600, 1 entries, 2 groups)
    ok   /etc/cockpit-secrets/safes/zz-throwaway-admin.kdbx -> 600 root:root
    ok   /home/cptest/.local/share/cockpit-secrets         -> 700 cptest:cptest
    ok   /home/cptest/.local/share/cockpit-secrets/…kdbx   -> 600 cptest:cptest
    ok   registry_errors is 0
    ok   zz-throwaway-admin defaulted to access=admin with no `access` key (I1)
         -> admin
    ok   zz-throwaway-user is access=user   -> user
    ok   zz-throwaway-nogroup is registered read-only -> ro
    ok   health reports no registry errors  -> []

The user-class safe's directory is made `0700 cptest:cptest` **before** the
file lands: `base.open_safe_fd` walks the ancestry and refuses a safe under a
group- or other-writable parent (I5), and a stock `0755` XDG directory would
have failed that for a reason that has nothing to do with the safe.

## 4 · The ADMIN class from the allowing side — PASS (98 checks)

The section this whole task exists for. Full log:
`/srv/jobs/outbox/cs-40-admin-allow.20260904-034805.977465/output.log`.

### A · Identity as direct root

    ok   health exits 0
    ok   stderr is silent for a root helper on an installed tree
    ok   euid is 0
    ok   real_uid is 0 with no escalation hint set
    ok   escalated is false for direct root
    ok   the detected admin group is `sudo` (this host has no `wheel`) -> sudo
    ok   class_available is admin -> admin

### B · Unlock → read → mutate → save, in one `open` session as root

**This is the thing that had never run.**

    ok   the session opens with a banner frame
    ok   root UNLOCKS the admin-class safe
         -> {"entries_total": 3, "expires_in": 899, "groups_total": 2,
             "session": true, "warnings": []}
    ok   tree returns the seeded group -> ['Root', 'Throwaway']
    ok   no listing row carries a password field
         -> ['attachments','has_totp','modified','tags','title','url',
             'username','uuid']
    ok   root ADDS an entry
    ok   the add is in memory only until save (saved is false)
    ok   root EDITS the entry -> {"changed": ["notes"]}
    ok   reveal returns exactly the password that was written
         -> {"expires_in": 15, "field": "password",
             "resolved_field": "Password"}
    ok   root SAVES the safe
         -> {"backup": "/etc/cockpit-secrets/safes/zz-throwaway-admin.kdbx.bak.d/
                        zz-throwaway-admin.kdbx.20260904T084811.973401.978016.bak",
             "bytes": 1973, "conflict": false, "ok": true}
    ok   the save took a backup first (I12)
    ok   the backup is 0600 root-owned -> 0600 0:0
    ok   lock drops the handle -> {"locked": 1, "ok": true}
    ok   the session closes cleanly -> reason "locked"
    ok   the session wrote nothing to stderr
    ok   the safe on disk actually changed -> 1877 -> 1973 bytes
    ok   the safe is still 0600 root:root after a root save -> 0600 0:0
    ok   the handle is dead in a new process
         -> {"detail": "this handle is not valid for this caller",
             "error": "access-denied"}
    ok   a second process re-unlocks the saved safe
    ok   the safe now holds exactly one more entry than before the save -> 3 -> 4
    ok   the added entry survived the save
    ok   its password reads back byte-identical after the round trip
         -> compared, not printed

The canary password is generated per run (`secrets.token_hex`), so the audit-log
grep in section C means something a committed constant could not.

The "handle is dead in a new process" row is the structural half of
non-negotiable 9: the passphrase is prompted on every unlock because a handle
cannot outlive the process that minted it, not because a policy says so.

### C · The root-owned state and audit directories

    ok   /var/lib/cockpit-secrets/state is 0700 root-owned -> 0700 0:0
    ok   /var/log/cockpit-secrets is 0700 root-owned       -> 0700 0:0
    ok   the audit log exists
    ok   the audit log is 0600 root:root -> 0600 0:0
    ok   the root path actually appended to it -> 1206 -> 4845 bytes
    ok   every audit line is one JSON object with exactly the fixed keys
    ok   the audit log contains no traceback
    ok   the passphrase does not appear in the audit log
    ok   the canary password does not appear in the audit log
    ok   the entry title does not appear in the audit log
    ok   no audit line carries a value-shaped key
    ok   the root save is recorded with uid 0 and euid 0
         -> {"artifact": null, "duration_ms": 2, "euid": 0, "note": "",
             "outcome": "ok", "pid": 978016, "rows": null,
             "safe": "zz-throwaway-admin", "session": true,
             "ts": "2026-09-04T08:48:11.975Z", "uid": 0, "ve…

(the report truncates an `extra` at 220 characters, so the trailing
`"verb": "save"` is cut off in the log; it is `save` by the filter that
selected the line.)
    ok   audit-tail returns metadata only -> {"n": 5}

Key set asserted line by line against the twelve `_AUDIT_KEYS` from
`docs/CONTRACT.md`: `ts verb safe uid euid outcome note duration_ms pid session
artifact rows`. No `value`, `password`, `title`, `detail` or `traceback` key
appears on any line, and neither canary string appears anywhere in the file.

### D · `SUDO_UID` / `PKEXEC_UID` — which real caller the helper believes

Every row runs at **euid 0** against the same admin safe with `probe`, which
gates but needs no credential — so a row can neither be explained by a wrong
passphrase nor move the lockout counter. `real_uid` is read separately from
`health`, so the identity and the decision are two independent measurements.

| Environment at euid 0 | `real_uid` | Verdict | Result |
|---|---:|---|---|
| (no hint at all) | 0 | ADMITTED | PASS |
| `SUDO_UID=1006` cpadmin, in `sudo` | 1006 | ADMITTED | PASS |
| `SUDO_UID=1007` cptestadm, in `sudo` | 1007 | ADMITTED | PASS |
| **`SUDO_UID=1005` cptest, NOT in `sudo`** | 1005 | **REFUSED** | PASS |
| `PKEXEC_UID=1006` | 1006 | ADMITTED | PASS |
| `PKEXEC_UID=1005` | 1005 | REFUSED | PASS |
| `SUDO_UID=1006` + `PKEXEC_UID=1005` | 1006 | ADMITTED — `SUDO_UID` wins | PASS |
| `SUDO_UID=1005` + `PKEXEC_UID=1006` | 1005 | REFUSED — `SUDO_UID` wins | PASS |
| `SUDO_UID=not-a-number` | 0 | ADMITTED, hint ignored | PASS |
| `SUDO_UID=0` | 0 | ADMITTED, hint ignored (`escalated=false`) | PASS |
| `SUDO_UID=424242` (no such account) | 424242 | REFUSED | PASS |

The refusal text is the same in every refused row:

    {"detail": "the calling user is not in an administrative group permitted
                to open this safe", "error": "access-denied"}

The two mixed rows are what pin the **order** rather than merely the effect:
`Identity.__init__` reads `SUDO_UID` first and stops at the first usable value.

Then the allowing side for an **escalated** caller rather than direct root:

    ok   an escalated `sudo` member (cpadmin) really unlocks the safe
         -> {"entries_total": 4, "expires_in": 899, "groups_total": 2,
             "session": true, "warnings": []}

…and the paired refusal is audited against the right person:

    ok   the refusal is audited against the REAL caller (uid 1005, euid 0)
         -> {"artifact": null, "duration_ms": 0, "euid": 0,
             "note": "class-refused", "outcome": "access-denied",
             "pid": 978293, "rows": null, "safe": "zz-throwaway-admin",
             "session": false, "ts": "2026-09-04T08:4…   (truncated at 220)

`uid` is the human, `euid` is the privilege. That pair in one line is what makes
an escalated refusal traceable at all.

### E · The registry `groups` gate is a second condition

    ok   direct root opens a safe whose `groups` names nobody — BY DESIGN
    ok   an escalated `sudo` member is REFUSED that safe (wrong group)

Both are correct and the asymmetry is deliberate: `gate()` treats uid 0 with no
escalation behind it as administrative by definition, because asking
`/etc/group` whether uid 0 is in `sudo` answers *no* on a perfectly normal host.
The `groups` list therefore constrains **who may escalate to** a safe, not
whether root can read it — which is the same thing the threat model already
says out loud (root is out of scope).

### F · The user class is refused **at** euid 0

    ok   root may not probe a user-class safe
    ok   root may not unlock a user-class safe even with the passphrase
         -> {"detail": "this safe is user-class and is not opened by a root
                        helper; call it without Cockpit's Administrative
                        access", "error": "access-denied"}

The complementary refusal, and not a nicety: a root helper opening a file inside
a directory the user controls is exactly the symlink race I5 exists for.

### G · The lockout counter (I16)

Real time, not a mock — the backoff is the property, so the job actually waits
2 + 4 + 8 + 16 seconds.

| Attempt | Answer | Counter | Backoff observed |
|---:|---|---:|---|
| 1 | `bad-credential` | `failures: 1` | "try again in 2 seconds" |
| 2 | `bad-credential` | `failures: 2` | "try again in 4 seconds" |
| 3 | `bad-credential` | `failures: 3` | "try again in 8 seconds" |
| 4 | `bad-credential` | `failures: 4` | "try again in 16 seconds" |
| 5 | `bad-credential` | `failures: 5` | "try again in 300 seconds" |

After each failure, the **correct** passphrase was tried immediately and was
also refused with `locked-out` — the check runs before the KDF, so the brake is
on the endpoint rather than on the guess. At the threshold the hard lockout
(`LOCKOUT_HARD_SECONDS = 300`) applies, measured at 300 s remaining.

    ok   the counter file is 0600 root-owned -> 0600 0:0
         (/var/lib/cockpit-secrets/state/fail.0.zz-throwaway-admin.json)
    ok   cptest CANNOT delete the counter
         -> rm: cannot remove '…/fail.0.zz-throwaway-admin.json': Permission denied
    ok   the counter file is still there
    ok   cptest cannot even list /var/lib/cockpit-secrets/state
         -> ls: cannot open file '…': Permission denied
    ok   cptest cannot read the counter
         -> cat: '…': Permission denied
    ok   root removed the counter and it is gone before the next unlock
    ok   root cleared the counter and the safe opens again
    ok   a successful unlock leaves no live counter
         -> {"doc": {"failures": 0, "locked_until": 0}, "exists": true}
    ok   the zeroed counter it wrote is still 0600 root-owned -> 0600 0:0

That last pair is finding **F2** — see below. The property holds (the counter no
longer bites); the mechanism is not what the docstring leads you to expect.

## 5 · The USER class on the real host, as `cptest` — PASS (34 checks)

Driven by `runuser -u cptest` with `env -i` and a minimal environment. cptest is
uid 1005 and is **not** in `sudo` — verified in the job's own preconditions:
`groups=cptest,video,render,edy-rdp`.

### Identity and state fallback

    ok   euid is cptest -> 1005
    ok   real_uid is cptest -> 1005
    ok   escalated is false
    ok   class_available is user, not admin -> user
    ok   state falls back to cptest's own directory
         -> {"reason": "system state directory is not writable by this uid;
                        using the caller's own state directory",
             "state_dir": "/home/cptest/.local/state/cockpit-secrets/state"}
    ok   cptest's audit log is not the root one
         -> /home/cptest/.local/state/cockpit-secrets/audit.log
    helper stderr: secrets-admin: mlockall failed (ENOMEM): secrets may reach
                   swap; this is expected for a non-root helper

That stderr line is I14 being reported honestly rather than pretended about, and
it is the only thing the unprivileged helper writes there.

### Opening their own safe, unescalated — all PASS

    ok   the user-class safe is listed and usable
    ok   the admin-class safe is listed but NOT usable, with a reason
    ok   probe of the user-class safe succeeds
    ok   cptest UNLOCKS their own safe with no escalation
    ok   entries lists the seeded entry
    ok   reveal returns a non-empty password (compared, not printed)
    ok   cptest may ADD to their own safe
    ok   cptest may SAVE their own safe
    ok   the saved safe is still 0600 and owned by cptest -> 0600 1005:1005

An admin safe being *listed* to cptest is deliberate — the page is more honest
saying "there is a safe here you cannot open" — and it is also the I3 test,
because being listed is exactly what a browser-side check would have been
tempted to treat as permission.

### Everything of the admin class is refused — all PASS

    ok   probe zz-throwaway-admin is refused
    ok   unlock zz-throwaway-admin is refused
    ok   probe zz-throwaway-nogroup is refused
    ok   unlock zz-throwaway-nogroup is refused
    ok   a wrong passphrase for an admin safe is the SAME refusal
         -> {"detail": "this safe is administrator-class; turn on Cockpit's
                        Administrative access and try again",
             "error": "access-denied"}

The last row is the taxonomy not doubling as an oracle (I6): the class gate runs
first, so a wrong passphrase and a wrong class are indistinguishable to cptest.

### `SUDO_UID` is not a group membership (I3) — PASS

    ok   SUDO_UID=cpadmin does NOT change the real caller below euid 0
         -> {"escalated": false, "euid": 1005, "real_uid": 1005}
    ok   ...and the admin safe is still refused

An unprivileged caller can set any environment variable they like. The helper
reads `SUDO_UID` **only** when euid is already 0, so setting it here changes
nothing — measured from both sides now, admitted at euid 0 and ignored below it.

### The files behind the helper — all PASS

Kernel answers, not the program's. A refusal from the helper would be worth
nothing if the same bytes were readable directly.

    ok   cannot read the admin safe file             -> PermissionError
    ok   cannot list /etc/cockpit-secrets/safes (0700 root) -> PermissionError
    ok   cannot read the root audit log              -> PermissionError
    ok   cannot list /var/log/cockpit-secrets (0700 root)   -> PermissionError
    ok   cannot list the root state directory        -> PermissionError
    ok   cannot list the passphrase directory        -> PermissionError
    ok   cannot read the throwaway passphrase file   -> PermissionError
    ok   the registry directory is readable (it is policy, not a secret)
    ok   cannot write a registry entry               -> PermissionError
    ok   cannot replace the installed helper         -> PermissionError
    ok   cannot write into the helper's library root -> PermissionError

`ENOENT` is explicitly not accepted as a refusal: the driver checks for
`PermissionError` specifically, because a missing file would pass a naive "it
raised" test while meaning the opposite.

## 6 · Uninstall, diff, reinstall — PASS (35 checks)

Before/after snapshots of every path the package touches (type, mode, owner,
path) plus a SHA-256 of every registry entry.

`install.sh --uninstall` removed **exactly** the software, 20 paths:

    - /usr/local/lib/cockpit-secrets{,/backends,/schema}
    -   backends/{__init__,base,kdbx,psafe3,twofish_pure}.py
    -   backends/__pycache__ and its four .pyc files
    -   schema/safe-registry.schema.json
    - /usr/local/sbin/secrets-admin
    - /usr/share/cockpit/secrets
    -   index.html, manifest.json, secrets.css, secrets.js

    ok   an uninstall adds nothing
    ok   absent: /usr/share/cockpit/secrets
    ok   absent: /usr/local/sbin/secrets-admin
    ok   absent: /usr/local/lib/cockpit-secrets

And kept exactly what its own closing message promises:

    ok   /etc/cockpit-secrets            -> 755 root:root
    ok   /etc/cockpit-secrets/safes.d    -> 755 root:root
    ok   /etc/cockpit-secrets/safes      -> 700 root:root
    ok   /var/log/cockpit-secrets        -> 700 root:root
    ok   /var/lib/cockpit-secrets/state  -> 700 root:root
    ok   /var/lib/cockpit-secrets/exports-> 700 root:root
    ok   the admin safe file survived    -> 600 root:root
    ok   the audit log survived          -> 600 root:root
    ok   every registry entry is byte-identical after the uninstall
         -> 5 file(s), sha256 unchanged
    ok   registry entry for zz-throwaway-admin survived
    ok   registry entry for zz-throwaway-nogroup survived
    ok   registry entry for zz-throwaway-user survived

The hash comparison is the point. "The file is still called that" and "the
policy is unchanged" are different claims, and only the second one matters for a
file that decides who may open a safe.

Reinstall:

    ok   install.sh (reinstall) exit status -> 0
    ok   reinstall raised no 'Action required' warnings -> 0
    ok   the reinstall kept the seeded examples rather than rewriting them
    ok   every registry entry is STILL byte-identical after the reinstall
    ok   the reinstall restored exactly what the uninstall removed
    ok   the reinstalled helper answers health
    ok   still nothing group- or world-writable after the reinstall

**The package was left installed**, as the next agent needs it.

> One test-side bug worth recording because it was silent: the first version of
> this step used `comm` on `sort`ed path lists without `LC_ALL=C`. glibc
> collation makes `sort` and `comm` disagree about paths containing hyphens, and
> `comm` printed `file 1 is not in sorted order` and produced a set difference
> that was quietly wrong — for a check whose whole job is "exactly this and
> nothing else", worse than an error. Both are pinned to `LC_ALL=C` now.

## 7 · Cleanup — PASS

    ok   removed /etc/cockpit-secrets/safes.d/90-zz-throwaway-admin.json
    ok   removed /etc/cockpit-secrets/safes.d/91-zz-throwaway-nogroup.json
    ok   removed /etc/cockpit-secrets/safes.d/92-zz-throwaway-user.json
    ok   removed /etc/cockpit-secrets/safes/zz-throwaway-admin.kdbx
    ok   removed …/zz-throwaway-admin.kdbx.bak.d  -> 3 backup generation(s)
    ok   removed /home/cptest/.local/share/cockpit-secrets/zz-throwaway-user.kdbx
    ok   removed …/zz-throwaway-user.kdbx.bak.d   -> 1 backup generation(s)
    ok   removed /home/cptest/.local/share/cockpit-secrets
    ok   removed /home/cptest/.local/state/cockpit-secrets
    ok   no lockout counter was left behind
    ok   destroyed /run/cockpit-secrets-roottest/pw (tmpfs)
    ok   absent: /run/cockpit-secrets-roottest
    ok   no throwaway safe remains in the registry -> no safes registered
    ok   registry_errors is 0 -> 0

---

## Findings

### F1 · The installed library root accumulates root-owned bytecode · severity LOW · FAIL

`install.sh` sweeps `__pycache__` out of `$LIBDIR/backends` and says why in a
comment — *"root-owned bytecode next to root-run source is a second thing to
keep honest and buys nothing"*. It then recreates it, because its own
**Verifying** step imports the package after the sweep has run.

Measured on the host:

    755 root:root /usr/local/lib/cockpit-secrets/backends/__pycache__
    600 root:root …/__pycache__/kdbx.cpython-314.pyc
    600 root:root …/__pycache__/psafe3.cpython-314.pyc
    644 root:root …/__pycache__/__init__.cpython-314.pyc
    644 root:root …/__pycache__/base.cpython-314.pyc

Attribution, measured rather than guessed — `20-verify-install.sh` deletes it and
re-imports:

    DIAGNOSIS: it is recreated by importing backends as root -
    install.sh's own smoke test does that AFTER its stale-file sweep.

The two different modes name the two different writers. `install.sh`'s
`python3 -c "import backends"` runs under `umask 022` and produced the 0644
files; the helper's own `health` smoke test runs under `harden_process`'s
`umask 077` and produced the 0600 ones. Both are steps of `install.sh`.

**Impact.** Low. Nothing is group- or other-writable, everything is root-owned,
`_trusted_dir` is satisfied, and CPython invalidates a `.pyc` whose source
mtime or size changed. It is a hygiene defect against the installer's own stated
invariant, not a privilege boundary.

**Fix (one line, in `install.sh` — not this task's file).** Run the two
verification steps with `PYTHONDONTWRITEBYTECODE=1` (or `python3 -B` for the
import probe), or move the stale-file sweep after the smoke test. The uninstall
already removes the bytecode correctly, so nothing else changes.

### F2 · `lockout_reset()` re-creates the counter file it just failed to unlink · severity LOW · noted

`lockout_reset()` unlinks the state file and, in the `except OSError` branch,
writes `{"failures": 0, "locked_until": 0}` instead. **`ENOENT` lands in that
branch too**, so a successful unlock with no counter present *creates* one.
Proved directly: root unlinked the file, a check confirmed it was gone, the next
successful unlock brought it back holding zeros.

**Impact.** Low, and the security property is intact: the file is 0600
root-owned, carries no value, and `lockout_check()` returns immediately on
`locked_until: 0`. The consequence is one small JSON file per `(uid, safe)` in
the state directory after the first successful unlock of each — including in
each user's own `~/.local/state/cockpit-secrets/state` on the user path.

The fallback write is right for the case it was written for (an unlink refused
by permissions); it is only wrong for "there was nothing to clear". Ignoring
`ENOENT` before falling back would close it.

This is recorded rather than treated as a failure because "a successful unlock
clears the counter" is true — the counter no longer bites. The test asserts the
property and reports the mechanism.

---

## Not attempted

Listed because a test that was not run is not a test that passed.

- **The browser.** Nothing in this run opened the Cockpit page, logged in,
  or exercised `superuser: "require"` through `cockpit.spawn`. The escalated
  identity was simulated the way `sudo` and `pkexec` do it — euid 0 with
  `SUDO_UID`/`PKEXEC_UID` set — which is the same input the helper sees, but the
  real bridge path was not driven. That is the next agent's walkthrough.
- **The optional agent.** `install.sh --with-agent` was never run, no
  `secrets-agent` unit was installed, and no agent was started as root. I18's
  second residual — the admin class separating operators by *instance* rather
  than by peercred — is therefore still untested on a real host.
- **`DESTDIR` staging.** `sudo DESTDIR=/tmp/stage ./install.sh` was not
  exercised; only a real install to `/`.
- **The `psafe3` backend at root.** Both throwaway safes are KDBX. The PWS3
  backend is covered unescalated by `tests/integration/`, and its availability
  is asserted here through `health`, but no PWS3 safe was opened as euid 0.
- **Key files, YubiKey, TOTP, export, `save-as`, `restore-backup`,
  `breach-check`, attachments and history at root.** All are covered
  unescalated by `tests/integration/newverbs.py`; none was re-run as euid 0.
  The export gate in particular was proved elsewhere inside
  `unshare --map-root-user`, not with real root.
- **The lockout's upper clamps.** `LOCKOUT_MAX_SECONDS` (900) and the
  clamp-on-read for a tampered or clock-skewed state file were not reached: the
  run stops at the threshold's 300 s.
- **A second concurrent operator.** Two admins with two sessions against one
  safe (I13's conflict path at root) was not exercised.
- **Reboot survival.** Nothing was restarted, so nothing proves the
  installation survives one — though it installs no unit and enables no service,
  so there is nothing to survive.

---

## What remains on the host

Confirmed from an unprivileged shell after `90-cleanup.sh`.

**Installed, deliberately left live:**

    drwxr-xr-x root:root  /usr/share/cockpit/secrets
      index.html  manifest.json  secrets.css  secrets.js        (0644 root:root)
    -rwxr-xr-x root:root  /usr/local/sbin/secrets-admin
    drwxr-xr-x root:root  /usr/local/lib/cockpit-secrets
      backends/{__init__,base,kdbx,psafe3,twofish_pure}.py      (0644 root:root)
      backends/__pycache__/*.pyc                                (F1)
      schema/safe-registry.schema.json                          (0644 root:root)
    drwxr-xr-x root:root  /etc/cockpit-secrets
    drwxr-xr-x root:root  /etc/cockpit-secrets/safes.d
      10-example-admin.json.example  20-example-user.json.example
    drwx------ root:root  /etc/cockpit-secrets/safes            (EMPTY)
    drwx------ root:root  /var/log/cockpit-secrets
      audit.log                                                 (0600 root:root)
    drwx------ root:root  /var/lib/cockpit-secrets
    drwx------ root:root  /var/lib/cockpit-secrets/state        (EMPTY)
    drwx------ root:root  /var/lib/cockpit-secrets/exports      (EMPTY)

**Gone:** every throwaway safe, backup ring and registry entry; cptest's
`~/.local/share/cockpit-secrets` and `~/.local/state/cockpit-secrets`; every
lockout counter; the tmpfs passphrase and its directory. `secrets-admin list`
now answers with no safes registered and `registry_errors: 0` — the same state a
fresh install leaves.

**Kept on purpose:** `/var/log/cockpit-secrets/audit.log`, 274 lines after
both runs, 168 of them naming a throwaway safe. It records who opened what, it contains no value
(asserted line by line in section 4C), and `install.sh --uninstall` keeps it for
the same reason. Delete it if a clean log is wanted before the walkthrough:

    rm -f /var/log/cockpit-secrets/audit.log

**Not touched at any point:** `cockpit.socket`. Still
`ActiveEnterTimestamp=Tue 2026-09-01 01:59:08 CDT`, three days older than this
work. The page appears in the menu on the next login; Cockpit rescans
`/usr/share/cockpit` by itself.
