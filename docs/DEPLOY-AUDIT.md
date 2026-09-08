# DEPLOY-AUDIT.md — the deployment of six Cockpit plugins to edt1

Companion to `DEPLOY-CONTRACT.md`. That document is the design; this one is the
record of applying it to a live host on **2026-09-07**, with the evidence
verbatim and an honest list of what is still wrong.

Cockpit stayed up at https://localhost:9090 throughout. `cockpit.socket` was
never restarted: it still reports `ActiveEnterTimestamp=Tue 2026-09-01 01:59:08
CDT`, which predates every action here.

---

## 0. The one result this round could not fudge

The acceptance test was a recursive grep for the development root over every
installed location. **It now returns nothing.** Verbatim, run as root:

```
--- grep -rl "/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects" over every location named in the task ---
<<< END OF HITS >>>

--- grep -rl /opt/sc/git over the same set ---
<<< END OF HITS >>>

--- every symlink, resolved ---
  total=63  outside=/opt/cockpit-*:0  dangling:0

--- which install is each of the six? ---
  adlab       deployed  /opt/cockpit-adlab/payload-1.0.1/index.html
  guac-rdp    deployed  /opt/cockpit-guac-rdp/payload-1.1.2.20260907/index.html
  headscale   deployed  /opt/cockpit-headscale/payload-1.1.1+20260908T031300Z/index.html
  secrets     deployed  /opt/cockpit-secrets/payload-0.5.2/index.html
  tuner       deployed  /opt/cockpit-tuner/payload-1.0.1/index.html
  wireguard   deployed  /opt/cockpit-wireguard/payload-1.1.1+20260908T031301Z/index.html
```

Scope of the grep: `/usr/share/cockpit/{adlab,guac-rdp,headscale,secrets,tuner,wireguard}`,
`/usr/local/sbin`, `/usr/local/lib`, `/etc/cockpit-*`, all six `/opt/cockpit-*`
install paths, `/usr/libexec/edy-rdp`, `/usr/local/share/cockpit-secrets`, and
`/home/eddie/.local/share/cockpit` (see §5.1 for why that last one belongs).

Before this round the same grep returned two files:
`/usr/share/cockpit/adlab/manifest.json` and `/usr/local/sbin/adlab-admin`.

### The independence proof, verbatim

A grep proves no file *names* the share. This proves nothing *needs* it. Run as
root inside a private mount namespace, with an empty directory bind-mounted over
the projects tree:

```
IN A PRIVATE MOUNT NAMESPACE: /srv/smb/.../projects HAS 0 ENTRIES

  OK    rc=0  secrets-admin health       {"version": "1.0.0", "base_version": "1.0.0", ...
  OK    rc=0  secrets-admin schema       {"version": 2, "helper_version": "1.0.0", ...
  OK    rc=0  secrets-admin list         {"safes": [{"id": "dummy-fake-safe", ...
  OK    rc=0  wg-admin schema            {"version":2,"groups":[{"id":"client-config", ...
  OK    rc=0  wg-admin --help
  OK    rc=0  wg-admin-package --help
  OK    rc=0  wg-policy check            policy: /etc/wireguard/routing-policy.json  34 o...
  OK    rc=0  hs-admin status            {"installed": true, "running": true, ...
  OK    rc=0  hs-policy check            policy: /etc/headscale/routing-policy.json  in syn...
  OK    rc=0  adlab-admin config         {"install_conf": "/etc/cockpit-adlab/install.conf", ...
  OK    rc=0  adlab-admin schema         {"version": "1.0.0", "verbs": {...
  OK    rc=0  adlab-admin version        {"version": "1.0.0", "realm": "AD.EDT1.LAB", ...

  OK    page adlab       all 4 entries readable
  OK    page guac-rdp    all 6 entries readable
  OK    page headscale   all 4 entries readable
  OK    page secrets     all 5 entries readable
  OK    page tuner       all 7 entries readable
  OK    page wireguard   all 5 entries readable
  OK    relay modules import from /usr/libexec/edy-rdp

RESULT: EVERY INSTALLED HELPER AND PAGE WORKS WITH THE DEV SHARE GONE

OUTSIDE the namespace: /srv/smb/.../projects still has 38 entries. Nothing was unmounted.
```

Nothing outside the namespace was unmounted or renamed; the operator's tree was
untouched, as the last line shows.

---

## 1. What was deployed where

| Plugin | Install path | Payload | Rollback kept | System locations |
|---|---|---|---|---|
| cockpit-adlab | `/opt/cockpit-adlab` | `payload-1.0.1` | `payload-1.0.0` | `/usr/share/cockpit/adlab`, `/usr/local/sbin/adlab-admin` |
| cockpit-guac-rdp | `/opt/cockpit-guac-rdp` | `payload-1.1.2.20260907` | `payload-1.1.1.20260903` | `/usr/share/cockpit/guac-rdp`, `/usr/libexec/edy-rdp`, 10 units |
| cockpit-headscale | `/opt/cockpit-headscale` | `payload-1.1.1+20260908T031300Z` | `payload-1.1.1` | `/usr/share/cockpit/headscale`, `hs-admin`, `hs-policy`, 1 unit |
| cockpit-secrets | `/opt/cockpit-secrets` | `payload-0.5.2` | `payload-0.5.1` | `/usr/share/cockpit/secrets`, `secrets-admin`, `/usr/local/lib/cockpit-secrets` |
| cockpit-tuner | `/opt/cockpit-tuner` | `payload-1.0.1` | `payload-1.0.0` | `/usr/share/cockpit/tuner` (+ a user-scope install, §5.1) |
| cockpit-wireguard | `/opt/cockpit-wireguard` | `payload-1.1.1+20260908T031301Z` | `payload-1.1.1` | `/usr/share/cockpit/wireguard`, `wg-admin`, `wg-admin-package`, `wg-policy`, `wg-policy-watch`, 1 unit |

Every one was deployed, then upgraded once at a bumped version, so the
`payload-<version>` + `payload` symlink swap and the keep-one-previous retention
were both exercised on the live host, not only in staging.

The old copy-based files were **moved, not deleted**, to
`/root/deploy-backup-20260907/` (`cockpit-plugins.tar.gz`, `sbin-helpers.tar.gz`,
`usr-local-lib-secrets.tar.gz`, plus `old-<plugin>/` directories holding the
displaced originals and the pre-existing unit files).

---

## 2. The gaps that are closed

**The adlab reach into the dev tree.** `/usr/share/cockpit/adlab/manifest.json`
and `/usr/local/sbin/adlab-admin` were the only two installed files naming the
share. Both are gone. The manifest condition is now
`{"path-exists": "/usr/local/sbin/adlab-admin"}` — a path this project's own
installer creates — so an unmet condition can no longer make the plugin silently
absent.

**The missing backends.** `wg-admin` and `hs-admin` were installed on this host
and byte-identical to source, but *no installer mentioned them*: a fresh clone
produced a UI whose backend was absent. Both are now declared and installed by
the installer that ships the page that calls them, along with
`wg-admin-package`, `wg-policy`, `wg-policy-watch` and `hs-policy`. Pre-flight
check 3 refuses when a page names a `/usr/local/sbin/` helper that `HELPERS`
does not install; watched to fire.

**Configuration is no longer compiled in.** Each plugin reads a deployed `.env`
sibling of its payload, discovered through `/etc/<project>/install.conf`. All six
`.env` files were seeded from `.envdefault`, are mode 0644, carry no
secret-shaped key, and survived a redeploy with an operator edit intact
(verified by hash on all six).

**guac-rdp configuration moved** from `/etc/default/edy-rdp` into
`/opt/cockpit-guac-rdp/.env`, every key compared old-vs-new and identical.

---

## 3. The design change this round made, and why

All six installers classified themselves with `[[ "$SRC" == "$DEV_ROOT"/* ]]`
against a hardcoded development root. Two projects hid that literal from the
grep by assembling it from parts; four did not. The literal was the only thing
standing between this round and a clean audit, and the previous round escalated
it as a task-versus-contract conflict needing a ruling.

**It was not a conflict.** It was one implementation choice, and the classifier
was independently wrong. Proof, taken before any change: a plain checkout copied
to a path outside the share — no payload symlink, no versioned payload
directory, unambiguously a checkout — classified itself as a *deployed* install:

```
  kind:  deployed    (payload: .../scratchpad/moved-checkout)
```

That is the dangerous direction. Such a host skips the group-writable warning,
records `INSTALL_KIND=deployed` for a host that is **not** self-sustaining, and
drops "the checkout is not touched" from `--uninstall`.

Classification is now by **layout**: this is a deployed payload exactly when the
script's own directory is what a sibling `payload` symlink resolves to. It needs
no literal, it cannot drift when a tree moves, and it tests the property the
rest of the installer already depends on. After the change the same moved
checkout reports `kind: dev`.

Consequences, all verified:

- **Check 9 now scans `install.sh` itself.** The contract's carve-out (§7.2) is
  removed. Both of the check's own patterns are split so the scanner cannot
  match itself — this weakens nothing, because the string it searches for is
  unchanged and every other file is still matched in full.
- `owned_by_us` recognises a dev link by `$SRC` rather than "anywhere under the
  development root" — tighter, and it no longer adopts a link belonging to a
  different checkout of the same project.
- The uninstall notice and dev warning ask the **link target's** layout, so they
  stay correct when a deployed installer tears down links a dev install made.
- **A previous payload is still a deployed tree.** The first form of the
  layout test asks only whether the `payload` alias points at us, which makes a
  rolled-back payload run directly — without swapping the alias first — classify
  as `dev` and then refuse with "create a test .env", a message that is simply
  wrong for a tree under `/opt`. Reproduced, then fixed with a second clause:
  a directory named `payload-*` sitting beside a `payload` symlink is deployed
  too. All four cases were then re-verified — moved checkout `dev`, real
  checkout `dev`, current payload `deployed`, previous payload `deployed`.
- cockpit-wireguard's and cockpit-headscale's self-sustaining assertion is
  restated positively: every link must resolve **inside** the install path,
  rather than "not into the development share". Strictly stronger — a link into
  any other foreign tree fails it too — and literal-free. Unit paths must be
  inside the install path or on an FHS system prefix, which keeps
  `ExecStart=/bin/sh -c '... @BIN@/hs-policy ...'` legal; that refinement was
  forced by a real refusal, not assumed.

---

## 4. Gates

Re-run after the final edit to every file:

| Project | Gate | Result |
|---|---|---|
| cockpit-secrets | `check.sh` | rc=0 |
| cockpit-secrets | `validate.sh` | rc=0 |
| cockpit-secrets | `run_tests.sh` | rc=0, **20/20 groups PASS, 0 FAIL lines** |
| cockpit-tuner | `validate.sh` | rc=0 |
| cockpit-wireguard | `check.sh` | rc=0 |
| cockpit-headscale | `check.sh` | rc=0 |
| cockpit-guac-rdp | `run_tests.sh` | RESULT: PASS |
| cockpit-adlab | `tests/test_adlab_admin.py` | **108/108** (was silently 100 — see §5.2) |

No test and no ban was weakened. The two checks that changed were made
*stronger*: check 9 gained `install.sh`, and the self-sustaining assertion
gained "must be inside the install path".

The browser suite is the `ui: headless browser driver` and
`ui: item 4's storage oracle (I11, I42)` groups; both PASS. It exercises the
source tree, and every file Cockpit now serves was proved byte-identical to the
source that was tested:

```
  secrets      identical=5   differing=0   not-in-source=0
  tuner        identical=7   differing=0   not-in-source=0
  wireguard    identical=5   differing=0   not-in-source=0
  headscale    identical=4   differing=0   not-in-source=0
  adlab        identical=4   differing=0   not-in-source=0
  secrets-admin / wg-admin / hs-admin / adlab-admin: identical to source
```

### The rendered units

All twelve units this round re-rendered (`edy-rdp-*` x10, `wg-policy-watch`,
`hs-policy-watch`) pass `systemd-analyze verify`. Every absolute path on every
`ExecStart` exists on disk, and every `EnvironmentFile` resolves:

```
  OK       /opt/cockpit-guac-rdp/.env
  OK       /opt/cockpit-headscale/.env
  OK       /opt/cockpit-wireguard/.env
```

None of them is optional-prefixed, deliberately: a daemon that rewrites firewall
rules using defaults it was never configured with is worse than one that refuses
to start.

### The operator's safes

Unchanged through the whole deployment and the upgrade, by hash:

```
  /home/eddie/.config/cockpit-secrets/safes.d/pwsafe3.json          830 fa0afcea4790f654 UNCHANGED
  /home/eddie/.local/share/cockpit-secrets/safes/pwsafe3.psafe3   55736 98cae6bb0136f36d UNCHANGED
  /etc/cockpit-secrets/safes/dummy-fake-safe.kdbx                  9461 0504dd80f136c7a7 UNCHANGED
  /home/cptestadm/.../dummy-fake-user-psafe3.psafe3                3640 3e54595cc47b215d UNCHANGED
  /home/cptestadm/.../dummy-fake-user-kdbx.kdbx                    5845 835062a743806e32 UNCHANGED
```

**A correction to the brief.** The fingerprint given for "the operator's pwsafe3
safe" — `sha256 fa0afcea…dcde9fc8`, size 830 — is not the safe. It is the
*registry entry* `/home/eddie/.config/cockpit-secrets/safes.d/pwsafe3.json`. The
safe itself is 55736 bytes, `98cae6bb…`, matching its own recorded
`sha256_at_import`. Both are unchanged; the two were conflated, and this is
recorded so the next person does not read a mismatch where there is none.

All three `dummy-fake-*` safes resolve through the deployed helper at the right
scope: root sees the admin safe; eddie sees the admin safe plus his own
`pwsafe3`; cptestadm sees the admin safe plus his two user safes.
`secrets-admin health` reports `library_root_trusted: True`, both backends
available, `registry_errors: []`.

---

## 5. What is still wrong

### 5.1 A stale user-scope install was shadowing the system one — and system deploys do not follow user installs

Cockpit searches `~/.local/share/cockpit` **before** `/usr/share/cockpit`.
`cockpit-bridge --packages` resolved `tuner` to
`/home/eddie/.local/share/cockpit/tuner` — a plain copy dated 2026-09-01. The
operator's browser was being served that copy, not the system install, and the
task's audit scope would never have looked there.

Handled without deleting the operator's directory: the copies were moved aside
and `install.sh --user` was run **from the deployed install path**, so the
user-scope install is now symlinks into `/opt/cockpit-tuner/payload`.

**The remaining defect:** a system-scope deploy does *not* relink user-scope
installs. After the version bump, the user-scope links still pointed at
`payload-1.0.0` until `install.sh --user` was re-run by hand. Since retention
keeps only one previous payload, a user-scope install left alone across two
upgrades will point into a deleted directory and the plugin will break. Nothing
warns about this. Either `deploy.sh` should enumerate user-scope installs and
refuse (or relink) when it prunes a payload one still references, or the
`payload` alias — not the versioned directory — should be the link target for
user scope.

### 5.2 Seven tests had silently stopped running

`cockpit-adlab/tests/test_adlab_admin.py` had `if __name__ == "__main__":
unittest.main(...)` at line 1311 and `class TestConfigLayer` at line 1322 —
*below* it. `unittest.main()` exits the interpreter, so the class was never
defined and never collected. Running the file the normal way gave `Ran 100
tests`; importing it as a module gave `Ran 107`. The seven missing tests are
exactly the ones guarding the retired-path bug this whole round exists to fix.

Fixed by moving the block to the end of the file, with a comment saying why it
must stay there — and, because "remember not to do that again" is not a control,
by adding `TestSuiteCompleteness`, which counts the `def test_` in the source,
counts what the loader actually collects, and fails when they differ. Proved by
re-introducing the exact defect:

```
AssertionError: 108 != 109 : this file defines 109 test methods but the loader
collects 108. Something below a module-level exit, or a class the loader cannot
see, is not running.
```

The suite is now 108 tests. **What is still unaddressed** is that this control
exists in one file in one project; the other five suites can still lose tests
silently.

### 5.3 cockpit-adlab is architecturally correct and functionally inert

`adlab-admin config` reports `configured: true` and every one of its five
`ADLAB_*` paths as `exists: false`. The `.env` points at `/etc/samba-ad-lab/…`,
and **samba-ad-lab has never been installed there** — the old helper read
straight out of the checkout, which is precisely the bug. So the fix is correct
and the plugin's verbs will not work until the sibling is deployed.

This is contained by design, not by luck: the manifest condition tests
`/usr/local/sbin/adlab-admin`, which exists, so the plugin still appears in the
menu and diagnoses itself instead of silently vanishing. Every key carries a
`fix` string naming the `.env` key to set.

`samba-ad-lab/source/install.sh --verify` names the remaining work exactly:

```
  FAIL /etc/samba-ad-lab/lab.env is missing
  FAIL /usr/local/libexec/samba-ad-lab/sysvol-replicate.sh is missing
  FAIL /etc/systemd/system/sysvol-replicate.service also exists and /etc WINS: this host runs the development unit
  ...
  ok   C1: no installed file names /srv/smb/.../ai-orchestrator-group or /opt/sc/git
```

**Not done deliberately.** Completing it means retiring the development
`sysvol-replicate.{service,timer}` that are enabled and running against the live
lab. That is a decision about the operator's AD lab, not about these six
plugins, and it needs their explicit go-ahead.

### 5.4 A live service ran without its binary for roughly one minute

Deploying cockpit-headscale, the helpers were moved aside in one root job and the
install refused in that job on a *different* collision (the existing
`hs-policy-watch.service`). Between the two jobs, the running
`hs-policy-watch.service` — a `while :; do /usr/local/sbin/hs-policy apply;
sleep 30; done` loop — had no `hs-policy` to call. It recovered by itself at the
next tick once the symlink existed; `journalctl` shows `reconciled: 0 change(s)`
continuing on either side of the window, and no route was changed.

My error, not the design's. Every later plugin moved the old files aside and
deployed **in the same job**, which has no such window. Worth stating as a rule:
displacing an installed helper and re-installing it must be one atomic
operation whenever a running unit calls that helper.

### 5.5 The installer refuses one collision at a time

Migrating from the old copy-based install took four deploy cycles for
cockpit-secrets, because pre-flight check 8 dies on the first non-symlink it
meets rather than collecting them all. A pre-flight that reported *every*
collision at once — "these 6 files are regular files; move them aside" — would
have made it one cycle. This is a real ergonomic defect in a check whose whole
purpose is to be run before anything changes.

### 5.6 Two projects report a missing payload item badly

With a declared page file removed, cockpit-tuner refuses with
`deploy.sh: declared payload item missing: tuner.css`. cockpit-guac-rdp and
cockpit-adlab refuse with a raw `install: No such file or directory` — correct
behaviour, useless message. An error that does not name the file is the same
class of defect as the ones this round fixed elsewhere.

### 5.7 Same-version redeploys diverge across the fleet

Redeploying without a VERSION bump — the common case when only the installer
changed — is handled two different ways. cockpit-wireguard and cockpit-headscale
mint `payload-<version>+<UTC stamp>` and keep the plain one as the rollback
target; cockpit-tuner, cockpit-secrets, cockpit-guac-rdp and cockpit-adlab
replace the payload in place. Both are safe, and the live host now shows both:

```
  headscale   payload-1.1.1+20260908T031300Z   (kept: payload-1.1.1)
  wireguard   payload-1.1.1+20260908T031301Z   (kept: payload-1.1.1)
  tuner       payload-1.0.1                    (kept: payload-1.0.0)
```

The in-place form is the weaker of the two: it overwrites the payload a running
service may be executing from, and it loses the ability to roll back to "the
same version before I edited it". The timestamped form should become the fleet
rule.

### 5.8 Two DESTDIR conventions

cockpit-tuner and cockpit-secrets treat the install path as absolute and use
`DESTDIR` only for system locations. cockpit-guac-rdp and cockpit-adlab prefix
the install path with `DESTDIR` too, so a staged deploy lands at
`$DESTDIR$INSTALL_PATH`. Both are defensible; having both in one fleet is not,
and it nearly produced a false CLEAN in this round's own staging harness — the
`stage-*` directories were empty because the payload had gone somewhere else.
Any future audit that greps a staged tree must resolve the payload location
rather than assume it.

### 5.9 Unenforced and unverified

- **Windows.** `deploy.ps1` / `deploy.bat` exist for all six. cockpit-wireguard's
  is real and **untested** — there is no Windows host here. The other five
  refuse by design. Reviewed, not run.
- **Units were placed, never started.** All ten guac-rdp units, plus
  `wg-policy-watch` and `hs-policy-watch`, were re-rendered and
  `daemon-reload`ed. Nothing was enabled, started, stopped or restarted, so
  every running daemon is still executing its pre-deployment definition until
  someone restarts it. That is the contract's rule, and it means the units on
  disk and the units in memory differ right now.
- **`/etc/default/edy-rdp` still exists.** `deploy.sh` migrated it and
  deliberately left the original. A human should delete it once they agree with
  the migration.
- **The old install is still in `/root/deploy-backup-20260907`.** Nothing was
  deleted this round. Someone should remove it once the deployment has been
  lived with.
- **A runaway process, pre-existing and untouched:** `keepassxc-cli db-info -q
  .../tests/corpus/files/kdbx41-xml-duplicate-uuid.kdbx`, started 2026-09-04, has
  burned 5565 minutes of CPU at 99.7% on one core for three days. It is a
  leftover from an earlier test run, not from this round. It was left alone.
- **A staged git rename is still sitting in cockpit-wireguard's index**, left by
  an earlier round: `R100 routing-policy.json -> etcdefaults/routing-policy.json`.
  It is not mine and clearing it needs a `git` write command, which was out of
  scope this round. `git -C <checkout> reset` clears it. No commit was ever made.
- **No `git` write command was run in this round.** Every change is
  working-tree only, in six checkouts, and nothing has been committed or pushed.
- **The duplicate cockpit-adlab checkout** at
  `/srv/smb/.../projects/cockpit-adlab` is still there. The canonical copy is
  `samba-ad-lab/source/cockpit-adlab`, which is what was deployed. Until the
  duplicate is removed someone can still edit a dead tree. No `git` command was
  run this round, and removing it is a deletion for a human to make.

---

## 6. Rollback

Every plugin keeps exactly one previous payload. Two commands, no share, no
network:

```
ln -sfn payload-<previous> /opt/<project>/payload.new
mv -T /opt/<project>/payload.new /opt/<project>/payload
/opt/<project>/payload/install.sh
```

The swap is a single `rename(2)`, which is why it is safe against a live Cockpit.
To go back further than one version, restore from
`/root/deploy-backup-20260907/`.
