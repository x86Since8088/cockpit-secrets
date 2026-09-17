# Deploying the cockpit-* plugins on a machine that is not edt1

Last measured: 2026-09-07. Sections 1, 2, 3.1, 3.2, 11.3 and 15 re-measured 2026-09-08
(branches, manifest conditions and installer file lists; see the note at the end of section 2).

---

## 0. Read this first

**These plugins have been installed and run on exactly one machine, ever:** a single Ubuntu
26.04.1 "resolute" host called edt1, Cockpit 360-1, Python 3.14.4, bash 5.3.9.

Everything in this document about Debian, Fedora, RHEL, Rocky or Alpine comes from two things
and only two things:

1. reading the installers' and helpers' own source, and
2. looking up package names and versions in those distributions' public repository indexes
   (`packages.debian.org`, `packages.ubuntu.com`, the Rocky and Fedora/EPEL mirror trees, and
   `apk` inside a throwaway Alpine container).

Nobody has ever run `install.sh` on any of them. No Cockpit page has ever been loaded on any of
them. No helper has ever been executed on any of them.

Three phrases are used throughout and they mean different things:

| phrase | meaning |
|---|---|
| **verified** / **measured** | it was run on edt1 (Ubuntu 26.04) and the output was read |
| **packaged** / **available** | the named package exists at that version in that distro's index. Nothing more. |
| **untested** | nobody has ever run it there. You are the first. |

"The package exists in that repo" is not "this has been deployed there". If your target is
anything other than Ubuntu 26.04, **you are the first person to attempt it.** Do it on a machine
you can rebuild, and read section 12 before you start so your bug report is useful the first
time.

---

## 1. Which tier are you in

Do not read the whole document. The six plugins are not equally portable, and the difference is
large enough that it decides your afternoon.

| tier | plugins | dependency weight | where it is plausible |
|---|---|---|---|
| **A — light** | `cockpit-tuner`, `cockpit-wireguard`, `cockpit-headscale` | Cockpit + one or two CLI tools | anywhere Cockpit >= 266 is packaged (i.e. everything below except Alpine) |
| **B — medium** | `cockpit-guac-rdp` | FreeRDP 3, gnome-remote-desktop >= 46, Xvfb, x11vnc, podman, nftables, systemd | Ubuntu 24.04 / 25.10 / 26.04, Debian 13, Fedora 43 / 44. **Not** Ubuntu 22.04, Debian 12, RHEL/Rocky 9, RHEL/Rocky 10, Alpine |
| **C — heavy** | `cockpit-secrets` | eight Python modules including a Botan 3 binding | Ubuntu 25.10 / 26.04, Debian 13, Fedora 44 fully; Fedora 43 and RHEL/Rocky 9 with one crypto path missing; RHEL/Rocky 10 only with a pip fallback and a source edit |

If you only want WireGuard or the tuner, you are in tier A and almost nothing in the rest of
this document applies to you.

`cockpit-adlab` is now in tier A on its dependencies, but it is a special case for a different
reason: it is useless without the samba-ad-lab containers it drives, and it ships inside that
project's repository rather than one of its own. It **is** published, and its manifest condition
is no longer an edt1-only path. See sections 2.2 and 11.3.

---

## 2. What you can clone

Six repositories are public. **The repository name does not match the plugin directory name,
and neither matches the menu label.** Nothing inside a clone tells you this: no README in any of
them contains a `git clone` line for itself — the clone step exists only here.

| clone this repo | installs as `/usr/share/cockpit/…` | Cockpit menu label |
|---|---|---|
| `x86Since8088/linux-cockpit-remote-desktop-guac` | `guac-rdp` | Remote Desktop |
| `x86Since8088/cockpit-headscale` | `headscale` | Headscale |
| `x86Since8088/cockpit-os-tuner` | `tuner` | System Tuner |
| `x86Since8088/cockpit-wireguard` | `wireguard` | WireGuard |
| `x86Since8088/cockpit-secrets` | `secrets` | Secrets |
| `x86Since8088/lin-ad-lab-with-cockpit` | `adlab` (in `cockpit-adlab/`) | AD Lab |

```bash
git clone https://github.com/x86Since8088/linux-cockpit-remote-desktop-guac.git
git clone https://github.com/x86Since8088/cockpit-headscale.git
git clone https://github.com/x86Since8088/cockpit-os-tuner.git
git clone https://github.com/x86Since8088/cockpit-wireguard.git
git clone https://github.com/x86Since8088/cockpit-secrets.git
git clone https://github.com/x86Since8088/lin-ad-lab-with-cockpit.git
```

`install.sh` is at the **root of the clone**, not under `source/` — except for
`lin-ad-lab-with-cockpit`, where the plugin is the `cockpit-adlab/` subdirectory and the
repository root holds the lab's own installer instead:

```bash
cd <clone-dir>
sudo ./install.sh
```

### 2.0 `install.sh` is not the deployment — `deploy.sh` is

Every `sudo ./install.sh` line in this document still works, and it is what you want while you
are trying a plugin out: `install.sh` is an **in-place install by symlink**. It copies nothing.
It links the files beside it into `/usr/share/cockpit/<name>`, `/usr/local/sbin` and systemd, so
the page Cockpit serves *is* your clone, and deleting or moving the clone breaks the install.

`deploy.sh`, beside it, is the real deployment and the only thing that copies bytes: it copies a
declared payload subset into `/opt/<project>/payload-<version>/`, seeds `[install path]/.env`
from `.envdefault` missing-only, swaps a `payload` symlink, and then runs the **same**
`install.sh` from there. On a host you intend to keep, run `sudo ./deploy.sh`, not
`sudo ./install.sh`.

Two consequences for everything below:

- Anywhere this document says `sudo ./install.sh`, `sudo ./deploy.sh` is the durable form.
- `deploy.sh` never enables a unit unless you ask: `--with-policy` (wireguard, headscale),
  `--with-timer` (tuner), `--with-agent` (secrets), `--with-users` / `--with-deps` /
  `--with-image` / `--with-units` (guac-rdp). `install.sh` never enables one at all.

The full model is `cockpit-secrets/source/docs/DEPLOY-CONTRACT.md`, which ships in the
cockpit-secrets clone.

### 2.1 cockpit-secrets — just clone it

PR #2 was merged. `main` exists, it is the default branch, and `HEAD` points at it. Re-measured
2026-09-08 with `git ls-remote --symref`: `ref: refs/heads/main  HEAD`, `refs/heads/main` at
`e5507c5`.

```bash
git clone https://github.com/x86Since8088/cockpit-secrets.git
```

**Do not pass `-b init/publish-0.5.1`.** Earlier revisions of this document told you to, and it
is now the worst option available: that branch still exists, at `ab895ad` — which is
`refs/pull/2/head`, the **pre-merge** commit. Cloning it gives you stale code and no error at all.

### 2.2 cockpit-adlab — you can get it, inside another repo

It ships inside the samba-ad-lab repository, because it is useless without the containers it
drives:

```bash
git clone https://github.com/x86Since8088/lin-ad-lab-with-cockpit.git
cd lin-ad-lab-with-cockpit/cockpit-adlab && sudo ./deploy.sh
```

Its manifest condition is now `path-exists /usr/local/sbin/adlab-admin` — its own helper, which
its own installer links — so it no longer disappears on a host that is not edt1. What it needs
instead is the lab: run the repository's own `install.sh` first, which puts `lab.env`, `rdp.env`
and the SYSVOL scripts under `/etc/samba-ad-lab` and `/usr/local/libexec/samba-ad-lab`. Read
section 11.3 before you start — the helper has a path-resolution defect that matters to you.

### 2.3 One more caveat on the clones

One build-host checkout is **not** `main`: `cockpit-guac-rdp` is on
`fix/exec-bits-on-execstart-targets`. So for that plugin, "cloned from main" is not the same
code that has been exercised here. The other five checkouts are on `main`.

The branch and clone facts in this section were re-measured on 2026-09-08 against the public
remotes and the build-host checkouts. Everything about *distributions other than Ubuntu 26.04*
was not re-measured and remains as described in section 0.

---

## 3. Three things that are true on every distro

Read these once. They are not repeated in each section.

### 3.1 A plugin whose `conditions` are unmet vanishes silently

Cockpit reads `manifest.json`. If a `conditions` entry names a path that does not exist, the
package **is not listed and no error is produced anywhere** — not in the browser, not in the
journal. This was measured on edt1 with a throwaway package: an unmet condition produced no
output at all from `cockpit-bridge --packages`, while a *malformed* manifest produced
`cockpit.packages-ERROR: …/manifest.json: Expecting property name … line 1 column 3`. So those
are two different diagnoses with two different symptoms.

The conditions that actually ship:

| plugin | condition | so it silently disappears when… |
|---|---|---|
| `cockpit-secrets` | `path-exists /usr/local/sbin/secrets-admin` | the helper failed to install |
| `cockpit-wireguard` | `path-exists /usr/local/sbin/wg-admin` | the helper failed to install. It no longer keys on `/usr/bin/wg`, so the "your distro puts `wg` elsewhere" trap is gone — but `wireguard-tools` is still a real runtime dependency, just not a manifest condition |
| `cockpit-adlab` | `path-exists /usr/local/sbin/adlab-admin` | the helper failed to install |
| `cockpit-headscale` | `path-exists /usr/local/sbin/hs-admin` | the helper failed to install |
| guac-rdp / tuner | none | n/a |

**The one diagnostic that answers "why isn't the page there":**

```bash
cockpit-bridge --packages | grep -E 'wireguard|headscale|tuner|guac-rdp|secrets'
```

- listed → the manifest parsed and the conditions are met. Your problem is browser cache or
  session; hard-reload (`Ctrl-Shift-R`), and **log out of Cockpit and back in** — a new *menu
  entry* needs a new login, not a reload.
- absent, no error → a `conditions` path does not exist. Check the table.
- `cockpit.packages-ERROR: …` → malformed manifest; it names the file and the column.

### 3.2 cockpit-wireguard installs its own backend now — this is FIXED

Earlier revisions of this document warned that `wgclient.js` called `/usr/local/sbin/wg-admin`
and that nothing installed it, so the client-provisioning UI shipped with no backend. **That was
fixed and the fix is what ships.** The `FILES`/`POLICY_FILES` arrays it described no longer
exist; the manifest block in `install.sh` declares

```
HELPERS=(wg-admin wg-admin-package wg-policy wg-policy-watch)
```

and `install.sh` links all four into `/usr/local/sbin/`. Verified on edt1 on 2026-09-08: all four
are symlinks there. There is no manual `install` step to perform, and running one would leave a
regular file where the installer expects a link.

The same defect existed in `cockpit-headscale` (`hs-admin` was placed by hand and referenced
nowhere) and is fixed the same way: `HELPERS=(hs-admin hs-policy)`.

What is genuinely still on you, on every distro: `wireguard-tools` itself. `wg-admin` drives
`wg`/`wg-quick` and nothing here installs them.

### 3.3 Nothing restarts Cockpit, and nothing needs to

Cockpit rescans packages on a new session. No installer touches `cockpit.service`. On
RHEL/Rocky/Fedora `cockpit.socket` is usually already enabled, so
`systemctl enable --now cockpit.socket` is typically a no-op — run it anyway, it is harmless.

---

## 4. Ubuntu 26.04 "resolute" — the only proven target

This is the build host. Everything below has been run.

```bash
sudo apt-get update
# tier A + C prerequisites
sudo apt-get install -y cockpit cockpit-bridge cockpit-ws \
  python3-pykeepass python3-argon2 python3-lxml python3-construct \
  python3-botan python3-cryptography python3-pyotp python3-jsonschema
# tier B prerequisites
sudo apt-get install -y podman freerdp3-x11 xvfb x11vnc nftables gnome-remote-desktop dbus
# tier A extras
sudo apt-get install -y wireguard-tools qrencode
```

Then, per plugin:

```bash
git clone https://github.com/x86Since8088/cockpit-os-tuner.git      && (cd cockpit-os-tuner && sudo ./install.sh)
git clone https://github.com/x86Since8088/cockpit-wireguard.git     && (cd cockpit-wireguard && sudo ./install.sh)
git clone https://github.com/x86Since8088/cockpit-headscale.git     && (cd cockpit-headscale && sudo ./install.sh)
git clone https://github.com/x86Since8088/linux-cockpit-remote-desktop-guac.git && (cd linux-cockpit-remote-desktop-guac && sudo ./install.sh)
git clone https://github.com/x86Since8088/cockpit-secrets.git       && (cd cockpit-secrets && sudo ./install.sh)
```

Remember section 3.2: also `sudo install -o root -g root -m 0755 wg-admin /usr/local/sbin/wg-admin`
if you want WireGuard client provisioning.

`headscale` is not packaged by Ubuntu; see section 10.

Log out of Cockpit and back in.

---

## 5. Ubuntu 25.10 "questing" — untested, dependencies satisfied

Package versions are available for all three tiers. Nobody has installed here.

```bash
sudo apt-get update
sudo apt-get install -y cockpit cockpit-bridge cockpit-ws \
  python3-pykeepass python3-argon2 python3-lxml python3-construct \
  python3-botan python3-cryptography python3-pyotp python3-jsonschema
sudo apt-get install -y podman freerdp3-x11 xvfb x11vnc nftables gnome-remote-desktop dbus
sudo apt-get install -y wireguard-tools qrencode
```

Then clone and install as in section 4.

Known differences from the proven host, none of them known to break anything:

- `python3-botan` is 3.7.1 here versus 3.10.0 on edt1 — a three-minor gap inside a crypto
  binding. Untested.
- `python3-argon2` is 21.1.0. **This is fine.** `requires.txt` declares `>=21.3`, but the code
  uses only `argon2.low_level.hash_secret_raw`, `argon2.low_level.Type.ID` / `.D` and
  `argon2.exceptions.Argon2Error` (measured by reading `backends/kdbx.py`), all of which have
  existed since argon2-cffi 18.2. The declared floor is over-stated; ignore it.
- The FreeRDP 3 client binary is `/usr/bin/xfreerdp3` here. The installer handles both names.

---

## 6. Ubuntu 24.04 "noble" — untested; guac-rdp and the light plugins only

**`cockpit-secrets` will not work here and there is no workaround from the archive.**
`python3-botan` is 2.19.3, which provides the module `botan2`. The code does `import botan3`.
These are different module names, not different versions of one module — verified on edt1 that
`import botan3` succeeds and `import botan2` raises `ModuleNotFoundError`. `python3-pykeepass`
is also 4.0.7 against a declared 4.1.1. Do not attempt tier C on noble.

Tiers A and B:

```bash
sudo apt-get update      # noble-updates must be enabled; it is by default
sudo apt-get install -y cockpit cockpit-bridge cockpit-ws \
  podman freerdp3-x11 xvfb x11vnc nftables gnome-remote-desktop dbus
sudo apt-get install -y wireguard-tools qrencode
```

```bash
git clone https://github.com/x86Since8088/linux-cockpit-remote-desktop-guac.git
cd linux-cockpit-remote-desktop-guac && sudo ./install.sh
```

Two things to check on noble specifically:

- `freerdp3-x11` reaches 3.31 only via **noble-updates** and only on **amd64**. The base pocket
  and the non-amd64 ports carry 3.5.0. That clears the `>=3.0` floor but is nine minor releases
  behind anything ever exercised. Confirm with `xfreerdp3 /version` before assuming.
- Cockpit is 314 here versus 360 on the build host — 46 releases of `cockpit.js`, CSS and API
  drift. The `"requires": {"cockpit": "266"}` in every manifest is an assertion, not a test
  result. If a page renders blank or mis-styled on noble, that is the first thing to suspect.

---

## 7. Ubuntu 22.04 "jammy" — not supported

Do not attempt this, and do not try to rescue it with backports.

- `freerdp3-x11` **does not exist** in jammy, jammy-updates or jammy-backports. guac-rdp cannot
  be installed by any apt route.
- `gnome-remote-desktop` is 42.9 against a required 46.
- `podman` is 3.4.4 against a required 4.0.
- `python3-botan` is 2.19.1 (module `botan2`), `python3-cryptography` 3.4.8, `python3-pyotp`
  2.3.0, `python3-pykeepass` 4.0.1 — tier C is far out of reach.
- Cockpit is 264-1, below the 266 floor. `jammy-backports` has `360-1~bpo22.04.1` which clears
  *that* one line — **and fixes nothing else on this list.** It is not a workaround.

Tier A might install, but the tuner is the only one whose dependencies jammy actually meets.

---

## 8. Debian 13 "trixie" — untested; all three tiers appear satisfiable

Cockpit is 337 in the base archive, comfortably above the 266 floor.

```bash
sudo apt-get update
sudo apt-get install -y cockpit cockpit-bridge cockpit-ws \
  python3-pykeepass python3-construct python3-botan python3-cryptography
sudo apt-get install -y podman freerdp3-x11 xvfb x11vnc nftables gnome-remote-desktop dbus
sudo apt-get install -y wireguard-tools qrencode
```

`python3-argon2`, `python3-lxml`, `python3-pyotp` and `python3-jsonschema` were **not looked up
for Debian**. Add them to the line and see what apt says:

```bash
sudo apt-get install -y python3-argon2 python3-lxml python3-pyotp python3-jsonschema
```

Notes specific to trixie:

- `python3-argon2` is 21.1.0, below the declared `>=21.3`. **That floor is over-declared and
  can be ignored** — see the argon2 note in section 5.
- `python3-botan` is 3.7.1 (module `botan3`), which is the right module. Untested against this
  code.
- `freerdp3-x11` is 3.15.0 in the base archive; `trixie-backports` has 3.30.0 if you want to be
  closer to what has been exercised.
- Python is 3.13 here versus 3.14 on the build host.

Then clone and install as in section 4.

---

## 9. Debian 12 "bookworm" — tier A only

Worth stating plainly because the usual reflex is wrong: **Cockpit is 287.1 in bookworm and
clears the 266 floor on its own.** You do not need `bookworm-backports` for Cockpit. The
blockers are elsewhere.

- **`cockpit-guac-rdp` cannot run.** `gnome-remote-desktop` is 43.3 against a required 46 and
  there is no backport. `freerdp3-x11` is absent from the base archive (3.10.3 is in
  `bookworm-backports`), but pulling it does not fix gnome-remote-desktop, so it does not help.
- **`cockpit-secrets` cannot run.** `python3-botan` is 2.19.3 (module `botan2`, not `botan3`),
  `python3-cryptography` is 38.0.4, `python3-pykeepass` is 4.0.3.

Tier A:

```bash
sudo apt-get update
sudo apt-get install -y cockpit cockpit-bridge cockpit-ws wireguard-tools qrencode
git clone https://github.com/x86Since8088/cockpit-os-tuner.git   && (cd cockpit-os-tuner && sudo ./install.sh)
git clone https://github.com/x86Since8088/cockpit-wireguard.git  && (cd cockpit-wireguard && sudo ./install.sh)
```

---

## 10. Fedora, RHEL and Rocky

Fedora 41 and 42 are EOL and gone from the mirrors. The live releases are 43 and 44. RHEL/Rocky
9 is at 9.8; RHEL/Rocky 10 at 10.2.

### 10.0 Read this before any dnf line in this section

**No installer enables EPEL or CRB.** On RHEL/Rocky, most of what tier A and tier C need lives
in EPEL. Without it `dnf install` fails with a bare "no match for argument", which reads like a
broken installer rather than a missing repo. And the enable command differs by generation:

Rocky/Alma 9, RHEL 9 (dnf4):
```bash
sudo dnf install -y epel-release                        # Rocky/Alma
# RHEL 9 instead:
#   sudo subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms
#   sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
sudo dnf config-manager --set-enabled crb
```

Rocky/Alma 10, RHEL 10 (**dnf5 — `--set-enabled` was removed**):
```bash
sudo dnf install -y epel-release                        # Rocky/Alma
# RHEL 10 instead:
#   sudo subscription-manager repos --enable codeready-builder-for-rhel-10-x86_64-rpms
#   sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
sudo dnf config-manager setopt crb.enabled=1
# (AlmaLinux 10 has enabled CRB by default since Sept 2025; this may be a no-op there.)
```

**firewalld.** Port 9090 is not open by default. Upstream firewalld's `public.xml` contains only
`ssh` and `dhcpv6-client`. The `cockpit` service definition exists (it ships in both firewalld
and `cockpit-ws`), so:

```bash
sudo firewall-cmd --add-service=cockpit --permanent && sudo firewall-cmd --reload
sudo firewall-cmd --list-services
```

No plugin here needs any port other than 9090.

**SELinux — this is better than you expect, and that is a finding rather than an omission.**
Fedora's policy was traced against every install path these installers use. `/usr/local/sbin`,
`/usr/libexec/edy-rdp` and `/usr/local/bin` all resolve to `bin_t`; `/usr/local/lib/cockpit-secrets`
resolves to `lib_t`; `/usr/share/cockpit/*` to `usr_t`. `install -D` creates files inside
already-correct directories, so they inherit the right type without anyone running `restorecon`.
There is no `cockpit_bridge_t` — the bridge runs in the logged-in user's own domain, which for a
default `unconfined_u` admin is `unconfined_t`, and `unconfined_t` may execute `bin_t` freely.
**No policy module needs to be written and SELinux is not a blocker in the default targeted
configuration.**

Caveat, stated honestly: that whole paragraph is derived from reading Fedora's `selinux-policy`
sources and Cockpit's `selinux/cockpit.te`. **`matchpathcon` and `ls -Z` were never run on an
SELinux host, because there isn't one here.** Zero AVC denials have been observed because zero
installs have happened.

The four ways it still goes wrong:

1. **You unpack to `$HOME` or `/tmp` and `mv` files into place.** `mv` preserves the source
   label (`user_home_t`, `tmp_t`) and the bridge then gets `avc: denied { execute }`. The
   installers use `install -D`, so this only bites if you stage by hand.
2. A tarball unpacked with `--xattrs`/`--selinux` carrying foreign labels.
3. **Confined admins.** `staff_t` / `user_t` cannot run `nft`, `wg`, `podman` or `systemctl`,
   and no policy module for these helpers exists. `sysadm_t` is the workable confined case. None
   of this arises under the default `unconfined_u`.
4. **Overwriting `/usr/libexec/gnome-remote-desktop-daemon`** with a patched build (guac-rdp
   only, Fedora only). That path has its own fcontext, `gnome_remote_desktop_exec_t`. `cp` over
   an existing file preserves the label, but `install`, `mv` or an unpack gives it `bin_t`, and
   grd then stops entering its own domain. It will mostly appear to work, which is the bad kind
   of failure. Always:
   ```bash
   sudo restorecon -v /usr/libexec/gnome-remote-desktop-daemon
   ```

When something does go wrong, what you see is not an SELinux message — it is Cockpit showing
"access-denied" or a generic spawn failure, with the AVC only in the audit log:

```bash
sudo restorecon -Rv /usr/local/sbin /usr/local/lib/cockpit-secrets /usr/libexec/edy-rdp
ls -Z /usr/local/sbin/secrets-admin        # expect system_u:object_r:bin_t:s0
sudo ausearch -m AVC,USER_AVC -ts recent
```

**The `sudo` group does not exist on this family.** See section 10.4 — this one bites guac-rdp
hard and fails closed with no obvious cause.

### 10.1 Fedora 44 — untested; all three tiers appear satisfiable

The only release in the RPM family where every tier-C runtime dependency is packaged.

```bash
sudo dnf install -y cockpit cockpit-bridge cockpit-ws cockpit-system
sudo dnf install -y python3-pykeepass python3-argon2-cffi python3-lxml python3-construct \
  python3-botan3 python3-cryptography python3-pyotp python3-jsonschema
sudo dnf install -y podman freerdp xorg-x11-server-Xvfb x11vnc nftables gnome-remote-desktop dbus-tools
sudo dnf install -y wireguard-tools iptables-nft qrencode
sudo firewall-cmd --add-service=cockpit --permanent && sudo firewall-cmd --reload
sudo systemctl enable --now cockpit.socket
```

Note the renames: `python3-argon2` → **`python3-argon2-cffi`**, `python3-botan` →
**`python3-botan3`**, `xvfb` → **`xorg-x11-server-Xvfb`**, `dbus` → **`dbus-tools`**,
`freerdp3-x11` → **`freerdp`**. Fedora ships the FreeRDP 3 client under the unsuffixed name
`xfreerdp`; guac-rdp's `install.sh` detects this and symlinks `/usr/local/bin/xfreerdp3`.

Clone and install as in section 4, then read 10.4.

One risk that runs the *other* way from the usual: Fedora 43's `python3-pykeepass` is already
**4.2.0**, newer than the 4.1.1.post1 everything was written against, and this code reaches into
pykeepass internals (`pykeepass.kdbx_parsing.common`, `pykeepass.pykeepass.binaries`) — exactly
the surface a minor release is free to move. Untested-newer is a real risk here.

### 10.2 Fedora 43 — untested; as above with one crypto path missing

Same commands as 10.1 **minus `python3-botan3`**, which is not built for F43 (only
`python3-botan2` 2.19.5, which is a different module the code does not import).

Consequence, split by code path because it genuinely differs:

- **Password Safe v3 still works.** `backends/psafe3.py:_resolve_provider()` falls back to
  `backends/twofish_pure.py`, a pure-Python Twofish. Slower, functional.
- **KDBX3 databases encrypted with Twofish cannot be opened at all.** `backends/kdbx.py:1274`
  has no fallback: it catches `ImportError` and raises
  `Unsupported("KDBX3 databases encrypted with Twofish need python3-botan")`.
- AES and ChaCha20 KDBX are unaffected — `botan3` is imported lazily.

### 10.3 RHEL / Rocky 9 — tier A and a degraded tier C. No guac-rdp.

**`cockpit-guac-rdp` cannot run on EL9.** Two independent hard stops: FreeRDP is **2.11.7** in
AppStream and FreeRDP 2 cannot connect to gnome-remote-desktop (the project's own `requires.txt`
is emphatic about this and the installer's `freerdp3_bin()` refuses to proceed); and
`gnome-remote-desktop` is **40.0** against a required 46. There is no EPEL freerdp3 for EL9.
Nothing short of a third-party build changes this.

Do the EPEL+CRB step from 10.0 first, then:

```bash
sudo dnf install -y cockpit cockpit-bridge cockpit-ws cockpit-system
sudo dnf install -y python3-pykeepass python3-argon2-cffi python3-lxml python3-construct \
  python3-cryptography python3-pyotp python3-jsonschema
sudo dnf install -y wireguard-tools iptables-nft qrencode
sudo firewall-cmd --add-service=cockpit --permanent && sudo firewall-cmd --reload
```

What you get, stated exactly:

- **No Twofish backend.** `python3-botan3` is not in EPEL 9. Same split as Fedora 43 in 10.2:
  PWS3 falls back to pure Python; **KDBX3-with-Twofish raises `Unsupported`.**
- **Four dependencies below their declared floors:** `python3-pykeepass` 4.0.5 (declared 4.1.1),
  `python3-lxml` 4.6.5 (4.9), `python3-cryptography` 36.0.1 (41), `python3-jsonschema` 3.2.0
  (4.0). EPEL may not replace RHEL packages, so nothing raises the last three.

  Three of those four are **probably** survivable, and it is worth being precise about why —
  these are inferences from reading imports, not from running anything:
  - jsonschema 3.2.0: the code only ever constructs `jsonschema.Draft7Validator`, which exists
    in 3.2.0.
  - cryptography 36.0.1: the only imports are
    `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes`. AES,
    ChaCha20 and CBC all exist in 36.
  - lxml 4.6.5: EPEL 9 built pykeepass 4.0.5 against it, so the dependency resolves. The
    declared 4.9 is a "not tested older" floor, not a known API break.
  - **pykeepass 4.0.5 is the one to actually worry about.** The code touches pykeepass
    internals. Nobody diffed 4.0.5 against 4.1.1. This is the most likely place for a "package
    exists, plugin still broken" outcome on EL9.
- `dbus` is 1.12.20 against a declared 1.14 (matters only for guac-rdp, which is blocked anyway).
- Python is 3.9. That floor holds up: all 19 Python files across the plugins parse cleanly under
  `ast.parse(..., feature_version=(3,9))` with zero PEP-604 unions in evaluated annotation
  position. That is a static grammar check, not an execution.

Switching to a RHEL 9 parallel Python stack does not help: there is `python3.12-cryptography` and
`python3.11-lxml`, but no `python3.1x-pykeepass`, `-pyotp`, `-jsonschema` or `-botan3` for any of
them. You would trade one missing package for four.

### 10.4 RHEL / Rocky 10 — tier A, and tier C only via pip. No guac-rdp.

**`cockpit-guac-rdp` cannot run on EL10 either, and the reason is surprising.** freerdp is 3.10.3
and gnome-remote-desktop is 49.3, so both EL9 blockers are gone. But **RHEL 10 removed the X.org
server**: there is no `xorg-x11-server-Xvfb` in BaseOS, AppStream, CRB or EPEL 10 — only
`xorg-x11-server-Xwayland` and `xwayland-run`. And **`x11vnc` is in EPEL 9 but not EPEL 10**,
anywhere. The bridge chain is xfreerdp3 → **Xvfb** → **x11vnc** → guacd-VNC → browser, and both
middle hops are missing. Rebuilding it on `xwayland-run` + `wayvnc` is a port, not an install.

Do the EPEL+CRB step from 10.0 (note the dnf5 syntax), then:

```bash
sudo dnf install -y cockpit cockpit-bridge cockpit-ws cockpit-system
sudo dnf install -y python3-argon2-cffi python3-lxml python3-construct python3-botan3 \
  python3-cryptography python3-pyotp python3-jsonschema
sudo dnf install -y wireguard-tools iptables-nft qrencode
sudo firewall-cmd --add-service=cockpit --permanent && sudo firewall-cmd --reload
```

**`python3-pykeepass` does not exist for EL10.** Not in EPEL 10 at any minor (`/10/` and `/10.4/`
were both checked). cockpit-secrets' entire KDBX engine is that module. The only option is pip,
and **the pip command alone is not enough**:

```bash
sudo dnf install -y python3-pip python3-devel gcc
sudo python3 -m venv --system-site-packages /usr/local/lib/cockpit-secrets/venv
sudo /usr/local/lib/cockpit-secrets/venv/bin/pip install 'pykeepass>=4.1.1'
sudo restorecon -Rv /usr/local/lib/cockpit-secrets
```

`--system-site-packages` matters: it lets the venv reuse the RPM `python3-botan3`,
`python3-cryptography` and `python3-argon2-cffi` instead of rebuilding them. The venv path under
`/usr/local/lib` matters too — it labels as `lib_t`, which is what a confined domain needs to
`map` the compiled extensions. Put it in `/opt` or `/srv` and you would be filing `execmod`
denials.

**And then you must edit the source.** `secrets-admin` starts `#!/usr/bin/env python3`, which
resolves to `/usr/bin/python3`, so the venv is invisible to it. Change the shebang to
`#!/usr/local/lib/cockpit-secrets/venv/bin/python3` before installing, or extend `LIBDIR_RUNTIME`
to put the venv's `site-packages` on `sys.path`. Anyone who runs the pip command and stops there
gets a helper that still reports pykeepass missing.

This is a source edit, not a packaging step. It is also completely untested.

### 10.5 The guac-rdp admin-group trap — every non-Debian distro

`cockpit-guac-rdp` hardcodes the administrator group as `sudo` in three places
(`etcdefaults/edy-rdp:16`, `systemd/edy-rdp-relay.service:16` as the built-in fallback, and
`relay/edy_rdp_relay.py` as the `--admin-group` argparse default). On Fedora, RHEL, Rocky, Arch
and openSUSE the admin group is `wheel`. `is_admin()` calls `grp.getgrnam("sudo").gr_mem`, so
**every user comes out non-admin** and the console-mirror and remote-host features fail closed
with no visible cause.

```bash
getent group sudo || echo "no 'sudo' group on this host — fix /etc/default/edy-rdp"
sudo sed -i 's/^EDY_RDP_ADMIN_GROUP=sudo/EDY_RDP_ADMIN_GROUP=wheel/' /etc/default/edy-rdp
sudo systemctl restart edy-rdp-relay.service
```

(Moot on EL9 and EL10, which cannot run guac-rdp at all. It applies on Fedora.)

Note `cockpit-secrets` gets this right — it tries `("sudo", "wheel")` in order. guac-rdp just
does not use that pattern.

---

## 11. Where it does not work

### 11.1 Alpine Linux — not supported, and not close

**Cockpit is not packaged for Alpine.** Not in v3.24/main, v3.24/community, edge/main,
edge/community, or edge/testing. This was checked with `apk search -x cockpit`,
`cockpit-bridge`, `cockpit-ws`, `cockpit-system` inside a live Alpine 3.24.1 container across all
five repositories: not found. The `>= 266` floor is not *unmet*, it is *unmeasurable* — there is
no package to have a version.

All six plugins install into `/usr/share/cockpit/<name>/` and are served by `cockpit-bridge`. No
Cockpit, no plugin. Everything else is downstream of that.

The rest, for completeness, because the dependency situation is genuinely better than the
verdict sounds:

- **bash is required at both install *and* run time, and Alpine's base image has none.** Every
  installer is `#!/usr/bin/env bash` and uses `[[ ]]`, arrays, process substitution and
  `shopt -s nullglob` — all parse errors under busybox `ash`, so the script dies before its first
  action. Worse, `wg-admin`, `hs-admin`, `wg-policy`, `hs-policy` and the guac-rdp headless
  scripts are `#!/bin/bash` — these are the privileged helpers Cockpit forks on every page
  action. `apk add bash` is a hard runtime prerequisite, not a build convenience.
- **`apk` is not in guac-rdp's `detect_pm()`** (the loop is `apt-get dnf yum pacman zypper`), so
  the installer dies with "no supported package manager found". That is at least a clean
  failure.
- **OpenRC, not systemd.** guac-rdp's entire runtime is 11 systemd units and a socket-activated
  relay; that is a rewrite of the process model, not a translation. cockpit-secrets' `--with-agent`
  option cannot be ported at all without giving up the SO_PEERCRED identity property it exists
  for. The tuner loses its snapshot timer. wireguard/headscale lose their reconcilers, and
  `hs-admin` uses `systemctl is-active` to report state, so **it would report a
  perfectly healthy OpenRC headscale as "not running"**.
- `useradd`/`groupadd` need `apk add shadow`. `/usr/sbin/nologin` does not exist (it is
  `/sbin/nologin`), so guac-rdp records a non-existent shell for its service account.
- What is **not** a problem: busybox coreutils. `install -D -m -o -g`, `stat -c`, `sed`, `find
  -print0`, `awk`, `getent` were all tested individually and all work. `coreutils` does not need
  installing.
- The dependency packages are mostly there and good: FreeRDP **3.31.0 under the exact binary
  name `xfreerdp3`**, gnome-remote-desktop 50, podman, nftables, x11vnc, xvfb, headscale,
  wireguard-tools, and six of the eight cockpit-secrets Python modules including a working
  `py3-botan3` — `botan3.BlockCipher("Twofish").block_size() == 16` was actually run on musl and
  returns 16. **musl is not the wall. The missing Cockpit and the missing systemd are the wall.**
- `py3-pykeepass` and `py3-pyotp` are not packaged. A `venv --system-site-packages` + `pip
  install pykeepass pyotp` was run in a clean container with no compiler and succeeded, pulling
  musllinux wheels. But it breaks a stated project policy (`requires.txt` says "no pip install
  step, no virtualenv, no vendored wheel") and drags in `pycryptodomex`, a library the project
  consciously avoided.

If someone wants to change this, the order is: (1) somebody packages or builds Cockpit for musl —
that is a precondition, not a step; (2) `apk add bash shadow`; (3) add an `apk` arm to guac-rdp's
`detect_pm()`/`pkg_for()`; (4) decide explicitly what cockpit-secrets does about pykeepass and
pyotp and amend `requires.txt` so the policy and the reality agree; (5) an OpenRC story per
plugin — with guac-rdp declared out of scope rather than half-ported.

### 11.2 Ubuntu 22.04 and Debian 12

See sections 7 and 9. Ubuntu 22.04 is dead for tiers B and C. Debian 12 is tier A only.

### 11.3 cockpit-adlab — deployable now, with one defect you must know about

The two reasons this section used to give are both gone. It **is** a git repository (it ships
inside `lin-ad-lab-with-cockpit`, section 2.2), and its committed `manifest.json` condition is
`{"path-exists": "/usr/local/sbin/adlab-admin"}` — its own helper, not an edt1 path. Nothing
tracked in that repository names `/opt/sc/git` any more. Verified 2026-09-08 by reading
`origin/main`.

**The defect that remains, and it is why this is still section 11 and not section 4.**
`adlab-admin` does not read the `.env` the deploy contract seeds for it. It resolves the lab
tree as `$ADLAB_LAB_ROOT` → the path recorded in `/etc/adlab/lab-root` → a built-in discovery
sweep, and derives `lab.env`, `rdp.env`, the SYSVOL script and the administrator passphrase file
from whatever that returns. None of its six declared `ADLAB_*` keys is used, and there is no
`adlab-admin config` verb, though both `deploy.sh` and the lab's `install.sh` tell you to run one.

> **This remediation does not work against a plain clone, and you should know why before you
> try it.** `adlab-admin`'s `_lab_root()` accepts a recorded path only when
> `<path>/source/lab.env` is a file. The published `lin-ad-lab-with-cockpit` repository has
> `lab.env` at its **top level** — there is no `source/` directory in it. So a path pointing at
> your clone is rejected and the plugin stays inert, with no error naming the cause. It works on
> the build host only because the orchestrator layout happens to supply that extra level
> (`projects/samba-ad-lab/` containing `source/`). To use it you must reproduce that shape —
> the recorded path has to be the **parent of a directory named `source`** that contains
> `lab.env` — or wait for the code to accept a repository root directly. The same caveat
> applies to the `ADLAB_LAB_ROOT` key.


For you, on a machine that is not edt1, that means:

- Nothing writes `/etc/adlab/lab-root`. Neither installer creates it.
- The built-in sweep looks for a tree at paths that exist only on the build host.
- So unless you set `ADLAB_LAB_ROOT` in the environment, or create `/etc/adlab/lab-root`
  containing the absolute path of your `lin-ad-lab-with-cockpit` clone, every verb that touches
  lab configuration fails — while the page itself loads normally, because the manifest condition
  is satisfied by the helper being installed.

Editing `.env` will not fix it; the helper never reads that file. This needs a code change and is
recorded, not solved.

---

## 12. When it does not appear or does not work

In this order.

```bash
# 1. Does Cockpit see the package at all? THE diagnostic.
cockpit-bridge --packages | grep -E 'wireguard|headscale|tuner|guac-rdp|secrets'

# 2. Did the files land with the right owner and mode?
ls -l  /usr/share/cockpit/<name>/       # dir 0755 root:root, files 0644 root:root
ls -lZ /usr/share/cockpit/<name>/       # SELinux hosts: usr_t

# 3. Is the helper present and answering?
/usr/local/sbin/secrets-admin health    # must be ONE JSON object, exit 0
ls -lZ /usr/local/sbin/secrets-admin    # SELinux hosts: expect bin_t

# 4. The binary each plugin keys on
command -v wg && ls -l /usr/bin/wg      # cockpit-wireguard's literal condition path
xfreerdp3 /version || xfreerdp /version # guac-rdp: MUST report 3.x
command -v grdctl nft Xvfb x11vnc podman headscale

# 5. guac-rdp security invariants
ss -tlnp | grep 4822                    # 127.0.0.1 only
sudo nft list table inet edy_rdp_guacd  # owner match admits only the edy-relay uid
systemctl status edy-rdp-relay.socket edy-rdp-guacd.service edy-rdp-firewall.service

# 6. Non-Debian only
getent group sudo || echo "set EDY_RDP_ADMIN_GROUP=wheel in /etc/default/edy-rdp"

# 7. SELinux hosts, only if something actually failed
sudo ausearch -m AVC,USER_AVC -ts recent

# 8. Dry-run without touching anything (tuner / headscale / guac-rdp only)
DESTDIR=/tmp/stage ./install.sh && find /tmp/stage -type f
```

Re-measured 2026-09-08, and the split is **not** the one earlier revisions of this document gave.
`cockpit-secrets`, `cockpit-tuner` and `cockpit-guac-rdp` stage as an ordinary user when
`DESTDIR=` is set (their EUID check is guarded by it), which is the cheapest way to see what an
installer would do to your machine. `cockpit-wireguard` and `cockpit-headscale` refuse non-root
**unconditionally** — their EUID check is not guarded by `DESTDIR`.

### One documented option that no longer misbehaves, and one that still bites

- **`cockpit-headscale --with-policy` is accepted now.** Earlier revisions said the argument loop
  rejected it. It does not: the flag survives as an alias for `--with-units`, because helpers are
  no longer opt-in — the page cannot work without `hs-admin`. `WITH_POLICY=1 ./install.sh`, which
  those revisions recommended instead, is what does **not** work: no environment variable is read.
  On `deploy.sh`, `--with-policy` is the flag that actually enables and starts the reconciler.
- **`cockpit-headscale`'s `HS_ACL_POLICY_FILE` defaults to
  `/var/snap/headscale/common/acl-policy.hujson`.** That path only means anything where headscale
  is the Canonical snap, and on this host it must be inside the snap's writable area because
  confinement stops the daemon reading `/etc`. On a distro-packaged or upstream-binary headscale,
  repoint it: it is an `.env` key, and the seed follows the key rather than a literal, so changing
  `HS_ACL_POLICY_FILE` before you deploy puts the seeded policy where you actually want it. The
  same is true of `HEADSCALE_BIN` and `HEADSCALE_CONFIG`, which are **required** keys precisely
  because headscale is packaged by no distribution and there is no layout to fall back on.

### One inference to check yourself on RPM distros

`cockpit-secrets --with-agent` installs units into `/usr/local/lib/systemd/{user,system}`. On the
build host both directories are in systemd's search path (measured with `systemd-analyze
unit-paths`). **It is an inference — not a measurement — that this is a Debian/Ubuntu patch and
that Fedora/RHEL's systemd does not search there.** If the inference is right, `--with-agent`
installs units systemd never sees. Check before relying on it:

```bash
systemd-analyze --user unit-paths | grep local
```

`--with-agent` is opt-in and the project argues against enabling it, so this blocks nothing by
default.

### `headscale` and `tailscale` are not packaged where you probably are

`headscale` 0.28.0 is in Fedora 44 and `headscale` is in Alpine's community repo. It is in **no**
EPEL 9, EPEL 10, Rocky, Debian or Ubuntu repository. `tailscale` is in none of these on any
release. `cockpit-headscale`'s helper shells out to `headscale` 63 times and `tailscale` 26
times, so on most targets you must install both from upstream yourself before the plugin does
anything. It will otherwise look completely broken.

Likewise `qrencode` is EPEL-only on RHEL/Rocky, and `wg-admin`'s auto-install path for it is
`apt-get install -y qrencode` with no dnf branch — so on the RPM family that path is dead.
Pre-install `qrencode` and the QR feature works; leave it out and it fails at the point of use
rather than at install time.

---

## 13. Uninstall

Every installer has `--uninstall`:

```bash
cd <clone-dir> && sudo ./install.sh --uninstall
```

**What that does not remove**, stated because you are deploying something unproven and need the
way back to be honest:

- **This is now much less bad than earlier revisions of this document said.** The manual cleanup
  they printed for `cockpit-wireguard` is obsolete: `--uninstall` stops and disables
  `wg-policy-watch.service`, removes it, removes all four `/usr/local/sbin` helper links, the page
  links and `install.conf`. `cockpit-headscale` and `cockpit-tuner` do the same for their units,
  in the right scope (`systemctl --user` for a `--user` tuner install). Do not run those `rm -f`
  lines; on a current install they would delete links the installer already removed.

  What every one of them keeps, deliberately, is your **data**: the `.env`, and the operator files
  each names on the way out — `WG_STATE_DIR` (peer keys, client configs) and `WG_POLICY_FILE` for
  wireguard, the routing and ACL policies for headscale, `TUNER_UNDO_DIR` (the root-owned undo
  journal, the only record of what was changed on the machine) and every user's history directory
  for tuner. Removing those is a separate, deliberate action.

- **`deploy.sh --uninstall` vs `--remove`.** On a host you deployed with `deploy.sh`, `--uninstall`
  runs the installed `install.sh --uninstall` and leaves the deployed tree under `/opt/<project>`
  in place — so the previous payload is still there and rollback is still two local commands.
  `--remove` deletes the deployed payloads as well.

- **cockpit-secrets** deliberately keeps `/etc/cockpit-secrets` (registry and safe files),
  `/var/log/cockpit-secrets` (audit log), `/var/lib/cockpit-secrets/state` (lockout counters) and
  `/var/lib/cockpit-secrets/exports`. It prints all of them and tells you to `shred -u` the
  exports directory, **because an export there is an entire safe in plaintext.** It also cannot
  stop another user's agent — root cannot reach another user's systemd instance.
- **cockpit-guac-rdp** removes the most: units (instances and sockets stopped first), the polkit
  rule, the nft drop-ins, tmpfiles, the D-Bus policy, the libexec links, the page links and
  `install.conf`. It does **not** delete the `edy-rdp` group or the `edy-relay` user — uids
  outlive packages, and a reused uid is a permission that silently belongs to somebody else.

  It also does **not** revert the OS packages, the guacd container image, the
  gnome-remote-desktop greeter patch and its apt hold, or the 3390 door credential. Earlier
  revisions of this document said the greeter patch was restored; it is not, and the current
  installer says so explicitly, for the reason that it never applied them — those are `deploy.sh`
  flags and host state, not things `install.sh` ever touched.

One thing to know before you install, not after: **the installers sweep stale files.** They do
not copy a payload — they link it — but after linking they delete anything in
`/usr/share/cockpit/<name>/` that is not on the declared `PAGE` line. Do not put anything of your
own there; the next install run removes it.

---

## 14. Tell me what happened

You are almost certainly the first person to run this on your distro. A report is far more useful
than a fix attempt. Please send, as text rather than screenshots:

1. **Which distro, exactly.** `cat /etc/os-release` and `uname -r`.
2. **Which plugin and which repo/branch.** `git -C <clone> rev-parse HEAD` and
   `git -C <clone> branch --show-current`.
3. **The full installer output.** Run it as `sudo ./install.sh 2>&1 | tee /tmp/install.log` and
   send `/tmp/install.log` whole. Do not trim it — the idempotency lines
   (installed/updated/unchanged) matter.
4. **`cockpit-bridge --packages`** output, in full. This distinguishes "condition unmet" from
   "malformed manifest" from "browser cache", and those have three different fixes.
5. **Versions of whatever the plugin actually needs**, e.g.
   `cockpit-bridge --version; python3 -V; xfreerdp3 /version; podman --version; wg --version`
   and, for cockpit-secrets:
   ```bash
   python3 -c 'import pykeepass, argon2, lxml, construct, cryptography, pyotp, jsonschema; print("core ok")'
   python3 -c 'import botan3; print(botan3.version_string())'
   /usr/local/sbin/secrets-admin health
   ```
6. **On SELinux hosts:** `getenforce`, `ls -lZ /usr/local/sbin/secrets-admin /usr/share/cockpit/<name>/`,
   and `sudo ausearch -m AVC,USER_AVC -ts recent`. A page that loads fine and then fails on the
   first privileged action is almost always an AVC, and the browser will not say so.
7. **What you saw versus what you expected**, in one sentence. "No menu entry after logout/login"
   and "menu entry present, page blank" and "page works, unlock fails" are three unrelated bugs.

If the page is not there at all, run step 4 before anything else. It answers that question by
itself most of the time.

---

## 15. Summary of what is proven and what is not

- **Proven:** all six plugins install and run on Ubuntu 26.04.1, Cockpit 360, Python 3.14.4.
  That is one host.
- **Package-verified, deployment-untested:** Ubuntu 24.04 / 25.10, Debian 13, Fedora 43 / 44,
  RHEL / Rocky 9 and 10 as scoped per section. Every version number in this document that is not
  about Ubuntu 26.04 came from a repository index, and most of them from a single lookup that was
  not cross-checked against a second source.
- **Known not to work:** Ubuntu 22.04 (tiers B and C), Debian 12 (tiers B and C), RHEL/Rocky 9
  and 10 (guac-rdp), Alpine (everything). `cockpit-adlab` is no longer in this list — it is
  publishable and installable now, but its helper cannot find the lab without
  `ADLAB_LAB_ROOT` or `/etc/adlab/lab-root`; see section 11.3.
- **Re-measured 2026-09-08, and only this:** the public branch state of every repository, the
  `conditions` in every shipped `manifest.json`, the helper arrays in `cockpit-wireguard`'s and
  `cockpit-headscale`'s `install.sh` (and the corresponding symlinks on edt1), and
  `adlab-admin`'s path resolution. The distribution matrix in sections 5–11 was **not**
  re-measured.
- **Not assessed at all:** `python3-pyotp`, `python3-lxml` and `python3-jsonschema` on Debian;
  `xvfb`, `x11vnc`, `nftables` and `dbus` outside the build host (presence assumed from these
  being universally packaged, not confirmed); RHEL proper as distinct from Rocky (all EL versions
  were read off Rocky mirrors); AlmaLinux; Arch; openSUSE.
- `cockpit-guac-rdp/docs/COMPATIBILITY.md` marks Ubuntu 26.04 "tested (edt1)" and every other row
  "expected". That distinction is the correct one and it is preserved here.
