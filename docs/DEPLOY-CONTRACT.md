# DEPLOY-CONTRACT

**The layout and the rules that `deploy.sh` / `deploy.ps1` / `deploy.bat` and `install.sh` obey,
in every project in this tree.**

This file is normative. It lives in `cockpit-secrets` because that is the project with the
strictest gate and the most-reviewed installer, but it governs `cockpit-adlab`,
`cockpit-guac-rdp`, `cockpit-headscale`, `cockpit-secrets`, `cockpit-tuner` and
`cockpit-wireguard` equally, and the non-Cockpit projects in the same tree where they deploy at
all. Where an implementer's judgement and this file disagree, this file wins or this file gets
edited — not both.

Six people implementing from this document must produce the same directory tree, the same
symlinks, the same refusals. Where that required a decision that could reasonably have gone the
other way, it is marked **[JC]** with the trade-off stated. There are eleven of them and they are
indexed at the end.

---

## 0 · The two processes, on one page

There are two, they are not the same thing, and today no project in this tree has either of them
right.

| | `install.sh` | `deploy.sh` / `deploy.ps1` / `deploy.bat` |
|---|---|---|
| **What it is** | An in-place install **by symlink**, from wherever it is run | The real deployment: a copy, then config, then `install.sh` |
| **Moves bytes?** | **No.** It links; it never copies the payload | Yes. It is the only thing that copies |
| **Where it is run from** | The payload it is linking — dev checkout *or* install path | The dev checkout (or an unpacked release) |
| **How many exist** | One per project, and it is the **same script** in both roles | One per project, per OS; **self-contained** |
| **Depends on a shared framework?** | No | **No** — four of these repos are public and cloned alone |
| **Owns units/tasks?** | Renders and places them. Does **not** enable or start | Enables and starts what the operator asked for |
| **Owns `.env`?** | No. Reads it, verifies it exists | Yes. Seeds it from `.envdefault`, **missing-only** |
| **Root?** | Yes | Yes |

The single idea that makes this work: **the script is the same; only where it is run from
differs.** Run `install.sh` from a dev checkout and you get a dev install, whose Cockpit page is
a set of symlinks into the checkout, so editing `secrets.js` in the editor changes what the
browser loads on the next reload. Run the *identical* script from `/opt/cockpit-secrets/payload`
and you get a production install, whose links point at a tree that has no relationship to the
share. Nothing in the script branches on "am I dev or prod" to decide *what* to link. It branches
only to *record* which it did — see §3.

**Self-sustaining is the acceptance test.** After `deploy.sh`, unmount
`/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage` and the plugin still works,
including every helper, unit and timer. A dev install is deliberately the opposite: unmount the
share and it breaks, because it *is* the share. That is the point of a dev install, and §3 exists
so that nobody ever has to guess which of the two a host is running.

---

## 1 · The install-path layout

### 1.1 Where `[install path]` defaults to

**Linux: `/opt/<project>`** — `/opt/cockpit-secrets`, `/opt/cockpit-wireguard`,
`/opt/samba-ad-lab`. `<project>` is the repository directory name, not the Cockpit page name;
`cockpit-secrets` deploys to `/opt/cockpit-secrets` and serves at `/usr/share/cockpit/secrets`.

Justification, because the alternative was real:

- FHS §3.13 gives `/opt` to "add-on application software packages" — self-contained, one
  directory per package, installed outside the distribution's package manager. That is exactly
  what these are: locally built trees carrying their own installer, their own units, their own
  config seed.
- `/usr/local/lib/<name>` was the runner-up and it loses on lifecycle. `cockpit-secrets`
  **already** uses `/usr/local/lib/cockpit-secrets` for its Python library root (`backends/`,
  `schema/`) — files that `secrets-admin` imports at runtime. Putting the deploy tree at the same
  prefix would mean one directory whose contents have two different owners, two different
  replacement rules and two different uninstall behaviours. Keep `/usr/local/lib/<name>` meaning
  "the library the helper imports"; it stays a *destination of* install, not the *location of*
  the install.
- `/srv` is for data served by this host, not software.
- **`/opt/sc/git/...` is retired and this contract is why.** The retired path was not bad because
  it was under `/opt`; it was bad because it was a **git checkout** living where a deployed
  package should be, so "the deployed thing" and "the thing I edit" were one directory and
  nobody could tell which was which. `/opt` holds *deployed installs only*. **A checkout must
  never appear under `/opt` again.** The one true dev location is
  `/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/<project>/source`
  and nowhere else.

`deploy.sh --install-to <path>` overrides the default. It is honoured verbatim, it must be
absolute, and it is recorded (§4.2) so nothing else has to guess.

**[JC-1]** `/opt/<project>` over `/usr/local/lib/<project>`. Trade-off: `/opt` on some hosts is a
separate, smaller filesystem, and a few hardening profiles mount it `noexec` — which would break
every helper here. `deploy.sh` therefore **tests for `noexec` on the target filesystem in its
pre-flight and refuses** rather than producing an install that fails at first click.

### 1.2 Windows

Windows is out of scope for the six Cockpit plugins — they run under Cockpit, which is Linux.
The Windows half of this contract exists for the deliverables that genuinely ship there:
`cockpit-wireguard/source/windows-client`, `edy-proxy-go`'s Windows agents, and anything else in
the tree that grows a `deploy.ps1`.

```
C:\Program Files\<Project>\payload\        the payload; replaced wholesale on upgrade
C:\ProgramData\<Project>\.env              operator config; seeded missing-only
C:\ProgramData\<Project>\state\            state that survives upgrade
C:\ProgramData\<Project>\logs\
```

Same split, same reasons: `Program Files` is UAC-protected and Administrators-writable only,
which is the correct home for code a service executes; `ProgramData` is where config and state
that must outlive an upgrade belong, and a service running as `LocalSystem` or a virtual account
can be granted write there without being granted write over its own binaries. **A service that
can rewrite its own executable is a persistence mechanism, not a service.**

**Windows does not get the symlink model.** `mklink` needs elevation or Developer Mode, junctions
behave differently under every backup and AV product on the estate, and `SeCreateSymbolicLink` is
an audited privilege. `deploy.ps1` copies into `payload\`, and the Windows equivalent of
"in-place install" is simply that `install.ps1` is *run from* `payload\` and registers services
pointing there. **[JC-2]** Trade-off: no live-edit dev install on Windows. Accepted; the dev loop
for those components is "build, `deploy.ps1 -InstallTo C:\dev\<Project>`, restart the service",
which is fast enough and does not require Developer Mode on a domain-joined box.

### 1.3 The tree

```
/opt/<project>/                       0755 root:root
├── payload -> payload-1.4.2          symlink, root:root       THE swap point (§1.5)
├── payload-1.4.2/                    0755 root:root           immutable once written
│   ├── VERSION                       0644
│   ├── install.sh                    0755                     the copy that gets run
│   ├── manifest.json                 0644
│   ├── index.html   *.js  *.css      0644                     the Cockpit page files
│   ├── bin/                          0755                     helpers + compiled artifacts
│   │   ├── secrets-admin             0755
│   │   └── ...
│   ├── lib/                          0755                     backends/, schema/, modules
│   ├── systemd/                      0755                     *.service.in, *.timer
│   ├── etcdefaults/                  0755                     seed data, if the project has it
│   └── .envdefault                   0644                     the seed, shipped, never read live
├── payload-1.4.1/                    0755 root:root           the previous version; rollback
├── .env                              0644 root:root           OPERATOR CONFIG — never replaced
├── .install-log                      0640 root:root           what deploy did, when, from where
└── state/                            0700 root:root           only if /var/lib is wrong (§1.4)
```

Rules that make this shape mean something:

1. **`payload-<version>/` is immutable once written.** Nothing at runtime writes inside it — not
   a log, not a cache, not a `__pycache__`. `cockpit-secrets` already enforces the equivalent
   with `sys.dont_write_bytecode` in `secrets-admin` and a library-root assertion at the end of
   every install run; that assertion generalises here: after install, **the payload must contain
   exactly the declared manifest (§7) and nothing else.**
2. **`.env` is a sibling of `payload/`, not a child of it.** This is the whole reason the layout
   has a level of nesting the operator's `[install path]/source` sketch did not. The operator's
   rule is that `.envdefault` seeds a `.env` *in the install path*; the operator's other rule is
   that an upgrade must not touch operator config. Both hold only if the thing an upgrade
   replaces is *inside* the install path rather than *being* it. `payload/` is that thing.
3. **`payload/` not `source/`.** The operator's sketch said `source/`, and for these six
   interpreted plugins `source` would be honest. It is still the wrong word: it invites exactly
   the confusion that killed `/opt/sc/git` — an operator who sees `/opt/cockpit-secrets/source`
   reasonably concludes it is a checkout and edits it. `payload` says "this is what was shipped
   here; edit it and your next deploy discards your edit," which is true. **[JC-3]** Trade-off:
   it is one more name to learn, and it diverges from the operator's sketch. Earned by the
   failure it prevents.
4. **No `source/` and `bin/` as *peers* at the install root.** `bin/` lives *inside* the payload
   (§1.6), because the executables are part of what an upgrade replaces atomically. A `bin/` at
   the install root, beside a `payload/` that also gets replaced, gives you two things to swap
   and therefore a window where they disagree.

### 1.4 State, logs, and what survives an upgrade

**Nothing an upgrade replaces may hold state.** The rule for deciding where something lives:

| The thing | Where | Survives upgrade | Survives `--uninstall` |
|---|---|---|---|
| Page files, helpers, libs, unit templates | `payload-<v>/` | no (that is the point) | no |
| Operator settings — paths, ports, toggles | `[install path]/.env` | **yes** | **yes** |
| System config the software manages (registry entries, policy docs) | `/etc/<project>/` | **yes** | **yes** |
| Secrets, key material, safe files | `/etc/<project>/` at 0700, **never** in `.env` | **yes** | **yes** |
| Runtime state — counters, tokens, caches | `/var/lib/<project>/` | **yes** | **yes** |
| Logs, audit | `/var/log/<project>/` | **yes** | **yes** |

`/etc`, `/var/lib` and `/var/log` are used **in preference to** anything under the install path.
An operator's backup policy, logrotate configuration, SELinux labelling and `restorecon` already
know those three trees; they do not know `/opt/<project>/state`. `cockpit-secrets` gets this
right today (`/etc/cockpit-secrets/`, `/var/lib/cockpit-secrets/state`,
`/var/log/cockpit-secrets/`) and that placement is hereby the rule, not that project's private
habit.

`[install path]/state/` in the tree above is the exception hatch for a component that genuinely
cannot use `/var/lib` — a relocatable install under `--install-to`, a per-tenant deployment where
two copies coexist on one host. **If you use it, say why in the project's README.** A second
`state/` where `/var/lib` would have done is a backup that silently does not cover you.

**`--uninstall` removes software. It never removes data.** It removes the payload, the symlinks,
the units. It leaves `.env`, `/etc/<project>`, `/var/lib/<project>`, `/var/log/<project>` and
names each one on the way out, exactly as `cockpit-secrets`' installer does today. Removing them
is a separate, deliberate, documented operator action — never a flag on the installer that
somebody reaches for while tired.

### 1.5 The upgrade, and why the payload is versioned

```bash
# in deploy.sh, running as root
NEW="$ROOT/payload-$VERSION"
rm -rf -- "$NEW.tmp"                       # safe: we just built this name, see §2.4
mkdir -p -- "$NEW.tmp"
copy_declared_payload_into "$NEW.tmp"      # §7: the ONE declared list, nothing else
mv -T -- "$NEW.tmp" "$NEW"                 # the new version now exists, complete
ln -sfn -- "payload-$VERSION" "$ROOT/payload.new"
mv -T -- "$ROOT/payload.new" "$ROOT/payload"   # atomic rename: the swap
```

`mv -T` over a symlink is a single `rename(2)`. There is no instant at which `payload` does not
resolve, which matters because Cockpit is **live on this host at https://localhost:9090** and a
browser may be loading the page during the swap.

Then, and only then, `deploy.sh` runs `"$ROOT/payload/install.sh"` — the copy that now lives at
the install path — which re-points the symlinks in `/usr/share/cockpit/<name>` and
`/usr/local/sbin` (§2) and re-renders the units (§6).

`deploy.sh` keeps **one** previous `payload-<version>` and deletes older ones. Rollback is
`ln -sfn payload-1.4.1 payload.new && mv -T payload.new payload && payload/install.sh`. That is
the entire reason for versioning the directory rather than replacing a plain `payload/` in place:
a bad deploy against a live Cockpit is recoverable in two commands with no network and no share.

**[JC-4]** Versioned payload + symlink over "stage into `payload.new/`, `mv` the old aside,
`mv` the new in". Trade-off: two `readlink` hops from `/usr/share/cockpit/<name>/index.html` to
the real file, and one more concept. Earned by atomicity plus rollback; and the idiom is
thoroughly familiar from every release-management tool anyone here has used. If a project has a
strong reason to keep `payload/` a plain directory it may, **provided** the swap is still a
rename and not a `cp` over a live tree — but it then has no rollback and must say so.

### 1.6 `bin/`, and why these six mostly will not use it

`payload/bin/` holds **executables**: compiled artifacts and the verb helpers.

For a **compiled** project — a Go service, a Rust tool, anything with a build step — `bin/`
carries the built binaries and `deploy.sh` **does not ship the source at all**. That is the
operator's rule and it is right: the artifact plus the essential folders (`systemd/`,
`etcdefaults/`, `lib/` if the binary needs data files beside it, `install.sh`, `.envdefault`),
not the tree. Shipping `.git`, `tests/`, `node_modules/` or a vendor directory to a production
host expands the attack surface for nothing.

**For these six, the source largely *is* the artifact and there is no build step to invent.**
They are HTML + JavaScript + Python + bash. `index.html`, `secrets.js` and `wgclient.js` are the
bytes the browser loads, unchanged — `check.sh` exists in this project precisely because "there
is no build step for a Cockpit package: the files in this directory are the files the browser
loads, byte for byte." Do not add a bundler, a minifier or a transpile step to satisfy an
aesthetic sense that deployment should compile something. **What `deploy.sh` still must do is
ship a subset**, because a checkout contains a great deal that a production host has no business
holding:

Shipped: `manifest.json`, `index.html`, the `*.js` and `*.css` the page references, the helpers,
`lib/` (`backends/`, `schema/`), `systemd/`, `etcdefaults/`, `.envdefault`, `install.sh`,
`VERSION`, `LICENSE`, `README.md`.

Not shipped: `.git/`, `.claude/`, `tests/`, `docs/`, `__pycache__/`, `check.sh`, `validate.sh`,
`run_tests.sh`, `function-map/`, any `.env`, any `*.example` that is not under `etcdefaults/`,
any fixture, and anything not named by the declared manifest (§7).

`cockpit-secrets`' helper is a single 450 KB `secrets-admin` file that today sits at the repo
root; `cockpit-wireguard` has four helpers at its root; `cockpit-tuner` already has `bin/`. In
the payload they all land in `payload/bin/`. `install.sh` reads them from `bin/` and links them
to `/usr/local/sbin`. In a **dev checkout** the helper may stay at the root — `install.sh`
resolves it as "`bin/<helper>` if that exists, else `<helper>` beside me", one three-line
function, and it is the only place the two layouts are allowed to differ.

**[JC-5]** Tolerating that one layout difference instead of forcing every repo to move its
helpers into `bin/` today. Trade-off: a small asymmetry in one function, forever. Earned because
the alternative is a coordinated move across six repos, four of them public with their own
clone-and-run instructions, to buy nothing an operator can see. New projects put helpers in
`bin/` from the start.

---

## 2 · What `install.sh` links, and how

`install.sh` performs an in-place install **by `ln`**. It does not copy the payload. What it
copies, at most, is seed data into `/etc` (§5) and rendered unit files into the systemd path
(§7) — neither of which is payload.

### 2.1 The Cockpit page: a real directory of per-file symlinks

```
/usr/share/cockpit/secrets/               0755 root:root   A REAL DIRECTORY
├── manifest.json -> /opt/cockpit-secrets/payload/manifest.json
├── index.html    -> /opt/cockpit-secrets/payload/index.html
├── secrets.js    -> /opt/cockpit-secrets/payload/secrets.js
├── secrets.css   -> /opt/cockpit-secrets/payload/secrets.css
└── theme.js      -> /opt/cockpit-secrets/payload/theme.js
```

**Not** one directory symlink `/usr/share/cockpit/secrets -> /opt/cockpit-secrets/payload`.

The case for the directory symlink is genuinely good and it is worth stating before rejecting it:
it is one atomic `ln -sfn`; it survives a payload that gains or loses a file without re-running
anything; there is exactly one link to reason about and exactly one to remove.

It loses on one fact that outweighs all of that: **`install.sh` is the same script in a dev
install, and in a dev install the directory it would link to is the checkout.** Link
`/usr/share/cockpit/secrets` at
`/srv/smb/.../cockpit-secrets/source` and Cockpit is now serving `.git/`, `.claude/`, `tests/`,
`docs/`, `validate.sh` and `function-map/` over HTTPS to any authenticated Cockpit session.
`/usr/share/cockpit/<name>` is a **web root**. Handing a web root a symlink to a directory whose
contents you do not enumerate is how repositories end up on the internet.

Per-file linking also buys three things the directory link cannot:

- **The installer can refuse.** It links from a declared list; a declared file that is missing
  stops the install before anything is written. That is the same mechanism as §7's gate and it is
  worth having twice.
- **The stale-file sweep still works.** `cockpit-secrets`' installer sweeps its package directory
  down to exactly its `PLUGIN` array, and that sweep is what makes the array *the* description of
  the installed state rather than a hopeful comment. There is nothing to sweep behind a directory
  symlink.
- **`--uninstall` is unambiguous.** Removing a named symlink cannot remove anything else.

The cost is real and is accepted: **adding a file to the page requires re-running `install.sh`**,
even on a dev install. `theme.js` — the file this project's page referenced while the installer
swept it back off the host on every run — is the reminder that an unenumerated page file is not a
hypothetical.

**[JC-6]** Per-file symlinks over one directory symlink, argued above. If a future project's page
genuinely has dozens of assets in subdirectories (a bundled icon set, `guacamole-common-js`), the
escape hatch is a **per-subdirectory** symlink for that asset directory only —
`/usr/share/cockpit/guac-rdp/guacamole-common-js -> .../payload/guacamole-common-js` — declared
in the manifest as a directory entry, and it must be a directory that contains *only* servable
assets. The top level stays per-file. Never link the payload root.

### 2.2 The helpers

```
/usr/local/sbin/secrets-admin -> /opt/cockpit-secrets/payload/bin/secrets-admin
/usr/local/sbin/wg-admin      -> /opt/cockpit-wireguard/payload/bin/wg-admin
```

Per-file, necessarily: `/usr/local/sbin` is a shared namespace that eight helpers from six
projects already occupy (`adlab-admin`, `hs-admin`, `hs-policy`, `secrets-admin`, `wg-admin`,
`wg-admin-package`, `wg-policy`, `wg-policy-watch`). There is no directory to link.

Two hard rules:

- **A helper that a shipped page calls must be declared and linked, or the install refuses.**
  This is §7, and it exists because `wg-admin` and `hs-admin` are installed on this host,
  byte-identical to source, and mentioned **zero times** by their own installers — while
  `wgclient.js` names `/usr/local/sbin/wg-admin` thirty times. A fresh clone of the public repo
  installs a UI whose backend is absent, and the only reason nobody has hit it is that this host
  was hand-fixed once.
- **`install.sh` must refuse to overwrite a `/usr/local/sbin` entry it does not already own.** If
  the path exists and is a symlink into *this* install path, replace it. If it exists and is a
  symlink elsewhere, or a regular file, **stop and name it**. Two projects fighting over one
  helper name is a bug that must surface at install time, not as an intermittent wrong-verb error
  six months later.

Ownership check, one function:

```bash
# 0 = we may replace it; nonzero = refuse and print why.
owned_by_us() {
    local link=$1 want=$2 cur
    [[ -e "$link" || -L "$link" ]] || return 0        # absent: ours to create
    [[ -L "$link" ]] || { warn "$link exists and is NOT a symlink"; return 1; }
    cur=$(readlink -f -- "$link") || return 1
    [[ "$cur" == "$ROOT"/* ]] || { warn "$link -> $cur, which is not under $ROOT"; return 1; }
    return 0
}
```

### 2.3 Mode and ownership through a symlink

Modes are set on the **target**, in the payload, by `deploy.sh` when it copies — `0644` for page
files and libs, `0755` for anything in `bin/`, `0755` for directories, all `root:root`. `chmod`
on a symlink is a no-op on Linux; `chown -h` changes the link's own owner and nothing that
matters. **An installer that thinks it is setting the mode of a page file by `chmod`-ing the
symlink is setting nothing.** Verify targets, not links:

```bash
find /usr/share/cockpit/secrets -type l -printf '%p -> %l\n' | while read -r l _ t; do
    stat -Lc '%a %U:%G %n' "$t"
done
```

A dev install will legitimately show `eddie:smbusers` and group-writable modes here, because the
share is group-writable. That is a fact about a dev install, not a defect, and it is one more
reason the two kinds must be distinguishable at a glance (§3.3).

### 2.4 `--uninstall`, and the mistake that deletes the operator's work

**The danger, stated plainly: `rm -rf /usr/share/cockpit/secrets` where that path is a symlink
to the dev checkout deletes the dev checkout.** With `rm -rf` on a symlink-to-directory, GNU
`rm` removes the link and not the target — but `rm -rf /usr/share/cockpit/secrets/` **with the
trailing slash** follows it, and so does `rm -rf "$PKGDIR"/*`, and so does `find "$PKGDIR"
-delete` on some layouts. One trailing slash between a routine uninstall and losing the tree.
`cockpit-wireguard`'s installer does `rm -rf -- "$PKGDIR"` today; that is correct only for as
long as `$PKGDIR` is a real directory, which is exactly the assumption this contract changes.

**Bans, absolute:**

1. **No `rm -r`, `rm -rf`, `find -delete` or `rsync --delete` may target any path under
   `/usr/share/cockpit`, `/usr/local/sbin`, `/etc`, `/var` or the install path.** Not with a
   trailing slash, not with a glob, not ever.
2. **The only `rm -rf` permitted anywhere in an installer or deploy script targets a
   `payload-*` directory under the install root**, and only after the three assertions in the
   idiom below.
3. Removal is per declared entry. If it is not in the manifest, the uninstaller does not touch
   it, which also means it cannot touch anything a *different* project put there.

**The safe idiom, to be copied verbatim:**

```bash
# Remove one thing we installed. Never follows a symlink, never recurses.
remove_link() {
    local p=$1
    if [[ -L "$p" ]]; then
        rm -f -- "$p"          # removes the LINK. The target is untouched.
        say "unlinked $p"
    elif [[ -e "$p" ]]; then
        warn "$p is not a symlink - left in place, remove it by hand if you meant to"
    fi
}

# Remove a directory we created, ONLY if we emptied it.
remove_dir_if_empty() {
    local p=$1
    [[ -d "$p" && ! -L "$p" ]] || return 0
    rmdir -- "$p" 2>/dev/null && say "removed empty $p" \
        || say "kept $p (not empty - something else lives there)"
}

# The ONE recursive removal this contract allows.
remove_old_payload() {
    local p=$1 real
    [[ -d "$p" && ! -L "$p" ]]           || die "refusing: $p is not a real directory"
    real=$(readlink -f -- "$p")          || die "refusing: cannot resolve $p"
    [[ "$real" == "$ROOT_REAL"/payload-* ]] \
        || die "refusing to recursively remove $real - not a payload dir under $ROOT_REAL"
    [[ "$real" != "$ROOT_REAL" ]]        || die "refusing: that is the install root"
    rm -rf -- "$real"
}
```

`$ROOT_REAL` is `readlink -f` of the install root, resolved **once**, at the top of the script.
Comparing against an unresolved `$ROOT` is how a symlinked `/opt` defeats the containment check.

`--uninstall` removes, in order: the units (stopped and disabled first, §6.4), the
`/usr/local/sbin` links, the `/usr/share/cockpit/<name>` links, then `rmdir` that directory. It
leaves the payload alone — `--uninstall` un-*installs*; removing the deployed tree is
`deploy.sh --remove`, a different verb in a different script, which is itself the only caller of
`remove_old_payload` on a current payload.

**And the one that catches the real accident:** if `readlink -f /usr/share/cockpit/<name>/index.html`
resolves under
`/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/`, `--uninstall` prints
**"this is a DEV install; only symlinks will be removed, the checkout is not touched"** before it
does anything. Costs one line. Buys the operator the sentence they need to not panic.

---

## 3 · Dev install versus deployed install

### 3.1 How the script knows

It derives its own location. It is never told.

```bash
SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
SRC="$(cd -- "$(dirname -- "$SELF")" && pwd)"
```

`readlink -f` first, then `dirname` — `cockpit-secrets` already does exactly this and
`cockpit-wireguard` does not (`dirname "${BASH_SOURCE[0]}"` alone), which means a
`cockpit-wireguard` installer invoked through a symlink resolves its payload relative to the
*link's* directory. Fix it in all six.

`$SRC` is the payload root, whichever kind of install this is going to be. Everything the script
links comes from `$SRC`. **Nothing else in the script may branch on which kind it is** — the
whole design collapses the moment "dev" and "prod" grow different link logic, because then the
thing you tested is not the thing you shipped.

The classification is used for **recording only**, and it is one rule:

```bash
DEV_ROOT=/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects
if [[ "$SRC" == "$DEV_ROOT"/* ]]; then KIND=dev; else KIND=deployed; fi
```

**[JC-7]** Classifying by path prefix rather than by a marker file in the checkout (`.devtree`).
Trade-off: a checkout copied outside the share misclassifies as `deployed`. Accepted, because the
path prefix is a fact the operator can verify with `ls` and a marker file is a fact they have to
go and find; and because §4 of the operator's model states the share is the *one* dev location,
so a checkout elsewhere is already out of contract.

### 3.2 What actually differs in the result

Only three things, and none of them is *what* gets linked:

| | Dev install | Deployed install |
|---|---|---|
| Symlink targets | `<share>/projects/<p>/source/...` | `/opt/<project>/payload/...` |
| `.env` read from | `$SRC/.env` (tests only, §4.3) | `/opt/<project>/.env` |
| Units | rendered, **not enabled** — and refused entirely unless `--with-units` | rendered; `deploy.sh` enables |

That last row is a rule, not an observation. **A dev install must not enable a system unit.** A
developer running `install.sh` from the share while a deployed install of the same project runs
on the same host would otherwise get two `wg-policy-watch` daemons reconciling the same firewall
against two different policy files. `install.sh` refuses to render units at all when `KIND=dev`
unless `--with-units` is passed explicitly, and even then it never enables or starts.

### 3.3 How an operator tells, at a glance

Three ways, in increasing order of how tired the operator is.

**The marker file** — written by `install.sh` on every run, at a fixed path:

```
/etc/<project>/install.conf              0644 root:root
```
```sh
# Written by install.sh. Do not edit; re-run install.sh instead.
INSTALL_KIND=deployed
INSTALL_PATH=/opt/cockpit-secrets
PAYLOAD=/opt/cockpit-secrets/payload
ENV_FILE=/opt/cockpit-secrets/.env
VERSION=1.4.2
INSTALLED_AT=2026-09-07T14:02:11Z
INSTALLED_BY=install.sh
```

Same format as `.env` (§4.1), so one parser reads both. It is `install.conf`, deliberately not
`.env`: **`.env` is the operator's and `install.conf` is the machine's**, and nothing good comes
of one file being both.

**The link itself**, for when there is no time to read a file:

```bash
readlink -f /usr/share/cockpit/secrets/index.html
# /opt/cockpit-secrets/payload-1.4.2/index.html          <- deployed
# /srv/smb/.../projects/cockpit-secrets/source/index.html <- dev
```

**Every host, every plugin, one command** — put this in each README under "which install is
this?":

```bash
for d in /usr/share/cockpit/*/; do
    n=${d%/}; n=${n##*/}
    t=$(readlink -f "$d/index.html" 2>/dev/null) || continue
    case $t in
      /srv/smb/share/sc/ai-orchestrator-group/*) k="DEV  (share)";;
      /opt/*)                                    k="prod (/opt)";;
      "")                                        k="?? no index.html";;
      *)                                         k="OTHER";;
    esac
    printf '%-12s %s  %s\n' "$n" "$k" "$t"
done
```

**And in the UI.** Where a project has a helper with a status or `health` verb — `secrets-admin
health`, `wg-admin schema` — it reports `install_kind` and `install_path` read from
`install.conf`, and the page shows a small "dev install" marker when it is not `deployed`.
**SHOULD, not MUST**: it is UI work in six plugins, and the file marker is what actually has to
exist. But a host where nobody can tell whether Cockpit is serving from a share or from `/opt` is
a host where the next outage — an unmounted share at 03:00 — is unexplainable, and the person
explaining it is looking at a browser, not a terminal.

---

## 4 · `.envdefault` → `[install path]/.env`

### 4.1 Format

**One grammar, parseable by `sh` and by Python with no library, and it is a strict subset of both.**

```
# A full-line comment. The '#' must be the first non-whitespace character.
KEY=value
KEY="value with spaces"
EMPTY=
```

- `KEY` matches `^[A-Z][A-Z0-9_]*$`. Uppercase, because these end up as shell variables and a
  lowercase one will one day collide with something.
- **No `export`.** A shell consumer uses `set -a; . "$ENV_FILE"; set +a` or reads the keys it
  wants; `export` in the file is noise that a Python parser then has to learn to strip.
- **Quoting: optional double quotes around the whole value, stripped if present. Single quotes
  are literal characters, not quoting.** No backslash escapes. If a value needs a `"` or a
  newline, it does not belong in `.env` — put it in a file and put the file's path in `.env`.
- **No variable interpolation. No `$`, no `${...}`, no `$(...)`, no backticks.** This is the rule
  that bans `lab.env`'s `ADMIN_PASS_FILE="$SECRET_DIR/administrator.pass"`. A shell expands that;
  Python does not, unless somebody writes a small shell-semantics engine, and the day somebody
  does is the day command substitution becomes a code-execution primitive in a root-read config
  file. **Write the value out in full, or let the consumer join the two.** For the AD lab, §8
  does the latter.
- **A trailing `#` is part of the value.** `PORT=9090 # cockpit` sets `PORT` to
  `9090 # cockpit`. Inline comments are the single most common way two parsers disagree; full-line
  comments only, and the value is everything after the first `=` with surrounding whitespace
  trimmed and one optional layer of double quotes removed.
- Blank lines ignored. Last occurrence of a duplicate key wins, and the loader **warns**.

The whole Python side:

```python
def load_env(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError("%s:%d: not KEY=VALUE" % (path, n))
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
                raise ValueError("%s:%d: bad key %r" % (path, n, k))
            if len(v) >= 2 and v[0] == v[-1] == '"':
                v = v[1:-1]
            if any(c in v for c in "$`"):
                raise ValueError("%s:%d: %s contains $ or ` - interpolation is "
                                 "not supported (docs/DEPLOY-CONTRACT.md §4.1)" % (path, n, k))
            out[k] = v
    return out
```

`.envdefault` is the same grammar, ships in the repo, is **fully commented** — every key with a
sentence saying what it does and what happens if it is wrong — and every key it defines carries
a working default or an empty value with a comment saying it is required.

### 4.2 Seeding

**`deploy.sh` seeds. `install.sh` never writes `.env`.**

```bash
if [[ -e "$ROOT/.env" ]]; then
    say "kept existing $ROOT/.env (not overwritten)"
    new_keys=$(comm -23 <(keys_of "$SRC/.envdefault") <(keys_of "$ROOT/.env"))
    [[ -z "$new_keys" ]] || warn "this version adds keys your .env does not set: $new_keys"
else
    install -m 0644 -o root -g root -- "$SRC/.envdefault" "$ROOT/.env"
    say "seeded $ROOT/.env from .envdefault - REVIEW IT before first use"
fi
```

Missing-only, never clobber. This is `etcdefaults/`'s existing behaviour generalised —
`cockpit-secrets` seeds registry examples only where nothing is there, because "an operator's
registry entry is the access-control policy for a safe; clobbering one would silently change who
can open what." A `.env` is the same class of object: it is what the operator decided.

The new-keys **warning** is the missing-only rule's known cost, paid honestly. A version that
adds `LISTEN_PORT` will not add it to an existing `.env`; the deploy says so, and `install.sh`'s
pre-flight (§7) turns "a required key is absent" into a refusal.

**Mode `0644 root:root`.** **[JC-8]** Not `0600`. `.env` carries locations and settings — never a
secret — so a restrictive mode buys nothing and costs something real: a user-class helper running
as the logged-on user (the `superuser: null` path in `cockpit-secrets`' contract) must be able to
read its own configuration. Making it `0600` would force that helper to escalate to read a port
number, which is a worse trade than the "leak" of an operator learning where the payload lives.

**The rule that makes 0644 safe, and it is enforced, not promised:** `deploy.sh` refuses to write
a `.env` whose value looks like a credential.

```bash
# Refuse a key that names a secret and whose value is not a path to one.
while IFS='=' read -r k v; do
    [[ "$k" =~ (PASS|PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PASSPHRASE) ]] || continue
    [[ "$k" =~ _(FILE|PATH|DIR|NAME|ID)$ ]] && continue        # a pointer, fine
    [[ -z "$v" ]] && continue                                  # unset, fine
    die "$k in .env looks like a secret value. A deployed .env carries locations and
         settings, never secrets. Put the material in /etc/<project>/ at 0700 and name
         the FILE here (${k}_FILE=...)."
done < <(grep -v '^[[:space:]]*#' "$ROOT/.env" | grep '=')
```

`ADMIN_PASS_FILE=/etc/samba-ad-lab/secrets/administrator.pass` passes. `ADMIN_PASS=Hunter2`
does not, and the deploy stops.

### 4.3 How a helper finds it — and cannot find the wrong one

**A deployed helper must never read a `source/.env`.** The mechanism is not discipline; it is
that the deployed helper is never given a way to look relative to itself.

Resolution order, exactly, for every helper in every project:

1. `$<NAME>_ENV` if set **and** `geteuid() != 0` **and** the file is owned by the invoking uid.
   Tests only. A root helper ignores it entirely and says so on stderr if it was set. An
   environment variable that redirects a root process's configuration is a privilege escalation,
   and the fact that this file holds no secrets does not change that it holds *paths the root
   helper will act on*.
2. `ENV_FILE=` from `/etc/<project>/install.conf`. **This is the normal path and it is the only
   one that exists on a production host.**
3. Nothing. **Fail, loudly, naming `install.conf`.** There is no step 4.

There is deliberately **no** "look beside me" step. A helper at
`/usr/local/sbin/secrets-admin` is a symlink; `readlink -f` on it lands in the payload; a
`.env` beside the payload is `[install path]/.env`, which is the right answer — and that is
precisely why it must not be *implemented*, because the same code in a dev install lands in the
checkout and reads `source/.env`, which is the failure this section exists to prevent. The
indirection through `install.conf` is what makes the dev/prod distinction a fact recorded at
install time rather than a coincidence of where a file happens to sit.

Note the contrast with `secrets-admin`'s **library** root, which *does* resolve relative to
itself ("the directory holding `secrets-admin`, else `/usr/local/lib/cockpit-secrets`"). That is
correct for code — code must match the payload it shipped with — and wrong for config, which must
match the *host*. **[JC-9]** Two different resolution strategies in one helper for two different
kinds of file. Trade-off: a reader has to notice they are different. Earned: they answer different
questions.

### 4.4 The standing greps

Run by `check.sh` (or `validate.sh` where the project has one), in CI, and by
`deploy.sh --verify`. Each must print nothing.

```bash
# 1. No shipped file ever names a source .env.
grep -RIn --exclude-dir=.git -e 'source/\.env' -e '"\.env"' -e "'\.env'" \
     -- bin/ lib/ *.js *.sh 2>/dev/null

# 2. No helper resolves .env relative to itself.
grep -RIn --exclude-dir=.git \
     -e 'dirname.*\.env' -e '__file__.*\.env' -e '\$SRC/\.env' -e 'BASH_SOURCE.*\.env' -- bin/ lib/

# 3. Every helper that reads config reads install.conf, or reads nothing.
grep -RIl --exclude-dir=.git -e 'load_env\|\.env' -- bin/ \
  | xargs -r grep -L 'install\.conf'          # any file listed is a violation

# 4. On a live host: the deployed helper reads the deployed .env and no other.
strace -f -e trace=openat -o /tmp/x.$$ /usr/local/sbin/secrets-admin version >/dev/null 2>&1
grep -F '.env' /tmp/x.$$ | grep -v '^.*/opt/'   # any line is a violation
rm -f /tmp/x.$$
```

Grep 4 is the one that proves it rather than arguing it. **[JC-10]** It requires `strace`, which
is not on every host. Where it is absent, the substitute is grep 3 plus a deliberate negative
test: put a booby-trapped `.env` in the checkout with an obviously wrong value, run the deployed
helper, and confirm it does not appear.

---

## 5 · The relationship to `etcdefaults/`

**`.envdefault` does not replace `etcdefaults/`. It is not its single-file form either. They seed
different kinds of thing, to different destinations, with different lifecycles — and they share
exactly one rule, which is missing-only.**

| | `.envdefault` | `etcdefaults/` |
|---|---|---|
| What it seeds | **Settings the software reads on every run** | **Data files the software manages** |
| Cardinality | Exactly one file, always present, always read | Zero or many; a working install may have none |
| Destination | `[install path]/.env` | `/etc/<project>/...` |
| Schema | The §4.1 grammar | The project's own (`safe-registry.schema.json`) |
| Seeded as | The live file | Often `*.example` — inert until the operator renames it |
| Missing means | **Refuse the install** (§7) | Fine; the software has nothing to manage yet |
| Who writes it after | Only the operator | The operator *and* the software |

The choosing rule, for an implementer holding a file and not knowing which it is:

> **Does the software read this to know how to behave, or does the software act on this as
> content?** Behaviour is `.envdefault`. Content is `etcdefaults/`.
>
> Second cut, if that is ambiguous: **can there be zero of them, or more than one?** If yes, it
> is `etcdefaults/`. `.env` is always exactly one.

Worked, on the two projects that have `etcdefaults/` today:

- **`cockpit-secrets/etcdefaults/*.json`** — registry entries under `/etc/cockpit-secrets/safes.d/`.
  Zero or many. Each is a distinct object with a schema, describing a safe and who may open it.
  The software validates them and acts on them. **`etcdefaults/`, correctly**, and they are seeded
  as `.json.example` precisely so the registry's `*.json` glob cannot pick one up — a beautiful
  detail that has no analogue in `.env`, because there is no glob and an inert `.env` is just a
  broken install. This project will *also* gain a `.envdefault` naming its registry directory,
  its log directory and its lockout thresholds.
- **`cockpit-guac-rdp/etcdefaults/edy-rdp`** — a single file of settings, seeded into `/etc`.
  **This is `.envdefault` wearing the wrong hat.** If its contents fit the §4.1 grammar, it
  becomes `.envdefault` and its destination moves to `[install path]/.env`. If it does not fit —
  if it is structured, or has sections — it stays in `etcdefaults/` and the project gets a
  separate `.envdefault` whose job is to name *where* it lives. Do not force one file to be both.

A project may have both; most will. A project may have `.envdefault` and no `etcdefaults/`; that
is the common case. **A project must never have `etcdefaults/` and no `.envdefault`** — if it has
system data to seed, it has at minimum a location to record, and that location belongs in `.env`
so nothing has to hardcode `/etc/<project>`.

---

## 6 · Services and scheduled tasks

Six of these projects already ship units — `wg-policy-watch.service`,
`hs-policy-watch.service`, `sysvol-replicate.{service,timer}`, `cockpit-tuner-snapshot.{service.in,timer}`,
eleven under `cockpit-guac-rdp/systemd/`, and `cockpit-secrets`' optional agent user unit. Today
they are created by whatever script felt like it. Ownership is now fixed.

### 6.1 Who owns what

- **`install.sh` renders and places.** It substitutes the install path into the unit templates,
  writes them to the system unit directory, runs `systemctl daemon-reload`. **It does not
  `enable`, `start`, `restart` or `disable` anything.** In a dev install it refuses to do even
  this much without `--with-units` (§3.2).
- **`deploy.sh` enables and starts**, and only what the operator asked for by flag —
  `--with-policy`, `--with-agent`, `--with-timer`, matching each project's existing opt-in flags.
  A deployment that silently starts a daemon which rewrites firewall rules is not a deployment
  anyone should run twice.
- **Neither ever touches `cockpit.socket`.** Not `restart`, not `reload`, not `try-restart`.
  Cockpit is live at https://localhost:9090 and rescans its package directory when a session
  starts. A page reload is sufficient; a logout/login is needed only for a changed menu entry.

The split matters because `install.sh` runs in both roles and `deploy.sh` runs in one. Anything
that changes the *running state of the host* belongs to the script that only ever runs on a host
being deployed to.

### 6.2 How a unit references the install path

**`@PLACEHOLDER@` templates. `*.service.in` → rendered.**

```ini
# systemd/wg-policy-watch.service.in
[Unit]
Description=WireGuard routing-policy reconciler
After=network-online.target

[Service]
Type=simple
ExecStart=@PAYLOAD@/bin/wg-policy-watch
EnvironmentFile=@ENV_FILE@
Restart=on-failure
```

```bash
render_unit() {                       # render_unit <name>
    local in="$SRC/systemd/$1.in" out="$UNITDIR/$1"
    [[ -f "$in" ]] || die "missing unit template $in"
    sed -e "s|@PAYLOAD@|$SRC|g" \
        -e "s|@INSTALL_PATH@|$ROOT|g" \
        -e "s|@ENV_FILE@|$ROOT/.env|g" \
        -e "s|@SBIN@|/usr/local/sbin|g" "$in" > "$out.new"
    grep -q '@[A-Z_]\+@' "$out.new" \
        && { rm -f "$out.new"; die "unrendered placeholder(s) in $1: $(grep -o '@[A-Z_]*@' "$out.new" | sort -u | tr '\n' ' ')"; }
    chmod 0644 "$out.new"; chown root:root "$out.new"
    mv -f -- "$out.new" "$out"
}
```

`cockpit-tuner` already does this (`@SNAPSHOT@` in
`systemd/cockpit-tuner-snapshot.service.in`). **Adopt tuner's pattern; reject `install-timer.sh`'s.**

`samba-ad-lab/sysvol/install-timer.sh` does:

```bash
sed "s#/opt/sc/git/samba-ad-lab/source/sysvol#$HERE#g" "$HERE/$u" > ...
```

It substitutes a **literal old path**, and it is a trap in three separate ways. It silently
no-ops if the committed unit is ever edited to a different path — you then install a unit
pointing at whatever the file said, with a success message. The committed unit is itself a valid
unit file naming a dead path, so it can be installed by hand or by a packaging tool and appear to
work. And it hardcodes the retired path in a file that must be grepped for the retired path,
which is why `samba-ad-lab` still contains it in thirteen places across nine files. A placeholder
that appears nowhere else is impossible to no-op silently: the `grep -q '@[A-Z_]\+@'` guard above
turns a missed substitution into a refusal instead of a working-looking unit.

Its one good idea is kept: `cd "$(dirname "$(readlink -f "$0")")"` — the script derives its own
location. That is §3.1 and it is correct.

`.timer` files need no rendering (they reference the `.service` by name) and are copied. They
still go through the placeholder check, because a timer that grew an `ExecStart` should fail
loudly.

**Unit directory: `/etc/systemd/system/`** for units the operator is expected to manage, which is
all of these. `/usr/local/lib/systemd/system/` is defensible for units considered part of the
software rather than the configuration — `cockpit-secrets` uses it for its agent template today
and may keep it. **[JC-11]** Trade-off: `/etc` units are what `systemctl edit` and every
troubleshooting article assume, and they survive an uninstall that forgets them (visibly, as a
failing unit, which is better than invisibly). `/usr/local/lib` keeps `/etc` clean and lets a
drop-in override without a diversion. Either is acceptable; **the project must pick one and record
it in `install.conf` as `UNITDIR=`,** so `--uninstall` on a host installed by a different version
still finds them.

### 6.3 `EnvironmentFile` and the two config files

A unit takes `EnvironmentFile=@ENV_FILE@` — that is `[install path]/.env`, and this is the second
consumer of the §4.1 grammar. systemd's `EnvironmentFile` parser is stricter than shell: it wants
`KEY=value`, it treats `#` at line start as a comment, and it does **not** do command
substitution. §4.1 was written to be a subset of what systemd, `sh` and Python all accept, and
that is not a coincidence.

`EnvironmentFile=` on a missing file makes the unit fail to start. Use `EnvironmentFile=-@ENV_FILE@`
**only** where the unit genuinely works with no configuration; otherwise let it fail, because a
daemon running with defaults it was not configured with is worse than a daemon that did not start.

### 6.4 What `--uninstall` must do to units

In this order, and failures are warnings, not aborts — an uninstall that stops halfway leaves a
worse host than one that finishes noisily:

```bash
for u in "${UNITS[@]}"; do
    systemctl stop    "$u" 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true     # removes enablement symlinks
    remove_link_or_file "$UNITDIR/$u"
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true         # else a removed unit lingers as failed
```

Templates (`edy-rdp-headless@.service`) need their **instances** stopped too:
`systemctl stop 'edy-rdp-headless@*'`. Sockets need the socket stopped before the service, or
systemd starts the service again on the next connection. `--uninstall` names every unit it
stopped, and every unit it found enabled that it did **not** recognise.

### 6.5 Windows, in outline

`deploy.ps1` after copying into `C:\Program Files\<Project>\payload`:

- **Services** — `New-Service -Name <Project> -BinaryPathName '"C:\Program Files\<Project>\payload\bin\svc.exe" --config "C:\ProgramData\<Project>\.env"' -StartupType Manual`.
  Manual, not Automatic: the operator starts it, same rule as §6.1. Run under a **virtual
  account** (`NT SERVICE\<Project>`) rather than `LocalSystem` where the work does not need
  machine identity. Grant it write on `C:\ProgramData\<Project>` only — never on `payload\`.
- **Scheduled Tasks** — `Register-ScheduledTask` with an action whose `-Execute` is under
  `payload\bin\` and `-WorkingDirectory` is `C:\ProgramData\<Project>`. Register it under a task
  folder named for the project (`\<Project>\`) so uninstall can enumerate it, and never at the
  root of the task library.
- **Templates** — same `@PLACEHOLDER@` idea, `(Get-Content $in) -replace '@PAYLOAD@', $payload`,
  with the same refusal if any `@...@` survives.
- **Uninstall** — `Stop-Service`; `sc.exe delete`; `Unregister-ScheduledTask -TaskPath '\<Project>\' -Confirm:$false`;
  remove `payload\`; **leave `C:\ProgramData\<Project>` alone**, and name it on the way out.
- **`deploy.bat`** is a thin wrapper: `powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" %*`.
  It exists so an operator can double-click, and it contains no logic — logic in two languages is
  logic that diverges.

---

## 7 · The completeness gate

**Every install and deploy script derives its payload from ONE declared list and refuses if the
page asks for something that list does not ship.**

This exists because of a measured defect. `wg-admin` and `hs-admin` are installed on this host,
byte-identical to their source, and their installers reference them **zero times**.
`cockpit-wireguard`'s `wgclient.js` names `wg-admin` thirty times and pins it in one constant at
line 68: `var WG_ADMIN = "/usr/local/sbin/wg-admin";`. A fresh clone installs a client UI whose
backend does not exist. `wg-admin-package`, `wg-policy`, `wg-policy-watch` and `hs-policy` get
checked the same way.

`cockpit-secrets` already has a gate of this shape and it is the model: one `PLUGIN` array that is
"three things at once: the copy list, the stale-file sweep, and the payload-present check — they
cannot disagree with each other because they are all reading this line," plus an HTML parser that
refuses an install where `index.html` references a file `PLUGIN` does not ship. That gate was
written after `theme.js` shipped in the page and not in the array, and the installed host deleted
it on every run. Generalise it.

### 7.1 The declaration

At the top of `install.sh`, and it is the only place any of this is written down:

```bash
PAGE=(manifest.json index.html wireguard.js wgclient.js wireguard.css)   # -> /usr/share/cockpit/<name>/
HELPERS=(wg-admin wg-admin-package wg-policy wg-policy-watch)            # -> /usr/local/sbin/
LIBS=(lib/schema lib/backends)                                           # -> /usr/local/lib/<project>/
UNITS=(wg-policy-watch.service)                                          # -> $UNITDIR, rendered
SEEDS=(etcdefaults)                                                      # -> /etc/<project>/, missing-only
ENVDEFAULT=.envdefault
REQUIRED_ENV=(WG_INTERFACE WG_POLICY_FILE)                               # keys .env must define
```

`deploy.sh` **sources this same declaration** rather than restating it —
`eval "$(sed -n '/^# BEGIN-MANIFEST/,/^# END-MANIFEST/p' "$SRC/install.sh")"`, or the declaration
moves to a `payload.manifest` file that both `source`. Either is fine; **two lists is not.** That
is the failure mode being designed out, and re-introducing it in the deploy script is the obvious
way to re-introduce it.

### 7.2 The pre-flight — every check refuses, before anything is written

Ordered so the cheapest refusal comes first, and **nothing is written until all of them pass**.

1. **Payload present.** Every entry of `PAGE`, `HELPERS`, `LIBS`, `UNITS` (as `<name>.in` or
   `<name>`), plus `$ENVDEFAULT`, exists under `$SRC`. Missing → refuse, list them all.
2. **The page asks only for what is shipped.** Parse `index.html` — parse, do not grep — and
   collect every `src`, `href` and `data` that resolves package-locally. Every one must be in
   `PAGE`. Skip anything with a scheme, an authority, a leading `/`, or a leading `../`
   (`../base1/cockpit.js` is Cockpit's own file). `cockpit-secrets`' implementation is the
   reference; copy it.
3. **Every helper the page names is shipped and will be linked.** *This is the `wg-admin` catch.*

   ```bash
   # Every /usr/local/sbin/<x> literal anywhere in the shipped page files.
   named=$(grep -oh '/usr/local/sbin/[A-Za-z0-9_-]\+' "${PAGE[@]/#/$SRC/}" \
           | sed 's#.*/##' | sort -u)
   for h in $named; do
       printf '%s\n' "${HELPERS[@]}" | grep -qx "$h" \
         || die "the page calls /usr/local/sbin/$h, which HELPERS does not install.
                 Add it to HELPERS, or stop the page calling it."
   done
   ```

   Comments count. `wgclient.js` names `wg-admin` in its header comment as well as in its
   constant, and a false positive here costs one word in an array while a false negative costs a
   UI with no backend. **Bias to declaring.**

   The corollary is a ban, because the grep can only see literals: **a shipped page file must
   name each helper it calls in exactly one top-of-file constant, as a literal absolute path.**
   `var WG_ADMIN = "/usr/local/sbin/wg-admin";` — good, and already the convention in
   `wgclient.js` and `secrets.js`. Building the path at runtime, or holding it in state a
   `cockpit.spawn` later reads, defeats the gate. Where a page must spawn a path from
   configuration (`cockpit-headscale`'s `state.bin`, which is the headscale binary and not a
   project helper), that value comes **from `.env` via the helper**, never from a literal the gate
   cannot see, and the project README says so.
4. **A declared helper that nothing calls is fine.** `wg-admin-package` is invoked by an operator,
   not by the page. Under-declaring is the bug; over-declaring is not.
5. **Every `UNITS` entry renders clean** — no `@PLACEHOLDER@` survives (§6.2), and every
   `ExecStart=` path, after rendering, points at a file the payload actually ships.
6. **`.envdefault` parses** under §4.1, and every key in `REQUIRED_ENV` appears in it.
7. **On install: `.env` exists and defines every `REQUIRED_ENV` key** with a non-empty value.
   Missing file → "run `deploy.sh` first, or create it from `.envdefault`". Missing key → name it.
   This is where §4.2's "missing-only seeding cannot add new keys" is caught, at the only moment
   it can be caught safely.
8. **Nothing declared collides with another project.** For each `HELPERS` entry and each
   `UNITS` entry, if the destination exists and is not ours (§2.2), refuse and name the owner.
9. **No `/opt/sc/git`, and no dev root, in anything being shipped.**

   ```bash
   grep -RIn -e '/opt/sc/git' \
        -e '/srv/smb/share/sc/ai-orchestrator-group' \
        -- "${PAGE[@]/#/$SRC/}" "${HELPERS[@]/#/$SRC/bin/}" "$SRC"/systemd/ "$SRC/$ENVDEFAULT" \
     && die "a shipped file hardcodes a dev or retired path. It belongs in .env."
   ```

   This one check, had it existed, would have caught all thirteen occurrences in `samba-ad-lab`,
   including the two that are broken right now.

### 7.3 Post-install assertion

After linking, `install.sh` asserts what it produced, and this is separate from the pre-flight on
purpose — a script that only checked its intentions would report the mode it meant to set:

- `/usr/share/cockpit/<name>/` contains **exactly** `${PAGE[@]}`, every one a symlink, every
  target resolving under `$SRC`, every target existing. Anything else present is swept (it is a
  symlink; `remove_link` handles it) and **named in the output**.
- Every `HELPERS` entry is a symlink under `/usr/local/sbin` resolving into `$SRC`, and
  `test -x` on the resolved target.
- The library root contains only what was declared — `cockpit-secrets`' existing
  `assert_library_root_clean` generalised, including the `__pycache__` sweep it learned to do.
- `install.conf` was written and its `PAYLOAD` resolves to `$SRC`.

---

## 8 · Worked example — cockpit-adlab and its sibling project

`cockpit-adlab` is the only plugin that needs another project's location, which makes it the
example. It was also, when this was written, the most broken thing in the tree; see the
status note in §8.1 for what has since been fixed.

### 8.1 What was wrong (audited 2026-09-08)

- `/usr/share/cockpit/adlab/manifest.json` and `/usr/local/sbin/adlab-admin` both contain
  `/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/samba-ad-lab/source/...`.
  A host whose share is unmounted has a plugin that is not merely broken but **absent**, because
  of the next point.
- `manifest.json` has `{"path-exists": "/opt/sc/git/samba-ad-lab/source/lab.env"}` — the retired
  path. **An unmet Cockpit condition makes the package silently absent**: no page, no menu entry,
  no error anywhere the operator will look. The condition currently points at a file that does not
  exist, and the tracked copy in `samba-ad-lab/source/cockpit-adlab/` differs from the installed
  copy only in these hardcoded paths.
- `adlab-admin` carries four path constants at lines 48–50 and 67, all naming `/opt/sc/git`.
- **`lab.env`'s `SECRET_DIR` is broken right now.** It says `/opt/sc/git/samba-ad-lab/.secrets`
  while the real secrets are at
  `/srv/smb/share/.../projects/samba-ad-lab/.secrets` (0700, root-only) — and `10-build.sh` runs
  `install -d -m 0700 "$SECRET_DIR"`, so **a build today silently creates an empty secrets
  directory at the dead path** and proceeds.
- `cockpit-adlab` is not a git repo, and a second tracked copy lives at
  `samba-ad-lab/source/cockpit-adlab/` (11 files; 9 identical). **The tracked copy under
  `samba-ad-lab/source/` is canonical.** The untracked `projects/cockpit-adlab/` becomes a
  deployed install at `/opt/cockpit-adlab`, produced by `deploy.sh`, and stops being a place
  anyone edits. It is not a seventh repository; it is the *output* of the sixth.

> **Status as of 2026-09-11.** Four of the five findings above are resolved; the fifth is
> structural and still open. Re-verified on edt1 while repairing the 17 `samba-ad-lab` containers
> that failed to start from the same root cause — bind-mount sources baked into the container
> config before the consolidation, which only surface on the next start.
>
> - **Resolved — hardcoded share path in the installed files.** Neither
>   `/usr/share/cockpit/adlab/manifest.json` nor `/usr/local/sbin/adlab-admin` hardcodes the share
>   path any more, so an unmounted share no longer makes the plugin *absent*.
> - **Resolved — the manifest condition.** The installed manifest and the canonical tracked copy
>   both gate on `{"path-exists": "/usr/local/sbin/adlab-admin"}` — exactly the rule §8.4
>   prescribes. The untracked `projects/cockpit-adlab/source/` copy still carried the retired path
>   until 2026-09-11 and has been aligned with the other two.
> - **Resolved — `adlab-admin`'s four path constants.** Replaced by `_lab_root()`, which resolves
>   `$ADLAB_LAB_ROOT` → the path recorded in `/etc/adlab/lab-root` (currently the projects tree) →
>   a discovery sweep for a tree that actually contains `source/lab.env`. **Caveat when auditing
>   this file:** its candidate literals are deliberately assembled from parts, so `grep -r` for a
>   retired root returns nothing even where one survives as a last-resort candidate. A clean grep
>   is not proof here; read `_lab_root()`.
> - **Resolved — `lab.env`'s `SECRET_DIR`.** It is no longer a literal. It is derived from
>   `lab.env`'s own location between explicit `>>> SECRET_DIR` / `<<< SECRET_DIR` markers, so it
>   follows the tree, and `install.sh` rewrites it to an absolute path only when installing to
>   `/etc/samba-ad-lab/lab.env`. Verified 2026-09-11: it resolves to the live `.secrets`, and all
>   eight lab credentials matched the edy vault byte-for-byte. A move can no longer produce the
>   empty-secrets-directory-at-a-dead-path failure described above.
> - **Resolved 2026-09-11 — the two copies.** Reconciled. The untracked
>   `projects/cockpit-adlab/source/` was verified to hold nothing the canonical tree lacks —
>   shared files byte-identical, only a superseded 1.6 KB `install.sh` differed, and no unit,
>   service or script on the host referenced it — and removed. Its `project_scope.md` was **not**
>   redundant: it carried a verified analysis of where the shipped helper departs from this
>   contract, found nowhere else. That is preserved at
>   `samba-ad-lab/source/cockpit-adlab/docs/CONTRACT-GAP.md` and **§8 should be read against it**
>   — it is the record of what this worked example has not yet achieved in practice. What remains
>   at `projects/cockpit-adlab/` is a tombstone redirecting to the canonical tree and to
>   `/opt/cockpit-adlab`; a backup of the removed tree is at
>   `_migration-preserve-20260905/cockpit-adlab-RETIRED-20260911.tar.gz`.

### 8.2 `.envdefault`, shipped in `samba-ad-lab/source/cockpit-adlab/`

```sh
# cockpit-adlab .envdefault - seeded to [install path]/.env by deploy.sh, missing-only.
# Locations and settings only. NEVER a secret: see docs/DEPLOY-CONTRACT.md section 4.2.

# Where the AD lab project is deployed on THIS host. Every path below is under it.
# Deployed:  /opt/samba-ad-lab/payload
# Dev:       /srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/samba-ad-lab/source
ADLAB_ROOT=/opt/samba-ad-lab/payload

# The lab's own settings file. adlab-admin reads it; it does not guess its location.
ADLAB_LAB_ENV=/opt/samba-ad-lab/payload/lab.env

# RDP settings, and the SYSVOL replication script the timer runs.
ADLAB_RDP_ENV=/opt/samba-ad-lab/payload/rdp/rdp.env
ADLAB_SYSVOL_REPLICATE=/opt/samba-ad-lab/payload/sysvol/sysvol-replicate.sh

# Where the lab's credential FILES live. Outside the payload, because the payload is
# replaced wholesale on every upgrade and credentials must survive one. 0700 root:root.
# This directory is created by the OPERATOR, once. No script creates it - see below.
ADLAB_SECRET_DIR=/etc/samba-ad-lab/secrets

# GPO templates, on a bind mount that persists across container recreate.
ADLAB_GPO_TEMPLATE_DIR=/var/lib/samba/gpo-templates
```

Note what is *not* here: `ADMIN_PASS_FILE`. `lab.env` builds it as
`ADMIN_PASS_FILE="$SECRET_DIR/administrator.pass"`, which §4.1 forbids because Python cannot
expand it. The consumer joins:

```python
env = load_env(ENV_FILE)
secret_dir = env["ADLAB_SECRET_DIR"]
admin_pass_file = os.path.join(secret_dir, "administrator.pass")
```

Nine lines of shell interpolation traded for two lines of join, in exchange for one grammar that
three parsers agree on.

### 8.3 `adlab-admin`

```python
INSTALL_CONF = "/etc/cockpit-adlab/install.conf"

def _env():
    conf = load_env(INSTALL_CONF)            # written by install.sh; §3.3
    return load_env(conf["ENV_FILE"])        # [install path]/.env; §4.3

E              = _env()
LAB_ENV        = E["ADLAB_LAB_ENV"]
RDP_ENV        = E["ADLAB_RDP_ENV"]
SYSVOL_REPL    = E["ADLAB_SYSVOL_REPLICATE"]
SECRET_DIR     = E["ADLAB_SECRET_DIR"]
ADMIN_PASS_FILE = os.path.join(SECRET_DIR, "administrator.pass")
```

Four hardcoded constants become four lookups. §7.2 check 9 makes a regression impossible: a
`/opt/sc/git` or a dev-root literal in a shipped file refuses the install.

**And `10-build.sh` stops creating the secrets directory.** Replace
`install -d -m 0700 "$SECRET_DIR"` with:

```bash
[[ -d "$SECRET_DIR" ]] || die "ADLAB_SECRET_DIR=$SECRET_DIR does not exist.
    Create it as root, 0700, and put the lab credentials in it. This script will not
    create it: an empty secrets directory silently created at the wrong path is how the
    lab ends up generating fresh credentials nobody has a record of."
```

That is the actual fix. Repointing the constant at the share would have made today's symptom go
away and left the mechanism — a build that manufactures an empty secrets directory wherever a
stale variable points — entirely intact.

### 8.4 The manifest condition — the important half

```json
"conditions": [
    {"path-exists": "/usr/local/sbin/adlab-admin"}
]
```

**Test what `install.sh` itself creates, and nothing else.** That is what `cockpit-secrets`
already does (`{"path-exists": "/usr/local/sbin/secrets-admin"}`) and it is correct for one
reason: an unmet condition makes the plugin **silently absent**, so the condition must only ever
be unmet in the one situation where silence is the right answer — the software genuinely is not
installed.

It must **not** test `lab.env`, or `ADLAB_ROOT`, or anything the operator configures. Consider the
new operator who deploys `cockpit-adlab` and has not yet deployed the AD lab. With a
sibling-testing condition, the AD Lab menu entry does not appear, Cockpit logs nothing they will
find, and their only recourse is to ask someone. With the condition above, the page appears, and
`adlab-admin` returns:

```json
{"error": "ADLAB_LAB_ENV=/opt/samba-ad-lab/payload/lab.env does not exist. Deploy samba-ad-lab, or point ADLAB_LAB_ENV at it in /opt/cockpit-adlab/.env."}
```

which the page renders as a configuration panel naming the file, the key and the fix. **A
diagnosis, in the place they are already looking, instead of a disappearance.** The rule
generalises: *a Cockpit condition may test only paths this project's own `install.sh` creates.
Anything an operator configures is checked at runtime and reported in the page.*

The same principle covers the sibling's absence at runtime. `adlab-admin` verbs that need the lab
return a structured error naming the missing path and the `.env` key; verbs that do not, work.

### 8.5 The resulting host

```
/opt/cockpit-adlab/payload -> payload-1.0.0/     bin/adlab-admin, manifest.json, index.html, ...
/opt/cockpit-adlab/.env                          the five ADLAB_* keys above     0644 root:root
/etc/cockpit-adlab/install.conf                  INSTALL_KIND=deployed, ENV_FILE=...   0644
/usr/share/cockpit/adlab/{manifest.json,index.html,adlab.js,adlab.css}   -> payload/*  symlinks
/usr/local/sbin/adlab-admin                      -> /opt/cockpit-adlab/payload/bin/adlab-admin
/etc/samba-ad-lab/secrets/                       0700 root:root, operator-created, survives all
/opt/samba-ad-lab/payload -> payload-1.0.0/      lab.env, sysvol/, rdp/, 10-build.sh, ...
/etc/systemd/system/sysvol-replicate.{service,timer}   rendered from .in, @PAYLOAD@ substituted
```

Unmount the share. Everything above still works. That is the test.

---

## 9 · Conformance checklist

A project conforms when every line is true. Put this in each project's README as a table with a
date.

**Layout** — deploys to `/opt/<project>` (or a recorded `--install-to`); payload under
`payload-<version>/` with a `payload` symlink; `.env` a sibling of `payload`, never a child;
state in `/var/lib`, logs in `/var/log`, system config in `/etc`; nothing runtime-writable inside
the payload.

**install.sh** — resolves itself with `readlink -f`; links, never copies the payload; per-file
symlinks into a real `/usr/share/cockpit/<name>` directory; per-file symlinks into
`/usr/local/sbin`; refuses to take over a path it does not own; writes
`/etc/<project>/install.conf`; renders units but never enables, starts or stops them; never
touches `cockpit.socket`; idempotent; `--uninstall` removes only declared entries, keeps all data
and names it, and contains no `rm -r` outside `remove_old_payload`.

**deploy.sh** — self-contained, no shared framework; copies only the declared payload; seeds
`.env` missing-only and refuses a secret-shaped value; runs `payload/install.sh` from the install
path; enables units only behind an explicit flag; keeps one previous payload; idempotent;
`--uninstall` and `--remove` are different verbs.

**Config** — one `.envdefault` in §4.1 grammar; helper resolves `.env` only via `install.conf`;
all four standing greps of §4.4 print nothing; `etcdefaults/` used only for managed data, per §5.

**Gate** — one declared manifest, sourced by both scripts; all nine pre-flight checks present; the
post-install assertion present; no `/opt/sc/git` and no dev-root literal in any shipped file.

**Unbreakable, for `cockpit-secrets` specifically** — `./run_tests.sh` 20/20, `./validate.sh`,
`./check.sh` all green after every change here. No secret on argv, env or temp file (I10); no
browser storage (I11); registry IDs not paths (I4); the class gate in the helper (I3); atomic
writes (I12); audit carries no value and no path (I15); no CSP relaxation (I9). **None of these
may be weakened to make a deploy script simpler.** If the contract and a ban conflict, the ban
wins and this document gets edited.

---

## 10 · Index of judgement calls

| | Call | Alternative rejected | Cost accepted |
|---|---|---|---|
| JC-1 | `/opt/<project>` as install root | `/usr/local/lib/<project>` | `noexec /opt` on hardened hosts; deploy pre-flights for it |
| JC-2 | No symlink model on Windows | `mklink` / junctions | No live-edit dev install on Windows |
| JC-3 | `payload/` not `source/` | The operator's sketch | One more name; diverges from the sketch |
| JC-4 | Versioned payload + symlink swap | Plain `payload/`, staged rename | Two `readlink` hops; one more concept |
| JC-5 | Helper may live at repo root in dev, `bin/` in payload | Force `bin/` in all six repos now | A small permanent asymmetry in one function |
| JC-6 | Per-file symlinks for the Cockpit page | One directory symlink | Adding a page file needs a re-run of `install.sh` |
| JC-7 | Classify dev/prod by path prefix | A `.devtree` marker in the checkout | A checkout outside the share misclassifies |
| JC-8 | `.env` at `0644` | `0600` | Readable location data, in exchange for user-class helpers that work |
| JC-9 | Config resolves via `install.conf`; libs resolve relative to the helper | One rule for both | A reader must notice they differ |
| JC-10 | `strace` proof of the `.env` a helper opens | Code review only | Needs `strace`; a negative test substitutes |
| JC-11 | Unit directory is per-project, recorded in `install.conf` | Mandate one for all six | Two possible answers on the estate; the record makes uninstall safe |
