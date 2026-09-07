# The design testbed — three throw-away safes, and how to rebuild them

Everything the design work is styled against lives in three safes that
`tests/browser/live-provision.spec.js` creates through the real Cockpit UI.
This file is the inventory: what exists, what is in it, where the
passphrases are, and the one command that rebuilds the lot from nothing.

Nobody should have to read a transcript to reproduce this.

---

## THE OPERATOR'S OWN SAFE IS NOT PART OF THIS AND IS NEVER TOUCHED

`pwsafe3` — user-class, imported, owned by `eddie`, registered in
`~/.config/cockpit-secrets/safes.d/pwsafe3.json` — is **real data**. Nothing
in the provisioning suite may unlock it, open it, read it, forget it, delete
it, or put it in a screenshot.

Three things keep that true rather than one:

1. `guard()` in `live-provision.spec.js` **throws** on `pwsafe3`, and throws
   again on any id that is not one of this suite's own three. Every verb call
   goes through it.
2. Nothing in the suite iterates the registry. Every id is a literal.
3. The suite signs in as `cptestadm`, and `pwsafe3` is in *eddie's* per-user
   registry, which `cptestadm` cannot read. Item **P7** asserts the page never
   rendered it, so the artefacts are provably clean rather than clean by
   argument.

**Record the file before and after any run** — this is the check, and it is
not the suite's to make about itself:

```sh
stat -c '%n %Y %s' ~/.config/cockpit-secrets/safes.d/pwsafe3.json
sha256sum        ~/.config/cockpit-secrets/safes.d/pwsafe3.json
```

Measured either side of the 2026-09-06 build, unchanged:

```
mtime 1788641512   size 830
fa0afcea4790f65425fd23fa2d3959660f7f298d9ebf2f647bf06d28dcde9fc8
```

`dummy-fake-safe` **is** visible to `eddie` — it is admin-class, so it lives in
the *system* registry `/etc/cockpit-secrets/safes.d` and every account sees the
card. That is the access model working, not a leak: an unescalated `list` for
`eddie` reports it `usable:false`.

---

## What exists

All three are owned by **`cptestadm`** (uid in `sudo`), created 2026-09-06.

| id | class | format | registry | file | mode |
|---|---|---|---|---|---|
| `dummy-fake-safe` | **admin** | kdbx | `/etc/cockpit-secrets/safes.d/dummy-fake-safe.json` | `/etc/cockpit-secrets/safes/dummy-fake-safe.kdbx` (root:root 0600) | rw |
| `dummy-fake-user-kdbx` | user | kdbx | `~cptestadm/.config/cockpit-secrets/safes.d/dummy-fake-user-kdbx.json` | `~cptestadm/.local/share/cockpit-secrets/safes/dummy-fake-user-kdbx.kdbx` (0600) | rw |
| `dummy-fake-user-psafe3` | user | psafe3 | `~cptestadm/.config/cockpit-secrets/safes.d/dummy-fake-user-psafe3.json` | `~cptestadm/.local/share/cockpit-secrets/safes/dummy-fake-user-psafe3.psafe3` (0600) | **ro** |

Both KDBX safes are AES-256 / Argon2id (8 rounds, 65536 KB) — the helper's own
defaults, not overridden. The PWS3 safe is `pws3-sha256`, 262 144 iterations,
declared format 0x030D.

### `dummy-fake-safe` — the big one

16 groups (15 + the recycle bin), 32 entries, 4 expired, two attachments.
`keepassxc-cli db-info` at euid 0 agrees. Three levels deep, deliberately
uneven:

```
Infrastructure/            (0)
  Servers/                 (8)   <- the crowded one
  Network/                 (0)
    Switches/              (3)
    Firewalls/             (2)
  Storage/                 (3)
Web Services/              (0)
  Internal/                (3)
  External/                (3)
Personal/                  (0)
  Finance/                 (3)
  Shopping/                (2)
  Media/                   (0)   <- the EMPTY one, on purpose
Archive/                   (0)
  2019/                    (3)
Recycle Bin/               (1)
(root)                     (1)
```

### `dummy-fake-user-kdbx` — the small user-class one

5 groups, 7 entries, 1 expired. `Work/{Accounts,Servers}`, `Home`, root.
Carries the "no password at all" entry, so the strength meter has an empty
case.

### `dummy-fake-user-psafe3` — the format-limited, read-only one

4 group paths, 5 entries. It exists to show two states the KDBX safes cannot:

* **read-only** — the card reads `read-only`, and the browse view refuses
  every write verb before anything is serialized;
* **format warnings** — Password Safe v3 has no tags and no name-keyed custom
  fields (a record is a list of *typed* fields, each type at most once), and a
  safe this program creates declares 0x030D, below the 0x030F that introduced
  attachments. `provision-data.js` therefore does not *send* those fields;
  the limits show up as the helper's own warnings on the safe, which is the
  state worth designing for.

---

## Where the awkward cases are

The layout has to survive all of these, so each one is somewhere specific and
`live-provision.spec.js` asserts the set is complete before it writes anything
(`D.SPECIALS`).

| case | entry |
|---|---|
| very long title (254 chars) | `Infrastructure/Servers` — "A deliberately, extravagantly…" |
| emoji + combining marks | `Web Services/Internal` — "🔐📦 Café résumé — combining à́̂ ☕🧪" |
| right-to-left title | `Web Services/External` — "لوحة تحكم وهمية — example.org" |
| no username | `Infrastructure/Servers` — srv-gamma IPMI |
| 300-character URL | `Infrastructure/Network/Switches` — sw-core-01 |
| 40-line note | `Infrastructure/Network/Firewalls` — fw-south |
| eight tags | `Infrastructure/Servers` — srv-alpha |
| no tags at all | `Infrastructure/Servers` — srv-beta |
| protected AND unprotected custom fields | `Infrastructure/Network/Firewalls` — fw-north (4 fields, 2 of each) |
| TOTP | `Infrastructure/Servers` — srv-theta (seed is sixteen A's) |
| tiny attachment (81 B) | `Infrastructure/Storage` — nas-01 |
| large attachment (720 000 B) | `Infrastructure/Storage` — nas-02 |
| expired | srv-delta, plus all three of `Archive/2019` |
| expires in three days | srv-epsilon (computed at run time, so it stays true) |
| never expires, explicitly | `Infrastructure/Network/Switches` — sw-lab-03 |
| root-group entry | "Front desk shared login (fictional, do not use)" |
| recycle bin | "Deleted fictional account (example.com)" |
| password strength, whole scale | `password1` → 40 chars of high entropy (`PW` in `provision-data.js`) |

**Why the large attachment is 720 000 bytes and not 1 MB.** The helper caps a
whole request — session frame included — at `constants.max_request_bytes`
(1 MiB here), and an attachment travels base64 inside that JSON object, at
4 bytes per 3. So a 1 MiB frame carries about 768 KiB of file, and the schema's
own `breaks_when_wrong` for `data_b64` says exactly that. 720 000 encodes to
960 000 and leaves headroom for the envelope. Asking for 1 048 576 would be
asking the transport for something it cannot carry.

---

## Everything in these safes is fake, and that is a security property

They are built to be screenshotted and shown to people. Every host is under
`example.com` / `example.org` / `example.net` (RFC 2606 §3 reserves them for
exactly this); every person is invented or is a long-dead computing figure the
operator named; no real company, product, bank or retailer appears; and there
are **no plausible-looking API keys or tokens** — where an entry needs a
token-shaped field, the value says what it is in words
(`NOT-A-REAL-TOKEN-example-only`). A fake secret that looks real is a fake
secret somebody will one day treat as real.

`tests/browser/provision-data.js` is the whole content of the testbed and
carries that rule at the top. Read it, not the transcript, if you want to
check the discipline held.

---

## The passphrases

Three files, mode **0600**, in a mode **0700** directory:

```
${XDG_RUNTIME_DIR}/cockpit-secrets-live/safe-dummy-fake-safe.pass
${XDG_RUNTIME_DIR}/cockpit-secrets-live/safe-dummy-fake-user-kdbx.pass
${XDG_RUNTIME_DIR}/cockpit-secrets-live/safe-dummy-fake-user-psafe3.pass
```

On this host that is `/run/user/1000/cockpit-secrets-live/` — **tmpfs**, so
they do not survive a reboot. Each is `python3 -c "import secrets;
print(secrets.token_urlsafe(24))"`, i.e. 32 URL-safe characters, written
**before** anything typed them.

**The values are not recorded anywhere else and must never be printed** — not
into a report, not into a `/srv/jobs` `output.log` (group-readable), not into
an artefact. They are throw-away by construction: lose them and the fix is to
rebuild the testbed, which is one command.

The same directory holds `cptestadm.pass`, the Cockpit account password the
suite signs in with. It is **not** created by this suite and is not throw-away.

---

## Rebuilding the whole testbed from scratch

One command. It generates any missing passphrase, then runs the suite, which
deletes any leftover `dummy-fake-*` safe **through the helper, by id, with the
confirmation token** before it creates anything — so it is idempotent and can
be run over the top of a half-finished previous attempt.

```sh
cd /srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator-storage/projects/cockpit-secrets/source && \
D="${XDG_RUNTIME_DIR}/cockpit-secrets-live" && install -d -m 0700 "$D" && \
for id in dummy-fake-safe dummy-fake-user-kdbx dummy-fake-user-psafe3; do \
  [ -s "$D/safe-$id.pass" ] || ( umask 077; python3 -c 'import secrets;print(secrets.token_urlsafe(24))' > "$D/safe-$id.pass" ); \
done && umask 077 && node tests/browser/live-provision.spec.js
```

It needs, and will say plainly if it does not have:

* Cockpit answering at `https://localhost:9090` (never started or restarted by
  the suite — `cockpit.socket` is a live service here);
* `$D/cptestadm.pass`, the account password for a principal in `sudo`;
* `/usr/local/sbin/secrets-admin`, `/usr/share/cockpit/secrets`,
  `/etc/cockpit-secrets/safes.d`;
* a resolvable Playwright (`PLAYWRIGHT_PATH`, the module path, or
  `/opt/sc/edy-local/e2e/node_modules/playwright`).

A missing precondition is a **NOT-ATTEMPTED with the path it looked at**, never
a guess and never a green line. Environment overrides are the same as the other
live specs: `COCKPIT_URL`, `SECRETS_LIVE_CREDS`, `SECRETS_LIVE_ADMIN`,
`SECRETS_LIVE_HEADED=1` to watch it happen.

Roughly two minutes on this host. Screenshots land in
`tests/browser/artifacts/` (0600, like every artefact this tree writes):
`create-<id>-dialog.png`, `create-<id>-result.png`, `open-<id>.png`,
`P1-escalation-prompt.png`, `P5-readonly-card.png`, `P6-safe-list.png`, and
`live-provision-result.json`.

### It will ask Cockpit for administrative access, and that is the point

An admin-class safe is created and opened with `superuser:"require"`. Measured
on Cockpit 360 (`docs/LIVE-WALKTHROUGH.md` item 9): from a session in limited
access that is refused **immediately** with `access-denied` and **no dialog is
drawn anywhere** — the escalation dialog belongs to the shell, and no API a
package page can reach will summon it. So item **P1** clicks Cockpit's own
"Limited access" header control and answers *Cockpit's* prompt, in the shell,
outside the plugin frame. If that prompt does not appear, every later item is
skipped with the reason rather than failing obscurely.

### Removing the testbed

```sh
# as cptestadm, through the helper — never with rm on a guessed path
for id in dummy-fake-safe dummy-fake-user-kdbx dummy-fake-user-psafe3; do
  printf '{"safe":"%s","delete_confirm":"delete-safe:%s"}' "$id" "$id" |
    /usr/local/sbin/secrets-admin safe-delete
done
```

`dummy-fake-safe` needs administrative access; `dummy-fake-user-psafe3` must be
flipped back to `rw` first (below) or its own read-only mode gets in the way.

### Flipping the PWS3 safe between read-only and read-write

`mode` is a **registry** field and there is no verb that edits a registry
entry — deliberately, because the registry is what the access model is keyed
on and a verb that rewrote it would be a verb that could re-class a safe. So
the suite sets it the way an operator would, by editing the JSON in the
account's own per-user registry, unescalated. Run as `cptestadm`:

```sh
python3 - dummy-fake-user-psafe3 rw <<'PY'
import json, os, sys, glob
want, mode = sys.argv[1], sys.argv[2]
assert want.startswith('dummy-fake-'), 'refused: not a testbed id'
assert mode in ('rw', 'ro'), 'refused: not a mode'
d = os.path.expanduser('~/.config/cockpit-secrets/safes.d')
for f in sorted(glob.glob(os.path.join(d, '*.json'))):
    try:
        o = json.load(open(f))
    except Exception:
        continue
    if o.get('id') != want:
        continue
    o['mode'] = mode
    t = f + '.tmp'
    fd = os.open(t, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as h:
        json.dump(o, h, indent=2, sort_keys=True); h.write('\n')
    os.replace(t, f)
    print('changed', os.path.basename(f), '->', mode)
PY
```

The two asserts are the guard: a path built from anything that is not a
`dummy-fake-` id is refused, so this cannot reach `pwsafe3.json` even if it is
handed the id.

---

## Verifying the testbed independently

Foreign oracles, because "a safe only we can read is the failure" (I19). Root
work goes through `/srv/jobs` — and **its `output.log` is group-readable, so
never let a passphrase or a decrypted value reach it.** Piping a 0600
passphrase file into `keepassxc-cli`'s stdin is fine; `db-info` prints
metadata only and echoes nothing it reads.

```sh
# as root, via /home/eddie/Documents/ClaudeSystem/submit-job.sh
CRED=/run/user/1000/cockpit-secrets-live
keepassxc-cli db-info -q /etc/cockpit-secrets/safes/dummy-fake-safe.kdbx \
    < "$CRED/safe-dummy-fake-safe.pass"
keepassxc-cli ls -R -q /etc/cockpit-secrets/safes/dummy-fake-safe.kdbx \
    < "$CRED/safe-dummy-fake-safe.pass"
```

What it said on 2026-09-06:

```
Name: Dummy fake safe (admin, throw-away)
Cipher: AES 256-bit
KDF: Argon2id (8 rounds, 65536 KB)
Recycle bin is enabled.
Number of groups: 16
Number of entries: 31
Number of expired entries: 4
```

There is **no third-party PWS3 CLI on this host** — `passwordsafe` is a
wxWidgets GUI that cannot be driven headlessly (`docs/HOST-FACTS.md`) — so the
psafe3 safe has no foreign oracle. `file(1)` confirms the container
(`Password Safe V3 database`, magic `PWS3`) and everything else about it comes
from this program's own backend. That is a stated gap, not a check.

---

## One thing this build found that is NOT about the testbed

**`tests/integration/` is not hermetic with respect to the per-user registry,
and has not been since the operator registered `pwsafe3` on 2026-09-05.**

`tests/integration/_env.py` builds a hermetic registry and sets
`COCKPIT_SECRETS_ETC` and `COCKPIT_SECRETS_VAR` — but the helper resolves the
*per-user* registry through `user_home()`, whose test seam is a third variable,
`COCKPIT_SECRETS_HOME`, which `_env.py` does not set. So the caller's real
`~/.config/cockpit-secrets/safes.d` is read straight into the "hermetic" env,
`assert_loaded(len(SAFES))` sees 10 entries where it expected 9, and **eight
integration files abort at build time**, before a single test body runs:

```
hermetic registry did not load: entries=10 errors=[]
```

Enumerated, the tenth entry is `pwsafe3` — `registry=user`, `origin=imported`.
None of the three testbed safes appear: `dummy-fake-safe` is masked by the
hermetic `COCKPIT_SECRETS_ETC`, and the two user-class ones belong to
`cptestadm`, not to whoever runs the suite.

Proved by pointing the existing seam at an empty directory and changing nothing
else:

```sh
EH=$(mktemp -d); chmod 700 "$EH"; COCKPIT_SECRETS_HOME="$EH" ./run_tests.sh
#   -> run_tests.sh: OK      (20/20, including all eight that had aborted)
```

The fix belongs in `_env.py` — one line beside the two it already sets,
pointing `COCKPIT_SECRETS_HOME` at `self.root` — and it is left to whoever owns
that file. It is recorded here because it is easy to mistake for damage done by
provisioning, and it is not: it is a pre-existing gap that the operator's own
safe made visible.
