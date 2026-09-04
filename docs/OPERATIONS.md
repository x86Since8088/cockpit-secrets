# Operating cockpit-secrets

The runbook: registering a safe, restoring one from the backup ring, getting out
of a `conflict`, rotating a master passphrase, the agent, the audit log, and
what to do when a save is refused to protect the file.

For what the program *is*, read [`../README.md`](../README.md); for the verb
interface, [`CONTRACT.md`](CONTRACT.md); for who it defends against,
[`THREAT-MODEL.md`](THREAT-MODEL.md). Hazard ids like **I13** point at
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).

## Where everything lives

| Path | Mode | What it is |
|---|---|---|
| `/etc/cockpit-secrets/safes.d/*.json` | `0644 root:root` | the registry — the only source of safes |
| `/etc/cockpit-secrets/safes/` | `0700 root:root` | admin-class safe files, each `0600 root:root` |
| `/usr/local/sbin/secrets-admin` | `0755 root:root` | the verb helper |
| `/usr/local/lib/cockpit-secrets/` | `0755 root:root` | `backends/`, `schema/` |
| `/var/log/cockpit-secrets/audit.log` | `0600 root:root` | verb, safe, uid, outcome — never a value |
| `/var/lib/cockpit-secrets/state/` | `0700 root:root` | per-(uid, safe) unlock-failure counters (I16) |
| `<safe>.bak.d/` | `0700`, files `0600` | the backup ring — the only undo this program has |

> **One rule that overrides convenience everywhere below.** Root work on this
> host goes through the `/srv/jobs` runner and **its `output.log` is
> group-readable**. Never put a passphrase on a command line, in a job script,
> or in a file a job reads. Nothing in this document does.

---

## 1 · Registering a safe

There is no "create a new safe" verb in 0.1.0, deliberately: a half-written new
database is exactly the failure this program exists to avoid. Create the safe in
KeePassXC or Password Safe, copy the file into place, then register it.

### An admin-class safe

```bash
# 1. put the file where only root can read it
install -o root -g root -m 0600 /path/to/lab-dc.kdbx /etc/cockpit-secrets/safes/lab-dc.kdbx

# 2. start from the seeded example - copy it, do not rename it
cp /etc/cockpit-secrets/safes.d/10-example-admin.json.example \
   /etc/cockpit-secrets/safes.d/10-lab-dc.json
$EDITOR /etc/cockpit-secrets/safes.d/10-lab-dc.json
chmod 0644 /etc/cockpit-secrets/safes.d/10-lab-dc.json
chown root:root /etc/cockpit-secrets/safes.d/10-lab-dc.json

# 3. prove the helper accepts it
secrets-admin health          # registry_errors[] must be empty
secrets-admin list            # the safe appears, locked
echo '{"safe":"lab-dc"}' | secrets-admin probe    # format, KDF, iterations, writable
```

Set at minimum `id`, `label`, `path` and `mode`. Leave `access` alone: **an
entry that omits it is `admin`**, which is the restrictive class, on purpose
(I1).

### A user-class safe

```json
{
  "id": "eddie-personal",
  "label": "Eddie's own safe",
  "format": "psafe3",
  "path": "/home/eddie/.local/share/cockpit-secrets/personal.psafe3",
  "access": "user",
  "owner": null,
  "mode": "rw"
}
```

The registry *entry* is still root-owned `0644` — only root decides what is a
safe. The safe *file* must be `0600` and owned by the user who will open it, and
no directory above it may be group- or other-writable. `"owner": null` means
"the caller", which is almost always what you want.

### When the safe does not appear

| Symptom | Cause | Fix |
|---|---|---|
| Not in `list`, named in `health.registry_errors` | the entry failed schema validation and was **dropped** — never partially applied, never defaulted open (I1) | the error names the field; validate by hand (below) |
| Not in `list`, nothing in `registry_errors` | two entries share an `id`; the lexically last file silently wins | make ids unique; the `nn-` prefix only orders the files |
| Everything returns `access-denied` | `access: "admin"` and Cockpit's Administrative access is off, or the caller is not in `groups` | turn on Administrative access; check `getent group sudo` |
| A user-class safe returns `access-denied` | the file is not owned by the caller, is not `0600`, or a parent directory is group-writable — the fd's `fstat` decides, not the path (I5) | `chown`/`chmod` the file and its parents |
| `invalid` on unlock | `format` does not match the bytes | fix `format`; the helper never guesses a format from attacker-supplied bytes |

Validate an entry by hand — the same check the helper runs:

```bash
python3 - <<'PY'
import json, glob
from jsonschema import Draft7Validator
schema = json.load(open("/usr/local/lib/cockpit-secrets/schema/safe-registry.schema.json"))
v = Draft7Validator(schema)
for path in sorted(glob.glob("/etc/cockpit-secrets/safes.d/*.json")):
    errs = sorted(v.iter_errors(json.load(open(path))), key=str)
    print(path, "OK" if not errs else "DROPPED: " + errs[0].message)
PY
```

### Testing an unlock from a shell, without leaking the passphrase

Use the page. If you must do it from a terminal, this reads the passphrase with
`getpass` and writes it to the helper's stdin — never argv, never a file, never
your shell history:

```bash
python3 - <<'PY'
import getpass, json, subprocess
req = {"safe": input("safe id: "), "password": getpass.getpass("passphrase: ")}
p = subprocess.run(["/usr/local/sbin/secrets-admin", "unlock"],
                   input=json.dumps(req), capture_output=True, text=True)
out = json.loads(p.stdout or "{}")
print({k: v for k, v in out.items() if k != "handle"})   # never print the handle
PY
```

---

## 2 · Backups: the ring, and restoring from it

Before the first new byte of every save, the current file is copied into a
retention ring. **It is the only undo this program has** — a save that succeeds
is not reversible any other way.

- Location: `<safe>.bak.d/` beside the safe, or the registry's `backup.dir`.
  Directory `0700`, generations `0600`. `/tmp` and `/var/tmp` are refused: a
  backup is exactly as sensitive as the safe.
- Name: `<safe-filename>.<YYYYMMDDTHHMMSS>.<microseconds>.<pid>.bak` — timestamp
  first, so lexical order is chronological order.
- Retention: `backup.keep` generations (default 10, max 100); the oldest is
  pruned once that many exist. Set it too low and a corruption you notice on the
  third save has already aged out.

```bash
ls -l /etc/cockpit-secrets/safes/lab-dc.kdbx.bak.d/     # newest sorts last
```

### Restoring

Lock the safe in the browser first (or just make sure nothing is mid-save), then:

```bash
cd /etc/cockpit-secrets/safes
cp -a lab-dc.kdbx lab-dc.kdbx.before-restore          # keep what you are replacing
install -o root -g root -m 0600 \
    lab-dc.kdbx.bak.d/lab-dc.kdbx.20260904T091500.123456.4711.bak \
    lab-dc.kdbx
echo '{"safe":"lab-dc"}' | secrets-admin probe          # it must parse
```

Then unlock it in the page and check that an entry you recognise is there. A
restore that parses is not the same as a restore that is the generation you
meant — `probe` proves the file is intact, your eyes prove it is the right one.

Restoring changes the file's fingerprint, so any browser tab still holding an
unlocked handle for it will refuse its next save with `conflict`. That is the
system working. Lock and unlock again.

---

## 3 · `conflict` — three different things wearing one word

`conflict` always means "this write would lose someone's data, so nothing was
written". The `detail` says which of the three it is.

**A · The file changed on disk.** `(mtime_ns, size, sha256)` is captured at
unlock and re-checked immediately before the write (I13). Another client, a
restore, or an `rsync` moved underneath you.

> Do not retry, and do not look for a force flag — there is not one. Your
> in-memory edits are the *old* file plus your changes; forcing would delete
> whatever the other writer did. Lock the safe, unlock it again (you will be
> prompted, as always), and redo the edit against the current file. If the edit
> was large, copy the values you need out of the page **before** you lock — after
> `lock` they are gone from the DOM by design.

**B · Someone else holds the lock file.** KeePass/KeePassXC use
`<name>.kdbx.lock`; Password Safe uses `<name>.plk`. The conflict names the
holder, read out of that file and sanitised — it is a file an attacker can
write, so treat the name as a hint, not as proof.

```bash
ls -l  /etc/cockpit-secrets/safes/lab-dc.kdbx.lock
cat    /etc/cockpit-secrets/safes/lab-dc.kdbx.lock     # a holder record; no secret is in it
```

Close the desktop client. Only if you are certain the holder is gone — the host
is named, the pid is gone, the person confirms — remove the lock by hand:

```bash
rm /etc/cockpit-secrets/safes/lab-dc.kdbx.lock
```

There is no stale-lock timeout and there never will be one: "the holder looks
dead" is a guess, and guessing wrong means two writers and a lost update. The
helper removes only a lock still carrying its own token.

**C · The lossless-save guard refused** — see §7.

---

## 4 · Rotating a master passphrase

**There is no rotate verb in 0.1.0.** Rotation rewrites the whole database under
a new key, and a half-written rewrite is the one outcome this program refuses to
risk. Do it in a real client:

1. **Back up out of band first.** `cp -a` the safe somewhere only root can read.
   The ring covers saves *this* program makes; it does not cover what another
   client is about to do.
2. Set `"mode": "ro"` on the registry entry, or lock the safe in the page, so
   nobody unlocks it mid-rotation.
3. Change the passphrase in KeePassXC or Password Safe — on your workstation, on
   a copy, or on the file in place if the client runs on this host.
   `keepassxc-cli` is installed here **as a test oracle only**; it is fine for a
   human to use interactively, but it must never appear in a runtime code path.
4. Put the rotated file back with `install -o root -g root -m 0600`, restore
   `"mode": "rw"`, and `probe` it.
5. Unlock it once in the page with the new passphrase.

Nothing else needs updating: the registry does not contain the passphrase, and
the lockout counters and audit log are keyed on `(uid, safe id)`, not on the
key. A registered `keyfile` still applies — rotating the passphrase does not
un-register it, and if `password_required` is `false` the key file is still the
only thing opening that safe.

Everyone holding an unlocked handle for that safe will get `conflict` or
`bad-credential` on their next verb. That is correct; tell them before you start.

---

## 5 · The agent, and why you probably should not

`secrets-agent` (I18) keeps a record of an unlocked safe behind an `AF_UNIX`
socket. It is **off by default, opt-in per safe**, and it should stay off on
almost every safe.

**READ THIS BEFORE YOU DECIDE: the agent does NOT stop the passphrase being
asked for.** As shipped it holds a *ticket* — a uid-bound note that safe X was
unlocked at time T, with both deadlines running — and no key material at all.
It cannot hand a later helper process an unlocked database, because it does not
have one. So enabling it does not buy fewer prompts.

What it buys is the thing that is genuinely hard without it: an unlock you can
**see** and **revoke**. Without the agent, a safe unlocked in one browser call
is already locked by the time the next one starts, and there is nothing to show
or to cancel — which is fine, and is why the default is off. With it, the page
can show "unlocked — N s remaining" from a number the helper did not invent,
that number survives a page reload, and a Lock button can revoke the hold for
every process at once. If your reason for wanting the agent was "stop asking
me", it will not do that and you should leave it off.

The cost is still real and still worth stating: an unlock now leaves a trace
outside the process that made it, bounded by timers rather than by the process
model, and every future "convenience" patch to that daemon is a patch to the
one component that could turn a ticket into a key.

If you enable it anyway, know exactly what you are buying:

```json
"agent": { "enabled": true, "idle_seconds": 300, "max_seconds": 3600 }
```

- `idle_seconds` counts from the **last use**, not from the unlock. It is the
  window in which someone at your unlocked screen reads the safe without knowing
  the passphrase. Above a few minutes you are running an unlocked password safe
  as a service.
- `max_seconds` is absolute and no amount of activity extends it.
- The handle is bound by `SO_PEERCRED` to the uid that created it; another uid
  gets `access-denied` — the same answer an unknown handle gets, so the socket
  cannot be used to enumerate which handles exist.
- For an `access: "admin"` safe the helper runs as root, so `SO_PEERCRED` sees
  uid 0 for every operator and cannot tell two administrators apart. The
  separation there is **one agent instance per operator** behind a 0700 run
  directory (`secrets-agent@<uid>`), which `install.sh --with-agent` installs
  into the system unit directory and deliberately does not enable.
- While the agent holds anything the page shows a persistent "unlocked — N s
  remaining" banner with a Lock button. **An unlocked safe must never be
  invisible.** If you ever see the agent holding a safe with no banner, that is a
  bug worth stopping for.

Install and enable — per user, in their own session, because it must run *as*
the user whose safes it holds:

```bash
sudo ./install.sh --with-agent          # installs the unit; enables nothing
systemctl --user daemon-reload
systemctl --user enable --now secrets-agent.socket
systemctl --user status secrets-agent.socket
```

Turn it off:

```bash
systemctl --user disable --now secrets-agent.socket
# then set "enabled": false in every registry entry that turned it on
secrets-admin health                     # agent state is reported here
```

`--with-agent` fails if `agent/` is not in the source tree at all — the agent was
allowed to be dropped rather than shipped half-defended. `secrets-admin health`
is the supported way to find out whether this installation has one.

---

## 6 · The audit log

`/var/log/cockpit-secrets/audit.log`, `0600 root:root`, one JSON object per
line: timestamp (UTC), verb, safe id, caller uid, outcome, duration.

**What is never in it:** a field value, an entry title, a passphrase, a path
taken from a request, or a traceback. A redaction filter runs over everything
the helper writes, and a unit test feeds a known passphrase through every log
call and greps the output for it (I15).

```bash
secrets-admin audit-tail --n 50        # the supported reader; metadata only

# who unlocked what today
python3 - <<'PY'
import json
for line in open("/var/log/cockpit-secrets/audit.log"):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("verb") == "unlock":
        print(e["ts"], e["uid"], e["safe"], e["outcome"])
PY

# failed unlocks per safe - the thing worth alerting on
awk '/"verb": ?"unlock"/ && /bad-credential/' /var/log/cockpit-secrets/audit.log | wc -l
```

Two entries that mean more than they look:

- `bad-credential` is returned identically for a wrong passphrase and a failed
  MAC, so the client cannot use unlock as a decryption oracle (I6). **The log is
  where the distinction is recorded** — if you are diagnosing a corrupt file
  rather than a forgotten passphrase, this is the only place that tells you.
- `reveal` writes one line per field opened, naming the field and never its
  value. A burst of them is a person copying a lot of passwords.

### Rotation

The installer does **not** install a logrotate rule — `/etc/logrotate.d` is
outside the set of paths it is allowed to touch. Add one yourself if you want
rotation, and keep the mode:

```
/var/log/cockpit-secrets/audit.log {
    weekly
    rotate 52
    compress
    missingok
    notifempty
    create 0600 root root
}
```

`create 0600 root root` is the load-bearing line. A rotation that recreates the
log `0644` publishes who holds which safes to every user on the host.

### Lockout state (I16)

Repeated failures against one `(uid, safe id)` back off exponentially and then
lock out. The counters are in `/var/lib/cockpit-secrets/state/`. The page shows
the remaining time; `locked-out` is a distinct error code from `bad-credential`.

Root can clear a lockout by removing that pair's state file. Treat it as a
security-relevant action: you are re-arming a guessing budget against a safe, and
the reason it locked out is in the audit log. Read that first.

---

## 7 · When a save is refused to protect the file (I22)

Before the first write to a safe, the helper does a parse → serialize → parse
round trip and compares. If any field would be dropped, the save is refused with
`conflict` **naming the field**.

This is not the library being fussy. Reading a KDBX 4.1 database with a library
that does not model every field and writing it back **deletes** what it did not
understand — custom icons, previous-parent-group, quality flags, plugin data —
and nothing tells you until the person who relied on that field notices. Refusing
to save beats quietly amputating a database.

You have three honest ways forward, and no force flag:

1. **Edit that safe in its own client.** KeePassXC understands everything in its
   own files. Use this page for the rest.
2. **Normalise the file.** Open it in KeePassXC, save it there, and re-`probe`
   it. If the field was written by a plugin you no longer use, a client-side
   save usually removes it and the guard then passes. Back up first.
3. **Set `"mode": "ro"`** on the registry entry and use the page for reading. A
   safe you can read and not write is more useful than a safe you can corrupt.

Related, and reported the same way: **KDBX 3.x is opened read-only** (I20).
KDBX 3.1 has no authenticated encryption, so a tampered file decrypts to
attacker-influenced XML with nothing to detect it. The page shows a persistent
banner saying so. The fix is an explicit, operator-confirmed upgrade to KDBX4
that writes a **new** file — never a silent in-place conversion.

The three read-only causes are deliberately three different error codes:

| Cause | Code |
|---|---|
| registry `"mode": "ro"` | `access-denied` |
| the format cannot be written safely (KDBX3, I20) | `unsupported` |
| the lossless guard would drop a field (I22) | `conflict` |

---

## 8 · Export and attachments — an exfiltration channel with a friendly name
(I21)

"Export the database as CSV" writes **every secret in that safe, in plaintext, to
a file on this host**. That is not a reporting feature with a security caveat; it
is the one operation that undoes everything else in this document. So:

- It is **off by default** and enabled per safe, by an operator, with
  `"export_allowed": true` in the registry entry. There is no global switch.
- It is **admin-only**. A non-admin caller is refused even on a safe that allows
  it, and even on a `user`-class safe.
- The destination is an **operator-configured directory**, never a path from the
  request (I4), and the file is written `0600` into a `0700` directory. It is
  `export_dir` from the registry entry, or `/var/lib/cockpit-secrets/exports`
  which `install.sh` creates. `export_dir` must be absolute, free of `..`, and
  is refused under `/tmp`, `/var/tmp` or `/dev/shm`; setting it while
  `export_allowed` is false is refused outright rather than ignored, because the
  two are one decision.
- The **file name is minted by the helper** — `<safe id>-<UTC stamp>.<ext>` —
  and the request has no say in it.
- The request must carry the exact token **`export-plaintext:<safe id>`**,
  compared in constant time. The token names the safe, so a confirmation an
  operator gave for a throwaway safe cannot be replayed against the
  domain-administrator one.
- Every export is **audited by file name** — the audit line names what was
  written and where, never what was in it.
- The page asks for an explicit confirmation that says, in plain words, what is
  about to be written in the clear.

If you turn it on, treat the output like the safe itself: it is the same secrets
with the encryption removed. Shred it when you are done — `rm` on a
copy-on-write filesystem does not overwrite anything — and remember it is not
covered by the backup ring, the audit trail of *reads*, or any of the file-mode
guards that protect the safe.

**Attachments are different, deliberately.** An attachment download streams
through the Cockpit channel to your browser rather than landing on this host's
disk. There is no attachment-export-to-path verb, for exactly the reason above.

## 9 · Uninstalling

```bash
sudo ./install.sh --uninstall
```

Removes the Cockpit package, the helper, the backends, the schema and any agent
unit. **Keeps** `/etc/cockpit-secrets/` (registry and safes),
`/var/log/cockpit-secrets/` (the audit log) and `/var/lib/cockpit-secrets/`
(lockout counters) — removing a program must not silently change who may open
what, and an uninstall must not be a way to clear a lockout. The installer
prints the exact `rm -rf` if you really want those gone.

It does not restart Cockpit. The page disappears from the menu on the next
login.

---

## 10 · Quick troubleshooting

| Symptom | Almost always |
|---|---|
| The page is not in the Cockpit menu | you have not logged out and back in; or `manifest.json` is invalid — but `install.sh` refuses to install an invalid one, so suspect a hand edit under `/usr/share/cockpit/secrets/` |
| The page loads blank, console shows one error | a JavaScript syntax error. `./check.sh` catches it; there is no build step, so nothing else will |
| Every admin safe says `access-denied` | Cockpit's Administrative access is off, or the caller is not in the entry's `groups` |
| `internal` from every verb | the helper cannot import `backends`. `python3 -c "import sys; sys.path.insert(0,'/usr/local/lib/cockpit-secrets'); import backends"` |
| `locked-out` and you are sure of the passphrase | the backoff from earlier failures (I16). Wait it out, or read the audit log to see whose failures they were |
| `unsupported` on a save | KDBX3 (I20), or the backend is not installed — check `secrets-admin health` |
| `mlockall` reported as failed in `health` | normal for the unescalated user path (`ENOMEM` against `RLIMIT_MEMLOCK`). It is reported honestly rather than claimed as success; the safe still works |
