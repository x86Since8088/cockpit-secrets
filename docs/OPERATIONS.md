# Operating cockpit-secrets

The runbook: creating a safe, adopting one you already have, registering one by
hand, removing one, restoring from the backup ring, getting out of a `conflict`,
rotating a master passphrase, the agent, the audit log, and what to do when a
save is refused to protect the file.

For what the program *is*, read [`../README.md`](../README.md); for the verb
interface, [`CONTRACT.md`](CONTRACT.md); for who it defends against,
[`THREAT-MODEL.md`](THREAT-MODEL.md). Hazard ids like **I13** point at
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).

## Where everything lives

| Path | Mode | What it is |
|---|---|---|
| `/etc/cockpit-secrets/safes.d/*.json` | `0644 root:root` | the **system registry** — the source of admin-class safes, and of any user-class safe an administrator registered by hand |
| `~/.config/cockpit-secrets/safes.d/*.json` | `0600 <user>`, dir `0700` | the **per-user registry**, read only by an unescalated helper running as that user, every entry forced to `access: "user"` (§1.4) |
| `/etc/cockpit-secrets/safes/` | `0700 root:root` | admin-class safe files, each `0600 root:root` |
| `~/.local/share/cockpit-secrets/safes/` | `0700 <user>` | user-class safe files this program created or imported, each `0600` |
| `/var/lib/cockpit-secrets/state/import/` | `0700 root:root` | in-flight `safe-import` uploads (admin class). Encrypted bytes, swept on an idle timer — §1.6 |
| `~/.local/state/cockpit-secrets/state/import/` | `0700 <user>` | the same, for a user-class import |
| `/usr/local/sbin/secrets-admin` | `0755 root:root` | the verb helper |
| `/usr/local/lib/cockpit-secrets/` | `0755 root:root` | `backends/`, `schema/` |
| `/var/log/cockpit-secrets/audit.log` | `0600 root:root` | verb, safe, uid, outcome — never a value |
| `/var/lib/cockpit-secrets/state/` | `0700 root:root` | per-(uid, safe) unlock-failure counters (I16) |
| `/var/lib/cockpit-secrets/exports/` | `0700 root:root` | **plaintext exports, if anyone ever ran the export verb** (I21) — §8 |
| `<safe>.bak.d/` | `0700`, files `0600` | the backup ring — the only undo this program has |

Every one of those survives `--uninstall`. The exports directory is the one to
look in first on a host you have inherited: it is created empty by `install.sh`
and it stays empty unless somebody deliberately dumped a safe in the clear, so
one `ls` answers a question you would otherwise have to reconstruct from the
audit log. See [§8, "The exports directory"](#the-exports-directory--find-it-read-the-ledger-destroy-the-file).

> **One rule that overrides convenience everywhere below.** Root work on this
> host goes through the `/srv/jobs` runner and **its `output.log` is
> group-readable**. Never put a passphrase on a command line, in a job script,
> or in a file a job reads. Nothing in this document does.

---

## 1 · Registering a safe

Four ways in, and they are not equivalent:

| | What it does | Who can |
|---|---|---|
| **§1.1 Create** (`safe-create`) | mints a brand-new empty safe *and* its registry entry | an administrator, for an admin safe; any user, for their own |
| **§1.2 Adopt** (`safe-import`) | uploads a safe you already have and registers it | the same |
| **§1.3 By hand, admin class** | you put the file there and write the entry yourself | root |
| **§1.4 By hand, user class** | the same, in the system registry, on a user's behalf | root |

Hand-registration is still fully supported and is the **only** way to reach the
fields the verbs deliberately do not set — `groups`, `agent`, `export_allowed`,
`keyfile`, `yubikey_slot`, `breach_corpus`, `backup`. A verb that could set
`groups` would be a verb that widens who may open a safe.

Then **§1.5** is the per-user registry and what it means for you and for the
administrator of this host, **§1.6** is finding and cleaning up an interrupted
upload, **§1.7** is removing a safe (forget versus delete), and **§1.8** is
moving one between the two registries.

### 1.1 · Creating a new safe

**Safes → “New safe…”** in the page. It asks for an id, a label, the format, the
access class, and the passphrase — in that order, and the passphrase last.

What the helper does with it, because it is worth knowing before you trust it:

- **You do not choose the file name or where it goes.** You choose an *id*. The
  helper mints `/etc/cockpit-secrets/safes/<id>.<ext>` for an admin safe, or
  `~/.local/share/cockpit-secrets/safes/<id>.<ext>` for your own. There is no field in
  the whole flow that is a path, and that is the point (I4).
- **The id must match `^[a-z0-9][a-z0-9-]{1,62}$`** (`constants.new_id_pattern`)
  — lower case, digits, hyphen, at least two characters, no dot and no
  underscore. Existing
  hand-written entries with a dot or an underscore keep working; you just cannot
  *mint* one, because a minted id becomes a file name.
- **An id that already exists is refused, and so is a file already sitting at
  the path it would mint.** Nothing here ever overwrites anything.
- **The passphrase is never on a command line.** It rides on stdin, like every
  other credential (I10).
- **You are told if your passphrase is weak, and it is still accepted.** The
  response carries the same `strength` verdict the tools page gives. Refusing an
  operator's chosen passphrase is not this program's decision; telling them is.
- **An empty passphrase with no key file is refused.** That is not a
  configuration, it is an unlocked file.
- The new database is **KDBX 4.1** with Argon2id, or PWS3 at Password Safe's own
  current write floor. It is never KDBX 3.x — that format has no authenticated
  encryption (I20) and this program will not create one.
- The safe is created, **re-opened with the same passphrase through the reader a
  later unlock will use**, and only *then* registered (I24/I41). A safe nobody
  can unlock never becomes a registry entry.
- **And if the registry entry cannot be written, the file is removed again.**
  A create either produces a listed safe or produces nothing; it does not leave
  a file with no entry pointing at it, which used to burn the id from inside the
  program (I45). The one case that cannot be made clean is the removal itself
  failing, and then the error NAMES the file to delete by hand.
- **The label may not contain invisible formatting characters** — bidi
  overrides, zero-width joiners, a BOM (I52). They make the name in the list
  differ from the name that was typed, and the registry schema names label
  confusion as how a passphrase gets typed into the wrong prompt. Accents, dashes
  and non-Latin scripts are all fine; it is the *invisible* ones that are
  refused, and they are refused rather than stripped, because silently altering
  your label would mean the list shows a name you did not choose.

Afterwards it is an ordinary entry. Edit `50-<id>.json` by hand for anything the
form did not offer, then `secrets-admin health` to confirm it still validates.

A created entry also records **where it came from**: `origin: "created"` and a
`created_utc`. An imported one records `origin: "imported"` and a `source` block
holding the header summary you were shown before you typed your passphrase. None
of the three grants anything — `safe-delete`'s gate is derived from the id, not
read from `origin` — but they are the difference between "this program made this
file" being a fact and being a story.

### 1.2 · Adopting a safe you already have

**Safes → “Add an existing safe…”.** You pick the `.kdbx` or `.psafe3` file, it uploads in
512 KiB chunks, and **only then** are you asked for its passphrase. That order is deliberate and
is not a UI preference:

- A large upload takes visible time. Asking for the passphrase in the file
  picker would keep it in browser memory for the whole transfer — the window the
  rest of this program works to make small (I11, I14). Asked afterwards, it
  exists for one request.
- **The header of a KDBX or PWS3 file is not secret.** Format, version, cipher,
  KDF and its cost are readable from the bytes by anyone holding the file — and
  you are holding the file. So the page shows you all of that with **no
  passphrase at all**, before you type anything, and you confirm you uploaded
  what you meant to.

  That summary is labelled *read from the file's header, not authenticated*, and
  you should read the label. On a file somebody tampered with, the summary is
  what the tamperer wrote. It is a "did I pick the right file" check, not an
  integrity check.

Then you type the passphrase, and **the file only lands if it opens.** That is
the safety property of the whole feature in one line: the only bytes that can
ever be written into the managed directory are bytes demonstrably a safe the
uploader can already open.

**A typo does not cost you the upload.** A wrong passphrase answers
`bad-credential` and the staged bytes stay; you get five attempts before the
staging is discarded. Note what that budget is and is not:

> It is a **resource** control on this host, not a credential control on that
> file. Whoever uploaded the file has the file, and can guess against their own
> copy offline as fast as they like — nothing here changes that, and pretending
> otherwise would be theatre. What it does buy is real: every attempt costs
> *this machine* one full KDF derivation at whatever cost the uploaded file
> declared. The five attempts and the fifteen-minute idle expiry exist to stop one
> browser tab burning a core. `import-commit` never returns `locked-out`, and
> the I16 unlock lockout is deliberately not involved — that counter belongs to
> a safe that exists.

Things that refuse the import outright, before any passphrase is asked for: a
declared size over 128 MiB (`Limits.MAX_SAFE_BYTES`); a SHA-256 that does not
match the bytes received; a file whose first four bytes are neither the KDBX nor
the PWS3 signature; and KDF parameters over this host's clamps (I7) — that last
one matters because a KDF bomb would otherwise be a passphrase prompt followed
by a several-minute hang.

### 1.3 · An admin-class safe, by hand

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

### 1.4 · A user-class safe in the system registry, by hand

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

### 1.5 · The per-user registry

`~/.config/cockpit-secrets/safes.d/*.json`, `0600`, in a `0700` directory, owned
by that user. It is what lets somebody register a safe of their own without an
administrator, and it is the only change 0.4.0 makes to this program's trust
model.

**If you are a user.** Your entries are read only when the helper is running as
you, unescalated. Everything else works the same. Four rules will bite you if
you hand-edit, and all four fail closed:

1. `"access": "admin"` in your registry is **not honoured**. It is dropped and
   logged. Every entry loaded from your registry is `user` class, full stop.
2. The `path` must still be a regular file **you own**, `0600`, with no
   group- or other-writable directory above it. The entry does not grant
   access; the `fstat` on the opened fd decides (I5).
3. If your `safes.d` directory or any file in it is group- or other-writable,
   or not owned by you, the **whole** registry is refused — not just the bad
   entry.
4. If the system registry declares the same `id`, the **system entry wins** and
   yours is reported in `secrets-admin health` as an error. It is never silently
   preferred, because "the safe you opened is not the one you registered" has to
   be visible.

```bash
mkdir -p  ~/.config/cockpit-secrets/safes.d
chmod 700 ~/.config/cockpit-secrets ~/.config/cockpit-secrets/safes.d
chmod 600 ~/.config/cockpit-secrets/safes.d/*.json
secrets-admin health   # registry_errors[] empty; registry_sources shows both registries
secrets-admin list     # your safes appear, locked
```

**If you administer this host.** What changed is bounded, and the honest summary
is the safety argument itself: reading a user's registry grants them no access
they did not already have. The helper is running *as them*, and rule 2 means it
will only open a file they own, `0600`, that they could have `cat`-ed anyway.
The registry does not confer a capability — it tells a program they are already
driving which of their own files to open. **It is a convenience surface, not a
privilege surface**, and that sentence stops being true if any of rules 1–3 is
ever relaxed.

Two consequences you should know about rather than discover:

- **There is no host-wide inventory of user-class safes, and there cannot be
  one** without giving a root process a reason to read those directories — which
  is precisely rule 1 of the design (a root-mode helper never opens a per-user
  registry). `secrets-admin health` run as root reports nothing about them. If
  you need the inventory, ask the filesystem and read the answer as metadata
  about files rather than as registry state:

  ```bash
  ls -l /home/*/.config/cockpit-secrets/safes.d/*.json 2>/dev/null
  ```

- **You cannot see a collision coming.** When you register a system safe with an
  id some user already used in their own registry, nothing warns you — you
  cannot read their registry. Their entry becomes shadowed and the error appears
  in *their* `health` output, not yours. The reverse is checked: a user creating
  a safe *can* read the system registry, so `safe-create` refuses a colliding id
  up front. An unreadable directory is worth more than a checkable one.

- **There is no switch to turn it off**, and that is a stated gap rather than a
  position. It cannot live in the registry itself (a setting stored where the
  user can write it is not a setting); it would need a root-owned policy file
  the unescalated helper reads and obeys, and 0.4.0 does not have one.

### 1.6 · An upload that did not finish

An in-flight `safe-import` stages the uploaded bytes in a private directory —
`/var/lib/cockpit-secrets/state/import/` for an admin-class import,
`~/.local/state/cockpit-secrets/state/import/` for a user-class one — as
`<32 hex characters>/`, `0700`, holding exactly two `0600` files: `blob` (the
encrypted database as it arrives) and `meta.json` (the declared id, label,
class, size, digest, and the attempt count). **Never `/tmp`, and never the final
path.** `health.import_staging.dir` is the authority on where it is; the two
paths above are what it says on this host.

It is destroyed on a successful commit, on an explicit abort, and on the idle
timer — 15 minutes measured from its **last use**, not from when the upload
started.

**Closing the tab does not clean it up**, and that is worth knowing because
everywhere else in this program a closed channel ends the operation. The staging
deliberately outlives the helper process — that is what lets a 128 MiB upload be
five short-lived helper invocations instead of one channel held open for
minutes — so an abandoned upload sits there, as an encrypted blob, until the
idle timer reaps it. The page calls abort when you cancel; the timer is what
covers a crashed browser, a `SIGKILL`, or a power loss mid-upload.

The supported way to look is the helper, which also sweeps:

```bash
secrets-admin health | python3 -c 'import json,sys
i = json.load(sys.stdin)["import_staging"]
print("staging dir     :", i["dir"])
print("staged now      :", i["staged"])
print("idle timeout    :", i["idle_seconds"], "s")
print("chunk / max size:", i["chunk_bytes"], "/", i["max_bytes"], "bytes")
print("attempts, at once:", i["max_attempts"], "/", i["max_concurrent"])'
```

It reports a **count and never a token.** A staging token is a bearer name — it
plus the right uid is what `import-commit` needs — so `health` is a diagnostic
and not a place to hand them out.

Stale directories are swept automatically on the **next verb of any kind** that
anyone runs — the sweep is in `init_state`, not in the import verbs, so a
`health` or a `list` cleans up too. It only looks under the staging root, only at
names matching the 32-hex token shape, only at entries that are **actually
directories** (a symlink wearing a token's name is skipped, not followed — I53),
and only at ones unused for longer than that idle window. The two files inside
are unlinked through a descriptor on the directory, so nothing outside the root
can be reached even by a name.

Two bounds, and they are different bounds: one caller may **hold** at most eight
stagings at once (`import_max_stagings`), and at most
`import_max_concurrent` (2) `import-inspect` / `import-commit` calls may be
**running** at once, per identity. The second is newer and closes a real hole —
nothing counted work in flight, and 32 simultaneous inspects of one 128 MiB
staging measured 7.6 GiB of resident memory across 32 processes (I54). The
(N+1)th caller gets `conflict` and can retry; the page does so automatically a
few times before it gives up.

If you are cleaning up by hand — after an unclean shutdown, say — this is safe
to do and safe to get slightly wrong:

```bash
ls -l /var/lib/cockpit-secrets/state/import/
# 32-hex directories are stagings; `slot-N` files are the concurrency locks and
# are recreated on demand, so removing them is harmless too.
rm -rf /var/lib/cockpit-secrets/state/import/*
```

**Staged bytes are an encrypted safe file.** No passphrase was ever written
there, nothing decrypted was ever written there, and the credential never
touched the staging at all — it arrives on the commit request and nowhere else.
So an orphan is a disk-space problem, not a disclosure. Do not reach for `shred`
here; §8's warning is about the exports directory, which is a genuinely
different thing.

### 1.7 · Removing a safe — forget, or delete

Two verbs, and the difference is the whole point.

**`safe-forget` removes the registry entry and leaves the file alone.** It is
the default, it is what the page offers first, and it destroys nothing. The safe
stops being something this page can open; the bytes stay exactly where they are,
and the response tells you the path so you can deal with the file yourself.
Reach for this one unless you have a specific reason not to.

**`safe-delete` forgets it *and* destroys the safe file and its entire backup
ring.** It is the only operation in this program that deliberately destroys
credentials, and the backup ring is the only undo this program has — so deleting
takes the undo with it.

It is gated four ways:

- an explicit confirmation token, **`delete-safe:<id>`**, naming the safe, so a
  confirmation you gave for a throwaway cannot be replayed against the
  domain-administrator one (the same idiom as `export`'s token);
- administrator class for an admin-class safe, like every admin verb;
- audited by **id**, never by path, with the number of backup generations
  destroyed recorded in the line;
- and the one that surprises people: **it refuses unless the file is at the path
  this program itself would mint for that id.** A safe you registered by hand at
  `/srv/keys/prod.kdbx` answers `access-denied` naming this rule. Forget it, then
  remove the file yourself. We only destroy what we created — an operator's own
  file at an operator's own path is not this program's to unlink.

That last rule also means a **user-class entry in the system registry cannot be
`safe-delete`d by anybody**: its path is inside a directory the user controls,
and asking a root process to `unlink` a path in a user-writable directory is the
I5 symlink hazard with a friendly button on it. Forget it and let the user
remove their own file.

Two more things `safe-delete` will NOT do, both deliberate and both stated in
the response rather than done quietly:

- **it does not sweep a backup directory the registry entry named.** The ring it
  destroys is the one derived from the safe's own path (`<safe>.bak.d/`), and
  only the files in it that look like generations this program wrote. An entry
  whose `backup.dir` points somewhere else keeps its copies, and the response
  says so in as many words — because unlinking inside a directory a
  request-editable field named is how one delete came to empty an operator's
  `~/docs` (I47);
- **it does not run at all while two registry files declare the same id.** Both
  `safe-forget` and `safe-delete` answer `conflict` naming the files, because
  removing one of two would report success and leave the safe registered under
  the other, with whatever `path` and `access` that one declares (I51). Delete
  the duplicate by hand first.

And the order it works in matters if something goes wrong: **the registry entry
is removed first, the bytes second.** A delete that cannot finish therefore
leaves more of the safe than you asked to destroy — never less than you were
told (I48).

**A deleted safe takes its lockout counter with it**, and so does a new safe
created at the same id (I55). Without that, six wrong guesses followed by a
delete and a re-create left the operator `locked-out` of a safe two seconds old
with the passphrase they had just chosen. The counter file itself stays on disk,
zeroed — see `lockout_reset`: unlinking a file other helper processes hold a
lock on is a worse bug than a 60-byte leftover.

| you want to | do |
|---|---|
| stop showing a safe on this page | `safe-forget` |
| decommission a safe you created here, permanently | `safe-delete` |
| decommission a safe registered by hand | `safe-forget`, then `shred -u` the file and its `.bak.d/` yourself |
| stop a user opening their own safe | nothing this program does. It is their file and they can read it without us |

### 1.8 · Moving a safe between the two registries

There is no verb for it, deliberately — it changes the access class, which is
the most dangerous field there is (I1), so it is two explicit halves with a
human in between.

**System (user class) → the user's own registry.** Nothing about the file
changes; only who decides it is a safe.

```bash
# as root: stop the system entry claiming the id, keep the file
echo '{"id":"eddie-personal"}' | secrets-admin safe-forget

# as the user: register it themselves
mkdir -p ~/.config/cockpit-secrets/safes.d && chmod 700 ~/.config/cockpit-secrets/safes.d
$EDITOR ~/.config/cockpit-secrets/safes.d/50-eddie-personal.json
chmod 600 ~/.config/cockpit-secrets/safes.d/50-eddie-personal.json
secrets-admin health
```

Do the forget **first**. While both exist the system entry wins and the user's
is reported as shadowed (rule 4 above) — harmless, but it looks like a fault.

**A user's safe → the system registry, as an admin-class safe.** This is a real
change of custody, not a move: the file has to become root-owned in a root-owned
directory, and the user loses access to it through this page.

```bash
install -o root -g root -m 0600 \
    /home/eddie/.local/share/cockpit-secrets/personal.kdbx \
    /etc/cockpit-secrets/safes/team-shared.kdbx
$EDITOR /etc/cockpit-secrets/safes.d/50-team-shared.json   # access: admin, groups: [sudo]
secrets-admin health
echo '{"safe":"team-shared"}' | secrets-admin probe
```

Then have the user remove their own entry and their own copy. Two things to say
out loud before you do this: the passphrase does not change, so everyone who
knew it still knows it; and until the user deletes their copy there are two
files, diverging from the first save onwards.

**Never** point a system `access: "admin"` entry at a path inside a user's home
directory. That asks a root helper to open a file in a directory that user
controls, and only the `O_NOFOLLOW` + fd-`fstat` + parent-directory checks stand
between that and a symlink attack (I5). Copy the file out first, as above.

### When the safe does not appear

| Symptom | Cause | Fix |
|---|---|---|
| Not in `list`, named in `health.registry_errors` | the entry failed schema validation and was **dropped** — never partially applied, never defaulted open (I1) | the error names the field; validate by hand (below) |
| Not in `list`, nothing in `registry_errors` | two entries share an `id`; the lexically last file silently wins | make ids unique; the `nn-` prefix only orders the files |
| Everything returns `access-denied` | `access: "admin"` and Cockpit's Administrative access is off, or the caller is not in `groups` | turn on Administrative access; check `getent group sudo` |
| A user-class safe returns `access-denied` | the file is not owned by the caller, is not `0600`, or a parent directory is group-writable — the fd's `fstat` decides, not the path (I5) | `chown`/`chmod` the file and its parents |
| `invalid` on unlock | `format` does not match the bytes | fix `format`; the helper never guesses a format from attacker-supplied bytes |
| A per-user entry is missing and `registry_errors` says it was shadowed | the system registry declares the same `id`, and the system entry wins (§1.5 rule 4) | rename the per-user entry's `id`, or have root `safe-forget` the system one |
| A per-user entry is missing and `registry_errors` names `access` | the entry declared `"access": "admin"` in a per-user registry, which is dropped rather than obeyed | set it to `"user"`, or ask an administrator to register it in the system registry |
| **Nothing at all** from a per-user registry | the directory or a file in it is group- or other-writable, or not owned by that user — the whole registry is then refused, not just the bad file | `chmod 700` the directory, `chmod 600` the entries, `chown` both |
| A user-class safe is invisible to `secrets-admin health` run as **root** | working as designed: a root-mode helper never opens a per-user registry (§1.5) | run the helper as that user, or list the files with `ls` |
| `conflict` from `safe-create` / adopt | the id, the path it would mint, or the entry file it would mint already exists — nothing is ever overwritten | pick another id, or forget the existing entry first |

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

That filter is a **safety net, not the rule** — the rule is that a value never
reaches a log call at all — and it is worth knowing exactly how far the net
reaches. It matches literal text, and `emit()` and `audit()` apply it to the
output of `json.dumps`, so a secret has to be matched in its JSON-escaped form
as well as its raw one. Until 0.2.1 it was not: a passphrase containing a double
quote or a NUL byte matched none of the filter's candidates, because `repr()` —
which was a candidate — renders both differently from JSON. No path in the
program actually put such a value in a response, and none does now; the hole was
in the last line of defence rather than in the line in front of it. Both JSON
renderings are candidates now (KNOWN_ISSUES I30), and the project's own
self-check no longer proves the point with an alphanumeric sentinel alone.

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
lock out. The counters are in `/var/lib/cockpit-secrets/state/`, one file per
pair, named `fail.<uid>.<safe id>.json`, `0600`. The page shows the remaining
time; `locked-out` is a distinct error code from `bad-credential`.

**A counter file exists only while there have been failures.** A successful
unlock *removes* it — it does not zero it. So `ls /var/lib/cockpit-secrets/state/`
is a straight answer to "who is currently failing against what", with no need to
read any of the files. (Before this was fixed, the first successful unlock of
every pair left a zeroed counter behind for good, so the directory filled up
with files that meant nothing; a file there did not mean what it looks like it
means. If you see zeroed counters on an older host, they are inert and safe to
delete — see `docs/ROOT-VERIFICATION.md` F2.)

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
| the bytes we built cannot be read back (I24) | `conflict` |
| the lock path holds something that is not a lock file (I28) | `conflict` |
| the backup generation could not be written — a full disk (I26) | `internal`, naming the errno |

The third of those is new in 0.2.1 and is the one to read twice if you see it.
`conflict: the database we built cannot be read back, so it was not written: …`
means the save produced bytes that this program's own reader refuses, and it
refused to publish them. **The live safe is untouched.** The detail names what
the reader objected to; that is the thing to fix (usually an oversized field or
attachment), and until it is fixed the safe is exactly as it was.

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

### The exports directory — find it, read the ledger, destroy the file

`install.sh` creates **`/var/lib/cockpit-secrets/exports/`, `0700 root:root`,
empty**, at install time. The helper would create it on first use anyway, so
this is not load-bearing — it is so the directory exists *before* anything lands
in it. A directory that appears the first time somebody dumps a safe in the
clear is a directory nobody has ever looked at.

`--uninstall` keeps it, along with the registry, the audit log and the lockout
counters. Removing the software must not be the moment plaintext copies of your
safes silently disappear — or silently survive unnoticed, which is the more
likely of the two.

**1 · Which safes can be dumped, and where would it land.** Ask the helper, not
the directory: an entry may set its own `export_dir`, so there can be more than
one such directory on the host and only the registry knows them all.

```bash
secrets-admin health | python3 -c 'import json,sys
h = json.load(sys.stdin)["export"]
print("default:", h["default_dir"])
for row in h["enabled_safes"]:
    print("  %-20s %-6s -> %s" % (row["safe"], row["access"], row["dir"]))'
```

`enabled_safes` empty is the answer you want: no registry entry sets
`export_allowed`, so no export can be written at all.

The sample output here and in steps 2 and 3 was measured against a **hermetic
test registry** with one export-enabled safe, so its paths are the test root's
(`COCKPIT_SECRETS_VAR` moves them; see the helper's "test seams"). On a real
host they read `/var/lib/…` instead — `default_dir` is reported unmoved, which
is why it is in the output at all:

```
default: /var/lib/cockpit-secrets/exports
  lab-export           admin  -> …/var/exports
```

**2 · What is in it right now.** Root only — the directory is `0700`:

```bash
ls -l /var/lib/cockpit-secrets/exports/
# -rw------- 1 root root 1742 …  lab-export-20260904T091822Z.csv
```

The name is minted by the helper as `<safe id>-<UTC stamp>.<ext>`, so the file
names alone tell you which safe and when. `O_EXCL`, so an export never
overwrites an earlier one: two dumps of the same safe are two files.

**3 · The ledger.** Every export attempt is in the audit log, and a successful
one carries the file name and the row count — never the content (I15/I21). This
finds exports that were written and then *moved somewhere else*, which is the
case an `ls` cannot see:

```bash
python3 -c 'import json,sys
for ln in open("/var/log/cockpit-secrets/audit.log"):
    d = json.loads(ln)
    if d["verb"] == "export":
        print(d["ts"], d["outcome"], d["safe"], d["artifact"], d["rows"])'
# 2026-09-04T09:18:22.123Z ok lab-export lab-export-20260904T091822Z.csv 6
```

An `outcome` that is not `ok` is a refused attempt — someone tried. Those are
worth reading in their own right: the export gate is four separate refusals, and
a run of them is a person working through the checklist.

**4 · Destroy it.** `shred -u`, not `rm`:

```bash
shred -u /var/lib/cockpit-secrets/exports/*
```

Say plainly what that does and does not buy you on this host. `/var` here is
**ext4** (`/dev/nvme0n1p2`), so `shred` overwriting in place is meaningful —
which it would **not** be on btrfs, ZFS or any copy-on-write filesystem, where
the overwrite lands in a new extent and the old one stays until it is reused.
Nothing overwrites the page cache, a snapshot, a backup of `/var`, or a copy you
made somewhere else. An export that has been on disk for a week has been backed
up; shredding the original does not reach the backup. The only version of this
that is fully true is not writing the export in the first place.

Nothing expires an export: there is no retention, no rotation, no cleanup timer,
and deliberately so — a program that deleted evidence of its own plaintext dumps
on a schedule would be worse. The directory is your responsibility from the
moment you set `export_allowed: true`.

**Attachments are different, deliberately.** An attachment download streams
through the Cockpit channel to your browser rather than landing on this host's
disk. There is no attachment-export-to-path verb, for exactly the reason above.

## 9 · Uninstalling

```bash
sudo ./install.sh --uninstall
```

Removes the Cockpit package, the helper, the backends, the schema and any agent
unit — both the per-user units and the `secrets-agent@.service` system template,
which `--with-agent` installs and an earlier version of the uninstall left
behind. **Keeps** `/etc/cockpit-secrets/` (registry and safes),
`/var/log/cockpit-secrets/` (the audit log), `/var/lib/cockpit-secrets/state/`
(lockout counters) and `/var/lib/cockpit-secrets/exports/` — removing a program
must not silently change who may open what, and an uninstall must not be a way
to clear a lockout. The installer prints the exact `rm -rf` if you really want
those gone.

Two things `--uninstall` does **not** reach, and both are deliberate. It never
touches `~/.config/cockpit-secrets/safes.d/` or `~/.local/share/cockpit-secrets/`
or `~/.local/state/cockpit-secrets/`
in anybody's home directory — the uninstaller runs as root and those are
per-user registries and per-user safes, so removing them would be exactly the
root-writes-into-a-user's-home operation the whole per-user design refuses
(§1.5). Users remove their own. And it leaves `/var/lib/cockpit-secrets/state/import/`
in place; it should be empty, and if it is not, §1.6 says what is in it
(encrypted bytes from an interrupted upload) and how to clear it.

**Look in the exports directory before you type that `rm -rf`.** It is the one
kept location that can hold plaintext copies of your safes, and `rm -rf` is not
how you destroy those — [§8](#the-exports-directory--find-it-read-the-ledger-destroy-the-file)
has the ledger query and the `shred`.

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
