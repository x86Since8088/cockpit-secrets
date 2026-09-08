# `etcdefaults/user-safes.d/` — the per-user registry example

One entry showing the shape of a file in a **per-user** registry:

```
~/.config/cockpit-secrets/safes.d/50-<id>.json      0600, owned by that user
~/.config/cockpit-secrets/safes.d/                  0700, owned by that user
```

It is validated against the same
[`../../schema/safe-registry.schema.json`](../../schema/safe-registry.schema.json)
as a system entry — there is one schema, and a per-user entry that fails it is
dropped exactly like a system one. What differs is not the shape but **who reads
it, and what the reader refuses to believe about it.**

> This directory is *not* seeded into `/etc/cockpit-secrets/safes.d/`. The
> installer's glob is `etcdefaults/*.json`, which does not descend, and that is
> deliberate: a per-user entry copied into the system registry would be an entry
> naming a path in somebody's home directory, read by a **root** helper — the
> exact "admin class on a user-controlled directory" mistake the system
> examples warn about. Copy it into a user's own tree by hand, as below.

## Why this registry exists at all

Root owns `/etc/cockpit-secrets/safes.d/`. An unprivileged user cannot write
there, so before 0.4.0 they could not have a safe of their own without an
administrator hand-writing an entry for them. The per-user registry is what lets
`safe-create` and `safe-import` work for a normal user.

**The safety argument, in one paragraph, because everything below depends on
it.** Reading this file grants the user no access they did not already have: the
helper is running *as them*, unescalated, and it will only open a file they own,
`0600`, with no group- or other-writable parent — all of which they could read
with `cat` regardless. The registry does not give them a capability; it tells a
program they are already driving which of their own files to open. It is a
**convenience surface, not a privilege surface**. That argument holds only while
rules 1–4 below hold. Relax any one of them and it stops being true.

## The five rules the helper enforces

**1 · It is read only by an unescalated helper (`euid != 0`).** The root path
never reads a per-user registry — it does not merge it, does not fall back to
it, and **does not open it at all**. There is no code path in which a root
process parses JSON out of a directory an unprivileged user can write.

**2 · Every entry is forced to `access: "user"`.** Whatever the file says. An
entry that declares `"access": "admin"` is not honoured, not silently corrected
and not partially applied — it is **dropped and logged**, and shows up in
`secrets-admin health` under `registry_errors[]`. A file the user can write must
never be a file that names its own access class; that is the trust root handed
over in one line.

**3 · The `path` must pass exactly the checks `open_safe_fd` already imposes.**
A regular file the calling user owns, mode `0600`, opened `O_NOFOLLOW` and
`fstat`ed on the returned fd, with no group- or other-writable directory above
it. A symlink, a file owned by someone else, or a `0644` file is
`access-denied` — the entry naming it changes nothing.

**4 · The directory and its files must be owned by that user and not group- or
other-writable, or the WHOLE per-user registry is refused.** Same fail-closed
rule as the system one, for the same reason: a registry a second party can edit
is a registry that grants itself that party's wishes. Refused means *no* entry
from it loads, not "the bad ones are skipped".

**5 · A system entry wins an id collision, and the shadowed entry is an
error.** If `/etc/cockpit-secrets/safes.d/` declares `id: "lab-dc"` and so does
`~/.config/cockpit-secrets/safes.d/`, the system entry is the one that resolves
and the per-user one is **reported in `health.registry_errors[]`**. It is never
silently preferred and never silently ignored — "your safe is not the one you
think it is" has to be visible or the user unlocks the wrong file.

There is a deliberate asymmetry in how collisions are *prevented*, and it falls
out of rule 1: a user creating a per-user safe can see the system registry, so
`safe-create` refuses a colliding id with `conflict`. An administrator creating
a **system** safe cannot see any per-user registry, so it cannot check — the
collision is discovered later, by rule 5, in that user's own `health` output.
That is the cost of rule 1 and it is the right way round: an unreadable
directory beats a checkable one.

## Adopting this example

```bash
mkdir -p  ~/.config/cockpit-secrets/safes.d
chmod 700 ~/.config/cockpit-secrets ~/.config/cockpit-secrets/safes.d

cp /usr/local/share/cockpit-secrets/examples/user-safes.d/50-example-personal.json \
   ~/.config/cockpit-secrets/safes.d/50-personal.json
$EDITOR ~/.config/cockpit-secrets/safes.d/50-personal.json   # id, label, path, format
chmod 600 ~/.config/cockpit-secrets/safes.d/50-personal.json

secrets-admin health   # registry_errors[] empty; registry_sources shows both registries
secrets-admin list     # your safe appears, locked
```

Set `id`, `label`, `path` and `format`. Leave `access` at `"user"` — it is
written out here as a courtesy to a human reader, and rule 2 would impose it
anyway. Leave `owner` at `null`, which means "the caller" and is what you want.

Most people should not do any of this by hand: **Safes → New safe** and
**Safes → Adopt a safe** in the page write exactly this file for you, into
exactly this directory, with exactly these modes.

## What the example's values mean

- `"mode": "ro"` — every shipped example is read-only so that a copy made
  without thinking cannot write to a safe.
- `"origin": "created"` with a `created_utc` — the shape `safe-create` writes.
  `"source": null` is correct here: a created safe was not imported, so there is
  no header summary to record. See `40-example-imported.json` for the shape with
  one.
- The path is under `/home/example/`, which does not exist. That is on purpose,
  as with every other example: an entry that resolved to a real file would be a
  real safe with real access rules that nobody consciously wrote.

## What the administrator of the host should know

Per-user registries are **not visible to root's `secrets-admin health`** — rule
1 again. There is no host-wide list of every user-class safe, and there cannot
be one without giving a root process a reason to read those directories.

If you need that inventory, ask the filesystem, not the helper, and read the
result as *metadata about files* rather than as registry state:

```bash
ls -l /home/*/.config/cockpit-secrets/safes.d/*.json 2>/dev/null
```

What this changes about your host is bounded and worth stating plainly: a user
who could already read their own files can now point this page at them. They
cannot create an admin-class safe (rule 2), cannot make the helper open a file
they do not own (rule 3), and cannot shadow a safe you registered (rule 5).

**There is no host-wide off switch, and that is a stated gap rather than a
position.** Deleting a user's `safes.d` does not stop them recreating it, and
the switch cannot live in the registry itself — a setting stored where the user
can write it is not a setting. Turning this off would need a root-owned policy
file the unescalated helper reads and obeys, which 0.4.0 does not have. Until it
does, the honest description of the control you have is the safety argument at
the top of this file: the feature grants no access the user did not already
have, so there is nothing to switch off except the convenience.
