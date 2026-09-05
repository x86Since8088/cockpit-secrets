# `schema/` — the safe registry

`safe-registry.schema.json` is a Draft-07 JSON Schema for one registry entry.
Every field it defines appears in [`../docs/CONTRACT.md`](../docs/CONTRACT.md)
and vice versa; the schema is the machine-readable half of that document and
`additionalProperties` is `false`, so drift between the two shows up as a
dropped entry rather than as a surprise.

## The registry is the only source of safes

There is **no verb that opens a caller-supplied path**. Verbs take an `id`; the
helper resolves that id to a path from this registry and nowhere else (I4). That
is what makes "user safe" and "admin safe" mean anything: nothing inside a KDBX
or `.psafe3` file records who may open it, so the access class is imposed from
outside the file or it does not exist at all (I1).

Layout, and it matters:

| Path | Mode | Owner |
|---|---|---|
| `/etc/cockpit-secrets/safes.d/` | `0755` | `root:root` |
| `/etc/cockpit-secrets/safes.d/*.json` | `0644` | `root:root` |
| `/etc/cockpit-secrets/safes/` | `0700` | `root:root` |
| an admin-class safe file | `0600` | `root:root` |
| a user-class safe file | `0600` | that user |
| `~/.config/cockpit-secrets/safes.d/` | `0700` | that user |
| `~/.config/cockpit-secrets/safes.d/*.json` | `0600` | that user |
| `~/.local/share/cockpit-secrets/safes/` | `0700` | that user |

`secrets-admin` refuses to trust either directory at all if it, or any entry in
it, is group- or other-writable. A registry an unprivileged user can edit is a
registry that grants itself root.

## One schema, two registries

The same schema validates both. What differs is not the shape but who reads it
and what the reader refuses to believe about it:

| | `/etc/cockpit-secrets/safes.d/` | `~/.config/cockpit-secrets/safes.d/` |
|---|---|---|
| Read when | always | **only when `euid != 0`** — a root-mode helper does not open it at all |
| `access` | as written; omitted ⇒ `admin` | **forced to `user`**; an entry declaring `admin` is dropped and logged |
| Trusted directory | `0755 root:root` | `0700`, owned by the calling user |
| Id collision | wins | loses, and the shadowed entry is reported in `health.registry_errors[]` |

**Why reading a user-writable file is safe here, in one paragraph.** The helper
is running *as that user*, unescalated, and the entry's `path` still has to pass
`open_safe_fd` — a regular file **they own**, `0600`, opened `O_NOFOLLOW` and
`fstat`ed on the returned fd, under no group- or other-writable directory. Every
file it can name is a file they could already read with `cat`. The registry
confers no capability; it tells a program they are already driving which of
their own files to open. It is a **convenience surface, not a privilege
surface**, and that stops being true the moment a root-mode helper reads one, or
an entry from one is allowed to name its own access class. The full rules are in
[`../docs/CONTRACT.md`](../docs/CONTRACT.md), "The per-user registry", and in
[`../etcdefaults/user-safes.d/README.md`](../etcdefaults/user-safes.d/README.md).

## The three fields that are records, not permissions

`origin`, `created_utc` and `source` were added with `safe-create` and
`safe-import`. Nothing is keyed on them — the backend reads the real file header
on every unlock and never consults `source`, and the access class comes from
`access` as it always did.

The one that invites a mistake is `origin`. Hand-writing `"origin": "created"`
does **not** persuade `safe-delete` to destroy a file: that gate is *derived*,
the entry's `path` must equal the path this program would mint for that id and
access class today, precisely so a field an operator can edit cannot talk the
helper into an `unlink`.

`source.sha256_at_import` looks like an integrity check and is not one. It is
the digest of the bytes **as uploaded**; it stops matching the moment the safe is
first saved, and that is correct. Reading a mismatch on a safe that has been in
use as evidence of tampering is a misreading of the field, not a finding.

All three are optional, so no entry written before they existed is disturbed by
their arrival — which is the only reason it was safe to add them to a schema
whose `additionalProperties` is `false`.

## The `id` pattern is deliberately looser than what the verbs mint

The schema accepts `^[a-z0-9][a-z0-9._-]*$`. `safe-create` and `safe-import`
mint against `^[a-z0-9][a-z0-9-]{1,62}$` — no dot, no underscore, at least two
characters — published as `constants.safe_id_pattern`.

The asymmetry is on purpose and it is not tidiness waiting to be fixed:
tightening the schema to match would **drop** every hand-written entry using a
dot or an underscore, which means silently deleting a working safe from an
operator's list on upgrade. The loose pattern is what the loader will *read*;
the strict one is what this program will *write*, because a minted id becomes a
file name it chose.

## The two access classes — and `admin` is the default

| | `access: "user"` | `access: "admin"` (**default**) |
|---|---|---|
| Helper euid | the logged-on user | `0`, or the verb is refused |
| Cockpit call | `cockpit.spawn([...])`, no `superuser` | `cockpit.spawn([...], {superuser: "require"})` |
| Extra gate | the safe file must be owned by the caller | the real caller (behind the escalation) must be in one of `groups`, defaulting to the host's admin group |
| Where the safe lives | a path that user owns, `0600` | `0600 root:root` |

**A registry entry that omits `access` is `admin`** — in the system registry.
(In a per-user registry the key is not honoured at all: every entry is forced to
`user`, and one declaring `admin` is dropped and logged rather than obeyed. A
file the user can write must never be the file that names its own access class.)
The schema declares `"default": "admin"` for exactly that reason. This is not a
stylistic choice:

- A typo in a field name (`"acess": "user"`) is refused outright by
  `additionalProperties: false`, so it cannot half-apply.
- A missing `access` key falls to the **restrictive** class, so a hand-edited
  file that loses a line fails closed. The opposite default would turn a
  truncated write into a privilege grant.
- An entry that fails validation for any reason is **dropped and logged**. It is
  never partially applied and never defaulted to the permissive class.

Both checks run **in the helper, on every verb**, from an identity the kernel
supplies (`geteuid`, `getuid`, `getgroups`, and `SUDO_UID`/`PKEXEC_UID` behind
an escalation) — never from the request body, and never in the browser. A
browser-side access check is cosmetic: the sibling project `cockpit-guac-rdp`
shipped one as its `I4` and had to tear it out when it turned out to be
bypassable by driving the backend directly. The UI here may *grey out* a safe
the caller cannot reach, but the greying is decoration and the helper is what
refuses (I3).

## The one rule the schema enforces that is not just a type

`password_required: false` is **invalid** unless `keyfile` or `yubikey_slot`
names a real key. It is expressed as an `anyOf` over four branches at the bottom
of the schema, and the branch that accepts a key file requires it to be a
`string` — so `{"password_required": false, "keyfile": null}` is refused, which
is the shape a half-finished edit actually produces.

The helper re-checks the same rule when it loads the entry. That is deliberate
duplication: a schema is a validator, not an enforcement point, and the only
enforcement that counts is the one in the process the user cannot rewrite.

Everything else about this project follows from the same idea. The passphrase is
prompted on **every** unlock, not because a setting says so, but because one
`cockpit.spawn` runs one short-lived helper for one operation and there is
nowhere for a handle to survive. `keyfile`, `yubikey_slot` and `agent.enabled`
are the only three fields that change that, all three default to "no", and
`agent.enabled` should stay that way on almost every safe (I18).

## Validating an entry by hand

```bash
python3 - <<'PY'
import json, glob, os
from jsonschema import Draft7Validator
schema = json.load(open("/usr/local/lib/cockpit-secrets/schema/safe-registry.schema.json"))
v = Draft7Validator(schema)
dirs = ["/etc/cockpit-secrets/safes.d",
        os.path.expanduser("~/.config/cockpit-secrets/safes.d")]   # yours, if you have one
for d in dirs:
    for path in sorted(glob.glob(os.path.join(d, "*.json"))):
        errs = sorted(v.iter_errors(json.load(open(path))), key=str)
        print(path, "OK" if not errs else "DROPPED: " + errs[0].message)
PY
```

Passing this is necessary and not sufficient for a per-user entry: the schema
cannot see that a root helper will not read it, that `access` is forced to
`user` whatever the file says, or that the directory has to be `0700` and yours.
`secrets-admin health` run **as you** is the check that covers those.

`secrets-admin health` reports the same thing as `registry_errors[]`, which is
the supported way to see why a safe is missing from the list.

## Field reference

Read the `$comment` on each property in the schema itself. Every one says what
breaks if that field is set wrong, which is more useful than a table here that
can drift away from it.
