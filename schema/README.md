# `schema/` — the safe registry

`safe-registry.schema.json` is a Draft-07 JSON Schema for one file in
`/etc/cockpit-secrets/safes.d/*.json`. Every field it defines appears in
[`../docs/CONTRACT.md`](../docs/CONTRACT.md) and vice versa; the schema is the
machine-readable half of that document and `additionalProperties` is `false`, so
drift between the two shows up as a dropped entry rather than as a surprise.

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

`secrets-admin` refuses to trust the directory at all if it, or any entry in it,
is group- or other-writable. A registry an unprivileged user can edit is a
registry that grants itself root.

## The two access classes — and `admin` is the default

| | `access: "user"` | `access: "admin"` (**default**) |
|---|---|---|
| Helper euid | the logged-on user | `0`, or the verb is refused |
| Cockpit call | `cockpit.spawn([...])`, no `superuser` | `cockpit.spawn([...], {superuser: "require"})` |
| Extra gate | the safe file must be owned by the caller | the real caller (behind the escalation) must be in one of `groups`, defaulting to the host's admin group |
| Where the safe lives | a path that user owns, `0600` | `0600 root:root` |

**A registry entry that omits `access` is `admin`.** The schema declares
`"default": "admin"` for exactly that reason. This is not a stylistic choice:

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
import json, sys, glob
from jsonschema import Draft7Validator
schema = json.load(open("/usr/local/lib/cockpit-secrets/schema/safe-registry.schema.json"))
v = Draft7Validator(schema)
for path in sorted(glob.glob("/etc/cockpit-secrets/safes.d/*.json")):
    errs = sorted(v.iter_errors(json.load(open(path))), key=str)
    print(path, "OK" if not errs else "DROPPED: " + errs[0].message)
PY
```

`secrets-admin health` reports the same thing as `registry_errors[]`, which is
the supported way to see why a safe is missing from the list.

## Field reference

Read the `$comment` on each property in the schema itself. Every one says what
breaks if that field is set wrong, which is more useful than a table here that
can drift away from it.
