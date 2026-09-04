# `etcdefaults/` — seeded registry examples

Two registry entries that `install.sh` copies into
`/etc/cockpit-secrets/safes.d/` so an operator has a correct shape to start
from. They are documentation that happens to be machine-checkable: the
installer validates both against
[`../schema/safe-registry.schema.json`](../schema/safe-registry.schema.json)
and refuses to install if either one is invalid, so an example cannot rot into
teaching a shape the helper would drop.

| File | Class | What it demonstrates |
|---|---|---|
| `10-example-admin.json` | `admin` (the default) | a root-owned safe under `/etc/cockpit-secrets/safes/`, gated on the `sudo` group |
| `20-example-user.json` | `user` | a safe in a user's own tree, opened by an unescalated helper running as that user |

Every field the schema allows is present in both, including the ones whose
value is the default, because a field you can see is a field you can reason
about. Read the `$comment` on each property in the schema for what breaks when
it is set wrong.

## The seeding rule: seed only what is missing, never clobber

`install.sh` copies each of these into `/etc/cockpit-secrets/safes.d/`
**only when nothing is there already**, and prints `kept existing …` when
something is. It never writes over a file in that directory.

That is not politeness. A registry entry *is* the access-control policy for a
safe — it decides the access class, which uid may open it, which groups gate
it, and whether the safe may be written at all. An installer that overwrote one
would silently change who can open what, and the operator's first hint would be
either a locked-out colleague or an unlocked safe.

## They are seeded *disabled*, and the file name is how

The helper's registry is `/etc/cockpit-secrets/safes.d/*.json`. These examples
are installed with a `.example` suffix — `10-example-admin.json.example` — which
that glob does not match. The registry loader never reads them.

The suffix, rather than an "enabled": false key, for two reasons:

- The schema sets `additionalProperties: false`, so there is no key that means
  "ignore this entry". Adding one would put a second, weaker way to express
  access policy next to the one the helper enforces.
- A live example entry would be worse than useless. It would show up in the safe
  list as a permanently broken row, which trains people to ignore broken rows in
  a page whose whole job is to be trusted — and the moment anyone happened to
  create a file at the example path, an entry nobody consciously wrote would
  become a **real safe with real access rules**. Access control must never
  appear by accident.

To use one, copy it — do not rename it — and edit the copy:

```bash
cp /etc/cockpit-secrets/safes.d/10-example-admin.json.example \
   /etc/cockpit-secrets/safes.d/10-lab-dc.json
$EDITOR /etc/cockpit-secrets/safes.d/10-lab-dc.json   # id, label, path, access
chmod 0644 /etc/cockpit-secrets/safes.d/10-lab-dc.json
chown root:root /etc/cockpit-secrets/safes.d/10-lab-dc.json
secrets-admin health          # registry_errors[] must be empty
```

`id` must be unique across the whole directory: two files declaring the same id
means the lexically last one wins, silently. The `nn-` prefix is only there to
make that ordering visible.

## The two access classes, and why `admin` is the default

|  | `access: "user"` | `access: "admin"` (**default**) |
|---|---|---|
| Helper euid | the logged-on user | `0`, or the verb is refused |
| Cockpit call | `cockpit.spawn([…])` | `cockpit.spawn([…], {superuser: "require"})` |
| Extra gate | the safe file must be owned by the caller | the real caller behind the escalation must be in one of `groups` |
| Safe file | `0600`, owned by that user, in their own tree | `0600 root:root`, in `/etc/cockpit-secrets/safes/` |

**An entry that omits `access` is `admin`.** The schema says
`"default": "admin"` and the helper resolves a missing key the same way. A
hand-edit that loses a line therefore fails closed: the entry becomes *harder*
to reach, not easier. The opposite default would turn a truncated write into a
privilege grant (`docs/KNOWN_ISSUES.md` I1).

Two related facts that are easy to get backwards:

- Setting `"user"` on a root-owned safe does not make it readable by that user.
  It makes every unlock fail `access-denied`, because the fd's `st_uid` will not
  match the caller.
- Setting `"admin"` on a safe inside a user's home directory is the dangerous
  direction: it asks a **root** helper to open a file in a directory that user
  controls, and only the `O_NOFOLLOW` + `fstat`-the-fd + parent-directory checks
  stand between that and a symlink attack (I5).

The whole directory is only trusted while it is `0755 root:root` with entries
`0644 root:root`. `secrets-admin` refuses to read a registry that is group- or
other-writable, because a registry an unprivileged user can edit is a registry
that grants itself root.
