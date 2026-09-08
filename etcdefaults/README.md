# `etcdefaults/` — seeded registry examples

Four registry entries that `install.sh` copies into
`/etc/cockpit-secrets/safes.d/` so an operator has a correct shape to start
from, plus one more in [`user-safes.d/`](user-safes.d/README.md) that it
deliberately does not copy anywhere. They are documentation that happens to be
machine-checkable: the installer validates every one of them against
[`../schema/safe-registry.schema.json`](../schema/safe-registry.schema.json)
and refuses to install if any is invalid, so an example cannot rot into
teaching a shape the helper would drop.

| File | Class | What it demonstrates |
|---|---|---|
| `10-example-admin.json` | `admin` (the default) | a root-owned safe under `/etc/cockpit-secrets/safes/`, gated on the `sudo` group |
| `20-example-user.json` | `user` | a safe in a user's own tree, opened by an unescalated helper running as that user |
| `30-example-created.json` | `admin` | what **`safe-create`** writes: `origin: "created"`, a `created_utc` stamp, and `source: null` because nothing was imported |
| `40-example-imported.json` | `admin` | what **`safe-import`** writes: `origin: "imported"` plus the `source` block recording the header summary read from the uploaded bytes |
| `user-safes.d/50-example-personal.json` | `user` | an entry in a **per-user** registry, `~/.config/cockpit-secrets/safes.d/`. Not seeded by the installer — see that directory's README for rules 1–5 and why |

Every field the schema allows is present in all of them, including the ones
whose value is the default, because a field you can see is a field you can
reason about. Read the `$comment` on each property in the schema for what
breaks when it is set wrong.

## The three provenance fields, and what an example cannot show you

`origin`, `created_utc` and `source` are **records, not permissions**. Nothing
is keyed on them; the helper reads the real header on every unlock and never
consults `source`. They exist so an operator can answer "where did this safe
come from, and what was it when it arrived" without unlocking it.

Two things about `40-example-imported.json` specifically:

- Its `sha256_at_import` is sixty-four zeros. That is not a digest of anything —
  it is obviously fabricated on purpose, so that nobody copies the example and
  ends up with a plausible-looking digest that describes a different file.
- A real one is the digest of the bytes **as uploaded**, and it stops matching
  the file on disk the moment the safe is first saved. It answers "is this the
  file I uploaded" at adoption time and nothing later. Reading a mismatch on a
  safe that has been in use as evidence of tampering is a misreading of the
  field, not a finding.

An entry written before 0.4.0 has none of these keys, which reads as
`origin: "manual"`, `created_utc: null`, `source: null` — the honest answer for
a file this program did not write. Adding them by hand to an old entry is
allowed and changes nothing about what the helper will do with it. In
particular, hand-writing `"origin": "created"` does **not** make `safe-delete`
willing to destroy a file: that gate is derived from the path, not read from
this field (`schema/safe-registry.schema.json`, the `origin` comment).

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

**Since 0.4.0 you usually should not do this by hand.** `safe-create` and
`safe-import` write the entry for you — into `/etc/cockpit-secrets/safes.d/` as
`50-<id>.json` for an admin-class safe, or into the caller's own
`~/.config/cockpit-secrets/safes.d/` for a user-class one — validated against
this schema *before* it lands and written by the same temp-file + `fsync` +
`os.replace` + directory-`fsync` path every other write in this program uses. A
half-written registry entry is dropped by the loader, which is correct and
silent, so the verbs never produce one. Hand-editing remains fully supported and
is the only way to reach the fields those verbs do not set (`groups`, `agent`,
`export_allowed`, `keyfile`, `yubikey_slot`, `breach_corpus`, `backup`).

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
