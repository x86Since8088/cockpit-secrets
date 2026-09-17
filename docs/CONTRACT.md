# secrets-admin contract

Same shape as `wg-admin` / `adlab-admin` / `hs-admin` on this host, with one addition forced
by the subject matter: **requests carry secrets, so requests arrive on stdin as JSON, not on
argv.**

- The plugin never runs raw commands. It calls ONE helper, `/usr/local/sbin/secrets-admin`,
  with a narrow verb.
- Every verb prints **exactly one JSON object on stdout and nothing else**. Diagnostics go to
  stderr. Exit 0 = success; on failure stdout carries `{"error": "..."}` and exit ≠ 0. The one
  exception is `open`, which is a session and writes one object per request line — that is
  what makes it the only verb dispatched separately. **`safe-import` is deliberately not a
  second one:** its five steps are five ordinary verbs tied together by a staging token, so a
  128 MiB upload does not need a channel held open for its whole life.
- The UI renders nothing it invented: every form, control, validation rule and label comes
  from `secrets-admin schema`.
- **No verb accepts a secret as an argument.** Passwords, key-file bytes and new values are
  fields of the JSON request object on stdin (I10).

**This file is the interface, and the whole build coordinates through it.** Where it and the
`schema` verb disagree, the schema is what the page actually reads — so a disagreement is a
bug in this file and gets fixed here, not worked around there. Schema version 2; helper 1.0.0.

> **One qualification learned by cross-checking the two, which a reader needs before trusting
> either.** The `schema` verb's `response` map is a *summary for a form renderer*, and for
> several verbs it is deliberately shorter than what the verb actually prints — `strength`
> returns six keys the schema does not name, `export` returns `mode` and `warning`, `health`
> returns eleven top-level keys the schema abbreviates to five. So: **the schema is
> authoritative for `request` fields** (that is what the page builds forms from, and what
> `validate.sh`'s I4 ban scans), and **this document is authoritative for `response` keys.** A
> response key named here and absent from the schema is not necessarily a lag; a *request*
> field named here and absent from the schema always is. The current list of both is at the
> end of this file.

## Invocation

```js
// user-class safe — helper runs as the logged-on user, no escalation
cockpit.spawn(["/usr/local/sbin/secrets-admin", "unlock"],
              { err: "message", superuser: null })

// admin-class safe — helper must be euid 0 or it refuses the verb
cockpit.spawn(["/usr/local/sbin/secrets-admin", "unlock"],
              { err: "message", superuser: "require" })
```

The request object is written to the child's stdin and the stream is closed:

```json
{ "safe": "lab-dc", "password": "…", "keyfile_b64": null, "session": null }
```

`manifest.json` declares `"superuser": "try"`: the page is usable without escalation (user
safes only, admin safes listed but locked) and gains the admin class when Cockpit's
Administrative access is on.

## Identity and access class

| | `access: "user"` | `access: "admin"` (**default**) |
|---|---|---|
| Helper euid | the logged-on user | 0, or the verb is refused |
| Cockpit call | no `superuser` | `superuser: "require"` |
| Caller check | file must be owned by the caller | caller uid ∈ an admin group (`sudo`/`wheel`), re-checked in the helper |
| Safe location | a path the user owns, `0600` | root-owned, `0600 root:root` |

A registry entry that omits `access` is **`admin`**. An entry that fails schema validation is
**dropped** and logged — never defaulted to the permissive class (I1).

## The registry — the only source of safes

`/etc/cockpit-secrets/safes.d/*.json`, directory `0755 root:root`, files `0644 root:root`.
Verbs take a registry **id**; there is no verb that opens a caller-supplied path (I4).

```json
{
  "id": "lab-dc",
  "label": "AD Lab domain accounts",
  "format": "kdbx",                     // "kdbx" | "psafe3"
  "path": "/etc/cockpit-secrets/safes/lab-dc.kdbx",
  "access": "admin",                    // omitted => "admin"
  "owner": null,                        // "user" class: uid/name, or "%u" for per-user
  "groups": ["sudo"],                   // additional gate for admin class
  "mode": "rw",                         // "rw" | "ro"
  "password_required": true,            // false ONLY with a keyfile/hardware key
  "keyfile": null,                      // absolute path, helper-side only
  "yubikey_slot": null,
  "agent": { "enabled": false, "idle_seconds": 300, "max_seconds": 3600,
             "allow_keep_open": false },   // I18 — may the idle timeout be suspended?
  "export_allowed": false,              // I21
  "export_dir": null,                   // I21 — absolute, never under /tmp
  "breach_corpus": null,                // absolute path to an OFFLINE corpus
  "backup": { "keep": 10, "dir": null },

  "origin": "manual",                   // "manual" | "created" | "imported" — a RECORD
  "created_utc": null,                  // when safe-create/safe-import wrote THIS ENTRY
  "source": null                        // header summary read at import; not re-verified
}
```

Those nineteen keys are the whole vocabulary. `export_dir` and `breach_corpus` are
helper-side absolute paths, never a path from a request (I4). `export_dir` is refused under
`/tmp`, `/var/tmp` and `/dev/shm`, and setting it while `export_allowed` is false is refused
rather than ignored — the two are one decision. `breach_corpus` names an offline file and
nothing else: **there is no online fallback and there will not be one.**

`origin`, `created_utc` and `source` were the last three added, with the registry-writing
verbs below. All three are **records, never permissions** — nothing is keyed on them,
and the backend reads the real header on every unlock rather than trusting `source`. The one
that invites a wrong assumption is `origin`: hand-writing `"origin": "created"` does **not**
persuade `safe-delete` to destroy a file. That gate is *derived* — the entry's `path` must
equal the path this program would mint for this id and access class today — precisely so a
field an operator can edit cannot talk the helper into an `unlink`.

`source.sha256_at_import` deserves its own sentence because it looks like an integrity check
and is not one: it is the digest of the bytes **as uploaded**, it stops matching the moment
the safe is first saved, and that is correct. It answers "is this the file I uploaded" at
adoption time. Nothing later.

An entry written before 0.4.0 carries none of the three, which reads as `manual` / `null` /
`null` — the honest answer for a file this program did not write. Because all three are
optional, adding them to the schema does not disturb one existing entry.

### An unknown key drops the entry

`schema/safe-registry.schema.json` is `additionalProperties: false` and every key this helper
validates is declared in it, so the two move together and an entry naming anything else is
**dropped**, with the reason in `health.registry_errors`. There is no tolerated class of schema
error and no key that is waved through: `"acess": "user"` half-applied would be the permissive
half (I1).

There was briefly an accommodation for exactly `export_dir` and `breach_corpus` — the helper
validated them before the schema file listed them, and without it an operator who added one
lost the whole entry on a host whose schema file lagged. It is **gone**, along with the
`registry_drift` key `health` used to report it through. The remedy for a helper that gains a
field is to ship the schema file with it, which is what `install.sh` does.

### The per-user registry — the one trust-model change in 0.4.0

Root owns `/etc/cockpit-secrets/safes.d/`, so an unprivileged user cannot register a safe
there, so before 0.4.0 they could not have one at all without an administrator. The second
registry is what makes `safe-create` and `safe-import` usable by a normal user:

| | system registry | per-user registry |
|---|---|---|
| Path | `/etc/cockpit-secrets/safes.d/*.json` | `~/.config/cockpit-secrets/safes.d/*.json` |
| Directory | `0755 root:root` | `0700`, owned by that user |
| Files | `0644 root:root` | `0600`, owned by that user |
| Read when | always | **only when `euid != 0`** |
| Access class | as written; omitted ⇒ `admin` | **forced to `user`**, whatever the file says |
| Written by | hand, and `safe-create` / `safe-import` for an admin-class safe | hand, and `safe-create` / `safe-import` for a user-class safe |

Both are validated by the same `schema/safe-registry.schema.json`. Five rules, all enforced in
the helper, none of them optional:

1. **A root-mode helper does not open it.** Not to merge it, not to fall back to it, not to
   report on it. There is no code path in which a root process parses JSON out of a directory
   an unprivileged user can write. This is rule 1 because rules 2–5 are consolation prizes if
   it is ever broken.
2. **Every entry loaded from it is forced to `access: "user"`.** An entry declaring `"admin"`
   is not honoured, not silently corrected, and not partially applied: it is **dropped and
   logged** into `health.registry_errors[]`. A file the user can write must never be the file
   that names its own access class.
3. **Its `path` must satisfy exactly what `open_safe_fd` already enforces** — a regular file
   the calling user owns, `0600`, opened `O_NOFOLLOW` and `fstat`ed on the returned fd, with
   no group- or other-writable directory above it (I5). The entry naming a file grants
   nothing; the fd's `fstat` decides.
4. **The directory and its files must be owned by that user and not group- or other-writable,
   or the whole per-user registry is refused** — the same fail-closed rule as the system one.
   Refused means no entry from it loads, not "the bad ones are skipped".
5. **A system entry wins an id collision, and the shadowed per-user entry is reported as an
   error** in `health.registry_errors[]` with a distinct reason. Never silently preferred,
   never silently dropped: "the safe you opened is not the one you registered" has to be
   visible.

`health` reports the two registries separately under **`registry_sources`** — the system
registry's directory, entry count and errors, and the same for the per-user one. On the root
path the per-user half is reported as **`null` and says so**, rather than being omitted: "this
helper did not read one" and "there was nothing to read" are different answers, and rule 1 is
the reason for the first.

**The safety argument, which is the whole justification and is repeated in a comment beside
the loader.** Reading this file grants the user no access they did not already have. The
helper is running *as them*, unescalated, and rule 3 means it will only ever open a file they
own, `0600`, that they could have read with `cat` anyway. The registry does not confer a
capability — it tells a program the user is already driving which of their own files to open.
**It is a convenience surface, not a privilege surface.** That argument depends on rules 1–4
in their entirety; relax any one and it stops holding, which is why the comment says so at the
place a future change would be made.

One asymmetry falls out of rule 1 and is stated rather than hidden: a user creating a
user-class safe *can* read the system registry, so `safe-create` refuses a colliding id up
front with `conflict`. An administrator creating a system-class safe *cannot* read any
per-user registry, so it cannot check — that collision surfaces later, by rule 5, in the
affected user's own `health` output. An unreadable directory is worth more than a checkable
one.

There is **no host-wide switch to disable per-user registries** in 0.4.0. It cannot live in
the registry itself (a setting stored where the user can write it is not a setting); it would
need a root-owned policy file the unescalated helper reads and obeys, and that file does not
exist. Named here as a gap rather than described as a decision.

## Verbs

Forty-two verbs — the thirty-three below plus the eight registry-writing ones added in
0.4.0 (`safe-create`, the five `import-*` steps, `safe-forget`, `safe-delete`) and `keep-open`,
added with the I18 keep-open relaxation. `schema` publishes all of them with their request fields, response keys,
`danger`/`mutates`/`needs` flags and a `breaks_when_wrong` sentence each; the tables here are
the prose, and the schema is the machine-readable form the page builds from.

```
secrets-admin schema                  -> { version, helper_version, base_version, verbs[],
                                           groups[], fields[], enums{}, constants{},
                                           ui_rules[] }
secrets-admin list                    -> { safes:[{id,label,format,access,mode,locked,reason,
                                           usable,password_required,needs_keyfile,agent_enabled,
                                           agent_keep_open_allowed,
                                           agent_keep_open_known,
                                           export_allowed,registry,origin,manageable,path?}],
                                           registry_errors:int }
secrets-admin probe    <stdin:{safe}> -> { format, version, kdf, iterations, needs_password,
                                           needs_keyfile, writable, needs_challenge,
                                           challenge_b64, yubikey_slot, warnings:[] }
secrets-admin unlock   <stdin:{safe,password,keyfile_b64,yubikey_response,session,max_seconds}>
                                      -> { handle, expires_in, entries_total, groups_total,
                                           warnings:[], agent? }
secrets-admin open     <stdin: request frames, one JSON object per line>
                                      -> a banner frame, one reply per frame, a closing frame
secrets-admin tree     <stdin:{handle}>        -> { groups:[{uuid,name,parent,count}] }
secrets-admin entries  <stdin:{handle,group,query,offset,limit}>
                                      -> { total, entries:[{uuid,title,username,url,tags,
                                           has_totp,attachments,modified}] }   # NO passwords
secrets-admin reveal   <stdin:{handle,uuid,field}>
                                      -> { field, value, expires_in, resolved_field? }
secrets-admin totp     <stdin:{handle,uuid}>         -> { code, seconds_remaining }
secrets-admin attach-list <stdin:{handle,uuid}>      -> { uuid, total,
                                                          attachments:[{name,size}] }
secrets-admin attach-get  <stdin:{handle,uuid,name}> -> { name, size, b64 }
secrets-admin add      <stdin:{handle,group,entry,autosave,override_stale}>
                                                     -> { uuid, saved }
secrets-admin edit     <stdin:{handle,uuid,changes,autosave,override_stale}>
                                                     -> { uuid, changed:[...], saved }
secrets-admin move     <stdin:{handle,uuid,group,…}>      -> { ok:true, saved }
secrets-admin rm       <stdin:{handle,uuid,permanent,…}>  -> { ok:true, recycled, saved }
secrets-admin group-add / group-rm / group-mv             -> { ok:true, saved }
secrets-admin save     <stdin:{handle,override_stale}>
                                      -> { ok:true, backup, bytes, conflict:false }
secrets-admin lock     <stdin:{handle|safe}>
                                      -> { ok:true, locked, agent_dropped? }
secrets-admin keep-open <stdin:{safe,enabled,handle?}>
                                      -> { ok:true, keep_open, affected, changed,
                                           expires_in, idle_expires_in, max_seconds,
                                           idle_seconds, session, session_keep_open,
                                           session_expires_in, session_idle_expires_in,
                                           session_idle_seconds, session_max_seconds,
                                           warnings? }
                                         # session_* describe THIS session's idle
                                         # timer — the one that ends the operator's
                                         # work. session_expires_in is the deadline
                                         # the page adopts; it never computes one.
secrets-admin generate <stdin:{policy}>  -> { value, entropy_bits, calculation,
                                              alphabet_size }
secrets-admin health                     -> { version, base_version, schema_version,
                                              backends:{kdbx:…, psafe3:…}, registry_errors:[],
                                              registry_root, registry_entries,
                                              registry_gate:{…}, registry_sources:{…},
                                              import_staging:{…}, agent:{…},
                                              export:{…}, breach:{…}, library_root,
                                              library_root_trusted, identity:{…},
                                              hardening:{…}, state:{…}, policy:{…}, debug }
secrets-admin audit-tail --n N           -> { entries:[…] }        # metadata only, never values
```

Every mutating verb takes `autosave` and `override_stale`, and every handle-taking verb accepts
the credential fields instead of a handle for a single-shot invocation — that is what
`request` in the schema means by `auth` (`handle`, `safe`, `password`, `keyfile_b64`,
`yubikey_response`, `session`).

### Verbs added after the first build

These **extend** the table above; nothing above changed shape. `unlock` gained one optional
request field and one conditional response key, and `lock` gained an alternative way to name
what to lock. Everything else is new.

```
secrets-admin history   <stdin:{handle|safe+credentials, uuid}>
                        -> { uuid, total, versions:[{index,when,title,username,
                             url,has_password,notes_len}], truncated?, warning? }   # NO passwords
secrets-admin history-restore <stdin:{…, uuid, index, autosave}>
                        -> { uuid, restored_from, saved }
secrets-admin attach-add <stdin:{…, uuid, name, data_b64, replace, autosave}>
                        -> { ok:true, name, size, saved }
secrets-admin attach-rm  <stdin:{…, uuid, name, autosave}>  -> { ok:true, name, saved }
secrets-admin save-as    <stdin:{…, name, override_stale}>  -> { ok:true, path, bytes, name }
secrets-admin backups    <stdin:{safe}>
                        -> { safe, dir, keep, total, backups:[{name,when,size}] }
secrets-admin restore-backup <stdin:{safe, name, override_stale}>
                        -> { ok:true, restored, bytes, backup, created, undo, ring_full }
secrets-admin export     <stdin:{safe, credentials, fmt, confirm}>
                        -> { path, bytes, entries, fmt, name, mode:"0600", warning }
secrets-admin strength   <stdin:{value}>
                        -> { length, guessable_length, alphabet_size, entropy_bits,
                             effective_bits, penalty_bits, category,
                             weaknesses:[{id,label,cost_bits}], calculation, source, note }
secrets-admin breach-check <stdin:{safe, value|sha1_prefix}>
                        -> { available, found:bool|null, count, prefix5, method, reason?,
                             network:"none", offline_only:true }
```

Rules these verbs add to the ones already stated, each of which is a refusal
before it is a feature:

- **`export` is administrator-class, whatever the registry says.** It is
  refused for a user-class safe even when the caller owns the file, refused
  unless `export_allowed` is true, refused unless the request carries the exact
  token `export-plaintext:<safe id>` (compared with a constant-time equality),
  and refused for an `fmt` outside `csv|xml|json`. The destination is
  `export_dir` or the host default — **never a path from the request** — and
  the file name is `<safe id>-<UTC stamp>.<ext>`, minted helper-side. The file
  is 0600 in a 0700 directory. The **content is not in the response**: the
  response names the file, its size and its row count, and those are what the
  audit line records (I21).
- **`save-as` and `restore-backup` take a NAME, never a path.** `save-as`
  refuses `/`, `\`, NUL, a leading `.`, `..`, and any existing target;
  `restore-backup`'s name must be a member of the listing `backups` returned,
  which is a membership test, not a sanitising step — there is nothing to
  escape from a set (I4).
- **`strength` and `breach-check` never echo the candidate.** `strength`
  returns no `value` key and no weakness quotes the text that triggered it;
  `breach-check` echoes at most five hex characters of the SHA-1, because the
  full digest of a password is offline-crackable. **`breach-check` has no
  network client**: every response carries `network:"none"` and
  `offline_only:true`, including the unavailable one.
- **`history` is ordered OLDEST FIRST and `index` counts forwards through
  time.** `index: 0` is the oldest recorded version; the highest index is the
  most recently archived one. `history-restore` is addressed by that index, so
  a UI that re-sorts must carry the row's `index` rather than recompute it from
  its own display order.
- **`history` never carries a password.** There is deliberately no
  `history-reveal`: reading an archived password is `history-restore` then
  `reveal`, which is two auditable acts and leaves a trace in the database
  itself, rather than one invisible one that would let a single unlock
  enumerate every password an entry has ever held.
- **`attach-add` takes base64 on the wire and the backend takes bytes.** The
  ceiling that actually bites is `MAX_REQUEST_BYTES` (1 MiB for the whole JSON
  object), not `MAX_ATTACHMENT_BYTES` (32 MiB) — base64 costs a third, so
  roughly 760 KiB of attachment fits. Both are checked; the schema's help text
  names both.

### `attach-list` — names in, bytes out

`entries` reports `attachments` as a **count**, on purpose: a listing must be able to show
that an entry HAS attachments without shipping them. A count is not addressable, though, and
`attach-get` is addressed by **name** — so until this verb existed a file could be uploaded
through `attach-add` and never fetched again, because nothing ever told the page what it was
called. `attach-list` is the missing half, and it is deliberately narrow:

```
attach-list <stdin:{handle|safe+credentials, uuid}>
    -> { uuid, total, attachments: [{name, size}] }
```

- **No bytes, ever.** It is not in the helper's `VALUE_BEARING_VERBS`, so the response goes
  through the same scrubber every listing does — a backend that returned a `b64` key here
  would lose it and be reported on stderr.
- **`size` is the declared length and is reported even when it exceeds
  `MAX_ATTACHMENT_BYTES`.** "There is a 40 MiB file here that this transport will not carry"
  is a more useful answer than an invisible row; `attach-get` is where the cap refuses.
- **An entry with no attachments answers `[]`; an unknown uuid answers `not-found`.** An empty
  list is a statement about the entry, not about the request.
- **The two formats differ in what the list can hold, not in the shape of it.** KDBX4 gives an
  entry any number of binaries. **Password Safe v3 gives a record at most one** — a record is a
  list of typed fields and a type appears at most once, so there is nowhere to put a second Att
  Content (§3.3 note [30], fields 0x25..0x29, introduced in format 0x030F / PasswordSafe
  V3.68). PWS3 therefore answers a list that is empty or one row long, always. A database
  declaring an older format version simply has no such fields and lists nothing; it is
  `attach-add` that refuses, naming the version, because a version is a reason not to WRITE and
  not a reason to misreport what the file already contains.

## The verbs that WRITE the registry — `safe-create`, `import-*`, `safe-forget`, `safe-delete`

Everything above this line reads the registry. These eight write it — `safe-create`, the five
`import-*` steps, `safe-forget` and `safe-delete` — and that is a different
kind of verb: **the registry is this program's trust root.** It says which files are safes,
where they live, and what access class each one has; every other control — the class gate, the
`fstat` ownership check, the backup ring, the export gate — is downstream of an entry these
verbs now produce. Letting a browser request reach it is the most dangerous change in the
project, and the shapes below are the reason it is survivable rather than a footnote to it.

Three constraints run through all of them and are not negotiable per-verb:

- **C1 · The path is minted by the helper, never supplied by the caller.** The caller sends an
  `id`. The helper derives the file name from that id and the managed directory for that
  access class. **There is no request field in any of these verbs that is a path, a file name,
  a directory, or a component of one** (I4) — which is also why `validate.sh`'s I4 ban, which
  scans the live `schema` verb for a request field named `path`/`dir`/`dest`/`filename`/…,
  keeps passing after this change.

  | access class | managed safe directory | minted safe path | minted registry entry |
  |---|---|---|---|
  | `admin` | `/etc/cockpit-secrets/safes/` `0700 root:root` | `<dir>/<id>.<ext>` `0600 root:root` | `/etc/cockpit-secrets/safes.d/50-<id>.json` `0644 root:root` |
  | `user` | `~/.local/share/cockpit-secrets/safes/` `0700 <user>` | `<dir>/<id>.<ext>` `0600 <user>` | `~/.config/cockpit-secrets/safes.d/50-<id>.json` `0600 <user>` |

  `<ext>` is `kdbx` or `psafe3`, chosen from the `format` enum — not from the request's text.
  The `50-` prefix leaves room below it for the hand-written entries operators already have
  and keeps the load order visible.

- **C2 · The id is checked against a hard allow-list before it reaches any filesystem call.**
  `^[a-z0-9][a-z0-9-]{1,62}$`, published as `constants.new_id_pattern`. Lower case, digits,
  hyphen; no dot, no slash, no NUL, no leading hyphen, no Unicode, minimum two characters.
  Anything else is `invalid` **before** a path is built from it. An id already present in the
  registry, or whose minted path or minted entry file already exists on disk, is `conflict`.
  **Neither is ever overwritten.**

  This is deliberately stricter than the registry schema's own `id` pattern, which still
  accepts `.` and `_` because entries written by hand before 0.4.0 use them. Tightening the
  schema would drop those entries — silently deleting a working safe from an operator's list
  on upgrade. So: the loose pattern is what the loader will *read*, the strict one is what
  these verbs will *mint*.

- **C3 · Admin is still the default.** A create or import with no `access` makes an
  **admin-class** safe and needs the admin gate exactly like every other admin verb: `euid ==
  0` and the real caller in an admin group (I1, I3). Two refusals fall straight out of the
  per-user registry's rule 1:
  - `access: "admin"` with `euid != 0` → `access-denied`.
  - `access: "user"` with `euid == 0` → `invalid`, detail "call this without escalation". A
    root helper must not write into a user's home directory, and it must not open the per-user
    registry to check what is already there. An administrator who wants a user-class entry in
    the *system* registry still writes it by hand, as before.

#### The request fields these verbs add

`schema.fields[]` gains thirteen entries. **Not one of them is a path, a file name, a directory
or a component of one** — check that against `validate.sh`'s I4 ban, which reads the live
schema and fails on a request field called `path`, `dir`, `dest`, `destination`,
`target_path`, `filename` or `file`. Two existing fields are reused unchanged (`keyfile_b64`, `safe`).

**`new_password` is a separate field from `password`, and that is not cosmetic.** `password`
means "the credential that opens a REGISTERED safe", and three promises are attached to that
meaning: the I16 lockout counts it, the per-safe rate cap bounds it, and a failure against it
waits out `Limits.FAIL_FLOOR_SECONDS`. None of the three applies to a passphrase being SET on a
safe that does not exist yet, or tried against a file the caller uploaded and still holds — so
calling it `password` would attach three guarantees this code does not keep.
`tests/integration/lockout.py` builds its list of credential-bearing verbs by asking the schema
which verbs declare `password`; that list stays true because these verbs honestly do not.

**`delete_confirm` is a separate field from `export`'s `confirm` for the same kind of reason,**
and getting that wrong was a real defect (I49): the verb read `confirm` while the schema
published `delete_confirm`, so through the published interface `safe-delete` could never
succeed and it destroyed on a field nobody had been told about.
`tests/ban_undeclared_fields.py` is now a standing gate: it walks the helper's AST, builds a
call graph, and refuses any verb that can reach a `req.get("x")` its own published request does
not declare.

| field | type / control | secret | used by |
|---|---|---|---|
| `id` | string / text | no | all four groups. The registry id — **not** a file name |
| `label` | string / text | no | `safe-create`, `import-begin` |
| `access` | string / select (`access` enum) | no | `safe-create`, `import-begin`. Omitted ⇒ `admin` |
| `mode` | string / select (`mode` enum) | no | `safe-create`, `import-begin`. Omitted ⇒ `rw` |
| `format` | string / select (`format` enum) | no | `safe-create`; `import-commit`, where it must equal what inspect reported |
| `total_bytes` | integer / number | no | `import-begin` |
| `sha256` | string / text | no | `import-begin`. 64 lower-case hex characters |
| `staging` | string / hidden | no | every `import-*` after `begin`. Opaque, uid-bound, **never a location** |
| `chunk_offset` | integer / number | no | `import-chunk`. The absolute byte offset of this chunk, which must equal the `received` the previous reply reported |
| `chunk_b64` | string / file-bytes | **no** | `import-chunk`. Base64 of one chunk of the ENCRYPTED database. Deliberately not `secret`: the uploader holds the file |
| `kdf` | object | no | `safe-create`. One sub-object, not three flat fields: `{memory_kib, time, parallelism}` for KDBX and `{iterations}` for PWS3, each optional and bounded on both sides |
| `make_keyfile` | bool / toggle | no | `safe-create`. Generate a key file as a SECOND factor; it is returned once and stored nowhere |
| `new_password` | string / password | **yes** | `safe-create`, `import-commit`. A SEPARATE field from `password` on purpose — see below |
| `delete_confirm` | string / text | no | `safe-delete`. `delete-safe:<id>`, compared in constant time |

`staging` is declared `secret: false` on purpose, and the reasoning is the same as `handle`'s
being `secret: true` is: a handle can be presented to read a decrypted value, so it is treated
as key-adjacent, while a staging token names an encrypted blob the presenter already uploaded.
It is still uid-bound, still never persisted in the browser (rule 2 applies to the whole page,
not only to fields flagged secret), and still answers `access-denied` — not `not-found` — to
anyone else.

### `safe-create` — a new, empty safe

```
secrets-admin safe-create <stdin:{id, label, format, access, new_password,
                                  keyfile_b64, make_keyfile, kdf}>
    -> { ok:true, safe:{…exactly as `list` reports it…}, registry:"system"|"user",
         bytes, format, kdf:{…}, strength:{entropy_bits, effective_bits, category,
         weaknesses:[…]}, keyfile_b64 (ONLY when make_keyfile),
         keyfile_warning (same condition) }
```

- `format` is required and is one of the `format` enum. A created KDBX is **KDBX 4.1** with
  AES-256 and Argon2id at 64 MiB / t=8 / p=2; a created PWS3 is written at
  `Limits.PWS3_WRITE_MIN_ITER`. It is **never** KDBX 3.x — that format has no authenticated
  encryption (I20) and this program does not create one.
- The KDF costs — `kdf: {memory_kib, time, parallelism}` for KDBX, `kdf: {iterations}` for
  PWS3 — are the only tuning a request may carry, they are optional, and they are **bounded on
  both sides**. The floors are `Limits`' OWN Argon2 write floors (OWASP's m=19 MiB, t=2, p=1)
  and the PWS3 write floor (262 144), and the ceilings are the `Limits` clamps re-checked by
  `Limits.check_argon2(..., for_write=True)` before the derivation (I7). The floor the schema
  PUBLISHES as `min` is the floor the backend ENFORCES — they were once independent, and a
  published bound that is not the enforced bound is worse than none. They are integers, not paths, so C1 is untouched; the cipher, the KDF
  algorithm and the PWS3 iteration count are **not** settable at all. There is no request
  that mints a deliberately weak safe.
- **The credential arrives on stdin like every other credential** (I10): `new_password`, and
  `keyfile_b64` for a KDBX key file (or `make_keyfile: true` to have one generated, returned
  ONCE and stored nowhere). Creating with an **empty passphrase and no key file is
  refused** (`invalid`) — that is not a configuration, it is an unlocked file.
  `keyfile_b64` on a `psafe3` create is `unsupported`, naming the format's limit.
- **The passphrase's strength is reported and never enforced.** `strength` runs on the chosen
  passphrase and its verdict rides in the response so the page can say "this is weak". It does
  not refuse. Choosing a passphrase is the operator's decision; telling them what they chose
  is ours.
- `mode` is optional and defaults to `"rw"`. `yubikey_slot`, `groups`, `agent`,
  `export_allowed`, `keyfile` (the registry's helper-side path, as distinct from the
  `keyfile_b64` used to create) and `breach_corpus` are **not** settable here — they are
  edited into the entry afterwards, by hand or by root. A verb that could set `groups` would
  be a verb that widens who may open a safe.
- Order of operations, and it is the order that matters:
  1. validate `id` (C2), resolve the access class and run its gate (C3);
  2. refuse a colliding id, minted path, or minted entry file (`conflict`);
  3. build the database in memory and write it to the minted path through the ordinary atomic
     path — temp file in the same directory, `O_EXCL`, `0600`, `fsync`, `os.replace`,
     `fsync(dir)` (I12);
  4. **re-open the file that landed, through the same reader a later unlock will use, with the
     same credential** (I24/I41). If it does not open, `unlink` it and answer `internal` — a
     safe nobody can unlock must not become a registry entry;
  5. validate the entry against `schema/safe-registry.schema.json` and only then write it
     atomically (C6 below).

  Nothing is registered until step 5, so every failure before it leaves the host exactly as it
  was. If step 4 fails *and* the `unlink` also fails, the response is still an error and the
  orphaned file is named in the `detail` — an unreferenced file is harmless, an unreported one
  is not.

### `safe-import` — adopt an existing safe, encrypted bytes first

**Five ordinary verbs, not a session.** One request in, one JSON object out, `cockpit.spawn`
per step, exactly like everything else. A safe is up to 128 MiB and one request is capped at
1 MiB, so an upload is necessarily chunked, and the chunks are reassembled in a **staging
directory that outlives the helper process** — which is what makes the steps separate verbs
rather than frames in one held-open channel, and what makes the idle timer, the sweep and the
per-caller staging limit meaningful rather than decorative.

```
secrets-admin import-begin   <stdin:{id, label, format, access, total_bytes, sha256}>
    -> { ok:true, staging, chunk_bytes, total_bytes, received:0, expires_in, next }

secrets-admin import-chunk   <stdin:{staging, chunk_offset, chunk_b64}>
    -> { ok:true, received, total_bytes, remaining, complete, next }

secrets-admin import-inspect <stdin:{staging}>
    -> { ok:true, staging, id, label, access, bytes, sha256_ok:true,
         authenticated:false, format, version, cipher, kdf, kdf_params:{…},
         iterations, compressed (kdbx only), needs_password, needs_keyfile,
         warnings:[], note, next }

secrets-admin import-commit  <stdin:{staging, new_password, keyfile_b64}>
    -> { ok:true, safe:{…as `list` reports it…}, registry, bytes, format,
         entries_total, groups_total, warnings:[] }

secrets-admin import-abort   <stdin:{staging}>
    -> { ok:true, dropped, id, discarded_bytes }
```

#### The `staging` token

`import-begin` mints it and every later step is addressed by it. It is an opaque
128-bit random token — `secrets.token_urlsafe(16)`, the same minting as a `handle` — **bound
to `(real uid, id, access class)`**, and it is the only thing that ties five separate
invocations into one upload. Rules it keeps, and they are the handle's rules for the handle's
reasons:

- **Presenting a staging token you do not own is `access-denied`, not `not-found`** —
  distinguishing them would turn these verbs into an oracle for which uploads exist.
- **It is not a credential and it opens nothing.** It names an encrypted blob and a declared
  id. Everything it can do still runs the access gate from kernel identity on every verb.
- **It is never a path.** The staging directory's name is derived from it helper-side; the
  token itself never reaches the response as a location, and no request field carries one (C1).
- One caller may hold `constants.import_max_stagings` (8) at once; the ninth `begin` is
  `conflict` naming the limit.

One honesty note, the same one the agent's `SO_PEERCRED` carries: **for the admin class the
helper runs as root, so the staging root cannot tell two administrators apart.** An
admin-class staging is visible to any administrator who can list `/var/lib/cockpit-secrets/
state/import/`. It contains an encrypted safe file that its uploader already possessed, and
root is out of scope in THREAT-MODEL.md — but "only the operator who started it can see it" is
a claim this design does **not** make for the admin class.

#### The ordering is a requirement, not a preference: bytes first, credential last

**No credential travels before `import-commit`.** Not in `begin`, not in any `chunk`,
not in `inspect`. `new_password` and `keyfile_b64` are legal fields on `import-commit` and on
no other verb in this group; sending either earlier is **`invalid`, naming the field** — not
tolerated-and-ignored.

That refusal is enforced in the DISPATCHER, not in the three verbs, and the difference matters
(I50). It was once true only that those verbs never READ a credential, which is not the same
as refusing one: they accepted `password`, `new_password`, `keyfile_b64` and `passphrase` and
answered `ok`, so the whole guarantee lived in `secrets.js` where any other client — or a
reordering of the page's steps — could undo it. `run_verb` now refuses a credential-bearing key
that the verb's OWN declared request does not list, so a verb written next year gets the
refusal without anybody adding a line.

Two reasons the ordering is fixed here rather than left to the page:

- **A large upload takes visible time.** Collecting the passphrase in the file-picker step
  means holding it in browser memory for the whole transfer — exactly the window I11 and I14
  exist to shrink. Prompting after the bytes are staged means it exists for one request.
- **The header of a KDBX or PWS3 file is not secret.** Format, version, cipher, KDF and its
  parameters are readable from the bytes by anyone who holds the file, and the person
  uploading it holds the file. So `import-inspect` can report all of it with **no credential
  at all**, and the operator confirms they uploaded the file they meant to *before* they type
  anything. The page must label that summary as what it is: **read from an unauthenticated
  header** — the response says `authenticated: false` for exactly this reason, and on a
  tampered file the summary is what the tamperer wrote.

#### Step by step

**`import-begin`** — declares `id`, `label`, `access` (omitted ⇒ `admin`, C3), optional
`mode`, `total_bytes` and `sha256` (lower-case hex, 64 characters, of the **whole** file). No
credential. It:

- validates the id (C2) and runs the access gate (C3);
- refuses a colliding id / minted path / minted entry file with `conflict`;
- **refuses a `total_bytes` over `Limits.MAX_SAFE_BYTES` (128 MiB) before a single byte
  arrives** — a declared size is checkable for free and there is no reason to receive 4 GiB
  before saying no;
- creates the staging directory: `<staging root>/<32 hex characters>/`, `mkdir` `0700`
  (atomic, `EEXIST` is a refusal), containing one file opened
  `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW`, `0600`. **Never the final path. Never `/tmp`.**

  | access class | staging root |
  |---|---|
  | `admin` | `/var/lib/cockpit-secrets/state/import/` `0700 root:root` |
  | `user` | `~/.local/state/cockpit-secrets/state/import/` `0700 <user>` |

  Staging is deliberately *not* required to share a filesystem with the managed safe
  directory: commit copies the staged bytes through the ordinary temp-file-in-the-target-
  directory path (I12), so `os.replace` is always intra-filesystem and this never depends on
  how the host is partitioned.

It mints and returns the `staging` token. There is no way to add a second file to a staging:
one staging is one safe.

**`import-chunk`** — `staging`, `offset` (decoded byte offset, which must equal the bytes
received so far) and `data_b64`. No credential. The cap is enforced **incrementally, as each chunk arrives, never
after**: a chunk that would take the total past the declared `total_bytes`, or past
`MAX_SAFE_BYTES`, is refused and the chunk is not written. The reply's `chunk_bytes` is 512 KiB
decoded, published in `constants.import_chunk_bytes`; the ceiling that actually bites is
`MAX_REQUEST_BYTES` (1 MiB for the whole JSON frame) and base64 costs a third, so 512 KiB
leaves headroom for the framing. An out-of-order `offset` is `invalid` and changes nothing —
this is a stream, not a random-access file. Every accepted chunk resets the staging's idle
clock, which is what "measured from its last use" means.

**`import-inspect`** — `staging`, and nothing else. No credential. In order:

1. the received length must equal the declared `total_bytes`;
2. the SHA-256 of the reassembled file must equal the declared `sha256`, compared with
   `hmac.compare_digest`;
3. the first bytes must match **exactly one of the two signatures this program knows** — KDBX
   `0x9AA2D903` or PWS3 `"PWS3"`. This is a two-way exact discriminator over known constants,
   not format guessing: bytes that are neither are refused here and no parser sees them;
4. the unauthenticated header is parsed, and only the header;
5. **the `Limits` KDF clamps are applied to the DECLARED parameters now** — `check_argon2`,
   `check_aeskdf_rounds`, `check_pws3_iter` — so a KDF bomb is refused before anyone is asked
   for a passphrase they would then wait minutes for (I7).

Any of those failing refuses the import **and destroys the staging**, because the bytes have
been shown not to be a safe of a format we support and there is nothing to retry against.
`import-inspect` is otherwise idempotent and may be repeated.

**`import-commit`** — **the credential arrives here, on stdin, for the first time.**
`staging`; `format`, the format the operator confirmed, which must equal what
`import-inspect` reported (else `invalid`); and `password` / `keyfile_b64`, the
credential. It:

1. re-runs the access gate — the class is re-checked on **this** verb, from kernel identity,
   exactly as on every other verb, and never taken from what `begin` recorded;
2. **parses the staged file with the real backend and requires the credential to open it.**
   This is what stops the verb being an arbitrary-write primitive: **the only bytes that can
   ever land are bytes that are demonstrably a safe the uploader can already open.** A file
   that does not open does not land;
3. copies the staged bytes into the minted path through the ordinary atomic write (I12);
4. re-opens the file that landed, with the same credential, through the same reader a later
   unlock will use (I24/I41) — if it does not open, `unlink` and refuse;
5. validates and atomically writes the registry entry, with `origin: "imported"`,
   `created_utc`, and the `source` block recording what step 4 of `import-inspect` read;
6. destroys the staging.

`id`, `label` and `access` are fixed by `import-begin` and **cannot be changed by
`import-commit`** — a commit that could restate the access class would be a way to upload
as a user and register as an administrator. They are not request fields on `commit` at all,
which is stronger than validating them there.

**A wrong passphrase at commit does NOT destroy the staging.** Re-uploading 100 MiB because of
a typo is a bug, not a security control: the verb answers `bad-credential`, the staged bytes
stay, and the `detail` names how many attempts are left (a count is not a secret). The budget
is `constants.import_max_attempts` (5) failed attempts **per staging**, after which the
staging is destroyed and the token answers `invalid` naming the exhausted budget.

> **Why that budget exists, written down so nobody mistakes it for something else.**
> Rate-limiting this guess is **theatre**. The person who uploaded the file *has* the file;
> they can guess against their own copy, offline, on their own hardware, as fast as they like,
> and nothing this host does changes that. What is **not** theatre is that every attempt costs
> *this machine* one full KDF derivation at parameters the uploaded file chose. So the attempt
> budget and the idle expiry are **resource controls on this host, not credential controls on
> that file**, and the code says so at the counter.
>
> The I16 unlock lockout is deliberately **not** wired in here, and this is the distinction
> I16 would otherwise blur. I16 counts failures per `(real uid, registry safe id)` against a
> safe that *exists*; during an import the id is not in the registry yet, so consulting it
> would (a) let anyone poison the lockout counter of an id a real safe later takes, and (b)
> hand the operator a resource control wearing the vocabulary of a credential control.
> **`import-commit` therefore never returns `locked-out`.** Exhausting the budget is
> `invalid`, and the detail says "attempt budget", not "locked out".

**`import-abort`** — `staging`, and it destroys it. It is the explicit half of something
that also happens on its own: **staging is destroyed on every failure path, on a successful
commit, and on the idle timer** (`constants.import_idle_seconds`, 900 s, measured from its
**last use** and not from the begin).

Because staging outlives the helper process, **a dropped Cockpit channel does not clean it
up** — say that plainly rather than implying the process model does the work here as it does
everywhere else. Closing the tab mid-upload leaves an encrypted blob on disk until the idle
timer reaps it. The page should call `import-abort` when the operator cancels; the timer
is what covers the case where it cannot.

So **stale staging is swept**: on **every verb of any kind**, because the sweep lives in
`init_state` rather than in the import verbs — a `health` or a `list` cleans up too. It is
reported by **`health.import_staging`** —
`{dir, staged, idle_seconds, chunk_bytes, max_bytes, max_attempts, max_concurrent, reason}` —
so an operator can answer "is anything staged, and what are the limits" with no credential.
It reports a **count and never a token**: a staging token plus the right uid is what
`import-commit` needs, so `health` is a diagnostic and not a place to hand them out.

The sweep removes only entries under the staging root, only names matching the 32-hex token
shape, only entries that are **actually directories** — a symlink wearing a token's name is
skipped rather than followed, and its two files are unlinked through a descriptor on the
directory rather than by path, so nothing outside the root is reachable even by name (I53) —
and only ones unused for longer than `constants.import_idle_seconds` (900 s).

Two bounds, and they count different things. `constants.import_max_stagings` (8) is how many
stagings one caller may **hold**. `constants.import_max_concurrent` (2) is how many
`import-inspect` / `import-commit` calls may be **running** at once, per identity, taken as a
non-blocking `flock` on a slot file inside the staging root. Nothing counted the second until
0.4.0, and 32 simultaneous inspects of one 128 MiB staging measured 7.6 GiB resident across 32
root-capable processes (I54). The (N+1)th caller is refused with `conflict` rather than queued:
queueing would hold a Cockpit channel open for the duration and turn a memory problem into a
channel-exhaustion problem.

Staged bytes are an **encrypted** safe file, so an orphan is a disk-space problem rather
than a disclosure — but a disk-space problem that nothing cleans up is how a host fills.

### `safe-forget` and `safe-delete` — because creating without removing is a trap

```
secrets-admin safe-forget <stdin:{safe}>
    -> { ok:true, forgotten:<id>, registry, file_kept:true, warning }

secrets-admin safe-delete <stdin:{safe, delete_confirm}>
    -> { ok:true, deleted:<id>, registry, file_removed, file_missing, bytes,
         backups_removed, overwritten, warning }
```

**`safe-forget` removes the registry entry and leaves the file exactly where it is.** It is
the default and the safe one: the safe stops being something this page can open, and not one
byte of anybody's credentials is destroyed. The response names the `path` that has been left
behind, because "we forgot it" is only a useful answer if you are told where it went.

**`safe-delete` forgets it *and* destroys the file and its whole backup ring.** It is the only
verb in this program that deliberately destroys credentials, so:

- it requires the exact confirmation token **`delete-safe:<id>`**
  (`constants.delete_confirm_prefix`), compared with `hmac.compare_digest`. The token names
  the safe, so a confirmation an operator gave for a throwaway cannot be replayed against the
  domain-administrator one — the same idiom as `export`'s `export-plaintext:<id>`;
- it is **admin-only for an admin-class safe**, like every admin verb;
- it is **audited by id, never by path**, and the audit line records the number of backup
  generations destroyed;
- it **refuses unless the entry's `path` is exactly the path this program would mint for that
  id and access class today.** This is the derived gate, and it is what confines destruction
  to files this program created. A hand-registered safe at `/srv/keys/prod.kdbx` — or a
  per-user entry pointing at something in the operator's own tree that is not a safe at all —
  answers `access-denied` naming the rule, and the operator forgets it and removes the file
  themselves. `origin` corroborates; it does not authorise (C1 again: we only destroy what we
  minted).

Both verbs act on **one registry**, chosen by where the entry actually lives, and the same
rules that govern reading it govern removing from it:

| entry lives in | `safe-forget` / `safe-delete` runs | who may |
|---|---|---|
| system registry, `access: "admin"` | escalated, `euid == 0` | the admin gate, as always |
| system registry, `access: "user"` | escalated, `euid == 0` | **admin only** — the entry file is `0644 root:root` and an unescalated helper cannot write it, whatever class the entry declares |
| per-user registry | unescalated, as that user | that user |

A system user-class entry is therefore forgettable by an administrator and **not
`safe-delete`-able by anyone**: its `path` is in a directory the user controls, so it fails
the derived gate above, and asking a root process to `unlink` a path inside a user-writable
directory is the I5 hazard with a friendly button on it. Forget it and let the user remove
their own file.

### What `list` now reports, and the errors these verbs can return

`list`'s rows gain three keys so the page can draw the right controls without inventing policy:

| key | meaning |
|---|---|
| `registry` | `"system"` or `"user"` — which registry this entry came from |
| `origin` | `"manual"` \| `"created"` \| `"imported"`, straight from the entry |
| `manageable` | whether **this caller** could `safe-forget` this entry. It is decoration in the usual way (I3): the helper is what refuses, and it re-derives the answer on the verb |

#### The full row, and `path` — the key R5 needs

The complete shape of one row, which is what the block at the top of "Verbs" now prints:

| key | type | meaning |
|---|---|---|
| `id` | string | the registry id. The ONLY thing a caller may send back (I4) |
| `label` | string | the operator's name for it |
| `format` | `"kdbx"` \| `"psafe3"` | |
| `access` | `"admin"` \| `"user"` | the class the helper enforces on every verb (I3) |
| `mode` | `"rw"` \| `"ro"` | registry read-only, which is one of the three distinct causes of "not writable" |
| `locked` | bool | **false only while this uid holds a live handle inside this process.** Outside an `open` session it is therefore always true, and that is the guarantee, not a wart |
| `reason` | string | why the row is not usable. `gate()`'s sentence, or the backend-availability one. Never a path, never a traceback |
| `usable` | bool | whether this caller could unlock it right now. **Two causes of false** — see `path` below |
| `password_required` | bool | from the entry; false for a key-file-only safe |
| `needs_keyfile` | bool | the entry names a `keyfile` **or** a `yubikey_slot` |
| `agent_enabled` | bool | the per-safe agent opt-in (I18) |
| `agent_keep_open_allowed` | bool | whether the keep-open toggle may be drawn for this safe. **The DAEMON's answer**, fetched by one `policy` call per access class — not a second read of `agent.allow_keep_open` by the helper, which is how the page and the gate came to disagree |
| `agent_keep_open_known` | bool | whether that answer came from the daemon at all. `false` means nothing could be asked, and `agent_keep_open_allowed` is then `false` because keep-open cannot work without a daemon — a different problem from "your registry says no", with a different fix |
| `export_allowed` | bool | whether `export` is permitted for this safe at all |
| `registry` · `origin` · `manageable` | | as the table above |
| `path` | string, **absent only when unresolvable** | where the file lives |

`registry_errors` is a top-level **count** beside `safes`, never the reasons: `health` is the verb
that carries those, and a reason names a file.

**`path` is published on every row.** R5 (docs/DESIGN.md §5.6) makes the path a selectable column
that is OFF by default and a section of the details pane that is always drawn in full, and neither
could ever render while the helper did not send one (§18.1). Four rules govern it, and the helper's
`v_list` docstring is the long form of all four:

1. **It is resolved, never recomputed.** The string is `resolve_entry(entry, ident)["path"]` — the
   same function `unlock`, `probe`, `save` and `safe-forget` resolve through — so the path the
   page shows is the path the helper would open, with `%u` expanded from the kernel identity and
   never from the request (I4). There is no second source of truth for it. The **one** case with
   no answer is a `%u` entry seen from a root helper, which has no login name to substitute; that
   row omits the key rather than publishing a path containing a literal `%u`. Absent, not `null`:
   a key that is not there cannot be read as a path this program failed to find.
2. **It is NOT behind `gate()`, and that was measured rather than assumed.** §18.1 prescribed
   "gated on access class"; built that way, it makes R5 unreachable for exactly the safe R5 asks
   to show. `secrets.js` spawns `list` with **no superuser option, always** (the matrix at
   `secrets.js:3190` — `list` names what exists, and whether a safe may be OPENED is decided per
   verb), so the euid asking is never root and the class gate refuses every admin-class row at
   both access levels. Driven live with administrative access ON, the pane for the system safe
   still drew no Path section. The reasoning that replaces it is a property of the **loader**:
   `list` runs at the caller's own euid, a registry file that euid cannot open is recorded as a
   registry error and never becomes a row (measured: `chmod 000` over an entry drops it to
   `unreadable (EACCES)` and its id leaves `list`), the system registry is 0755/0644 root-owned
   policy, and the per-user registry is only ever read out of the caller's own home. Every row
   therefore came from a file the caller could already read, and `path` is a field of that file.
3. **`usable: false` is not a reason to withhold it** — though its two causes are still worth
   separating: the class gate refused, or the FORMAT's backend is unavailable on this host. A
   `mode: "ro"` safe gets its path, because read-only is a statement about writes. A safe whose
   **file has vanished** gets its path, because that is the case R5 exists for; nothing in this
   verb stats a file, so it is also not an existence oracle. A per-user entry **shadowed** by a
   system id is not a row at all — the loader drops it and records a registry error (C4 rule 5) —
   so the path shown is the system entry's, which is the file that would actually be opened.
4. **It never reaches the audit log or an error string.** A path names a home directory and
   therefore an account, and it names this host's filesystem layout; that is why the column is off
   by default and why the full path lives in a pane the operator opens deliberately. I15 keeps it
   out of the audit line, whose keys `audit()` asserts against a fixed set on every write, and
   `reason` above carries only sentences that interpolate no path.

| verb | can return |
|---|---|
| `safe-create` | `invalid` (bad id, empty credential with no key file, `access:"user"` while escalated, unknown `format`), `access-denied` (admin gate; managed directory not owned/moded as required), `conflict` (id, minted path or minted entry already exists), `unsupported` (`keyfile_b64` on `psafe3`), `internal` (the created file did not read back — nothing was registered) |
| `import-*` | `invalid` (bad id, credential sent before commit, declared size over `MAX_SAFE_BYTES`, a bad `chunk_offset`, sha-256 mismatch, unknown signature, KDF over the clamps, attempt budget exhausted), `access-denied` (admin gate, **or a staging token belonging to another uid**), `not-found` (a staging token that never existed or has expired), `conflict` (id / minted path / minted entry exists; or more than `import_max_stagings` open), `bad-credential` (commit only: the staged file did not open — staging kept), `unsupported` (a format the backend cannot open for writing), `internal` |
| `safe-forget` | `not-found` (no such id in a registry this caller reads), `access-denied` (wrong class, or a system entry from an unescalated helper), `internal` |
| `safe-delete` | everything `safe-forget` can, plus `invalid` (missing or malformed `delete_confirm`), `conflict` (two registry files declare that id — I51), `access-denied` (the token did not match, **or the derived path gate refused**) |

`safe-create`, `import-commit`, `safe-forget` and `safe-delete` are all
`mutates: true`, `danger: true`, and audited by id and outcome — never by path, never by value
(I15). None of them ever returns `locked-out`.

### C6 · Registry writes are atomic and validated before they land

Every entry these verbs write is serialized, **validated against
`schema/safe-registry.schema.json` before it touches the filesystem**, and then written
`0644 root:root` (system) or `0600 <user>` (per-user) by temp file + `fsync` + `os.replace` +
directory `fsync` — the same `atomic_replace` primitive as every other write in this program
(I12, I13, non-negotiable 6).

A half-written registry entry is **dropped by the loader**, which is correct and fail-closed,
and also *silent*: the operator's safe simply is not in the list. So the rule is not "the
loader copes"; the rule is **never produce one**.

## The `entry` and `changes` objects

`add` takes a whole `entry`; `edit` takes a partial `changes` and returns the field NAMES it
changed, never the values. Both are described by the same nine sub-fields in the schema, and
**all nine are honoured by both backends or refused with the format's own reason** — a name a
schema-driven form can send and the backend then calls "unknown" is a control that can only
ever fail.

| sub-field | type | KDBX | Password Safe v3 |
|---|---|---|---|
| `title` | string | Title | Title (0x03) |
| `username` | string | UserName | Username (0x04) |
| `password` | string, **secret** | Password | Password (0x06), old value pushed to History (0x0f) |
| `url` | string | URL | URL (0x0d) |
| `notes` | string | Notes | Notes (0x05) |
| `tags` | array of strings | Tags | **`unsupported`** — §3.3 lists no tag field |
| `totp_uri` | `otpauth://` URI, **secret** | the `otp` string field | parsed into Two Factor Key (0x1b) + TOTP Length/Time Step |
| `expires` | ISO-8601 UTC, or null for never | ExpiryTime **and** the Expires flag | Password Expiry Time (0x0a); null deletes it |
| `custom` | object, **secret** | named string fields | **`unsupported`** — no name-keyed field space |

Three of those are worth stating rather than leaving in a table:

- **`totp_uri` is a URI on the wire and a SEED in the file.** PWS3 stores the raw seed, not
  base32 and not the URI, so the URI is taken apart helper-side; storing the text verbatim
  would produce an entry whose codes are always wrong. `otpauth://hotp` and an `algorithm`
  other than SHA-1 are refused with `unsupported`, because §3.3 note [29] defines only SHA-1
  and there is no counter field.
- **`expires` sets the DATE.** It used to be read as a bare boolean on KDBX, so a page that
  sent the timestamp the schema asked for set the flag, left the date alone, and got
  `changed: ["expires"]` back — a wrong answer that reported success, on the one field where
  the wrong answer is "this credential never expires". A string now sets both; a bool is the
  flag alone (KDBX only — PWS3 stores only a date and refuses a bare `true`); null or `""` is
  never.
- **`custom` is a MAP, and the whole of what a "custom field" is here.**

```json
"changes": {
  "custom": {
    "API token":     { "value": "…", "protected": true },
    "Support phone": { "value": "+44…", "protected": false },
    "Old field":     null
  }
}
```

  - The **key** is the field's name inside the entry. KeePass reserves `Title`, `UserName`,
    `Password`, `URL`, `Notes`, `Tags`, `IconID`, `Times`, `History` and `otp`; those ten are
    refused (`invalid`). pykeepass guards this with an `assert`, which vanishes under `-O`, so
    the backend checks it itself — and `custom:Password` would otherwise be a third spelling of
    the door that reads the master password while the audit line said "custom field". The
    schema publishes the key's rule as a field descriptor of its own (`fields[].key`), so a
    renderer does not have to assume it.
  - The **value** is `{value, protected}`. A bare string is shorthand for a protected value.
    `null` DELETES the named field — meaningful on `changes`, where there is something to
    delete.
  - **`protected` defaults to `true`, and setting it false stores the value as plain text
    inside the database.** It is still encrypted with the file, but KeePassXC shows it unmasked
    in the entry view and exports it unmasked, and this page lists its name with the
    unprotected fields. Nothing warns about it later; the flag is only recorded.
  - Only the names sent are touched. The entry's other custom fields are left alone.
  - **Reading one back is `reveal` with `field: "custom:<name>"`** — the same door as every
    other value, one field, one audit line. `entries` never carries a custom field's value, and
    `attach-list`'s sibling for field names is KDBX's `fields()`, which is not yet a verb.
  - **Password Safe v3 answers `unsupported` and names the limit.** A PWS3 record is a list of
    TYPED fields, each type appearing at most once; 0xdf ("custom-text-field") is one such
    type, not a dictionary. There is nowhere to create a named field. Writing it into Notes
    would invent a convention no other Password Safe implementation reads, so it is refused
    instead — keep entries that need custom fields in a KDBX safe.

The schema declares `custom` with `control: "json"` and `secret: true`. `json` is the control
the shipped renderer can actually draw for a map whose keys are the operator's, and `secret`
puts it on the right side of every rule that matters: it is excluded from the non-secret
`values()` path, written into the request immediately before the spawn, and wiped after (I11).
`fields[].key` and `fields[].fields` describe the key and the value shapes for a renderer that
grows a proper key/value control later; neither is required to draw it today.

### `handle` semantics — the part that decides whether this is safe

- **Default (agent off): a handle is single-process and dies with the helper.** One
  `cockpit.spawn` per verb means one unlock per verb, so **the password is prompted every
  time** — that is the requirement, and the default configuration meets it by construction,
  not by policy.
- Mutating flows that need several verbs under one unlock run inside a **single** helper
  invocation kept open on its stdin stream (the `open` session), which ends when the channel
  closes, the idle timer fires, or `lock` is called.
- With `agent.enabled` (I18), the handle is held by `secrets-agent` behind an `AF_UNIX`
  socket with `SO_PEERCRED`, bound to the creating uid, with hard idle and absolute
  lifetimes. Opt-in per safe, never global.
- A handle is an opaque 128-bit random token, bound to `(uid, safe id, pid or agent session)`.
  Presenting a handle you do not own is an access-denied, not a not-found. The contract fixes
  the **entropy**, not the alphabet: `secrets-admin` mints `secrets.token_urlsafe(16)`, and the
  agent's token class is base64url to match.

#### What the agent holds — a ticket, not a key

**`secrets-agent` holds the handle. It does not hold key material, and `secrets-admin` never
sends it any.** That is the line above taken literally, and it is what keeps non-negotiable 9
intact: because the agent cannot hand a later helper process anything that reopens a safe, the
passphrase is still prompted on every unlock, by construction rather than by policy.

A ticket is a uid-bound record that safe X was unlocked at time T with both deadlines running.
It buys the half of I18 that is about **visibility and revocation**:

- `health.agent.{user,admin}.status.holdings[]` answers "what is unlocked right now, and for how
  much longer" with no handle and no passphrase, so an unlock survives a page reload as something
  the operator can SEE. I18's "an unlocked safe must never be invisible" is paid for here.
- `unlock`'s response gains an `agent` block **only** when the daemon actually took the handle —
  never when the agent is disabled, the socket is absent, or the daemon refused.
- `lock` accepts a **bare `safe`** as well as a handle, so a Lock button can revoke a ticket after
  the helper that minted it has exited. `agent_dropped` appears only when the registry enabled the
  agent for that safe.

It deliberately does **not** buy "do not ask me again". The daemon's `put` still accepts an
optional `material` field and that path is tested, because I18 sanctions a material-carrying agent
as a per-safe opt-in — but nothing in this tree produces key material, nothing consumes it, and
`secrets-admin` strips a `material` key out of any agent reply at the door. Implementing a real
reattach starts by deleting that line, deliberately.

##### The ticket protocol on the wire

Newline-delimited JSON over the `AF_UNIX` socket, one request object per line, one reply per
line, UTF-8, every line capped; a malformed or oversized line is answered and then the
connection is closed. Four operations, and `secrets-admin` is only ever the client:

```
-> {"op":"put","safe":"lab-dc","handle":"<token>","idle_seconds":300,"max_seconds":3600}
<- {"ok":true,"handle":"<token>","safe":"lab-dc","expires_in":3600,
    "idle_seconds":300,"max_seconds":3600,"material_held":false}

-> {"op":"get","safe":"lab-dc","handle":"<token>"}
<- {"ok":true,"safe":"lab-dc","material_held":false,"expires_in":2871,
    "idle_expires_in":300}

-> {"op":"drop","safe":"lab-dc"}        # or {"handle":…} / {"all":true}
<- {"ok":true,"dropped":1}

-> {"op":"policy","safes":["lab-dc","other"]}
<- {"ok":true,"available":true,"keep_open":{"lab-dc":true,"other":false}}
   # the one reader of agent.allow_keep_open, made addressable so the helper
   # asks the process that refuses instead of reading the registry itself

-> {"op":"keep-open","safe":"lab-dc","enabled":true}     # or {"handle":…}
<- {"ok":true,"safe":"lab-dc","keep_open":true,"changed":1,"affected":1,
    "expires_in":3412,"idle_expires_in":null,"idle_seconds":300,"max_seconds":3600}

-> {"op":"status"}
<- {"ok":true,"pid":…,"owner_uid":…,"holdings":[…],"idle_seconds":…,"max_seconds":…,
    "clock":"BOOTTIME","socket":{…},"session":{…}}
```

`material` is optional on `put` and this client never sends it, so `material_held` is always
`false` and `get` carries no `material` key — that is the ticket, and it is the whole of what
the daemon holds. Errors use the taxonomy below verbatim, and an unknown handle and another
uid's handle return the SAME `access-denied`: distinguishing them would turn `get` into an
enumeration oracle that says which tokens exist.

Four rules the helper's agent client keeps, in order of how much they matter: **off unless the
registry says otherwise**; **never start the daemon** (no fork, no exec, no socket activation, no
creating the run directory); **never fail a verb because of the agent** (every call returns None
on any error, so a hung or hostile daemon costs one extra prompt, never a failed verb); and
**validate the socket before speaking to it** — owner and mode on the 0700 run directory and on
the socket node, by `lstat`, never `stat`.

The third rule has **exactly one exception, and it is the `keep-open` verb**. Every other agent
call is a side effect of a verb that is about something else, so a daemon that cannot answer
costs one extra prompt. `keep-open` IS the agent operation: if the daemon did not hear it, the
idle timeout is still running, and a helper that answered `ok` anyway would hand the page a
toggle reading "on" over a safe about to lock itself. So that verb answers `unsupported` when the
agent does not reply, and the operator is told that nothing changed.

#### `keep-open` — suspending the idle timeout, and what still bounds it

`agent.allow_keep_open` (default **false**, and it needs `agent.enabled` too) permits an operator
control that **suspends the IDLE timer that would otherwise end their working session**, and the
agent ticket's idle timer with it. It exists because the idle timer is the one that fires in the
middle of a task.

**WHICH TIMER, AND WHY THAT SENTENCE IS THE WHOLE FEATURE.** The first implementation suspended the
agent TICKET's idle timer only. The agent holds a ticket and no key material — "no key material
crosses this socket in either direction", above — so suspending it kept nothing open: what ends an
operator's session is `SESSION_IDLE_SECONDS` in the helper's own `open` session, where the channel
going quiet exits the process and the exit takes the unlock. The toggle went on, the banner said
they would not be locked out, and they were locked out on the original schedule. `keep-open` now
suspends the SESSION's idle timer — inside an `open` session, which is the only place there is one
— and asks the daemon to suspend the ticket's so the two agree about one fact. Outside a session
the verb still changes the ticket, and says in `warnings` that there was no session idle timeout to
suspend rather than claiming one was.

**THE STANDING BAN: THE THING GATED AND THE THING AFFECTED ARE THE SAME SCOPE.** There is exactly
one idle timer in a helper session and it ends the whole process, so suspending it suspends the
only idle protection every safe that process has unlocked has. The daemon's gate is about ONE
safe. Those are different scopes, and the gap between them was a bypass: with `lab-A` opted in and
`lab-B` opted out, one session holding both could toggle `lab-A` and keep `lab-B` open through
silence it would otherwise have died in — while the page drew no toggle on `lab-B`'s row at all.

So the rule, and it is a rule rather than a note because **this mistake has now been made twice**
(the first was `op_put`, gating on the request's safe while acting on a holding found by handle):

> Wherever keep-open is granted, the scope the gate was asked about MUST be the scope the grant
> affects. The grant affects the whole session, so the gate is asked about the whole session.

In code that is: the suspension is in force only while EVERY safe the session holds has been
affirmed by the daemon (`held <= allowed`); that comparison, in `SessionWindow._rescope`, is the
only line in the program that assigns `keep_open`; the mutator takes the session's held set
keyword-only and without a default so a call site cannot narrow it by forgetting an argument; the
scope is re-derived after every verb, because `unlock` is a verb and a scope checked only at the
toggle could be walked around by unlocking afterwards; and the reply to the verb that broke the
scope carries the state AFTER the re-derivation, because the page adopts from replies.
`validate.sh` greps for every one of those.

Precisely what it does and does not change:

- **The absolute lifetime is untouched by any client.** The session's `SESSION_MAX_SECONDS` is
  counted from the session's START, not from the toggle and not from now; the agent's `max_seconds`
  still counts from the unlock; `expires_in` still reports them; and both still end a suspended
  holding. "Keep it open" means "until the absolute deadline", never "until I say so".
  **One input may raise the session's bound: the safe's own registry entry** (`agent.max_seconds`),
  because the registry is the operator's policy file rather than a client. It is capped at
  `SESSION_KEEP_OPEN_CEILING` (the same 3600 s ceiling a `session` frame is clamped to), announced
  on stderr when it goes above the default, idempotent (`started + capped`, so re-sending the
  toggle cannot ratchet it), and **refused outright once a client has shortened the lifetime** —
  a client that could shorten the bound and get it back by clicking a toggle would have found an
  indirect way to extend its own. That guard covers BOTH doors a client can shorten through: a
  `session` frame and `unlock`'s own `max_seconds`. It used to cover only the first, so shortening
  at the unlock and then toggling handed the lifetime straight back.
  **And the raise is contingent on the suspension**: switching keep-open off, or having it revoked,
  gives it back and re-publishes the lowered `session_expires_in`/`session_max_seconds` in the same
  reply. Left standing, it was an extension bought with two clicks.
- **Every presence lock still fires, immediately.** `drop` (which is what the page's Lock button,
  its `pagehide` handler and its hidden-tab timer all reach), SIGTERM, the daemon's logind poll
  when the session locks or ends, and its freeze detector when the machine suspends. Those are not
  timeouts; they are "nobody is here", and suppressing them is the hazard rather than the rest of
  the job. Two of them used to miss: the page's `pagehide` and hidden-tab handlers ran entirely
  inside `if (SESSION)`, so a SUSPENDED holding the page did not create sailed through both while
  the banner promised otherwise. They now reach every suspended holding the page can see, whoever
  created it. An ordinary, unsuspended holding still outlives the tab — that is what the agent is
  for, and its idle timer still bounds it.
- **A suspended session re-asks ON A CLOCK, and cannot outlive its permission or the presence
  signals.** Every `SESSION_KEEP_OPEN_RECHECK_SECONDS` — counted from the last re-ask, at the TOP
  of the session loop, so it happens whether the session is silent or busy. It used to live in the
  idle-timeout branch, which meant it was reached only by a session that had gone quiet: a session
  that kept talking never re-asked at all, and a withdrawn opt-in or a presence signal landing at
  the daemon reached exactly the sessions that were about to end anyway. The re-ask covers EVERY
  safe in the grant and re-derives the scope over every safe the session HOLDS, so an opt-in
  withdrawn from a held safe that was never toggled revokes the suspension too. A refusal puts the idle timer back **without resetting it** — the session has been idle
  for however long it has been idle — and the session then ends on the ordinary idle rule. An
  answer of `affected: 0` means the daemon is no longer holding that safe, which can only be a
  presence drop or its own absolute deadline, and the session ends with `reason: "agent-released"`.
- **OFF always reaches the session's own timer, even when the daemon refuses it.** The daemon gates
  both directions and must (its OFF resets the holding's idle timer, so an ungated OFF is a
  keepalive) — which means it refuses OFF for a safe whose opt-in has just been withdrawn. The
  helper used to relay that refusal, so the operator whose registry had changed under them could
  not turn the toggle off at all. The daemon's gate is unchanged; the helper resumes its own idle
  timer regardless and says in `warnings` that the daemon refused its half. Resuming a timer is
  strictly more protective than not resuming it and grants a caller nothing.
- **The suspension dies with the session — ALL of it, on every exit including SIGTERM.**
  `run_session`'s teardown lifts it at the daemon for **every** safe the grant covered and says how
  many and which; it used to name the last safe toggled, release that one, and report that it had
  released them all. A suspension that outlived its session is what made the page's banner go on
  promising protection for a session that had ended. And the teardown now runs on the path Cockpit
  actually takes: the page's `proc.close("terminated")` SIGNALS the helper, and with no handler
  that was the kernel's default — the process died where it stood and the release never ran at all.
  SIGTERM and SIGHUP unwind into the teardown (`reason: "terminated"`); SIGKILL still cannot, and
  the daemon's `reconcile_keep_open` and presence drops are the backstop for that.
- **A withdrawn opt-in reaches a LIVE suspension.** The daemon reconciles every suspended holding
  against the registry before each expiry scan (`reconcile_keep_open`, throttled by
  `POLICY_RECHECK_SECONDS`), clears the ones it no longer allows and does **not** `touch()` them —
  so a holding that has genuinely been idle is dropped by that same pass, and one that is being
  used survives with its idle timer running again. Without this, `allow_keep_open: false` only ever
  stopped the NEXT request and a running suspension kept its permission for the rest of the
  holding's lifetime: a gate that cannot be withdrawn.
- **The DAEMON decides, not the caller — and it is the ONLY reader.** `secrets-agent` reads the
  registry itself — one boolean per id, nothing else, `O_NOFOLLOW` on the directory and the file,
  refusing anything another uid can write — and answers `access-denied` for a safe that did not opt
  in, whatever the client says. **Both directions are gated identically**: `{"enabled": false}` used
  to skip the gate and still reset the idle timer, which made it a handle-free, passphrase-free
  keepalive that worked on safes the registry had never opted in. It is gated now, and the reset
  happens only for a holding that really was suspended. `op_put`'s gate is evaluated against the
  safe the holding will HAVE after any relabel, not against the one in the request — the former was
  bypassable in three messages by re-putting a handle onto an allowed safe and then back.
  The helper no longer forms its own opinion at all: `v_keep_open` relays the daemon's answer, and
  `list` gets `agent_keep_open_allowed` from the daemon's `policy` op. Two readers of one registry
  key gave two answers, and the operator was shown one and governed by the other.
  `--no-keep-open` is an agent-wide ceiling above all of it, and no registry entry lifts it.
- **It is audited and it is visible, and the audit says WHICH DIRECTION.** One metadata-only line
  per holding per change (`op: "keep-open"`, the safe, the uid, `enabled`/`disabled` — never a
  value and never a path). The helper's own line carries `note: "keep-open-on"` or
  `"keep-open-off"`; those two strings were being set and then dropped, because `audit()` keeps
  only notes in its declared set and neither was in it — so every line read `"note": ""` and the
  log could not tell the timer being switched off from it being switched back on. Also
  `status`/`health` report `keep_open` per holding plus a `keep_open: {available, registry_dirs,
  suspended}` block, so the state is inspectable without the page.
- **`idle_expires_in` is `null` while it is suspended**, not a large number. A caller must be able
  to tell "no idle deadline is running" from "one is, and it is far away"; a number is what a UI
  would draw a countdown from. `Number(null)` is 0, so a page that reads it as a number counts
  down to a lock that is not coming.

Non-negotiable 9 is unaffected: the agent still holds a ticket rather than key material, so a
suspended holding still cannot reopen a safe without the passphrase.

### Error taxonomy

One shape, deliberately coarse so it cannot be used as an oracle (I6):

```json
{ "error": "access-denied" | "not-found" | "locked-out" | "bad-credential"
          | "conflict" | "unsupported" | "invalid" | "internal",
  "detail": "operator-safe sentence, never a value, never a traceback" }
```

`bad-credential` covers both a wrong password and a failed MAC, and the failure path has a
constant time floor. The distinction is recorded in the audit log, not returned.

Two of the eight are routinely confused and the difference is what an operator does next:
**`invalid` means the request was malformed** — the caller can fix it and try again.
**`unsupported` means the FORMAT cannot do this** — the request was correct and the answer will
not change until the safe is a different file. Every place a backend cannot honour a
well-formed request (`tags` and `custom` on PWS3, `otpauth://hotp`, writing a KDBX3) answers
`unsupported` with the format's own reason, never `invalid`, because `invalid` reads as "you
typed that wrong".

## Non-negotiables

1. No secret on argv, in the environment, or in a temp file (I10).
2. No secret in `localStorage`/`sessionStorage`/IndexedDB/cookies (I11).
3. Nothing decrypted leaves the backend adapter before its MAC verifies; all comparisons are
   `hmac.compare_digest` (I6).
4. Verbs take registry ids, never paths; files are opened `O_NOFOLLOW` and validated by
   `fstat` on the fd (I4, I5).
5. Writes are: backup → temp file → `fsync` → `os.replace` → `fsync(dir)`, with a
   changed-on-disk re-check immediately before (I12, I13).
6. Access class is enforced in the helper on every verb, never in the browser (I3).
7. The audit log records verb, safe, uid and outcome — never a value, never a traceback (I15).
8. No `set -x` in any wrapper. No CSP relaxation in `manifest.json` (I9).
9. **The passphrase is prompted on EVERY unlock** (I18), which the agent's ticket keeps true
   by construction rather than by policy.

---

## `constants{}` — what the schema verb publishes

The page must never hard-code any of these; the helper is the one place they are defined, and
`constants` is how they reach the browser. Measured from the live helper on 2026-09-04:

```
reveal_seconds 15 · fail_floor_seconds 0.75 · session_idle_seconds 120 ·
session_max_seconds 900 · lockout_threshold 5 · lockout_max_seconds 900.0 ·
lockout_safe_threshold 20 · lockout_safe_window_seconds 60.0 ·
max_request_bytes 1048576 · max_keyfile_bytes 1048576 · max_safe_bytes 134217728 ·
max_attachment_bytes 33554432 · max_yubikey_response_bytes 1024 · max_entries 100000 ·
helper "/usr/local/sbin/secrets-admin" · registry_dir "/etc/cockpit-secrets/safes.d" ·
export_dir_default "/var/lib/cockpit-secrets/exports" ·
export_confirm_prefix "export-plaintext:" · breach_corpus_file "breach-corpus.txt" ·
agent_admin_run "/run/cockpit-secrets"
```

0.4.0 adds these, and the registry-writing verbs are unusable without them:

| constant | value | what it is |
|---|---|---|
| `new_id_pattern` | `^[a-z0-9][a-z0-9-]{1,62}$` | the id allow-list these verbs MINT against (C2). Stricter than the schema's `id` pattern, on purpose |
| `user_registry_dir` | `~/.config/cockpit-secrets/safes.d` | the per-user registry for **this caller**. `null` when `euid == 0` — a root helper does not have one and must not report one |
| `user_safes_dir` | `~/.local/share/cockpit-secrets/safes` | managed safe directory for the `user` class |
| `safes_dir` | `/etc/cockpit-secrets/safes` | managed safe directory for the `admin` class |
| `registry_dir` | `/etc/cockpit-secrets/safes.d` | the system registry directory |
| `import_chunk_bytes` | `524288` (`IMPORT_CHUNK_BYTES`) | decoded bytes per `import-chunk`; base64 plus framing stays under `max_request_bytes`. `import-begin`'s reply names it as `chunk_bytes` |
| `import_idle_seconds` | `900` (`IMPORT_IDLE_SECONDS`) | staging expiry, measured from its **last use**, and the same threshold the sweep uses. A **resource** control |
| `import_max_stagings` | `8` (`IMPORT_MAX_STAGINGS`) | concurrent stagings one caller may HOLD. Bounds "start ten thousand uploads" |
| `import_max_attempts` | `5` (`IMPORT_MAX_ATTEMPTS`) | failed `import-commit` credentials before the staging is destroyed. A **resource** control, never a credential control — see the note under `import-commit` |
| `import_max_concurrent` | `2` (`IMPORT_MAX_CONCURRENT`) | how many `import-inspect` / `import-commit` calls may be RUNNING at once, per identity. A different bound from `import_max_stagings`, and the one that was missing (I54). The (N+1)th caller gets `conflict`, never a queue |
| `delete_confirm_prefix` | `delete-safe:` (`DELETE_CONFIRM_PREFIX`) | `safe-delete`'s token is this plus the id |

The KDF a `safe-create` uses is published on the `kdf` FIELD rather than as a constant,
because it is a sub-form the page renders: each sub-field carries its own `default`, `min` and
`max`. The defaults are KDBX Argon2id at m=64 MiB / t=8 / p=2 and PWS3 at 262 144 iterations;
the floors are `Limits`' own write floors (OWASP's m=19 MiB / t=2 / p=1, and PWS3's 262 144)
and the ceilings are the `Limits` clamps. **The published `min` is the enforced floor** — they
were once separate numbers, and a bound the schema advertises that the backend then refuses is
worse than no bound at all.


## Where this document and the live `schema` verb currently disagree

Cross-checked field by field against `COCKPIT_SECRETS_ETC=/nonexistent ./secrets-admin schema`.
First run against the 33-verb helper on 2026-09-04, and **re-run against the shipped 0.4.0
helper the same day** (`helper_version 1.0.0`, `base_version 1.0.0`, schema version 2, **41
verbs, 43 fields**). Reported rather than papered over, in three groups.

The re-run's mechanical results: every verb the schema publishes is named in this document, and
`schema` and this file agree on the id, the group, `needs`, `mutates`, `danger` and the request
list of all 41. What still differs is group B below, which is the schema's `response` map being
an abbreviation rather than either side being wrong.

**A · Fixed in this document (it was lagging the code).** `restore-backup` also returns `undo`
and `ring_full`; `breach-check` also returns `reason`; `strength` returns `length`,
`alphabet_size`, `penalty_bits`, `source` and `note` on top of what was listed; `schema`
returns `helper_version` and `base_version`; `health` returns eleven top-level keys this file
had summarised as eight. All corrected above.

**B · The `schema` verb's `response` map is an abbreviation, and the helper is the one to
change.** These are not errors in this document — the verbs really do return the keys — but a
page that trusted `schema.verbs[].response` as a complete list would be wrong:

| verb | returns, but `schema` does not declare |
|---|---|
| `schema` | `helper_version`, `base_version`, `ui_rules` |
| `strength` | `length`, `guessable_length`, `alphabet_size`, `penalty_bits`, `source`, `note` |
| `export` | `mode: "0600"`, `warning` (both present in the helper at the response construction) |
| `health` | `version`, `base_version`, `schema_version`, `registry_root`, `registry_entries`, `registry_gate`, `agent`, `export`, `breach`, `library_root`, `library_root_trusted`, `identity`, `debug` |

`guessable_length` is the interesting one: it was named in this document and *not* in the
schema, and the runtime does return it — so the document was right and the schema map was
short. That is the case for the rule stated at the top: **schema is authoritative for
requests, this file for responses.**

**C · Cross-checkable now, and cross-checked.** Everything in "The verbs that WRITE the
registry" was specified here *ahead of* the helper — at the time it was written
`secrets-admin schema` listed 33 verbs and none of `safe-create`, `import-*`, `safe-forget`
or `safe-delete` existed. It now lists **42 verbs and 44 fields** (`keep-open`, and the
`enabled` field it reads, are the most recent pair), every one of those blocks
is checkable against a running helper, and the section below records what disagreed and which
side moved.

Two of the three groups above are unchanged by that: the `schema` verb's `response` map is
still an abbreviation (group B), and `list`'s map has been widened to name the keys it
actually returns — sixteen as of R5's `path`, **seventeen** since `keep-open` added
`agent_keep_open_allowed`, and **eighteen** since that key started carrying the daemon's answer
and needed `agent_keep_open_known` beside it to say whether there was one — and this document's
own inline block had lagged at ten until that
pass re-checked the whole row against the running helper. The row below is checked against a
running helper, not maintained by hand: a key added to `v_list` and not added here is the same
defect the table below records.

---

## Where this document and the shipped helper agreed after 0.4.0's integration

This section replaces the "currently disagree" list that stood here while the registry-write
verbs were still being written. Every item in it was resolved in one direction or the other,
and the direction is recorded because "it was fixed" is not a checkable claim.

**The standing rule, unchanged:** the `schema` verb is authoritative for REQUEST fields —
`secrets.js` builds its forms from it and cannot see this file — and this document is
authoritative for RESPONSE keys and for behaviour.

| What disagreed | Resolved by | Why that direction |
|---|---|---|
| verb ids `safe-import-begin` … | **this document** now says `import-begin` … | the schema is authoritative for the interface; the page, the tests and the audit log all already used the shipped names |
| `offset` / `data_b64` on a chunk | **this document** now says `chunk_offset` / `chunk_b64` | same rule. `data_b64` is a different field with a different meaning (`attach-add`), and reusing it here would have made one name mean two things |
| `kdf_memory_kib` / `kdf_time` / `kdf_parallelism` as three flat fields | **this document** now says one `kdf` object | the helper publishes a sub-form so the page can render the KDBX and PWS3 parameter sets without inventing which apply to which |
| `password` on `safe-create` and `import-commit` | **this document** now says `new_password` | `password` carries three promises (the I16 lockout, the per-safe cap, the constant-time floor) that do not apply to setting a passphrase on a safe that does not exist yet. `tests/integration/lockout.py` derives its verb list from that field name and stays true because of it |
| `confirm` on `safe-delete` | **the helper** now reads `delete_confirm`, which is what this document and the schema both published | the code was reading `export`'s field name, so the verb was unreachable through the published interface (I49). `tests/ban_undeclared_fields.py` is the standing gate |
| `safe-forget` returning no `path` | **the helper** now returns it | this document said the response names the file left behind, and it was right: "we stopped listing it" is only useful if you are told where it went. The path is in the RESPONSE and still never in the audit line |
| `list` rows missing `origin` and `manageable` | **the helper** now returns both | this document specified them; the entries carry `origin` as of I46, and `manageable` is computed from the same two facts the verb gates on |
| `list` rows missing `path` — so R5's Path column and the pane's Path section could never render | **the helper** now returns it on every row it can resolve | neither side had specified it: docs/DESIGN.md §5.6 designed both halves of R5 against a field the helper does not publish and never said to check, and it looked as if it worked only because `tests/browser/harness.js` supplies `path` in its canned `list` reply. The live page had never once shown one. The page needed no change; this is `v_list` catching up to the requirement, and the four rules it now follows are above |
| §18.1's prescription that the new `path` be "gated on access class" | **docs/DESIGN.md §18.1 is wrong** and this document is the correction | built that way and driven live, it delivers R5 for a per-user safe and withholds it for the system safe — the one §18.1 was written about. `secrets.js` spawns `list` unescalated always, by design, so `gate()` refuses admin-class rows at every access level and the Path section can never draw for one. What makes the field safe is the loader (rule 2 above), not the class model |
| this document's inline `list` block naming ten keys where the helper returns sixteen | **this document** now names all sixteen, plus `registry_errors` | the standing rule — schema is authoritative for requests, this file for responses — only holds if this file is actually re-read against a running helper. `password_required`, `needs_keyfile`, `agent_enabled` and `export_allowed` had been shipping unlisted since before 0.4.0 |
| `handle` undeclared on `backups`, `breach-check`, `restore-backup` and `export` | **the schema** now declares it on all four | all four resolve their safe through `_entry_for`, which accepts one — so the capability was real, unpublished, and (once the dispatcher started refusing undeclared credential fields) unusable. Verified working inside a real `open` session afterwards |
| `constants.new_id_pattern` vs `constants.new_id_pattern` | **this document** now cites `new_id_pattern` | the shipped constant name |
| `constants.create_kdbx_kdf_min` (8 MiB / t=2 / p=1) | **the helper** now publishes `Limits`' own Argon2 WRITE floors (m=19 MiB, t=2, p=1) as the schema `min` | the helper advertised a floor of 8 MiB that the backend then refused. A published bound that is not the enforced bound is worse than no bound |

Two constants this document did not know about, both added by the integration:

- **`import_max_concurrent`** (2) — how many `import-inspect` / `import-commit` calls may run
  at once, per identity. Every other import limit counts things a caller may HOLD; none
  counted things RUNNING, and 32 simultaneous inspects of one 128 MiB staging measured 7.6 GiB
  resident across 32 root-capable processes (I54). The (N+1)th caller is refused with
  `conflict`, never queued: queueing would hold a Cockpit channel open for the duration.
- **`compressed`** on `import-inspect` — an optional boolean from the outer header, present
  for KDBX and absent for PWS3, which has no such concept. Reported as `null` rather than
  `false` when the format has no answer.
