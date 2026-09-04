# secrets-admin contract

Same shape as `wg-admin` / `adlab-admin` / `hs-admin` on this host, with one addition forced
by the subject matter: **requests carry secrets, so requests arrive on stdin as JSON, not on
argv.**

- The plugin never runs raw commands. It calls ONE helper, `/usr/local/sbin/secrets-admin`,
  with a narrow verb.
- Every verb prints **exactly one JSON object on stdout and nothing else**. Diagnostics go to
  stderr. Exit 0 = success; on failure stdout carries `{"error": "..."}` and exit ≠ 0. The one
  exception is `open`, which is a session and writes one object per request line — that is
  what makes it the only verb dispatched separately.
- The UI renders nothing it invented: every form, control, validation rule and label comes
  from `secrets-admin schema`.
- **No verb accepts a secret as an argument.** Passwords, key-file bytes and new values are
  fields of the JSON request object on stdin (I10).

**This file is the interface, and the whole build coordinates through it.** Where it and the
`schema` verb disagree, the schema is what the page actually reads — so a disagreement is a
bug in this file and gets fixed here, not worked around there. Schema version 2; helper 1.0.0.

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
  "agent": { "enabled": false, "idle_seconds": 300, "max_seconds": 3600 },
  "export_allowed": false,              // I21
  "export_dir": null,                   // I21 — absolute, never under /tmp
  "breach_corpus": null,                // absolute path to an OFFLINE corpus
  "backup": { "keep": 10, "dir": null }
}
```

Those sixteen keys are the whole vocabulary. `export_dir` and `breach_corpus` were the last
two added, with the verbs below; both are helper-side absolute paths, never a path from a
request (I4). `export_dir` is refused under `/tmp`, `/var/tmp` and `/dev/shm`, and setting it
while `export_allowed` is false is refused rather than ignored — the two are one decision.
`breach_corpus` names an offline file and nothing else: **there is no online fallback and there
will not be one.**

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

## Verbs

Thirty-three verbs. `schema` publishes all of them with their request fields, response keys,
`danger`/`mutates`/`needs` flags and a `breaks_when_wrong` sentence each; the tables here are
the prose, and the schema is the machine-readable form the page builds from.

```
secrets-admin schema                  -> { version, verbs[], groups[], fields[], enums{},
                                           constants{}, ui_rules[] }
secrets-admin list                    -> { safes:[{id,label,format,access,mode,locked,reason,
                                           usable}] }
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
secrets-admin generate <stdin:{policy}>  -> { value, entropy_bits, calculation,
                                              alphabet_size }
secrets-admin health                     -> { backends:{kdbx:…, psafe3:…}, registry_errors:[],
                                              registry_gate:{…}, agent:{…}, export:{…},
                                              breach:{…}, hardening:{…}, state:{…} }
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
                        -> { ok:true, restored, bytes, backup, created }
secrets-admin export     <stdin:{safe, credentials, fmt, confirm}>
                        -> { path, bytes, entries, fmt, name, mode:"0600", warning }
secrets-admin strength   <stdin:{value}>
                        -> { entropy_bits, effective_bits, category, guessable_length,
                             weaknesses:[{id,label,cost_bits}], calculation }
secrets-admin breach-check <stdin:{safe, value|sha1_prefix}>
                        -> { available, found:bool|null, count, prefix5, method,
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
