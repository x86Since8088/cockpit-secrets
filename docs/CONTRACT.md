# secrets-admin contract

Same shape as `wg-admin` / `adlab-admin` / `hs-admin` on this host, with one addition forced
by the subject matter: **requests carry secrets, so requests arrive on stdin as JSON, not on
argv.**

- The plugin never runs raw commands. It calls ONE helper, `/usr/local/sbin/secrets-admin`,
  with a narrow verb.
- Every verb prints **exactly one JSON object on stdout and nothing else**. Diagnostics go to
  stderr. Exit 0 = success; on failure stdout carries `{"error": "..."}` and exit ≠ 0.
- The UI renders nothing it invented: every form, control, validation rule and label comes
  from `secrets-admin schema`.
- **No verb accepts a secret as an argument.** Passwords, key-file bytes and new values are
  fields of the JSON request object on stdin (I10).

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

`export_dir` and `breach_corpus` are **extensions** to the original entry, added
with the verbs below. Both are helper-side absolute paths, never a path from a
request (I4). `export_dir` is refused under `/tmp`, `/var/tmp` and `/dev/shm`,
and setting it while `export_allowed` is false is refused rather than ignored —
the two are one decision. `breach_corpus` names an offline file and nothing
else: **there is no online fallback and there will not be one.**

## Verbs

```
secrets-admin schema                  -> { version, verbs[], groups[], fields[], enums{} }
secrets-admin list                    -> { safes:[{id,label,format,access,mode,locked,reason}] }
secrets-admin probe    <stdin:{safe}> -> { format, version, kdf, iterations, needs_password,
                                           needs_keyfile, writable, warnings:[] }
secrets-admin unlock   <stdin:{safe,password,keyfile_b64,session}>
                                      -> { handle, expires_in, entries_total, groups_total, warnings:[] }
secrets-admin tree     <stdin:{handle}>        -> { groups:[{uuid,name,parent,count}] }
secrets-admin entries  <stdin:{handle,group,query,offset,limit}>
                                      -> { total, entries:[{uuid,title,username,url,tags,
                                           has_totp,attachments,modified}] }   # NO passwords
secrets-admin reveal   <stdin:{handle,uuid,field}>   -> { field, value, expires_in }
secrets-admin totp     <stdin:{handle,uuid}>         -> { code, seconds_remaining }
secrets-admin attach-get <stdin:{handle,uuid,name}>  -> { name, size, b64 }
secrets-admin add      <stdin:{handle,group,entry}>  -> { uuid }
secrets-admin edit     <stdin:{handle,uuid,changes}> -> { uuid, changed:[...] }
secrets-admin move     <stdin:{handle,uuid,group}>   -> { ok:true }
secrets-admin rm       <stdin:{handle,uuid,permanent}> -> { ok:true, recycled:bool }
secrets-admin group-add / group-rm / group-mv         -> { ok:true }
secrets-admin save     <stdin:{handle}>  -> { ok:true, backup, bytes, conflict:false }
secrets-admin lock     <stdin:{handle}>  -> { ok:true }
secrets-admin generate <stdin:{policy}>  -> { value, entropy_bits }
secrets-admin health                     -> { backends:{kdbx:…, psafe3:…}, registry_errors:[],
                                             registry_drift:[], agent:{…}, export:{…}, breach:{…} }
secrets-admin audit-tail --n N           -> { entries:[…] }        # metadata only, never values
```

### Verbs added after the first build

These **extend** the table above; nothing above changed shape. `unlock` gained
one optional request field and one conditional response key, and `lock` gained
an alternative way to name what to lock. Everything else is new.

```
secrets-admin history   <stdin:{handle|safe+credentials, uuid}>
                        -> { uuid, total, versions:[{index,when,title,username,
                             url,has_password,notes_len}] }        # NO passwords
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
  object), not `MAX_ATTACHMENT_BYTES` — base64 costs a third, so roughly 760
  KiB of attachment fits. Both are checked; the schema's help text names both.

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
