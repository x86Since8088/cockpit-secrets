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
  "backup": { "keep": 10, "dir": null }
}
```

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
secrets-admin health                     -> { backends:{kdbx:…, psafe3:…}, registry_errors:[] }
secrets-admin audit-tail --n N           -> { entries:[…] }        # metadata only, never values
```

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
  Presenting a handle you do not own is an access-denied, not a not-found.

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
