# Threat model — cockpit-secrets

## What this program is

A Cockpit page on edt1 that lets the **logged-on Cockpit user** type a passphrase to unlock a
KeePass (KDBX) or Password Safe v3 safe and then fully manage it — browse, reveal, copy, add,
edit, move, delete, attach, save. Safes are either **user** class or **admin** class;
**admin is the default**.

## Adversaries in scope

| # | Adversary | Capability | Defence |
|---|---|---|---|
| A1 | Another unprivileged local user | shell on edt1, can read `/proc`, connect to loopback and unix sockets, create symlinks in their own tree | `O_NOFOLLOW` + fd-`fstat` ownership checks (I5); nothing on argv/env (I10); `SO_PEERCRED` + 0700 run dir on the agent (I18); registry and admin safes root-owned `0600` |
| A2 | A non-admin Cockpit user | a Cockpit session, can open devtools, edit JS, replay any channel | class re-checked in the helper on every verb (I3); registry ids not paths (I4); `superuser:"require"` on admin verbs (I2) |
| A3 | A malicious or corrupted safe file | full control of file bytes — KDF params, field lengths, inner XML | KDF clamps (I7); XXE-hardened parser (I8); length/size caps; verify-before-use (I6) |
| A4 | XSS anywhere in the Cockpit origin | runs script in the page's origin | nothing persisted client-side (I11); no CSP relaxation (I9); handles bound to uid+pid, expiring |
| A5 | A stale or concurrent desktop client | writes the same file from KeePassXC or Password Safe | lock files honoured + changed-on-disk re-check + refuse, never merge (I13) |
| A6 | An interrupted write | power loss, OOM kill, `SIGKILL` mid-save | backup ring + temp-file + `fsync` + atomic rename (I12) |
| A7 | An impatient operator | wants convenience over prompting | prompt-every-time is the *default configuration*, not a setting; the agent is opt-in per safe with hard timeouts (I18) |

## Explicitly out of scope — stated, not hidden

- **Root on edt1.** Root can read the helper's memory, replace the helper, and read the
  registry. Nothing here defends against that, and no password manager on any machine does.
  The mitigations in I14 (no core dumps, non-dumpable, best-effort `mlock`, millisecond
  process lifetime) raise the cost; they do not change the conclusion.
- **A compromised browser or endpoint.** If the machine typing the passphrase is owned, the
  passphrase is owned.
- **Cockpit's own authentication and TLS.** We depend on it and do not re-implement it.
- **Cryptanalysis of AES-256, ChaCha20, Twofish, Argon2 or SHA-256.** We implement the
  formats correctly; we do not second-guess their primitives.
- **Key escrow, recovery, and rotation of the safes' own master passphrases.** Losing the
  passphrase means losing the safe, by design.

## The one property everything else serves

> A decrypted value exists only inside one short-lived helper process, only after its MAC has
> verified, only for a caller the kernel says is entitled to it, and only for as long as one
> operation takes.
