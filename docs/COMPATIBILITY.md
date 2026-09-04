# Compatibility

What this build opens, what it writes, and — the part that matters more —
**how each row was established**. A row that says "verified" names the command
that verified it. A row that says "untested" says so plainly rather than being
quietly rolled into the row above it.

Measured on edt1, 2026-09-04, Python 3.14.4, `python3-pykeepass` 4.1.1,
`python3-botan` 3.10, `keepassxc-cli` 2.7.10 (**test oracle only** — it appears
in no runtime path).

Reproduce the whole table with:

    ./run_tests.sh

---

## 1. KeePass (KDBX)

| Format | Cipher | KDF | Read | Write | Evidence |
|---|---|---|---|---|---|
| KDBX 4.1 | AES-256 | Argon2id | yes | yes | `tests/integration/flow.py`; the file we wrote is then read back by `keepassxc-cli ls -R` / `show -a Password` with empty stderr |
| KDBX 4.1 | ChaCha20 | Argon2d | yes | yes | fixture `lab-kdbx41-chacha20-argon2d.kdbx`, opened and re-saved; `keepassxc-cli db-info` accepts the result |
| KDBX 4.0 | AES-256 | Argon2d | yes | yes | fixture `lab-kdbx40-aes256-argon2d.kdbx` |
| KDBX 4.x | AES-256 | AES-KDF | yes | yes | 60 000-round fixture built and opened |
| KDBX 3.1 | AES-256 | AES-KDF | yes | **no — `unsupported` (I20)** | `flow.py` asserts both halves: it reads, and `add`+autosave answers `unsupported` |
| KDBX 3.x / 4.x | **Twofish** | any | code exists | code exists | **UNTESTED — no fixture exists.** `keepassxc-cli` cannot create a Twofish database, so none could be built on this host. KDBX4 authentication is cipher-independent and IS covered; only the decryption itself is unexercised. KDBX3+Twofish needs `python3-botan` and raises `unsupported` without it rather than skipping the check. |

**KDBX 3.x is opened read-only on purpose.** The format has no authenticated
encryption: a tampered file decrypts to attacker-influenced data with nothing to
detect it. It is opened with a banner and every write answers `unsupported`,
which is a *different* code from the registry's `mode: "ro"` (`access-denied`)
and from the losslessness guard (`conflict`) — see §4.

### Credentials

| Credential | Supported | Evidence |
|---|---|---|
| passphrase | yes | every fixture |
| key file, 32-byte raw | yes | backend harness |
| key file, KeePass XML 1.0 | yes | backend harness |
| key file, KeePass XML 2.0 (hash-checked, constant-time) | yes | fixtures `*-keyfile-only.keyx`, `*-password-and-keyfile.keyx`; a corrupted `Hash` attribute gives `invalid` |
| passphrase **and** key file | yes | `flow.py` |
| key file only, `password_required: false` | yes | `flow.py`; `keepassxc-cli -k --no-password` opens the same file |
| **YubiKey challenge-response** | **no — `unsupported`** | `yubikey_slot` is validated, reported by `list`/`probe`, and passed to the backend, which raises `unsupported` naming the field. It is never silently downgraded to passphrase-only, because an operator who believes a second factor is in play when it is not is worse off than one who is told it is unavailable. |

### KeePass features

| Feature | Behaviour |
|---|---|
| entry history | browsable and restorable through the backend's additive API; **no verb exposes it yet**, so the UI has no History button |
| attachments | download works (`attach-get`); **add/replace/remove exist in the backend but have no verb**, so the UI has no upload |
| protected custom fields | revealed one at a time via `reveal` with `custom:<name>` |
| TOTP (KeePassXC `otp`, KeePass 2.x `TimeOtp-*`) | yes; codes match `keepassxc-cli show -t` and pyotp |
| HOTP (`HmacOtp-*`) | code returned at the counter **stored in the file**; the counter is **not advanced**, because a read verb that dirties the database is a save waiting to surprise someone |
| recycle bin | honoured; `rm` reports `recycled: true/false` |
| KDBX 3 → 4 upgrade | implemented (`upgrade_to_kdbx4`), **no verb exposes it yet** |

---

## 2. Password Safe (PWS3)

| Aspect | Behaviour | Evidence |
|---|---|---|
| format V3 (`PWS3` tag) | read + write | `tests/integration/flow.py`; `python3 -m backends.psafe3` |
| Twofish-CBC | Botan primary, pure-Python fallback | **728 published ECB vectors pass on both providers** (Schneier's `ecb_ival.txt` and Botan's `twofish.vec`, digests recorded in `tests/vectors/twofish_ecb.json`) |
| key stretch (`[KEYSTRETCH]` §4.1) | read 2048…8 388 608; **write floor 262 144** | a legacy file below the floor is re-stretched at unlock and saved at the floor |
| unknown header and record fields | preserved byte-for-byte | round-trip asserted field-by-field, and by the independent Go oracle |
| `0x11 Empty Groups` | preserved; dropped for a group that gains a member, per §3.2 note [16] | |
| attachments (§3.3 note [30]) | one per record, read via `attach-get` | **no populated attachment fixture exists** in this format |
| TOTP | Config hash 0x00 (SHA-1) only; 0x01–0x03 raise `unsupported` | RFC 6238 appendix-B vectors |
| tags | **always `[]`** — PWS3 §3.3 defines no tag field | synthesising them from the group path would invent data the file does not contain |
| recycle bin | **none** — `rm` always reports `recycled: false` | the backup ring is the only undo, so the UI must confirm a delete explicitly |
| key file | **none — `unsupported`** | PWS3 has no key-file concept; a non-empty key file is refused rather than ignored |
| `version` from `probe` | reports `"3"` | the format sub-version lives in the ENCRYPTED header, so a locked probe cannot honestly report more |
| a database we CREATE | stamped 0x030D (V3.30) | old enough that every maintained client reads it without a "newer format" prompt |
| a database we OPENED | keeps its own declared version | bumping it because we saved would claim features we did not add |

### Interop evidence for PWS3, honestly ranked

There is **no foreign PWS3 implementation on this host.** Ubuntu's
`passwordsafe` ships `/usr/bin/pwsafe`, the GUI, and no CLI. Driving it
headlessly was attempted and does not work: under Xvfb it maps **zero windows**
(`xwininfo -root -children` reports no children), so there is nothing to type
into, and `--validate=FILE` never returns.

In descending strength:

1. **The published Twofish ECB vectors** — genuinely foreign, and they caught a
   real bug in the pure-Python implementation during development.
2. **`tests/oracle/pws3_oracle`** — an independent Go implementation written
   from the spec by an author who had not read the Python. Both directions
   round-trip. It is a second opinion, not an outside authority.
3. **A second reader/writer written from the spec** in a scratchpad, sharing no
   code with the module but sharing an author.
4. **The KDF checked against pwsafe's own `StretchKey` source.**

**A file written by the real Password Safe GUI, opened by us, remains the
missing piece.** It needs a human at a GUI. I19 stays **partially open** for
PWS3, and `tests/fixtures/README.md` carries the same table.

By contrast, KDBX interop is closed: `keepassxc-cli` is a genuinely foreign
implementation, it reads every file we write, and we read every file it writes.

---

## 3. Host and platform

| Component | Version | Note |
|---|---|---|
| Cockpit | 360 | `superuser: "try"`; the page is usable unescalated for user-class safes |
| Python | 3.14.4 | distro |
| `python3-pykeepass` | 4.1.1 | forces the GPL-3.0 licence |
| `python3-botan` | 3.10 | Twofish; lazily imported, so a KDBX unlock never pulls it in |
| `python3-cryptography` | 46.0.5 | |
| `python3-jsonschema` | 4.19.2 | optional — the built-in validator is the enforcement point and runs either way; the gate only ever REMOVES entries, so its absence cannot admit one |
| `keepassxc-cli` | 2.7.10 | **test oracle only.** It appears in `tests/oracle/`, `tests/fixtures/` and the corpus `--check` and nowhere else |
| browser | Cockpit's default CSP (`default-src 'self'`) | no inline script/style, no `eval`, no WASM, no CSP relaxation |

### Two upstream defects found and worked around

Both are in `pykeepass`, both are reachable from ordinary use, and both are
fixed inside `backends/kdbx.py` rather than reported and lived with:

1. **XPath injection reachable from `reveal(uuid, field)`.**
   `Entry._get_string_field()` formats the field name into
   `String/Key[text()="{}"]/../Value` and hands it to lxml. Measured before the
   fix: a crafted field name returned **another field's protected value**. All
   field access is now done by comparing element text in Python. *Anyone else
   passing caller-supplied text to a pykeepass `find_*` / `set_custom_property`
   call has the same bug.*
2. **`delete_binary()` corrupts attachment references.** It renumbers via
   `find_attachments()`, which does not descend into `History`, leaving
   `Binary/Value/@Ref` attributes pointing one slot too high — at someone else's
   bytes. Caught because `keepassxc-cli` reported `Unmapped keys left.`
   Deletion is now reference-counted over the whole tree.

---

## 4. Error codes an operator will meet

Three separate causes of "cannot write", three separate codes. This is
deliberate: collapsing them would tell an operator to fix the wrong thing.

| Cause | Code | What to do |
|---|---|---|
| registry `mode: "ro"` | `access-denied` | change the registry entry |
| KDBX 3.x (I20) | `unsupported` | convert the database to KDBX 4 |
| the losslessness guard tripped (I22) | `conflict` | the save would have dropped a field this build cannot represent; do not force it |
| the file changed on disk since unlock | `conflict` | re-open and redo the change. **Never merge** |
| a lock file held by someone else | `conflict` naming the holder | close it in that client, or set `override_stale` if you know the holder is gone |

A **wrong passphrase and a failed MAC are the same code with the same detail
string** (`bad-credential`), on purpose (I6), and the failure path has a
constant-time floor. Measured: a wrong passphrase takes ~0.90–1.01 s against
~0.30 s for a right one on these fixtures — the wrong path is *slower*, never
faster, and a structurally broken file is floored identically.

---

## 5. Not compatible, and not claimed to be

- **`secrets-agent` (I18) does not exist.** The `agent` block is validated and
  reported, and the `session` field is plumbed through, but nothing creates a
  socket. The default — **prompt on every unlock** — is what actually runs, and
  it is true by construction rather than by policy: one helper process per
  operation, no handle that outlives it.
- **No `export` verb (I21).** `export_allowed` is validated and reported by
  `list`; no verb consumes it.
- **No master-passphrase rotation and no create-a-safe verb.** Use the desktop
  client; `docs/OPERATIONS.md` gives the procedure.
- **No `save-as`, no restore-from-backup verb.** The backup ring is on disk and
  an operator restores from it by hand. The UI renders the "Save as…" button
  disabled with that reason, rather than pretending.
- **The `euid == 0` admin path is verified only from the refusing side** by the
  standing suite, because nothing in it runs as root. The allowing side was
  exercised once through the `/srv/jobs` runner during development; re-running
  it is a root job, not a test.
