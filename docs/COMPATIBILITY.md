# Compatibility

What this build opens, what it writes, what interoperates — and, the part that
decides whether any of it is worth reading, **how each row was established.**

A row in §2–§7 names the command that produced it and was run on this host
while this file was being written. Anything believed but never actually run is
in **[§8, "Believed but NOT verified"](#8-believed-but-not-verified)**, on its
own, under its own heading, so that no reader can mistake one for the other.
That separation is the whole point: `docs/KNOWN_ISSUES.md` **I19** says
*"'compliant' is a claim, not a test result"*, and a table that quietly mixes
the two is exactly how a claim gets mistaken for a result.

Measured on **edt1, 2026-09-04**.

---

## 1. Exact versions tested

Nothing below was inferred from a package name; each was asked for its version
on this host.

| Component | Version | Role |
|---|---|---|
| Cockpit | **360** | the host service. `superuser: "try"`; the page is usable unescalated for user-class safes |
| Python | **3.14.4** | distro |
| `python3-pykeepass` | **4.1.1.post1** | **runtime** — the KDBX engine. Forces the GPL-3.0 licence on this package |
| `python3-botan` | **Botan 3.10.0** (Ubuntu) | **runtime** — Twofish. Lazily imported, so a KDBX AES unlock never pulls it in |
| `python3-cryptography` | **46.0.5** | runtime — AES, ChaCha20, SHA, HMAC |
| `python3-argon2` (`argon2-cffi`) | **25.1.0** | runtime — Argon2d/id |
| `python3-pyotp` | **2.9.0** | runtime — TOTP |
| `python3-lxml` / `python3-construct` | **6.0.2** / **2.10.68** | runtime — pykeepass dependencies |
| `python3-jsonschema` | **4.19.2** | optional. The helper's built-in registry validator is the enforcement point and runs either way; the extra gate can only ever *remove* an entry, so its absence cannot admit one |
| `keepassxc-cli` | **2.7.10** | **TEST ONLY** — the foreign KDBX oracle. It appears in `tests/`, and in no runtime path |
| `passwordsafe` (`/usr/bin/pwsafe`) | **1.22.0+dfsg-1** | test — GUI only. See §3.3; it produced nothing |
| Go | **go1.26.0 linux/amd64** | test — builds `tests/oracle/pws3_oracle` offline from the module cache |
| `gjs` (SpiderMonkey) | **1.88.0** | test — the JavaScript syntax gate (`check.sh`) and the function-map's JS parser |
| Node | **v22.22.1** | test — runs the browser driver |
| Playwright | **1.62.1** | test — resolved from `/opt/sc/edy-local/e2e/node_modules`, not vendored here |
| Browser | **Chrome for Testing 151.0.7922.34** (Chromium 151) | test — what `tests/browser/ui.spec.js` actually drives |
| Browser policy | Cockpit's default CSP, `default-src 'self'` | no inline script/style, no `eval`, no WASM, **no CSP relaxation** (I9) |

Reproduce §2–§7 with the two commands below. Their results on this host, on the
day this file was written:

| Command | Result (re-run from a clean tree, 2026-09-04, VERSION 0.2.1) |
|---|---|
| `./validate.sh` | OK — **47 PASS / 0 FAIL**, plus `Ran 38 tests … OK` |
| `./check.sh` | `secrets.js syntax OK` |
| `python3 backends/base.py` | PASS — 118 checks, 0 failures |
| `python3 -m backends.psafe3` | PASS — 18 checks, `psafe3 self-check: OK` |
| `python3 -m backends.kdbx` | PASS — 28 checks, `kdbx self-check: OK` |
| `python3 agent/secrets_agent.py --selfcheck` | PASS — 61 checks, 0 failures |
| twofish ECB vectors, both providers | PASS — 728 vectors × 2 providers, encrypt **and** decrypt, 0 failures |
| `tests/integration/flow.py` | PASS — 86 checks, 0 failures (10 s) |
| `tests/integration/conformance.py` | PASS — 83 checks, 0 failures (2 s) |
| `tests/integration/properties.py` | PASS — 27 checks, 0 failures (18 s) |
| `tests/integration/newverbs.py` | PASS — 220 checks, 0 failures (12 s) |
| `tests/integration/agent_cycle.py` | PASS — 45 checks, 0 failures (6 s) |
| `tests/integration/adversarial.py` | PASS — 73 checks, 0 failures (13 s) |
| `tests/integration/corpus_vs_helper.py` | PASS — 67 checks, 0 failures (83 s) |
| `tests/corpus/gen_corpus.py --check` | PASS — 67 cases, 0 disagreed with their sidecar |
| `tests/oracle/build.sh` | PASS — the Go oracle's known-answer vectors |
| `tests/fixtures/gen_fixtures.sh` | PASS — 33 checks; every fixture re-verified by `keepassxc-cli` |
| `node tests/browser/ui.spec.js` | **244 passed, 0 failed** |
| `./run_tests.sh` | **17 of 17 stages PASS**, exit 0 |
| `./tests/browser/run-live.sh` (the LIVE page) | **129/130** — one FAIL, and it is a defect in the test: KNOWN_ISSUES **I42** |
| the KDBX interop matrix (§2.2) | **14/14** |
| the PWS3 oracle matrix (§3.2) | **7/7** |

    ./run_tests.sh                     # everything above except the browser
    node tests/browser/ui.spec.js      # the page, in a real browser

---

## 2. KeePass (KDBX)

### 2.1 Formats read and written

| Format | Cipher | KDF | Read | Write | Evidence |
|---|---|---|---|---|---|
| KDBX 4.1 | AES-256 | Argon2id | yes | yes | `probe` reports `4.1 / argon2id`; unlock→edit→save→`keepassxc-cli db-info` + `ls -R -f` + `show -s` all clean |
| KDBX 4.1 | ChaCha20 | Argon2d | yes | yes | same round trip on `lab-kdbx41-chacha20-argon2d.kdbx` |
| KDBX 4.0 | AES-256 | Argon2d | yes | yes | same round trip on `lab-kdbx40-aes256-argon2d.kdbx` |
| **KDBX 4.0** | **Twofish-256** | **Argon2d** | **yes** | — | **new fixture, and it is no longer an untested row.** `lab-kdbx40-twofish-argon2d.kdbx` opens here (`probe` → `4.0 / argon2d`, 2 entries, sentinel revealed) *and* in `keepassxc-cli db-info`, which reports **`Cipher: Twofish 256-bit`**. See §8 for the part of the Twofish story that is still unverified |
| KDBX 3.1 | AES-256 | **AES-KDF** | yes | **no — `unsupported`** | `probe` reports `3.1 / aes-kdf, iterations 1000000`, sets `writable: false` and returns the I20 banner; `edit` and `save` both answer `unsupported` with the reason. This is the only AES-KDF row that has a file — see §8 for KDBX 4 + AES-KDF |

**KDBX 3.x is opened read-only on purpose (I20).** The format has no
authenticated encryption: a tampered file decrypts to attacker-influenced data
with nothing to detect it. Measured refusal detail:

> `KDBX 3.x has no authenticated encryption, so this backend opens it
> read-only; use upgrade_to_kdbx4 to convert it`

That is a *different* code from the registry's `mode: "ro"` (`access-denied`)
and from the losslessness guard (`conflict`) — see §6.

### 2.2 The interop matrix

Seven operations, both directions — the six the interop question asks for, plus
attachment *removal*, which is where the interesting failure lives (§7).
**"by us"** means our backend performed the operation and wrote the file and
`keepassxc-cli` then had to accept the result; **"by keepassxc-cli"** means the
reverse. Run with the harness described in §2.5. Every row below is a real
result and **all 14 passed**; the byte counts are from the pristine
`lab-kdbx41-aes256-argon2id.kdbx`.

| Operation | Written by **us** → read by `keepassxc-cli` | Written by **`keepassxc-cli`** → read by **us** |
|---|---|---|
| **create** | `save_as` to a fresh path wrote **4 021 bytes, mode 0600**; `db-info`, `ls -R -f` and `show -s` all accept it and the sentinel is present. (There is no create-from-nothing verb — see §9 — so `save_as` is what "create" means here) | `db-create` + `add` → we `probe` it as **3.1 / aes-kdf** and list the entry. `db-create` has no cipher/format switch and *always* writes KDBX 3.1 + AES-KDF |
| **edit** | username, password and notes all read back **exactly** by `show -s -a` | `edit -u --url --notes -p` → our `reveal` returns all four fields exactly |
| **add attachment** | 1 024 bytes attached, then recovered **byte-identical** by `attachment-export`; the entry's pre-existing attachments are still listed and `db-info` reports no `Unmapped keys left.` | `attachment-import` of 768 bytes → our `attach_get` returns identical bytes and the entry lists 3 attachments |
| **remove attachment** | one of two removed; `keepassxc-cli` reports **no `Unmapped keys left.`** and the surviving `blob.bin` still exports byte-identical (256 bytes). This is the row that catches the `pykeepass.delete_binary()` defect in §7 | `attachment-rm` is symmetrical and covered by the round trip above |
| **add custom field** | plain **and** protected custom fields both read back by name; `show --all` prints ours as `PROTECTED` **exactly** as it prints the fixture's own protected field, which KeePassXC itself wrote | `keepassxc-cli` has no `--set-attribute`; `import` of KeePass2 XML is the only way it writes one, and that is how the fixtures were made. We read the plain `Lab Ticket` = `LAB-4711` and the protected `API Token` from a database `import` produced |
| **delete to recycle bin** | `rm(permanent=False)` reports `recycled: true` and `ls -R -f` shows `/Recycle Bin/Expiring Account` | `rm` → we see the `Recycle Bin` group and the entry still present |
| **save** (no semantic change) | edit + `save` → tree unchanged, `db-info`/`ls`/`show` clean, backup ring written | `edit -t` rewrites the file (digest changes); we still open it as **4.1 / argon2id**, 6 entries, sentinel intact |

**`export_plain` against KeePassXC's own exporter**, since that is the newest
and most dangerous surface:

| | ours | `keepassxc-cli export` |
|---|---|---|
| CSV | 1 742 B — **the same ten column headers KeePassXC emits, in the same order** (`Group, Title, Username, Password, URL, Notes, TOTP, Icon, Last Modified, Created`), plus five it does not have (`Tags`, `Expires`, `Expiry Time`, `Attachments`, `Custom Fields`) | 1 295 B |
| XML | 22 087 B — root element `KeePassFile`, an element vocabulary **identical** to theirs (no tag in one that is missing from the other), and the same **9** `Entry` elements | 18 785 B |
| JSON | 8 081 B — ours only; KeePassXC has no JSON export | — |
| HTML | `unsupported` | ≈3.9 kB |

Both exporters put the sentinel in the clear, which is the point of §5.

### 2.3 Credentials

All three key-file forms were built from one 32-byte secret, used to create a
database, and then **unlocked, edited, `save`d and `save_as`ed** here — with
`keepassxc-cli` reading every result:

| Credential | Supported | Evidence |
|---|---|---|
| passphrase | yes | every fixture |
| key file, **32-byte raw** | yes | `unlock` ok, 1 entry, password revealed; `save` 1 525 B, `save_as` 1 525 B; `keepassxc-cli ls -R -f -k` reads both, rc 0 |
| key file, **KeePass XML 1.00** (`<Data>` base64, no `Hash`) | yes | same round trip; `keepassxc-cli` rc 0 |
| key file, **KeePass XML 2.0** (hex `<Data Hash="…">`, hash-checked) | yes | same round trip; `keepassxc-cli` rc 0. The committed `lab-kdbx41-*.keyx` fixtures are this form |
| a **corrupted** XML 2.0 `Hash` attribute | refused | `invalid` — *"the XML key file failed its own integrity check"* |
| passphrase **and** key file | yes | `lab-kdbx-pwkf` unlocks, 6 entries |
| key file only, `password_required: false` | yes | `lab-kdbx-kf` unlocks, 6 entries; `keepassxc-cli ls --no-password -k` opens the same file, rc 0 |
| **YubiKey challenge-response** | **plumbing works; the hardware path is UNVERIFIED** | see §8. The four registry/request combinations were measured and each behaves as designed — but there is **no token on this host** and no database keyed with a challenge component, so the composite-key construction has never been proved against anything |

### 2.4 KeePass features

| Feature | Behaviour | Evidence |
|---|---|---|
| entry history | browsable and restorable, and the **`history` verb never returns a password**: the keys are `index, when, title, username, url, has_password, notes_len, has_totp, attachments` | `history` on a twice-saved entry returned 2 versions with exactly those keys |
| `history-restore` | in memory only; returns `{uuid, restored_from, saved:false}` | measured |
| attachments | `attach-get` / `attach-add` / `attach-rm` all have verbs and all round-trip through `keepassxc-cli` | §2.2 |
| custom fields | present, protected-flag honoured — **but the documented `reveal` spelling is broken.** See the finding below | §2.2, §6 |
| TOTP (KeePassXC `otp`, KeePass 2.x `TimeOtp-*`) | yes | **our code, `pyotp` and `keepassxc-cli show -t` returned the identical 6 digits** in the same window |
| HOTP (`HmacOtp-*`) | code returned at the counter **stored in the file**; the counter is **not advanced** | measured: `HmacOtp-Secret-Base32` + `HmacOtp-Counter=7` on a real entry gave `449891`, identical to `pyotp.HOTP(seed).at(7)`; calling it twice returned the same code and the file still says `7`. A read verb that dirties the database is a save waiting to surprise someone |
| recycle bin | honoured; `rm` reports `recycled: true/false` | §2.2 |
| `save-as` | takes a **name**, never a path — the copy is created beside the safe (I4) | verb returned `{path, bytes: 4 021, name, ok}` and `keepassxc-cli ls -R -f` read the result |
| `backups` / `restore-backup` | the ring is listed and restorable through verbs | `backups` returned the ring directory, `keep: 3` |
| KDBX 3 → 4 upgrade | implemented (`upgrade_to_kdbx4`) | no verb exposes it |

> ### FIXED — `reveal` could not reach a custom field, or the TOTP seed
>
> **Found, recorded and then fixed during integration.** `docs/CONTRACT.md`
> and the helper's own schema both say a custom field is revealed as
> **`custom:<name>`**, and the helper's `_FIELD_RE` accepts only that
> spelling. The KDBX backend did not strip the prefix: it looked up a `String`
> element literally named `custom:Lab Ticket` and did not find one. The schema
> also publishes `totp` (labelled "TOTP secret") as a `reveal` option, and
> neither backend mapped that name to its own name for the seed. Measured end
> to end through the real helper, before:
>
> ```
> reveal field="custom:Lab Ticket"  -> {"error":"not-found","detail":"no such field"}
> reveal field="totp"               -> {"error":"not-found","detail":"no such field"}
> reveal field="Lab Ticket"         -> {"error":"invalid", ...}   # the regex refuses it
> ```
>
> So no custom field, protected or plain, was revealable through the helper on
> either format, and the page's "reveal this custom field" control could not
> work. Each half was individually correct — the helper's vocabulary, the
> backend's storage — which is why only an end-to-end check found it.
>
> The mapping from a contract field name to a storage key is what a backend is
> for, so the fix is on that side of the boundary and is different for each
> format. KDBX strips `custom:` and looks the remainder up among the
> NON-RESERVED string fields only, so `custom:Password` is not-found rather
> than a second door to the master password behind an audit line that says
> "custom field". PWS3 answers `unsupported` naming the reason: a record is a
> list of TYPED fields and a type appears at most once, so there is no
> name-keyed space to look a name up in. After:
>
> ```
> kdbx   custom:Lab Ticket -> {"field":"custom:Lab Ticket","value":"…",
>                              "resolved_field":"Lab Ticket"}
> kdbx   custom:Password   -> {"error":"not-found"}
> kdbx   totp              -> the otpauth:// seed
> psafe3 custom:anything   -> {"error":"unsupported","detail":"Password Safe v3
>                              records carry typed fields, not named custom …"}
> psafe3 totp              -> the seed as unpadded base32
> ```
>
> Standing check: `tests/integration/newverbs.py`, section "reveal — every
> published field name reaches a value", walks the whole published vocabulary
> on both formats, so a future name added to the schema without a backend
> mapping fails immediately.

### 2.5 How the matrix was run

A scratch harness (not part of the package) copies a fixture into a private
`0700` directory, drives `backends/kdbx.py` directly for our half, and shells
out to `keepassxc-cli` for the foreign half, with the passphrase on **stdin**
in both directions — `keepassxc-cli` has no `--password` option at all, which
is upstream's own good design and the house rule here too (I10). The whole
matrix is 14 checks and all 14 passed.

---

## 3. Password Safe (PWS3)

### 3.1 What the backend does

| Aspect | Behaviour | Evidence |
|---|---|---|
| format V3 (`PWS3` tag) | read + write | `probe` → `version 3, kdf pws3-sha256, iterations 262144`; unlock/edit/save all `ok` |
| Twofish-CBC | Botan primary, pure-Python fallback | **728 published ECB vectors pass on both providers** (178×128-bit, 243×192-bit, 307×256-bit) |
| key stretch (`[KEYSTRETCH]` §4.1) | read 2 048…8 388 608; **write floor 262 144** | a legacy file below the floor is re-stretched at unlock and saved at the floor |
| unknown header and record fields | preserved byte-for-byte | the Go oracle reads types `0x1b` and `0xc0` **identically** before and after we rewrite the file |
| `0x11 Empty Groups` | both occurrences preserved; dropped for a group that gains a member, per §3.2 note [16] | measured: `['Empty','Empty.Deeper']` → `['Empty.Deeper']` after adding an entry to `Empty` |
| attachments (§3.3 note [30]) | `attach_add` / `attach_rm` / `attach_get` all work, one per record | `attach_add` → `{ok, name, size}`; `attach_get` after `attach_rm` → `not-found` |
| entry history | the field is modelled; the fixture record has none, so `history` returns `[]` and `history_restore` answers `not-found: this entry has no password history` | measured |
| `export_plain` | **`csv` and `json` yes; `xml` raises `unsupported`** | the refusal detail is the reason: *"Password Safe v3's XML export is a GUI feature with its own schema, not part of the file format; this backend will not emit a file claiming to be it"* |
| `save_as` | yes | wrote 1 096 bytes after a delete in the same session, and **the Go oracle then verified its HMAC** (`hmac_ok: true`, the 3 surviving records, `iter 262144`, `version 0x0311` carried through) |
| TOTP | Config hash 0x00 (SHA-1) only; 0x01–0x03 raise `unsupported` | measured: a Two-Factor Key field set to the RFC's example seed produced `516814`, identical to `pyotp.TOTP(seed).now()`; setting `0x0d TOTP Config` to `0x01` then gave *"this entry uses a reserved TOTP hash algorithm"* |
| tags | **always `[]`** — PWS3 §3.3 defines no tag field | verified across every record: synthesising them from the group path would invent data the file does not contain |
| recycle bin | **none** — `rm` always reports `recycled: false` | measured. The backup ring is the only undo, so the UI must confirm a delete explicitly |
| key file | **none — `unsupported`** | `unlock` with `keyfile_b64` → *"Password Safe v3 has no key-file support"*. Refused, never ignored |
| `version` from `probe` | reports `"3"` | the format sub-version lives in the ENCRYPTED header, so a locked probe cannot honestly report more |
| a database with **no** Version header field | stamped 0x030D (V3.30) on write | old enough that every maintained client reads it without a "newer format" prompt. Note that 0x030D is *below* the 0x030F attachments were introduced in, so such a database cannot take one until an operator raises its declared version |
| a database we OPENED | keeps its own declared version | verified: the fixture goes in and comes out `0x0311`. Bumping it because we saved would claim features we did not add |

### 3.2 The oracle matrix, both directions

`tests/oracle/pws3_oracle` is an independent Go implementation written from
`formatV3.txt` v3.31. Seven checks, all passed:

| Check | Direction | Result |
|---|---|---|
| oracle writes, we read | Go → us | 1 560 bytes / 4 records; we probe it and reveal the sentinel |
| non-ASCII survives | Go → us | `Ünïcødé — 日本語 🔐` intact |
| we write, oracle reads | us → Go | **the oracle verifies our HMAC** and reads back the edited `Username` and `Notes`; header field count unchanged (11 → 11), 4 records |
| unknown fields preserved | us → Go | `0x1b` and `0xc0` byte-identical across our rewrite; both repeated `0x11` kept |
| empty-group rule §3.2[16] | us → Go | the group that gained a member stops being declared empty; the other is kept |
| wrong passphrase, same code | both | ours and the oracle both answer `bad-credential`, with no way to tell a wrong passphrase from a failed MAC |
| the added interface | us | `export csv`/`json` ok, `xml` `unsupported`, `history` `[]`, `attach_add`/`attach_rm` ok, `save_as` ok |

### 3.3 PWS3's oracle is weaker than KDBX's, and here is exactly how

**No file written by the real Password Safe GUI exists here, and none can be
produced on this host.** That is not an omission; it was attempted again while
writing this file, with a control to prove the tooling was not at fault:

| Attempt | Result (measured 2026-09-04) |
|---|---|
| `pwsafe --help`, with and without a display | prints its usage on **stderr** and exits **255** — not 0. (`docs/HOST-FACTS.md` records exit 0; this run disagrees, and the option list it prints is the same) |
| `timeout 45 xvfb-run -a pwsafe --validate=FILE </dev/null` | **rc 124 — timed out.** Zero bytes on stdout, zero on stderr |
| `Xvfb :97` + `pwsafe --validate=FILE`, waited 25 s, then `xwininfo -root -children` | process alive, **0 children** — no window mapped at all, nothing for `xdotool` to type into, no output on either stream |
| **control:** `xmessage` on the *same* Xvfb | **1 child** — `0x200024 "xmessage"`. The display server is fine; `pwsafe` is what maps nothing |

The control is the addition. It rules out "our Xvfb is broken" and leaves only
"this program cannot be driven without a human at a GUI."

So, in descending strength, what PWS3 compliance actually rests on:

1. **The published Twofish ECB vectors** — genuinely foreign (Schneier's
   `ecb_ival.txt` and Botan's `twofish.vec`), 728 of them, passing on both the
   Botan and the pure-Python provider.
2. **A third Twofish implementation** — Perl's `Crypt::Twofish` 2.18, used in
   §8 to check the KDBX3 Twofish-CBC path that has no fixture.
3. **`tests/oracle/pws3_oracle`** — an independent Go implementation, written
   from the spec by an author who had not read the Python, using
   `golang.org/x/crypto/twofish`. Both directions round-trip and it verifies
   our HMAC. It is a second opinion, not an outside authority.
4. **The key stretch checked for SHAPE, not just for agreement.**
   `pws3_oracle vectors` asserts `X0 = SHA256(pass‖salt)`, `Xi = SHA256(Xi-1)`,
   `P' = X_ITER` — iterated SHA-256, *not* PBKDF2 — and returns
   `keystretch_shape_ok: true`. That exists so nobody can quietly "fix" it into
   PBKDF2 and have both implementations agree with each other and with nothing
   else. Measured on this host together with the three all-zero-key Twofish ECB
   vectors, which the same command reports as matching for 128, 192 and 256
   bits.

**I19 therefore stays partially open for PWS3.** By contrast, KDBX interop is
closed: `keepassxc-cli` is a genuinely foreign implementation, it reads every
file we write, and we read every file it writes.

---

## 4. The corpus

`tests/corpus/` holds **67 deliberately malformed files** — truncations at every
structural boundary, flipped header and HMAC bytes, Argon2 parameters demanding
4 GiB, billion-laughs XML, compression bombs, a PWS3 file whose MAC covers the
padded blocks instead of the field data. `corpus_vs_helper.py` asserts the
helper's answer for each: **67 checks, 0 failures**, slowest refusal
`kdbx41-compression-bomb-size.kdbx` at 1.22 s against a 15 s budget — no case
takes the helper out the way four of them take the oracle out.

Two measured facts about the oracle here, both recorded in `gen_corpus.py`:

* **Five cases open cleanly in `keepassxc-cli`** and must still be refused by
  us — the two compression bombs, the deep-nesting XML, the duplicate-UUID
  database and the external-entity document. KeePassXC has no decompression
  cap, no group-depth cap and no UUID-uniqueness check, so this is the one
  place where the foreign oracle is silent and `Limits` in `backends/base.py`
  is the only defence.
* **Four cases take `keepassxc-cli` out entirely** — it hangs past the 25 s
  budget on the Argon2 `t=10⁶` and `m=4 GiB` bombs, the AES-KDF 10⁹ bomb and
  the duplicate-UUID file. A timeout is neither "opened" nor "refused"; it is
  the oracle being defeated by the file, and the corpus records it as such
  rather than scoring it.

---

## 5. Exports and the plaintext surface (I21)

`export_plain()` is the single most dangerous method in this package: it
returns **every secret in the database, in the clear, in one buffer.** Its
gating was measured, not assumed:

| Check | Result |
|---|---|
| `export` verb on a **user-class** safe | `access-denied` — *"export is an administrator-class verb; this safe is user-class"* |
| `export_allowed` in the registry | validated and reported by `list` |
| the allowed path (admin class, `export_allowed: true`) | **not exercised — it needs euid 0.** See §8 |

---

## 6. Error codes an operator will meet

Five separate causes of "cannot write". They are deliberately *not* collapsed
into one code, because an operator acts on each differently — though three of
them do share `conflict`, and the detail string is what separates those. All
five measured through the real helper:

| Cause | Code | Measured detail | What to do |
|---|---|---|---|
| registry `mode: "ro"` | `access-denied` | — | change the registry entry |
| KDBX 3.x (I20) | `unsupported` | *"KDBX 3.x has no authenticated encryption…use upgrade_to_kdbx4"* | convert the database to KDBX 4 |
| the file changed on disk since unlock | `conflict` | *"the safe file changed on disk since it was unlocked"* | re-open and redo the change. **Never merge** |
| a lock file held by someone else | `conflict` **naming the holder** | *"the safe is locked by [Lock] Time=… ID=… User=someone Machine=elsewhere; close it there, or override the stale lock explicitly"* | close it in that client, or set `override_stale` if you know the holder is gone |
| the losslessness guard tripped (I22) | `conflict` | — | the save would drop a field this build cannot represent; do not force it |

Other measured codes:

| Situation | Code | Detail |
|---|---|---|
| wrong passphrase | `bad-credential` | *"the passphrase, key file or file integrity check did not match this safe"* |
| a failed MAC | `bad-credential` | **the identical string.** The distinction is in the audit log only (I6). Measured across the corpus: `kdbx41-flip-header-hmac`, `kdbx41-flip-block-hmac`, `kdbx41-flip-ciphertext`, `kdbx31-flip-ciphertext`, `pws3-flip-hmac` and `pws3-flip-ciphertext` all answer `bad-credential`, at 0.91–1.04 s — the same code, the same detail and the same timing band as a wrong passphrase |
| `yubikey_response` for a safe with no `yubikey_slot` | `invalid` | *"this safe registers no yubikey_slot, so a hardware-key response is not part of its credential"* |
| a safe with `yubikey_slot` and no response | `bad-credential` | the same string as a wrong passphrase, so the failure cannot say which factor was missing |
| `yubikey_response` on a KDBX 3.x safe | `unsupported` | *"challenge-response is implemented for KDBX 4 only: KeePassXC folds the token's answer into the final key rather than the composite key for KDBX 3.x"* |
| key file supplied to a PWS3 safe | `unsupported` | *"Password Safe v3 has no key-file support"* |
| `reveal` of a custom field | `not-found` | **a defect — see the finding in §2.4** |

### The constant-time floor, measured

Five unlocks each way against `lab-kdbx41`, lockout counter cleared between:

| | min | max |
|---|---|---|
| correct passphrase | **0.312 s** | 0.326 s |
| wrong passphrase | **1.007 s** | 1.019 s |

The wrong path is *slower* than the right one on every sample and never faster,
which is the property the floor exists to provide.
`tests/integration/properties.py` measured the same thing independently and for
both formats: KDBX wrong 1.044 s vs right 0.347 s, PWS3 wrong 0.917 s vs right
0.318 s, every failure over the 0.75 s floor — **and a structurally broken file
(`invalid: this file is not a KeePass database`) is floored identically at
1.045 s**, so the failure shape cannot be used to tell a wrong passphrase from a
corrupt file by timing either.

---

## 6a. The browser half

`node tests/browser/ui.spec.js` serves the real `index.html`, `secrets.js` and
`secrets.css` (there is no build step, so what the test loads is what
`install.sh` copies), stubs only `cockpit.spawn`, and drives **Chromium 151**
through Playwright 1.62.1. Result on this host:

    124 passed, 0 failed

The rows that belong in a compatibility record rather than a test log:

| Claim | Measured |
|---|---|
| the page draws everything the helper declares | **all 14 declared control types render**, 14 fields for 14 controls; **all 32 declared verbs are reachable** through the UI |
| nothing persists in the browser (I11) | `localStorage` 0 keys, `sessionStorage` 0 keys, no cookie set, after a real unlock |
| the passphrase path (I10) | the passphrase **never appeared on argv** and **did** travel in a request body on stdin — checked against what the stub actually received, not against what the page meant to send |
| the passphrase field | no `name`, `autocomplete="off"`, not inside a `<form>` |
| no CSP relaxation (I9) | no `eval`, no `Function`, no `WebAssembly`, no inline `<style>`/`<script>`, and `secrets.js` **names no browser storage API at all** |
| YubiKey UI | the touch prompt, the declared slot and the full challenge are shown; an `unsupported` backend is reported as exactly that, the page states it will **not** fall back to passphrase-only, and exactly **one** unlock is attempted — never a silent retry |
| accessibility | labelled `aria-modal` dialog, focus moves in on open, the trap holds for 30 tabs, Escape closes, status region polite / error region assertive, **0 px horizontal overflow at 640 px** |
| console | no uncaught page error and no console error anywhere in the walkthrough |

What this does **not** cover is in §8: the stub records `superuser: "require"`
but never honours it, so the escalation path has never run against a real
Cockpit bridge.

---

## 7. Two upstream defects found and worked around

Both are in `pykeepass`, both are reachable from ordinary use, and both are
fixed inside `backends/kdbx.py` rather than reported and lived with.

1. **XPath injection reachable from `reveal(uuid, field)`.**
   `Entry._get_string_field()` formats the field name into
   `String/Key[text()="{}"]/../Value` and hands it to lxml. Measured before the
   fix (recorded in `docs/UPSTREAM-REVIEW.md`): a crafted field name returned
   **another field's protected value**. All field access is now done by
   comparing element text in Python. **Re-checked while writing this file:**
   three injection payloads — including
   `Lab Ticket"]/../Value|//String[Key="Password"]/Value["` — all answer
   `not-found` and none returns the sentinel, while the plain name `Lab Ticket`
   still returns `LAB-4711`. *Anyone else passing caller-supplied text to a
   pykeepass `find_*` / `set_custom_property` call has the same bug.*

   **That warning was right and was not acted on.** `KdbxBackend.add()` was the
   other call site: `PyKeePass.add_entry` opens by calling
   `find_entries(title=…, username=…)` unconditionally, before it even looks at
   `force_creation`, so an entry titled `a"b` — a legal KeePass title — answered
   `internal / "the KDBX engine could not open this database"`, which was both a
   verb the caller could not use and a sentence that was false. Fixed in the
   same way (`add_entry` is called with constant empty strings and the two
   fields are written by `_set_field`), and `validate.sh` now BANS the four
   pykeepass names from `backends/kdbx.py` outright rather than warning about
   them in prose. See KNOWN_ISSUES I32.
2. **`delete_binary()` corrupts attachment references.** It renumbers via
   `find_attachments()`, which does not descend into `History`, leaving
   `Binary/Value/@Ref` attributes pointing one slot too high — at someone
   else's bytes. Deletion is now reference-counted over the whole tree. The
   **"remove attachment / by us"** row in §2.2 is the standing check: it removes
   one of two attachments and requires `keepassxc-cli` to report no
   `Unmapped keys left.` *and* the survivor to export byte-identical.

### One interaction to know about, found while writing this file

`backends/kdbx._install_xml_hardening()` replaces the `etree` name **inside
pykeepass's own module namespace** so the inner XML is parsed with entities and
DTDs off (I8). It is process-global, and it raises our `Invalid` where lxml
would raise `XMLSyntaxError`. `pykeepass/kdbx_parsing/common.py:139` parses a
key file with `etree.fromstring()` inside a `try` that expects the lxml
exception and falls back to treating the bytes as raw key material — so once
`backends.kdbx` is imported, **that fallback no longer runs** and a *raw*
(non-XML) key file makes `pykeepass` raise `invalid: the key file is not
well-formed XML`. Reproduced, with the traceback, on this host.

No shipping path is affected: our `unlock` computes the composite key itself
rather than handing the key file to pykeepass, and read / `save` / `save_as`
with a raw 32-byte key file were all verified above. It is recorded because the
first code that *does* let pykeepass parse a key file — a create-a-safe verb,
say — will hit it, and the failure will look like a corrupt key file rather
than like a hardening side effect.

---

## 8. Believed but NOT verified

Everything here is code that exists and is expected to work. **The claim in the
left column has never been run against the thing it names.** Where partial
evidence exists the middle column says exactly how far it goes and no further;
the right column says what is still missing and why this host cannot supply it.

This section is separate because a believed row sitting in a table of measured
rows *reads* as measured, and that is the failure mode I19 names. Nothing here
should be quoted as compatibility.

| Claim | What IS verified | What is NOT, and why it cannot be here |
|---|---|---|
| **YubiKey challenge-response opens a database keyed with one** | the plumbing, all four cases: no slot + no response → normal unlock; no slot + response → `invalid`; slot + no response → `bad-credential`; slot + response → the response is folded into the composite key. `probe` publishes the challenge (`hmac-sha1`, 64 bytes, derived from the KDF seed) | **There is no YubiKey on this host** — no `ykman`, no `ykchalresp`, nothing YubiCo on the USB bus — and no KDBX database keyed with a challenge component exists, because producing one needs the token. So `_yubikey_component()` = SHA-256 over the raw answer has **never been shown to produce a key that opens a real KeePassXC challenge-response database.** If that construction differs from KeePassXC's by one detail, every such database fails to open and nothing here would have caught it |
| **KDBX 3.x + Twofish decrypts a real file** | the *primitive* is verified, and by a genuinely third party: `backends/kdbx._decrypt_prefix()` — Botan's `BlockCipher("Twofish")` with CBC composed by hand — was fed ciphertext produced by **Perl `Crypt::Twofish` 2.18** and returned the plaintext exactly, for both the full 48-byte buffer and the 32-byte prefix `_verify_kdbx3()` actually asks for | **No KDBX 3.x + Twofish file exists.** `keepassxc-cli` cannot create one (no cipher switch), so the header parse, the stream-start-bytes check and the block-digest walk *around* that primitive have never run on a real Twofish KDBX3 database |
| **KDBX 4 + Twofish, beyond the one fixture** | `lab-kdbx40-twofish-argon2d.kdbx` opens here and in `keepassxc-cli`, which confirms `Cipher: Twofish 256-bit` | that fixture's container was **written by this project**, not by KeePassXC — `keepassxc-cli` cannot create a Twofish database at all. A foreign reader accepting our file is real evidence; a foreign *writer* producing one for us to read does not exist on this host, so the read path has never seen Twofish bytes laid out by someone else |
| **KDBX 4 + AES-KDF** | nothing | **no such file exists on this host and none can be made here.** `keepassxc-cli db-create` always writes KDBX 3.1 + AES-KDF and `db-edit` has no KDF switch; `tests/fixtures/kdbx_reformat.py` deliberately refuses `--kdf aeskdf`, on the grounds that a 3.1 + AES-KDF fixture straight out of `db-create` has better provenance than anything it could synthesise. So AES-KDF is verified **only** in its KDBX 3.1 form (1 000 000 rounds, read-only), and the KDBX 4 combination — which `Limits.check_aeskdf_rounds` clamps and the writer would emit — has never been read or written |
| **A `.psafe3` this program wrote is one this program can read back** | KDBX only. `_verify_own_output` re-opens every KDBX save through the reader before it is written, so a KDBX file this program writes is one it can open | **not true of PWS3.** `backends/psafe3.py` has no such check and its once-per-session losslessness guard latches after the first save, so a second save in one session can write a Password Safe file this program's own reader then refuses. Reproduced 2026-09-04; see KNOWN_ISSUES I41. A foreign reader's view of such a file is unknown, because none was produced for `keepassxc-cli` (which cannot read PWS3 anyway) or for the Password Safe GUI (which cannot be driven here) |
| **A `.psafe3` written by the real Password Safe GUI** | nothing | see §3.3. `pwsafe` maps no window headlessly (proved against an `xmessage` control on the same Xvfb) and `--validate` never returns. This needs a human at a GUI |
| **KeePass 2.x (the C# implementation) reading our files** | nothing | not installed here, and not installable offline. `keepassxc-cli` is a different implementation of the same format, not the reference one |

### 8a. What moved OUT of §8 on 2026-09-04, and the evidence that moved it

Three rows in the table above were true when they were written and are not true any more. They
are recorded here rather than silently deleted, because "this used to be unverified and here is
what changed" is the only form of that claim a reader can check.

| Row, as it read | What it says now, and the evidence |
|---|---|
| *"`superuser: "require"` under a real Cockpit bridge — the browser suite stubs `cockpit.spawn`; **no test has ever run against a real bridge**"* | **VERIFIED.** `tests/browser/live-access.spec.js` item 9 drives live Cockpit 360 at `https://localhost:9090` signed in as a real account, with nothing stubbed. Both directions hold: with administrative access off, the bridge refuses immediately and **draws no prompt anywhere** (measured — the escalation dialog belongs to Cockpit's shell and nothing a package page can reach makes it appear); after Cockpit's own header control grants it, `cockpit.permission.allowed === true` and the admin-class safe opens. 22/22, run twice from a reset state on 2026-09-04 |
| *"the `access: "admin"` class in general — only ever proved to *refuse*"* | **VERIFIED in both directions.** The refusing side: all 33 verbs driven as `cptest` (uid 1005, not in `sudo`) against a real root-owned admin safe, every one `access-denied`, plus the same refusal for autosave mutations carrying the correct passphrase. The allowing side: item 9 above renders 6 entry rows out of a root-owned KDBX the driving account cannot read unescalated |
| *"the `export` verb's ALLOWED path — nothing in the standing suite runs as euid 0"* | **VERIFIED, and this row was already stale.** `tests/integration/newverbs.py` runs the export allow-path inside `unshare --map-root-user`, where `os.geteuid()` really is 0: the file lands 0600 in a 0700 directory under `export_dir`, named helper-side, content absent from the reply, audit line carrying the name and row count and no value. Re-run green in the re-gate (220 checks, 0 failures). What is still **not** covered is the SUDO_UID / group-membership branch of `gate()`, because inside that namespace the caller's real uid is 0 too — that half needs the `/srv/jobs` runner, and it is exercised there for the lockout path only (KNOWN_ISSUES I40) |

---

## 9. Not compatible, and not claimed to be

- **No create-a-safe verb and no master-passphrase rotation.** `save-as` copies
  an *open* database to a new name; it cannot make one from nothing, and it
  cannot change the passphrase. Use the desktop client; `docs/OPERATIONS.md`
  has the procedure.
- **No PWS3 XML export.** Password Safe's XML export is a GUI feature with its
  own schema, not part of the file format, so `export_plain(fmt="xml")` answers
  `unsupported` rather than emitting a file that claims to be it.
- **No HTML export.** `keepassxc-cli` has one; we do not.
- **No online breach lookup, and there will not be one.** `breach-check` is
  offline-only against a local corpus. With none configured it says so:
  *"no breach corpus is configured for this safe … There is no online fallback
  and there will not be one."* The helper makes no outbound network connection
  of any kind.
- **The plugin opens no TCP port.** The browser reaches the helper through
  `cockpit.spawn` — a process and a pipe. The only socket in the package is the
  agent's `AF_UNIX` one (I18), and `function-map/` records that absence entry
  by entry so it can be proved from the inventory rather than from this
  sentence: 902 of its 911 entries carry `ports: []`, the nine that do not are
  the functions that operate the agent socket, and

      grep -rn --include='*.yaml' 'transport: "\(tcp\|udp\)"' function-map/

  finds nothing.

---

## 10. Divergences introduced by the adversarial review

Three places where this package now deliberately does something KeePassXC does not, or stops
doing something it used to. Each is here because "we differ from the reference" is exactly the
kind of fact §7 exists to record, and because two of the three are visible in bytes an operator
may hand to another tool.

### 10.1 The decompression ratio guard no longer refuses ordinary content

§4 records the ratio guard as the one place where the foreign oracle is silent — KeePassXC has
no decompression cap, so the corpus's compression bombs open there and must be refused here.
That is still true, and both bombs are still refused. What is no longer true is that the RATIO
is the thing doing it.

DEFLATE cannot expand a stream by more than 1032:1. Measured on this host with zlib 1.3,
`zlib.compress(b"\0" * n, 9)` reaches 1028:1 for every n from 1 MiB to 256 MiB. A threshold of
200:1 therefore never separated a bomb from ordinary compressible content — it only decided how
compressible a legitimate attachment was allowed to be, and it decided wrong in both directions:

* a KDBX 4 database this package wrote, carrying one ordinary 8 MiB log file as an attachment,
  was refused by this package at every subsequent unlock and read by `keepassxc-cli` perfectly;
* KDBX 3.1 databases written by `keepassxc-cli 2.7.10`, whose attachments are gzipped one by one
  in the binary pool, were refused at `fields`, `attach_list`, `attach_get` and `export_plain`.

Both are now accepted, which is a **compliance improvement**, not a relaxation: what replaced
the ratio is an absolute cap enforced incrementally (so peak memory is bounded whatever the
ratio), structural caps on what the payload may CONTAIN (a field value over
`MAX_FIELD_BYTES`, a pooled binary over `MAX_ATTACHMENT_BYTES`, more than `MAX_ENTRIES` entries
or `MAX_GROUPS` groups), and a wall-clock budget over the parse. The structural caps are the
ones that refuse the corpus bombs, and they refuse them for a reason that is true of the file
rather than true of its compressor. See KNOWN_ISSUES I23 and I25.

The read and write limits are now the same number: `_check_text` has always enforced
`MAX_FIELD_BYTES` on the write path, and the structural cap enforces it on the read path. That
is what makes "this package cannot write a file its own reader refuses" a property rather than a
hope — and `_verify_own_output` proves it per save by re-opening the bytes before they replace
anything (I24).

### 10.2 CSV export neutralises formula-leading cells; KeePassXC does not

`export --format csv` in KeePassXC 2.7.10 writes field values verbatim. This package prefixes an
apostrophe to any cell beginning with `=`, `+`, `-`, `@`, TAB or CR, because a spreadsheet hands
such a cell to its formula parser even inside RFC-4180 quotes and the export is the one artefact
that holds every credential in the safe at once (CWE-1236; KNOWN_ISSUES I31).

**What this costs the round trip.** `_export_csv`'s column set is still KeePassXC's ten columns
in KeePassXC's order, so the file still imports. But a value legitimately beginning with one of
those characters gains a leading apostrophe, and KeePassXC's CSV importer will import the
apostrophe as part of the value. A password like `-hunter2` therefore needs one leading
apostrophe stripped on the far side.

The export reply says so, per export: it carries `neutralised: N` and a warning naming the
characters. `N` is 0 for every ordinary database, so the noise is paid only when it is the answer
to a real question. The trade-off, and the two alternatives that were rejected, are argued in
docs/RESIDUAL-RISK.md §2.

### 10.3 A repeated field name is refused, as KeePassXC refuses it

KeePassXC 2.7.10 refuses to open a KDBX whose entry carries two `<String>` elements with the same
`<Key>`: *"Error while reading the database: Duplicate custom attribute found"*. This package
used to open such a file and show the FIRST value. It now refuses the field, at every read and
every write, which brings it into line with the reference — and, more importantly, stops `edit`
from reporting a password rotation that only touched one of the two copies. See KNOWN_ISSUES
I29.

For PWS3 the same rule is applied to a repeated record field type, per formatV3.txt §3.3. One
half of the original finding is **not** claimed, because it could not be checked: that pwsafe's
`CItem::SetField` keeps the LAST occurrence. There is no pwsafe source or GUI on this host, and
`tests/oracle/pws3_oracle` is this project's own Go writer — §3.3 already records that gap. The
verified reference disagreement is the KDBX one.

### 10.4 The hardware-token challenge does not rotate, and now says so

§2.3 describes the challenge-response construction. What it did not say, and what
`docs/RESIDUAL-RISK.md §1` now argues in full, is that KeePassXC's `Kdbx4Writer` calls
`Kdf::randomizeSeed()` on every save while `_serialize` deliberately does not — so the token's
20-byte answer for a given file is a constant here and a per-save value there. `probe` and
`unlock` both warn about it now. It is not mechanically fixed; the reasoning is in the residual
register rather than hidden in a docstring.

### 10.5 A Password Safe file this program writes may not be one it can read

Found by the 2026-09-04 re-gate; **this is an open defect, not a deliberate divergence**, and it
is in this section because it is a statement about bytes another tool may be handed.

§10.1 and KNOWN_ISSUES I23 state the principle: *"the read and write limits are now the same
number and this program cannot write a file its own reader refuses."* That is true for KDBX,
where `_verify_own_output` re-opens every save through the reader before the bytes reach disk.
It is **not** true for Password Safe v3, which has no such check and whose once-per-session
losslessness guard latches after the first save.

Measured: a second save in one session wrote a `.psafe3` carrying a 5 MiB field — legal in the
format, over this program's own 4 MiB per-field cap — reported `{"ok": true, "bytes": 5244200}`,
and the resulting file answered `bad-credential` on reopen. Whether the real Password Safe GUI
would open that file is **unknown**: formatV3.txt sets no per-field maximum, so a compliant
reader plausibly would, which would make it a file this program wrote, cannot read, and would
tell the operator was protected by the wrong passphrase. Nothing on this host can settle that —
see §3.3 and RESIDUAL-RISK §3.5.

Tracked as KNOWN_ISSUES I41 with the fix shape. Until it is closed, the honest form of the §10.1
claim is *"for KDBX."*
