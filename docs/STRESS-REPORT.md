# Stress report — the complete red-team record

This is the record of six adversarial lenses attacking cockpit-secrets 0.2.0, the remediation
that answered them, and an independent re-gate of the result on **2026-09-04**. It is written
to be read by somebody who does not believe it.

It exists because of one sentence in `docs/KNOWN_ISSUES.md` I19: *a reader and a writer that
share a bug agree perfectly.* Version 0.2.0 passed `./run_tests.sh` 16/16, `./validate.sh`
15/15, a live 10-item browser walkthrough 140/140 and a 233-check root-side verification —
and every one of those tests was written by the system that wrote the code. Sixteen defects
were found in it anyway.

---

## How to read this document

Every attack in §5 carries one of three verdicts. They are not interchangeable and the third
one is the important one.

| Verdict | Meaning |
|---|---|
| **PASS** | The attack was executed and the defence held. This is evidence the defence works. |
| **FAIL** | The attack was executed and found a defect. Every FAIL has a finding id. |
| **NOT-ATTEMPTED** | Nobody ran it. It is listed with the reason. **A NOT-ATTEMPTED is never reported as a pass.** |

Two provenance markers appear throughout, because this document has two authors:

| Marker | Meaning |
|---|---|
| **[attack]** | Measured during the adversarial pass, by the lens named in the section heading. Recorded here; not independently re-run in the re-gate. |
| **[re-gate]** | Measured again on 2026-09-04 during this re-gate, against the reinstalled 0.2.1 build. The command and the raw output are in the entry. |

An entry with no marker is a static fact about the source tree, checkable by reading it.

**The attacks that failed are in this document deliberately and at length.** A report that
lists only findings reads as though nothing was checked, and an attack that bounced off a
defence is the only evidence that defence exists. §5 is roughly four parts bounced attack to
one part finding, which is the true ratio.

---

## 1. Verdict

Sixteen defects were found. Fourteen were fixed and one was argued and left standing with a
runtime warning; those fifteen were the remediation's scope and all fifteen hold up under
re-examination. **Three further defects were found or confirmed during this re-gate**, plus one
test defect. One of them — `REGATE-03` — is a defect the remediation states in writing that it
fixed, and did not.

**UPDATE, 2026-09-04, the close-out pass (§8).** All four are now closed. REGATE-01/02/03 were
each re-reproduced before being fixed, and REGATE-04 was fixed by the pass that could report on
it independently, which is what its entry asked for. The statuses in the table below are as of
the close-out; §4 keeps each finding's original text, because a report that overwrites what it
first said is not a record.

| # | Finding | Severity | Status after the re-gate |
|---|---|---|---|
| CRYPTO-01 | `save()` wrote a database the plugin could never reopen | High | **FIXED** — I23, I24 |
| CRYPTO-02 | PWS3's losslessness guard latches; a later save is unchecked | Medium | **FIXED** — I41, I24 (close-out, §8) |
| CRYPTO-03 | The hardware-token challenge never rotates | Low | **OPEN, argued** — I35, RESIDUAL-RISK §1 |
| CRYPTO-04 | Duplicate field types resolved first-wins | Low | **FIXED** — I29 |
| INPUT-1 | `MAX_ENTRIES` enforced after the parse | Medium | **FIXED** — I25 |
| INPUT-2 | A deeply nested request answered `internal` | Low | **FIXED** — I33 |
| LEAKAGE-01 | `redact()` missed JSON-escaped secrets | Low | **FIXED** — I30 |
| LEAKAGE-02 | Live-harness artefacts written under the umask | Low | **FIXED** — I34 |
| LEAKAGE-03 | CSV export was an execution channel | Low | **FIXED** — I31 |
| LEAKAGE-04 | Caller text reached a pykeepass XPath through `add` | Low | **FIXED** — I32 |
| DURABILITY-1 | `_ring_backup` ignored the `os.write()` return value | High | **FIXED** — I26 |
| DURABILITY-2 | A failed lock payload write left an orphan lock | Low | **FIXED** — I28 |
| DURABILITY-3 | "This restore is itself undoable" was false | Low | **FIXED** — I33 |
| DURABILITY-4 | A truncated backup generation was restorable | Low | **FIXED** — I27 |
| DURABILITY-5 | A directory at the lock path was unrecoverable | Low | **FIXED** — I28 |
| WEB-01 | The unlock lockout does not survive concurrency | Medium | **FIXED** — I39 (close-out, §8) |
| — | The admin lockout counter is shared by all operators | Medium | **FIXED** — I40 (close-out, §8) |
| — | The live suite's I11 storage check is a false statement | Low | **FIXED** — I42 (close-out, §8) |

### Two gaps in the finding numbering, and what happened to each

The attack pass named sixteen defects; the remediation report addresses fourteen. The two
missing ids are not clerical.

* **CRYPTO-02** was folded into the CRYPTO-01 remediation, which states that
  `_verify_own_output` *"also fixes the latched `_assert_lossless` gap (and the same latent
  latch on the PWS3 side)"*. **It does not.** `backends/kdbx.py` calls `_verify_own_output`
  on every save; `backends/psafe3.py` has no such call and `_lossless_checked` still latches.
  Reproduced in this re-gate as REGATE-03 below.
* **WEB-01** was named by the browser lens (*"the lockout is a different matter — that is
  WEB-01"*) and appears in no remediation entry. Reproduced in this re-gate as REGATE-01.

---

## 2. The gates, re-run from a clean state

All of the following were run on 2026-09-04 against the source tree at
`/srv/smb/…/projects/cockpit-secrets/source`, VERSION 0.2.1, with `git status --porcelain`
showing only the remediation's own edits. **[re-gate]**

| Gate | Command | Result |
|---|---|---|
| JavaScript syntax | `./check.sh` | **PASS** — `secrets.js syntax OK`, exit 0 |
| Standing bans + units | `./validate.sh` | **PASS** — **47 PASS / 0 FAIL**; unittest `Ran 38 tests … OK` (5.3 s); exit 0 |
| Full suite | `./run_tests.sh` | **PASS** — **17 of 17 stages**, `run_tests.sh: OK`, exit 0 |
| Corpus sidecars | `python3 tests/corpus/gen_corpus.py --check` | **PASS** — `67 cases checked, 0 disagreed with their sidecar` |
| `os.write` AST ban | `python3 tests/ban_os_write.py` | **PASS** — exit 0 |
| Oracle build | `bash tests/oracle/build.sh` | **PASS** — `go1.26.0`, `pws3_oracle (3581529 bytes)` |

`run_tests.sh`, stage by stage, with the check count each stage printed:

| Stage | Checks | Time |
|---|---|---|
| syntax and standing bans (`validate.sh`) | 47 PASS / 0 FAIL + 38 unit tests | 7 s |
| javascript syntax (`check.sh`) | 1 file | 0 s |
| `backends/base.py` self-check | **118 checks, 0 failures** | 0 s |
| `backends/psafe3` self-check | 18 checks, `psafe3 self-check: OK` | 1 s |
| `backends/kdbx` self-check | 28 checks, `kdbx self-check: OK` | 0 s |
| agent self-check | **61 checks, 0 failures** | 0 s |
| Twofish ECB vectors, both providers | `botan 728 vectors, 0 failure(s)` / `pure 728 vectors, 0 failure(s)` | 1 s |
| integration: contract flow, both formats | **86 checks, 0 failures** | 10 s |
| integration: cross-backend conformance | **83 checks, 0 failures** | 2 s |
| integration: load-bearing properties | **27 checks, 0 failures** | 18 s |
| integration: the second-wave verbs | **220 checks, 0 failures** | 12 s |
| integration: the unlock agent, end to end | **45 checks, 0 failures** | 6 s |
| integration: the adversarial findings | **73 checks, 0 failures** | 13 s |
| integration: corpus vs the helper | **67 checks, 0 failures** | 83 s |
| oracles: build and known-answer vectors | build OK | 0 s |
| fixtures: verify against `keepassxc-cli` | 33 PASS | 3 s |
| ui: headless browser driver | **244 passed, 0 failed** | 24 s |

**1 188 independent assertions plus 2 912 Twofish vector comparisons, zero failures.**

Nothing was weakened to get there. No test, ban, budget or threshold was edited during this
re-gate; `git status --porcelain` over `tests/` and `validate.sh` is unchanged from what the
remediation left.

### The one gate that is not green

> **CLOSED in the close-out pass (§8.2). The section below is kept as it was written.** The
> failing assertion was the test defect it says it was; it has since been rewritten to be
> *correct* rather than lenient, and the live suite now scores **131/131, exit 0, all ten
> items**. See §8.2 and KNOWN_ISSUES I42.

The live browser walkthrough is **129/130**, not 140/140, and it was 129/130 twice.

```
./tests/browser/run-live.sh
  live-ui      107/108 checks held    items 1,2,3,4,5,6,7,10   — item 4 FAIL
  live-access   22/22  checks held    items 8,9
  exit 1
```

Run 2 was executed after restoring all three safes to pristine fixture bytes, removing their
backup rings and clearing their lockout counters, and produced the identical result. The
failing assertion, verbatim:

```
FAIL  the unlock added NOTHING to either storage area
      ([] local, ["cockpit:page_status"] session, against the baseline taken
       before any safe was opened)
```

**This is a defect in the test, not in the page**, and it is written up as REGATE-04 with the
measurement that proves it. The page is byte-identical to the one that scored 140/140:
`secrets.js` sha256 `7f03c81c…` in the tree, on the host, and in `docs/LIVE-WALKTHROUGH.md`'s
record of that run. Every other assertion in item 4 — the ones that would catch a real leak —
passed:

```
PASS  no storage key belongs to this package ([])
PASS  the plugin frame opened no IndexedDB database ([])
PASS  the passphrase string appears nowhere in the plugin frame's DOM
PASS  the passphrase is in neither storage area
PASS  the passphrase is in no cookie
PASS  no live input or textarea still holds the passphrase
PASS  the passphrase is absent from Cockpit's shell page too — same origin, same risk
PASS  the now-detached passphrase input was WIPED, not just removed
```

---

## 3. What the host actually serves

Before this re-gate the live Cockpit page ran the **0.2.0** helper: the remediation deliberately
did not install itself. It has now been installed through the `/srv/jobs` root runner
(`install.sh`, 4 changes, 21 unchanged, 0 warnings), and served-versus-source was verified by
sha256 for **every** installed artefact, not only the four that changed. **[re-gate]**

| Installed path | sha256 (first 16) | |
|---|---|---|
| `/usr/local/sbin/secrets-admin` | `6d07ac960590d634` | MATCH |
| `/usr/local/lib/cockpit-secrets/backends/base.py` | `9b20d7e44a23354a` | MATCH |
| `/usr/local/lib/cockpit-secrets/backends/kdbx.py` | `082c7df76588c247` | MATCH |
| `/usr/local/lib/cockpit-secrets/backends/psafe3.py` | `3503e1a8169d6969` | MATCH |
| `/usr/local/lib/cockpit-secrets/backends/twofish_pure.py` | `f17e2cdb146bc7fc` | MATCH |
| `/usr/local/lib/cockpit-secrets/backends/__init__.py` | `8eea9b00b4d3c0fb` | MATCH |
| `/usr/local/lib/cockpit-secrets/schema/safe-registry.schema.json` | `577c13f67ea46708` | MATCH |
| `/usr/share/cockpit/secrets/secrets.js` | `7f03c81c8919baf3` | MATCH |
| `/usr/share/cockpit/secrets/secrets.css` | `a4ae61cd91f6de0c` | MATCH |
| `/usr/share/cockpit/secrets/index.html` | `67cbc958a6beddc3` | MATCH |
| `/usr/share/cockpit/secrets/manifest.json` | `bb51d6b9956403a4` | MATCH |

`cockpit.socket` was never stopped, started or reloaded; it has been up continuously since
2026-09-01 01:59:08 and answered HTTP 200 throughout.

---

## 4. The three defects this re-gate found

### REGATE-01 · The unlock lockout does not survive concurrency (was WEB-01) · Sev M · FIXED in the close-out (§8)

I16 promises *"a per-(uid, safe id) failure counter … with exponential backoff and a lockout
threshold"*. The counter is a read-modify-write with no lock: `lockout_fail()` calls
`_lockout_read()`, computes, and calls `_lockout_write()`, which opens `O_TRUNC` and replaces
the file. `lockout_check()` runs **before** the KDF and `lockout_fail()` **after**, so the race
window is the whole derivation.

Fired at a hermetic registry, wrong passphrases only, counter cleared before each batch: **[re-gate]**

```
sequential control, 8 guesses one at a time
   1  bad-credential   0.32s      <- evaluated
   2  locked-out       0.27s
   …8  locked-out                  bad-credential accepted sequentially: 1

10 concurrent  -> {'bad-credential': 10}                 10 evaluated
25 concurrent  -> {'bad-credential': 22, 'locked-out': 3} 22 evaluated
50 concurrent  -> {'bad-credential': 44, 'locked-out': 6} 44 evaluated
   counter file after the 50: {"failures": 43, …}   <- 7 increments lost outright
```

Sequentially the brake is aggressive — one wrong guess and the next is refused. Fired in
parallel, 44 of 50 guesses were evaluated against the KDF. The counter loses updates as well as
failing to gate: 50 attempts left `failures: 43`.

**What it is not.** It is not an offline attack and it does not remove the KDF's cost: every one
of those 44 paid a full Argon2 derivation, and I16's *other* control — the constant-time failure
floor — is untouched (measured separately by the browser lens at 200 samples each way, fully
separated, `correct.max 0.8743 s < wrong.min 1.0249 s`). What is defeated is the specific
promise that guessing is bounded by a threshold rather than only by CPU. The reachable attacker
is anyone who can spawn the helper concurrently: the safe's own owner for a user-class safe, or
script in the Cockpit origin (A4) driving `cockpit.spawn` in a loop.

**Fix shape, not applied here:** take the lock file, or an `O_EXCL` sidecar, across the
read-modify-write; or make the counter an append-only file whose length is the count.

---

### REGATE-02 · Every administrator shares one lockout counter per admin safe · Sev M · FIXED in the close-out (§8)

`_lockout_path()` (`secrets-admin:1203`) builds `"fail.%d.%s.json" % (os.geteuid(), safe_id)`.
On the admin path every operator is euid 0. `ident.real_uid` is available at that point and is
not used. I16 and `docs/ARCHITECTURE.md` step 6 both say the counter is per-**(uid, safe id)**.

The browser lens flagged this from reading and could not reproduce it, because reaching euid 0
needs the superuser path `cptest` cannot obtain. Reproduced here through the root job runner
against a real root-owned admin-class registry entry, using invented wrong passphrases that are
credentials for nothing: **[re-gate]**

```
operator A (SUDO_UID=1000) makes 5 wrong attempts on an ADMIN safe
    -> bad-credential, then locked-out ×4
counter files that now exist:
    fail.0.zz-lockout-probe.json          <- one file.  euid, not uid.
      {"failures": 1, "locked_until": …}

operator B (SUDO_UID=1007) has typed nothing at all, and offers the CORRECT passphrase:
    -> locked-out
```

One administrator's single typo locks a different administrator out of a safe they hold the
correct passphrase for. The counter also cannot attribute: the audit log records the operator,
the lockout state does not.

**Fix shape, not applied here:** key the path on `ident.real_uid` (falling back to euid when
there is no `SUDO_UID`/`PKEXEC_UID`), and say in I16 which identity is meant.

---

### REGATE-03 · PWS3 never got CRYPTO-01's per-save reader check (was CRYPTO-02) · Sev M · FIXED in the close-out (§8)

The KDBX save path gained the fix the remediation describes: `backends/kdbx.py` `save()` calls
`_assert_lossless()` **and then `_verify_own_output(data)`**, and `_verify_own_output` re-opens
the bytes through the same reader a later unlock uses. `backends/psafe3.py` `save()` calls
`_ensure_lossless()` and nothing else. `_ensure_lossless` short-circuits on
`self._lossless_checked`, which is set `True` on its first run and cleared only in `lock()`.

So on PWS3 the I22 round-trip guard runs **once per session**, not once per save, exactly as
before the remediation — while `docs/KNOWN_ISSUES.md` I24 states the fix *"also closes the
latent half of the same latch on the PWS3 side"*.

Reproduced against the real backend, on a copy of the committed fixture: **[re-gate]**

```
latch after unlock              : False
save 1 (ordinary edit)          : True   file c7d274f5f7c39638
latch AFTER save 1              : True          <- guard now disabled for the session

save 2, 5 MiB notes field in the SAME session
   edit accepted the 5 MiB value
   save 2  -> {'ok': True, 'bytes': 5244200, 'conflict': False}
   file c7d274f5f7c39638 -> 889c891b0d3edc0c  *** REWRITTEN ***

reopen the file that save reported ok
   -> BadCredential: "bad-credential: the passphrase did not open this safe"
   (stderr, from the reader: "PWS3 field length 5242880 exceeds the 4194304 byte limit")
```

The safe is destroyed, `save()` answered `ok`, and the reader then blames the operator's
passphrase — the one taxonomy that will send them to guess again and burn REGATE-01's counter.
The previous generation is in the backup ring, so this is recoverable data loss, not permanent.

I23 states the principle this violates in its own words: *"the read and write limits are now the
same number and **this program cannot write a file its own reader refuses**."* That is true of
KDBX and false of PWS3.

**How far it is reachable today, measured rather than assumed.** Through the shipping helper it
is **not** reachable by this route: `MAX_REQUEST_BYTES` is 1 MiB and `edit` carries the whole new
field value, so a frame setting a >4 MiB field is refused and the session closes (measured — the
helper closed stdin on a 1.37 MiB frame). `serialize()` does still check `MAX_SAFE_BYTES` at
`psafe3.py:1347`, so the whole-file-too-big route is caught. What is unguarded is the per-field
cap, and the only thing standing between it and an operator is a transport limit that exists for
an unrelated reason. Any caller that reaches the backend directly — a future verb, the agent, a
script, the test suite — has no such limit.

**Fix shape, not applied here:** give `Psafe3Backend.save()` and `save_as()` the same
`_verify_own_output` treatment `KdbxBackend` has, and correct the I24 text.

---

### REGATE-04 · The live suite's I11 storage check is a false statement · Sev L · FIXED in the close-out (§8)

`item4`'s difference check flags any key that appeared **or whose value changed length** between
a baseline snapshot and the post-unlock snapshot. The comment explains why length is included,
and the reason is good: *"overwriting Cockpit's own key with a passphrase would otherwise slip
through a names-only comparison."*

But a Cockpit package page is an iframe on the shell's own origin, and Cockpit's shell writes
`sessionStorage["cockpit:page_status"]` asynchronously on behalf of stock pages that have nothing
to do with this package. Measured, with the secrets package never opened in the browser context: **[re-gate]**

```
A. right after login, shell page   session=["cockpit:v2-machines.json"]
B. after opening stock /system     session=["cockpit:page_status","cockpit:v2-machines.json"]
   value: {"localhost":{"updates":{…"Checking for package updates…"…},
                        "system/services":{"type":"error","title":"1 service has failed",
                                           "details":["edy-rdp-headless@1000.service"]}}}
   mentions 'secret'? false
```

and the value changes length while it sits there, again with this package never opened:

```
t+2s   len=235  …"Checking for package updates..."…
t+10s  len=235
t+20s  len=223  …"Security updates available"…
t+30s  len=223
```

That 235→223 transition is exactly what item 4 reported. In run 1 the key was absent from the
baseline and appeared later; in run 2 it was present in the baseline and changed length later.
Both are Cockpit's own shell. `secrets.js` contains no `page_status`, and two separate standing
gates assert it names no browser storage API at all — both PASS.

**Fix shape, not applied here.** Deliberately not applied: quietly editing an oracle so that a
number comes out right is the exact failure mode this whole exercise exists to catch, and this
assertion should be re-armed by somebody who is not also reporting on it. The sound version keeps
the hazard the length check was reaching for and drops the false attribution: for a key that
changed, ask **inside the page** whether the new value contains the passphrase or a marker from
this package, and return a boolean rather than the value — strictly stronger than a length
comparison, which a same-length overwrite would already defeat.

---

## 5. The attack record

### 5.1 Cryptographic correctness and format compliance

#### Attacks that failed — the defences held

| Attack | How | Verdict |
|---|---|---|
| Twofish gives a wrong answer somewhere | All 728 committed vectors pushed through an independent Go oracle (`golang.org/x/crypto/twofish@v0.48.0`) **first, to test the vector file itself** — 0 bad. Then all 728 through `botan3.BlockCipher("Twofish")` and through `backends/twofish_pure.Twofish`, encrypt **and** decrypt. Covers 178 × 128-bit, 243 × 192-bit, 307 × 256-bit — the whole ecb_ival chain and the Botan table, not the two vectors in HOST-FACTS.md. | **PASS** — 0 failures each **[attack]**, re-run in the re-gate: `botan 728 vectors, 0 failure(s)` / `pure 728 vectors, 0 failure(s)` **[re-gate]** |
| The hand-composed CBC chains wrongly | `_cbc_decrypt`'s bulk-ECB-then-XOR shortcut XORs against `IV ‖ ct[:-16]`; checked against a naive per-block reference. | **PASS** — byte-identical plaintext **[attack]** |
| A partial last block is mishandled | The format guarantees whole blocks and `_split_prefix` refuses a body that is not a whole number of blocks, so no partial block exists to get wrong. | **PASS** — by construction **[attack]** |
| KDBX4 block-MAC index binding is decorative | A 3 151 249-byte file with five payload blocks: swap block 0 with block 1 (identical framing, only the index differs); replay block 0 into index 1's slot; flip one ciphertext byte; delete the terminator; flip a header byte. | **PASS** — `BadCredential`, `BadCredential`, `BadCredential`, `Invalid: the KDBX payload is truncated`, `Invalid`. `struct.pack("<Q", index)` really is inside the MAC input. The final zero-length block is itself MAC-verified. **[attack]** |
| Bytes appended after the terminator reach plaintext | Appended and read back. | **PASS** — ignored, as KeePass's own reader ignores them; they cannot reach any plaintext, so not reported as a finding **[attack]** |
| The two header checks run in the wrong order | KeePassXC 2.7.10's `Kdbx4Reader.cpp`, `Kdbx4Writer.cpp`, `CompositeKey.cpp`, `Database.cpp` and pwsafe's `PWSfileV3.cpp`, `Util.cpp`, `ItemData.cpp` fetched from upstream and read side by side with this code. | **PASS** — header SHA-256 first as a credential-independent `Invalid`, then the header HMAC under `SHA-512(masterSeed‖transformedKey‖0x01)` with block index `UINT64_MAX`, then every payload block, all before a byte reaches pykeepass. `finalKey = SHA256(masterSeed‖transformedKey)` matches. Every comparison `hmac.compare_digest`. **[attack]** |
| A save reuses a (key, IV) pair | Three consecutive `_serialize(reseed=True)` calls on one open database. | **PASS** — three distinct master seeds, three distinct encryption IVs, three distinct 64-byte inner protected-stream keys; `keepassxc-cli show -s` read the correct protected password out of all three, which also proves the inner-random-stream rotation is consistent **[attack]** |
| A weak RNG is hiding somewhere | `grep` over the whole tree. | **PASS** — `import secrets as _sysrandom` and `os.urandom` only; `random` is not imported anywhere in runtime code; no `SystemRandom`, `randint` or seeded generator **[attack]** |
| PWS3 key stretching diverges from the reference | `PWSfileV3::StretchKey` read from upstream: `X0 = SHA256(passphrase‖salt)` then N × `SHA256(X)`, UTF-8, no terminator — not PBKDF2. | **PASS** — exactly `StretchedKey.derive`; `H(P')` compared with `constant_time_eq` before anything else **[attack]** |
| The PWS3 parser disagrees with a third implementation | A from-spec Python reader written to the reference's *streaming* control flow (raw terminal-block comparison before decryption, 11 data bytes in the length block, `ceil((len-11)/16)` spill blocks, HMAC over field data only in file order) — deliberately not derived from either the project's reader or its own Go oracle. | **PASS** — byte-identical 43-field stream on the committed fixture; it verified the HMAC on files `psafe3.serialize()` wrote; `tests/oracle/pws3_oracle` agreed with both **[attack]** |
| The PWS3 parse can be driven off the rails | Declared lengths `0xFFFFFFFF` / `0x80000000` / `0x7FFFFFFF` / exactly 4 MiB / 4 MiB+1 / larger-than-remaining; every field length across the 11-byte boundary (0,1,10,11,12,15,16,17,26,27,28); a record with zero fields; three empty records; 200 000 empty records; one record with 100 000 fields; an unterminated final record; an END field carrying data; a raw EOF marker planted at a block boundary inside the ciphertext. | **PASS** — every case a typed error; every post-decrypt structural failure collapsed to the identical `bad-credential`; the real reason went only to stderr through `redact()`; not one untyped exception or traceback **[attack]** |
| Forge a PWS3 file that MACs but parses differently | The HMAC covers field DATA only, so the 4 length bytes, the type byte and the padding are unauthenticated — a real lever. Changing plaintext block *i* under CBC means flipping ciphertext block *i-1*. | **PASS** — that garbles block *i-1* into an unpredictable 32-bit declared length and `_check_field_length` refuses it in O(1) long before the MAC gate. Without K there is no controllable rewrite; with K you are the file's author. **[attack]** |
| The YubiKey composite key is built wrongly | Read from KeePassXC 2.7.10's sources, not from a description: `CompositeKey::rawKey` hashes every static key first and appends `challenge()` last; `challenge()` is SHA-256 over each token's raw answer; `transform` uses `kdf.seed()` as the challenge except for the legacy KDBX3 AES-KDF, which this code refuses rather than implementing a second untestable construction; `performChallenge` pads with `padLen = 64 - size` bytes of value `padLen` and truncates to 20 bytes. | **PASS** — `_pkcs7_to`, `_yubikey_component` and `_composite_key` all match, including "no token means the composite is unchanged". Both frozen regression digests recomputed from scratch: `2ec9767e…07f16b72` and `7c99602d…cb9cc553`, both correct. **[attack]** — and see the NOT-ATTEMPTED register: no token has ever answered one. |
| XXE / entity expansion / decompression bombs | `file:///etc/passwd`, an external-DTD `SYSTEM` reference, billion-laughs, 5 000-deep nesting, `xi:include`, a 400 MiB gzip bomb in 407 697 bytes. | **PASS** — `pykeepass.kdbx_parsing.common.etree` **is** `_HardenedEtree` and `.zlib` **is** `_BoundedZlib` at runtime, not merely in intent; all refused; `xi:include` parses but lxml never expands it without an explicit `xinclude()` call, which nothing here makes **[attack]** |
| A3 header tampering with every MAC re-sealed | Derived the transformed key, rewrote header fields, re-sealed the header SHA-256, the header HMAC and every block MAC so the file authenticates. A 4-byte encryption IV, a 64-byte IV, an unknown compression flag. | **PASS** — each `Invalid: this database is malformed or truncated` through `_map_pykeepass_error`; no traceback, no `construct` digest in the message **[attack]** |
| A digest comparison short-circuits | Every MAC, key hash, handle, confirmation token and backup name traced. | **PASS** — all through `constant_time_eq`/`compare_digest`; `find_session` deliberately does not short-circuit its loop; the only `==` on a digest is inside a self-check assertion **[attack]** |
| A structural refusal returns faster than a real attempt | `v_unlock`'s floor coverage. | **PASS** — `FailFloor` is waited out on `BadCredential`, on every other `SecretsError` (a clamp refusal, an unparseable header, a missing file) and on the catch-all **[attack]** |
| KDBX3 → KDBX4 upgrade silently downgrades protection | Converted, then opened in `keepassxc-cli`. | **PASS** — opens with the right password and the `Protected="True"` count in the new inner XML is identical to the source's (12 attributes over 8 password fields) **[attack]** |
| A PWS3 oversized save gets past the guard on the FIRST save | 5 MiB note, saved with no prior successful save in the session. | **PASS** — caught by `_ensure_lossless`, file on disk untouched **[attack]**. The *second* save is REGATE-03. |

#### Findings

* **CRYPTO-01 — FAIL.** `attach_add` of an ordinary 8 MiB log file produced a 33 KB database;
  `save` answered `{'ok': True, 'bytes': 32965}`; every later `unlock` answered
  `invalid: ratio 258:1 over the 200:1 limit` while `keepassxc-cli ls` listed the entries.
  The read half reproduced against a KDBX 3.1 built entirely by `keepassxc-cli`. Fixed — I23, I24.
  DEFLATE's physical maximum is 1032:1 (measured 1028:1 here from 1 MiB to 256 MiB), so no ratio
  threshold separates a bomb from a log file. Re-verified green in the re-gate by
  `test_crypto01_*` (in the 38) and the `crypto01_foreign` section of `adversarial.py` (in the 73).
* **CRYPTO-02 — FAIL, and still open.** See REGATE-03.
* **CRYPTO-03 — FAIL, argued, left standing.** Three identical challenges from this program
  versus a fresh one after one `keepassxc-cli` save. `docs/RESIDUAL-RISK.md` §1 carries the
  argument and the conditions that would reverse it; `probe` and `unlock` now both warn.
* **CRYPTO-04 — FAIL.** `DECOY-first` on KDBX where KeePassXC refuses the file outright
  ("Duplicate custom attribute found"), and the same on PWS3 through the project's own
  serializer. Fixed — I29. The pwsafe "last wins" half is **not claimed**: there is no pwsafe
  source or GUI on this host to check it against.

---

### 5.2 Access control, identity, privilege and the installed footprint

Every attempt to reach an admin safe, or to read a file the caller does not own, was refused.
All of these were run live as `cptest` (uid 1005, not in `sudo`) via `runuser -u cptest` from a
root job, so the kernel identity was genuinely 1005. **[attack]**

| # | Attack | Verdict |
|---|---|---|
| 1 | All 33 verbs driven directly as `cptest` against an admin-class safe | **PASS** — every safe-operating verb `{"error":"access-denied"}` with the class-refused detail, rc=1. `gate(entry, ident)` is re-derived inside every verb against the resolved entry and hard-requires `ident.euid == 0` for `access:"admin"`, so the file is never opened and no header/kdf/iteration/count/format facts leak. The mutating verbs that lack a handle answer `invalid` on a request-shape precheck first — but that message is identical whether the safe exists, is admin, or is user, so it is not an existence oracle. |
| 2 | Autosave mutations (`add`/`edit`/`rm`/`attach-add` with `autosave:true` **and the real password**) against the admin safe, to prove the gate runs before the KDF | **PASS** — all `access-denied`; `_mutate → need_backend → lookup_safe → gate → do_unlock`, and `gate` raises before `do_unlock`'s KDF |
| 3 | `SUDO_UID`/`PKEXEC_UID` spoofing on `unlock`: 0, 1000, 1005, −1, 99999999999999999999, `"root"`, both set and disagreeing | **PASS** — all eight `access-denied`. `Identity` reads those variables **only** when euid == 0; at euid 1005 they are ignored entirely |
| 4 | `COCKPIT_SECRETS_ETC` pointed at a `cptest`-owned registry declaring a *user*-class safe whose path is the root-owned admin safe; and a second pointed at `/etc/shadow` | **PASS** — the registry loaded (that seam is honoured for a non-root helper by design) but `probe` and `unlock`-with-the-real-password both answered `access-denied: safe file is not accessible to this caller`. `open_safe_fd` `fstat`s the fd it opened and requires `st_uid == euid`. I5 doing its job. |
| 5 | Symlink: a user-class safe whose path is a `cptest`-owned symlink to the root safe | **PASS** — `access-denied: safe path is a symbolic link`. `O_NOFOLLOW` → `ELOOP` → `AccessDenied`; fd-checked, so no TOCTOU window |
| 6 | Cross-safe pivot inside one `open` session: open a genuinely-owned user safe (positive control: valid 22-char handle, `entries_total=1`), then name the admin safe in later frames by `safe`+`password` and by `probe` | **PASS** — every such frame `access-denied`. Each verb re-runs `gate` against the entry **it** resolves from that frame; a handle for safe A never authorises safe B |
| 7 | Forged / replayed handle from a fresh process | **PASS** — `access-denied: this handle is not valid for this caller`. Handles live only in the in-process dict, are minted with `secrets.token_urlsafe(16)`, compared with `constant_time_eq` without early-out, and additionally checked for `uid == euid` **and** `pid == pid` |
| 8 | **Positive control** — `cptest` opening a user-class safe it genuinely owns | **PASS** — unlocked, handle returned. This is what makes 1–7 refusals of a working system rather than a broken build that refuses everything |
| 9 | The installed footprint, audited by `stat` from outside | **PASS** — helper 0755 root:root; lib, backends, schema 0755/0644 root:root; `/etc/cockpit-secrets/safes`, `/var/log/cockpit-secrets`, `/var/lib/cockpit-secrets` all 0700 root:root; `safes.d` 0755 with 0644 files. Nothing group- or other-writable, nothing sensitive world-readable |

**Deliberately not reported as findings**, because A2 explicitly sanctions them: `list` names every
registered safe to every caller with the reason it is unusable, so a safe's existence, label,
format and access class were never secret.

---

### 5.3 Secret leakage through every channel

A unique master passphrase and unique per-entry sentinels were planted, every verb exercised, and
then every channel hunted. **[attack]**

| # | Attack | Verdict |
|---|---|---|
| 1 | `/proc` of a live unlocked helper, **from the same uid** | **PASS** — `harden_process()`'s `prctl(PR_SET_DUMPABLE,0)` re-owns the sensitive nodes to root: `environ`, `maps`, `mem`, `auxv` and the whole `fd/` directory answer "Permission denied" to the process's own owner. `cmdline` is readable and carries only `… secrets-admin open` — no verb takes a credential on argv (I10) |
| 2 | Core dump through the apport pipe (a pipe handler is **not** stopped by `RLIMIT_CORE=0`) | **PASS** — `kill -SEGV` on the live unlocked helper produced no file in `/var/crash`. **Control**, to prove the test can detect a dump: an ordinary `python3` holding a sentinel, SEGV'd, produced a 1.33 MB `.crash` whose CoreDump section contains the sentinel 23 times. The hardening is what made the difference |
| 3 | Whole-filesystem sentinel sweep during and after a full verb walk | **PASS** — `grep -rl` over `/tmp`, `/var/tmp`, `/dev/shm`, `/run`, `/var/log`, `~/.cache`, `~/.local` and both journals: **zero** occurrences outside the driver's own scripts |
| 4 | The audit log, across ~30 verbs including `reveal`, `export` and five failed unlocks | **PASS** — every line the fixed 13-key shape with `note` drawn from a frozen 17-item vocabulary; 0600, `O_NOFOLLOW\|O_APPEND`, `fchmod`ed back to 0600; not one value, title, field name or path |
| 5 | The lockout state file | **PASS** — 0600, `{"failures":…,"locked_until":…,"last":…}` only; no passphrase, no hash of one, no salt |
| 6 | Error-path echo: malformed JSON carrying the sentinel eight ways (truncated, trailing garbage, bare string, bad `\` escape, 1.1 MB oversize, `password` as an object, 200-deep, duplicate keys), with `COCKPIT_SECRETS_DEBUG=1` set throughout | **PASS** — a fixed sentence every time; the sentinel in neither stdout nor stderr in any case |
| 7 | Tracebacks with debug on | **PASS** — none reached stderr from any reachable error path, including LEAKAGE-04's `XPathEvalError`; the barrier's `{"error":"internal","detail":type(exc).__name__}` held |
| 8 | Attacker-controlled text in an error message: `.lock` files holding HTML, an OSC/CSI escape sequence, 300 A's, a U+202E bidi override, embedded quotes and backslashes | **PASS, essentially** — the holder string *is* echoed, but `_sanitize_detail` strips every C0/C1 control (the escape came back as inert `]0;pwned[31mRED`), caps at 64 chars, collapses whitespace; and `secrets.js` has no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`, so the markup is a text node. Only the bidi override survives, which is cosmetic |
| 9 | `redact()` against a regex metacharacter, a backslash, a newline and U+2028 | **PASS for four of six** — `str.replace`, not `re`, so `SENT.*[a-z]+$^(\d)` is matched literally; backslash and newline covered by the `repr()` candidate; U+2028 covered because `ensure_ascii=False` keeps it a real character. `"` and NUL got through → **LEAKAGE-01** |
| 10 | Value echo in the metadata verbs | **PASS** — `strength` returns weakness ids and an entropy calculation and never a fragment of the candidate; `entries`, `tree`, `history`, `attach-list` return no value-shaped key; `run_verb` scrubs every non-value-bearing verb against a 13-name banned-key set |
| 11 | The export path in full, at a real euid 0 under `unshare --map-root-user` | **PASS** — 0600 inside a 0700 directory, named helper-side, content absent from the JSON reply, audit line carrying the name and row count and no value; a sweep afterwards found the plaintext only in that one file. Backup ring files 0600 in a 0700 `.bak.d`, holding ciphertext |
| 12 | `/srv/jobs` output logs | **PASS** — `grep -rl` for the fixture passphrase and the sentinel across all 2 088 outbox directories: zero hits. `/srv/jobs/outbox` is `drwxrwx--- root:users` and `cptest` is not in `users` |
| 13 | A1's actual reach, executed as uid 1005 | **PASS** — refused on `/srv/smb`, `/etc/cockpit-secrets/safes`, `/srv/jobs/outbox`, `/var/lib/cockpit-secrets`. It *can* list `safes.d` and run `list`/`health`, which is by design: naming is not opening |
| 14 | Browser-side persistence, by inspection of the shipped 331 KB `secrets.js` | **PASS** — names no browser storage API at all: no `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, `caches`. The passphrase input has no `name`, no form ancestor, `autocomplete=off`, `spellcheck=false`, `autocapitalize=none`, `autocorrect=off`. `hideNow()` removes the text node and writes the mask back rather than hiding it with CSS |

#### Findings

* **LEAKAGE-01 — FAIL.** Reproduced against the installed helper: a passphrase containing `"` or
  NUL passed the redaction filter untouched, because `_redaction_candidates` generated `repr()`
  but not the JSON rendering, and those differ. The project's own self-check used an alphanumeric
  sentinel, which is why 15/15 passed. Fixed — I30.
* **LEAKAGE-02 — FAIL.** `03-revealed.png` (a photograph of an unmasked password in a live
  Cockpit session) and the decrypted attachment `.bin` were `-rw-rw-r--` on an SMB-exported tree.
  Fixed — I34. **Re-verified in this re-gate**: after two full live runs, every one of the 44
  artefacts on disk is `-rw-------`; `find … ! -perm 600` is empty. **[re-gate]**
* **LEAKAGE-03 — FAIL.** `=cmd\|' /C calc'!A0` written to a CSV export verbatim. Fixed — I31,
  with the fidelity cost made loud (`neutralised: N`) rather than hidden. The leakage lens noted
  it had not checked whether PWS3's export shared the fix; **it does** —
  `backends/psafe3.py:2873` uses `base.CsvWriter`, and `validate.sh` bans a raw `csv.writer`
  outside `base.py`. **[re-gate]**
* **LEAKAGE-04 — FAIL.** All six titles reproduced; an entry titled `a"b`, a perfectly legal
  KeePass title, answered `internal: the KDBX engine could not open this database` — a sentence
  that was not true. Fixed — I32.

---

### 5.4 Untrusted input, parser safety and resource exhaustion (A3 — the file is the attacker)

**[attack]**

| Attack | Verdict |
|---|---|
| KDF parameters at and over the ceiling: Argon2 `m=1 GiB, t=32, p=8` exactly at the clamp and `m=4 GiB, t=1e6, p=255` over it; AES-KDF rounds at exactly 100 000 000 and at 1e9 — on `unlock`, `probe` and the corpus path | **PASS** — over-limit refused in ~1 s by `_clamp_kdf` before any derivation; the at-limit Argon2 file peaked ~1.07 GiB and was still stopped by the header-hash check; the at-limit AES-KDF file was caught by the 20 s `kdf_budget` backstop. None reached OOM |
| PWS3 `ITER` at 0, 1, 2047, 262144, 8388608, 2³¹, 2³²−1 | **PASS** — all clamped by `check_pws3_iter` before stretching |
| Verify-before-use (I6): every corpus file and every crafted file | **PASS** — no sentinel ever leaked. Flipping any header/ciphertext/HMAC byte yields `bad-credential` or `invalid` with the same flattened detail; a wrong passphrase and a corrupt file are indistinguishable to the client |
| PWS3 hostile field lengths (`0xFFFFFFFF`, a 2 GiB attachment) | **PASS** — fail O(1) against `check_length`/`available`, never allocate |
| XML hardening on **every** parse, not just the first | **PASS** — the module-global `_HardenedEtree`/`_BoundedZlib` proxies are installed at import and re-asserted idempotently with a canary that **fails closed**. Billion-laughs, an external entity to `file:///etc/shadow` + `/etc/hostname` + a loopback HTTP URL, and 10 000-deep nesting all `invalid`, with no file disclosure, no SSRF, no `RecursionError`. The key-file parse routes through the same parser |
| Decompression bounded incrementally rather than after the fact | **PASS** — `decompressobj(...).decompress(data, MAX_INNER_BYTES)` with `unconsumed_tail`/`eof` checked, so the size bomb is caught mid-inflate (peaked ~577 MB, returned `invalid`) |
| Group-depth exhaustion: a synthetic KDBX4 with 250 nested groups | **PASS** — unlocks, and `tree()` refuses with "nested deeper than 64 levels"; PWS3 derived group paths depth- and count-capped the same way |
| PWS3 exhaustion: a 120 MiB body just under `MAX_SAFE_BYTES` with 10⁶ zero-length fields; files with up to 800 k fields | **PASS** — all `bad-credential` in ~1–2 s with bounded RSS. The field-count cap (`MAX_ENTRIES*8`) plus a single bulk CBC decrypt keep it linear: PWS3 shows no analogue of the KDBX quadratic |
| Request framing at the boundary | **PASS** — exactly `MAX_REQUEST_BYTES` accepted, +1 refused by arithmetic before the allocation grows; duplicate keys collapse last-wins harmlessly; non-UTF-8 and embedded-NUL bodies `invalid`; a 100 000-digit integer literal rejected |
| Registry attacks (I1/I4): a >64 KiB entry; nested array/object; ids and paths with NUL, newline, `..`, `/var/../etc` | **PASS** — each dropped with a reason, and every drop **fail-closed** — never defaulted to the permissive class |
| A NUL in an attachment name | **PASS** — no filesystem path to reach: `attach_get` compares `att.filename == name` and streams through the Cockpit channel; `export`/`save-as`/`restore` derive names helper-side and reject slashes, backslashes, NUL and dot-leading names |
| The whole committed 135-file corpus through the real helper with per-child RSS and wall-clock measured | **PASS** — every case matched its expected taxonomy inside its budget. Re-run in the re-gate: **67 cases, 0 disagreed with their sidecar** **[re-gate]** |

#### Findings

* **INPUT-1 — FAIL.** 100 000 entries in a 3.8 MB file: 46 s at 100 % CPU, 313 MB RSS, and
  **accepted**. `MAX_ENTRIES` was checked after `PyKeePass(...)` had already parsed the payload,
  and pykeepass evaluates `tree.getpath(elem)` once per failing protected value, which is
  O(N²). On an admin safe the burnt core and memory are root's. Fixed — I25: the clamps moved
  into the parse and `Limits.parse_budget()` preempts with `setitimer(ITIMER_REAL)`, its
  exception deriving from `BaseException` so pykeepass's and construct's broad handlers cannot
  swallow it. Same file now: `invalid: opening this database exceeded its 20.0s budget` at 20 s.
* **INPUT-2 — FAIL.** 100 000 open brackets → `RecursionError` → `{"error":"internal"}`, in the
  same breath as `not json` correctly getting `invalid`. Taxonomy, not denial of service (bounded
  at ~0.1 s by Python's recursion limit) — but the audit log and the client both key off that
  code. Fixed — I33.

---

### 5.5 Durability, concurrency and data loss

**[attack]**

| Attack | Verdict |
|---|---|
| **SIGKILL at every step of the save sequence.** A custom `sitecustomize` interposer counted every `os.open`/`write`/`fsync`/`replace`/`unlink`/`makedirs`/`fchmod` touching the safes directory and killed at the Nth. A baseline save is exactly 22 such operations, so the whole sequence was enumerated and killed at every one of N=1..23 | **PASS** — `BROKEN AT: []`. The safe always existed, always hashed to either the old or the new bytes, and always opened. The only call that touches the target is `os.replace`, it is last, and the temp file is in the same directory |
| The same, randomised: 120 iterations mixing kdbx and psafe3 with random syscall indices 1..26 **and** wall-clock SIGKILL at a random 50–1200 ms offset (arbitrary instruction boundaries, not only syscalls) | **PASS** — `iterations 120 killed=94 completed=26  BROKEN COUNT: 0` |
| Beat the `(mtime_ns, size, sha256)` fingerprint — rewrite the safe between unlock and save and restore `mtime_ns` with `os.utime` | **PASS** — `conflict: the safe file changed on disk since it was unlocked`, and the foreign bytes still on disk afterwards |
| The same with a **same-length one-bit change and the identical `mtime_ns`**, so two of three fields match exactly | **PASS** — still `conflict`, still nothing written. sha256 over the whole file is not spoofable and the check is not short-circuited by the cheap fields |
| Two `open` sessions unlocking the same safe, both editing, both saving | **PASS** — first `{"ok": true}`, second `conflict`, file holds the first session's value. No silent merge, no lost update |
| A foreign KeePassXC-shaped lock file present | **PASS** — `conflict: the safe is locked by keepassxc…`, original unchanged, holder name sanitised |
| A symlink at the lock path | **PASS** — `O_EXCL` wins over `O_NOFOLLOW`, so `EEXIST` → an ordinary `Conflict` rather than a followed link |
| A stale `<path>.tmp-<otherpid>` in the directory | **PASS** — ignored; save succeeds; never mistaken for the safe |
| Full and read-only filesystems: seven free-space levels on a 256 K tmpfs (200/2000/4200/4700/5000/9000/20000 bytes free) | **PASS** — every failing case left `unchanged=True` and `reopen=True` |
| A read-only safe directory (0500), as a genuinely unprivileged user | **PASS** — `internal: lock file could not be created`, original untouched, no debris |
| The backup directory replaced by a regular file | **PASS** — `internal / FileExistsError`, original untouched |
| Inode exhaustion (tmpfs `nr_inodes=64` driven to zero) | **PASS** — three saves failed at the lock with `ENOSPC`, no debris, original unchanged, and the save succeeded normally once inodes were freed. ENOSPC, EROFS and EDQUOT all land after the backup and before `os.replace` |
| Force the backup ring to prune the only good copy | **PASS — could not.** `keep` is bounded to [1,100] by `validate_entry` before the backend sees it and `_ring_backup` refuses `keep < 1` as a second gate; the pruner sorts on a microsecond-resolution UTC field that comes first in the name, so lexical order is chronological order, and it only deletes `gens[:-keep]` — the newest generation is structurally unreachable |
| Backup file modes on every path, including a mid-save kill and `restore-backup`'s own pre-restore backup | **PASS** — every generation 0600 via explicit `os.fchmod`, ring directory chmod'ed 0700 even when `makedirs`' `exist_ok` skipped the mode |
| `restore-backup` as a cross-user primitive | **PASS** — `_read_backup` refuses a generation whose `st_uid != geteuid()` and refuses any group/other bit; `atomic_replace` passes `expect_uid=geteuid()`; the name is checked by membership of the `scandir` listing rather than by path sanitisation, so no traversal-shaped name survives |
| **A hypothesis that turned out to be wrong, recorded rather than reported:** that `LockFile.lock_path_for(path, "psafe3")` collapses to the safe's own path for an extensionless path, which with `override_stale` would unlink the safe | **PASS — the hypothesis was false.** `os.path.splitext(p)[0] + ".plk"` maps `/x/team` to `/x/team.plk`. Measured across five path shapes. The only residue is that two differently-named safes in one directory can share one `.plk`, costing a spurious `Conflict` and never a byte |

**Two hygiene observations, deliberately not reported as findings** because reaching them needs
write access to the safe's own directory — the owner for a user-class safe, root for an
admin-class one, and root is out of scope: `os.makedirs(bdir, exist_ok=True)` follows a symlinked
backup directory without complaint, and an operator-owned 0500 ring directory is silently
chmod'ed back to 0700. A deliberately read-only ring is not honoured. Worth an operator's
attention; not a boundary crossing.

#### Findings

* **DURABILITY-1 — FAIL, and the most serious of the fourteen.** `_ring_backup`'s copy loop
  advanced by the bytes **read**, not the bytes written. On a 256 KiB tmpfs a 4661-byte safe
  produced a 4096-byte "generation" that was `fsync`'d, listed by `backups` with a plausible size
  and timestamp, and accepted by `restore-backup` — which wrote it over the live safe, after which
  the safe did not open. Some of those saves returned `"saved": true`. Fixed — I26, with an AST
  ban (`tests/ban_os_write.py`) that **counts** rather than describes: exactly one `os.write` call
  node in the program, inside `write_all`. `base.py` is deliberately not exempt — the first
  version of that ban exempted it and passed with the bug put back.
* **DURABILITY-2 / DURABILITY-5 — FAIL.** An orphan lock at 0 bytes free wedged a safe
  permanently (`acquire()` raised from inside `__enter__`, so `__exit__` never ran); and a
  *directory* at the lock path produced `internal / IsADirectoryError` with `override_stale`
  unreachable, because the error was raised inside the `except FileExistsError` handler where the
  sibling `except OSError` cannot catch it. Fixed — I28.
* **DURABILITY-3 — FAIL.** Every `restore-backup` reply said "…so this restore is itself
  undoable"; measured with keep=3, four saves then five restores left the starting state in zero
  of three slots. Fixed — I33. The finding also claimed an unauthenticated destruction path for
  A4; **the skeptic refuted that half and the refutation stands**: script in the Cockpit origin
  has `cockpit.spawn` with arbitrary argv and can simply unlink a user-class safe, so the verb
  grants no primitive such an attacker lacks. What was fixed is an over-claiming confirm string.
* **DURABILITY-4 — FAIL.** `_read_backup` bounded a generation by "not empty" plus four bytes of
  magic — and a prefix of a real database keeps its magic. Fixed — I27, with `verify_structure`
  whose ABC default **refuses** rather than returning true, and which is looked up through
  `load_backend_class` rather than `backend_for` because the lazily-imported module would
  otherwise raise `Unsupported` and be read as "no check exists". That last detail was caught by
  the regression test, not by review.

---

### 5.6 The browser surface, and every oracle the interface offers (A2/A4)

Run against the **live** Cockpit 360 page at `https://localhost:9090/secrets`, signed in as
`cptest`, against a deliberately hostile user-class KDBX safe registered in the real
`/etc/cockpit-secrets/safes.d`. Nothing stubbed. **[attack]**

| # | Attack | Verdict |
|---|---|---|
| 1 | HTML/script injection through every string field: title `<img src=x onerror="window.__PWN=1;document.title='PWNED'">`, username `</span><script>…</script>`, url `javascript:…`, notes `data:text/html,…`, group and entry names of the same shapes, custom fields named `<b>bold-name</b>`, `style`, `__proto__`, `constructor`, an attachment named `evil.html` — rendered in the table **and** the detail panel | **PASS** — `__PWN*` keys `[]`; `document.title` "Secrets"; `img` count 0; every anchor on the page `["#sec-main"]`; zero elements with any `on*` attribute; the payload entity-escaped inside `<h3>`/`<dd>`. The page has exactly one `innerHTML` mention in 6 469 lines and it is a comment. Entry URLs are not rendered as links, so there is no `href` sink |
| 2 | CSP violations, collected in every frame via a context init script | **PASS** — `[]`. Console errors and pageerrors from the plugin's own URLs `[]`. `manifest.json` carries no `content-security-policy` key |
| 3 | DOM-id collision: a tag and a custom field both named `sec-agent-banner`, a real id the page uses | **PASS** — duplicate-id scan `[]`. Every generated control id is `"sec-c" + (++CTRL_SEQ)`; no id is derived from safe content |
| 4 | ANSI / control characters | **PASS** — could not be placed in a KDBX at all: lxml refuses `\x1b`/`\x07`. `emit()` escapes every C0 control even with `ensure_ascii=False`, and `_sanitize_detail` strips them from every error detail. RTL override, zero-width and BOM reach the page and render as inert text |
| 5 | `a.download` with a traversal-shaped name (`../../../../../../tmp/PWNED-TRAVERSAL.txt`) | **PASS** — Chrome sanitised it to `_.._.._.._.._.._tmp_PWNED-TRAVERSAL.txt`; nothing written outside the download directory. The blob is created `application/octet-stream` on purpose, so a stored `text/html` attachment cannot choose how the origin renders it |
| 6 | A 10 MB single-line value, then 2 MiB of incompressible hex to get past the decompression guard | **PASS** — 2 097 152 characters revealed in 652–702 ms with no hang, no console error, correct re-masking |
| 7 | UI spoofing: an entry whose username reads "Administrative access required" and whose notes draw an ASCII fake unlock prompt (`.sec-value` is `white-space: pre-wrap`, so it does render multi-line) | **PASS** — it renders inside the bordered monospace value box under the widget's own header and countdown; it cannot create an input, cannot escape the box, and cannot reach the topbar or the agent banner, which live above the view switch |
| 8 | I11 as a **difference**: localStorage, sessionStorage, `indexedDB.databases()` and `document.cookie` snapshotted before the unlock modal opened and again after a successful unlock | **PASS at the time** — keys added `[]`, values changed `[]`. **This is the assertion that now fails; see REGATE-04** |
| 9 | What an XSS landing after the unlock can actually reach: `Object.getOwnPropertyNames(window)` diffed against a fresh blank same-origin iframe | **PASS** — the plugin adds **nothing**; the only extras are `cockpit` and `debugging`, both from cockpit.js. `window.SESSION`, `.BROWSE`, `.SCHEMA`, `.PROBES`, `.WIPERS`, `.CLIP`, `.SAFES` all `undefined` (the file is one IIFE). No element carries any `data-*` attribute. An XSS finds no handle and no value; it would have to keylog the modal |
| 10 | A revealed value surviving in the DOM: reveal, switch entry mid-countdown, go back to the list, search `document.documentElement.innerHTML` for the marker | **PASS** — absent in both cases. `hideNow()` clears and appends a fresh mask node rather than hiding a live one |
| 11 | Clipboard expiry, with `navigator.clipboard.writeText` instrumented from an init script | **PASS** — write #1 (len 26) resolved, the chip counted down, at t+15 s write #2 (len 0) resolved and `readText()` returned `""` |
| 12 | Timing: wrong vs right passphrase, 200 samples each, real 0.75 s floor, lockout cleared between samples | **PASS** — `wrong n=200 min=1.0249 med=1.0525 max=1.0946`; `correct n=200 min=0.7681 med=0.8265 max=0.8743`. Fully separated in the direction I16 requires: a wrong passphrase never answers faster than a right one. Two *different* wrong passphrases are indistinguishable |
| 13 | Is the floor on every credential path or only `unlock`? | **PASS** — `entries`/`reveal`/`attach-list`/`history` with a wrong passphrase all ~1.06–1.09 s via `need_backend → do_unlock`. `export` returns in 0.177 s because the class gate refuses before any credential is touched, which is correct |
| 14 | Existence oracle: a safe that exists vs one that does not vs one you may not reach (n=30 each) | **PASS** — 0.3192 s / 0.1822 s / 0.1858 s. The last two are distinguishable by code, not by timing, and it is not a leak: `v_list` deliberately names every registered safe to every caller with the reason it is unusable |
| 15 | Does `probe` over-share with someone who cannot open the safe? | **PASS** — `gate()` runs before `resolve_entry`, `load_backend_class` and `_guard_file`, so a non-admin gets `access-denied` and zero header facts |
| 16 | Is "a non-PWS3 file answers `invalid`, not `bad-credential`" a decryption oracle? | **PASS — measured and it is not.** The gap is real (0.9566 s vs 1.0659 s, non-overlapping) but the answer is passphrase-**independent**, and the ~110 ms is the cost of importing the kdbx backend before `FailFloor` starts. It is a function of the safe's declared format, which `list` and `probe` publish anyway |
| 17 | Entry-uuid and custom-field existence | **PASS** — distinguishable by detail but only to a caller who already supplied the passphrase and can enumerate everything with `entries`. No boundary crossed |
| 18 | `health` and `audit-tail` across principals, live as `cptest` | **PASS** — state and audit paths under `/home/cptest`, every one of 50 audit rows uid 1005, nothing of uid 1000's visible; both verbs with `superuser:"require"` refused by the bridge before the helper runs |
| 19 | Can the failure floor be starved? | **PASS** — `FailFloor` is `time.monotonic()` plus one `sleep`, so load can only lengthen it; at 50-way concurrency each attempt took ~12 s wall. **The lockout is a different matter and is REGATE-01** |
| 20 | Can a hostile file name a response key? | **PASS** — `scrub_listing` rebuilds every non-value-bearing response and drops 13 value-shaped names; `attach-list` rebuilds its rows key by key; `entries`/`history`/`attach-list` have fixed shapes |
| 21 | Attacker text inside a helper `detail`, which the page renders verbatim | **PASS** — the only interpolations into `probe` warnings are integers and a Twofish provider name; `_sanitize_detail` strips controls, collapses whitespace, truncates at 240 |
| 22 | `redact()` as an oracle | **PASS** — the only string it can reveal is the candidate the caller supplied, and `do_unlock` zeroes every `Secret` in a `finally` before any response is serialised |
| 23 | The page's own network surface | **PASS** — no `fetch`, `XMLHttpRequest`, `location.*`, `window.open`, `<img>`, `<iframe>` or external asset anywhere in `secrets.js`; a revealed value is never passed to `announce()`, `title`, or any attribute |

#### Findings and follow-ups

* **WEB-01 — FAIL.** Reproduced in this re-gate as **REGATE-01**.
* **The attachment blob URL outlives an explicit Lock.** The leakage lens reported this from
  reading `secrets.js:4715-4725` — `downloadAttachment()` revokes on a fixed 10 s `setTimeout`
  and `lockNow()` does not revoke — and honestly declined to report it as a finding because it
  could not drive a browser. **Measured in this re-gate**, in the live page against the real
  helper, with `URL.createObjectURL`/`revokeObjectURL` hooked from a context init script: **[re-gate]**

  ```
  downloaded attachment: walkthrough.txt
  blob URLs minted=1 revoked=0
  BEFORE LOCK, fetch(blobUrl): refused   cspViolation="connect-src <- blob"
  Lock clicked; page is back on the safe list
  AFTER LOCK:  this URL revoked? false   fetch still refused (connect-src)
  AFTER LOCK, via window.open navigation: document reachable but EMPTY
               (the blob is application/octet-stream, so it downloads rather than renders)
  AFTER LOCK, re-download via a synthetic <a download>:
               SUCCEEDED — 47 decrypted bytes written as exfil-after-lock.bin
  ```

  So: the code fact is confirmed — Lock does not revoke it. The *script-readable* routes are
  closed, and closed by a control this package deliberately does not relax: `connect-src` refuses
  `fetch`/XHR against the blob, with Chrome naming the directive, and the deliberate
  `application/octet-stream` type means a navigation yields an empty document. What remains is
  that script in the origin can re-trigger a **download** of the decrypted bytes for up to 10 s
  after the operator has locked the safe. Severity low — it needs A4, it needs the attachment to
  have been downloaded already in that session, the window is ≤10 s, and the bytes land on the
  operator's own disk rather than reaching the attacker directly. It is nonetheless a real gap
  between what the Lock button says and what the browser is still holding. Recorded as **I36**.
* **`clipboardClear()` announces success before the write resolves.** `secrets.js:2604` kills the
  interval and sets `CLIP.armed = false` **before** the async `writeText`, catches a rejection
  with a bare `/* best effort */`, then unconditionally announces "Clipboard cleared because …".
  If the write ever rejects — Chrome's documented "Document is not focused" is the obvious case —
  the password stays in the clipboard, the countdown is gone, nothing retries, and the page says
  it succeeded. **NOT REPRODUCED.** Two independent lenses tried: Playwright's Chromium never let
  a tab actually become hidden or lose focus (`visibilityState` stayed `"visible"` and
  `document.hasFocus()` stayed `true` through `bringToFront()` on a second tab, headless **and**
  headed under Xvfb), and revoking the `clipboard-write` permission mid-countdown did not make
  `writeText` reject. Neither lens reported it as a finding and neither does this document.
  Testing it needs a real desktop browser a human can defocus. Recorded as **I37**.
* **The agent's `_note()` does not redact.** `agent/secrets_agent.py:348` writes to stderr
  directly where `secrets-admin:401` passes through `redact()`. Every current call site passes a
  static string or an already-redacted `SecretsError.detail`, so there is no live escape — this
  is a hole in a last line of defence, which is the same shape as I30 and the same reason it
  matters. Recorded as **I38**.

---

## 6. The NOT-ATTEMPTED register

Nothing in this section was tested. It is here so that no reader mistakes an absence for a pass.

| Area | Why not | Consequence |
|---|---|---|
| **A real YubiKey** | No token exists on this host and nothing on it can create one. | The challenge/response arithmetic is verified against KeePassXC 2.7.10's own source and against two frozen digests recomputed independently, but **no token has ever answered a challenge from this program.** `docs/COMPATIBILITY.md` §2.3 and §10 say so. CRYPTO-03 is a statement about the challenge the *file* publishes, which needed no hardware. |
| **A `.psafe3` written by the real Password Safe GUI** | `pwsafe` 1.22 is wxWidgets-only. Measured: `pwsafe --validate` maps **no** X window under Xvfb and never returns, while `xmessage` on the same Xvfb maps one — so the display is real and pwsafe is the thing that will not be driven. `--help` exits 255 and writes to stderr. | I19 stays partially open for PWS3. Compensating: a from-spec third implementation, a Go oracle, and upstream C++ read by hand (`docs/formatV3.txt` sha256 `68cdd7515ad5bdff…` matches the host copy). Where this report says "the reference would do X", that is **read from C++, not executed.** |
| **The unlock agent at real root** | `secrets-agent` is not installed on this host — no binary, no unit, no socket — and it is off by default in the registry. | The `SO_PEERCRED`, deadline-cap and ticket-handling attacks were **reasoned about from source and from `docs/CONTRACT.md`, not executed**. `systemd-analyze security` on the units was N/A because no units exist. I18's second residual — that the admin class separates operators by *instance* rather than by peercred — is unexercised. |
| **KDBX3 tamper-differential fuzzing** | KDBX 3.1 has no authenticated encryption; the code opens it read-only behind a persistent banner and I20 accepts the residual by design. | Hunting there is hunting for a documented property. The KDBX3 read-only refusal and its banner were **not** exercised in the live page either. |
| **The payload block-size ceiling at the limit** | `_verify_kdbx4` bounds a block at `MAX_FIELD_BYTES` (4 MiB); KeePass, KeePassXC and pykeepass all write 1 MiB blocks (measured: a 3 MiB payload produced 1 048 576-byte blocks). No legitimate writer that exceeds it could be produced. | A writer choosing a larger block size would be refused. Not reported as a finding because there is no such writer to prove it with. |
| **Genuine power loss / barrier failure** | Processes were killed; power was not cut, and `dm-flakey`/`dm-log-writes` were not used. | The `fsync` of the temp file and of the directory are present and in the right order, which is what a review can establish. Whether the underlying device honours them is untested. |
| **DURABILITY-1's short write on ext4** | Reproduced for real on tmpfs (which returns partial counts at ENOSPC) and separately by injection. ext4's delayed allocation typically defers ENOSPC to `fsync` rather than returning a short count. | The defect is unconditional and the injected reproduction is filesystem-independent, but the *frequency* is filesystem-dependent: tmpfs, NFS and CIFS are the realistic triggers — **and this project's own source tree is on an SMB share.** |
| **The hostile-filesystem matrix against PWS3** | The 120-iteration randomised kill run covered `lab-pws3`; the full-disk / read-only / inode-exhaustion / symlinked-ring matrix was run against KDBX only. | The write primitive is shared (`psafe3.py:1425-1427` goes through the same `LockFile` and `atomic_replace`), so identical behaviour is expected — but it was not measured. |
| **PWS3 through the leakage lens** | Every leakage test ran against KDBX. | `backends/psafe3.py`'s export and error paths were not exercised for leakage. Its CSV writer **was** confirmed in this re-gate to be the neutralising one. |
| **PWS3 and KDBX3 through the browser lens** | Only KDBX4 fixtures were built for the page. PWS3's text fields are not constrained by XML the way KDBX's are, so PWS3 is the right format for the control-character rendering tests KDBX simply refused to store. | The rendering of odd encodings from a PWS3 safe is untested, and the browser lens declined to author a `.psafe3` fixture with the code under attack, which was the right call. |
| **Two concurrent operators, and a root helper's `/proc`** | All `/proc` probing was against a user-class helper running as uid 1000. | The admin path's `/proc` from a second uid is unmeasured. |
| **Swap** | The helper reports `mlockall` failing with ENOMEM for every non-root invocation (`RLIMIT_MEMLOCK` is 8192 bytes here), so a user-class helper's decrypted safe is swappable, and `/swap.img` is unreadable without root. | Stated honestly in I14 and `docs/ROOT-VERIFICATION.md`. **Unverified rather than disproven.** |
| **Playwright trace/video capture** | Not enabled by `run-live.sh` as far as could be determined, but this was not measured. | Only the screenshots on disk were audited for mode. Those are all 0600. |
| **`COCKPIT_SECRETS_LIB` against a root helper** | The code refuses it when euid == 0 (`secrets-admin:176`), confirmed by reading; driving a root helper *as* `cptest` needs the superuser path `cptest` cannot obtain. | Refusal verified statically, not empirically. For a non-root helper it is honoured, which only runs code as the caller themselves — no escalation, by design. |
| **The "script's own directory is group-writable" warning** | On the installed footprint the helper is root-owned in `/usr/local/sbin`, so the warning path is unreachable by an unprivileged user. | It would only bite if root ran the helper directly out of the group-writable source tree, which is not the installed configuration. |

---

## 7. Host state after this re-gate

* **The package is installed and is the 0.2.1 source**, verified by sha256 across all eleven
  installed artefacts (§3). This is a change from before the re-gate, when the host served 0.2.0.
* **The registry is empty.** `secrets-admin list` → `{"safes": [], "registry_errors": 0}`.
  `/etc/cockpit-secrets/safes.d` holds only the two shipped `.example` files.
  `/etc/cockpit-secrets/safes/` is empty. The `90-attack-hostile.json` entry that earlier reports
  mention was already gone when this re-gate began.
* **The three throwaway safes** built for the live walkthrough
  (`zz-throwaway-admin-kdbx`, `zz-throwaway-user-kdbx`, `zz-throwaway-user-pws3`), their registry
  entries, their backup rings and `/home/cptestadm/.local/share/cockpit-secrets` were **removed**.
  So was the `zz-lockout-probe` safe used for REGATE-02.
* **`/var/lib/cockpit-secrets/state` is empty** — every lockout counter this re-gate created was
  removed. **`/var/lib/cockpit-secrets/exports` is empty**, which matters: a file there is an
  entire safe in plaintext.
* **`cockpit.socket` was never stopped, started or reloaded**, and has been up since
  2026-09-01 01:59:08.
* **No `git` write command was run.**
* **The credentials directory `${XDG_RUNTIME_DIR}/cockpit-secrets-live` remains**, 0700 with five
  0600 files. It is not this re-gate's creation — it predates it — and it is on tmpfs, so a reboot
  removes it. It holds two Cockpit account passwords and the published fixture passphrase.
* Live-suite artefacts under `tests/browser/artifacts/` were rewritten by two runs. They are
  git-ignored, all 0600, and two of them contain plaintext secret material by design (a
  screenshot of a revealed password and a decrypted attachment body) — the published fixture
  passphrase, in throwaway safes that no longer exist.
* Working files from this re-gate (probe scripts, raw logs, timing captures) are under this
  session's scratchpad only. Nothing was written to `/etc`, `/usr` or `/var` except the install
  itself and the throwaway registry entries that were then removed.

**§8.6 below supersedes this section for the state of the host as it stands now.**

---

## 8. The close-out pass, 2026-09-04

The re-gate ended with three defects open (`REGATE-01/02/03`) and one test defect
(`REGATE-04`), each recorded rather than rushed. This section is the record of closing them.
Two agents fixed the three product defects; this pass integrated their work, **re-verified all
three without taking either report on trust**, fixed REGATE-04, reinstalled, re-ran the live
walkthrough and swept the documents. **[close-out]** marks what was measured here.

### 8.1 The independent verification, and what it found

Taking a fix report on trust is how REGATE-03 survived a remediation in the first place — the
remediation *said* the PWS3 half was fixed. So each of the three was re-checked with a probe
written for this pass, not with the fixing agent's own test.

**REGATE-03 / I41 — corrupt the serialisation in flight, and see which layer catches it.**
The probe replaces the bytes a save is about to write with the same bytes with one byte
bit-flipped, for **both** backends, and asks whether the save catches it or the next unlock
does. A corrupt MAC is the cleanest injection because it is what a writer bug looks like from
the reader's side and it cannot be confused with a bounds check the writer happens to share
with the reader. **[close-out]**

```
psafe3   save verdict : Conflict
         detail       : the database we built cannot be read back, so it was not written:
                        the HMAC of a file we just built does not verify
         live file    : UNCHANGED
         fresh unlock : opens, 4 entries
kdbx     save verdict : Conflict
         detail       : this database cannot be written without losing data: the database
                        could not be re-read after a trial serialisation
         live file    : UNCHANGED
         fresh unlock : opens, 6 entries
```

Then the negative control, which is the half that makes the above mean something. With
`self.verify_own_output(data, expect)` deleted from `Psafe3Backend.save` — and nothing else
changed — **the defect reproduced end to end and was watched failing**:

```
psafe3   save verdict : save() returned {'ok': True, 'bytes': 1544, 'conflict': False}
         live file    : *** REWRITTEN ***
         fresh unlock : BadCredential: the passphrase did not open this safe
```

That is I41's exact shape: a save that reports success, a rewritten file, and a reader that
blames the operator's passphrase. The line was restored and the probe went green again.

**A methodological note, because the first attempt at that control was invalid.** The probe
originally worked in `/tmp`, and `atomic_replace` refuses a backup ring under `/tmp` — so the
reverted run stopped at a *different* guard and printed a `conflict` that had nothing to do with
the fix. It looked like a pass. The probe was moved to `$XDG_RUNTIME_DIR` and only then did the
control fail the way it had to. A negative control that stops early is worse than none, because
it certifies the wrong thing.

**REGATE-01 / I39 — N concurrent guesses must leave the counter reading exactly N.** The
shipped regression test asserts `counter == attempts evaluated`, which is the right invariant
but is satisfied at N=1 because the backoff refuses attempts 2..N. To measure the literal
lost-update property the probe drives a throwaway copy of the helper with
`LOCKOUT_THRESHOLD`/`LOCKOUT_SAFE_THRESHOLD` raised and `LOCKOUT_BASE_SECONDS` zeroed, so all
30 attempts are **admitted** and a lost increment is the only thing that can make the counter
read less than 30. Nothing shipped was modified; the copies live in the scratchpad. Both
helpers, same hermetic registry, same 30 concurrent processes: **[close-out]**

```
pre-fix helper (committed HEAD ef44542)
   outcomes    : {'bad-credential': 30}
   counters    : {'fail.1000.lab-kdbx41.json': 3}
   counter sum : 3    <- 27 increments lost
fixed helper (working tree)
   outcomes    : {'bad-credential': 30}
   counters    : {'fail.1000.lab-kdbx41.json': 30}
   counter sum : 30   <- exact
```

**REGATE-02 / I40 — two administrators, two counters, at a real euid 0.** `unshare -r` gives a
real euid 0 with a real uid of 0 behind it, so this one can only be measured through the root
runner. `tests/root/45-lockout-principals.sh`, submitted to `/srv/jobs`, **35 checks, 0
failures**, including the three that are the defect itself: **[close-out]**

```
ok  the counter file names A's REAL uid (1006), not euid 0
      -> /var/lib/cockpit-secrets/state/fail.1006.zz-throwaway-admin.json
ok  there is NO euid-keyed counter (the I40 file name)
ok  operator B, who has typed nothing, opens the safe with the correct passphrase
ok  A is still inside their own backoff window, correct passphrase and all
ok  A's counter records exactly the one failure A made
```

The third and fourth of those have to hold *together*: "fix it by counting nobody" would pass
the B check and destroy I16.

### 8.2 REGATE-04, fixed by somebody who could report on it

Its own entry asked for that, and this pass is it. The repair is in I42 in full; the short form
is that a length comparison was replaced by an in-page content probe, and the exemption it
needed was bounded by name **and** by content rather than by name alone. The proof that it is
strictly stronger rather than merely quieter is that the old check got two of four scenarios
wrong and the new one gets none wrong — including a same-length overwrite with the passphrase,
a real leak the old check could not see. `tests/browser/storage-check.selftest.js` pins that,
needs no browser, and runs in `run_tests.sh`.

### 8.3 The gates, from a clean state **[close-out]**

Every gate below was run against the final state of the tree, VERSION 0.3.0.

```
./check.sh                        secrets.js syntax OK
./validate.sh                     OK — 48 standing bans PASS, 0 FAIL, 38 unit tests OK
python3 backends/base.py          131 checks, 0 failure(s)
python3 -m backends.psafe3        psafe3 self-check: OK
python3 -m backends.kdbx          kdbx self-check: OK
python3 agent/secrets_agent.py --selfcheck   61 checks, 0 failure(s)
tests/corpus/gen_corpus.py --check           67 cases, 0 disagreed with their sidecar
tests/oracle/build.sh             OK  pws3_oracle (3581529 bytes), go1.26.0
./run_tests.sh                    OK — 19/19 PASS

integration, each run directly:
   flow 86/0   conformance 83/0   properties 27/0   newverbs 220/0
   agent_cycle 45/0   adversarial 87/0   lockout 56/0   corpus_vs_helper 67/0

tests/root/run-all.sh (full 10 -> 90, through /srv/jobs, real euid 0):
   10-install 7/0    20-verify-install 34/0   30-throwaway 11/0   40-admin-allow 98/0
   45-lockout-principals 35/0   50-user-class 34/0   60-uninstall-reinstall 35/0
   90-cleanup 14/0                                  all eight steps exit 0

./tests/browser/run-live.sh (installed package, this host's live Cockpit, exit 0):
   live-ui      109/109 checks held   items 1, 2, 3, 4, 5, 6, 7, 10
   live-access   22/22  checks held   items 8, 9
   131 checks held, 0 FAIL, 0 NOT-ATTEMPTED — all ten items
```

**Nothing was weakened to get any of that green.** The one place a constant is touched anywhere
in the suite is the psafe3 self-check's `Limits.MAX_ENTRIES = 0` for the duration of one save,
restored in a `finally` — which *induces* a genuine reader/writer asymmetry rather than removing
a guard, and is the honest twin of the KDBX test it was modelled on. The probe helpers in §8.1
are throwaway copies in a scratchpad and are not the shipped gate.

### 8.4 What the host serves, after the close-out **[close-out]**

`tests/root/run-all.sh` reinstalled from the 0.3.0 tree (step 10, then again at step 60), and
served-versus-source was checked by sha256 for **all eleven** installed artefacts — the four
package files, the helper, the five backend modules and the registry schema. All eleven match.

```
/usr/share/cockpit/secrets/secrets.js                 7f03c81c8919baf3260229a17c13e452707c0ec866fa9ecc2e4c397d1082db08
/usr/local/sbin/secrets-admin                         54d767c0d528ce0281ae1b8944973c01702aabfd6a82a7e8b12b78b80572b469
/usr/local/lib/cockpit-secrets/backends/base.py       58fd58c9ce8722c77011df9113a24d38bd43dbfe8fa00b04d3c5efd95b44736b
/usr/local/lib/cockpit-secrets/backends/psafe3.py     1d5e41d5124f805e0751294f632f8a02e05a1c7763d80440b2df4d6375b5645c
   … and 7 more, all MATCH
```

`secrets.js` is byte-identical to the page that scored 140/140 before the re-gate, 129/130 in
the re-gate (the one failure being REGATE-04, a defect in the test) and 131/131 here;
no browser-side code changed in this round. `cockpit.socket` was never stopped, started or
reloaded.

### 8.5 What is still open after the close-out

Nothing that was found is left unfixed, and these are the things the close-out could not settle
rather than chose not to. All are in `docs/RESIDUAL-RISK.md` in full.

* **Two implementations of one save-time rule.** `backends/kdbx.py` satisfies the standing ban
  with its own private `_verify_own_output` instead of the shared `Backend.verify_own_output`.
  Both were measured and both hold; two copies of a rule is nonetheless the shape that produced
  REGATE-03. Follow-up, not a defect. RESIDUAL-RISK §1.4.
* **The ban is static.** It requires a verify call in the same function body as the write; a
  backend that hid the write behind a helper method would pass it.
* **Nobody enumerated the other helper-written fields** that grow across calls the way the PWS3
  password history does. The per-save check covers the class, so this is a gap in knowledge.
* **The per-safe rate cap has never bitten on a real host.** Only three uids are in `sudo` here,
  so the per-principal backoff stops an identity-varying attacker at 3 attempts, far short of
  the cap of 20 — measured: 60 attempts cycling three uids gave 3 `bad-credential` and 57
  `locked-out`. The cap is proved at the module boundary against 25 synthetic principals. On a
  host with a large admin group it is the control that matters and it is untried there.
* **20 / 60 s are a judgement, not a measurement.** Nobody has attacked those numbers.
* **Fail-closed on a busy counter** lets somebody who can hold one counter file open deny one
  principal one safe while they hold it. Deliberate, measured (5.31 s bounded, other principals
  unaffected), and re-examinable by somebody else.
* Everything in `docs/RESIDUAL-RISK.md` Part 3 is unchanged: no YubiKey, no foreign PWS3 file,
  no KDBX 4 + AES-KDF, the agent has never run as root, and real power loss was never tested.

### 8.6 Host state after the close-out **[close-out]**

This supersedes §7.

* **The package installed is the 0.3.0 source**, sha256-verified served-versus-source across all
  eleven installed artefacts (§8.4). Installed twice during the run — `tests/root/10-install.sh`
  and again at `60-uninstall-reinstall.sh` — and audited from a **separate** root job each time.
* **The registry is empty.** `secrets-admin health` → `registry_entries=0, registry_errors=[]`;
  `secrets-admin list` → *none registered*. `/etc/cockpit-secrets/safes.d` holds only the two
  shipped `.example` files, which the registry's `*.json` glob does not match.
* **`/etc/cockpit-secrets/safes/` is empty**, and so are
  **`/var/lib/cockpit-secrets/state/`** (no lockout counter and no per-safe window left behind)
  and **`/var/lib/cockpit-secrets/exports/`** — the last of which matters, because a file there
  is an entire safe in plaintext.
* **The three live-walkthrough subjects were re-created and destroyed again.** They had to be:
  `90-cleanup.sh` removed them at the end of the re-gate, and the live suite cannot run without
  registered safes. Seeded from the **committed fixtures** through `/srv/jobs` (`cs-live-seed`),
  removed by exact path afterwards (`cs-live-cleanup`), together with their backup rings,
  `/home/cptestadm/.local/share/cockpit-secrets`, `/home/cptestadm/.local/state/cockpit-secrets`,
  and a leftover `.plk`.
* **`cockpit.socket` was never stopped, started or reloaded** — `ActiveEnterTimestamp` is still
  `Tue 2026-09-01 01:59:08 CDT`, unchanged across every job in this pass.
* **No `git` write command was run.** `git status --short` shows 19 modified and 4 new files, all
  of them this round's work.
* `/var/log/cockpit-secrets/audit.log` is **680 lines, 0600 root:root**, 407 of them naming a
  throwaway safe that no longer exists. Deliberate: an audit log is not a throwaway safe, and it
  carries no value, no entry title and no path from a request.

**What remains on the host that this pass did NOT create, and did not remove:**

* `${XDG_RUNTIME_DIR}/cockpit-secrets-live` — 0700, five 0600 files, **used but not created by
  this pass**; it predates it. It holds two Cockpit test-account passwords and the fixture
  passphrase that is published in `tests/fixtures/manifest.json` on purpose. It is on tmpfs, so a
  reboot removes it. Removing it is the operator's call, and doing so means the live suite cannot
  run again without re-creating it.
* `tests/browser/artifacts/` — 49 files, **all 0600**, rewritten by this round's live run and
  git-ignored. Two contain plaintext secret material by design: a screenshot taken deliberately
  between "Reveal" and the countdown ending, and a decrypted attachment body. Both are the
  published fixture passphrase, in throwaway safes that no longer exist.
* Two Cockpit test accounts, `cptestadm` (uid 1007, in `sudo`) and `cptest` (uid 1005, not in
  `sudo`), plus `cpadmin` (uid 1006). Created by earlier rounds; the root suite needs them.
* Working files for this pass — the two independent probes and the raw logs — are under this
  session's scratchpad only. **The throwaway helper copies used for the I39 probe, which had
  `LOCKOUT_THRESHOLD` and `LOCKOUT_BASE_SECONDS` altered, were deleted**; nothing with a weakened
  constant in it was left anywhere on this host.

---
