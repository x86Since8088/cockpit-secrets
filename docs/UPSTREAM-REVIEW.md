# Upstream review — what we adopt, what we reject, and why

Survey date: **2026-09-03**. Host: edt1, Ubuntu (`resolute` pockets), Cockpit **360**,
Python **3.14.4**, `python3-cryptography` **46.0.5** installed. Everything below marked
*(verified)* was checked on this host with `apt-cache policy`, the package file lists, or a
direct fetch of upstream source/docs — not inferred from a search snippet.

The rule for this project: **no upstream goes in without a named licence, a named
maintenance status, and a named failure mode.** A library that cannot be pinned to those
three facts is a liability in a program that holds every credential we own.

---

## 1. Availability on this host *(verified)*

| Package | Candidate | Ships | Installed? |
|---|---|---|---|
| `keepassxc-full` | 2.7.10+dfsg1-2ubuntu1 | `/usr/bin/keepassxc`, **`/usr/bin/keepassxc-cli`**, `keepassxc-proxy` | no |
| `passwordsafe` | 1.22.0+dfsg-1 | **`/usr/bin/pwsafe` only** — the wxWidgets GUI | no |
| `python3-pykeepass` | 4.1.1.post1-1 | KDBX3 + KDBX4 read/write | no |
| `python3-argon2` | 25.1.0-2 | Argon2id/d/i bindings | no |
| `python3-botan` | 3.10.0+dfsg-2 | Botan 3 FFI — **has Twofish** | no |
| `python3-pycryptodome` | 3.20.0+dfsg-3build1 | AES/ChaCha20 — **no Twofish** | no |
| `kpcli` | 3.8.1-1.1build1 | Perl KeePass CLI | no |

**The load-bearing finding:** the Ubuntu `passwordsafe` package ships **no CLI**. There is a
`pwsafe-cli` target in the upstream `pwsafe/pwsafe` tree, but it is not packaged here. So
"shell out to the reference implementation" is available for KDBX and **not** available for
Password Safe v3. The two formats therefore get different strategies, and that asymmetry is
the single most important architectural fact in this project.

---

## 2. KDBX (KeePass 2.x / KeePassXC) candidates

### 2.1 `pykeepass` — **ADOPTED as the KDBX engine**
`https://github.com/libkeepass/pykeepass` · **GPL-3.0** · actively developed (509 commits,
open issues/PRs being serviced) · distro-packaged here as `python3-pykeepass` 4.1.1.

- KDBX3 **and** KDBX4; attachments, entry history, custom fields, OTP-URI parsing.
- Pure in-process Python: **no subprocess, so no argv, no pty, no output parsing.** For a
  program whose whole job is to not leak a password, "the secret never becomes a process
  argument or a terminal transcript" is worth more than any feature.
- Dependencies (`lxml`, `construct`, `argon2-cffi`, `pycryptodome`) are all distro-packaged.

**Licence consequence, stated up front:** linking GPL-3.0 makes `cockpit-secrets`
GPL-3.0. Cockpit itself is LGPL-2.1+, which is compatible for an internal, non-redistributed
Cockpit package. `source/LICENSE` must say GPL-3.0 and the task list must not quietly
re-license it later.

**Known sharp edges to defend against, not assume away:**
- `pykeepass` will happily open a KDBX3 database. KDBX3.1 has **no authenticated
  encryption** — a tampered file decrypts to attacker-influenced XML. Treat KDBX3 as
  read-only-and-warn, and offer an explicit "upgrade to KDBX4" action, never a silent one.
- KDF parameters come **from the file**. A hostile file can specify Argon2 with
  `m=4 GiB, t=100` and OOM/park the helper. Parameters must be range-checked *before* the
  KDF runs (see I7).
- `lxml` parses the decrypted inner XML. Entity expansion / DTD handling must be explicitly
  disabled at our layer rather than trusted upstream (see I8).

### 2.2 `keepassxc-cli` — **ADOPTED as an interop oracle, REJECTED as the engine**
KeePassXC 2.7.10 · GPL-2.0-or-later/GPL-3.0 · the most-audited KDBX implementation available.

*(verified from the upstream man page)*: there is **no option that accepts a password as a
command-line argument** — credentials come from the prompt/stdin, `--key-file`, or
`--yubikey`; `-q/--quiet` silences the prompt; `open` gives a scripted shell session.
That is a genuinely good design and it is the behaviour we copy.

Rejected as the engine because driving it means either (a) a pty, or (b) piping the master
password into a child's stdin on **every** operation and screen-scraping human-formatted
output. Both add a process boundary the secret must cross for no gain over an in-process
library. Kept as an **oracle**: every database we write must open cleanly in
`keepassxc-cli db-info`/`ls`, and every database it writes must open cleanly in ours. That
interop matrix is the actual evidence for "full compliance"; a passing self-test is not.

### 2.3 `kdbxweb` + `argon2-browser` (decrypt in the browser) — **REJECTED**
MIT, well-regarded, and superficially the most attractive option: the master password never
leaves the browser.

It loses on three counts, and the third is fatal:
1. Cockpit's default CSP is `default-src 'self'` *(Cockpit ships this and it already breaks
   inline styles — cockpit#13810)*. Argon2 in the browser means WASM, which means adding
   `wasm-unsafe-eval` to the package manifest's CSP. **Weakening the CSP of a page that
   handles every password we own, in order to handle those passwords, is a bad trade.**
2. The whole encrypted database must be shipped into browser memory, where it lands in a
   GC'd heap we cannot zero, can be paged to swap, and is reachable from any XSS anywhere in
   the Cockpit origin.
3. **Enforcement moves to the client.** The user/admin split this project exists to
   implement would become a browser-side `if`, which is exactly the cosmetic gate
   cockpit-guac-rdp logged as `I4` and had to tear out. Access class must be decided by a
   process the user cannot rewrite.

### 2.4 `kpcli` (Perl), `libkeepass` (Python) — **REJECTED**
`libkeepass` is **deprecated by its own authors in favour of pykeepass** and lacks Argon2 and
ChaCha20 protected values — i.e. it cannot do KDBX4 at all. `kpcli` is another
scrape-a-CLI shape with no advantage over `keepassxc-cli`.

---

## 3. Password Safe v3 (`.psafe3`) candidates

### 3.1 `ronys/pypwsafe` — **REJECTED. Do not vendor, do not port.**
*(verified from the upstream README)*: **GPLv2, pure-Python 2**, unmaintained, Windows
unsupported, "unit tests are out-of-date", and — the disqualifier — the authors' own known-issues
list says there **may be an issue with the order in which `NonDefaultPrefsHeader` serializes
preferences for HMAC validation**.

An acknowledged, unfixed ambiguity in *the authentication tag computation* is not a rough
edge; it means the library may write files whose HMAC other implementations reject, or accept
files it should not. Its README even points readers at the official CLI instead. The
downstream fork `pypwsafev3` inherits the same lineage and the same caveat.

### 3.2 `lucasepe/pwsafe` (Go), `1uckyPh4nt0m/pwsafer` + `pwsafe` (Rust), `marcbutler/libpsafe3` (C), `Crypt::PWSafe3` (Perl) — **REJECTED as dependencies, ADOPTED as cross-reading**
Each is a sound-looking implementation in the wrong language for this codebase: pulling in a
Go or Rust toolchain, or a C library with its own memory-safety surface, to add one block
cipher to a Python helper is a large attack-surface increase for a small win. `pwsafer` is
notable as the crate that had to be re-cut when `block-cipher-trait` was yanked — a reminder
that these are small, thinly-staffed projects.

They stay useful as **second opinions when our reader and the spec disagree**. Read them; do
not link them.

### 3.3 Implement the format — **ADOPTED**
Password Safe v3 is small, frozen, and fully specified in `pwsafe/pwsafe/docs/formatV3.txt`.
*(verified against that document)* the layout is:

```
"PWS3" | SALT(32) | ITER(uint32 LE) | H(P')(32) | B1 B2 B3 B4 (4x16) | IV(16)
      | Twofish-CBC(K, HDR ‖ R1..Rn) | "PWS3-EOFPWS3-EOF" | HMAC-SHA256(L, ...)(32)
```

with `P'` derived by **iterated SHA-256 key stretching (Gladman), not PBKDF2**; `K` (record
key) recovered by Twofish-**ECB**-decrypting `B1‖B2` under `P'`, and `L` (HMAC key) from
`B3‖B4`; the HMAC covering **the plaintext field data** of every header and record field.

> Scrutiny note: a well-ranked search result confidently described this KDF as "PBKDF2 with
> SHA-256". It is not. **Implement from `formatV3.txt`, never from a summary** — that single
> error would produce a file no real Password Safe could ever open.

Five subtleties that separate a working reader from a compliant one, each of which must land
as a test:
- The HMAC covers **field data only** — not the 4-byte length, not the type byte, not the
  random padding. Getting this wrong yields a file that round-trips through *our* code and
  through nothing else.
- The EOF block `PWS3-EOFPWS3-EOF` is **unencrypted** and is what tells you where the HMAC
  starts. A file without it is truncated: refuse it, do not "recover what you can".
- `ITER` is attacker-controlled: floor it at the format's current **262 144** on write and
  range-check it on read (see I7). `ITER` from a hostile file is a CPU bomb.
- Fields are `len(4 LE) | type(1) | data | padding-to-16`; a hostile `len` is a memory bomb.
- **The HMAC is at the end of the file, so the format forces you to decrypt before you can
  authenticate.** That is inherent and cannot be fixed. What *can* be fixed: verify the HMAC
  before any decrypted value is returned, written, or logged, and treat everything before
  that point as untrusted parser input.

**Twofish** comes from `python3-botan` (Botan 3.10 — a maintained, audited, general-purpose
crypto library) with a small pure-Python fallback used only where Botan is absent. Both paths
must pass the **official Twofish ECB test vectors** in CI. A random PyPI `twofish` wheel is
not an acceptable substitute for either.

**Oracle problem:** with no packaged CLI, the interop oracle for `.psafe3` is weaker than for
KDBX. Compensate with (a) the published test vectors, (b) round-trip fuzzing, (c) at least
one file produced by the real `pwsafe` GUI committed as a fixture, and (d) a documented
manual check. Say so honestly in the docs rather than claiming parity we cannot demonstrate.

---

## 4. Bad practices found in the wild — the "do not do this" list

Collected from the surveyed projects, from web-based password-manager integrations
generally, and from this host's own issue registers. Every item maps to a `KNOWN_ISSUES` id
and to an assertion in the test suite.

| # | Bad practice | Why it is fatal here | Register |
|---|---|---|---|
| 1 | Master password on `argv` | `/proc/<pid>/cmdline` is world-readable; it reaches shell history and audit logs | I10 |
| 2 | Password in an env var | `/proc/<pid>/environ` is inherited by every child | I10 |
| 3 | Password in a temp file | Survives a crash, lands on disk, races on permissions | I10 |
| 4 | Caching the password in `localStorage`/`sessionStorage`/IndexedDB | Origin-wide, persistent, readable by any XSS in the Cockpit origin | I11 |
| 5 | Access class enforced in browser JS | Trivially bypassed by driving the helper directly — cockpit-guac-rdp `I4` | I3 |
| 6 | Trusting a client-supplied file path | Path traversal / symlink into someone else's safe | I4, I5 |
| 7 | Trusting KDF parameters from the file | Argon2 `m=4 GiB` is a remote OOM | I7 |
| 8 | XML parsed with entities/DTD enabled | XXE and billion-laughs on the decrypted inner XML | I8 |
| 9 | Returning plaintext before verifying the MAC | Turns a parser bug into a decryption oracle | I6 |
| 10 | `==` on MACs and password hashes | Timing oracle; use `hmac.compare_digest` | I6 |
| 11 | Writing the safe in place | A crash mid-write destroys the database — no undo | I12 |
| 12 | Ignoring `.lock`/`.plk` files | Silent lost-update against a desktop client | I13 |
| 13 | Assuming Python can wipe a secret | `str` is immutable and interned; only `bytearray` can be zeroed, and even then swap/core dumps leak | I14 |
| 14 | Leaving core dumps and `ptrace` enabled | `gcore` on the helper yields every plaintext | I14 |
| 15 | Logging the safe's contents on error | Tracebacks print locals; audit logs are group-readable (`wg-admin` learned this) | I15 |
| 16 | Unbounded unlock attempts | Offline-grade guessing against an online service | I16 |
| 17 | Clipboard copy with no expiry | Any page can read the clipboard afterwards | I17 |
| 18 | Weakening CSP for WASM | See 2.3 | I9 |
| 19 | An unlock agent with no idle timeout | Rebuilds the thing we said we would not build — a permanently unlocked safe | I18 |
| 20 | Claiming compliance from self-tests | Round-tripping through your own bug proves nothing | I19 |

---

## 5. Decisions

1. **Decrypt server-side, in a verb helper.** Never in the browser. Enforcement lives where
   the user cannot rewrite it.
2. **KDBX via `pykeepass` in-process; `keepassxc-cli` as the interop oracle only.**
3. **PSAFE3 implemented from `formatV3.txt`; Twofish from Botan, with test vectors.**
4. **Password on stdin, once per operation, never persisted anywhere.** The default is a
   prompt every time; a stored key file or hardware key is the only exemption, and the
   optional agent is off unless deliberately enabled and always has a hard idle timeout.
5. **Two access classes, `admin` (default) and `user`,** decided by a root-owned registry and
   enforced by the helper against a kernel-supplied identity.
6. **The project is GPL-3.0** because of (2).

## 6. Sources

- pykeepass — https://github.com/libkeepass/pykeepass
- libkeepass (deprecated, superseded by pykeepass) — https://github.com/libkeepass/libkeepass
- KeePassXC `keepassxc-cli` man page — https://github.com/keepassxreboot/keepassxc/blob/develop/docs/man/keepassxc-cli.1.adoc
- KDBX 4.1 format notes — https://keepass.info/help/kb/kdbx.html · https://keepass.info/help/kb/kdbx_4.html
- Independent KDBX4 write-up — https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/
- Password Safe v3 format spec — https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
- Password Safe upstream — https://github.com/pwsafe/pwsafe
- pypwsafe (rejected) — https://github.com/ronys/pypwsafe
- pwsafer (Rust, cross-read) — https://github.com/1uckyPh4nt0m/pwsafer
- lucasepe/pwsafe (Go, cross-read) — https://github.com/lucasepe/pwsafe
- libpsafe3 (C, cross-read) — https://github.com/marcbutler/libpsafe3
- Crypt::PWSafe3 (Perl, cross-read) — https://metacpan.org/pod/Crypt::PWSafe3
- Cockpit developer guide (`cockpit.spawn`, `superuser`) — https://docs.cockpit-project.org/cockpit-guide/latest/guide/development.html
- Cockpit CSP behaviour — https://github.com/cockpit-project/cockpit/issues/13810
- "Is Cockpit Secure?" — https://cockpit-project.org/blog/is-cockpit-secure.html
