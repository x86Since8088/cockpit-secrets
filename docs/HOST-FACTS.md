# Verified host facts — measured, not inferred

Anything here was run on edt1 and its real output recorded. Prefer this file over re-deriving,
and correct it if you measure something different (say so in your report).

## Twofish from Botan — use `BlockCipher`, NOT `SymmetricCipher`

`python3-botan` 3.10.0 is installed. The obvious API is a dead end and the working one is not
obvious, so this is the single most expensive fact in the file:

```python
import botan3 as botan
botan.SymmetricCipher("Twofish/CBC/NoPadding")   # BotanException: botan_cipher_init failed: -40 (Not implemented)
botan.SymmetricCipher("Twofish/ECB/NoPadding")   # same — Botan's AEAD/cipher-mode FFI has no Twofish
```

`BlockCipher` does have it, and it matches the official vectors:

```python
import botan3 as botan, binascii
bc = botan.BlockCipher("Twofish")     # block_size()=16, keylength 16..32
bc.set_key(bytes(16))
binascii.hexlify(bc.encrypt(bytes(16))).upper()   # b'9F589F5CF6122C32B6BFEC2F2AE8C35A'  ✅ official 128-bit vector
bc = botan.BlockCipher("Twofish"); bc.set_key(bytes(32))
binascii.hexlify(bc.encrypt(bytes(16))).upper()   # b'57FF739D4DC92C1BD7FC01700CC8216F'  ✅ official 256-bit vector
```

Methods: `algo_name, block_size, clear, decrypt, encrypt, keylength_modulo,
maximum_keylength, minimum_keylength, set_key`.

**Consequence for `backends/psafe3.py`:** `BlockCipher` is a raw ECB block primitive — it
encrypts/decrypts whole blocks with no mode and no padding. That is exactly what PWS3 needs:
raw ECB for recovering K and L from `B1..B4`, and CBC composed by hand over the body. Compose
CBC yourself (XOR the previous ciphertext block); do not go looking for a Botan CBC mode for
Twofish, because there isn't one. **Do not conclude "Botan cannot do Twofish" from the
`SymmetricCipher` failure and fall back to the pure-Python implementation** — Botan is the
audited path and it works.

## `/usr/bin/pwsafe` — the GUI accepts some arguments

**`pwsafe --help` exits 255, not 0, and writes its usage to STDERR, not stdout.** This file
recorded exit 0; two independent runs during the second build measured 255, with and without a
display, so the record was wrong and is corrected here. It matters because "did pwsafe accept
this?" is the shape of every attempt to use it as an oracle, and a harness that reads the exit
code gets "failed" for a successful help request — which is one of the ways the PWS3 oracle was
believed to be closer than it is (I19).

The usage it prints lists: `-r/--read-only`, `-v/--validate=<str>` ("validate (and repair)
database"), `-e/--encrypt=<str>`, `-d/--decrypt=<str>`, `-c/--close`, `-s/--silent`,
`-m/--minimized`, `-u/--username`, `-h/--hostname`, `-g/--config_file`,
`--yubi-polling-interval`.

Under `Xvfb`, `pwsafe --validate` maps **no** X window and never returns, while `xmessage` on
the same Xvfb maps one — so the display is real and pwsafe is the thing that will not be
driven. That control is what turns "we could not automate it" into "it cannot be automated
here".

It is still a wxWidgets GUI and will want a display and an interactive passphrase dialog, so it
is **not** a scriptable CLI. `--validate` is worth an attempt under `Xvfb` as a genuine foreign
check on a file we wrote; if it cannot be driven non-interactively, say so plainly rather than
implying we have an oracle we do not (KNOWN_ISSUES I19). `-e`/`-d` encrypt arbitrary files with
Password Safe's file-encryption feature — they are NOT a `.psafe3` database dump.

## Installed for this project (2026-09-03, all verified present)

| Package | Version | Role |
|---|---|---|
| `python3-pykeepass` | 4.1.1.post1-1 | **runtime** — KDBX engine |
| `python3-argon2` | 25.1.0-2 | runtime — Argon2 KDF |
| `python3-botan` | 3.10.0+dfsg-2 | **runtime** — Twofish (see above) |
| `python3-lxml`, `python3-construct` | 6.0.2, 2.10.68 | runtime — pykeepass deps |
| `python3-pyotp` | 2.9.0-2build1 | runtime — TOTP |
| `python3-cryptography` | 46.0.5 | runtime — SHA/HMAC/AES |
| `python3-pytest` | 9.0.2-4 | test |
| `keepassxc-full` | 2.7.10+dfsg1-2ubuntu1 | **TEST ONLY** — `keepassxc-cli` interop oracle |
| `passwordsafe` | 1.22.0+dfsg-1 | test — GUI only, see above |
| `libcrypt-twofish-perl` | 2.18-1build6 | test — a third independent Twofish for vector cross-checks |

Also present: Python 3.14.4, `gjs`, node v22.22.1, a cached Playwright chromium, Go 1.26 with
`golang.org/x/crypto@v0.48.0` already in `$(go env GOMODCACHE)` (has `x/crypto/twofish`), and
outbound network.

## systemd 259 ignores `RuntimeDirectoryMode=` in a `.socket` unit

Measured twice, both directions, on `systemd 259 (259.5-0ubuntu3.4)`:

```
# a SOCKET unit with RuntimeDirectory=sdprobe-x, RuntimeDirectoryMode=0700
drwxr-xr-x /run/user/1000/sdprobe-x          # ← 0755. The mode was ignored.

# a SERVICE unit with the same two settings, via systemd-run --user
drwx------ /run/user/1000/sdprobe-y          # ← 0700. Honoured.
```

The agent's whole uid separation rests on that directory being 0700, so both socket units carry
`ExecStartPost=/usr/bin/chmod 0700 …` with **no** leading `-`: a run directory that cannot be
made 0700 must fail the unit rather than start an agent behind a world-listable path.

Related, and also measured: with `ProtectHome=yes` on a **user** unit, `/run/user` is not
visible inside the service's mount namespace, so the agent cannot stat its own socket path. That
is the sandbox working — it only needs the inherited fd — and the 0700 guarantee comes from the
socket unit's unsandboxed `ExecStartPost`, not from the agent's own check.

`/run/systemd/sessions/<id>` is readable but its first line says it is private and must not be
parsed, and it carries no lock hint: `loginctl` is the only supported source. `loginctl -p A -p B
--value` prints properties in systemd's own order, **not** the order asked, so a multi-property
read must use the `KEY=value` form.

## Cockpit

Version 360, running as a system service and reachable at `https://localhost:9090` (verified
HTTP 200). **Never stop or restart `cockpit.socket`.** Existing packages under
`/usr/share/cockpit/`: `adlab`, `guac-rdp`, `headscale`, `tuner`, `wireguard`, plus stock.

## Root

Interactive `sudo` is unavailable. Root work goes through the `/srv/jobs` inbox job runner
(`submit-job.sh`). **Its `output.log` is group-readable — never print a passphrase or a safe's
contents from a job.**

## Test accounts already on this host — reuse these, do not create new ones

| Account | uid | In `sudo`? | Use |
|---|---|---|---|
| `eddie` | 1000 | yes | the operator; the developing user |
| `cptest` | 1005 | **no** | the non-admin principal for every access-control and Playwright refusal test |
| `cpadmin` | — | yes | an admin principal distinct from the operator |
| `cptestadm` | — | yes | second admin principal, for two-admin isolation checks |

`cptest` was created for `cockpit-adlab` as a throwaway Cockpit test user and is the right
account for KNOWN_ISSUES I3 ("a browser-side access check is cosmetic") and the A1/A2 attacks in
docs/THREAT-MODEL.md: drive `secrets-admin` directly as `cptest` and prove the helper refuses.

**The admin group on this host is `sudo`** (there is no `wheel` group) — `getent group sudo`
returns `eddie,cpadmin,cptestadm`. The registry's `groups` default and the helper's admin-group
detection must handle both names but will resolve to `sudo` here.

`Xvfb` and `xvfb-run` are installed, so a headless attempt at the `pwsafe --validate` oracle is
possible.
