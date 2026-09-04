# Residual risk — what someone can still do

`docs/KNOWN_ISSUES.md` lists hazards and the mitigations that close them. `docs/STRESS-REPORT.md`
is the record of attacking those mitigations. **This file is the honest remainder: the things an
attacker, or an ordinary operator having a bad day, can still do to this program on this host.**

It is written in plain language on purpose. If you have to already understand the codebase to
understand a risk, the risk has not been disclosed — it has been filed.

Two rules for this file:

1. **No hedging.** "Could theoretically" and "in principle" are not used. Either something works
   or it has not been tried, and if it has not been tried it says so.
2. **Nothing is left out because it is embarrassing.** Section 3 exists because a residual-risk
   register with no open defects in it is a marketing document.

---

## Part 1 · What someone can do right now

### 1.1 Root on this host reads everything

Anybody with root on edt1 can read the helper's memory while a safe is open, replace the helper
with one that keeps a copy, read the registry, and read every admin-class safe file directly.
Nothing in this program stops that and nothing in it pretends to. The hardening in I14 — no core
dumps, a non-dumpable process, a best-effort `mlock`, a process that lives for milliseconds —
raises the cost and does not change the conclusion. This is true of every password manager on
every machine. It is listed here anyway, because a threat model that puts root out of scope and a
risk register that never mentions root are two documents that together tell a reader something
false.

### 1.2 Passphrase guessing is not rate-limited if you guess in parallel

The lockout counter that is supposed to stop repeated guesses is read, incremented and written
back with no lock between the three steps. Fire fifty unlock attempts at once and forty-four of
them are evaluated instead of five. Measured: fifty concurrent wrong guesses produced forty-four
`bad-credential` answers and left the counter reading 43. Guessing still costs a full key
derivation per attempt, so this is not an offline attack and not a fast one — but the specific
promise that guessing is bounded by a threshold rather than only by CPU is not kept. Anyone who
can run the helper repeatedly can do this: the owner of a user-class safe, or script running in
the Cockpit page's origin. Tracked as **I39**.

### 1.3 One administrator can lock every other administrator out of a safe

The lockout counter for an admin-class safe is named after the *effective* user id, and every
administrator is root when they open one. So there is one counter per admin safe, shared by
everyone. Measured: one administrator mistyped a passphrase once; a second administrator, who had
typed nothing, immediately offered the correct passphrase and was refused. Two consequences. An
administrator who is merely clumsy denies the safe to their colleagues, and an administrator who
is malicious can do it on purpose and cannot be identified from the lockout state, because the
state records no identity. The audit log does record who tried. Tracked as **I40**.

### 1.4 A Password Safe file can be destroyed by a second save, and the save says it worked

For Password Safe v3 files only, the check that a save will produce a readable file runs once per
session instead of once per save. Save twice in one session and the second save is unchecked.
Measured: the second save wrote a file the program's own reader then refused, and reported
`{"ok": true}` while doing it. Worse, on reopening, the operator is told the passphrase did not
match — so the natural next move is to try more passphrases and trip the lockout, on a safe that
is not actually locked but broken. The previous version is in the backup ring, so the data is
recoverable if the operator knows to look. KDBX files are not affected; they got this check and
Password Safe files did not. Through the web page today this is hard to reach, because a single
request is capped at 1 MiB and that cap happens to block the route — but that cap exists for an
unrelated reason and is the only thing in the way. Tracked as **I41**.

### 1.5 A hardware token's answer, seen once, opens the file for as long as the file exists

If a safe is protected by a YubiKey, this program sends the same challenge to the token every
time, so the token gives the same answer every time. Anyone who sees that answer once can open
the file until somebody re-keys it in KeePassXC. KeePassXC changes the challenge every time it
saves, which retires the previous answer; this program cannot, for the reason argued at length in
Part 2 §1. The only attacker in scope who can see the answer is script running in the Cockpit
page's origin — and that attacker captures the typed passphrase in the same keystroke, which does
not rotate under any implementation. The program now says this out loud in both the `probe` and
the `unlock` reply, so an operator is told at the moment it matters. Tracked as **I35**.

### 1.6 A decrypted attachment stays retrievable for ten seconds after you press Lock

When you download an attachment, the decrypted bytes are handed to the browser through a
temporary URL that is released on a ten-second timer. Pressing Lock does not release it early.
Measured in the live page: after Lock, the URL was still valid and script in the page was able to
trigger a second download of the decrypted file. It cannot be *read* by script — the page's
security policy refuses that, and the bytes are typed so the browser downloads rather than
displays them — so the exposure is that an attacker already running in the page can put a copy of
the file on the operator's disk for up to ten seconds after the operator believed the safe was
closed. Small, real, and a gap between what the Lock button says and what the browser is holding.
Tracked as **I36**.

### 1.7 The clipboard may not actually be cleared, and the page will say it was

The page copies a password, counts down, and clears it. The clearing is a browser call that can
fail — the documented case is a tab that does not have focus — and the code announces success
before finding out, having already cancelled the countdown. If that call ever fails, the password
stays on the clipboard, nothing retries, and the operator is told it is gone. **Nobody has managed
to make it fail.** Two independent attempts could not get an automated browser to lose focus or to
reject the write. So this is a shape in the code that would be a real defect if the failure ever
occurs, and it has not been observed. Testing it needs a person at a real desktop browser.
Tracked as **I37**.

### 1.8 A user-class safe's contents can reach swap

The helper asks the kernel not to page its memory out. For any non-root run that request fails,
because the memory-lock limit on this host is 8 KB. So while a safe is open as an ordinary user,
its decrypted contents can be written to swap and can outlive the process. This has not been
demonstrated — reading the swap file needs root, which is out of scope — so it is unverified
rather than disproven, which is a weaker statement than "safe". Part of I14.

### 1.9 A passphrase cannot be erased from memory, and this is a property of Python

A password read into a Python string cannot be overwritten; the language does not allow it. The
program reads secrets into byte arrays and zeroes those, keeps the process alive for milliseconds
rather than hours, and turns off core dumps — all of which shrink the window without closing it.
Part of I14, and nothing in the review made it worse.

### 1.10 A tampered KDBX 3.1 file cannot be detected

KeePass's older file format has no integrity protection, so a modified file decrypts to
attacker-influenced content with nothing to notice. This program opens such files read-only
behind a permanent banner and offers an explicit upgrade to the newer format, which is the whole
of the available defence. Nobody fuzzed the KDBX 3.1 read path for parser differentials, on the
grounds that it is hunting for a documented property. I20.

### 1.11 Another program can still overwrite a safe during a save

Before writing, the program re-checks that the file on disk is the one it opened, and it takes
the same lock file KeePassXC and Password Safe use. A different program that ignores lock files
can still write in the gap between that check and the rename. This is what advisory locking
means and the code says so in as many words. Two cooperating instances of this program cannot
collide; a foreign writer that does not cooperate can. I13.

### 1.12 Every Cockpit user can see that a safe exists

The safe list names every registered safe to every caller, with its label, format and access
class, and a reason if they cannot open it. That is deliberate: it is how somebody learns why
their safe is not working instead of filing a bug. It also means the existence and the name of an
administrator's safe are not secret from a non-administrator. Sanctioned by the threat model's
A2 row; stated here so nobody discovers it and calls it a leak.

### 1.13 The unlock agent, if you turn it on, weakens two things

The agent ships disabled and should stay that way. Turned on, it holds a ticket rather than key
material, so it cannot hand anybody an unlocked safe — but it detects screen-lock by polling
every ten seconds, so there is up to a ten-second gap between the screen locking and the ticket
being dropped; and for admin-class safes it separates operators by giving each their own agent
behind a private directory, not by asking the kernel who is calling, because for a root helper
the kernel says "root" for everybody. The correct fix is for the root helper to drop to the
operator's identity before connecting, and it is not implemented. I18.

---

## Part 2 · The decisions behind two of these

### 2.1 Why the hardware-token challenge is not rotated (I35)

**Severity: low.** Found by adversarial review (CRYPTO-03), confirmed by an independent skeptic
who lowered it from medium to low.

#### What was measured

`challenge_for()` sends `kdf_params["salt"]` — the KDF seed, PKCS7-padded to 64 bytes — to the
token as the challenge. `_serialize(reseed=True)` rotates the master seed, the encryption IV and
the inner protected-stream key on every save, and deliberately does not rotate the KDF seed.

On the committed fixture, on this host:

```
cockpit-secrets, before any save : 5kQm9oYIyWAoPZxQ6rOO+zB49HBUh6KK
cockpit-secrets, after save 1    : 5kQm9oYIyWAoPZxQ6rOO+zB49HBUh6KK
cockpit-secrets, after save 2    : 5kQm9oYIyWAoPZxQ6rOO+zB49HBUh6KK
keepassxc-cli, after ONE save    : a/HYIMXJ1tEPaoti+uZeN0ISmJvSe+wE
```

KeePassXC's `Kdbx4Writer::writeDatabase` calls `db->setKey(db->key(), false, true)`, which invokes
`Kdf::randomizeSeed()` on **every** save and re-challenges the token to rebuild the composite key.
So under KeePassXC a captured 20-byte HMAC-SHA1 response is retired at the operator's next save.
Here it opens the file for as long as the file exists.

#### Why the obvious fix does not exist

The composite key for a challenge-response database contains `SHA-256(response to the challenge
derived from the CURRENT seed)`. Rotate the seed and the next unlock challenges the token with the
new seed, gets a different response, and builds a different composite key — the file no longer
opens. **Rotating the seed therefore requires a fresh token answer at SAVE time**, which is
exactly what KeePassXC does because KeePassXC talks to the token itself.

This program does not. The token is driven by the browser: `probe` publishes the challenge, the
operator touches the key, the answer comes back in the `unlock` request. There is no round in that
protocol in which the helper can ask for a second answer, because the helper decides the new seed
and the client cannot answer a challenge that does not exist yet.

#### The two fixes considered, and their cost

**(a) A second challenge round.** `probe` mints the *next* seed as well as reading the current one
and publishes both challenges. The operator touches the token twice. The client returns the
pre-minted seed and its answer with every save-bearing request; `save()` rotates to that seed.

This works, and it is the correct shape. It costs: two new fields in the `probe` reply, two in
every mutating verb's request, a schema change, a UI change, a second physical touch of the token
per unlock, and a new failure mode (a save that cannot complete because the client did not carry
the second answer). All of it lands on a code path that **has never been exercised against a real
device**. `docs/COMPATIBILITY.md` §2.3 and §8 record it plainly: there is no YubiKey on this host,
no database keyed with a challenge component exists, and the composite-key construction has unit
vectors but has never had a token answer one. Rewriting unverifiable plumbing to be more elaborate
is how a real bug ships with nothing to catch it.

**(b) Hold the composite key and re-derive on every save.** For a database with **no** challenge
component this is straightforward: keep the 32-byte composite in a `Secret`, mint a new KDF seed
at save time, re-derive, write. It matches KeePassXC exactly.

It also buys nothing here. The finding's whole impact is about the token, and (b) cannot help the
token case for the reason above. What it *would* do is pay a full KDF — seconds, for a database
with a real Argon2 cost — on every save, and hold one more piece of key material for the life of
the session. The transformed key is already held and already sufficient to open the file, so the
marginal exposure is small; the marginal benefit is smaller still, because the attacker who can
read helper memory is root, and root is out of scope by the threat model's own terms.

#### Why the residual is acceptable

* The only in-scope adversary who can observe another operator's response is **A4 (XSS in the
  Cockpit origin)** — and an attacker in that position captures the **passphrase** in the same
  keystroke. The passphrase does not rotate under any implementation. The marginal loss is
  therefore only the window KeePassXC would have closed at the next save.
* **A2** (a non-admin with devtools) driving their own session learns nothing they did not supply.
* KeePassXC's rotation only fires on save, so a read-mostly safe has the same permanence there.
* No such database exists on this host to be at risk.

#### What is done instead

The deviation is no longer silent, which was the actual defect — the `_serialize` docstring
justified not rotating the salt purely in terms of not holding the passphrase, and neither it nor
any document stated the consequence for the second factor. `probe` **and** `unlock` now both warn,
in the reply the operator's page renders:

> this safe's hardware-token challenge is its KDF seed, and this program does not rotate that seed
> when it saves: the token's answer for this file is the same value every time, so anyone who
> observes it once can open the file until the file is re-keyed elsewhere. KeePassXC rotates the
> seed on every save and retires the previous answer.

Both doors say it, because a caller that goes straight to `unlock` — the agent, a script, the
integration suite — never sees a probe. The remedy available today is in `docs/COMPATIBILITY.md`:
re-key the database in KeePassXC, which rotates the seed and retires every previous answer.

#### What would change this decision

Any one of: a real token on this host to test against; a database keyed with a challenge component
in the fixture set; or an unrelated reason to add a second round trip to the unlock protocol, at
which point (a) becomes nearly free. `test_crypto03_the_challenge_is_still_the_kdf_seed` exists to
fail the moment somebody changes the rotation behaviour, so the warning cannot outlive the
condition it describes.

### 2.2 The stated cost of CSV formula neutralisation (I31)

Not a residual hazard — the hazard is fixed — but a residual **cost**, recorded because it is a
deliberate loss of fidelity and an operator can be bitten by it.

`base.csv_cell()` prefixes any cell beginning with `=`, `+`, `-`, `@`, TAB or CR with an
apostrophe, because a spreadsheet hands such a cell to its formula parser even inside RFC-4180
quotes. There is no neutralisation a plain CSV reader can undo unambiguously, so a **legitimate**
value beginning with one of those characters — a password like `-hunter2` is the realistic case —
is changed in the export.

The alternatives were: leave the bytes alone as KeePassXC does, which keeps byte-fidelity and
leaves an exfiltration primitive in the artefact that contains every credential at once; or refuse
to export an entry whose field looks like a formula, which turns a hostile safe into a denial of
the operator's own recovery path. Neither is better.

The cost is made loud rather than silent: the `export` reply carries `neutralised: N` and a warning
naming the characters and telling the operator to strip one leading apostrophe on import, and the
change is visible in the file itself. `_export_csv`'s docstring pins the column set to KeePassXC's
so the file still imports; this is the one place where the bytes deliberately differ from what
KeePassXC would have written, and `docs/COMPATIBILITY.md` records it as such.

---

## Part 3 · What has never been tested

Everything in this part is code that exists and is expected to work. **None of it has been run
against the thing it names.** An untested path is not a safe path, and this section is the reason
this file is not comfortable.

### 3.1 No YubiKey has ever answered a challenge from this program

There is no hardware token on this host — no `ykman`, no `ykchalresp`, nothing YubiCo on the USB
bus — and no KDBX database keyed with a challenge component exists, because producing one needs
the token. The plumbing is verified in all four cases (no slot and no response, no slot and a
response, a slot and no response, a slot and a response), the key composition was read line by
line out of KeePassXC 2.7.10's own `CompositeKey.cpp` and `YubiKeyInterfaceUSB.cpp`, and both
frozen regression digests were recomputed independently and matched. **None of that is a token
opening a file.** If `_yubikey_component()` — SHA-256 over the raw 20-byte answer — differs from
KeePassXC's by one detail, every challenge-response database fails to open and nothing in this
project would have caught it. Buy a YubiKey before promising anybody this works.

### 3.2 No KDBX 3.x + Twofish file has ever been read

The Twofish primitive itself is verified three ways, including by a genuinely third party:
`backends/kdbx._decrypt_prefix()` was fed ciphertext produced by Perl `Crypt::Twofish` 2.18 and
returned the plaintext exactly, and all 728 committed vectors pass through Botan, through the pure
Python implementation, and through an independent Go oracle. But `keepassxc-cli` cannot create a
Twofish database, so **no KDBX 3.x + Twofish file exists** and the header parse, the
stream-start-bytes check and the block-digest walk *around* that verified primitive have never run
on one.

### 3.3 No foreign program has ever written a Twofish KDBX for us to read

`lab-kdbx40-twofish-argon2d.kdbx` opens in `keepassxc-cli` — re-confirmed during this re-gate:
`Cipher: Twofish 256-bit`, 2 entries listed. That is real evidence that a foreign *reader* accepts
what this program writes. It is not evidence about reading, because that file's container was
written by this project and `keepassxc-cli` cannot produce a Twofish database at all. The read
path has never seen Twofish bytes laid out by somebody else.

### 3.4 KDBX 4 with AES-KDF has never been read or written

No such file exists on this host and none can be made here. `keepassxc-cli db-create` always writes
KDBX 3.1 + AES-KDF and `db-edit` has no KDF switch, and `tests/fixtures/kdbx_reformat.py`
deliberately refuses to synthesise one on the grounds that a real 3.1 file has better provenance
than a manufactured 4.x one. So AES-KDF is verified only in its KDBX 3.1 form, read-only, at
1 000 000 rounds. The KDBX 4 combination — which `Limits.check_aeskdf_rounds` clamps and which
this program's writer would happily emit — is untested in both directions.

### 3.5 No Password Safe file written by the real Password Safe has ever been read

`pwsafe` 1.22 is installed and is a wxWidgets GUI. Under Xvfb it maps **no** window and
`--validate` never returns, while `xmessage` on the same display maps one — so the display is real
and pwsafe is the thing that will not be driven. Compensating evidence is genuine but is not a
foreign file: a from-spec third implementation of the reader that agrees byte for byte, a Go
oracle that agrees with both, and the upstream C++ read by hand (`docs/formatV3.txt` sha256
`68cdd7515ad5bdff…`, matching the copy on this host). Everywhere the documentation says "the
reference would do X", that was **read from C++, not executed.** Closing this needs a human at a
GUI.

### 3.6 The unlock agent has never run as root

`secrets-agent` is not installed on this host: no binary, no systemd unit, no socket. The
integration suite drives a real daemon self-bound as an ordinary user and proves 45 checks about
tickets, deadlines, caps and revocation. Nothing has ever exercised it at euid 0, which is exactly
the configuration where its weakest property lives — that `SO_PEERCRED` reports uid 0 for every
operator, so separation comes from one agent per operator behind a private directory rather than
from the kernel. `systemd-analyze security` on the units was not run because there are no units.
The agent is off by default and this is a reason to leave it off.

### 3.7 Real power loss has never been tested

Processes were killed at all 22 syscalls in a save, then 120 more times at random offsets, and the
safe survived every time. Power was never cut, and `dm-flakey` / `dm-log-writes` were not used. The
`fsync` of the temp file and of the directory are present and in the right order, which is what a
review can establish. Whether the storage device honours them is untested — and this project's own
source tree lives on an SMB share, where that question is least comfortable.

### 3.8 The short-write defect was never reproduced on ext4

`I26` was reproduced for real on tmpfs, which returns partial write counts when it runs out of
space, and separately by injecting a short write. ext4's delayed allocation usually defers the
out-of-space error to `fsync` instead of returning a short count, so the natural trigger may not
fire on this host's root filesystem. The defect was unconditional and the fix is unconditional;
what is filesystem-dependent is how often it would have bitten. tmpfs, NFS and CIFS are the
realistic triggers.

### 3.9 Password Safe was not put through the leakage or the browser lens

Every leakage test and every browser-rendering test ran against KDBX. Password Safe's export and
error paths were never checked for leaks — its CSV writer was confirmed during this re-gate to be
the same neutralising one, which closes part of it — and no `.psafe3` fixture was ever rendered in
the page. That last gap matters more than it sounds: Password Safe fields are not constrained by
XML the way KDBX fields are, so PWS3 is the right format for exactly the control-character and
odd-encoding rendering tests that KDBX refused to store.

### 3.10 The hostile-filesystem matrix was not run against Password Safe

Full disk, read-only directory, inode exhaustion and a symlinked backup ring were all exercised
against KDBX only. The write primitive is shared, so identical behaviour is expected. It was not
measured.

### 3.11 The KDBX 3.1 read-only banner has never been seen in the browser

I20's mitigation — open read-only, show a permanent banner, offer an explicit upgrade — was
verified at the helper. No KDBX 3.1 safe was ever registered for the live page, so the banner's
rendering and the page's read-only refusal are unverified.

### 3.12 Nobody has driven the admin path's `/proc`, or two operators at once

All process-inspection tests ran against a helper running as an ordinary user. The admin path runs
as root, and what a second unprivileged user can see of *that* process was not measured.
