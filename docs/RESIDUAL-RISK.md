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

### 1.2 Passphrase guessing against one safe is capped at 20 attempts a minute, not at 5

**This section used to say something worse and is kept, rewritten, rather than deleted.** It read
"guessing is not rate-limited if you guess in parallel", and it was right: fifty unlock attempts
fired at once were thirty-four evaluated against a threshold of five, and left the counter reading
three. That was **I39**, and it is fixed — the attempt is now reserved under an exclusive lock
*before* the key derivation rather than recorded after it, so fifty concurrent guesses now behave
exactly like fifty sequential ones: one evaluated, forty-nine refused.

What is left is the deliberate ceiling. Guessing against one safe is bounded by two counters: five
attempts per operator before a five-minute lockout, and — because an attacker who has already
reached euid 0 can present a different `SUDO_UID` to each attempt and collect a fresh
per-operator counter — **twenty attempts per safe per sixty seconds, from everybody together**.
Twenty guesses a minute is a rate limit, not a wall. Against a passphrase worth having it is
nothing; against a four-digit PIN reused as a passphrase it is ten thousand seconds. The people
who can spend it are the administrators of this host and root, who as section 1.1 says can read
the safe file directly and guess offline at whatever rate their hardware allows. So this ceiling
buys nothing against the attacker of section 1.1 and everything against a script in the Cockpit
page's origin, which is who it is for.

### 1.3 An administrator can deny one safe to their colleagues for up to a minute

**This section also used to say something worse.** It read "one administrator can lock every other
administrator out of a safe", and it was right: the counter was named after the *effective* user
id, every administrator is root when they open an admin-class safe, and one clumsy operator's typo
refused everybody else with the correct passphrase. That was **I40**, and it is fixed — the
counter is named after the *real* caller behind the escalation, so an operator's failures are
their own, and the lockout state can now attribute where before only the audit log could.

What is left is the shared half, and it is deliberate. The per-safe cap in section 1.2 counts
every principal together, so an administrator who fires twenty wrong guesses at a safe inside one
minute denies it to every other administrator until that window ends. Bounded at **sixty
seconds**, whatever they do, because the window is fixed rather than escalating — and any
successful unlock, by anybody, clears it immediately. That bound is the reason the cap is a rate
limit and not a second lockout: giving it the per-operator escalation would have let one bad
actor deny a safe for fifteen minutes, which is a worse thing to be able to do than the thing the
cap prevents.

An administrator who wants to deny their colleagues a safe has better options than this anyway:
they are root, and section 1.1 applies.

### 1.4 A save that a backend cannot read back is refused — and one backend still has its own copy of that rule

**This section used to describe a live defect and is kept, rewritten, rather than deleted.** It
read *"a Password Safe file can be destroyed by a second save, and the save says it worked"*, and
it was right: the round-trip check ran once per session instead of once per save, the second save
in a session wrote a file the program's own reader then refused, and it reported `{"ok": true}`
while doing it — after which the operator was told their **passphrase** did not match a safe that
was not locked but broken. That was **I41**, and it is fixed. Every save in both formats now
re-opens the exact bytes through the reader a later unlock uses, before those bytes replace a
working file, and a failure is a `conflict` that names what the reader objected to with the live
file byte-for-byte untouched.

The section also said the defect was hard to reach through the page because a request is capped at
1 MiB. **That was wrong and is corrected here rather than quietly dropped**: the password-history
field is written by the helper rather than carried by the caller and grows one ordinary edit at a
time, so the largest frame needed to reach the defect was 65 680 bytes — six per cent of the cap
that was supposed to be in the way. It was reachable through the shipping `edit` verb.

What is left is a **drift risk, not a defect.** The shared policy lives in
`backends/base.Backend.verify_own_output`, whose two format hooks refuse by default so a new
backend cannot save at all rather than saving unchecked bytes, and a standing ban
(`_unverified_writes`) fails any backend `save`/`save_as` that reaches `atomic_replace` without
calling a verify. Three things are still true and are the honest remainder:

* `backends/kdbx.py` satisfies the ban with its **own private** `_verify_own_output` and does not
  route through the shared policy. The guarantee is identical today — measured, both backends, in
  the same probe — but two implementations of one rule is the exact shape that produced I41 in the
  first place. Making `KdbxBackend` implement `read_back`/`diff_read_back` and deleting the private
  copy is the follow-up.
* The ban is **static**. It reads the source and requires a verify call in the same function body
  as the write. A backend that hid the write behind a helper method would pass it. A runtime stamp
  — the verify records a digest and the write refuses bytes without one — would be stronger and
  needs the kdbx unification first.
* Nobody has **enumerated which other helper-written fields grow across calls** the way the
  password history does. `0x0f` was enough to prove reachability, and the per-save check now covers
  the whole class rather than that one field, so this is a gap in knowledge rather than in the
  guard.

And the limit that matters most for Password Safe is still §3.5: "our reader accepts our writer"
is all that is proved. The refusals now agree with themselves; whether the real Password Safe
would accept a field this program writes is unknown and unclaimed.

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

### 3.9 Password Safe was not put through the leakage lens

Every leakage test ran against KDBX. Password Safe's export and error paths were never checked for
leaks — its CSV writer was confirmed during the re-gate to be the same neutralising one, which
closes part of it.

**The "never rendered in the page" half of this section is now false and has been removed.** A
`.psafe3` safe is driven through the live page in `tests/browser/live-ui.spec.js` item 6, both
before and after the I41 fix: add, edit, custom-field refusal, attach, list, download, history,
save and reopen, most recently on 2026-09-04. What remains untested is narrower and still worth
saying: Password Safe fields are not constrained by XML the way KDBX fields are, so PWS3 is the
right format for exactly the control-character and odd-encoding rendering tests that KDBX refused
to store, and **those** have never been run in a browser against either format.

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

---

## Part 4 · What the 0.4.0 registry-write feature leaves open

Creating and adopting safes gave a browser request its first write into the trust root. Twelve
defects were found and closed (I43–I54 in `docs/KNOWN_ISSUES.md`). These are what is left.

### 4.1 An unprivileged user can still destroy their own files with `safe-delete` — through the file, not through the verb

`safe-delete` now refuses unless the entry's `path` is exactly the path this program would mint
for that id and access class today, so a hand-written entry pointing at `~/.ssh/id_ed25519` is
`access-denied` and the file is untouched. What that gate does **not** do is stop a user destroying
a safe **this program did create**. That is the verb working: the operator asked, typed
`delete-safe:<id>` in full, and the safe was theirs.

The honest residue is the blast radius of a mistyped id: the confirmation token names the safe, but
two safes whose ids differ by one character are two tokens that differ by one character, and the
`_shred` is not recoverable through this program. The backup ring goes with the file deliberately
(leaving complete copies of a safe somebody asked to destroy would make the verb a lie), so there
is no undo inside the program at all. `safe-forget` is the reversible half and is offered beside it.

### 4.2 `_shred` is a courtesy, and the response says so

Unchanged from 0.3.0 and worth repeating because `safe-delete` is new: the overwrite-then-unlink is
meaningless on a copy-on-write filesystem, on an SSD, and against any snapshot, journal or backup.
The verb's `warning` says this in full every time. An operator who reads "overwritten: true" and
stops taking other precautions has been misled by the word, not by the code.

### 4.3 A ring at a registry-supplied `backup.dir` is left behind by `safe-delete`

Deliberate, and it is the safe half of I47's fix: this verb will not unlink inside a directory a
request-editable field named. So a safe whose entry sets `backup.dir` is destroyed while complete
copies of it may remain in that directory. The response says so in as many words — but nothing
removes them, and an operator who does not read the warning will believe the safe is gone.

### 4.4 `unlock` on a large registered safe is still unbounded

I54 bounded `import-inspect` and `import-commit` to `IMPORT_MAX_CONCURRENT` (2) simultaneous
callers, because those two are the verbs a caller can point at 128 MiB of their own choosing
without needing a registered safe or an administrator. `unlock` has the same per-request shape —
one full file read plus a KDF at up to `ARGON2_MAX_MEMORY_KIB` — and has **no cap at all**. N
simultaneous unlocks of a large registered safe is N times that cost, and each is its own process.

It is not fixed here for one reason and it is not a good enough reason to be comfortable with: the
lockout (I16) bounds how many FAILED unlocks one principal can make, but nothing bounds successful
ones, and extending the work slot to `unlock` would change the behaviour of every existing verb in
a release whose subject is the write path. Somebody should do it.

### 4.5 The staged-upload retry bound is a resource control, not a credential control

Stated in the code and repeated here because it is easy to misread. `IMPORT_MAX_ATTEMPTS` (5) and
`IMPORT_IDLE_SECONDS` (900) do **not** protect the uploaded safe from guessing: the person who
uploaded it still holds it and can guess against their own copy offline as fast as their hardware
allows. They protect **this host's CPU and disk**, because every attempt costs one full KDF
derivation on a helper that may be root. The I16 lockout is deliberately not wired into
`import-commit` and the page does not imply it is.

### 4.6 One user can hold 1 GiB of this host's disk for 15 minutes, on purpose

`IMPORT_MAX_STAGINGS` (8) × `MAX_SAFE_BYTES` (128 MiB) is a gigabyte per identity, held until the
idle sweep at 900 s. That is the intended bound and it is enforced (the 7th–10th `import-begin`
return `conflict`), but it is a bound *chosen*, not a bound that is small. On a host with a small
`/var` this is a way for an ordinary user to fill it. `health.import_staging` reports the count.

### 4.7 A per-user entry whose file has vanished cannot be forgotten

C4 rule 3 requires a per-user entry's `path` to pass `open_safe_fd`, and it was not relaxed — so an
entry naming a file that no longer exists is DROPPED at load and `safe-forget` cannot reach it. The
drop is reported in `health.registry_errors` and the message NAMES THE FILE TO REMOVE, and the file
is in the caller's own home where `rm` is a real remedy. A **system** entry whose file vanished is
not dropped, stays listed, and can still be forgotten — which is the case that matters, because
only root could clean `/etc`.

### 4.8 If the system registry root is untrusted or missing, per-user safes disappear too

`load_registry` returns early when the system registry root fails its trust check, and the per-user
registry is not read either. Fail-closed and unchanged from before this feature, but newly
surprising: removing `/etc/cockpit-secrets` now makes a user's OWN safes vanish from `list`, not
just the administrator's.

### 4.9 A safe created here always has a passphrase, and a key-file-only import is refused

Stricter than C7 asks, and structural rather than lazy: this helper never registers a key-file
PATH, and `safe-registry.schema.json` permits `password_required: false` only alongside a
registered `keyfile` or `yubikey_slot`. Writing "no passphrase" would mean storing the key file at
a path we register, and the schema's own comment says what that is worth — *"an attacker who gets
the safe gets the key in the same directory"*. So `import-commit` refuses a file that opens with a
key file and no passphrase, with `unsupported` and the reason.
`tests/fixtures/lab-kdbx41-keyfile-only.kdbx` is therefore not importable through this verb. An
administrator can still hand-write that entry.

### 4.10 The dispatcher's credential guard is a name check, not a taint analysis

`_refuse_undeclared_credential` refuses a request key that is a declared secret field, or one of
the aliases named in `_CREDENTIAL_ALIASES`. A client that shipped a passphrase to `import-begin`
under a key called `note` would not be caught: nothing inspects the VALUE, and nothing could
without being a worse idea than the problem. What the guard buys is that the obvious spellings —
the ones a real client or a real regression would use — are refused by name on the server, so C5's
ordering is no longer a promise made only by `secrets.js`.

### 4.11 A PWS3 this program creates cannot take attachments

`Backend.build_new` writes format version **0x030D**, and the attachment fields (0x25..0x29)
were introduced at **0x030F** (Password Safe V3.68), so `attach-add` refuses on a Password Safe
database `safe-create` made — correctly, and naming the version. Everything else on it works:
entries, fields, TOTP, history, save.

The version is deliberately not raised, and the reasoning is `backends/psafe3.py`'s: a declared
version is a claim about which readers can open a file, raising it would make every safe created
here unreadable by Password Safe before 3.68, and **there is no Password Safe on this host to
check either choice against** (COMPATIBILITY §3.3). Refusing loudly at a version everything reads
is the conservative half of that trade.

What was actually wrong was that nobody was told until they tried. `safe-create` now returns a
`warnings` entry saying it at the moment the operator picks the format, with the remedy in the
same sentence — create the safe in Password Safe itself and adopt it here. It was found by
running the live walkthrough against a CREATED PWS3 rather than the committed fixture, which is
the kind of thing only a live run finds.

### 4.12 A 128 MiB upload has been staged, but never committed

The memory measurements in I54 used a real 128 MiB staging. What was never built is a VALID 128 MiB
safe, so `import-commit` at that size — and the sustained half of I54's amplification, where a
valid large staging survives a successful inspect and can be re-inspected without limit — is
inference from two measured facts rather than one measured attack. `MAX_ATTACHMENT_BYTES` (32 MiB)
against `MAX_REQUEST_BYTES` (1 MiB) makes building one slow.
