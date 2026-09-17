# `secrets-agent` — the unlock agent, and the case against turning it on

This directory holds the one component of cockpit-secrets that exists to make
the program *weaker*. Read this before enabling it. If you skim, read §1 and §6.

---

## 1 · What it is, and what it costs

`secrets-agent` is a small daemon that holds a record of an unlocked safe behind
an `AF_UNIX` socket — see §4 for what a "record" is and is not; against the
shipped helper it is a **ticket** carrying no key material. It is **off by
default in two independent
places**: no socket exists until someone enables a systemd unit, and nothing is
held until a registry entry sets `agent.enabled: true` for that safe. The helper
never starts it.

Here is the property you give up.

Without the agent, "the passphrase is prompted on every unlock" is not a policy.
It is a fact about the process model. The browser calls `cockpit.spawn` once per
verb; the bridge forks a `secrets-admin`, writes one JSON request to its stdin,
reads one JSON object back, and reaps the child. When that process exits, every
key derived inside it is gone with it, and nothing was written anywhere that
could outlive it. The *next* verb therefore starts from a locked file and needs
the passphrase again — not because a timer fired, but because the thing that
held the key does not exist any more. To break that you would have to change the
process model, not flip a setting. There is no "remember this passphrase"
checkbox to add, because there is nowhere to put the answer.

With the agent, there is somewhere to put the answer. The guarantee becomes a
promise kept by timers, and a promise is only as good as the code that keeps it.
Every bug in this daemon, every missed timeout, every future "convenience" patch
is now a safe that is open while nobody is looking at it — which is precisely
the property this project exists not to have (docs/KNOWN_ISSUES.md **I18**).

So the honest framing is not "here is a convenience feature with some
mitigations". It is: **this is a deliberate, bounded regression, and you should
be able to say out loud why you need it.**

## 2 · Exactly what it weakens, in one table

| Without the agent | With the agent |
|---|---|
| A key exists only inside one short-lived process, for one operation | A key exists in a daemon for up to `idle_seconds` after its last use, and up to `max_seconds` in total |
| Someone at your unlocked screen must know the passphrase to read a safe | Someone at your unlocked screen reads the safe with no passphrase, for the length of `idle_seconds` |
| Nothing to attack between operations | A long-lived process holding plaintext, reachable over a socket |
| The prompt is the audit trail | The banner is the audit trail, and it must never be missing |

`idle_seconds` is the number that matters, and it is the one people are tempted
to raise. It is not "how long until it locks". It is **the size of the window in
which your unlocked, unattended screen is an unlocked, unattended password
safe.** Above a few minutes you are running one as a service.

And `agent.allow_keep_open` is that same temptation with no number on it at all.
It permits a per-session control that **switches `idle_seconds` off** for one
safe, so the window above becomes the whole of `max_seconds`. It is false by
default, it needs `agent.enabled` as well, **the daemon reads it off the registry
itself and refuses a request for a safe that did not set it** — a client's word
is not accepted for this — and `--no-keep-open` turns the feature off for the
whole agent whatever any registry says. What it does NOT touch, and must never:
`max_seconds` (still counted from the unlock, still unextendable by any message
a client can send), and every presence lock — SIGTERM, the logind session lock,
the suspend detector, and the `drop` the page's Lock button, its `pagehide`
handler and its hidden-tab timer all reach. Those are not timeouts; they are
"nobody is here". Set `allow_keep_open` on the safe you keep open while you
work. Do not set it on the one that matters most.

**And it is one switch over a whole helper session, not one per safe.** For a
release, `allow_keep_open: false` bought a safe nothing whenever any OTHER safe
the same session held was opted in: the helper has a single idle timer and
suspending it suspended the protection on both. `secrets-admin` now refuses the
suspension unless every safe the session holds has been affirmed here, so the
weakest safe in a session governs. That is a helper-side rule — this daemon has
no idea what a caller's session holds — and the practical consequence for an
operator is the one worth remembering: **a safe with `allow_keep_open` set is
not made safer by being opened next to one without it.**

## 3 · What it does to earn its place

- **`SO_PEERCRED` is the identity.** The connecting process's `(pid, uid, gid)`
  come from the kernel and cannot be forged by the client. A holding belongs to
  the uid that created it; any other uid gets `access-denied`.
- **An unknown handle and someone else's handle are the same answer.** Both are
  `access-denied`, never `not-found`. The difference would be an enumeration
  oracle telling a caller which tokens exist.
- **Group membership on the socket is not identity.** It is a coarse gate at
  best, and this agent does not use one: the run dir is `0700` and the socket
  `0600`, so the only non-owner who can reach it is root, who is out of scope in
  docs/THREAT-MODEL.md because root can read this process's memory anyway.
- **Two hard timers.** `idle_seconds` (default 300) restarts on every `put` and
  `get`. `max_seconds` (default 3600) restarts on nothing. A client may ask for
  a *shorter* window and is clamped if it asks for a longer one, and re-`put`ting
  a token that is already held keeps the original absolute deadline — so no
  amount of activity rides one unlock past the cap.
- **`status` is deliberately not "use".** The UI polls it to draw the
  "unlocked — N s remaining" banner. If polling reset the idle timer, the banner
  would keep alive precisely the thing it exists to warn about.
- **`CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`.** Monotonic time does not advance
  while the machine is suspended, so an agent using it would come back from an
  eight-hour suspend with 297 of its 300 idle seconds intact. Boottime counts
  suspended time, which is the only reading of "idle for five minutes" that
  means anything to someone who closed a lid.
- **It locks on session events.** Everything is dropped and zeroed on `SIGTERM`,
  `SIGINT`, `SIGHUP`, when logind reports the owner's sessions locked or gone,
  and when the process notices it was frozen (suspend, hibernate, `SIGSTOP`).
- **It writes nothing to disk.** No state file, no cache, no resume across a
  restart — restarting the agent loses everything it holds, on purpose. It emits
  one JSON line per operation on **stderr** (`{when, op, safe, uid, outcome}`),
  which is metadata only: never a value, and never a handle token, because a
  token is a credential and a log of tokens would be a log of keys.
- **It refuses to run as root**, unless you pass `--allow-root` and mean it. An
  agent running as root serves everyone and identifies no one.

## 4 · The gotcha it cannot engineer away

From the `peercred-unix-relay` pattern's own list, and it applies here:

> `SO_PEERCRED` identifies the connecting **process**, not the **human**. It is
> an auth signal only if the thing that connects runs *as the user*.

For `access: "user"` safes that holds: the helper runs unescalated under the
user's own Cockpit bridge, so the peer uid is the user. For `access: "admin"`
safes it does not: the helper is **root**, so the peer uid is 0 for every
operator and the credential cannot tell two admins apart.

The agent's answer is structural, not cryptographic: **one instance per
operator**, `secrets-agent@<uid>`, each with its own `0700` run dir. What
separates two admins is which socket the root helper connects to, not what the
kernel says about the peer. That is a weaker guarantee than the user-class one
and it is stated here rather than hidden.

The clean fix is available and preferred: **have the root helper fork, drop to
the operator's uid, and connect as them.** Then the peer uid is the operator
again, `SO_PEERCRED` means what it says, and the system unit needs no uid
exception at all. Until the helper does that, the alternative is
`--allow-peer-uid 0`, shipped **commented out** in
`systemd/system/secrets-agent@.service`. Note what that flag is and is not: it
admits a uid to *speak* to the socket. It does not let that uid read a holding
another uid created — the ownership check has no exception in it, and the tests
below prove it in both directions.

## 5 · Turning it on

Per user, in that user's own session, because it must run *as* the person whose
material it holds:

```bash
sudo ./install.sh --with-agent          # installs the units; enables nothing
systemctl --user daemon-reload
systemctl --user enable --now secrets-agent.socket
systemctl --user status  secrets-agent.socket
```

Then, and only then, per safe, in `/etc/cockpit-secrets/safes.d/<id>.json`:

```json
"agent": { "enabled": true, "idle_seconds": 300, "max_seconds": 3600 }
```

Both halves are required. Enabling the unit without the registry flag holds
nothing; setting the registry flag without the unit finds no socket.

The admin-class system template is **not** installed by `install.sh`. Install it
deliberately, having read §4:

```bash
sudo install -m0644 agent/systemd/system/secrets-agent@.socket \
                    agent/systemd/system/secrets-agent@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secrets-agent@1000.socket     # numeric uid
```

## 6 · Seeing a live handle, and killing it

**An unlocked safe must never be invisible.** The page shows a persistent
"unlocked — N s remaining" banner with a Lock button whenever the agent holds
anything; if you ever see the agent holding a safe with no banner, that is a bug
worth stopping for.

From a shell, ask the agent itself:

```bash
# what is held, how much time is left
printf '{"op":"status"}\n' | nc -U "$XDG_RUNTIME_DIR/cockpit-secrets/agent.sock"

# drop ONE holding, by handle
printf '{"op":"drop","handle":"<token>"}\n' | nc -U "$XDG_RUNTIME_DIR/cockpit-secrets/agent.sock"

# drop EVERYTHING this uid holds
printf '{"op":"drop","all":true}\n'       | nc -U "$XDG_RUNTIME_DIR/cockpit-secrets/agent.sock"
```

The blunt instruments, in increasing order of finality:

```bash
systemctl --user stop secrets-agent.service     # SIGTERM: drops and zeroes all
systemctl --user stop  secrets-agent.socket     # ...and removes the socket
systemctl --user disable --now secrets-agent.socket   # off until re-enabled
```

Then set `"enabled": false` in every registry entry that turned it on;
`secrets-admin health` reports whether this installation has an agent at all.

What you cannot do from the outside is inspect the material. `harden_process()`
sets `prctl(PR_SET_DUMPABLE, 0)`, so `/proc/<pid>` is root-owned and even the
owning user cannot read the process's fds, maps or memory. Root still can —
docs/THREAT-MODEL.md says so plainly, and no password manager on any machine
solves that.

## 7 · Protocol

Newline-delimited JSON over `AF_UNIX`; one request object per line, one reply
object per line, every line capped at 2 MiB. A malformed or oversized line is
answered and then the connection is closed.

| op | request | reply |
|---|---|---|
| `put` | `{"op":"put","safe":"lab-dc","handle":"<token>","material":"<b64>","idle_seconds":300,"max_seconds":3600}` | `{"ok":true,"handle":"<token>","safe":…,"expires_in":…,"idle_seconds":…,"max_seconds":…,"material_held":bool}` |
| `get` | `{"op":"get","handle":"<token>"}` | `{"ok":true,"safe":…,"material":"<b64>","material_held":bool,"expires_in":…,"idle_expires_in":…}` |
| `drop` | `{"op":"drop","handle":"<token>"}`, `{"op":"drop","safe":"lab-dc"}` or `{"op":"drop","all":true}` | `{"ok":true,"dropped":N}` |
| `keep-open` | `{"op":"keep-open","safe":"lab-dc","enabled":true}` or `{"op":"keep-open","handle":"<token>","enabled":true}` | `{"ok":true,"safe":…,"keep_open":bool,"changed":N,"affected":N,"expires_in":…,"idle_expires_in":null,…}` |
| `policy` | `{"op":"policy","safes":["lab-dc","other"]}` | `{"ok":true,"available":bool,"keep_open":{"lab-dc":true,"other":false}}` — the ONE reader of `agent.allow_keep_open`, made addressable so `secrets-admin` asks the process that refuses instead of reading the registry a second time |
| `status` | `{"op":"status"}` | `{"ok":true,"pid":…,"owner_uid":…,"holdings":[…],"keep_open":{…},"socket":{…},"session":{…}}` |

**`material` IS OPTIONAL, AND `secrets-admin` NEVER SENDS IT.** Omit it and the
holding is a **ticket**: a uid-bound record that safe X was unlocked at time T,
with both deadlines running and nothing in it that could reopen the safe. `get`
on a ticket answers `material_held:false` and carries no `material` key —
`false` and not `""`, because a caller must be able to tell "there is nothing to
give you" from "here is nothing", and `""` is exactly what a bug produces.

That is the only mode the helper uses, and §1's bargain is narrower because of
it: what you give up is not "the passphrase is prompted on every unlock" — that
still holds, because the agent has nothing to hand a later process — but the
guarantee that an unlock leaves NO trace outside the process that made it. What
you buy is the other half of I18: an unlock that is visible (`health.agent`
answers with no handle and no passphrase, so a hold survives a page reload as
something on screen) and revocable (`lock` with a bare safe id reaches a ticket
after the helper that minted it has exited). The material path is kept and
tested because I18 sanctions it as a per-safe opt-in, and because a future
reattach needs it — but nothing in this tree produces key material, and
`secrets-admin` strips a `material` key out of any reply at the door.

The `drop`-by-safe form is what `lock` sends: a Lock button has a safe id and no
handle. It is scoped to the caller's own holdings by the same rule as every
other form, and dropping a safe that is not held is `{"dropped":0}`, not
not-found — "lock something nobody unlocked" is a satisfied request, and a
not-found would tell a caller which safes are held.

`handle` is optional on `put`; the agent mints a 128-bit token when it is
absent. A supplied token must match `[A-Za-z0-9_-]{22,128}` — base64url, which
is a superset of hex, because `secrets-admin` mints `secrets.token_urlsafe(16)`
and docs/CONTRACT.md fixes the *entropy* of a handle, not its alphabet.
`idle_seconds`/`max_seconds` on `put` may only shorten the window.
Errors use docs/CONTRACT.md's taxonomy verbatim:
`{"error":"access-denied"|"not-found"|"invalid"|"unsupported"|"internal","detail":"…"}`.

`keep-open` suspends the **idle** timer for one safe's holdings — and, when the
caller is `secrets-admin` running an `open` session, that session's own idle
timer too, which is the one the operator actually feels. (The agent holds a
ticket and no key material, so suspending the ticket's timer alone keeps nothing
open; a release shipped doing exactly that and the operator was locked out on
the original schedule with the toggle on.)

**THE SESSION HALF IS SCOPED BY THE HELPER, AND THIS OP CANNOT DO IT.** This
daemon answers about ONE safe, because a holding is one safe. The helper's idle
timer is not: there is one of it per session and it ends the whole process, so
it is the only idle protection every safe that session has unlocked has.
`secrets-admin` therefore refuses to suspend it unless EVERY safe the session
holds has been affirmed here (it asks `policy` for exactly those ids), and ends
the suspension the moment the session opens one that has not. Nothing about that
rule can live in this file — the daemon does not know what a caller's session
holds — which is precisely why the two must not be confused: an `ok` from this
op is an answer about a ticket, never a grant over a session. It applies only
where
the registry entry sets `agent.allow_keep_open` — the daemon reads that for
itself, and answers `access-denied` otherwise, so a client that had been talked
into asking gets nowhere. `enabled:false` resumes it, and resumes it *from now*,
which is exactly what a `get` would have done; the alternative would make "off"
an alias for "lock immediately", and `drop` already is that. The absolute
deadline is not touched by any of it. `idle_expires_in` comes back **`null`**
while a holding is suspended rather than a large number, so a caller can tell
"no idle deadline is running" from "one is, and it is far away". There is no
`{"all":true}` form and there will not be one. Turning it on is audited, one
metadata-only line per holding.

`status` lists only the caller's own holdings (with a count of the total, which
is not sensitive), for the same reason `get` gives one answer for "unknown" and
"not yours". Its `keep_open` block — `{available, registry_dirs, suspended}` —
says whether this daemon offers the feature at all, where it looks for the
per-safe opt-in, and how many of the caller's holdings are running with the idle
timer off, so that state is inspectable without the page.

The daemon reads the registry for **one boolean per safe id and nothing else**.
It resolves no path out of an entry, opens no safe, follows no symlink
(`O_NOFOLLOW` on the directory and on the file), and ignores any file another
uid can write. It fails closed on every unknown. Note that the shipped **user**
unit sets `ProtectHome=yes`, which would hide `~/.config/cockpit-secrets/safes.d`
from it entirely — the unit binds that one directory back in read-only for this
Both DIRECTIONS of `keep-open` are gated the same way, and so is a `put` that
would carry a suspension onto a different safe: the gate is evaluated against
the safe the holding will HAVE, after any relabel, not against the id in the
request. A suspension already running is re-checked against the registry before
every expiry scan (`reconcile_keep_open`), so withdrawing `allow_keep_open`
reaches it rather than only the next request; the idle timer comes back
un-reset, which means a holding that has genuinely been idle is dropped by that
same pass.

reason, and an agent running under an older copy of it will refuse keep-open for
every user-class safe.

## 8 · Files

| Path | What |
|---|---|
| `secrets_agent.py` | the daemon; `--selfcheck` runs its own tests |
| `systemd/secrets-agent.socket` `.service` | the **user** units, installed by `install.sh --with-agent`, enabled by nobody |
| `systemd/system/secrets-agent@.socket` `.service` | the **system** template for the admin class, instanced on the numeric uid, installed by hand |

Both unit pairs set `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX`,
`IPAddressDeny=any`, `LimitCORE=0` and a `@system-service` syscall filter.

One measured wrinkle, recorded because it cost time: on systemd 259
`RuntimeDirectoryMode=` is honoured for a `.service` and **ignored for a
`.socket`** — a socket unit's `RuntimeDirectory=` lands `0755`. Both socket
units therefore carry an `ExecStartPost=/usr/bin/chmod 0700 …`, without a
leading `-`, so a run dir that cannot be made `0700` fails the unit instead of
listening in a directory everyone can read the name of. The agent repeats the
check itself where it can see the directory.

## 9 · Verifying it

```bash
python3 agent/secrets_agent.py --selfcheck        # 46 checks, refusals included
systemd-analyze verify --user agent/systemd/secrets-agent.socket \
                              agent/systemd/secrets-agent.service
systemd-analyze verify agent/systemd/system/secrets-agent@.socket \
                       agent/systemd/system/secrets-agent@.service
```

The test that matters most is the cross-uid one: a second uid must not be able
to use a handle it did not create. Drive the agent from a second account
(`cptest`, docs/HOST-FACTS.md) over a deliberately world-writable socket — so
that the *only* thing that can refuse is `SO_PEERCRED` and not the file mode —
and assert `access-denied` on `get`, on `drop`, and an empty `holdings` list in
`status`, in both directions.
