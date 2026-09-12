#!/usr/bin/env python3
"""agent/secrets_agent.py — `secrets-agent`, the opt-in unlock agent (I18).

This is the one place in cockpit-secrets that rebuilds the thing the rest of the
project exists to avoid: a process that holds unlocked material when nobody is
looking at it. docs/ARCHITECTURE.md calls the default model "true by
construction rather than by policy" — one `cockpit.spawn` per verb, one helper
process per operation, no place for a key to survive, therefore the passphrase
is demanded every time. This file replaces that construction with a promise
enforced by timers, which is strictly weaker.

So it is built to be more paranoid than the thing it makes convenient:

  - **Off by default, twice.** No socket exists unless someone enables a systemd
    unit, and nothing is held unless a registry entry sets `agent.enabled: true`
    for that safe. The helper never starts this daemon.
  - **`SO_PEERCRED` is the identity**, read from the kernel and unforgeable by
    the client. A holding belongs to the uid that created it and to no other
    uid, ever — not even to a uid the operator explicitly admitted to the
    socket (`--allow-peer-uid`), which controls only who may *speak*, never who
    may *read someone else's holding*.
  - **Both timers are hard.** `idle_seconds` resets on use, `max_seconds` never
    does, and no client message can extend either: a `put` may only SHORTEN the
    window, and re-putting an existing token keeps the original absolute
    deadline. `status` deliberately does NOT count as use — the UI polls it to
    draw the "unlocked, N s left" banner, and a banner that keeps the safe open
    by being looked at would be the whole hazard with a countdown drawn on it.
  - **One timer can be suspended, and only by the operator's own policy file.**
    `keep_open` stops the IDLE timer for one holding so a safe does not lock in
    the middle of a task. It changes nothing else: `max_seconds` still runs,
    still counts from the unlock, and still cannot be pushed out by any client
    or by this flag. It is refused unless the safe's registry entry sets
    `agent.allow_keep_open`, which the DAEMON reads for itself — see
    `RegistryPolicy`, and `op_keep_open` for why the idle timer was the only
    one worth suspending.
  - **Nothing reaches disk.** No state file, no cache, no resume-after-restart.
    Restarting the agent loses everything it holds, on purpose. It writes one
    JSON line per operation to **stderr** — `{when, op, safe, uid, outcome}`,
    metadata only, never a value and never a handle token (a token is a
    credential; a log of tokens is a log of keys).

**The gotcha this design is pinned on**, from the `peercred-unix-relay` pattern:
`SO_PEERCRED` identifies the connecting *process*, not the *human*. It is an
identity signal only because the agent runs AS the user whose material it holds
and the client is that user's own Cockpit bridge. Where a single privileged
broker connects on behalf of everyone — the `access: "admin"` path, where the
helper is root — the peer uid is the broker's and buys nothing. That is why the
admin-class unit is a template instanced on the operator's uid: the separation
between two admins comes from running one agent per operator behind a 0700 run
dir, not from `SO_PEERCRED`. See agent/README.md, which says so at more length
and argues against turning any of this on.

Group membership on the socket, likewise, is a coarse gate and not an identity.
This agent does not use one: the run dir is 0700 and the socket 0600, so the
only non-owner who can reach it is root, who could read this process's memory
anyway (docs/THREAT-MODEL.md puts root out of scope).

Protocol — newline-delimited JSON, one request object per line, one reply object
per line, UTF-8, every line capped (`MAX_LINE_BYTES`); a malformed or oversized
line is answered and then the connection is closed.

    -> {"op":"put","safe":"lab-dc","handle":"<token>","material":"<base64>",
        "idle_seconds":300,"max_seconds":3600}
    <- {"ok":true,"handle":"<token>","safe":"lab-dc","expires_in":3600,
        "idle_seconds":300,"max_seconds":3600,"material_held":true}

    -> {"op":"get","handle":"<token>"}
    <- {"ok":true,"safe":"lab-dc","material":"<base64>","material_held":true,
        "expires_in":2871,"idle_expires_in":300}

    -> {"op":"drop","handle":"<token>"}   # or {"safe":"lab-dc"} / {"all":true}
    <- {"ok":true,"dropped":1}

`material` IS OPTIONAL. Omit it and the holding is a TICKET: a uid-bound record
that safe X was unlocked at time T, with both deadlines running and nothing to
reopen it with. `get` on a ticket answers `material_held:false` and carries no
`material` key. **That is the only mode `secrets-admin` uses** — it never sends
material, because docs/CONTRACT.md says the agent holds the HANDLE and
non-negotiable 9 says the passphrase is prompted on every unlock. `op_put`'s
docstring argues the split at length. The material path is kept, tested and
unused; it is what a future opt-in reattach would need, and I18 sanctions it as
a per-safe opt-in, but nothing in this tree produces key material today.

    -> {"op":"keep-open","safe":"lab-dc","enabled":true}   # or {"handle":…}
    <- {"ok":true,"safe":"lab-dc","keep_open":true,"changed":1,"affected":1,
        "expires_in":3412,"idle_expires_in":null,"idle_seconds":300,
        "max_seconds":3600}

    -> {"op":"status"}
    <- {"ok":true,"pid":…,"owner_uid":…,"holdings":[…],"idle_seconds":300,
        "max_seconds":3600,"clock":"BOOTTIME","socket":{…},"session":{…}}

    -> {"op":"policy","safes":["lab-dc","other"]}
    <- {"ok":true,"available":true,
        "keep_open":{"lab-dc":true,"other":false}}
       # the ONE reader of agent.allow_keep_open, made addressable so the
       # helper asks instead of reading the registry a second time

Errors use docs/CONTRACT.md's taxonomy verbatim:
`{"error":"access-denied"|"not-found"|"invalid"|"unsupported"|"internal",
  "detail":"…"}`. An unknown handle and another uid's handle return the SAME
`access-denied` — distinguishing them would turn `get` into an enumeration
oracle that says which tokens exist.

Run modes:

    secrets-agent.socket   systemd hands the listening fd on fd 3 (preferred:
                           systemd creates it with the right owner and mode and
                           no cross-namespace chown is needed)
    python3 secrets_agent.py --run-dir DIR      self-bind, 0700 dir / 0600 socket
    python3 secrets_agent.py --selfcheck        run this file's self-check
    python3 secrets_agent.py --no-keep-open     refuse keep-open for every safe,
                                                whatever any registry says

stdlib only, plus `backends/base.py` for `harden_process`, `Secret`, `redact`
and the error taxonomy. No pip. Python 3.9+ (developed on 3.14.4).
"""

import argparse
import base64
import errno
import hmac
import json
import os
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

# ===========================================================================
# locating backends/ — the same discipline secrets-admin applies, for the same
# reason: this is CODE, and this process holds passphrases.
# ===========================================================================


def _trusted_dir(path, euid):
    """True when `path` is a directory this euid may safely import code from.

    Opened `O_NOFOLLOW|O_DIRECTORY` and checked by `fstat` on the **fd**, never
    by a second `stat` of the path — a path can change between two calls and a
    file descriptor cannot (I5, the same rule `base.open_safe_fd` keeps).
    """
    if not path or not os.path.isabs(path):
        return False
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0))
        st = os.fstat(fd)
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    if not stat.S_ISDIR(st.st_mode):
        return False
    if st.st_uid not in (0, euid):
        return False
    # Group- or other-writable means someone else can drop a .py in it, which
    # for a code directory is arbitrary execution inside the process that holds
    # every passphrase this user has typed today.
    return not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _install_lib_path():
    """Put the directory holding `backends/` on `sys.path`; return it.

    Same honest asymmetry as `secrets-admin`: the tree this file itself lives in
    is reported rather than refused (a development checkout on this host is
    group-writable, and pretending otherwise would be theatre — the module is
    already reachable), while every other candidate must pass `_trusted_dir`.
    """
    euid = os.geteuid()
    here = os.path.dirname(os.path.realpath(__file__))
    own = os.path.dirname(here)          # …/source, or …/lib/cockpit-secrets
    for cand in (own, "/usr/local/lib/cockpit-secrets",
                 "/usr/share/cockpit/secrets"):
        try:
            if not os.path.isfile(os.path.join(cand, "backends", "base.py")):
                continue
        except (OSError, ValueError):
            continue
        trusted = _trusted_dir(cand, euid)
        if cand == own and not trusted:
            sys.stderr.write(
                "secrets-agent: WARNING: %s is group/other-writable or not "
                "owned by root or this user; importing backends from it "
                "anyway because it is this script's own tree. Install the "
                "agent root-owned before trusting this host.\n" % cand)
        elif not trusted:
            sys.stderr.write("secrets-agent: ignoring untrusted library root "
                             "%s (ownership or mode)\n" % cand)
            continue
        if cand not in sys.path:
            sys.path.insert(0, cand)
        return cand
    return None


LIB_ROOT = _install_lib_path()

try:
    from backends.base import (                                    # noqa: E402
        AccessDenied, Internal, Invalid, Limits, Secret, SecretsError,
        harden_process, redact,
    )
except ImportError as exc:                                         # noqa: F841
    sys.stderr.write(
        "secrets-agent: cannot import backends.base (looked in %s). The agent "
        "holds secrets and will not run without the hardening, zeroing and "
        "redaction primitives that live there.\n" % (LIB_ROOT or "nowhere"))
    sys.exit(2)


VERSION = "1.0.0"

# ===========================================================================
# policy constants — every one of them a ceiling, never a floor
# ===========================================================================

#: The published defaults, and the ones docs/OPERATIONS.md and the registry
#: schema name. `--idle-seconds`/`--max-seconds` may go BELOW these (shorter is
#: always safer, and the tests need seconds rather than hours); going above is
#: bounded by the two ceilings underneath.
DEFAULT_IDLE_SECONDS = 300
DEFAULT_MAX_SECONDS = 3600

#: Hard ceilings. These match the registry schema's maxima on purpose, so the
#: agent never silently refuses a schema-valid entry — but a window above the
#: defaults is logged loudly at start-up, because "an unlocked password safe as
#: a service" is what that configuration is.
IDLE_CEILING_SECONDS = 3600
LIFETIME_CEILING_SECONDS = 86400

#: How many unlocked safes one agent will hold at once. Not a performance
#: number: every holding is a safe that is open while nobody watches, and a
#: client that can ask for unbounded holdings can pin unbounded plaintext.
MAX_HOLDINGS = 16

#: How many ids one `policy` request may ask about. The helper asks once per
#: access class with the ids it is already listing, so this is a registry's
#: worth of safes and not a feed.
MAX_POLICY_SAFES = 512
#: Simultaneous connections. The clients are one Cockpit bridge's helpers.
MAX_CONNECTIONS = 16
#: A connection that has said nothing for this long is dropped. A client that
#: opens sockets and never speaks is either broken or squatting.
CONNECTION_IDLE_SECONDS = 30

#: One protocol line. Material is capped at `Limits.MAX_KEYFILE_BYTES` (1 MiB),
#: base64 inflates it by 4/3, and the JSON envelope is small — 2 MiB is that
#: with room, and it is a cap rather than a stream so a client cannot balloon
#: the agent by never sending a newline.
MAX_LINE_BYTES = 2 * 1024 * 1024
#: The material one `put` may carry. Reuses the helper's key-file ceiling
#: because that is the largest legitimate thing an unlock needs to remember.
MAX_MATERIAL_BYTES = Limits.MAX_KEYFILE_BYTES

#: WHERE THE DAEMON LOOKS FOR THE PER-SAFE `agent.allow_keep_open` OPT-IN.
#: The same two directories `secrets-admin` reads, in the same order, because
#: the two must not be able to disagree about what the operator wrote. The
#: SYSTEM one is root-owned policy and wins; the per-user one is the caller's
#: own and is consulted second. Neither is created here and nothing in either
#: is used for anything but one boolean — see `RegistryPolicy`.
DEFAULT_SYSTEM_REGISTRY = "/etc/cockpit-secrets/safes.d"
USER_REGISTRY_REL = (".config", "cockpit-secrets", "safes.d")

#: Bounds on that read. A registry is an operator's directory, not a feed, but
#: the daemon that holds every passphrase this user has typed today is not the
#: process to hand an unbounded `listdir` and an unbounded `read`.
MAX_REGISTRY_FILES = 512
MAX_REGISTRY_FILE_BYTES = 256 * 1024

#: Handle tokens are the helper's 128-bit opaque tokens (docs/CONTRACT.md,
#: "an opaque 128-bit random token"). The contract fixes the ENTROPY, not the
#: alphabet, and `secrets-admin` mints `secrets.token_urlsafe(16)` — 128 bits
#: in base64url, which a hex-only class rejected outright. Widened to the
#: base64url alphabet, which is a superset of hex, so every token this daemon
#: used to accept it still accepts. It stays a narrow, explicit character class
#: for the reason it always was: this string is compared, logged only as
#: present/absent, and never interpolated anywhere.
#:
#: The lower bound is 22 characters because that is what 128 bits of base64url
#: is (`len(token_urlsafe(16)) == 22`); hex needs 32 for the same entropy, and
#: taking the smaller of the two is the price of accepting both alphabets. It
#: is a shape check, not an entropy check — the daemon cannot audit a token's
#: randomness, and a caller that mints a weak token is only weakening its own
#: holding, which no length rule here could prevent.
_TOKEN_RE = re.compile(r"\A[A-Za-z0-9_-]{22,128}\Z")
#: Registry ids, matching schema/safe-registry.schema.json exactly. The id
#: reaches log lines, so it is validated rather than sanitised after the fact.
_SAFE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,62}\Z")

#: Event-loop tick. Bounds how late an expiry can fire and how late a session
#: lock is noticed; also the interval the freeze detector measures against.
TICK_SECONDS = 5.0
#: A gap between ticks larger than TICK + this means the machine was suspended
#: or the process was stopped. See `_check_freeze`.
FREEZE_SLACK_SECONDS = 30.0
#: How often the logind session state is polled. A poll, not a subscription —
#: stated as such here and in the report, because the difference is real.
SESSION_POLL_SECONDS = 10.0

#: How often a LIVE suspension is re-checked against the registry that granted
#: it. The opt-in is an operator decision that can be withdrawn, and a gate
#: that only ran at the moment of the request is a gate that cannot be
#: withdrawn — the suspension would outlive the permission for the rest of the
#: holding's absolute lifetime. See `Agent.reconcile_keep_open`.
POLICY_RECHECK_SECONDS = 15.0

#: systemd's socket-activation contract: the first passed fd is always 3.
SD_LISTEN_FDS_START = 3

#: `struct ucred { pid_t pid; uid_t uid; gid_t gid; }` — three ints, native.
_UCRED = struct.Struct("3i")


# ===========================================================================
# clock — BOOTTIME, not MONOTONIC, and the difference is a security property
# ===========================================================================

def _pick_clock():
    """Return (clock_id, name).

    `CLOCK_MONOTONIC` does **not** advance while the machine is suspended, so an
    agent using it would come back from an eight-hour suspend still holding an
    unlocked safe with 297 of its 300 idle seconds left. `CLOCK_BOOTTIME` counts
    suspended time, which is the only reading of "idle for five minutes" that
    means anything to someone who closed a laptop lid.
    """
    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    if boottime is not None:
        try:
            time.clock_gettime(boottime)
            return boottime, "BOOTTIME"
        except OSError:
            pass
    sys.stderr.write("secrets-agent: WARNING: CLOCK_BOOTTIME is unavailable; "
                     "falling back to CLOCK_MONOTONIC, which does not count "
                     "suspended time. Timeouts will under-count across a "
                     "suspend.\n")
    return time.CLOCK_MONOTONIC, "MONOTONIC"


_CLOCK_ID, CLOCK_NAME = _pick_clock()


def now():
    """Seconds on the chosen clock. Never `time.time()`: a wall clock can be
    stepped backwards, and a deadline a client can move by changing the date is
    not a deadline."""
    return time.clock_gettime(_CLOCK_ID)


# ===========================================================================
# audit — metadata only, to stderr, so systemd's journal is the only writer
# ===========================================================================

def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def audit(op, safe, uid, outcome, detail=None):
    """One JSON line on stderr: `{when, op, safe, uid, outcome}` (I15).

    Never a value, never a traceback, and never the handle token — a token is a
    credential for the material it names, so a log of tokens would be a log of
    keys sitting in the journal long after the material was zeroed. `detail`
    goes through `redact()` against every live `Secret` first, so even a mistake
    in a caller cannot put material here.

    stderr and nothing else: under systemd this is the journal, which is the
    operator's log and not the agent's state. The agent must have no state file
    at all, so it must not own a log file either — see the module docstring.
    """
    rec = {"when": _utc_now(), "op": op, "safe": safe, "uid": uid,
           "outcome": outcome}
    if detail:
        rec["detail"] = redact(str(detail))[:200]
    try:
        sys.stderr.write(json.dumps(rec, separators=(",", ":"),
                                    sort_keys=True) + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass            # a failed log line must never take the agent down


def _note(msg):
    """Operator-facing diagnostic, distinguishable from an audit line."""
    try:
        sys.stderr.write("secrets-agent: %s\n" % msg)
        sys.stderr.flush()
    except OSError:
        pass


# ===========================================================================
# registry policy — the one thing this daemon reads off the disk, and why
# ===========================================================================

class RegistryPolicy:
    """Answers ONE question per safe id: may this safe suspend its idle timer?

    **THE DAEMON IS THE AUTHORITY, NOT THE CALLER.** `keep_open` turns off the
    only automatic defence the agent has against an operator who walks away, so
    "is that permitted for this safe?" cannot be a field in the request that
    asks for it. The registry is the operator's policy file — the same file the
    access class, the timeouts and the read-only flag come from — and this class
    is the daemon reading it for itself rather than trusting a client that has
    already read it once.

    **WHAT IT READS, AND WHAT IT REFUSES TO READ.** One boolean per id:
    `agent.allow_keep_open`. `path`, `keyfile`, `export_dir` and every other
    key in an entry are ignored by construction — the agent opens no safe, and
    a daemon that started resolving paths out of the registry would be a daemon
    with a reason to open one. It never writes, never creates a directory, and
    never follows a symlink (`O_NOFOLLOW` on both the directory and the file,
    `fstat` on the fd and never a second `stat` of the path — I5).

    **IT FAILS CLOSED, AND THERE IS NO OTHER BRANCH.** No entry, no registry,
    an unreadable directory, an unparsable file, a file some other uid can
    write: every one of those answers "not allowed", with a reason that names
    no path (I15). The one asymmetry worth stating out loud is that the shipped
    USER unit sets `ProtectHome=yes`, so on a stock install this class cannot
    see `~/.config/cockpit-secrets/safes.d` at all and a user-class safe simply
    cannot turn keep-open on. `agent/systemd/secrets-agent.service.in` binds
    that one directory back in read-only for exactly this reason; an
    installation that has not is refused rather than guessed at.

    **A SYSTEM ENTRY WINS.** Directories are consulted in order and the first
    one holding the id decides, which is the rule `secrets-admin` applies to
    the same two registries: a file the user can write must not be able to
    overrule root's answer about the user's own safe.
    """

    def __init__(self, dirs, euid):
        self.dirs = tuple(d for d in dirs if d)
        self.euid = euid

    # -- one entry file ----------------------------------------------------

    def _read_entry(self, dirfd, name):
        """The parsed JSON object in `name`, or None when it is not usable.

        Opened relative to an already-validated directory fd, so the name is
        never joined into a path this function then re-opens.
        """
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                         | os.O_NONBLOCK, dir_fd=dirfd)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > MAX_REGISTRY_FILE_BYTES:
                return None
            # A registry file another uid may write is a registry file that
            # names its own policy. Refused rather than read.
            if st.st_uid not in (0, self.euid):
                return None
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None
            data = os.read(fd, MAX_REGISTRY_FILE_BYTES + 1)
        except OSError:
            return None
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if len(data) > MAX_REGISTRY_FILE_BYTES:
            return None
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            # An entry this daemon cannot parse is an entry that grants
            # nothing. `secrets-admin` reports the same file as a registry
            # error, which is where an operator finds out why.
            return None
        return doc if isinstance(doc, dict) else None

    # -- one directory -----------------------------------------------------

    def _scan_dir(self, path, safe):
        """(True/False, reason) when `path` holds `safe`; (None, reason) else."""
        dfd = None
        try:
            dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                          | os.O_CLOEXEC)
            st = os.fstat(dfd)
            if not stat.S_ISDIR(st.st_mode):
                return None, "a registry root is not a directory"
            if st.st_uid not in (0, self.euid):
                return None, "a registry root is owned by another user"
            if st.st_mode & stat.S_IWOTH:
                return None, "a registry root is world-writable"
            names = sorted(n for n in os.listdir(dfd)
                           if n.endswith(".json"))[:MAX_REGISTRY_FILES]
            found = None
            for name in names:      # lexically LAST wins, as the helper does
                doc = self._read_entry(dfd, name)
                if doc is None or doc.get("id") != safe:
                    continue
                cfg = doc.get("agent")
                cfg = cfg if isinstance(cfg, dict) else {}
                found = (cfg.get("allow_keep_open") is True
                         and cfg.get("enabled") is True)
            if found is None:
                return None, "no entry for this safe in that registry"
            if found:
                return True, ""
            return False, ("the registry entry does not set both "
                           "agent.enabled and agent.allow_keep_open")
        except OSError:
            return None, "a registry root could not be read"
        finally:
            if dfd is not None:
                try:
                    os.close(dfd)
                except OSError:
                    pass

    # -- the answer --------------------------------------------------------

    def allows_keep_open(self, safe):
        """(True, "") when the operator opted this safe in; (False, why) else."""
        if not self.dirs:
            return False, "this agent has no registry to consult"
        why = "no registry entry for this safe"
        for path in self.dirs:
            verdict, reason = self._scan_dir(path, safe)
            if verdict is True:
                return True, ""
            if verdict is False:
                return False, reason        # a system entry ends the search
            if reason:
                why = reason
        return False, why


def default_registry_dirs():
    """The two directories `RegistryPolicy` consults when none were named.

    `COCKPIT_SECRETS_ETC` and `COCKPIT_SECRETS_HOME` are honoured because
    `secrets-admin` honours them and the two must read the same registry —
    without them the integration suite would be testing this daemon against
    the operator's REAL registry, which is worse than a seam. They are read
    from THIS PROCESS's environment, which systemd (or whoever started the
    agent) set; a client on the socket cannot reach it.
    """
    etc = os.environ.get("COCKPIT_SECRETS_ETC")
    system = (os.path.join(etc, "safes.d") if etc and os.path.isabs(etc)
              else DEFAULT_SYSTEM_REGISTRY)
    home = os.environ.get("COCKPIT_SECRETS_HOME") or os.path.expanduser("~")
    dirs = [system]
    if home and os.path.isabs(home):
        dirs.append(os.path.join(home, *USER_REGISTRY_REL))
    return dirs


# ===========================================================================
# Holding — one unlocked safe's material, with its two deadlines
# ===========================================================================

class Holding:
    """The material for one safe, the token that names it, and who owns it.

    Both the token and the material live in wipeable buffers: the material in a
    `Secret` (see its docstring for what that does and does not buy), the token
    in a `bytearray` this class zeroes in place. `__slots__` means there is no
    instance `__dict__` for a stray attribute assignment to leave a second,
    unzeroed copy in.

    `material` is `None` for a TICKET-ONLY holding — the mode `secrets-admin`
    uses, where the agent remembers that a safe was unlocked and by whom but
    holds nothing that could reopen it. Every deadline, ownership and audit
    rule below is identical for both kinds; only `zero()` and the two ops that
    hand material back have anything to branch on.
    """

    __slots__ = ("_token", "safe", "uid", "material", "created", "last_used",
                 "idle_seconds", "max_seconds", "keep_open")

    def __init__(self, token, safe, uid, material, idle_seconds, max_seconds,
                 keep_open=False):
        # bytearray(str) needs an encoding; the token is ASCII hex by
        # construction (_TOKEN_RE), so this cannot be lossy.
        self._token = bytearray(token.encode("ascii"))
        self.safe = safe
        self.uid = uid
        self.material = material                 # a Secret; we own it now
        self.created = now()
        self.last_used = self.created
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds
        #: The IDLE timer is suspended for this holding. `max_seconds` is not
        #: affected and cannot be: see `expires_in`. Set only through
        #: `Agent._require_keep_open_allowed`, which reads the registry.
        self.keep_open = bool(keep_open)

    # -- identity ----------------------------------------------------------

    def owned_by(self, uid, token_bytes):
        """Constant-time "is this the caller's holding?".

        `compare_digest` on the token rather than `==` for the usual reason (I6)
        — a token is a credential and an early-exit comparison leaks its prefix
        one byte at a time. The uid check is a plain integer compare because
        there is nothing to leak: the caller already knows their own uid.
        """
        return uid == self.uid and hmac.compare_digest(
            bytes(self._token), token_bytes)

    def token_str(self):
        """The token, for a reply to its own owner. Never for a log line."""
        return self._token.decode("ascii")

    # -- deadlines ---------------------------------------------------------

    def touch(self):
        """Reset the IDLE timer. Deliberately does not touch `created`: the
        absolute deadline is not extendable by use, which is the entire point of
        having two timers instead of one."""
        self.last_used = now()

    def expires_in(self, at=None):
        """Seconds until this holding dies, whichever deadline comes first.

        With `keep_open` the idle deadline is not one of the candidates — that
        is the whole of what the flag does. **The absolute deadline is still
        here, still counted from `created`, and still the value nothing can
        move**, so a suspended holding is bounded by `max_seconds` exactly as a
        normal one is and "keep it open" can never mean "keep it open forever".
        """
        at = now() if at is None else at
        absolute = self.created + self.max_seconds
        if self.keep_open:
            return absolute - at
        return min(absolute, self.last_used + self.idle_seconds) - at

    def idle_expires_in(self, at=None):
        """Seconds until the IDLE deadline, or None while it is suspended.

        None rather than a large number: a caller must be able to tell "there
        is no idle deadline running" from "there is one, and it is far away",
        and a number is exactly what a UI would draw a countdown from.
        """
        if self.keep_open:
            return None
        at = now() if at is None else at
        return self.last_used + self.idle_seconds - at

    def expired(self, at=None):
        return self.expires_in(at) <= 0

    def why_expired(self, at=None):
        """Which deadline fired — for the audit line, not for the client."""
        at = now() if at is None else at
        if self.created + self.max_seconds <= at:
            return "absolute"
        return "idle"

    # -- lifetime ----------------------------------------------------------

    def zero(self):
        """Overwrite material and token in place. Idempotent."""
        if self.material is not None:       # None == a ticket-only holding
            try:
                self.material.zero()
            except Exception:                               # noqa: BLE001
                pass
        n = len(self._token)
        if n:
            self._token[:] = b"\x00" * n     # overwrite, then release
            del self._token[:]

    def __repr__(self):
        return "<Holding safe=%s uid=%d live=%s>" % (
            self.safe, self.uid, bool(len(self._token)))

    __str__ = __repr__


# ===========================================================================
# Agent — the policy. No sockets in here; see Server for the plumbing.
# ===========================================================================

class Agent:
    """Holds material, enforces admission, ownership and both deadlines.

    Split from the socket handling so the rules can be exercised without a
    socket — `_selfcheck()` drives this class directly, including the refusals.
    """

    def __init__(self, owner_uid, *, idle_seconds=DEFAULT_IDLE_SECONDS,
                 max_seconds=DEFAULT_MAX_SECONDS, allow_peer_uids=(),
                 keep_open_available=True, policy=None):
        self.owner_uid = owner_uid
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds
        #: Extra uids ADMITTED to the socket. This is a speaking gate and
        #: nothing more: an admitted uid gets its own holdings and can never
        #: reach anyone else's, because `owned_by()` compares the creating uid
        #: and has no exception in it. Empty by default.
        self.allow_peer_uids = frozenset(allow_peer_uids)
        #: Whether this agent will honour `keep_open` AT ALL. A ceiling, never
        #: a floor: `--no-keep-open` refuses every request whatever a registry
        #: says, and nothing turns it back on over the wire.
        self.keep_open_available = bool(keep_open_available)
        #: The registry this daemon consults for `agent.allow_keep_open`. Never
        #: consulted for anything else, and never for a path.
        self.policy = policy or RegistryPolicy((), owner_uid)
        self.holdings = []           # list, not dict: scanned in fixed order
        #: Filled in by main() once the socket and the watcher exist, so
        #: `status` can tell an operator what the agent thinks its own socket
        #: mode and session state are. Metadata about the agent, not about any
        #: safe, so it is not gated on ownership.
        self.socket_facts = {}
        self.watcher = None
        #: How often `reconcile_keep_open` re-reads the registry for a LIVE
        #: suspension. An attribute rather than the constant so a test can set
        #: it to 0 and measure the revocation instead of waiting for it.
        self.policy_recheck = POLICY_RECHECK_SECONDS
        self._last_reconcile = 0.0

    # -- admission ---------------------------------------------------------

    def admits(self, uid):
        """May this peer uid speak to the agent at all?

        The 0700 run dir already refuses everyone but the owner and root; this
        is the same rule stated where a reader can see it, and it is what
        remains when systemd (not this process) created the socket.
        """
        return uid == self.owner_uid or uid in self.allow_peer_uids

    # -- lookup ------------------------------------------------------------

    def _find(self, uid, token):
        """The caller's live holding for `token`, or `AccessDenied`.

        **An unknown token and another uid's token are the same answer.** A
        `not-found` for one and an `access-denied` for the other would let a
        caller enumerate which tokens exist on this agent, which is exactly the
        oracle docs/CONTRACT.md flattened the error taxonomy to prevent (I6).
        """
        want = token.encode("ascii")
        found = None
        for h in self.holdings:      # scan them all: no early exit, no timing
            if h.owned_by(uid, want):
                found = h
        if found is None:
            raise AccessDenied("no such handle for this caller")
        return found

    # -- expiry ------------------------------------------------------------

    def refresh(self, at=None, force=False):
        """Reconcile live suspensions against the registry, THEN sweep.

        In that order, and it is the only order: a suspension the operator has
        just stopped allowing has to be gone before the deadlines are read, so
        that the very same pass applies the idle timer it was hiding.

        It is a separate function from `sweep` because `sweep` is one of the
        four the standing bans hold to a rule — it, `drop_all`,
        `_check_session` and `_check_freeze` must not so much as MENTION
        `keep_open`, because the day one of them grows a branch that spares a
        suspended holding is the day a toggle starts outliving a locked screen.
        Reconciliation is the opposite operation — it takes suspensions AWAY —
        and it earns its own name rather than an exemption inside a function
        that is not allowed to have one.
        """
        at = now() if at is None else at
        self.reconcile_keep_open(at, force=force)
        return self.sweep(at)

    def sweep(self, at=None):
        """Drop and zero everything whose deadline has passed. Returns how many.

        Called from the event loop on every tick and before every operation, so
        an expired holding cannot be read by a request that arrives in the same
        millisecond as its deadline.
        """
        at = now() if at is None else at
        dropped = 0
        for h in list(self.holdings):
            if h.expired(at):
                why = h.why_expired(at)
                self.holdings.remove(h)
                audit("expire", h.safe, h.uid, "dropped", why)
                h.zero()
                dropped += 1
        return dropped

    def reconcile_keep_open(self, at=None, force=False):
        """Re-read the registry for every LIVE suspension and end the ones it
        no longer allows. Returns how many were ended.

        **THE OPT-IN IS WITHDRAWABLE, AND THIS IS WHAT MAKES IT SO.** Without
        this, `agent.allow_keep_open: false` only stopped the NEXT request: a
        holding suspended a minute earlier kept its suspension for the rest of
        its absolute lifetime, so an operator who revoked the permission —
        which is the one action they have when they decide a safe should not be
        held open — changed nothing about the safe that was actually being held
        open. A gate that runs only at the moment of the request is a gate that
        cannot be withdrawn.

        **THE IDLE TIMER COMES BACK UNTOUCHED, AND THAT IS DELIBERATE.**
        `last_used` is not reset here. A holding that has been suspended and
        idle for an hour therefore has an idle deadline an hour in the past and
        is dropped by the same sweep, which is the honest outcome: the timer
        that would have locked it is being re-imposed, and it had already
        elapsed. A holding that is actually being used has a fresh `last_used`
        and survives, which is equally honest. Touching it here would hand a
        revoked suspension one last free idle window.

        Throttled to `policy_recheck` because it reads files; `force` is for
        the ops that must not answer out of a stale read.
        """
        at = now() if at is None else at
        live = [h for h in self.holdings if h.keep_open]
        if not live:
            return 0
        if not force and (at - self._last_reconcile) < self.policy_recheck:
            return 0
        self._last_reconcile = at
        ended = 0
        for h in live:
            if self.keep_open_available:
                allowed, why = self.policy.allows_keep_open(h.safe)
                if allowed:
                    continue
            else:
                why = "disabled on this agent"
            h.keep_open = False          # NO touch(): see the docstring
            ended += 1
            audit("keep-open", h.safe, h.uid, "revoked", why)
        if ended:
            _note("the registry no longer allows keep-open for %d holding(s); "
                  "their idle timers are running again" % ended)
        return ended

    def next_deadline(self, at=None):
        """Seconds until the earliest expiry, or None when nothing is held."""
        at = now() if at is None else at
        if not self.holdings:
            return None
        return max(0.0, min(h.expires_in(at) for h in self.holdings))

    def drop_all(self, reason):
        """Zero everything. The response to SIGTERM, a session lock, a suspend
        and the end of the process."""
        n = len(self.holdings)
        for h in self.holdings:
            audit("drop", h.safe, h.uid, "dropped", reason)
            h.zero()
        self.holdings = []
        return n

    # -- the keep-open gate ------------------------------------------------

    def _require_keep_open_allowed(self, safe, uid):
        """Refuse unless the REGISTRY says this safe may suspend its idle timer.

        Two gates, in this order, and the caller is not consulted by either:

          1. `--no-keep-open` — an operator-set ceiling on this whole daemon.
          2. `agent.allow_keep_open` on the safe's own registry entry, read by
             `RegistryPolicy` off the disk. Absent, unreadable or false all
             answer the same way: no.

        `access-denied` rather than `unsupported`, because the request is
        perfectly well formed and the answer will change the moment the
        operator edits their registry — and rather than `invalid`, which reads
        as "you typed that wrong". The audit line names the safe, the uid and
        the outcome and nothing else: no path, no registry file name, no value
        (I15).
        """
        if not self.keep_open_available:
            audit("keep-open", safe, uid, "denied", "disabled on this agent")
            raise AccessDenied("this agent does not offer keep-open")
        allowed, why = self.policy.allows_keep_open(safe)
        if not allowed:
            audit("keep-open", safe, uid, "denied", why)
            raise AccessDenied("the registry does not allow keep-open for this "
                               "safe (%s)" % why)

    # -- operations --------------------------------------------------------

    def op_put(self, uid, req):
        """Take custody of one safe's material, or of a bare ticket.

        The window may only ever be SHORTENED: the effective idle and absolute
        seconds are `min(configured, requested)`. And re-putting a token that is
        already held keeps the ORIGINAL `created`, so a client cannot ride one
        unlock past `max_seconds` by re-sending the material it already has.

        **`material` IS OPTIONAL, AND `secrets-admin` NEVER SENDS IT.** That is
        the reconciliation this file and the helper needed, and it goes this way
        round rather than the other for one reason: docs/CONTRACT.md says "the
        HANDLE is held by `secrets-agent`", and non-negotiable 9 says the
        passphrase is prompted on every unlock. A material-carrying holding
        would let a second helper process reopen a safe with no prompt. I18
        permits exactly that as a per-safe opt-in, so the capability is kept —
        but nothing in this tree produces key material, nothing consumes it, and
        shipping a live material path that only a future caller could use is a
        loaded gun. What the helper does send is a ticket: a uid-bound record
        that safe X was unlocked at time T, with both deadlines running.

        A ticket buys the half of I18 that is about VISIBILITY and REVOCATION —
        `health.agent` can show "unlocked, N s remaining" from a number the
        helper did not invent, and `lock` can revoke across processes — without
        buying the half that is about not being asked again. The two halves were
        always separable; only one of them weakens anything.
        """
        self.refresh(force=True)
        safe = _require_safe_id(req.get("safe"))
        token = _require_token(req.get("handle"), allow_none=True)
        material = _decode_material(req.get("material"), allow_none=True)
        try:
            idle = _clamp_shorter(req.get("idle_seconds"), self.idle_seconds)
            lifetime = _clamp_shorter(req.get("max_seconds"), self.max_seconds)
            # ABSENT means "leave it as it is", which matters for a re-put:
            # `secrets-admin` never sends this field, and a re-put that
            # silently cleared a suspension the operator had asked for would
            # be a toggle that turns itself off. False still means false.
            keep = req.get("keep_open")
            if keep is not None and not isinstance(keep, bool):
                raise Invalid("keep_open is not a boolean")
            if token is None:
                # No token offered: mint one. `Secret.random` is
                # `secrets.token_bytes`, never `random` — this token is what
                # binds a holding to a caller.
                minted = Secret.random(16)
                try:
                    token = bytes(minted.bytes).hex()
                finally:
                    minted.zero()

            existing = None
            for h in self.holdings:
                if h.owned_by(uid, token.encode("ascii")):
                    existing = h

            # ================================================================
            # THE KEEP-OPEN GATE, ON THE SAFE THIS HOLDING WILL *HAVE*.
            #
            # It used to sit above, keyed on `req["safe"]` and run only when
            # the request said `keep_open: true`. Both halves were wrong, and
            # together they were a three-message bypass of the registry:
            #
            #   put {safe: denied}                      -> a handle
            #   put {handle, safe: allowed, keep_open}  -> gate passes on the
            #                                              ALLOWED id
            #   put {handle, safe: denied}              -> `keep` is absent, so
            #                                              "leave it as it is"
            #                                              carried the
            #                                              suspension back onto
            #                                              the DENIED safe
            #
            # `existing` is found by HANDLE, so the third message relabels the
            # holding and the gate never runs. The fix is to stop asking about
            # the request and ask about the holding: compute what `keep_open`
            # will actually BE — the request's value, or the one being carried
            # forward — and gate that against the safe the holding will carry
            # after the relabel. Nothing has been mutated yet when this raises.
            # ================================================================
            effective_keep = (keep if keep is not None
                              else (bool(existing.keep_open)
                                    if existing is not None else False))
            if effective_keep:
                self._require_keep_open_allowed(safe, uid)

            if existing is not None:
                # Replace the material, keep the absolute deadline. A
                # ticket-only re-put over a material-carrying holding zeroes
                # the material and leaves the ticket: a downgrade is always
                # allowed, because forgetting a key is never the unsafe
                # direction.
                old, existing.material = existing.material, material
                material = None
                if old is not None:
                    old.zero()
                existing.safe = safe
                existing.idle_seconds = min(existing.idle_seconds, idle)
                existing.max_seconds = min(existing.max_seconds, lifetime)
                existing.keep_open = effective_keep
                existing.touch()
                held = existing
            else:
                if len(self.holdings) >= MAX_HOLDINGS:
                    raise Invalid("this agent already holds the maximum of %d "
                                  "safes" % MAX_HOLDINGS)
                held = Holding(token, safe, uid, material, idle, lifetime,
                               effective_keep)
                material = None                 # the Holding owns it now
                self.holdings.append(held)
        finally:
            # If anything above raised, the material never reached a Holding
            # and nothing else will ever zero it.
            if material is not None:
                material.zero()

        # The audit line says which kind of holding this is, because "the agent
        # is holding a key" and "the agent is holding a note that says a key
        # once existed" are very different facts to read off a log six months
        # later. It is a shape, not a value (I15).
        audit("put", safe, uid, "ok",
              "idle=%d max=%d %s%s" % (held.idle_seconds, held.max_seconds,
                                       "material" if held.material is not None
                                       else "ticket-only",
                                       " keep-open" if held.keep_open else ""))
        return {"ok": True, "handle": held.token_str(), "safe": held.safe,
                "expires_in": int(held.expires_in()),
                "idle_seconds": held.idle_seconds,
                "max_seconds": held.max_seconds,
                "keep_open": held.keep_open,
                "material_held": held.material is not None}

    def op_get(self, uid, req):
        """Hand the material back to the uid that deposited it, and only to it.

        A ticket-only holding answers with everything EXCEPT `material`, and
        says so with `material_held: false` rather than an empty string: a
        caller must be able to tell "there is nothing to give you" from "here
        is nothing", and `""` is exactly the value a bug produces.
        """
        self.sweep()
        token = _require_token(req.get("handle"))
        h = self._find(uid, token)
        h.touch()               # `get` is use; the idle timer restarts here
        out = {"ok": True, "safe": h.safe,
               "material_held": h.material is not None,
               "keep_open": h.keep_open,
               "expires_in": int(h.expires_in()),
               "idle_expires_in": _maybe_int(h.idle_expires_in())}
        if h.material is not None:
            # b64encode makes an immutable copy the GC owns and `zero()` cannot
            # reach, and json.dumps makes another as a str. Unavoidable on the
            # way out, the same leak `Secret.str_view()` documents; it is
            # bounded by the reply being written and dropped immediately.
            out["material"] = base64.b64encode(h.material.bytes).decode("ascii")
        audit("get", h.safe, uid, "ok")
        return out

    def op_drop(self, uid, req):
        """Forget one holding, this caller's holdings for one safe, or all.

        The by-SAFE form is what `secrets-admin`'s `lock` verb sends: a Lock
        button has a safe id and no handle — the helper that minted the handle
        exited when its verb returned. It is scoped to the caller's own
        holdings by the same `h.uid == uid` rule as every other form, so it can
        no more reach another operator's ticket than `drop` by handle can.
        """
        self.sweep()
        if req.get("all") is True:
            mine = [h for h in self.holdings if h.uid == uid]
            return self._drop_these(uid, mine, "client")
        if "safe" in req and req.get("handle") is None:
            safe = _require_safe_id(req.get("safe"))
            mine = [h for h in self.holdings if h.uid == uid and h.safe == safe]
            # An empty result is `dropped: 0`, not not-found: "lock a safe that
            # is not held" is a satisfied request, and answering not-found
            # would tell a caller which safes are held (the same enumeration
            # oracle `get` is flattened to avoid).
            return self._drop_these(uid, mine, "client by-safe")
        token = _require_token(req.get("handle"))
        h = self._find(uid, token)
        return self._drop_these(uid, [h], "client")

    def _drop_these(self, uid, holdings, reason):
        """Remove and zero a list of this caller's holdings. One audit line
        each, so a by-safe drop of three tickets is three lines, not one."""
        for h in holdings:
            self.holdings.remove(h)
            audit("drop", h.safe, uid, "dropped", reason)
            h.zero()
        return {"ok": True, "dropped": len(holdings)}

    def op_keep_open(self, uid, req):
        """Suspend, or resume, the IDLE timer for this caller's holdings.

        Two shapes, exactly as `drop` has two: a HANDLE names one holding, and
        a bare SAFE names every holding this caller has for that safe. The
        second is the one the page can send — `health` strips the token before
        the browser sees it, so a banner has a safe id and nothing else. There
        is no `{"all": true}` form, and there will not be one.

        THE ABSOLUTE DEADLINE IS NOT TOUCHED BY THIS OPERATION AND CANNOT BE.
        `max_seconds` still counts from the unlock, `expires_in` still reports
        it, and a holding whose lifetime runs out while keep-open is on is
        dropped by the same sweep as any other. "Keep it open" therefore means
        "until the absolute deadline", never "until I say so" — that bound is
        what makes this a bounded relaxation instead of a hole.

        **Why the idle timer was the only one worth suspending.** The idle
        timer is the one that fires in the middle of a task, and it is also the
        one a client ALREADY controls: `get` is use, and use resets it, so a
        caller holding the token could keep a holding alive indefinitely by
        polling. This op is that same power made explicit, registry-gated,
        audited and visible in `status` — strictly less dangerous than the loop
        it replaces, because the loop was silent. The absolute deadline has
        never been client-controllable and is not made so here.

        **What is NOT suspended, and must never be.** Every presence signal
        stays in force: `drop_all` on SIGTERM, on a logind session that locks
        or ends (`Server._check_session`), on a tick gap that says the machine
        was suspended (`Server._check_freeze`), and on the client's own `drop`
        — which is what the page's Lock button, its `pagehide` handler and its
        hidden-tab timer all reach. Those are not timeouts. They are "nobody is
        here", and an agent that ignored them because a toggle was on would be
        holding a safe open for a room with nobody in it. If you are here to
        finish the job by making keep-open suppress those too: that is the
        hazard, not the leftover.

        Turning it OFF resets the idle timer rather than resuming it from a
        `last_used` that may be an hour old. That is exactly what a `get` would
        have done, so it grants nothing new — and the alternative would make
        Off an alias for "lock immediately", which is a control this protocol
        already has and calls `drop`.

        **OFF IS GATED EXACTLY LIKE ON, AND ONLY RESETS WHAT IT REALLY
        RESUMED.** It used to be neither. `{"enabled": false}` skipped
        `_require_keep_open_allowed` entirely and still ran `touch()` on every
        holding this uid had for the named safe — so an ungated, handle-free,
        passphrase-free message reset the idle timer of any held safe,
        including safes the registry had never opted into keep-open at all, and
        a loop of them held any unlock open for its whole absolute lifetime.
        That is the `get`-polling power without `get`'s handle.

        Two changes close it, and both are needed. The registry gate now runs
        for BOTH directions, so the message is refused on a safe that never
        opted in. And the idle timer is reset only for a holding that was
        ACTUALLY suspended — resuming nothing resets nothing, so even inside an
        opted-in safe the off direction cannot be used as a keepalive.
        """
        self.refresh(force=True)
        enabled = req.get("enabled")
        if not isinstance(enabled, bool):
            raise Invalid("enabled is missing or not a boolean")
        if req.get("all") is not None:
            # There is no "keep everything open". A control that suspends the
            # idle timer on every safe at once is the property this project
            # exists to avoid, wearing a convenience's clothes.
            raise Invalid("keep-open names one safe or one handle, never all")

        # BY SAFE, which is the form the page's banner can actually send: the
        # helper that minted the handle exited with its verb, and `health`
        # strips the token before the browser ever sees it. Same scoping rule
        # as `drop`'s by-safe form — this caller's own holdings and no others.
        if req.get("handle") is None:
            safe = _require_safe_id(req.get("safe"))
            self._require_keep_open_allowed(safe, uid)
            mine = [h for h in self.holdings
                    if h.uid == uid and h.safe == safe]
        else:
            token = _require_token(req.get("handle"))
            one = self._find(uid, token)
            # Re-derived here and NOT inherited from the `put` that created
            # the holding: the operator may have revoked the opt-in since,
            # and a gate that only runs once is a gate that runs at the
            # wrong time (I3's rule, one layer down). Both directions, for the
            # reason in the docstring.
            self._require_keep_open_allowed(one.safe, uid)
            safe, mine = one.safe, [one]

        changed = 0
        for h in mine:
            was = h.keep_open
            if was != enabled:
                changed += 1
            h.keep_open = enabled
            # ONLY for a holding that really was suspended. `touch()` on a
            # holding that was never suspended is a free idle window handed out
            # by a message that carries no handle and no passphrase.
            if not enabled and was:
                h.touch()
        # One line per holding, so a by-safe toggle over two holdings is two
        # lines and not one summary somebody has to reconstruct.
        for h in mine:
            audit("keep-open", h.safe, uid, "ok",
                  "enabled" if enabled else "disabled")
        if not mine:
            # A satisfied request that changed nothing, answered the way
            # `drop` answers the same shape: not-found here would say which
            # safes this agent is holding.
            audit("keep-open", safe, uid, "ok", "nothing held")
        soonest = min(mine, key=lambda h: h.expires_in()) if mine else None
        return {"ok": True, "safe": safe, "keep_open": enabled,
                "changed": changed, "affected": len(mine),
                "expires_in": (int(soonest.expires_in())
                               if soonest is not None else None),
                "idle_expires_in": (_maybe_int(soonest.idle_expires_in())
                                    if soonest is not None else None),
                "idle_seconds": (soonest.idle_seconds
                                 if soonest is not None else None),
                "max_seconds": (soonest.max_seconds
                                if soonest is not None else None)}

    def _holding_row(self, h, at=None):
        """One holding as `status` and `keep-open` both describe it."""
        at = now() if at is None else at
        return {"handle": h.token_str(), "safe": h.safe,
                "age": int(at - h.created),
                "keep_open": h.keep_open,
                "expires_in": int(h.expires_in(at)),
                "idle_expires_in": _maybe_int(h.idle_expires_in(at))}

    def op_status(self, uid, req):
        """What this caller is holding, and the agent's own settings.

        **Does not call `touch()`.** The UI polls this to draw the "unlocked,
        N s remaining" banner (docs/OPERATIONS.md), and if looking at the
        countdown reset the countdown the idle timeout would never fire while
        the page was open — the banner would keep alive precisely the thing it
        exists to warn about.

        Lists only the caller's own holdings, for the same reason `_find` gives
        one answer for "unknown" and "not yours": another uid's holdings are not
        this caller's business to enumerate.
        """
        self.refresh()
        at = now()
        mine = [h for h in self.holdings if h.uid == uid]
        return {"ok": True, "pid": os.getpid(), "owner_uid": self.owner_uid,
                "version": VERSION, "clock": CLOCK_NAME,
                "idle_seconds": self.idle_seconds,
                "max_seconds": self.max_seconds,
                "holdings": [self._holding_row(h, at) for h in mine],
                "holdings_total": len(self.holdings),
                # So the state is inspectable without the page: whether this
                # daemon offers keep-open at all, where it looks for the
                # per-safe opt-in, and how many of the caller's holdings are
                # currently running with the idle timer suspended.
                "keep_open": {
                    "available": self.keep_open_available,
                    "registry_dirs": list(self.policy.dirs),
                    "suspended": sum(1 for h in mine if h.keep_open)},
                "socket": dict(self.socket_facts),
                "session": {
                    "watched": bool(self.watcher and self.watcher.enabled),
                    "state": self.watcher.state if self.watcher else None,
                    "poll_seconds": (self.watcher.interval
                                     if self.watcher else None)}}

    def op_policy(self, uid, req):
        """Answer, for the named safes, whether the REGISTRY allows keep-open.

        **THIS OP EXISTS SO THERE IS ONE READER OF THAT REGISTRY KEY.** Before
        it, `secrets-admin` read `agent.allow_keep_open` out of its own loaded
        registry to decide whether to draw the toggle and whether to refuse the
        verb, and this daemon read the same key off the disk for itself. Two
        readers with two loaders, two sets of ownership rules and two shadowing
        rules give two answers, and the operator is shown one and governed by
        the other. The daemon is the authority — it is the process that
        actually refuses — so the helper now ASKS instead of deciding, and
        `RegistryPolicy` is the only code in the project that reads the key.

        It discloses one boolean per id the caller already named, to a peer
        that already passed `SO_PEERCRED`, and it touches no holding: it is the
        policy read, made addressable, and nothing else. It does not say
        whether a safe EXISTS — an id this registry has never heard of and one
        it has heard of and refused both answer `false`, which is the same
        flattening `_find` applies to handles.
        """
        safes = req.get("safes")
        if not isinstance(safes, list) or not safes:
            raise Invalid("policy names a list of safe ids")
        if len(safes) > MAX_POLICY_SAFES:
            raise Invalid("policy names at most %d safe ids"
                          % MAX_POLICY_SAFES)
        out = {}
        for sid in safes:
            out[_require_safe_id(sid)] = bool(
                self.keep_open_available
                and self.policy.allows_keep_open(sid)[0])
        return {"ok": True, "available": self.keep_open_available,
                "keep_open": out}

    OPS = {"put": op_put, "get": op_get, "drop": op_drop,
           "keep-open": op_keep_open, "status": op_status,
           "policy": op_policy}

    def dispatch(self, uid, req):
        op = req.get("op")
        if not isinstance(op, str) or op not in self.OPS:
            raise Invalid("unknown or missing op")
        return self.OPS[op](self, uid, req)


# ===========================================================================
# request field validation — every field, before it is used for anything
# ===========================================================================

def _require_safe_id(value):
    if not isinstance(value, str) or not _SAFE_ID_RE.match(value):
        raise Invalid("safe id is missing or not a valid registry id")
    return value


def _require_token(value, allow_none=False):
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _TOKEN_RE.match(value):
        # Never echo the offending string: it may be someone's live token.
        raise Invalid("handle is missing or not a valid token")
    return value


def _decode_material(value, *, allow_none=False):
    """base64 -> a `Secret`. Returns a Secret the caller must own or zero.

    `allow_none` returns None for an absent field — a TICKET-ONLY holding. See
    `op_put` for why that is the mode `secrets-admin` uses and this one is not.
    An explicit `null` is the same as absent; an empty string is still an
    error, because "" is a caller that meant to send material and sent none.
    """
    if allow_none and value is None:
        return None
    if not isinstance(value, str):
        raise Invalid("material is missing or not a string")
    if len(value) > (MAX_MATERIAL_BYTES * 4) // 3 + 8:
        raise Invalid("material exceeds %d bytes" % MAX_MATERIAL_BYTES)
    try:
        sec = Secret.from_b64(value)     # validates base64, caps at 1 MiB
    except Invalid:
        # Re-worded, not re-raised verbatim: `from_b64` names the helper's
        # `keyfile_b64` field, which is not what the agent's protocol calls
        # this. Never echo the offending text — it is material.
        raise Invalid("material is not valid base64")
    if len(sec) == 0:
        sec.zero()
        raise Invalid("material is empty")
    if len(sec) > MAX_MATERIAL_BYTES:
        sec.zero()
        raise Invalid("material exceeds %d bytes" % MAX_MATERIAL_BYTES)
    return sec


def _maybe_int(value):
    """`int(value)`, or None for None. `idle_expires_in` returns None while the
    idle timer is suspended, and `int(None)` is a TypeError in the one place
    that must not raise."""
    return None if value is None else int(value)


def _clamp_shorter(requested, configured):
    """A client may only shorten the window it is given, never lengthen it.

    A missing or unusable value means "use the configured window". A value
    above it is clamped down rather than refused, so a registry entry written
    against the schema's looser maxima still works and gets the agent's answer
    rather than an error.
    """
    if requested is None:
        return configured
    if isinstance(requested, bool) or not isinstance(requested, int):
        raise Invalid("a timeout field is not an integer")
    if requested < 1:
        raise Invalid("a timeout field is not positive")
    return min(configured, requested)


# ===========================================================================
# socket set-up — socket activation preferred, self-bind as the fallback
# ===========================================================================

def take_listen_fds():
    """Return the sockets systemd passed, or [] when it passed none.

    The contract: `LISTEN_PID` is this pid, `LISTEN_FDS` is a count, and the
    descriptors start at 3. The variables are removed from the environment
    afterwards so a child (`loginctl`) cannot inherit them and think it was
    socket-activated.
    """
    try:
        want_pid = int(os.environ.pop("LISTEN_PID", "0") or 0)
        count = int(os.environ.pop("LISTEN_FDS", "0") or 0)
    except ValueError:
        return []
    os.environ.pop("LISTEN_FDNAMES", None)
    if want_pid != os.getpid() or count <= 0:
        return []
    out = []
    for i in range(count):
        fd = SD_LISTEN_FDS_START + i
        try:
            sock = socket.socket(family=socket.AF_UNIX,
                                 type=socket.SOCK_STREAM, fileno=fd)
        except OSError as exc:
            raise Internal("systemd passed fd %d but it is not usable: %s"
                           % (fd, errno.errorcode.get(exc.errno, exc.errno)))
        if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
            raise Internal("systemd passed a socket that is not an AF_UNIX "
                           "stream socket")
        if not sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
            raise Internal("systemd passed a socket that is not listening")
        sock.setblocking(False)
        out.append(sock)
    return out


def default_run_dir(uid):
    """`$XDG_RUNTIME_DIR/cockpit-secrets`, or `/run/user/<uid>/cockpit-secrets`.

    **Never `/tmp`.** This is a multi-user host (docs/THREAT-MODEL.md A1): a
    predictable path in a world-writable directory is a symlink race against a
    process that holds passphrases. If neither runtime directory exists the
    agent refuses to start rather than inventing somewhere to put a socket.
    """
    base = os.environ.get("XDG_RUNTIME_DIR")
    if not base:
        base = "/run/user/%d" % uid
    if not os.path.isdir(base):
        raise Internal("no per-user runtime directory (%s does not exist); "
                       "start the agent from a logged-in session or pass "
                       "--run-dir" % base)
    return os.path.join(base, "cockpit-secrets")


def bind_socket(run_dir, uid):
    """Self-bind the listening socket: run dir 0700, socket 0600. Returns it.

    Every check here is on the directory rather than on the socket file,
    because the directory is what makes the socket's own mode un-raceable: a
    0700 directory owned by us means nobody else can create, replace or even
    look up a name inside it between our `bind()` and our `stat()`.
    """
    parent = os.path.dirname(run_dir)
    if not os.path.isdir(parent):
        raise Internal("%s does not exist" % parent)
    try:
        os.mkdir(run_dir, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise Internal("cannot create %s: %s"
                       % (run_dir, errno.errorcode.get(exc.errno, exc.errno)))

    # O_NOFOLLOW + fstat on the fd, never a second stat of the path (I5).
    dfd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                  | os.O_CLOEXEC)
    try:
        st = os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode):
            raise Internal("%s is not a directory" % run_dir)
        if st.st_uid != uid:
            raise Internal("%s is owned by uid %d, not %d"
                           % (run_dir, st.st_uid, uid))
        if st.st_mode & 0o077:
            # Repair it once — an mkdir under a loose umask in a previous run
            # is a plausible way to get here, and refusing outright would be
            # unhelpful when the fix is one fchmod on a directory we own.
            os.fchmod(dfd, 0o700)
            st = os.fstat(dfd)
            if st.st_mode & 0o077:
                raise Internal("%s is not 0700 and cannot be made 0700"
                               % run_dir)
    finally:
        os.close(dfd)

    path = os.path.join(run_dir, "agent.sock")
    # Remove a stale socket, but only after proving it IS a socket we own. The
    # 0700 directory means nobody else could have put anything here; this is
    # the belt to that brace, and it refuses to unlink a regular file.
    try:
        old = os.lstat(path)
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != uid:
            raise Internal("%s exists and is not our socket; refusing to "
                           "remove it" % path)
        os.unlink(path)
    except FileNotFoundError:
        pass

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # bind() takes the mode from the umask, and there is no way to pass one.
    # Setting it around the call is how the socket is created 0600 rather than
    # created loose and tightened afterwards, which would be a race.
    old_umask = os.umask(0o177)
    try:
        sock.bind(path)
    finally:
        os.umask(old_umask)
    st = os.lstat(path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(path, 0o600)
    sock.listen(MAX_CONNECTIONS)
    sock.setblocking(False)
    return sock


def socket_facts(sock):
    """Owner and mode of the listening socket, for `status` and the start-up
    line. Reported rather than enforced when systemd created it: refusing an fd
    systemd already handed us would be theatre, but saying what it looks like
    lets an operator see a misconfigured unit."""
    facts = {"path": None, "mode": None, "uid": None, "dir_mode": None,
             "dir_uid": None, "visible": False}
    try:
        path = sock.getsockname()
    except OSError:
        return facts
    if not isinstance(path, str) or not path:
        return facts                      # abstract namespace or unnamed
    facts["path"] = path
    try:
        st = os.lstat(path)
        facts["mode"] = "0%03o" % stat.S_IMODE(st.st_mode)
        facts["uid"] = st.st_uid
        dst = os.stat(os.path.dirname(path))
        facts["dir_mode"] = "0%03o" % stat.S_IMODE(dst.st_mode)
        facts["dir_uid"] = dst.st_uid
        facts["visible"] = True
    except OSError:
        # Expected under the user unit: ProtectHome=yes hides /run/user from
        # this process. `visible` stays False so the caller says "not visible"
        # rather than printing a row of Nones that reads like a failure.
        pass
    return facts


def tighten_socket_dir(sock, uid):
    """Make the directory holding a systemd-created socket 0700 if it is ours.

    MEASURED on this host (systemd 259): `RuntimeDirectoryMode=0700` is honoured
    for a **service** unit and NOT for a **socket** unit — a socket unit's
    `RuntimeDirectory=` lands 0755 whatever the mode says. The units work around
    it with an `ExecStartPost=chmod`, and this is the second half of that belt:
    the agent refuses to be the only thing standing between another local uid
    and its socket just because a unit file was edited. The 0600 socket already
    stops a connect(), but "0700 run dir" is the stated defence (I18) and a
    defence that is only sometimes in force is one nobody can rely on.

    Uses `fchmod` on an `O_NOFOLLOW|O_DIRECTORY` fd, never `chmod` on a path.

    Under the shipped USER unit this is expected to be unable to look: the unit
    sets `ProtectHome=yes`, which makes `/run/user` inaccessible inside the
    service's mount namespace, so the agent cannot reach the directory its own
    socket lives in. That is the sandbox working — the agent needs the inherited
    fd and nothing else — so an EACCES here is reported at note level and the
    0700 guarantee comes from the socket unit's `ExecStartPost=chmod`, which
    runs unsandboxed. The system template's `/run/cockpit-secrets/<uid>` is not
    under `/run/user`, and there this function can and does look.
    """
    try:
        path = sock.getsockname()
    except OSError:
        return
    if not isinstance(path, str) or not path:
        return
    parent = os.path.dirname(path)
    fd = None
    try:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | os.O_CLOEXEC)
        st = os.fstat(fd)
        if st.st_uid != uid or not st.st_mode & 0o077:
            return
        os.fchmod(fd, 0o700)
        _note("tightened %s from 0%03o to 0700 (a socket unit's "
              "RuntimeDirectoryMode is not applied by systemd)"
              % (parent, stat.S_IMODE(st.st_mode)))
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT):
            _note("cannot see %s from inside the sandbox (%s); its mode is the "
                  "socket unit's business, not the agent's"
                  % (parent, errno.errorcode.get(exc.errno, exc.errno)))
        else:
            _note("cannot tighten %s to 0700: %s"
                  % (parent, errno.errorcode.get(exc.errno, exc.errno)))
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def peer_credentials(conn):
    """(pid, uid, gid) from the kernel. The client does not get a say."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    return _UCRED.unpack(raw)


# ===========================================================================
# session watcher — a POLL of logind, and honest about being one
# ===========================================================================

class SessionWatcher:
    """Watches whether the owner still has an unlocked, active login session.

    This is a **poll** (`loginctl show-session`), not a D-Bus subscription to
    the `Lock` signal. Subscribing would need a GLib main loop inside an event
    loop that is already a `selectors` loop, or a long-lived `gdbus monitor`
    child whose human-readable output would have to be parsed; polling a
    property every `SESSION_POLL_SECONDS` is the version whose failure modes are
    obvious. The cost is up to one poll interval of latency between the screen
    locking and the material being dropped, which is stated in the report and in
    agent/README.md rather than glossed.

    `/run/systemd/sessions/<id>` is not parsed even though it is readable: its
    first line says "This is private data. Do not parse." and it carries no
    lock hint anyway.

    States: "unlocked" (at least one active, unlocked session), "locked" (the
    owner has sessions and every one of them is locked or inactive), "none" (no
    sessions at all), "unknown" (logind could not be asked).
    """

    def __init__(self, uid, *, enabled=True,
                 interval=SESSION_POLL_SECONDS, binary="/usr/bin/loginctl"):
        self.uid = uid
        self.enabled = enabled
        self.interval = interval
        self.binary = binary
        self.state = None
        self.available = None       # None = not yet asked
        self._next_poll = 0.0

    def _run(self, args, timeout=5.0):
        try:
            proc = subprocess.run([self.binary] + args, timeout=timeout,
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 \
            else None

    @staticmethod
    def _props(text):
        """Parse `KEY=value` lines.

        `--value` is NOT used with several `-p` flags: systemd prints them in
        its own order, not the order they were asked for, so a positional read
        of the output silently mixes up which answer is which. Measured on this
        host — `-p LockedHint -p Active -p State -p Class --value` printed
        Class, Active, State, LockedHint.
        """
        out = {}
        for line in (text or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                out[key.strip()] = value.strip()
        return out

    def poll(self, force=False):
        """Return the current state, at most once per interval."""
        if not self.enabled:
            return "unknown"
        at = now()
        if not force and at < self._next_poll and self.state is not None:
            return self.state
        self._next_poll = at + self.interval

        text = self._run(["show-user", str(self.uid), "-p", "Sessions"])
        if text is None:
            if self.available is None:
                _note("logind cannot be queried (%s); the lock-on-screen-lock "
                      "defence is NOT in force for this agent"
                      % self.binary)
            self.available = False
            self.state = "unknown"
            return self.state
        self.available = True
        sessions = self._props(text).get("Sessions", "").split()
        if not sessions:
            self.state = "none"
            return self.state
        for sid in sessions[:16]:       # bounded: this string comes from logind
            det = self._run(["show-session", sid, "-p", "LockedHint",
                             "-p", "Active", "-p", "State"])
            if det is None:
                continue                # the session went away between calls
            props = self._props(det)
            if (props.get("LockedHint", "yes") == "no"
                    and props.get("Active", "no") == "yes"):
                self.state = "unlocked"
                return self.state
        self.state = "locked"
        return self.state


# ===========================================================================
# Server — the event loop, the connections, the signals
# ===========================================================================

class Connection:
    """One client, its kernel-supplied identity, and its bounded read buffer."""

    __slots__ = ("sock", "pid", "uid", "gid", "buf", "opened", "closing")

    def __init__(self, sock, pid, uid, gid):
        self.sock = sock
        self.pid, self.uid, self.gid = pid, uid, gid
        self.buf = bytearray()
        self.opened = now()
        self.closing = False


class Server:
    """Owns the listening socket, the connections and the loop."""

    def __init__(self, agent, listeners, watcher, *, tick=TICK_SECONDS):
        self.agent = agent
        self.listeners = listeners
        self.watcher = watcher
        self.tick = tick
        self.sel = selectors.DefaultSelector()
        self.conns = {}
        self.running = True
        self.exit_reason = "stopped"
        self._last_tick = now()
        self._wake_r = self._wake_w = None

    # -- set-up ------------------------------------------------------------

    def install_signals(self):
        """SIGTERM/SIGINT/SIGHUP end the agent; everything held is zeroed first.

        A self-pipe rather than a flag: a signal that arrives while the loop is
        blocked in `select()` must wake it now, not at the next tick, because
        "drop everything on SIGTERM" is a promise about latency as much as about
        behaviour.
        """
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_r, False)
        os.set_blocking(self._wake_w, False)
        signal.set_wakeup_fd(self._wake_w)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self._on_signal)
        # SIGPIPE would kill the agent when a client vanishes mid-reply, and a
        # client that hangs up is normal, not fatal.
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        self.sel.register(self._wake_r, selectors.EVENT_READ, "wake")

    def _on_signal(self, signum, frame):
        self.running = False
        self.exit_reason = signal.Signals(signum).name

    # -- loop --------------------------------------------------------------

    def serve(self):
        for lsock in self.listeners:
            self.sel.register(lsock, selectors.EVENT_READ, "listen")
        try:
            while self.running:
                timeout = self._timeout()
                for key, _events in self.sel.select(timeout):
                    if key.data == "listen":
                        self._accept(key.fileobj)
                    elif key.data == "wake":
                        try:
                            os.read(self._wake_r, 4096)
                        except OSError:
                            pass
                    else:
                        self._readable(key.data)
                self._tick()
        finally:
            n = self.agent.drop_all(self.exit_reason)
            audit("stop", None, self.agent.owner_uid, "ok",
                  "%s, %d holding(s) dropped" % (self.exit_reason, n))
            self._close_all()
        return 0

    def _timeout(self):
        """Sleep no longer than the next thing that must happen."""
        candidates = [self.tick]
        nxt = self.agent.next_deadline()
        if nxt is not None:
            candidates.append(max(0.05, nxt))
        return min(candidates)

    def _tick(self):
        """Expiry, the freeze detector, the session poll, connection reaping."""
        at = now()
        gap = at - self._last_tick
        self._last_tick = at
        self._check_freeze(gap)
        self.agent.refresh(at)
        self._check_session()
        for conn in list(self.conns.values()):
            if not conn.buf and at - conn.opened > CONNECTION_IDLE_SECONDS:
                self._close(conn)

    def _check_freeze(self, gap):
        """A gap much larger than the tick means we were not running.

        Suspend, hibernate, `SIGSTOP`, a cgroup freeze — from inside the process
        they look identical, and all of them mean the agent was holding
        plaintext through a period it could not police. `CLOCK_BOOTTIME` already
        makes the deadlines count that time, so this is not about the arithmetic;
        it is the "lock on suspend" rule, implemented as the one signal that is
        actually observable from here.
        """
        if gap > self.tick + FREEZE_SLACK_SECONDS and self.agent.holdings:
            n = self.agent.drop_all("frozen")
            _note("a %.0f s gap between ticks means this process was suspended "
                  "or stopped; dropped %d holding(s)" % (gap, n))

    def _check_session(self):
        """Drop everything when the owner's session locks, ends, or changes."""
        if not self.watcher.enabled:
            return
        previous = self.watcher.state
        state = self.watcher.poll()
        if state == "unknown":
            return                      # the defence is unavailable; said once
        # Any change is treated as a lock event, including "locked" -> the
        # session coming back: an unlock the agent did not witness is exactly
        # the moment to make the next use cost a passphrase.
        if (state != "unlocked" or (previous is not None
                                    and previous != state)) \
                and self.agent.holdings:
            n = self.agent.drop_all("session-" + state)
            _note("logind session state is %r; dropped %d holding(s)"
                  % (state, n))

    # -- connections -------------------------------------------------------

    def _accept(self, lsock):
        try:
            conn_sock, _ = lsock.accept()
        except OSError:
            return
        try:
            pid, uid, gid = peer_credentials(conn_sock)
        except OSError:
            conn_sock.close()
            return
        if len(self.conns) >= MAX_CONNECTIONS:
            audit("connect", None, uid, "refused", "too many connections")
            _send(conn_sock, {"error": "internal",
                              "detail": "the agent is busy"})
            conn_sock.close()
            return
        if not self.agent.admits(uid):
            # The whole point of the daemon, in four lines: the kernel said who
            # this is, and it is not the uid this agent belongs to.
            audit("connect", None, uid, "denied", "peer uid not admitted")
            _send(conn_sock, {"error": "access-denied",
                              "detail": "this agent does not serve your uid"})
            conn_sock.close()
            return
        conn_sock.setblocking(False)
        conn = Connection(conn_sock, pid, uid, gid)
        self.conns[conn_sock.fileno()] = conn
        self.sel.register(conn_sock, selectors.EVENT_READ, conn)

    def _readable(self, conn):
        try:
            chunk = conn.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._close(conn)
            return
        if not chunk:
            self._close(conn)
            return
        conn.buf += chunk
        if len(conn.buf) > MAX_LINE_BYTES:
            # Cap the line, do not stream: an unbounded buffer is how a client
            # with no secrets at all makes the agent spend the machine.
            _send(conn.sock, {"error": "invalid",
                              "detail": "request line exceeds %d bytes"
                                        % MAX_LINE_BYTES})
            audit("request", None, conn.uid, "invalid", "oversized line")
            self._close(conn)
            return
        while b"\n" in conn.buf:
            line, _, _rest = conn.buf.partition(b"\n")
            del conn.buf[:len(line) + 1]
            try:
                if not self._handle_line(conn, line):
                    return
            finally:
                # The line held base64 material on the way in. `partition`
                # made this copy; wipe it rather than leaving it for the GC.
                if line:
                    line[:] = b"\x00" * len(line)
            if conn.closing:
                return

    def _handle_line(self, conn, line):
        """One request, as the live `bytearray` the caller will wipe.

        Kept as a bytearray rather than converted to `bytes` because `json.loads`
        accepts the buffer directly, and every immutable copy of a line that
        carried material is one more thing nothing can overwrite.

        Returns False when the connection was closed.
        """
        if not line.strip():
            return True
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("not an object")
        except (UnicodeDecodeError, ValueError):
            # A malformed line closes the connection: a client that cannot
            # frame JSON is not a client whose next line should be trusted.
            _send(conn.sock, {"error": "invalid",
                              "detail": "request is not a JSON object"})
            audit("request", None, conn.uid, "invalid", "malformed line")
            self._close(conn)
            return False
        op = req.get("op")
        try:
            reply = self.agent.dispatch(conn.uid, req)
        except SecretsError as exc:
            audit(op if isinstance(op, str) else "?", None, conn.uid,
                  exc.code, exc.detail)
            _send(conn.sock, exc.to_json())
            return True
        except Exception as exc:                            # noqa: BLE001
            # The exception barrier (I15). A traceback here would print locals,
            # and the locals in this file are material.
            audit(op if isinstance(op, str) else "?", None, conn.uid,
                  "internal", type(exc).__name__)
            _send(conn.sock, {"error": "internal",
                              "detail": "the agent could not complete that "
                                        "request"})
            return True
        _send(conn.sock, reply)
        return True

    def _close(self, conn):
        if conn.closing:
            return
        conn.closing = True
        try:
            self.sel.unregister(conn.sock)
        except (KeyError, ValueError, OSError):
            pass
        self.conns.pop(conn.sock.fileno(), None)
        try:
            conn.sock.close()
        except OSError:
            pass
        # Whatever was half-read is dropped in place rather than left for the
        # GC: a partial line can contain base64 material.
        if conn.buf:
            conn.buf[:] = b"\x00" * len(conn.buf)
            del conn.buf[:]

    def _close_all(self):
        for conn in list(self.conns.values()):
            self._close(conn)
        try:
            self.sel.close()
        except Exception:                                   # noqa: BLE001
            pass


def _send(sock, obj):
    """One JSON object, one newline, best effort."""
    try:
        data = (json.dumps(obj, separators=(",", ":"), sort_keys=True)
                + "\n").encode("utf-8")
    except (TypeError, ValueError):
        data = b'{"error":"internal","detail":"unserialisable reply"}\n'
    try:
        sock.sendall(data)
    except OSError:
        pass            # the client hung up; not the agent's problem
    finally:
        # The reply to `get` carries base64 material. The bytes object is
        # immutable and cannot be wiped, but dropping the reference here is
        # still the earliest point it can become garbage.
        del data


# ===========================================================================
# fd hygiene — harden_process cannot do this one for us
# ===========================================================================

def close_extra_fds(keep):
    """Close every descriptor above 2 except the ones in `keep`.

    `harden_process(close_fds=True)` closes everything above 2, which would
    close the listening socket systemd just handed us on fd 3. So the agent
    calls it with `close_fds=False` and does this instead — same intent (an
    inherited fd is both a leak channel and a handle on files this process has
    no business holding), one exception, made explicit.
    """
    closed = 0
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return -1
    for name in names:
        try:
            fd = int(name)
        except ValueError:
            continue
        if fd < 3 or fd in keep:
            continue
        try:
            os.close(fd)
            closed += 1
        except OSError:
            pass                # already gone, or never ours
    return closed


# ===========================================================================
# main
# ===========================================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="secrets-agent",
        description="The opt-in unlock agent for cockpit-secrets (I18). "
                    "Off by default; see agent/README.md before enabling it.")
    p.add_argument("--run-dir", metavar="DIR",
                   help="Directory to self-bind agent.sock in. Created 0700, "
                        "socket 0600. Ignored under systemd socket activation, "
                        "which is the preferred way to run this. Default: "
                        "$XDG_RUNTIME_DIR/cockpit-secrets.")
    p.add_argument("--idle-seconds", type=int, default=DEFAULT_IDLE_SECONDS,
                   metavar="N",
                   help="Idle timeout, reset on every use. Default %d, ceiling "
                        "%d. A client may ask for less, never more."
                        % (DEFAULT_IDLE_SECONDS, IDLE_CEILING_SECONDS))
    p.add_argument("--max-seconds", type=int, default=DEFAULT_MAX_SECONDS,
                   metavar="N",
                   help="Absolute lifetime, never reset by use. Default %d, "
                        "ceiling %d." % (DEFAULT_MAX_SECONDS,
                                         LIFETIME_CEILING_SECONDS))
    p.add_argument("--owner-uid", type=int, default=None, metavar="UID",
                   help="The uid this agent serves. Defaults to its own euid, "
                        "which is the only value that makes SO_PEERCRED an "
                        "identity rather than a broker's signature.")
    p.add_argument("--allow-peer-uid", type=int, action="append", default=[],
                   metavar="UID", dest="allow_peer_uid",
                   help="Additionally admit this uid to the socket. A speaking "
                        "gate ONLY: an admitted uid still cannot read a "
                        "holding another uid created. Use it for the "
                        "admin-class root helper, and read agent/README.md "
                        "first.")
    p.add_argument("--registry-dir", metavar="DIR", action="append",
                   default=[], dest="registry_dir",
                   help="Where to look for the per-safe agent.allow_keep_open "
                        "opt-in. Repeatable; the FIRST directory holding an id "
                        "decides, so name the root-owned one first. Default: "
                        "%s then ~/%s. Nothing else in a registry entry is "
                        "read, and no file in one is ever opened for writing."
                        % (DEFAULT_SYSTEM_REGISTRY,
                           "/".join(USER_REGISTRY_REL)))
    p.add_argument("--no-keep-open", action="store_true",
                   help="Refuse keep-open for every safe, whatever the "
                        "registry says. A ceiling on this daemon, not a "
                        "default a client can lift: keep-open suspends the "
                        "idle timeout, and the idle timeout is what locks a "
                        "safe when the operator walks away.")
    p.add_argument("--no-session-watch", action="store_true",
                   help="Do not poll logind. Turns OFF locking when the screen "
                        "locks or the session ends; say why if you use it.")
    p.add_argument("--session-poll-seconds", type=float,
                   default=SESSION_POLL_SECONDS, metavar="N",
                   help="How often to poll logind (default %.0f)."
                        % SESSION_POLL_SECONDS)
    p.add_argument("--tick-seconds", type=float, default=TICK_SECONDS,
                   metavar="N", help=argparse.SUPPRESS)
    p.add_argument("--allow-root", action="store_true",
                   help="Permit running as euid 0. Almost always wrong: an "
                        "agent that is root serves everyone and identifies "
                        "no one.")
    p.add_argument("--selfcheck", action="store_true",
                   help="Run this file's self-check and exit.")
    p.add_argument("--version", action="version",
                   version="secrets-agent %s" % VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selfcheck:
        return _selfcheck()

    # Socket activation is read FIRST, because the answer decides which fds
    # close_extra_fds() must keep.
    try:
        listeners = take_listen_fds()
    except SecretsError as exc:
        _note(exc.detail)
        return 2

    # I14. close_fds=False on purpose — see close_extra_fds().
    report = harden_process(close_fds=False, quiet=True)
    keep = {s.fileno() for s in listeners}
    close_extra_fds(keep)

    euid = os.geteuid()
    if euid == 0 and not args.allow_root:
        _note("refusing to run as root. The agent must run AS the user whose "
              "material it holds, or SO_PEERCRED reports this process's uid "
              "for every caller and identifies nobody (the peercred-unix-relay "
              "pattern's first gotcha). Use the templated system unit, which "
              "sets User=<uid>.")
        return 2
    owner = args.owner_uid if args.owner_uid is not None else euid

    idle = max(1, min(args.idle_seconds, IDLE_CEILING_SECONDS))
    lifetime = max(1, min(args.max_seconds, LIFETIME_CEILING_SECONDS))
    if lifetime < idle:
        # An absolute lifetime shorter than the idle window is not an error,
        # it just means the idle timer can never fire first. Say so once.
        _note("max_seconds (%d) is below idle_seconds (%d); the absolute "
              "deadline will always fire first" % (lifetime, idle))
    if idle > DEFAULT_IDLE_SECONDS or lifetime > DEFAULT_MAX_SECONDS:
        _note("WARNING: configured window idle=%ds max=%ds is looser than the "
              "documented default of %ds/%ds. idle_seconds is the window in "
              "which someone at an unlocked screen reads the safe without "
              "knowing the passphrase." % (idle, lifetime,
                                           DEFAULT_IDLE_SECONDS,
                                           DEFAULT_MAX_SECONDS))
    if args.allow_peer_uid:
        _note("WARNING: additionally admitting uid(s) %s to the socket. They "
              "can create and read their OWN holdings only."
              % ",".join(str(u) for u in args.allow_peer_uid))

    reg_dirs = args.registry_dir or default_registry_dirs()
    policy = RegistryPolicy(reg_dirs, euid)
    if args.no_keep_open:
        _note("keep-open is disabled on this agent; every request for it will "
              "be refused whatever a registry entry says.")
    agent = Agent(owner, idle_seconds=idle, max_seconds=lifetime,
                  allow_peer_uids=args.allow_peer_uid,
                  keep_open_available=not args.no_keep_open, policy=policy)

    bound_path = None
    if not listeners:
        try:
            run_dir = args.run_dir or default_run_dir(euid)
            listeners = [bind_socket(run_dir, euid)]
            bound_path = listeners[0].getsockname()
        except SecretsError as exc:
            _note(exc.detail)
            return 2
        except OSError as exc:
            _note("cannot bind the agent socket: %s"
                  % errno.errorcode.get(exc.errno, exc.errno))
            return 2

    watcher = SessionWatcher(owner, enabled=not args.no_session_watch,
                             interval=args.session_poll_seconds)
    if watcher.enabled:
        watcher.poll(force=True)
    else:
        _note("WARNING: --no-session-watch: this agent will NOT drop material "
              "when the screen locks or the session ends.")

    tighten_socket_dir(listeners[0], euid)
    facts = socket_facts(listeners[0])
    audit("start", None, owner, "ok",
          "pid=%d activated=%s idle=%d max=%d clock=%s mlockall=%s"
          % (os.getpid(), bound_path is None, idle, lifetime, CLOCK_NAME,
             report.get("mlockall")))
    _note("keep-open %s; registry consulted for agent.allow_keep_open: %s"
          % ("available (per-safe, registry-gated)" if agent.keep_open_available
             else "DISABLED for every safe", ", ".join(reg_dirs) or "nothing"))
    _note("listening on %s (%s), owner uid %d, idle %ds, max %ds, session %s"
          % (facts["path"],
             "socket %s uid %s, dir %s uid %s"
             % (facts["mode"], facts["uid"], facts["dir_mode"],
                facts["dir_uid"]) if facts["visible"]
             else "mode not visible from inside the sandbox",
             owner, idle, lifetime, watcher.state or "unwatched"))
    if facts["mode"] and facts["mode"] != "0600":
        _note("WARNING: the listening socket is %s, not 0600. Only the "
              "SO_PEERCRED check stands between another local uid and this "
              "agent." % facts["mode"])
    if facts["dir_mode"] and facts["dir_mode"] != "0700":
        _note("WARNING: the socket's directory is %s, not 0700."
              % facts["dir_mode"])

    agent.socket_facts = facts
    agent.watcher = watcher
    server = Server(agent, listeners, watcher, tick=args.tick_seconds)
    server.install_signals()
    try:
        return server.serve()
    finally:
        # Only unlink what we created. A systemd-managed socket belongs to
        # systemd and removing it would break the next activation.
        if bound_path:
            try:
                os.unlink(bound_path)
            except OSError:
                pass


# ===========================================================================
# self-check — `python3 agent/secrets_agent.py --selfcheck`
# ===========================================================================

def _selfcheck():                                           # noqa: C901
    """Exercise the load-bearing paths, including the refusals.

    A guard that has never been observed refusing is a guard nobody has tested,
    so every check below that matters is a refusal: another uid's handle, an
    unknown handle, an over-long line, a client trying to lengthen its own
    window, and both deadlines actually firing.

    The one thing this cannot do in-process is present a genuinely different
    kernel uid to a live socket; that test drives the agent from a second uid
    and lives outside this file.
    """
    import shutil
    import tempfile
    import threading

    failures = []
    checks = [0]

    def ok(label, cond):
        checks[0] += 1
        if cond:
            print("  ok    %s" % label)
        else:
            print("  FAIL  %s" % label)
            failures.append(label)

    def raises(label, exc_type, fn):
        checks[0] += 1
        try:
            fn()
        except exc_type as exc:
            print("  ok    %-50s -> %s(%r)"
                  % (label, type(exc).__name__, exc.detail))
            return
        except BaseException as exc:                        # noqa: BLE001
            print("  FAIL  %s -> wrong exception %s: %s"
                  % (label, type(exc).__name__, exc))
            failures.append(label)
            return
        print("  FAIL  %s -> no exception" % label)
        failures.append(label)

    print("cockpit-secrets agent/secrets_agent.py self-check (v%s)" % VERSION)
    me = os.geteuid()
    tok_a = "a" * 32
    tok_b = "b" * 32
    material = base64.b64encode(b"correct-horse-battery-staple").decode()

    # ------------------------------------------------------------ policy --
    print("\n== defaults (I18) ==")
    ok("idle default is 300", DEFAULT_IDLE_SECONDS == 300)
    ok("absolute default is 3600", DEFAULT_MAX_SECONDS == 3600)
    ok("the clock counts suspended time", CLOCK_NAME == "BOOTTIME")

    print("\n== ownership is the uid the kernel reported ==")
    ag = Agent(me)
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    ok("owner can read its own holding",
       ag.op_get(me, {"handle": tok_a})["material"] == material)
    raises("another uid gets access-denied, not not-found", AccessDenied,
           lambda: ag.op_get(me + 1, {"handle": tok_a}))
    raises("an unknown handle gets the SAME access-denied", AccessDenied,
           lambda: ag.op_get(me, {"handle": tok_b}))
    raises("another uid cannot drop it either", AccessDenied,
           lambda: ag.op_drop(me + 1, {"handle": tok_a}))
    ok("status lists only the caller's holdings",
       ag.op_status(me + 1, {})["holdings"] == [])
    ok("status still reports the total", ag.op_status(me + 1, {})
       ["holdings_total"] == 1)
    ok("a foreign uid is not admitted", ag.admits(me + 1) is False)
    ok("the owner is admitted", ag.admits(me) is True)
    ag.drop_all("selfcheck")

    print("\n== the client may only SHORTEN its window ==")
    ag = Agent(me, idle_seconds=100, max_seconds=200)
    r = ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material,
                       "idle_seconds": 9999, "max_seconds": 9999})
    ok("a longer idle request is clamped down", r["idle_seconds"] == 100)
    ok("a longer absolute request is clamped down", r["max_seconds"] == 200)
    r = ag.op_put(me, {"safe": "lab-dc", "handle": tok_b, "material": material,
                       "idle_seconds": 5, "max_seconds": 6})
    ok("a shorter request is honoured", (r["idle_seconds"], r["max_seconds"])
       == (5, 6))
    raises("a non-integer timeout is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "x", "handle": tok_a,
                                  "material": material,
                                  "idle_seconds": "lots"}))
    ag.drop_all("selfcheck")

    print("\n== both deadlines fire, and use extends only one ==")
    ag = Agent(me, idle_seconds=1, max_seconds=60)
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    h = ag.holdings[0]
    h.last_used -= 2.0                       # simulate 2 s of idleness
    ok("the idle deadline is in the past", h.expired())
    ok("sweep() drops it", ag.sweep() == 1 and not ag.holdings)

    ag = Agent(me, idle_seconds=60, max_seconds=1)
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    h = ag.holdings[0]
    ag.op_get(me, {"handle": tok_a})         # use it: idle resets...
    h.created -= 2.0                         # ...but the absolute one does not
    ok("use does not extend the absolute deadline", h.expired())
    ok("the audit reason is 'absolute'", h.why_expired() == "absolute")

    print("\n== re-put cannot ride one unlock past the cap ==")
    ag = Agent(me, idle_seconds=60, max_seconds=60)
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    born = ag.holdings[0].created
    ag.holdings[0].created -= 30.0
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    ok("re-putting the same token keeps the original birth time",
       ag.holdings[0].created < born)
    ok("and does not add a second holding", len(ag.holdings) == 1)
    ag.drop_all("selfcheck")

    print("\n== material is zeroed, never echoed ==")
    ag = Agent(me)
    ag.op_put(me, {"safe": "lab-dc", "handle": tok_a, "material": material})
    h = ag.holdings[0]
    buf = h.material.bytes                   # the LIVE buffer, deliberately
    ok("the holding has the material", len(buf) > 0)
    ok("repr() never shows material", "horse" not in repr(h))
    ag.drop_all("selfcheck")
    ok("drop_all zeroed the buffer in place", len(buf) == 0)
    ok("and the token buffer too", h.token_str() == "")

    print("\n== field validation ==")
    ag = Agent(me)
    raises("a bad safe id is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "../etc/shadow", "handle": tok_a,
                                  "material": material}))
    raises("a bad token is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "x", "handle": "nothex",
                                  "material": material}))
    raises("non-base64 material is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "x", "handle": tok_a,
                                  "material": "not base64!!"}))
    raises("empty material is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "x", "handle": tok_a,
                                  "material": ""}))
    raises("an unknown op is refused", Invalid,
           lambda: ag.dispatch(me, {"op": "exfiltrate"}))
    raises("a missing op is refused", Invalid, lambda: ag.dispatch(me, {}))
    ok("a minted token is accepted when none is offered",
       len(ag.op_put(me, {"safe": "x", "material": material})["handle"]) == 32)
    ag.drop_all("selfcheck")

    # The reconciliation with `secrets-admin`: see op_put's docstring. These
    # are the three shapes the shipped helper actually sends, none of which the
    # first draft of this daemon accepted.
    print("\n== ticket-only holdings, the mode secrets-admin uses ==")
    ag = Agent(me)
    # Exactly what `secrets-admin`'s `new_session()` mints: 22 base64url
    # characters carrying 128 bits, complete with the two characters a hex-only
    # class rejected. Written out rather than generated so a regression names
    # the alphabet that broke.
    urlsafe = "Vg-3xK_pQ7ZtLm4Nb1RsCw"
    put = ag.op_put(me, {"safe": "lab-dc", "handle": urlsafe})
    ok("a base64url handle is accepted", put["handle"] == urlsafe)
    ok("put with no material reports material_held false",
       put["material_held"] is False)
    got = ag.op_get(me, {"handle": urlsafe})
    ok("get on a ticket carries NO material key", "material" not in got)
    ok("get on a ticket says material_held false",
       got["material_held"] is False)
    ok("a ticket still carries both deadlines",
       got["expires_in"] > 0 and got["idle_expires_in"] > 0)
    ok("the holding really holds nothing",
       ag.holdings[0].material is None)
    raises("an explicitly empty material is still refused", Invalid,
           lambda: ag.op_put(me, {"safe": "x", "handle": tok_b,
                                  "material": ""}))
    # A material put over a ticket, and a ticket put over material: both are
    # legal, and the downgrade must actually zero what it replaced.
    ag.op_put(me, {"safe": "lab-dc", "handle": urlsafe, "material": material})
    ok("material can be added to an existing ticket",
       ag.holdings[0].material is not None)
    sec = ag.holdings[0].material
    ag.op_put(me, {"safe": "lab-dc", "handle": urlsafe})
    ok("a ticket re-put downgrades the holding",
       ag.holdings[0].material is None)
    ok("the replaced material was zeroed", len(sec) == 0)
    ag.drop_all("selfcheck")

    # ------------------------------------------------------- keep-open ----
    #
    # Every check here is a refusal or a bound. The one permissive case exists
    # so the refusals are known to be refusals and not a feature that never
    # works: a gate that has never been seen letting anything through is a
    # gate nobody has tested either.
    print("\n== keep-open is REFUSED unless the registry opts the safe in ==")
    reg = tempfile.mkdtemp(prefix="secrets-agent-registry.")
    try:
        def write_entry(name, sid, enabled, allow):
            cfg = {"enabled": enabled, "idle_seconds": 300,
                   "max_seconds": 3600}
            if allow is not None:
                cfg["allow_keep_open"] = allow
            body = {"id": sid, "label": sid, "format": "kdbx",
                    "path": "/nonexistent/%s.kdbx" % sid, "agent": cfg}
            path = os.path.join(reg, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(body, fh)
            os.chmod(path, 0o600)

        write_entry("10-opted-in.json", "keeper", True, True)
        write_entry("20-plain.json", "plain", True, False)
        write_entry("30-absent.json", "silent", True, None)
        write_entry("40-agent-off.json", "agentless", False, True)
        os.chmod(reg, 0o700)
        policy = RegistryPolicy([reg], me)

        ok("an opted-in safe is allowed",
           policy.allows_keep_open("keeper")[0] is True)
        ok("allow_keep_open:false is refused",
           policy.allows_keep_open("plain")[0] is False)
        ok("an absent allow_keep_open is refused",
           policy.allows_keep_open("silent")[0] is False)
        ok("allow_keep_open without agent.enabled is refused",
           policy.allows_keep_open("agentless")[0] is False)
        ok("a safe with no entry at all is refused",
           policy.allows_keep_open("never-registered")[0] is False)
        ok("...and the reason names no path",
           reg not in policy.allows_keep_open("never-registered")[1])
        ok("an agent with no registry refuses everything",
           RegistryPolicy([], me).allows_keep_open("keeper")[0] is False)

        ag = Agent(me, idle_seconds=60, max_seconds=600, policy=policy)
        raises("put with keep_open on a safe that did not opt in",
               AccessDenied,
               lambda: ag.op_put(me, {"safe": "plain", "handle": tok_a,
                                      "keep_open": True}))
        ok("...and nothing was held as a consolation prize",
           not ag.holdings)
        raises("a non-boolean keep_open is invalid, not access-denied", Invalid,
               lambda: ag.op_put(me, {"safe": "keeper", "handle": tok_a,
                                      "keep_open": "yes"}))

        put = ag.op_put(me, {"safe": "keeper", "handle": tok_a,
                             "keep_open": True})
        ok("put with keep_open on an opted-in safe is accepted",
           put["keep_open"] is True)
        ok("...and put still reports the ABSOLUTE lifetime",
           put["max_seconds"] == 600)

        print("\n== keep-open suspends the IDLE timer and NOTHING else ==")
        h = ag.holdings[0]
        h.last_used -= 10000.0              # an hour past any idle deadline
        ok("the idle deadline is long gone and the holding lives",
           not h.expired() and ag.sweep() == 0)
        ok("idle_expires_in is None, not a big number",
           h.idle_expires_in() is None)
        ok("get reports it as None over the wire",
           ag.op_get(me, {"handle": tok_a})["idle_expires_in"] is None)
        ok("...and says the holding is suspended",
           ag.op_get(me, {"handle": tok_a})["keep_open"] is True)
        row = ag.op_status(me, {})["holdings"][0]
        ok("status reports keep_open per holding", row["keep_open"] is True)
        ok("...and counts the suspended ones",
           ag.op_status(me, {})["keep_open"]["suspended"] == 1)

        # THE BOUND. The absolute deadline is the reason this is a relaxation
        # and not a hole, so it is checked from both sides: it still fires,
        # and no client can push it out.
        h.created -= 10000.0
        ok("the ABSOLUTE deadline still fires under keep-open", h.expired())
        ok("...and the audit reason is 'absolute'",
           h.why_expired() == "absolute")
        ok("...and sweep really drops it", ag.sweep() == 1 and not ag.holdings)

        put = ag.op_put(me, {"safe": "keeper", "handle": tok_a,
                             "keep_open": True, "max_seconds": 999999})
        ok("a client asking for a longer lifetime is still clamped",
           put["max_seconds"] == 600)
        born = ag.holdings[0].created
        ag.holdings[0].created -= 300.0
        ag.op_put(me, {"safe": "keeper", "handle": tok_a, "keep_open": True})
        ok("re-putting under keep-open keeps the original birth time",
           ag.holdings[0].created < born)
        ok("a re-put with no keep_open key leaves the suspension alone",
           ag.op_put(me, {"safe": "keeper", "handle": tok_a})["keep_open"]
           is True)

        print("\n== the keep-open op: ownership, the toggle, and the refusals ==")
        raises("another uid cannot turn it on", AccessDenied,
               lambda: ag.op_keep_open(me + 1, {"handle": tok_a,
                                                "enabled": True}))
        raises("...nor off", AccessDenied,
               lambda: ag.op_keep_open(me + 1, {"handle": tok_a,
                                                "enabled": False}))
        raises("an unknown handle is the SAME access-denied", AccessDenied,
               lambda: ag.op_keep_open(me, {"handle": tok_b,
                                            "enabled": True}))
        raises("a missing 'enabled' is invalid", Invalid,
               lambda: ag.op_keep_open(me, {"handle": tok_a}))
        off = ag.op_keep_open(me, {"handle": tok_a, "enabled": False})
        ok("turning it off resumes the idle timer from now",
           off["keep_open"] is False and off["idle_expires_in"] > 0)
        ok("...and says it changed something", off["changed"] == 1)
        ok("turning it off twice changes nothing",
           ag.op_keep_open(me, {"handle": tok_a,
                                "enabled": False})["changed"] == 0)
        on = ag.op_keep_open(me, {"handle": tok_a, "enabled": True})
        ok("turning it back on suspends the idle timer again",
           on["keep_open"] is True and on["idle_expires_in"] is None)
        ok("...and never reports a longer absolute lifetime than the cap",
           on["expires_in"] <= 600)

        # THE FORM THE BANNER SENDS: a safe id and no handle, because the
        # helper that minted the token exited with its verb.
        raises("a by-safe keep-open on a safe that did not opt in is refused",
               AccessDenied,
               lambda: ag.op_keep_open(me, {"safe": "plain",
                                            "enabled": True}))
        bysafe = ag.op_keep_open(me, {"safe": "keeper", "enabled": False})
        ok("a by-safe keep-open reaches the holding with no handle",
           bysafe["affected"] == 1 and bysafe["keep_open"] is False)
        ok("...and another uid's by-safe keep-open touches nothing",
           ag.op_keep_open(me + 1, {"safe": "keeper",
                                    "enabled": False})["affected"] == 0
           and len(ag.holdings) == 1)
        ok("a by-safe keep-open for a safe that is not held is 0, not "
           "not-found",
           ag.op_keep_open(me, {"safe": "keeper",
                                "enabled": False})["affected"] == 1)
        raises("there is no keep-everything-open form", Invalid,
               lambda: ag.op_keep_open(me, {"all": True, "enabled": True}))
        ag.drop_all("selfcheck")

        # A holding created BEFORE the opt-in was withdrawn must not keep the
        # permission it was born with: the gate is re-derived on every verb
        # (I3), including this one.
        ag.op_put(me, {"safe": "plain", "handle": tok_a})
        raises("keep-open on an existing holding for a safe that never opted "
               "in is refused", AccessDenied,
               lambda: ag.op_keep_open(me, {"handle": tok_a,
                                            "enabled": True}))
        ag.drop_all("selfcheck")

        # ==================================================================
        # REGRESSION: THE THREE-MESSAGE RELABEL BYPASS OF THE REGISTRY GATE
        #
        # `op_put` used to evaluate the gate against the safe id in the
        # REQUEST, while `existing` was found by HANDLE — so a re-put could
        # relabel a holding onto another safe, and the "absent keep_open means
        # leave it as it is" rule then carried the suspension onto a safe the
        # registry refuses. Three messages, no passphrase, no new handle:
        #
        #   put {safe: plain}                       -> a handle on a DENIED safe
        #   put {handle, safe: keeper, keep_open}   -> gated on the ALLOWED id
        #   put {handle, safe: plain}               -> the suspension rides back
        #
        # Revert the gate in `op_put` to `if keep is True:` on `safe` and the
        # last `ok()` below fails: the holding comes back labelled `plain`
        # with `keep_open` true, and the skeptic's measurement — alive twelve
        # seconds into a five-second idle window — follows from it.
        # ==================================================================
        print("\n== keep-open cannot be relabelled onto a refused safe ==")
        ag.drop_all("selfcheck")
        ag.op_put(me, {"safe": "plain", "handle": tok_a})
        ag.op_put(me, {"safe": "keeper", "handle": tok_a, "keep_open": True})
        ok("a relabel onto an allowed safe may suspend",
           ag.holdings[0].keep_open is True
           and ag.holdings[0].safe == "keeper")
        raises("...and the relabel BACK onto a refused safe is refused, "
               "even though the request carries no keep_open at all",
               AccessDenied,
               lambda: ag.op_put(me, {"safe": "plain", "handle": tok_a}))
        ok("...leaving the holding on the safe that was allowed to suspend it",
           len(ag.holdings) == 1 and ag.holdings[0].safe == "keeper"
           and ag.holdings[0].keep_open is True)
        # The same, one message shorter: a first `put` naming the denied safe
        # with the flag set was already refused, and still is.
        ag.drop_all("selfcheck")
        raises("a direct put of keep_open onto a refused safe is still refused",
               AccessDenied,
               lambda: ag.op_put(me, {"safe": "plain", "handle": tok_a,
                                      "keep_open": True}))

        # ==================================================================
        # REGRESSION: `{"enabled": false}` WAS AN UNGATED IDLE-TIMER RESET
        #
        # No registry opt-in, no handle, no passphrase — and it ran `touch()`
        # on every holding this uid had for the named safe. Two guarantees
        # replace it, and each has its own check: the gate refuses the message
        # on a safe that never opted in, and even where it IS allowed the
        # reset only happens for a holding that was really suspended.
        #
        # Revert either half — drop the `self._require_keep_open_allowed` call
        # from the by-safe branch, or change `if not enabled and was:` back to
        # `if not enabled:` — and the matching check below fails.
        # ==================================================================
        print("\n== the OFF direction is gated, and resets nothing it did "
              "not resume ==")
        ag.drop_all("selfcheck")
        ag.op_put(me, {"safe": "plain", "handle": tok_a})
        raises("off is refused on a safe that never opted in — by safe id",
               AccessDenied,
               lambda: ag.op_keep_open(me, {"safe": "plain",
                                            "enabled": False}))
        raises("...and by handle", AccessDenied,
               lambda: ag.op_keep_open(me, {"handle": tok_a,
                                            "enabled": False}))
        stale = ag.holdings[0]
        stale.last_used -= 30.0
        was_last_used = stale.last_used
        ok("...and the refused message moved no idle deadline",
           ag.holdings[0].last_used == was_last_used)

        ag.drop_all("selfcheck")
        ag.op_put(me, {"safe": "keeper", "handle": tok_a})   # NOT suspended
        ag.holdings[0].last_used -= 30.0
        before = ag.holdings[0].last_used
        off = ag.op_keep_open(me, {"safe": "keeper", "enabled": False})
        ok("off on an allowed-but-unsuspended holding changes nothing",
           off["changed"] == 0 and off["affected"] == 1)
        ok("...and does NOT reset its idle timer",
           ag.holdings[0].last_used == before)
        ag.op_keep_open(me, {"safe": "keeper", "enabled": True})
        ag.holdings[0].last_used -= 30.0
        off = ag.op_keep_open(me, {"safe": "keeper", "enabled": False})
        ok("off on a holding that really was suspended resumes it",
           off["changed"] == 1 and off["keep_open"] is False)
        ok("...and DOES reset the idle timer it just re-imposed",
           ag.holdings[0].last_used > before)

        # ==================================================================
        # REGRESSION: REVOKING THE OPT-IN MUST REACH A LIVE SUSPENSION
        #
        # The gate used to run only when a request asked for something, so a
        # holding suspended before the operator edited their registry kept the
        # suspension for the rest of its absolute lifetime. Delete the
        # `reconcile_keep_open` call from `sweep` and the two checks below
        # fail: the holding stays suspended and stays alive.
        # ==================================================================
        print("\n== revoking allow_keep_open ends a LIVE suspension ==")
        ag.drop_all("selfcheck")
        ag.policy_recheck = 0.0
        ag.op_put(me, {"safe": "keeper", "handle": tok_a, "keep_open": True})
        ag.holdings[0].last_used -= 10000.0        # far past any idle deadline
        ok("it is suspended and alive with its idle deadline long gone",
           ag.holdings[0].keep_open is True and not ag.holdings[0].expired())
        write_entry("10-opted-in.json", "keeper", True, False)   # revoked
        ag.refresh(force=True)
        ok("the withdrawn opt-in ended the suspension and the idle timer that "
           "came back took the holding with it", not ag.holdings)
        write_entry("10-opted-in.json", "keeper", True, True)    # restored

        # A holding that is actually being USED survives the same revocation:
        # the idle timer is re-imposed, not fired.
        ag.op_put(me, {"safe": "keeper", "handle": tok_a, "keep_open": True})
        write_entry("10-opted-in.json", "keeper", True, False)
        ag.refresh(force=True)
        ok("a freshly used holding survives the revocation, with its idle "
           "timer running again",
           len(ag.holdings) == 1 and ag.holdings[0].keep_open is False
           and isinstance(ag.holdings[0].idle_expires_in(), float))
        write_entry("10-opted-in.json", "keeper", True, True)
        ag.drop_all("selfcheck")
        ag.policy_recheck = POLICY_RECHECK_SECONDS

        # ==================================================================
        # ONE READER. `policy` is how `secrets-admin` stops reading
        # `agent.allow_keep_open` for itself and asks the process that
        # actually refuses.
        # ==================================================================
        print("\n== the policy op: one reader for allow_keep_open ==")
        pol = ag.op_policy(me, {"safes": ["keeper", "plain", "silent",
                                          "never-registered"]})
        ok("it answers the same verdicts RegistryPolicy gives",
           pol["keep_open"] == {"keeper": True, "plain": False,
                                "silent": False, "never-registered": False})
        ok("...and says whether this daemon offers the feature at all",
           pol["available"] is True)
        ok("a --no-keep-open daemon answers false for an opted-in safe",
           Agent(me, policy=policy, keep_open_available=False)
           .op_policy(me, {"safes": ["keeper"]})["keep_open"]["keeper"]
           is False)
        raises("policy names a list, not a safe", Invalid,
               lambda: ag.op_policy(me, {"safe": "keeper"}))
        raises("...and the list is bounded", Invalid,
               lambda: ag.op_policy(me, {"safes": ["keeper"]
                                         * (MAX_POLICY_SAFES + 1)}))
        ok("policy holds nothing and drops nothing", not ag.holdings)

        print("\n== --no-keep-open is a ceiling no registry can lift ==")
        deaf = Agent(me, policy=policy, keep_open_available=False)
        raises("put with keep_open is refused", AccessDenied,
               lambda: deaf.op_put(me, {"safe": "keeper", "handle": tok_a,
                                        "keep_open": True}))
        deaf.op_put(me, {"safe": "keeper", "handle": tok_a})
        raises("...and so is the op", AccessDenied,
               lambda: deaf.op_keep_open(me, {"handle": tok_a,
                                              "enabled": True}))
        ok("status says the daemon does not offer it",
           deaf.op_status(me, {})["keep_open"]["available"] is False)
        # THE CONTRACT CHANGED HERE, DELIBERATELY. Off used to be ungated —
        # "it only ever reduces privilege, so let it through" — and that made
        # it an ungated, handle-free idle-timer RESET on any held safe,
        # including safes no registry ever opted in. It is now refused by the
        # same gate as On. Nothing is lost: on this daemon nothing can be
        # suspended in the first place, and `reconcile_keep_open` is what ends
        # a suspension the policy stops allowing — not the client.
        raises("turning it OFF is refused by the same ceiling", AccessDenied,
               lambda: deaf.op_keep_open(me, {"handle": tok_a,
                                              "enabled": False}))
        ok("...and nothing was suspended for it to have resumed",
           deaf.op_status(me, {})["keep_open"]["suspended"] == 0)
        deaf.drop_all("selfcheck")

        print("\n== a registry file another uid could write is not read ==")
        loose = os.path.join(reg, "50-loose.json")
        write_entry("50-loose.json", "loose", True, True)
        os.chmod(loose, 0o666)
        ok("a group/world-writable entry grants nothing",
           policy.allows_keep_open("loose")[0] is False)
        os.chmod(loose, 0o600)
        ok("...and the same file at 0600 does",
           policy.allows_keep_open("loose")[0] is True)
        with open(os.path.join(reg, "60-broken.json"), "w") as fh:
            fh.write("{not json")
        os.chmod(os.path.join(reg, "60-broken.json"), 0o600)
        ok("an unparsable file does not stop the readable ones",
           policy.allows_keep_open("keeper")[0] is True)
    finally:
        shutil.rmtree(reg, ignore_errors=True)

    print("\n== drop by safe, which is what `lock` sends ==")
    ag = Agent(me)
    ag.op_put(me, {"safe": "lab-dc", "handle": "a" * 32})
    ag.op_put(me, {"safe": "lab-dc", "handle": "b" * 32})
    ag.op_put(me, {"safe": "other", "handle": "c" * 32})
    ok("drop by safe takes every holding for that safe",
       ag.op_drop(me, {"safe": "lab-dc"})["dropped"] == 2)
    ok("and leaves the others alone",
       len(ag.holdings) == 1 and ag.holdings[0].safe == "other")
    ok("dropping a safe that is not held is 0, not not-found",
       ag.op_drop(me, {"safe": "never-held"})["dropped"] == 0)
    ok("another uid's by-safe drop takes nothing",
       ag.op_drop(me + 1, {"safe": "other"})["dropped"] == 0
       and len(ag.holdings) == 1)
    raises("a bad safe id in a by-safe drop is refused", Invalid,
           lambda: ag.op_drop(me, {"safe": "../etc"}))
    ag.drop_all("selfcheck")

    print("\n== the holdings cap ==")
    ag = Agent(me)
    for i in range(MAX_HOLDINGS):
        ag.op_put(me, {"safe": "s%d" % i, "handle": "%032x" % i,
                       "material": material})
    raises("one past the cap is refused", Invalid,
           lambda: ag.op_put(me, {"safe": "over", "handle": "f" * 32,
                                  "material": material}))
    ok("nothing was dropped to make room", len(ag.holdings) == MAX_HOLDINGS)
    ag.drop_all("selfcheck")

    print("\n== loginctl property parsing ==")
    w = SessionWatcher(me, enabled=False)
    props = w._props("LockedHint=no\nActive=yes\nState=active\n")
    ok("KEY=value lines parse", props == {"LockedHint": "no", "Active": "yes",
                                          "State": "active"})
    ok("a disabled watcher reports unknown", w.poll() == "unknown")

    # ------------------------------------------------------- live socket --
    print("\n== a real socket, self-bound ==")
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    tmpdir = tempfile.mkdtemp(prefix="secrets-agent-selfcheck.", dir=base)
    try:
        run_dir = os.path.join(tmpdir, "run")
        lsock = bind_socket(run_dir, me)
        try:
            st = os.lstat(lsock.getsockname())
            dst = os.stat(run_dir)
            ok("the run dir is 0700", stat.S_IMODE(dst.st_mode) == 0o700)
            ok("the socket is 0600", stat.S_IMODE(st.st_mode) == 0o600)
            ok("the socket is ours", st.st_uid == me)

            ag = Agent(me, idle_seconds=30, max_seconds=30)
            srv = Server(ag, [lsock], SessionWatcher(me, enabled=False),
                         tick=0.2)
            srv.install_signals()
            thread = threading.Thread(target=srv.serve, daemon=True)
            thread.start()

            replies = _talk(lsock.getsockname(), [
                {"op": "put", "safe": "lab-dc", "handle": tok_a,
                 "material": material},
                {"op": "status"},
                {"op": "get", "handle": tok_a},
                {"op": "drop", "handle": tok_a},
                {"op": "get", "handle": tok_a},
            ])
            ok("put over the wire", replies[0].get("ok") is True)
            ok("status shows one holding",
               len(replies[1].get("holdings", [])) == 1)
            ok("get returns the material",
               replies[2].get("material") == material)
            ok("drop reports one", replies[3].get("dropped") == 1)
            ok("get after drop is access-denied",
               replies[4].get("error") == "access-denied")

            bad = _talk_raw(lsock.getsockname(), b"{not json}\n" + b"x" * 10)
            ok("a malformed line is answered 'invalid'",
               bad and bad[0].get("error") == "invalid")

            srv.running = False
            srv.exit_reason = "selfcheck"
            thread.join(timeout=5)
            ok("the server stopped", not thread.is_alive())
        finally:
            try:
                lsock.close()
            except OSError:
                pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n%d checks, %d failure(s)" % (checks[0], len(failures)))
    for f in failures:
        print("  FAILED: %s" % f)
    return 1 if failures else 0


def _talk(path, requests):
    """Send each request, read one reply per request. Self-check helper."""
    out = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        buf = b""
        for req in requests:
            s.sendall((json.dumps(req) + "\n").encode())
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            line, _, buf = buf.partition(b"\n")
            out.append(json.loads(line) if line else {})
    return out


def _talk_raw(path, blob):
    """Send raw bytes and read whatever comes back. Self-check helper."""
    out = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(blob)
        buf = b""
        try:
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            return out
        for line in buf.split(b"\n"):
            if line.strip():
                out.append(json.loads(line))
    return out


if __name__ == "__main__":
    sys.exit(main())
