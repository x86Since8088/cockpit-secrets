"""backends — format adapters for cockpit-secrets.

    base.py     the shared foundation: error taxonomy, Secret, process
                hardening, the O_NOFOLLOW file guard, the atomic write, the
                lock-file conventions, the Limits clamps, and the Backend ABC
    kdbx.py     KeePass KDBX 3.x/4.x via pykeepass  (Task 3)
    psafe3.py   Password Safe v3, implemented from formatV3.txt  (Task 4)

Everything a backend or the helper needs from the foundation is re-exported
here, so `from backends import Secret, BadCredential, open_safe_fd` works and
`secrets-admin` never has to reach past this package boundary.

Backends are imported LAZILY by `secrets-admin`, not here: a psafe3 unlock must
not drag in the KDBX XML stack and a kdbx unlock must not drag in Botan. A format
whose module is missing or fails to import is reported as `unsupported` by
`backend_for()`, never as a traceback.

(The XML library is deliberately not named in this package's shared files, and
neither is the parser flag that hardens it. `validate.sh` implements the I8 ban
as two greps over `backends/`: if the library's name appears anywhere in the
tree, the hardening flag must appear too. Both are string matches, so a mention
in prose here would satisfy the second grep on behalf of a backend that had not
actually set it. The ban has to fire on a real use; keeping both tokens out of
the shared files is what keeps it able to.)

Licence: GPL-3.0 — forced by linking pykeepass. See ../LICENSE.
"""

from .base import (                                          # noqa: F401
    # error taxonomy (docs/CONTRACT.md)
    SecretsError, AccessDenied, NotFound, LockedOut, BadCredential,
    Conflict, Unsupported, Invalid, Internal, ERROR_CODES, ERROR_CLASSES,
    # secret handling
    Secret, constant_time_eq, redact, REDACT_MIN_LEN, REDACTED,
    # process and file primitives
    harden_process, open_safe_fd, SafeFile, Fingerprint,
    atomic_replace, LockFile,
    # policy clamps
    Limits,
    # the adapter interface
    Backend, register_backend, backend_for, known_formats,
    VERSION,
)

__all__ = [
    "SecretsError", "AccessDenied", "NotFound", "LockedOut", "BadCredential",
    "Conflict", "Unsupported", "Invalid", "Internal",
    "ERROR_CODES", "ERROR_CLASSES",
    "Secret", "constant_time_eq", "redact", "REDACT_MIN_LEN", "REDACTED",
    "harden_process", "open_safe_fd", "SafeFile", "Fingerprint",
    "atomic_replace", "LockFile",
    "Limits",
    "Backend", "register_backend", "backend_for", "known_formats",
    "VERSION",
]
