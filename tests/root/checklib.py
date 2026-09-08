"""Shared plumbing for the tests/root Python drivers.

These drivers speak to the INSTALLED `/usr/local/sbin/secrets-admin` over its
real interface: a JSON request object on the child's stdin, one JSON object per
reply on its stdout (docs/CONTRACT.md). Nothing here stubs a backend, imports
the helper, or reaches into its internals — the point of this directory is to
prove behaviour of the thing that is actually installed, as the identity the
kernel actually reports.

Two rules that are not negotiable in here, both because these drivers run
inside a job whose `output.log` is group-readable by `users` (I15):

  * `scrub()` runs over everything printed. A reply carrying a revealed
    password, a keyfile, an attachment or an export is printed with those keys
    replaced by a type-and-length placeholder. A check asserts a value; it
    never displays one.
  * the passphrase is read from its 0600 file by `read_passphrase()` and put
    ONLY on the helper's stdin. It is never an argument, never an environment
    variable, never printed. That is the same rule the program itself keeps
    (I10), applied to its test harness, because a harness that leaks the
    passphrase has disproved the property it was measuring.
"""
import json
import os
import subprocess
import sys

#: Where the installed helper lives. Overridable so a script can point at a
#: staged copy, but every job in this directory uses the installed path on
#: purpose: that is the artefact under test.
HELPER = os.environ.get("CS_HELPER", "/usr/local/sbin/secrets-admin")

#: Keys whose VALUE is a secret or a payload, at any depth. Compared
#: case-insensitively against the whole key name; a substring rule would be
#: cleverer and would also redact `password_required`, which is policy and is
#: exactly the sort of thing a reader of this log needs to see.
SECRET_KEYS = frozenset((
    "password", "passphrase", "value", "keyfile_b64", "data_b64", "b64",
    "secret", "material", "code", "yubikey_response",
))


def scrub(obj):
    """Return `obj` with every secret-valued key replaced by a placeholder.

    Recursive, and applied at print time rather than at construction time, so a
    reply shape that grows a new payload key still has to be added to
    SECRET_KEYS deliberately — but a *nested* one is caught today.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SECRET_KEYS and v is not None:
                out[k] = "<redacted %s len=%d>" % (
                    type(v).__name__, len(v) if hasattr(v, "__len__") else 0)
            else:
                out[k] = scrub(v)
        return out
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def brief(obj, limit=200):
    """One short line for the report's `extra` column, always scrubbed."""
    return json.dumps(scrub(obj), sort_keys=True)[:limit]


def read_passphrase(path):
    """Read the throwaway passphrase from its 0600 tmpfs file, refusing a file
    whose mode drifted.

    The mode check is not ceremony. Every claim this suite makes about not
    leaking the passphrase rests on that file being unreadable to anyone but
    root, so a 0644 file must stop the run rather than quietly produce a green
    report that means nothing.
    """
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise SystemExit("%s is mode 0%o; refusing to use a passphrase file "
                         "that is not 0600" % (path, st.st_mode & 0o777))
    with open(path, "r") as fh:
        return fh.read().rstrip("\n")


class Report:
    """One line per check, a count at the end, exit 0 or 1 — the shape
    backends/base.py's self-check set and tests/integration reuses."""

    def __init__(self, title):
        self.title = title
        self.failures = []
        self.count = 0
        print("== %s ==" % title)

    def check(self, name, cond, extra=""):
        self.count += 1
        print("  %-4s %s%s"
              % ("ok" if cond else "FAIL", name,
                 ("  -> " + str(extra)[:220]) if extra else ""))
        if not cond:
            self.failures.append(name)
        return bool(cond)

    def note(self, text):
        print("     %s" % str(text)[:220])

    def section(self, name):
        print("\n-- %s --" % name)

    def finish(self):
        print("\n%d checks, %d failure(s)%s"
              % (self.count, len(self.failures),
                 (": " + ", ".join(self.failures)) if self.failures else ""))
        return 1 if self.failures else 0


def run(verb, req=None, argv=(), env=None, timeout=180, helper=None):
    """One single-shot verb against the installed helper.

    Returns (parsed stdout, returncode, stderr). `env` REPLACES the
    environment when given — the SUDO_UID / PKEXEC_UID matrix depends on
    controlling it exactly, and inheriting a stray SUDO_UID from the caller
    would silently invalidate every row of it.
    """
    p = subprocess.run(
        [helper or HELPER, verb] + list(argv),
        input=json.dumps(req if req is not None else {}),
        env=env if env is not None else os.environ.copy(),
        text=True, capture_output=True, timeout=timeout, cwd="/")
    try:
        out = json.loads(p.stdout)
    except Exception:
        out = {"_unparseable": p.stdout[:300]}
    return out, p.returncode, p.stderr


def base_env(**overrides):
    """A clean environment for the helper: the current one with every identity
    hint REMOVED, plus whatever the caller wants set.

    `SUDO_UID` in particular is inherited from whatever escalated us, and a
    matrix row that means "no escalation hint at all" has to actually have
    none.
    """
    env = os.environ.copy()
    for var in ("SUDO_UID", "SUDO_GID", "SUDO_USER", "PKEXEC_UID"):
        env.pop(var, None)
    for k, v in overrides.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = str(v)
    return env


class Session:
    """The `open` session: newline-delimited request frames, one reply line
    each — the only invocation shape in which a mutation survives to a save,
    because a handle is single-process and dies with the helper
    (docs/CONTRACT.md, "handle semantics")."""

    def __init__(self, env=None, helper=None):
        self.p = subprocess.Popen(
            [helper or HELPER, "open"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, cwd="/",
            env=env if env is not None else os.environ.copy())
        self.banner = self._read()

    def _read(self):
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("the helper closed stdout")
        return json.loads(line)

    def call(self, verb, **kw):
        kw["verb"] = verb
        self.p.stdin.write(json.dumps(kw) + "\n")
        self.p.stdin.flush()
        return self._read()

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        rest = self.p.stdout.read()
        err = self.p.stderr.read()
        self.p.wait(timeout=60)
        return rest, err, self.p.returncode


def main_guard(fn):
    """Run `fn(report)` and exit with its verdict, turning an unexpected
    exception into a FAIL rather than a traceback in a group-readable log.

    Only the exception TYPE is printed. A traceback prints locals, and in this
    program a local is the safe — the same reasoning as the helper's own
    exception barrier (I15).
    """
    def wrapper(title):
        rep = Report(title)
        try:
            fn(rep)
        except Exception as exc:                               # noqa: BLE001
            rep.check("driver completed without an unexpected exception",
                      False, type(exc).__name__)
        sys.exit(rep.finish())
    return wrapper
