"""Shared plumbing for the integration suite: a hermetic registry, built from
the committed fixtures, that the real `secrets-admin` will actually accept.

Every script in this directory drives the REAL helper against REAL fixture
safes. Nothing here stubs a backend or a response — that is the whole point:
the unit self-checks (`python3 backends/base.py`, `python3 -m backends.psafe3`)
and the per-backend harnesses each prove one half, and these scripts prove the
halves fit together.

Three environment facts this module exists to get right, all of which cost real
debugging time when they were got wrong:

  * `open_safe_fd` requires the safe be `0600` and owned by the caller, and the
    source tree is group-writable (0775 over SMB), so a fixture MUST be copied
    out of it before it can be opened at all.
  * the helper refuses the WHOLE registry when its root directory is
    group-writable — correctly, per I1. `os.makedirs(mode=...)` applies the mode
    to the LEAF only, so the intermediates come out `0777 & ~umask` and the
    whole run then answers `not-found` for every case, which reads exactly like
    a taxonomy disagreement. Every level is chmod'ed explicitly below.
  * `atomic_replace` REFUSES a backup ring under `/tmp` or `/var/tmp`, so a
    save into a `/tmp` fixture dir fails with `invalid`. The default root here
    is the user's XDG runtime directory.
"""
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(os.path.dirname(HERE))          # .../source
HELPER = os.path.join(SRC, "secrets-admin")
FIXTURES = os.path.join(SRC, "tests", "fixtures")
CORPUS = os.path.join(SRC, "tests", "corpus", "files")

MANIFEST = json.load(open(os.path.join(FIXTURES, "manifest.json")))
SENTINEL = MANIFEST["sentinel"]
PW = "fixture-pass-do-not-reuse"


def default_root():
    """Somewhere private, not group-writable, and not under /tmp."""
    base = os.environ.get("XDG_RUNTIME_DIR") or os.path.expanduser("~/.cache")
    return os.path.join(base, "cockpit-secrets-integration")


#: id -> (fixture file, registry overrides). Kept here so every script names a
#: safe the same way and a fixture rename is a one-line change.
SAFES = {
    "lab-kdbx41": ("lab-kdbx41-aes256-argon2id.kdbx", {"format": "kdbx"}),
    "lab-kdbx40": ("lab-kdbx40-aes256-argon2d.kdbx", {"format": "kdbx"}),
    "lab-kdbx31": ("lab-kdbx31-aes256-aeskdf.kdbx", {"format": "kdbx"}),
    "lab-chacha": ("lab-kdbx41-chacha20-argon2d.kdbx", {"format": "kdbx"}),
    "lab-kdbx-kf": ("lab-kdbx41-keyfile-only.kdbx",
                    {"format": "kdbx", "password_required": False,
                     "keyfile": "lab-kdbx41-keyfile-only.keyx"}),
    "lab-kdbx-pwkf": ("lab-kdbx41-password-and-keyfile.kdbx",
                      {"format": "kdbx",
                       "keyfile": "lab-kdbx41-password-and-keyfile.keyx"}),
    "lab-pws3": ("lab-pws3.psafe3", {"format": "psafe3"}),
    # The same files registered a second way, to exercise the two refusals that
    # are registry decisions rather than file properties.
    "lab-ro": ("lab-kdbx41-aes256-argon2id.kdbx",
               {"format": "kdbx", "mode": "ro"}),
    "lab-admin": ("lab-kdbx40-aes256-argon2d.kdbx",
                  {"format": "kdbx", "access": "admin"}),
}


class Env:
    """A hermetic registry rooted at `root`, rebuildable at any time."""

    def __init__(self, root=None):
        self.root = root or default_root()
        self.etc = os.path.join(self.root, "etc")
        self.var = os.path.join(self.root, "var")
        self.safes_d = os.path.join(self.etc, "safes.d")
        self.safes = os.path.join(self.etc, "safes")
        self.env = dict(os.environ)
        self.env["COCKPIT_SECRETS_ETC"] = self.etc
        self.env["COCKPIT_SECRETS_VAR"] = self.var

    # -- construction ------------------------------------------------------

    def build(self):
        shutil.rmtree(self.root, ignore_errors=True)
        for d in (self.root, self.etc, self.var, self.safes, self.safes_d):
            os.makedirs(d, exist_ok=True)
        # Explicitly, every level: see the module docstring.
        for d in (self.root, self.etc, self.var, self.safes):
            os.chmod(d, 0o700)
        os.chmod(self.safes_d, 0o755)
        self.reset_safes()
        for i, (sid, (fixture, over)) in enumerate(sorted(SAFES.items())):
            entry = {
                "id": sid, "label": fixture, "format": over["format"],
                "path": os.path.join(self.safes, fixture),
                "access": over.get("access", "user"),
                "mode": over.get("mode", "rw"),
                "password_required": over.get("password_required", True),
                "backup": {"keep": 3, "dir": None},
            }
            if entry["access"] == "user":
                entry["owner"] = "%u"
            if over.get("keyfile"):
                entry["keyfile"] = os.path.join(self.safes, over["keyfile"])
            path = os.path.join(self.safes_d, "%02d-%s.json" % (10 + i, sid))
            with open(path, "w") as fh:
                json.dump(entry, fh, indent=1)
            os.chmod(path, 0o644)
        self.assert_loaded(len(SAFES))
        return self

    def reset_safes(self):
        """Restore every safe to pristine fixture bytes and clear the debris a
        previous run's save (or a killed save) left behind."""
        for name in os.listdir(self.safes) if os.path.isdir(self.safes) else []:
            p = os.path.join(self.safes, name)
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.unlink(p)
        for _sid, (fixture, over) in SAFES.items():
            for f in [fixture] + ([over["keyfile"]] if over.get("keyfile") else []):
                dst = os.path.join(self.safes, f)
                if not os.path.exists(dst):
                    shutil.copy(os.path.join(FIXTURES, f), dst)
                    os.chmod(dst, 0o600)

    def clear_lockout(self):
        """The lockout counter refuses after 5 bad credentials, which would
        turn a corpus of failures into a run of `locked-out`. Clearing it is a
        test seam, not a policy change: the counter itself is still verified by
        fail_timing.py."""
        shutil.rmtree(os.path.join(self.var, "state"), ignore_errors=True)

    def destroy(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # -- invocation --------------------------------------------------------

    def run(self, verb, req=None, argv=(), timeout=300, extra_env=None):
        """One single-shot verb. Returns (parsed stdout, returncode, stderr)."""
        env = dict(self.env)
        if extra_env:
            env.update(extra_env)
        p = subprocess.run([sys.executable, HELPER, verb] + list(argv),
                           cwd=SRC, env=env,
                           input=json.dumps(req if req is not None else {}),
                           text=True, capture_output=True, timeout=timeout)
        try:
            out = json.loads(p.stdout)
        except Exception:
            out = {"_unparseable": p.stdout[:400]}
        return out, p.returncode, p.stderr

    def assert_loaded(self, expected):
        h, _rc, _err = self.run("health")
        if h.get("registry_entries") != expected:
            raise SystemExit(
                "hermetic registry did not load: entries=%s errors=%s\n"
                "(the usual cause is a group-writable directory somewhere "
                "above %s)"
                % (h.get("registry_entries"), h.get("registry_errors"),
                   self.etc))
        return h


class Session:
    """The `open` session: newline-delimited request frames, one reply line
    each, with the unsolicited banner and closing frames routed out — exactly
    what secrets.js does."""

    def __init__(self, env, verbose=False):
        self.env = env
        self.verbose = verbose
        self.p = subprocess.Popen(
            [sys.executable, HELPER, "open"], cwd=SRC, env=env.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
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
        out = self._read()
        if self.verbose:
            print("    %-11s -> %s" % (verb, json.dumps(out)[:220]))
        return out

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        rest = self.p.stdout.read()
        err = self.p.stderr.read()
        self.p.wait(timeout=30)
        return rest, err, self.p.returncode


class Report:
    """The shape base.py's self-check set: one line per check, a count at the
    end, exit 0 or 1."""

    def __init__(self, title):
        self.title = title
        self.failures = []
        self.count = 0
        print("== %s ==" % title)

    def check(self, name, cond, extra=""):
        self.count += 1
        print("  %-4s %s%s"
              % ("ok" if cond else "FAIL", name,
                 ("  -> " + str(extra)[:200]) if extra else ""))
        if not cond:
            self.failures.append(name)
        return bool(cond)

    def section(self, name):
        print("\n-- %s --" % name)

    def finish(self):
        print("\n%d checks, %d failure(s)%s"
              % (self.count, len(self.failures),
                 (": " + ", ".join(self.failures)) if self.failures else ""))
        return 1 if self.failures else 0
