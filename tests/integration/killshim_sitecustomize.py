"""TEST-ONLY interposer. Imported by `site` at interpreter startup, so it is in
place before secrets-admin or backends/base.py run a single line. It replaces
os.replace with a SIGKILL, which lands the process at exactly the instant
atomic_replace has written and fsynced its temp file and is about to rename it
over the original — the one moment a non-atomic writer would corrupt the safe.
Nothing in the project tree is modified to make this happen."""
import os
import signal

if os.environ.get("CS_KILL_AT_REPLACE") == "1":
    def _die_instead_of_renaming(src, dst, **kw):
        with open(os.environ["CS_KILL_WITNESS"], "w") as fh:
            fh.write("%s\n%s\n%d\n" % (src, dst, os.path.getsize(src)))
        os.kill(os.getpid(), signal.SIGKILL)
    os.replace = _die_instead_of_renaming
