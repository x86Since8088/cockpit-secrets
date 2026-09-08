# tests/root — the half of the access model that needs root

Everything else in `tests/` proves the admin class from the **refusing** side.
That is worth something, but only half: a helper that refused every verb would
pass all of it. This directory is the other half. It installs the package on
the real host, opens a real admin-class safe as **euid 0**, changes it, saves
it, and proves the change is still there when another process opens the file.

It is also the only place in the tree that runs as root at all, so it is where
the installation itself gets audited: what `install.sh` actually put on disk,
with what modes, and what `--uninstall` actually removes.

`docs/ROOT-VERIFICATION.md` is the record of a real run — every command, its
real output, and PASS/FAIL. This file is how to run it again.

---

## Running it

Root work on edt1 goes through the `/srv/jobs` inbox runner; interactive `sudo`
does not work here (`docs/HOST-FACTS.md`, "Root"). `submit.sh` stages a job and
hands it over; nothing in this directory calls `sudo` and nothing needs to.

    cd tests/root
    ./run-all.sh                     # the whole suite, 10 -> 90
    ./run-all.sh 40                  # one step
    ./submit.sh --timeout 900 40-admin-allow.sh

| Step | What it establishes | ~time |
|---|---|---|
| `10-install.sh` | `install.sh` runs clean as root; `cockpit.socket` is not disturbed | 10 s |
| `20-verify-install.sh` | every installed path, mode and owner; nothing from `tests/`; nothing group-writable; the helper resolves its installed library root | 5 s |
| `30-throwaway-safes.sh` | mints the passphrase; builds one admin-class and one user-class safe plus three registry entries under the REAL `/etc/cockpit-secrets` | 5 s |
| `40-admin-allow.sh` | **the allowing side**: root unlocks, reads, mutates and saves; the state and audit directories; `SUDO_UID`/`PKEXEC_UID`; the lockout counter | 60 s |
| `45-lockout-principals.sh` | **I40**: two escalated operators, two lockout counters — A's typo does not refuse B with the correct passphrase, A is still counted, and the class gate is what bounds identity variation | 15 s |
| `50-user-class.sh` | the user class as `cptest`, unescalated: their own safe works, nothing of the admin class does | 10 s |
| `60-uninstall-reinstall.sh` | `--uninstall` removes exactly the software and keeps the registry byte for byte; then reinstalls | 20 s |
| `90-cleanup.sh` | removes every throwaway subject and the passphrase, and prints what is left on the host | 5 s |

The steps are **ordered and stateful**. 30 mints the passphrase the later steps
need; 90 destroys it. Running 40 without 30 is refused by 40's own
preconditions rather than producing a page of misleading red.

`run-all.sh` does **not** stop at the first failure. Steps 10–60 are
measurements, and stopping early would leave the throwaway subjects in the live
registry — `90-cleanup.sh` is the step that must always get to run.

## The passphrase

The one secret this suite handles. `30-throwaway-safes.sh` generates a fresh
one with `secrets.token_urlsafe(24)` straight into a file opened `0600` inside
a `0700` root-owned directory **on `/run`, which is tmpfs** — so it never
reaches persistent storage — and `90-cleanup.sh` destroys it. Nothing prints
it, nothing puts it on argv, and no environment variable carries it: the
drivers read the file and put the value on the helper's stdin as JSON, which is
the rule the program itself lives by (I10).

`50-user-class.sh` needs it as `cptest`, who must not be able to read that
file. Root pipes the value into the driver's **stdin** instead, and
`driver_user.py` asserts that cptest cannot list the directory or open the file
— the piping is not a convenience, it is what lets that assertion be true.

It is generated rather than borrowed from the committed fixture constant
(`tests/integration/_env.py`, `PW`) because a constant would have to be copied
into a job script under `/srv/jobs`, and **that directory is group-readable by
`users`**. The same reason is why nothing here ever echoes a value:
`output.log` is group-readable, and `checklib.scrub()` runs over everything
printed.

## The files

| File | Role |
|---|---|
| `rootlib.sh` | sourced by every job: paths, the throwaway names, the passphrase helpers, the shell reporter |
| `checklib.py` | the Python drivers' plumbing: `Report`, `run()`, `Session`, `scrub()`, `base_env()` |
| `mkdb.py` | builds one throwaway KDBX with `pykeepass` directly — not through a backend, so the subject is a database this program did not write (I19) |
| `driver_admin.py` | section A–G of the allowing-side proof |
| `driver_user.py` | the user class, run as `cptest` by `runuser` |
| `submit.sh` | stages a job (script → `run.sh`, plus `rootlib.sh` and the drivers) and submits it. Compiles every `.py` first |
| `run-all.sh` | the ordered run, with per-step timeouts |

Two constraints shaped the layout, both from `docs/03-job-runner.md`:

* **A job's working directory is its outbox folder, `root:users` 0770.**
  `cptest` is not in `users`, so it cannot chdir there — every script captures
  `JOBDIR` first, sources `rootlib.sh` by absolute path, then `cd /` before any
  `runuser`. `50-user-class.sh` copies the two files cptest must read into a
  0755 tmpfs directory and removes them afterwards.
* **`output.log` is group-readable.** There is no `set -x` anywhere in this
  directory, for the same reason there is none anywhere else in the tree (I15).

## What this suite does not do

It never stops, restarts or reloads `cockpit.socket`. Cockpit is a live service
on edt1 and rescans `/usr/share/cockpit` on the next page load anyway, so a
restart would buy nothing and cost every open session. `10-install.sh` and
`20-verify-install.sh` record `ActiveEnterTimestamp` and `InvocationID` before
and after and assert they did not move.

It does not exercise the browser, the optional agent, a `DESTDIR` staging
install, or the `psafe3` backend at root. `docs/ROOT-VERIFICATION.md` lists
those as **not attempted**, which is not the same as passing.
