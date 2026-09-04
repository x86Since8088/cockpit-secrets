# tests/integration — the seams, not the pieces

Everything in this directory drives the **real** `secrets-admin` against the
**real** fixture safes in `tests/fixtures/`. Nothing here stubs a backend, a
response or a file. That is the point: the pieces already have proofs of their
own, and none of those proofs crosses a module boundary.

| Proof | What it covers | Who wrote it |
|---|---|---|
| `python3 backends/base.py` | the shared foundation, 106 checks | the base author |
| `python3 -m backends.psafe3` | the PWS3 parser/serialiser, 19 checks | the psafe3 author |
| `tests/oracle/` + `tests/fixtures/gen_fixtures.sh` | **foreign** implementations (`keepassxc-cli`, an independent Go PWS3 reader/writer, published Twofish vectors) | the oracles author |
| `tests/corpus/gen_corpus.py --check` | the malformed corpus against those foreign implementations | the oracles author |
| **this directory** | **the helper, the two backends, the registry and the schema working as one program** | the integrator |

## The scripts

    python3 tests/integration/flow.py             # ~25 s
    python3 tests/integration/conformance.py      # ~20 s
    python3 tests/integration/properties.py       # ~40 s
    python3 tests/integration/newverbs.py         # ~50 s
    python3 tests/integration/agent_cycle.py      # ~40 s
    python3 tests/integration/corpus_vs_helper.py # ~85 s

`run_tests.sh` in the source root runs all six plus every other gate.

- **`flow.py`** — the contract flow end to end on BOTH formats: probe → unlock →
  tree → entries → reveal → totp → add → edit → move → save → lock, an `open`
  session doing several mutations under one unlock, a *fresh process* reopening
  what the save wrote, the three distinct read-only causes (registry `mode:"ro"`
  → `access-denied`, KDBX 3.x → `unsupported`, per I20), the key-file
  credentials, and the access-class refusals.
- **`conformance.py`** — runs every verb on both backends and compares the
  response *shapes* to each other and to what the `schema` verb declares. This
  is the drift detector: the two backends were written by people who never saw
  each other's code, and a contract key that means two things is not a contract.
- **`properties.py`** — I10 (nothing in `/proc/<pid>/cmdline` or `environ`, with
  a control proving the reader works), I12 (SIGKILL between the temp write and
  the rename leaves the original byte-identical), I13 (a stale lock is refused
  and overridable only explicitly), I16 (the wrong passphrase is not faster than
  the right one, and every failure meets the floor).
- **`newverbs.py`** — the ten verbs added after the first build, on BOTH
  formats: history and history-restore (including the ordering, which was wrong
  in three places at once), the whole `reveal` field vocabulary, attachments,
  save-as and every traversal shape, backups and restore-backup, strength,
  breach-check, and **the export gate proved as a pair** — the same request
  refused as uid 1000 and accepted inside `unshare --map-root-user`, where
  `os.geteuid()` really is 0. A refusal on its own proves nothing: a verb that
  always fails also always refuses.
- **`agent_cycle.py`** — the real helper against the real `secrets-agent`. They
  were written in parallel and did not agree about `put`, about `drop`, or about
  the token alphabet; this is the script that made them. Agent OFF (the default)
  is proved to create no socket, add no key to `unlock`, and leave nothing
  behind; agent ON is proved to take a **ticket and not key material**, to be
  visible to a SECOND helper process, to be revoked by `lock` with a bare safe
  id, and to expire on its own deadline. Also the refusals: a 0755 run
  directory and a regular file on the socket path are both declined, silently
  and without failing the verb.
- **`corpus_vs_helper.py`** — all 67 malformed-input cases through the helper,
  each compared to its sidecar's expected code, its wall-clock budget and its
  `must_not_leak` list. The budget is not decoration: it is what distinguishes
  "the KDF parameters were clamped **before** deriving" from "after".

## Two environment facts that cost real debugging time

1. **`open_safe_fd` requires `0600` and caller ownership**, and the source tree
   is group-writable over SMB, so a fixture must be **copied out of it** before
   it can be opened at all. `_env.py` does that.
2. **The helper refuses the whole registry when its root is group-writable**
   (correctly — I1). `os.makedirs(mode=…)` applies the mode to the *leaf* only,
   so the intermediates come out `0777 & ~umask`; the whole run then answers
   `not-found` for every case, which reads exactly like a taxonomy
   disagreement. `_env.py` chmods every level and `Env.assert_loaded()` fails
   loudly rather than letting a broken setup masquerade as a result.

Related: `atomic_replace` **refuses a backup ring under `/tmp` or `/var/tmp`**,
and `validate_new_path` refuses to write a database there at all, so the
hermetic root defaults to `$XDG_RUNTIME_DIR`, never `/tmp`. If your
`XDG_RUNTIME_DIR` is itself under `/tmp`, set `COCKPIT_SECRETS_TEST_ROOT` to
somewhere else or `save-as` will correctly refuse and the run will look broken.

3. **The hermetic root is PER-PID.** `Env.build()` opens with `shutil.rmtree`,
   so a fixed root meant two scripts running at once deleted each other's
   registry mid-run — surfacing as `entries=0` or a `FileNotFoundError` from an
   unlink, both of which read exactly like a real registry bug. It cost two
   people real debugging time during the second build. `COCKPIT_SECRETS_TEST_ROOT`
   overrides it when you want a stable directory to poke at afterwards.

## `killshim_sitecustomize.py`

The I12 test has to stop the process at one exact instruction: after the temp
file is written and fsynced, before `os.replace` renames it over the safe. It
does that with a `sitecustomize.py` placed on `PYTHONPATH` — imported by `site`
at interpreter startup, before any project code runs — which replaces
`os.replace` with a `SIGKILL`. **Nothing in the project tree is modified,
conditionally compiled or given a test hook to make this work**, which is what
makes the result mean anything.

## What these scripts still do not cover

- **No root-owned registry.** `newverbs.py` does run the export allow-path at a
  real `euid == 0` inside `unshare --map-root-user`, which exercises that branch
  of `gate()` for real — but inside the namespace the caller's REAL uid is 0 too,
  so the `SUDO_UID`/group-membership branch is correctly skipped rather than
  tested. That half, and a registry genuinely owned by root, need the
  `/srv/jobs` runner.
- **No second real uid.** The agent's cross-uid refusals are proved against a
  distinct kernel uid from `/etc/subuid` via a user namespace, not against the
  `cptest` account named in docs/HOST-FACTS.md. The agent's check is uid-based
  and cannot tell the two apart, but the account was not the one used.
- **No YubiKey.** The challenge/response arithmetic has frozen regression
  vectors; no token has ever answered one, and those vectors are not interop
  vectors — nobody outside this tree has ever computed them.
- **No Cockpit bridge.** The page is driven by the Playwright harness against a
  stubbed `cockpit.spawn`; `superuser: "require"` has never been exercised
  against a real bridge.
- **No file written by the real Password Safe GUI** exists on this host, so I19
  stays partially open for PWS3. See `tests/fixtures/README.md`.
