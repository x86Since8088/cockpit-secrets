#!/usr/bin/env python3
"""The registry WRITE path, and the twelve defects a red-team round found in it.

Every check here fails if its fix is reverted, and each section says which
invariant it is really asserting -- a check whose name is only an issue id
stops meaning anything the moment somebody renumbers the issues.

WHY THIS FILE IS SEPARATE FROM `newverbs.py`. That script proves the eight
registry verbs DO their job. This one proves they cannot be talked into doing
something else, which needs a different fixture: a per-user registry the caller
can write (C4 hands them that deliberately), files that are not safes, entries
pointing outside the managed directories, and a staging directory raced against
its own commit.

Run: python3 tests/integration/registry_writes.py
"""
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import Report, HELPER, SRC, PW                          # noqa: E402

FIXTURE = os.path.join(SRC, "tests", "fixtures",
                       "lab-kdbx41-aes256-argon2id.kdbx")

#: A passphrase used only by this script. Not the fixture credential, so a grep
#: that finds it in a log has found THIS run leaking, not a fixture.
NEWPW = "regwrite-pass-2f81ce-do-not-reuse"

#: Characters that make a rendered label differ from the stored one. Written as
#: \\u escapes on purpose: a source file carrying a literal U+202E reverses
#: itself in every reviewer's editor, which is the very confusion under test.
SPOOF_LABELS = {
    "bidi override U+202E": "Personal ‮ybdk.CD balbaL‬",
    "zero-width space U+200B": "lab​dc",
    "zero-width joiner U+200D": "lab‍dc",
    "left-to-right mark U+200E": "lab‎dc",
    "byte order mark U+FEFF": "﻿lab-dc",
    "first strong isolate U+2068": "a⁨b⁩",
    "C0 control U+0001": "labdc",
}

#: Labels that must still be accepted. A refusal that catches everything is not
#: a refusal, it is an outage.
GOOD_LABELS = ["Lab DC", "Personal – notes", "Café keys",
               "日本語", "a" * 128]


def _root():
    """Private, not group-writable, and NOT under /tmp.

    `validate_new_path` refuses to write a database under /tmp -- correctly --
    and `open_safe_fd` refuses a safe with a group-writable ancestor, so the
    XDG runtime directory is the only convenient place all of this works. The
    pid segment stops two concurrent runs deleting each other's tree.
    """
    override = os.environ.get("COCKPIT_SECRETS_TEST_ROOT")
    base = (override or os.environ.get("XDG_RUNTIME_DIR")
            or os.path.expanduser("~/.cache"))
    return os.path.join(base, "cockpit-secrets-regwrite-%d" % os.getpid())


class Lab:
    """A hermetic ETC + VAR + HOME the helper will accept, rebuildable."""

    def __init__(self):
        self.root = _root()
        self.etc = os.path.join(self.root, "etc")
        self.var = os.path.join(self.root, "var")
        self.home = os.path.join(self.root, "home")

    def build(self):
        shutil.rmtree(self.root, ignore_errors=True)
        for path, mode in ((self.root, 0o700), (self.etc, 0o755),
                           (self.var, 0o700), (self.home, 0o700),
                           (os.path.join(self.etc, "safes"), 0o700),
                           (os.path.join(self.etc, "safes.d"), 0o755)):
            os.makedirs(path, exist_ok=True)
            os.chmod(path, mode)
        # The schema file goes beside the registry root so `_publish_entry`'s
        # jsonschema gate is the REAL one on every check here. Without it the
        # builtin validator runs alone, and a helper/schema disagreement --
        # which is exactly what one of these findings was -- could not be seen.
        shutil.copy(os.path.join(SRC, "schema", "safe-registry.schema.json"),
                    os.path.join(self.etc, "safe-registry.schema.json"))
        return self

    def destroy(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @property
    def env(self):
        out = dict(os.environ)
        out["COCKPIT_SECRETS_ETC"] = self.etc
        out["COCKPIT_SECRETS_VAR"] = self.var
        out["COCKPIT_SECRETS_HOME"] = self.home
        return out

    @property
    def user_reg(self):
        return os.path.join(self.home, ".config", "cockpit-secrets", "safes.d")

    @property
    def user_safes(self):
        return os.path.join(self.home, ".local", "share", "cockpit-secrets",
                            "safes")

    @property
    def sys_reg(self):
        return os.path.join(self.etc, "safes.d")

    def run(self, verb, req=None, timeout=300):
        proc = subprocess.run([sys.executable, HELPER, verb],
                              cwd=SRC, env=self.env,
                              input=json.dumps(req if req is not None else {}),
                              text=True, capture_output=True, timeout=timeout)
        try:
            return json.loads(proc.stdout)
        except Exception:
            return {"_unparseable": proc.stdout[:300], "_rc": proc.returncode,
                    "_err": proc.stderr[-300:]}

    def create(self, sid, fmt="kdbx", label=None, **kw):
        req = {"id": sid, "label": label or sid, "format": fmt,
               "access": "user", "new_password": NEWPW}
        req.update(kw)
        return self.run("safe-create", req)

    def user_dirs(self):
        """Create the per-user tree the way the helper does: 0700 all the way.

        `os.makedirs` applies its mode to the LEAF only, so intermediates come
        out 0777 & ~umask -- group-writable on this host -- and `open_safe_fd`
        then refuses every safe underneath. That cost real debugging time in
        `_env.py` too, which is why it is a named function in both places.
        """
        for path in (os.path.join(self.home, ".config"),
                     os.path.join(self.home, ".config", "cockpit-secrets"),
                     self.user_reg, os.path.join(self.home, ".local"),
                     os.path.join(self.home, ".local", "share"),
                     os.path.join(self.home, ".local", "share",
                                  "cockpit-secrets"),
                     self.user_safes):
            os.makedirs(path, exist_ok=True)
            os.chmod(path, 0o700)

    def plant_user_entry(self, name, doc):
        self.user_dirs()
        path = os.path.join(self.user_reg, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle)
        os.chmod(path, 0o600)
        return path

    def upload(self, sid, data, fmt="kdbx", label=None, access="user"):
        """begin -> chunk*, returning the staging token. No inspect, no commit."""
        digest = hashlib.sha256(data).hexdigest()
        begun = self.run("import-begin",
                         {"id": sid, "label": label or sid, "format": fmt,
                          "access": access, "total_bytes": len(data),
                          "sha256": digest})
        token = begun.get("staging")
        if not token:
            return None, begun
        size = begun.get("chunk_bytes") or 512 * 1024
        off = 0
        while off < len(data):
            piece = data[off:off + size]
            self.run("import-chunk",
                     {"staging": token, "chunk_offset": off,
                      "chunk_b64": base64.b64encode(piece).decode("ascii")})
            off += len(piece)
        return token, begun

    def staging_root(self):
        return self.run("health")["import_staging"]["dir"]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


# ===========================================================================


def section_delete_gate(lab, rep):
    """I47: safe-delete destroys ONLY a file this program minted, and only the
    ring it derives from that path.

    THE INVARIANT: **safe-delete is not a destroy-arbitrary-file primitive.**
    C4 hands every unprivileged user a registry they can write, so an entry
    naming any file they own is a thing they can produce with `cat >`. The file
    was shredded and unlinked without ever being opened through a backend --
    512 bytes of /dev/urandom declared `psafe3` was enough -- and a registry
    `backup.dir` pointed at an unrelated directory had that whole directory
    swept, with the confirmation token naming only the safe id.
    """
    rep.section("safe-delete destroys only what this program made (I47)")

    lab.build()
    victim_dir = os.path.join(lab.home, "private")
    os.makedirs(victim_dir, 0o700)
    victim = os.path.join(victim_dir, "id_ed25519")
    with open(victim, "wb") as handle:
        handle.write(os.urandom(512))
    os.chmod(victim, 0o600)
    before = sha256_file(victim)
    lab.plant_user_entry("hand.json",
                         {"id": "hand-written", "label": "not ours",
                          "format": "psafe3", "path": victim})
    listed = [s["id"] for s in lab.run("list").get("safes", [])]
    rep.check("the hand-written entry loads, so a refusal below is about the "
              "gate and not about the entry", "hand-written" in listed, listed)
    out = lab.run("safe-delete", {"safe": "hand-written",
                                  "delete_confirm": "delete-safe:hand-written"})
    rep.check("safe-delete on a hand-registered file is access-denied",
              out.get("error") == "access-denied", json.dumps(out)[:200])
    rep.check("and the file is untouched, byte for byte",
              os.path.exists(victim) and sha256_file(victim) == before)
    out = lab.run("safe-forget", {"safe": "hand-written"})
    rep.check("safe-forget still works on it (C8's escape hatch)",
              out.get("ok") is True, json.dumps(out)[:160])

    lab.build()
    rep.check("a safe this program created", lab.create("ring-bomb").get("ok"))
    docs = os.path.join(lab.home, "docs")
    os.makedirs(docs, 0o700)
    for name in ("taxes.pdf", "keys.txt"):
        with open(os.path.join(docs, name), "w", encoding="utf-8") as handle:
            handle.write("x" * 64)
    entry_path = os.path.join(lab.user_reg, "ring-bomb.json")
    with open(entry_path, encoding="utf-8") as handle:
        doc = json.load(handle)
    doc["backup"] = {"keep": 10, "dir": docs}
    with open(entry_path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    os.chmod(entry_path, 0o600)
    out = lab.run("safe-delete", {"safe": "ring-bomb",
                                  "delete_confirm": "delete-safe:ring-bomb"})
    rep.check("the delete of the safe itself still succeeds",
              out.get("ok") is True, json.dumps(out)[:160])
    rep.check("a registry backup.dir is NOT swept",
              sorted(os.listdir(docs)) == ["keys.txt", "taxes.pdf"],
              sorted(os.listdir(docs)) if os.path.isdir(docs) else "GONE")
    rep.check("and the response SAYS the copies are still there",
              "NOT touched" in (out.get("warning") or ""), out.get("warning"))

    lab.build()
    lab.create("ring-ok")
    safe = os.path.join(lab.user_safes, "ring-ok.kdbx")
    ring = safe + ".bak.d"
    os.makedirs(ring, 0o700)
    generations = ["ring-ok.kdbx.20260904T120000.000001.11.bak",
                   "ring-ok.kdbx.20260904T120001.000002.12.bak"]
    strangers = ["NOT-A-GENERATION",
                 "other.kdbx.20260904T120000.000001.9.bak"]
    for name in generations + strangers:
        with open(os.path.join(ring, name), "w", encoding="utf-8") as handle:
            handle.write("x" * 40)
        os.chmod(os.path.join(ring, name), 0o600)
    out = lab.run("safe-delete", {"safe": "ring-ok",
                                  "delete_confirm": "delete-safe:ring-ok"})
    rep.check("the DERIVED ring's own generations are destroyed",
              out.get("backups_removed") == 2, json.dumps(out)[:160])
    rep.check("and nothing else in that directory is",
              sorted(os.listdir(ring)) == sorted(strangers),
              sorted(os.listdir(ring)) if os.path.isdir(ring) else "GONE")
    rep.check("the safe file is gone", not os.path.exists(safe))


def section_delete_order(lab, rep):
    """I48: the registry entry goes first, the bytes second.

    THE INVARIANT: **a delete that cannot finish leaves MORE of the safe than
    the operator asked to destroy, never less than they were told.** The file
    and its whole backup ring were shredded, the registry unlink then failed
    with `access-denied`, and the operator was told nothing had happened while
    `list` still showed the safe usable.
    """
    rep.section("a delete that is refused destroys nothing (I48)")
    lab.build()
    lab.create("late-fail")
    safe = os.path.join(lab.user_safes, "late-fail.kdbx")
    before = sha256_file(safe)
    os.chmod(lab.user_reg, 0o500)              # the registry unlink will fail
    try:
        out = lab.run("safe-delete",
                      {"safe": "late-fail",
                       "delete_confirm": "delete-safe:late-fail"})
    finally:
        os.chmod(lab.user_reg, 0o700)
    rep.check("the refusal is reported", out.get("error") == "access-denied",
              json.dumps(out)[:200])
    rep.check("and the safe file is STILL THERE, byte for byte",
              os.path.exists(safe) and sha256_file(safe) == before)
    rep.check("and it still unlocks, so it is a safe and not shredded noise",
              lab.run("unlock", {"safe": "late-fail",
                                 "password": NEWPW}).get("handle") is not None)
    rep.check("and it is still listed as usable, which is now TRUE",
              [(s["id"], s["usable"]) for s in lab.run("list")["safes"]]
              == [("late-fail", True)])


def section_confirm_field(lab, rep):
    """I49: the gate the operator types is the gate the code checks.

    THE INVARIANT: **a destructive verb reads the field its own schema
    declares.** It read `confirm` while the schema published `delete_confirm`,
    so through the published interface the verb could never succeed -- and it
    destroyed on a field nobody was told about.
    """
    rep.section("safe-delete's confirm is the SCHEMA-DECLARED field (I49)")
    schema = lab.run("schema")
    declared = {v["id"]: v["request"] for v in schema["verbs"]}
    rep.check("the schema declares delete_confirm and not confirm",
              "delete_confirm" in declared.get("safe-delete", [])
              and "confirm" not in declared.get("safe-delete", []),
              declared.get("safe-delete"))
    lab.build()
    lab.create("conf-1")
    out = lab.run("safe-delete", {"safe": "conf-1",
                                  "delete_confirm": "delete-safe:conf-1"})
    rep.check("the declared field DELETES", out.get("ok") is True,
              json.dumps(out)[:160])
    rep.check("the file is gone",
              not os.path.exists(os.path.join(lab.user_safes, "conf-1.kdbx")))
    lab.create("conf-2")
    out = lab.run("safe-delete", {"safe": "conf-2",
                                  "confirm": "delete-safe:conf-2"})
    rep.check("the old undeclared spelling does not delete",
              out.get("error") is not None, json.dumps(out)[:160])
    rep.check("and its file survives",
              os.path.exists(os.path.join(lab.user_safes, "conf-2.kdbx")))
    for bad in (None, "", "delete-safe:", "conf-2", "delete-safe:conf-1",
                "delete-safe:conf-2 ", ["delete-safe:conf-2"], 7):
        out = lab.run("safe-delete", {"safe": "conf-2", "delete_confirm": bad})
        rep.check("a confirm of %r is refused" % (bad,),
                  out.get("error") == "access-denied", json.dumps(out)[:120])
    rep.check("after all of that the safe is still there",
              os.path.exists(os.path.join(lab.user_safes, "conf-2.kdbx")))


def section_precommit_credentials(lab, rep):
    """I50: the pre-commit import steps REFUSE a credential.

    THE INVARIANT: **C5's ordering is enforced by the helper, not by the page.**
    The three pre-commit verbs never READ a credential, which is not the same
    as refusing one: they accepted `password`, `new_password`, `keyfile_b64`
    and `passphrase` and answered ok. Any other client -- or a regression in the
    page's step ordering -- could hold a passphrase in browser memory for a
    whole 128 MiB upload and ship it with every chunk frame.
    """
    rep.section("import-begin/chunk/inspect refuse a credential (I50)")
    lab.build()
    data = open(FIXTURE, "rb").read()
    digest = hashlib.sha256(data).hexdigest()

    for field in ("password", "new_password", "keyfile_b64", "passphrase"):
        out = lab.run("import-begin",
                      {"id": "cred-1", "label": "cred", "format": "kdbx",
                       "access": "user", "total_bytes": len(data),
                       "sha256": digest, field: "CANARY"})
        rep.check("import-begin + %s is invalid" % field,
                  out.get("error") == "invalid", json.dumps(out)[:160])
        rep.check("  and the refusal names the field",
                  field in (out.get("detail") or ""), out.get("detail"))

    token, _begun = lab.upload("cred-1", data)
    rep.check("a clean import-begin still works", token is not None)
    out = lab.run("import-chunk",
                  {"staging": token, "chunk_offset": 0, "chunk_b64": "QQ==",
                   "new_password": "CANARY"})
    rep.check("import-chunk + a credential is invalid",
              out.get("error") == "invalid", json.dumps(out)[:160])
    out = lab.run("import-inspect", {"staging": token, "password": "CANARY"})
    rep.check("import-inspect + a credential is invalid",
              out.get("error") == "invalid", json.dumps(out)[:160])
    rep.check("import-inspect WITHOUT one still works",
              lab.run("import-inspect", {"staging": token}).get("ok") is True)
    out = lab.run("import-commit", {"staging": token, "new_password": PW})
    rep.check("import-commit -- the one step that takes it -- still commits",
              out.get("ok") is True, json.dumps(out)[:160])

    # The guard is GENERIC — it lives in the dispatcher and is driven by each
    # verb's own declared request — so it is proved on a verb outside the
    # import feature. `probe` reads a request and declares no secret field.
    # (`list` and `health` declare `stdin: false` and never read a body at all,
    # so a credential sent to them does not reach the helper to be refused; the
    # guard is about verbs that DO parse one.)
    out = lab.run("probe", {"safe": "cred-1", "password": "CANARY"})
    rep.check("the guard is generic: probe + password is invalid too",
              out.get("error") == "invalid", json.dumps(out)[:160])
    out = lab.run("safe-forget", {"safe": "cred-1", "password": "CANARY"})
    rep.check("safe-forget + password is invalid",
              out.get("error") == "invalid", json.dumps(out)[:120])
    rep.check("and a verb that DOES declare one still accepts it",
              lab.run("unlock", {"safe": "cred-1",
                                 "password": PW}).get("handle") is not None)


def section_single_read(lab, rep):
    """I43: the bytes that are PROVEN are the bytes that LAND.

    THE INVARIANT: **a file that does not open does not land.** `import-commit`
    validated one read of the staged blob and wrote a second read of it, with a
    full KDF derivation in between and nothing tying the two together, so an
    import that reported success could register a file that is not a safe.

    Driven as a real race: an expensive KDF widens the window, the commit runs
    in a thread, and the staged blob is overwritten with noise while it derives.
    """
    rep.section("the validated bytes are the landed bytes (I43)")
    lab.build()
    made = lab.create("expensive",
                      kdf={"memory_kib": 262144, "time": 24, "parallelism": 2})
    rep.check("an expensive safe to import", made.get("ok") is True,
              json.dumps(made)[:200])
    data = open(os.path.join(lab.user_safes, "expensive.kdbx"), "rb").read()
    lab.run("safe-forget", {"safe": "expensive"})

    token, _begun = lab.upload("landed", data)
    rep.check("inspect passes",
              lab.run("import-inspect",
                      {"staging": token}).get("sha256_ok") is True)
    blob = os.path.join(lab.staging_root(), token, "blob")
    noise = os.urandom(len(data))
    result = {}

    def commit():
        result["out"] = lab.run("import-commit",
                                {"staging": token, "new_password": NEWPW})

    thread = threading.Thread(target=commit)
    thread.start()
    time.sleep(1.2)                     # inside the derivation
    swapped = False
    try:
        with open(blob, "r+b") as handle:
            handle.write(noise)
        swapped = True
    except OSError:
        pass
    thread.join()
    rep.check("the staged blob really was swapped mid-commit (the control)",
              swapped)
    out = result["out"]
    landed = os.path.join(lab.user_safes, "landed.kdbx")
    if out.get("ok"):
        got = open(landed, "rb").read()
        rep.check("the landed bytes are the VALIDATED ones, never the swapped "
                  "ones", got == data and got != noise)
        rep.check("and the registered safe opens",
                  lab.run("unlock", {"safe": "landed",
                                     "password": NEWPW}).get("handle")
                  is not None)
    else:
        rep.check("or the commit refused outright and NOTHING landed",
                  not os.path.exists(landed), json.dumps(out)[:200])
        rep.check("with a typed refusal, not an internal",
                  out.get("error") in ("invalid", "conflict", "bad-credential"),
                  json.dumps(out)[:200])
        rep.check("and the id is not registered",
                  "landed" not in [s["id"] for s in lab.run("list")["safes"]])

    # The SIGNATURE is the fix -- there is no path left to re-read from -- so
    # the signature is asserted rather than only the behaviour.
    helper_src = open(HELPER, encoding="utf-8").read()
    rep.check("_open_candidate takes bytes, not a path",
              "def _open_candidate(fmt, data, password, keyfile, *, mine):"
              in helper_src)
    rep.check("_header_facts takes bytes, not a path",
              "def _header_facts(fmt, data):" in helper_src)


def section_orphan(lab, rep):
    """I45: a failed registry write leaves no orphan file.

    THE INVARIANT: **a create either produces a listed safe or produces
    nothing.** A file that landed with no entry pointing at it burned the id
    from inside the program: create said `conflict`, `list` did not show it,
    and forget and delete both needed an entry that did not exist.
    """
    rep.section("a failed create leaves neither half behind (I45)")
    for verb in ("create", "import"):
        lab.build()
        lab.user_dirs()
        os.chmod(lab.user_reg, 0o500)          # the registry write will fail
        try:
            if verb == "create":
                out = lab.create("orphan-one")
            else:
                token, _begun = lab.upload("orphan-one",
                                           open(FIXTURE, "rb").read())
                lab.run("import-inspect", {"staging": token})
                out = lab.run("import-commit",
                              {"staging": token, "new_password": PW})
        finally:
            os.chmod(lab.user_reg, 0o700)
        rep.check("%s: the failure is reported" % verb,
                  out.get("error") is not None, json.dumps(out)[:200])
        left = sorted(os.listdir(lab.user_safes))
        rep.check("%s: no orphan file was left in the managed directory" % verb,
                  left == [], left)
        again = lab.create("orphan-one")
        rep.check("%s: the id is reusable afterwards" % verb,
                  again.get("ok") is True, json.dumps(again)[:200])
        rep.check("%s: and the safe is listed" % verb,
                  "orphan-one" in [s["id"]
                                   for s in lab.run("list").get("safes", [])])


def section_provenance(lab, rep):
    """I46: the helper writes what its own loader accepts.

    THE INVARIANT: **the helper and its schema file agree about the registry
    vocabulary.** `origin`, `created_utc` and `source` were declared in the
    schema, documented in CONTRACT.md and shipped in examples, and
    `_KNOWN_KEYS` did not list them -- so an operator who copied a shipped
    example got an entry jsonschema accepted and the helper silently dropped.
    """
    rep.section("the three provenance keys load and are written (I46)")
    lab.build()
    shipped = 0
    for name in ("30-example-created.json", "40-example-imported.json"):
        src = os.path.join(SRC, "etcdefaults", name)
        if not os.path.exists(src):
            continue
        dst = os.path.join(lab.sys_reg, name)
        shutil.copy(src, dst)
        os.chmod(dst, 0o644)
        shipped += 1
    health = lab.run("health")
    rep.check("the %d shipped provenance examples load with no registry errors"
              % shipped, health.get("registry_errors") == [],
              json.dumps(health.get("registry_errors"))[:300])
    rep.check("and they are counted as entries",
              health.get("registry_entries", 0) == shipped,
              health.get("registry_entries"))

    lab.build()
    rep.check("a create succeeds", lab.create("prov-1").get("ok") is True)
    with open(os.path.join(lab.user_reg, "prov-1.json"), encoding="utf-8") as h:
        doc = json.load(h)
    rep.check("a created entry records origin: created",
              doc.get("origin") == "created", doc.get("origin"))
    rep.check("and a created_utc ending in a literal Z",
              isinstance(doc.get("created_utc"), str)
              and doc["created_utc"].endswith("Z"), doc.get("created_utc"))
    rep.check("and NO source, because nothing was imported",
              "source" not in doc)

    data = open(FIXTURE, "rb").read()
    token, _begun = lab.upload("prov-2", data)
    lab.run("import-inspect", {"staging": token})
    out = lab.run("import-commit", {"staging": token, "new_password": PW})
    rep.check("an import succeeds", out.get("ok") is True,
              json.dumps(out)[:200])
    with open(os.path.join(lab.user_reg, "prov-2.json"), encoding="utf-8") as h:
        doc = json.load(h)
    rep.check("an imported entry records origin: imported",
              doc.get("origin") == "imported", doc.get("origin"))
    source = doc.get("source") or {}
    rep.check("and a source block carrying the digest it verified",
              source.get("sha256_at_import")
              == hashlib.sha256(data).hexdigest(), json.dumps(source)[:220])
    rep.check("and the header facts the operator was shown before typing",
              source.get("cipher") == "aes256"
              and source.get("kdf") == "argon2id"
              and source.get("format_version") == "4.1",
              json.dumps(source)[:220])
    rep.check("the entry round-trips through the loader (it is listed)",
              "prov-2" in [s["id"] for s in lab.run("list").get("safes", [])])
    rep.check("with no registry errors",
              lab.run("health").get("registry_errors") == [],
              json.dumps(lab.run("health").get("registry_errors"))[:300])

    for bad in ({"origin": "trusted"},
                {"created_utc": "yesterday"},
                {"source": {"cipher": "aes256"}},
                {"source": {"inspected_utc": "2026-09-04T00:00:00Z",
                            "kdf_params": {"lanes": 4}}}):
        entry = {"id": "bad-prov", "label": "bad", "format": "kdbx",
                 "path": os.path.join(lab.user_safes, "prov-1.kdbx")}
        entry.update(bad)
        lab.plant_user_entry("bad-prov.json", entry)
        errors = lab.run("health").get("registry_errors") or []
        rep.check("a malformed %r drops the entry with a reason"
                  % sorted(bad)[0],
                  any(e.get("file") == "bad-prov.json" for e in errors),
                  json.dumps(errors)[:220])
    os.unlink(os.path.join(lab.user_reg, "bad-prov.json"))


def section_forget_duplicates(lab, rep):
    """I51: forget refuses an id two registry files declare.

    THE INVARIANT: **safe-forget does not report success while the safe stays
    registered.** With two files declaring one id it unlinked the winner, the
    loser was promoted on the next load, and the operator believed a safe was
    unregistered while it remained fully reachable -- with whatever `path`,
    `access` and `mode` the survivor declares.
    """
    rep.section("forget refuses an id two registry files declare (I51)")
    lab.build()
    lab.create("dup-1")
    shutil.copy(os.path.join(lab.user_reg, "dup-1.json"),
                os.path.join(lab.user_reg, "00-alias.json"))
    os.chmod(os.path.join(lab.user_reg, "00-alias.json"), 0o600)
    out = lab.run("safe-forget", {"safe": "dup-1"})
    rep.check("safe-forget is a conflict, not a false success",
              out.get("error") == "conflict", json.dumps(out)[:200])
    rep.check("and it names both files",
              "00-alias.json" in (out.get("detail") or "")
              and "dup-1.json" in (out.get("detail") or ""), out.get("detail"))
    rep.check("both files are still there",
              sorted(os.listdir(lab.user_reg))
              == ["00-alias.json", "dup-1.json"])
    out = lab.run("safe-delete", {"safe": "dup-1",
                                  "delete_confirm": "delete-safe:dup-1"})
    rep.check("safe-delete refuses too", out.get("error") == "conflict",
              json.dumps(out)[:160])
    rep.check("and the safe file survives",
              os.path.exists(os.path.join(lab.user_safes, "dup-1.kdbx")))
    os.unlink(os.path.join(lab.user_reg, "00-alias.json"))
    rep.check("with the duplicate removed, forget works again",
              lab.run("safe-forget", {"safe": "dup-1"}).get("ok") is True)


def section_label_spoofing(lab, rep):
    """I52: a label cannot render as something other than what was typed.

    THE INVARIANT: **the name in the list is the name that was typed.** The
    registry schema names label confusion as the way a passphrase gets typed
    into the wrong prompt, and this release is the first time a label reaches
    the registry from a browser form at all.
    """
    rep.section("labels reject invisible formatting characters (I52)")
    lab.build()
    for index, (name, label) in enumerate(sorted(SPOOF_LABELS.items())):
        out = lab.run("safe-create",
                      {"id": "spoof-%d" % index, "label": label,
                       "format": "kdbx", "access": "user",
                       "new_password": NEWPW})
        rep.check("a label with a %s is refused" % name,
                  out.get("error") == "invalid", json.dumps(out)[:160])
        rep.check("  and nothing was created for it",
                  not os.path.exists(os.path.join(lab.user_safes,
                                                  "spoof-%d.kdbx" % index)))
    for index, label in enumerate(GOOD_LABELS):
        out = lab.run("safe-create",
                      {"id": "good-%d" % index, "label": label,
                       "format": "kdbx", "access": "user",
                       "new_password": NEWPW})
        rep.check("a legitimate label %r is accepted" % label[:20],
                  out.get("ok") is True, json.dumps(out)[:160])
        rep.check("  and stored verbatim",
                  out.get("safe", {}).get("label") == label)


def section_fifo(lab, rep):
    """I44: a registry path naming a FIFO cannot hang the helper.

    THE INVARIANT: **the plugin can always answer `schema` and `health`.** The
    S_ISREG refusal in `open_safe_fd` runs AFTER the open, and `open(2)` on a
    FIFO with no writer blocks forever -- so the check that was supposed to
    make a FIFO safe could never run, and every helper invocation hung,
    including the two a stuck plugin needs to explain itself with.
    """
    rep.section("a FIFO in the registry is refused, not blocked on (I44)")
    lab.build()
    fifo = os.path.join(lab.home, "hang.fifo")
    os.mkfifo(fifo, 0o600)
    lab.plant_user_entry("fifo.json",
                         {"id": "pu-fifo", "label": "fifo", "format": "kdbx",
                          "path": fifo})
    for verb in ("schema", "health", "list"):
        started = time.time()
        try:
            out = lab.run(verb, timeout=20)
            answered = True
        except subprocess.TimeoutExpired:
            out, answered = {}, False
        rep.check("%s answers instead of hanging (%.2fs)"
                  % (verb, time.time() - started),
                  answered and not out.get("_unparseable"),
                  json.dumps(out)[:160])
    errors = lab.run("health").get("registry_errors") or []
    rep.check("and the entry is dropped with a reason naming the file",
              any(e.get("file") == "fifo.json" for e in errors),
              json.dumps(errors)[:240])
    rep.check("the FIFO itself is untouched",
              stat.S_ISFIFO(os.stat(fifo).st_mode))
    os.unlink(fifo)


def section_sweep_symlink(lab, rep):
    """I53: the staging sweep does not follow a symlink.

    THE INVARIANT: **the sweep destroys stagings and nothing else.** It accepted
    any name matching the 32-hex token pattern, aged it with `os.stat` (which
    follows symlinks) and unlinked `blob` and `meta.json` by path -- so a
    symlink named like a token had its TARGET emptied, on every helper
    invocation, including at euid 0.
    """
    rep.section("the staging sweep skips a non-directory (I53)")
    lab.build()
    root = lab.staging_root()
    os.makedirs(root, exist_ok=True)
    os.chmod(root, 0o700)
    outside = os.path.join(lab.home, "outside")
    os.makedirs(outside, 0o700)
    for name in ("blob", "meta.json", "keepme"):
        with open(os.path.join(outside, name), "w", encoding="utf-8") as handle:
            handle.write("x")
    link = os.path.join(root, "b" * 32)
    os.symlink(outside, link)
    old = time.time() - 10 * 86400
    os.utime(outside, (old, old))
    lab.run("health")                       # any verb runs the sweep
    rep.check("the symlink's target is untouched",
              sorted(os.listdir(outside)) == ["blob", "keepme", "meta.json"],
              sorted(os.listdir(outside)) if os.path.isdir(outside) else "GONE")
    rep.check("and the symlink is left alone rather than half-removed",
              os.path.islink(link))
    os.unlink(link)

    token, _begun = lab.upload("sweepme", open(FIXTURE, "rb").read())
    staged = os.path.join(root, token)
    rep.check("a real staging exists (the positive control)",
              os.path.isdir(staged))
    meta_path = os.path.join(staged, "meta.json")
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)
    meta["used"] = int(time.time()) - 10 * 86400
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle)
    lab.run("health")
    rep.check("and an idle one IS swept", not os.path.exists(staged))


def section_concurrency(lab, rep):
    """I54: the two expensive import verbs are bounded.

    THE INVARIANT: **one upload cannot buy unbounded work.** Every other import
    limit counts things a caller may HOLD; none counted things RUNNING, and
    each helper invocation is its own process -- 32 simultaneous inspects of one
    128 MiB staging were measured at 7.6 GiB resident across 32 processes, every
    one of them euid 0 on the admin path.
    """
    rep.section("concurrent import work is bounded, and refuses rather than "
                "queues (I54)")
    lab.build()
    limit = lab.run("schema")["constants"].get("import_max_concurrent")
    rep.check("the bound is published as a constant",
              isinstance(limit, int) and limit >= 1, limit)
    token, _begun = lab.upload("conc", open(FIXTURE, "rb").read())
    lab.run("import-inspect", {"staging": token})

    outs = [None] * (limit + 6)

    def go(index):
        outs[index] = lab.run("import-inspect", {"staging": token})

    threads = [threading.Thread(target=go, args=(i,))
               for i in range(len(outs))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    refused = [o for o in outs if (o or {}).get("error") == "conflict"]
    passed = [o for o in outs if (o or {}).get("ok")]
    rep.check("some of %d simultaneous inspects are refused" % len(outs),
              len(refused) >= 1,
              "ok=%d conflict=%d" % (len(passed), len(refused)))
    rep.check("every refusal is a retryable conflict, never an internal",
              all((o or {}).get("error") in (None, "conflict") for o in outs),
              [(o or {}).get("error") for o in outs])
    rep.check("the staging survives a refusal: it is a throttle, not a destroy",
              lab.run("import-inspect", {"staging": token}).get("ok") is True)
    rep.check("and the commit still works afterwards",
              lab.run("import-commit",
                      {"staging": token,
                       "new_password": PW}).get("ok") is True)


def section_reused_id(lab, rep):
    """I55: a NEW safe at a reused id does not inherit the old one's lockout.

    THE INVARIANT: **the I16 counter belongs to a safe, and a safe that has been
    destroyed takes its counter with it.** The counter is keyed on (real uid,
    safe id), and until 0.4.0 an id was never freed from inside this program —
    so a counter and the safe it counted for had the same lifetime and nothing
    had to say this out loud. `safe-delete` broke it: the counter survived, and
    a safe created at the same id afterwards was `locked-out` on its FIRST
    unlock, with the passphrase the operator had just chosen.

    Found by cleaning up after the live walkthrough, which is the only reason it
    was found at all: nothing else in this suite deletes a safe and then reuses
    its id.
    """
    rep.section("a new safe at a reused id starts with a clean counter (I55)")
    for route in ("delete", "forget"):
        lab.build()
        lab.create("reuse")
        for i in range(6):
            lab.run("unlock", {"safe": "reuse", "password": "wrong-%d" % i})
        state = os.path.join(lab.var, "state")
        counter = os.path.join(state, "fail.%d.reuse.json" % os.getuid())
        rep.check("%s: the failures are on record before anything is removed"
                  % route,
                  os.path.exists(counter)
                  and json.load(open(counter)).get("failures", 0) >= 1,
                  json.load(open(counter)) if os.path.exists(counter) else None)
        if route == "delete":
            out = lab.run("safe-delete", {"safe": "reuse",
                                          "delete_confirm": "delete-safe:reuse"})
            rep.check("delete: the safe is destroyed", out.get("ok") is True,
                      json.dumps(out)[:140])
        else:
            out = lab.run("safe-forget", {"safe": "reuse"})
            rep.check("forget: the entry is removed", out.get("ok") is True,
                      json.dumps(out)[:140])
            os.unlink(os.path.join(lab.user_safes, "reuse.kdbx"))
        again = lab.create("reuse")
        rep.check("%s: the id can be created again" % route,
                  again.get("ok") is True, json.dumps(again)[:160])
        out = lab.run("unlock", {"safe": "reuse", "password": NEWPW})
        rep.check("%s: and the BRAND-NEW safe opens with the passphrase that "
                  "was just chosen — not `locked-out`" % route,
                  out.get("handle") is not None,
                  {k: out.get(k) for k in ("error", "detail")})
        # The counter file is ZEROED and not unlinked, deliberately: unlinking a
        # file other helpers hold an flock on is I39 reached from the one path
        # allowed to make the counter smaller.
        if route == "delete":
            rep.check("delete: the counter file is kept and zeroed rather than "
                      "unlinked (the flock inode discipline)",
                      os.path.exists(counter), counter)


def section_audit(lab, rep):
    """I15 re-proved on the new write path: no path, no credential, in the log.

    Included rather than trusted because these fixes deliberately ADDED paths
    to two error DETAILS (the orphan message, the per-user drop message), and
    the line between "an error detail may name a file the caller can already
    see" and "the audit log may not" is exactly the kind of thing that erodes.
    """
    rep.section("the audit log carries no path and no credential (I15)")
    lab.build()
    lab.create("aud-1")
    token, _begun = lab.upload("aud-2", open(FIXTURE, "rb").read())
    lab.run("import-inspect", {"staging": token})
    lab.run("import-commit", {"staging": token, "new_password": PW})
    lab.run("safe-forget", {"safe": "aud-2"})
    lab.run("safe-delete", {"safe": "aud-1",
                            "delete_confirm": "delete-safe:aud-1"})
    # `health` is asked where the log is rather than guessed at: `init_state`
    # puts it under `<var>/log`, and a test that hard-codes the layout starts
    # passing for the wrong reason the day the layout moves.
    log = lab.run("health").get("state", {}).get("audit_log") \
        or os.path.join(lab.var, "log", "audit.log")
    rep.check("the audit log was written", os.path.exists(log), log)
    text = open(log, encoding="utf-8", errors="replace").read() \
        if os.path.exists(log) else ""
    rep.check("with lines for the new verbs",
              "safe-create" in text and "safe-delete" in text
              and "import-commit" in text, text[-200:])
    for needle in (NEWPW, PW, lab.home, ".kdbx", "/home/", token or "TOKEN"):
        rep.check("the log does not contain %r" % needle[:40],
                  needle not in text)
    lines = [json.loads(x) for x in text.splitlines()
             if x.strip().startswith("{")]
    rep.check("no line carries an artifact",
              all(ln.get("artifact") in (None, "") for ln in lines))
    rep.check("no line reports an internal outcome",
              all(ln.get("outcome") != "internal" for ln in lines),
              [ln for ln in lines if ln.get("outcome") == "internal"][:2])


def main():
    rep = Report("registry writes -- the twelve defects, closed")
    lab = Lab()
    try:
        section_delete_gate(lab, rep)
        section_delete_order(lab, rep)
        section_confirm_field(lab, rep)
        section_precommit_credentials(lab, rep)
        section_single_read(lab, rep)
        section_orphan(lab, rep)
        section_provenance(lab, rep)
        section_forget_duplicates(lab, rep)
        section_label_spoofing(lab, rep)
        section_fifo(lab, rep)
        section_sweep_symlink(lab, rep)
        section_concurrency(lab, rep)
        section_reused_id(lab, rep)
        section_audit(lab, rep)
    finally:
        lab.destroy()
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
