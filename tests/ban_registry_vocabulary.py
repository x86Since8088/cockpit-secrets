#!/usr/bin/env python3
"""THE HELPER AND ITS OWN SCHEMA FILE MUST AGREE ABOUT REGISTRY KEYS. (I46)

Run by `validate.sh`. Exit 0 when `secrets-admin`'s `_KNOWN_KEYS` and
`schema/safe-registry.schema.json`'s `properties` are the same set.

WHY THIS IS A STANDING GATE AND NOT A ONE-OFF FIX. `origin`, `created_utc` and
`source` were declared in the schema, documented in `docs/CONTRACT.md` and
shipped in three `etcdefaults/` examples -- and `_KNOWN_KEYS` did not list them.
`validate_entry()` runs BEFORE the jsonschema gate and drops an entry with an
unknown key, so an operator who copied a shipped example got a registry entry
that jsonschema accepted, `install.sh`'s example loop validated, and the helper
silently discarded. Their safe simply did not appear in `list`, and the only
clue was a line in `health.registry_errors` they had no reason to open.

The failure is symmetric and both directions are checked:

  * a key in the SCHEMA but not in `_KNOWN_KEYS` -- the operator writes what the
    documentation shows them and the entry vanishes;
  * a key in `_KNOWN_KEYS` but not in the SCHEMA -- the helper accepts a field
    its own installed schema will reject on the next load, which is the same
    disappearance with the two gates swapped. The comment above `_KNOWN_KEYS`
    describes exactly this having been tolerated once as "schema drift", and
    says why it is not coming back.

`_KNOWN_KEYS` is read out of the source text rather than by importing the
helper: importing it runs `harden_process()` and the library search, which is a
great deal of machinery for one tuple, and this gate has to work on a file that
does not import cleanly.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
HELPER = os.path.join(SRC, "secrets-admin")
SCHEMA = os.path.join(SRC, "schema", "safe-registry.schema.json")


def known_keys():
    """The `_KNOWN_KEYS` tuple, from the source text.

    Anchored on the assignment and stopped at the closing paren, so a later
    tuple in the file cannot be picked up by accident. A missing or unreadable
    tuple is a FAILURE, not an empty set: an empty set compares unequal to the
    schema and reports something useful, whereas a silent `set()` would make
    this gate pass on a helper that had lost the constant entirely.
    """
    text = open(HELPER, encoding="utf-8").read()
    match = re.search(r"^_KNOWN_KEYS = \((.*?)\)\n", text, re.S | re.M)
    if not match:
        print("_KNOWN_KEYS was not found in secrets-admin")
        return None
    return set(re.findall(r'"([a-z_0-9]+)"', match.group(1)))


def main():
    names = known_keys()
    if names is None:
        return 1
    schema = json.load(open(SCHEMA, encoding="utf-8"))
    declared = set(schema.get("properties") or {})
    if not declared:
        print("safe-registry.schema.json declares no properties")
        return 1
    missing = sorted(declared - names)
    extra = sorted(names - declared)
    if not missing and not extra:
        print("%d registry keys, agreed by both gates" % len(names))
        return 0
    if missing:
        print("declared in safe-registry.schema.json but NOT in _KNOWN_KEYS "
              "(the helper will DROP an entry that uses one): %s"
              % ", ".join(missing))
    if extra:
        print("in _KNOWN_KEYS but NOT declared in safe-registry.schema.json "
              "(additionalProperties:false will drop it on the next load): %s"
              % ", ".join(extra))
    return 1


if __name__ == "__main__":
    sys.exit(main())
