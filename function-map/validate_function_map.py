#!/usr/bin/env python3
"""validate_function_map.py — the second opinion on this tree.

The canonical validator ships with the orchestrator:

    cd .../ai-orchestrator
    python3 ai-orchestrator.py function-map validate --strict \
        --project cockpit-secrets --root .../source/function-map

That one is the authority and this one does not replace it. It exists because
that validator loads the schema through its own resolver, and "the loader
agrees with itself" is not evidence of anything. This script reads the three
canonical schema FILES, inlines the two `$ref` siblings by hand, asserts no
unresolved `$ref` survived the inlining, and validates every entry with
`jsonschema`'s Draft-07 validator directly — plus the one rule that lives in
prose rather than in the schema: **`FunctionName` must equal the filename.**

    ./function-map/validate_function_map.py            # exit 0 = clean
    ./function-map/validate_function_map.py --schemas /other/schemas/function-map

Exit 0 when every file validates and every name matches; 1 on any failure;
2 when the schemas or `jsonschema`/`PyYAML` cannot be found (a missing tool is
not a passing test).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SCHEMAS = Path("/srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator/"
                       "schemas/function-map")


def load_schema(schema_dir: Path) -> dict:
    """function_entry.yaml with service_type.yaml and port_spec.yaml inlined."""
    import yaml
    root = yaml.safe_load((schema_dir / "function_entry.yaml").read_text())
    svc = yaml.safe_load((schema_dir / "service_type.yaml").read_text())
    port = yaml.safe_load((schema_dir / "port_spec.yaml").read_text())
    props = root["properties"]
    props["service-type"] = svc
    props["ports"]["items"] = port

    def no_external_refs(node, path="$"):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if ref is not None and not str(ref).startswith("#"):
                raise SystemExit("unresolved $ref at %s: %s" % (path, ref))
            for k, v in node.items():
                no_external_refs(v, path + "." + k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                no_external_refs(v, "%s[%d]" % (path, i))

    no_external_refs(root)
    return root


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schemas", type=Path, default=DEFAULT_SCHEMAS,
                    help="directory holding the three canonical schema files")
    ap.add_argument("--tree", type=Path, default=HERE,
                    help="function-map tree to validate (default: this one)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    try:
        import yaml                                              # noqa: F401
        from jsonschema import Draft7Validator
    except ImportError as e:
        print("validate_function_map.py: %s — nothing was validated, and that "
              "is not a pass. Install python3-jsonschema / python3-yaml." % e,
              file=sys.stderr)
        return 2
    if not (a.schemas / "function_entry.yaml").exists():
        print("validate_function_map.py: no schemas at %s — nothing was "
              "validated." % a.schemas, file=sys.stderr)
        return 2

    validator = Draft7Validator(load_schema(a.schemas))
    checked = bad = mismatched = 0
    for f in sorted(a.tree.rglob("*.yaml")):
        checked += 1
        entry = yaml.safe_load(f.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(entry), key=lambda e: list(e.path))
        if errors:
            bad += 1
            print("FAIL %s" % f.relative_to(a.tree))
            for e in errors[:4]:
                print("      %s %s" % (list(e.path), e.message[:200]))
        if not isinstance(entry, dict) or entry.get("FunctionName") != f.stem:
            mismatched += 1
            print("NAME %s: FunctionName=%r does not match the filename"
                  % (f.relative_to(a.tree),
                     entry.get("FunctionName") if isinstance(entry, dict)
                     else None))

    if not a.quiet:
        print("%d files, %d schema failure(s), %d filename mismatch(es)"
              % (checked, bad, mismatched))
    return 1 if (bad or mismatched) else 0


if __name__ == "__main__":
    sys.exit(main())
