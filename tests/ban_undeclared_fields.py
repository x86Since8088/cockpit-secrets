#!/usr/bin/env python3
"""EVERY REQUEST FIELD A VERB READS MUST BE ONE ITS SCHEMA DECLARES. (I49)

Run by `validate.sh`. Exit 0 when no verb -- through any function it can reach
-- reads a `req` key its own `schema` entry omits.

THE DEFECT THIS GENERALISES. `v_safe_delete` read `req.get("confirm")` -- the
`export` verb's field name -- while the schema published `delete_confirm`, and
`docs/CONTRACT.md` and `secrets.js` both used `delete_confirm`. Through the
published interface the destructive verb could therefore never succeed, and it
destroyed on a field nobody had been told about. The typed confirmation an
operator sees was decorative, and the obvious fix at the caller (start sending
`confirm`) would have left the UI and the helper permanently out of sync.

That is a whole CLASS of mistake -- a verb quietly reading something the
contract does not mention -- and a static check closes it for good. `schema` is
this project's single source of truth for the UI; a field the UI cannot know
about is a field no conforming client can send, so a verb that needs one is a
verb that cannot be driven.

HOW IT WORKS
------------
The verb table comes from the LIVE `schema` verb, because the whole point is to
compare against what is PUBLISHED rather than against a second list kept here.

The reads come from an AST walk of `secrets-admin`: every `req.get("x")`,
`req["x"]` and `req.pop("x")` string literal, attributed to the function it
appears in. A verb's fields are then the union over every function it can reach
through a **call graph built from the same AST** -- so `_new_credentials`,
which reads `new_password` and `keyfile_b64` for `safe-create` and
`import-commit`, is charged to those two verbs and to no others.

The graph is name-based and therefore approximate in one direction only: it can
over-approximate (two functions with the same name, a name used as a value),
which produces a FALSE FAILURE that a human then reads -- and never a false
pass, which is the direction that matters for a gate. Recursion is handled by
the visited set.

`_ALWAYS` is the small set of frame-level keys that belong to the protocol
rather than to any verb. They are named here, once, instead of being exempted
verb by verb.
"""
import ast
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
HELPER = os.path.join(SRC, "secrets-admin")

#: Protocol keys, not verb fields. `verb` names the frame inside an `open`
#: session and is stripped by the session loop before the verb ever runs.
_ALWAYS = frozenset(("verb",))


def verb_table():
    """The live `schema` verb's table: {verb id: set of declared request fields}."""
    env = dict(os.environ)
    # A nonexistent registry root: `schema` is static and needs none, and this
    # keeps the gate from depending on whatever is installed on the host.
    env["COCKPIT_SECRETS_ETC"] = "/nonexistent-validate-sh"
    proc = subprocess.run([sys.executable, HELPER, "schema"], cwd=SRC, env=env,
                          capture_output=True, text=True, timeout=120)
    doc = json.loads(proc.stdout)
    return {v["id"]: set(v.get("request") or []) for v in doc["verbs"]}


def _own_literals(node):
    """Every `req.get("x")` / `req["x"]` / `req.pop("x")` literal in `node`.

    Nested function definitions are included: a closure inside a verb is that
    verb's code.
    """
    found = set()
    for sub in ast.walk(node):
        target = None
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr in ("get", "pop") \
                and isinstance(sub.func.value, ast.Name) \
                and sub.func.value.id == "req" and sub.args:
            target = sub.args[0]
        elif isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) \
                and sub.value.id == "req":
            target = sub.slice
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            found.add(target.value)
    return found


def _callees(node, known):
    """Names in `known` that `node` calls, or mentions as a value.

    A bare `Name` is counted as well as a `Call`, because a function handed to
    something else (`spec["fn"]`) is still reachable. Over-approximating here
    only ever adds fields to a verb's charged set, which can produce a failure
    a human reads -- never a silent pass.
    """
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in known and sub.id != node.name:
            out.add(sub.id)
    return out


def main():
    table = verb_table()
    tree = ast.parse(open(HELPER, encoding="utf-8").read())
    functions = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[n.name] = n
    literals = {name: _own_literals(node) for name, node in functions.items()}
    graph = {name: _callees(node, functions)
             for name, node in functions.items()}

    def reachable_fields(start):
        seen, stack, fields = {start}, [start], set(literals.get(start, ()))
        while stack:
            cur = stack.pop()
            for nxt in graph.get(cur, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                stack.append(nxt)
                fields |= literals.get(nxt, set())
        return fields

    problems = []
    checked = 0
    for name in sorted(functions):
        if not name.startswith("v_"):
            continue
        # v_safe_create -> "safe-create", v_import_begin -> "import-begin".
        vid = name[2:].replace("_", "-")
        if vid not in table:
            candidates = [k for k in table if k.replace("-", "_") == name[2:]]
            if not candidates:
                extra = reachable_fields(name) - _ALWAYS
                if extra:
                    problems.append("%s reads %s but no schema verb maps to it"
                                    % (name, sorted(extra)))
                continue
            vid = candidates[0]
        checked += 1
        undeclared = reachable_fields(name) - table[vid] - _ALWAYS
        if undeclared:
            problems.append(
                "%s (verb %s) reads %s, which its schema request does not "
                "declare. Declared: %s"
                % (name, vid, sorted(undeclared), sorted(table[vid])))

    if problems:
        for line in problems:
            print(line)
        return 1
    print("%d verb functions checked against the live schema; every request "
          "literal any of them can reach is declared" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
