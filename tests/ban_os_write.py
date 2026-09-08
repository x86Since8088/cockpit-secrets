#!/usr/bin/env python3
"""validate.sh's DURABILITY-1 ban: exactly one os.write() in the program.

`os.write()` may write FEWER bytes than it was given. `backends/base.py`
`_ring_backup` advanced by the bytes it had READ rather than the bytes the
kernel had taken, so one short write on a nearly full filesystem produced a
truncated backup generation that was fsync'd, named, listed by the `backups`
verb with a plausible size, and accepted by `restore-backup` — which wrote it
over the live safe.

Every other data-carrying write in the program looped correctly. That is why
nothing caught the one that did not, and it is why the rule is now COUNTED
rather than described: the whole program may contain exactly one code line that
calls `os.write()`, and it must be the one inside `write_all()`.

`backends/base.py` is deliberately not exempt. Exempting the file would leave
the function this finding is about unwatched, which is what a first attempt at
this ban did — it passed with the bug put back. The check parses each file and
looks for `os.write` CALL nodes, so the several comments in this tree that
explain the rule do not trip it.

Exit 0 when the invariant holds, 1 with the offending lines on stderr when it
does not. Run from the package root.
"""
import ast
import pathlib
import sys

#: The one call that is allowed, and the function it has to be inside.
ALLOWED_FILE = "backends/base.py"
ALLOWED_FUNC = "write_all"


def _calls(tree):
    """Every `os.write(...)` CALL in a module, with the function around it.

    Parsed, not grepped. A first version of this check matched text, and every
    docstring and comment in this tree that explains WHY os.write must not be
    called bare — there are several, deliberately — matched it too. A ban that
    fires on its own rationale is a ban somebody switches off.
    """
    out = []
    scope = []

    class Walk(ast.NodeVisitor):
        def visit_FunctionDef(self, node):      # noqa: N802
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):             # noqa: N802
            fn = node.func
            if (isinstance(fn, ast.Attribute) and fn.attr == "write"
                    and isinstance(fn.value, ast.Name) and fn.value.id == "os"):
                out.append((node.lineno, scope[-1] if scope else "<module>"))
            self.generic_visit(node)

    Walk().visit(tree)
    return out


def offenders(root="."):
    base = pathlib.Path(root)
    files = [base / "secrets-admin"]
    files += sorted(base.glob("backends/*.py"))
    files += sorted(base.glob("agent/*.py"))
    found = []
    for path in files:
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError):
            continue
        for lineno, func in _calls(tree):
            found.append((str(path.relative_to(base)), lineno, func))
    return found


def main():
    found = offenders()
    ok = (len(found) == 1
          and found[0][0] == ALLOWED_FILE
          and found[0][2] == ALLOWED_FUNC)
    if not ok:
        if not found:
            sys.stderr.write("        no os.write() call found at all — has "
                             "write_all() been removed?\n")
        for name, n, func in found:
            sys.stderr.write("        %s:%d: inside %s()\n" % (name, n, func))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
