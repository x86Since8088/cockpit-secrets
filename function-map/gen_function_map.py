#!/usr/bin/env python3
r"""gen_function_map.py — regenerate `function-map/` from the sources beside it.

WHY THIS FILE EXISTS
====================
`function-map/` is an inventory of every function in this package, one YAML per
symbol, validated against the canonical schemas in
`ai-orchestrator/schemas/function-map/`. Nine hundred YAML files cannot be
hand-maintained: the second time somebody renames a helper the map becomes a
document that describes a program which no longer exists, which is worse than
no map at all. So the map is GENERATED and the generator is the artifact that
is reviewed.

    ./function-map/gen_function_map.py            # rewrite the tree
    ./function-map/gen_function_map.py --check    # exit 1 if it would change

Regeneration is idempotent: running it twice back to back produces byte-identical
files. The only field that could drift is `DateCreated`, and that is read back
out of the existing entry before the file is rewritten (see `_date_created`).

WHAT IT PARSES, AND WITH WHAT
=============================
Nothing here guesses at syntax it could ask a real parser about:

  * Python  — the stdlib `ast` module.
  * JavaScript — SpiderMonkey's `Reflect.parse()` driven through `gjs`, which is
    already this project's JS syntax gate (`check.sh`). A real parser, not a
    regex, because `secrets.js` is one 3 000-line IIFE full of nested functions
    and brace counting would silently mis-nest them.
  * Go — `go/parser` from the Go standard library, via a throwaway program this
    script writes to a temp dir and runs with `go run`. Offline; stdlib only.

The two helper programs are embedded as strings below rather than committed as
separate files, so `function-map/` stays "one generator, one README, and YAML".

THE `ports` FIELD IS THE POINT
==============================
Every entry in this project carries `ports: []` unless it participates in the
`secrets-agent` AF_UNIX socket (I18), which is the only listening surface the
package can ever have. cockpit-secrets opens **no TCP port at all**: the browser
half talks to the helper through `cockpit.spawn`, which is a process and a pipe,
and the helper talks to the safe through a file descriptor. Recording that
absence mechanically — rather than asserting it in prose — is what makes it
checkable from the inventory later:

    grep -rl --include='*.yaml' 'transport: "unix"' function-map/
        # the only entries with a transport endpoint: the nine that operate
        # the agent's AF_UNIX socket, and nothing else

    grep -rn --include='*.yaml' 'transport: "\(tcp\|udp\)"' function-map/
        # finds nothing, and that is the claim worth being able to check

A password manager that listens on nothing is a security property, and this is
where it is proved.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent

# ---------------------------------------------------------------- selection --

# Directories never walked. `function-map` itself is excluded so the generator
# does not inventory itself; `tests/corpus/files` holds 67 deliberately
# malformed binaries and no code.
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".playwright", "test-results",
    "function-map", "audit", "backups",
}
SKIP_RELDIRS = {"tests/corpus/files"}

# Extensionless executables that are really Python. `secrets-admin` is the
# helper; anything else added later is picked up by the shebang sniff below.
PY_SHEBANG = re.compile(rb"^#!.*\bpython3?\b")


def discover_modules() -> list[Path]:
    """Every source file in the package that holds functions, sorted."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(SOURCE):
        rel_dir = os.path.relpath(dirpath, SOURCE).replace("\\", "/")
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS
            and (rel_dir == "." and d or f"{rel_dir}/{d}") not in SKIP_RELDIRS
        )
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = str(p.relative_to(SOURCE)).replace("\\", "/")
            if any(rel.startswith(s + "/") for s in SKIP_RELDIRS):
                continue
            if name.endswith((".py", ".js", ".go")):
                found.append(p)
            elif "." not in name and os.access(p, os.X_OK) and p.is_file():
                # `secrets-admin` has no extension. Sniff, do not hardcode.
                try:
                    if PY_SHEBANG.match(p.read_bytes()[:64]):
                        found.append(p)
                except OSError:
                    pass
    return found


def language_of(path: Path) -> str:
    if path.suffix == ".js":
        return "javascript"
    if path.suffix == ".go":
        return "go"
    return "python"


def classify(rel: str, lang: str) -> tuple[str, str]:
    """(side, service-type) for a module, by rule rather than by heuristic.

    side          — `client` is the browser half and nothing else. JavaScript
                    is not the test: `tests/browser/*.js` is Node running on the
                    host that *drives* a browser, so it is `server` like every
                    other harness. Only the files a browser actually loads —
                    `secrets.js` today — are `client`.

    service-type  — `WebPage` for the renderer, `Ext_service` for every
                    out-of-process thing: the helper, the agent, the backends,
                    and the test drivers that spawn `secrets-admin`,
                    `keepassxc-cli`, `pws3_oracle` and Playwright.

    Nothing in this package is `API`. The schema's own gloss would let the
    helper's verbs claim it ("CLI subcommands"), and that reading is defensible;
    this project pins `Ext_service` instead because the only consumer, the
    Cockpit page, reaches every one of them by spawning an external process and
    speaking JSON over its pipes. The distinction is recorded here rather than
    argued in each of nine hundred files.
    """
    if lang == "javascript" and not rel.startswith("tests/"):
        return "client", "WebPage"
    return "server", "Ext_service"


# ------------------------------------------------------------------- ports --

# I18. `agent/secrets_agent.py`'s socket is the ONLY transport endpoint in this
# package, and it is a filesystem socket with no port number. Detection is
# mechanical so that the map cannot fall behind the code: a function gets the
# entry when its module mentions AF_UNIX AND the function itself performs a
# socket operation. Nine functions qualify today — eight in the agent and
# `agent_call` in the helper, which is the client half.
AGENT_PORT = {
    "name": "secrets-agent",
    "description": ("AF_UNIX socket in a 0700 per-user run dir; peer identity "
                    "from SO_PEERCRED. The only listening surface in this "
                    "package, and it has no port number (I18)."),
    "transport": "unix",
    "protocol": "json-lines",
    "number": None,
}
# An OPERATION, not a mention. `build_parser` and `main` both name SO_PEERCRED
# in their help text; naming the socket is not participating in it, and an
# inventory that cannot tell those apart cannot be used to answer "what listens
# here".
_SOCKET_OP = re.compile(
    r"socket\.socket\s*\(|"
    r"\.(bind|listen|accept|connect|recv|recvmsg|sendall|sendmsg|makefile"
    r"|getsockopt)\s*\(")


def ports_for(module_text: str, span_text: str) -> list[dict]:
    """`[]` for everything that is not the agent's socket. See module docstring."""
    if "AF_UNIX" not in module_text:
        return []
    if not _SOCKET_OP.search(span_text):
        return []
    return [dict(AGENT_PORT)]


# ------------------------------------------------------------------ symbols --


_BANNER = re.compile(r"^[-=*_~#/ ]*$")


def lead_comment(lines: list[str], lineno: int, line_prefix: str,
                 allow_block: bool) -> str:
    """The comment block directly above a definition, cleaned up.

    Handles the three idioms in this tree: a run of `#` lines (Python), a run of
    `//` lines (JS/Go), and a `/* … */` block (JS). One blank line and any
    number of decorator lines may sit between the comment and the `def`.

    A line that is nothing but a rule ("-----------") is dropped, and a section
    banner that carries a title (`/* --- the unlock session --------- *`) is
    dropped too WHEN prose follows it: the prose is the description, and
    prefixing it with the section heading only makes the first sentence read
    like a fragment.
    """
    i = lineno - 2
    while i >= 0 and (lines[i].lstrip().startswith("@") or
                      lines[i].strip() == "" and i == lineno - 2):
        i -= 1
    if i < 0:
        return ""

    def clean(t: str) -> tuple[str, bool]:
        """(text, was-a-rule-banner)."""
        heading = bool(re.search(r"[-=]{3,}", t))
        t = t.strip().strip("-=*_ ").strip()
        return ("", heading) if _BANNER.match(t) else (t, heading)

    s = lines[i].strip()
    if allow_block and s.endswith("*/"):
        block: list[str] = []
        j = i
        while j >= 0:
            t = lines[j].strip()
            block.append(t)
            if t.startswith("/*"):
                break
            j -= 1
        else:
            return ""
        rows = []
        for t in reversed(block):
            t = re.sub(r"^/\*+", "", t)
            t = re.sub(r"\*/\s*$", "", t)
            t = re.sub(r"^\*+", "", t)
            rows.append(clean(t))
    else:
        rows = []
        while i >= 0:
            t = lines[i].strip()
            if not t.startswith(line_prefix):
                break
            rows.append(clean(t[len(line_prefix):]))
            i -= 1
        rows.reverse()

    while rows and rows[0][1] and any(text for text, head in rows[1:] if not head):
        rows.pop(0)
    # Joined with newlines, not spaces: these blocks run to forty lines and
    # `first_paragraph()` needs the blank lines to find where the summary ends
    # and the essay begins.
    return "\n".join(text for text, _ in rows).strip()


class Sym:
    """One extracted symbol, before it becomes YAML."""

    __slots__ = ("name", "kind", "lineno", "end_lineno", "params", "returns",
                 "calls", "doc", "lead", "decorators")

    def __init__(self, name, kind, lineno, end_lineno, params, returns,
                 calls, doc, lead, decorators=()):
        self.name = name
        self.kind = kind
        self.lineno = lineno
        self.end_lineno = end_lineno
        self.params = params
        self.returns = returns
        self.calls = calls
        self.doc = doc
        self.lead = lead
        self.decorators = list(decorators)


# ------------------------------------------------------------ python parsing --

_PY_RET_KIND = {
    ast.Dict: "dict", ast.DictComp: "dict",
    ast.List: "list", ast.ListComp: "list",
    ast.Tuple: "tuple", ast.Set: "set", ast.SetComp: "set",
    ast.JoinedStr: "str", ast.Compare: "bool",
    ast.GeneratorExp: "generator",
}


def _py_return_kind(node: ast.AST) -> str:
    """A coarse, honest return type for an unannotated function.

    This tree carries almost no annotations, and inventing `Any` for every entry
    would make `ReturnType` worthless. Literal shapes cover most of it: the
    verbs return dicts, the predicates return bools. Anything computed by a call
    is reported as `any` rather than guessed at.
    """
    if isinstance(node, ast.Constant):
        v = node.value
        return "None" if v is None else type(v).__name__
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return "bool"
    if isinstance(node, ast.BoolOp):
        return "any"
    for cls, name in _PY_RET_KIND.items():
        if isinstance(node, cls):
            return name
    return "any"


def _py_returns(fn: ast.AST) -> str:
    if getattr(fn, "returns", None) is not None:
        return ast.unparse(fn.returns)
    kinds: set[str] = set()
    has_yield = False
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue                       # a nested def has its own entry
        if isinstance(n, ast.Return):
            kinds.add("None" if n.value is None else _py_return_kind(n.value))
        elif isinstance(n, (ast.Yield, ast.YieldFrom)):
            has_yield = True
        stack.extend(ast.iter_child_nodes(n))
    if has_yield:
        return "generator"
    if not kinds:
        return "None"
    if "any" in kinds:
        # One branch returns a literal and another returns whatever some call
        # produced. `any` is the honest superset; reporting only the literal
        # branch would claim a narrower type than the function has.
        return "any"
    return " | ".join(sorted(kinds))


def _py_params(fn: ast.AST, drop_self: bool) -> list[dict]:
    a = fn.args
    out: list[dict] = []
    positional = list(a.posonlyargs) + list(a.args)
    defaults = list(a.defaults)
    pad = len(positional) - len(defaults)

    def one(arg, default, note=""):
        d = {"name": arg.arg,
             "type": ast.unparse(arg.annotation) if arg.annotation else "any"}
        if default is not None:
            d["default"] = ast.unparse(default)
        if note:
            d["kind"] = note
        out.append(d)

    for i, arg in enumerate(positional):
        if i == 0 and drop_self and arg.arg in ("self", "cls"):
            continue
        one(arg, defaults[i - pad] if i >= pad else None)
    if a.vararg:
        one(a.vararg, None, "vararg")
    for arg, default in zip(a.kwonlyargs, a.kw_defaults):
        one(arg, default, "keyword-only")
    if a.kwarg:
        one(a.kwarg, None, "kwarg")
    return out


def _py_calls(fn: ast.AST) -> list[tuple[str, str]]:
    """(object, attribute) pairs for every call in the body, nested defs aside."""
    out: list[tuple[str, str]] = []
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.append(("", f.id))
            elif isinstance(f, ast.Attribute):
                base = f.value
                obj = base.id if isinstance(base, ast.Name) else (
                    "self" if isinstance(base, ast.Attribute)
                    and isinstance(base.value, ast.Name)
                    and base.value.id == "self" else "")
                out.append((obj, f.attr))
        stack.extend(ast.iter_child_nodes(n))
    return out


def parse_python(path: Path, text: str) -> tuple[list[Sym], dict]:
    tree = ast.parse(text, filename=str(path))
    lines = text.splitlines()
    syms: list[Sym] = []
    # `from .base import Invalid, Secret` — used to resolve cross-module calls.
    imported: dict[str, str] = {}
    classes: dict[str, str] = {}          # qualname of every class, for `self.`

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = alias.name

    def walk(node, prefix, in_class):
        # Descends through `if`/`try`/`with`/`for` as well as class and function
        # bodies: `tests/integration/killshim_sitecustomize.py` defines its
        # interposer inside an `if`, and a walker that only looked at `.body`
        # of defs and classes silently lost it.
        for n in ast.iter_child_nodes(node):
            if isinstance(n, ast.ClassDef):
                classes[prefix + n.name] = prefix + n.name
                walk(n, prefix + n.name + ".", True)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = prefix + n.name
                decs = [ast.unparse(d) for d in n.decorator_list]
                kind = "async function" if isinstance(n, ast.AsyncFunctionDef) \
                    else ("method" if in_class else "function")
                if "staticmethod" in decs:
                    kind = "static method"
                elif "classmethod" in decs:
                    kind = "class method"
                elif "property" in decs:
                    kind = "property"
                syms.append(Sym(
                    name=q, kind=kind, lineno=n.lineno,
                    end_lineno=getattr(n, "end_lineno", n.lineno),
                    params=_py_params(n, in_class and "staticmethod" not in decs),
                    returns=_py_returns(n),
                    calls=_py_calls(n),
                    doc=ast.get_docstring(n) or "",
                    lead=lead_comment(lines, n.lineno, "#", False),
                    decorators=decs))
                walk(n, q + ".", False)
            else:
                walk(n, prefix, in_class)

    walk(tree, "", False)
    return syms, {"imported": imported, "classes": classes}


# -------------------------------------------------------- javascript parsing --

# Driven through gjs, which is SpiderMonkey. `Reflect.parse` is a real parser
# and gives the Mozilla Parser API AST; check.sh already requires gjs, so this
# adds no dependency the project did not have.
GJS_EXTRACTOR = r"""
// Emitted by gen_function_map.py. Reads a JS file, prints one JSON array of
// named functions with their qualified names, params, calls and return shapes.
const [file] = ARGV;
const bytes = imports.gi.GLib.file_get_contents(file)[1];
const src = imports.byteArray ? imports.byteArray.toString(bytes)
                              : new TextDecoder().decode(bytes);
const ast = Reflect.parse(src, { source: file, loc: true });

const out = [];

function pname(p) {
    if (!p) return "_";
    if (p.type === "Identifier") return p.name;
    if (p.type === "AssignmentPattern") return pname(p.left);
    if (p.type === "RestElement") return "..." + pname(p.argument);
    if (p.type === "ObjectPattern") return "{destructured}";
    if (p.type === "ArrayPattern") return "[destructured]";
    return "_";
}

function retKind(n) {
    if (!n) return "undefined";
    switch (n.type) {
    case "ObjectExpression": return "object";
    case "ArrayExpression": return "array";
    case "Literal":
        if (n.value === null) return "null";
        return typeof n.value;
    case "TemplateLiteral": return "string";
    case "BinaryExpression":
        return (["==","!=","===","!==","<",">","<=",">=","in","instanceof"]
                .indexOf(n.operator) >= 0) ? "boolean" : "any";
    case "UnaryExpression": return n.operator === "!" ? "boolean" : "any";
    case "FunctionExpression":
    case "ArrowFunctionExpression": return "function";
    case "NewExpression": return "object";
    default: return "any";
    }
}

// A function literal usually has no id of its own in this codebase — it is
// `s.send = function (body) {...}` or `const scen = (over) => {...}`. The name
// therefore comes from the construct that BINDS it, handed down as `pending`.
// Without this, `openSession.send`, the four `s.*` session methods and every
// arrow-bound helper in the test drivers are anonymous and vanish from the map.
function bindingName(node) {
    if (!node) return null;
    switch (node.type) {
    case "Identifier": return node.name;
    case "Literal":    return String(node.value);
    case "MemberExpression":
        if (node.property && node.property.type === "Identifier") {
            const obj = (node.object && node.object.type === "Identifier")
                      ? node.object.name + "." : "";
            return obj + node.property.name;
        }
        return null;
    default: return null;
    }
}

// Walk every node, tracking the innermost NAMED function so anonymous
// callbacks do not break the qualified name of a function declared inside one.
function walk(node, scope, owner, pending) {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
        for (const c of node) walk(c, scope, owner, null);
        return;
    }
    if (!node.type) return;

    const isFn = node.type === "FunctionDeclaration"
              || node.type === "FunctionExpression"
              || node.type === "ArrowFunctionExpression";

    if (isFn) {
        const nm = (node.id && node.id.name) ? node.id.name : pending;
        let rec = owner;
        if (nm) {
            // A "#" prefix marks a function bound as an object-literal or class
            // MEMBER, and it is load-bearing: secrets.js `makeControl` contains
            // both a private `function validate()` and a `validate:` member of
            // the object it returns. Without the marker both are
            // "makeControl.validate" and one silently overwrites the other.
            const qual = nm.charAt(0) === "#"
                       ? (scope ? scope + nm : nm)
                       : (scope ? scope + "." + nm : nm);
            rec = {
                name: qual, plain: nm,
                kind: node.type === "ArrowFunctionExpression"
                     ? (node.async ? "async arrow function" : "arrow function")
                     : (node.generator ? "generator function"
                        : (node.async ? "async function" : "function")),
                line: node.loc.start.line, end: node.loc.end.line,
                params: (node.params || []).map(pname),
                calls: [], returns: [], scope: scope
            };
            out.push(rec);
            scope = qual;
        }
        // An expression-bodied arrow returns its expression; there is no
        // ReturnStatement to pick that up from.
        if (rec && node.body && node.body.type !== "BlockStatement")
            rec.returns.push(retKind(node.body));
        walk(node.body, scope, rec, null);
        return;
    }

    if (node.type === "CallExpression" || node.type === "NewExpression") {
        const c = node.callee;
        if (owner && c) {
            if (c.type === "Identifier") owner.calls.push(["", c.name]);
            else if (c.type === "MemberExpression" && c.property
                     && c.property.type === "Identifier") {
                const obj = (c.object && c.object.type === "Identifier")
                          ? c.object.name : "";
                owner.calls.push([obj, c.property.name]);
            }
        }
    }
    if (node.type === "ReturnStatement" && owner)
        owner.returns.push(retKind(node.argument));

    // The constructs that give a function literal a name.
    let namedChild = null, namedAs = null;
    if (node.type === "VariableDeclarator" && node.init) {
        namedChild = node.init; namedAs = bindingName(node.id);
    } else if (node.type === "AssignmentExpression" && node.operator === "="
               && node.right) {
        namedChild = node.right; namedAs = bindingName(node.left);
    } else if ((node.type === "Property" || node.type === "MethodDefinition")
               && node.value && node.key) {
        const kn = bindingName(node.key);
        namedChild = node.value; namedAs = kn === null ? null : "#" + kn;
    }

    for (const k in node) {
        if (k === "loc" || k === "type") continue;
        const child = node[k];
        walk(child, scope, owner,
             (namedChild !== null && child === namedChild) ? namedAs : null);
    }
}

walk(ast, "", null, null);
print(JSON.stringify(out));
"""


def parse_javascript(path: Path, text: str) -> tuple[list[Sym], dict]:
    gjs = shutil.which("gjs")
    if not gjs:
        raise SystemExit(
            "gen_function_map.py: gjs is not installed, so secrets.js cannot be\n"
            "parsed. This generator will not fall back to a regex scanner: a map\n"
            "built from a guess is worse than no map. Install it with:\n"
            "    apt-get install gjs")
    with tempfile.TemporaryDirectory(prefix="fnmap-js-") as td:
        script = Path(td) / "extract.js"
        script.write_text(GJS_EXTRACTOR, encoding="utf-8")
        proc = subprocess.run([gjs, str(script), str(path)],
                              capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("gen_function_map.py: gjs failed on %s\n%s"
                         % (path, proc.stderr.strip()))
    raw = json.loads(proc.stdout)
    lines = text.splitlines()

    syms = []
    for r in raw:
        rets = sorted(set(r["returns"])) or ["undefined"]
        if len(rets) > 1 and "any" in rets:
            rets = ["any"]
        syms.append(Sym(
            name=r["name"], kind=r["kind"], lineno=r["line"], end_lineno=r["end"],
            params=[{"name": p, "type": "any"} for p in r["params"]],
            returns=" | ".join(rets),
            calls=[tuple(c) for c in r["calls"]],
            doc="", lead=lead_comment(lines, r["line"], "//", True)))
    return syms, {"imported": {}, "classes": {}}


# ---------------------------------------------------------------- go parsing --

GO_EXTRACTOR = r"""
// Emitted by gen_function_map.py. go/parser over one file; JSON on stdout.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type fn struct {
	Name    string     `json:"name"`
	Kind    string     `json:"kind"`
	Line    int        `json:"line"`
	End     int        `json:"end"`
	Params  []param    `json:"params"`
	Returns string     `json:"returns"`
	Calls   [][]string `json:"calls"`
	Doc     string     `json:"doc"`
}

func typeString(fset *token.FileSet, src []byte, e ast.Expr) string {
	if e == nil {
		return ""
	}
	return string(src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
}

type namedLit struct {
	name string
	lit  *ast.FuncLit
}

// params + result signature, rendered from the source bytes so the text is
// exactly what the author wrote.
func signature(fset *token.FileSet, src []byte, ft *ast.FuncType) ([]param, string) {
	ps := []param{}
	if ft.Params != nil {
		for _, fl := range ft.Params.List {
			t := typeString(fset, src, fl.Type)
			if len(fl.Names) == 0 {
				ps = append(ps, param{Name: "_", Type: t})
			}
			for _, n := range fl.Names {
				ps = append(ps, param{Name: n.Name, Type: t})
			}
		}
	}
	rets := []string{}
	if ft.Results != nil {
		for _, fl := range ft.Results.List {
			t := typeString(fset, src, fl.Type)
			n := len(fl.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				rets = append(rets, t)
			}
		}
	}
	rs := strings.Join(rets, ", ")
	if len(rets) > 1 {
		rs = "(" + rs + ")"
	}
	if rs == "" {
		rs = "void"
	}
	return ps, rs
}

// Calls made directly by this body. A FuncLit bound to a name is skipped —
// it becomes its own entry — while an anonymous callback's calls are
// attributed to the function that contains it, matching what the Python and
// JavaScript extractors do.
func bodyCalls(body ast.Node) ([][]string, []namedLit) {
	calls := [][]string{}
	lits := []namedLit{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if id, ok := x.Lhs[0].(*ast.Ident); ok {
					if fl, ok := x.Rhs[0].(*ast.FuncLit); ok {
						lits = append(lits, namedLit{id.Name, fl})
						return false
					}
				}
			}
		case *ast.ValueSpec:
			if len(x.Names) == 1 && len(x.Values) == 1 {
				if fl, ok := x.Values[0].(*ast.FuncLit); ok {
					lits = append(lits, namedLit{x.Names[0].Name, fl})
					return false
				}
			}
		case *ast.CallExpr:
			switch c := x.Fun.(type) {
			case *ast.Ident:
				calls = append(calls, []string{"", c.Name})
			case *ast.SelectorExpr:
				obj := ""
				if id, ok := c.X.(*ast.Ident); ok {
					obj = id.Name
				}
				calls = append(calls, []string{obj, c.Sel.Name})
			}
		}
		return true
	})
	return calls, lits
}

func main() {
	// The path arrives in the environment, not on argv: `go run prog.go x.go`
	// would treat a trailing .go argument as a second file to compile.
	path := os.Getenv("FNMAP_GO_FILE")
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := []fn{}

	// Named closures are symbols too, and they nest, so this is recursive.
	var emitLits func(prefix string, lits []namedLit)
	emitLits = func(prefix string, lits []namedLit) {
		for _, nl := range lits {
			ps, rs := signature(fset, src, nl.lit.Type)
			calls, inner := bodyCalls(nl.lit.Body)
			qual := prefix + "." + nl.name
			out = append(out, fn{
				Name: qual, Kind: "closure",
				Line:   fset.Position(nl.lit.Pos()).Line,
				End:    fset.Position(nl.lit.End()).Line,
				Params: ps, Returns: rs, Calls: calls, Doc: "",
			})
			emitLits(qual, inner)
		}
	}

	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		kind := "function"
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			kind = "method"
			rt := typeString(fset, src, fd.Recv.List[0].Type)
			name = strings.TrimPrefix(rt, "*") + "." + name
		}
		ps, rs := signature(fset, src, fd.Type)
		calls, lits := bodyCalls(fd)
		doc := ""
		if fd.Doc != nil {
			doc = strings.TrimSpace(fd.Doc.Text())
		}
		out = append(out, fn{
			Name: name, Kind: kind,
			Line: fset.Position(fd.Pos()).Line,
			End:  fset.Position(fd.End()).Line,
			Params: ps, Returns: rs, Calls: calls, Doc: doc,
		})
		emitLits(name, lits)
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
}
"""


def parse_go(path: Path, text: str) -> tuple[list[Sym], dict]:
    go = shutil.which("go")
    if not go:
        raise SystemExit(
            "gen_function_map.py: the Go toolchain is not installed, so\n"
            "tests/oracle/pws3_oracle.go cannot be parsed. `go/parser` is\n"
            "stdlib and needs no network. Install Go, or drop the .go file.")
    with tempfile.TemporaryDirectory(prefix="fnmap-go-") as td:
        prog = Path(td) / "extract.go"
        prog.write_text(GO_EXTRACTOR, encoding="utf-8")
        env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod",
                   FNMAP_GO_FILE=str(path),
                   GOCACHE=os.environ.get("GOCACHE",
                                          str(Path.home() / ".cache" / "go-build")))
        proc = subprocess.run([go, "run", str(prog)],
                              capture_output=True, text=True, cwd=td, env=env)
    if proc.returncode != 0:
        raise SystemExit("gen_function_map.py: go/parser failed on %s\n%s"
                         % (path, proc.stderr.strip()))
    raw = json.loads(proc.stdout)
    lines = text.splitlines()
    syms = []
    for r in raw:
        syms.append(Sym(
            name=r["name"], kind=r["kind"], lineno=r["line"], end_lineno=r["end"],
            params=r["params"], returns=r["returns"],
            calls=[tuple(c) for c in r["calls"]],
            doc=r["doc"], lead=lead_comment(lines, r["line"], "//", True)))
    return syms, {"imported": {}, "classes": {}}


PARSERS = {"python": parse_python, "javascript": parse_javascript, "go": parse_go}


# ------------------------------------------------------------- descriptions --

_WS = re.compile(r"\s+")
_SENT = re.compile(r"(?<=[.!?])\s")


def first_paragraph(s: str, limit: int = 480) -> str:
    """First sentence(s) of a docstring or comment, whitespace-collapsed."""
    s = s.strip()
    if not s:
        return ""
    para = s.split("\n\n")[0]
    para = _WS.sub(" ", para).strip()
    if len(para) <= limit:
        return para
    cut = para[:limit]
    parts = _SENT.split(cut)
    if len(parts) > 1:
        return " ".join(parts[:-1]).strip()
    return cut.rsplit(" ", 1)[0] + "…"


def describe(sym: Sym, rel: str) -> str:
    """Prefer the author's own words; state plainly when there are none.

    The fallback is deliberately structural. Paraphrasing an identifier into a
    sentence ("Handles the entry") would put nine hundred confident-sounding
    inventions into a document whose whole value is that it can be trusted, so
    the generator says what it knows — where the function is, what it takes,
    what it gives back — and says outright that the source documented nothing.
    """
    d = first_paragraph(sym.doc) or first_paragraph(sym.lead)
    if d:
        return d
    args = ", ".join(p["name"] for p in sym.params) or "no arguments"
    return ("Not documented in the source (no docstring, no leading comment). "
            "%s defined at %s:%d-%d; takes %s; returns %s."
            % (sym.kind.capitalize(), rel, sym.lineno, sym.end_lineno,
               args, sym.returns))


# ------------------------------------------------- tasks (I-ids and TODOs) ---

ISSUE_RE = re.compile(r"\bI([1-9]|1[0-9]|2[0-2])\b")
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b[:\s]*(.{0,160})")


def tasks_for(span: str) -> tuple[list[str], list[str]]:
    """CompletedTasks / PendingTasks, read out of the code itself.

    `CompletedTasks` are the KNOWN_ISSUES hazard ids the function's own comments
    cite — this tree cites them constantly and at the point of the mitigation,
    so the citation IS the record of which hazard the function closes.
    `PendingTasks` are TODO/FIXME/XXX/HACK markers in the same span.
    """
    done = sorted({"docs/KNOWN_ISSUES.md#I" + m for m in ISSUE_RE.findall(span)},
                  key=lambda s: int(s.rsplit("I", 1)[1]))
    pend = []
    for kind, rest in TODO_RE.findall(span):
        rest = _WS.sub(" ", rest).strip(" -–—*/#")
        pend.append("%s: %s" % (kind, rest) if rest else kind)
    return done, sorted(set(pend))


# -------------------------------------------------------------- references ---


def resolve_calls(sym: Sym, module_index: dict, global_index: dict,
                  meta: dict, lang: str) -> list[str]:
    """Turn raw call sites into FunctionNames that exist in this map.

    Resolution order, most specific first:
      1. `self.x()`     -> `<EnclosingClass>.x`
      2. a nested sibling in the same enclosing scope
      3. a symbol in the same module
      4. a name this module imported, matched against the whole map
      5. a name unique across the whole map
      6. `Type(...)` in Python -> `Type.__init__`
    Anything that does not resolve is dropped rather than recorded as a dangling
    edge: a reference to something outside this package (`json.dumps`,
    `pykeepass.PyKeePass`) is a dependency, not a function-map edge.
    """
    owner = sym.name.rsplit(".", 1)[0] if "." in sym.name else ""
    out: set[str] = set()
    for obj, attr in sym.calls:
        cands: list[str] = []
        if obj == "self" and owner:
            cands.append(owner + "." + attr)
        if obj and obj not in ("self",):
            cands.append(obj + "." + attr)                       # Cls.method()
            if lang == "python" and obj in meta.get("imported", {}):
                cands.append(meta["imported"][obj] + "." + attr)
        if not obj:
            if owner:
                cands.append(owner + "." + attr)                 # sibling nested
            cands.append(attr)
            if lang == "python":
                cands.append(attr + ".__init__")                 # constructor
        for c in cands:
            if c in module_index:
                out.add(module_index[c])
                break
            if c in global_index and len(global_index[c]) == 1:
                out.add(global_index[c][0])
                break
    out.discard(sym.name)
    return sorted(out)


# -------------------------------------------------------------- yaml output --


def yaml_str(s: str) -> str:
    """Double-quoted YAML scalar. Explicit, so nothing is ever re-typed as a
    bool, a number, a date or null by the reader's implicit typing rules."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') \
                 .replace("\n", " ").replace("\t", " ") + '"'


def dump_entry(e: dict) -> str:
    L: list[str] = []
    L.append("# Generated by function-map/gen_function_map.py — do not hand-edit.")
    L.append("# Regenerate with:  ./function-map/gen_function_map.py")
    L.append("FunctionName: %s" % yaml_str(e["FunctionName"]))
    L.append("Module:")
    L.append("  Name: %s" % yaml_str(e["Module"]["Name"]))
    L.append("  RelativePath: %s" % yaml_str(e["Module"]["RelativePath"]))
    L.append("  LastWriteTime: %s" % yaml_str(e["Module"]["LastWriteTime"]))
    L.append("Description: %s" % yaml_str(e["Description"]))
    if e["Parameters"]:
        L.append("Parameters:")
        for p in e["Parameters"]:
            keys = [k for k in ("name", "type", "default", "kind", "description")
                    if k in p]
            L.append("  - " + "\n    ".join(
                "%s: %s" % (k, yaml_str(str(p[k]))) for k in keys))
    else:
        L.append("Parameters: []")
    L.append("ReturnType: %s" % yaml_str(e["ReturnType"]))
    if e["References"]:
        L.append("References:")
        L.extend("  - %s" % yaml_str(r) for r in e["References"])
    else:
        L.append("References: []")
    for key in ("CompletedTasks", "PendingTasks"):
        if e[key]:
            L.append("%s:" % key)
            L.extend("  - %s" % yaml_str(v) for v in e[key])
        else:
            L.append("%s: []" % key)
    L.append("ReplacedBy: %s" % (yaml_str(e["ReplacedBy"])
                                 if e["ReplacedBy"] else "null"))
    L.append("DateCreated: %s" % yaml_str(e["DateCreated"]))
    L.append("DateModified: %s" % yaml_str(e["DateModified"]))
    L.append("service-type: %s" % yaml_str(e["service-type"]))
    if e["ports"]:
        L.append("ports:")
        for p in e["ports"]:
            L.append("  - name: %s" % yaml_str(p["name"]))
            L.append("    description: %s" % yaml_str(p["description"]))
            L.append("    transport: %s" % yaml_str(p["transport"]))
            L.append("    protocol: %s" % yaml_str(p["protocol"]))
            L.append("    number: %s" % ("null" if p["number"] is None
                                         else int(p["number"])))
    else:
        # The whole point of the exercise: this package listens on nothing.
        L.append("ports: []")
    return "\n".join(L) + "\n"


DATE_RE = re.compile(r'^DateCreated:\s*"([^"]+)"', re.M)


def _date_created(target: Path, fallback: str) -> str:
    """Keep the original DateCreated so regeneration is idempotent over time."""
    try:
        m = DATE_RE.search(target.read_text(encoding="utf-8"))
        if m:
            return m.group(1)
    except OSError:
        pass
    return fallback


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc) \
             .replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------- main --


def _disambiguate(syms: list[Sym], rel: str) -> None:
    """Make every qualified name unique within its module, deterministically.

    Qualification handles almost everything, but not two object literals in one
    function that each declare a member of the same name — `renderDetail` in
    `secrets.js` builds four separate reveal widgets, each with its own
    `fetch:`. When a name collides, EVERY symbol carrying it (not just the
    later ones) gains an `@<line>` suffix, so the result does not depend on
    which one the parser happened to reach first and adding a fifth does not
    rename the other four's neighbours.
    """
    seen: dict[str, int] = {}
    for s in syms:
        seen[s.name] = seen.get(s.name, 0) + 1
    for s in syms:
        if seen[s.name] > 1:
            s.name = "%s@%d" % (s.name, s.lineno)


def build() -> dict[Path, str]:
    """Render the whole tree in memory. Nothing is written by this function."""
    modules = discover_modules()
    parsed: list[dict] = []
    global_index: dict[str, list[str]] = {}

    for path in modules:
        rel = str(path.relative_to(SOURCE)).replace("\\", "/")
        lang = language_of(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        syms, meta = PARSERS[lang](path, text)
        _disambiguate(syms, rel)
        side, service = classify(rel, lang)
        parsed.append({"path": path, "rel": rel, "lang": lang, "text": text,
                       "syms": syms, "meta": meta, "side": side,
                       "service": service,
                       "mtime": iso(path.stat().st_mtime)})
        for s in syms:
            global_index.setdefault(s.name, []).append(s.name)
            plain = s.name.rsplit(".", 1)[-1]
            if plain != s.name:
                global_index.setdefault(plain, []).append(s.name)

    files: dict[Path, str] = {}
    for m in parsed:
        rel, lang, text = m["rel"], m["lang"], m["text"]
        lines = text.splitlines()
        mod_dir = HERE / m["side"] / lang / re.sub(r"\.(py|js|go)$", "", rel)
        module_index = {s.name: s.name for s in m["syms"]}
        for s in m["syms"]:
            module_index.setdefault(s.name.rsplit(".", 1)[-1], s.name)
        for s in m["syms"]:
            span = "\n".join(lines[max(0, s.lineno - 4):s.end_lineno])
            done, pend = tasks_for(span)
            entry = {
                "FunctionName": s.name,
                "Module": {
                    "Name": Path(rel).name,
                    "RelativePath": rel,
                    "LastWriteTime": m["mtime"],
                },
                "Description": describe(s, rel),
                "Parameters": s.params,
                "ReturnType": s.returns,
                "References": resolve_calls(s, module_index, global_index,
                                            m["meta"], lang),
                "CompletedTasks": done,
                "PendingTasks": pend,
                "ReplacedBy": None,
                "DateCreated": m["mtime"],
                "DateModified": m["mtime"],
                "service-type": m["service"],
                "ports": ports_for(text, span),
            }
            target = mod_dir / (s.name + ".yaml")
            if target in files:
                # Two symbols in one module claiming one filename would make the
                # second silently overwrite the first, and the map would be
                # quietly incomplete — the one failure mode this inventory
                # exists to prevent. Refuse loudly instead.
                raise SystemExit(
                    "gen_function_map.py: two symbols in %s both map to %s "
                    "(qualification is not enough here). Fix the extractor's "
                    "naming before regenerating." % (rel, target.name))
            entry["DateCreated"] = _date_created(target, m["mtime"])
            files[target] = dump_entry(entry)
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if the tree is not up to date")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    files = build()
    existing = {p for p in HERE.rglob("*.yaml")}
    wanted = set(files)

    changed, created, removed = [], [], sorted(existing - wanted)
    for target, body in sorted(files.items()):
        if not target.exists():
            created.append(target)
        elif target.read_text(encoding="utf-8") != body:
            changed.append(target)

    if a.check:
        drift = created + changed + removed
        for p in drift:
            print("out of date: %s" % p.relative_to(HERE))
        if not a.quiet:
            print("%d entries, %d out of date" % (len(files), len(drift)))
        return 1 if drift else 0

    for p in removed:
        p.unlink()
    for target, body in sorted(files.items()):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    # Prune directories the last run emptied, so a renamed module does not
    # leave a husk behind.
    for d in sorted((p for p in HERE.rglob("*") if p.is_dir()),
                    key=lambda p: len(p.parts), reverse=True):
        if not any(d.iterdir()):
            d.rmdir()

    if not a.quiet:
        with_ports = sum(1 for b in files.values() if "\nports: []" not in b)
        print("function-map: %d entries "
              "(%d new, %d changed, %d removed); "
              "%d with a transport endpoint, %d with none"
              % (len(files), len(created), len(changed), len(removed),
                 with_ports, len(files) - with_ports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
