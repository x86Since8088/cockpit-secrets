# function-map — every function in this package, as data

One YAML file per function, validated against the canonical schemas in
`ai-orchestrator/schemas/function-map/`. It is **generated**, never
hand-maintained, and the generator is the thing to review:

```sh
./function-map/gen_function_map.py            # rewrite the tree
./function-map/gen_function_map.py --check    # exit 1 if it is out of date
./function-map/validate_function_map.py       # exit 1 if anything is invalid
```

Regeneration is idempotent — two runs over an unchanged tree produce
byte-identical files, proved on a frozen snapshot of the source — so `--check`
is safe to wire into a gate. Three files here are not entries:
`gen_function_map.py`, `validate_function_map.py` and this README.

---

## Why generated

A password manager is exactly the kind of program where an inventory that has
quietly gone stale is worse than no inventory: somebody asks "what listens on
this host?", reads a file that describes last month's code, and answers wrong.
Nine hundred YAML files cannot be kept true by hand. So the map is derived
from the source, the derivation is one reviewable script, and the script says
plainly where the source told it nothing.

## Layout

**911 entries** at the last regeneration:

```
function-map/
├── client/javascript/
│   └── secrets/ ......................................... 223   secrets.js, the page
├── server/javascript/
│   └── tests/browser/{harness,ui.spec}/ .................  14   Node, drives a browser
├── server/python/
│   ├── secrets-admin/ ................................... 149   the helper
│   ├── agent/secrets_agent/ .............................  65   the unlock agent (I18)
│   ├── backends/{base,kdbx,psafe3,twofish_pure}/ ......... 349
│   └── tests/{corpus,fixtures,integration}/**/ ..........  77
└── server/go/
    └── tests/oracle/pws3_oracle/ ........................  34   the PWS3 oracle
```

The brief said `function-map/{client,server}/{javascript,python,go}/<FunctionName>.yaml`.
There is one extra path segment here — the **module** — and it is not
decoration:

* `_note` exists in both `secrets-admin` and `backends/base.py`;
  `_selfcheck`, `_selfcheck.ok` and `_selfcheck.raises` exist in both
  `backends/base.py` and `backends/psafe3.py`; `main` exists in seven modules.
  A flat directory would have silently overwritten one entry with another, and
  the map would have been wrong in exactly the way this exercise exists to
  prevent.
* The schema set's own example paths already carry a module segment —
  `server/python/coordinator/_dispatch_next.yaml` in
  `schemas/function-map/dependency_ref.yaml`.

`FunctionName` still equals the filename, as required.

### How a name is built

| Form | Example | Meaning |
|---|---|---|
| bare | `harden_process` | a module-level function |
| `Class.method` | `KdbxBackend.unlock`, `randSource.fill` | a method (Go methods use the receiver type) |
| `outer.inner` | `Psafe3Backend._ensure_lossless.describe`, `openSession.consume`, `doWrite.optHex` | a function nested inside another, including named Go closures |
| `outer.obj.prop` | `openSession.s.send` | a function literal assigned to a member (`s.send = function …`) |
| `outer#prop` | `makeControl#validate`, `buildForm#wipeSecrets` | a function literal that is a **member of an object literal** — `{ validate: function () {…} }`. The `#` is load-bearing: `makeControl` contains *both* a private `function validate()` and a `validate:` member of the object it returns, and without the marker one would silently overwrite the other |
| `…@<line>` | `renderDetail#fetch@3449` | last-resort disambiguation when a name still collides — `renderDetail` builds four reveal widgets, each with its own `fetch:`. When a name collides, **every** symbol carrying it gains the suffix, so the result does not depend on which one the parser reached first |

The generator **refuses to run** rather than let two symbols write the same
file; see the `SystemExit` in `build()`. A silently incomplete inventory is the
one outcome worse than none.

## How the symbols are extracted

Nothing is guessed at by regex where a real parser exists:

| Language | Parser | Notes |
|---|---|---|
| Python | stdlib `ast` | walks into `if`/`try`/`with` bodies too — `tests/integration/killshim_sitecustomize.py` defines its interposer inside an `if`, and a walker that only looked at class and function bodies lost it |
| JavaScript | SpiderMonkey `Reflect.parse()` via `gjs` | `check.sh` already requires `gjs`, so this adds no dependency. `secrets.js` is one 3 000-line IIFE of nested functions; brace counting would mis-nest them. The walker also resolves the name of an *anonymous* function literal from whatever binds it — `var`/`const` declarator, assignment, object property, class method — because almost every function in this codebase is bound that way rather than declared with an `id` |
| Go | `go/parser` via a throwaway `go run` program | stdlib only, `GOPROXY=off`, no network. Also captures named closures (`add := func(...)`) as `<enclosing>.<name>`, and excludes a named closure's calls from its parent while attributing an *anonymous* callback's calls to the parent — matching what the other two extractors do |

Both helper programs are embedded in `gen_function_map.py` as strings and
written to a temp dir at run time, so this directory stays "one generator, one
README, and YAML". If `gjs` or `go` is missing the generator **fails loudly**
rather than falling back to a regex scanner: a map built from a guess is worse
than no map.

## Field conventions

| Field | Where it comes from |
|---|---|
| `Description` | the function's own docstring, else the comment block directly above it, else a **structural** sentence that says outright that the source documented nothing and gives the location, arguments and return type. Identifiers are never paraphrased into invented prose. Currently **529 of 911** entries carry the author's own words and **382** carry the structural fallback — those 382 are where the source has neither a docstring nor a comment, and the map says so instead of making something up |
| `Parameters[]` | the real signature: names, annotations where they exist (`any` where they do not), defaults, and `kind` for varargs / keyword-only / `**kwargs`. Go and the Go closures carry their real types |
| `ReturnType` | the annotation when there is one; otherwise inferred from the `return` statements — literal shapes give `dict`, `list`, `bool`, `str`…, a `yield` gives `generator`, and anything computed by a call gives `any`. `any` wins over a concrete kind when a function mixes them, because the narrower answer would be a claim the code does not support |
| `References[]` | call sites resolved to FunctionNames **that exist in this map**: `self.x()` → `<Class>.x`, then a nested sibling, then the same module, then an imported name, then a globally unique name, and in Python `Type(...)` → `Type.__init__`. A call that resolves to nothing in the map (`json.dumps`, `pykeepass.PyKeePass`) is dropped rather than recorded as a dangling edge — that is a dependency, not a function-map edge |
| `CompletedTasks[]` | the `docs/KNOWN_ISSUES.md` hazard ids the function's own comments cite. This tree cites them constantly and *at the point of the mitigation*, so the citation is the record of which hazard the code closes. **213 of 911** entries cite at least one, which also makes the map a usable index into the hazard register: `grep -rl 'KNOWN_ISSUES.md#I10' function-map/` lists every function that claims to close I10 |
| `PendingTasks[]` | `TODO` / `FIXME` / `XXX` / `HACK` markers inside the function's span. **Empty on every entry today** — there is not one such marker anywhere in this tree |
| `ReplacedBy` | `null` throughout — nothing in this package supersedes anything yet |
| `DateCreated` | preserved from the existing entry when there is one, so regeneration does not rewrite history; the module's mtime otherwise |
| `DateModified`, `Module.LastWriteTime` | the module file's mtime, UTC, whole seconds |
| `service-type` | `WebPage` for `secrets.js`, `Ext_service` for everything that runs outside the browser |
| `ports[]` | see below |

### `service-type`: why nothing here is `API`

The schema's own gloss would let the helper's verbs claim `API` ("CLI
subcommands"), and that reading is defensible. This project pins `Ext_service`
for every server-side symbol instead, because the only consumer — the Cockpit
page — reaches all of them by spawning an external process and speaking JSON
over its pipes. The rule is written once, in `classify()`, rather than argued
in nine hundred files.

## `ports` — the point of the exercise

**cockpit-secrets opens no TCP port at all.** The browser half reaches the
helper through `cockpit.spawn`, which is a process and a pipe; the helper
reaches the safe through a file descriptor. There is no HTTP listener, no
socket bound to an address, nothing for `ss -ltn` to find.

So **902 of the 911 entries carry `ports: []`**, and that emptiness is the
record. The only nine non-empty entries are the functions that actually operate
the `secrets-agent` AF_UNIX socket (I18) — a filesystem socket with
`transport: unix`, `protocol: json-lines` and `number: null`, because it has no
port number to record:

```
server/python/agent/secrets_agent/take_listen_fds     server/python/agent/secrets_agent/Server._accept
server/python/agent/secrets_agent/bind_socket         server/python/agent/secrets_agent/Server._readable
server/python/agent/secrets_agent/peer_credentials    server/python/agent/secrets_agent/_talk
server/python/agent/secrets_agent/_send               server/python/agent/secrets_agent/_talk_raw
server/python/secrets-admin/agent_call
```

Check it from the inventory rather than from prose:

```sh
# every entry that declares a transport endpoint — the nine above
grep -rl --include='*.yaml' 'transport: "unix"' function-map/

# nothing anywhere declares a TCP or UDP one
grep -rn --include='*.yaml' 'transport: "\(tcp\|udp\)"' function-map/
echo "exit $? (1 = none, which is the expected answer)"
```

Detection is mechanical, so the map cannot fall behind the code: a function
gets the entry when its module mentions `AF_UNIX` **and** the function itself
performs a socket operation (`socket.socket(`, `.bind(`, `.listen(`,
`.accept(`, `.connect(`, `.recv(`, `.sendall(`, `.getsockopt(`, …). Naming the
socket is not participating in it — `build_parser` and `main` both mention
`SO_PEERCRED` in their help text and correctly get `ports: []`.

## Validation

The canonical validator ships with the orchestrator and is what this tree is
checked against:

```sh
cd /srv/smb/share/sc/ai-orchestrator-group/ai-orchestrator
python3 ai-orchestrator.py function-map validate --strict \
    --project cockpit-secrets \
    --root .../projects/cockpit-secrets/source/function-map
```

It uses `jsonschema` Draft-07 against
`schemas/function-map/{function_entry,service_type,port_spec}.yaml` and prints
one line per file plus a count. `--strict` additionally rejects any
`service-type` outside the enum. Last run: **911 files, 0 failures, strict.**

That validator resolves the two `$ref` siblings through its own loader, and "a
loader agreeing with itself" is not evidence of anything. So this tree is also
checked a second way, by a script that ships beside the generator:

```sh
./function-map/validate_function_map.py
# 911 files, 0 schema failure(s), 0 filename mismatch(es)
```

It reads the three canonical schema **files**, inlines the `$ref` siblings by
hand, asserts no unresolved `$ref` survived, runs `jsonschema`'s Draft-07
validator directly, and additionally enforces the one rule that lives in prose
rather than in the schema — **`FunctionName` must equal the filename**. If
`jsonschema` or `PyYAML` is missing it exits **2** and says nothing was
validated, because a missing tool is not a pass.

### One thing to know about the schema set

`schemas/function-map/index.yaml` describes itself as **revision 3** and says
that revision tightened `References[]` to the structured `dependency_ref`
shape. The `function_entry.yaml` actually on disk is the earlier form:
`References` is `oneOf [array of strings, object]`, and `port_spec.yaml` has no
`urls` key. This tree is generated to match **the schema files that exist**,
not the changelog in `index.yaml`, and it validates clean against them. If
`function_entry.yaml` is later updated to the shape `index.yaml` advertises,
`resolve_calls()` and `dump_entry()` are the two functions to change, and the
map can be regenerated in under a second.
