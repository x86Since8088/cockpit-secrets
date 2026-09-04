# Oracles — the foreign implementations compliance is measured against

`docs/KNOWN_ISSUES.md` **I19**: *"a reader and a writer that share a bug
round-trip perfectly and interoperate with nothing."*

Nothing in this directory is part of the product. Nothing here is installed, and
nothing here may ever be imported, exec'd or shelled out to by `secrets-admin`,
`backends/`, `agent/` or the plugin. These are the second opinions.

| Tool | What it is | Foreign? |
|---|---|---|
| `kdbx_oracle.sh` | a wrapper over the installed `keepassxc-cli` 2.7.10 | **yes** — KeePassXC is the most-audited KDBX implementation available |
| `pws3_oracle` (Go) | an independent Password Safe v3 reader/writer | **partly** — a different language, written from the spec, by an author who had not read `backends/psafe3.py`. It is not a third party. |

Password Safe v3 gets the weaker answer because Ubuntu's `passwordsafe` package
ships only the GUI and `pwsafe --validate` cannot be driven headlessly. The
measurements behind that claim are in `../fixtures/README.md`; the short version
is that under `Xvfb` it maps no window at all and has to be killed.

---

## `pws3_oracle` — Password Safe v3, in Go

```sh
./build.sh                    # offline: GOPROXY=off, module cache only
./build.sh --net              # allow the network if the cache is cold

printf '%s' "$PASS" | ./pws3_oracle read  --file safe.psafe3
printf '%s' "$PASS" | ./pws3_oracle read  --file safe.psafe3 --no-values
printf '%s' "$PASS" | ./pws3_oracle write --file new.psafe3 --json spec.json
printf '%s' "$PASS" | ./pws3_oracle forge --file bad.psafe3 --json forge.json
./pws3_oracle vectors         # Twofish + key-stretch known-answer tests
```

* **The passphrase is read from stdin. There is deliberately no `--password`.**
* One JSON object on stdout, diagnostics on stderr, exit 0 = success — the same
  contract as `secrets-admin` (`docs/CONTRACT.md`).
* On failure stdout carries `{"error": ..., "detail": ...}` using the same eight
  codes, so a test can compare the two directly without a translation table.
* A wrong passphrase, a failed HMAC and a pre-MAC parse failure all return the
  **same** code and the **same** detail. The distinguishing reason goes to
  stderr only — otherwise the oracle would be a decryption oracle too (I6).
* `build.sh` refuses to finish unless `vectors` passes, so a build whose Twofish
  is wrong cannot be mistaken for evidence.

`forge` is file surgery for `../corpus/gen_corpus.py`: it does the real
Twofish and the real HMAC over deliberately hostile plaintext, so the corpus
tests a parser rather than a blob. `--seed` makes every random value
deterministic; it is TEST-ONLY, it prints a warning, and it must never be used
for a real safe.

### The three things this format punishes

Written down here because each of them produces a file that round-trips through
its own implementation and opens in nothing else — the exact I19 failure:

1. **The key stretch is iterated SHA-256, not PBKDF2.** `formatV3.txt` §2.3
   references `[KEYSTRETCH]` §4.1: `X0 = SHA256(pass‖salt)`, `Xi = SHA256(Xi-1)`,
   `P' = X_ITER`. `vectors` asserts this shape so nobody can "fix" it into
   PBKDF2 quietly.
2. **The HMAC covers field DATA only** — not the 4-byte length, not the type
   byte, not the random padding (§2.11). `../corpus/files/pws3-hmac-over-blocks.psafe3`
   is a file whose MAC covers the whole padded blocks; a reader that accepts it
   has this bug.
3. **The EOF block is unencrypted and is what locates the HMAC** (§2.10). A file
   without it is truncated. Refuse it; never recover what you can.

## `kdbx_oracle.sh` — KDBX, via keepassxc-cli

```sh
printf '%s\n' "$PASS" | ./kdbx_oracle.sh verify --file safe.kdbx
printf '%s\n' "$PASS" | ./kdbx_oracle.sh ls     --file safe.kdbx --recursive --flat
printf '%s\n' "$PASS" | ./kdbx_oracle.sh show   --file safe.kdbx --entry '/Lab/Nested/Router' --protected
printf '%s\n' "$PASS" | ./kdbx_oracle.sh info   --file safe.kdbx
./kdbx_oracle.sh help
```

`verify` is the one to compare against `secrets-admin`: it prints a single JSON
object with the format version (read from the file's own header bytes, since
`db-info` does not report it), cipher, KDF, group and entry counts, and every
entry path.

Three rules the wrapper exists to enforce in one place:

1. **stdin only.** `keepassxc-cli` has no `--password` option at all — that is
   upstream's own good design (`docs/UPSTREAM-REVIEW.md` §2.2) and this wrapper
   copies it. There is no `--password` flag here either.
2. **always `-q`**, so nothing blocks on a prompt and no prompt text lands in
   output a test parses. The cost is that `-q` also swallows KeePassXC's error
   text, so on a failure `verify` gives you the exit status and an empty `raw`.
3. The passphrase is piped with the bash **builtin** `printf`, and never with a
   here-string. Bash implements `<<<` with a temporary file, which is bad
   practice #3 in `docs/UPSTREAM-REVIEW.md` §4 and the "no secret in a temp
   file" half of I10.

### Measured limits of this oracle

* `db-create` and `import` **always** write KDBX 3.1 with AES-KDF. There is no
  flag for the format version, the cipher or the KDF, and `--decryption-time`
  only changes the round count. `../fixtures/gen_fixtures.sh` works around this;
  see that directory's README for exactly how, and for what it costs in
  provenance.
* KeePassXC writes the **lowest** format version that can express the database,
  so a file is only 4.1 once it contains a 4.1-only element.
* KeePassXC has no decompression cap, no group-depth cap and no UUID-uniqueness
  check. Four corpus cases open cleanly in it and must still be refused by us —
  they are listed in `gen_corpus.py`'s `kxc_opens`. Where the oracle is silent,
  the caps in `backends/base.py` `Limits` are the only defence.
