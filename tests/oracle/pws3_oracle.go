// pws3_oracle — an INDEPENDENT Password Safe v3 (.psafe3) reader/writer.
//
// WHY THIS EXISTS
// ---------------
// docs/KNOWN_ISSUES.md I19: "a reader and a writer that share a bug round-trip
// perfectly and interoperate with nothing." The KDBX side of this project gets
// keepassxc-cli as a foreign oracle. Password Safe v3 gets nothing — Ubuntu's
// `passwordsafe` package ships /usr/bin/pwsafe, the wxWidgets GUI, and no CLI
// (docs/UPSTREAM-REVIEW.md §1). So the closest thing to a foreign implementation
// we can have is one written in a *different language*, from the *specification*,
// by someone who has not read the Python.
//
// This program was written from
//   https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt  (v3.31)
// alone. It does not import, vendor, transliterate or consult
// source/backends/psafe3.py, nor any of the implementations catalogued in
// docs/UPSTREAM-REVIEW.md §3.2. Keep it that way: the moment somebody "fixes"
// this file by copying the Python, the artifact is worth nothing and I19 is
// back open.
//
// TEST-ONLY. This binary is never installed, never shipped, and never appears in
// a runtime code path. It prints decrypted values on purpose — that is what an
// oracle does — so never run it from a /srv/jobs job (docs/HOST-FACTS.md: job
// logs are group-readable). Use --no-values when you only need structure.
//
// HOUSE CONVENTIONS IT STILL FOLLOWS (docs/CONTRACT.md)
//   - the passphrase arrives on STDIN, never on argv and never in the
//     environment (I10). /proc/<pid>/cmdline is world-readable.
//   - exactly ONE JSON object on stdout and nothing else; diagnostics on stderr.
//   - exit 0 = success; on failure stdout carries {"error":...,"detail":...}
//     using the same eight-code taxonomy as secrets-admin.
//   - a wrong passphrase and a failed HMAC return the SAME code and the SAME
//     detail, so the oracle is not a decryption oracle either (I6). The
//     distinguishing reason goes to stderr, which is this program's audit log.
//
// FORMAT, as read off formatV3.txt §2:
//
//	TAG(4) | SALT(32) | ITER(4 LE) | H(P')(32) | B1 B2 B3 B4 (4x16) | IV(16)
//	      | Twofish-CBC_K( HDR ‖ R1..Rn ) | "PWS3-EOFPWS3-EOF"(16) | HMAC(32)
//
//	P'  = key stretch [KEYSTRETCH §4.1] over SHA-256: X0 = H(pass‖salt),
//	      Xi = H(Xi-1) for i in 1..ITER, P' = X_ITER.        (§2.3)  NOT PBKDF2.
//	H(P') = SHA-256(P'), the passphrase check value.          (§2.5)
//	K   = Twofish-ECB-decrypt(P', B1‖B2)  — the record key.   (§2.6)
//	L   = Twofish-ECB-decrypt(P', B3‖B4)  — the HMAC key.     (§2.7)
//	field = len(4 LE) ‖ type(1) ‖ data ‖ random pad to a 16-byte multiple;
//	        the first block carries at most 11 bytes of data.  (§3)
//	HMAC-SHA256(L, ‖ of every field's DATA ONLY) — not the length,
//	        not the type byte, not the padding.                (§2.11)
//
// Build:  ./build.sh          Run:  ./pws3_oracle read --file x.psafe3 < pass
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/twofish"
)

const (
	oracleVersion = "1.0.0"

	tagPWS3   = "PWS3"
	eofMarker = "PWS3-EOFPWS3-EOF" // §2.10, exactly one block, UNENCRYPTED
	blockSize = 16                 // Twofish block size, and the field padding unit

	// TAG 4 + SALT 32 + ITER 4 + H(P') 32 + B1..B4 64 + IV 16.
	preambleLen = 4 + 32 + 4 + 32 + 64 + 16 // = 152
	// EOF block + HMAC.
	trailerLen = blockSize + sha256.Size // = 48

	// §2.4 / docs/KNOWN_ISSUES.md I7. ITER comes out of the file, so it is
	// attacker-controlled: a hostile value is a CPU bomb that would park this
	// process for days. Range-check it BEFORE the stretch loop runs, never
	// after. These bounds are Limits.PWS3_MIN_ITER / PWS3_MAX_ITER /
	// PWS3_WRITE_MIN_ITER from backends/base.py, restated here because an
	// independent oracle may not import the thing it is checking.
	minIter      = 2048
	maxIter      = 8388608
	writeMinIter = 262144 // the format's current floor (§2.4, format 0x030F)

	// Caps so a hostile file cannot turn this into an allocator DoS. The
	// oracle mirrors Limits.MAX_SAFE_BYTES / MAX_FIELD_BYTES.
	maxSafeBytes  = 134217728 // 128 MiB
	maxFieldBytes = 4194304   // 4 MiB
	maxFields     = 2000000   // structural sanity ceiling across the whole file

	// Default database format version written by `write`. §3.2[1].
	defaultFormatVersion = 0x0311

	fieldEND = 0xff // §3.2[17] / §3.3[28] — terminates the header and each record
)

// ---------------------------------------------------------------- errors ----

// oracleError carries the same eight-code taxonomy as docs/CONTRACT.md so a
// test can assert on the code without translating between two vocabularies.
type oracleError struct {
	Code   string `json:"error"`
	Detail string `json:"detail"`
	// reason never reaches stdout. It is the "audit log" half of I6: the
	// caller learns *that* the file failed, stderr records *why*.
	reason string
}

func (e *oracleError) Error() string { return e.Code + ": " + e.Detail }

func errf(code, detail string) *oracleError { return &oracleError{Code: code, Detail: detail} }

// badCredential is the ONLY constructor used for both a wrong passphrase and a
// failed HMAC. Both callers pass the identical detail string on purpose: if the
// two answers ever differ, unlock becomes a decryption oracle (I6).
const badCredentialDetail = "the passphrase is wrong, or the file is corrupt or has been tampered with"

func badCredential(reason string) *oracleError {
	return &oracleError{Code: "bad-credential", Detail: badCredentialDetail, reason: reason}
}

// ------------------------------------------------------------ field types ---

type kind int

const (
	kText kind = iota
	kUUID
	kTime
	kU16
	kU32
	kI32
	kByte
	kBinary
	kEmpty
)

type typeInfo struct {
	name string
	kind kind
}

// formatV3.txt §3.2 — header field types.
var headerTypes = map[byte]typeInfo{
	0x00: {"Version", kU16},
	0x01: {"UUID", kUUID},
	0x02: {"NonDefaultPreferences", kText},
	0x03: {"TreeDisplayStatus", kText},
	0x04: {"LastSaveTime", kTime},
	0x05: {"WhoPerformedLastSave", kText}, // DEPRECATED as of format 0x0302
	0x06: {"WhatPerformedLastSave", kText},
	0x07: {"LastSavedByUser", kText},
	0x08: {"LastSavedOnHost", kText},
	0x09: {"DatabaseName", kText},
	0x0a: {"DatabaseDescription", kText},
	0x0b: {"DatabaseFilters", kText},
	0x0c: {"Reserved0C", kBinary},
	0x0d: {"Reserved0D", kBinary},
	0x0e: {"Reserved0E", kBinary},
	0x0f: {"RecentlyUsedEntries", kText},
	0x10: {"NamedPasswordPolicies", kText},
	0x11: {"EmptyGroups", kText}, // §3.2[16] — may legally appear more than once
	0x12: {"Yubico", kBinary},
	0x13: {"LastMasterPassphraseChange", kTime},
	0xff: {"END", kEmpty},
}

// formatV3.txt §3.3 — record field types.
var recordTypes = map[byte]typeInfo{
	0x01: {"UUID", kUUID},
	0x02: {"Group", kText},
	0x03: {"Title", kText},
	0x04: {"Username", kText},
	0x05: {"Notes", kText},
	0x06: {"Password", kText},
	0x07: {"CreationTime", kTime},
	0x08: {"PasswordModificationTime", kTime},
	0x09: {"LastAccessTime", kTime},
	0x0a: {"PasswordExpiryTime", kTime},
	0x0b: {"Reserved0B", kBinary},
	0x0c: {"LastModificationTime", kTime},
	0x0d: {"URL", kText},
	0x0e: {"Autotype", kText},
	0x0f: {"PasswordHistory", kText},
	0x10: {"PasswordPolicy", kText},
	0x11: {"PasswordExpiryInterval", kU32},
	0x12: {"RunCommand", kText},
	0x13: {"DoubleClickAction", kU16},
	0x14: {"EmailAddress", kText},
	0x15: {"ProtectedEntry", kByte},
	0x16: {"OwnSymbolsForPassword", kText},
	0x17: {"ShiftDoubleClickAction", kU16},
	0x18: {"PasswordPolicyName", kText},
	0x19: {"EntryKeyboardShortcut", kU32},
	0x1a: {"Reserved1A", kUUID},
	0x1b: {"TwoFactorKey", kBinary},
	0x1c: {"CreditCardNumber", kText},
	0x1d: {"CreditCardExpiration", kText},
	0x1e: {"CreditCardVerificationValue", kText},
	0x1f: {"CreditCardPIN", kText},
	0x20: {"QRCode", kText},
	0x21: {"TOTPConfig", kByte},
	0x22: {"TOTPLength", kByte},
	0x23: {"TOTPTimeStep", kByte},
	0x24: {"TOTPStartTime", kTime},
	0x25: {"AttTitle", kText},
	0x26: {"AttMediaType", kText},
	0x27: {"AttFileName", kText},
	0x28: {"AttModificationTime", kTime},
	0x29: {"AttContent", kBinary},
	0x2a: {"PasskeyCredentialID", kBinary},
	0x2b: {"PasskeyRelyingPartyID", kText},
	0x2c: {"PasskeyUserHandle", kBinary},
	0x2d: {"PasskeyAlgorithmID", kI32},
	0x2e: {"PasskeyPrivateKey", kBinary},
	0x2f: {"PasskeySignCount", kU32},
	0x30: {"CustomTextField", kText},
	0xff: {"END", kEmpty},
}

func lookup(inHeader bool, t byte) typeInfo {
	tbl := recordTypes
	if inHeader {
		tbl = headerTypes
	}
	if ti, ok := tbl[t]; ok {
		return ti
	}
	// §4.1: an unknown type is NOT an error. Preserve it as opaque bytes.
	return typeInfo{fmt.Sprintf("Unknown_0x%02x", t), kBinary}
}

// ------------------------------------------------------------- JSON shape ---
//
// Every output struct has a fixed field order, so encoding/json produces
// byte-identical output for identical input — "canonical JSON" in the sense the
// task asked for. Do not swap these for map[string]any.

type jField struct {
	Type  int     `json:"type"`
	Name  string  `json:"name"`
	Len   int     `json:"len"`
	Hex   *string `json:"hex"`   // nil under --no-values
	Text  *string `json:"text"`  // nil unless the data is valid UTF-8 text
	Value *string `json:"value"` // rendered interpretation, nil when there is none
}

type jRecord struct {
	Index  int      `json:"index"`
	Fields []jField `json:"fields"`
}

type jRead struct {
	Oracle    string    `json:"oracle"`
	Format    string    `json:"format"`
	Tag       string    `json:"tag"`
	FileBytes int       `json:"file_bytes"`
	Iter      uint32    `json:"iter"`
	SaltHex   string    `json:"salt_hex"`
	IVHex     string    `json:"iv_hex"`
	HMACHex   string    `json:"hmac_hex"`
	HMACOK    bool      `json:"hmac_ok"`
	BodyBytes int       `json:"body_bytes"`
	Version   *string   `json:"version"`
	Header    []jField  `json:"header"`
	Records   []jRecord `json:"records"`
	Counts    jCounts   `json:"counts"`
}

type jCounts struct {
	HeaderFields int `json:"header_fields"`
	Records      int `json:"records"`
	RecordFields int `json:"record_fields"`
}

type jWrite struct {
	Oracle       string `json:"oracle"`
	Format       string `json:"format"`
	Path         string `json:"path"`
	FileBytes    int    `json:"file_bytes"`
	Iter         uint32 `json:"iter"`
	HeaderFields int    `json:"header_fields"`
	Records      int    `json:"records"`
	Deterministic bool  `json:"deterministic"`
}

// ------------------------------------------------------ random / entropy ----

// randSource is crypto/rand in every normal run. `--seed` swaps in a
// deterministic PRNG so a committed fixture regenerates byte-for-byte; that is
// a TEST-ONLY convenience and the program says so loudly on stderr, because a
// deterministic salt in a real safe would be a catastrophe.
type randSource struct {
	det *mrand.ChaCha8
}

func newRandSource(seed string) *randSource {
	if seed == "" {
		return &randSource{}
	}
	var s [32]byte
	sum := sha256.Sum256([]byte("pws3_oracle deterministic fixture seed:" + seed))
	copy(s[:], sum[:])
	fmt.Fprintf(os.Stderr, "pws3_oracle: WARNING --seed given: salt, keys, IV and field padding "+
		"are DETERMINISTIC. Test fixtures only. Never a real safe.\n")
	return &randSource{det: mrand.NewChaCha8(s)}
}

func (r *randSource) fill(b []byte) {
	if r.det == nil {
		if _, err := rand.Read(b); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		return
	}
	// ChaCha8.Read never fails.
	_, _ = r.det.Read(b)
}

func (r *randSource) bytes(n int) []byte {
	b := make([]byte, n)
	r.fill(b)
	return b
}

// ------------------------------------------------------------- primitives ---

// stretchKey implements formatV3.txt §2.3 / [KEYSTRETCH] §4.1.
//
// THE trap in this format: a confident-sounding write-up will tell you this is
// "PBKDF2-HMAC-SHA256". It is not — it is plain iterated SHA-256 with no HMAC
// and no counter block, and getting it wrong produces a file no Password Safe
// on earth can open (docs/UPSTREAM-REVIEW.md §3.3 flags exactly this).
//
//	X0 = SHA256(passphrase ‖ salt)
//	Xi = SHA256(Xi-1)        for i = 1 .. iter
//	P' = X_iter
func stretchKey(pass, salt []byte, iter uint32) [sha256.Size]byte {
	h := sha256.New()
	h.Write(pass)
	h.Write(salt)
	var x [sha256.Size]byte
	copy(x[:], h.Sum(nil))
	for i := uint32(0); i < iter; i++ {
		x = sha256.Sum256(x[:])
	}
	return x
}

// ecbCrypt runs Twofish in raw ECB over `in`, which must be a whole number of
// blocks. Only ever used on B1..B4 (§2.6, §2.7) — 64 bytes of key material.
// ECB is correct *here* and nowhere else in this format.
func ecbCrypt(key, in []byte, decrypt bool) ([]byte, error) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errf("internal", "twofish key setup failed")
	}
	if len(in)%blockSize != 0 {
		return nil, errf("invalid", "ECB input is not a whole number of blocks")
	}
	out := make([]byte, len(in))
	for off := 0; off < len(in); off += blockSize {
		if decrypt {
			c.Decrypt(out[off:off+blockSize], in[off:off+blockSize])
		} else {
			c.Encrypt(out[off:off+blockSize], in[off:off+blockSize])
		}
	}
	return out, nil
}

func cbcDecrypt(key, iv, in []byte) ([]byte, error) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errf("internal", "twofish key setup failed")
	}
	if len(in)%blockSize != 0 {
		return nil, errf("invalid", "encrypted body is not a whole number of blocks")
	}
	out := make([]byte, len(in))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(out, in)
	return out, nil
}

func cbcEncrypt(key, iv, in []byte) ([]byte, error) {
	c, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errf("internal", "twofish key setup failed")
	}
	if len(in)%blockSize != 0 {
		return nil, errf("invalid", "plaintext body is not a whole number of blocks")
	}
	out := make([]byte, len(in))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(out, in)
	return out, nil
}

// ------------------------------------------------------------ field codec ---

type rawField struct {
	Type byte
	Data []byte
}

// parseFields walks the decrypted body. EVERYTHING in here is attacker-shaped
// until the HMAC verifies (I6), so every read is bounds-checked against what is
// actually left rather than against the declared length.
//
// §3: first block = len(4 LE) ‖ type(1) ‖ up to 11 data bytes ‖ random pad;
// each further block carries 16 more data bytes, the last one padded.
func parseFields(body []byte) ([]rawField, error) {
	var out []rawField
	off := 0
	for off < len(body) {
		if len(body)-off < blockSize {
			return nil, errf("invalid", "truncated field block")
		}
		declared := binary.LittleEndian.Uint32(body[off : off+4])
		ftype := body[off+4]

		// I7-shaped check: refuse the length before allocating anything for it.
		// A hostile len of 0xFFFFFFFF is a memory bomb, and on a 32-bit int it
		// is also an overflow. Compare in uint64 so nothing can wrap.
		if uint64(declared) > uint64(maxFieldBytes) {
			return nil, errf("invalid", fmt.Sprintf(
				"field 0x%02x declares %d bytes, over the %d byte cap", ftype, declared, maxFieldBytes))
		}
		flen := int(declared)

		// Total blocks: one for the header block, plus one per 16 bytes of the
		// data that did not fit in its 11 spare bytes.
		blocks := 1
		if flen > 11 {
			blocks += (flen - 11 + blockSize - 1) / blockSize
		}
		need := blocks * blockSize
		if len(body)-off < need {
			return nil, errf("invalid", fmt.Sprintf(
				"field 0x%02x declares %d bytes but only %d remain", ftype, flen, len(body)-off))
		}

		data := make([]byte, 0, flen)
		first := flen
		if first > 11 {
			first = 11
		}
		data = append(data, body[off+5:off+5+first]...)
		if flen > 11 {
			data = append(data, body[off+blockSize:off+blockSize+(flen-11)]...)
		}

		out = append(out, rawField{Type: ftype, Data: data})
		if len(out) > maxFields {
			return nil, errf("invalid", "field count exceeds the structural ceiling")
		}
		off += need
	}
	return out, nil
}

// encodeField is the inverse of the above. Padding is random per §3 ("the extra
// bytes are filled with random values") — which is also why a PWS3 file never
// round-trips to identical bytes unless --seed pins the RNG.
func encodeField(rs *randSource, f rawField) []byte {
	flen := len(f.Data)
	blocks := 1
	if flen > 11 {
		blocks += (flen - 11 + blockSize - 1) / blockSize
	}
	buf := make([]byte, blocks*blockSize)
	rs.fill(buf) // pad first, then overwrite the meaningful bytes
	binary.LittleEndian.PutUint32(buf[0:4], uint32(flen))
	buf[4] = f.Type
	first := flen
	if first > 11 {
		first = 11
	}
	copy(buf[5:], f.Data[:first])
	if flen > 11 {
		copy(buf[blockSize:], f.Data[first:])
	}
	return buf
}

// hmacInput is §2.11, and it is the single most commonly botched line in a PWS3
// implementation: the MAC covers the field DATA and nothing else — not the
// 4-byte length, not the type byte, not the random padding. An implementation
// that includes any of those round-trips through itself and interoperates with
// nothing at all.
func hmacInput(fields []rawField) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		b.Write(f.Data)
	}
	return b.Bytes()
}

// --------------------------------------------------------------- rendering --

func renderValue(ti typeInfo, data []byte) (text *string, value *string) {
	s := string(data)
	if utf8.Valid(data) && ti.kind == kText {
		t := s
		text = &t
	}
	switch ti.kind {
	case kUUID:
		if len(data) == 16 {
			v := fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16])
			value = &v
		}
	case kTime:
		// §3.1.3 — 32-bit LE seconds since the Unix epoch, UTC.
		if len(data) == 4 {
			v := time.Unix(int64(binary.LittleEndian.Uint32(data)), 0).UTC().Format(time.RFC3339)
			value = &v
		}
	case kU16:
		if len(data) == 2 {
			v := fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(data))
			value = &v
		}
	case kU32:
		if len(data) == 4 {
			v := strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data)), 10)
			value = &v
		}
	case kI32:
		if len(data) == 4 {
			v := strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(data))), 10)
			value = &v
		}
	case kByte:
		if len(data) == 1 {
			v := strconv.Itoa(int(data[0]))
			value = &v
		}
	case kText:
		if text == nil && len(data) > 0 {
			// A "text" field that is not valid UTF-8 is exactly the corpus case
			// tests/corpus non-utf8-*: say so instead of emitting mojibake.
			v := "<not valid UTF-8>"
			value = &v
		}
	}
	return
}

func toJField(inHeader bool, f rawField, withValues bool) jField {
	ti := lookup(inHeader, f.Type)
	out := jField{Type: int(f.Type), Name: ti.name, Len: len(f.Data)}
	if !withValues {
		return out
	}
	h := hex.EncodeToString(f.Data)
	out.Hex = &h
	out.Text, out.Value = renderValue(ti, f.Data)
	return out
}

// --------------------------------------------------------------- read verb --

func doRead(path string, pass []byte, withValues bool) (*jRead, error) {
	raw, err := readFileCapped(path)
	if err != nil {
		return nil, err
	}

	// ---- structure, before any crypto ----------------------------------
	if len(raw) < preambleLen+trailerLen {
		return nil, errf("invalid", "file is shorter than the smallest possible PWS3 database")
	}
	if string(raw[0:4]) != tagPWS3 {
		return nil, errf("invalid", "missing the PWS3 tag")
	}
	salt := raw[4:36]
	iter := binary.LittleEndian.Uint32(raw[36:40])
	storedHP := raw[40:72]
	b1b2b3b4 := raw[72:136]
	iv := raw[136:152]

	// ---- I7: clamp ITER BEFORE the KDF, not after ----------------------
	// This check is the whole reason the corpus carries iter-0 / iter-1 /
	// iter-2147483647 files with a time budget: each must fail here, in
	// microseconds, without ever entering the stretch loop.
	if iter < minIter || iter > maxIter {
		return nil, errf("invalid", fmt.Sprintf(
			"ITER %d is outside the permitted range [%d, %d]", iter, minIter, maxIter))
	}

	// ---- locate the EOF block (§2.10) ----------------------------------
	// The EOF block is plaintext and block-aligned, so walking the ciphertext
	// region a block at a time is the reference behaviour. A file with no EOF
	// block is TRUNCATED: refuse it, never "recover what you can".
	bodyEnd := -1
	for off := preambleLen; off+blockSize <= len(raw); off += blockSize {
		if string(raw[off:off+blockSize]) == eofMarker {
			bodyEnd = off
			break
		}
	}
	if bodyEnd < 0 {
		return nil, errf("invalid", "no PWS3-EOF block: the file is truncated")
	}
	if len(raw)-(bodyEnd+blockSize) != sha256.Size {
		return nil, errf("invalid", fmt.Sprintf(
			"expected %d HMAC bytes after the EOF block, found %d",
			sha256.Size, len(raw)-(bodyEnd+blockSize)))
	}
	cipherBody := raw[preambleLen:bodyEnd]
	storedMAC := raw[bodyEnd+blockSize:]

	// ---- passphrase check (§2.5) ---------------------------------------
	pprime := stretchKey(pass, salt, iter)
	gotHP := sha256.Sum256(pprime[:])
	// subtle.ConstantTimeCompare, never bytes.Equal: this is the Go spelling of
	// hmac.compare_digest, and comparing a key-check value with == is item 10
	// of the bad-practice table in docs/UPSTREAM-REVIEW.md §4.
	if subtle.ConstantTimeCompare(gotHP[:], storedHP) != 1 {
		return nil, badCredential("H(P') mismatch: wrong passphrase")
	}

	// ---- recover K and L (§2.6, §2.7) ----------------------------------
	kl, err := ecbCrypt(pprime[:], b1b2b3b4, true)
	if err != nil {
		return nil, err
	}
	keyK := kl[0:32]
	keyL := kl[32:64]

	body, err := cbcDecrypt(keyK, iv, cipherBody)
	if err != nil {
		return nil, err
	}

	// The bytes we are about to walk are decrypted but NOT yet authenticated,
	// and the format gives us no way round that: the MAC covers field *data*,
	// so the fields have to be parsed before the tag can be computed. What we
	// can control is what a failure here tells the caller. Reporting "field
	// 0xdf declares 1564092348 bytes" would report how far the parser got
	// through attacker-chosen plaintext — the padding-oracle shape, and exactly
	// the "parser bug becomes a decryption oracle" hazard in I6. So every
	// pre-MAC parse failure collapses into the same bad-credential answer as a
	// wrong passphrase, and the real reason goes to stderr only.
	fields, err := parseFields(body)
	if err != nil {
		var oe *oracleError
		reason := "body parse failed before MAC verification"
		if errors.As(err, &oe) {
			reason = "body parse failed before MAC verification: " + oe.Detail
		}
		return nil, badCredential(reason)
	}

	// ---- verify the MAC (§2.11) BEFORE anything is rendered ------------
	// I6: the HMAC lives at the END of the file, so the format forces
	// decrypt-then-authenticate. What we control is that nothing decrypted
	// escapes this function until the tag checks out. Note the identical
	// error to the wrong-passphrase path above.
	mac := hmac.New(sha256.New, keyL)
	mac.Write(hmacInput(fields))
	if subtle.ConstantTimeCompare(mac.Sum(nil), storedMAC) != 1 {
		return nil, badCredential("HMAC mismatch: the file is corrupt or tampered with")
	}

	// ---- only now may values be rendered --------------------------------
	out := jRead{
		Oracle:    "pws3_oracle " + oracleVersion,
		Format:    "psafe3",
		Tag:       tagPWS3,
		FileBytes: len(raw),
		Iter:      iter,
		SaltHex:   hex.EncodeToString(salt),
		IVHex:     hex.EncodeToString(iv),
		HMACHex:   hex.EncodeToString(storedMAC),
		HMACOK:    true,
		BodyBytes: len(body),
		Header:    []jField{},
		Records:   []jRecord{},
	}

	inHeader := true
	cur := jRecord{Index: 0, Fields: []jField{}}
	for _, f := range fields {
		jf := toJField(inHeader, f, withValues)
		if inHeader {
			if f.Type == 0x00 && len(f.Data) == 2 {
				v := fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(f.Data))
				out.Version = &v
			}
			out.Header = append(out.Header, jf)
			if f.Type == fieldEND {
				inHeader = false
			}
			continue
		}
		cur.Fields = append(cur.Fields, jf)
		if f.Type == fieldEND {
			cur.Index = len(out.Records)
			out.Records = append(out.Records, cur)
			cur = jRecord{Fields: []jField{}}
		}
	}
	if len(cur.Fields) > 0 {
		// Trailing fields with no END: a structural fault worth naming rather
		// than silently dropping.
		return nil, errf("invalid", "the last record is not terminated by an END field")
	}
	if inHeader {
		return nil, errf("invalid", "the header is not terminated by an END field")
	}

	out.Counts.HeaderFields = len(out.Header)
	out.Counts.Records = len(out.Records)
	for _, r := range out.Records {
		out.Counts.RecordFields += len(r.Fields)
	}
	return &out, nil
}

// -------------------------------------------------------------- write verb --

// writeSpec is the JSON accepted by `write --json`. A field carries exactly one
// of hex / text / uuid / time / u16 / u32 / b64; the encoder rejects two.
type writeSpec struct {
	Iter    *uint32       `json:"iter"`
	Version *int          `json:"version"`
	Header  []specField   `json:"header"`
	Records []specRecord  `json:"records"`
}

type specRecord struct {
	Fields []specField `json:"fields"`
}

type specField struct {
	Type int     `json:"type"`
	Hex  *string `json:"hex"`
	Text *string `json:"text"`
	B64  *string `json:"b64"`
	UUID *string `json:"uuid"`
	Time *string `json:"time"` // RFC3339, or a decimal unix timestamp
	U16  *int    `json:"u16"`
	U32  *int64  `json:"u32"`
}

func (sf specField) raw() (rawField, error) {
	if sf.Type < 0 || sf.Type > 255 {
		return rawField{}, errf("invalid", fmt.Sprintf("field type %d is out of range", sf.Type))
	}
	var got []([]byte)
	add := func(b []byte) { got = append(got, b) }
	if sf.Hex != nil {
		b, err := hex.DecodeString(*sf.Hex)
		if err != nil {
			return rawField{}, errf("invalid", "field hex is not valid hexadecimal")
		}
		add(b)
	}
	if sf.Text != nil {
		add([]byte(*sf.Text))
	}
	if sf.B64 != nil {
		b, err := b64decode(*sf.B64)
		if err != nil {
			return rawField{}, errf("invalid", "field b64 is not valid base64")
		}
		add(b)
	}
	if sf.UUID != nil {
		b, err := parseUUID(*sf.UUID)
		if err != nil {
			return rawField{}, err
		}
		add(b)
	}
	if sf.Time != nil {
		secs, err := parseTime(*sf.Time)
		if err != nil {
			return rawField{}, err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(secs))
		add(b)
	}
	if sf.U16 != nil {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(*sf.U16))
		add(b)
	}
	if sf.U32 != nil {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(*sf.U32))
		add(b)
	}
	switch len(got) {
	case 0:
		return rawField{Type: byte(sf.Type), Data: []byte{}}, nil
	case 1:
		if len(got[0]) > maxFieldBytes {
			return rawField{}, errf("invalid", "field data exceeds the field cap")
		}
		return rawField{Type: byte(sf.Type), Data: got[0]}, nil
	default:
		return rawField{}, errf("invalid", fmt.Sprintf(
			"field type 0x%02x gives more than one value encoding", sf.Type))
	}
}

func doWrite(path string, pass []byte, spec *writeSpec, rs *randSource, allowWeakIter bool, det bool) (*jWrite, error) {
	iter := uint32(writeMinIter)
	if spec.Iter != nil {
		iter = *spec.Iter
	}
	// §2.4 + I7: the current format floor is 262144 on WRITE. Older databases
	// are silently upgraded to it when saved, so writing below it produces a
	// file that is legal to read but out of spec to create.
	if !allowWeakIter && iter < writeMinIter {
		return nil, errf("invalid", fmt.Sprintf(
			"ITER %d is below the format write floor of %d (pass --allow-weak-iter to forge one anyway)",
			iter, writeMinIter))
	}
	if iter > maxIter {
		return nil, errf("invalid", fmt.Sprintf("ITER %d exceeds the read cap of %d", iter, maxIter))
	}

	// ---- header: Version first (§2.9.1), END last ----------------------
	// section 2.9.1: the header BEGINS with the Version field and is terminated
	// by END, and both are mandatory. So Version is hoisted to the front and END
	// appended at the back no matter what order the spec listed them in — a
	// writer that emits them in the caller's order produces a file that is
	// out of spec in a way most readers happen to tolerate, which is the worst
	// kind of bug to ship in an oracle.
	var version *rawField
	var header []rawField
	for _, sf := range spec.Header {
		if sf.Type == fieldEND {
			continue
		}
		f, err := sf.raw()
		if err != nil {
			return nil, err
		}
		if sf.Type == 0x00 && version == nil {
			v := f
			version = &v
			continue
		}
		header = append(header, f)
	}
	if version == nil {
		v := defaultFormatVersion
		if spec.Version != nil {
			v = *spec.Version
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(v))
		version = &rawField{Type: 0x00, Data: b}
	}
	header = append([]rawField{*version}, header...)
	header = append(header, rawField{Type: fieldEND, Data: []byte{}})

	fields := append([]rawField{}, header...)
	for i, r := range spec.Records {
		n := 0
		for _, sf := range r.Fields {
			if sf.Type == fieldEND {
				continue
			}
			f, err := sf.raw()
			if err != nil {
				return nil, err
			}
			fields = append(fields, f)
			n++
		}
		if n == 0 {
			return nil, errf("invalid", fmt.Sprintf("record %d has no fields", i))
		}
		fields = append(fields, rawField{Type: fieldEND, Data: []byte{}})
	}

	var body bytes.Buffer
	for _, f := range fields {
		body.Write(encodeField(rs, f))
	}

	blob, err := assemble(rs, pass, iter, nil, nil, nil, nil, nil,
		body.Bytes(), hmacInput(fields), nil, false, nil)
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, blob); err != nil {
		return nil, err
	}
	return &jWrite{
		Oracle:        "pws3_oracle " + oracleVersion,
		Format:        "psafe3",
		Path:          path,
		FileBytes:     len(blob),
		Iter:          iter,
		HeaderFields:  len(header),
		Records:       len(spec.Records),
		Deterministic: det,
	}, nil
}

// -------------------------------------------------------------- forge verb --
//
// `forge` exists for tests/corpus/gen_corpus.py: it builds a structurally
// deliberate file — an out-of-range ITER, a hostile field length, a missing EOF
// block, a MAC computed over the wrong bytes — while still doing the real
// crypto, so the corpus tests a parser and not a byte-blob. It is the reason
// the corpus generator does not need a second PWS3 implementation of its own.

type forgeSpec struct {
	Iter        *uint32 `json:"iter"`
	RawIterHex  *string `json:"raw_iter_hex"`  // 4 bytes written literally as ITER
	SaltHex     *string `json:"salt_hex"`
	IVHex       *string `json:"iv_hex"`
	HPHex       *string `json:"hp_hex"`        // override the stored H(P')
	KHex        *string `json:"k_hex"`         // override the record key K
	LHex        *string `json:"l_hex"`         // override the HMAC key L
	BodyHex     string  `json:"body_hex"`      // raw plaintext body, zero-padded to 16
	HMACDataHex *string `json:"hmac_data_hex"` // explicit HMAC input
	HMACHex     *string `json:"hmac_hex"`      // explicit HMAC value
	OmitEOF     bool    `json:"omit_eof"`
	TrailingHex *string `json:"trailing_hex"`
}

func doForge(path string, pass []byte, spec *forgeSpec, rs *randSource) (*jWrite, error) {
	iter := uint32(writeMinIter)
	if spec.Iter != nil {
		iter = *spec.Iter
	}
	body, err := hex.DecodeString(spec.BodyHex)
	if err != nil {
		return nil, errf("invalid", "body_hex is not valid hexadecimal")
	}
	if len(body)%blockSize != 0 {
		pad := blockSize - len(body)%blockSize
		body = append(body, make([]byte, pad)...)
	}

	var macData []byte
	if spec.HMACDataHex != nil {
		if macData, err = hex.DecodeString(*spec.HMACDataHex); err != nil {
			return nil, errf("invalid", "hmac_data_hex is not valid hexadecimal")
		}
	} else {
		fs, perr := parseFields(body)
		if perr != nil {
			// A forged body that this parser refuses is legitimate: MAC over
			// nothing rather than refuse to produce the corpus file.
			macData = []byte{}
		} else {
			macData = hmacInput(fs)
		}
	}

	optHex := func(p *string, want int, what string) ([]byte, error) {
		if p == nil {
			return nil, nil
		}
		b, e := hex.DecodeString(*p)
		if e != nil {
			return nil, errf("invalid", what+" is not valid hexadecimal")
		}
		if want > 0 && len(b) != want {
			return nil, errf("invalid", fmt.Sprintf("%s must be %d bytes", what, want))
		}
		return b, nil
	}
	salt, err := optHex(spec.SaltHex, 32, "salt_hex")
	if err != nil {
		return nil, err
	}
	iv, err := optHex(spec.IVHex, 16, "iv_hex")
	if err != nil {
		return nil, err
	}
	hp, err := optHex(spec.HPHex, 32, "hp_hex")
	if err != nil {
		return nil, err
	}
	keyK, err := optHex(spec.KHex, 32, "k_hex")
	if err != nil {
		return nil, err
	}
	keyL, err := optHex(spec.LHex, 32, "l_hex")
	if err != nil {
		return nil, err
	}
	macOverride, err := optHex(spec.HMACHex, 32, "hmac_hex")
	if err != nil {
		return nil, err
	}
	rawIter, err := optHex(spec.RawIterHex, 4, "raw_iter_hex")
	if err != nil {
		return nil, err
	}
	trailing, err := optHex(spec.TrailingHex, 0, "trailing_hex")
	if err != nil {
		return nil, err
	}

	blob, err := assemble(rs, pass, iter, rawIter, salt, iv, hp, keyK, body, macData,
		keyL, spec.OmitEOF, macOverride)
	if err != nil {
		return nil, err
	}
	if trailing != nil {
		blob = append(blob, trailing...)
	}
	if err := writeFile(path, blob); err != nil {
		return nil, err
	}
	return &jWrite{
		Oracle:        "pws3_oracle " + oracleVersion,
		Format:        "psafe3-forged",
		Path:          path,
		FileBytes:     len(blob),
		Iter:          iter,
		HeaderFields:  0,
		Records:       0,
		Deterministic: rs.det != nil,
	}, nil
}

// assemble lays out §2 in order. Every override is nil in the honest path.
func assemble(rs *randSource, pass []byte, iter uint32, rawIter, salt, iv, hp, keyK, body,
	macData, keyL []byte, omitEOF bool, macOverride []byte) ([]byte, error) {

	if salt == nil {
		salt = rs.bytes(32)
	}
	if iv == nil {
		iv = rs.bytes(16)
	}
	if keyK == nil {
		keyK = rs.bytes(32)
	}
	if keyL == nil {
		keyL = rs.bytes(32)
	}
	// §2.7 implementation note: "K and L must NOT be related." Two independent
	// draws satisfy that; deriving one from the other would not.

	pprime := stretchKey(pass, salt, iter)
	if hp == nil {
		sum := sha256.Sum256(pprime[:])
		hp = sum[:]
	}
	b1b4, err := ecbCrypt(pprime[:], append(append([]byte{}, keyK...), keyL...), false)
	if err != nil {
		return nil, err
	}
	cipherBody, err := cbcEncrypt(keyK, iv, body)
	if err != nil {
		return nil, err
	}

	mac := macOverride
	if mac == nil {
		m := hmac.New(sha256.New, keyL)
		m.Write(macData)
		mac = m.Sum(nil)
	}

	var out bytes.Buffer
	out.WriteString(tagPWS3)
	out.Write(salt)
	if rawIter != nil {
		out.Write(rawIter)
	} else {
		var ib [4]byte
		binary.LittleEndian.PutUint32(ib[:], iter)
		out.Write(ib[:])
	}
	out.Write(hp)
	out.Write(b1b4)
	out.Write(iv)
	out.Write(cipherBody)
	if !omitEOF {
		out.WriteString(eofMarker)
	}
	out.Write(mac)
	return out.Bytes(), nil
}

// ------------------------------------------------------------ vectors verb --

// The published Twofish all-zero-key ECB known-answer vectors. They are here so
// a build on a new host proves the cipher before anything trusts it, and they
// are quoted independently in docs/HOST-FACTS.md (measured there against
// Botan 3.10, which is the Python side's Twofish).
var twofishKATs = []struct{ keyLen int; ct string }{
	{16, "9f589f5cf6122c32b6bfec2f2ae8c35a"},
	{24, "efa71f788965bd4453f860178fc19101"},
	{32, "57ff739d4dc92c1bd7fc01700cc8216f"},
}

func doVectors() (any, error) {
	type kat struct {
		Bits int    `json:"bits"`
		Want string `json:"want"`
		Got  string `json:"got"`
		OK   bool   `json:"ok"`
	}
	res := struct {
		Oracle  string `json:"oracle"`
		Twofish []kat  `json:"twofish_ecb_zero_key"`
		CBCOK   bool   `json:"cbc_roundtrip_ok"`
		KDFOK   bool   `json:"keystretch_shape_ok"`
		OK      bool   `json:"ok"`
	}{Oracle: "pws3_oracle " + oracleVersion, OK: true}

	for _, v := range twofishKATs {
		c, err := twofish.NewCipher(make([]byte, v.keyLen))
		if err != nil {
			return nil, errf("internal", "twofish key setup failed")
		}
		out := make([]byte, blockSize)
		c.Encrypt(out, make([]byte, blockSize))
		got := hex.EncodeToString(out)
		ok := got == v.ct
		res.Twofish = append(res.Twofish, kat{v.keyLen * 8, v.ct, got, ok})
		if !ok {
			res.OK = false
		}
	}

	// CBC composed over the same primitive must undo itself — this is the mode
	// the whole body rides on.
	key := bytes.Repeat([]byte{0x5a}, 32)
	iv := bytes.Repeat([]byte{0xa5}, 16)
	pt := bytes.Repeat([]byte{0x11}, 64)
	ct, err := cbcEncrypt(key, iv, pt)
	if err != nil {
		return nil, err
	}
	rt, err := cbcDecrypt(key, iv, ct)
	if err != nil {
		return nil, err
	}
	res.CBCOK = bytes.Equal(pt, rt)
	if !res.CBCOK {
		res.OK = false
	}

	// The stretch is iterated SHA-256, NOT PBKDF2: with iter=0 it must be
	// exactly SHA256(pass‖salt). If somebody "fixes" stretchKey into PBKDF2
	// this assertion is what catches it.
	h := sha256.New()
	h.Write([]byte("pass"))
	h.Write([]byte("salt"))
	var want [32]byte
	copy(want[:], h.Sum(nil))
	res.KDFOK = stretchKey([]byte("pass"), []byte("salt"), 0) == want &&
		stretchKey([]byte("pass"), []byte("salt"), 1) == sha256.Sum256(want[:])
	if !res.KDFOK {
		res.OK = false
	}
	if !res.OK {
		return res, errf("internal", "a known-answer test failed; do not trust this build")
	}
	return res, nil
}

// --------------------------------------------------------------- plumbing ---

func readFileCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errf("not-found", "no such file")
		}
		return nil, errf("access-denied", "cannot open the file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, errf("internal", "cannot stat the file")
	}
	if !st.Mode().IsRegular() {
		return nil, errf("invalid", "not a regular file")
	}
	if st.Size() > maxSafeBytes {
		return nil, errf("invalid", "file is larger than the safe-size cap")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSafeBytes+1))
	if err != nil {
		return nil, errf("internal", "read failed")
	}
	return raw, nil
}

func writeFile(path string, data []byte) error {
	// 0600 — a throwaway fixture is still a safe, and a world-readable one
	// would trip the ownership/mode checks in base.open_safe_fd.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return errf("internal", "write failed")
	}
	return nil
}

// readPassphrase takes the whole of stdin and strips ONE trailing newline (and
// a CR before it), so `printf '%s' pw |` and `echo pw |` both work. The
// passphrase never touches argv or the environment (I10).
func readPassphrase() ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return nil, errf("internal", "cannot read the passphrase from stdin")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b, nil
}

// wipe is best-effort defence in depth, the Go spelling of I14: Go's GC may
// already have copied the slice, and this cannot stop that. It costs nothing
// and it keeps the passphrase out of the tail of the heap for the process's
// remaining microseconds.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseUUID(s string) ([]byte, error) {
	c := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(c)
	if err != nil || len(b) != 16 {
		return nil, errf("invalid", "uuid must be 16 bytes of hexadecimal")
	}
	return b, nil
}

func parseTime(s string) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, errf("invalid", "time must be RFC3339 or a unix timestamp")
	}
	return t.Unix(), nil
}

func b64decode(s string) ([]byte, error) {
	// Standard base64, strictly: a hand-rolled decoder that silently skips
	// whatever it does not recognise would let a malformed spec through as
	// something that looks like data.
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// emit prints exactly one JSON object on stdout and nothing else.
func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func die(err error) {
	var oe *oracleError
	if !errors.As(err, &oe) {
		// Never let a raw Go error reach stdout: it can carry a path, a length,
		// or in the worst case a fragment of plaintext (I15).
		oe = errf("internal", "unexpected failure")
		fmt.Fprintf(os.Stderr, "pws3_oracle: %v\n", err)
	}
	if oe.reason != "" {
		fmt.Fprintf(os.Stderr, "pws3_oracle: %s\n", oe.reason)
	}
	emit(oe)
	os.Exit(2)
}

const usage = `pws3_oracle ` + oracleVersion + ` — independent Password Safe v3 reader/writer (TEST ONLY)

  pws3_oracle read  --file F [--no-values]        passphrase on stdin
  pws3_oracle write --file F --json SPEC [--seed S] [--allow-weak-iter]
  pws3_oracle forge --file F --json SPEC [--seed S]     (corpus surgery)
  pws3_oracle vectors                             Twofish/KDF known-answer tests
  pws3_oracle version

The passphrase is ALWAYS read from stdin. There is deliberately no --password.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
	verb := args[0]
	flags := map[string]string{}
	bools := map[string]bool{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--no-values", "--allow-weak-iter", "--help", "-h":
			bools[strings.TrimLeft(a, "-")] = true
		case "--file", "--json", "--seed":
			if i+1 >= len(args) {
				die(errf("invalid", a+" needs a value"))
			}
			flags[strings.TrimLeft(a, "-")] = args[i+1]
			i++
		default:
			die(errf("invalid", "unknown argument "+a))
		}
	}
	if bools["help"] || bools["h"] {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(0)
	}

	switch verb {
	case "version":
		emit(map[string]string{"oracle": "pws3_oracle", "version": oracleVersion})
		return

	case "vectors":
		res, err := doVectors()
		if err != nil {
			if res != nil {
				emit(res)
			}
			fmt.Fprintf(os.Stderr, "pws3_oracle: %v\n", err)
			os.Exit(2)
		}
		emit(res)
		return

	case "read":
		path := flags["file"]
		if path == "" {
			die(errf("invalid", "read needs --file"))
		}
		pass, err := readPassphrase()
		if err != nil {
			die(err)
		}
		defer wipe(pass)
		out, err := doRead(path, pass, !bools["no-values"])
		wipe(pass)
		if err != nil {
			die(err)
		}
		emit(out)
		return

	case "write", "forge":
		path := flags["file"]
		if path == "" {
			die(errf("invalid", verb+" needs --file"))
		}
		specPath := flags["json"]
		if specPath == "" {
			die(errf("invalid", verb+" needs --json"))
		}
		blob, err := os.ReadFile(specPath)
		if err != nil {
			die(errf("not-found", "cannot read the spec file"))
		}
		pass, perr := readPassphrase()
		if perr != nil {
			die(perr)
		}
		defer wipe(pass)
		rs := newRandSource(flags["seed"])

		if verb == "write" {
			var spec writeSpec
			if err := json.Unmarshal(blob, &spec); err != nil {
				die(errf("invalid", "the spec file is not valid JSON for `write`"))
			}
			out, werr := doWrite(path, pass, &spec, rs, bools["allow-weak-iter"], flags["seed"] != "")
			wipe(pass)
			if werr != nil {
				die(werr)
			}
			emit(out)
			return
		}
		var spec forgeSpec
		if err := json.Unmarshal(blob, &spec); err != nil {
			die(errf("invalid", "the spec file is not valid JSON for `forge`"))
		}
		out, ferr := doForge(path, pass, &spec, rs)
		wipe(pass)
		if ferr != nil {
			die(ferr)
		}
		emit(out)
		return

	default:
		fmt.Fprint(os.Stderr, usage)
		die(errf("invalid", "unknown verb "+verb))
	}
}
