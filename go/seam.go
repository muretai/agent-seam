// SPDX-License-Identifier: MIT

// Package seam is the Go reference for the seam: the byte contract two programs that have
// never met authenticate each other with. It is held to vectors/wire_vectors.json by
// conformance/main.go, the same file the JavaScript and Python references are held to.
//
// STANDARD LIBRARY ONLY. crypto/ed25519 is in it; base58 and the canonical encoder are
// forty lines each and are written here rather than pulled in, so that a reader can audit
// the whole path from a public key to a signature without leaving this file.
//
// WHERE A PORT ACTUALLY BREAKS. Not the signatures — every language has Ed25519, and it
// either verifies or it does not. It breaks in the JSON encoder, silently: a key order that
// is right for one alphabet, a float spelled two ways, an integer that rounds. Nothing
// throws; the signature simply stops verifying and the only diagnostic anyone gets is
// "signature verification failed". Everything below Canonical exists to stop that.
package seam

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------- reading the JSON

// Unmarshal reads the JSON a signer or verifier is about to work on, and it deliberately
// takes the name a Go programmer reaches for. encoding/json is the obvious thing to call
// here and the wrong thing to call, so this reference had better own the obvious name.
//
// TWO REFUSALS ENCODING/JSON DOES NOT MAKE — it silently REPAIRS both instead:
//
//  1. invalid UTF-8 bytes inside a string, and
//  2. an unpaired \uD800–\uDFFF escape.
//
// Each becomes U+FFFD during Decode, before Canonical is ever called. And U+FFFD is
// perfectly valid UTF-8, so the utf8.ValidString guard in encodeString cannot see that
// anything happened — by the time the value reaches the encoder the evidence is gone.
// Every other reference refuses these: Python's json.loads keeps the lone surrogate in the
// str and .encode("utf-8") raises on it, the JavaScript reference refuses it in
// assertEncodable, and serde_json refuses it at the parse boundary. Go alone repairs it
// and signs.
//
// AND IT IS NOT A SPELLING DIFFERENCE, WHICH IS WHY IT IS WORTH A PARSER. {"s":"\ud800"},
// {"s":"\udfff"} and {"s":"\ufffd"} are three different documents. After encoding/json
// they are one document, and they sign one identical byte string. So a signature made over
// a message containing a literal U+FFFD also authenticates, at a Go receiver, a message
// containing \ud800 instead — content substitution under a signature that verifies. That
// is strictly worse than a silent replacement, because nothing fails and no one is told.
//
// Numbers keep their literal text (UseNumber), so 1 and 1.0 stay different all the way to
// the encoder; and a second top-level value is refused rather than quietly ignored, so one
// document means one signature.
func Unmarshal(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("json: input is not valid UTF-8 — Python's bytes.decode(\"utf-8\") raises here rather than substituting U+FFFD")
	}
	if err := refuseUnpairedSurrogates(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("json: more than one top-level value")
	}
	return v, nil
}

// CanonicalFromJSON is Unmarshal followed by Canonical: raw JSON bytes in, the exact bytes
// to sign out. It is the whole supported path, and the one to reach for unless the value
// is being built in Go rather than read off a wire.
func CanonicalFromJSON(data []byte) ([]byte, error) {
	v, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	return Canonical(v)
}

// refuseUnpairedSurrogates walks the raw document because the repair happens inside
// encoding/json and cannot be detected afterwards. It has to be string-aware — a \\ is an
// escaped backslash and the "u" after it is an ordinary letter, not the start of an escape
// — so this is a scanner rather than a regexp over the bytes.
//
// It refuses only what it is certain about. A malformed \u escape, a trailing backslash, a
// truncated document: those are left alone, because encoding/json reports them with a
// better message and a position, and two parsers disagreeing about which error to name is
// its own kind of drift.
func refuseUnpairedSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = false
			i++
		case c != '\\':
			i++
		case i+1 >= len(data):
			return nil // a trailing backslash; encoding/json will say so
		case data[i+1] != 'u':
			i += 2 // \" \\ \/ \b \f \n \r \t — two bytes, and the second is never a quote
		default:
			r, ok := hex4(data, i+2)
			if !ok {
				return nil // malformed \u escape; leave the message to encoding/json
			}
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				// A high surrogate is only legal immediately before a low-surrogate
				// ESCAPE. A literal astral character after it does not pair with it, and
				// Python would keep the lone surrogate and then refuse to encode it.
				paired := i+8 <= len(data) && data[i+6] == '\\' && data[i+7] == 'u'
				if paired {
					lo, okLo := hex4(data, i+8)
					paired = okLo && lo >= 0xDC00 && lo <= 0xDFFF
				}
				if !paired {
					return unpairedSurrogate(r, i)
				}
				i += 12
			case r >= 0xDC00 && r <= 0xDFFF:
				return unpairedSurrogate(r, i) // a low surrogate with no high before it
			default:
				i += 6
			}
		}
	}
	return nil
}

func unpairedSurrogate(r rune, at int) error {
	return fmt.Errorf("json: unpaired surrogate escape \\u%04x at byte %d — encoding/json would repair it to U+FFFD, "+
		"which is a different document that signs the same bytes", r, at)
}

func hex4(data []byte, i int) (rune, bool) {
	if i+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[i : i+4] {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | d
	}
	return r, true
}

// ---------------------------------------------------------------- canonical JSON

// Canonical renders v exactly as Python's
// json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8").
//
// v must come from Unmarshal above, not from encoding/json. Two reasons, and the second
// is the expensive one:
//
// The plain decoder turns every number into a float64, which loses the difference between
// 1 and 1.0 — Python writes "1.0" where JavaScript writes "1", and no verifier can
// reconstruct afterwards which was signed. UseNumber fixes that, and Unmarshal sets it.
//
// But a value that has been through encoding/json has ALSO already been laundered: every
// unpaired surrogate escape and every invalid UTF-8 byte in it was replaced by U+FFFD on
// the way in. Nothing downstream can detect that, this function included — U+FFFD is a
// legitimate character that all four references encode happily, so refusing it here would
// only trade one split for another. The refusal has to happen at the parse boundary, and
// that is what Unmarshal is for.
func Canonical(v any) ([]byte, error) {
	var b strings.Builder
	if err := encodeValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encodeValue(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return encodeString(b, x)
	case json.Number:
		return encodeNumber(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Python sorts by Unicode code point. Go compares strings by UTF-8 byte, and UTF-8
		// byte order IS code point order — the one place a port gets a hard rule for free.
		// (A UTF-16 language does not: there � sorts after an astral character, and
		// Python puts it before. That is the `key-ordering-unicode` vector.)
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := encodeValue(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical: cannot encode %T (decode with UseNumber())", v)
	}
	return nil
}

// encodeString matches json.dumps(ensure_ascii=False): the short escapes Python uses, a
// lowercase \u00xx for the remaining control characters, and everything else literal —
// including "/", DEL and every non-ASCII rune.
//
// AND IT REFUSES INVALID UTF-8, which is why it returns an error at all. The canonical
// encoding is defined as Python's json.dumps(...).encode("utf-8"), and .encode("utf-8")
// RAISES on a lone surrogate — a Python str carrying U+D800 never becomes bytes. Go has
// no such gate: `for _, r := range s` yields U+FFFD for every byte it cannot decode and
// says nothing, so a caller handing in "pay \x80 me" would sign "pay \uFFFD me" and
// believe it had signed what it passed. That is not a formatting difference. Sender and
// receiver would disagree about what the message SAYS, and the signature over the
// substituted bytes would verify — which is worse than a signature that fails.
//
// Go's utf8.ValidString is the right gate and not merely an approximate one: it rejects
// surrogate halves (the WTF-8 spellings ed a0 80 .. ed bf bf) as well as truncated and
// overlong sequences, so one check covers both halves of what Python refuses — the lone
// surrogate the JavaScript reference refuses in assertEncodable, and the invalid byte
// sequence Python's bytes.decode("utf-8") never lets become a str in the first place.
//
// Every byte this reference signs passes through here: Canonical is the only door to the
// signing payload, and every string in it — object keys included — is checked. There is
// no second boundary where raw bytes become a signed string.
func encodeString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canonical: string is not valid UTF-8 (%q) — Python's .encode(\"utf-8\") raises here rather than substituting U+FFFD", s)
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// MaxSafeInteger is 2**53-1: the largest integer a JavaScript Number holds exactly. Python
// would carry more, so an integer past this is not a formatting difference between the two
// references — it is silent corruption, and it is refused rather than signed.
const MaxSafeInteger = 1<<53 - 1

func encodeNumber(b *strings.Builder, n json.Number) error {
	s := n.String()
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if i > MaxSafeInteger || i < -MaxSafeInteger {
			return fmt.Errorf("canonical: integer outside +/-(2**53-1) (%s)", s)
		}
		b.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical: non-finite or unreadable number (%s)", s)
	}
	if f == math.Trunc(f) {
		// 1.0, -0.0, 2e3. Python writes "1.0", JavaScript writes "1", and JSON.parse
		// cannot tell afterwards which was meant. A signer must never emit one.
		return fmt.Errorf("canonical: integral float (%s) — Python and JavaScript spell it differently", s)
	}
	if a := math.Abs(f); a < 1e-4 || a >= 1e21 {
		// The two references switch to exponent notation at different magnitudes and spell
		// the exponent differently (1e-07 against 1e-7). Outside this band, refuse.
		return fmt.Errorf("canonical: float needs exponent notation (%s)", s)
	}
	b.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
	return nil
}

// ---------------------------------------------------------------- base58btc and did:key

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58Encode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for _, c := range data { // every leading zero byte is one leading '1'
		if c != 0 {
			break
		}
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func b58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, c := range []byte(s) {
		i := strings.IndexByte(b58Alphabet, c)
		if i < 0 {
			return nil, fmt.Errorf("base58: %q is not in the alphabet", string(c))
		}
		n.Add(n.Mul(n, radix), big.NewInt(int64(i)))
	}
	out := n.Bytes()
	lead := 0
	for lead < len(s) && s[lead] == b58Alphabet[0] {
		lead++
	}
	return append(make([]byte, lead), out...), nil
}

// ed25519 multicodec: 0xed 0x01, then the 32-byte public key.
var ed25519Multicodec = []byte{0xed, 0x01}

// DIDFromPublicKey renders a 32-byte Ed25519 public key as did:key. The DID IS the key:
// no registry answers for it, and nothing expires.
func DIDFromPublicKey(pub []byte) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did:key: public key is %d bytes, want 32", len(pub))
	}
	return "did:key:z" + b58Encode(append(append([]byte{}, ed25519Multicodec...), pub...)), nil
}

// PublicKeyFromDID is the other direction: it is the CODEC, and nothing more. It answers
// "what 32 bytes does this DID spell?", byte for byte, including spellings no honest key
// generator would ever produce — vectors/wire_vectors.json pins the round trip for
// 00..00 (a point of order 4) and ff..ff (the non-canonical spelling of y = 18), and all
// four references must reproduce both. The JavaScript reference draws the line in the same
// place: publicKeyHexFromDid decodes anything, and node:crypto does the refusing inside
// verify.
//
// So a VERIFIER must not stop here. Use VerifyingKeyFromDID, which is this plus the
// refusal below; anything that takes these bytes straight to ed25519.Verify inherits the
// permissive RFC 8032 check and, with it, the one blob that authenticates everything.
func PublicKeyFromDID(did string) ([]byte, error) {
	const prefix = "did:key:z"
	if !strings.HasPrefix(did, prefix) {
		return nil, fmt.Errorf("did:key: %q does not start with %q", did, prefix)
	}
	raw, err := b58Decode(did[len(prefix):])
	if err != nil {
		return nil, err
	}
	if len(raw) != 2+ed25519.PublicKeySize || raw[0] != ed25519Multicodec[0] || raw[1] != ed25519Multicodec[1] {
		return nil, fmt.Errorf("did:key: not an ed25519 multicodec of the right length")
	}
	return raw[2:], nil
}

// ---------------------------------------------------------------- small-order keys

// THE ONE BLOB THAT AUTHENTICATES EVERYTHING. Ed25519's group has a cofactor of 8: eight
// points sit outside the prime-order subgroup, with orders 1, 2, 4 and 8. Take the one of
// order 1 — the identity, encoded as 0x01 followed by 31 zero bytes — and publish it as
// your did:key. It renders as a perfectly ordinary DID. But verification asks whether
// [S]B == R + [h]A, and when A is the identity, [h]A is the identity for EVERY scalar h.
// So R = the identity, S = 0 satisfies the equation over ANY message. The attacker needs
// no private key and never had one: one DID and one constant 64-byte blob authenticate
// every message they will ever send, to everyone, forever. The other seven torsion points
// are the same class of problem with more arithmetic in front of them.
//
// crypto/ed25519 implements the permissive RFC 8032 check — "it's sufficient, but not
// required, to check [S]B = R + [k]A'" — and the standard library exposes no strict mode,
// so this table is how the Go reference refuses them. It is not a local hardening choice:
// node:crypto refuses all fourteen (measured, not assumed), and ed25519-dalek's
// verify_strict refuses them. A Go build that accepted what the other three refuse would
// not be a bug in Go. It would be a split in the contract, and the worst kind — the kind
// where the attacker picks which implementation reads their message.
//
// FOURTEEN ENCODINGS, NOT EIGHT. Seven spellings of y, each with the sign bit clear or
// set. Where x = 0 (y = 0 and y = q-1) the sign bit is simply a second spelling of one
// point, and a permissive decoder accepts both. y = q and y = q+1 are the non-canonical
// spellings of y = 0 and y = 1: they fit in 255 bits only because 2**255 - q == 19, which
// is also why no other point on this curve has a second spelling worth listing. This is
// libsodium's blocklist, and it was re-derived here from curve arithmetic — every entry
// decompressed, checked to be on the curve, and checked to satisfy [8]P == identity —
// rather than copied from memory. Do not edit an entry without redoing that.
var smallOrderPublicKeys = decodeKeyTable([]string{
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4:  y = 0, x = sqrt(-1)
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4:  y = 0, x = -sqrt(-1) — a different point, not a second spelling
	"0100000000000000000000000000000000000000000000000000000000000000", // order 1:  THE IDENTITY. This is the key the whole comment above is about.
	"0100000000000000000000000000000000000000000000000000000000000080", // order 1:  the identity again, sign bit set over x = 0 — a second spelling of the same point
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8:  same y, other x
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8:  y = q minus the y above
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8:  same y, other x
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2:  y = q-1, x = 0
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 2:  y = q-1, sign bit set over x = 0 — a second spelling
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 4:  y = q, the NON-CANONICAL spelling of y = 0
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 4:  y = q, sign bit set
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 1:  y = q+1, the NON-CANONICAL spelling of the identity
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 1:  y = q+1, sign bit set
})

// decodeKeyTable panics rather than returning an error: a mistyped entry above is a hole
// in the only thing standing between this reference and a universal forgery, and it must
// stop the program at startup rather than wait for the one message that exploits it.
func decodeKeyTable(hexes []string) [][]byte {
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			panic("seam: the small-order table is corrupt at " + h)
		}
		out = append(out, b)
	}
	return out
}

// IsSmallOrderPublicKey reports whether pub is one of the fourteen encodings above — a key
// under which a single constant signature verifies over every message. It is a plain scan,
// not a constant-time one, and deliberately: a public key is public, and the answer leaks
// nothing an attacker did not choose themselves.
func IsSmallOrderPublicKey(pub []byte) bool {
	for _, k := range smallOrderPublicKeys {
		if bytes.Equal(pub, k) {
			return true
		}
	}
	return false
}

// VerifyingKeyFromDID is the ingress every verifier must use: PublicKeyFromDID, plus the
// refusal. Split from the codec on purpose — the codec has to spell anything, because the
// did vectors pin encodings a verifier must never accept — and this is the only door in
// this file from a DID to bytes that are about to answer a signature question.
func VerifyingKeyFromDID(did string) ([]byte, error) {
	pub, err := PublicKeyFromDID(did)
	if err != nil {
		return nil, err
	}
	if IsSmallOrderPublicKey(pub) {
		return nil, fmt.Errorf("did:key: %s is a small-order point — one signature verifies under it over every message, so it names nobody", did)
	}
	return pub, nil
}

// ---------------------------------------------------------------- the signature field

// DecodeSignature reads the base64 a signature arrives in and demands that it have exactly
// ONE spelling. The rule is character for character the one js/seam.mjs applies in
// strictB64 and the one shared/ applies in its _b64_sig helpers; whichever side is more
// permissive becomes the split, so it is written out here rather than delegated.
//
//  1. the standard alphabet and nothing else — ^[A-Za-z0-9+/]*={0,2}$, so "-" and "_" are
//     refused and padding can only be the trailing one or two characters;
//  2. length a multiple of 4;
//  3. decode, RE-ENCODE, and demand the input back character for character.
//
// THE THIRD RULE IS THE ONLY ONE THAT SAYS CANONICAL, and the first two look total without
// it. A 64-byte signature is 88 characters ending "=="; its last data character carries 6
// bits of which the decoder reads 2 and DISCARDS 4, so all 16 characters sharing those top
// 2 bits decode to the identical 64 bytes. "…BQ==" through "…Bf==" are ONE signature under
// SIXTEEN names, and every one of them is well-formed base64 that Go's StdEncoding accepts
// — it checks the alphabet, never the residual. One "=" discards 2 bits: a family of 4.
//
// Every encoder ever written puts zeros in the discarded bits, so everything an honest
// signer produced round-trips unharmed and no golden vector moves. Only a hand-edited
// residual fails, which is exactly the input that had no honest way to exist — a signature
// re-spelled by someone who wanted two names for one authorisation, or wanted a receiver
// that de-duplicates on the string to see two messages where there is one.
//
// It does NOT check the length of the decoded bytes. That belongs where it already is, in
// VerifySignature, and keeping this about the SPELLING alone lets the same rule cover every
// base64 field the contract compares by identity rather than only the 64-byte ones. An
// empty string decodes to no bytes without error, exactly as strictB64 does, and is then
// refused by the length check like any other wrong-sized signature.//
// WHY THIS RULE IS FOR BASE64 AND NOT FOR did:key. base64 has a degeneracy base58 does
// not: the trailing bits of a padded string are unconstrained, so one byte string has a
// family of names. did:key is base58 over a big integer, which is unique once the byte
// length is fixed — and PublicKeyFromDID fixes it at 34, with a leading 0xed that can
// never be a leading zero byte, so no leading "1" survives either. Measured rather than
// assumed: 2798 alternate spellings of one DID — every single-character substitution,
// every insertion at each end, and one to three leading "1"s — and not one of them
// decoded to the same key. The hex in the vectors is not a wire field at all. So the rule
// is drawn where the degeneracy actually is, and nowhere else.
func DecodeSignature(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("signature: base64 length %d is not a multiple of 4", len(s))
	}
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 {
		return nil, fmt.Errorf("signature: %q has more than two padding characters", s)
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			// Go's decoder silently skips \r and \n, and base64url's "-" and "_" are a
			// different alphabet for the same bytes. Both are a second spelling.
			return nil, fmt.Errorf("signature: %q is not in the standard base64 alphabet", string(c))
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if canon := base64.StdEncoding.EncodeToString(raw); canon != s {
		return nil, fmt.Errorf("signature: %q is not the canonical base64 of the bytes it decodes to — that is %q, "+
			"and the difference is the trailing bits no decoder reads", s, canon)
	}
	return raw, nil
}

// ---------------------------------------------------------------- the signing envelope

// Envelope is the six fields that are signed, and the only six. ContextId may be absent,
// and is then null in the bytes.
type Envelope struct {
	From      string
	To        string
	MessageID string
	ContextID *string
	Timestamp int64
	Text      string
}

// SigningPayload is the exact bytes a sender signs and a receiver verifies.
func (e Envelope) SigningPayload() ([]byte, error) {
	var ctx any
	if e.ContextID != nil {
		ctx = *e.ContextID
	}
	return Canonical(map[string]any{
		"from":      e.From,
		"to":        e.To,
		"messageId": e.MessageID,
		"contextId": ctx,
		"timestamp": json.Number(strconv.FormatInt(e.Timestamp, 10)),
		"text":      e.Text,
	})
}

// Sign returns the raw 64-byte signature over the canonical payload.
func (e Envelope) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	payload, err := e.SigningPayload()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, payload), nil
}

// VerifySignature answers one question: did the key `from` names sign these exact bytes?
// It never trusts a key carried by the message itself.
func (e Envelope) VerifySignature(sig []byte) bool {
	if e.From == "" || len(sig) != ed25519.SignatureSize {
		return false
	}
	// R — the first 32 bytes of the signature — gets the same table. ed25519-dalek's
	// verify_strict refuses a small-order R as well as a small-order A, and node:crypto
	// refuses it too (measured: a signature with R = the identity and a correctly computed
	// S under an HONEST key verifies in crypto/ed25519 and fails in Node). crypto/ed25519
	// has no strict mode, so the check is made here, against the same fourteen encodings —
	// a byte string decompresses to a small-order point exactly when it is one of them.
	//
	// Why it is worth a line: without it, anyone holding their own private key can produce
	// a SECOND, different 64-byte signature over a message they already signed, and both
	// verify. Anything downstream that treats the signature bytes as the identity of a
	// message — a dedup key, a replay guard, an idempotency token — is then defeated by
	// the sender themselves. It also keeps this reference and the Rust one answering the
	// same thing, which after verify_strict they otherwise would not.
	if IsSmallOrderPublicKey(sig[:ed25519.PublicKeySize]) {
		return false
	}
	pub, err := VerifyingKeyFromDID(e.From)
	if err != nil {
		return false
	}
	payload, err := e.SigningPayload()
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// Verify adds the question a receiver must also ask: was this addressed to me? A valid
// signature on a message meant for someone else is still a message meant for someone else.
func (e Envelope) Verify(sig []byte, recipientDID string) bool {
	if recipientDID == "" || e.To != recipientDID {
		return false
	}
	return e.VerifySignature(sig)
}
