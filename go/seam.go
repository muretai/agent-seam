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
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- canonical JSON

// Canonical renders v exactly as Python's
// json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8").
//
// v must come from a json.Decoder with UseNumber() set. That is not a convenience: the
// plain decoder turns every number into a float64, which loses the difference between 1
// and 1.0 — and that difference is the single most expensive bug this contract exists to
// prevent, because Python writes "1.0" where JavaScript writes "1" and no verifier can
// reconstruct which was signed.
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
		encodeString(b, x)
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
			encodeString(b, k)
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
func encodeString(b *strings.Builder, s string) {
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

// PublicKeyFromDID is the other direction, and it is where a verifier must go: a message
// names its sender in `from`, and the verifying key is derived FROM that name rather than
// taken from anything the message also carries.
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
	pub, err := PublicKeyFromDID(e.From)
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
