// SPDX-License-Identifier: MIT

// Command conformance holds the Go reference to vectors/wire_vectors.json — the same file
// the JavaScript and Python references are held to, and the reason a third language can be
// added without asking anyone's permission.
//
// The positive half proves this build produces the same BYTES as every other
// implementation. The negative half proves it REFUSES what it must: a float no two
// languages spell alike, an integer that would round, a signature by the wrong key, a
// message addressed to somebody else. An implementation that reproduces every positive
// vector and refuses nothing authenticates no one.
//
//	cd go && go run ./conformance
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	seam "github.com/muretai/agent-seam/go"
)

var (
	pass     int
	failures []string
)

func check(ok bool, label, detail string) {
	if ok {
		pass++
		return
	}
	line := label
	if detail != "" {
		line += "\n      " + detail
	}
	failures = append(failures, line)
}

// decode reads JSON the way the contract requires: numbers keep their literal text, so
// 1 and 1.0 stay different all the way to the encoder.
func decode(b []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	return d.Decode(v)
}

func findVectors() (string, []byte) {
	for _, p := range []string{
		"../vectors/wire_vectors.json",
		"../../vectors/wire_vectors.json",
		"vectors/wire_vectors.json",
	} {
		if b, err := os.ReadFile(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs, b
		}
	}
	fmt.Fprintln(os.Stderr, "error: vectors/wire_vectors.json not found — run this from the go/ directory")
	os.Exit(2)
	return "", nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func envelopeOf(m map[string]any) seam.Envelope {
	e := seam.Envelope{From: str(m, "from"), To: str(m, "to"), MessageID: str(m, "messageId"), Text: str(m, "text")}
	if c, ok := m["contextId"].(string); ok {
		e.ContextID = &c
	}
	if n, ok := m["timestamp"].(json.Number); ok {
		e.Timestamp, _ = n.Int64()
	}
	return e
}

func main() {
	path, raw := findVectors()
	var v map[string]any
	if err := decode(raw, &v); err != nil {
		fmt.Fprintln(os.Stderr, "error: the vectors are not readable:", err)
		os.Exit(2)
	}

	// ---- canonical: the bytes, case by case
	canonical, _ := v["canonical"].([]any)
	for _, c := range canonical {
		m := c.(map[string]any)
		got, err := seam.Canonical(m["payload"])
		name := str(m, "name")
		want := str(m, "canonical")
		if err != nil {
			check(false, "canonical/"+name, "refused a case it must render: "+err.Error())
			continue
		}
		check(string(got) == want, "canonical/"+name,
			fmt.Sprintf("got  %s\n      want %s\n      %s", got, want, str(m, "why")))
	}

	// ---- numberHazards: values a signer must never emit. The JavaScript runner counts
	// these and leaves them; here they are executed, because a Go encoder that quietly
	// rendered one would be exactly the drift the group exists to catch.
	hazards, _ := v["numberHazards"].([]any)
	for _, c := range hazards {
		m := c.(map[string]any)
		_, err := seam.Canonical(m["payload"])
		check(err != nil, "numberHazard/"+str(m, "name"),
			"rendered a value Python and JavaScript spell differently ("+str(m, "pythonCanonical")+" against "+str(m, "javascriptWouldWrite")+")")
	}

	// ---- did:key, both directions
	dids, _ := v["did"].([]any)
	ed := 0
	for _, c := range dids {
		m := c.(map[string]any)
		if str(m, "curve") != "ed25519" {
			continue
		}
		ed++
		var pub []byte
		fmt.Sscanf(str(m, "publicHex"), "%x", &pub)
		pub = make([]byte, 32)
		for i := 0; i < 32; i++ {
			fmt.Sscanf(str(m, "publicHex")[i*2:i*2+2], "%02x", &pub[i])
		}
		got, err := seam.DIDFromPublicKey(pub)
		check(err == nil && got == str(m, "did"), "did/encode/"+str(m, "publicHex")[:8],
			fmt.Sprintf("got %s, want %s", got, str(m, "did")))
		back, err := seam.PublicKeyFromDID(str(m, "did"))
		check(err == nil && fmt.Sprintf("%x", back) == str(m, "publicHex"), "did/decode/"+str(m, "publicHex")[:8],
			fmt.Sprintf("got %x, want %s", back, str(m, "publicHex")))
	}

	// ---- the signing envelope: the exact bytes that are signed
	envs, _ := v["envelope"].([]any)
	for _, c := range envs {
		m := c.(map[string]any)
		got, err := envelopeOf(m).SigningPayload()
		want := str(m, "signingPayload")
		check(err == nil && string(got) == want, "envelope/"+str(m, "name"),
			fmt.Sprintf("got  %s\n      want %s", got, want))
	}

	// ---- a round trip through this build's own signer and verifier
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	did, _ := seam.DIDFromPublicKey(priv.Public().(ed25519.PublicKey))
	ctx := "c1"
	e := seam.Envelope{From: did, To: did, MessageID: "m1", ContextID: &ctx, Timestamp: 1752451200, Text: "hi ⚡ 日本語"}
	sig, err := e.Sign(priv)
	check(err == nil && e.Verify(sig, did), "envelope/round-trip",
		"this build cannot verify what it just signed")

	// ---- the refusals
	rejects, _ := v["reject"].(map[string]any)
	msgs, _ := rejects["message"].([]any)
	for _, c := range msgs {
		m := c.(map[string]any)
		in, _ := m["input"].(map[string]any)
		if in == nil {
			in = m
		}
		e := envelopeOf(in)
		recipient := str(m, "recipientDid")
		if recipient == "" {
			recipient = str(in, "recipientDid")
		}
		if recipient == "" {
			recipient = e.To
		}
		sig, _ := base64.StdEncoding.DecodeString(str(in, "sig"))
		check(!e.Verify(sig, recipient), "reject/"+str(m, "name"),
			"ACCEPTED a message it must refuse — "+str(m, "note"))
	}

	if len(failures) > 0 {
		fmt.Printf("\nFAILED — %d of %d checks:\n\n", len(failures), pass+len(failures))
		for _, f := range failures {
			fmt.Println("  ✗ " + f)
		}
		fmt.Println("\nA drift here is not cosmetic: these are the bytes every other implementation")
		fmt.Println("reproduces, and a mismatch is a signature that verifies nowhere.")
		os.Exit(1)
	}
	fmt.Printf("OK — %d checks: the bytes match, every value no two languages spell alike was refused,\n", pass)
	fmt.Printf("     and every message that must be refused was.\n     (%d ed25519 did cases; vectors: %s)\n", ed, path)
}
