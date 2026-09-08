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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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

// decode reads JSON the way the contract requires, and goes through seam.Unmarshal rather
// than encoding/json to do it. That is the point of the exercise: the runner must exercise
// the path a user is told to take. Numbers keep their literal text, so 1 and 1.0 stay
// different all the way to the encoder — and an unpaired surrogate escape or an invalid
// UTF-8 byte is refused here instead of being repaired to U+FFFD three lines before the
// bytes get signed.
func decode(b []byte) (map[string]any, error) {
	v, err := seam.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the vectors are not a JSON object")
	}
	return m, nil
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

func flag(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
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
	v, err := decode(raw)
	if err != nil {
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
		// The recipient comes from the TOP LEVEL of the case — the caller's own idea of
		// who it is — and falls back to `to`. It never comes from inside `input`, which is
		// what arrived on the wire. There used to be a `str(in, "recipientDid")` step in
		// this chain, and it would have made `wire-names-its-own-recipient` unable to fail:
		// the runner would have supplied the very field the case exists to prove is ignored.
		//
		// `verifierNamesNoRecipient` says the verifier knows nobody, so it is handed "".
		// envelopeOf never reads `recipientDid`, and Envelope has no such member, so in Go
		// the wire's self-nomination is structurally unreachable; what this case pins here
		// is that Verify REFUSES an empty recipient rather than helpfully substituting
		// e.To, which is the JavaScript defect ported.
		recipient := str(m, "recipientDid")
		if recipient == "" && !flag(m, "verifierNamesNoRecipient") {
			recipient = e.To
		}
		// The base64 goes through seam.DecodeSignature, and its error is a REFUSAL rather
		// than something to drop on the floor. Discarding it here used to leave an empty
		// slice that failed the signature check for an unrelated reason, so a vector that
		// exists to pin the SPELLING of a signature would have passed for the wrong cause —
		// and a `sig-not-canonical-base64` case would have looked green while the rule it
		// tests did not exist.
		sig, sigErr := seam.DecodeSignature(str(in, "sig"))
		refused := sigErr != nil || !e.Verify(sig, recipient)
		check(refused, "reject/"+str(m, "name"),
			"ACCEPTED a message it must refuse — "+str(m, "note"))
	}

	// ---- the encoding boundary: raw document BYTES, through the supported path
	//
	// This group carries the hex of a whole JSON document rather than a value, because the
	// defect it pins cannot survive a parse. encoding/json REPAIRS an unpaired surrogate
	// escape and an invalid UTF-8 byte into U+FFFD before Canonical is ever called, and
	// U+FFFD is a perfectly good character that every reference encodes happily — so by the
	// time there is a value to inspect, nothing anywhere can tell that the document was
	// rewritten. Three different documents become one, and they sign one byte string.
	//
	// So the path here is seam.CanonicalFromJSON — Unmarshal, which owns both refusals,
	// followed by Canonical — and NOT json.Unmarshal followed by seam.Canonical, which
	// would print green for every case in `refuse` while doing exactly the thing the group
	// exists to forbid. The runner must exercise the path a user is told to take.
	encoding, _ := rejects["encoding"].(map[string]any)
	accepts, _ := encoding["accept"].([]any)
	for _, c := range accepts {
		m := c.(map[string]any)
		raw, err := hex.DecodeString(str(m, "documentHex"))
		if err != nil {
			check(false, "encoding/accept/"+str(m, "name"), "documentHex is not hex: "+err.Error())
			continue
		}
		got, err := seam.CanonicalFromJSON(raw)
		want := str(m, "canonical")
		if err != nil {
			check(false, "encoding/accept/"+str(m, "name"),
				"refused a document it must render: "+err.Error()+"\n      "+str(m, "why"))
			continue
		}
		check(string(got) == want, "encoding/accept/"+str(m, "name"),
			fmt.Sprintf("got  %s\n      want %s", got, want))
	}
	refuses, _ := encoding["refuse"].([]any)
	for _, c := range refuses {
		m := c.(map[string]any)
		raw, err := hex.DecodeString(str(m, "documentHex"))
		if err != nil {
			check(false, "encoding/refuse/"+str(m, "name"), "documentHex is not hex: "+err.Error())
			continue
		}
		_, err = seam.CanonicalFromJSON(raw)
		check(err != nil, "encoding/refuse/"+str(m, "name"),
			"ACCEPTED bytes it must refuse — "+str(m, "why"))
	}

	// ---- reject.keystate: SKIPPED HERE, AND SAID SO.
	//
	// This reference implements no KeyState — there is no resolveOpDid in seam.go, so there is
	// nothing here to hold to the anti-rollback ratchet. That is a legitimate subset (a
	// language may implement some groups and not others; tools/manifest.json says which), and
	// it is also exactly the shape of the failure this whole round exists to prevent: a group
	// nobody loops over is carried in the file and checked by nobody, and it looks identical to
	// a group that passes.
	//
	// So the omission is asserted rather than assumed. The group must be PRESENT and non-empty
	// — if it disappears from the vectors, or arrives empty, this build goes red and somebody
	// reads this comment — and the verdict below prints the skip by name. An implementation
	// that later grows a KeyState resolver replaces these four lines with a real loop.
	keystate, _ := rejects["keystate"].(map[string]any)
	ksAccept, _ := keystate["accept"].([]any)
	ksRefuse, _ := keystate["refuse"].([]any)
	skipped := len(ksAccept) + len(ksRefuse)
	check(skipped > 0, "keystate/skipped-deliberately",
		"reject.keystate is missing or empty — this runner skips the group ON PURPOSE and "+
			"cannot skip a group that is not there")

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
	fmt.Printf("     SKIPPED ON PURPOSE: reject.keystate, %d cases — this reference implements no\n", skipped)
	fmt.Printf("     KeyState, so it has no resolver to hold to the ratchet. Said out loud because a\n")
	fmt.Printf("     group nobody loops over looks exactly like a group that passes.\n")
}
