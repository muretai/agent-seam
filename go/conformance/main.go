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

// WHICH GROUP PRODUCED WHICH CHECKS. droveGroup closes a section: it attributes every check
// counted since the previous call to name, which is a group name spelled EXACTLY as
// tools/manifest.json spells it for this language. The verdict then diffs the two.
//
// Attribution by delta rather than by wrapping each check keeps the loops below unchanged and
// works because the sections are contiguous; a group whose loop ran zero times closes with a
// delta of zero, which is precisely the case this exists to catch.
var (
	drove      = map[string]int{}
	droveOrder []string
	droveMark  int
)

func droveGroup(name string) {
	total := pass + len(failures)
	if _, seen := drove[name]; !seen {
		droveOrder = append(droveOrder, name)
	}
	drove[name] += total - droveMark
	droveMark = total
}

// findManifest locates tools/manifest.json the same way findVectors locates the vectors. A
// missing manifest is fatal rather than skipped: the whole point of reading it is that the
// coverage claim cannot be quietly absent.
func findManifest() (string, []byte) {
	for _, p := range []string{
		"../tools/manifest.json",
		"../../tools/manifest.json",
		"tools/manifest.json",
	} {
		if b, err := os.ReadFile(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs, b
		}
	}
	fmt.Fprintln(os.Stderr, "error: tools/manifest.json not found — run this from the go/ directory")
	os.Exit(2)
	return "", nil
}

// strings reads a JSON array of strings out of a decoded manifest entry.
func stringsOf(m map[string]any, k string) []string {
	raw, _ := m[k].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

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
	droveGroup("canonical")

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
	droveGroup("numberHazards")

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
	droveGroup("did(ed25519)")

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
	droveGroup("envelope")

	// ---- the refusals
	rejects, _ := v["reject"].(map[string]any)

	// reject.did — the other direction of the codec above.
	//
	// `did` is ten positive round-trips, and a decoder that answered `raw[2:]` for anything at
	// all would pass every one of them, so spec §2's two verdict rules are pinned here from the
	// side that can fail. `x25519-multicodec` is the sharp one: THIRTY-FOUR BYTES, exactly what
	// an ed25519 did:key decodes to, so only the PREFIX check refuses it and a decoder that
	// measures alone hands back somebody's X25519 key as a verification key.
	//
	// The group carries no over-long case, and that is deliberate: no over-long base58 string
	// can decode to 34 bytes (a longer string is a larger integer, and leading '1's only add
	// leading zero bytes), so the length rule refuses every one of them with or without a cap.
	// Such a vector would be green in an implementation that has no cap at all — a check that
	// cannot fail. The cap is in seam.go as MaxBase58Len regardless, because it buys CPU.
	didRejects, _ := rejects["did"].([]any)
	check(len(didRejects) > 0, "did/reject/group-present",
		"reject.did is missing or empty — this runner loops over it and cannot loop over nothing")
	for _, c := range didRejects {
		m := c.(map[string]any)
		if _, err := seam.PublicKeyFromDID(str(m, "did")); err == nil {
			check(false, "did/reject/"+str(m, "name"),
				"DECODED a did:key it must refuse — "+str(m, "why"))
		} else {
			check(true, "did/reject/"+str(m, "name"), "")
		}
	}
	droveGroup("reject.did")

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
	droveGroup("reject.message")

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
	droveGroup("reject.encoding")

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

	// ---- reject.cardpub: SKIPPED HERE TOO, AND SAID SO, for the same reason and by the same
	// discipline. There is no card envelope in seam.go — the README's coverage table has marked
	// `cardpub` as "—" for Go since this reference was written — so there is nothing here to
	// hold to it. The group is new in 0.3.1 and is the one that closes the largest hole in this
	// repository, so it is worth stating plainly that Go is not one of the implementations
	// closing it: an omission nobody can see is the same as a check nobody has.
	cardRejects, _ := rejects["cardpub"].([]any)
	cardSkipped := len(cardRejects)
	check(cardSkipped > 0, "cardpub/skipped-deliberately",
		"reject.cardpub is missing or empty — this runner skips the group ON PURPOSE and "+
			"cannot skip a group that is not there")

	// ---- what the manifest declares this implementation covers.
	//
	// A COUNT NOBODY ASSERTS IS A COUNT THAT CAN QUIETLY FALL, and this repository has the
	// measurement: 0.3.1 deleted four guards at once and 0.3.0's suite stayed fully green. A
	// bare floor would not have caught this round's finding either — an emptied, renamed or
	// filter-missed vector group produces zero checks and this file prints OK with a smaller
	// number nobody reads, because nothing here ever knew what the number should be.
	//
	// tools/manifest.json has always listed, per implementation, the groups it covers and the
	// groups it deliberately skips. NOTHING READ IT. It was documentation, so it could say
	// anything, and a group renamed in the vectors and missed by a loop was invisible on both
	// sides at once. It is the assertion now, and the diff runs BOTH WAYS: every declared group
	// must have produced a check (an emptied or missed group), and every group driven must be
	// declared (a group RENAMED, which the one-way check goes green on the moment the runner
	// and the vectors agree on a name the manifest never heard of).
	//
	// The skips are held to the same standard from the other side: a group this runner asserts
	// it is skipping must be listed as a skip, and must not also be listed as covered.
	mpath, mraw := findManifest()
	man, err := decode(mraw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: tools/manifest.json is not readable:", err)
		os.Exit(2)
	}
	impls, _ := man["implementations"].([]any)
	var mine map[string]any
	for _, it := range impls {
		if m, ok := it.(map[string]any); ok && str(m, "lang") == "go" {
			mine = m
		}
	}
	check(mine != nil, "manifest/go-is-an-implementation",
		"tools/manifest.json ("+mpath+") has no entry with lang \"go\"")
	declared := stringsOf(mine, "groups")
	skips := stringsOf(mine, "skips")
	check(len(declared) > 0, "manifest/go-declares-its-groups",
		"the manifest lists no `groups` for go — this whole section then asserts nothing")
	for _, name := range declared {
		check(drove[name] > 0, "manifest/group-drove-checks/"+name,
			fmt.Sprintf("tools/manifest.json declares `%s` for go and this run produced %d checks "+
				"from it. An emptied, renamed or filter-missed vector group prints OK; this is "+
				"what stops it.", name, drove[name]))
	}
	for _, name := range droveOrder {
		check(contains(declared, name), "manifest/group-is-declared/"+name,
			"this runner drove `"+name+"` and the manifest does not declare it for go — either "+
				"the manifest is stale or the group was renamed on one side only")
	}
	// The two groups asserted-and-skipped above must be exactly the two the manifest calls
	// skips, and a group cannot be both covered and skipped.
	for _, name := range []string{"reject.keystate", "reject.cardpub"} {
		check(contains(skips, name), "manifest/skip-is-declared/"+name,
			"this runner skips `"+name+"` by name and the manifest does not list it under `skips`")
	}
	for _, name := range skips {
		check(!contains(declared, name), "manifest/skip-is-not-also-covered/"+name,
			"the manifest lists `"+name+"` as both covered and skipped for go")
		check(drove[name] == 0, "manifest/skipped-group-drove-nothing/"+name,
			"the manifest calls `"+name+"` a skip and this runner attributed checks to it")
	}

	// The absolute floor, DELIBERATELY EXACT rather than generous. Raising it is the correct
	// response to adding a check; being unable to run it down is the point. It catches a group
	// that shrinks without emptying, which the diff above cannot see.
	const floor = 88
	if pass+len(failures) < floor {
		failures = append(failures, fmt.Sprintf("suite/check-count-floor\n      only %d checks ran "+
			"and at least %d were expected. Something stopped being checked; the rows above will "+
			"not say so, because a check that does not run reports nothing.", pass+len(failures), floor))
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
	fmt.Printf("     SKIPPED ON PURPOSE: reject.keystate, %d cases — this reference implements no\n", skipped)
	fmt.Printf("     KeyState, so it has no resolver to hold to the ratchet; and reject.cardpub,\n")
	fmt.Printf("     %d cases — no card envelope here either. Said out loud because a group nobody\n", cardSkipped)
	fmt.Printf("     loops over looks exactly like a group that passes.\n")
}
