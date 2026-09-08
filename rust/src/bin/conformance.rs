// SPDX-License-Identifier: MIT

//! Holds the Rust reference to `vectors/wire_vectors.json` — the same file the JavaScript,
//! Python and Go references are held to, and the reason a fourth language can be added
//! without asking anyone's permission.
//!
//! The positive half proves this build produces the same BYTES as every other
//! implementation. The negative half proves it REFUSES what it must: a float no two languages
//! spell alike, an integer that would round, a signature by the wrong key, a message
//! addressed to somebody else. An implementation that reproduces every positive vector and
//! refuses nothing authenticates no one.
//!
//!     cd rust && cargo run --quiet --bin conformance

use agent_seam::{canonical, decode_signature, did_from_public_key, public_key_from_did, Envelope};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::process::exit;

struct Report {
    pass: usize,
    failures: Vec<String>,
}

impl Report {
    fn check(&mut self, ok: bool, label: &str, detail: &str) {
        if ok {
            self.pass += 1;
        } else if detail.is_empty() {
            self.failures.push(label.to_string());
        } else {
            self.failures.push(format!("{label}\n      {detail}"));
        }
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

/// Hex to bytes, or None. `reject.encoding` carries whole documents this way because a raw
/// invalid UTF-8 byte cannot be written inside a JSON string at all — the vector file would
/// have to be invalid itself to carry one literally.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn envelope_of(m: &Value) -> Envelope {
    Envelope {
        from: s(m, "from").into(),
        to: s(m, "to").into(),
        message_id: s(m, "messageId").into(),
        context_id: m
            .get("contextId")
            .and_then(|c| c.as_str())
            .map(String::from),
        timestamp: m.get("timestamp").and_then(|t| t.as_i64()).unwrap_or(0),
        text: s(m, "text").into(),
    }
}

fn find_vectors() -> (String, String) {
    for p in [
        "../vectors/wire_vectors.json",
        "../../vectors/wire_vectors.json",
        "vectors/wire_vectors.json",
    ] {
        if let Ok(t) = std::fs::read_to_string(p) {
            let abs = std::fs::canonicalize(p)
                .map(|a| a.display().to_string())
                .unwrap_or_else(|_| p.to_string());
            return (abs, t);
        }
    }
    eprintln!("error: vectors/wire_vectors.json not found — run this from the rust/ directory");
    exit(2);
}

fn main() {
    let (path, raw) = find_vectors();
    let v: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: the vectors are not readable: {e}");
            exit(2);
        }
    };
    let mut r = Report {
        pass: 0,
        failures: vec![],
    };

    // ---- canonical: the bytes, case by case
    for c in v["canonical"].as_array().unwrap_or(&vec![]) {
        let name = s(c, "name");
        let want = s(c, "canonical");
        match canonical(&c["payload"]) {
            Ok(got) => r.check(
                got == want,
                &format!("canonical/{name}"),
                &format!("got  {got}\n      want {want}\n      {}", s(c, "why")),
            ),
            Err(e) => r.check(
                false,
                &format!("canonical/{name}"),
                &format!("refused a case it must render: {e}"),
            ),
        }
    }

    // ---- numberHazards: values a signer must never emit. The JavaScript runner counts these
    // and leaves them; here, as in Go, they are executed, because a Rust encoder that quietly
    // rendered one would be exactly the drift the group exists to catch.
    for c in v["numberHazards"].as_array().unwrap_or(&vec![]) {
        r.check(
            canonical(&c["payload"]).is_err(),
            &format!("numberHazard/{}", s(c, "name")),
            &format!(
                "rendered a value Python and JavaScript spell differently ({} against {})",
                s(c, "pythonCanonical"),
                s(c, "javascriptWouldWrite")
            ),
        );
    }

    // ---- did:key, both directions
    let mut ed = 0;
    for c in v["did"].as_array().unwrap_or(&vec![]) {
        if s(c, "curve") != "ed25519" {
            continue;
        }
        ed += 1;
        let hex = s(c, "publicHex");
        let pk: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        let got = did_from_public_key(&pk).unwrap_or_default();
        r.check(
            got == s(c, "did"),
            &format!("did/encode/{}", &hex[..8]),
            &format!("got {got}, want {}", s(c, "did")),
        );
        let back = public_key_from_did(s(c, "did")).unwrap_or([0u8; 32]);
        let back_hex: String = back.iter().map(|b| format!("{b:02x}")).collect();
        r.check(
            back_hex == hex,
            &format!("did/decode/{}", &hex[..8]),
            &format!("got {back_hex}, want {hex}"),
        );
    }

    // ---- the signing envelope: the exact bytes that are signed
    for c in v["envelope"].as_array().unwrap_or(&vec![]) {
        let want = s(c, "signingPayload");
        let got = envelope_of(c).signing_payload().unwrap_or_default();
        r.check(
            got == want,
            &format!("envelope/{}", s(c, "name")),
            &format!("got  {got}\n      want {want}"),
        );
    }

    // ---- a round trip through this build's own signer and verifier
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let sk = SigningKey::from_bytes(&seed);
    let did = did_from_public_key(sk.verifying_key().as_bytes()).unwrap_or_default();
    let e = Envelope {
        from: did.clone(),
        to: did.clone(),
        message_id: "m1".into(),
        context_id: Some("c1".into()),
        timestamp: 1752451200,
        text: "hi ⚡ 日本語".into(),
    };
    let payload = e.signing_payload().unwrap_or_default();
    let sig = sk.sign(payload.as_bytes());
    r.check(
        e.verify(&sig.to_bytes(), &did),
        "envelope/round-trip",
        "this build cannot verify what it just signed",
    );

    // ---- the refusals
    for c in v["reject"]["message"].as_array().unwrap_or(&vec![]) {
        let input = c.get("input").unwrap_or(c);
        let e = envelope_of(input);
        // The recipient comes from the TOP LEVEL of the case — the caller's own idea of who
        // it is — and falls back to `to`. It never comes from inside `input`, which is what
        // arrived on the wire. There used to be an `s(input, "recipientDid")` step in this
        // chain, and it would have made `wire-names-its-own-recipient` unable to fail: the
        // runner would have supplied the very field the case exists to prove is ignored.
        //
        // `verifierNamesNoRecipient` says the verifier knows nobody, so it is handed "".
        // `envelope_of` never reads `recipientDid` and `Envelope` has no such member, so in
        // Rust the wire's self-nomination is structurally unreachable; what this case pins
        // here is that `verify` REFUSES an empty recipient rather than helpfully substituting
        // `self.to`, which is the JavaScript defect ported.
        let mut recipient = s(c, "recipientDid").to_string();
        if recipient.is_empty() && !c["verifierNamesNoRecipient"].as_bool().unwrap_or(false) {
            recipient = e.to.clone();
        }
        // The base64 goes through agent_seam::decode_signature — the library, not a
        // hand-rolled decoder in this file that did `continue` on anything outside the
        // alphabet. Its error is a REFUSAL: a vector that pins the SPELLING of a signature
        // has to fail for that reason and not because a permissive decoder happened to
        // produce the wrong bytes.
        let decoded = decode_signature(s(input, "sig"));
        let refused = decoded
            .as_ref()
            .map(|sig| !e.verify(sig, &recipient))
            .unwrap_or(true);
        r.check(
            refused,
            &format!("reject/{}", s(c, "name")),
            &format!("ACCEPTED a message it must refuse — {}", s(c, "note")),
        );
    }

    // ---- the encoding boundary: raw document BYTES, not a value
    //
    // This group carries the hex of a whole JSON document, because the defect it pins cannot
    // survive a parse: a repairing reader turns an unpaired surrogate escape and an invalid
    // UTF-8 byte alike into U+FFFD, and U+FFFD is a legitimate character every reference
    // encodes happily — three different documents become one and sign one byte string, with
    // nothing failing and nobody told. Go's encoding/json does that, which is why the Go
    // reference had to grow its own parse boundary.
    //
    // serde_json does not, and `from_slice` is the reason this loop is three lines rather than
    // thirty: it validates UTF-8 on the way in and refuses a lone surrogate escape while
    // parsing. This half of the contract comes free in Rust — which is worth checking rather
    // than assuming, because "free" is exactly the kind of guarantee a dependency bump moves.
    for c in v["reject"]["encoding"]["accept"]
        .as_array()
        .unwrap_or(&vec![])
    {
        let name = s(c, "name");
        let want = s(c, "canonical");
        match unhex(s(c, "documentHex"))
            .ok_or_else(|| "documentHex is not hex".to_string())
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).map_err(|e| e.to_string()))
            .and_then(|doc| canonical(&doc))
        {
            Ok(got) => r.check(
                got == want,
                &format!("encoding/accept/{name}"),
                &format!("got  {got}\n      want {want}"),
            ),
            Err(e) => r.check(
                false,
                &format!("encoding/accept/{name}"),
                &format!(
                    "refused a document it must render: {e}\n      {}",
                    s(c, "why")
                ),
            ),
        }
    }
    for c in v["reject"]["encoding"]["refuse"]
        .as_array()
        .unwrap_or(&vec![])
    {
        let refused = unhex(s(c, "documentHex"))
            .ok_or_else(|| "documentHex is not hex".to_string())
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).map_err(|e| e.to_string()))
            .and_then(|doc| canonical(&doc))
            .is_err();
        r.check(
            refused,
            &format!("encoding/refuse/{}", s(c, "name")),
            &format!("ACCEPTED bytes it must refuse — {}", s(c, "why")),
        );
    }

    // ---- reject.keystate: SKIPPED HERE, AND SAID SO.
    //
    // This reference implements no KeyState — there is no `resolve_op_did` in lib.rs, so there
    // is nothing here to hold to the anti-rollback ratchet. That is a legitimate subset (a
    // language may implement some groups and not others; tools/manifest.json says which), and
    // it is also exactly the shape of the failure this round exists to prevent: a group nobody
    // loops over is carried in the file and checked by nobody, and it looks identical to a
    // group that passes.
    //
    // So the omission is asserted rather than assumed. The group must be PRESENT and non-empty
    // — if it vanishes from the vectors, or arrives empty, this build goes red and somebody
    // reads this comment — and the verdict below prints the skip by name. An implementation
    // that later grows a KeyState resolver replaces this with a real loop.
    let ks_skipped = v["reject"]["keystate"]["accept"]
        .as_array()
        .map_or(0, Vec::len)
        + v["reject"]["keystate"]["refuse"]
            .as_array()
            .map_or(0, Vec::len);
    r.check(
        ks_skipped > 0,
        "keystate/skipped-deliberately",
        "reject.keystate is missing or empty — this runner skips the group ON PURPOSE and \
         cannot skip a group that is not there",
    );

    if !r.failures.is_empty() {
        println!(
            "\nFAILED — {} of {} checks:\n",
            r.failures.len(),
            r.pass + r.failures.len()
        );
        for f in &r.failures {
            println!("  ✗ {f}");
        }
        println!("\nA drift here is not cosmetic: these are the bytes every other implementation");
        println!("reproduces, and a mismatch is a signature that verifies nowhere.");
        exit(1);
    }
    println!(
        "OK — {} checks: the bytes match, every value no two languages spell alike was refused,",
        r.pass
    );
    println!("     and every message that must be refused was.");
    println!("     ({ed} ed25519 did cases; vectors: {path})");
    println!(
        "     SKIPPED ON PURPOSE: reject.keystate, {ks_skipped} cases — this reference implements"
    );
    println!(
        "     no KeyState, so it has no resolver to hold to the ratchet. Said out loud because"
    );
    println!("     a group nobody loops over looks exactly like a group that passes.");
}
