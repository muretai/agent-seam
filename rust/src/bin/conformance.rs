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

use agent_seam::{canonical, did_from_public_key, public_key_from_did, Envelope};
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

/// Base64 decode, twenty lines, so the crate list stays at the two that earn it.
fn b64(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let Some(i) = A.iter().position(|&a| a == c) else {
            continue;
        };
        acc = (acc << 6) | i as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
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
        let mut recipient = s(c, "recipientDid").to_string();
        if recipient.is_empty() {
            recipient = s(input, "recipientDid").to_string();
        }
        if recipient.is_empty() {
            recipient = e.to.clone();
        }
        let sig = b64(s(input, "sig"));
        r.check(
            !e.verify(&sig, &recipient),
            &format!("reject/{}", s(c, "name")),
            &format!("ACCEPTED a message it must refuse — {}", s(c, "note")),
        );
    }

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
}
