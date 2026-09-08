// SPDX-License-Identifier: MIT

//! The Rust reference for the seam: the byte contract two programs that have never met
//! authenticate each other with. It is held to `vectors/wire_vectors.json` by
//! `src/bin/conformance.rs`, the same file the JavaScript, Python and Go references answer to.
//!
//! WHERE A PORT ACTUALLY BREAKS. Not the signatures — Ed25519 either verifies or it does not.
//! It breaks in the JSON encoder, silently: a key order that is right for one alphabet, a
//! float spelled two ways, an integer that rounds. Nothing throws; the signature simply stops
//! verifying and the only diagnostic anyone gets is "signature verification failed".

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use std::fmt::Write as _;

// ---------------------------------------------------------------- canonical JSON

/// The largest integer a JavaScript Number holds exactly. Python would carry more, so an
/// integer past this is not a formatting difference between two references — it is silent
/// corruption, and it is refused rather than signed.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Renders `v` exactly as Python's
/// `json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
///
/// `v` must come from `serde_json` built with `arbitrary_precision`. That is not a
/// convenience: without it every number arrives as `f64`, which loses the difference between
/// `1` and `1.0` — the single most expensive difference this contract exists to prevent,
/// because Python writes `1.0` where JavaScript writes `1` and no verifier can afterwards
/// reconstruct which was signed.
pub fn canonical(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    encode_value(&mut out, v)?;
    Ok(out)
}

fn encode_value(out: &mut String, v: &Value) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) => encode_string(out, s),
        Value::Number(n) => encode_number(out, n.as_str())?,
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_value(out, e)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            // Python sorts by Unicode code point. Rust's `str` ordering is byte-wise over
            // UTF-8, and UTF-8 byte order IS code point order — the one hard rule a Rust or
            // Go port gets for free, and the one a UTF-16 language does not: there U+FFFD
            // sorts AFTER an astral character and Python puts it before.
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_string(out, k);
                out.push(':');
                encode_value(out, &m[*k])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Matches `json.dumps(ensure_ascii=False)`: the short escapes Python uses, a lowercase
/// `\u00xx` for the remaining control characters, and everything else literal — including
/// `/`, DEL and every non-ASCII character.
fn encode_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn encode_number(out: &mut String, lit: &str) -> Result<(), String> {
    if let Ok(i) = lit.parse::<i64>() {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
            return Err(format!("canonical: integer outside +/-(2**53-1) ({lit})"));
        }
        let _ = write!(out, "{i}");
        return Ok(());
    }
    let f: f64 = lit
        .parse()
        .map_err(|_| format!("canonical: unreadable number ({lit})"))?;
    if !f.is_finite() {
        return Err(format!("canonical: non-finite number ({lit})"));
    }
    if f == f.trunc() {
        // 1.0, -0.0, 2e3. Python writes "1.0", JavaScript writes "1", and JSON.parse cannot
        // tell afterwards which was meant. A signer must never emit one.
        return Err(format!(
            "canonical: integral float ({lit}) — Python and JavaScript spell it differently"
        ));
    }
    let a = f.abs();
    if a < 1e-4 || a >= 1e21 {
        // The references switch to exponent notation at different magnitudes and spell the
        // exponent differently (1e-07 against 1e-7). Outside this band, refuse.
        return Err(format!("canonical: float needs exponent notation ({lit})"));
    }
    let _ = write!(out, "{f}");
    Ok(())
}

// ---------------------------------------------------------------- base58btc and did:key

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58btc, written over bytes rather than a big integer because Rust's standard library
/// has no arbitrary-precision integer and a third crate would not earn its place here.
pub fn b58_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in data {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for &b in data {
        if b != 0 {
            break;
        }
        out.push(B58[0] as char); // every leading zero byte is one leading '1'
    }
    for &d in digits.iter().rev() {
        out.push(B58[d as usize] as char);
    }
    out
}

pub fn b58_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = B58
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| format!("base58: {:?} is not in the alphabet", c as char))?
            as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out: Vec<u8> = s
        .bytes()
        .take_while(|&c| c == B58[0])
        .map(|_| 0u8)
        .collect();
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// ed25519 multicodec: 0xed 0x01, then the 32-byte public key.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Renders a 32-byte Ed25519 public key as `did:key`. The DID IS the key: no registry
/// answers for it, and nothing expires.
pub fn did_from_public_key(pub_key: &[u8]) -> Result<String, String> {
    if pub_key.len() != 32 {
        return Err(format!(
            "did:key: public key is {} bytes, want 32",
            pub_key.len()
        ));
    }
    let mut buf = ED25519_MULTICODEC.to_vec();
    buf.extend_from_slice(pub_key);
    Ok(format!("did:key:z{}", b58_encode(&buf)))
}

/// The other direction, and where a verifier must go: a message names its sender in `from`,
/// and the verifying key is derived FROM that name rather than taken from anything the
/// message also carries.
pub fn public_key_from_did(did: &str) -> Result<[u8; 32], String> {
    let rest = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| format!("did:key: {did:?} does not start with \"did:key:z\""))?;
    let raw = b58_decode(rest)?;
    if raw.len() != 34 || raw[0] != ED25519_MULTICODEC[0] || raw[1] != ED25519_MULTICODEC[1] {
        return Err("did:key: not an ed25519 multicodec of the right length".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[2..]);
    Ok(out)
}

// ---------------------------------------------------------------- the signing envelope

/// The six fields that are signed, and the only six. `context_id` may be absent, and is then
/// `null` in the bytes.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: String,
    pub to: String,
    pub message_id: String,
    pub context_id: Option<String>,
    pub timestamp: i64,
    pub text: String,
}

impl Envelope {
    /// The exact bytes a sender signs and a receiver verifies.
    pub fn signing_payload(&self) -> Result<String, String> {
        let mut m = serde_json::Map::new();
        m.insert("from".into(), Value::String(self.from.clone()));
        m.insert("to".into(), Value::String(self.to.clone()));
        m.insert("messageId".into(), Value::String(self.message_id.clone()));
        m.insert(
            "contextId".into(),
            match &self.context_id {
                Some(c) => Value::String(c.clone()),
                None => Value::Null,
            },
        );
        m.insert(
            "timestamp".into(),
            serde_json::from_str(&self.timestamp.to_string()).map_err(|e| e.to_string())?,
        );
        m.insert("text".into(), Value::String(self.text.clone()));
        canonical(&Value::Object(m))
    }

    /// Did the key `from` names sign these exact bytes? Never trusts a key the message carries.
    pub fn verify_signature(&self, sig: &[u8]) -> bool {
        if self.from.is_empty() || sig.len() != 64 {
            return false;
        }
        let Ok(pk) = public_key_from_did(&self.from) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        let mut raw = [0u8; 64];
        raw.copy_from_slice(sig);
        vk.verify(payload.as_bytes(), &Signature::from_bytes(&raw))
            .is_ok()
    }

    /// Adds the question a receiver must also ask: was this addressed to me? A valid
    /// signature on a message meant for someone else is still meant for someone else.
    pub fn verify(&self, sig: &[u8], recipient_did: &str) -> bool {
        if recipient_did.is_empty() || self.to != recipient_did {
            return false;
        }
        self.verify_signature(sig)
    }
}
