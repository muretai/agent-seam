// SPDX-License-Identifier: MIT

//! The Rust reference for the seam: the byte contract two programs that have never met
//! authenticate each other with. It is held to `vectors/wire_vectors.json` by
//! `src/bin/conformance.rs`, the same file the JavaScript, Python and Go references answer to.
//!
//! WHERE A PORT ACTUALLY BREAKS. Not the signatures — Ed25519 either verifies or it does not.
//! It breaks in the JSON encoder, silently: a key order that is right for one alphabet, a
//! float spelled two ways, an integer that rounds. Nothing throws; the signature simply stops
//! verifying and the only diagnostic anyone gets is "signature verification failed".

// `Verifier` (the trait behind the permissive `verify`) is deliberately NOT imported:
// verification here goes through the inherent `verify_strict`, and leaving the trait out
// means a future edit cannot reach for the permissive check by accident.
use ed25519_dalek::{Signature, VerifyingKey};
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
///
/// NO UTF-8 GUARD HERE, AND NOT BECAUSE IT DOES NOT MATTER. The Go reference needs one and
/// carries an explicit parser for it: `encoding/json` REPAIRS an unpaired `\uD800`–`\uDFFF`
/// escape to U+FFFD on the way in, so `{"s":"\ud800"}` and `{"s":"\ufffd"}` become one
/// document and sign one identical byte string. Rust cannot reach that state: a `&str` is
/// UTF-8 by construction and cannot hold a lone surrogate, and `serde_json` refuses the
/// escape at the parse boundary rather than repairing it — measured, on every spelling:
/// lone high, lone low, either one inside a KEY, a reversed pair, a high followed by a
/// literal astral character, by plain text, by end-of-string, and by a second high; plus
/// raw invalid UTF-8 bytes through `from_slice`. All refused. A legitimate literal U+FFFD
/// and a well-formed pair still parse and encode, which is the half that must not break —
/// all four references canonicalize those and refusing them here would trade one split for
/// another.
///
/// BUT THAT VERDICT IS THE CRATE'S, NOT THIS FILE'S. Nothing in the seam states it, no
/// vector pins it, and a dependency's behaviour that nothing pins is a verdict that can
/// move under you between two minor versions — the same argument that made `verify_strict`
/// and SMALL_ORDER_PUBLIC_KEYS worth writing down. There is nothing to guard against here
/// today, so there is no code; if `serde_json` ever starts repairing instead of refusing,
/// this is the comment that says where to look, and the fix is Go's: a check at the parse
/// boundary, never in this function.
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

/// The other direction: the CODEC, and nothing more. It answers "what 32 bytes does this
/// DID spell?", byte for byte, including spellings no honest key generator would ever
/// produce — `vectors/wire_vectors.json` pins the round trip for `00..00` (a point of
/// order 4) and `ff..ff` (the non-canonical spelling of y = 18), and all four references
/// must reproduce both. The JavaScript reference draws the line in the same place:
/// `publicKeyHexFromDid` decodes anything, and `node:crypto` does the refusing inside
/// verify.
///
/// So a VERIFIER must not stop here — use [`verifying_key_from_did`], which is this plus
/// the refusal below.
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

// ---------------------------------------------------------------- small-order keys

/// THE ONE BLOB THAT AUTHENTICATES EVERYTHING. Ed25519's group has a cofactor of 8: eight
/// points sit outside the prime-order subgroup, with orders 1, 2, 4 and 8. Take the one of
/// order 1 — the identity, encoded as `0x01` followed by 31 zero bytes — and publish it as
/// your `did:key`. It renders as a perfectly ordinary DID. But verification asks whether
/// `[S]B == R + [h]A`, and when `A` is the identity, `[h]A` is the identity for EVERY
/// scalar `h`. So `R` = the identity, `S` = 0 satisfies the equation over ANY message. The
/// attacker needs no private key and never had one: one DID and one constant 64-byte blob
/// authenticate every message they will ever send, to everyone, forever. The other seven
/// torsion points are the same class of problem with more arithmetic in front of them.
///
/// `verify_strict` already refuses these, and it is what [`Envelope::verify_signature`]
/// calls. This table is here anyway, for the reason the crate header gives: a reader
/// should be able to follow the whole path from a public key to a signature without
/// leaving this file, and "the dependency handles it" is exactly the sentence that stops
/// being true one minor version later, silently, in the one place where silence is the
/// whole problem. It is also what makes the Go and Rust references literally the same
/// refusal rather than two refusals that happen to agree today.
///
/// FOURTEEN ENCODINGS, NOT EIGHT. Seven spellings of y, each with the sign bit clear or
/// set. Where x = 0 (y = 0 and y = q-1) the sign bit is simply a second spelling of one
/// point, and a permissive decoder accepts both. y = q and y = q+1 are the non-canonical
/// spellings of y = 0 and y = 1: they fit in 255 bits only because `2**255 - q == 19`,
/// which is also why no other point on this curve has a second spelling worth listing.
/// This is libsodium's blocklist, re-derived here from curve arithmetic — every entry
/// decompressed, checked to be on the curve, and checked to satisfy `[8]P == identity` —
/// rather than copied from memory. Do not edit an entry without redoing that.
pub const SMALL_ORDER_PUBLIC_KEYS: [[u8; 32]; 14] = [
    hex32("0000000000000000000000000000000000000000000000000000000000000000"), // order 4:  y = 0, x = sqrt(-1)
    hex32("0000000000000000000000000000000000000000000000000000000000000080"), // order 4:  y = 0, x = -sqrt(-1) — a different point, not a second spelling
    hex32("0100000000000000000000000000000000000000000000000000000000000000"), // order 1:  THE IDENTITY. This is the key the whole comment above is about.
    hex32("0100000000000000000000000000000000000000000000000000000000000080"), // order 1:  the identity again, sign bit set over x = 0 — a second spelling of one point
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), // order 8
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"), // order 8:  same y, other x
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), // order 8:  y = q minus the y above
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"), // order 8:  same y, other x
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // order 2:  y = q-1, x = 0
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // order 2:  y = q-1, sign bit set over x = 0 — a second spelling
    hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // order 4:  y = q, the NON-CANONICAL spelling of y = 0
    hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // order 4:  y = q, sign bit set
    hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // order 1:  y = q+1, the NON-CANONICAL spelling of the identity
    hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // order 1:  y = q+1, sign bit set
];

/// Parses one table entry at COMPILE time, so a mistyped digit above is a build failure
/// rather than a hole in the only thing standing between this reference and a universal
/// forgery.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    if b.len() != 64 {
        panic!("small-order table: an entry is not 64 hex digits");
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nybble(b[i * 2]) * 16 + nybble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nybble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("small-order table: not a lowercase hex digit"),
    }
}

/// Whether `pk` is one of the fourteen encodings above — a key under which a single
/// constant signature verifies over every message. A plain scan, not a constant-time one,
/// and deliberately: a public key is public, and the answer leaks nothing an attacker did
/// not choose themselves.
pub fn is_small_order_public_key(pk: &[u8]) -> bool {
    SMALL_ORDER_PUBLIC_KEYS.iter().any(|k| k == pk)
}

/// The ingress every verifier must use: [`public_key_from_did`] plus the refusal. Split
/// from the codec on purpose — the codec has to spell anything, because the `did` vectors
/// pin encodings a verifier must never accept — and this is the only door in this file
/// from a DID to bytes that are about to answer a signature question.
pub fn verifying_key_from_did(did: &str) -> Result<[u8; 32], String> {
    let pk = public_key_from_did(did)?;
    if is_small_order_public_key(&pk) {
        return Err(format!(
            "did:key: {did} is a small-order point — one signature verifies under it over every message, so it names nobody"
        ));
    }
    Ok(pk)
}

// ---------------------------------------------------------------- the signature field

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, written here rather than taken as a third crate — twenty lines, and it
/// is needed for the re-encoding check below, which is the whole rule.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Reads the base64 a signature arrives in and demands that it have exactly ONE spelling.
/// The rule is character for character the one `js/seam.mjs` applies in `strictB64` and the
/// one `shared/` applies in its `_b64_sig` helpers; whichever side is more permissive
/// becomes the split, so it is written out here rather than delegated.
///
///  1. the standard alphabet and nothing else — `^[A-Za-z0-9+/]*={0,2}$`, so `-` and `_`
///     are refused and padding can only be the trailing one or two characters;
///  2. length a multiple of 4;
///  3. decode, RE-ENCODE, and demand the input back character for character.
///
/// THE THIRD RULE IS THE ONLY ONE THAT SAYS CANONICAL, and the first two look total without
/// it. A 64-byte signature is 88 characters ending `==`; its last data character carries 6
/// bits of which the decoder reads 2 and DISCARDS 4, so all 16 characters sharing those top
/// 2 bits decode to the identical 64 bytes. `…BQ==` through `…Bf==` are ONE signature under
/// SIXTEEN names. One `=` discards 2 bits: a family of 4.
///
/// This replaces a hand-rolled decoder in the conformance runner that did `continue` on any
/// character outside the alphabet — the most permissive of the four references, silently
/// discarding junk the way `Buffer.from` and a bare `b64decode` used to. A rule that lives
/// in a test is not part of the contract, which is why it is here and the runner calls it.
///
/// It does NOT check the length of the decoded bytes: that belongs where it already is, in
/// [`Envelope::verify_signature`], and keeping this about the SPELLING alone lets one rule
/// cover every base64 field the contract compares by identity.///
/// WHY THIS RULE IS FOR BASE64 AND NOT FOR `did:key`. base64 has a degeneracy base58 does
/// not: the trailing bits of a padded string are unconstrained, so one byte string has a
/// family of names. `did:key` is base58 over a big integer, which is unique once the byte
/// length is fixed — and [`public_key_from_did`] fixes it at 34, with a leading `0xed` that
/// can never be a leading zero byte, so no leading `1` survives either. Measured rather
/// than assumed: 2798 alternate spellings of one DID, and not one decoded to the same key.
/// So the rule is drawn where the degeneracy actually is, and nowhere else.
pub fn decode_signature(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 4 != 0 {
        return Err(format!(
            "signature: base64 length {} is not a multiple of 4",
            s.len()
        ));
    }
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 {
        return Err(format!(
            "signature: {s:?} has more than two padding characters"
        ));
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 4 * 3);
    for c in body.bytes() {
        let Some(i) = B64.iter().position(|&a| a == c) else {
            return Err(format!(
                "signature: {:?} is not in the standard base64 alphabet",
                c as char
            ));
        };
        acc = (acc << 6) | i as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    let canon = b64_encode(&out);
    if canon != s {
        return Err(format!(
            "signature: {s:?} is not the canonical base64 of the bytes it decodes to — that is \
             {canon:?}, and the difference is the trailing bits no decoder reads"
        ));
    }
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
        let Ok(pk) = verifying_key_from_did(&self.from) else {
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
        // verify_strict, NOT verify. `verify` is dalek's legacy-compatible check — the
        // permissive RFC 8032 equation, kept because "one doesn't simply get to change the
        // definition of a cryptographic primitive ten years after-the-fact". It accepts a
        // small-order public key, and with it the constant blob that authenticates every
        // message (see SMALL_ORDER_PUBLIC_KEYS). verify_strict is the check RFC 8032 §5.1.7
        // and "Taming the Many EdDSAs" recommend: it refuses a small-order A *and* a
        // small-order R, so a signature is malleable neither in the key nor in the nonce.
        // node:crypto refuses the same keys, which is the point — this line is what makes
        // the Rust reference answer a forged blob the way the JavaScript one does.
        vk.verify_strict(payload.as_bytes(), &Signature::from_bytes(&raw))
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
