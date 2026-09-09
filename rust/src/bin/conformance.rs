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

/// WHICH GROUP PRODUCED WHICH CHECKS. `close` ends a section: it attributes every check counted
/// since the previous call to `name`, which is a group name spelled EXACTLY as
/// `tools/manifest.json` spells it for this language. The verdict then diffs the two.
///
/// Attribution by delta rather than by wrapping each `check` keeps the loops below unchanged and
/// works because the sections are contiguous; a group whose loop ran zero times closes with a
/// delta of zero, which is precisely the case this exists to catch.
struct Groups {
    drove: Vec<(String, usize)>,
    mark: usize,
}

impl Groups {
    fn close(&mut self, r: &Report, name: &str) {
        let total = r.pass + r.failures.len();
        self.drove.push((name.to_string(), total - self.mark));
        self.mark = total;
    }
    fn count(&self, name: &str) -> usize {
        self.drove
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, c)| c)
            .sum()
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

/// A JSON array of strings, or an empty vector.
fn strings_of(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Locate `tools/manifest.json` the way `find_vectors` locates the vectors. A missing manifest
/// is fatal rather than skipped: the point of reading it is that the coverage claim cannot be
/// quietly absent.
fn find_manifest() -> (String, String) {
    for p in [
        "../tools/manifest.json",
        "../../tools/manifest.json",
        "tools/manifest.json",
    ] {
        if let Ok(t) = std::fs::read_to_string(p) {
            let abs = std::fs::canonicalize(p)
                .map(|a| a.display().to_string())
                .unwrap_or_else(|_| p.to_string());
            return (abs, t);
        }
    }
    eprintln!("error: tools/manifest.json not found — run this from the rust/ directory");
    exit(2);
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
    let mut g = Groups {
        drove: vec![],
        mark: 0,
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
    g.close(&r, "canonical");

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
    g.close(&r, "numberHazards");

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
    g.close(&r, "did(ed25519)");

    // ---- reject.did: the other direction of the codec above.
    //
    // `did` is ten positive round-trips, and a decoder that answered `raw[2..]` for anything at
    // all would pass every one of them — so spec §2's two verdict rules, the multicodec and the
    // length, are pinned here from the side that can fail. `x25519-multicodec` is the sharp
    // one: THIRTY-FOUR BYTES, exactly what an ed25519 `did:key` decodes to, so only the PREFIX
    // check refuses it and a decoder that measures alone hands back somebody's X25519 key as a
    // verification key.
    //
    // The group carries no over-long case, deliberately: no over-long base58 string can decode
    // to 34 bytes (a longer string is a larger integer, and leading '1's only add leading zero
    // bytes), so the length rule refuses every one of them with or without a cap — such a
    // vector would be green in an implementation that has none. The cap is in lib.rs as
    // MAX_BASE58_LEN regardless, because it buys CPU rather than a verdict.
    let did_rejects = v["reject"]["did"].as_array().cloned().unwrap_or_default();
    r.check(
        !did_rejects.is_empty(),
        "did/reject/group-present",
        "reject.did is missing or empty — this runner loops over it and cannot loop over nothing",
    );
    for c in &did_rejects {
        r.check(
            public_key_from_did(s(c, "did")).is_err(),
            &format!("did/reject/{}", s(c, "name")),
            &format!("DECODED a did:key it must refuse — {}", s(c, "why")),
        );
    }
    g.close(&r, "reject.did");

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
    g.close(&r, "envelope");

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
    g.close(&r, "reject.message");

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
    g.close(&r, "reject.encoding");

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

    // ---- reject.cardpub: SKIPPED HERE TOO, AND SAID SO, by the same discipline and for the
    // same reason. There is no card envelope in lib.rs — the README's coverage table has marked
    // `cardpub` as "—" for Rust since this reference was written — so there is nothing here to
    // hold to it. The group is new in 0.3.1 and closes the largest hole this repository had, so
    // it is worth saying plainly that Rust is not one of the implementations closing it.
    let card_skipped = v["reject"]["cardpub"].as_array().map_or(0, Vec::len);
    r.check(
        card_skipped > 0,
        "cardpub/skipped-deliberately",
        "reject.cardpub is missing or empty — this runner skips the group ON PURPOSE and \
         cannot skip a group that is not there",
    );

    // ---- what the manifest declares this implementation covers.
    //
    // A COUNT NOBODY ASSERTS IS A COUNT THAT CAN QUIETLY FALL, and this repository has the
    // measurement: 0.3.1 deleted four guards at once and 0.3.0's suite stayed fully green. A
    // bare floor would not have caught this round's finding either — an emptied, renamed or
    // filter-missed vector group produces zero checks and this file prints OK with a smaller
    // number nobody reads, because nothing here ever knew what the number should be.
    //
    // `tools/manifest.json` has always listed, per implementation, the groups it covers and the
    // groups it deliberately skips. NOTHING READ IT. It was documentation, so it could say
    // anything, and a group renamed in the vectors and missed by a loop was invisible on both
    // sides at once. It is the assertion now, and the diff runs BOTH WAYS: every declared group
    // must have produced a check (an emptied or missed group), and every group driven must be
    // declared (a group RENAMED, which the one-way check goes green on the moment the runner
    // and the vectors agree on a name the manifest never heard of).
    //
    // The skips are held to the same standard from the other side: a group this runner asserts
    // it is skipping must be listed as a skip, and must not also be listed as covered.
    let (mpath, mraw) = find_manifest();
    let man: Value = match serde_json::from_str(&mraw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: tools/manifest.json is not readable: {e}");
            exit(2);
        }
    };
    let mine = man["implementations"]
        .as_array()
        .and_then(|a| a.iter().find(|m| s(m, "lang") == "rust"))
        .cloned()
        .unwrap_or(Value::Null);
    r.check(
        !mine.is_null(),
        "manifest/rust-is-an-implementation",
        &format!("tools/manifest.json ({mpath}) has no entry with lang \"rust\""),
    );
    let declared = strings_of(&mine, "groups");
    let skips = strings_of(&mine, "skips");
    r.check(
        !declared.is_empty(),
        "manifest/rust-declares-its-groups",
        "the manifest lists no `groups` for rust — this whole section then asserts nothing",
    );
    for name in &declared {
        let n = g.count(name);
        r.check(
            n > 0,
            &format!("manifest/group-drove-checks/{name}"),
            &format!(
                "tools/manifest.json declares `{name}` for rust and this run produced {n} checks \
                 from it. An emptied, renamed or filter-missed vector group prints OK; this is \
                 what stops it."
            ),
        );
    }
    let driven: Vec<String> = g.drove.iter().map(|(n, _)| n.clone()).collect();
    for name in &driven {
        r.check(
            declared.contains(name),
            &format!("manifest/group-is-declared/{name}"),
            &format!(
                "this runner drove `{name}` and the manifest does not declare it for rust — \
                 either the manifest is stale or the group was renamed on one side only"
            ),
        );
    }
    // The two groups asserted-and-skipped above must be exactly the two the manifest calls
    // skips, and a group cannot be both covered and skipped.
    for name in ["reject.keystate", "reject.cardpub"] {
        r.check(
            skips.iter().any(|x| x == name),
            &format!("manifest/skip-is-declared/{name}"),
            &format!(
                "this runner skips `{name}` by name and the manifest does not list it under \
                 `skips`"
            ),
        );
    }
    for name in &skips {
        r.check(
            !declared.contains(name),
            &format!("manifest/skip-is-not-also-covered/{name}"),
            &format!("the manifest lists `{name}` as both covered and skipped for rust"),
        );
        r.check(
            g.count(name) == 0,
            &format!("manifest/skipped-group-drove-nothing/{name}"),
            &format!("the manifest calls `{name}` a skip and this runner attributed checks to it"),
        );
    }

    // The absolute floor, DELIBERATELY EXACT rather than generous. Raising it is the correct
    // response to adding a check; being unable to run it down is the point. It catches a group
    // that shrinks without emptying, which the diff above cannot see.
    const FLOOR: usize = 88;
    if r.pass + r.failures.len() < FLOOR {
        let ran = r.pass + r.failures.len();
        r.failures.push(format!(
            "suite/check-count-floor\n      only {ran} checks ran and at least {FLOOR} were \
             expected. Something stopped being checked; the rows above will not say so, because \
             a check that does not run reports nothing."
        ));
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
    println!(
        "     SKIPPED ON PURPOSE: reject.keystate, {ks_skipped} cases — this reference implements"
    );
    println!("     no KeyState, so it has no resolver to hold to the ratchet; and reject.cardpub,");
    println!(
        "     {card_skipped} cases — no card envelope here either. Said out loud because a group"
    );
    println!("     nobody loops over looks exactly like a group that passes.");
}
