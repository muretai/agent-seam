#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/*
 * js/conformance/run.mjs — hold js/seam.mjs to the golden vectors.
 *
 * The positive half proves this build produces the same BYTES as every other implementation
 * (canonical JSON, did:key, the six signed fields, card envelopes, cryptobox); the negative
 * half proves it REFUSES what it must — the half that catches an implementation which
 * verifies nothing. A drift in either direction is silent on the wire.
 *
 * Ported from @muretai/agent-entry's conformance/run.mjs (29 checks over the published subset)
 * and extended to the groups the block implements: did decode, cardpub verify, cryptobox open,
 * device binding v2, and Web Bot Auth over vectors/wba_vectors.json.
 *
 * NOT here (follow-ups, see README): `ownerState`, `binding` v1, `relay`, `invite`,
 * `domainLinkage` (no JS implementation in the block). `keystate` IS here now, as
 * `reject.keystate`: the anti-rollback ratchet, driven through the four-argument
 * `resolveOpDid(rootDid, inline, now, { pinned })`.
 *
 * Run:  node js/conformance/run.mjs      (from the repo root)      npm test
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  canonicalJSON, canonicalFromJSON, didFromPublicKeyHex, publicKeyHexFromDid, publicKeyFromSeedHex,
  signingPayload, signEnvelope, verifyEnvelope, cardEnvelopePayload, verifyCardEnvelope,
  encPubHex, openBox, verifyDeviceBindingV2, wbaVerifyRequest, resolveOpDid,
} from '../seam.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(HERE, '..', '..', 'vectors', 'wire_vectors.json'), 'utf8'));
const wba = JSON.parse(readFileSync(join(HERE, '..', '..', 'vectors', 'wba_vectors.json'), 'utf8'));

let pass = 0;
const failures = [];

function check(ok, label, detail) {
  if (ok) { pass += 1; return true; }
  failures.push(detail ? `${label}\n      ${detail}` : label);
  return false;
}
const attempt = (fn) => { try { return fn(); } catch (e) { return `THREW: ${e.message}`; } };

// WHICH GROUP PRODUCED WHICH CHECKS. `drove(name)` closes a section: it attributes every check
// counted since the previous call to `name`, which is a group name spelled EXACTLY as
// `tools/manifest.json` spells it for this language. The verdict then diffs the two.
//
// Attribution by delta rather than by wrapping each `check` keeps the loops below unchanged and
// works because the sections are contiguous and in order; a group whose loop ran zero times
// closes with a delta of zero, which is precisely the case this exists to catch.
const drove = new Map();
let droveMark = 0;
function droveGroup(name) {
  const total = pass + failures.length;
  drove.set(name, (drove.get(name) ?? 0) + (total - droveMark));
  droveMark = total;
}

// ---------------------------------------------------------------- canonical JSON
for (const v of vectors.canonical) {
  const got = attempt(() => canonicalJSON(v.payload));
  check(got === v.canonical, `canonical/${v.name}`,
        got === v.canonical ? '' : `want ${JSON.stringify(v.canonical)}\n      got  ${JSON.stringify(got)}`);
}
droveGroup('canonical');

// `numberHazards` is DELIBERATELY NOT EXECUTED, and reading it is the point. Every case
// there is a value whose canonical bytes differ between languages, so asserting either
// spelling would be asserting one runtime's float formatting — the opposite of the
// contract. The rule it carries is a SIGNER discipline (`signMustNotEmit`), not a
// canonicaliser output: never sign a payload containing one, because the bytes you produce
// will only verify where they were produced.
const hazards = vectors.numberHazards?.length ?? 0;

// ---------------------------------------------------------------- did:key, both directions
for (const v of vectors.did) {
  if (v.curve !== 'ed25519') continue;          // p256 did:key is not an envelope signer
  const got = attempt(() => didFromPublicKeyHex(v.publicHex));
  check(got === v.did, `did/encode/${v.publicHex.slice(0, 12)}…`, got === v.did ? '' : `want ${v.did}\n      got  ${got}`);
  const back = attempt(() => publicKeyHexFromDid(v.did));
  check(back === v.publicHex, `did/decode/${v.did.slice(8, 20)}…`, back === v.publicHex ? '' : `want ${v.publicHex}\n      got  ${back}`);
}
droveGroup('did');
// The other direction of the same door. `did` above is ten positive round-trips, and a decoder
// that answered `raw.subarray(2)` for anything at all would pass every one of them — so
// `spec/seam.md` §2's two verdict rules, the multicodec and the length, are pinned from the side
// that can fail. `x25519-multicodec` is the sharp one: 34 bytes, exactly what an ed25519 did:key
// decodes to, so only the PREFIX check refuses it and a decoder that measures alone hands back
// somebody's X25519 key as a verification key.
for (const c of vectors.reject.did) {
  let refused;
  try { publicKeyHexFromDid(c.did); refused = false; } catch { refused = true; }
  check(refused, `did/reject/${c.name}`, `DECODED a did:key it must refuse — ${c.why || ''}`);
}
droveGroup('reject.did');

// ---------------------------------------------------------------- the six signed fields
for (const v of vectors.envelope) {
  const fields = { from: v.from, to: v.to, messageId: v.messageId,
                   contextId: v.contextId ?? null, timestamp: v.timestamp, text: v.text };
  const got = attempt(() => signingPayload(fields));
  check(got === v.signingPayload, `envelope/${v.name}`,
        got === v.signingPayload ? '' : `want ${JSON.stringify(v.signingPayload)}\n      got  ${JSON.stringify(got)}`);
}
// A signature this build makes must verify in this build — the weakest claim on its own,
// which is exactly why the byte checks above and the refusals below are not optional.
{
  const seed = '11'.repeat(32);
  const from = didFromPublicKeyHex(publicKeyFromSeedHex(seed));
  const fields = { from, to: from, messageId: 'm1', contextId: null, timestamp: 1752451200, text: 'round trip' };
  const sig = signEnvelope(seed, fields);
  check(verifyEnvelope({ ...fields, sig }, { recipientDid: from }), 'envelope/round-trip');
}
droveGroup('envelope');

// ---------------------------------------------------------------- the refusals
// The case's message lives under `input`; `recipientDid` (when a case pins one) sits beside
// it at the TOP LEVEL, and that distinction is what this loop turns on. The top level is the
// CALLER — the verifier's own idea of who it is. Everything inside `input` arrived on the wire
// and is the attacker's to write.
//
// So the fallback chain reads the top level and then `input.to`, and NEVER
// `input.recipientDid`. It used to read that too, which quietly made
// `wire-names-its-own-recipient` unable to fail: the runner would have handed `verifyEnvelope`
// the very field the case exists to prove is ignored, and the check would have been green
// whichever way the library behaved.
//
// `verifierNamesNoRecipient` is the other half. The verifier is called with NO recipient at
// all, while the message's own unsigned `recipientDid` is copied into `fields` and left
// exactly where a fallback would find it. `verifyEnvelope` must refuse before it ever looks at
// the signature — which is genuinely valid, for a real recipient — because who "me" is comes
// from the caller or from nowhere.
for (const v of vectors.reject.message) {
  const m = v.input ?? v;
  const fields = { from: m.from, to: m.to, messageId: m.messageId, contextId: m.contextId ?? null,
                   timestamp: m.timestamp, text: m.text, sig: m.sig };
  if (m.recipientDid !== undefined) fields.recipientDid = m.recipientDid;   // unsigned, and bait
  const opts = v.verifierNamesNoRecipient ? {} : { recipientDid: v.recipientDid ?? m.to };
  let accepted;
  try { accepted = verifyEnvelope(fields, opts); }
  catch { accepted = false; }                    // refusing by throwing is still refusing
  check(accepted === false, `reject/${v.name}`,
        accepted === false ? '' : `ACCEPTED a message it must refuse — ${v.note || v.why || ''}`);
}
droveGroup('reject.message');

// ---------------------------------------------------------------- the encoding boundary
// `reject.encoding` carries RAW DOCUMENT BYTES as hex rather than a parsed value, because the
// defect it pins does not survive a parse: a repaired lone surrogate and a repaired invalid
// byte are both U+FFFD by then, and U+FFFD is a character this reference encodes happily. The
// evidence is gone one line before the bytes get signed.
//
// THE PATH IS `canonicalFromJSON`, one named function of the library, and that it is not three
// lines of this runner is the fix 0.3.1 made. This loop used to assemble its own boundary —
// `new TextDecoder('utf-8', { fatal: true })`, then `JSON.parse`, then `canonicalBytes` — which
// held the reference to a RECIPE rather than to the seam, and the recipe was wrong in a way the
// runner could not see. `ignoreBOM` defaults to FALSE, and the flag means "do not STRIP", so
// that decoder silently removed a leading U+FEFF: `EF BB BF {"a":1}` parsed cleanly here while
// Go and Rust refused it at the first byte, and on this side two distinct byte strings
// collapsed to one canonical form. A runner must exercise the path a user is told to take, and
// there was no such path — only an instruction to build one.
//
// Three doors behind that one call, and the group carries a case for each. The BOM/encoding
// guard. The FATAL decode: `buf.toString('utf8')` REPAIRS — measured on this build,
// `truncated-utf8-sequence`, `stray-continuation-byte` and `surrogate-encoded-as-utf8` all come
// back as ordinary strings and canonicalize without complaint, two of them straight into the
// canonical bytes of `literal-replacement-char`, which is a document in the ACCEPT half. And
// `assertEncodable` inside `canonicalBytes`, which is what refuses the surrogate ESCAPES —
// legal JSON text, illegal strings, invisible to any decoder because the document is pure
// ASCII.
{
  const enc = vectors.reject.encoding;
  const bytes = (hex) => Buffer.from(hex, 'hex');
  for (const c of enc.accept) {
    const got = attempt(() => canonicalFromJSON(bytes(c.documentHex)).toString('utf8'));
    check(got === c.canonical, `encoding/accept/${c.name}`,
          got === c.canonical ? '' : `want ${JSON.stringify(c.canonical)}\n      got  ${JSON.stringify(got)}`);
  }
  for (const c of enc.refuse) {
    let refused;
    try { canonicalFromJSON(bytes(c.documentHex)); refused = false; } catch { refused = true; }
    check(refused, `encoding/refuse/${c.name}`, `ACCEPTED bytes it must refuse — ${c.why || ''}`);
  }
}
droveGroup('reject.encoding');

// ---------------------------------------------------------------- the KeyState ratchet
// Most records in this group VERIFY, and the ratchet cases are not about a bad signature — what
// is refused there is a RESOLVER with no memory of this root, which answers with whatever the
// presenter attached and therefore honours an older, still-validly-signed KeyState in which a
// burned op-key was not yet burned.
//
// The three `keystate-bad-signature` cases are the exception, and they are here because that
// design made the ROOT SIGNATURE untested: with every record verifying on purpose, nothing
// asked whether `verifyKeystate` checked one. Measured on 0.3.1 — short-circuit `verifyBytes`
// inside `verifyKeystate` and this file printed OK at 118. `inline-signature-forged`,
// `pin-signature-forged` and `unverified-root-rotated-pin` are the three doors an unsigned
// record comes through: the record the sender attached, the record the caller kept, and a pin
// claiming a `rootKey` that is neither the DID's own nor anything a lineage could reveal.
//
// So the call is the FOUR-argument form, `resolveOpDid(rootDid, inline, checkNow, { pinned })`,
// and `opts.pinned` is that memory. The two references take these in a different ORDER — Python
// is `resolve_op_did(root, inline, pinned, now=…)` — which is why the vector carries `pinned`
// and `inline` as named fields and never as positions.
//
// Both halves of every case are asserted: the DID that must come back, AND that it is not the
// one the attacker was fishing for. Only the second would let a resolver pass by answering the
// root every time — safe, and wrong in a way nobody notices until every enrolled peer's
// messages start failing as an unknown signer.
//
// A THROW IS THAT CASE FAILING, NOT THE RUNNER CRASHING. The `revoked-ops-*` cases carry
// `mustNotRaise`, and they earn it: `revokedOps: 5` and `revokedOps: true` are records a
// stranger can mint against their own root key, they VERIFY, and Python's `x in 5` used to take
// a TypeError straight out through a resolver documented as pure and total. `attempt` turns any
// throw into a `THREW: …` string, which can never equal the expected DID, so the case fails by
// name and the reader learns which contract broke rather than that something exploded. An
// exception and a wrong answer are both refusals of the contract; they are different refusals.
//
// The `kind` comes from WHICH LIST the case is in, never from sniffing a field. It used to be
// derived from the presence of `mustNotResolveTo`, and the `revoked-ops-*` cases carry that
// field too — over-revocation sends the resolver to the root, which is precisely the wrong
// answer worth naming — so the sniff would have labelled half the accept half as refusals.
{
  const ks = vectors.reject.keystate;
  for (const [kind, group] of [['accept', ks.accept], ['refuse', ks.refuse]]) {
    for (const c of group) {
      const got = attempt(() => resolveOpDid(ks.rootDid, c.inline, ks.checkNow, { pinned: c.pinned }));
      check(got === c.expect && got !== c.mustNotResolveTo, `keystate/${kind}/${c.name}`,
            `want ${c.expect}\n      got  ${got}\n      ${c.why || ''}`);
    }
  }
}
droveGroup('reject.keystate');

// ---------------------------------------------------------------- the signed Agent Card envelope
for (const c of vectors.cardpub) {
  const got = attempt(() => cardEnvelopePayload(c.card, c.ts));
  check(got === c.envelopePayload, `cardpub/payload/${c.name}`, got === c.envelopePayload ? '' : `want ${c.envelopePayload}\n      got  ${got}`);
  const env = { v: 1, typ: 'agentcard', card: c.card, ts: c.ts, sig: c.sig };
  const ok = attempt(() => verifyCardEnvelope(env, c.card.did));
  check(ok !== null && ok !== false && !String(ok).startsWith('THREW'), `cardpub/verify/${c.name}`, `got ${JSON.stringify(ok).slice(0, 80)}`);
}
{
  const c0 = vectors.cardpub[0];
  const env = { v: 1, typ: 'agentcard', card: c0.card, ts: c0.ts, sig: c0.sig };
  const wrong = attempt(() => verifyCardEnvelope(env, 'did:key:zSomeoneElse'));
  check(wrong === null || wrong === false, 'cardpub/wrong-did-refused', `got ${JSON.stringify(wrong).slice(0, 80)}`);
}
droveGroup('cardpub');
// THE NEGATIVE HALF, and the reason everything above it proved less than it looked. Those checks
// assert only that `verifyCardEnvelope` returned something non-null, and `cardpub/wrong-did-
// refused` exercises the `expectedDid !== card.did` STRING COMPARISON — which runs perfectly
// well inside a verifier that never looks at a signature. Measured before 0.3.1:
// `verifyCardEnvelope` cut down to a shape check plus `return card` — no base64 decode, no
// length bound, no payload, no crypto — kept this runner green at 105 and `npm test` green at
// 17 + 105. An implementation of the card envelope that returns the card for ANY signature was
// CONFORMANT by this repository's own suite, and the signed card is the only proof that a DID
// belongs to an origin: every consumer treats a non-null return as identity proven.
//
// `expectedDid` comes off the TOP LEVEL of the case — the caller's own idea of whose card it
// asked for — and never out of `envelope`, which arrived on the wire. Same rule as
// `recipientDid` in `reject.message`, and for the same reason.
for (const c of vectors.reject.cardpub) {
  const got = attempt(() => verifyCardEnvelope(c.envelope, c.expectedDid));
  const refused = got === null || got === false || String(got).startsWith('THREW');
  check(refused, `cardpub/reject/${c.name}`,
        `ACCEPTED a card envelope it must refuse — ${c.why || ''}\n      got ${JSON.stringify(got).slice(0, 80)}`);
}
droveGroup('reject.cardpub');

// ---------------------------------------------------------------- cryptobox: open what core sealed
{
  const b = vectors.cryptobox;
  check(attempt(() => encPubHex(b.senderSeed)) === b.senderEncPub, 'cryptobox/encPub/sender');
  check(attempt(() => encPubHex(b.recipientSeed)) === b.recipientEncPub, 'cryptobox/encPub/recipient');
  // `adHex` is read with NO default. Every case carries it, empty ones included, so that a
  // missing field throws here instead of quietly becoming the empty `ad` — which is the wrong
  // answer for the one case that has associated data, and would look green.
  const ad = (c) => Buffer.from(c.adHex, 'hex');
  for (const c of b.open) {
    const pt = attempt(() => openBox(b.recipientSeed, b.senderEncPub, c.blob, ad(c)));
    const hex = pt && typeof pt !== 'string' ? Buffer.from(pt).toString('hex') : String(pt);
    check(hex === c.plaintextHex, `cryptobox/open/${c.name}`, hex === c.plaintextHex ? '' : `want ${c.plaintextHex}\n      got  ${hex}`);
  }
  // The `ad` BINDING. The AEAD tag covers the associated data, so the same blob under the wrong
  // `ad` — or under none, which is the shape a port actually ships — is an AUTHENTICATION
  // failure, not a decode failure. `null`, and never a partial read: a caller who binds a
  // contextId and then opens the box under a different one has bound nothing.
  for (const c of b.mustNotOpen) {
    const pt = attempt(() => openBox(b.recipientSeed, b.senderEncPub, c.blob, ad(c)));
    check(pt === null, `cryptobox/must-not-open/${c.name}`,
          `OPENED a box sealed under different associated data — ${c.why || ''}`);
  }
}
droveGroup('cryptobox');

// ---------------------------------------------------------------- device-key binding v2
//
// `expectedDeviceDid` COMES OFF THE CASE AND NOWHERE ELSE. It is the CALLER's own idea of which
// device is sending — the same distinction the reject loop one screen above draws for
// `recipientDid`, and the same defect, still live here until 0.3.1: this loop read
// `c.deviceDid ?? binding.deviceDid ?? null`, and every case's top-level `deviceDid` EQUALS the
// binding's own, so the expected value was the binding's value every time and
// `deviceDid !== expectedDeviceDid` was a branch no case could take. The anti-copy pin — "a
// binding lifted onto another sender's message fails", the belt over the piecewise checks — had
// no test at all, in either reference.
//
// A fallback to the binding is not a convenience, it is the bug: it asks the attacker who the
// attacker is. So there is none, in either loop. A case that carries no `expectedDeviceDid`
// gets `null`, which is "the caller names nobody" — a real mode of the API, and visibly not the
// pin being exercised.
{
  const b = vectors.bindingV2;
  for (const c of b.cases) {
    const binding = c.binding ?? c.input ?? c;
    const ok = attempt(() => verifyDeviceBindingV2(binding,
      { now: b.checkNow, expectedDeviceDid: c.expectedDeviceDid ?? null }));
    check(ok === true, `bindingV2/accept/${c.name}`, `got ${JSON.stringify(ok).slice(0, 80)}`);
  }
  for (const r of b.reject) {
    const binding = r.binding ?? r.input ?? r;
    let ok;
    try {
      ok = verifyDeviceBindingV2(binding, { now: b.checkNow, expectedDeviceDid: r.expectedDeviceDid ?? null });
    } catch { ok = false; }
    check(ok === false, `bindingV2/reject/${r.name}`, `ACCEPTED a binding it must refuse — ${r.note || r.why || ''}`);
  }
  // THE PAIR. `binding-lifted-to-another-device` carries the accepted case's BYTES; only the
  // caller's expectation differs. Asserting the refusal alone would be met by a verifier that
  // refuses that record for some other reason, so the identity of the two records is asserted
  // here rather than trusted from the generator.
  const lifted = b.reject.find((r) => r.name === 'binding-lifted-to-another-device');
  const own = b.cases.find((c) => c.name === 'no-expiry');
  check(!!lifted && !!own
        && JSON.stringify(lifted.input) === JSON.stringify(own.binding)
        && lifted.expectedDeviceDid !== own.expectedDeviceDid
        && attempt(() => verifyDeviceBindingV2(lifted.input,
             { now: b.checkNow, expectedDeviceDid: own.expectedDeviceDid })) === true,
        'bindingV2/anti-copy-pin-is-the-only-difference',
        'the lifted binding must be byte-identical to the accepted one and differ only in who '
        + 'the caller expected — otherwise its refusal pins something other than the pin');
}
droveGroup('bindingV2');

// ---------------------------------------------------------------- Web Bot Auth (RFC 9421 subset), verify-only
for (const c of wba.accept) {
  const got = attempt(() => wbaVerifyRequest(c.headers, { authority: wba.authority, jwks: wba.jwks, now: wba.now }));
  check(got === c.expect_did, `wba/accept/${c.name}`, got === c.expect_did ? '' : `want ${c.expect_did}\n      got  ${got}`);
}
for (const c of wba.reject) {
  let got;
  try { got = wbaVerifyRequest(c.headers, { authority: wba.authority, jwks: wba.jwks, now: wba.now }); } catch { got = null; }
  check(got === null, `wba/reject/${c.name}`, `ACCEPTED as ${got}`);
}
droveGroup('webBotAuth(wba_vectors)');

// ---------------------------------------------------------------- what the manifest declares
//
// A COUNT NOBODY ASSERTS IS A COUNT THAT CAN QUIETLY FALL, and this repository has the
// measurement: 0.3.1 deleted four guards at once and 0.3.0's suite stayed fully green. A bare
// floor would not have caught this round's finding either — an emptied, renamed or
// filter-missed vector group produces zero checks and this file prints OK with a smaller
// number that nobody reads, because nothing here ever knew what the number should be.
//
// `tools/manifest.json` has always listed, per implementation, the groups that implementation
// covers. NOTHING READ IT. It was documentation, so it could say anything, and a group renamed
// in the vectors and missed by a loop was invisible on both sides at once. It is the assertion
// now, and the diff runs BOTH WAYS:
//
//   - every group the manifest declares for `js` must have produced at least one check. This
//     is what catches a group emptied, deleted, or missed by a filter;
//   - every group this runner drove must be declared. This is what catches a group RENAMED —
//     the one-way check would go green the moment the runner and the vectors agreed on a new
//     name the manifest had never heard of.
//
// The floor below is the belt: it catches a group that shrinks without emptying, which the
// diff cannot see.
const manifest = JSON.parse(readFileSync(join(HERE, '..', '..', 'tools', 'manifest.json'), 'utf8'));
const declared = manifest.implementations.find((x) => x.lang === 'js')?.groups ?? [];
check(declared.length > 0, 'manifest/js-declares-its-groups',
      'tools/manifest.json has no `groups` for lang "js" — this whole section then asserts nothing');
for (const name of declared) {
  const n = drove.get(name) ?? 0;
  check(n > 0, `manifest/group-drove-checks/${name}`,
        `tools/manifest.json declares \`${name}\` for js and this run produced ${n} checks from it. `
        + 'An emptied, renamed or filter-missed vector group prints OK; this is what stops it.');
}
for (const name of drove.keys()) {
  check(declared.includes(name), `manifest/group-is-declared/${name}`,
        `this runner drove \`${name}\` and tools/manifest.json does not declare it for js — `
        + 'either the manifest is stale or the group was renamed on one side only');
}

// The absolute floor, and it is DELIBERATELY EXACT rather than generous. Raising it is the
// correct response to adding a check; being unable to run it down is the point.
const FLOOR = 149;

// ---------------------------------------------------------------- verdict
if (pass + failures.length < FLOOR) {
  failures.push(`suite/check-count-floor\n      only ${pass + failures.length} checks ran and at `
    + `least ${FLOOR} were expected. Something stopped being checked; the rows above will not `
    + 'say so, because a check that does not run reports nothing.');
}
if (failures.length) {
  console.log(`FAILED — ${failures.length} of ${pass + failures.length} checks:\n`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  console.log('\nA mismatch here is not cosmetic: these bytes are what every other implementation signs and verifies.\n');
  process.exit(1);
}
console.log(`OK — ${pass} checks: the bytes match, every case that must be refused was, and what core sealed opens.`);
console.log(`     (${hazards} numberHazards read, not executed: a SIGNER rule, not bytes any single runtime can be held to.)\n`);
