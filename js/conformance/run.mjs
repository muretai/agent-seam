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
  canonicalJSON, canonicalBytes, didFromPublicKeyHex, publicKeyHexFromDid, publicKeyFromSeedHex,
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

// ---------------------------------------------------------------- canonical JSON
for (const v of vectors.canonical) {
  const got = attempt(() => canonicalJSON(v.payload));
  check(got === v.canonical, `canonical/${v.name}`,
        got === v.canonical ? '' : `want ${JSON.stringify(v.canonical)}\n      got  ${JSON.stringify(got)}`);
}

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

// ---------------------------------------------------------------- the encoding boundary
// `reject.encoding` carries RAW DOCUMENT BYTES as hex rather than a parsed value, because the
// defect it pins does not survive a parse: a repaired lone surrogate and a repaired invalid
// byte are both U+FFFD by then, and U+FFFD is a character this reference encodes happily. The
// evidence is gone one line before the bytes get signed.
//
// THE DECODE MUST BE FATAL, and that is the trap. `buf.toString('utf8')` REPAIRS — measured on
// this build: `truncated-utf8-sequence`, `stray-continuation-byte` and `surrogate-encoded-as-
// utf8` all come back as ordinary strings and canonicalize without complaint, two of them
// straight into the canonical bytes of `literal-replacement-char`, which is a document in the
// ACCEPT half. A runner that decoded that way would print three green checks for three
// documents this reference had just silently rewritten. So the boundary is a fatal
// TextDecoder, which is what the seam asks of any JavaScript caller reading bytes off a wire.
//
// `canonicalBytes`, not `canonicalJSON`: `assertEncodable` lives in the former, and it is what
// refuses the surrogate ESCAPES — legal JSON text, illegal strings, which the fatal decoder
// cannot see because the document is pure ASCII. Two doors in JavaScript where Go has one, and
// both are required.
{
  const fatal = new TextDecoder('utf-8', { fatal: true });
  const parse = (hex) => JSON.parse(fatal.decode(Buffer.from(hex, 'hex')));
  const enc = vectors.reject.encoding;
  for (const c of enc.accept) {
    const got = attempt(() => canonicalBytes(parse(c.documentHex)).toString('utf8'));
    check(got === c.canonical, `encoding/accept/${c.name}`,
          got === c.canonical ? '' : `want ${JSON.stringify(c.canonical)}\n      got  ${JSON.stringify(got)}`);
  }
  for (const c of enc.refuse) {
    let refused;
    try { canonicalBytes(parse(c.documentHex)); refused = false; } catch { refused = true; }
    check(refused, `encoding/refuse/${c.name}`, `ACCEPTED bytes it must refuse — ${c.why || ''}`);
  }
}

// ---------------------------------------------------------------- the KeyState ratchet
// Every record in this group VERIFIES. Nothing here is about a bad signature — what is refused
// is a RESOLVER with no memory of this root, which answers with whatever the presenter attached
// and therefore honours an older, still-validly-signed KeyState in which a burned op-key was
// not yet burned.
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

// ---------------------------------------------------------------- device-key binding v2
{
  const b = vectors.bindingV2;
  for (const c of b.cases) {
    const binding = c.binding ?? c.input ?? c;
    const ok = attempt(() => verifyDeviceBindingV2(binding, { now: b.checkNow, expectedDeviceDid: c.deviceDid ?? binding.deviceDid ?? null }));
    check(ok === true, `bindingV2/accept/${c.name}`, `got ${JSON.stringify(ok).slice(0, 80)}`);
  }
  for (const r of b.reject) {
    const binding = r.binding ?? r.input ?? r;
    let ok;
    try { ok = verifyDeviceBindingV2(binding, { now: b.checkNow }); } catch { ok = false; }
    check(ok === false, `bindingV2/reject/${r.name}`, `ACCEPTED a binding it must refuse — ${r.why || ''}`);
  }
}

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

// ---------------------------------------------------------------- verdict
if (failures.length) {
  console.log(`FAILED — ${failures.length} of ${pass + failures.length} checks:\n`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  console.log('\nA mismatch here is not cosmetic: these bytes are what every other implementation signs and verifies.\n');
  process.exit(1);
}
console.log(`OK — ${pass} checks: the bytes match, every case that must be refused was, and what core sealed opens.`);
console.log(`     (${hazards} numberHazards read, not executed: a SIGNER rule, not bytes any single runtime can be held to.)\n`);
