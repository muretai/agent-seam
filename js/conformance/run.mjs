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
 * NOT here (follow-ups, see README): `keystate`/`ownerState` (verifyKeystate is pinned only by
 * core's live harness — no vector group yet), `binding` v1, `relay`, `invite`, `domainLinkage`
 * (no JS implementation in the block).
 *
 * Run:  node js/conformance/run.mjs      (from the repo root)      npm test
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  canonicalJSON, didFromPublicKeyHex, publicKeyHexFromDid, publicKeyFromSeedHex, signingPayload,
  signEnvelope, verifyEnvelope, cardEnvelopePayload, verifyCardEnvelope, encPubHex, openBox,
  verifyDeviceBindingV2, wbaVerifyRequest,
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
// it at the top level. Reading the recipient from the top level is what makes each case
// exercise the attack it is named for rather than fail for "no recipient".
for (const v of vectors.reject.message) {
  const m = v.input ?? v;
  const fields = { from: m.from, to: m.to, messageId: m.messageId, contextId: m.contextId ?? null,
                   timestamp: m.timestamp, text: m.text, sig: m.sig };
  let accepted;
  try { accepted = verifyEnvelope(fields, { recipientDid: v.recipientDid ?? m.recipientDid ?? m.to }); }
  catch { accepted = false; }                    // refusing by throwing is still refusing
  check(accepted === false, `reject/${v.name}`, accepted === false ? '' : `ACCEPTED a message it must refuse — ${v.why || ''}`);
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
  for (const c of b.open) {
    const pt = attempt(() => openBox(b.recipientSeed, b.senderEncPub, c.blob));
    const hex = pt && typeof pt !== 'string' ? Buffer.from(pt).toString('hex') : String(pt);
    check(hex === c.plaintextHex, `cryptobox/open/${c.name}`, hex === c.plaintextHex ? '' : `want ${c.plaintextHex}\n      got  ${hex}`);
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
