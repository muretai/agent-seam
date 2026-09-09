// SPDX-License-Identifier: MIT
/*
 * agent-seam/js/seam.mjs — the seam: the byte contract two programs that have never met
 * authenticate each other with, as ONE file with no dependencies. It belongs to no
 * implementation. THIS IS ITS HOME. Edit it here; every consumer re-vendors.
 *
 * WHO CARRIES A COPY. The Agent Entry door (`@muretai/agent-entry`, muretai-agent-entry.mjs)
 * carries the block between the `CANONICAL JSON` banner and `// ---- end of the seam` verbatim,
 * plus the declarations under the `// ---- pinned:` marker (the wire constants, the JSON-RPC
 * error table and three small helpers the block calls): `scripts/vendor-seam.mjs` there splices
 * the block in, and `conformance/seam-twin.mjs` fails when either drifts. `@muretai/agent-site-checker`
 * and `@muretai/agent-web-router` vendor this whole file beside themselves. Every copy sits next
 * to a VENDOR.json naming the commit and the sha256 it was taken at; tools/manifest.json here says
 * what may be cut and where the banners are. No line numbers anywhere on purpose: the block sits
 * at different lines in every consumer.
 *
 * WHAT IS HERE. Canonical JSON, Ed25519 over a seed, base58btc + did:key, the signing envelope
 * (six frozen fields), KeyState v1, Web Bot Auth (RFC 9421 subset, verify-only), device-key
 * binding v2 (P-256 countersign), the signed Agent Card envelope, cryptobox (X25519 +
 * ChaCha20-Poly1305) — and the wire constants and JSON-RPC error table the spec pins. Nothing
 * here dials out, listens, or keeps state: the door's ladder, store and HTTP live in the door.
 * The Python twin of every function is python/shared/; both are held to vectors/ by the runners.
 */

import {
  createHash, createPrivateKey, createPublicKey, createCipheriv, createDecipheriv,
  diffieHellman, hkdfSync, randomBytes, sign as nodeSign, verify as nodeVerify,
} from 'node:crypto';
import { Buffer } from 'node:buffer';

// ---- pinned: declarations the door carries verbatim, up to the CANONICAL JSON banner
export const PROTOCOL_VERSION = '0.2';
export const MAX_TEXT_BYTES = 64 * 1024;
export const MAX_BODY_BYTES = 1024 * 1024;
export const CLOCK_WINDOW_S = 300;
export const REPLAY_TTL_S = 600;
export const CARD_SIG_REFRESH_S = 3600;
export const AGENT_CARD_PATH = '/.well-known/agent-card.json';
export const AGENT_CARD_PATH_LEGACY = '/.well-known/agent.json';
export const AGENT_CARD_SIG_PATH = '/.well-known/agent-card.sig.json';
export const SIGNED_ENVELOPE_SCHEME = 'did-key-ed25519';
export const AGENT_ENTRY_REL = 'https://muretai.net/rel/agent-entry';

/** JSON-RPC + Muretai L2 error objects, message strings included — a client greps these. */
export const ERRORS = {
  PARSE_ERROR: { code: -32700, message: 'Parse error' },
  INVALID_REQUEST: { code: -32600, message: 'Invalid Request' },
  METHOD_NOT_FOUND: { code: -32601, message: 'Method not found' },
  INVALID_PARAMS: { code: -32602, message: 'Invalid params' },
  INTERNAL_ERROR: { code: -32603, message: 'Internal error' },
  UNAUTHENTICATED: { code: -32001, message: 'Signature verification failed' },
  REPLAY_REJECTED: { code: -32002, message: 'Replay or stale message' },
  WRONG_RECIPIENT: { code: -32003, message: 'Message not addressed to me' },
  RATE_LIMITED: { code: -32004, message: 'Rate limited' },
  MESSAGE_TOO_LARGE: { code: -32005, message: 'Message text too large' },
};

function asciiLower(s) {
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    out += (c >= 65 && c <= 90) ? String.fromCharCode(c + 32) : s[i];
  }
  return out;
}

const CARD_ENVELOPE_VERSION = 1;
const CARD_ENVELOPE_TYPE = 'agentcard';

// ================================================================ CANONICAL JSON
//
// Reproduces, byte for byte:
//   json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False,
//              allow_nan=False).encode("utf-8")
//
// The four traps, each pinned by a case in the golden vectors (`wire_vectors.json`):
//   1. KEY ORDER is by UNICODE CODE POINT. JavaScript's default string sort compares
//      UTF-16 code UNITS, which disagrees for astral characters (U+1F600 sorts BEFORE
//      U+FFFD by unit, AFTER it by code point). `codePointCompare` below is deliberate.
//   2. NON-ASCII STAYS LITERAL (ensure_ascii=False). JSON.stringify already does this,
//      but most hand-rolled canonicalizers \u-escape and are then wrong for every
//      Japanese message on the network.
//   3. Python's ESCAPE SET is exactly: the seven shorthands (" \ \b \f \n \r \t), every
//      other control char < 0x20 as lowercase \u00xx — and NOTHING else. `/` and DEL
//      (0x7F) are NOT escaped. Many JSON writers escape both; that is a silent break.
//   4. NUMBERS. Only integers inside +/-(2**53-1) and ordinary fractional floats are
//      emitted; anything whose rendering differs between Python and JavaScript THROWS
//      rather than producing bytes only Python can verify (see numberHazards in the
//      vectors: 1.0, -0.0, 1e-07, 1e+16, 2**53+1 …).

const ESCAPES = new Map([
  ['"', '\\"'], ['\\', '\\\\'], ['\b', '\\b'], ['\f', '\\f'],
  ['\n', '\\n'], ['\r', '\\r'], ['\t', '\\t'],
]);
// eslint-disable-next-line no-control-regex
const NEEDS_ESCAPE = /[\u0000-\u001f"\\]/;

function encodeString(s) {
  if (!NEEDS_ESCAPE.test(s)) return `"${s}"`;
  let out = '"';
  for (const ch of s) {                       // iterates by CODE POINT, not code unit
    const shorthand = ESCAPES.get(ch);
    if (shorthand !== undefined) { out += shorthand; continue; }
    const cp = ch.codePointAt(0);
    if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, '0')}`;   // lowercase hex
    else out += ch;                            // '/' and DEL included: NOT escaped
  }
  return out + '"';
}

function encodeNumber(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    // allow_nan=False. NaN/Infinity are not JSON (RFC 8259) and no two languages agree
    // on a spelling — refuse to sign them rather than emit a token nobody can check.
    throw new TypeError(`canonicalJSON: non-finite number (${n})`);
  }
  if (Number.isInteger(n)) {
    if (!Number.isSafeInteger(n)) {
      // Not a formatting mismatch — SILENT DATA CORRUPTION. Python has arbitrary
      // precision; a JS Number rounds. Signed integers stay inside +/-(2**53-1).
      throw new RangeError(`canonicalJSON: integer outside +/-(2**53-1) (${n})`);
    }
    return String(n);                          // -0 renders "0", same as Python's int 0
  }
  const rendered = String(n);
  if (rendered.includes('e') || rendered.includes('E')) {
    // Python zero-pads and always signs the exponent (1e-07); JS writes 1e-7. And the
    // thresholds at which each switches to exponent notation differ (Python 1e16, JS 1e21).
    throw new RangeError(`canonicalJSON: float needs exponent notation (${rendered}) — `
      + 'Python and JavaScript spell it differently; use an integer');
  }
  if (Math.abs(n) < 1e-4) {
    // Python's repr switches to exponent below 1e-4 while JS still writes decimals.
    throw new RangeError(`canonicalJSON: float too small to render identically (${rendered})`);
  }
  return rendered;
}

/** Compare two strings by UNICODE CODE POINT (Python's `str` order), not UTF-16 unit. */
function codePointCompare(a, b) {
  if (a === b) return 0;
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i), cb = b.codePointAt(j);
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i >= a.length && j < b.length) return -1;   // a is a prefix of b
  if (j >= b.length && i < a.length) return 1;
  return 0;
}

function encodeValue(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return encodeString(v);
    case 'number': return encodeNumber(v);
    case 'boolean': return v ? 'true' : 'false';
    case 'bigint':
      // A BigInt would render exactly, but it can also exceed 2**53-1 silently on the
      // way back in through JSON.parse. Refuse, like every other unrenderable number.
      throw new TypeError('canonicalJSON: BigInt is not representable on this wire');
    case 'object': break;
    default:
      throw new TypeError(`canonicalJSON: cannot encode ${typeof v}`);
  }
  if (Array.isArray(v)) return `[${v.map(encodeValue).join(',')}]`;
  const keys = Object.keys(v).sort(codePointCompare);
  const parts = [];
  for (const k of keys) {
    const val = v[k];
    if (val === undefined) {
      // Python has no `undefined`: a key whose value is undefined would silently vanish
      // from JSON.stringify and change the signed bytes. Say so instead.
      throw new TypeError(`canonicalJSON: key ${JSON.stringify(k)} is undefined`);
    }
    parts.push(`${encodeString(k)}:${encodeValue(val)}`);
  }
  return `{${parts.join(',')}}`;
}

/** Canonical JSON STRING (UTF-8 when encoded) for `value`. Throws on anything whose
 *  bytes would differ from Python's. */
export function canonicalJSON(value) {
  return encodeValue(value);
}

/** Canonical JSON as a UTF-8 Buffer — the bytes that actually get signed. */
export function canonicalBytes(value) {
  const s = canonicalJSON(value);
  assertEncodable(s);
  return Buffer.from(s, 'utf8');
}

/** `fatal: true` refuses invalid UTF-8 instead of substituting U+FFFD. `ignoreBOM: true` does
 *  NOT mean "ignore a BOM" — it means "do not STRIP one", which is the half that matters, and
 *  the flag's name has cost this family a day before. The default decoder silently removes a
 *  leading U+FEFF, so `EF BB BF {"a":1}` parsed cleanly here and was refused by Go and Rust:
 *  the same bytes, conformant on two references and not on the other two. */
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** The five byte order marks, longest first — UTF-32-LE's begins with UTF-16-LE's. */
const JSON_BOMS = [[0x00, 0x00, 0xfe, 0xff], [0xff, 0xfe, 0x00, 0x00],
  [0xef, 0xbb, 0xbf], [0xfe, 0xff], [0xff, 0xfe]];

/**
 * Raw document BYTES in, the exact bytes to sign out — the whole supported path for a document
 * read off a wire, and the twin of Go's `seam.CanonicalFromJSON`, Rust's
 * `serde_json::from_slice` + `canonical`, and Python's `crypto.canonical_from_json`.
 *
 * THREE DOORS, AND EACH ONE IS LOAD-BEARING. The BOM check below, because RFC 8259 §8.1 says a
 * networked JSON text carries no byte order mark and because stripping one makes
 * `EF BB BF {"a":1}` and `{"a":1}` — two distinct wire documents — sign ONE byte string, which
 * is the lone-surrogate collision of 0.3.0 wearing a different hat: content substitution under
 * a signature that verifies. The fatal decode, because `Buffer.toString('utf8')` REPAIRS an
 * invalid byte to U+FFFD, and U+FFFD is a character this reference encodes happily, so the
 * evidence is gone one line before the bytes get signed. And `assertEncodable` inside
 * `canonicalBytes`, because a lone surrogate can ride as a `\ud800` ESCAPE — pure ASCII, which
 * no decoder can see.
 *
 * Callers used to be told to assemble this themselves ("a fatal TextDecoder, then
 * canonicalBytes"), and a recipe in a document is not a guard: the one caller who reaches for
 * the default decoder gets a boundary that repairs, and nothing anywhere says so.
 */
export function canonicalFromJSON(raw) {
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  for (const bom of JSON_BOMS) {
    if (bytes.length >= bom.length && bom.every((b, i) => bytes[i] === b)) {
      throw new SyntaxError(
        `json: document begins with a byte order mark (${Buffer.from(bom).toString('hex')}) — `
        + 'RFC 8259 §8.1 forbids one, and stripping it makes two distinct documents sign one '
        + 'byte string');
    }
  }
  return canonicalBytes(JSON.parse(UTF8_STRICT.decode(bytes)));
}

/** Refuse lone surrogates. Python's `.encode("utf-8")` RAISES on them; Node silently
 *  substitutes U+FFFD, which would sign different bytes than the sender believes. */
function assertEncodable(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('lone surrogate in payload');
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new TypeError('lone surrogate in payload');
    }
  }
}

/** The bytes of a standard-base64 field that has EXACTLY ONE spelling, or null.
 *
 *  `Buffer.from(s, 'base64')` skips every character outside the alphabet and shrugs at
 *  padding, so "AAAA", "A A A A", "AAAA!!!" and "AAAA=" all decode to the same four bytes.
 *  A signature therefore has unlimited spellings: the same authenticated message can be
 *  re-serialized without limit, and a peer that stores, logs or DE-DUPLICATES by the literal
 *  `sig` string sees a fresh message every time. Python's `b64decode(..., validate=True)`
 *  refuses all three, so a leniently-decoded field is also a twin divergence waiting for the
 *  one input where the two implementations disagree about what arrived.
 *
 *  TWO tests, because THE ALPHABET IS NOT ENOUGH and assuming it is, is the trap this
 *  function was first written into. `WBA_B64_STANDARD` (declared with the WBA constants
 *  further down — one alphabet, in one place, because two copies of it drift) plus
 *  `length % 4 === 0` is exactly what the Web Bot Auth parser applies to a `Signature`
 *  member, and it looks total: the regex spells the alphabet without `=`, so padding can
 *  only be the trailing one or two characters it allows. It still leaves a whole FAMILY of
 *  spellings, because the last data character of a PADDED string carries bits nobody reads.
 *  A 64-byte signature is 88 characters ending `==`; its final data character holds 6 bits
 *  of which the decoder uses 2 and DISCARDS 4, so all 16 characters that share those top 2
 *  bits decode to the identical 64 bytes — "…BQ==" through "…Bf==" are ONE signature under
 *  SIXTEEN names, every one of them well-formed base64 that Python's
 *  `b64decode(validate=True)` accepts too (it checks the alphabet, never the residual —
 *  it takes all 64 characters there). One `=` discards 2 bits: a family of 4.
 *
 *  So the second test is the only one that actually says CANONICAL: decode, RE-ENCODE, and
 *  demand the input back character for character. Every encoder in every language writes the
 *  discarded bits as zero, so everything a real encoder ever produced round-trips unharmed
 *  and no golden vector can move; only a hand-edited residual fails, which is precisely the
 *  input that had no honest way to exist. Note where this leaves the twins: the residual is
 *  a hole they SHARED, so closing it here does not create a divergence out of a divergence —
 *  but shared/ does not round-trip yet and should, or the two will disagree about one
 *  re-spelled signature in fifteen out of sixteen tries.
 *
 *  Refusal is `null`; each caller turns that into its OWN failure value (false / null),
 *  never a throw, because every one of them is on the untrusted path. */
function strictB64(value) {
  if (typeof value !== 'string') return null;
  if (!WBA_B64_STANDARD.test(value) || value.length % 4 !== 0) return null;
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value) return null;   // the discarded trailing bits, above
  return raw;
}

/** The bytes of an UNPADDED base64url field that has exactly one spelling, or null — the
 *  base64url twin of `strictB64`, same trap, different alphabet. A 32-byte Ed25519 public
 *  key is 43 characters: 258 bits carrying 256, so the LAST character holds 2 bits nobody
 *  reads and the key has FOUR spellings — "…hzc", "…hzd", "…hze", "…hzf" decode to the
 *  identical 32 bytes. Not academic on this path: `wbaThumbprint` derives the `keyid` from
 *  the CANONICAL re-encoding, so all four spell ONE key id, and a JWKS could carry one key
 *  four times while a directory that de-duplicates by the `x` string counts four.
 *
 *  THE RULE, spelled out because shared/jws.unb64url must agree with it character for
 *  character and whichever side is more permissive becomes the split:
 *    1. a string, else null;
 *    2. `WBA_B64URL` — `[A-Za-z0-9_-]` only, so "+", "/" and "=" are refused and the input
 *       is UNPADDED base64url or nothing;
 *    3. `length % 4 !== 1` — one leftover character carries 6 bits and no byte;
 *    4. decode, RE-ENCODE UNPADDED, and demand the input back character for character.
 *  The EMPTY STRING PASSES this gate: it decodes to zero bytes and re-encodes to itself, and
 *  it is the CALLER's length check that refuses it. A codec gate must not be the thing that
 *  decides how long a key is — that belongs where the key's size is known.
 *
 *  Rule 3 is SUBSUMED by rule 4 (an unpadded encoding's length is never ≡ 1 mod 4, so such
 *  an input can never equal a re-encoding) and is kept on purpose: it is cheaper than the
 *  decode, it states the format's own reason rather than a consequence of it, and it is the
 *  rule the Python twin spells out — dropping it here would leave two files whose rules READ
 *  differently while behaving identically, which is the diff nobody re-derives at 2am. */
function strictB64Url(value) {
  if (typeof value !== 'string') return null;
  if (!WBA_B64URL.test(value) || value.length % 4 === 1) return null;
  const raw = Buffer.from(value, 'base64url');
  if (raw.toString('base64url') !== value) return null;   // the discarded trailing bits
  return raw;
}

// ================================================================ Ed25519 (node:crypto)
//
// Node wants DER, not raw bytes. These two prefixes are the whole trick:
//   PKCS#8 private = 302e020100300506032b657004220420 || <32-byte seed>
//   SPKI    public = 302a300506032b6570032100        || <32-byte public key>
// (0x2b6570 is OID 1.3.101.112 = Ed25519; 0x2b656e is 1.3.101.110 = X25519.)

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function seedBuffer(seedHex) {
  if (typeof seedHex !== 'string') throw new TypeError('seed must be a 64-char hex string');
  const seed = Buffer.from(seedHex.trim(), 'hex');
  if (seed.length !== 32) throw new TypeError('seed must be 32 bytes (64 hex chars)');
  return seed;
}

function ed25519PrivateKey(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seedBuffer(seedHex)]),
    format: 'der', type: 'pkcs8',
  });
}

function ed25519PublicKey(publicRaw) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicRaw]),
    format: 'der', type: 'spki',
  });
}

/** Raw 32-byte Ed25519 public key for a seed. */
export function publicKeyFromSeedHex(seedHex) {
  const pub = createPublicKey(ed25519PrivateKey(seedHex));
  return pub.export({ format: 'der', type: 'spki' }).subarray(ED25519_SPKI_PREFIX.length);
}

/** Raw Ed25519 signature over `message` (Buffer|string), as a Buffer. A STRING message is
 *  the last place a payload becomes bytes, so it is guarded here as well as at every
 *  canonical-payload site: Node's UTF-8 encoder answers a lone surrogate with U+FFFD and
 *  signs it, while Python's `.encode("utf-8")` raises — the signature would then be over
 *  bytes the sender never wrote and the twin cannot even produce. */
export function signBytes(seedHex, message) {
  if (!Buffer.isBuffer(message)) assertEncodable(String(message));
  const m = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
  return nodeSign(null, m, ed25519PrivateKey(seedHex));
}

// The Ed25519 points of small order, in every canonical AND non-canonical 32-byte
// spelling. `[h]A` is the identity for each of them, so `R = A, S = 0` satisfies
// `[S]B == R + [h]A` over EVERY message: one constant blob authenticates anything, and
// no private key exists or is needed. The identity point renders as a well-formed
// `did:key`, so the codec cannot be the place this is caught.
//
// This list is the twin of `_ED25519_SMALL_ORDER` in python/shared/crypto.py and must
// stay byte-identical to it. Fourteen entries: a strict RFC 8032 decoder yields eleven,
// and the three extra non-canonical spellings (y = p, p+1) are carried because a decoder
// that masks y to 255 bits accepts them as the same point.
const ED25519_SMALL_ORDER = new Set([
  // y = 0 (x = ±sqrt(-1)) — order 4
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  // y = 1 (x = 0) — order 1: the IDENTITY, the element that signs everything
  '0100000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000080',
  // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  // order 8 (the other one)
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  // y = p-1 (x = 0) — order 2
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  // y = p, i.e. y == 0 — the NON-CANONICAL spelling of the order-4 point
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  // y = p+1, i.e. y == 1 — the NON-CANONICAL spelling of the IDENTITY
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
]);

// 2^255 - 19, as the little-endian y coordinate is compared against it.
const ED25519_P = (1n << 255n) - 19n;

function leToBigInt(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i -= 1) n = (n << 8n) | BigInt(buf[i]);
  return n;
}

/** The byte-level gate every Ed25519 verification here opens with — the twin of Python's
 *  `_ed25519_wire_ok`, and the reason this file does not delegate point validity to the
 *  host. It cannot: measured 2026-09-09, `node:crypto.verify` on the identity point with
 *  `R = identity, S = 0` answers FALSE on Node 26.5.1 and TRUE on Node 22.23.2 — the same
 *  bytes, the same reported OpenSSL 3.6.3, opposite verdicts. The package declares
 *  `engines.node >= 20`, so on the floor it supports, the host is not a guard.
 *
 *  Four refusals, at the one place a public key ENTERS verification so every caller
 *  inherits them: the key and the signature's R component are each refused if they are a
 *  small-order encoding, and each refused if their y is not reduced below p (a decoder
 *  that masks y to 255 bits would otherwise read two spellings as one point). */
function ed25519WireOk(publicRaw, signature) {
  if (ED25519_SMALL_ORDER.has(publicRaw.toString('hex'))) return false;
  const r = signature.subarray(0, 32);
  if (ED25519_SMALL_ORDER.has(r.toString('hex'))) return false;
  const mask255 = (1n << 255n) - 1n;
  return (leToBigInt(publicRaw) & mask255) < ED25519_P
      && (leToBigInt(r) & mask255) < ED25519_P;
}

/** Verify a raw Ed25519 signature. Never throws — bad key/sig bytes answer false. */
export function verifyBytes(publicRaw, signature, message) {
  try {
    if (!Buffer.isBuffer(publicRaw) || publicRaw.length !== 32) return false;
    if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
    if (!ed25519WireOk(publicRaw, signature)) return false;
    if (!Buffer.isBuffer(message)) assertEncodable(String(message));   // same as signBytes
    const m = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
    return nodeVerify(null, m, ed25519PublicKey(publicRaw), signature);
  } catch {
    return false;
  }
}

/** A fresh 32-byte identity seed as hex. THIS IS THE PRIVATE KEY — never log or ship it. */
export function newSeedHex() {
  return randomBytes(32).toString('hex');
}

/** A fresh message/correlation id (same shape as Python's uuid4().hex). */
export function newId() {
  return randomBytes(16).toString('hex');
}

// ================================================================ base58btc + did:key

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX = new Map([...B58].map((c, i) => [c, BigInt(i)]));
/** Every legitimate base58 here (a DID is ~48 chars) is far under this. The cap guards the
 *  O(n^2) bignum loop from an attacker-chosen `from` field — the decoder runs BEFORE any
 *  signature check, so an unbounded input is free CPU exhaustion (shared/crypto:184). */
const MAX_B58_LEN = 512;
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);

function b58encode(data) {
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    const r = n % 58n;
    n /= 58n;
    out = B58[Number(r)] + out;
  }
  let pad = 0;
  for (const b of data) { if (b === 0) pad++; else break; }
  return '1'.repeat(pad) + out;
}

function b58decode(s) {
  if (typeof s !== 'string') throw new TypeError('base58: not a string');
  if (s.length > MAX_B58_LEN) throw new RangeError('base58 input too long');
  let n = 0n;
  for (const ch of s) {
    const v = B58_INDEX.get(ch);
    if (v === undefined) throw new TypeError(`base58: bad character ${JSON.stringify(ch)}`);
    n = n * 58n + v;
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const raw = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let pad = 0;
  for (const ch of s) { if (ch === '1') pad++; else break; }
  return Buffer.concat([Buffer.alloc(pad), raw]);
}

/** 32-byte Ed25519 public key (hex or Buffer) -> `did:key:z…`. */
export function didFromPublicKeyHex(publicHex) {
  const pub = Buffer.isBuffer(publicHex) ? publicHex : Buffer.from(publicHex, 'hex');
  if (pub.length !== 32) throw new TypeError('an ed25519 public key is 32 bytes');
  return 'did:key:z' + b58encode(Buffer.concat([MULTICODEC_ED25519, pub]));
}

/** `did:key:z…` -> 32-byte Ed25519 public key, hex. Enforces the 0xed01 multicodec and the
 *  34-byte total: with did:key the DID IS the key, so this is the whole "key lookup". */
export function publicKeyHexFromDid(did) {
  return publicKeyFromDid(did).toString('hex');
}

function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new TypeError(`unsupported DID method: ${String(did).slice(0, 32)}`);
  }
  const raw = b58decode(did.slice('did:key:z'.length));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new TypeError('not an ed25519 did:key');
  }
  return raw.subarray(2);
}

/** The did:key a seed controls. */
export function didFromSeedHex(seedHex) {
  return didFromPublicKeyHex(publicKeyFromSeedHex(seedHex));
}

// ================================================================ the signing envelope

/** The SIX frozen signed fields, canonicalized (shared/crypto.signing_payload). Nothing
 *  else is signed: `replyTo`, `auto`, `group`, `vc` … all ride as UNSIGNED metadata.
 *  `timestamp` is passed through AS GIVEN — never coerced, because the type on the wire
 *  IS the type in the signed bytes (send ints; verify whatever arrived). */
export function signingPayload(fields) {
  return canonicalJSON({
    contextId: fields.contextId ?? null,
    from: fields.from,
    messageId: fields.messageId,
    text: fields.text,
    timestamp: fields.timestamp,
    to: fields.to,
  });
}

/** base64 (standard alphabet, WITH padding) of the Ed25519 signature over the six fields. */
export function signEnvelope(seedHex, fields) {
  if (!seedHex) throw new TypeError('signEnvelope: no seed (this agent entry cannot sign)');
  const payload = signingPayload(fields);
  assertEncodable(payload);
  return signBytes(seedHex, Buffer.from(payload, 'utf8')).toString('base64');
}

/** Question 1 ONLY: does `sig` verify under the key DERIVED FROM `from`, over the six
 *  fields? Total and fail-closed — a malformed DID, bad base64, unrenderable number or
 *  short signature all answer false rather than throwing. */
export function verifyEnvelopeSignature(fields, opts = {}) {
  try {
    if (!fields || typeof fields !== 'object') return false;
    // `from` (the key) and `sig` must be there; `to` may be the EMPTY STRING — that is how
    // an anonymous-lane reply is addressed ("signed by me, to nobody in particular"), and
    // refusing it here would make core's own walk-in answer read as unsigned.
    if (!fields.from || !fields.sig || typeof fields.to !== 'string') return false;
    const payload = signingPayload(fields);
    assertEncodable(payload);
    const sig = strictB64(fields.sig);
    if (sig === null || sig.length !== 64) return false;
    // Payload `from` stays the root DID. `signerDid` is the verifying key when the
    // sender enrolled a delegated op-key (T142 A2); omitted → `from` (the un-enrolled
    // / this-door-reply case).
    const signerDid = opts.signerDid || fields.from;
    return verifyBytes(publicKeyFromDid(signerDid), sig, Buffer.from(payload, 'utf8'));
  } catch {
    return false;
  }
}

/**
 * Is this envelope an authentic statement ADDRESSED TO ME? Two questions, not one:
 *
 *   1. does `sig` verify under the key derived FROM `from`? With did:key the DID IS the
 *      key, so `from` is never taken as a label — that mistake is how a client ends up
 *      accepting a valid signature by a DIFFERENT identity than the one it displays
 *      (wire_vectors `reject.message/from-not-signer`, the crown-jewel case);
 *   2. is `to` the recipient I am? A signature that verifies FOR SOMEONE ELSE is still a
 *      perfectly valid signature — it is just not my mail. `wire_vectors
 *      reject.message/wrong-recipient` is exactly that: `mustReject: true` even though
 *      the signature checks out, because in core the "to == me" half lives one layer up
 *      (agent/inbox.verify -> WRONG_RECIPIENT).
 *
 * A module-level function has no "me", so the recipient must be NAMED by the caller —
 * `verifyEnvelope(fields, { recipientDid })`. THE WIRE CANNOT NAME ITS OWN RECIPIENT.
 * `fields` is the stranger's object; `recipientDid` is not one of the six signed fields,
 * so a fallback that read it from there let the message answer question 2 itself: an
 * envelope captured on its way to one door replayed at ANY other door by adding one
 * unsigned `recipientDid` equal to its own `to`, and the check that exists to say "this
 * is my mail" said nothing. Only the verifier knows who it is. An unnamed recipient is
 * UNKNOWN, and unknown fails closed: an envelope nobody claims cannot be verified as
 * theirs. When you deliberately want question 1 alone (auditing a stored message, say),
 * call `verifyEnvelopeSignature`.
 *
 * Never throws.
 */
export function verifyEnvelope(fields, opts = {}) {
  try {
    if (!fields || typeof fields !== 'object') return false;
    const recipient = opts.recipientDid ?? opts.me ?? null;
    if (typeof recipient !== 'string' || !recipient) return false;
    if (fields.to !== recipient) return false;
    return verifyEnvelopeSignature(fields, opts);
  } catch {
    return false;
  }
}

// ================================================================ KeyState (inline op-key, T142 A2)
//
// A persisted muretai identity enrolls a genesis KeyState at birth and signs
// messages with a delegated op-key while `from` stays the root DID. This door
// used to verify under `from` only, which refused every default-enrolled
// visitor. Resolve the op-key from a valid inline KeyState (root-signed, pin
// to the claimed `from`); a missing or invalid record falls back to `from`.
// No directory. The pin store is the CALLER's — `resolveOpDid(..., { pinned })`;
// with none this is first contact and revocation is unenforceable (read why there).

const KEYSTATE_TYP = 'muretai/keystate/1';
// Lockstep with shared/keystate._FIELDS_V1 / _signed_names: presence of
// encPubPqHash (even "") selects the T142 list. A V1-only list made every
// default-enrolled visitor fail verify and fall back to the root DID, so
// the op-signed envelope was -32001 at this door only (Python twin accepted).
const KEYSTATE_FIELDS_V1 = [
  'typ', 'rootDid', 'epoch', 'rootKey', 'rootNextHash',
  'opDid', 'opNextHash', 'encPub', 'encNextHash',
  'guardiansHash', 'revokedOps', 'notBefore', 'notAfter', 'ts',
];
function keystateSignedNames(ks) {
  if (ks && Object.prototype.hasOwnProperty.call(ks, 'encPubPqHash')) {
    return KEYSTATE_FIELDS_V1.concat(['encPubPqHash']);
  }
  return KEYSTATE_FIELDS_V1;
}
const MAX_KEYSTATE_EPOCH = 2147483647; // 2**31 - 1, shared/keystate.MAX_EPOCH

export function verifyKeystate(ks, expectedRootDid, now) {
  try {
    if (!ks || typeof ks !== 'object') return false;
    if (ks.typ !== KEYSTATE_TYP) return false;
    const rootDid = ks.rootDid;
    const epoch = ks.epoch;
    if (!Number.isInteger(epoch) || epoch < 0 || epoch > MAX_KEYSTATE_EPOCH) return false;
    if (expectedRootDid != null && rootDid !== expectedRootDid) return false;
    const didKey = publicKeyHexFromDid(rootDid);
    if (ks.rootKey !== didKey) return false;
    const sig = strictB64(ks.sig);
    if (sig === null || sig.length !== 64) return false;
    const payloadObj = {};
    for (const k of keystateSignedNames(ks)) {
      payloadObj[k] = ks[k] === undefined ? null : ks[k];
    }
    const payload = canonicalJSON(payloadObj);
    // The one canonical payload in this file that reached `Buffer.from(…, 'utf8')` unguarded.
    // A KeyState is attacker-supplied and its signed names are copied straight off it, so a
    // lone surrogate anywhere in `opDid`/`rootNextHash`/… would have been encoded as U+FFFD
    // and verified against bytes the root never signed, while the Python twin raises on the
    // very same record. It throws; the enclosing try answers false, which is this function's
    // only refusal — a KeyState nobody can encode identically is not a valid KeyState.
    assertEncodable(payload);
    const pub = Buffer.from(String(ks.rootKey), 'hex');
    if (pub.length !== 32) return false;
    if (!verifyBytes(pub, sig, Buffer.from(payload, 'utf8'))) return false;
    if (now != null) {
      const nb = ks.notBefore || 0;
      const na = ks.notAfter;
      if (now < nb) return false;
      if (na != null && now > na) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Is `opDid` in this record's burn list? The list is an ARRAY of DIDs, and a `revokedOps`
 *  that is not one burns nothing here. shared/keystate.op_is_revoked runs Python's `in`
 *  against whatever it finds instead, so on a root-signed `revokedOps: "did:key:zABC…"` that
 *  is a SUBSTRING test (every op whose DID is a substring of it reads as burned) and on a
 *  `revokedOps: 5` it raises TypeError out through `resolve_op_did`, which catches nothing.
 *  Both records are malformed either way and no honest signer mints one; this side keeps the
 *  type check because a burn list you cannot enumerate is not a burn list, and because a
 *  resolver that throws is a resolver a stranger can turn off. */
function keystateBurnsOp(ks, opDid) {
  return !!ks && Array.isArray(ks.revokedOps) && ks.revokedOps.includes(opDid);
}

/**
 * WHICH KEY does this message's signature get checked against — the root DID in `from`, or a
 * delegated op-key its sender enrolled while `from` stayed the root?
 *
 * Called with THREE arguments this is first contact, and it answers exactly what it has
 * always answered: a root-signed inline KeyState names the op-key; a missing, expired,
 * wrong-root or unparseable one falls back to `from`. Read the next paragraph before you
 * rely on that.
 *
 * WITHOUT A PIN, `revokedOps` IS UNENFORCEABLE — and until this comment nothing in this file
 * admitted it, so a caller reading the old one would reasonably believe the revocation list
 * did something. It does not. The list is read off the very record being judged, and that
 * record is the SENDER's: root-signed, therefore authentic, but authenticity is not
 * freshness. A thief holding a burned op-key attaches an OLDER, still-validly-signed KeyState
 * in which that key is not yet revoked, and this function honours it. The list can only ever
 * incriminate a key its own presenter chose to incriminate. The same missing memory costs two
 * more: a record at a LOWER `epoch` than one already seen is accepted as readily as a higher
 * one, so rollback is free; and two records at the SAME epoch naming different `opDid`s are
 * both acceptable, so a fork is invisible. Three findings, one bug — the resolver remembers
 * nothing about this root.
 *
 * `opts.pinned` IS that memory: a KeyState for this same root that the CALLER kept from an
 * earlier, verified contact. Given one, this becomes a ratchet, mirroring
 * shared/keystate.resolve_op_did rather than inventing a second policy for the same wire:
 *
 *   - THE PIN IS VERIFIED BEFORE IT IS TRUSTED (`verifyKeystate` against `rootDid`). A pin
 *     that does not verify is not a pin. A pin that was SUPPLIED and does not verify is a
 *     broken store — not a first contact — so it fails closed to the root rather than
 *     silently degrading to the unpinned answer this whole parameter exists to end; `null` /
 *     `undefined` is the honest "no record yet" and keeps that answer. The validity WINDOW is
 *     deliberately NOT applied to the pin: `notAfter` says a record may no longer authorize a
 *     key, not that we never saw it, and expiring the pin would hand the thief his replay
 *     back on a clock.
 *   - AN INLINE RECORD DISPLACES THE PIN ONLY AT A STRICTLY GREATER EPOCH. Equal is not an
 *     upgrade, it is a fork — two histories at one epoch — and the one we verified ourselves
 *     is the one we keep. (Measured on the Python side 2026-08-11: pinned epoch 1 -> op1, a
 *     replayed epoch-1 record naming op0 resolved to op0.) Identical content makes `>` and
 *     `>=` the same no-op; differing content is exactly when it matters.
 *   - AND ONLY UNDER THE SAME `rootKey`. `rootKey` is what authorizes a KeyState, and a
 *     genesis key authorizes one at ANY epoch, so a record signed by a STOLEN GENESIS key
 *     out-epochs an already-pinned root-rotated one. No lineage travels inline (there is no
 *     wire field for one), so an inline record may advance the epoch under the root key we
 *     already hold and never change it; a genuine root rotation arrives through a pull and a
 *     fresh pin. Here the test is belt-and-braces — `verifyKeystate` pins `rootKey` to the
 *     DID's own key, so two records that both verify against one `rootDid` cannot differ —
 *     and it stays because it is the rule, not because today's did:key makes it free.
 *   - THE PIN'S `revokedOps` BINDS, AND SO DOES THE INLINE ONE: the UNION, not the pin alone.
 *     The pin's half is the half with teeth, because the stranger did not choose it. The
 *     inline half is honoured too and costs nothing: a key the presenter's OWN record calls
 *     dead is dead by admission, and an attacker who dislikes that entry simply omits it —
 *     which leaves him exactly where the pin already had him. A burned answer falls back to
 *     the key the pin still stands behind, and to the root if that one is burned too.
 *
 * The parameter is where this stops. GIVING THE DOOR A PIN STORE IS A SEPARATE, DELIBERATE
 * FOLLOW-UP: the seam exposes the argument and fixes the policy, `@muretai/agent-entry`
 * supplies the memory — what it keys the store by, when it writes, and what an operator sees
 * when a peer's epoch walks backwards are its decisions, not the wire's. Until it does, every
 * door calling this with three arguments is on the first-contact answer above, revocation and
 * all, and should say so rather than believe otherwise.
 *
 * Hence the shape: a FOURTH parameter, defaulted — never a changed signature. The door
 * splices this region into its own single file verbatim and calls `resolveOpDid(from,
 * meta.keystate, ts)`; its conformance twin compares the spliced DEFINITION and never the
 * call site. A breaking signature would therefore land a new definition beside an unchanged
 * three-argument call — the timestamp read as a pinned KeyState, `now` undefined, the
 * validity window quietly no longer checked — and every test in both repositories would stay
 * green. With no pin the answer here is what it was before this paragraph existed, case for
 * case.
 *
 * Never throws.
 */
export function resolveOpDid(rootDid, inlineKeystate, now, opts = {}) {
  // `opts` is read totally: a primitive, null, or a caller who passed nothing all read as
  // "no pin", which is the three-argument path.
  const claimedPin = opts == null ? null : opts.pinned;
  if (claimedPin != null && !verifyKeystate(claimedPin, rootDid)) return rootDid;
  const pin = claimedPin == null ? null : claimedPin;
  const inline = (inlineKeystate && verifyKeystate(inlineKeystate, rootDid, now))
    ? inlineKeystate : null;

  // Adoption. With no pin every verifying inline record is "current" — that IS first contact.
  let current = pin;
  if (inline !== null
      && (pin === null || (inline.rootKey === pin.rootKey && inline.epoch > pin.epoch))) {
    current = inline;
  }

  const op = current === null ? rootDid : (current.opDid || rootDid);
  // The PIN's list first — the half the stranger did not choose. A key it burns falls back to
  // the key the pin does still stand behind, not to the root: the pin is a verified record of
  // this identity and its own op is the best thing in the room.
  if (pin !== null && keystateBurnsOp(pin, op)) {
    const held = pin.opDid || rootDid;
    // shared/keystate.resolve_op_did returns `held` unconditionally here, so a pin that burns
    // its OWN opDid resolves there to the key it has just declared dead. Re-test it; nobody
    // vouched for anything, and the root is the only honest answer left.
    return keystateBurnsOp(pin, held) ? rootDid : held;
  }
  // Then the record we actually resolved through. With no pin this IS the whole revocation
  // check, and it is the unenforceable one — see the second paragraph above.
  if (current !== null && keystateBurnsOp(current, op)) return rootDid;
  return op;
}

// ================================================================ Web Bot Auth (RFC 9421 subset, verify-only) — T107
//
// The INBOUND half only: did the holder of one of the keys this entry was GIVEN sign
// THIS request, for THIS authority, as a `web-bot-auth` request? It mirrors EXACTLY the
// subset shared/webbotauth.py::verify_request implements — no more (content digests,
// @query-param, per-item parameters and every other RFC 9421 feature are refused, not
// ignored) and no less. The two are pinned to one fixture, `wba_vectors.json`:
// a vector one twin accepts and the other refuses is a red suite. Verification is
// BYTE-FAITHFUL, not canonical: the signature base is rebuilt from the RECEIVED
// `@signature-params` text, so a peer who orders or spaces parameters differently still
// verifies (signing is canonical, verifying is byte-faithful — the shared/jws.py split).
//
// One rule governs every caller in this file: WBA never changes a verdict — it only
// ever ADDS identity (`wba_did` on the backend envelope, a `wbaVisits` count). Absent,
// invalid, expired, unknown-key and tampered all behave exactly like "no WBA".

const WBA_TAG_REQUEST = 'web-bot-auth';
/** RFC 9421's HTTP-signature-registry name — NOT JOSE's "EdDSA". Same curve, two
 *  registries; mixing the spellings is a silent interop failure. */
const WBA_ALG = 'ed25519';
/** Tolerance for the peer's clock being ahead, applied to `created` only. */
const WBA_CLOCK_SKEW = 300;
/** The loosest accepted `expires - created`: these headers are a bearer credential
 *  while they live (webbotauth.REQUEST_SIG_WINDOW + CLOCK_SKEW). */
const WBA_MAX_REQUEST_LIFETIME = 600;
/** Refuse to even tokenize an absurd header — bounds parser work on hostile input. */
const WBA_MAX_HEADER_CHARS = 8192;
/** Standard base64, padded — what Python's base64.b64decode(validate=True) accepts.
 *  Node's Buffer.from(s, 'base64') silently IGNORES invalid characters and tolerates
 *  any padding, which is the classic twin-divergence; pre-validating is what keeps one
 *  Signature value from being two different byte strings. */
const WBA_B64_STANDARD = /^[A-Za-z0-9+/]*={0,2}$/;
/** Unpadded base64url — what shared/jws.unb64url accepts for a JWK `x` ("+", "/" and
 *  "=" refused; a length ≡ 1 (mod 4) has no byte decoding). */
const WBA_B64URL = /^[A-Za-z0-9_-]*$/;

/** Serialize an RFC 8941 sf-string: quoted, `\` and `"` escaped — the only two escapes
 *  the RFC defines. */
function wbaSfString(s) {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** Python str.strip()'s default whitespace set, exactly — NOT String.prototype.trim().
 *  The two runtimes disagree at the edges (Python also strips \x1c-\x1f and \x85; JS
 *  also strips U+FEFF), and a covered header value the twins trim differently is a
 *  signature base only one of them can rebuild. */
const WBA_PY_WS_CLASS = '[\\t\\n\\v\\f\\r \\x1c-\\x1f\\x85\\xa0\\u1680'
  + '\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]+';
const WBA_PY_WS = new RegExp(`^${WBA_PY_WS_CLASS}|${WBA_PY_WS_CLASS}$`, 'g');
function wbaPyStrip(s) {
  return s.replace(WBA_PY_WS, '');
}

function wbaIsKeyFirst(ch) { return (ch >= 'a' && ch <= 'z') || ch === '*'; }
function wbaIsKeyRest(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
    || ch === '_' || ch === '-' || ch === '.' || ch === '*';
}

/** An RFC 8941 key (a dictionary label or a parameter name) -> [key, next] or null. */
function wbaParseKey(s, i) {
  if (i >= s.length || !wbaIsKeyFirst(s[i])) return null;
  let j = i + 1;
  while (j < s.length && wbaIsKeyRest(s[j])) j += 1;
  return [s.slice(i, j), j];
}

/** A quoted sf-string. Only `\"` and `\\` are escapes; every other character must be
 *  printable ASCII — rejecting the rest is what keeps one byte string from having two
 *  spellings. */
function wbaParseSfString(s, i) {
  if (i >= s.length || s[i] !== '"') return null;
  i += 1;
  let out = '';
  while (i < s.length) {
    const ch = s[i];
    if (ch === '\\') {
      i += 1;
      if (i >= s.length || (s[i] !== '"' && s[i] !== '\\')) return null;
      out += s[i];
      i += 1;
    } else if (ch === '"') {
      return [out, i + 1];
    } else if (ch >= ' ' && ch <= '~') {
      out += ch;
      i += 1;
    } else {
      return null;
    }
  }
  return null;
}

/** An sf-integer: optional `-`, at most 15 ASCII digits (safely inside 2^53). */
function wbaParseInteger(s, i) {
  let j = i;
  if (j < s.length && s[j] === '-') j += 1;
  let k = j;
  while (k < s.length && s[k] >= '0' && s[k] <= '9') k += 1;
  if (k === j || (k - j) > 15) return null;
  return [parseInt(s.slice(i, k), 10), k];
}

/** The only parameter value types in this profile: sf-string and sf-integer. */
function wbaParseBareItem(s, i) {
  if (i < s.length && s[i] === '"') return wbaParseSfString(s, i);
  return wbaParseInteger(s, i);
}

/** `*( ";" *SP key [ "=" bare-item ] )`. A repeated name is REFUSED rather than
 *  last-wins; a valueless parameter is boolean true. */
function wbaParseParams(s, i) {
  const params = new Map();
  while (i < s.length && s[i] === ';') {
    i += 1;
    while (i < s.length && s[i] === ' ') i += 1;
    const gotKey = wbaParseKey(s, i);
    if (gotKey === null) return null;
    const name = gotKey[0];
    i = gotKey[1];
    if (params.has(name)) return null;
    if (i < s.length && s[i] === '=') {
      const val = wbaParseBareItem(s, i + 1);
      if (val === null) return null;
      params.set(name, val[0]);
      i = val[1];
    } else {
      params.set(name, true);
    }
  }
  return [params, i];
}

/** The covered components: `"(" *SP [ sf-string *( 1*SP sf-string ) *SP ] ")"`.
 *  Per-item parameters are refused — they change what a component MEANS, and a profile
 *  that does not implement them must not silently ignore them. */
function wbaParseInnerList(s, i) {
  if (i >= s.length || s[i] !== '(') return null;
  i += 1;
  const items = [];
  for (;;) {
    while (i < s.length && s[i] === ' ') i += 1;
    if (i >= s.length) return null;
    if (s[i] === ')') return [items, i + 1];
    const got = wbaParseSfString(s, i);
    if (got === null) return null;
    i = got[1];
    if (i < s.length && s[i] !== ' ' && s[i] !== ')') return null;  // incl. ';' per-item
    items.push(got[0]);
  }
}

function wbaSkipOws(s, i) {
  while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i += 1;
  return i;
}

/** Parse a `Signature-Input` value into entries, PRESERVING the raw text of each
 *  entry's value — RFC 9421 signs that text, so rebuilding it from the parsed
 *  structure would only work for peers who serialize exactly as we do. */
function wbaParseSignatureInput(value) {
  const s = value;
  const n = s.length;
  let i = wbaSkipOws(s, 0);
  if (i >= n) return null;
  const entries = [];
  for (;;) {
    const gotKey = wbaParseKey(s, i);
    if (gotKey === null) return null;
    const label = gotKey[0];
    i = gotKey[1];
    if (i >= n || s[i] !== '=') return null;
    i += 1;
    const start = i;
    const gotList = wbaParseInnerList(s, i);
    if (gotList === null) return null;
    const components = gotList[0];
    i = gotList[1];
    const gotParams = wbaParseParams(s, i);
    if (gotParams === null) return null;
    const params = gotParams[0];
    i = gotParams[1];
    entries.push({ label, components, params, signatureParams: s.slice(start, i) });
    i = wbaSkipOws(s, i);
    if (i >= n) return entries;
    if (s[i] !== ',') return null;
    i = wbaSkipOws(s, i + 1);
    if (i >= n) return null;                 // trailing comma
  }
}

/** Parse a `Signature` value: `label=:<standard base64>:` entries. */
function wbaParseSignature(value) {
  const s = value;
  const n = s.length;
  let i = wbaSkipOws(s, 0);
  if (i >= n) return null;
  const out = [];
  for (;;) {
    const got = wbaParseKey(s, i);
    if (got === null) return null;
    const label = got[0];
    i = got[1];
    if (i + 1 >= n || s[i] !== '=' || s[i + 1] !== ':') return null;
    i += 2;
    const end = s.indexOf(':', i);
    if (end < 0) return null;
    const b64 = s.slice(i, end);
    if (!WBA_B64_STANDARD.test(b64) || b64.length % 4 !== 0) return null;
    const raw = Buffer.from(b64, 'base64');
    i = end + 1;
    if (i < n && s[i] === ';') return null;   // parameters on a signature member
    out.push([label, raw]);
    i = wbaSkipOws(s, i);
    if (i >= n) return out;
    if (s[i] !== ',') return null;
    i = wbaSkipOws(s, i + 1);
    if (i >= n) return null;
  }
}

/** The `(Signature-Input, Signature)` pair as verifiable entries, or null. Duplicate
 *  labels, a label present in one header but not the other, and every unexpected byte
 *  return null — each is a case where two implementations could disagree about what
 *  was signed. Never throws. */
function wbaParseSignatureHeaders(sigInput, sig) {
  try {
    if (typeof sigInput !== 'string' || typeof sig !== 'string') return null;
    if (sigInput.length > WBA_MAX_HEADER_CHARS || sig.length > WBA_MAX_HEADER_CHARS) {
      return null;
    }
    const entries = wbaParseSignatureInput(sigInput);
    const sigs = wbaParseSignature(sig);
    if (entries === null || sigs === null) return null;
    const labels = entries.map((e) => e.label);
    if (new Set(labels).size !== labels.length) return null;
    const byLabel = new Map();
    for (const [label, raw] of sigs) {
      if (byLabel.has(label)) return null;
      byLabel.set(label, raw);
    }
    if (byLabel.size !== labels.length) return null;
    for (const label of labels) { if (!byLabel.has(label)) return null; }
    for (const e of entries) e.sig = byLabel.get(e.label);
    return entries;
  } catch {
    return null;
  }
}

/** Case-insensitive header lookup over a plain mapping. A non-string value (an array,
 *  a number) reads as absent, never coerced. */
function wbaHeaderGet(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  for (const key of Object.keys(headers)) {
    if (asciiLower(key) === name) {
      const v = headers[key];
      return typeof v === 'string' ? v : null;
    }
  }
  return null;
}

/** The 32 raw key bytes of an Ed25519 OKP JWK, or null — the strict gate every
 *  untrusted key passes through (mirrors shared/webbotauth.public_from_jwk). `x` goes
 *  through `strictB64Url`, so ONE key has ONE `x`: the alphabet test this line used to
 *  carry left the four spellings the last character's two unread bits allow. The 32-byte
 *  length is checked HERE and not in the codec — this is where it is known what a key is. */
function wbaPublicFromJwk(jwk) {
  try {
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return null;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
    const raw = strictB64Url(jwk.x);
    return raw !== null && raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

/** RFC 7638 thumbprint of an Ed25519 public key — the `keyid` on the wire. Built from
 *  the CANONICAL re-encoding of the key bytes, so a differently-spelled (but valid) `x`
 *  still names the same key. The literal member order crv,kty,x IS Python's
 *  sort_keys+compact form (x is base64url, so no JSON escaping can differ). */
function wbaThumbprint(publicRaw) {
  const payload = `{"crv":"Ed25519","kty":"OKP","x":"${publicRaw.toString('base64url')}"}`;
  return createHash('sha256').update(payload, 'utf8').digest('base64url');
}

/** Resolve each covered component to the value to re-sign over, or null. `@authority`
 *  comes from the VERIFIER (our canonical baseUrl) — never from the message; every
 *  other derived component is refused; header values are stripped with Python's set. */
function wbaComponentValues(components, authority, headers) {
  const out = [];
  const seen = new Set();
  for (const name of components) {
    if (typeof name !== 'string' || name !== asciiLower(name) || seen.has(name)) {
      return null;
    }
    seen.add(name);
    if (name === '@authority') {
      out.push([name, authority]);
    } else if (name.startsWith('@')) {
      return null;
    } else {
      const value = wbaHeaderGet(headers, name);
      if (value === null) return null;
      out.push([name, wbaPyStrip(value)]);
    }
  }
  return out;
}

/** The exact bytes covered by the signature (RFC 9421 §2.5): one `"name": value` line
 *  per component, then `"@signature-params": <received text>`, LF-joined, no trailing
 *  newline. */
function wbaSignatureBase(pairs, paramsText) {
  const lines = pairs.map(([name, value]) => `${wbaSfString(asciiLower(name))}: ${value}`);
  lines.push(`${wbaSfString('@signature-params')}: ${paramsText}`);
  return Buffer.from(lines.join('\n'), 'utf8');
}

/** One parsed entry, checked end to end against one key. Order matters only for cost:
 *  the cheap policy checks run before the Ed25519 verification. */
function wbaEntryVerifies(entry, { keyid, publicRaw, authority, headers, now }) {
  const params = entry.params;
  if (params.get('keyid') !== keyid || params.get('tag') !== WBA_TAG_REQUEST) return false;
  const alg = params.get('alg');
  if (alg !== undefined && alg !== WBA_ALG) return false;
  const created = params.get('created');
  const expires = params.get('expires');
  if (!Number.isInteger(created) || !Number.isInteger(expires)) return false;
  if (created > now + WBA_CLOCK_SKEW || now >= expires) return false;
  if (expires <= created || (expires - created) > WBA_MAX_REQUEST_LIFETIME) return false;
  const components = entry.components || [];
  // Without @authority the signature says nothing about WHERE it was served.
  if (!components.includes('@authority')) return false;
  const pairs = wbaComponentValues(components, authority, headers);
  if (pairs === null) return false;
  return verifyBytes(publicRaw, entry.sig, wbaSignatureBase(pairs, entry.signatureParams));
}

/** The DID that signed this inbound request, or null. Never throws. `jwks` is a
 *  directory document ({keys:[…]}) already established as trustworthy — who the keys
 *  belong to was decided before this was called (DECISION 2: keys are GIVEN, never
 *  fetched on the hot path). Mirrors shared/webbotauth.verify_request exactly;
 *  `wba_vectors.json` holds the two to one verdict per input. */
export function wbaVerifyRequest(headers, { authority, jwks, now } = {}) {
  try {
    const entries = wbaParseSignatureHeaders(
      wbaHeaderGet(headers, 'signature-input') || '',
      wbaHeaderGet(headers, 'signature') || '');
    if (!entries || !entries.length) return null;
    const keys = (jwks && typeof jwks === 'object' && !Array.isArray(jwks))
      ? jwks.keys : null;
    if (!Array.isArray(keys)) return null;
    const auth = wbaPyStrip(String(authority || '')).toLowerCase();
    if (!auth) return null;
    const moment = Math.floor(
      (now === undefined || now === null) ? Date.now() / 1000 : now);
    for (const jwk of keys) {
      const publicRaw = wbaPublicFromJwk(jwk);
      if (publicRaw === null) continue;
      const keyid = wbaThumbprint(publicRaw);
      for (const entry of entries) {
        if (wbaEntryVerifies(entry, { keyid, publicRaw, authority: auth,
                                      headers, now: moment })) {
          return didFromPublicKeyHex(publicRaw);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ================================================================ device-key binding v2 (T102)
//
// The ACCOUNT layer: a message may carry a countersigned DeviceKeyBinding v2 in
// metadata.binding proving its device DID belongs to an OWNER DID. This is the JS twin of
// shared/keybinding.verify_device_binding_v2 + the agent entry's account resolution, byte-pinned
// by the golden vectors' `bindingV2` group.
//
// Two signatures, over the SAME canonical bytes: the OWNER (root) signs, and the DEVICE
// countersigns — the countersignature is what stops a foreign owner claiming someone else's
// device. `typ` lives INSIDE the signed bytes (domain separation), and ts/validUntil are
// INTEGERS (a float's repr is not reproducible cross-language). Unlike the Python reference
// there is no "P-256 owner without a backend → unbound" branch: node:crypto verifies P-256
// natively, so a P-256 owner binding is fully checked here — the documented, expected
// asymmetry (the stdlib Python path treats the very same binding as unbound).

/** `typ` of the countersigned account binding (shared/keybinding.BINDING_V2_TYP). */
export const BINDING_V2_TYP = 'muretai/devicebinding/2';

// SPKI DER prefix for a P-256 public key carrying a COMPRESSED SEC1 point (33 bytes). OpenSSL
// (node:crypto) accepts compressed points, so the did:key point embeds directly — no
// decompression. 0x2a8648ce3d0201 = id-ecPublicKey, 0x2a8648ce3d030107 = prime256v1.
const P256_SPKI_PREFIX = Buffer.from(
  '3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex');

/** The longest ASN.1 DER an ECDSA-P-256 signature can be: SEQUENCE(2+) of two INTEGERs each
 *  at most 33 bytes of content (32 + the 0x00 a high bit forces) plus 2 bytes of tag+length.
 *  A ceiling, not an equality, because r and s shrink when they have leading zero bytes. */
const MAX_P256_DER_SIG_BYTES = 72;

/** did:key → { curve, key }: ('ed25519', 32-byte pubkey) or ('p256', 33-byte compressed
 *  point). Curve-agnostic sibling of `publicKeyFromDid` (which is ed25519-only, for the
 *  message envelope that is always ed25519). Throws on anything else. */
function decodeDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new TypeError(`unsupported DID method: ${String(did).slice(0, 32)}`);
  }
  const raw = b58decode(did.slice('did:key:z'.length));
  if (raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01) {
    return { curve: 'ed25519', key: raw.subarray(2) };       // 0xed01 multicodec
  }
  if (raw.length === 35 && raw[0] === 0x80 && raw[1] === 0x24) {
    return { curve: 'p256', key: raw.subarray(2) };          // varint(0x1200) = p256-pub
  }
  throw new TypeError('unsupported did:key multicodec (not ed25519 or p256)');
}

/** Verify an ES256 signature over `message` for a 33-byte compressed P-256 point. Accepts
 *  both encodings clients emit (shared/crypto.p256_verify): raw r||s (64 bytes, WebCrypto /
 *  IEEE P1363) and ASN.1 DER (Secure Enclave / WebAuthn). Never throws. */
function p256Verify(compPoint, signature, message) {
  try {
    if (!Buffer.isBuffer(compPoint) || compPoint.length !== 33) return false;
    const key = createPublicKey({
      key: Buffer.concat([P256_SPKI_PREFIX, compPoint]), format: 'der', type: 'spki' });
    if (signature.length === 64) {
      return nodeVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return nodeVerify('sha256', message, key, signature);    // DER (Secure Enclave)
  } catch {
    return false;
  }
}

/** Curve-dispatching signature verify against a did:key — the binding's owner may be
 *  ed25519 OR p256; the device is always ed25519. Total and fail-closed. */
function verifyDidSig(did, signature, message) {
  try {
    const { curve, key } = decodeDidKey(did);
    if (curve === 'ed25519') return verifyBytes(key, signature, message);
    if (curve === 'p256') return p256Verify(key, signature, message);
    return false;
  } catch {
    return false;
  }
}

/** Canonical bytes BOTH keys sign — exactly the five declared fields
 *  (shared/keybinding._binding_v2_payload). `canonicalBytes` sorts keys by code point, so
 *  the object order here is irrelevant; the emitted bytes are
 *  {"deviceDid":…,"rootDid":…,"ts":…,"typ":…,"validUntil":…}. */
function bindingV2Payload(rootDid, deviceDid, ts, validUntil) {
  return canonicalBytes({ typ: BINDING_V2_TYP, rootDid, deviceDid, ts, validUntil });
}

/**
 * Verify a v2 binding — the twin of shared/keybinding.verify_device_binding_v2. TOTAL on
 * untrusted input (returns false, never throws). All must hold: typ matches; rootDid and
 * deviceDid are non-empty strings; ts/validUntil are safe integers; `expectedDeviceDid`
 * (when given) matches deviceDid (anti-copy pin); `now` given + validUntil non-zero → not
 * expired; the OWNER signed the canonical five fields; the DEVICE countersigned the same.
 */
export function verifyDeviceBindingV2(binding, { now = null, expectedDeviceDid = null } = {}) {
  try {
    if (!binding || typeof binding !== 'object') return false;
    if (binding.typ !== BINDING_V2_TYP) return false;
    const { rootDid, deviceDid, ts, validUntil } = binding;
    if (typeof rootDid !== 'string' || !rootDid) return false;
    if (typeof deviceDid !== 'string' || !deviceDid) return false;
    if (!Number.isSafeInteger(ts) || !Number.isSafeInteger(validUntil)) return false;
    if (expectedDeviceDid !== null && deviceDid !== expectedDeviceDid) return false;
    if (now !== null && validUntil !== 0 && now > validUntil) return false;
    const sig = strictB64(binding.sig);
    const deviceSig = strictB64(binding.deviceSig);
    if (sig === null || deviceSig === null) return false;
    // Every other signature site here bounds its decoded length before handing the bytes to a
    // verifier; these two did not, and they are the last attacker-controlled byte strings in
    // this function. The DEVICE is always ed25519, so its countersignature is exactly 64
    // bytes and anything else is not a countersignature. The OWNER is the one signature in
    // the file that is NOT always 64: `p256Verify` above deliberately accepts both encodings
    // a p256 client emits — raw r||s (64) and ASN.1 DER from a Secure Enclave / WebAuthn
    // (~70-72) — so an equality here would silently refuse every Secure Enclave owner the
    // Python twin still accepts. The bound is therefore per curve, read from the owner's own
    // did:key (junk there throws, and the enclosing try answers false).
    if (deviceSig.length !== 64) return false;
    const ownerCurve = decodeDidKey(rootDid).curve;
    if (ownerCurve === 'ed25519' ? sig.length !== 64 : sig.length > MAX_P256_DER_SIG_BYTES) {
      return false;
    }
    const payload = bindingV2Payload(rootDid, deviceDid, ts, validUntil);
    return verifyDidSig(rootDid, sig, payload) && verifyDidSig(deviceDid, deviceSig, payload);
  } catch {
    return false;
  }
}

// ================================================================ signed Agent Card envelope

/** The canonical bytes a card envelope signs: {card, ts, typ, v} (shared/cardpub).
 *  `ts` MUST be an INTEGER epoch — a float `ts` renders through Python's repr and is,
 *  by construction, unverifiable outside Python. */
export function cardEnvelopePayload(card, ts) {
  return canonicalJSON({ card, ts, typ: CARD_ENVELOPE_TYPE, v: CARD_ENVELOPE_VERSION });
}

/** Wrap `card` in the signed envelope served at /.well-known/agent-card.sig.json. */
export function makeCardEnvelope(seedHex, card, ts) {
  if (!Number.isSafeInteger(ts)) {
    throw new TypeError('card envelope ts must be an INTEGER epoch (a float is Python-only)');
  }
  const payload = cardEnvelopePayload(card, ts);
  assertEncodable(payload);
  return {
    v: CARD_ENVELOPE_VERSION,
    typ: CARD_ENVELOPE_TYPE,
    card,
    ts,
    sig: signBytes(seedHex, Buffer.from(payload, 'utf8')).toString('base64'),
  };
}

/** Verify a card envelope; returns the inner card or null. `expectedDid` is the
 *  anti-substitution check — a signature only proves "X signed X's card". */
export function verifyCardEnvelope(envelope, expectedDid = null) {
  try {
    if (!envelope || typeof envelope !== 'object') return null;
    if (envelope.typ !== CARD_ENVELOPE_TYPE) return null;
    const { card, ts, sig } = envelope;
    if (!card || typeof card !== 'object' || !card.did || sig == null || ts == null) return null;
    if (expectedDid !== null && card.did !== expectedDid) return null;
    const raw = strictB64(sig);
    if (raw === null || raw.length !== 64) return null;
    const payload = cardEnvelopePayload(card, ts);
    assertEncodable(payload);
    return verifyBytes(publicKeyFromDid(card.did), raw, Buffer.from(payload, 'utf8'))
      ? card : null;
  } catch {
    return null;
  }
}

// ================================================================ cryptobox (X25519 + ChaCha20)
//
// STATIC-STATIC sealed box (shared/cryptobox.py). The X25519 key is a pure function of the
// SAME Ed25519 seed the agent already holds, so there is no second key to provision:
//   x25519_private = sha256("agentnet-x25519:" || ed25519_seed)
//   shared         = X25519(my_private, their_public)                    (raw ECDH)
//   key            = HKDF-SHA256(shared, salt=32 zero bytes, info="agentnet-box-v1", 32)
//   blob           = base64(nonce[12] || ciphertext || tag[16])
// salt=None in Python's HKDF means "HashLen zero bytes", hence Buffer.alloc(32).

const BOX_INFO = Buffer.from('agentnet-box-v1', 'utf8');
const BOX_SALT = Buffer.alloc(32);
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function x25519PrivateRaw(seedHex) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from('agentnet-x25519:', 'utf8'), seedBuffer(seedHex)]))
    .digest();
}

function x25519PrivateKey(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, x25519PrivateRaw(seedHex)]),
    format: 'der', type: 'pkcs8',
  });
}

/** The X25519 public key (hex) a peer needs to seal a box to this seed. Safe to publish. */
export function encPubHex(seedHex) {
  const pub = createPublicKey(x25519PrivateKey(seedHex));
  return pub.export({ format: 'der', type: 'spki' })
    .subarray(X25519_SPKI_PREFIX.length).toString('hex');
}

function boxKey(seedHex, theirPubHex) {
  const theirPub = Buffer.from(String(theirPubHex), 'hex');
  if (theirPub.length !== 32) throw new TypeError('peer X25519 public key must be 32 bytes');
  const shared = diffieHellman({
    privateKey: x25519PrivateKey(seedHex),
    publicKey: createPublicKey({
      key: Buffer.concat([X25519_SPKI_PREFIX, theirPub]), format: 'der', type: 'spki',
    }),
  });
  return Buffer.from(hkdfSync('sha256', shared, BOX_SALT, BOX_INFO, 32));
}

/** The bytes an argument MEANT, or a TypeError naming it. `Buffer.from(String(x), 'utf8')`
 *  stood here, and `String()` has an answer for everything: an object becomes
 *  "[object Object]", an array its comma-joined elements, `null` "null", `undefined`
 *  "undefined". A caller who passed the wrong shape — the parsed message where its encoded
 *  body belonged, an array of contextIds as associated data — got a perfectly well-formed
 *  box bound to meaningless AAD, and DIFFERENT values collided onto the SAME AAD, which is
 *  the one thing associated data exists to prevent: `{a:1}` and `{b:2}` both bind
 *  "[object Object]", so each opens the other's box. A wrong type here is a bug in the
 *  caller, not a message from a stranger, and it is worth a throw. A string is encoded
 *  UTF-8 through `assertEncodable` for the reason `signBytes` does: a lone surrogate
 *  would be sealed as U+FFFD, so the recipient decrypts text the sender never wrote and the
 *  Python twin (which takes bytes) could not have produced those bytes at all. Absent still
 *  means "no associated data" — what the `= Buffer.alloc(0)` defaults promise. */
function bytesArg(value, name) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value === null || value === undefined) return Buffer.alloc(0);
  if (typeof value === 'string') { assertEncodable(value); return Buffer.from(value, 'utf8'); }
  throw new TypeError(
    `${name} must be a Buffer, Uint8Array, string, or null/undefined for none `
    + `(got ${Array.isArray(value) ? 'array' : typeof value})`);
}

/** Encrypt to the holder of `theirPubHex`. Returns base64(nonce || ciphertext || tag).
 *  A fresh random nonce per call, so the output is never reproducible — which is why the
 *  wire vectors pin only the OPEN direction. */
export function seal(seedHex, theirPubHex, plaintext, ad = Buffer.alloc(0)) {
  const pt = bytesArg(plaintext, 'seal: plaintext');
  const aad = bytesArg(ad, 'seal: ad');
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('chacha20-poly1305', boxKey(seedHex, theirPubHex), nonce,
    { authTagLength: TAG_BYTES });
  if (aad.length) cipher.setAAD(aad, { plaintextLength: pt.length });
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString('base64');
}

/** Decrypt a box sealed by the matching peer. Returns a Buffer, or **null on ANY failure**
 *  (bad base64, truncated blob, wrong key, AD mismatch, auth-tag failure) — the caller's
 *  verification path stays branch-simple, exactly like shared/cryptobox.open_box. */
export function openBox(seedHex, theirPubHex, blobB64, ad = Buffer.alloc(0)) {
  // The `ad` guard sits ABOVE the try ON PURPOSE. Everything inside answers with null —
  // that is the contract, and it is right for a stranger's blob. But a wrong-typed `ad` is
  // not a cryptographic failure, it is a programming error in THIS process, and letting the
  // catch swallow it would teach the caller "wrong key or tampered box" when the truth is
  // "you passed an object". Loud for our own bug, quiet for the stranger's.
  const aad = bytesArg(ad, 'openBox: ad');
  try {
    const raw = Buffer.from(String(blobB64), 'base64');
    if (raw.length < NONCE_BYTES + TAG_BYTES) return null;
    const nonce = raw.subarray(0, NONCE_BYTES);
    const ct = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    const decipher = createDecipheriv('chacha20-poly1305', boxKey(seedHex, theirPubHex), nonce,
      { authTagLength: TAG_BYTES });
    decipher.setAuthTag(tag);
    if (aad.length) decipher.setAAD(aad, { plaintextLength: ct.length });
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null;
  }
}

// ---- end of the seam
// The door calls this one unexported helper (its JWKS gate); exported here so a door built on
// this file needs nothing the block does not already have.
export { wbaPublicFromJwk };
