"""
shared/jws.py
Minimal compact JWS (RFC 7515) over Ed25519 — the ONE wire primitive the domain
binding (shared/domainbind.py, T88) and the Web Bot Auth bridge
(shared/webbotauth.py, T89) both need.

Why this module exists at all:
  Every signed artifact muretai already ships (introductions, org bindings, contact
  grants, card envelopes) uses shared/crypto.canonical + standard base64 — a format
  we control end to end. The two features above are different: they must be readable
  by software we do NOT control (a DIF-aware verifier reading a Domain Linkage
  Credential; anything that consumes a JOSE token). Those ecosystems speak compact
  JWS: base64url(header) "." base64url(payload) "." base64url(signature). So this is
  a deliberate, narrow concession to an outside format — NOT a new house style. Do not
  migrate existing signed objects onto it.

Why so small: only what interop needs. EdDSA/Ed25519 only, no JWK/JWS header
resolution, no `crit`, no detached payloads, no compression. Everything else a
general JOSE library offers is attack surface we would have to defend.

Two invariants worth stating loudly, because both are places JWT libraries have
historically been broken:

1. `alg` is CHECKED, never TRUSTED. verify_compact() demands the header say exactly
   "EdDSA" and then verifies with Ed25519 regardless — the algorithm is decided by
   the verifier's policy, not by the attacker-supplied token. This is what closes
   the classic alg:"none" / alg:"HS256" confusion family.
2. Verification operates on the bytes AS RECEIVED. The signing input is re-derived
   by splitting the token on ".", never by re-serializing the decoded payload. So
   canonicalization can play no part on the verify path — which also sidesteps the
   float-repr interop landmine documented in shared/cardpub.py (a JSON number that
   only Python reproduces byte-for-byte would otherwise become unverifiable
   elsewhere). Callers must still put INTEGER epoch seconds in payloads they mint.

Signing goes through a `sign_bytes` callable (Identity.sign_bytes) rather than raw
key material, exactly like shared/orgbind.make_membership — so a remote-signer
identity (keys/<name>.signer.json, no local seed) works unchanged.

Pure standard library.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
import json
import re
from typing import Callable, Optional, Tuple

from shared import crypto

#: The only algorithm this module will emit or accept. Ed25519 is what did:key
#: encodes and what Web Bot Auth mandates, so one value covers both features.
ALG = "EdDSA"

#: Refuse absurd tokens before doing any work. A Domain Linkage Credential is a few
#: hundred bytes; anything near this cap is either a bug or an attempt to make a
#: verifier chew through attacker-chosen input.
MAX_TOKEN_BYTES = 16384

#: The base64url alphabet, WHOLE. Anchored with \A/\Z and not ^/$ because PYTHON's `$` also
#: matches just before a final newline, so `^…$` would accept a value with a trailing LF —
#: precisely one of the second spellings this regex exists to refuse. (JavaScript's `$` has no
#: such exception, which is why the twin's `WBA_B64URL` in js/seam.mjs spells the same rule
#: `^[A-Za-z0-9_-]*$`. Same accepted set, two languages' anchors.) Compiled once: it runs on
#: every segment of every token. NECESSARY BUT NOT SUFFICIENT — see rule 3 in unb64url.
_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]*\Z")


def b64url(data: bytes) -> str:
    """base64url WITHOUT padding (RFC 7515 §2 requires the padding be stripped)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(s: str) -> bytes:
    """Decode unpadded base64url, or raise ValueError. ONE spelling per byte string.

    Three rules, and none of them is what the standard library does:

      1. EVERY character must be in the base64url alphabet. `base64.urlsafe_b64decode`
         silently DISCARDS every byte outside the alphabet — not just the standard-base64
         "+", "/" and "=" this function used to name by hand, but whitespace, punctuation,
         control characters, anything. So "AAAA" and "A A A A" were the same three bytes,
         and a 43-character JWK `x` with a newline, a tab or three "!" wedged into it was
         the same key as the honest spelling. The old guard LOOKED like it worked only
         because `-len(s) % 4` is computed on the RAW length, so some junk counts happened
         to misalign the padding and raise — luck, per input, not a rule.
      2. A length congruent to 1 (mod 4) is refused explicitly. Six bits is not a byte, so
         NO byte string encodes to such a length. Today's CPython happens to raise on it
         from inside binascii ("number of data characters … cannot be 1 more than a multiple
         of 4"), but that is the C decoder's error checking, not a rule this function ever
         stated — and the identical input is silently TRUNCATED by Node's
         `Buffer.from(x, "base64url")`, which is why the JavaScript twin checks it by hand.
         Stating it here costs one comparison and makes both implementations refuse the same
         strings for the same reason, instead of each inheriting whatever its base64 decoder
         does this release. (Same argument shared/neturl.py makes for canonicalizing an
         address itself rather than trusting version-dependent `ipaddress` predicates.)
      3. The decoded bytes must RE-ENCODE to the input, exactly. This is the rule that
         actually delivers the "one spelling" in the first line, and rules 1 and 2 do not
         imply it — read this part twice, because the alphabet check LOOKS complete and is
         not. A base64 character carries 6 bits and a byte carries 8, so unless the length
         is a multiple of 4 the final character has bits that no byte claims: 43 characters
         (the length of an Ed25519 JWK `x`) is 258 bits carrying 256, and the last two bits
         are discarded on decode. Every one of the 4 values of those bits spells a
         DIFFERENT, alphabet-clean, correctly-lengthed string that decodes to the SAME 32
         key bytes — "…Hh8", "…Hh9", "…Hh-" and "…Hh_" are one key with four names. The
         size of the family is fixed by the length mod 4: ≡ 3 leaves 2 spare bits and so
         FOUR names (a 32-byte key, a 32-byte thumbprint); ≡ 2 leaves 4 and so SIXTEEN —
         which is what an Ed25519 signature segment is, 64 bytes in 86 characters; ≡ 0 is
         exact and already has one. Re-encoding and comparing collapses every family to the
         single member a standard encoder emits, because `b64url` always writes the spare
         bits as zero. The JavaScript twin's `WBA_B64URL` had the identical hole and is
         closing it the same way in the same round — this was never a divergence between
         the implementations, only a gap they shared.

    Why an alias matters more here than in a general codec: the value is very often a JWK
    `x` — a PUBLIC KEY (shared/webbotauth.public_from_jwk) — and a relying party is
    entitled to treat that literal string as the key's NAME: to store it, index it, compare
    it, de-duplicate on it. Under the old check one key had endlessly many names, so a
    directory could hold N entries for a single key, a check keyed on the string could miss
    the key it was meant to match, and a peer echoing an `x` back could re-spell it in
    transit without changing the key it names. The same argument applies to the header and
    signature segments verify_compact() splits out: two token texts decoding alike is the
    shape every signature-stripping trick is cut from.

    `validate=True` is NOT the fix, tempting as the name is: it validates the STANDARD
    alphabet (so "-" and "_" would be the rejects) and it rejects the very padding we
    strip. The alphabet has to be checked here, before the stdlib is allowed to be
    generous.

    A wire contract whose two reference implementations disagree about which strings are
    keys is not a contract — and one where BOTH accept four strings for one key is not much
    better, which is why rule 3 lands on both sides together."""
    if not isinstance(s, str):
        raise ValueError("expected str")
    if not _B64URL_RE.match(s):
        raise ValueError("not unpadded base64url")
    if len(s) % 4 == 1:
        raise ValueError("not unpadded base64url (a length of 1 mod 4 decodes to nothing)")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as exc:                       # binascii.Error and friends
        raise ValueError(f"bad base64url: {exc}") from exc
    # Rule 3, and the only one that actually makes the mapping injective: b64url() writes
    # the final character's spare bits as zero, so re-encoding names the ONE member of the
    # trailing-bit family a standard encoder would have produced. Cheap, total, and it
    # cannot drift from the encoder because it IS the encoder.
    if b64url(raw) != s:
        raise ValueError("not canonical base64url (it re-encodes to a different string)")
    return raw


def kid_for(did: str) -> str:
    """The JOSE `kid` for a did:key: the DID's own verification-method id.

    For did:key the verification method is `<did>#<multibase-key>` — the fragment
    repeats the key because, for a self-certifying DID, the key IS the identifier.
    A verifier never needs to resolve this: it can read the key straight out of
    `iss`. We emit it because DIF/JOSE tooling expects a `kid` to be dereferenceable
    in the issuer's DID document, and this is that document's only entry."""
    return "%s#%s" % (did, did.rsplit(":", 1)[-1])


def signing_input(header: dict, payload: dict) -> bytes:
    """The exact ASCII bytes that get signed: b64url(header) "." b64url(payload).

    Serialization is sort_keys + compact separators so a given (header, payload) pair
    always yields the same token — the wire vectors pin these bytes. This determinism
    matters only on the SIGN side; verification never calls this (see module docstring)."""
    def _part(obj: dict) -> str:
        return b64url(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8"))
    return ("%s.%s" % (_part(header), _part(payload))).encode("ascii")


def sign_compact(payload: dict, *, did: str,
                 sign_bytes: Callable[[bytes], str],
                 header: Optional[dict] = None) -> str:
    """Mint a compact JWS. `sign_bytes` is Identity.sign_bytes: bytes -> STANDARD
    base64 str (that is the repo-wide signing convention; we re-encode to base64url
    here rather than asking every identity backend to change)."""
    hdr = {"alg": ALG, "typ": "JWT", "kid": kid_for(did)}
    if header:
        hdr.update(header)
    if hdr.get("alg") != ALG:
        raise ValueError("this module signs EdDSA only")
    si = signing_input(hdr, payload)
    # The one other base64 decode in this module, and deliberately NOT given unb64url's
    # strictness: this reads OUR OWN signer's output (Identity.sign_bytes, standard base64
    # per the repo-wide convention), not a value off the wire, and a remote-signer backend
    # is free to hand back a padded / newline-terminated blob the way any base64 producer
    # may. The alias worry does not arise either — the bytes are immediately re-encoded
    # with b64url() into a token, so a signer that spelled its output oddly produces a
    # signature that simply fails to verify, loudly, rather than a second name for a key.
    raw = base64.b64decode(sign_bytes(si))
    return "%s.%s" % (si.decode("ascii"), b64url(raw))


def decode_unverified(token: str) -> Optional[Tuple[dict, dict, bytes, bytes]]:
    """(header, payload, signing_input, signature) with NO signature check, or None.

    Never raises. The name is a warning: everything it returns is attacker-controlled
    until verify_compact() has passed. Used by verifiers that must read `iss` to learn
    WHICH key to check against — the one legitimate reason to look before verifying."""
    try:
        if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            return None
        parts = token.split(".")
        if len(parts) != 3:                        # a JWE (5 parts) is not a JWS
            return None
        h_b64, p_b64, s_b64 = parts
        header = json.loads(unb64url(h_b64).decode("utf-8"))
        payload = json.loads(unb64url(p_b64).decode("utf-8"))
        sig = unb64url(s_b64)
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return header, payload, ("%s.%s" % (h_b64, p_b64)).encode("ascii"), sig
    except Exception:
        return None


def verify_compact(token: str, did: str) -> Optional[dict]:
    """The payload iff the token is a valid EdDSA JWS signed by `did`'s key, else None.

    Fails closed on everything: wrong alg, bad base64, malformed JSON, wrong key,
    truncated signature. Never raises — callers treat None as "no proof", which is
    the same posture as shared/cardpub.verify_card_envelope and
    shared/orgbind.verify_membership."""
    parsed = decode_unverified(token)
    if parsed is None:
        return None
    header, payload, si, sig = parsed
    # Policy, not negotiation: the token does not get to pick the algorithm.
    if header.get("alg") != ALG:
        return None
    if len(sig) != 64:                             # Ed25519 signatures are fixed-width
        return None
    if not crypto.verify(did, sig, si):
        return None
    return payload


def payload_of(token: str) -> Optional[dict]:
    """Convenience: the unverified payload only (or None). Same warning as
    decode_unverified — never make a trust decision on this."""
    parsed = decode_unverified(token)
    return None if parsed is None else parsed[1]
