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
from typing import Callable, Optional, Tuple

from shared import crypto

#: The only algorithm this module will emit or accept. Ed25519 is what did:key
#: encodes and what Web Bot Auth mandates, so one value covers both features.
ALG = "EdDSA"

#: Refuse absurd tokens before doing any work. A Domain Linkage Credential is a few
#: hundred bytes; anything near this cap is either a bug or an attempt to make a
#: verifier chew through attacker-chosen input.
MAX_TOKEN_BYTES = 16384


def b64url(data: bytes) -> str:
    """base64url WITHOUT padding (RFC 7515 §2 requires the padding be stripped)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(s: str) -> bytes:
    """Decode unpadded base64url. Raises ValueError on anything malformed.

    Strict on purpose: `validate=True` rejects characters outside the base64url
    alphabet instead of silently discarding them, so two different token strings can
    never decode to the same bytes (a signature-stripping trick in disguise)."""
    if not isinstance(s, str):
        raise ValueError("expected str")
    # Reject the standard-base64 alphabet explicitly: "+" and "/" decoding as though
    # they were "-" and "_" would let one signature validate under two spellings.
    if "+" in s or "/" in s or "=" in s:
        raise ValueError("not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as exc:                       # binascii.Error and friends
        raise ValueError(f"bad base64url: {exc}") from exc


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
