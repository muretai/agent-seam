"""
shared/crypto.py
L2 identity-layer crypto core.

  - Ed25519 sign/verify
      Preferred: the `cryptography` library (fast when available)
      Fallback:  pure-Python implementation (RFC 8032 reference, zero deps)
  - did:key  a self-certifying identifier where the public key IS the DID
      did:key:z<base58btc(0xed01 + 32-byte public key)>
      -> No server needed to resolve a DID; key = identity = address in one.
      -> did:wba (web-hosted) COEXISTS with this, but is NOT a swap: V1.1 binds
         the key thumbprint into the DID path and needs a resolver (fetch
         did.json + DataIntegrityProof + binding check), which public_from_did
         cannot do offline.
  - Message signing envelope
      Signed payload: canonical JSON of {from, to, messageId, contextId,
      timestamp, text}.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

# ================================================================ Ed25519
# Backend selection: cryptography (fast) -> pure-Python (zero deps)

_FORCE_PURE = os.environ.get("AGENTNET_PURE_ED25519") == "1"

try:
    if _FORCE_PURE:
        raise ImportError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature

    BACKEND = "cryptography"

    def ed25519_public_from_seed(seed: bytes) -> bytes:
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        from cryptography.hazmat.primitives import serialization as ser
        return sk.public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw)

    def ed25519_sign(seed: bytes, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    def ed25519_verify(public: bytes, signature: bytes,
                       message: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

except ImportError:
    # ---------------- Pure-Python Ed25519 (based on the RFC 8032 reference) --
# Structure and helper names follow the reference implementation printed as RFC 8032's code
# component (itself derived from D. J. Bernstein's public-domain `ed25519.py`). The RFC's
# code component is offered under the Revised BSD licence; the public-domain original
# imposes nothing. Neither conflicts with this file's MIT grant — the attribution is here
# because an irrevocable licence should not rest on an unstated provenance.
    # Slow (sign/verify take hundreds of ms) but fine for a prototype.
    BACKEND = "pure-python"

    _b = 256
    _q = 2 ** 255 - 19
    _l = 2 ** 252 + 27742317777372353535851937790883648493

    def _H(m: bytes) -> bytes:
        return hashlib.sha512(m).digest()

    def _inv(x: int) -> int:
        return pow(x, _q - 2, _q)

    _d = -121665 * _inv(121666) % _q
    _I = pow(2, (_q - 1) // 4, _q)

    def _xrecover(y: int) -> int:
        xx = (y * y - 1) * _inv(_d * y * y + 1)
        x = pow(xx, (_q + 3) // 8, _q)
        if (x * x - xx) % _q != 0:
            x = (x * _I) % _q
        if x % 2 != 0:
            x = _q - x
        return x

    _By = 4 * _inv(5) % _q
    _Bx = _xrecover(_By)
    _B = (_Bx, _By)

    def _edwards(P, Q):
        x1, y1 = P
        x2, y2 = Q
        x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
        y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
        return (x3 % _q, y3 % _q)

    def _scalarmult(P, e: int):
        Q = (0, 1)
        while e > 0:
            if e & 1:
                Q = _edwards(Q, P)
            P = _edwards(P, P)
            e >>= 1
        return Q

    def _encodepoint(P) -> bytes:
        x, y = P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    def _decodepoint(s: bytes):
        n = int.from_bytes(s, "little")
        y = n & ((1 << 255) - 1)
        x = _xrecover(y)
        if (x & 1) != ((n >> 255) & 1):
            x = _q - x
        P = (x, y)
        if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
            raise ValueError("point not on curve")
        return P

    def _bit(h: bytes, i: int) -> int:
        return (h[i // 8] >> (i % 8)) & 1

    def _clamp_scalar(h: bytes) -> int:
        return (2 ** (_b - 2)
                + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2)))

    def _hint(m: bytes) -> int:
        return int.from_bytes(_H(m), "little")

    def ed25519_public_from_seed(seed: bytes) -> bytes:
        h = _H(seed)
        a = _clamp_scalar(h)
        return _encodepoint(_scalarmult(_B, a))

    def ed25519_sign(seed: bytes, message: bytes) -> bytes:
        h = _H(seed)
        a = _clamp_scalar(h)
        pk = _encodepoint(_scalarmult(_B, a))
        r = _hint(h[32:64] + message)
        R = _scalarmult(_B, r)
        S = (r + _hint(_encodepoint(R) + pk + message) * a) % _l
        return _encodepoint(R) + S.to_bytes(32, "little")

    def ed25519_verify(public: bytes, signature: bytes,
                       message: bytes) -> bool:
        if len(signature) != 64 or len(public) != 32:
            return False
        try:
            R = _decodepoint(signature[:32])
            A = _decodepoint(public)
        except ValueError:
            return False
        S = int.from_bytes(signature[32:64], "little")
        if S >= _l:
            return False
        h = _hint(signature[:32] + public + message)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))


def new_seed() -> bytes:
    """Generate a 32-byte private-key seed from a cryptographic RNG."""
    return os.urandom(32)


# ================================================================ base58btc

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


_MAX_B58_LEN = 512   # every legit base58 here (DIDs ~48, invite codes, zKeys) is < 64


def b58decode(s: str) -> bytes:
    # Guard the O(n^2) bignum loop below against a pathologically long input. This is
    # the single chokepoint through which an attacker-controlled `from`/DID reaches the
    # decoder (public_from_did/key_from_did call it BEFORE any length or signature
    # check), so an unbounded `from` field would pin a CPU for seconds-to-minutes per
    # request at both the relay (_verify_rpc_sig) and every node inbox (verify_envelope).
    # A generous cap neutralizes that unauthenticated CPU-exhaustion at zero cost.
    if len(s) > _MAX_B58_LEN:
        raise ValueError("base58 input too long")
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


# ================================================================ did:key

_MULTICODEC_ED25519 = b"\xed\x01"   # multicodec: ed25519-pub


def did_from_public(public: bytes) -> str:
    """32-byte Ed25519 public key -> did:key:z... Rejects any other length: a 33-byte
    compressed P-256 point fed here would emit a well-formed-LOOKING DID under the
    Ed25519 multicodec that every verifier downstream silently rejects (T101 anchor
    note). P-256 keys go through did_from_p256()."""
    if len(public) != 32:
        raise ValueError(
            f"expected a 32-byte Ed25519 public key, got {len(public)} bytes"
            " (a 33-byte compressed point is P-256 — use did_from_p256)")
    return "did:key:z" + b58encode(_MULTICODEC_ED25519 + public)


def public_from_did(did: str) -> bytes:
    """did:key:z... -> 32-byte Ed25519 public key. Self-certifying, so no server
    needed. Ed25519-only by design (the zero-dependency core); a P-256 did:key
    raises here. Use key_from_did()/verify() for curve-agnostic handling."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did!r}")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] != _MULTICODEC_ED25519 or len(raw) != 34:
        raise ValueError("not an ed25519 did:key")
    return raw[2:]


# ================================================================ P-256 (optional)
# Secure Enclave / passkey / WebAuthn keys are P-256 (secp256r1 / ES256), NOT
# Ed25519. P-256 verification is an OPTIONAL capability that requires the
# `cryptography` library (there is no pure-Python P-256 fallback) — the same dep
# exception as the relay/E2E layer. The zero-dependency core stays Ed25519-only.
#
# This exists for the device-key hierarchy (shared/keybinding.py): a hardware
# P-256 ROOT key (Secure Enclave / passkey) authorizes a software Ed25519 device
# key, and the Ed25519 device key does all day-to-day signing (messages, name
# registration). So the wire protocol never has to verify P-256 except when
# checking a root->device binding (e.g. at the registrar), and the Ed25519 core
# path below is never affected by P-256 being present or absent.

_MULTICODEC_P256 = bytes([0x80, 0x24])   # varint(0x1200) = p256-pub multicodec

try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import utils as _asym_utils
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    P256_AVAILABLE = True
except ImportError:
    P256_AVAILABLE = False


def did_from_p256(comp_pub: bytes) -> str:
    """33-byte compressed SEC1 P-256 point -> did:key:zDn... (multicodec p256-pub)."""
    if len(comp_pub) != 33 or comp_pub[0] not in (0x02, 0x03):
        raise ValueError("expected a 33-byte compressed P-256 point")
    return "did:key:z" + b58encode(_MULTICODEC_P256 + comp_pub)


def key_from_did(did: str) -> tuple[str, bytes]:
    """did:key -> (curve, public-key-bytes): ("ed25519", 32-byte key) or
    ("p256", 33-byte compressed point). Lets a verifier dispatch by key type while
    the DID stays self-certifying (the key IS the identifier). Raises on anything
    that is neither curve."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did!r}")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] == _MULTICODEC_ED25519 and len(raw) == 34:
        return "ed25519", raw[2:]
    if raw[:2] == _MULTICODEC_P256 and len(raw) == 35:
        return "p256", raw[2:]
    raise ValueError("unsupported did:key multicodec (not ed25519 or p256)")


def _coerce_ecdsa_der(signature: bytes) -> bytes | None:
    """Normalize a P-256 signature to ASN.1 DER. A raw r||s pair (64 bytes, the
    WebCrypto form) is converted; an already-DER signature (Secure Enclave /
    WebAuthn) is passed through after a validating decode. None if neither."""
    if len(signature) == 64:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            return _asym_utils.encode_dss_signature(r, s)
        except Exception:
            return None
    try:
        _asym_utils.decode_dss_signature(signature)   # validate it is DER
        return signature
    except Exception:
        return None


def p256_verify(comp_pub: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an ES256 (ECDSA-P-256 / SHA-256) signature. Accepts both encodings
    clients emit: ASN.1 DER (Secure Enclave / WebAuthn) and raw r||s (WebCrypto).
    Returns False (never raises) if `cryptography` is unavailable or the signature
    is invalid — so this can be called safely from the zero-dep paths."""
    if not P256_AVAILABLE:
        return False
    der = _coerce_ecdsa_der(signature)
    if der is None:
        return False
    try:
        pub = _ec.EllipticCurvePublicKey.from_encoded_point(
            _ec.SECP256R1(), comp_pub)
        pub.verify(der, message, _ec.ECDSA(_hashes.SHA256()))
        return True
    except (_InvalidSignature, ValueError):
        return False
    except Exception:
        return False


def verify(did: str, signature: bytes, message: bytes) -> bool:
    """Curve-dispatching signature verification against a did:key. ed25519 uses the
    zero-dependency core; p256 uses the optional `cryptography` backend. The
    generic entry point for every DID-based verifier in shared/ and agent/ — a new
    key type is one branch here, not N call sites (T142 A1). Never raises.

    "Never raises" has to hold for a DID that is not a string at all: every binding
    verifier (tlsbind, keybinding, ygg) hands this whatever a stranger's card said,
    and `key_from_did(123)` raised AttributeError out of `startswith` — through the
    verifier and into the card fetch. The type check is here, at
    the one place every DID-based verifier funnels through."""
    if not isinstance(did, str):
        return False
    try:
        curve, pub = key_from_did(did)
        if curve == "ed25519":
            return ed25519_verify(pub, signature, message)
        if curve == "p256":
            return p256_verify(pub, signature, message)
    except Exception:
        return False
    return False


def did_from_raw_pub(pub: bytes) -> str:
    """Rebuild a did:key from raw public-key bytes stored WITHOUT a multicodec
    prefix (KeyState.rootKey hex, a JWK `x`, an iroh endpoint id). 32 bytes is
    Ed25519; 33-byte compressed point is P-256. Length picks the constructor
    because those records have no prefix (A1 is not a wire change); the DID then
    carries the multicodec so verify() dispatches on key type, not length."""
    if len(pub) == 32:
        return did_from_public(pub)
    if len(pub) == 33:
        return did_from_p256(pub)
    raise ValueError(
        f"unsupported raw public key length {len(pub)} "
        "(want 32=ed25519 or 33=p256)")


def verify_raw(pub: bytes, signature: bytes, message: bytes) -> bool:
    """Curve-dispatching verify against raw public-key bytes. Never raises.
    Call sites that hold a key rather than a DID (KeyState.rootKey, transport
    endpoint ids, JWKs) go through here so a new curve is still one branch."""
    try:
        return verify(did_from_raw_pub(pub), signature, message)
    except (ValueError, TypeError):
        return False


# ================================================================ signing envelope

def canonical(payload: dict[str, Any]) -> bytes:
    """Canonical JSON of the signed payload (fixed key order, no whitespace).
    Exposed as a public helper so L2 message signing (signing_payload) and L3
    introduction signing (shared/vc.py) share the exact same canonicalization.
    Fixing key order makes the bytes independent of dict insertion order, so the
    same content always yields the same signed payload.

    Note: ensure_ascii=False is intentional and part of the wire protocol
    (do not change); it affects only how runtime user data is encoded, not the
    source language of this project."""
    # allow_nan=False: NaN/Infinity are not valid JSON (RFC 8259) and are non-portable
    # across languages — REFUSE to sign them (raise ValueError) rather than emit a token
    # other implementations cannot reproduce or would reject. protocol.loads also rejects
    # them on the wire, so a non-finite literal can never reach a signing/verify path.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


# Backward-compatible alias (for existing call sites).
_canonical = canonical


# RESERVED, NOT PRESENT: these six fields are protocol-fixed
# (principle 4). Do NOT add replyTo (or any field) here to make reply attribution
# tamper-proof — use a DETACHED replyToSig instead, owner-gated. Trigger + design:
# docs/IMPLEMENTATION_BACKLOG.md "Deferred (trigger-gated)".
def signing_payload(from_did: str, to_did: str, message_id: str,
                    context_id: str | None, timestamp: float,
                    text: str) -> bytes:
    return canonical({
        "from": from_did, "to": to_did, "messageId": message_id,
        "contextId": context_id, "timestamp": timestamp, "text": text,
    })


def sign_envelope(seed: bytes, from_did: str, to_did: str, message_id: str,
                  context_id: str | None, timestamp: float,
                  text: str) -> str:
    sig = ed25519_sign(seed, signing_payload(
        from_did, to_did, message_id, context_id, timestamp, text))
    return base64.b64encode(sig).decode("ascii")


def verify_envelope(from_did: str, to_did: str, message_id: str,
                    context_id: str | None, timestamp: float,
                    text: str, sig_b64: str) -> bool:
    """Verify the message envelope under from_did. Curve-agnostic (dispatches
    through verify()); with did:key the DID itself IS the key. Never raises.
    Delegates to `verify_signed_envelope` with the root as the signer."""
    return verify_signed_envelope(
        from_did, to_did, message_id, context_id, timestamp, text, sig_b64)


def verify_signed_envelope(from_did: str, to_did: str, message_id: str,
                           context_id: str | None, timestamp: float,
                           text: str, sig_b64: str, *,
                           signer_did: str | None = None) -> bool:
    """Verify a signed message envelope.

    The payload's `from` is always `from_did` (the stable root DID; the six
    signed fields are frozen). The verifying key is `signer_did` when given,
    otherwise `from_did`. An enrolled sender signs with a hot op-key while
    `from` stays the root — inbox and outbox must use this split or a
    default-enrolled peer's reply looks like tampering (T142 A2).

    Dispatches through `verify` so a P-256 op-key is a policy decision, not
    an Ed25519-only decode failure."""
    signer = signer_did or from_did
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    return verify(signer, sig, signing_payload(
        from_did, to_did, message_id, context_id, timestamp, text))


#: Multicodec names `crypto.verify` can check today. Unknown names are skipped
#: (A3 classical-accept / forward compatibility). A known name whose signature
#: fails is a refusal — a downgrade cannot hide inside `metadata.sigs`.
_KNOWN_SIG_ALG = {"ed25519-pub": "ed25519", "p256-pub": "p256"}


def extra_sigs_ok(from_did: str, to_did: str, message_id: str,
                  context_id: str | None, timestamp: float,
                  text: str, sigs: Any, *,
                  signer_did: str | None = None) -> bool:
    """T142 A3: additive `metadata.sigs` beside the existing `sig`.

    `sigs` absent/None → True (today's messages). Not a list → False.
    Each entry is `{alg, sig}`. Unknown `alg` is skipped. A known `alg`
    is verified over the same six-field payload as `sig`, with the same
    operational key. No ML-DSA implementation here — that is C1.
    """
    if sigs is None:
        return True
    if not isinstance(sigs, list):
        return False
    signer = signer_did or from_did
    try:
        curve, _pub = key_from_did(signer)
    except Exception:
        return False
    payload = signing_payload(
        from_did, to_did, message_id, context_id, timestamp, text)
    for entry in sigs:
        if not isinstance(entry, dict):
            return False
        alg = entry.get("alg")
        sig_b64 = entry.get("sig")
        if not isinstance(alg, str) or not isinstance(sig_b64, str):
            return False
        want = _KNOWN_SIG_ALG.get(alg)
        if want is None:
            continue
        if want != curve:
            return False
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            return False
        if not verify(signer, sig, payload):
            return False
    return True
