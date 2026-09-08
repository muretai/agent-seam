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

# ---------------- the gate BOTH backends open with --------------------------------------
# These rules live OUTSIDE the backend `try` on purpose. They are what must hold whichever
# backend answers, and the library backend has no point arithmetic to reach for -- it hands
# 32 bytes to OpenSSL and gets a boolean back -- so the only place it can state them is on
# the encoded bytes. The pure backend then states them the SAME way, because two halves of
# one file reaching opposite verdicts on the same wire bytes is this repository's worst
# failure, and the two halves are picked by an environment variable a deployer sets.

_P25519 = 2 ** 255 - 19     # the field prime; a point encoding carries y in its low 255 bits

#: The 14 encodings of a point of order 1, 2, 4 or 8 -- every point on this curve that is
#: NOT of prime order l. Seven y values, each with the sign bit clear and set (the sign bit
#: is not part of the order, so both spellings of each must go; three of the fourteen are
#: `x = 0` with the sign bit set, which a strict decoder refuses anyway -- they are kept so
#: that Go, Rust and Python blacklist the SAME set of bytes rather than the same set of
#: points). The table is used for the public key A *and* for the signature's R, because a
#: byte string decompresses to a small-order point exactly when it is one of these.
#:
#: This is libsodium's `ge25519_has_small_order` blacklist, byte for byte the same table
#: go/seam.go and rust/src/lib.rs now carry. Measured on this machine over five sample
#: messages: node's `crypto.verify` accepted 0 of the 14 as a signing key, Go's stdlib
#: `crypto/ed25519` accepted 3, `cryptography` accepted 3, and the pure backend accepted 12.
#: Only the JavaScript reference was already right, which is how a DID WITH NO PRIVATE KEY
#: BEHIND IT could authenticate everything: verification asks [S]B == R + [h]A, and for a
#: small-order A the term [h]A is the identity for EVERY h, so `R = <that point>, S = 0`
#: verifies over ANY message. The attacker publishes the DID and one constant 64-byte blob
#: signs their whole life -- no key, no forgery work, no per-message step. Python has to
#: refuse what JavaScript refuses, or the door answers differently depending on which
#: language opened it.
#: Each entry below was re-derived and its order re-checked with this file's own _scalarmult.
_ED25519_SMALL_ORDER = frozenset({
    # y = 0 (x = +-sqrt(-1)) -- order 4
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    # y = 1 (x = 0) -- order 1: the IDENTITY, the element that signs everything
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"),
    # order 8
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    # order 8 (the other one)
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    # y = p-1 (x = 0) -- order 2
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    # y = p, i.e. y == 0 -- the NON-CANONICAL spelling of the order-4 point
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    # y = p+1, i.e. y == 1 -- the NON-CANONICAL spelling of the IDENTITY
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
})


def _ed25519_wire_ok(public: bytes, signature: bytes) -> bool:
    """The byte-level gate every Ed25519 verification in this file opens with.

    Four refusals, in the one place a public key ENTERS verification so that every caller
    -- `verify`, `verify_raw`, `verify_signed_envelope`, `extra_sigs_ok`, and every consumer
    that vendors this slice -- inherits them without a second call site to remember:

      1. shapes: a 32-byte key and a 64-byte signature, or nothing to talk about;
      2. a small-order A: the 14 blobs above, which authenticate every message under a key
         nobody holds the private half of;
      3. a small-order R -- the signature's first 32 bytes. A byte string decompresses to a
         small-order point exactly when it is one of the same 14, so one table answers both
         questions. This one is NOT delegable and not optional: measured on this machine, a
         signature `R = identity, S = h*a mod l` over an HONEST message under an HONEST key
         satisfies [S]B == R + [h]A, and node's `crypto.verify` REFUSES it while
         `cryptography` ACCEPTS it. Both are OpenSSL; they are different OpenSSL builds. A
         verdict that moves with whichever libcrypto the machine happens to link is not a
         contract, so it is pinned here instead of inherited. (What it buys: the key holder
         cannot mint a second, differently-spelled signature over a message they already
         signed -- the same non-repudiation reason `S < l` exists. Rust's `verify_strict`
         and Go's own table refuse it too.)
      4. one point, ONE spelling: y is read from the low 255 bits, so y and y+p are two
         byte strings naming the SAME point, and RFC 8032 5.1.3 calls the y >= p encoding
         invalid. Refused here for A and R alike.

         This last one is DEFENCE rather than contract, and the difference is worth stating
         because Go and Rust state the rule only through the table above. It cannot pull
         Python away from them: a non-canonical encoding names a point whose y is 0..18, and
         nobody can produce a verifying signature under such a key (its discrete log is
         unknown) or with such an R (finding r with [r]B in that range is a ~2^-251 search)
         -- except for the small-order ones, which the table already holds. So this line
         only ever turns a False into a False. It is kept because it is also what the other
         two references DO, measured rather than assumed: node's `crypto.verify` and Go's
         stdlib `crypto/ed25519` both refuse `ff..ff` and `ee..7f` as a verification key
         today, and the pure backend accepted the second of those before this change -- its
         mask folded y and y+p onto one point, exactly the hole `_decodepoint` now names.

    What this deliberately does NOT do is test `[l]A == identity` ("is A of prime order?").
    A key carrying a torsion component (A = A' + T, order 8l, not small order) is accepted
    today by node, by `cryptography` and by the pure backend alike -- measured on all three
    -- so refusing it here would open a NEW split, in the other direction, against the very
    twin this change exists to rejoin. The rule enforced is the one all four implementations
    already share.
    """
    if len(public) != 32 or len(signature) != 64:
        return False
    if bytes(public) in _ED25519_SMALL_ORDER:
        return False
    if bytes(signature[:32]) in _ED25519_SMALL_ORDER:
        return False
    _mask255 = (1 << 255) - 1
    return ((int.from_bytes(public, "little") & _mask255) < _P25519
            and (int.from_bytes(signature[:32], "little") & _mask255) < _P25519)


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
        # The gate FIRST, and on the raw bytes. OpenSSL under `cryptography` says yes to
        # two things node's OpenSSL says no to: `R = <small-order point>, S = 0` under a
        # small-order KEY, and a small-order R under an honest key. Handing these bytes
        # straight to the library is how Python answered a signature JavaScript refused,
        # and there is no point arithmetic in this branch to ask instead -- the encoded
        # bytes are the only thing this backend can inspect, so the table is mandatory.
        if not _ed25519_wire_ok(public, signature):
            return False
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
    _q = _P25519            # one spelling of the field prime, shared with the gate above
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
        # RFC 8032 5.1.3 step 1: an encoding whose y is >= p is INVALID. The mask above
        # is why it has to be said out loud -- masking to 255 bits silently folds y and
        # y+p onto one point, so the same signature had several byte spellings. Said
        # here rather than only at the call site so R and A both inherit it, and so any
        # future caller of _decodepoint does too.
        if y >= _q:
            raise ValueError("non-canonical point encoding (y >= p)")
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
        # `mod l` on BOTH hash-derived scalars, as RFC 8032 5.1.6 steps 2 and 4 write them.
        # The emitted bytes are unchanged -- B has order l, so [r]B == [r mod l]B, and S is
        # reduced mod l anyway -- which is why the pinned vectors still match. It is written
        # out because the verify path below MUST reduce (there the value changes), and a
        # reader who sees one reduction and not the other has to work out which is load-
        # bearing; both are, one for correctness and one for the wire staying identical.
        r = _hint(h[32:64] + message) % _l
        R = _scalarmult(_B, r)
        k = _hint(_encodepoint(R) + pk + message) % _l
        S = (r + k * a) % _l
        return _encodepoint(R) + S.to_bytes(32, "little")

    def ed25519_verify(public: bytes, signature: bytes,
                       message: bytes) -> bool:
        # The same gate the library backend opens with, spelled by the same function, so
        # the two backends cannot drift apart on which keys and which point encodings are
        # admissible. _decodepoint below re-states the canonical-y half; that redundancy
        # is deliberate -- the gate is the contract, the decoder is the arithmetic.
        if not _ed25519_wire_ok(public, signature):
            return False
        try:
            R = _decodepoint(signature[:32])
            A = _decodepoint(public)
        except ValueError:
            return False
        S = int.from_bytes(signature[32:64], "little")
        # RFC 8032 5.1.7 step 1: S must be the CANONICAL scalar, 0 <= S < l. Without it
        # S + l is a second valid signature over the same message under the same key --
        # malleability, i.e. one authenticated fact with two spellings again. OpenSSL
        # (node, `cryptography`) and libsodium both enforce it; this line is what keeps
        # the pure backend from being the one that does not.
        if S >= _l:
            return False
        # `mod l` -- RFC 8032 5.1.7 step 2 says h = SHA-512(R || A || M) mod L, and the
        # 512-bit value _hint returns is NOT that. For an A of prime order the two agree
        # ([h]A == [h mod l]A), which is why this hid; for any A outside the prime-order
        # subgroup they do not, and the pure backend and the library backend then reached
        # OPPOSITE verdicts on the same 64 bytes -- a split inside one language, decided
        # by an environment variable. Measured: an order-8 key with S = 0 was accepted by
        # `cryptography` and refused here. The gate above now refuses that key outright,
        # but the reduction is what makes the two backends compute the same thing for
        # every key they both still accept (a torsion-carrying A among them).
        h = _hint(signature[:32] + public + message) % _l
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
    note). P-256 keys go through did_from_p256().

    DELIBERATELY NOT refused here: a small-order or non-canonically-encoded key (see
    _ED25519_SMALL_ORDER). This function is a byte transform, not a verifier -- multicodec
    prefix, base58btc -- and vectors/wire_vectors.json PINS its output for exactly two such
    keys (`did[0]` is the all-zero point, order 4; `did[1]` is all-0xff, y > p) which the
    JavaScript, Go and Rust implementations each re-derive. Refusing them here would make
    Python the one implementation that cannot reproduce the published vectors: a split, to
    fix a split. The refusal belongs where the key is USED to authenticate something, and
    that is `_ed25519_wire_ok`, which every verification path opens with -- so a DID minted
    from one of these keys is still a DID whose signatures nothing will ever accept. An
    honest key cannot land here anyway: `ed25519_public_from_seed` clamps its scalar, so
    what it returns is always in the prime-order subgroup.

    Go and Rust put their refusal in a second ingress beside the codec
    (`VerifyingKeyFromDID` / `verifying_key_from_did`). Python puts it one level LOWER, in
    `ed25519_verify`, because a DID is not the only way a key reaches a verifier here: the
    slice also verifies against RAW key bytes that never had a DID -- `keystate.rootKey`
    hex and a Web Bot Auth JWK `x`, both of which arrive through `verify_raw`. A
    `verifying_key_from_did` would have left those two doors open. Nothing above
    `ed25519_verify` has to remember the rule, and no public signature changed."""
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


#: The standard base64 alphabet -- no base64url ("-", "_"), no whitespace, no line breaks.
_B64_STD_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def b64_strict(value: Any) -> bytes | None:
    """THE base64 reader for anything signed. Decodes ONE spelling of standard, padded
    base64 -- or None. Never raises.

    Public, and the one place this rule is written down for the whole slice. It was five
    places for a while (a private copy each in keystate, keybinding, cardpub and
    ownerstate beside this one), which is exactly the drift the note on the JavaScript
    twin's `WBA_B64_STANDARD` warns about: two copies of a wire rule are two rules as soon
    as one of them is edited. Read a signature or a key off the wire through here.

    Its base64url sibling -- unpadded, "-"/"_", the JWK `x` and JWS segment alphabet --
    lives in `jws.unb64url` and is a DIFFERENT rule on purpose. The two must move
    together: a change to what counts as one spelling here is a change there.

    `base64.b64decode(s, validate=True)` is not a strict enough wire reader: `validate`
    only rejects characters outside the alphabet, and still tolerates a length that is not
    a multiple of 4 and padding that a strict reader must refuse. So the same 64 signature
    bytes arrived under several different `sig` strings, and a signature with several
    spellings is one that a replay cache keyed on the STRING cannot de-duplicate, and one
    two implementations can disagree about. This is the same rule the point encodings are
    held to above: one fact, one spelling.

    The rule is the JavaScript twin's `strictB64`, character for character:
    `^[A-Za-z0-9+/]*={0,2}$`, `length % 4 == 0`, and a re-encode that must reproduce the
    input exactly. Written without `re` because the slice adds no import it does not
    already carry, and because the check is four lines either way.

    The re-encode is the leg that is easy to miss and matters most HERE. 64 bytes is not a
    multiple of 3, so the final base64 character of a signature carries four bits that
    belong to no byte, and every decoder -- Python's and node's alike -- silently discards
    them. That is SIXTEEN strings per signature, fifteen of which are respellings a replay
    cache keyed on `sig` reads as new. `base64.b64encode` emits the one canonical form
    (standard alphabet, padded), so comparing against it is the whole rule.
    """
    if not isinstance(value, str) or len(value) % 4 != 0:
        return None
    body = value
    for _ in range(2):                 # at most two "=", and only at the very end
        if body.endswith("="):
            body = body[:-1]
    # "=" is not in the alphabet, so a third pad character, or padding in the middle
    # ("AA=A"), fails right here -- which is exactly what the twin's regex refuses.
    if any(ch not in _B64_STD_ALPHABET for ch in body):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return None
    if base64.b64encode(raw).decode("ascii") != value:
        return None                    # the discarded trailing bits were not zero
    return raw


#: Pre-publication name, kept so a vendored copy mid-upgrade still imports.
_b64_strict = b64_strict


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

    The signature is read strictly: `b64_strict` (one spelling only) and then
    EXACTLY 64 decoded bytes, which is the JavaScript twin's rule
    (`verifyEnvelopeSignature`: `sig.length !== 64 -> false`). Python accepting
    an envelope JavaScript refuses is the split this pinning exists to close,
    so the length is not negotiable here.

    What that costs, stated plainly because it used to say the opposite: a
    P-256 op-key signing an ENVELOPE must present the 64-byte raw r||s form
    (WebCrypto). ASN.1 DER (Secure Enclave / WebAuthn, ~70-72 bytes) is
    refused by this function — not by the curve dispatch. Verification still
    goes through `verify`, so a P-256 signer is a policy decision rather than
    an Ed25519-only decode failure, and `p256_verify`/`_coerce_ecdsa_der`
    still accept DER everywhere that is not the six-field envelope (binding
    proofs, card envelopes, `extra_sigs_ok`)."""
    signer = signer_did or from_did
    # Alphabet, padding and length are checked BEFORE the decode and BEFORE any curve
    # dispatch, so one signature has one spelling on this wire, in this language, matching
    # the JavaScript twin byte for byte. `sig_b64` is whatever a stranger put in the field
    # -- None (the pinned `missing-sig` reject vector), a number, a base64url string -- and
    # all of them answer False here rather than raising.
    #
    # The 64-byte length is the twin's rule too (`verifyEnvelopeSignature`: sig.length !==
    # 64 -> false). NOTE the one narrowing it brings on this side: a P-256 op-key signing
    # an envelope must now present the 64-byte raw r||s form (WebCrypto), not ASN.1 DER
    # (Secure Enclave / WebAuthn, ~70-72 bytes). `_coerce_ecdsa_der` still accepts both, so
    # the curve dispatch is untouched; it is only the envelope that is pinned to 64.
    sig = b64_strict(sig_b64)
    if sig is None or len(sig) != 64:
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
        # Same one-spelling rule as `sig` itself -- an additive signature is still a
        # signature, and a sloppy reader here would hand back the alternative spellings the
        # strict reader above just took away. No length gate: `alg` may name p256-pub,
        # whose DER encoding is not 64 bytes, and the ed25519 length check already lives in
        # `_ed25519_wire_ok` where every backend inherits it.
        sig = b64_strict(sig_b64)
        if sig is None:
            return False
        if not verify(signer, sig, payload):
            return False
    return True
