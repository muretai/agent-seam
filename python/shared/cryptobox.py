"""
shared/cryptobox.py
End-to-end encryption box for agent-to-agent messages.

Why this exists:
  L1/L2 sign every message so the recipient knows *who* sent it and that it was
  not tampered with — but the plaintext still travels in the clear (and through
  any relay/tunnel in between). For private payloads (e.g. booking details,
  contact info) we want confidentiality on top of authenticity. This module
  provides a small sealed-box primitive built on the same Ed25519 seed an agent
  already holds, so no new key material has to be provisioned or exchanged.

Design (why these choices):
  - X25519 keys are derived *deterministically* from the existing 32-byte
    Ed25519 seed (sha256-domain-separated), so an agent's encryption public key
    is a pure function of its identity seed — no extra key to store or publish
    beyond a 64-hex string anyone can recompute from the seed they own.
  - v1 is a STATIC-STATIC box: X25519 ECDH is symmetric, so the same shared
    secret is reached from either side. `seal(A_seed, B_pub, pt)` is therefore
    opened by `open_box(B_seed, A_pub, blob)`. No ephemeral key / handshake is
    needed, which keeps it a one-shot, stateless call that composes with the
    existing fire-and-forget message flow.
  - v2 (T142 B1) is hybrid: the AEAD key is HKDF(x25519_ss || mlkem_ss) with
    info `agentnet-box-v2`. The sender encapsulates to the recipient's ML-KEM-768
    public key; the 1088-byte ciphertext rides in the blob. Old peers keep
    opening v1. `open_box` tries v2 when the blob carries the v2 magic, else v1.
  - HKDF-SHA256 turns the raw ECDH (and, in v2, KEM) output into a uniform
    32-byte key; the domain-separation info string versions the scheme.
  - ChaCha20-Poly1305 (AEAD) gives confidentiality + integrity in one step and
    binds optional associated data (`ad`), letting a caller cryptographically
    pin a context (e.g. a contextId) to the ciphertext.

  Requires the `cryptography` package (always available in this deployment);
  unlike shared/crypto.py there is no pure-Python fallback here.
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
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: v2 blob prefix. A v1 blob is base64(12-byte random nonce || ct); four ASCII
#: bytes colliding with a uniform nonce is 2^-32 per blob, and a mismatch fails
#: closed (open returns None) rather than silently decrypting as v1.
V2_MAGIC = b"a2b2"
_MLKEM_PUB_BYTES = 1184
_MLKEM_CT_BYTES = 1088


def _priv_from_seed(seed: bytes) -> X25519PrivateKey:
    """Deterministically derive an X25519 private key from an Ed25519 seed.

    Domain-separated sha256 keeps the encryption key independent from the
    signing key while still being a pure function of the one seed an agent
    already controls.
    """
    priv_bytes = hashlib.sha256(b"agentnet-x25519:" + seed).digest()
    return X25519PrivateKey.from_private_bytes(priv_bytes)


def _shared(my_seed: bytes, their_pub_hex: str) -> bytes:
    """Derive the 32-byte symmetric key shared with `their_pub_hex`.

    Raw X25519 ECDH output is run through HKDF-SHA256 so the result is a
    uniformly random key suitable for ChaCha20-Poly1305.
    """
    priv = _priv_from_seed(my_seed)
    their_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(their_pub_hex))
    shared = priv.exchange(their_pub)
    return _hkdf(b"agentnet-box-v1", shared)


def _hkdf(info: bytes, ikm: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(ikm)


def _mlkem_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import (  # noqa: F401
            MLKEM768PrivateKey)
        return True
    except Exception:
        return False


def _mlkem_seed(ed_seed: bytes) -> bytes:
    """64-byte FIPS-203 seed, domain-separated from the Ed25519 / X25519 derivations."""
    return (hashlib.sha256(b"agentnet-mlkem-768-a:" + ed_seed).digest()
            + hashlib.sha256(b"agentnet-mlkem-768-b:" + ed_seed).digest())


def _mlkem_priv(ed_seed: bytes):
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    return MLKEM768PrivateKey.from_seed_bytes(_mlkem_seed(ed_seed))


def enc_pub_pq_hex(seed: bytes) -> str:
    """ML-KEM-768 public key (2368 hex chars) derived from `seed`, or '' if unavailable.

    Safe to publish. Empty when the optional `cryptography` ML-KEM backend is
    missing (principle 1: E2E stays opt-in)."""
    try:
        return _mlkem_priv(seed).public_key().public_bytes_raw().hex()
    except Exception:
        return ""


def enc_pub_hex(seed: bytes) -> str:
    """Return the hex (64 chars) X25519 public key derived from `seed`.

    This is the value a peer needs in order to seal a box to this agent; it is
    recomputable by anyone holding the seed and safe to publish.
    """
    priv = _priv_from_seed(seed)
    return priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()


def _seal_v1(my_seed: bytes, their_pub_hex: str,
             plaintext: bytes, ad: bytes) -> str:
    key = _shared(my_seed, their_pub_hex)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)
    return base64.b64encode(nonce + ct).decode("ascii")


def _seal_v2(my_seed: bytes, their_pub_hex: str, their_pq_pub_hex: str,
             plaintext: bytes, ad: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
    their_pq = bytes.fromhex(their_pq_pub_hex)
    if len(their_pq) != _MLKEM_PUB_BYTES:
        raise ValueError("ML-KEM-768 public key must be 1184 bytes")
    pub = MLKEM768PublicKey.from_public_bytes(their_pq)
    mlkem_ss, kem_ct = pub.encapsulate()
    if len(kem_ct) != _MLKEM_CT_BYTES:
        raise ValueError("unexpected ML-KEM ciphertext length")
    x_ss = _priv_from_seed(my_seed).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(their_pub_hex)))
    key = _hkdf(b"agentnet-box-v2", x_ss + mlkem_ss)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)
    return base64.b64encode(V2_MAGIC + kem_ct + nonce + ct).decode("ascii")


def seal(my_seed: bytes, their_pub_hex: str,
         plaintext: bytes, ad: bytes = b"",
         their_pq_pub: str = "") -> str:
    """Encrypt `plaintext` to the holder of `their_pub_hex`.

    When `their_pq_pub` is a 2368-hex ML-KEM-768 public key and the ML-KEM
    backend is present, this is a v2 hybrid box. Otherwise it is v1
    (base64(nonce || ciphertext)), byte-compatible with every existing peer.
    `ad` is authenticated but not encrypted (e.g. bind a contextId).
    """
    if (their_pq_pub and len(their_pq_pub) == _MLKEM_PUB_BYTES * 2
            and _mlkem_available()):
        try:
            return _seal_v2(my_seed, their_pub_hex, their_pq_pub, plaintext, ad)
        except Exception:
            # A malformed advertised PQ key must not brick send: fall back to v1.
            pass
    return _seal_v1(my_seed, their_pub_hex, plaintext, ad)


def _open_v1(my_seed: bytes, their_pub_hex: str, raw: bytes, ad: bytes) -> bytes:
    if len(raw) < 12:
        raise ValueError("truncated v1 box")
    nonce, ct = raw[:12], raw[12:]
    key = _shared(my_seed, their_pub_hex)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, ad)


def _open_v2(my_seed: bytes, their_pub_hex: str, raw: bytes, ad: bytes) -> bytes:
    body = raw[len(V2_MAGIC):]
    if len(body) < _MLKEM_CT_BYTES + 12:
        raise ValueError("truncated v2 box")
    kem_ct = body[:_MLKEM_CT_BYTES]
    nonce = body[_MLKEM_CT_BYTES:_MLKEM_CT_BYTES + 12]
    ct = body[_MLKEM_CT_BYTES + 12:]
    mlkem_ss = _mlkem_priv(my_seed).decapsulate(kem_ct)
    x_ss = _priv_from_seed(my_seed).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(their_pub_hex)))
    key = _hkdf(b"agentnet-box-v2", x_ss + mlkem_ss)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, ad)


def open_failure_reason(blob_b64: str) -> str:
    """Why `open_box` returned None, as far as this process can tell.

    `open_box` collapses every cause into None so the caller's branch stays simple,
    and that is right — but an operator cannot act on None. One cause is not a
    mistake and never resolves by retrying: a v2 hybrid blob on a build with no
    ML-KEM backend can NEVER be opened here, no matter how correct the keys are.
    That is a different sentence from "wrong recipient", and it is the sentence an operator
    is owed: a bounce that blames the relay, which never opened the box, while nothing
    anywhere names the real reason, is how a build-capability mismatch goes undiagnosed.
    Everything else stays honestly vague — this function reports what it can prove,
    not a guess."""
    from shared import peercompat
    try:
        raw = base64.b64decode(blob_b64)
    except Exception:
        return peercompat.OPEN_FAIL_UNKNOWN
    if raw.startswith(V2_MAGIC) and not _mlkem_available():
        return peercompat.OPEN_FAIL_NO_PQ_BACKEND
    return peercompat.OPEN_FAIL_UNKNOWN


def open_box(my_seed: bytes, their_pub_hex: str,
             blob_b64: str, ad: bytes = b"") -> bytes | None:
    """Decrypt a box produced by `seal` from the matching peer.

    Returns the plaintext, or None on ANY failure (malformed base64, truncated
    blob, wrong key/recipient, AD mismatch, or auth-tag failure). Returning None
    rather than raising keeps the caller's verification path branch-simple.
    A v2 blob is opened as v2 only; a v1 blob as v1 — no silent cross-version.
    """
    try:
        raw = base64.b64decode(blob_b64)
        if raw.startswith(V2_MAGIC):
            return _open_v2(my_seed, their_pub_hex, raw, ad)
        return _open_v1(my_seed, their_pub_hex, raw, ad)
    except Exception:
        # Any error (InvalidTag, bad hex, bad base64, short blob) => no plaintext.
        return None
