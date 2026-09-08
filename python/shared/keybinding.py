"""
shared/keybinding.py
Device-key hierarchy (the "light user" identity model). A signed statement in
which a ROOT identity authorizes a DEVICE key to act on its behalf.

Why this exists (design):
  An iPhone/native light user's durable identity is best anchored in a
  hardware-backed, non-extractable key — but Secure Enclave / passkey / WebAuthn
  keys are P-256 (ES256), and this network's day-to-day signing (messages, name
  registration, ygg bindings) is Ed25519. The reconciliation, already foreshadowed
  by shared/ygg.py and MASTER_PLAN §4, is a hierarchy:

    root key (P-256 hardware, OR Ed25519) -- "who you are", rarely used
        │  signs a DeviceKeyBinding
        ▼
    device key (software Ed25519)         -- "this device", does all signing

  The device key's Ed25519 DID is what appears on the wire, so every existing
  verifier is unchanged and fully compatible. Only a party that wants to confirm
  "this device key is backed by that root" verifies the binding here — and because
  it goes through crypto.verify(), the ROOT may be Ed25519 OR P-256 transparently.
  Theft of a device key is recoverable: the root re-authorizes a fresh device key
  (and the WoT re-vouches), the social-recovery property that sets this apart from
  blockchain assets.

This module is pure standard library (+ shared/crypto). P-256 roots additionally
need the optional `cryptography` backend (crypto.P256_AVAILABLE); an Ed25519 root
works in the zero-dependency core. Mirrors shared/ygg.make_ygg_binding exactly.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

from typing import Callable

from shared import crypto


# ------------------------------------------------------------------ reading a signature
# The base64 SPELLING rule -- one signature, one string, trailing bits and all -- lives in
# ONE place for the whole slice: `crypto.b64_strict`. It was briefly written out here as
# well, and in three sibling modules beside it, which is exactly the drift the JavaScript
# twin's note on `WBA_B64_STANDARD` warns about ("two copies of it drift"). Read a signature
# off the wire through that function; change the rule there and every module moves at once.
#
# What stays HERE is the half a shared decoder cannot know: how LONG a signature may be.
# That depends on the curve of the key this particular site is holding, so it belongs beside
# the site, not in the decoder.

#: The longest ASN.1 DER an ECDSA-P-256 signature can be: a SEQUENCE whose two INTEGERs each
#: carry at most 33 content bytes (32, plus the 0x00 a high bit forces) behind a 2-byte
#: tag+length, inside a 2-byte SEQUENCE header. A CEILING, not an equality -- r and s shrink
#: when they have leading zero bytes -- and the reason the OWNER's signature is bounded by
#: the curve its did:key names instead of at a flat 64: a Secure-Enclave / WebAuthn root
#: emits DER, not raw r||s. Only the DEVICE half, which is Ed25519 by construction, is 64.
_MAX_P256_DER_SIG_BYTES = 72


def _binding_payload(root_did: str, device_did: str, ts: float) -> bytes:
    """Canonical bytes the ROOT key signs. Reuses the L2 canonical JSON encoder so
    the binding shares the project's one canonicalization (like ygg bindings)."""
    return crypto.canonical({
        "rootDid": root_did, "deviceDid": device_did, "ts": ts,
    })


def make_device_binding(root_did: str, device_did: str, ts: float,
                        root_sign: Callable[[bytes], str]) -> dict:
    """Build a signed statement that ROOT authorizes DEVICE.

    `root_sign` is the root key's signer (taking raw bytes -> base64 signature):
    e.g. Identity.sign_bytes for an Ed25519 root, or a Secure Enclave / WebAuthn
    callback that produces an ES256 signature for a P-256 root. The root private
    key never passes through this module."""
    sig = root_sign(_binding_payload(root_did, device_did, ts))
    return {"rootDid": root_did, "deviceDid": device_did, "ts": ts, "sig": sig}


def verify_device_binding(binding: dict) -> bool:
    """Verify a device binding (safe on untrusted input, never raises): the key
    behind rootDid signed exactly (rootDid, deviceDid, ts). Curve-agnostic — an
    Ed25519 or a P-256 root both verify via crypto.verify(). Returns False if a
    P-256 root is used but the optional `cryptography` backend is absent."""
    try:
        root_did = binding["rootDid"]
        device_did = binding["deviceDid"]
        ts = binding["ts"]
        sig = crypto.b64_strict(binding.get("sig"))
        if sig is None:
            return False
        # No LENGTH bound on this one, deliberately: the root here is Ed25519 OR P-256, and a
        # P-256 root is the whole reason v1 exists (a Secure Enclave / WebAuthn key signs
        # ASN.1 DER, ~70-72 bytes, which `crypto.p256_verify` accepts alongside raw r||s --
        # test_keybinding 2-2 pins both). A flat 64 would refuse exactly the roots this
        # module was built for. The spelling is what was ambiguous; the length was not.
        # Payload build inside the try: canonical JSON raises on `ts: 1e400`, and a
        # verifier that never raises must not raise on a VALUE either.
        return crypto.verify(root_did, sig, _binding_payload(root_did, device_did, ts))
    except Exception:
        return False


# ---------------------------------------------------------------- v2 (T102)
# The ACCOUNT-layer binding: v1 above stays verifiable for existing artifacts but
# never grants account attribution — a v1 binding carries only the ROOT's word,
# so a foreign owner could claim someone else's device by re-signing its DID.
# v2 closes that with a COUNTERSIGNATURE (the device signs the same bytes), puts
# `typ` INSIDE the signed payload (domain separation + the signer-server denylist
# match), and pins `ts`/`validUntil` to INTEGERS — Python's float repr is not
# reproducible cross-language, so a float here would be bytes only Python can
# verify. validUntil is the only
# revocation a stateless verifier (an agent entry with no network) can honor; 0 means
# no expiry.

#: `typ` of the countersigned account binding — inside the signed bytes, and on
#: the signer-server key-authority denylist (agent/signer_server.py).
BINDING_V2_TYP = "muretai/devicebinding/2"


def _require_int(value, field: str) -> int:
    """The integer-timestamp rule, ENFORCED at mint time: bool is an int subtype
    in Python and would canonicalize as true/false, and a float's repr is not
    reproducible outside Python — either one signed here is an artifact no other
    language can verify. Raise, don't coerce: a coercion would silently change
    the signed bytes out from under the caller."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer (got {type(value).__name__}); "
                         f"float/bool timestamps are not reproducible on the wire")
    return value


def _binding_v2_payload(root_did: str, device_did: str, ts: int,
                        valid_until: int) -> bytes:
    """Canonical bytes BOTH keys sign — exactly the five declared fields, so the
    two signatures cover the same statement and neither party can be replayed
    into a different one."""
    return crypto.canonical({
        "typ": BINDING_V2_TYP, "rootDid": root_did, "deviceDid": device_did,
        "ts": ts, "validUntil": valid_until,
    })


def make_device_binding_v2(root_did: str, device_did: str, *, ts: int,
                           valid_until: int = 0,
                           root_sign: Callable[[bytes], str]) -> dict:
    """Owner half of a v2 binding: the OWNER (root) key signs
    (typ, rootDid, deviceDid, ts, validUntil). The result is not yet a valid v2
    binding — it still needs the device's countersignature
    (countersign_device_binding), which is what stops a foreign owner from
    claiming a device that never consented. `valid_until` 0 = no expiry."""
    ts = _require_int(ts, "ts")
    valid_until = _require_int(valid_until, "validUntil")
    sig = root_sign(_binding_v2_payload(root_did, device_did, ts, valid_until))
    return {"typ": BINDING_V2_TYP, "rootDid": root_did, "deviceDid": device_did,
            "ts": ts, "validUntil": valid_until, "sig": sig}


def countersign_device_binding(binding: dict, *,
                               device_sign: Callable[[bytes], str]) -> dict:
    """Device half: the DEVICE key countersigns the same canonical bytes the
    owner signed, completing the v2 binding. Returns a NEW dict (the input is
    not mutated). The payload is rebuilt from the binding's own fields, so a
    device cannot be tricked into countersigning bytes that differ from what it
    can read in the dict."""
    ts = _require_int(binding["ts"], "ts")
    valid_until = _require_int(binding.get("validUntil", 0), "validUntil")
    payload = _binding_v2_payload(binding["rootDid"], binding["deviceDid"],
                                  ts, valid_until)
    return {**binding, "deviceSig": device_sign(payload)}


def verify_device_binding_v2(binding: dict, *, now: float | None = None,
                             expected_device_did: str | None = None) -> bool:
    """Verify a v2 binding. TOTAL on untrusted input: returns False, never
    raises — this is called on attacker-supplied wire metadata.

    All of these must hold:
      - typ == muretai/devicebinding/2 (domain separation);
      - ts and validUntil are INTEGERS (bool is an int subtype and is rejected
        too; a float is bytes only Python could have signed);
      - `now` given and validUntil non-zero -> not expired;
      - `expected_device_did` given -> binding.deviceDid matches it (the
        anti-copy pin: a binding lifted onto another sender's message fails);
      - the OWNER key (rootDid) signed the canonical five fields — curve-
        agnostic via crypto.verify, so the owner may be Ed25519 or P-256
        (P-256 returns False without the optional `cryptography` backend);
      - the DEVICE key (deviceDid) countersigned the same bytes.
    """
    try:
        if binding.get("typ") != BINDING_V2_TYP:
            return False
        root_did = binding["rootDid"]
        device_did = binding["deviceDid"]
        ts = binding["ts"]
        valid_until = binding["validUntil"]
        if isinstance(ts, bool) or not isinstance(ts, int):
            return False
        if isinstance(valid_until, bool) or not isinstance(valid_until, int):
            return False
        if expected_device_did is not None and device_did != expected_device_did:
            return False
        if now is not None and valid_until != 0 and now > valid_until:
            return False
        sig = crypto.b64_strict(binding.get("sig"))
        device_sig = crypto.b64_strict(binding.get("deviceSig"))
        if sig is None or device_sig is None:
            return False
        # These two are the last attacker-controlled byte strings in this function, and the
        # twin bounds both (js/seam.mjs `verifyDeviceBindingV2`), so this side must too or a
        # binding JavaScript refuses is one Python accepts.
        #
        # The DEVICE is always Ed25519 -- that is the hierarchy this module documents at the
        # top ("device key (software Ed25519)"), and its Ed25519 DID is what appears on the
        # wire -- so its countersignature is exactly 64 bytes and anything else is not a
        # countersignature. Note what this narrows: a P-256 device presenting a DER
        # countersignature verified here until now (`crypto.verify` dispatches on the DID's
        # curve) and is refused by the twin, so it is refused here as well.
        #
        # The OWNER is the one signature in this file that is NOT always 64: an owner may be
        # a Secure-Enclave / WebAuthn P-256 key emitting DER. The bound is therefore read
        # from the owner's own did:key -- junk there raises out of `key_from_did` into the
        # enclosing `except`, which is the same False it has always answered.
        if len(device_sig) != 64:
            return False
        owner_curve, _owner_pub = crypto.key_from_did(root_did)
        if owner_curve == "ed25519":
            if len(sig) != 64:
                return False
        elif len(sig) > _MAX_P256_DER_SIG_BYTES:
            return False
        payload = _binding_v2_payload(root_did, device_did, ts, valid_until)
        return (crypto.verify(root_did, sig, payload)
                and crypto.verify(device_did, device_sig, payload))
    except Exception:
        return False
