"""
test_keybinding.py — device-key hierarchy (shared/keybinding.py + the P-256
support in shared/crypto.py)

The headline case: an iPhone light user whose ROOT identity is a Secure Enclave /
passkey P-256 key authorizes a software Ed25519 DEVICE key, which is what appears
on the wire (so the rest of the network is unchanged and fully compatible).

  Part 1: Ed25519 root authorizes Ed25519 device (+ tamper/forgery rejection)
  Part 2: P-256 (Secure Enclave-style) root authorizes Ed25519 device
          — both signature encodings (DER and raw r||s); did:key round-trip;
            tamper / foreign-root rejection
  Part 3: crypto.verify() curve dispatch + public_from_did back-compat
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM (the `agent-seam` repository, MIT): this suite travels with the bytes it
# checks, so it carries their licence. Its home is agent-seam; Muretai core vendors it verbatim
# at a pinned commit (shared/VENDOR.json there) and is AGPL-3.0-or-later around it.
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared import crypto, keybinding

print(f"signing backend: {crypto.BACKEND}  P256_AVAILABLE={crypto.P256_AVAILABLE}")

TS = 1750000000.0


def ed_signer(seed):
    return lambda msg: base64.b64encode(crypto.ed25519_sign(seed, msg)).decode("ascii")


# The device key is always a software Ed25519 key (the wire identity).
dev_seed = crypto.new_seed()
dev_did = crypto.did_from_public(crypto.ed25519_public_from_seed(dev_seed))

# ================================================== Part 1: Ed25519 root

print("\n=== 1-1: Ed25519 root authorizes Ed25519 device ===")
root_seed = crypto.new_seed()
root_did = crypto.did_from_public(crypto.ed25519_public_from_seed(root_seed))
b = keybinding.make_device_binding(root_did, dev_did, TS, ed_signer(root_seed))
assert keybinding.verify_device_binding(b)
print(f"OK: {root_did[:20]}… authorizes {dev_did[:20]}…")

print("\n=== 1-2: tamper / forgery rejected ===")
other = crypto.did_from_public(crypto.ed25519_public_from_seed(crypto.new_seed()))
for field, val in [("deviceDid", other), ("rootDid", other), ("ts", 1.0)]:
    bb = dict(b)
    bb[field] = val
    assert not keybinding.verify_device_binding(bb), field
bb = dict(b)
bb["sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")
assert not keybinding.verify_device_binding(bb)
bb["sig"] = "not-base64!!!"
assert not keybinding.verify_device_binding(bb)
# Foreign root: someone else signs but claims root_did.
forged = keybinding.make_device_binding(root_did, dev_did, TS, ed_signer(crypto.new_seed()))
assert not keybinding.verify_device_binding(forged)
print("OK: field tamper, bad signature, and foreign-root all rejected")

print("\n=== 1-3: a binding that is a dict with UNSIGNABLE values is False, never a raise ===")
# Found by audit: the verifiers rebuilt the payload OUTSIDE their try, so a legal JSON
# `"ts": 1e400` (inf, which canonical JSON refuses) and a `rootDid` that is not a string
# (`key_from_did(123).startswith`) raised out of "safe on untrusted input, never raises".
import json                                                       # noqa: E402
v2_ok = keybinding.countersign_device_binding(
    keybinding.make_device_binding_v2(root_did, dev_did, ts=int(TS), valid_until=int(TS) + 3600,
                                      root_sign=ed_signer(root_seed)),
    device_sign=ed_signer(dev_seed))
assert keybinding.verify_device_binding_v2(v2_ok), "the well-formed v2 binding verifies"
for field, raw in [("ts", "1e400"), ("ts", "-1e400"), ("rootDid", "123"), ("rootDid", "null"),
                   ("rootDid", "[1]"), ("deviceDid", "{}"), ("sig", "5")]:
    bb = dict(b); bb[field] = json.loads(raw)
    try:
        assert keybinding.verify_device_binding(bb) is False, (field, raw)
    except AssertionError:
        raise
    except Exception as e:                                        # noqa: BLE001
        raise AssertionError(f"verify_device_binding raised on {field}={raw}: {e!r}")
    if v2_ok is not None:
        b2 = dict(v2_ok); b2[field] = json.loads(raw)
        try:
            assert keybinding.verify_device_binding_v2(b2) is False, (field, raw)
        except AssertionError:
            raise
        except Exception as e:                                    # noqa: BLE001
            raise AssertionError(f"verify_device_binding_v2 raised on {field}={raw}: {e!r}")
print("OK: inf timestamps and non-string DIDs are refused without a traceback")

# ================================================== Part 2: P-256 root

if crypto.P256_AVAILABLE:
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives import hashes, serialization

    print("\n=== 2-1: P-256 (Secure Enclave-style) root -> Ed25519 device ===")
    sk = ec.generate_private_key(ec.SECP256R1())
    comp = sk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    p_did = crypto.did_from_p256(comp)
    curve, pub = crypto.key_from_did(p_did)
    assert curve == "p256" and pub == comp                 # did:key round-trip
    print(f"OK: P-256 did:key {p_did[:20]}… round-trips (compressed point)")

    def der_signer(msg):                                   # Secure Enclave / WebAuthn
        return base64.b64encode(sk.sign(msg, ec.ECDSA(hashes.SHA256()))).decode("ascii")

    def raw_signer(msg):                                   # WebCrypto (raw r||s)
        der = sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode("ascii")

    print("\n=== 2-2: both signature encodings verify ===")
    for label, signer in [("DER", der_signer), ("raw r||s", raw_signer)]:
        bp = keybinding.make_device_binding(p_did, dev_did, TS, signer)
        assert keybinding.verify_device_binding(bp), label
    print("OK: P-256 root authorizes the Ed25519 device key (DER + raw r||s)")

    print("\n=== 2-3: P-256 tamper / foreign-root rejected ===")
    bp = keybinding.make_device_binding(p_did, dev_did, TS, der_signer)
    t = dict(bp)
    t["deviceDid"] = other
    assert not keybinding.verify_device_binding(t)
    sk2 = ec.generate_private_key(ec.SECP256R1())

    def der_signer2(msg):
        return base64.b64encode(sk2.sign(msg, ec.ECDSA(hashes.SHA256()))).decode("ascii")

    foreign = keybinding.make_device_binding(p_did, dev_did, TS, der_signer2)  # signed by sk2, claims p_did
    assert not keybinding.verify_device_binding(foreign)
    print("OK: P-256 device tamper and foreign-root rejected")
else:
    print("\n=== Part 2 SKIPPED: P-256 needs the optional `cryptography` backend ===")

# ================================================== Part 3: dispatch + back-compat

print("\n=== 3-1: crypto.verify() dispatch + public_from_did back-compat ===")
msg = b"a signed message"
sig = crypto.ed25519_sign(dev_seed, msg)
assert crypto.verify(dev_did, sig, msg)                    # ed25519 via generic verify
assert not crypto.verify(dev_did, sig, b"tampered")
assert not crypto.verify("did:key:zNotADid", sig, msg)     # malformed -> False, no raise
# ...and "never raises" holds for a DID that is not a string, or a signature that is not
# bytes: every binding verifier funnels a stranger's card through here.
for bad_did in (None, 123, [dev_did], {"did": dev_did}, b"did:key:z"):
    assert crypto.verify(bad_did, sig, msg) is False, repr(bad_did)
assert crypto.verify(dev_did, "not-bytes", msg) is False
assert crypto.verify(dev_did, sig, None) is False
if crypto.P256_AVAILABLE:
    try:
        crypto.public_from_did(p_did)                      # still Ed25519-only
        assert False, "public_from_did accepted a P-256 did:key"
    except ValueError:
        pass
print("OK: ed25519 verifies via dispatch; public_from_did stays Ed25519-only")

print("\nALL KEYBINDING TESTS PASSED")
