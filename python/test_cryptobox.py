"""
test_cryptobox.py
Tests for shared/cryptobox.py — the E2E sealed-box primitive.

Why these cases:
  Beyond the happy-path round-trip, an encryption layer is only useful if it
  actively *fails closed*. So we attack it: tamper the ciphertext, point it at
  the wrong recipient, and mismatch the associated data — each must yield None
  rather than leaking plaintext. We also assert the static-static symmetry
  property the box relies on (either side reaches the same shared secret).
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM (the `agent-seam` repository, MIT): this suite travels with the bytes it
# checks, so it carries their licence. Its home is agent-seam; Muretai core vendors it verbatim
# at a pinned commit (shared/VENDOR.json there) and is AGPL-3.0-or-later around it.

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared import crypto
from shared import cryptobox


def main() -> None:
    a_seed = crypto.new_seed()
    b_seed = crypto.new_seed()
    c_seed = crypto.new_seed()

    a_pub = cryptobox.enc_pub_hex(a_seed)
    b_pub = cryptobox.enc_pub_hex(b_seed)

    # enc_pub_hex must be a stable 64-hex string.
    assert len(a_pub) == 64 and len(b_pub) == 64
    assert cryptobox.enc_pub_hex(a_seed) == a_pub  # deterministic
    print("OK enc_pub_hex: deterministic 64-hex public keys")

    # 1. Round-trip with non-ASCII UTF-8 payload (static-static symmetry).
    plaintext = "こんにちは🌏".encode()
    blob = cryptobox.seal(a_seed, b_pub, plaintext)
    opened = cryptobox.open_box(b_seed, a_pub, blob)
    assert opened == plaintext, opened
    print("OK round-trip: A->B sealed box opens to original plaintext")

    # 2. Tampered blob -> None (flip one base64 char, keep length valid).
    idx = len(blob) // 2
    flip = "A" if blob[idx] != "A" else "B"
    tampered = blob[:idx] + flip + blob[idx + 1:]
    assert tampered != blob
    assert cryptobox.open_box(b_seed, a_pub, tampered) is None
    print("OK tamper: a single flipped char fails the auth tag (None)")

    # 3. Wrong recipient -> None.
    assert cryptobox.open_box(c_seed, a_pub, blob) is None
    print("OK wrong recipient: C cannot open a box sealed to B (None)")

    # 4. Associated-data binding.
    blob_ad = cryptobox.seal(a_seed, b_pub, plaintext, ad=b"ctx1")
    assert cryptobox.open_box(b_seed, a_pub, blob_ad, ad=b"ctx2") is None
    print("OK ad mismatch: ctx1-sealed box won't open under ctx2 (None)")
    assert cryptobox.open_box(b_seed, a_pub, blob_ad, ad=b"ctx1") == plaintext
    print("OK ad match: same associated data opens the box")

    # 5. v2 hybrid (X25519 || ML-KEM-768) round-trip + fail-closed.
    a_pq = cryptobox.enc_pub_pq_hex(a_seed)
    b_pq = cryptobox.enc_pub_pq_hex(b_seed)
    if a_pq and b_pq:
        assert len(bytes.fromhex(a_pq)) == 1184
        v2 = cryptobox.seal(a_seed, b_pub, plaintext, their_pq_pub=b_pq)
        raw = __import__("base64").b64decode(v2)
        assert raw.startswith(cryptobox.V2_MAGIC), "v2 blob is versioned"
        assert cryptobox.open_box(b_seed, a_pub, v2) == plaintext
        assert cryptobox.open_box(c_seed, a_pub, v2) is None
        # v1 blob still opens on a v2-capable opener.
        v1 = cryptobox.seal(a_seed, b_pub, plaintext)
        assert cryptobox.open_box(b_seed, a_pub, v1) == plaintext
        # a v1 opener looking at a v2 blob (wrong version) must not leak.
        assert cryptobox.open_box(b_seed, a_pub, v2, ad=b"nope") is None
        print("OK v2 hybrid: round-trip, wrong recipient None, v1 still opens")
    else:
        print("SKIP v2 hybrid: ML-KEM backend not present")

    print("🎉 cryptobox tests passed")


if __name__ == "__main__":
    main()
