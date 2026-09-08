#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""python/test_ed25519_backend_agreement.py — the two Ed25519 backends answer THE SAME.

`shared/crypto.py` has two of them: the library backend (`cryptography`, and PyNaCl where
it is the one installed) and a pure-Python RFC 8032 fallback that a deployer selects with
`AGENTNET_PURE_ED25519=1`. They are different code reaching the same verdict, and which
one runs is decided by an environment variable — not by the message, not by the sender,
not by anything either end of the wire can see.

So read a failure here correctly: **a disagreement between the two columns is a CONTRACT
SPLIT, not a test failure.** It means the same 64 bytes under the same key over the same
message authenticate a stranger on one deployment and do not on another, and no amount of
care at the call sites can recover from that — the caller asked one question and got two
answers. The same is true of the third column: `want` is what the JavaScript, Go and Rust
twins answer (measured on node's `crypto.verify`, which is OpenSSL's Ed25519), and a
Python column that disagrees with it splits the seam four ways instead of two.

The backend is chosen once, at import time, by a `try:` around the library import — there
is no re-selecting it inside a live interpreter. So this file re-execs ITSELF twice as a
subprocess, once with `AGENTNET_PURE_ED25519` cleared and once with it set to "1", each
child printing one JSON verdict per corpus case, and the parent compares the two lists.
Adding a case means adding it to `corpus()` in one place; both children then run it.

The corpus is the class of inputs where an implementation is tempted to be lenient:
valid signatures, the 14 small-order public keys, non-canonical point encodings of A and
of R, an unreduced S, a wrong message, a truncated signature, and every base64 spelling of
one correct signature.

Run:  python3 python/test_ed25519_backend_agreement.py
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from shared import crypto                              # noqa: E402

# ---------------------------------------------------------------- the corpus

#: The 14 encodings of a point of order 1, 2, 4 or 8 — libsodium's
#: `ge25519_has_small_order` blacklist. A signature `R = <the point>, S = 0` verifies
#: over ANY message under a small-order key, because [h]A collapses for every h; the
#: attacker needs no private key, only the DID and one constant 64-byte blob.
SMALL_ORDER = [
    "0000000000000000000000000000000000000000000000000000000000000000",  # y=0,   order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # y=0,   sign set
    "0100000000000000000000000000000000000000000000000000000000000000",  # y=1,   THE IDENTITY
    "0100000000000000000000000000000000000000000000000000000000000080",  # y=1,   sign set
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8, sign set
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8, sign set
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y=p-1, order 2
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # y=p-1, sign set
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y=p    (== 0)
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # y=p,   sign set
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y=p+1  (== 1)
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # y=p+1, sign set
]

L = 2 ** 252 + 27742317777372353535851937790883648493
P = 2 ** 255 - 19


def _noncanonical_encodings() -> list[bytes]:
    """Every 32-byte encoding whose y is >= p. y lives in the low 255 bits, so y + p fits
    only for y < 19 — the whole non-canonical space is the 19 values p..p+18, each with
    the sign bit clear and set. Two byte strings for one point is one authenticated fact
    with two spellings; RFC 8032 5.1.3 calls the larger one invalid."""
    out = []
    for y in range(P, P + 19):
        for sign in (0, 1):
            out.append(((y | (sign << 255))).to_bytes(32, "little"))
    return out


_B64_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 "0123456789+/")


def _trailing_bit_respellings(sig_b64: str) -> list[tuple[str, str]]:
    """Every OTHER base64 string that decodes to exactly these 64 bytes.

    64 is not a multiple of 3, so the last quantum encodes one byte in two characters:
    six bits, then two bits plus FOUR that belong to no byte and that every decoder —
    Python's and node's alike — silently discards. The fifteen characters sharing the real
    one's top two bits therefore decode identically. Each is checked, not assumed.
    """
    assert len(sig_b64) == 88 and sig_b64.endswith("=="), sig_b64
    want = base64.b64decode(sig_b64)
    real = _B64_ALPHABET.index(sig_b64[-3])
    out = []
    for i in range(real & 0b110000, (real & 0b110000) + 16):
        if i == real:
            continue
        alt = sig_b64[:-3] + _B64_ALPHABET[i] + "=="
        assert base64.b64decode(alt) == want, "respelling changed the bytes"
        out.append((_B64_ALPHABET[i], alt))
    return out


def _small_order_r_signature(seed: bytes, msg: bytes, r_bytes: bytes) -> bytes:
    """Mint a signature whose R is a SMALL-ORDER point and whose equation really holds.

    The interesting forgery is not `S = 0` under a junk key — it is this one, under an
    HONEST key over an HONEST message. With R = the identity, [S]B == R + [h]A collapses
    to [S]B == [h]A, so S = h*a mod l satisfies it exactly. Only the key holder can mint
    it, which is the point: it is a SECOND signature, spelled differently, over a message
    they already signed — the same non-repudiation hole `S < l` exists to close.

    Written out here rather than pinned as a hex constant so it stays derivable when the
    corpus message changes, and computed with plain integers so the library child can mint
    it too (there is no point arithmetic to borrow from `shared.crypto` in that branch).
    """
    import hashlib
    q, l = P, L
    inv = lambda x: pow(x, q - 2, q)                              # noqa: E731
    d = -121665 * inv(121666) % q
    ii = pow(2, (q - 1) // 4, q)

    def xrecover(y: int) -> int:
        xx = (y * y - 1) * inv(d * y * y + 1)
        x = pow(xx, (q + 3) // 8, q)
        if (x * x - xx) % q:
            x = x * ii % q
        return q - x if x % 2 else x

    def add(p1, p2):
        x1, y1 = p1
        x2, y2 = p2
        return ((x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q,
                (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q)

    def mul(p1, e):
        acc = (0, 1)
        while e > 0:
            if e & 1:
                acc = add(acc, p1)
            p1 = add(p1, p1)
            e >>= 1
        return acc

    by = 4 * inv(5) % q
    base = (xrecover(by), by)
    h = hashlib.sha512(seed).digest()
    a = 2 ** 254 + sum(2 ** i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    pub = (mul(base, a)[1] | ((mul(base, a)[0] & 1) << 255)).to_bytes(32, "little")
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + msg).digest(), "little") % l
    s = (k * a) % l
    # the equation really holds: [S]B == identity + [k]A
    assert mul(base, s) == add((0, 1), mul(mul(base, a), k)), \
        "the small-order-R forgery does not satisfy the verification equation"
    return r_bytes + s.to_bytes(32, "little")


def _envelope_seed() -> bytes:
    """A seed whose signature's base64 contains BOTH '+' and '/', so the base64url case
    below is a real alternative spelling rather than the same string twice."""
    for i in range(1, 256):
        seed = bytes([i]) * 32
        b64 = crypto.sign_envelope(seed, "did:key:zFROM", "did:key:zTO",
                                   "m1", "c1", 1752451200, "hi")
        if "+" in b64 and "/" in b64:
            return seed
    raise AssertionError("no seed produced a signature with both '+' and '/'")


def corpus() -> list[tuple[str, object, object]]:
    """(name, verdict, want) for every case, in a fixed order both children reproduce."""
    seed = bytes([7]) * 32
    pub = crypto.ed25519_public_from_seed(seed)
    did = crypto.did_from_public(pub)
    msg = b"the six fields, canonicalised"
    good = crypto.ed25519_sign(seed, msg)

    rows: list[tuple[str, object, object]] = []

    def case(name: str, want: bool, fn) -> None:
        try:
            got: object = bool(fn())
        except Exception as exc:                 # an exception is a verdict too: if one
            got = "EXC:" + type(exc).__name__    # backend raises and the other returns
        rows.append((name, got, want))           # False, that is still a split.

    # ---- the positive controls. Without these the whole file passes by refusing
    # everything, which is a fail-CLOSED implementation of nothing.
    case("valid signature", True, lambda: crypto.ed25519_verify(pub, good, msg))
    case("valid, through verify(did:key)", True, lambda: crypto.verify(did, good, msg))
    case("valid, through verify_raw(pub)", True, lambda: crypto.verify_raw(pub, good, msg))
    case("wrong message", False,
         lambda: crypto.ed25519_verify(pub, good, b"a different message"))
    case("signature from another key", False,
         lambda: crypto.ed25519_verify(
             crypto.ed25519_public_from_seed(bytes([9]) * 32), good, msg))

    # ---- small-order keys: one blob authenticates everything
    for hexk in SMALL_ORDER:
        k = bytes.fromhex(hexk)
        case(f"small-order key {hexk[:8]}… R=A,S=0", False,
             lambda k=k: crypto.ed25519_verify(k, k + bytes(32), msg))
        # …and over a SECOND, unrelated message under the same blob: that is what makes it
        # a universal forgery rather than one bad signature.
        case(f"small-order key {hexk[:8]}… same blob, other message", False,
             lambda k=k: crypto.ed25519_verify(k, k + bytes(32), b"pay the attacker"))
        # …and through the DID path, which is how it would actually arrive on the wire.
        case(f"small-order key {hexk[:8]}… via did:key", False,
             lambda k=k: crypto.verify(crypto.did_from_public(k), k + bytes(32), msg))

    # ---- a small-order R under an HONEST key. `cryptography` accepts the first of these
    # and node's `crypto.verify` refuses it — the same library family, different builds, so
    # the verdict moved with whichever libcrypto the machine linked. Pinned here instead.
    for label, r_hex in (("identity", SMALL_ORDER[2]),
                         ("identity spelled y = p+1", SMALL_ORDER[12])):
        forged = _small_order_r_signature(seed, msg, bytes.fromhex(r_hex))
        case(f"small-order R ({label}), equation HOLDS, honest key", False,
             lambda f=forged: crypto.ed25519_verify(pub, f, msg))
        case(f"small-order R ({label}), through verify(did:key)", False,
             lambda f=forged: crypto.verify(did, f, msg))
    for hexk in SMALL_ORDER:
        case(f"small-order R {hexk[:8]}…, S = 0, honest key", False,
             lambda h=hexk: crypto.ed25519_verify(
                 pub, bytes.fromhex(h) + bytes(32), msg))
        case(f"small-order R {hexk[:8]}…, honest S, honest key", False,
             lambda h=hexk: crypto.ed25519_verify(
                 pub, bytes.fromhex(h) + good[32:], msg))

    # ---- non-canonical encodings, split into the two groups ON PURPOSE.
    #
    # Group 1 is the four spellings that are ALSO in the small-order table (y = p and
    # y = p+1, both sign bits). Every reference refuses those, by the table, and nothing
    # about them rests on an argument.
    #
    # Group 2 is the other thirty-four: y in p+2 .. p+18, both sign bits. Python refuses
    # them because `_ed25519_wire_ok` rejects any y >= p; Go and Rust have no such rule and
    # reach the same verdict by a DIFFERENT route — the encoding names a point whose y is
    # 2..18, and no verifying signature can exist under such a key (its discrete log is
    # unknown) or with such an R (finding r with [r]B in that range is a ~2^-250 search),
    # so the only reachable cases are the ones the table already holds. That is a REASONING
    # STEP standing between Python and the other three references, and a reasoning step in
    # a contract belongs in a test rather than in a comment. These cases are where it
    # surfaces if it is ever wrong: they must be False here, and False in Go and Rust too,
    # however each of the three arrives at it.
    small = {bytes.fromhex(h) for h in SMALL_ORDER}
    for enc in _noncanonical_encodings():
        group = "also small-order" if enc in small else "NOT small-order"
        tag = f"{group}) {enc.hex()[:6]}…{enc.hex()[-2:]}"
        case(f"non-canonical A ({tag}, R = A, S = 0", False,
             lambda e=enc: crypto.ed25519_verify(e, e + bytes(32), msg))
        case(f"non-canonical A ({tag}, an honest signature", False,
             lambda e=enc: crypto.ed25519_verify(e, good, msg))
        case(f"non-canonical A ({tag}, via did:key", False,
             lambda e=enc: crypto.verify(crypto.did_from_public(e), e + bytes(32), msg))
        case(f"non-canonical R ({tag}, honest key and S", False,
             lambda e=enc: crypto.ed25519_verify(pub, e + good[32:], msg))
        case(f"non-canonical R ({tag}, honest key, S = 0", False,
             lambda e=enc: crypto.ed25519_verify(pub, e + bytes(32), msg))
    # The split above is only meaningful if the arithmetic behind it holds: 19 y values
    # (p..p+18) x 2 sign bits = 38 encodings, of which exactly 4 are in the table. Assert
    # it rather than trusting the loop to have found what it was supposed to find.
    _nc = _noncanonical_encodings()
    assert len(_nc) == 38 and sum(1 for e in _nc if e in small) == 4, \
        f"non-canonical space is not 38 encodings with 4 tabled: {len(_nc)}"

    # ---- S must be the canonical scalar 0 <= S < l (RFC 8032 5.1.7 step 1). S + l is a
    # SECOND valid signature over the same message under the same key if it is not checked.
    s_int = int.from_bytes(good[32:], "little")
    if s_int + L < 2 ** 256:
        case("S + l (malleable second spelling)", False,
             lambda: crypto.ed25519_verify(
                 pub, good[:32] + (s_int + L).to_bytes(32, "little"), msg))
    case("S = l exactly", False,
         lambda: crypto.ed25519_verify(pub, good[:32] + L.to_bytes(32, "little"), msg))

    # ---- shapes
    case("signature truncated to 63 bytes", False,
         lambda: crypto.ed25519_verify(pub, good[:63], msg))
    case("signature padded to 65 bytes", False,
         lambda: crypto.ed25519_verify(pub, good + b"\x00", msg))
    case("public key truncated to 31 bytes", False,
         lambda: crypto.ed25519_verify(pub[:31], good, msg))
    case("empty signature", False, lambda: crypto.ed25519_verify(pub, b"", msg))

    # ---- base64: one signature, ONE spelling (verify_signed_envelope reads the wire)
    e_seed = _envelope_seed()
    e_pub = crypto.ed25519_public_from_seed(e_seed)
    e_did = crypto.did_from_public(e_pub)
    fields = (e_did, "did:key:zTO", "m1", "c1", 1752451200, "hi")
    sig_b64 = crypto.sign_envelope(e_seed, *fields)

    def env(s):
        return crypto.verify_envelope(*fields, s)

    spellings = [
        ("base64 canonical (the only accepted spelling)", True, sig_b64),
        ("base64 padding stripped", False, sig_b64.rstrip("=")),
        ("base64 one char short", False, sig_b64[:-1]),
        ("base64 trailing newline", False, sig_b64 + "\n"),
        ("base64 embedded newline", False, sig_b64[:44] + "\n" + sig_b64[44:]),
        ("base64 leading space", False, " " + sig_b64),
        ("base64 trailing space", False, sig_b64 + " "),
        ("base64 internal spaces", False, sig_b64[:44] + " " + sig_b64[44:]),
        ("base64 non-alphabet junk spliced in", False,
         sig_b64[:44] + "!!!!" + sig_b64[44:]),
        ("base64url spelling of the same bytes", False,
         base64.urlsafe_b64encode(base64.b64decode(sig_b64)).decode("ascii")),
        ("base64 three pad characters", False, sig_b64[:-3] + "==="),
        ("base64 pad in the middle", False, sig_b64[:40] + "=" + sig_b64[41:]),
        # 64 is not a multiple of 3, so the LAST data character of a signature carries four
        # bits that belong to no byte and every decoder discards. The fifteen characters
        # sharing the real one's top two bits decode to THE SAME 64 BYTES: fifteen extra
        # spellings of one signature, which a replay cache keyed on the `sig` STRING reads
        # as fifteen new messages. Each one is checked to decode identically before it is
        # used, so this case cannot quietly degrade into "a different, invalid signature".
        *[(f"base64 discarded trailing bits (…{c}==)", False, s)
          for c, s in _trailing_bit_respellings(sig_b64)],
        ("base64 of 63 bytes", False,
         base64.b64encode(base64.b64decode(sig_b64)[:63]).decode("ascii")),
        ("base64 of 65 bytes", False,
         base64.b64encode(base64.b64decode(sig_b64) + b"\x00").decode("ascii")),
        ("base64 empty string", False, ""),
    ]
    for name, want, s in spellings:
        case(name, want, lambda s=s: env(s))

    # `sig` is whatever a stranger put in the field, and the pinned `missing-sig` reject
    # vector puts null there. None of these may raise out of a verifier.
    for name, s in (("sig is None", None), ("sig is an int", 1234),
                    ("sig is a list", ["AAAA"]), ("sig is bytes", b"AAAA")):
        case(name, False, lambda s=s: env(s))

    # ---- the same discipline on the additive `metadata.sigs` lane (T142 A3)
    case("extra_sigs_ok: canonical spelling", True,
         lambda: crypto.extra_sigs_ok(
             *fields, [{"alg": "ed25519-pub", "sig": sig_b64}]))
    case("extra_sigs_ok: unpadded spelling", False,
         lambda: crypto.extra_sigs_ok(
             *fields, [{"alg": "ed25519-pub", "sig": sig_b64.rstrip("=")}]))
    case("extra_sigs_ok: whitespace spelling", False,
         lambda: crypto.extra_sigs_ok(
             *fields, [{"alg": "ed25519-pub", "sig": sig_b64 + "\n"}]))
    case("extra_sigs_ok: small-order signer", False,
         lambda: crypto.extra_sigs_ok(
             crypto.did_from_public(bytes.fromhex(SMALL_ORDER[2])), *fields[1:],
             [{"alg": "ed25519-pub",
               "sig": base64.b64encode(bytes.fromhex(SMALL_ORDER[2])
                                       + bytes(32)).decode("ascii")}]))

    return rows


# ---------------------------------------------------------------- child / parent

def emit() -> None:
    rows = corpus()
    print(json.dumps({"backend": crypto.BACKEND,
                      "rows": [[n, v, w] for n, v, w in rows]}))


def run_child(pure: bool) -> dict:
    env = dict(os.environ)
    if pure:
        env["AGENTNET_PURE_ED25519"] = "1"
    else:
        env.pop("AGENTNET_PURE_ED25519", None)
    r = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--emit"],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(f"the {'pure' if pure else 'library'} backend child failed")
    return json.loads(r.stdout.strip().splitlines()[-1])


def main() -> None:
    lib = run_child(pure=False)
    pur = run_child(pure=True)

    print(f"backends: {lib['backend']}  vs  {pur['backend']}")
    if lib["backend"] == pur["backend"]:
        # Only one backend is installable here, so the agreement column is vacuous. The
        # `want` column is not — say which half of the test is still doing work rather
        # than printing a green line that means less than it looks.
        print("  NOTE: only one backend is available in this interpreter "
              "(`cryptography` is not installed?). The two columns are the same code; "
              "the agreement leg is vacuous and only the `want` leg discriminates.")

    assert len(lib["rows"]) == len(pur["rows"]), "the two children ran different corpora"

    splits: list[str] = []
    wrong: list[str] = []
    for (n1, v1, w1), (n2, v2, w2) in zip(lib["rows"], pur["rows"]):
        assert n1 == n2, f"corpus order differs between children: {n1!r} vs {n2!r}"
        if v1 != v2:
            splits.append(f"  SPLIT  {n1}: {lib['backend']}={v1!r}  {pur['backend']}={v2!r}")
        if v1 != w1:
            wrong.append(f"  WRONG  {n1}: {lib['backend']}={v1!r}, want {w1!r}")
        if v2 != w2:
            wrong.append(f"  WRONG  {n1}: {pur['backend']}={v2!r}, want {w2!r}")

    for line in splits:
        print(line)
    for line in wrong:
        print(line)

    n = len(lib["rows"])
    if splits or wrong:
        print(f"\nFAILED — {len(splits)} split(s), {len(wrong)} wrong verdict(s) "
              f"over {n} cases.")
        if splits:
            print("A SPLIT IS NOT A TEST FAILURE. It means shared/crypto.py answers the "
                  "same wire bytes two ways depending on an environment variable: the "
                  "same signature authenticates a stranger on one deployment and not on "
                  "another. Fix the backends, never the corpus.")
        raise SystemExit(1)

    print(f"\nOK — {n} cases, both backends agree, and both agree with the "
          f"JavaScript/Go/Rust twins.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--emit":
        emit()
    else:
        main()
