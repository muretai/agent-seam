#!/usr/bin/env python3
"""
tools/gen_wba_vectors.py — deterministic Web Bot Auth REQUEST-verification vectors.

Why this file exists (T107): the Agent Entry verifies inbound RFC 9421 signatures in TWO
independent implementations — Python (`shared/webbotauth.verify_request`, reused by the
reference entry) and the JS twin's own verify-only subset in
the JavaScript door. Hand-rolled parsers disagree one comma at a
time, and a parser that disagrees is a signature that never verifies with no diagnostic —
so, exactly like `vectors/wire_vectors.json`, the two are pinned to ONE frozen
fixture: every vector here is re-derived through the Python verifier by
`test_webbotauth.py::test_request_vectors` (so the file cannot drift from the module) and
through the JS verifier by the contract suite's WBA part.

DETERMINISTIC on purpose: the identity is the pinned `test_webbotauth.py` fixture seed
(bytes(range(32))), timestamps are constants, and every reject case is derived by
explicit surgery on honestly-signed headers. Re-running the generator on an unchanged
tree writes byte-identical JSON; a diff in the output IS a change to the verify contract.

All names follow principle 8: authorities live under `.example`.

    python3 python/tools/gen_wba_vectors.py     # writes vectors/wba_vectors.json
"""
# SPDX-License-Identifier: MIT
# Part of the WIRE CONTRACT (PROVENANCE.md): copied from Muretai core, with the edits that
# file records, and published here under MIT with the bytes it checks.
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from shared import crypto, jws  # noqa: E402
from shared import webbotauth as wba  # noqa: E402

# agent-seam: the vectors live beside the implementations; AGENT_SEAM_WBA_OUT redirects the write
# so a re-derivation can be diffed against the committed file.
OUT = Path(os.environ.get("AGENT_SEAM_WBA_OUT") or REPO.parent / "vectors" / "wba_vectors.json")

#: The pinned identity — test_webbotauth.py's vector fixture, byte for byte.
SEED = bytes(range(32))
CREATED = 1754870400
EXPIRES = CREATED + 300
#: Verification moment: a little after signing, inside every honest window.
NOW = CREATED + 10

AUTHORITY = "entry.example"
OTHER_AUTHORITY = "elsewhere.example"
AGENT_URL = "https://agent.example/hp"

#: A second, FOREIGN key — valid signatures under it must not verify against the
#: directory above (its JWK is deliberately NOT in `jwks`).
FOREIGN_SEED = bytes(range(1, 33))

#: Two keys that ARE in the directory — as MALFORMED entries. Each is a real Ed25519 key,
#: signing honestly, under its own real RFC 7638 thumbprint; the only defect is how the
#: directory spells its `x`. A permissive reader finds the key and accepts the request; a
#: reader that holds `x` to ONE spelling finds no key at all and refuses.
#:
#: WHY THE DEFECT GOES IN THE DIRECTORY AND NOT IN THE HEADERS. `keyid` is the thumbprint of
#: the CANONICAL JWK — `jwk_thumbprint` re-derives it through `jwk_from_public` — so a
#: re-spelled `x` thumbprints to exactly the same keyid as the honest spelling, and putting the
#: bad spelling in the headers would change nothing anybody could observe. The directory is
#: where it bites: `public_from_jwk` is the gate every untrusted entry passes through, and if
#: it repairs, one key has many names in the one document whose whole job is naming keys.
FOREIGN_SEED_LACED = bytes([0x5A] * 32)      # its `x` gets whitespace wedged into it
FOREIGN_SEED_RESPELT = bytes([0x6B] * 32)    # its `x` gets a trailing-bit sibling


class _Signer:
    """The minimal sign_bytes surface, seed-local to this generator."""

    def __init__(self, seed: bytes) -> None:
        self.seed = seed
        self.public = crypto.ed25519_public_from_seed(seed)
        self.did = crypto.did_from_public(self.public)

    def sign_bytes(self, message: bytes) -> str:
        import base64
        return base64.b64encode(crypto.ed25519_sign(self.seed, message)).decode("ascii")


ME = _Signer(SEED)
FOREIGN = _Signer(FOREIGN_SEED)
LACED = _Signer(FOREIGN_SEED_LACED)
RESPELT = _Signer(FOREIGN_SEED_RESPELT)

JWK = wba.jwk_from_public(ME.public)
KEYID = wba.jwk_thumbprint(JWK)
FOREIGN_KEYID = wba.jwk_thumbprint(wba.jwk_from_public(FOREIGN.public))
LACED_KEYID = wba.jwk_thumbprint(wba.jwk_from_public(LACED.public))
RESPELT_KEYID = wba.jwk_thumbprint(wba.jwk_from_public(RESPELT.public))

#: The base64url alphabet, in index order, for the trailing-bit sibling below.
_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def laced_x(public: bytes) -> str:
    """The honest `x` with a space and a tab wedged into it.

    This is not a hypothetical. `base64.urlsafe_b64decode` DISCARDS every byte outside the
    alphabet before decoding, so the laced string and the honest one used to be the same key —
    and the guard that preceded `jws.unb64url`'s alphabet rule only ever refused such an input
    by luck, because `-len(s) % 4` is computed on the RAW length and some junk counts happen to
    misalign the padding. This lacing is chosen to be one of the counts where the luck runs
    out: 45 characters, three pad characters, and a permissive decoder returns the honest 32
    bytes. Asserted below rather than believed."""
    x = jws.b64url(public)
    return x[:10] + " " + x[10:20] + "\t" + x[20:]


def respelt_x(public: bytes) -> str:
    """The honest `x` with its LAST character replaced by a trailing-bit sibling.

    43 characters carry 258 bits for a 256-bit key, so the final character has two bits that
    belong to no byte and every decoder discards them: four alphabet-clean, correctly-lengthed
    strings decode to one key. This is the family `jws.unb64url`'s re-encode leg collapses, and
    it is the one an alphabet check cannot see — the string below is base64url and nothing but
    base64url."""
    x = jws.b64url(public)
    v = _B64URL.index(x[-1])
    return x[:-1] + _B64URL[(v & 0b111100) | ((v & 0b11) ^ 1)]


LACED_JWK = {"crv": "Ed25519", "kty": "OKP", "x": laced_x(LACED.public)}
RESPELT_JWK = {"crv": "Ed25519", "kty": "OKP", "x": respelt_x(RESPELT.public)}


def _permissive(x: str) -> bytes:
    """What a directory reader that repairs would make of `x` — the pre-`unb64url` behaviour,
    reproduced here so the two entries below are pinned as REAL degeneracies rather than as
    strings that merely look odd."""
    import base64
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


for _jwk, _signer, _what in ((LACED_JWK, LACED, "whitespace-laced"),
                             (RESPELT_JWK, RESPELT, "trailing-bit")):
    assert wba.public_from_jwk(_jwk) is None, \
        f"the {_what} entry must be UNREADABLE to the strict reader"
    assert _permissive(_jwk["x"]) == _signer.public, \
        f"…and READABLE to a permissive one, or the {_what} case pins nothing"
    assert _jwk["x"] != jws.b64url(_signer.public), "…and it must differ from the honest spelling"

AGENT_SF = '"' + AGENT_URL + '"'
COMPONENTS = (("@authority", AUTHORITY), ("signature-agent", AGENT_SF))


def sf(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sign_exact(signer: _Signer, components, params: str, label: str = "sig1"):
    """Sign an EXACT @signature-params text (test_webbotauth.py::raw_sig's move)."""
    base = wba.signature_base(components, params)
    return "%s=%s" % (label, params), "%s=:%s:" % (label, signer.sign_bytes(base))


def headers(sig_input: str, sig: str, agent: str = AGENT_SF) -> dict:
    out = {"signature-input": sig_input, "signature": sig}
    if agent is not None:
        out["signature-agent"] = agent
    return out


def params_text(*, created=CREATED, expires=EXPIRES, keyid=KEYID, tag=wba.TAG_REQUEST,
                alg=wba.ALG, components=('@authority', 'signature-agent'),
                order=("created", "expires", "keyid", "alg", "tag"),
                extra: str = "") -> str:
    inner = " ".join(sf(c) for c in components)
    vals = {"created": "created=%d" % created, "expires": "expires=%d" % expires,
            "keyid": "keyid=%s" % sf(keyid), "tag": "tag=%s" % sf(tag),
            "alg": ("alg=%s" % sf(alg)) if alg else None}
    parts = [vals[k] for k in order if vals.get(k)]
    return "(%s);%s%s" % (inner, ";".join(parts), extra)


accept = []
reject = []


def ok(name: str, hdrs: dict) -> None:
    accept.append({"name": name, "headers": hdrs, "expect_did": ME.did})


def bad(name: str, hdrs: dict) -> None:
    reject.append({"name": name, "headers": hdrs})


# ---- accept ------------------------------------------------------------------

honest = params_text()
si, s = sign_exact(ME, COMPONENTS, honest)
ok("the canonical request signature (fixed param order, alg present)", headers(si, s))

si, s = sign_exact(ME, COMPONENTS,
                   params_text(order=("keyid", "tag", "created", "expires", "alg")))
ok("params REORDERED but honestly signed — verification is byte-faithful, not "
   "canonical", headers(si, s))

si, s = sign_exact(ME, COMPONENTS, params_text(alg=None))
ok("alg omitted (RFC 9421 allows it; the keyid pins the curve)", headers(si, s))

si, s = sign_exact(ME, (("@authority", AUTHORITY),),
                   params_text(components=("@authority",)))
ok("@authority alone — the one REQUIRED component", headers(si, s))

f_si, f_s = sign_exact(FOREIGN, COMPONENTS, params_text(keyid=FOREIGN_KEYID),
                       label="siga")
m_si, m_s = sign_exact(ME, COMPONENTS, honest, label="sigb")
ok("two entries; only the second is ours — a foreign label does not poison the set",
   headers(f_si + ", " + m_si, f_s + ", " + m_s))

# ---- reject ------------------------------------------------------------------

si, s = sign_exact(ME, COMPONENTS, honest)
bad("tampered Signature (one flipped base64 character)",
    headers(si, s[:-6] + ("A" if s[-6] != "A" else "B") + s[-5:]))

bad("tampered Signature-Agent header (the signature covers its value)",
    headers(si, s, agent='"https://evil.example/hp"'))

si2, s2 = sign_exact(ME, (("@authority", OTHER_AUTHORITY),
                          ("signature-agent", AGENT_SF)), honest)
bad("signed for a DIFFERENT authority — same headers replayed at us", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS,
                     params_text(created=CREATED - 1000, expires=CREATED - 400))
bad("expired (now past `expires`)", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS,
                     params_text(created=NOW + 400, expires=NOW + 900))
bad("created in the future (beyond clock skew)", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS,
                     params_text(created=CREATED, expires=CREATED + 700))
bad("lifetime over the request cap (700 s > 600 s) — a long-lived bearer header",
    headers(si2, s2))

si2, s2 = sign_exact(FOREIGN, COMPONENTS, params_text(keyid=FOREIGN_KEYID))
bad("a VALID signature under a key that is not in the directory", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS, params_text(tag=wba.TAG_DIRECTORY))
bad("tag confusion — a directory self-attestation replayed as a request",
    headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS, params_text(alg="EdDSA"))
bad('alg="EdDSA" — JOSE\'s name in the HTTP-signature registry slot', headers(si2, s2))

per_item = honest.replace(sf("@authority"), sf("@authority") + ';name="q"', 1)
si2, s2 = sign_exact(ME, COMPONENTS, per_item)
bad("per-item parameters on a covered component (out of profile)", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS, honest)
bad("duplicate label in Signature-Input",
    headers(si2 + ", " + si2, s2))

dup_param = honest + (";keyid=%s" % sf(KEYID))
si2, s2 = sign_exact(ME, COMPONENTS, dup_param)
bad("a repeated parameter name (two keyids)", headers(si2, s2))

si2, s2 = sign_exact(ME, (("signature-agent", AGENT_SF),),
                     params_text(components=("signature-agent",)))
bad("no @authority component — the signature proves nothing about WHERE",
    headers(si2, s2))

si2, s2 = sign_exact(ME, (("@method", "POST"), ("@authority", AUTHORITY)),
                     params_text(components=("@method", "@authority")))
bad("an unsupported derived component (@method)", headers(si2, s2))

si2, s2 = sign_exact(ME, (("@AUTHORITY", AUTHORITY),),
                     params_text(components=("@AUTHORITY",)))
bad("an uppercase component name", headers(si2, s2))

si2, s2 = sign_exact(ME, (("@authority", AUTHORITY), ("@authority", AUTHORITY)),
                     params_text(components=("@authority", "@authority")))
bad("a duplicated component", headers(si2, s2))

si2, s2 = sign_exact(ME, COMPONENTS, honest)
bad("parameters on a Signature member (out of profile)", headers(si2, s2 + ";x=1"))

si2, s2 = sign_exact(ME, COMPONENTS, honest)
bad("an absurdly long Signature-Input (parser work bound)",
    headers(si2 + " " * 9000, s2))

si2, s2 = sign_exact(ME, COMPONENTS, honest)
bad("invalid base64 in the Signature value",
    headers(si2, s2.replace(":", ":!", 1)))

si2, s2 = sign_exact(ME, COMPONENTS, honest, label="sig1")
bad("label present in Signature-Input but missing from Signature",
    headers(si2, s2.replace("sig1=", "sig9=", 1)))

si2, s2 = sign_exact(ME, COMPONENTS, honest)
bad("trailing comma in Signature-Input", headers(si2 + ",", s2))

bad("no signature headers at all", {"signature-agent": AGENT_SF})

bad("Signature present, Signature-Input absent",
    {"signature": s, "signature-agent": AGENT_SF})

# The two directory entries whose `x` is spelled wrong. Everything about these requests is
# honest — a real key, a real signature, the real thumbprint as `keyid` — and the directory
# does hold the key, in the sense that a repairing reader would find it. It must be refused,
# because a JWK `x` names a key only when it is spelled the one way.
si2, s2 = sign_exact(LACED, COMPONENTS, params_text(keyid=LACED_KEYID))
bad("a directory JWK whose `x` is laced with whitespace — urlsafe_b64decode DISCARDS every "
    "byte outside the alphabet, so this used to be the same key under another name",
    headers(si2, s2))

si2, s2 = sign_exact(RESPELT, COMPONENTS, params_text(keyid=RESPELT_KEYID))
bad("a directory JWK whose `x` is a TRAILING-BIT sibling — 43 characters carry 258 bits for a "
    "256-bit key, so four alphabet-clean strings decode to one key and only a re-encode tells "
    "them apart", headers(si2, s2))

# ------------------------------------------------------------------------------

document = {
    "_": ("GENERATED by tools/gen_wba_vectors.py — do not edit. Frozen inputs to "
          "verify_request; re-derived by test_webbotauth.py (Python) and the contract "
          "suite's WBA part (JS). now/authority/jwks are the verifier's inputs. `jwks` holds "
          "ONE readable key and two entries whose `x` is spelled wrong — one laced with "
          "whitespace, one a trailing-bit sibling. Those two are not decoration: the requests "
          "signed under them are otherwise perfect, so a reader that repairs an `x` accepts "
          "them, and a JWK `x` has exactly one spelling or a key has many names."),
    "seed_hex": SEED.hex(),
    "did": ME.did,
    "jwks": {"keys": [JWK, LACED_JWK, RESPELT_JWK]},
    "authority": AUTHORITY,
    "now": NOW,
    "accept": accept,
    "reject": reject,
}

# GENERATION DISCIPLINE, the same rule test_wire_vectors.py states: a vector nobody has watched
# accept or refuse is decoration. Every case goes through the REAL verifier here, against the
# document exactly as it is about to be written, so a case that is wrong cannot reach the file —
# and the two malformed directory entries cannot silently stop mattering if `unb64url` is ever
# loosened, because the requests they carry would start verifying right here.
for _case in accept:
    _got = wba.verify_request(_case["headers"], authority=AUTHORITY,
                              jwks=document["jwks"], now=NOW)
    assert _got == _case["expect_did"], ("accept case does not verify", _case["name"], _got)
for _case in reject:
    _got = wba.verify_request(_case["headers"], authority=AUTHORITY,
                              jwks=document["jwks"], now=NOW)
    assert _got is None, ("reject case was ACCEPTED", _case["name"], _got)

OUT.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n",
               encoding="utf-8")
print(f"wrote {OUT}: {len(accept)} accept, {len(reject)} reject "
      f"({len(document['jwks']['keys'])} directory entries, "
      f"{sum(1 for k in document['jwks']['keys'] if wba.public_from_jwk(k) is None)} of them "
      "unreadable on purpose)")
