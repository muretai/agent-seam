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

JWK = wba.jwk_from_public(ME.public)
KEYID = wba.jwk_thumbprint(JWK)
FOREIGN_KEYID = wba.jwk_thumbprint(wba.jwk_from_public(FOREIGN.public))

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

# ------------------------------------------------------------------------------

document = {
    "_": ("GENERATED by tools/gen_wba_vectors.py — do not edit. Frozen inputs to "
          "verify_request; re-derived by test_webbotauth.py (Python) and the contract "
          "suite's WBA part (JS). now/authority/jwks are the verifier's inputs."),
    "seed_hex": SEED.hex(),
    "did": ME.did,
    "jwks": {"keys": [JWK]},
    "authority": AUTHORITY,
    "now": NOW,
    "accept": accept,
    "reject": reject,
}

OUT.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n",
               encoding="utf-8")
print(f"wrote {OUT}: {len(accept)} accept, {len(reject)} reject")
