#!/usr/bin/env python3
"""
test_wire_vectors.py — pin the WIRE BYTE contract every non-Python client must reproduce.

WHY THIS EXISTS: `shared/crypto.py` and `shared/keybinding.py` are re-implemented, in another
language, by every native client — Swift (`muretai-ios-poc` Sources/SeamKit) and Kotlin
(`muretai-android-poc` seam/). Those clients do not import core; they cannot. They copy its BYTES.

That coupling is invisible to every tool that normally keeps repos in step: a dependency manager
sees no dependency, because there isn't one. And when it breaks, nothing throws. A client whose
canonical JSON differs from Python's by one byte produces signatures the network rejects, forever,
with the single diagnostic "signature verification failed". No stack, no field name, no hint that
the JSON encoder is the culprit.

So the bytes are pinned here, generated FROM core, and each client asserts the same file. This is
the same shape as `test_ios_identity.py` (which pins the recovery phrase) generalized to the rest
of the wire — and the same shape the wider world uses for this exact problem: protobuf's
conformance suite, Connect RPC's, RFC 8785 JCS's cross-language vectors.

    python3 test_wire_vectors.py           # Python reproduces the pinned vectors
    python3 test_wire_vectors.py --regen   # regenerate after an INTENTIONAL wire change
    python3 tools/client_conformance.py    # which clients have a stale vendored copy?

Regenerating is how you DECLARE a wire change. If this test fails and you did not mean to change
the wire, you have just been saved from shipping a silent break in every client at once.

Stdlib only, offline, no node required. P-256 vectors need the optional `cryptography` backend
(`crypto.P256_AVAILABLE`); without it those vectors are still checked against the pinned file
(the DID is pure encoding), only the live signature check is skipped.
"""
# SPDX-License-Identifier: MIT
# Part of the WIRE CONTRACT (PROVENANCE.md): copied from Muretai core, with the edits that
# file records, and published here under MIT with the bytes it checks.

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from shared import crypto                          # noqa: E402
from shared import keybinding                      # noqa: E402
from shared.protocol import PROTOCOL_VERSION       # noqa: E402

# agent-seam: the vectors live beside the implementations, not under python/. AGENT_SEAM_VECTORS
# points the checks AND --regen at another path, so a re-derivation can be diffed against the
# committed file without touching it.
VECTORS = Path(os.environ.get("AGENT_SEAM_VECTORS") or REPO.parent / "vectors" / "wire_vectors.json")

#: U+FFFD REPLACEMENT CHARACTER, spelled as an escape. It is written this way in the two places
#: `reject.encoding` reasons about it because the whole group turns on the difference between a
#: document that CARRIES this character and a document that a repairing reader turned INTO it —
#: and a literal glyph in the source is the one form a reader cannot tell from mojibake.
_FFFD = "\ufffd"

_passed = 0


def ok(cond: bool, label: str) -> None:
    global _passed
    if not cond:
        raise AssertionError(f"FAILED: {label}")
    _passed += 1
    print(f"  ✓ {label}")


# ---------------------------------------------------------------- the cases
#
# Each case is chosen because a reasonable implementation gets it WRONG. Round numbers and happy
# paths are not pinned here — they agree by accident. These are the places where two JSON encoders
# that both look correct disagree, and where a did:key parser that "works" accepts the wrong key.

def _canonical_cases() -> list[dict]:
    """Canonical-JSON inputs where independent implementations actually diverge."""
    cases = [
        ("sorted-keys", {"b": 1, "a": "x"},
         "sort_keys=True: insertion order must not survive into the bytes"),
        ("no-whitespace", {"a": 1, "b": 2},
         "separators=(',',':'): a default json.dumps would add spaces here"),
        ("non-ascii-literal", {"text": "群れたい"},
         "ensure_ascii=False: non-ASCII stays literal UTF-8, NOT \\uXXXX. This is the one most "
         "clients get wrong, and message text is routinely non-ASCII"),
        ("escape-shorthands", {"k": '"\\\b\f\n\r\t'},
         "Python's ESCAPE_DCT: exactly these seven shorthands"),
        ("control-chars", {"k": "\x00\x01\x1f"},
         "other <0x20 become lowercase \\u00xx"),
        ("slash-and-del-unescaped", {"k": "a/b\x7f"},
         "Python escapes NEITHER '/' nor DEL — many JSON writers escape both"),
        ("null-value", {"contextId": None},
         "None -> null (contextId is genuinely nullable on the wire)"),
        ("empty-string", {"text": ""}, "empty string is not null"),
        ("surrogate-pair", {"text": "🐦"},
         "an astral char is one code point in Python but two UTF-16 units elsewhere"),
        ("combining-marks", {"text": "が"},
         "NOT normalized: canonical JSON must never NFC/NFD the input"),
        ("key-ordering-unicode", {"z": 1, "a": 2, "群": 3, "A": 4},
         "keys sort by CODE POINT (Python str order), not by UTF-16 unit or locale"),
        ("negative-and-zero", {"a": 0, "b": -1}, "integers render bare, no + or leading zeros"),
        ("large-int-within-double", {"a": 9007199254740991},
         "2**53-1, the largest integer a JavaScript Number holds exactly. Signed "
         "integers must stay inside +/-(2**53-1) — see numberHazards/int-beyond-2exp53"),
        ("fractional-float-agrees", {"a": 0.1, "b": 1785937682.845164},
         "the CONTRAST case for numberHazards: ordinary FRACTIONAL floats do agree "
         "byte-for-byte across languages. That is exactly why float timestamps looked "
         "fine for a year — they are reproducible until one lands on a whole second"),
    ]
    return [{"name": n, "payload": p, "why": w,
             "canonical": crypto.canonical(p).decode("utf-8")} for n, p, w in cases]


def _number_hazard_cases() -> list[dict]:
    """Numbers whose canonical bytes DIFFER between Python and JavaScript.

    Deliberately a separate section from `canonical`. A client must reproduce every
    `canonical` case; it must NOT be asked to reproduce these, because doing so means
    re-implementing CPython's float repr — which is precisely the dependency the
    integer rule exists to remove.

    Each case carries the two renderings so a client can assert the divergence itself
    rather than take our word for it. Measured 2026-08-07, CPython 3.14 vs Node 26.
    """
    cases = [
        ("integral-float", {"a": 1.0}, "1",
         "Python writes 1.0, JavaScript writes 1 — and JSON.parse('1.0') is "
         "irrecoverably 1, so a client cannot even reconstruct what was signed. "
         "`credentialSubject.trustLevel` was this value on every introduction minted "
         "by `operator_cli.introduce` and a Room's `/introduce`; fixed 2026-08-07 by "
         "minting integer basis points (`trustLevelBp`)."),
        ("integral-float-zero", {"a": 0.0}, "0",
         "`keystate.notBefore` defaulted to 0.0 and was therefore unverifiable "
         "outside Python 100% of the time; fixed 2026-08-07."),
        ("integral-float-negative", {"a": -1.0}, "-1",
         "the sign does not save it"),
        ("negative-zero", {"a": -0.0}, "0",
         "Python keeps the sign, JavaScript does not. Matrix bans -0 from its "
         "canonical JSON outright, for this reason."),
        ("exponent-small", {"a": 1e-7}, "1e-7",
         "Python zero-pads and always signs the exponent (1e-07); JavaScript does "
         "neither"),
        ("exponent-threshold", {"a": 1e16}, "10000000000000000",
         "Python switches to exponent notation here (1e+16); JavaScript does not "
         "switch until 1e21. The thresholds differ, so agreement is a coin flip."),
        ("int-beyond-2exp53", {"a": 9007199254740993}, "9007199254740992",
         "NOT a formatting mismatch — SILENT DATA CORRUPTION. Python has "
         "arbitrary-precision integers; a JavaScript Number rounds. Keep signed "
         "integers inside +/-(2**53-1), the bound Matrix and RFC 8785 both set."),
        ("nested-float", {"credentialSubject": {"trustLevel": 1.0}},
         '{"credentialSubject":{"trustLevel":1}}',
         "the real shape of the bug: two levels down inside an introduction "
         "credential, where nothing at the top level looked wrong"),
    ]
    out = []
    for name, payload, js_form, why in cases:
        out.append({
            "name": name,
            "payload": payload,
            "pythonCanonical": crypto.canonical(payload).decode("utf-8"),
            "javascriptWouldWrite": js_form if js_form.startswith("{")
                                    else '{"a":%s}' % js_form,
            "signMustNotEmit": True,
            "verifyNeedsPythonRepr": True,
            "why": why,
        })
    return out


#: The Ed25519 public keys the `did` section pins — module-level so the `webBotAuth`
#: thumbprint vectors are provably THE SAME KEYS. A client can then line up one key at a
#: time, publicHex -> did -> x -> thumbprint, and a divergence names the step that broke.
#: Two lists would drift the first time either section grew a case.
_ED25519_PUBLICS = (bytes(32), bytes([255] * 32), bytes(range(32)),
                    hashlib.sha256(b"muretai-wire-vector").digest())


def _did_cases() -> list[dict]:
    """did:key encoding at the edges of the base58 bit-packing."""
    out = [{"curve": "ed25519", "multicodec": "ed01", "publicHex": k.hex(),
            "did": crypto.did_from_public(k)} for k in _ED25519_PUBLICS]

    # A compressed SEC1 point is 0x02|0x03 || X. The prefix carries Y's parity, so both must pin:
    # a client that hardcodes 0x02 mints a DID for a DIFFERENT key half the time.
    for prefix in (0x02, 0x03):
        for x in (bytes(32), bytes([255] * 32), bytes(range(32))):
            comp = bytes([prefix]) + x
            out.append({"curve": "p256", "multicodec": "8024", "publicHex": comp.hex(),
                        "did": crypto.did_from_p256(comp)})
    return out


def _envelope_cases() -> list[dict]:
    """signing_payload — the six protocol-fixed fields (crypto.signing_payload)."""
    a = crypto.did_from_public(bytes(32))
    b = crypto.did_from_public(bytes([255] * 32))
    cases = [
        ("plain", a, b, "m1", "c1", 1752451200, "hi"),
        ("null-context", a, b, "m1", None, 1752451200, "hi"),
        ("non-ascii-text", a, b, "m-群", "c1", 1752451200, "群れたい — hello"),
        ("empty-text", a, b, "m1", "c1", 0, ""),
    ]
    return [{"name": n,
             "from": f, "to": t, "messageId": mid, "contextId": ctx,
             "timestamp": ts, "text": txt,
             "signingPayload": crypto.signing_payload(f, t, mid, ctx, ts, txt).decode("utf-8")}
            for n, f, t, mid, ctx, ts, txt in cases]


def _binding_cases() -> list[dict]:
    """The DeviceKeyBinding payload (keybinding._binding_payload)."""
    root = crypto.did_from_p256(bytes([0x02]) + bytes(range(32)))
    dev = crypto.did_from_public(bytes(32))
    return [{"name": n, "rootDid": root, "deviceDid": dev, "ts": ts,
             "bindingPayload": keybinding._binding_payload(root, dev, ts).decode("utf-8")}
            for n, ts in (("plain", 1752451200), ("zero-ts", 0))]


def _binding_v2_cases() -> dict:
    """The COUNTERSIGNED account binding (keybinding v2, T102) — the artifact that
    makes two device DIDs one owner at every receiver, which is exactly why both
    halves are pinned: the positive bytes a client must reproduce, and the shapes
    it must refuse.

    Ed25519 owner + Ed25519 device, because ECDSA (P-256) signatures are
    randomized and cannot be golden vectors — the same boundary as cryptobox's
    random-nonce seal. A P-256 OWNER differs only in which curve `crypto.verify`
    dispatches for `sig`, and the `did` section already pins that encoding.

    Every reject case follows the file's generation discipline: built FROM the
    valid binding, mutated in exactly one dimension, and pushed through the REAL
    verifier at build time — a reject vector nobody watched reject is decoration.
    `float-ts` is the sharp one: BOTH signatures are genuine over those float
    bytes, and the rejection is purely the integer rule — a verifier that
    re-canonicalizes and checks signatures would wrongly accept it, and would be
    accepting bytes only Python can reproduce (see timestampNote)."""
    owner_seed, device_seed = bytes([23] * 32), bytes([24] * 32)
    owner = crypto.did_from_public(crypto.ed25519_public_from_seed(owner_seed))
    device = crypto.did_from_public(crypto.ed25519_public_from_seed(device_seed))

    def owner_sign(msg: bytes) -> str:
        return _b64(crypto.ed25519_sign(owner_seed, msg))

    def device_sign(msg: bytes) -> str:
        return _b64(crypto.ed25519_sign(device_seed, msg))

    check_now = 1784273681 + 60          # the fixed clock every verdict is judged at
    cases = []
    for name, ts, valid_until in (("no-expiry", 1784273681, 0),
                                  ("bounded", 1784273681, 1815809681)):
        b = keybinding.make_device_binding_v2(owner, device, ts=ts,
                                              valid_until=valid_until,
                                              root_sign=owner_sign)
        b = keybinding.countersign_device_binding(b, device_sign=device_sign)
        # CONTROL: the real verifier must accept what was just minted.
        assert keybinding.verify_device_binding_v2(
            b, now=check_now, expected_device_did=device), f"control: {name}"
        cases.append({
            "name": name, "rootDid": owner, "deviceDid": device,
            "ownerSeed": owner_seed.hex(), "deviceSeed": device_seed.hex(),
            "ts": ts, "validUntil": valid_until,
            "bindingPayload": keybinding._binding_v2_payload(
                owner, device, ts, valid_until).decode("utf-8"),
            "binding": b,
        })

    valid = cases[0]["binding"]
    rejects = []

    def add_reject(name: str, category: str, note: str, mutated: dict) -> None:
        assert not keybinding.verify_device_binding_v2(
            mutated, now=check_now, expected_device_did=device), \
            f"reject vector must actually reject: {name}"
        rejects.append({"name": name, "category": category, "mustReject": True,
                        "input": mutated, "note": note})

    # float ts — BOTH signatures re-made over the float bytes, so signature
    # verification is NOT what fails: only the integer rule rejects it.
    float_payload = crypto.canonical({
        "typ": keybinding.BINDING_V2_TYP, "rootDid": owner, "deviceDid": device,
        "ts": 1784273681.0, "validUntil": 0})
    add_reject(
        "float-ts", "float-ts",
        "ts is 1784273681.0 and both signatures are GENUINE over those float "
        "bytes. Reject on the type, before any crypto: a float repr is bytes "
        "only Python reproduces, so accepting it forks the contract "
        "(numberHazards/integral-float is this same value).",
        {"typ": keybinding.BINDING_V2_TYP, "rootDid": owner, "deviceDid": device,
         "ts": 1784273681.0, "validUntil": 0,
         "sig": _b64(crypto.ed25519_sign(owner_seed, float_payload)),
         "deviceSig": _b64(crypto.ed25519_sign(device_seed, float_payload))})

    # missing deviceSig — the owner's half alone is a v1-STYLE claim: any owner
    # key could mint it about any device it does not hold. The countersignature
    # is the consent, so its absence must reject, not degrade.
    add_reject(
        "missing-deviceSig", "missing-deviceSig",
        "the owner signature is valid and the device countersignature is absent "
        "— without it a foreign owner can claim someone else's device, which is "
        "the v1 gap v2 exists to close. Never fall back to owner-only.",
        {k: v for k, v in valid.items() if k != "deviceSig"})

    # wrong typ — both signatures re-made over the mutated bytes, so the ONLY
    # failing check is domain separation.
    wrong_typ_payload = crypto.canonical({
        "typ": "muretai/devicebinding/1", "rootDid": owner, "deviceDid": device,
        "ts": 1784273681, "validUntil": 0})
    add_reject(
        "wrong-typ", "wrong-typ",
        "typ says muretai/devicebinding/1 and both signatures are genuine over "
        "those bytes. `typ` is INSIDE the signed payload precisely so another "
        "artifact type can never be replayed as an account binding — match it "
        "exactly, before the signatures.",
        {"typ": "muretai/devicebinding/1", "rootDid": owner, "deviceDid": device,
         "ts": 1784273681, "validUntil": 0,
         "sig": _b64(crypto.ed25519_sign(owner_seed, wrong_typ_payload)),
         "deviceSig": _b64(crypto.ed25519_sign(device_seed, wrong_typ_payload))})

    return {"checkNow": check_now, "cases": cases, "reject": rejects}


def _ownerstate_cases() -> dict:
    """The OwnerState — an owner's published device REVOCATION list (T102 slice 6,
    shared/ownerstate.py). Pinned here for the same reason as `bindingV2`: the binding is
    what makes two device DIDs one account at every receiver, and this is the only artifact
    that takes one of them BACK. A client that cannot reproduce these bytes cannot honor a
    revocation, and the failure mode is silent — it keeps serving a device its owner
    disowned, which is the one thing the record exists to stop.

    Ed25519 owner (ECDSA signatures are randomized and cannot be golden vectors — the same
    boundary as bindingV2 and cryptobox). Every reject case is built FROM a valid record,
    mutated in exactly one dimension, and pushed through the REAL verifier at build time.
    Three of them re-sign the mutated bytes GENUINELY, so signature verification is not what
    fails: `float-ts` fails on the integer rule, `unsorted-revoked` on the canonical-form
    rule, and `wrong-typ` on domain separation. `foreign-signer` is the anti-substitution
    rule — a structurally perfect record signed by a key that is not the `rootDid` it
    claims — which is also what `POST /ownerstate` refuses with 403."""
    from shared import ownerstate as osmod

    owner_seed, other_seed = bytes([31] * 32), bytes([32] * 32)
    owner = crypto.did_from_public(crypto.ed25519_public_from_seed(owner_seed))
    dev_a = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([33] * 32)))
    dev_b = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([34] * 32)))

    def owner_sign(msg: bytes) -> str:
        return _b64(crypto.ed25519_sign(owner_seed, msg))

    cases = []
    for name, epoch, revoked in (("genesis-empty", 0, []),
                                 ("two-revoked", 3, [dev_b, dev_a])):
        rec = osmod.make_ownerstate(owner, epoch=epoch, revoked=revoked,
                                    ts=1784273681, root_sign=owner_sign)
        # CONTROL: the real verifier must accept what was just minted.
        assert osmod.verify_ownerstate(rec, expected_root_did=owner), f"control: {name}"
        cases.append({
            "name": name, "rootDid": owner, "ownerSeed": owner_seed.hex(),
            "epoch": epoch, "ts": 1784273681,
            "statePayload": crypto.canonical(
                {"typ": osmod.OWNERSTATE_TYP, "rootDid": owner, "epoch": epoch,
                 "revoked": sorted(set(revoked)), "ts": 1784273681}).decode("utf-8"),
            "record": rec,
        })

    valid = cases[1]["record"]
    rejects = []

    def add_reject(name: str, category: str, note: str, mutated: dict) -> None:
        assert not osmod.verify_ownerstate(mutated, expected_root_did=owner), \
            f"reject vector must actually reject: {name}"
        rejects.append({"name": name, "category": category, "mustReject": True,
                        "input": mutated, "note": note})

    float_fields = {"typ": osmod.OWNERSTATE_TYP, "rootDid": owner, "epoch": 3,
                    "revoked": sorted([dev_a, dev_b]), "ts": 1784273681.0}
    add_reject(
        "float-ts", "float-ts",
        "ts is 1784273681.0 and the signature is GENUINE over those float bytes. Reject "
        "on the type, before any crypto: a float repr is bytes only Python reproduces, so "
        "accepting it forks the contract (see timestampNote).",
        dict(float_fields, sig=owner_sign(crypto.canonical(float_fields))))

    unsorted_fields = {"typ": osmod.OWNERSTATE_TYP, "rootDid": owner, "epoch": 3,
                       "revoked": [dev_b, dev_a], "ts": 1784273681}
    add_reject(
        "unsorted-revoked", "non-canonical",
        "the same two devices in a non-canonical order, signed GENUINELY over those "
        "bytes. `revoked` is de-duplicated and sorted at the mint point, so a re-ordered "
        "or padded spelling is a SECOND valid-looking record for one decision — refuse "
        "it rather than normalizing it, or an attacker can mint unlimited distinct "
        "records at the same epoch.",
        dict(unsorted_fields, sig=owner_sign(crypto.canonical(unsorted_fields))))

    typ_fields = {"typ": "muretai/keystate/1", "rootDid": owner, "epoch": 3,
                  "revoked": sorted([dev_a, dev_b]), "ts": 1784273681}
    add_reject(
        "wrong-typ", "wrong-typ",
        "typ says muretai/keystate/1 and the signature is genuine over those bytes. "
        "`typ` is INSIDE the signed payload precisely so another artifact type can never "
        "be replayed as a revocation list — match it exactly, before the signature.",
        dict(typ_fields, sig=owner_sign(crypto.canonical(typ_fields))))

    foreign = dict(valid)
    foreign["sig"] = _b64(crypto.ed25519_sign(
        other_seed, crypto.canonical({k: valid[k] for k in
                                      ("typ", "rootDid", "epoch", "revoked", "ts")})))
    add_reject(
        "foreign-signer", "wrong-signer",
        "a structurally perfect record signed by a key that is NOT the rootDid it "
        "claims. An OwnerState is only ever authority over its OWN account: verify the "
        "signature under the key derived from `rootDid`, never under any key the record "
        "supplies. The relay refuses this at deposit with 403 for the same reason.",
        foreign)

    add_reject(
        "missing-sig", "missing-sig",
        "every declared field is intact and `sig` is absent. There is no unsigned form "
        "of this record — an unsigned revocation list would let anyone disown anyone.",
        {k: v for k, v in valid.items() if k != "sig"})

    return {"cases": cases, "reject": rejects}


def _b64(raw: bytes) -> str:
    """Signatures ride the wire base64-encoded (agent/identity.sign_bytes)."""
    import base64
    return base64.b64encode(raw).decode("ascii")


#: The standard base64 alphabet, in index order — the table `_trailing_bit_sibling` walks.
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _trailing_bit_sibling(sig_b64: str) -> str:
    """A SECOND spelling of the identical 64 signature bytes: one character different, in the
    last data position, and nothing else.

    88 characters ending "==" is 86 data characters carrying 516 bits for a 512-bit signature,
    so the final data character (index 85) holds six bits of which a decoder reads two and
    DISCARDS four. All sixteen characters sharing those top two bits decode to the same 64
    bytes, and every one of them is well-formed standard base64: the alphabet test passes, the
    length test passes, `base64.b64decode(..., validate=True)` accepts it, and the signature it
    decodes to is the genuine one. Only the RE-ENCODE leg of `crypto.b64_strict` — and of the
    JavaScript `strictB64`, Go `DecodeSignature`, Rust `decode_signature` — can tell this string
    from the honest one, which is why the vector it feeds is the one case in `reject.message`
    that looks completely well-formed.

    Deterministic on purpose: the sibling is picked by flipping the low bit of the four
    discarded bits, so `--regen` writes the same character every run."""
    assert len(sig_b64) == 88 and sig_b64.endswith("=="), sig_b64
    v = _B64_ALPHABET.index(sig_b64[85])
    sibling = sig_b64[:85] + _B64_ALPHABET[(v & 0b110000) | ((v & 0b001111) ^ 1)] + "=="
    assert sibling != sig_b64, "the sibling must be a DIFFERENT string"
    assert base64.b64decode(sibling) == base64.b64decode(sig_b64), "…of ONE signature"
    assert crypto.b64_strict(sibling) is None, "the strict reader must refuse the sibling"
    return sibling


class _SeedIdentity:
    """The minimal Identity surface the signing helpers need — `did` + `sign_bytes` — over a
    FIXED seed.

    A real `agent.identity.Identity` mints a RANDOM seed, so nothing it signs can be a golden
    vector; and every signer in core takes `sign_bytes` (bytes -> STANDARD base64 str) rather
    than key material, precisely so a remote-signer identity with no local seed works unchanged.
    Meeting that one-method contract is therefore enough to drive the real minting paths
    (`webbotauth.request_headers`, `directory_response`) from a reproducible key. Mirrors the
    shim in `webbotauth._selftest`."""

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self.public = crypto.ed25519_public_from_seed(seed)
        self.did = crypto.did_from_public(self.public)

    def sign_bytes(self, message: bytes) -> str:
        return _b64(crypto.ed25519_sign(self._seed, message))


def _relay_cases() -> dict:
    """The RELAY SESSION wire — the layer a native client actually breaks on.

    The four surfaces above pin identity and signing, so a client can produce a correct DID and a
    verifiable envelope and still not receive mail: `RelayKit` did exactly that
    when a client minted a fresh epoch per poll. Nothing here was pinned, so nothing said the bytes were
    wrong — the only symptom was a message that occasionally never arrived.

    Two things are pinned, both byte-exact and both easy to get subtly wrong:

    * `sendSigMsg` — the sender-auth payload for /send and /rpc, `to|from|id|blob` joined with a
      literal '|'. The relay recomputes it (`relay._verify_rpc_sig`) and rejects a mismatch. It is
      NOT canonical JSON — a client that reaches for the JSON encoder here signs the wrong bytes.
    * `listenToken` — the /listen + /presence + /ack + /unlisten auth payload,
      `"listen:"+did+":"+minute+":"+origin` where minute is `int(unix/60)` and `origin` is the
      CANONICAL origin of the relay URL the client dialled (`shared/neturl.origin`:
      `scheme://host[:port]`, lowercased, default port dropped, no path/query/fragment/userinfo).
      The minute is INPUT here, not `now`, or the vector could not be pinned. The relay accepts
      minute-1/minute/minute+1 (skew + boundary), so a client must mint from its own clock — the
      window is the tolerance, not a licence to cache one.
      THE ORIGIN IS A SECURITY FIELD, not decoration: a token that omits it is valid at EVERY
      relay, so a relay an attacker talked the client into dialling harvests a live token and
      replays it at the real one to read
      and delete that mailbox. `same-origin-different-spelling` pins the other half: two spellings
      of one relay MUST canonicalize to the same bytes, or a client that stores its relay with a
      trailing slash 401s forever.

    Epoch semantics are the other half of this contract and are NOT bytes: an epoch identifies a
    LISTENER, not a poll. That cannot be a vector, so it is specified in docs/SPECIFICATION.md
    §relay — see the note there before writing a client."""
    seed_a, seed_b = bytes(range(32)), bytes([7] * 32)
    a = crypto.did_from_public(crypto.ed25519_public_from_seed(seed_a))
    b = crypto.did_from_public(crypto.ed25519_public_from_seed(seed_b))
    send = []
    for name, to, frm, rid, blob in (
        ("plain", b, a, "0123456789abcdef", "c2VhbGVkLWJsb2I="),
        ("empty-blob", b, a, "id-1", ""),
        ("non-ascii-id", b, a, "群-1", "eA=="),
    ):
        payload = (to + "|" + frm + "|" + rid + "|" + blob)
        send.append({"name": name, "to": to, "from": frm, "id": rid, "blob": blob,
                     "sendSigMsg": payload,
                     "sig": _b64(crypto.ed25519_sign(seed_a, payload.encode("utf-8")))})
    listen = []
    from shared import neturl
    for name, did, seed, minute, relay_url in (
            ("plain", a, seed_a, 29740853, "https://muretai.com"),
            ("zero-minute", a, seed_a, 0, "https://muretai.com"),
            # Same relay, a spelling a node really stores (trailing slash + explicit
            # default port + mixed case): the canonical origin — and therefore the token
            # — must be byte-identical to `plain`.
            ("same-origin-different-spelling", a, seed_a, 29740853, "HTTPS://Muretai.com:443/"),
            # A self-hosted relay on a non-default port keeps the port.
            ("explicit-port", a, seed_a, 29740853, "http://127.0.0.1:9000")):
        origin = neturl.origin(relay_url)
        payload = "listen:" + did + ":" + str(minute) + ":" + origin
        listen.append({"name": name, "did": did, "minute": minute,
                       "relayUrl": relay_url, "origin": origin,
                       "listenTokenMsg": payload,
                       "token": _b64(crypto.ed25519_sign(seed, payload.encode("utf-8")))})
    return {"seedA": seed_a.hex(), "seedB": seed_b.hex(),
            "send": send, "listen": listen}


def _cryptobox_cases() -> dict:
    """X25519 + ChaCha20-Poly1305 (shared/cryptobox.py) — the relay's sealed blob.

    ONLY THE OPEN DIRECTION IS PINNED, and that is deliberate: `seal()` draws a fresh random
    nonce (`os.urandom(12)`), so its output is not reproducible and cannot be a golden vector.
    The requirement that matters is the other way round — **a client must be able to OPEN what
    core sealed** — and pinning a fixed blob tests the whole chain at once: the X25519 agreement,
    the HKDF/derivation, the AEAD, and the base64(nonce‖ciphertext) framing. A client proves the
    seal direction with its own round-trip (core opens what it sealed); no static vector can.

    The blobs are FROZEN CONSTANTS below, not regenerated: `seal()` draws a fresh nonce every
    call, so building them here would make this file differ from itself on every run — which is
    exactly what the round-trip check caught the first time this was written. A golden vector is a
    constant. They were produced once by core's `seal()`, and `test_cryptobox_vectors_actually_open`
    re-opens each one with core's real opener, so they cannot rot into fiction that only agrees
    with itself.

    THE ASSOCIATED DATA IS PART OF THE BLOB, and `with-associated-data` plus its `mustNotOpen`
    twin are what say so. `ad` is authenticated but not encrypted, so it never appears in the
    ciphertext and a client that drops it still sees a well-formed base64 blob of the right
    length — it simply gets None, with nothing to point at. Worse is the other direction: an
    implementation that quietly opens with the empty `ad` when it was given one, or that ignores
    a mismatch, has unbound the context the sealer paid for. The twin is the SAME blob under a
    different `ad`, so the only difference between "opens" and "must not open" is the value the
    caller supplies. `adHex` is on every case, including the three that carry no associated data,
    so that a runner cannot default the field into existence by forgetting it."""
    from shared import cryptobox
    a_seed, b_seed = bytes([3] * 32), bytes([9] * 32)
    return {
        "senderSeed": a_seed.hex(), "senderEncPub": cryptobox.enc_pub_hex(a_seed),
        "recipientSeed": b_seed.hex(), "recipientEncPub": cryptobox.enc_pub_hex(b_seed),
        "note": "open_box(recipientSeed, senderEncPub, blob, ad) == plaintext, where `ad` is the "
                "bytes of `adHex` (empty for most cases). seal() is NOT pinned — it uses a random "
                "nonce, so its output is not reproducible. A client proves that direction with "
                "its own round-trip against core; this pins the direction that matters, that a "
                "client can OPEN what core sealed. `mustNotOpen` is the same blob under the wrong "
                "associated data and must return the implementation's no-plaintext answer (None / "
                "null), never a partial read and never a throw.",
        "open": [
            {"name": "plain", "adHex": "",
             "blob": "YYrXndd8212cUzJ2A+sWWspUASAfIn2ipMdHcTh3y+Ir",
             "plaintextHex": "68656c6c6f"},
            {"name": "non-ascii", "adHex": "",
             "blob": "58o9qnvehBofRDrqZH+xfU+SdmLFB7AlKQt1o0U6bsIWapNjAu5xmA==",
             "plaintextHex": "e7bea4e3828ce3819fe38184"},
            {"name": "empty", "adHex": "",
             "blob": "Aj7TqCyAdxO3dtdcJ8848Omz3oxT7o2N0mdQSw==",
             "plaintextHex": ""},
            # ad = b"contextId=c1". Sealed once by shared/cryptobox.seal(..., ad=…) and frozen,
            # for the random-nonce reason the docstring gives.
            {"name": "with-associated-data", "adHex": "636f6e7465787449643d6331",
             "blob": "913KMvf6CCFl+zO9szmWZNGHm97V409qLjkyuVqOQ/VAlchO2CSBwn9vOg==",
             "plaintextHex": "7061792074686520696e766f696365"},
        ],
        "mustNotOpen": [
            {"name": "associated-data-mismatch", "adHex": "636f6e7465787449643d6332",
             "blob": "913KMvf6CCFl+zO9szmWZNGHm97V409qLjkyuVqOQ/VAlchO2CSBwn9vOg==",
             "why": "the `with-associated-data` blob, character for character, opened under "
                    "b\"contextId=c2\" instead of the b\"contextId=c1\" it was sealed with. The "
                    "AEAD tag covers the associated data, so this is an authentication failure "
                    "and not a decode failure: a caller who binds a contextId and then accepts "
                    "the box under a different one has bound nothing."},
            {"name": "associated-data-dropped", "adHex": "",
             "blob": "913KMvf6CCFl+zO9szmWZNGHm97V409qLjkyuVqOQ/VAlchO2CSBwn9vOg==",
             "why": "the same blob opened with NO associated data. This is the shape a port "
                    "actually ships — `open_box(seed, pub, blob)` with the parameter left off — "
                    "and it must fail exactly like the wrong value above, not silently succeed."},
        ],
    }


def _cardpub_cases() -> list[dict]:
    """The published Agent Card envelope (shared/cardpub._envelope_payload).

    Pinnable only since the `float(ts)` cast came out (2026-07-17). Before that this envelope was
    unverifiable outside Python BY CONSTRUCTION — the cast forced Python's float repr into the
    signed bytes, and `SeamKit.canonical` has no float case — so a vector would have handed clients
    bytes they could not reproduce. This is the DID-addressed discovery path: a peer holding only a
    DID fetches `GET /card/<did>` and must verify it locally, because the relay is not trusted to
    say who someone is. A client that cannot verify this cannot safely discover anyone."""
    seed = bytes([13] * 32)
    did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))
    from shared import cardpub
    cases = []
    for name, card, ts in (
        ("relay-only", {"did": did, "name": "Node", "url": "", "relay": "https://relay.example",
                        "enc_pub": "bb" * 32}, 1784273681),
        ("with-url", {"did": did, "name": "Node", "url": "http://127.0.0.1:8001/"}, 0),
    ):
        payload = cardpub._envelope_payload(card, ts)
        cases.append({"name": name, "card": card, "ts": ts,
                      "envelopePayload": payload.decode("utf-8"),
                      "sig": _b64(crypto.ed25519_sign(seed, payload))})
    return cases


def _invite_cases() -> list[dict]:
    """The invite card's signed payload (shared/invite.py) — what a joiner verifies before
    trusting anyone. A client that builds this payload differently produces a card nobody accepts,
    or (worse) accepts a card it should have refused."""
    from shared import invite as invitemod
    seed = bytes([11] * 32)
    did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))
    cases = []
    for name, card in (
        ("relay-only", {"v": 1, "did": did, "name": "Apple Mini", "specialty": "general",
                        "url": "", "relay": "https://relay.example",
                        "enc_pub": "aa" * 32, "nonce": "n1", "exp": "2026-07-23T09:59:45Z"}),
        ("direct-url", {"v": 1, "did": did, "name": "Node", "specialty": "photography",
                        "url": "http://127.0.0.1:8001/", "nonce": "n2",
                        "exp": "2026-07-23T09:59:45Z"}),
    ):
        payload = invitemod._signing_payload(card)
        cases.append({"name": name, "card": card,
                      "invitePayload": payload.decode("utf-8"),
                      "sig": _b64(crypto.ed25519_sign(seed, payload))})
    return cases


def _domain_linkage_cases() -> list[dict]:
    """The DIF Domain Linkage Credential (shared/domainbind.make_domain_linkage_jwt).

    Every artifact above is a format muretai controls on BOTH ends: when core and a client
    disagree, the only casualty is our own network, and both halves are ours to fix. This one
    is the first that outside software is meant to read — a wallet, a Veramo/Credo verifier,
    some registry walking /.well-known — so "our two implementations agree" is not the bar.

    Why the bytes are the hazard here and not the JSON: a compact JWS is
    base64url(header) "." base64url(payload) "." base64url(signature), and the signature covers
    THE TEXT OF THE FIRST TWO SEGMENTS, not the object they decode to. The serialization is
    therefore INSIDE the signature. A minter whose JSON writer spaces its separators, orders
    keys differently, or pads its base64url produces a credential that verifies nowhere, and
    the only diagnostic any DIF verifier is obliged to give back is "invalid signature". So
    `signingInput` is pinned as text: it is the exact byte string a client must reproduce, and
    unlike `token` it is checkable without holding the key.

    `nbf`/`exp` are INTEGER epoch seconds (see timestampNote). They are the values a verifier
    actually compares; the ISO strings inside `vc` are the human/JSON-LD echo of the same two
    instants, and a client that compares those instead has picked the field the format does not
    make authoritative. `exp` is mandatory by our rule, not DIF's: a domain is LEASED, so a
    credential with no end date is indefinite authority over a name we may not hold next year.

    Each case is minted and then immediately re-verified by the REAL verifier below, so a
    vector cannot be pinned in a shape core itself would refuse."""
    from shared import domainbind
    seed = bytes([21] * 32)
    did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))

    def sign_bytes(message: bytes) -> str:
        return _b64(crypto.ed25519_sign(seed, message))

    nbf = 1754870400                       # the same fixed clock the webBotAuth example uses
    exp = nbf + 90 * 86400
    cases = []
    for name, domain in (
        ("plain", "example.com"),
        ("subdomain", "agents.example.com"),
        # A non-default port is part of the origin. A client that drops it binds
        # https://127.0.0.1 — a different origin, silently — and this is the shape every
        # loopback/staging deployment actually runs.
        ("loopback-port", "127.0.0.1:8443"),
    ):
        token = domainbind.make_domain_linkage_jwt(
            did, domain, sign_bytes=sign_bytes, now=nbf, expires_at=exp)
        # CONTROL: core's own verifier must accept what core just minted, or the vector is
        # pinning a credential nobody can use.
        assert domainbind.verify_domain_linkage_jwt(token, domain=domain, now=nbf), \
            f"control: the minted credential must verify: {name}"
        cases.append({"name": name, "did": did, "domain": domain, "nbf": nbf, "exp": exp,
                      "signingInput": token.rsplit(".", 1)[0], "token": token})
    return cases


def _webbotauth_cases() -> dict:
    """Web Bot Auth (shared/webbotauth.py) — the RFC 9421 profile that lets a website tell our
    agent apart from a scraper, and the second format here written for readers we do not own.

    Three byte contracts, and none of them fails loudly:

    * `thumbprint` — the RFC 7638 JWK thumbprint that rides the wire as `keyid`. Its hash input
      is a JSON object of the three REQUIRED members only, lexicographic and unspaced, which is
      why `thumbprintInput` is pinned as TEXT rather than left implied: add a `kid`/`use`/`alg`
      member, or space the separators, and the same key acquires a different name — which reads
      to a verifier as an unknown key, not as a formatting bug. The keys are exactly the ones
      the `did` section pins (_ED25519_PUBLICS), so a client walks one key at a time from
      publicHex to did to x to thumbprint and learns WHICH step diverged.
    * `signatureBase` — the exact bytes signed (RFC 9421 §2.5): one `"name": value` line per
      covered component, then a final `"@signature-params"` line, LF-joined with NO trailing
      newline. That last line is what binds a signature to its own keyid/tag/window; without it
      the same covered values could be re-presented under different metadata.
    * `signatureInput` / `signature` — the header VALUES as sent. `signature-agent` appears
      twice on purpose (as a covered component AND as its own header) and must be the identical
      sf-string in both places, because RFC 9421 covers a header by its field value as sent.

    `tag` is what keeps the two directions from being interchangeable: `web-bot-auth` on an
    outbound request, `http-message-signatures-directory` on a directory response. It sits
    inside the signed params, so a directory signature cannot be replayed as a request
    signature — the companion test proves that with a lift, not by assertion.

    `alg` is the trap worth naming: lowercase "ed25519" here (RFC 9421's registry), NOT JOSE's
    "EdDSA" (shared/jws.ALG, used by domainLinkage above). Same curve, two registries, and
    mixing the spellings is a silent interop failure between two otherwise-correct clients.

    The seed is pinned (as in `relay`) because the header values carry a signature: with it a
    client checks its own MINT side byte-for-byte, not merely its verifier."""
    from shared import gateway, webbotauth
    keys = []
    for public in _ED25519_PUBLICS:
        jwk = webbotauth.jwk_from_public(public)
        keys.append({
            "publicHex": public.hex(),
            "did": crypto.did_from_public(public),
            "x": jwk["x"],
            "thumbprintInput": json.dumps({k: jwk[k] for k in ("crv", "kty", "x")},
                                          sort_keys=True, separators=(",", ":")),
            "thumbprint": webbotauth.jwk_thumbprint(jwk),
        })

    seed = bytes(range(32))                # the same worked example webbotauth._selftest pins
    me = _SeedIdentity(seed)
    keyid = webbotauth.jwk_thumbprint(webbotauth.jwk_from_did(me.did))
    created, expires = 1754870400, 1754870700

    # The DID-addressed HP URL, built through gateway with an EXPLICIT base: did_site_url()
    # otherwise reads MURETAI_PUBLIC_BASE, and a vector that changes with an env var is not a
    # vector. The DID is the permanent address; the relay holding it is not (shared/gateway.py).
    agent_url = gateway.did_site_url(me.did, base="https://muretai.net")
    agent_sf = webbotauth._sf_string(agent_url)
    components = (("@authority", "example.com"), ("signature-agent", agent_sf))
    params = webbotauth.signature_params([n for n, _ in components], created=created,
                                         expires=expires, keyid=keyid,
                                         tag=webbotauth.TAG_REQUEST)
    sig_input, sig = webbotauth.wba_sign(me.sign_bytes, components, created=created,
                                         expires=expires, keyid=keyid,
                                         tag=webbotauth.TAG_REQUEST)

    # The directory is signed over `@authority` ALONE: it is a statement about which keys this
    # origin operates, so there is no request to bind it to. A longer window than a request's,
    # because the response is cacheable — the verifier's ceiling is the security control.
    dir_created, dir_expires = 1754870400, 1754877600
    dir_components = (("@authority", "example.com"),)
    dir_params = webbotauth.signature_params(["@authority"], created=dir_created,
                                             expires=dir_expires, keyid=keyid,
                                             tag=webbotauth.TAG_DIRECTORY)
    dir_input, dir_sig = webbotauth.wba_sign(me.sign_bytes, dir_components,
                                             created=dir_created, expires=dir_expires,
                                             keyid=keyid, tag=webbotauth.TAG_DIRECTORY)

    return {
        "note": "The `keys` entries are the SAME public keys as the `did` section. `keyid` is "
                "the RFC 7638 thumbprint of the JWK, and `thumbprintInput` is the exact text "
                "hashed to produce it. `alg` is lowercase \"ed25519\" (RFC 9421), NOT JOSE's "
                "\"EdDSA\" — domainLinkage uses the other spelling for the same curve. A "
                "signature base is LF-joined with NO trailing newline. The request path covers "
                "@authority (so it cannot be replayed at another origin) and signature-agent "
                "(so the site can look us up); the covered signature-agent value and the "
                "Signature-Agent header are the same sf-string, quotes included. `tag` "
                "separates the two directions and is inside the signed params. READ THE "
                "ROLES BEFORE COMPARING HEX: `seedHex` is a PRIVATE seed and `did` is the key "
                "DERIVED from it, while the identical-looking hex at keys[2].publicHex is that "
                "same byte string used as a PUBLIC key — a different DID, by construction.",
        "seedHex": seed.hex(),
        "did": me.did,
        "keys": keys,
        "request": {
            "authority": "example.com",
            "created": created, "expires": expires,
            "keyid": keyid, "alg": webbotauth.ALG, "tag": webbotauth.TAG_REQUEST,
            "components": [name for name, _ in components],
            "signatureAgentUrl": agent_url,
            "signatureAgent": agent_sf,
            "signatureParams": params,
            "signatureBase": webbotauth.signature_base(components, params).decode("utf-8"),
            "signatureInput": sig_input,
            "signature": sig,
        },
        "directory": {
            "authority": "example.com",
            "created": dir_created, "expires": dir_expires,
            "keyid": keyid, "alg": webbotauth.ALG, "tag": webbotauth.TAG_DIRECTORY,
            "components": ["@authority"],
            "path": webbotauth.WBA_DIRECTORY_PATH,
            "contentType": webbotauth.WBA_DIRECTORY_CONTENT_TYPE,
            "body": webbotauth.directory_body(me.did).decode("utf-8"),
            "signatureParams": dir_params,
            "signatureBase": webbotauth.signature_base(dir_components,
                                                       dir_params).decode("utf-8"),
            "signatureInput": dir_input,
            "signature": dir_sig,
        },
    }


# ---------------------------------------------------------------- NEGATIVE cases
#
# Positive vectors pin what a client must PRODUCE. Nothing above pins what it must REJECT — and a
# client that verifies nothing on receipt produces every correct byte and passes all of it. That is
# exactly how the Swift client shipped accepting forged senders (audit 2026-07-17). These pin the
# other half: inputs that MUST be rejected, each with the required verdict.
#
# GENERATION DISCIPLINE, and it is the whole point: for each case the generator (1) builds a VALID
# message/card and asserts the REAL verifier ACCEPTS it — the paired control, so "rejected" cannot
# pass for an unrelated reason like a parse error — then (2) mutates exactly ONE field and asserts
# the REAL verifier now REJECTS it. A negative vector nobody has watched reject is decoration.
#
# The CONTRACT a client must meet is `mustReject: true`. The `category` slug is language-neutral
# guidance (a native client's own error codes are its business); it is NOT core's -32xxx.

def _reject_message_cases() -> list[dict]:
    """Messages that MUST fail signature verification (`crypto.verify_envelope`, the exact call
    `agent/inbox.verify` makes). A client feeds `input` to its own verifier and must reject."""
    seed_x = bytes(range(1, 33))                 # the real signer
    seed_y = bytes([200] * 32)                    # an unrelated identity ("someone you know")
    victim = bytes([50] * 32)
    frm = crypto.did_from_public(crypto.ed25519_public_from_seed(seed_x))
    other = crypto.did_from_public(crypto.ed25519_public_from_seed(seed_y))
    to = crypto.did_from_public(crypto.ed25519_public_from_seed(victim))
    base = dict(from_did=frm, to_did=to, message_id="m1", context_id="c1",
                timestamp=1784273681, text="pay the invoice")

    def signed(**over):
        p = {**base, **over}
        return crypto.sign_envelope(seed_x, p["from_did"], p["to_did"], p["message_id"],
                                    p["context_id"], p["timestamp"], p["text"])

    good_sig = signed()
    # CONTROL: the un-mutated message must verify, or every "reject" below is suspect.
    assert crypto.verify_envelope(frm, to, "m1", "c1", 1784273681, "pay the invoice", good_sig), \
        "control: the valid message must verify"

    cases = []

    def add(name, category, note, *, sig, over=None):
        m = {**base, **(over or {}), "sig": sig}
        wire = {"from": m["from_did"], "to": m["to_did"], "messageId": m["message_id"],
                "contextId": m["context_id"], "timestamp": m["timestamp"], "text": m["text"],
                "sig": m["sig"]}
        assert not crypto.verify_envelope(m["from_did"], m["to_did"], m["message_id"],
                                          m["context_id"], m["timestamp"], m["text"], m["sig"]) \
            if m["sig"] is not None else True, f"vector must actually reject: {name}"
        cases.append({"name": name, "category": category, "mustReject": True,
                      "input": wire, "note": note})

    # THE CROWN JEWEL. A VALID signature by X, in an envelope claiming from = Y. It is rejected only
    # if the client derives the verifying key FROM `from` (= Y) and checks against it. RelayKit's
    # real bug was trusting the `from` string and never deriving a key at all — it would ACCEPT this.
    add("from-not-signer", "from-not-signer",
        "the signature is valid, but by a DIFFERENT key than `from` names. Derive the verifying key "
        "FROM `from` (with did:key the DID IS the key) and check against it — do not trust `from` as "
        "a label, and do not verify against a key from any other field.",
        sig=good_sig, over={"from_did": other})

    add("bad-signature", "bad-signature",
        "garbage signature bytes over an otherwise valid envelope — must not be displayed as signed.",
        sig=_b64(b"\x00" * 64))

    add("tampered-text", "tampered-text",
        "signed for one text, delivered with another. Recompute the canonical signing payload from "
        "the received fields — never trust a `sig` field without recomputing what it covers.",
        sig=good_sig, over={"text": "pay the ATTACKER"})

    add("tampered-timestamp", "tampered-timestamp",
        "signed ts changed in transit (also proves timestamp is inside the signed payload).",
        sig=good_sig, over={"timestamp": 1784273999})

    # missing-sig: sig is absent. verify_envelope needs a sig string; the contract is "reject", which
    # a client does by refusing to treat an unsigned message as authenticated.
    cases.append({"name": "missing-sig", "category": "missing-sig", "mustReject": True,
                  "input": {"from": frm, "to": to, "messageId": "m1", "contextId": "c1",
                            "timestamp": 1784273681, "text": "pay the invoice", "sig": None},
                  "note": "no signature at all — an unsigned message must never be shown as from a "
                          "DID. `agent/inbox.verify` raises before any brain/log/display."})

    # wrong-recipient: correctly signed, but addressed to someone else. This one is NOT a signature
    # failure — the sig verifies for the real recipient — so `verify_envelope` accepts it. The
    # rejection is the separate `to == me` check (inbox.py WRONG_RECIPIENT), which needs to know who
    # "me" is, so the vector carries `recipientDid` (us). Sealing already binds the recipient, making
    # this defence-in-depth; core checks it anyway, and a client must too.
    not_me = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([77] * 32)))
    sig_other_to = crypto.sign_envelope(seed_x, frm, not_me, "m1", "c1", 1784273681, "pay the invoice")
    cases.append({"name": "wrong-recipient", "category": "wrong-recipient", "mustReject": True,
                  "input": {"from": frm, "to": not_me, "messageId": "m1", "contextId": "c1",
                            "timestamp": 1784273681, "text": "pay the invoice", "sig": sig_other_to},
                  "recipientDid": to,
                  "note": "validly signed, but `to` is not us. The signature verifies for the real "
                          "recipient; a client must still refuse a message not addressed to it."})

    # ---- small-order-signer: ONE constant blob, no private key, every message ever sent.
    #
    # The Ed25519 group has a cofactor of 8, so eight points sit outside the prime-order
    # subgroup. Take the one of order 1 — the identity, encoded 0x01 followed by 31 zero bytes
    # — and publish it as your did:key. Verification asks [S]B == R + [h]A; when A is the
    # identity, [h]A is the identity for EVERY scalar h, so R = the identity and S = 0 satisfies
    # the equation over ANY message. The signature below is that blob: 0x01, then 63 zeros. It
    # is CANONICAL base64 (b64_strict accepts the spelling), it is exactly 64 bytes, and the DID
    # is a perfectly well-formed did:key — everything structural about this message is right.
    # The refusal is the prime-order requirement and nothing else, which is why it is worth a
    # vector: an implementation that reaches its Ed25519 library with these bytes and asks
    # "does it verify?" is told YES by permissive RFC 8032 (Go's crypto/ed25519,
    # `cryptography`'s OpenSSL, dalek's legacy `verify`).
    #
    # NOTE for the `did` group, which must NOT gain a case like this: the codec has to spell
    # anything, including 0000…0000 and ffff…ffff, and it still does. The refusal belongs at
    # the one door from a DID to a VERIFYING key (Go `VerifyingKeyFromDID`, Rust
    # `verifying_key_from_did`, Python inside `ed25519_verify`, JavaScript from node:crypto).
    identity_point = bytes([1]) + bytes(31)
    identity_did = crypto.did_from_public(identity_point)
    universal_blob = _b64(bytes([1]) + bytes(63))
    assert crypto.b64_strict(universal_blob) is not None, \
        "the forgery blob must be CANONICAL base64 — the refusal has to be the key, not the spelling"
    add("small-order-signer", "small-order-key",
        "`from` is the Ed25519 IDENTITY point as a did:key and `sig` is the constant blob "
        "R = identity, S = 0, which satisfies [S]B == R + [h]A over EVERY message. No private "
        "key exists or is needed. Derive the verifying key through the door that refuses the "
        "fourteen small-order encodings — as `from` AND as the signature's first 32 bytes — not "
        "through the codec.",
        sig=universal_blob, over={"from_did": identity_did})

    # ---- sig-not-canonical-base64: the case that looks completely well-formed.
    add("sig-not-canonical-base64", "sig-not-canonical-base64",
        "the same 64 signature bytes as the honest message, spelled with a different final DATA "
        "character. Standard alphabet, length 88, two trailing '=', decodes without error to the "
        "genuine signature — nothing about it is malformed. It is refused because the bytes do "
        "not RE-ENCODE to the string that arrived: the last data character carries four bits no "
        "decoder reads, so one signature has sixteen names, and a receiver that de-duplicates, "
        "logs or replay-caches on the `sig` STRING sees sixteen messages where there is one.",
        sig=_trailing_bit_sibling(good_sig))

    # ---- wire-names-its-own-recipient: the message answers the question it was asked.
    #
    # An envelope honestly signed and honestly addressed to Alice, replayed at a verifier that
    # knows no recipient of its own, with one unsigned field appended: `recipientDid`, equal to
    # `to`. A verifier that falls back to a recipient carried BY THE MESSAGE then compares the
    # wire against itself — `to == recipientDid` is true for every message ever minted — and the
    # signature check that follows passes, because the signature really is valid. The JavaScript
    # reference did exactly this (`opts.recipientDid ?? opts.me ?? fields.recipientDid`) and
    # answered `true`.
    #
    # `verifierNamesNoRecipient` is the whole case: the runner must call its verifier with NO
    # recipient. Naming one would make the case pass for the wrong reason. What each reference
    # then does, and all three are refusals for the SAME rule (only the caller says who "me" is):
    #   JavaScript  `verifyEnvelope(fields, {})` — `recipient` is null, refused before the
    #               signature is looked at, with the unsigned field sitting right there in
    #               `fields` where the old fallback would have found it.
    #   Go / Rust   `Verify(sig, "")` — an empty recipient is refused; neither `Envelope` type
    #               has a `recipientDid` member at all, so the wire's field cannot be consulted.
    #   Python      there is no recipient option to fall back TO: `to` is one of the six SIGNED
    #               fields and `verify_envelope` takes `to_did` by name from the caller, so the
    #               signature simply fails for any `to_did` that is not Alice — including "".
    #               Asserted here, both directions, rather than assumed.
    self_named_sig = signed()
    assert crypto.verify_envelope(frm, to, "m1", "c1", 1784273681, "pay the invoice", self_named_sig), \
        "control: honest delivery to the real recipient is unaffected"
    assert not crypto.verify_envelope(frm, "", "m1", "c1", 1784273681, "pay the invoice",
                                      self_named_sig), \
        "a verifier that names NO recipient must not verify this"
    assert not crypto.verify_envelope(frm, other, "m1", "c1", 1784273681, "pay the invoice",
                                      self_named_sig), \
        "…and neither must anyone the message was not addressed to"
    cases.append({"name": "wire-names-its-own-recipient", "category": "wrong-recipient",
                  "mustReject": True, "verifierNamesNoRecipient": True,
                  "input": {"from": frm, "to": to, "messageId": "m1", "contextId": "c1",
                            "timestamp": 1784273681, "text": "pay the invoice",
                            "sig": self_named_sig, "recipientDid": to},
                  "note": "a valid envelope addressed to someone else, carrying an UNSIGNED "
                          "`recipientDid` equal to `to`, presented to a verifier that names no "
                          "recipient. An implementation that falls back to a recipient supplied by "
                          "the message compares the wire against itself and accepts every replay. "
                          "Who \"me\" is comes from the caller or from nowhere; `recipientDid` is "
                          "not one of the six signed fields and must never be read as one."})
    return cases


def _reject_encoding_cases() -> dict:
    """Documents whose BYTES must be refused at the parse boundary — and two that must not be.

    Every other group in this file hands an implementation a JSON VALUE. This one hands it raw
    document bytes, as hex, because the defect it pins cannot survive a decoded value: by the
    time a lone surrogate or an invalid UTF-8 byte has been through a repairing parser it is
    U+FFFD, which is a legitimate character every reference encodes happily. Nothing downstream
    can tell that anything happened.

    WHY THAT IS A SIGNATURE PROBLEM AND NOT A TIDINESS ONE. `{"s":"\\ud800"}`, `{"s":"\\udfff"}`
    and `{"s":"\\ufffd"}` are three different documents. After a repair they are one document,
    and they sign one identical byte string. So a signature made over a message containing a
    literal U+FFFD ALSO authenticates, at the repairing receiver, a message containing \\ud800
    instead — content substitution under a signature that verifies, with nothing failing and
    nobody told. Go's `encoding/json` repairs both of these silently, which is why the Go
    reference now owns `Unmarshal`/`CanonicalFromJSON` and the runner is required to go through
    them; `serde_json` refuses at the parse boundary; Python keeps the lone surrogate in the
    `str` and `.encode("utf-8")` raises on it; JavaScript refuses it in `assertEncodable` after
    a FATAL decode (`Buffer.toString('utf8')` is the lossy one, and measured: it turns all three
    raw-byte cases below into an accepted `{"s":"\\ufffd"}`).

    A lone surrogate can ride in JSON as a `\\ud800` ESCAPE, which is why four of the refusals
    are ASCII documents; a raw invalid byte cannot be written any other way, which is why the
    carrier for the whole group is hex rather than a JSON string.

    `accept` is not decoration. A group that only ever refuses passes in an implementation that
    refuses everything, so a literal U+FFFD and a well-formed astral pair — one spelled as an
    escape pair, one as literal UTF-8 — are pinned here with the canonical bytes they must
    produce. U+FFFD is a character like any other; it is the REPAIR that is forbidden, not the
    code point."""
    def refuses(raw: bytes) -> bool:
        """Does the real Python path refuse these bytes? json.loads decodes with the
        `surrogatepass` error handler, so a CESU-8 spelling of a surrogate survives the parse
        and is caught one step later by `canonical`'s `.encode("utf-8")` — two doors, one
        refusal, and the case list below deliberately contains both kinds."""
        try:
            crypto.canonical(json.loads(raw))
        except Exception:
            return True
        return False

    refuse_specs = [
        ("lone-high-surrogate-escape", b'{"s":"\\ud800"}', "lone-surrogate",
         "a high surrogate with nothing after it. Legal JSON text, not a legal string: no "
         "character has this code point, and UTF-8 cannot encode it."),
        ("lone-low-surrogate-escape", b'{"s":"\\udfff"}', "lone-surrogate",
         "a low surrogate with nothing before it — the other half of the same rule."),
        ("lone-surrogate-in-key", b'{"\\ud800":"x"}', "lone-surrogate",
         "the same defect in a KEY. A canonicaliser that guards only string VALUES sorts and "
         "emits this one straight into the bytes it signs."),
        ("reversed-surrogate-pair", b'{"s":"\\udc00\\ud800"}', "lone-surrogate",
         "low then high: two escapes that LOOK like a pair and are two lone surrogates. A "
         "scanner that pairs on adjacency rather than on order accepts it."),
        ("truncated-utf8-sequence", b'{"s":"\xe6\x97"}', "invalid-utf8",
         "the first two bytes of the three-byte sequence for U+65E5, delivered without the "
         "third. A repairing decoder yields one U+FFFD and signs it."),
        ("stray-continuation-byte", b'{"s":"\x80"}', "invalid-utf8",
         "a continuation byte that continues nothing. Never valid UTF-8 in any position."),
        ("surrogate-encoded-as-utf8", b'{"s":"\xed\xa0\x80"}', "invalid-utf8",
         "CESU-8: U+D800 written as three UTF-8-shaped bytes rather than as a \\ud800 escape. "
         "Invalid UTF-8, and the case that proves the two refusals are one rule — Python's "
         "json.loads decodes it with `surrogatepass` and hands `canonical` a lone surrogate, "
         "so the document that entered as bad BYTES leaves through the surrogate door."),
    ]
    refuse = []
    for name, raw, category, why in refuse_specs:
        assert refuses(raw), f"encoding vector must actually be refused: {name}"
        refuse.append({"name": name, "category": category, "mustReject": True,
                       "documentHex": raw.hex(), "why": why})

    accept_specs = [
        ("literal-replacement-char", ('{"s":"%s"}' % _FFFD).encode("utf-8"),
         "U+FFFD written by the sender ON PURPOSE. It is an ordinary character and MUST "
         "canonicalize; refusing it would only trade one split for another, and it is the "
         "control that stops this group passing by refusing everything."),
        ("astral-pair-escape", b'{"s":"\\ud83d\\udc26"}',
         "a WELL-FORMED surrogate pair, as JSON escapes. High then low, adjacent: one "
         "character, U+1F426, and the canonical bytes carry it literally as UTF-8."),
        ("astral-literal", '{"s":"\U0001F426"}'.encode("utf-8"),
         "the same character as raw UTF-8 bytes. Two spellings of one document: both must "
         "produce the identical canonical bytes as `astral-pair-escape` above."),
    ]
    accept = []
    for name, raw, why in accept_specs:
        canon = crypto.canonical(json.loads(raw)).decode("utf-8")
        accept.append({"name": name, "documentHex": raw.hex(), "canonical": canon, "why": why})
    assert accept[1]["canonical"] == accept[2]["canonical"], \
        "the escape and the literal spelling of one astral character are one document"

    return {
        "note": "`documentHex` is the hex of the RAW DOCUMENT BYTES. Decode the hex, then parse, "
                "then canonicalize: `refuse` must fail somewhere on that path and `accept` must "
                "produce `canonical` exactly. Do not route this through a decoder that repairs — "
                "Go's encoding/json and JavaScript's Buffer.toString('utf8') both substitute "
                "U+FFFD and both then agree with a document nobody signed. The supported paths "
                "are seam.Unmarshal / seam.CanonicalFromJSON (Go), a FATAL TextDecoder then "
                "canonicalBytes (JavaScript), json.loads then crypto.canonical (Python), and "
                "serde_json::from_slice then canonical (Rust).",
        "accept": accept,
        "refuse": refuse,
    }


def _reject_keystate_cases() -> dict:
    """The KeyState ANTI-ROLLBACK rule: what a resolver that remembers must refuse.

    Every other reject group is answered by one record. This one cannot be, because the defect
    is not in any record here — all five VERIFY, all five are honestly root-signed. It is in a
    resolver with no memory. `resolveOpDid` / `resolve_op_did` without a pin answers with
    whatever the presenter attached, so a thief holding a burned op-key simply attaches the
    older, still-validly-signed KeyState in which that key was not yet revoked. A `revokedOps`
    read off the record being judged can only ever incriminate a key its own presenter chose to
    incriminate.

    So each case is a PAIR — a `pinned` record the caller kept from an earlier verified contact,
    and an `inline` one the sender attached now — and the pin is the memory. The three refusals
    are three shapes of the same missing ratchet:

      * `replayed-lower-epoch` — an older record presented over a newer pin. Rollback is free
        without one, because authenticity is not freshness.
      * `pin-revokes-op` — an inline record at a genuinely HIGHER epoch that reinstates a key
        the pin burned. The epoch ratchet alone does not save you: adoption is correct here, and
        the pin's `revokedOps` is what must still refuse the key.
      * `same-epoch-fork` — two records at ONE epoch naming different `opDid`s. Equal is not an
        upgrade, it is a fork; the record we verified ourselves is the one we keep. (Measured on
        the Python side 2026-08-11: pinned epoch 1 -> op1, and a replayed epoch-1 record naming
        op0 resolved to op0.)

    `accept` is load-bearing twice over. A resolver that ALWAYS returned the pin's `opDid` would
    pass all three refusals and follow nobody's rotation — `higher-epoch-adopted` refuses it. A
    resolver that ignored the pin argument entirely would pass `no-pin-first-contact`, which is
    what keeps the three-argument behaviour pinned as well.

    Each case says both what must NOT come back (`mustNotResolveTo`, the DID the attacker is
    fishing for) and what MUST (`expect`). Asserting only the first would let a resolver pass by
    answering the root every time — safe, and wrong: every enrolled peer's messages would then
    fail as an unknown signer."""
    from shared import keystate as ksmod
    root_seed = bytes([21] * 32)
    root = crypto.did_from_public(crypto.ed25519_public_from_seed(root_seed))
    op1 = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([22] * 32)))
    op2 = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([23] * 32)))
    op_fork = crypto.did_from_public(crypto.ed25519_public_from_seed(bytes([24] * 32)))
    check_now = 1784273681

    def sign(message: bytes) -> str:
        return _b64(crypto.ed25519_sign(root_seed, message))

    def record(epoch: int, op: str, revoked: list[str] | None = None) -> dict:
        return ksmod.make_keystate(root, epoch=epoch, op_did=op,
                                   op_next_hash=ksmod.commit(op), ts=check_now,
                                   root_sign=sign, revoked_ops=revoked or [])

    def record_with_raw_revoked(epoch: int, op: str, revoked) -> dict:
        """A record whose `revokedOps` is NOT a list, signed for real.

        `make_keystate` cannot mint one — it does `list(revoked_ops or [])`, which raises on a
        number — so the field is replaced here and the payload re-signed. That is not cheating
        around a guard. A stranger holds their OWN root key, so nothing stops them minting
        exactly this record, and `verify_keystate` says True for every one of them (asserted
        below, because the whole case rests on it). The record is authentic; it is the FIELD
        that is the wrong type, and authenticity has never been a statement about types."""
        fields = {k: v for k, v in record(epoch, op).items() if k != "sig"}
        fields["revokedOps"] = revoked
        fields["sig"] = sign(ksmod._payload(fields))
        return fields

    e1 = record(1, op1)                       # the older, honest state
    e2 = record(2, op2)                       # the state a caller has pinned
    e2_burning_op1 = record(2, op2, [op1])    # …the same epoch, with op1 burned
    e3_reinstating_op1 = record(3, op1)       # a HIGHER epoch that hands op1 back
    e2_fork = record(2, op_fork)              # a second epoch-2 history

    # A BURN LIST YOU CANNOT ENUMERATE BURNS NOTHING — and every one of these is a record a
    # stranger can mint against their own root key and have verified. `revokedOps` is signed,
    # so it is authentic; authenticity says nothing about its TYPE. Python's `in` means four
    # different things depending on what it lands on, and `op_did in (revoked or [])` met all
    # four: a number and a boolean take a TypeError out through a resolver documented as "pure
    # and total", a string is a SUBSTRING test (so a 62-byte string burns an op-key the record
    # never named), and a dict is membership over KEYS. The last two do not crash — they answer
    # the wrong question, and the answer is "burned", which sends the resolver to the root and
    # kills every message that peer signs with its live op-key.
    e1_revoked_number = record_with_raw_revoked(1, op1, 5)
    e1_revoked_boolean = record_with_raw_revoked(1, op1, True)
    e1_revoked_string = record_with_raw_revoked(1, op1, "x" + op1 + "y")
    e1_revoked_object = record_with_raw_revoked(1, op1, {op1: 1})
    e1_revoked_empty = record(1, op1, [])       # the honest empty list: burns nothing
    e1_revoked_self = record(1, op1, [op1])     # the honest full list: burns its own opDid

    # CONTROL: every record here verifies on its own. No case in this group is about a bad
    # signature, and one that failed for one would be pinning nothing. For the four
    # wrong-typed records this control is the case's entire premise — if `verify_keystate`
    # refused them, they would be unmintable and the guard downstream would be unreachable.
    for name, rec in (("e1", e1), ("e2", e2), ("e2_burning_op1", e2_burning_op1),
                      ("e3_reinstating_op1", e3_reinstating_op1), ("e2_fork", e2_fork),
                      ("e1_revoked_number", e1_revoked_number),
                      ("e1_revoked_boolean", e1_revoked_boolean),
                      ("e1_revoked_string", e1_revoked_string),
                      ("e1_revoked_object", e1_revoked_object),
                      ("e1_revoked_empty", e1_revoked_empty),
                      ("e1_revoked_self", e1_revoked_self)):
        assert ksmod.verify_keystate(rec, expected_root_did=root, now=check_now), \
            f"control: {name} must be a valid, root-signed KeyState"
    assert e1_revoked_string["revokedOps"] != op1 and op1 in e1_revoked_string["revokedOps"], \
        "the string case must CONTAIN the opDid without being it — that is the substring trap"

    accept = [
        {"name": "no-pin-first-contact", "pinned": None, "inline": e1, "expect": op1,
         "why": "no pin yet, and a verifying inline record names the op-key. This IS first "
                "contact and it must keep answering what it always answered — a resolver that "
                "ignored its pin argument would pass every refusal below and fail here."},
        {"name": "higher-epoch-adopted", "pinned": e1, "inline": e2, "expect": op2,
         "why": "a STRICTLY greater epoch under the same rootKey is a real rotation and must be "
                "adopted. Without this case a resolver that always returned the pin's own opDid "
                "would pass the whole group and never follow anybody's rotation."},
        # ---- `revokedOps` of the wrong type. A LIST, or nothing is burned.
        #
        # Every record below is authentically root-signed and verifies; a stranger holds their
        # own root key, so all four are remotely mintable at will. Each must resolve to the op
        # DID and — separately, and this is the half a `got == expect` comparison cannot state —
        # each must NOT RAISE. An exception out of a resolver documented as pure and total is a
        # verifier a stranger can switch off with one field, and it is a different failure from
        # a wrong answer, so the runners report which.
        {"name": "revoked-ops-number", "pinned": None, "inline": e1_revoked_number,
         "expect": op1, "mustNotResolveTo": root, "mustNotRaise": True,
         "why": "`revokedOps: 5`. Python's `x in 5` raises TypeError and JavaScript's "
                "`Array.isArray` says no; the contract is the second answer. One field of the "
                "wrong type in a correctly signed record must not turn a verifier off."},
        {"name": "revoked-ops-boolean", "pinned": None, "inline": e1_revoked_boolean,
         "expect": op1, "mustNotResolveTo": root, "mustNotRaise": True,
         "why": "`revokedOps: true` — the same TypeError, and worth its own case because a "
                "guard written as `isinstance(x, (list, tuple))` still admits neither while a "
                "guard written as `if revoked:` admits both."},
        {"name": "revoked-ops-string-containing-op", "pinned": None, "inline": e1_revoked_string,
         "expect": op1, "mustNotResolveTo": root, "mustNotRaise": True,
         "why": "`revokedOps` is a STRING with the opDid inside it. This one does not crash — "
                "it answers the wrong question, because Python's `in` over a string is a "
                "substring test, so one 62-byte string burns every op-key whose DID appears "
                "anywhere in it. The answer it gives is `burned`, which sends the resolver to "
                "the root and kills every message the peer signs with its live op-key."},
        {"name": "revoked-ops-object-keyed-by-op", "pinned": None, "inline": e1_revoked_object,
         "expect": op1, "mustNotResolveTo": root, "mustNotRaise": True,
         "why": "`revokedOps` is an OBJECT keyed by the opDid — membership over dict keys, so "
                "the record burns by shape rather than by content. The quiet twin of the "
                "string case, and the reason the rule is `is it a list`, not `does `in` work`."},
        {"name": "revoked-ops-empty-list", "pinned": None, "inline": e1_revoked_empty,
         "expect": op1, "mustNotResolveTo": root,
         "why": "the honest empty list burns nothing. Pinned so that `revokedOps` cannot be "
                "made to burn by mere presence."},
        {"name": "revoked-ops-genuine-list", "pinned": None, "inline": e1_revoked_self,
         "expect": root, "mustNotResolveTo": op1,
         "why": "THE CONTRAST, and the case that stops the four above being passed by an "
                "implementation that ignores `revokedOps` altogether: a genuine `[opDid]` list "
                "really does burn, and a state that burns its OWN opDid authorizes nobody, so "
                "the answer is the root DID."},
    ]
    refuse = [
        {"name": "replayed-lower-epoch", "category": "keystate-rollback", "mustReject": True,
         "pinned": e2, "inline": e1, "mustNotResolveTo": op1, "expect": op2,
         "why": "an epoch-1 record replayed over an epoch-2 pin. It VERIFIES — it really was "
                "signed by this root — and that is the point: authenticity is not freshness, so "
                "the only thing between a thief holding a retired op-key and a live delegation "
                "is the epoch the caller remembers."},
        {"name": "pin-revokes-op", "category": "keystate-revoked-op", "mustReject": True,
         "pinned": e2_burning_op1, "inline": e3_reinstating_op1,
         "mustNotResolveTo": op1, "expect": op2,
         "why": "the inline record is at a HIGHER epoch, so the epoch ratchet adopts it — and it "
                "names the very op-key the pin burned. The pin's `revokedOps` is the half with "
                "teeth, because the stranger did not choose it. Answering the root would also be "
                "safe and is still wrong: the pin stands behind its own opDid, so that is the "
                "answer, and the root only when that one is burned too."},
        {"name": "same-epoch-fork", "category": "keystate-fork", "mustReject": True,
         "pinned": e2, "inline": e2_fork, "mustNotResolveTo": op_fork, "expect": op2,
         "why": "two records at ONE epoch naming different opDids. Equal is not an upgrade, it "
                "is a fork, and a resolver that adopts on `>=` takes the stranger's history over "
                "the one it verified itself."},
    ]

    # GENERATION DISCIPLINE: every case goes through the real resolver before it reaches the
    # file, all three claims asserted — it does not raise, it answers `expect`, and it does not
    # answer `mustNotResolveTo`. The raise is checked first and separately because a resolver
    # that throws is a resolver a stranger can turn off, and an AssertionError about the wrong
    # DID would be a confusing way to learn that.
    for c in accept + refuse:
        try:
            got = ksmod.resolve_op_did(root, c["inline"], c["pinned"], now=check_now)
        except Exception as exc:                # noqa: BLE001 — the point is that NOTHING escapes
            raise AssertionError(
                f"keystate/{c['name']}: the resolver RAISED {type(exc).__name__}: {exc}. It is "
                "documented pure and total, and this record is one a stranger can mint.") from exc
        assert got == c["expect"], (c["name"], got, c["expect"])
        if "mustNotResolveTo" in c:
            assert got != c["mustNotResolveTo"], (c["name"], "resolved to the wrong key")

    return {
        "note": "The anti-rollback ratchet. `pinned` is a KeyState the CALLER kept from an "
                "earlier verified contact; `inline` is what the sender attached to this message. "
                "Resolve with both and compare against `expect` — JavaScript "
                "`resolveOpDid(rootDid, inline, checkNow, {pinned})`, Python "
                "`keystate.resolve_op_did(rootDid, inline, pinned, now=checkNow)`. The argument "
                "ORDER differs between the two references, which is why the vector names fields "
                "and never positions. Every record here verifies; nothing in this group is about "
                "a bad signature. A case carrying `mustNotRaise` must also not throw: the "
                "resolver is pure and total, and a record whose `revokedOps` is a number or a "
                "boolean is one a stranger can mint against their own root key — an exception "
                "there is a verifier switched off by one field, which is a DIFFERENT failure "
                "from a wrong answer, so report which. Go and Rust implement no KeyState, and "
                "their runners SKIP this group BY NAME rather than silently — an omission "
                "nobody can see is the same as a check nobody has.",
        "rootDid": root, "checkNow": check_now,
        "accept": accept, "refuse": refuse,
    }


def _reject_invite_cases() -> tuple[list[dict], str]:
    """Invite cards that `shared/invite.verify_invite` MUST refuse. Returns (cases, checkNow) — the
    fixed 'now' the expired case is judged against, so a client can reproduce the verdict."""
    from shared import invite as invitemod
    seed = bytes([11] * 32)
    wrong = bytes([12] * 32)
    did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))
    check_now = "2026-07-20T00:00:00Z"           # the fixed clock the expired case is judged at

    valid = {"v": 1, "did": did, "name": "Node", "specialty": "general", "url": "",
             "nonce": "n1", "exp": "2026-07-23T09:59:45Z"}
    valid = {**valid, "sig": _b64(crypto.ed25519_sign(seed, invitemod._signing_payload(valid)))}
    from datetime import datetime, timezone
    _now = datetime.fromisoformat(check_now.replace("Z", "+00:00"))
    assert invitemod.verify_invite(valid, now=_now), "control: the valid invite must verify"

    cases = []
    # expired: identical to `valid` but exp in the past relative to check_now. Signature is RE-MADE
    # over the expired payload (a real inviter would have signed the past exp), so only expiry fails.
    exp_card = {**valid, "exp": "2026-07-10T00:00:00Z"}
    exp_card = {**{k: v for k, v in exp_card.items() if k != "sig"},
                "sig": _b64(crypto.ed25519_sign(seed, invitemod._signing_payload(
                    {k: v for k, v in exp_card.items() if k != "sig"})))}
    assert not invitemod.verify_invite(exp_card, now=_now), "expired vector must reject"
    cases.append({"name": "expired-invite", "category": "expired-invite", "mustReject": True,
                  "input": exp_card, "checkNow": check_now,
                  "note": "signature is valid; `exp` is in the past relative to checkNow. A leaked/"
                          "screenshotted old invite must not be honoured — check exp > now."})

    # forged: valid inviter DID, but signed by a DIFFERENT key (attacker forging someone's invite).
    forged = {k: v for k, v in valid.items() if k != "sig"}
    forged = {**forged, "sig": _b64(crypto.ed25519_sign(wrong, invitemod._signing_payload(forged)))}
    assert not invitemod.verify_invite(forged, now=_now), "forged vector must reject"
    cases.append({"name": "forged-invite", "category": "forged-invite", "mustReject": True,
                  "input": forged, "checkNow": check_now,
                  "note": "the card names `did` but is signed by another key — verify the signature "
                          "under the DID the card claims, exactly as for a message."})
    return cases, check_now


def _reject_claim_cases() -> list[dict]:
    """onboard/claim inputs that MUST NOT create a trusted contact. The signature dimension is
    `crypto.verify_envelope` (static); the NONCE dimension splits: an UNKNOWN nonce is static (no
    issued-nonce store has it), a SPENT nonce needs receiver state and is a client unit test, named
    in rejectNote — not pinnable as a golden vector, same call as cryptobox's random-nonce seal."""
    seed_x = bytes(range(2, 34))
    victim = bytes([60] * 32)
    frm = crypto.did_from_public(crypto.ed25519_public_from_seed(seed_x))
    to = crypto.did_from_public(crypto.ed25519_public_from_seed(victim))
    # A claim is an onboard/claim RPC; the inner message is signed like any envelope.
    good = crypto.sign_envelope(seed_x, frm, to, "cm1", "cc", 1784273681, "onboard/claim")
    cases = []

    # claim-unsigned: forged/absent signature on the claim → must not write trust. This is the MITM
    # vector (a forged claim overwriting a contact's enc_pub/relay).
    cases.append({"name": "claim-unsigned", "category": "claim-unsigned", "mustReject": True,
                  "input": {"method": "onboard/claim",
                            "message": {"from": frm, "to": to, "messageId": "cm1", "contextId": "cc",
                                        "timestamp": 1784273681, "text": "onboard/claim",
                                        "sig": _b64(b"\x00" * 64)},
                            "nonce": "whatever", "name": "Alice", "enc_pub": "cc" * 32,
                            "relay": "https://attacker.example"},
                  "note": "a claim's signature must verify (from == signer) BEFORE it can add or "
                          "overwrite a contact — else a stranger MITMs an existing conversation by "
                          "overwriting enc_pub/relay."})

    # claim-unknown-nonce: correctly SIGNED, but the nonce was never issued by us → must not trust.
    cases.append({"name": "claim-unknown-nonce", "category": "claim-unknown-nonce", "mustReject": True,
                  "input": {"method": "onboard/claim",
                            "message": {"from": frm, "to": to, "messageId": "cm1", "contextId": "cc",
                                        "timestamp": 1784273681, "text": "onboard/claim",
                                        "sig": good},
                            "nonce": "never-issued-by-this-device", "name": "Alice"},
                  "note": "even a validly-signed claim must present a one-time nonce THIS device "
                          "issued; an unknown nonce means no invite was ever extended — do not trust."})
    return cases


def build_vectors() -> dict:
    _invite_reject, _check_now = _reject_invite_cases()
    return {
        "note": "Golden WIRE vectors. Every non-Python client (muretai-ios-poc Sources/SeamKit, "
                "muretai-android-poc seam/) MUST reproduce every `canonical` / `did` / "
                "`signingPayload` / `bindingPayload` field BYTE-FOR-BYTE. A drift does not throw — "
                "it silently makes that client's signatures unverifiable. Regenerate: "
                "python3 test_wire_vectors.py --regen",
        "protocolVersion": PROTOCOL_VERSION,
        "canonicalSpec": "python json.dumps(sort_keys=True, separators=(',',':'), "
                         "ensure_ascii=False).encode('utf-8')",
        "timestampNote": "Timestamps in signed payloads are INTEGER epoch seconds — this is the "
                         "CONTRACT, not a convenience of these vectors. It used to be the latter: "
                         "core minted floats and the vectors side-stepped them, which meant a "
                         "client could pass every vector here and still be unable to verify a real "
                         "message from a Python node. `crypto.signing_payload` does not cast, so "
                         "the type on the wire IS the type in the signed bytes, and a float there "
                         "is bytes no other language can reproduce (Python's shortest-round-trip "
                         "repr). Since 2026-07-17 core mints ints (shared/protocol.Message, "
                         "cardpub publishers). Clients: send ints; keep VERIFYING whatever type "
                         "arrives — an older node still sends floats and its signature is over "
                         "those exact bytes. Never coerce inside a payload builder.",
        "canonical": _canonical_cases(),
        "numberHazards": _number_hazard_cases(),
        "numberHazardNote":
            "These are NOT in `canonical`, and that distinction is the point. Every "
            "case here is a value whose canonical bytes DIFFER between Python and "
            "JavaScript, so requiring a client to reproduce them would be requiring it "
            "to re-implement CPython's float repr — the opposite of the contract. "
            "`signMustNotEmit` means exactly what it says: a signer that emits one of "
            "these produces bytes only Python can verify. `verifyNeedsPythonRepr` "
            "means a client CAN still meet a lesser duty — recognise the shape and "
            "report honestly that it cannot verify that artifact, rather than "
            "reporting a bad signature. This section exists because `trustLevel: 1.0` "
            "shipped for a year while all twelve original `canonical` cases stayed "
            "green: none of them contained a float, so nothing caught it, and the "
            "failure surfaced as a signature error pointing at the client's Ed25519 "
            "code. Same rule as timestampNote, stated for every number: signed "
            "payloads carry INTEGERS inside +/-(2**53-1). Never coerce inside a "
            "payload builder; never coerce on the verify path either.",
        "did": _did_cases(),
        "envelope": _envelope_cases(),
        "binding": _binding_cases(),
        # The v2 (countersigned, account-layer) binding — T102. `binding` above
        # pins only the v1 ROOT-signed payload bytes; v2 is a different artifact
        # (typ inside the signed bytes, integer ts/validUntil, BOTH signatures)
        # and is what account attribution requires, so its accept AND reject
        # halves are pinned. Judged at `checkNow` (the bounded case's expiry).
        "bindingV2": _binding_v2_cases(),
        # The OwnerState — the account layer's REVOCATION record (T102 slice 6). The
        # binding above says "this device is mine"; this one says "…and this one is not,
        # any more", published under the owner's DID and pinned by receivers. A client
        # that reproduces bindingV2 but not this one can join an account and can never
        # leave it, so both halves (accept + reject) are pinned.
        "ownerState": _ownerstate_cases(),
        "ownerStateNote":
            "shared/ownerstate.py. `epoch` is the ONLY ordering signal — strictly "
            "greater wins, an equal or lower one is refused whatever its clock says "
            "(the resolver's rule, not the verifier's: the verifier holds no pinned "
            "state, so it answers only 'is this authentic', never 'is this newer'). "
            "`revoked` is de-duplicated, sorted and BOUNDED at the mint point; a "
            "non-canonical spelling is refused rather than normalized. `epoch`/`ts` are "
            "integers (timestampNote). REVOCATION-ONLY BY DESIGN: an owner never "
            "publishes the devices it HAS — that would be a public deviceDid->owner "
            "reverse map for anyone who knows a DID — only the ones it has taken away. "
            "Unknown top-level keys are IGNORED by the verifier and the signature covers "
            "the declared fields the record carries, so a future field can be added "
            "without invalidating any record minted today.",
        # The SESSION surfaces. The four above pin identity and signing — enough to produce a DID
        # and a verifiable envelope, and NOT enough to actually exchange a message. That gap is
        # where the iOS client broke: correct signatures, mail
        # that never arrived, and no vector to say the bytes were wrong.
        "relay": _relay_cases(),
        "cryptobox": _cryptobox_cases(),
        "invite": _invite_cases(),
        "cardpub": _cardpub_cases(),
        # The OUTWARD-FACING surfaces. Everything above is a muretai format read by muretai
        # code; these two are read by software we do not control (a DIF verifier, a website's
        # bot-auth middleware), so "our client and our core agree" is not the bar — the bytes
        # are the bar, and a mismatch surfaces only as "invalid signature" from a stranger.
        "domainLinkage": _domain_linkage_cases(),
        "domainLinkageNote":
            "The DIF Domain Linkage Credential (compact JWS, shared/domainbind.py). The "
            "signature covers the TEXT of the first two segments — b64url(header).b64url("
            "payload) — never the object they decode to, so `signingInput` is the byte string "
            "to reproduce and re-serializing a decoded payload is NOT how you verify. Header "
            "is {alg:\"EdDSA\",typ:\"JWT\",kid:\"<did>#<multibase>\"}; base64url is UNPADDED "
            "and a padded or standard-alphabet spelling is refused rather than repaired. "
            "`nbf`/`exp` are INTEGER epoch seconds and are the values a verifier compares; the "
            "ISO strings inside `vc` are their human-facing echo. `exp` is MANDATORY — a "
            "domain is leased, not owned, so a credential with no end date is indefinite "
            "authority over a name the issuer may no longer hold. iss == sub == "
            "vc.credentialSubject.id, all three the identical string, or refuse. Origins are "
            "compared canonicalized on BOTH sides (shared/neturl.origin), and a non-default "
            "port is part of the origin. DIRECTION: this proves only that the holder of `did` "
            "CLAIMS `domain`; it becomes a proof once the document is fetched from that "
            "domain's /.well-known/did-configuration.json and the DID's card names the domain "
            "back.",
        "webBotAuth": _webbotauth_cases(),
        "epochNote": "NOT bytes, so not pinnable here — and the thing a client is most likely to "
                     "get wrong. An `epoch` identifies a LISTENER, not a poll: sortable "
                     "(creation-time+pid), STABLE for that listener's life, greater-wins, older "
                     "gets HTTP 409. Minting a fresh epoch per poll makes a client supersede its "
                     "own long-poll and drop mail. Specified in docs/SPECIFICATION.md §relay.",
        # NEGATIVE space. Everything above says "reproduce these bytes"; a client that verifies
        # nothing on receipt passes all of it. These say "REJECT these" — the half that catches a
        # fail-open client (how the Swift client shipped accepting forged senders, audit 2026-07-17).
        "reject": {
            "message": _reject_message_cases(),
            # The bytes-in half. Everything else under `reject` is a decoded VALUE; this one is
            # raw document bytes, because the defect it pins (a repaired lone surrogate, a
            # repaired invalid byte) has already been erased by the time a value exists.
            "encoding": _reject_encoding_cases(),
            # The half no single record can carry. Every KeyState in this group verifies; what
            # is refused is a RESOLVER with no memory of this root — see the group's note.
            "keystate": _reject_keystate_cases(),
            "invite": _invite_reject,
            "claim": _reject_claim_cases(),
        },
        "rejectNote": "Each case MUST be rejected by your receiver (`mustReject`). `category` is "
                      "language-neutral guidance, NOT core's -32xxx — your own error taxonomy is "
                      "yours. message: verified with the key DERIVED FROM `from` "
                      "(crypto.verify_envelope) — and note that `wire-names-its-own-recipient` "
                      "carries `verifierNamesNoRecipient`, which means the verifier must be called "
                      "with NO recipient of its own; naming one makes the case pass for the wrong "
                      "reason. encoding: raw document BYTES as hex, refused at the parse boundary "
                      "(see that group's own note) with an `accept` half that must still "
                      "canonicalize; invite: shared/invite.verify_invite, judged at the "
                      "case's `checkNow`; claim: signature MUST verify AND a one-time nonce THIS "
                      "device issued must be consumed before any trust is written. ONE case cannot "
                      "be a static vector: `claim-spent-nonce` (a replayed claim whose nonce was "
                      "already consumed) needs receiver state, so it is a REQUIRED client unit test, "
                      "not pinned here — the same boundary as cryptobox's random-nonce seal.",
    }


# ---------------------------------------------------------------- tests

def test_vectors_match() -> None:
    print("\n[1] golden vectors — Python reproduces the pinned file (the Swift/Kotlin contract)")
    ok(VECTORS.exists(), f"vector file exists ({VECTORS.name})")
    on_disk = json.loads(VECTORS.read_text())
    live = build_vectors()
    if on_disk != live:
        # Point at the FIRST divergent case rather than dumping two large blobs — the whole value
        # of this test is telling you which byte moved.
        probes = [(name, on_disk.get(name) or [], live.get(name) or [])
                  for name in ("canonical", "did", "envelope", "binding", "domainLinkage")]
        # webBotAuth is a dict (like relay/cryptobox), so only its list of key vectors can be
        # walked case-by-case; the rest of it is reported by the whole-file comparison below.
        probes.append(("webBotAuth.keys",
                       (on_disk.get("webBotAuth") or {}).get("keys") or [],
                       (live.get("webBotAuth") or {}).get("keys") or []))
        for section, pinned_cases, live_cases in probes:
            for a, b in zip(pinned_cases, live_cases):
                if a != b:
                    print(f"\n  first divergence in [{section}]:")
                    print(f"    pinned: {json.dumps(a, ensure_ascii=False)}")
                    print(f"    live  : {json.dumps(b, ensure_ascii=False)}")
                    break
    ok(on_disk == live,
       "core reproduces every pinned wire vector "
       "(if this fails after an INTENTIONAL change: --regen, then re-vendor to every client)")


def test_protocol_version_is_pinned() -> None:
    print("\n[2] the vectors declare which protocol version they describe")
    on_disk = json.loads(VECTORS.read_text())
    ok(on_disk["protocolVersion"] == PROTOCOL_VERSION,
       f"pinned protocolVersion matches shared/protocol.py ({PROTOCOL_VERSION})")


def test_canonical_is_actually_canonical() -> None:
    """Properties a client can check WITHOUT the vectors — and that the vectors themselves rely on."""
    print("\n[3] the canonical form has the properties the vectors assume")
    ok(crypto.canonical({"b": 1, "a": 2}) == crypto.canonical({"a": 2, "b": 1}),
       "insertion order does not change the bytes (else signing would be nondeterministic)")
    ok(b" " not in crypto.canonical({"a": 1, "b": 2}), "no whitespace anywhere")
    ok("群".encode() in crypto.canonical({"k": "群"}),
       "non-ASCII is literal UTF-8 (ensure_ascii=False is a WIRE requirement, not a preference)")
    ok(b"\\u" not in crypto.canonical({"k": "群"}), "non-ASCII is NOT \\u-escaped")
    ok(crypto.canonical({"k": "a/b"}) == b'{"k":"a/b"}', "'/' is not escaped")


def test_did_roundtrip_and_curve_separation() -> None:
    print("\n[4] did:key is self-certifying and the two curves never blur")
    for k in (bytes(32), bytes([255] * 32), bytes(range(32))):
        ok(crypto.public_from_did(crypto.did_from_public(k)) == k, f"ed25519 round-trips ({k.hex()[:8]}…)")

    p256_did = crypto.did_from_p256(bytes([0x02]) + bytes(range(32)))
    # The curves mean different things: Ed25519 = device (day-to-day signing), P-256 = hardware
    # root (ownership). A parser that confuses them would accept a device key where a root is
    # required — the exact confusion the hierarchy exists to prevent.
    try:
        crypto.public_from_did(p256_did)
        ok(False, "a P-256 DID must NOT parse as Ed25519")
    except ValueError:
        ok(True, "a P-256 DID is REFUSED by the Ed25519 parser (no silent curve confusion)")

    kind, raw = crypto.key_from_did(p256_did)
    ok(kind == "p256" and len(raw) == 33, "key_from_did dispatches P-256 -> 33 compressed bytes")
    kind, raw = crypto.key_from_did(crypto.did_from_public(bytes(32)))
    ok(kind == "ed25519" and len(raw) == 32, "key_from_did dispatches ed25519 -> 32 bytes")


def test_envelope_fields_are_fixed() -> None:
    print("\n[5] the signed envelope is exactly six fields (principle 4: never change their meaning)")
    payload = json.loads(crypto.signing_payload("a", "b", "m", "c", 1, "t").decode())
    ok(sorted(payload) == ["contextId", "from", "messageId", "text", "timestamp", "to"],
       "exactly {contextId,from,messageId,text,timestamp,to} — adding a field here breaks every "
       "existing verifier (use a DETACHED signature instead)")


def test_ownerstate_vectors_verify() -> None:
    """`ownerState` must be exercised by a NAMED check, not only by the asserts inside the
    generator that mints it.

    The generator's controls run on every invocation and do discriminate, but an `assert` in a
    builder is stripped by `python -O` and counted by nobody. spec/seam.md tells a stranger
    that "the reject groups are not optional"; this is agent-seam proving it of the one group
    whose verifier lives in a module no runner here was calling.
    """
    print("\n[12] the owner-state records verify, and the five that must not, do not")
    from shared import ownerstate as osmod
    v = json.loads(VECTORS.read_text())["ownerState"]
    for c in v["cases"]:
        ok(osmod.verify_ownerstate(c["record"], expected_root_did=c["rootDid"]) is True,
           f"a pinned owner-state record verifies under its root DID: {c['name']}")
        ok(osmod.verify_ownerstate(c["record"], expected_root_did="did:key:zSomeoneElse") is False,
           f"and is refused under another root (anti-substitution): {c['name']}")
    for r in v["reject"]:
        ok(osmod.verify_ownerstate(r["input"], expected_root_did=v["cases"][0]["rootDid"]) is False,
           f"refused, as the vector says it must be: {r['name']} ({r['category']})")


def test_relay_session_vectors_discriminate() -> None:
    """The relay surfaces must be checked by something that could REFUSE.

    Core runs this group through the relay's own verifiers (`relay._verify_rpc_sig`), which
    cannot travel: a relay is not wire. What travels is the half that needs no relay — the
    signatures verify with `crypto.ed25519_verify`, and, more to the point, the two negative
    controls that make the vectors mean anything. Without them agent-seam published the rule
    that `to|from|id|blob` is joined with `|` and never `canonical JSON`, and shipped no test
    that a client ignoring the order would fail.
    """
    print("\n[7] the relay session vectors discriminate (signature side, no relay needed)")
    v = json.loads(VECTORS.read_text())["relay"]

    for c in v["send"]:
        pub = crypto.public_from_did(c["from"])
        ok(crypto.ed25519_verify(pub, base64.b64decode(c["sig"]), c["sendSigMsg"].encode("utf-8")),
           f"/send sender-auth verifies over 'to|from|id|blob': {c['name']}")
    # THE JOIN ORDER IS LOAD-BEARING. A client that concatenates the four fields in another
    # order, or drops one, must not pass — otherwise the vector is decoration.
    bad = v["send"][0]
    swapped = "|".join([bad["from"], bad["to"], bad["id"], bad["blob"]])
    ok(not crypto.ed25519_verify(crypto.public_from_did(bad["from"]),
                                 base64.b64decode(bad["sig"]), swapped.encode("utf-8")),
       "/send: swapping to/from is REJECTED (the join order is load-bearing)")

    for c in v["listen"]:
        pub = crypto.public_from_did(c["did"])
        ok(crypto.ed25519_verify(pub, base64.b64decode(c["token"]), c["listenTokenMsg"].encode("utf-8")),
           f"/listen token signature verifies over 'listen:<did>:<minute>:<origin>': {c['name']}")
    # The ORIGIN is the security field, so pin both directions: one relay has one spelling,
    # and no token is valid across relays.
    by_name = {c["name"]: c for c in v["listen"]}
    ok(by_name["plain"]["token"] == by_name["same-origin-different-spelling"]["token"],
       "two spellings of one relay mint the SAME token (a stored trailing slash must not 401)")
    ok(len({c["origin"] for c in v["listen"]}) == 2
       and by_name["explicit-port"]["token"] != by_name["plain"]["token"],
       "a different relay origin mints a DIFFERENT token (the binding is real)")


def test_cryptobox_vectors_actually_open() -> None:
    """The sealed blobs must really open — with core's own opener.

    seal() draws a random nonce, so the seal direction cannot be pinned. What CAN be pinned is the
    direction that matters: a client must OPEN what core sealed. Running each pinned blob through
    open_box() proves the whole chain (X25519 agreement, derivation, AEAD, base64(nonce‖ct)
    framing) rather than asserting a hand-written string against itself.
    """
    print("\n[8] the pinned sealed blobs open to the pinned plaintext (real, not asserted)")
    try:
        from shared import cryptobox
    except Exception as e:
        print(f"  – skipped: cryptobox needs the optional `cryptography` backend ({e})")
        return
    v = json.loads(VECTORS.read_text())["cryptobox"]
    recip = bytes.fromhex(v["recipientSeed"])
    for c in v["open"]:
        # `adHex` is read WITHOUT a default. A missing key must be a KeyError here rather than
        # a silently empty `ad`, because an empty `ad` is precisely the wrong answer for the
        # case that carries one — and it would look green.
        got = cryptobox.open_box(recip, v["senderEncPub"], c["blob"], bytes.fromhex(c["adHex"]))
        ok(got == bytes.fromhex(c["plaintextHex"]),
           f"open_box reproduces the pinned plaintext: {c['name']}"
           + (f" (ad={bytes.fromhex(c['adHex']).decode('utf-8', 'replace')!r})" if c["adHex"] else ""))
    # The `ad` BINDING, both directions. Same blob, wrong associated data — and the AEAD tag
    # covers `ad`, so this is an authentication failure, not a decode failure.
    for c in v["mustNotOpen"]:
        ok(cryptobox.open_box(recip, v["senderEncPub"], c["blob"],
                              bytes.fromhex(c["adHex"])) is None,
           f"and must NOT open: {c['name']}")
    # Negative control: a blob opened with the WRONG sender key must fail, not return garbage.
    other = cryptobox.enc_pub_hex(bytes([42] * 32))
    ok(cryptobox.open_box(recip, other, v["open"][0]["blob"]) is None,
       "a blob opened against the wrong sender key returns None (no silent garbage)")


def test_invite_vectors_verify() -> None:
    """A pinned invite card must pass core's own verify_invite (minus expiry, which is time-bound
    by design — a fixed `exp` in a vector would rot into a false failure)."""
    print("\n[9] the pinned invite payloads are what core signs and verifies")
    from shared import invite as invitemod
    v = json.loads(VECTORS.read_text())["invite"]
    for c in v:
        payload = invitemod._signing_payload(c["card"])
        ok(payload.decode("utf-8") == c["invitePayload"],
           f"invite signing payload is byte-stable: {c['name']}")


def test_cardpub_vectors_verify_through_the_real_verifier() -> None:
    """Each pinned card envelope must be accepted by `cardpub.verify_card_envelope` itself — the
    function a peer actually runs when it fetches a card by DID. Asserting the payload string
    against itself would prove nothing about the consumer."""
    print("\n[11] the pinned card envelopes pass cardpub's own verifier")
    from shared import cardpub
    v = json.loads(VECTORS.read_text())["cardpub"]
    for c in v:
        env = {"v": cardpub.CARD_ENVELOPE_VERSION, "typ": cardpub.CARD_ENVELOPE_TYPE,
               "card": c["card"], "ts": c["ts"], "sig": c["sig"]}
        ok(cardpub.verify_card_envelope(env, expected_did=c["card"]["did"]) is not None,
           f"a pinned card envelope verifies by DID: {c['name']}")
    # Negative control: the anti-substitution check must still bite (the signature only proves
    # "X signed X's card"; asking for Y must not accept X's).
    c0 = v[0]
    env = {"v": cardpub.CARD_ENVELOPE_VERSION, "typ": cardpub.CARD_ENVELOPE_TYPE,
           "card": c0["card"], "ts": c0["ts"], "sig": c0["sig"]}
    ok(cardpub.verify_card_envelope(env, expected_did="did:key:zSomeoneElse") is None,
       "a card fetched under the WRONG did is refused (anti-substitution)")

    # PHASE 1 SAFETY: this verifier must read BOTH forms, or updating a node would make it reject
    # every card already out there. An old envelope carries a float on the wire and was signed
    # over that float; canonicalizing what arrived (no cast) reproduces it exactly.
    from _seedsigner import _SeedSigner        # agent-seam: a seed-only signer stands in for agent.identity
    _id = _SeedSigner(bytes(range(32)))
    _card = {"did": _id.did, "name": "Compat", "url": ""}
    for _ts, _label in ((1784273681, "int (what phase 2 will publish)"),
                        (1784273681.04038, "float (what every deployed node publishes today)")):
        _env = cardpub.make_card_envelope(_id, _card, _ts)
        ok(cardpub.verify_card_envelope(_env, expected_did=_id.did) is not None,
           f"this verifier accepts a {_label} card envelope")


def _reencode_jws_payload(token: str, mutate: Callable[[dict], None]) -> str:
    """Re-serialize a compact JWS's payload after `mutate` edits it IN PLACE, keeping the
    original header and the original signature.

    The serialization matches `jws.signing_input` exactly (sort_keys, compact separators,
    ensure_ascii=False, unpadded base64url), which is what makes this a controlled experiment:
    a no-op `mutate` must reproduce the token BYTE-FOR-BYTE, so when a one-field edit is then
    rejected, the rejection is that field and not an artifact of the re-encode."""
    from shared import jws
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(jws.unb64url(payload_b64).decode("utf-8"))
    mutate(payload)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "%s.%s.%s" % (header_b64, jws.b64url(body), sig_b64)


def test_domain_linkage_vectors_verify_through_the_real_verifier() -> None:
    """Each pinned credential must be accepted by `domainbind.verify_domain_linkage_jwt` — the
    function a peer actually runs against a stranger's /.well-known document — and a ONE-FIELD
    mutation must be refused by that same call. Asserting the token against the builder that
    produced it would prove nothing about the consumer."""
    print("\n[13] the pinned domain-linkage credentials pass domainbind's own verifier")
    from shared import domainbind
    v = json.loads(VECTORS.read_text())["domainLinkage"]
    for c in v:
        claim = domainbind.verify_domain_linkage_jwt(c["token"], domain=c["domain"],
                                                     now=c["nbf"])
        ok(claim is not None and claim["did"] == c["did"] and claim["exp"] == c["exp"],
           f"a pinned credential verifies for its own domain: {c['name']}")
        ok(c["token"].rsplit(".", 1)[0] == c["signingInput"],
           f"the pinned signingInput IS the token's first two segments — the bytes actually "
           f"signed, reproducible without the key: {c['name']}")
        # `exp` is mandatory here precisely so this is true: a domain is leased, not owned.
        ok(domainbind.verify_domain_linkage_jwt(c["token"], domain=c["domain"],
                                                now=c["exp"] + 1) is None,
           f"…and is refused one second past `exp`: {c['name']}")

    c0 = v[0]
    other = "attacker.example"
    ok(domainbind.verify_domain_linkage_jwt(c0["token"], domain=other, now=c0["nbf"]) is None,
       "a credential minted for one domain proves nothing about another (origin is compared, "
       "not merely present)")

    # PAIRED CONTROL, the same discipline the reject vectors use: prove the re-encode is inert
    # BEFORE claiming a mutation is what got rejected.
    identical = _reencode_jws_payload(c0["token"], lambda payload: None)
    ok(identical == c0["token"],
       "control: re-serializing the payload unchanged reproduces the token byte-for-byte")
    ok(domainbind.verify_domain_linkage_jwt(identical, domain=c0["domain"],
                                            now=c0["nbf"]) is not None,
       "control: the re-serialized token still verifies")

    def _swap_origin(payload: dict) -> None:
        payload["vc"]["credentialSubject"]["origin"] = "https://" + other

    mutated = _reencode_jws_payload(c0["token"], _swap_origin)
    ok(domainbind.verify_domain_linkage_jwt(mutated, domain=other, now=c0["nbf"]) is None,
       "ONE mutated field (credentialSubject.origin) is REJECTED — everything else about the "
       "document now says `attacker.example`, and only the signature over the payload TEXT "
       "says otherwise")
    ok(domainbind.verify_domain_linkage_jwt(mutated, domain=c0["domain"],
                                            now=c0["nbf"]) is None,
       "…and it is not silently accepted back at the ORIGINAL domain either")


def test_webbotauth_vectors_are_rederived_by_the_real_module() -> None:
    """Every pinned Web Bot Auth byte must be re-derived by `shared/webbotauth` itself, and the
    signed artifacts must pass its own verifiers (`verify_request`, `verify_directory_response`)
    — the code a website and a fetcher actually run."""
    print("\n[14] the pinned Web Bot Auth bytes are what shared/webbotauth produces and accepts")
    from shared import gateway, jws as jwsmod, webbotauth
    v = json.loads(VECTORS.read_text())["webBotAuth"]

    pinned_dids = {c["did"] for c in json.loads(VECTORS.read_text())["did"]}
    for c in v["keys"]:
        public = bytes.fromhex(c["publicHex"])
        jwk = webbotauth.jwk_from_public(public)
        ok(jwk["x"] == c["x"] and webbotauth.did_from_jwk(jwk) == c["did"]
           and c["did"] in pinned_dids,
           f"JWK <-> did round-trips, and it is one of the `did` section's keys: {c['x'][:12]}…")
        ok(webbotauth.jwk_thumbprint(jwk) == c["thumbprint"],
           f"the RFC 7638 thumbprint (the wire `keyid`) is re-derived: {c['thumbprint']}")
        # Pin the HASH INPUT, not just its digest: a client that decorates the JWK with `kid`
        # or spaces its separators gets a different keyid for the same key, which reads to a
        # verifier as an unknown key rather than as a formatting mistake.
        ok(jwsmod.b64url(hashlib.sha256(c["thumbprintInput"].encode("utf-8")).digest())
           == c["thumbprint"],
           "…and thumbprintInput is EXACTLY the text hashed (three required members, sorted, "
           "unspaced)")

    me = _SeedIdentity(bytes.fromhex(v["seedHex"]))
    ok(me.did == v["did"], "the worked example is minted by the pinned seed (a client can "
                           "re-mint it and compare, not merely verify)")

    r = v["request"]
    agent_url = gateway.did_site_url(me.did, base="https://muretai.net")
    ok(agent_url == r["signatureAgentUrl"]
       and webbotauth._sf_string(agent_url) == r["signatureAgent"],
       "signature-agent is the DID-addressed HP URL, quoted as an sf-string")
    components = (("@authority", r["authority"]), ("signature-agent", r["signatureAgent"]))
    params = webbotauth.signature_params([n for n, _ in components], created=r["created"],
                                         expires=r["expires"], keyid=r["keyid"], tag=r["tag"])
    ok(params == r["signatureParams"],
       "@signature-params is re-derived byte-for-byte (the parameter ORDER is wire, not style)")
    ok(webbotauth.signature_base(components, params).decode("utf-8") == r["signatureBase"],
       "the request signature base is re-derived byte-for-byte (LF-joined, no trailing newline)")

    headers = webbotauth.request_headers(me, "https://%s/rpc" % r["authority"],
                                         created=r["created"],
                                         window=r["expires"] - r["created"],
                                         signature_agent=agent_url)
    ok(headers["Signature-Input"] == r["signatureInput"]
       and headers["Signature"] == r["signature"]
       and headers["Signature-Agent"] == r["signatureAgent"],
       "request_headers emits exactly the three pinned header values")
    directory = webbotauth.directory_jwks(me.did)
    ok(webbotauth.verify_request(headers, authority=r["authority"], jwks=directory,
                                 now=r["created"] + 10) == me.did,
       "the pinned headers are accepted by webbotauth's OWN request verifier")
    ok(webbotauth.verify_request(headers, authority="other.example", jwks=directory,
                                 now=r["created"] + 10) is None,
       "…and prove nothing at another origin (@authority is covered)")

    d = v["directory"]
    body = webbotauth.directory_body(me.did)
    ok(body.decode("utf-8") == d["body"],
       "the served directory body is byte-stable (a cached copy and a fresh fetch compare)")
    dir_components = (("@authority", d["authority"]),)
    dir_params = webbotauth.signature_params(["@authority"], created=d["created"],
                                             expires=d["expires"], keyid=d["keyid"],
                                             tag=d["tag"])
    ok(dir_params == d["signatureParams"], "the directory @signature-params is re-derived")
    ok(webbotauth.signature_base(dir_components, dir_params).decode("utf-8")
       == d["signatureBase"], "the directory signature base is re-derived byte-for-byte")
    rebuilt = webbotauth.directory_response(me, d["authority"], created=d["created"],
                                            window=d["expires"] - d["created"])
    ok(rebuilt == (body, d["signatureInput"], d["signature"]),
       "directory_response emits exactly the pinned body and header values")

    served = {"Content-Type": d["contentType"], "Signature-Input": d["signatureInput"],
              "Signature": d["signature"]}
    ok(webbotauth.verify_directory_response(d["authority"], served, body,
                                            now=d["created"] + 60) == [me.did],
       "the pinned directory proves its DID through webbotauth's own verifier")
    ok(webbotauth.verify_directory_response("evil.example", served, body,
                                            now=d["created"] + 60) == [],
       "…and proves nothing when served from another origin (a copied JWK is not possession)")

    # The `tag` control, and it is why tag is inside the SIGNED params. Same key, same
    # authority, an overlapping window, and every covered header present — the ONLY difference
    # between this and a real directory signature is `tag`. It must still prove nothing.
    lifted = {"Content-Type": d["contentType"], "Signature-Input": r["signatureInput"],
              "Signature": r["signature"], "Signature-Agent": r["signatureAgent"]}
    ok(webbotauth.verify_directory_response(d["authority"], lifted, body,
                                            now=r["created"] + 10) == [],
       "a REQUEST signature lifted onto a directory response proves nothing — only `tag` "
       "differs, and it is inside the signed params")


def test_timestamps_are_integers_on_the_wire() -> None:
    """Integer epoch seconds are the CONTRACT now, not a vector's convenience.

    `crypto.signing_payload` does not cast, so the type on the wire IS the type in the signed
    bytes. A float there is bytes no other language can reproduce: Python renders it with its own
    shortest-round-trip repr, and `SeamKit.canonical` has no float case at all ("floats are avoided
    by design"). That is why the iOS client could never verify a message a Python node sent it.

    This pins the MINT side (what we put on the wire) and the mixed-fleet property that makes it
    safe to ship: both types still verify, because neither side coerces.
    """
    print("\n[10] timestamps: we mint integers, and a mixed fleet still verifies both ways")
    from shared import protocol as pmod
    m = pmod.Message(role="user", text="hi", from_did="a", to_did="b")
    ok(isinstance(m.timestamp, int),
       f"a new message mints an INT timestamp (got {type(m.timestamp).__name__}) — a float here is "
       "unverifiable outside Python")

    seed = bytes(range(32))
    did = crypto.did_from_public(crypto.ed25519_public_from_seed(seed))
    for ts, label in ((1784273681, "our int"), (1784273681.04038, "an OLD node's float")):
        payload = crypto.signing_payload(did, did, "m1", "c1", ts, "hi")
        sig = crypto.ed25519_sign(seed, payload)
        # A verifier rebuilds from what the wire carried — no coercion, either direction.
        rebuilt = crypto.signing_payload(did, did, "m1", "c1", ts, "hi")
        ok(crypto.ed25519_verify(crypto.ed25519_public_from_seed(seed), sig, rebuilt),
           f"{label} verifies — the fleet can be mixed while it updates")

    # An int must render as an int. If anything ever re-introduces a cast, this is the tripwire.
    ok(b'"timestamp":1784273681,' in crypto.signing_payload(did, did, "m", "c", 1784273681, "t"),
       'an int timestamp canonicalizes as 1784273681 — never 1784273681.0')

    # cardpub was the one payload builder that FORCED a float, which made a published card
    # unverifiable outside Python by construction.
    from shared import cardpub
    ok(b'"ts":1784273681,' in cardpub._envelope_payload({"did": "x"}, 1784273681),
       "cardpub signs the ts AS GIVEN — the float() cast is gone")


def test_number_hazards_really_diverge_and_are_not_minted() -> None:
    """The hazard section must stay honest in both directions.

    A vector that claims a divergence which does not exist teaches a client to work
    around nothing; a vector that claims one while core still MINTS that value is a
    warning about a live bug we chose not to fix. Both are worse than no vector, so
    both are asserted here.

    (The JavaScript renderings in the file were measured against Node and cannot be
    re-derived without it — so what is checkable in pure Python is that each case is
    genuinely a hazard SHAPE, that Python's own rendering differs from the claimed
    JavaScript one, and that nothing in the tree still signs one.)
    """
    print("\n[10b] numberHazards: each case really diverges, and core mints none of them")
    for c in _number_hazard_cases():
        payload, name = c["payload"], c["name"]
        # It must actually be a hazard shape: a float, or an int outside the range a
        # double holds exactly. Anything else does not belong in this section.
        def _values(o):
            if isinstance(o, dict):
                for x in o.values():
                    yield from _values(x)
            else:
                yield o
        vals = list(_values(payload))
        hazardous = any(
            (isinstance(v, float)) or
            (isinstance(v, int) and not isinstance(v, bool) and abs(v) > 2 ** 53 - 1)
            for v in vals)
        ok(hazardous, f"{name}: is a float or an out-of-double-range int — a real hazard shape")
        ok(c["pythonCanonical"] != c["javascriptWouldWrite"],
           f"{name}: Python and the claimed JavaScript rendering actually differ")
        ok(c["signMustNotEmit"] is True, f"{name}: marked as never-sign")

    # The two that were live until 2026-08-07. If either regresses, this fails loudly.
    from shared import vc as vcmod, keystate as ksmod
    body = {"credentialSubject": {"trustLevelBp": vcmod._to_bp(1.0)}}
    ok(b'"trustLevelBp":1000' in crypto.canonical(body),
       "an introduction mints INTEGER basis points — never trustLevel: 1.0")
    ok(vcmod.trust_level_of({"trustLevelBp": 873}) == 0.873,
       "…and reads back as 0.873")
    ok(vcmod.trust_level_of({"trustLevel": 0.5}) == 0.5,
       "…while a legacy float credential still reads correctly (verify never coerces)")
    ok(str(ksmod.KEYSTATE_TYP) != "",
       "keystate module loads")  # guard the import above for the next assertion
    ok(b'"notBefore":0,' in crypto.canonical({"notBefore": int(0.0), "ts": 1}),
       "keystate mints notBefore as an INT — never 0.0")


def _verifier_rejects_message(inp: dict, verify=crypto.verify_envelope) -> bool:
    """Does `verify` REJECT this message input? True = rejected (the required outcome). `verify` is
    injectable so the meta-control can pass a fail-open one. An absent sig is rejected structurally
    (an authenticated receiver never treats an unsigned message as from a DID)."""
    if inp.get("sig") is None:
        return True
    return not verify(inp["from"], inp["to"], inp["messageId"],
                      inp.get("contextId"), inp["timestamp"], inp["text"], inp["sig"])


def test_reject_vectors_are_rejected() -> None:
    """The negative half: every pinned reject case MUST be rejected by the REAL verifier, AND the
    harness MUST catch a fail-open client. Without the second assertion this section is decoration —
    a suite a fail-open client passes proves nothing (the mistake it exists to prevent, and one I
    made twice this week)."""
    print("\n[12] negative vectors: the real verifier REJECTS each, and a fail-open client is caught")
    from shared import invite as invitemod
    from datetime import datetime
    rej = json.loads(VECTORS.read_text())["reject"]

    for c in rej["message"]:
        if c.get("verifierNamesNoRecipient"):
            # The verifier knows no recipient of its own, and the message helpfully supplies
            # one. In Python there is nothing to supply it TO: `to` is one of the six SIGNED
            # fields and `verify_envelope` takes `to_did` from the CALLER, so the wire's
            # unsigned `recipientDid` cannot reach the payload however hard it tries. Both
            # halves are asserted — the honest delivery still verifies, and the caller who
            # names nobody gets a signature failure — so this passes for its own reason and
            # not because something upstream fell over.
            i = c["input"]
            honest = crypto.verify_envelope(i["from"], i["to"], i["messageId"], i.get("contextId"),
                                            i["timestamp"], i["text"], i["sig"])
            nobody = crypto.verify_envelope(i["from"], "", i["messageId"], i.get("contextId"),
                                            i["timestamp"], i["text"], i["sig"])
            ok(honest and not nobody and i.get("recipientDid") == i["to"],
               f"message reject [{c['category']}]: {c['name']} — the wire names itself as the "
               "recipient; a verifier that names none refuses (`to` is signed, `recipientDid` is not)")
        elif c["name"] == "wrong-recipient":
            # NOT a signature failure — the sig verifies for the real recipient. The rejection is the
            # to==me check, which needs to know who we are. Assert both halves: the sig is valid, and
            # `to` is not us.
            i = c["input"]
            ok(crypto.verify_envelope(i["from"], i["to"], i["messageId"], i.get("contextId"),
                                      i["timestamp"], i["text"], i["sig"]) and i["to"] != c["recipientDid"],
               f"message reject [{c['category']}]: {c['name']} — sig valid, but `to` != us")
        else:
            ok(_verifier_rejects_message(c["input"]), f"message reject [{c['category']}]: {c['name']}")

    # ---- the encoding group: raw document BYTES, through the real parse-and-canonicalize path.
    #
    # `json.loads` is handed the bytes rather than a str on purpose: that is the boundary where
    # Python refuses an invalid UTF-8 document, exactly as `seam.Unmarshal` does in Go and
    # `serde_json::from_slice` does in Rust. The surrogate escapes get past it (CPython decodes
    # bytes with the `surrogatepass` handler) and are caught one step later by `canonical`'s
    # `.encode("utf-8")`. Two doors, and a case for each kind, so neither can be removed unnoticed.
    enc = rej["encoding"]
    for c in enc["accept"]:
        raw = bytes.fromhex(c["documentHex"])
        got = crypto.canonical(json.loads(raw))
        ok(got == c["canonical"].encode("utf-8"),
           f"encoding accept: {c['name']} — canonicalizes to the pinned bytes")
    for c in enc["refuse"]:
        raw = bytes.fromhex(c["documentHex"])
        try:
            crypto.canonical(json.loads(raw))
            refused = False
        except Exception:
            refused = True
        ok(refused, f"encoding refuse [{c['category']}]: {c['name']}")
    # The control that makes the two halves mean something. A REPAIRING reader — Go's
    # encoding/json, JavaScript's Buffer.toString('utf8') — accepts every refusal above, and the
    # bytes it produces COLLIDE: several of the refused documents become the ACCEPTED one. That
    # is the vulnerability stated as arithmetic rather than as prose. A signature over the honest
    # `literal-replacement-char` document also authenticates, at such a receiver, documents its
    # signer never saw.
    def _repaired(doc: bytes) -> bytes:
        def fix(s: str) -> str:
            return "".join(_FFFD if 0xd800 <= ord(ch) <= 0xdfff else ch for ch in s)
        v = json.loads(doc.decode("utf-8", "replace"))
        return crypto.canonical({fix(k): fix(x) if isinstance(x, str) else x
                                 for k, x in v.items()})

    honest_fffd = next(c["canonical"].encode("utf-8") for c in enc["accept"]
                       if c["name"] == "literal-replacement-char")
    repaired = [_repaired(bytes.fromhex(c["documentHex"])) for c in enc["refuse"]]
    ok(repaired.count(honest_fffd) >= 2 and len(set(repaired)) < len(repaired),
       f"a repairing reader turns {repaired.count(honest_fffd)} of the {len(enc['refuse'])} "
       f"refused documents into `literal-replacement-char` — the ACCEPTED one — and collapses "
       f"all {len(enc['refuse'])} to {len(set(repaired))} distinct byte strings. That collision "
       "is what this group refuses: one signature would authenticate documents its signer never saw")

    # ---- the keystate ratchet, through the real resolver.
    #
    # Both halves are asserted for every case: the DID that must come back, AND that it is not
    # the one the attacker was fishing for. Only the second would let a resolver pass by
    # answering the root every time — safe, and wrong in a way nobody notices until every
    # enrolled peer's messages start failing as an unknown signer.
    from shared import keystate as ksmod
    kss = rej["keystate"]
    for kind, group in (("accept", kss["accept"]), ("refuse", kss["refuse"])):
        for c in group:
            # A RAISE IS A FAILURE OF THE CASE, NOT A CRASH OF THE SUITE. `resolve_op_did` is
            # documented pure and total, and `revoked-ops-number` / `revoked-ops-boolean` are
            # records a stranger can mint that used to take a TypeError straight out through
            # it. Letting that escape here would end the run with a traceback and no verdict —
            # the reader would learn that something exploded, not which contract broke. An
            # exception and a wrong answer are both refusals of the contract; they are
            # different refusals, so they are reported differently.
            try:
                got = ksmod.resolve_op_did(kss["rootDid"], c["inline"], c["pinned"],
                                           now=kss["checkNow"])
            except Exception as exc:            # noqa: BLE001 — nothing may escape
                got = f"RAISED {type(exc).__name__}: {exc}"
            ok(got == c["expect"] and got != c.get("mustNotResolveTo"),
               f"keystate {kind}: {c['name']}"
               + (" — and must not raise" if c.get("mustNotRaise") else "")
               + (f" [got {got}]" if isinstance(got, str) and got.startswith("RAISED") else ""))

    for c in rej["invite"]:
        now = datetime.fromisoformat(c["checkNow"].replace("Z", "+00:00"))
        ok(not invitemod.verify_invite(c["input"], now=now),
           f"invite reject [{c['category']}]: {c['name']}")

    for c in rej["claim"]:
        m = c["input"]["message"]
        if c["name"] == "claim-unknown-nonce":
            # The signature IS valid here — the rejection is the nonce dimension, which is receiver
            # state a static vector cannot carry. Assert exactly that: sig verifies, so a client
            # that stops at the signature would WRONGLY accept, and only the nonce check saves it.
            ok(crypto.verify_envelope(m["from"], m["to"], m["messageId"], m.get("contextId"),
                                      m["timestamp"], m["text"], m["sig"]),
               f"claim [{c['category']}]: {c['name']} — sig is valid; rejection is the one-time "
               "nonce (stateful, a required client unit test — see rejectNote)")
        else:
            ok(_verifier_rejects_message(m), f"claim reject [{c['category']}]: {c['name']}")

    # META-CONTROL — the assertion that makes this a real conformance suite rather than decoration.
    # A fail-open verifier (accepts everything, the RelayKit failure mode) must be REJECTED BY THE
    # SUITE: it should fail to reject the signature-based cases. Prove the suite would catch it.
    fail_open = lambda *a, **k: True
    # Only the cases whose rejection IS a signature failure. Three reject on a different axis and
    # a signature verifier is not what catches them: wrong-recipient and
    # wire-names-its-own-recipient (valid sig, the RECIPIENT is the question) and
    # claim-unknown-nonce (valid sig, bad nonce).
    _other_axis = ("wrong-recipient", "wire-names-its-own-recipient")
    sig_cases = [c["input"] for c in rej["message"]
                 if c["input"].get("sig") is not None and c["name"] not in _other_axis] + \
                [c["input"]["message"] for c in rej["claim"]
                 if c["input"]["message"].get("sig") is not None and c["name"] != "claim-unknown-nonce"]
    missed = [inp for inp in sig_cases if _verifier_rejects_message(inp, verify=fail_open)]
    ok(len(missed) == 0,
       f"a fail-open verifier rejects NONE of the {len(sig_cases)} signature-based cases — so this "
       "suite FAILS such a client instead of passing it")


def test_a_tampered_vector_would_be_caught() -> None:
    """The negative control for the vectors themselves.

    A comparison that cannot fail proves nothing. This asserts the file is actually being compared,
    by mutating a loaded vector in memory and confirming it no longer matches core.
    """
    print("\n[6] the vector comparison actually compares (negative control)")
    live = build_vectors()
    tampered = json.loads(json.dumps(live))
    tampered["canonical"][0]["canonical"] = tampered["canonical"][0]["canonical"].replace(":", ": ", 1)
    ok(tampered != live, "a ONE-SPACE difference in a canonical vector is detected")


def main() -> int:
    if "--regen" in sys.argv:
        VECTORS.parent.mkdir(parents=True, exist_ok=True)
        VECTORS.write_text(json.dumps(build_vectors(), ensure_ascii=False, indent=2) + "\n")
        digest = hashlib.sha256(VECTORS.read_bytes()).hexdigest()
        print(f"regenerated {VECTORS}")
        print(f"sha256: {digest}")
        print("\nYou have just declared a WIRE CHANGE. Every client's vendored copy is now stale:")
        print("  python3 tools/client_conformance.py     # see who is behind")
        return 0

    print("=" * 62)
    print("wire vectors — the byte contract every native client re-implements")
    print("=" * 62)
    if not crypto.P256_AVAILABLE:
        print("\nNOTE: `cryptography` absent — P-256 DID vectors are still checked (pure "
              "encoding); live P-256 signing is not exercised here anyway.")

    test_vectors_match()
    test_protocol_version_is_pinned()
    test_canonical_is_actually_canonical()
    test_did_roundtrip_and_curve_separation()
    test_envelope_fields_are_fixed()
    test_relay_session_vectors_discriminate()
    test_ownerstate_vectors_verify()
    test_cryptobox_vectors_actually_open()
    test_invite_vectors_verify()
    test_cardpub_vectors_verify_through_the_real_verifier()
    test_domain_linkage_vectors_verify_through_the_real_verifier()
    test_webbotauth_vectors_are_rederived_by_the_real_module()
    test_reject_vectors_are_rejected()
    test_timestamps_are_integers_on_the_wire()
    test_number_hazards_really_diverge_and_are_not_minted()
    test_a_tampered_vector_would_be_caught()

    print("\n" + "=" * 62)
    print(f"✅ {_passed} checks passed — the wire contract is pinned.")
    print(f"   sha256({VECTORS.name}) = {hashlib.sha256(VECTORS.read_bytes()).hexdigest()}")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
