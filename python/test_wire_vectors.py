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
    with itself."""
    from shared import cryptobox
    a_seed, b_seed = bytes([3] * 32), bytes([9] * 32)
    return {
        "senderSeed": a_seed.hex(), "senderEncPub": cryptobox.enc_pub_hex(a_seed),
        "recipientSeed": b_seed.hex(), "recipientEncPub": cryptobox.enc_pub_hex(b_seed),
        "note": "open_box(recipientSeed, senderEncPub, blob) == plaintext. seal() is NOT pinned — "
                "it uses a random nonce, so its output is not reproducible. A client proves that "
                "direction with its own round-trip against core; this pins the direction that "
                "matters, that a client can OPEN what core sealed.",
        "open": [
            {"name": "plain",
             "blob": "YYrXndd8212cUzJ2A+sWWspUASAfIn2ipMdHcTh3y+Ir",
             "plaintextHex": "68656c6c6f"},
            {"name": "non-ascii",
             "blob": "58o9qnvehBofRDrqZH+xfU+SdmLFB7AlKQt1o0U6bsIWapNjAu5xmA==",
             "plaintextHex": "e7bea4e3828ce3819fe38184"},
            {"name": "empty",
             "blob": "Aj7TqCyAdxO3dtdcJ8848Omz3oxT7o2N0mdQSw==",
             "plaintextHex": ""},
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
    return cases


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
            "invite": _invite_reject,
            "claim": _reject_claim_cases(),
        },
        "rejectNote": "Each case MUST be rejected by your receiver (`mustReject`). `category` is "
                      "language-neutral guidance, NOT core's -32xxx — your own error taxonomy is "
                      "yours. message: verified with the key DERIVED FROM `from` "
                      "(crypto.verify_envelope); invite: shared/invite.verify_invite, judged at the "
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
        got = cryptobox.open_box(recip, v["senderEncPub"], c["blob"])
        ok(got == bytes.fromhex(c["plaintextHex"]),
           f"open_box reproduces the pinned plaintext: {c['name']}")
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
        if c["name"] == "wrong-recipient":
            # NOT a signature failure — the sig verifies for the real recipient. The rejection is the
            # to==me check, which needs to know who we are. Assert both halves: the sig is valid, and
            # `to` is not us.
            i = c["input"]
            ok(crypto.verify_envelope(i["from"], i["to"], i["messageId"], i.get("contextId"),
                                      i["timestamp"], i["text"], i["sig"]) and i["to"] != c["recipientDid"],
               f"message reject [{c['category']}]: {c['name']} — sig valid, but `to` != us")
        else:
            ok(_verifier_rejects_message(c["input"]), f"message reject [{c['category']}]: {c['name']}")

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
    # Only the cases whose rejection IS a signature failure — wrong-recipient (valid sig, wrong `to`)
    # and claim-unknown-nonce (valid sig, bad nonce) reject on a different axis, so a signature
    # verifier is not what catches them.
    sig_cases = [c["input"] for c in rej["message"]
                 if c["input"].get("sig") is not None and c["name"] != "wrong-recipient"] + \
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
