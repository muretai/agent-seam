"""
shared/vc.py
L3 trust-layer (WoT) introduction = Verifiable Credential (a minimal,
W3C-VC-aligned implementation).

An introduction is a signed statement that "the issuer vouches for the subject
(credentialSubject.id), toward a specific recipient (introducedTo), with some
expertise and a trustLevel". This is the basic unit of the web of trust:

  - Why a VC: to make "who introduced whom" tamper-evident and to put the
    introducer's reputation on the line. No introduction means no contact
    (= a structural spam barrier).
  - Why include introducedTo: to prevent replaying an introduction (using a
    credential meant for A to gain access to B). A recipient only accepts
    introductions addressed to itself.
  - Why Ed25519 + canonical JSON: to reuse the same crypto base as L2 message
    signing (shared/crypto.py) and keep zero dependencies.

Signed payload: the VC body minus `proof`, canonicalized via crypto.canonical.
proof.jws holds base64(Ed25519 signature). Verification derives the public key
from the issuer (did:key) — as in L2, the DID itself is the key, so there is no
separate key/ID match to perform.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Any

from shared import crypto

VC_TYPE = ["VerifiableCredential", "AgentIntroduction"]
RECOVERY_VC_TYPE = ["VerifiableCredential", "AgentRecoveryAttestation"]
PROOF_TYPE = "Ed25519Signature2020"

# ---------------------------------------------------------------- provenance (T72)
#
# Every introduction now records HOW it came to exist, in a signed, additive
# `provenance` field of the VC body:
#
#   provenance: {mode: "requested", request: <signed request record>}   or
#   provenance: {mode: "proactive"}
#
# Why: an introducer used to be able to mint "subject may reach target" with no
# on-network record of whether the subject ever asked. That made the audit
# question "who initiated this?" unanswerable. Now the subject's ask is itself a
# SIGNED record (the ordinary L2 message envelope: the six signed fields + sig),
# embedded verbatim in the VC, so all three parties can prove the chain from
# their own stores: the subject's request (subject-signed) -> the introduction
# (introducer-signed, embedding the request) -> the target's acceptance. The
# relay stays blind — provenance rides inside the VC, which is end-to-end.
#
# `mode: "proactive"` keeps introducer-initiated vouching legal, but explicit
# and permanently stamped: nothing is silent. A VC with NO provenance field is
# tolerated (minted by a pre-T72 node); a VC with an UNKNOWN mode is rejected
# (fail closed — an unrecognized provenance claim is not a verified one).

MODE_REQUESTED = "requested"
MODE_PROACTIVE = "proactive"

#: The canonical marker for a TARGETED introduction request. It rides in the
#: signed `text` of the request message on purpose: the L2 signed payload is the
#: frozen six-field envelope (principle 4), so the target DID must live inside
#: one of those fields to be covered by the subject's signature.
INTRO_REQUEST_PREFIX = "introduce-me-to:"

#: How long a subject's request stays live (matches the default introduction
#: validity window, so "the subject asked recently" and "the vouch is fresh"
#: age on the same clock).
INTRO_REQUEST_TTL_DAYS = 30

#: Allowed forward clock skew for a request timestamp (same order as the L2
#: message freshness window): a request "signed in the future" is rejected.
INTRO_REQUEST_SKEW = 300


def intro_request_text(target_did: str) -> str:
    """The signed message text for 'introduce me to <target_did>'."""
    return INTRO_REQUEST_PREFIX + target_did


def intro_request_record(msg: Any) -> dict[str, Any]:
    """Shape a verified request Message into the storable/embeddable record.

    The record is the six signed envelope fields plus the signature, and
    optionally the sender's KeyState (T142 A2). `timestamp` is kept with its
    wire type (no cast): the canonical encoder renders the received type, and
    a cast would break the signature (see shared/protocol.Message.timestamp).
    `keystate` is unsigned additive metadata that is itself root-signed, so a
    holder can resolve the op-key the subject signed with."""
    rec = {"from": msg.from_did, "to": msg.to_did, "messageId": msg.messageId,
           "contextId": msg.contextId, "timestamp": msg.timestamp,
           "text": msg.text, "sig": msg.sig}
    ks = getattr(msg, "keystate", None)
    if ks:
        rec["keystate"] = ks
    return rec


def intro_request_target(record: dict[str, Any]) -> str | None:
    """The target DID a request names, or None for the expertise (referral)
    form, where the subject asked for discovery and delegated the choice of
    target to the introducer."""
    try:
        text = record.get("text") or ""
    except AttributeError:
        return None
    if text.startswith(INTRO_REQUEST_PREFIX):
        target = text[len(INTRO_REQUEST_PREFIX):].strip()
        return target or None
    return None


def verify_intro_request(record: dict[str, Any],
                         expected_subject: str | None = None,
                         expected_target: str | None = None,
                         expected_introducer: str | None = None,
                         now: datetime | None = None,
                         max_age_seconds: float = INTRO_REQUEST_TTL_DAYS * 86400
                         ) -> bool:
    """Verify one signed introduction-request record. Never raises (fail closed).

      1. Structure: the six envelope fields + sig are present.
      2. Signature: the subject's signature verifies over the canonical
         envelope. Payload `from` is the root DID; the verifying key is the
         op-key when a valid `keystate` is attached (T142 A2 default
         enrollment), else `from`. A missing/invalid KeyState falls back to
         `from` (pre-A2 / un-enrolled subjects).
      3. Bindings: `from` == expected_subject (the VC's credentialSubject.id),
         `to` == expected_introducer (the VC's issuer — a request addressed to
         introducer B can never be embedded by introducer C), and for a
         TARGETED request the named DID == expected_target.
      4. Freshness: signed within `max_age_seconds` before `now` (and not
         after it, beyond a small skew). `now` is the VC's issuanceDate when
         checking an embedded request — the request had to be live AT MINT
         TIME; a stored VC must not start failing as the request ages."""
    try:
        if not isinstance(record, dict):
            return False
        frm, to = record.get("from"), record.get("to")
        mid, text, sig = (record.get("messageId"), record.get("text"),
                          record.get("sig"))
        ts = record.get("timestamp")
        if not (frm and to and mid and text and sig) or ts is None:
            return False
        import time as _time
        from shared import keystate as ks_mod
        ks = record.get("keystate")
        op = ks_mod.resolve_op_did(
            frm, ks if isinstance(ks, dict) else None, None, now=_time.time())
        # NO cast on ts: the canonical bytes must match what the subject signed.
        if not crypto.verify_signed_envelope(
                frm, to, mid, record.get("contextId"),
                ts, text, sig, signer_did=op):
            return False
        if expected_subject is not None and frm != expected_subject:
            return False
        if expected_introducer is not None and to != expected_introducer:
            return False
        if (expected_target is not None
                and intro_request_target(record) != expected_target):
            return False
        now_dt = now or datetime.now(timezone.utc)
        now_epoch = now_dt.timestamp()
        age = now_epoch - float(ts)
        if age < -INTRO_REQUEST_SKEW:      # signed in the future
            return False
        if age > max_age_seconds:          # stale: the ask is no longer live
            return False
        return True
    except Exception:
        return False


def provenance_summary(vc: dict[str, Any] | None) -> str:
    """One human line answering "who initiated this introduction?" — rendered
    wherever a party reviews a VC (requests queue, gate/held-intro prints)."""
    prov = (vc or {}).get("provenance")
    if not isinstance(prov, dict):
        return "unrecorded provenance (minted by a pre-provenance node)"
    mode = prov.get("mode")
    if mode == MODE_PROACTIVE:
        return "proactive — introducer initiated"
    if mode == MODE_REQUESTED:
        req = prov.get("request") or {}
        frm = (req.get("from") or "?")[:20]
        try:
            day = datetime.fromtimestamp(
                float(req.get("timestamp")), timezone.utc).strftime("%Y-%m-%d")
        except (TypeError, ValueError):
            day = "?"
        return f"requested by {frm}… on {day}"
    return f"unknown provenance mode {mode!r}"


# ---------------------------------------------------------------- time helpers

def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string (trailing Z)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 string into an aware datetime. Python 3.10's
    fromisoformat cannot parse a trailing 'Z', so normalize it to '+00:00'."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------- signed payload

def _credential_body(vc: dict[str, Any]) -> dict[str, Any]:
    """The VC body minus `proof` (= the signed payload)."""
    return {k: v for k, v in vc.items() if k != "proof"}


def signing_payload(vc: dict[str, Any]) -> bytes:
    """Canonical bytes of the VC body minus `proof` (same rule as L2 signing)."""
    return crypto.canonical(_credential_body(vc))


# ---------------------------------------------------------------- trust level
#
# The vouch strength is minted as `trustLevelBp` — an INTEGER in basis points
# (0-1000, so 0.873 -> 873). It used to be `trustLevel`, a float, and that made every
# introduction unverifiable outside Python:
#
#   Python  json.dumps(1.0) -> "1.0"        JavaScript  JSON.stringify(1.0) -> "1"
#
# and `JSON.parse("1.0")` is irrecoverably `1`, so a client cannot even reconstruct
# what was signed. This is not an edge case — `operator_cli.introduce` and a Room's
# `/introduce` both mint exactly 1.0, and the referral path mints 1.0 for its BEST
# result (a direct contact with an exact expertise match), so the strongest vouches
# were the ones that broke. Measured against the browser client, 2026-08-07.
#
# It is the same defect core already fixed for message timestamps on 2026-07-17, and
# the same remedy: mint the reproducible type, never coerce on the verify path. See
# FIXED(canonical-float-timestamp-nonpython) and the vectors' `timestampNote`
# ("Never coerce inside a payload builder"). Basis points are chosen over a float
# with a pinned format because 0-1000 is exactly representable everywhere and needs
# no number-formatting agreement at all — the same call Matrix made when it banned
# floats from its own canonical JSON, which is byte-for-byte ours.
#
# Verification is UNCHANGED: `signing_payload` canonicalizes whatever the wire
# carried, so a VC minted before this change still verifies against its own bytes.

BP_SCALE = 1000


def _to_bp(trust_level: float) -> int:
    """0.0-1.0 float -> 0-1000 integer basis points, clamped."""
    return max(0, min(BP_SCALE, int(round(float(trust_level) * BP_SCALE))))


def trust_level_of(subject: dict[str, Any]) -> float | None:
    """Read a credentialSubject's vouch strength as a 0.0-1.0 float.

    Prefers the integer `trustLevelBp`; falls back to the legacy float `trustLevel`
    so credentials issued before 2026-08-07 keep reading correctly. Absent-tolerant,
    the same additive pattern `provenance` uses — there is no version field on the VC
    body and none is needed.
    """
    if not isinstance(subject, dict):
        return None
    bp = subject.get("trustLevelBp")
    if isinstance(bp, int) and not isinstance(bp, bool):
        return bp / BP_SCALE
    legacy = subject.get("trustLevel")
    if isinstance(legacy, (int, float)) and not isinstance(legacy, bool):
        return float(legacy)
    return None


# ---------------------------------------------------------------- issuance

def issue_introduction(identity, subject_did: str, introduced_to_did: str,
                       expertise, trust_level: float,
                       valid_until: str,
                       issuer_endpoint: str | None = None,
                       request: dict[str, Any] | None = None,
                       mode: str | None = None) -> dict[str, Any]:
    """Issue an introduction.

    identity          : the issuer's Identity. Signs via sign_bytes.
    subject_did       : DID of the subject being introduced.
    introduced_to_did : DID of the recipient this introduction may be shown to.
    expertise         : expertise; a plain string is normalized to a 1-item list.
    trust_level       : 0.0-1.0 trust (how strongly the issuer vouches).
    valid_until       : expiry (ISO 8601 string).
    issuer_endpoint   : issuer's public URL. Included in the signed payload
                        (tamper-proof) so the recipient can reach /revocations
                        to check for revocation.
    request           : the subject's signed introduction-request record
                        (intro_request_record) -> mode "requested", record
                        embedded verbatim in the signed VC body.
    mode              : "requested" / "proactive". Defaults from `request`
                        (present -> requested, absent -> proactive), so every
                        newly minted VC carries a mode — nothing is silent.

    Fail-fast at mint time (defense in depth — the target re-verifies anyway):
    a "requested" VC without a verifying request record, or a "proactive" one
    smuggling a record, raises ValueError rather than minting an introduction
    whose provenance claim its own issuer cannot back."""
    if isinstance(expertise, str):
        expertise = [expertise]
    if mode is None:
        mode = MODE_REQUESTED if request is not None else MODE_PROACTIVE
    if mode == MODE_REQUESTED:
        if not verify_intro_request(request, expected_subject=subject_did,
                                    expected_introducer=identity.did):
            raise ValueError(
                "cannot mint a 'requested' introduction: no verifying signed "
                "request from the subject (wrong signer, wrong parties, or "
                "stale)")
        named = intro_request_target(request)
        if named is not None and named != introduced_to_did:
            raise ValueError(
                "cannot mint a 'requested' introduction: the subject's request "
                "names a different target")
    elif mode == MODE_PROACTIVE:
        if request is not None:
            raise ValueError("a 'proactive' introduction must not embed a "
                             "request record (pick one mode)")
    else:
        raise ValueError(f"unknown introduction mode {mode!r}")
    vc: dict[str, Any] = {
        "id": "urn:uuid:" + uuid.uuid4().hex,
        "type": list(VC_TYPE),
        "issuer": identity.did,
        "issuanceDate": now_iso(),
        "credentialSubject": {
            "id": subject_did,
            "introducedTo": introduced_to_did,
            "expertise": list(expertise),
            # INTEGER basis points, 0-1000, NOT a float — see trust_level_of() below
            # and vectors/wire_vectors.json `timestampNote`. `trust_level` stays a
            # 0.0-1.0 float in this function's signature so no caller changes; only the
            # bytes that get signed change.
            "trustLevelBp": _to_bp(trust_level),
            "validUntil": valid_until,
        },
        # Additive, inside the signed body (everything except `proof` is
        # signed), so provenance is tamper-evident under the issuer's key and
        # old verifiers — which canonicalize the WHOLE body — still verify it.
        "provenance": ({"mode": MODE_REQUESTED, "request": dict(request)}
                       if mode == MODE_REQUESTED else {"mode": MODE_PROACTIVE}),
    }
    if issuer_endpoint:
        vc["issuerEndpoint"] = issuer_endpoint.rstrip("/")
    vc["proof"] = {
        "type": PROOF_TYPE,
        "created": now_iso(),
        "verificationMethod": identity.did,
        "jws": identity.sign_bytes(signing_payload(vc)),
    }
    return vc


# ---------------------------------------------------------------- verification

def verify_introduction(vc: dict[str, Any],
                        expected_subject: str | None = None,
                        expected_recipient: str | None = None,
                        now: datetime | None = None) -> bool:
    """Verify an introduction. Returns False if any check fails.

      1. Structure present (type/issuer/credentialSubject/proof)
      2. proof.jws verifies under the issuer's key (= untampered)
      3. subject matches the expected value (anti-replay)
      4. introducedTo matches the expected value (the recipient) (anti-replay)
      5. validUntil is in the future (not expired)
      6. Provenance (T72), when the `provenance` field is present:
         "proactive" needs nothing further; "requested" must embed the
         SUBJECT's verifying signed request, bound to this VC's subject and
         issuer, live at issuanceDate, and — for a targeted request — naming
         this VC's introducedTo (an introducer cannot repoint a request at a
         different target). Absent provenance is tolerated (a VC minted by a
         pre-T72 node); an unknown mode fails closed. Freshness is anchored to
         issuanceDate, not to "now", so a stored VC's verdict is stable over
         its own validity window.
    """
    try:
        if not isinstance(vc, dict):
            return False
        if "AgentIntroduction" not in (vc.get("type") or []):
            return False
        issuer = vc.get("issuer")
        subj = vc.get("credentialSubject")
        proof = vc.get("proof")
        if not (issuer and isinstance(subj, dict) and isinstance(proof, dict)):
            return False

        # 2. Signature check (derive the public key from the issuer's did:key)
        jws = proof.get("jws")
        if not jws:
            return False
        try:
            sig = base64.b64decode(jws)
        except Exception:
            return False
        if not crypto.verify(issuer, sig, signing_payload(vc)):
            return False

        # 3-4. Anti-replay
        if expected_subject is not None and subj.get("id") != expected_subject:
            return False
        if (expected_recipient is not None
                and subj.get("introducedTo") != expected_recipient):
            return False

        # 5. Expiry
        valid_until = subj.get("validUntil")
        if not valid_until:
            return False
        now = now or datetime.now(timezone.utc)
        if _parse_iso(valid_until) <= now:
            return False

        # 6. Provenance (see the docstring). The issuer signature above already
        # proves the ISSUER vouches for these bytes; this step checks that the
        # SUBJECT's embedded ask is genuine — a colluding issuer signing a VC
        # around a forged request must still fail here.
        prov = vc.get("provenance")
        if prov is not None:
            if not isinstance(prov, dict):
                return False
            mode = prov.get("mode")
            if mode == MODE_PROACTIVE:
                pass
            elif mode == MODE_REQUESTED:
                req = prov.get("request")
                issued = vc.get("issuanceDate")
                if not issued:
                    return False
                anchor = _parse_iso(issued)
                if not verify_intro_request(req,
                                            expected_subject=subj.get("id"),
                                            expected_introducer=issuer,
                                            now=anchor):
                    return False
                named = intro_request_target(req)
                if named is not None and named != subj.get("introducedTo"):
                    return False
            else:
                return False   # unknown mode: fail closed

        return True
    except Exception:
        # Fail closed: any error means "not verified" (never leak exceptions
        # into the trust decision).
        return False


# ---------------------------------------------- recovery attestation (guardian)

def issue_recovery_attestation(identity, old_did: str, new_did: str,
                               guardianset_epoch: int, guardians_hash: str,
                               valid_until: str,
                               issuer_endpoint: str | None = None) -> dict[str, Any]:
    """A guardian's signed statement "newDid IS the same entity as oldDid" (WoT social
    recovery, shared/recovery.py + shared/guardianset.py). Mirrors issue_introduction. The
    attestation is BOUND to (oldDid, newDid, guardianSetEpoch, guardiansHash) so a guardian's
    signature for one migration can never authorize a different migration or a different
    guardian policy. `identity` = the guardian's Identity (signs via sign_bytes)."""
    vc: dict[str, Any] = {
        "id": "urn:uuid:" + uuid.uuid4().hex,
        "type": list(RECOVERY_VC_TYPE),
        "issuer": identity.did,
        "issuanceDate": now_iso(),
        "credentialSubject": {
            "oldDid": old_did,
            "newDid": new_did,
            "guardianSetEpoch": int(guardianset_epoch),
            "guardiansHash": guardians_hash,
            "validUntil": valid_until,
        },
    }
    if issuer_endpoint:
        vc["issuerEndpoint"] = issuer_endpoint.rstrip("/")
    vc["proof"] = {
        "type": PROOF_TYPE,
        "created": now_iso(),
        "verificationMethod": identity.did,
        "jws": identity.sign_bytes(signing_payload(vc)),
    }
    return vc


def verify_recovery_attestation(vc: dict[str, Any],
                                expected_old: str | None = None,
                                expected_new: str | None = None,
                                expected_guardians_hash: str | None = None,
                                now: datetime | None = None) -> bool:
    """Verify ONE guardian recovery attestation (safe on untrusted input, never raises):
    structure + the guardian's signature (curve-agnostic) + the (old,new[,guardiansHash])
    binding + not expired. It does NOT decide whether the ISSUER is an authorized guardian —
    the caller counts verified attestations against its pinned GuardianSet (Increment 4)."""
    try:
        if not isinstance(vc, dict):
            return False
        if "AgentRecoveryAttestation" not in (vc.get("type") or []):
            return False
        issuer = vc.get("issuer")
        subj = vc.get("credentialSubject")
        proof = vc.get("proof")
        if not (issuer and isinstance(subj, dict) and isinstance(proof, dict)):
            return False
        jws = proof.get("jws")
        if not jws:
            return False
        if not crypto.verify(issuer, base64.b64decode(jws), signing_payload(vc)):
            return False
        if expected_old is not None and subj.get("oldDid") != expected_old:
            return False
        if expected_new is not None and subj.get("newDid") != expected_new:
            return False
        if (expected_guardians_hash is not None
                and subj.get("guardiansHash") != expected_guardians_hash):
            return False
        vu = subj.get("validUntil")
        if not vu:
            return False
        now = now or datetime.now(timezone.utc)
        if _parse_iso(vu) <= now:
            return False
        return True
    except Exception:
        return False
