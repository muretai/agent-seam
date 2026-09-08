"""
shared/cardpub.py
A signed, relay-publishable Agent Card envelope — DID-addressed card discovery.

Why this exists:
  An overlay (--yggdrasil) node advertises its Agent Card `url` as the routable,
  key-derived IPv6, so `/.well-known/agent.json` is reachable ONLY on the overlay;
  a relay-only node serves no card at all. A peer that has just a DID (no overlay,
  no prior invite) therefore cannot fetch the live card. This module wraps the exact
  build_agent_card dict in a signed envelope the node PUBLISHES to the relay under its
  DID (relay.py `POST /card`), so anyone can fetch AND verify it by DID over plain
  HTTPS (`GET /card/<did>`) without joining the overlay.

The envelope:
  { "v":1, "typ":"agentcard", "card": <the exact build_agent_card dict>,
    "ts": <float>, "sig": <base64> }
  sig = base64(sign over crypto.canonical({"v","typ","card","ts"}))

Design (why this shape):
  - WRAP, don't sign-in-place: `/.well-known/agent.json` stays the current UNSIGNED
    A2A card (byte-for-byte backward-compatible); only the published copy is signed.
  - `typ` gives domain separation: a node signs many blobs with the same identity key
    (ygg/tls bindings, invite cards, fleet reports) — the tag stops one signature
    being replayed as another kind of statement.
  - `ts` is INSIDE the signed payload, so a third party cannot strip/rewind it to
    defeat the relay's monotonic anti-rollback guard.
  - Curve-agnostic: verifies via crypto.verify (ed25519 core / p256 optional backend),
    so a future P-256/WebAuthn DID's card still verifies (same as shared/fleet.py).
  - The relay VERIFIES this envelope at deposit (a node publishes only for its OWN
    self-certifying did:key), and every fetcher RE-verifies it locally — the relay is
    never trusted. Verifying a public card erodes no confidentiality (it never touches
    a message blob), so the relay's "blind to message content" posture is intact.

Reuses shared/crypto only (zero deps), mirroring shared/invite.py + shared/fleet.py.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

from typing import Any

from shared import crypto

CARD_ENVELOPE_VERSION = 1
CARD_ENVELOPE_TYPE = "agentcard"


def _envelope_payload(card: dict[str, Any], ts: float) -> bytes:
    """Canonical signed bytes: version + type + card + ts (never the sig itself).
    crypto.canonical sorts keys recursively, so the bytes are independent of JSON
    key order — an envelope round-tripped through the relay re-verifies exactly.

    `ts` is canonicalized AS GIVEN — the payload builder never casts it, so the signed bytes are
    exactly the wire type (the rule `crypto.signing_payload` follows: canonicalize what the wire
    carried, never what you wish it carried). This matters because `crypto.canonical` renders a float
    via Python's `repr`, which a non-Python verifier (e.g. the Swift `SeamKit.canonical`, whose value
    type has no float case) cannot reproduce — so ANY signed artifact carrying a float `ts` is, by
    construction, unverifiable outside Python.

    HONEST CURRENT STATE (do not misread as "floats are gone"): the shipped publisher
    `agent/outbox.publish_card` still passes `time.time()` (a FLOAT), so a real published card today
    carries a float and is Python-only to verify — as are ~12 other signed artifacts
    (site/fleet/keystate/guardianset/recovery/deal/org/ygg/tls/vc/revocations). Flipping publishers to
    int epoch seconds is a COORDINATED migration (the running relay/fleet still `float(ts)`-cast at
    verify, so an uncoordinated flip 400-rejects live cards). When that migration lands, this
    note becomes "publishers pass int epoch seconds"."""
    return crypto.canonical({
        "v": CARD_ENVELOPE_VERSION,
        "typ": CARD_ENVELOPE_TYPE,
        "card": card,
        "ts": ts,
    })


def make_card_envelope(identity, card: dict[str, Any], ts: float) -> dict[str, Any]:
    """Wrap `card` (a shared/protocol.build_agent_card dict) in a signed envelope.
    The sig covers canonical(v,typ,card,ts) and `card["did"]` is the signer, so the
    relay and any fetcher verify against the same DID — nobody can publish under
    another identity's DID."""
    return {
        "v": CARD_ENVELOPE_VERSION,
        "typ": CARD_ENVELOPE_TYPE,
        "card": card,
        # epoch seconds AS GIVEN (a float today; int after the migration — see _envelope_payload).
        # The wire type IS the signed type: do NOT cast here, or the wire would carry a value that
        # `_envelope_payload` did not sign. Both must take `ts` as given so they can never disagree.
        "ts": ts,
        "sig": identity.sign_bytes(_envelope_payload(card, ts)),
    }


def verify_card_envelope(envelope: Any,
                         expected_did: str | None = None) -> dict[str, Any] | None:
    """Return the inner card iff the envelope is authentic, else None (never raises).

      1. shape present (v/typ/card/ts/sig and card["did"]);
      2. typ is the card-envelope tag (domain separation);
      3. sig verifies under card["did"] over canonical(v,typ,card,ts);
      4. expected_did is None OR card["did"] == expected_did — the anti-substitution
         check: the signature only proves "X signed X's card"; binding the caller's
         requested DID proves it is the identity that was actually asked for.
    """
    try:
        if not isinstance(envelope, dict):
            return None
        if envelope.get("typ") != CARD_ENVELOPE_TYPE:
            return None
        card = envelope.get("card")
        ts = envelope.get("ts")
        sig = envelope.get("sig")
        if not (isinstance(card, dict) and card.get("did")
                and sig is not None and ts is not None):
            return None
        did = card["did"]
        if expected_did is not None and did != expected_did:
            return None
        sig_raw = crypto.b64_strict(sig)
        if sig_raw is None:
            return None
        # No LENGTH bound, unlike the twin's flat 64 (js/seam.mjs `verifyCardEnvelope`): that
        # side reads an Ed25519 card DID or nothing, while this envelope is documented
        # curve-agnostic in the header above -- a P-256 / WebAuthn DID's card verifies here,
        # and such a signer emits ASN.1 DER of ~70-72 bytes. A wrong-length Ed25519 signature
        # is already refused one line later by `crypto.verify`, so a flat 64 would change no
        # verdict on any card the twin can read and would refuse a publisher this module
        # promises to read. The spelling was the split; the length is not.
        # `ts` AS RECEIVED — the `float(ts)` that was here is what makes this verifier able to read
        # an OLDER node's card at all: those envelopes carry a float on the wire, so canonicalizing
        # what arrived reproduces their signed bytes exactly. Coercing instead would have re-rendered
        # a new node's int as "…​.0" and rejected every card it publishes.
        if not crypto.verify(did, sig_raw, _envelope_payload(card, ts)):
            return None
        return card
    except Exception:
        return None
