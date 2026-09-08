"""
shared/protocol.py
A2A-compatible wire format + the L2 signing envelope.

L2 extension: the signing envelope rides in the Message metadata
  metadata: { from: <DID>, to: <DID>, sig: <base64>, timestamp: <epoch> }
See shared/crypto.signing_payload for the signed payload.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from shared import peercompat, version

PROTOCOL_VERSION = "0.2"

# A2A Agent Card discovery paths (RFC 8615 well-known URIs). The current A2A spec serves
# the card at /.well-known/agent-card.json; /.well-known/agent.json is the LEGACY path.
# We serve BOTH (agent-card.json canonical + agent.json alias) and, when fetching a peer,
# try the canonical path first and fall back to the legacy one — so a node mid-migration
# interoperates with peers on either path (our own already-deployed fleet is on the old
# path). AGENT_CARD_PATHS is the ordered (canonical-first) tuple fetchers iterate.
AGENT_CARD_PATH = "/.well-known/agent-card.json"
AGENT_CARD_PATH_LEGACY = "/.well-known/agent.json"
AGENT_CARD_PATHS = (AGENT_CARD_PATH, AGENT_CARD_PATH_LEGACY)

# T85: the SIGNED sibling of the plain card — the SAME card dict wrapped in a
# shared/cardpub envelope (Ed25519 over canonical(v,typ,card,ts), signed by card["did"]).
# ADDITIVE ONLY: the plain A2A card at AGENT_CARD_PATHS stays byte-identical, so A2A
# compatibility (CLAUDE.md principle 4) is untouched and an A2A-only client never sees
# this path. It exists because the plain card is a self-assertion — anyone can serve a
# card claiming anyone's DID — so `peer add` had no way to prove a DID->url binding
# without going through the relay. Fetching the envelope here proves the claimed DID's
# OWN key signed a card, and requiring that card's `url` to share the dialled ORIGIN
# proves it signed a card for THIS host (otherwise a re-served copy of a victim's
# genuine envelope would pass). See Outbox.fetch_card_verified.
AGENT_CARD_SIG_PATH = "/.well-known/agent-card.sig.json"


def new_id() -> str:
    return uuid.uuid4().hex


def message_id_ok(message_id: Any) -> bool:
    """True when `messageId` can key replay/dedup. An explicit empty string is
    not a missing key: `from_a2a` used to keep `""`, which made async
    `msglog.has`/`claim` no-ops — an empty key silently disabled replay defence."""
    return isinstance(message_id, str) and bool(message_id.strip())


# ---------------------------------------------------------------- Message

@dataclass
class Message:
    role: str                       # "user" (sender) / "agent" (responder)
    text: str
    messageId: str = field(default_factory=new_id)
    contextId: str | None = None
    #: INTEGER epoch seconds — the signed wire contract (see the note below).
    #:
    #: The annotation stays `float` on purpose: a message RECEIVED from an older node carries a
    #: fractional timestamp and must still parse and verify. We only stop MINTING them.
    #:
    #: Why this changed. `timestamp` is inside the signed payload, and `crypto.signing_payload`
    #: does NOT cast — it canonicalizes whatever type the wire carried. So the wire type IS the
    #: contract, and a float one is a contract no other language can hold: Python renders
    #: 1784273681.04038 with its own shortest-round-trip repr, and a client must reproduce those
    #: bytes exactly or the signature is unverifiable, with "signature verification failed" as the
    #: only clue. The Swift seam does not even try — `SeamKit.canonical`'s value type has no float
    #: case ("floats are avoided by design") — which is why the iOS client could never verify a
    #: message a Python node sent it, and (measured 2026-07-17) ended up verifying nothing at all.
    #: Integers side-step the whole class: every language renders 1784273681 identically.
    #:
    #: Backward compatible in BOTH directions, which is what makes it safe to ship into a live
    #: fleet: an old node re-canonicalizes the int it receives (no cast) and verifies us fine, and
    #: we re-canonicalize its float and verify it fine.
    timestamp: float = field(default_factory=lambda: int(time.time()))
    # ---- L2 signing envelope ----
    from_did: str | None = None
    to_did: str | None = None
    sig: str | None = None          # base64(Ed25519 signature)
    # ---- L3 WoT extension (optional) ----
    # On first contact, attach a handshake introduction (shared/vc.py). We only
    # add a new `vc` key to metadata without changing the meaning of existing
    # fields, so A2A compatibility is preserved.
    vc: dict[str, Any] | None = None
    # ---- auto-reply hint (optional, UNSIGNED) ----
    # Marks a message as machine-generated (an auto-responder). Additive metadata
    # like `vc`; NOT part of the signed payload, so it is a politeness/loop hint,
    # not a security boundary. Used to surface 🤖 in the UI and to bound auto↔auto
    # ping-pong (see agent/msglog.auto_streak + the operator turn cap).
    auto: bool = False
    # ---- coordination payload (optional, UNSIGNED) ----
    # A small structured turn for goal-driven coordination (scheduling a meeting,
    # planning a trip, ...): {type: propose|counter|accept|confirm|cancel, goal?,
    # options?, choice?, ref?}. Additive metadata like `vc`/`auto`; the signed
    # `text` carries the human-readable content, this mirrors it as structure the
    # UI and a brain can act on. See agent/coordination.py.
    coordination: dict[str, Any] | None = None
    # ---- group overlay (optional, UNSIGNED) ----
    # Group-chat context for a message that is part of a room: {room_id, name,
    # host, author, members:[{did,name,role}], mentions:[did]}. Additive metadata
    # like `vc`/`auto`/`coordination`; NOT part of the signed payload, so a
    # group-unaware client safely ignores it and still threads the message 1:1 by
    # the (unchanged, pairwise) contextId. It carries the speaker/roster/mention
    # boundary a client needs so its LLM can tell participants apart instead of
    # collapsing them into one "user". Set by room.py on broadcast; see
    # docs/GROUP_MENTIONS.md. A detached `group.sig` is a future (Phase 3) option.
    group: dict[str, Any] | None = None
    # ---- reply pointer (optional, UNSIGNED) ----
    # The messageId of the message this one replies to (Slack/Twitter-thread style).
    # Threading itself is already carried by the SIGNED contextId (and the group
    # overlay's room_id); replyTo is the finer-grained "in reply to message X"
    # pointer a client renders as a thread tree. Additive metadata like `group`/
    # `auto`/`coordination`; NOT part of the signed payload, so it is a UI/threading
    # hint, not a security boundary (a malicious hub/relay could rewrite it). If
    # tamper-proof reply attribution is ever needed, promote it into the signed
    # payload — a deliberate, owner-gated protocol change. The network only DEFINES
    # this field (so clients interoperate); building/rendering the tree is the
    # client's job. See docs/GROUP_MENTIONS.md.
    # RESERVED: `replyToSig`, a DETACHED signature, is the shape reserved for making this
    # tamper-proof. It is not in the six signed fields and must not be added to them.
    replyTo: str | None = None
    # ---- deal receipt (optional, additive) ----
    # A bilateral, hash-committed deal receipt exchanged between two parties:
    # {kind: "offer"|"receipt", receipt: <shared/deal.py record>, terms?, salt?}.
    # The receipt itself carries its OWN 2-of-2 signatures (sigA/sigB over a
    # canonical payload) — that is where its security lives, exactly like `vc`
    # carries its own proof. So `deal` rides as additive metadata (not part of the
    # message's signed envelope), like `vc`/`coordination`/`group`. `terms`+`salt`
    # are included only on an "offer" so the counterparty can verify the commitment
    # (H(terms‖salt)==termsHash); the durable receipt itself is hash-only. See
    # shared/deal.py and docs/IMPLEMENTATION_BACKLOG.md T16.
    deal: dict[str, Any] | None = None
    # ---- gifted introduction (optional, additive) ----
    # A "held" introduction handed to the recipient for OUTBOUND use — e.g. a Room
    # broker minting an introduction of member X to member Y sends X this VC so X can
    # later first-contact Y. Distinct from `vc` (the GATE credential the recipient
    # presents about THEMSELVES): here `held_vc` names the recipient as the subject
    # and someone ELSE as introducedTo, so the recipient stores it (add_held_intro)
    # rather than being admitted by it. The VC carries its own proof, so all of these
    # ride as additive metadata like `vc`/`deal` (not part of the signed envelope).
    # See room.py `/introduce` and agent/inbox.py (store on receipt from a trusted peer).
    #
    # The VC names only DIDs, so HOW to reach the target rides alongside it:
    # `held_vc_url` is the target's HTTP endpoint, and `held_vc_relay` +
    # `held_vc_enc_pub` are its relay coordinates. A relay-only target has no url, so
    # without the relay pair the recipient holds an introduction it cannot act on
    # (agent_mcp.contact_expert refuses: "no way to reach them"). The referral (pull)
    # path already returns the same three, so the gifted (push) path matches it.
    held_vc: dict[str, Any] | None = None
    held_vc_url: str | None = None
    held_vc_relay: str | None = None
    held_vc_enc_pub: str | None = None

    # ---- KeyState (key rotation, optional, self-signed) ----
    # A root-signed KeyState (shared/keystate.py) delegating this sender's current
    # rotatable operational signing key. Ridden inline so an aware receiver can resolve
    # + pin the op-key on first contact without a card fetch. Additive metadata like
    # `vc`/`deal`: it carries its OWN root signature (not part of the six signed fields),
    # and the message's `from` stays the stable root DID. Absent for a sender that
    # never persisted (in-memory test identities); a persisted local identity
    # carries a genesis KeyState by default (T142 A2).
    keystate: dict[str, Any] | None = None
    # ---- DeviceKeyBinding (owner account, optional, self-signed) (T102) ----
    # A countersigned v2 DeviceKeyBinding (shared/keybinding.py) proving this
    # sender's device DID belongs to an OWNER DID, so receive-side account
    # resolution can collapse sibling devices into one account. Additive metadata
    # exactly like `keystate`: it carries its OWN two signatures (owner + device,
    # over canonical bytes that include `typ`), it is NOT part of the six signed
    # fields, and `from` stays the wire (device) DID. Absent for unbound senders
    # (the whole existing fleet) — the receive path is then byte-identical.
    # Present-but-invalid is rejected fail-closed (agent/inbox._resolve_account).
    binding: dict[str, Any] | None = None
    # ---- additive signatures (T142 A3, optional) ----
    # `[{alg, sig}, …]` beside `sig`. Unknown algs are skipped (forward
    # compatibility). A known alg that fails to verify is refused even when
    # `sig` passes. Not part of the six signed fields.
    sigs: list | None = None

    def to_a2a(self) -> dict[str, Any]:
        out = {
            "kind": "message",
            "role": self.role,
            "parts": [{"kind": "text", "text": self.text}],
            "messageId": self.messageId,
            "contextId": self.contextId,
            "metadata": {
                "timestamp": self.timestamp,
                "from": self.from_did,
                "to": self.to_did,
                "sig": self.sig,
                "vc": self.vc,
                "auto": self.auto,
                "coordination": self.coordination,
                "group": self.group,
                "replyTo": self.replyTo,
                "deal": self.deal,
                "held_vc": self.held_vc,
                "held_vc_url": self.held_vc_url,
                "held_vc_relay": self.held_vc_relay,
                "held_vc_enc_pub": self.held_vc_enc_pub,
                "keystate": self.keystate,
                "binding": self.binding,
            },
        }
        # T142 A3: omit when absent so today's envelopes stay byte-identical.
        if self.sigs is not None:
            out["metadata"]["sigs"] = self.sigs
        return out

    @classmethod
    def from_a2a(cls, obj: dict[str, Any]) -> "Message":
        if obj.get("kind") != "message":
            raise ValueError("not a message object")
        # `or []` (not a default arg): an inbound A2A object with "parts": null
        # would make `.get("parts", [])` return None and the loop TypeError — the
        # same reason `metadata` below is guarded with `or {}`.
        texts = [p.get("text", "") for p in (obj.get("parts") or [])
                 if isinstance(p, dict) and p.get("kind") == "text"]
        meta = obj.get("metadata") or {}
        # Missing key -> mint (local / incomplete objects). Present-but-empty is
        # an attacker-chosen id that disables durable dedup; refuse it here so
        # every from_a2a caller (not only verify) sees the same contract.
        if "messageId" in obj:
            mid = obj["messageId"]
            if not message_id_ok(mid):
                raise ValueError("messageId must be a non-empty string")
        else:
            mid = new_id()
        return cls(
            role=obj.get("role", "user"),
            text="\n".join(texts),
            messageId=mid,
            contextId=obj.get("contextId"),
            # A timestamp the peer SENT is used verbatim — never coerced. The signature is over
            # the type that was on the wire, so casting here would make an old node's float, or a
            # client's int, unverifiable. The default only matters for an unsigned local message.
            timestamp=meta.get("timestamp", int(time.time())),
            from_did=meta.get("from"),
            to_did=meta.get("to"),
            sig=meta.get("sig"),
            vc=meta.get("vc"),
            auto=bool(meta.get("auto", False)),
            coordination=meta.get("coordination"),
            group=meta.get("group"),
            replyTo=meta.get("replyTo"),
            deal=meta.get("deal"),
            held_vc=meta.get("held_vc"),
            held_vc_url=meta.get("held_vc_url"),
            held_vc_relay=meta.get("held_vc_relay"),
            held_vc_enc_pub=meta.get("held_vc_enc_pub"),
            keystate=meta.get("keystate"),
            binding=meta.get("binding"),
            sigs=meta.get("sigs"),
        )


# ---------------------------------------------------------------- Agent Card

def skills_from_profile(profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Build the A2A-standard `skills` list for an agent.

    Always advertises the base messaging capability (`signed-direct-chat`).
    When a T10 profile carries tags/role, it ALSO appends an `expertise` skill so
    a peer can discover *what an agent does* by reading the card alone — without
    having to send a probe message and wait for a reply. This puts the domain in
    the standard `skills` array (which generic A2A clients read), not only in the
    Muretai-specific `profile` field."""
    skills: list[dict[str, Any]] = [{
        "id": "chat",
        "name": "signed-direct-chat",
        "description": "Ed25519-signed direct messages (L2)",
        "tags": ["chat", "signed"],
    }]
    if profile:
        tags = list(profile.get("tags") or [])
        role = profile.get("role")
        bio = profile.get("bio")
        if tags or (role and role != "specialist") or bio:
            desc = bio or (("Handles: " + ", ".join(tags)) if tags
                           else "Domain expertise")
            skills.append({
                "id": "expertise",
                "name": role or "specialist",
                "description": desc,
                "tags": tags,
            })
    return skills


# Only these profile fields are PUBLIC and may ride on the signed Agent Card. The
# stored profile.json ALSO holds private/operational fields — `webhook_token` (a bearer
# secret!), `webhook_url`, `preauthorized` (the owner's auto-approve allowlist), `intent`
# (a private negotiation goal, documented in agent/profile.py as "never signed"),
# `brain`/`beatless_cmd`, `relay`, and the gate-policy knobs (`trust_query`,
# `connect_policy`, `revocation_policy`, `dm_policy`, …). None of those may be signed into
# a card that `publish_card` posts to the relay's DID-addressed directory and that anyone
# holding the DID can fetch (`GET /card/<did>`). This whitelist is the documented T10
# surface (SPECIFICATION.md §1: "profile (tags/bio/affiliation/role)"); `display_name` is
# the owner's chosen public name. Anything not on this list stays off the card: a profile is
# a place operators put secrets, and a card is fetched by anyone holding the DID.
PUBLIC_PROFILE_FIELDS = ("display_name", "bio", "tags", "affiliation", "role")


def public_profile(profile: dict[str, Any] | None) -> dict[str, Any] | None:
    """Project a stored profile down to the fields safe to publish on the Agent Card.

    Defense-in-depth: the card carries ONLY `PUBLIC_PROFILE_FIELDS`, so a private field
    (a webhook bearer token, the pre-authorization allowlist, a private `intent`) can
    never leak into a signed, published card regardless of what the caller passes in.
    Returns None when no public field is present, so the card omits `profile` exactly as
    it did before for an agent with no SNS fields set."""
    if not profile:
        return None
    pub = {k: profile[k] for k in PUBLIC_PROFILE_FIELDS if k in profile}
    return pub or None


def build_agent_card(name: str, description: str, url: str, did: str,
                     skills: list[dict[str, Any]] | None = None,
                     profile: dict[str, Any] | None = None,
                     relay: str | None = None,
                     enc_pub: str | None = None,
                     ygg: dict[str, Any] | None = None,
                     tls: dict[str, Any] | None = None,
                     org: dict[str, Any] | None = None,
                     contact: dict[str, Any] | None = None,
                     domains: "list[str] | None" = None,
                     udp: dict[str, Any] | None = None,
                     iroh: dict[str, Any] | None = None,
                     muretai: dict[str, Any] | None = None,
                     room: dict[str, Any] | None = None,
                     enc_pub_pq: str | None = None,
                     front: dict[str, Any] | None = None
                     ) -> dict[str, Any]:
    """A2A-compatible Agent Card. The "did" field is this project's extension
    (intended to become part of a future WoT extension proposal to A2A).

    `profile` (T10) is an additive SNS-style profile (tags/bio/affiliation/role);
    it only adds a field and never changes existing ones, so A2A compatibility is
    preserved.
    `iroh` (T129) is the signed transport binding authorizing the direct QUIC fast
    path; additive and optional, absent entirely unless the operator turned the fast
    path on.
    `relay`/`enc_pub` (T11) advertise a store-and-forward relay URL and the
    X25519 public key (hex) for E2E sealing — additive only, never changing
    existing fields.
    `domains` (T88) is the reverse half of a domain binding: the names this agent
    claims to speak for. Additive and evidence-free by design — see the comment at
    the emit site.
    `muretai` (T20) is an additive capability block letting an A2A-only client
    feature-detect this node's trust/identity/discovery layer (WoT participation,
    the trust/status query, MCP-brain bindability, and the supported RPC methods)
    straight from the card.
    `room` (T23, GROUP_TYPES.md) is the additive group self-description
    (`muretai.room`): when given it is nested under `muretai.room` so a Room
    advertises that it IS a group and WHAT type (the 4-axis policy + member count).
    Additive only: a non-room agent passes room=None and gets no `muretai.room`,
    so unaware clients are unaffected. If `muretai` is None but `room` is given we
    create a minimal muretai block to carry it (the room IS muretai-layer info)."""
    card = {
        "protocolVersion": PROTOCOL_VERSION,
        "name": name,
        "description": description,
        "url": url,
        "did": did,                  # <- L2 extension: the agent's decentralized identity
        "version": version.installed_version(),  # single source of truth (shared/version.py)
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": skills or [],
    }
    pub_profile = public_profile(profile)
    if pub_profile:
        card["profile"] = pub_profile  # <- T10 extension: PUBLIC fields only (public_profile);
                                       #    private profile keys (webhook_token/preauthorized/
                                       #    intent/…) are stripped, never published
    if relay:
        card["relay"] = relay     # <- T11: relay URL for store-and-forward E2E transport
    if enc_pub:
        card["enc_pub"] = enc_pub  # <- T11: X25519 public key (hex) for E2E sealing
    if enc_pub_pq:
        card["enc_pub_pq"] = enc_pub_pq  # <- T142 B2: ML-KEM-768 pub (hex); unsigned
                                         #    like enc_pub. Seal prefers the KeyState
                                         #    hash-binding when pinned.
        cap = card.setdefault("capabilities", {})
        pq = cap.setdefault("pq", {})
        kems = list(pq.get("kem") or [])
        if "mlkem-768" not in kems:
            kems.append("mlkem-768")
        pq["kem"] = kems
    if ygg:
        card["ygg"] = ygg  # <- T14: signed binding {did, yggPub, yggAddr, ts, sig}
                           #    authorizing a routable overlay (Yggdrasil) address
    if tls:
        card["tls"] = tls  # <- signed binding {did, certFp, ts, sig} pinning the
                           #    self-signed cert on the https direct endpoint to the DID
    if org:
        card["org"] = org  # <- signed OrgMembership {orgDid, agentDid, role, …, sig}
                           #    (shared/orgbind.py) — this agent provably belongs to an
                           #    org; a peer verifies it pinned to THIS card's did on contact
    if contact:
        card["contact"] = contact  # <- signed ContactGrant {typ:"contact-grant", did, uses,
                                   #    exp, …, sig} (shared/contactgrant.py) — a storefront's
                                   #    publishable front door: a cold visitor redeems it
                                   #    (contact/redeem) to become a bounded connection
    if front:
        # T143: signed live-front door {typ:"muretai/front/1", did, mode, paths,
        # ts, validUntil, sig}. Additive — a card without one is unchanged.
        # The object is NOT key authority (see shared/front.py). /v1 is
        # refused at mint; the relay later 404s it rather than fall through.
        card["front"] = front
    if domains:
        # T88: the domains this agent CLAIMS to speak for — the REVERSE EDGE only.
        # Deliberately just a list of names and NOT a credential: the proof lives at
        # the domain (its /.well-known/did-configuration.json serves a Domain Linkage
        # Credential signed by this DID, shared/domainbind.py), and a signed blob here
        # would only be the same self-assertion twice. A verifier needs BOTH halves —
        # the domain naming the DID and the card naming the domain back — so this list
        # is what makes the binding bilateral: without it, a hostile domain could list a
        # victim's DID and claim the victim as its own agent. It is a CLAIM, never
        # evidence; reading it should trigger a fetch, not a belief.
        #
        # NOT a profile field, on purpose: PUBLIC_PROFILE_FIELDS is the owner's
        # free-text SNS surface, and everything in it is whatever the owner typed. A
        # domain list is machine-consumed input to a verification procedure, so it lives
        # at the card's top level beside the other bindings (org/tls/ygg) rather than
        # inside a bag of prose. Capped at the same 5 as agent/domainstore.MAX_CARD_DOMAINS
        # (hardcoded rather than imported: shared/ must not depend on agent/) — every
        # domain listed is an outbound HTTPS fetch this agent asks strangers to make.
        card["domains"] = [str(d) for d in domains][:5]
    if udp:
        card["udp"] = udp  # <- T61: UDP hole-punch CAPABILITY marker, e.g.
                           #    {"v":1,"reflector":"host:port"}. A capability + the
                           #    reflector this node uses — NEVER an ephemeral ip:port
                           #    (a punched mapping is learned live via signaling, not
                           #    the signed card). Signals "I can do direct-UDP punch".
    if iroh:
        card["iroh"] = iroh  # <- T129: the SIGNED, endpoint-countersigned transport
                             #    binding {typ,did,endpointId,relay,ts,validUntil,sig,
                             #    endpointSig} authorizing the direct QUIC fast path
                             #    (shared/irohbind.py). Unlike `udp` above this is not a
                             #    capability marker but a verifiable statement, because
                             #    the well-known card is unsigned and its DID-keyed copy
                             #    lives in a mutable directory — an unsigned coordinate
                             #    would be an on-path attacker's field to fill in, and a
                             #    swapped fallback relay is both a denial of service and a
                             #    seat from which to watch who talks to whom. NEVER any
                             #    direct ip:port: those leak the operator's network
                             #    location and go stale, and the transport discovers live
                             #    paths by itself (same rule as `udp`).
    # T20 capability block; T23 nests the group self-description under it. Built
    # UNCONDITIONALLY since 2026-09-01, because of the three fields below: every card
    # must say what the process serving it is RUNNING, including a card that carries no
    # other muretai capability. When only `room` is given we still surface it, since
    # "this is a group of type X" is muretai-layer info an A2A-only client
    # feature-detects exactly like the rest of the block.
    block = dict(muretai) if muretai else {}
    if room:
        block["room"] = room       # <- T23: group self-description (GROUP_TYPES.md §3)
    # The RUNNING process (shared/version constants), not `installed_version()`. The
    # top-level `version` above is the marker semver — what this box is INSTALLED at —
    # and a resident that was never restarted after an updater swap reports the NEW
    # marker while still executing the OLD code. That gap is what makes a version split
    # invisible: the peer looks current on every surface, and the only symptom is a decrypt
    # bounce that names the relay, which had nothing to do with it. A peer cannot ask "are you
    # actually running what you claim" unless the card answers it. See shared/peercompat.
    block.update(peercompat.card_muretai_version_fields())
    card["muretai"] = block
    return card


# ---------------------------------------------------------------- JSON-RPC 2.0

PARSE_ERROR = {"code": -32700, "message": "Parse error"}
INVALID_REQUEST = {"code": -32600, "message": "Invalid Request"}
METHOD_NOT_FOUND = {"code": -32601, "message": "Method not found"}
INVALID_PARAMS = {"code": -32602, "message": "Invalid params"}
INTERNAL_ERROR = {"code": -32603, "message": "Internal error"}
# ---- L2 extension errors ----
UNAUTHENTICATED = {"code": -32001, "message": "Signature verification failed"}
REPLAY_REJECTED = {"code": -32002, "message": "Replay or stale message"}
WRONG_RECIPIENT = {"code": -32003, "message": "Message not addressed to me"}
RATE_LIMITED = {"code": -32004, "message": "Rate limited"}
MESSAGE_TOO_LARGE = {"code": -32005, "message": "Message text too large"}

#: Maximum size of a message's `text`, in UTF-8 bytes.
#:
#: A message is signed, fanned out and stored forever, so an unbounded `text` is
#: unbounded cost on machines that never agreed to it: a room post is delivered
#: to every member AND carries its own text twice (once in `text`, once inside
#: the `author_proof` envelope), so one post costs roughly 2x(N-1) copies of it.
#: Before this, the only ceiling was the incidental 1 MiB HTTP body cap in
#: shared/httputil.py — a memory-safety backstop, not a protocol rule.
#:
#: 64 KiB is ~8x the largest message ever actually sent on the network (8,117
#: chars, measured 2026-08-05), and leaves room under the body cap even for the
#: room case after base64 sealing inflates it ~33%.
#:
#: Measured in BYTES, not characters: a limit in characters is not a limit on
#: what anyone has to store, since one character can be four bytes.
MAX_TEXT_BYTES = int(os.environ.get("AGENTNET_MAX_TEXT_BYTES", str(64 * 1024)))


def text_too_large(text: str | None) -> int:
    """Bytes over MAX_TEXT_BYTES, or 0 if the text is within the limit.

    One helper so the send side, the receive side and the relay cannot drift
    into three different notions of "too large"."""
    n = len((text or "").encode("utf-8"))
    return max(0, n - MAX_TEXT_BYTES)
# ---- L3 WoT extension errors ----
INTRO_REQUIRED = {"code": -32010, "message": "Introduction required"}
INTRO_INVALID = {"code": -32011, "message": "Introduction invalid or revoked"}
FORBIDDEN_QUERY = {"code": -32012, "message": "Trust query not permitted"}
# The introduction is cryptographically valid and unrevoked, but its issuer is
# not a direct contact of the recipient — so we do not honor the vouch. Kept
# distinct from -32011 (invalid/revoked) so the sender gets the right remedy:
# get introduced by someone the recipient actually knows (a mutual), or send a
# connect/request. See Inbox._gate / TrustStore.is_allowed.
INTRO_UNTRUSTED_ISSUER = {"code": -32013,
                          "message": "Introduction issuer not trusted"}
# An introduction naming this sender EXISTS and is valid, but the recipient has not
# accepted it yet (introduce/propose is queued for their review). Distinct from
# -32010 (no introduction at all) because the remedy is different: wait — a human or
# their agent is deciding. Normally the sender never sees this: the recipient HOLDS
# the first contact on the review row and replays it on approval. It is emitted only
# when holding is impossible (a group message, an empty body, or a full queue).
INTRO_NOT_ACCEPTED = {"code": -32014,
                      "message": "Introduction awaiting recipient approval"}
# (T88) The recipient requires a VERIFIED DOMAIN BINDING from the sender and this
# node holds no fresh verdict for that DID (profile.domain_gate == "require", an
# opt-in stricter than the introduction ladder above — the sender may be perfectly
# well introduced and still land here). Distinct from -32010/-32011 because the
# remedy is neither an introduction nor a fresh vouch: the sender must bind a domain
# to its DID (host the Domain Linkage Credential, name the domain back on its card)
# and let the recipient re-run a verification. Absence of a cached verdict IS the
# refusal — the gate never fetches (see Inbox._gate).
DOMAIN_REQUIRED = {"code": -32015, "message": "Verified domain required"}
# The node does not run the trust layer AT ALL, so there is nothing here to judge an
# introduction against. Distinct from -32011 for the reason -32013 and -32014 are distinct
# from it: the remedy is different, and -32011's own message asserts something FALSE here.
# "Introduction invalid or revoked" is a verdict on the asker's introduction; a caller
# reading the code — which is what a client library surfaces — concludes it was rejected on
# the merits and stops, when the correct action is to tell the far side to start its node
# with --wot. Measured 2026-09-02: an honest introducer spent a round trip on that.
INTRO_LAYER_OFF = {"code": -32016,
                   "message": "This node does not run the trust layer"}
# ---- connect-request errors (asymmetric member-to-member connection) ----
CONNECT_REFUSED = {"code": -32020, "message": "Connect requests not accepted"}
CONNECT_NOT_PENDING = {"code": -32021, "message": "No such pending request"}
CONNECT_ALREADY = {"code": -32022, "message": "Already connected"}
# ---- relay transport (listener fencing, T11) ----
# A newer listener for this DID has superseded an older long-poll. Last-writer-wins
# fencing guarantees AT MOST ONE active drainer per DID, so two instances of the
# same identity can never silently split (and half-drop) the inbound queue.
SUPERSEDED_LISTENER = {"code": -32030,
                       "message": "Superseded by a newer listener for this DID"}
# ---- key rotation (KeyState delegation, shared/keystate.py) ----
# The sender rotated to an operational sub-key the verifier can't currently resolve —
# it holds no/stale KeyState. Soft: the peer should (re)fetch the card/KeyState and
# retry (not a hard authentication failure). Reserved; the inline-keystate path uses
# -32001 today, this is the resolve-by-DID (card directory) remedy.
ROTATION_REQUIRED = {"code": -32040, "message": "Rotation required — refresh KeyState"}
# A presented KeyState is invalid: op-key not delegated, epoch superseded/downgraded
# (anti-rollback), op-key revoked, or outside its validity window.
KEYSTATE_INVALID = {"code": -32041, "message": "KeyState invalid or superseded"}
# A KeyState / GuardianSet / migration root signature failed, or a pre-rotation
# preimage (opNextHash/rootNextHash) mismatched on reveal.
CONTROLLER_SIG_INVALID = {"code": -32043,
                          "message": "Controller signature invalid"}
# A guardian recovery migration is below the pinned threshold, an attester is not in the
# verifier's pinned GuardianSet, or an attestation's (old,new,guardiansHash) binding mismatched.
RECOVERY_ATTESTATION_INVALID = {"code": -32042,
                                "message": "Recovery attestation invalid or below threshold"}
# A recover migration is still inside its dispute window (effectiveAfter not reached), or was
# vetoed by a valid AbortRecovery / superseding live-root KeyState (no duplicity override).
MIGRATION_PENDING_OR_VETOED = {"code": -32044,
                               "message": "Migration pending or vetoed"}
# The new key did not consent (RecoveryClaim missing/invalid) or does not control newDid.
MIGRATION_CLAIM_INVALID = {"code": -32045, "message": "Migration claim invalid"}
# ---- remote ops (T118 R0, agent/remoteops.py + agent/inbox._serve_remote_op) ----
# A remote-ops envelope (`muretai/ops/1` in the signed text) reached a node whose
# executor is ON, from an authenticated peer that is NOT a paired device of this
# node's owner. Deliberately distinct from -32010: only already-gated peers ever
# reach the executor, so the disclosure ("this node runs remote ops") is a
# recorded, harmless divergence — while a STRANGER's attempt still dies in the
# gate with the ordinary -32010, and a REVOKED device is refused with the
# stranger's exact -32010 code and sentence (concealment, the T102 posture).
REMOTE_OPS_REFUSED = {"code": -32046, "message": "Remote ops refused"}
# An owner device asked for a verb outside the allowlist or outside its own
# capability set (keys/account/devices.json). The remedy is a node-side grant,
# not a different credential.
REMOTE_OPS_VERB_DENIED = {"code": -32047, "message": "Remote ops verb denied"}
# (The -32050/-32051 pair is double-reserved elsewhere — T61 UDP vs room memory —
# and deliberately NOT used here.)

# ---- DID-gated artifacts (T70, band -32060..-32069) ----
# Uniform, detail-free refusal: unknown / never-granted / revoked / deleted /
# storeless. Anti-enumeration — the four cases MUST be byte-identical on the wire
# (handle_rpc omits `data` when detail is empty; handlers pass "").
ARTIFACT_UNAVAILABLE = {"code": -32060, "message": "Artifact unavailable"}
# Expired or fetch-count exhausted. Only ever returned to a DID that was NAMED
# in a grant — a stranger still sees -32060.
ARTIFACT_GRANT_EXHAUSTED = {"code": -32061,
                            "message": "Artifact grant expired or exhausted"}


# ------------------------------------------------- capability degradation (R2)
# What a caller may do when a peer refuses a method with -32601. The class is a
# property of the OPERATION, fixed here, never of what the peer advertised: a peer
# must not be able to induce a weaker code path by lying in its card or in its
# refusal. Fail OPEN on reachability (always attempt the modern method), fail
# CLOSED on privilege (nothing arriving from the network authorizes a downgrade).
#
#   A  transport/representation — same semantics, different bytes. Silent, automatic.
#   B  consent-preserving loss  — the operation gets poorer; NOBODY gains access.
#                                 Fail loudly, naming the peer's build and the remedy.
#   C  consent-weakening        — the fallback would grant access the far side never
#                                 agreed to. REFUSE by default; only an explicit
#                                 per-invocation operator flag may authorize it.
#   D  unknown capability       — no card, `methods` null, 404. Attempt the method.
DEGRADE_TRANSPORT = "A"
DEGRADE_LOSSY = "B"
DEGRADE_CONSENT = "C"
DEGRADE_UNKNOWN = "D"

#: Every JSON-RPC method this protocol defines, mapped to its degradation class.
#: A new method cannot be added to the dispatch table without appearing here —
#: `agent.inbox` binds handlers against these keys and a test asserts the two key
#: sets are identical in BOTH directions, so classification cannot be skipped.
#:
#: Only `introduce/propose` is class C, and that is the finding this table exists
#: for: falling back to the legacy bare-VC gift opens the TARGET's gate without
#: ever asking them. The receive-side control that holds such a first contact for
#: review (`Inbox._hold_for_introduction`) shipped in the SAME commit as
#: `handle_introduce_propose`, so a node answering -32601 here predates the
#: compensating control by construction — the fallback is only ever reached on
#: nodes where nothing catches it.
METHOD_CLASSES: dict[str, str] = {
    "message/send": DEGRADE_LOSSY,
    "referral/request": DEGRADE_LOSSY,
    "introduction/request": DEGRADE_LOSSY,
    "onboard/claim": DEGRADE_LOSSY,
    "trust/status": DEGRADE_LOSSY,
    "connect/request": DEGRADE_LOSSY,
    "connect/respond": DEGRADE_LOSSY,
    "introduce/propose": DEGRADE_CONSENT,
    "introduce/respond": DEGRADE_LOSSY,
    "contact/redeem": DEGRADE_LOSSY,
    "net.udp.offer": DEGRADE_TRANSPORT,
    "artifact/fetch": DEGRADE_LOSSY,
    "artifact/list": DEGRADE_LOSSY,
}


def degradation_class(method: str) -> str:
    """The degradation class of a call, or D (unknown) for a method this build has
    never heard of. Never consults a peer — see METHOD_CLASSES."""
    return METHOD_CLASSES.get(method, DEGRADE_UNKNOWN)


def rpc_request(method: str, params: dict[str, Any],
                req_id: str | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id or new_id(),
            "method": method, "params": params}


def rpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def rpc_error(req_id: Any, error: dict[str, Any],
              detail: Any = None) -> dict[str, Any]:
    """Build a JSON-RPC error response. `detail` becomes the standard `data`
    member.

    `detail` is deliberately `Any`, not `str`: -32601 carries a STRUCTURED
    capability block (see `method_capabilities`) while every other code carries
    a human string. JSON-RPC 2.0 defines `data` as "a primitive or structured
    value", so widening it is spec-conformant and additive — an old receiver
    simply sends none, and an old SENDER only ever `str()`s the whole error dict
    into a message, so a dict here degrades to readable text rather than
    crashing. Nothing in-tree indexes `data` as a string except the -32602
    assertion in test_audit_hardening.py, which this does not touch."""
    err = dict(error)
    if detail:
        err["data"] = detail
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def unsupported_method(err: Any) -> bool:
    """True when a JSON-RPC error object is a definitive -32601 "method not found".

    THE ONLY WAY a caller may establish a negative capability (rule R1): a card is
    self-signed and may lie in either direction, so only an observed refusal from
    that peer, for that method, counts. Accepts the error object itself or a whole
    response dict, and is total — junk in returns False rather than raising, because
    every caller uses it inside an exception path where a second exception would
    mask the first."""
    if isinstance(err, dict) and "error" in err and "code" not in err:
        err = err.get("error")
    if not isinstance(err, dict):
        return False
    return err.get("code") == METHOD_NOT_FOUND["code"]


def method_capabilities(err: Any) -> dict[str, Any]:
    """Read the additive capability block off a -32601 error.

    Returns `{method, methods, version, protocolVersion}` where **`methods` is
    `None` when the peer sent no `data`** — the whole live fleet predates this
    payload, so absence means UNKNOWN CAPABILITY SET, never "supports nothing".
    An empty list, by contrast, is a peer explicitly claiming an empty surface;
    both are inert, because under R1 nothing a peer says can stop a caller from
    ATTEMPTING a method (fail open on reachability), and the refusal it gets back
    is what settles it.

    Total by design: a bare `{"code": -32601, "message": ...}` from an old node,
    a `data` that is a plain string, or a `data.methods` that is not a list all
    yield the same unknown-capability answer instead of raising."""
    if isinstance(err, dict) and "error" in err and "code" not in err:
        err = err.get("error")
    out: dict[str, Any] = {"method": None, "methods": None,
                           "version": None, "protocolVersion": None}
    if not isinstance(err, dict):
        return out
    data = err.get("data")
    if not isinstance(data, dict):
        return out           # old node (no data) or a string detail -> unknown
    methods = data.get("methods")
    out["methods"] = list(methods) if isinstance(methods, list) else None
    for k in ("method", "version", "protocolVersion"):
        v = data.get(k)
        out[k] = v if isinstance(v, str) else None
    return out


def _reject_nonfinite(token: str) -> Any:
    """parse_constant hook: reject the non-standard JSON literals NaN / Infinity /
    -Infinity. RFC 8259 forbids them; they are non-portable across languages and, if one
    reached a signing/verify path, would canonicalize to a token other implementations
    cannot reproduce. Rejecting at the parse boundary keeps them out of the whole system."""
    raise ValueError(f"non-finite JSON literal not allowed: {token}")


def dumps(obj: Any) -> bytes:
    # allow_nan=False: never emit NaN/Infinity (see _reject_nonfinite / crypto.canonical).
    return json.dumps(obj, ensure_ascii=False, allow_nan=False).encode("utf-8")


def loads(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), parse_constant=_reject_nonfinite)


def loads_object(raw: bytes) -> dict:
    """`loads` with a top-level type contract: the value MUST be a JSON object.

    A JSON document may legally be an array, string, number, bool or null, and every
    JSON-RPC entry point assumes a dict. `handle_rpc` reads `req.get("id")` before its
    own try block, so a body of `[]` raised AttributeError out of `do_POST` — no HTTP
    response, connection reset, and the rejection never logged, bypassing the generic
    -32700/-32600 discipline the handler otherwise keeps. Callers already answer 400 on
    a parse exception, so raising ValueError here needs no new error path."""
    obj = loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("top-level JSON value must be an object")
    return obj
