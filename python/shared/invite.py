"""
shared/invite.py
Seamless onboarding: a signed, self-contained "contact card" packed into a
single invite link / QR.

Why this exists:
  The L3 gate (agent/inbox._gate) blocks any contact without a prior
  introduction, so the hardest real-world step is the very first handshake
  between two strangers' agents. Today that means hand-copying ~60-char DIDs,
  endpoint URLs, and VC JSON files, and both sides running `trust add`.

  An invite collapses all of that into one artifact the inviter signs and the
  invitee imports. Two people meet, each shows a QR (or pastes a link); each
  side ends up directly trusting the other. No DID typing, no file shuffling.

The minted shareable form is `https://muretai.com/i/<code>` (the signed card
is stored on the relay). Older encodings
`agent://invite?d=<base64url(json)>` and `https://…/invitation#d=<token>` are
still decoded by `resolve_link` so existing mail works; they are not minted.

The signature does double duty: with did:key the DID *is* the public key, so a
valid signature proves the inviter controls the DID AND binds the endpoint url
to it (a tampered url or a forged card fails verification). `exp` bounds the
window; `nonce` is a one-time value the inviter remembers so a remote invite
link can be redeemed exactly once (see agent/inbox.handle_claim).

Reuses shared/crypto only (zero deps), mirroring shared/vc.py's
"canonical body, then sign" pattern.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from shared import crypto
from shared import vc as vcmod   # reuse the ISO time parser (vcmod._parse_iso)
from shared import httpua

# Short-link registration + resolution hit the relay over urllib; a bare Python-urllib UA is
# 403'd by a Cloudflare-fronted relay (shared/httpua.py), so every dial in this module has to
# carry a non-default one. It rides on the REQUEST: either as an explicit header on the
# Request `register_short` builds (the shape shared/webbotauth.py's directory fetch uses), or
# from `neturl.opener()`, whose addheaders already carries `httpua.USER_AGENT`.
#
# NOT from `httpua.install()`, which is where it used to come from. That function calls
# `urllib.request.install_opener` — a PROCESS-GLOBAL mutation — and it was invoked from a
# `_ua_installed()` helper at each of the three functions that dial. So merely resolving one
# invite link silently replaced the HOST APPLICATION's global opener, discarding whatever
# proxy, authentication, cookie or redirect handlers it had installed; shared/ is vendored
# verbatim into other people's programs, many of which import this module for `verify_invite`
# alone. Moving the call from import time to the dialing functions (which is what the previous
# round did) shrank the window without changing the fact: a library does not get to rewrite a
# global on its caller's behalf. The header belongs on the request, where it is visible at the
# call site and affects nothing else. `install()` stays public for an APPLICATION to call
# deliberately at its own startup.

SCHEME = "agent://invite?d="
DEFAULT_TTL_SECONDS = 7 * 24 * 3600    # an invite is good for a week by default


# ---------------------------------------------------------------- signed payload

def _signing_payload(card: dict[str, Any]) -> bytes:
    """Canonical bytes of the card minus `sig` (same rule as L2 / VC signing)."""
    return crypto.canonical({k: v for k, v in card.items() if k != "sig"})


# ---------------------------------------------------------------- create

def make_invite(identity, url: str | None, specialty: str = "general",
                name: str | None = None,
                ttl_seconds: int = DEFAULT_TTL_SECONDS,
                nonce: str | None = None,
                purpose: str | None = None,
                desired_tags=None,
                relay: str | None = None,
                enc_pub: str | None = None,
                ygg: dict | None = None,
                org: dict | None = None,
                bio: str | None = None,
                tags=None) -> dict[str, Any]:
    """Mint a signed contact card.

    identity     : the inviter's Identity (signs via sign_bytes; key never leaves).
    url          : the inviter's reachable endpoint (advertised so the invitee
                   can reply and so a remote claim can call back). May be empty
                   for an in-person mutual exchange where both sides scan.
    specialty    : free-form expertise tag, stored as the peer's expertise.
    name         : display name (defaults to the identity's name).
    ttl_seconds  : validity window; `exp` is now + ttl.
    nonce        : one-time value; generated if not supplied. The caller should
                   persist it (TrustStore.add_invite_nonce) to accept a later
                   remote claim that redeems this invite.
    purpose      : optional free text — what the meeting/connection is about.
                   The recipient hub uses it to route to the right local agent.
    desired_tags : optional list of tags the inviter wants the recipient agent to
                   match (routing hint). Both are covered by the signature.
    relay/enc_pub: optional T11 store-and-forward relay URL and X25519 public key
                   (hex) for E2E sealing; both are covered by the signature.
    ygg          : optional T14 signed overlay binding {did,yggPub,yggAddr,ts,sig}
                   so the acceptor learns the inviter's routable IPv6 (the Address
                   layer) at connect time; covered by the invite signature, and
                   independently verifiable via shared/ygg.verify_ygg_binding.
    """
    exp = (datetime.now(timezone.utc)
           + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    card: dict[str, Any] = {
        "v": 1,
        "did": identity.did,
        "name": name or identity.name,
        "url": (url or "").rstrip("/"),
        "specialty": specialty,
        "nonce": nonce or os.urandom(16).hex(),
        "exp": exp,
    }
    # Optional routing fields — added only when present, so old invites are
    # unchanged and the signature (card minus sig) still covers them.
    if purpose:
        card["purpose"] = purpose
    if desired_tags:
        card["desired_tags"] = [str(t) for t in desired_tags]
    if relay:
        card["relay"] = relay
    if enc_pub:
        card["enc_pub"] = enc_pub
    if ygg:
        card["ygg"] = ygg
    if org:
        card["org"] = org      # inviter's signed OrgMembership (shared/orgbind.py), so the
                               # acceptor learns "member of org X" at connect; covered by the
                               # invite signature, and independently verifiable + agent-pinned
    # Self-description carried at connect so a peer shows a real card, not a bare DID
    # (relay-only agents can't serve /.well-known/agent.json). Covered by the signature.
    if bio:
        card["bio"] = bio
    if tags:
        card["tags"] = [str(t) for t in tags]
    card["sig"] = identity.sign_bytes(_signing_payload(card))
    return card


# ---------------------------------------------------------------- verify

def verify_invite(card: dict[str, Any], now: datetime | None = None) -> bool:
    """Verify an invite card. Returns False on any failure (fail closed).

      1. Structure present (did / sig / exp)
      2. sig verifies under the inviter's did:key (= untampered, url bound)
      3. exp is in the future (not stale)
    """
    try:
        if not isinstance(card, dict):
            return False
        did, sig, exp = card.get("did"), card.get("sig"), card.get("exp")
        if not (did and sig and exp):
            return False
        try:
            sig_raw = base64.b64decode(sig)
        except Exception:
            return False
        if not crypto.verify(did, sig_raw, _signing_payload(card)):
            return False
        now = now or datetime.now(timezone.utc)
        if vcmod._parse_iso(exp) <= now:
            return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- link / QR codec

def _token(card: dict[str, Any]) -> str:
    """The base64url(json) payload — fragment/URL safe (no '=' padding)."""
    raw = json.dumps(card, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def encode_link(card: dict[str, Any]) -> str:
    """Pack a card into agent://invite?d=<base64url(json)> — the retired deep-link
    form. Still decoded by resolve_link so leftover mail works; create_invite
    no longer mints this."""
    return SCHEME + _token(card)


def web_link(card: dict[str, Any], base: str) -> str:
    """Pack a card into <base>/invitation#d=<token> — the retired fragment form.
    Still decoded by resolve_link (keys on `d=`); create_invite no longer mints
    this. The token rides in the fragment, so a host serving the landing page
    never receives it. The legacy `/i#d=` path stays valid as an alias."""
    return base.rstrip("/") + "/invitation#d=" + _token(card)


def decode_link(link: str) -> dict[str, Any]:
    """Inverse of encode_link. Raises ValueError if the link is malformed."""
    link = link.strip()
    if "d=" not in link:
        raise ValueError("not an agent invite link")
    b = link.split("d=", 1)[1].strip()
    b += "=" * (-len(b) % 4)               # restore base64 padding
    raw = base64.urlsafe_b64decode(b.encode("ascii"))
    card = json.loads(raw.decode("utf-8"))
    if not isinstance(card, dict):
        raise ValueError("invite payload is not an object")
    return card


def _serves_code(base: str, code: str, timeout: float) -> bool:
    """Whether `base` actually serves the invite `code` — i.e. it fronts the SAME relay
    the card was stored on. This is the safety check that makes canonicalization sound:
    a short code lives in ONE relay's store, so rewriting the host is only valid across
    hosts that share that store (muretai.com / muretai.net / the hosted relay origin do; a
    self-hosted or private relay does not).

    Guarded and capped like `resolve_link`, though `base` here is our own gateway rather
    than a stranger's: two functions that dial the same path must not diverge on how they
    dial it, or the next reader has to work out which one was the hardened one."""
    from shared import httputil, neturl
    if not neturl.peer_base_ok(base):
        return False
    try:
        with neturl.opener().open(neturl.join(base, "/i/" + code), timeout=timeout) as r:
            raw = httputil.read_response(r, budget_s=timeout)
        card = json.loads(raw.decode("utf-8"))
        return isinstance(card, dict) and bool(card.get("sig"))
    except Exception:
        return False


def register_short(card: dict[str, Any], relay_base: str,
                   *, timeout: float = 10.0,
                   public_base: str | None = None) -> str | None:
    """POST a SIGNED card to the relay's `/i` and return the short link, or None on any
    failure. `create_invite` requires this (retry once, then refund and fail) — it does
    not fall back to `#d=` or `agent://`. Used so an AI agent can be handed a short,
    un-manglable code.

    The returned link is CANONICALIZED to the public invite base (gateway.invite_base(),
    override with `public_base`) whenever that host actually serves the code. Why this is
    not cosmetic: the relay mints the link from the request's `Host` header, so without
    this the link is whatever URL the node was configured with — an agent on
    `--relay https://a-relay.example` published `a-relay.example/i/<code>`
    invitations (observed on three independent agents, including our own platform agent,
    which broadcast one to a whole room). A node's transport config is replaceable; the
    invitation is public and brand-facing, so it must not inherit it.

    We VERIFY rather than assume: register on the node's own relay, rebuild the link
    against the canonical base, and only adopt it if a GET there returns the card. So a
    self-hosted/private relay keeps its own link (rewriting it would hand out a DEAD link
    to a store that never had the code), and a new alias for the muretai relay works with
    no list to maintain and nothing to forget to update.

    `relay_base` IS SOMEBODY ELSE'S STRING. It arrives from `--relay`, from a node.env an
    installer wrote, and from the `relay` field of an invite card the INVITER signed — a
    field `verify_invite` proves the authorship of and says nothing about the shape of. This
    function used to hand it to a bare `urllib.request.urlopen`, which is a server-side
    request to an arbitrary host and an arbitrary scheme (urlopen's default opener serves
    `file://` too), a 302 into a private network followed without a second look, and a
    `.read()` with no ceiling on either the body or the clock. It now dials the way
    `_serves_code` and `resolve_link` in this same module dial: the SSRF guard first, the
    path joined rather than concatenated, the redirect-checking opener, and a capped,
    time-budgeted read. Two functions in one module that dial the same relay must not
    disagree about how, or the next reader has to work out which one was the hardened one."""
    from shared import httputil, neturl
    if not neturl.peer_base_ok(relay_base):
        return None                            # same fail-closed None as every other failure
    import urllib.request
    try:
        data = json.dumps(card, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            neturl.join(relay_base, "/i"), data=data,
            headers={"Content-Type": "application/json",
                     # Explicit, like shared/webbotauth.py's directory fetch. `neturl.opener()`
                     # supplies the same value as a default, but a Request that names its own
                     # User-Agent does not depend on which opener happens to send it — and
                     # nothing here mutates a global to get it (see the note above SCHEME).
                     "User-Agent": httpua.USER_AGENT},
            method="POST")
        with neturl.opener().open(req, timeout=timeout) as resp:
            # `budget_s=timeout`, the same value `_serves_code` and `resolve_link` pass: a
            # wall-clock ceiling on the body, because `timeout=` is only a per-recv socket
            # deadline and a trickling responder resets it forever (httputil.read_response).
            raw = httputil.read_response(resp, budget_s=timeout)
        r = json.loads(raw.decode("utf-8"))
        link, code = r.get("link"), r.get("code")
        if not link:
            return None
        if not code:                       # older relay: no code to canonicalize with
            return link
        from shared import gateway
        base = (public_base or gateway.invite_base()).rstrip("/")
        canonical = base + "/i/" + code
        if canonical == link:
            return link                    # already canonical — no extra round trip
        return canonical if _serves_code(base, code, timeout) else link
    except Exception:
        return None


def resolve_link(link: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Return the invite card from a link, handling the minted form and leftovers:
      - short:   https://<base>/i/<code>                                  → GET the card JSON
      - inline:  agent://invite?d=<tok>  /  https://…/invitation#d=<tok>  → decode locally

    New invites are always `/i/<code>` because an AI agent cannot reliably pass a ~600-char
    `#d=` token verbatim (LLMs re-serialize and corrupt it), and because `agent://` is a
    macOS-shaped assumption this project does not build on. The older inline forms are still
    DECODED so existing mail keeps working. The card is fetched from the relay that stored it;
    the fetched card is the SAME signed dict, so verify_invite still holds. Raises ValueError
    on a malformed link and propagates network errors (the caller treats either as
    'cannot join').

    THE HOST IN THE LINK IS THE ATTACKER'S CHOICE, and this fetch happens BEFORE anything
    is verified — before `verify_invite`, and one line before the `plain_http_url`
    gate in `connector/join.py`, which checks the relay the CARD names, not the host the
    LINK names. So it gets the same three controls every other peer-supplied URL gets — the
    SSRF guard, the redirect-checking opener, and the response cap — instead of a bare
    `urlopen().read()` that would follow a 302 anywhere and read a body of any size
    """
    link = link.strip()
    if "d=" in link:
        return decode_link(link)
    import re
    from shared import httputil, neturl
    m = re.search(r"(https?://[^/\s]+)/i/([A-Za-z0-9_-]+)", link)
    if not m:
        raise ValueError("not a muretai invite link")
    base, code = m.group(1), m.group(2)
    if not neturl.peer_base_ok(base):
        raise ValueError("invite link points at a host we refuse to dial (SSRF guard)")
    with neturl.opener().open(neturl.join(base, "/i/" + code), timeout=timeout) as r:
        raw = httputil.read_response(r, budget_s=timeout)
    card = json.loads(raw.decode("utf-8"))
    if not isinstance(card, dict):
        raise ValueError("invite payload is not an object")
    return card
