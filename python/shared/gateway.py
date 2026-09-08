"""
shared/gateway.py
The canonical PUBLIC base for DID-addressed Agent-HP URLs — the one place that turns
a DID into the human-facing web address to share.

Why this exists (design):
  An HP is served at `<host>/<zKey>`, and historically `<host>` was the RELAY the
  page happened to be stored on (e.g. https://a-relay.example/z6Mk...). That
  bakes a REPLACEABLE transport location into a PERMANENT identity's URL: the moment
  relays scale / shard / fail over, the shared link breaks and UX diverges per relay.

  The DID is the permanent, location-independent address; the relay is fungible
  transport. So the URL we ADVERTISE must be a stable GATEWAY host that resolves the
  DID to whatever relay currently holds it — not the relay host itself. This module
  is that gateway base. It changes only the human-facing URL string; message routing
  and the `POST /site` publish target still use the real relay (connector.DEFAULT_RELAY).

  This works cleanly because an HP is a self-signed envelope the relay serves and
  re-verifies content-blind: any host — the gateway, any relay, any shard — can serve
  the exact same bytes and re-verify, so the serving location is interchangeable.

Env override: MURETAI_PUBLIC_BASE (e.g. a self-hosted gateway or a test host).
Pure standard library. Read dynamically per call so an override / test takes effect
without re-import (mirrors agent/paths.data_root_default).
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import os
import re
from urllib.parse import parse_qs, quote, unquote, urlparse

#: A did:key multibase key (the address root of /a/<zKey> and HP URLs).
_ZKEY_RE = re.compile(r"^z[1-9A-HJ-NP-Za-km-z]{16,128}$")

#: The default canonical gateway is the NETWORK domain `muretai.net` (`.net` = the
#: machine-addressable network; `muretai.com` stays the human/brand face). It serves
#: DID-addressed HPs at `/<zKey>` and gives that untrusted, self-signed content its OWN
#: origin, isolated from the brand site's cookies/session. The end state has LANDED:
#: `muretai.net` points DIRECTLY at the relay origin (route-based, Host-agnostic) and
#: answers in ONE hop with NO redirect — measured 2026-08-24, `GET https://muretai.net/`
#: -> 200 and `GET /<zKey>` -> the relay's own bytes. (It formerly 301-redirected to
#: `muretai.com`; this note used to say so, and was stale.) Do NOT reintroduce a redirect
#: hop here: a redirecting gateway is silently fatal to any consumer forbidden from
#: following redirects. Override with MURETAI_PUBLIC_BASE.
DEFAULT_PUBLIC_BASE = "https://muretai.net"


def public_base() -> str:
    """The canonical public base for HP URLs: ``MURETAI_PUBLIC_BASE`` if set, else
    ``DEFAULT_PUBLIC_BASE``. Trailing slashes are stripped so callers can append
    ``/<zKey>`` unconditionally."""
    return (os.environ.get("MURETAI_PUBLIC_BASE") or DEFAULT_PUBLIC_BASE).rstrip("/")


#: The canonical base for a shareable INVITE link (`<base>/i/<code>`). Deliberately
#: `.com`, NOT the `.net` HP gateway above: an invite is the most HUMAN-facing artifact
#: we produce, and it travels in the same invitation as the install one-liner
#: (`curl https://muretai.com/install`). Minting its link on another host splits one
#: invitation across two brands. (The `.net` isolation rationale above is about giving
#: untrusted self-signed HP content its own origin — an invite carries no such content,
#: it is a code the relay resolves.) Override with MURETAI_INVITE_BASE.
DEFAULT_INVITE_BASE = "https://muretai.com"


def invite_base() -> str:
    """The canonical public base for invite links: ``MURETAI_INVITE_BASE`` if set, else
    ``DEFAULT_INVITE_BASE``. Trailing slashes stripped so callers can append ``/i/<code>``.

    Why this is not simply the node's relay (the bug this exists to kill): the relay
    builds the link from the request's ``Host`` header (`relay.py` `_do_invite_store`), so
    the link inherited whatever URL the node happened to be configured with — a node on
    ``--relay https://a-relay.example`` published `a-relay.example/i/<code>`
    invitations. That bakes REPLACEABLE transport config into a PUBLIC, permanent-looking,
    brand-facing artifact, which is the same disease `public_base()` above was written to
    cure for HP URLs — invites just never took the medicine."""
    return (os.environ.get("MURETAI_INVITE_BASE") or DEFAULT_INVITE_BASE).rstrip("/")


def zkey_of(did: str) -> str:
    """The multibase key of a did:key (the address root of an HP URL). A non-did:key
    string is returned unchanged so this never raises on a placeholder."""
    prefix = "did:key:"
    return did[len(prefix):] if did.startswith(prefix) else did


def add_page_url(did: str, base: str | None = None) -> str:
    """Public human add page for a DID: ``<invite_base>/a/<zKey>``.

    Same host as invite links (``.com``): a person opens this the way they open
    a Grok Bot card, then Add hands off to their local node. Override the host
    via ``base`` or ``MURETAI_INVITE_BASE`` — never bake a node's relay here.
    """
    return f"{(base or invite_base()).rstrip('/')}/a/{zkey_of(did)}"


def add_deeplink(did: str) -> str:
    """``agent://add?did=<did>`` — the installed-node handoff from the add page."""
    return "agent://add?did=" + quote(did, safe="")


def connect_pick_url(did: str, *, port: int = 8090) -> str:
    """Local console Agents list with this peer attached.

    ``http://127.0.0.1:<port>/?connect=<zKey>``. The public ``/a/`` page cannot
    list this machine's keys. Connect and ``agent://add`` open this URL so the
    owner picks from the searchable Agents list, not a dump select.
    """
    return f"http://127.0.0.1:{int(port)}/?connect={zkey_of(did)}"


def did_from_add_ref(ref: str) -> str | None:
    """A did:key from an add-page URL, a card URL, a deeplink, or a raw DID.

    Used by the add page, ``contact redeem``, and the console paste box so one
    parse owns every share form. Returns None when the string is not an add ref.
    """
    raw = (ref or "").strip()
    if not raw:
        return None
    if raw.startswith("did:key:") and _ZKEY_RE.match(raw[8:]):
        return raw
    if _ZKEY_RE.match(raw):
        return "did:key:" + raw
    parsed = urlparse(raw)
    q = parse_qs(parsed.query)
    if "add?did=" in raw or raw.startswith("agent://add"):
        inner = unquote((q.get("did") or [""])[0])
        return did_from_add_ref(inner) if inner and inner != raw else None
    inner = unquote((q.get("connect") or [""])[0])
    if inner and inner != raw:
        return did_from_add_ref(inner)
    m = re.search(r"/a/(z[1-9A-HJ-NP-Za-km-z]+)", raw)
    if m and _ZKEY_RE.match(m.group(1)):
        return "did:key:" + m.group(1)
    m = re.search(r"/card/(did:key:z[1-9A-HJ-NP-Za-km-z]+)", raw)
    if m:
        return m.group(1)
    return None


def did_site_url(did: str, path: str = "", base: str | None = None) -> str:
    """Build the canonical public HP URL for a DID: ``<base>/<zKey><path>``.

    The single place this URL is constructed, so the relay host is never re-baked into
    a shared link. `path` is an optional in-site path for a v2 multi-file site (e.g.
    ``/about.html`` or ``/project/``); `base` overrides the gateway (defaults to
    public_base())."""
    return f"{base or public_base()}/{zkey_of(did)}{path}"
