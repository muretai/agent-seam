"""
shared/httpua.py
Give every relay-bound urllib request a non-default User-Agent.

Why this exists: the node's relay client (agent/outbox.py, agent/relayclient.py,
shared/invite.py, and the other urllib call sites) talks to the relay over
`urllib.request`, which stamps the default `User-Agent: Python-urllib/<x.y>` on
each request. When the relay is fronted by Cloudflare (muretai.com / muretai.net
after the T39 domain split), Cloudflare's Bot Fight Mode 403s that exact UA — so
EVERY send / long-poll / short-link registration is blocked and a freshly
installed node can join but never message. Any non-default UA passes.

Design: install ONE process-wide opener whose `addheaders` carries our UA. The
module-level `urllib.request.urlopen` used by every call site consults this
global opener, and its default header is applied only when a Request does not
already set User-Agent — so this is a single, side-effect-free-to-callers fix
that needs no change at the ~30 individual call sites. Idempotent; safe to call
from every entrypoint / transport module.

This is defense-in-depth: the primary fix is not depending on Cloudflare blocking
our UA, but a WAF that blocks a bare Python UA is common enough that a real HTTP
client SHOULD identify itself anyway.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import urllib.request

from shared.version import VERSION

# Identify the node like a normal HTTP client. Kept deliberately boring (no
# Mozilla spoofing): it just needs to not be the bare `Python-urllib` string.
USER_AGENT = f"muretai-node/{VERSION}"

_installed = False


def install(force: bool = False) -> None:
    """Install a global urllib opener that stamps USER_AGENT on every request.

    Idempotent: the first call wins; later calls are no-ops unless `force`. Uses
    build_opener() so all default handlers (proxy, redirect, https) are kept —
    we only add the UA header."""
    global _installed
    if _installed and not force:
        return
    opener = urllib.request.build_opener()
    # addheaders provides DEFAULTS: a Request that already set User-Agent (none of
    # ours do) still wins, so this never overrides an explicit header.
    opener.addheaders = [("User-Agent", USER_AGENT)]
    urllib.request.install_opener(opener)
    _installed = True
