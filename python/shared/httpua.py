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

Design, and the boundary that matters: `install()` builds ONE opener whose
`addheaders` carries our UA and makes it the process-wide default, so a call
site that builds no opener of its own picks it up from `urllib.request.urlopen`.
That is a mutation of GLOBAL state belonging to whoever imported us, which makes
it an APPLICATION's call to make at its own startup and never a library's on the
way past — see install()'s docstring for what it destroys. Code inside shared/
therefore attaches the UA to the REQUEST instead: named in the headers of the
`urllib.request.Request` it builds (shared/invite.py, shared/webbotauth.py), or
supplied by `neturl.opener()`, whose own addheaders carries USER_AGENT. Nothing
in shared/ calls install(), and nothing in shared/ should.

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

    THIS MUTATES PROCESS-GLOBAL STATE, and that is the whole of its contract:
    `urllib.request.install_opener` replaces `urllib.request`'s default opener for the
    ENTIRE interpreter, discarding whatever opener the embedding application had put
    there — its proxy handler, its authentication, its cookie jar, its redirect policy.
    `shared/` is vendored verbatim into other people's programs, so "the interpreter" is
    usually not ours.

    A LIBRARY MUST NEVER CALL THIS as a side effect of a protocol function. shared/invite.py
    did, from a `_ua_installed()` helper on each of its three dialing functions, which meant
    that merely resolving an invite link re-configured its caller's HTTP client — a change
    the caller did not ask for, cannot see, and would go looking for somewhere else
    entirely. Attach the UA to the request instead: name it in the Request's headers, or
    dial through `neturl.opener()`, whose addheaders already carries USER_AGENT.

    This is for an APPLICATION to call once, deliberately, at its own startup — an
    entrypoint that has decided it owns this process's urllib configuration. It stays
    public for exactly that, and for nothing else.

    Idempotent: the first call wins; later calls are no-ops unless `force`. Uses
    build_opener() so all default handlers (proxy, redirect, https) are kept — we only add
    the UA header. "Kept" means the handlers build_opener() constructs fresh, NOT the ones
    an application already installed; those are precisely what this call throws away."""
    global _installed
    if _installed and not force:
        return
    opener = urllib.request.build_opener()
    # addheaders provides DEFAULTS: a Request that already set User-Agent (none of
    # ours do) still wins, so this never overrides an explicit header.
    opener.addheaders = [("User-Agent", USER_AGENT)]
    urllib.request.install_opener(opener)
    _installed = True
