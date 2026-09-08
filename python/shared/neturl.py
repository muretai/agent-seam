"""
shared/neturl.py
The SSRF / address guard for every URL that reaches us from someone else.

Why this lives in shared/ rather than agent/outbox.py, where it started: the guard was
applied at exactly two chokepoints (`fetch_card`, `_post_direct`) while a peer-supplied
URL reaches at least eight more — the `relay` field, the UDP destinations, the mid-gate
`/revocations` fetch, and the invite/grant link resolvers. `agent/trust.py` cannot import
the transport layer to borrow it, so the guard has to sit below both. It is stdlib-only
(CLAUDE.md principle 1) and never raises.

Three things it does that the original did not:

1. CANONICALIZES THE ADDRESS BEFORE TESTING IT. `ipaddress` exposes `is_link_local` etc.
   per address FAMILY, and whether an IPv4-mapped IPv6 address (`::ffff:169.254.169.254`)
   reports the IPv4 answer depends on the CPython version — it does on 3.13+, it does not
   on 3.9-3.12, which principle 1 commits to supporting. A security control must not have
   a correctness that varies with the interpreter, so we unwrap the mapped form ourselves
   and test the real destination. Same for the 6to4, Teredo and NAT64 embeddings, which no
   CPython version unwraps.

2. RESTRICTS THE SCHEME. Without an allowlist, urllib's default opener happily serves
   `file:///etc/passwd` from a peer-supplied "URL".

3. REFUSES A PEER-SUPPLIED BASE THAT CARRIES A QUERY OR FRAGMENT, and joins paths itself.
   Callers used to build `base.rstrip("/") + "/rpc"`, which leaves an attacker's `#`
   intact — and `urllib.request.Request` splits the fragment off, so `/rpc` is discarded
   and the request lands on whatever path the peer named. `peer_base_ok` + `join` remove
   the possibility rather than asking every call site to remember.

What stays ALLOWED, deliberately: loopback, private and ULA ranges. LAN peers, the local
demo/test fleet and the Yggdrasil overlay (0200::/7, ULA fc00::/7) all dial them
legitimately. The guard's job is to refuse addresses that can only point back into our own
trust boundary, not to require a public internet.

A SECOND, STRICTER POLICY lives here too (`ip_public` / `host_public` / `opener_no_redirect`),
for the one job the paragraph above is wrong for: fetching EVIDENCE from a domain
(agent/domainverify.py). "Is this dialable" and "is this the host the rest of the world
reaches at that name" are different questions, and mixing them would have meant either
weakening the transport guard or refusing the LAN. They are separate functions rather than
a flag so a call site cannot pick the lenient answer by accident.

RESIDUAL, AND EVERY IMPLEMENTATION HAS IT UNLESS IT PINS THE ADDRESS. Resolving a name and
connecting to it are two different moments. This module answers "is that name safe to dial"
at the first moment; the HTTP client resolves again at the second, and a name whose owner
controls its DNS can answer differently the second time. Deciding on one address and
connecting to another is the whole of DNS rebinding, and no amount of care in the check
closes it — only carrying the APPROVED ADDRESS down to the socket does. `opener()` below
closes the redirect half (every hop is re-checked); the resolve-then-connect half is a
property of the shape, and a client that must not be rebound has to pin.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_SCHEMES = ("http", "https")

# The SHAPE of a relay URL we are willing to write into a config file or a command line.
# Kept byte-for-byte in step with `_MRT_URL_RE` in installer/common.sh (mrt_check_relay):
# scheme, a hostname or a bracketed IPv6 literal, an optional port, an optional path of
# unreserved characters. No userinfo, no query, no fragment — and therefore no quote,
# no `$(`, no backtick, no `;`, no space: nothing a shell or a sourced env file could
# read as anything but a URL. This is a SYNTACTIC gate (no DNS, no reachability), so it
# is safe to apply before anything is trusted; peer_base_ok / host_dialable stay the
# SSRF gates for the moment a URL is actually dialled.
_PLAIN_HTTP_URL_RE = re.compile(
    r"^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")


def plain_http_url(url) -> bool:
    """True iff `url` is a plain http(s) URL by shape — the check a relay address must pass
    BEFORE it is interpolated anywhere (a `shell=True` install command, a sourced
    `node.env`, a profile written for a later launcher).

    Why a separate function and not `peer_base_ok`: that one resolves DNS and answers
    "may I dial this now", which is the wrong question at join time (the joiner may be
    offline, the relay may be down, and the answer must not depend on it) — and it never
    looked at the characters, which is the whole attack. An invite card is signed by the
    INVITER, who chose every byte of its `relay`, and `verify_invite` checks the signature,
    not the shape; an audit found a caller reaching `shell=True` unquoted in the
    OpenClaw wiring and `${RELAY:-…}` in node.env. Refuse it here, once, on the way in.

    `fullmatch`, not `match`: Python's `$` also matches immediately BEFORE a final
    newline, so `.match()` accepted a relay ending in a bare LF — which bash's
    `[[ =~ ]]` in `mrt_check_relay` refuses, breaking the byte-for-byte parity this
    docstring claims. A relay ending in a newline is exactly the shape that would
    smuggle a second line into a file written on the Python side and checked on the
    shell side.
    """
    return isinstance(url, str) and bool(_PLAIN_HTTP_URL_RE.fullmatch(url))
MAX_REDIRECTS = 5

_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")

# Unique Local Addresses. `IPv6Address.is_private` already covers fc00::/7 on every
# supported interpreter; the network is named anyway so `ip_public` can state the
# refusal explicitly instead of inheriting it from a predicate whose membership list
# has changed between CPython releases.
_ULA = ipaddress.IPv6Network("fc00::/7")



def local_ip() -> str:
    """This machine's LAN address, as a peer on the same network would dial it.

    The UDP-connect trick: connecting a datagram socket sends nothing, but it makes the
    kernel choose a source address by consulting the routing table, which is exactly the
    question being asked — "which of my interfaces would answer for the outside world".
    `10.255.255.255` is picked because it is a routable-looking address nobody is expected
    to actually have, so the choice is not skewed by whatever happens to be up.

    Falls back to loopback rather than raising: a machine with no route still has to be
    able to start a node, and a node advertising 127.0.0.1 is a visible wrong answer,
    while an exception at startup is an invisible one.

    Lives HERE rather than in an entry point: it used to sit in one launcher's module and be
    imported from there by everything else, which made every caller depend on that launcher.
    A utility three modules need is not a property of one of them.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()

def _canonical_ip(ip):
    """The address a packet actually reaches, for the embeddings CPython does not unwrap.

    Returns an IPv4Address for a mapped/6to4/Teredo/NAT64 form, else `ip` unchanged.
    Returning the unwrapped address means every caller tests the REAL destination with
    the IPv4 predicates, independent of interpreter version."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return ip
    for attr in ("ipv4_mapped", "sixtofour"):
        v4 = getattr(ip, attr, None)
        if v4 is not None:
            return v4
    teredo = getattr(ip, "teredo", None)
    if teredo:
        return teredo[1]                      # the client's IPv4, not the server's
    if ip in _NAT64 or ip in _NAT64_LOCAL:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def ip_dialable(ip) -> bool:
    """True if `ip` is a plausible peer address rather than a pointer back at us.

    Refused: link-local (169.254.0.0/16 is cloud instance metadata; fe80::/10 is IPv6
    autoconf), unspecified, and multicast. Loopback/private/ULA stay allowed — see the
    module docstring.

    Deliberately NOT `is_reserved`: the Yggdrasil overlay addresses peers in 0200::/7,
    which CPython reports as reserved, so adding that predicate refuses a transport the
    project ships (caught by test_outbox_ssrf.py). The defect this function fixes is the
    missing CANONICALIZATION, not an under-tight range list — the ranges were reviewed
    and are correct. Widening them is a separate decision with its own regression risk."""
    ip = _canonical_ip(ip)
    return not (ip.is_link_local or ip.is_unspecified or ip.is_multicast)


def ip_public(ip) -> bool:
    """True if `ip` is on the PUBLIC internet — the stricter policy an evidence fetch needs.

    `ip_dialable` above deliberately tolerates loopback, private and ULA addresses,
    because those are real transports between peers on a LAN or the overlay. Domain
    verification asks a different question. A `/.well-known/…` document is evidence
    ONLY if it came from the host the rest of the world reaches at that name; an answer
    inside our own boundary is either our own infrastructure being talked into vouching
    for a stranger's domain, or a rebind. Neither is evidence, so both are refused.

    Refused on top of the ip_dialable set: loopback, private, ULA (fc00::/7) and
    `is_reserved` — the last of which excludes the Yggdrasil overlay (0200::/7). The
    overlay is a legitimate transport and a legitimate peer address; it is not a public
    origin, and a name that resolves there cannot be serving the world's copy of a
    domain's linkage document.

    Canonicalizes first, for the same interpreter-independence reason as ip_dialable.
    `ipaddress.*.is_global` is the core test; the explicit predicates in front of it are
    not decoration — the exact ranges `is_global`/`is_private` cover have been adjusted
    across CPython releases (3.9 through 3.13 do not agree on all of them), and a
    security control must not have an answer that varies with the interpreter. Fails
    CLOSED and never raises: a non-address argument is "not public", not a traceback."""
    try:
        ip = _canonical_ip(ip)
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip in _ULA:
            return False
        return bool(ip.is_global)
    except Exception:
        return False


def host_dialable(endpoint: str | None) -> bool:
    """True if `endpoint` has an allowed scheme and every address its host resolves to is
    dialable. An IP literal is tested directly; a DNS name is resolved and EVERY answer
    must pass, so `metadata.google.internal` and an A-record pointed at 169.254.169.254
    are both caught. Never raises."""
    # The module contract is "never raises", and these three are called with values
    # that came off the wire (a peer's card, a fetched document). A non-string there
    # is a refusal, not a TypeError from urlsplit — the same guard origin() already
    # carries. Found by the T88 audit: the hardening had been applied to origin() only.
    if not isinstance(endpoint, str):
        return False
    if not endpoint:
        return False
    try:
        parts = urllib.parse.urlsplit(endpoint)
    except ValueError:
        return False
    if parts.scheme not in ALLOWED_SCHEMES:
        return False                          # kills file://, ftp://, and scheme-less
    try:
        host = parts.hostname
    except ValueError:
        return False                          # malformed authority / bad IPv6 literal
    if not host:
        return False
    try:
        return ip_dialable(ipaddress.ip_address(host))
    except ValueError:
        pass                                  # a DNS hostname -> resolve it
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, ValueError):
        return True        # unresolvable -> let the normal urlopen surface the error
    for info in infos:
        try:
            if not ip_dialable(ipaddress.ip_address(info[4][0])):
                return False
        except ValueError:
            continue
    return True


def host_public(endpoint: str | None) -> bool:
    """True if `endpoint` is an http(s) URL whose host resolves ONLY to public addresses.

    Same shape as host_dialable — parse, test an IP literal directly, resolve a DNS name
    and require EVERY answer to pass — with two deliberate differences:

      - the per-address test is `ip_public`, not `ip_dialable` (see above);
      - a name that does not resolve, or resolves to nothing usable, is FALSE.
        host_dialable answers True there so the ordinary urlopen surfaces a real network
        error; this function is a policy gate in FRONT of an evidence fetch, and "I
        cannot see where this points" is not a reason to proceed.

    The all-answers rule is the whole point: a name answering with both a public
    address and 127.0.0.1 is refused outright, because which of the two we would have
    connected to is the resolver's choice — that is, the attacker's — not ours. One
    public answer must never launder a rebinding attack.

    Says nothing about the SCHEME beyond http(s): whether plaintext http is acceptable
    is the caller's policy (agent/domainverify.py requires https), not an address fact.
    Never raises."""
    # The module contract is "never raises", and these three are called with values
    # that came off the wire (a peer's card, a fetched document). A non-string there
    # is a refusal, not a TypeError from urlsplit — the same guard origin() already
    # carries. Found by the T88 audit: the hardening had been applied to origin() only.
    if not isinstance(endpoint, str):
        return False
    if not endpoint:
        return False
    try:
        parts = urllib.parse.urlsplit(endpoint)
    except ValueError:
        return False
    if parts.scheme not in ALLOWED_SCHEMES:
        return False
    try:
        host = parts.hostname
    except ValueError:
        return False                          # malformed authority / bad IPv6 literal
    if not host:
        return False
    try:
        return ip_public(ipaddress.ip_address(host))
    except ValueError:
        pass                                  # a DNS hostname -> resolve it
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return False                          # unresolvable -> fail closed, unlike above
    seen = False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False                      # an answer we cannot even parse
        if not ip_public(address):
            return False
        seen = True
    return seen


def peer_base_ok(base: str | None) -> bool:
    """True if `base` is safe to use as the ROOT of a URL we will build a path onto.

    Stricter than host_dialable: a base carrying a query or fragment is refused outright,
    because callers append a path to it and urllib would then drop the appended path into
    the fragment. `http://127.0.0.1:8090/api/update/apply#` + "/rpc" is a POST to
    /api/update/apply, not to /rpc.

    Tested on the RAW string, not the parsed components: a base ending in a bare `#` parses
    to an EMPTY fragment, so `not parts.fragment` would wave through the exact input that
    makes the trick work."""
    if not isinstance(base, str):
        return False
    if not host_dialable(base):
        return False
    return "#" not in base and "?" not in base


_DEFAULT_PORT = {"http": 80, "https": 443}


def origin(url: str | None) -> str:
    """The canonical `scheme://host[:port]` of `url` — one spelling per relay.

    This is the string a listener token is BOUND to on both sides
    (`agent/relayclient.listen_token` signs it, `relay._verify_listen_token` checks it),
    which is why it lives here rather than in either of them: two implementations of
    "the same relay" that disagree by one character do not fail loudly — they 401 every
    drain, forever, and look like a broken relay. One function, one answer.

    Canonicalization, all of it load-bearing because each is a spelling a node really
    stores for the SAME relay:
      - scheme and host lowercased            (`HTTPS://Muretai.COM` == `https://muretai.com`)
      - the scheme's default port dropped     (`https://x:443` == `https://x`)
      - a single trailing dot on the host dropped (`https://x.` == `https://x` — DNS-equal)
      - path, query, fragment, and userinfo removed (`https://x/rpc?a#b` == `https://x`,
        so a stored relay with or without a trailing slash mints the SAME token)
      - IPv6 literals keep their brackets     (`http://[::1]:9000`)

    Returns "" for anything that is not an http(s) URL — unparseable, scheme-less, no
    host, a bad port, or a non-http scheme. "" is never a member of any accepted-origin
    set, so a caller that cannot be canonicalized mints a token nothing accepts (a loud
    401) rather than one that silently matches something else.

    NON-STRINGS fold to "" rather than raising. Callers feed this values that a REMOTE
    party chose — `Outbox.card_binds_to` passes `card["url"]` straight from a fetched
    Agent Card — so a card whose `url` is a list/int/dict reached `url.strip()` and threw
    AttributeError out of the middle of a security decision. It failed closed, but an
    unhandled exception inside the function an access check rests on is the wrong shape:
    the answer to "is this a relay URL" for a list is "no", not a traceback. Found by
    attacking T85 (2026-08-09)."""
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return ""
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return ""                             # not a relay URL (file:, ws:, scheme-less)
    try:
        host = parts.hostname                 # lowercased by urllib; userinfo excluded
        port = parts.port                     # raises ValueError on a bad port
    except ValueError:
        return ""
    if not host:
        return ""
    host = host.lower().rstrip(".")           # trailing dot: DNS-equal, byte-different
    if not host:
        return ""
    if ":" in host:                           # IPv6 literal — urllib strips the brackets
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORT[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def join(base: str, path: str) -> str:
    """Build `base` + `path` so the peer cannot steer where the request lands.

    Rebuilds the URL from parsed components with query and fragment forced empty, so any
    `?`/`#` in the peer's base is dropped rather than swallowing our path. `path` is ours
    (a literal like "/rpc"), not the peer's."""
    parts = urllib.parse.urlsplit(base)
    merged = parts.path.rstrip("/") + "/" + path.lstrip("/")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, merged, "", ""))


class _UndrainedBody:
    """A 3xx response body that declines to be read.

    `HTTPRedirectHandler.http_error_302` calls `fp.read()` — no amount, to EOF — on the
    REDIRECT's own body before it opens the next hop. That read happens INSIDE
    `opener().open()`, so neither `httputil.read_response`'s size cap nor its `budget_s`
    deadline is anywhere near it: both of those only ever see the FINAL response object
    that `open()` returns. A single `302` with an endless chunked body (or a
    `Content-Length: 10000000000`, or one byte per socket-timeout-minus-epsilon) is
    therefore an unbounded read on every guarded fetch — including
    `agent/trust._fetch_revocations`, which runs inside the inbox gate against a URL a
    contact's own credential named, and the peer-relay reads in `agent/outbox.py`.

    Reading NOTHING is correct here, not merely a tighter cap: urllib closes the socket
    the instant the response exists (`AbstractHTTPHandler.do_open` ends with
    `h.sock.close(); h.sock = None`), so no connection is ever reused and the drain buys
    nothing at all. The stdlib discards those bytes either way — we decline to receive
    them first."""

    def __init__(self, fp):
        self._fp = fp

    def read(self, amt=None):
        return b""

    def __getattr__(self, name):
        return getattr(self._fp, name)


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Re-run the guard on every redirect target.

    Without this the guard is evaluated once, against the original URL, and a single 302
    from a host the attacker already controls reaches anything — no racing resolver
    needed, unlike the rebind residual."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not host_dialable(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "redirect to a non-routable host (SSRF guard)",
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        return super().http_error_302(req, _UndrainedBody(fp), code, msg, headers)

    # The stdlib aliases the other four codes to the FUNCTION OBJECT it defined, not to
    # the name — `http_error_301 = ... = http_error_302` inside HTTPRedirectHandler — so
    # a subclass overriding only `http_error_302` still serves 301/303/307/308 from the
    # parent, with the unbounded drain intact. Re-alias, or the fix covers one code in 5.
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_opener: urllib.request.OpenerDirector | None = None


def opener() -> urllib.request.OpenerDirector:
    """A urllib opener that re-checks the guard on redirects and carries our User-Agent.

    Use this instead of the global `urlopen` for anything peer-facing. Built lazily so
    importing this module stays free, and cached because building an opener per request
    would drop connection reuse."""
    global _opener
    if _opener is None:
        from shared import httpua
        o = urllib.request.build_opener(_GuardedRedirect())
        o.addheaders = [("User-Agent", httpua.USER_AGENT)]
        _opener = o
    return _opener


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of re-checking the guard and following it.

    _GuardedRedirect above is right for a peer ENDPOINT: nodes move, relays redirect,
    and all the guard has to do is hold at the new address. It is wrong for an
    ORIGIN-BOUND resource. A well-known document is the answer to "what does THIS origin
    publish at THIS path", and a 3xx is an answer about somewhere else — following one
    would let a domain hand its own proof obligation to a host it does not control, and
    a verifier would record the redirect target's evidence under the original name. The
    Web Bot Auth profile forbids following redirects for the same reason from the other
    direction: a request signature covers the ORIGINAL `@authority`, so a followed
    redirect can only ever arrive somewhere unsigned.

    Raised as HTTPError (carrying the real 3xx code) rather than a bare exception, so a
    caller can distinguish "it redirected" from "it was unreachable" and say so."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "refusing to follow a redirect (origin-bound fetch)", headers, fp)


def opener_no_redirect() -> urllib.request.OpenerDirector:
    """An opener that carries our User-Agent and treats any 3xx as an error.

    Built fresh per call, unlike `opener()`. The caching there pays for connection reuse
    on the hot peer-messaging path; these fetches are rare, deliberate and origin-bound,
    and keeping them out of the shared opener means an evidence fetch never inherits
    (nor contributes to) state built up by ordinary peer traffic."""
    from shared import httpua
    o = urllib.request.build_opener(_NoRedirect())
    o.addheaders = [("User-Agent", httpua.USER_AGENT)]
    return o


def urlopen_guarded(url, *, timeout: float, data: bytes | None = None,
                    method: str | None = None, headers: dict | None = None,
                    wba_identity=None):
    """urlopen for a peer-supplied URL: guard the host, then fetch through `opener()`.

    Raises ValueError when the guard refuses, so callers can map it to their own error
    type (PeerError, an undecidable revocation result, …) rather than silently proceeding.

    `wba_identity` (optional, T89) is an Identity whose Web Bot Auth headers should
    authenticate this ONE request: shared.webbotauth.request_headers(identity, url) is
    merged in before the Request is built, and anything the caller passed in `headers`
    wins over the merged values (case-insensitively) — the caller is closer to the
    request than we are. The module is imported lazily, inside the branch, so the
    ordinary path keeps its import cost and its zero-dependency profile.

    PASSING THE PARAMETER *IS* THE OPT-IN, and that is the design, not a convenience:
    signing announces "this is muretai's agent" to whoever we dial, so it must never
    happen by default. Expressing the opt-in as an argument at the call site means
    relay-bound and peer-bound internal traffic is untouched BY CONSTRUCTION — there is
    no host denylist to keep current, no risk that a new relay hostname starts leaking
    signed identity because someone forgot to add it, and a reader can see from one line
    of a call site whether that request is signed.

    On a REDIRECT the signature simply stops working, which is the correct outcome and
    needs no extra code: urllib re-sends our headers to the new location, but the
    signature covers the original `@authority`, so the new host sees a signature that
    does not verify for it and treats the request as unsigned. Fail-closed by
    construction — and because this is a public-key signature over metadata, nothing
    secret is disclosed by the header travelling somewhere it does not validate."""
    target = url if isinstance(url, str) else url.full_url
    if not host_dialable(target):
        raise ValueError(f"refusing to dial a non-routable host (SSRF guard): {target}")
    signed: dict = {}
    if wba_identity is not None:
        from shared import webbotauth
        signed = webbotauth.request_headers(wba_identity, target)
    if isinstance(url, str):
        merged = dict(headers or {})
        present = {k.lower() for k in merged}
        for key, value in signed.items():
            if key.lower() not in present:
                merged[key] = value
        req = urllib.request.Request(url, data=data, method=method, headers=merged)
    else:
        req = url
        for key, value in signed.items():
            if not req.has_header(key.capitalize()):   # urllib's own header key form
                req.add_header(key, value)
    return opener().open(req, timeout=timeout)
