"""
test_webbotauth.py — the T89 Web Bot Auth bridge, end to end (shared/webbotauth.py).

The bridge's whole claim is that ONE Ed25519 key is both a muretai did:key and a Web Bot
Auth JWK, so a spec-conformant key directory an operator already publishes doubles as a
DOMAIN -> DID proof. That claim is only worth anything because the directory response is
SIGNED by the very key it advertises: a public JWK is copyable, a signature over
`@authority` is not. Almost every test below exists to hold that one line.

  Part 1  happy path — the pinned wire vectors (JWK <-> did:key, RFC 7638 thumbprint,
          the signature base byte for byte), request sign -> verify, directory build ->
          verify, and the Signature-Agent value under a MURETAI_PUBLIC_BASE override.
  Part 2  attacks, each named for what it is: copied-jwk-directory (THE proof-of-possession
          test), tampered-signature-base, expired-window / created-in-future /
          window-too-long, keyid-not-in-directory, replayed-headers-on-another-body,
          wrong-alg, tag-confusion, directory-over-redirect, oversized-directory.
  Part 3  the NODE route (agent/inbox.py): media type, an allowlisted Host gets a
          signature that verifies, a non-allowlisted Host gets the body and NOTHING else
          (host-header-signing-oracle), and the cache serves byte-identical signatures.
  Part 4  the RELAY route (relay.py / relay_proxy.py): deposit -> serve verbatim, a bad or
          copied deposit refused, the unsigned derived fallback, the raw envelope view,
          and the proxy's DID routing for both new path shapes.
  Part 5  the OUTBOUND hook (shared/neturl.urlopen_guarded): silent by default, correct
          when asked, and working through an identity that exposes only `.did` and
          `.sign_bytes` (remote-signer safety).

Style mirrors test_httpua.py / test_orgbind.py: plain asserts, banner prints, a __main__
runner, temp state kept out of the repo's keys/.

Run:  python3 test_webbotauth.py
      AGENTNET_PURE_ED25519=1 python3 test_webbotauth.py
"""
# SPDX-License-Identifier: MIT
# Part of the WIRE CONTRACT (PROVENANCE.md): copied from Muretai core, with the edits that
# file records, and published here under MIT with the bytes it checks.
from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from shared import crypto, gateway, jws, neturl, protocol as p, webbotauth as wba
# agent-seam: a seed-only signer stands in for agent.identity.Identity. The three tests that
# drove a node route, a relay route and the outbound hook stay in core (they need agent/ and relay).
from _seedsigner import _SeedSigner

print(f"signing backend: {crypto.BACKEND}")

# ------------------------------------------------------------------ fixtures

#: The pinned vector. A seed of bytes(range(32)) is the one input every part of this
#: suite (and shared/webbotauth._selftest) agrees on, so a change that moves any of the
#: three constants below has broken interoperability with every peer already speaking
#: this profile — these are the contract, not an implementation detail.
SEED = bytes(range(32))
VECTOR_DID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
VECTOR_X = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
VECTOR_KEYID = "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"
CREATED = 1754870400
EXPIRES = 1754870700
NOW = CREATED                     # every fixed-time assertion is anchored here

KEYS = Path(tempfile.mkdtemp(prefix="wba-keys-"))

ME = _SeedSigner(SEED)                       # the vector identity
THIEF = _SeedSigner(bytes(range(64, 96)))  # copies public keys, holds no secret
OTHER = _SeedSigner(bytes(range(96, 128)))

CTYPE = {"Content-Type": wba.WBA_DIRECTORY_CONTENT_TYPE}


class Env:
    """Set environment variables for a block and restore them EXACTLY, including
    "was unset" — the whole suite runs in one process, and a leaked MURETAI_PUBLIC_BASE
    would silently change what a later part signs (a Signature-Agent that no longer
    matches the vector) instead of failing where the mistake was made."""

    def __init__(self, **kw: Optional[str]) -> None:
        self._want = kw
        self._old: Dict[str, Optional[str]] = {}

    def __enter__(self) -> "Env":
        for key, value in self._want.items():
            self._old[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc: Any) -> bool:
        for key, value in self._old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


class RemoteSigner:
    """An identity that exposes ONLY `did` and `sign_bytes` — no seed, anywhere.

    This is the shape a keys/<name>.signer.json identity really has, and __slots__ makes
    the absence enforceable: any code that reaches for `_seed` (or grows a new attribute)
    raises here instead of quietly working on a developer's laptop and breaking on a node
    whose key lives in an external signer."""

    __slots__ = ("did", "_sign")

    def __init__(self, did: str, sign_bytes: Any) -> None:
        self.did = did
        self._sign = sign_bytes

    def sign_bytes(self, message: bytes) -> str:
        return self._sign(message)


def signed(sig_input: str, sig: str, **extra: str) -> Dict[str, str]:
    """A served directory response's headers: the media type (which the verifier checks
    before anything else) plus the RFC 9421 pair."""
    out = dict(CTYPE)
    out["Signature-Input"] = sig_input
    out["Signature"] = sig
    out.update(extra)
    return out


def raw_sig(identity: Any, components: Sequence[Tuple[str, str]],
            params: str, label: str = "sig1") -> Tuple[str, str]:
    """Sign an EXACT `@signature-params` text — the escape hatch signature_params() does
    not give us. A test needs it to produce params a conforming peer could legitimately
    send (an omitted `alg`) and params an attacker would (a foreign `keyid`), both carrying
    a REAL Ed25519 signature over the matching base, so what is under test is the policy
    check and not a broken signature."""
    base = wba.signature_base(components, params)
    return "%s=%s" % (label, params), "%s=:%s:" % (label, identity.sign_bytes(base))


def hget(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup for a captured/received header mapping.

    Needed because urllib re-cases every header it sends through `str.capitalize()`, so
    the `Signature-Input` we hand it arrives at the far end as `Signature-input`. HTTP
    field names are case-insensitive and the signature covers the LOWERCASED component
    name, so this is correct on the wire — a test that looked the key up exactly would be
    asserting urllib's spelling, not the protocol's."""
    lowered = name.lower()
    for key, value in dict(headers).items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return None


def has_wba_headers(headers: Any) -> bool:
    """True when EITHER signature header is present. Both-or-neither is the invariant
    (one alone is unverifiable), so the absence assertions test for either."""
    return (hget(headers, "Signature-Input") is not None
            or hget(headers, "Signature") is not None)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_get(port: int, path: str = wba.WBA_DIRECTORY_PATH,
             host_header: Optional[str] = None) -> Tuple[int, Dict[str, str], bytes]:
    """GET over loopback with FULL control of the Host header — the one request field the
    node's signing decision is driven by, and therefore the one this suite must be able to
    forge (see the host-header-signing-oracle test)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers={} if host_header is None
                     else {"Host": host_header})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class Quiet(http.server.BaseHTTPRequestHandler):
    """A stub origin that does not narrate the suite's own traffic.

    Deliberately left on the default HTTP/1.0: these stubs run on a single-threaded
    HTTPServer, and an HTTP/1.1 keep-alive would park the one handler thread waiting for
    a second request on a socket the client has finished with — a `shutdown()` that hangs
    the suite instead of failing it. One request per connection is what a stub wants."""

    def log_message(self, *args: Any) -> None:
        return


def serve(handler_cls: Any) -> Tuple[Any, str]:
    """Bind a loopback stub (port 0) and start it. Returns (server, "127.0.0.1:<port>") —
    the authority string a Web Bot Auth verifier will derive for it."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "127.0.0.1:%d" % server.server_address[1]


def wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("server on port %d never came up" % port)


# ============================================================ Part 1: happy path

def test_jwk_did_roundtrip() -> None:
    print("\n=== 1-1: JWK <-> did:key roundtrip (pinned vector) ===")
    assert ME.did == VECTOR_DID, ME.did
    jwk = wba.jwk_from_did(ME.did)
    assert jwk == {"crv": "Ed25519", "kty": "OKP", "x": VECTOR_X}, jwk
    assert set(jwk) == {"crv", "kty", "x"}, "a JWK carries the RFC 7638 required set only"
    assert wba.did_from_jwk(jwk) == ME.did
    assert wba.public_from_jwk(jwk) == ME.public
    # The bridge is a re-encoding of ONE number, so the round trip must be exact both ways.
    assert crypto.did_from_public(wba.public_from_jwk(jwk)) == ME.did
    # Two spellings of one key would thumbprint differently, which is the ambiguity the
    # whole proof rests on not having — so a padded / standard-alphabet `x` is REFUSED,
    # never repaired.
    assert wba.public_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": VECTOR_X + "="}) is None
    assert wba.public_from_jwk({"kty": "OKP", "crv": "Ed25519",
                                "x": VECTOR_X.replace("_", "/")}) is None
    assert wba.public_from_jwk({"kty": "OKP", "crv": "X25519", "x": VECTOR_X}) is None
    assert wba.public_from_jwk({"kty": "EC", "crv": "P-256", "x": VECTOR_X}) is None
    assert wba.public_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": "AA"}) is None
    assert wba.did_from_jwk("not a jwk") is None and wba.did_from_jwk(None) is None
    print("OK: one key, two spellings; every other spelling is refused")


def test_thumbprint() -> None:
    print("\n=== 1-2: RFC 7638 thumbprint is the keyid on the wire ===")
    jwk = wba.jwk_from_did(ME.did)
    assert wba.jwk_thumbprint(jwk) == VECTOR_KEYID
    # Recomputed here from the RFC's own construction (required members, lexicographic,
    # no whitespace) rather than from the module — otherwise the test would only prove
    # the module agrees with itself.
    literal = ('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % VECTOR_X).encode("utf-8")
    assert jws.b64url(hashlib.sha256(literal).digest()) == VECTOR_KEYID
    # Decoration must not move the identifier: two parties naming one key always agree.
    assert wba.jwk_thumbprint(dict(jwk, kid="k1", use="sig",
                                   alg="EdDSA")) == VECTOR_KEYID
    try:
        wba.jwk_thumbprint({"kty": "EC", "crv": "P-256", "x": VECTOR_X})
        raise AssertionError("a non-Ed25519 JWK must not yield a thumbprint")
    except ValueError:
        pass
    print("OK: thumbprint matches the RFC construction and ignores decoration")


def test_signature_base_vector() -> None:
    print("\n=== 1-3: the worked signature base, byte for byte ===")
    agent_sf = '"https://muretai.net/%s"' % gateway.zkey_of(ME.did)
    components = (("@authority", "example.com"), ("signature-agent", agent_sf))
    params = wba.signature_params([n for n, _ in components], created=CREATED,
                                  expires=EXPIRES, keyid=VECTOR_KEYID,
                                  tag=wba.TAG_REQUEST)
    base = wba.signature_base(components, params)
    expected = (
        '"@authority": example.com\n'
        '"signature-agent": '
        '"https://muretai.net/z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"\n'
        '"@signature-params": ("@authority" "signature-agent")'
        ';created=1754870400;expires=1754870700'
        ';keyid="1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"'
        ';alg="ed25519";tag="web-bot-auth"'
    ).encode("utf-8")
    assert base == expected, base.decode("utf-8")
    # No trailing newline, and the params line is LAST — that final line is what binds a
    # signature to its own metadata (keyid / tag / window).
    assert not base.endswith(b"\n")
    assert base.splitlines()[-1].startswith(b'"@signature-params": ')
    # Integer epochs only: a float renders per-language and stops being interoperable.
    assert ";created=1754870400;" in params and ".0" not in params
    print("OK: the pinned base matches (this is the interop contract)")


def test_request_roundtrip_and_signature_agent() -> None:
    print("\n=== 1-4: request sign -> verify, and Signature-Agent under a base override ===")
    with Env(MURETAI_PUBLIC_BASE="https://gw.example"):
        headers = wba.request_headers(ME, "https://shop.example/rpc", created=CREATED)
        # The HP URL is the stable, location-independent address — the gateway override
        # is what a self-host sets, so the header must follow it and not a baked default.
        assert headers["Signature-Agent"] == '"https://gw.example/%s"' % gateway.zkey_of(ME.did)
        # The COMPONENT value and the emitted HEADER value must be the same sf-string, or
        # the verifier re-signs over text the sender never sent.
        entries = wba.parse_signature_headers(headers["Signature-Input"],
                                              headers["Signature"])
        assert entries and entries[0]["components"] == ["@authority", "signature-agent"]
        assert entries[0]["params"]["tag"] == wba.TAG_REQUEST
        assert entries[0]["params"]["keyid"] == VECTOR_KEYID
        directory = wba.directory_jwks(ME.did)
        assert wba.verify_request(headers, authority="shop.example", jwks=directory,
                                  now=CREATED + 10) == ME.did
        # Origin-bound: the same bytes prove nothing anywhere else.
        assert wba.verify_request(headers, authority="other.example", jwks=directory,
                                  now=CREATED + 10) is None
    # And the override really is the only source of that value.
    with Env(MURETAI_PUBLIC_BASE=None):
        default = wba.request_headers(ME, "https://shop.example/rpc", created=CREATED)
        assert default["Signature-Agent"] == '"%s"' % gateway.did_site_url(ME.did)
    print("OK: request headers verify, bound to the authority and to the gateway base")


def test_directory_roundtrip() -> None:
    print("\n=== 1-5: directory build -> verify_directory_response roundtrip ===")
    body, sig_input, sig = wba.directory_response(ME, "muretai.example", created=CREATED)
    assert body == wba.directory_body(ME.did)
    assert json.loads(body.decode("utf-8")) == {"keys": [wba.jwk_from_did(ME.did)]}
    served = signed(sig_input, sig)
    assert wba.verify_directory_response("muretai.example", served, body,
                                         now=CREATED + 60) == [ME.did]
    # Case and surrounding whitespace on the authority are normalized by the verifier,
    # because the signer normalized them too (one spelling per origin).
    assert wba.verify_directory_response(" MURETAI.example ", served, body,
                                         now=CREATED + 60) == [ME.did]
    # The media type is load-bearing: an HTML error page is not a key directory.
    assert wba.verify_directory_response(
        "muretai.example", {"Content-Type": "text/html",
                            "Signature-Input": sig_input, "Signature": sig},
        body, now=CREATED + 60) == []
    # charset parameters are fine (startswith, not equality).
    assert wba.verify_directory_response(
        "muretai.example",
        {"Content-Type": wba.WBA_DIRECTORY_CONTENT_TYPE + "; charset=utf-8",
         "Signature-Input": sig_input, "Signature": sig},
        body, now=CREATED + 60) == [ME.did]
    # A remote-signer identity (no seed) produces the identical artifact.
    stub = RemoteSigner(ME.did, ME.sign_bytes)
    rbody, rin, rsig = wba.directory_response(stub, "muretai.example", created=CREATED)
    assert (rbody, rin, rsig) == (body, sig_input, sig)
    print("OK: a signed directory proves its DID; the media type and the seed-free "
          "signer both hold")


def test_enabled_flag() -> None:
    print("\n=== 1-6: the bridge is opt-in (MURETAI_WBA) ===")
    with Env(MURETAI_WBA=None):
        assert wba.enabled() is False
    with Env(MURETAI_WBA="1"):
        assert wba.enabled() is True
    with Env(MURETAI_WBA="true"):
        assert wba.enabled() is False, "only the exact '1' switches it on"
    print("OK: off unless explicitly switched on")


# ============================================================ Part 2: attacks

def test_attack_copied_jwk_directory() -> None:
    print("\n=== 2-1: ATTACK copied-jwk-directory (THE proof-of-possession test) ===")
    # evil.example serves the victim's REAL public JWK. Nothing about the body is forged
    # — it is byte-identical to what the victim publishes — and that is the point: if the
    # verifier believed CONTENT, this would be a free, silent takeover of the victim's DID.
    stolen = wba.directory_body(ME.did)

    # (a) no signature at all.
    assert wba.verify_directory_response("evil.example", CTYPE, stolen, now=NOW) == []

    # (b) a perfectly valid RFC 9421 signature — by the THIEF's key, over evil.example.
    thief_keyid = wba.jwk_thumbprint(wba.jwk_from_did(THIEF.did))
    t_in, t_sig = wba.wba_sign(THIEF.sign_bytes, (("@authority", "evil.example"),),
                               created=NOW, expires=NOW + wba.DIR_SIG_WINDOW,
                               keyid=thief_keyid, tag=wba.TAG_DIRECTORY)
    assert wba.verify_directory_response("evil.example", signed(t_in, t_sig),
                                         stolen, now=NOW + 60) == []

    # (c) the victim's OWN genuine signature, lifted from the victim's own origin.
    v_body, v_in, v_sig = wba.directory_response(ME, "victim.example", created=NOW)
    assert wba.verify_directory_response("evil.example", signed(v_in, v_sig),
                                         v_body, now=NOW + 60) == []
    assert wba.verify_directory_response("victim.example", signed(v_in, v_sig),
                                         v_body, now=NOW + 60) == [ME.did]

    # The rule is proof of possession, not a blocklist: the thief's OWN key on the
    # thief's OWN domain still proves exactly what it should.
    t_body, t_in2, t_sig2 = wba.directory_response(THIEF, "evil.example", created=NOW)
    assert wba.verify_directory_response("evil.example", signed(t_in2, t_sig2),
                                         t_body, now=NOW + 60) == [THIEF.did]
    print("OK: a copied public JWK proves nothing, on any origin, with any signature "
          "but its own")


def test_attack_tampered_signature_base() -> None:
    print("\n=== 2-2: ATTACK tampered-signature-base ===")
    authority = "muretai.example"
    body, sig_input, sig = wba.directory_response(ME, authority, created=NOW)
    served = signed(sig_input, sig)
    assert wba.verify_directory_response(authority, served, body, now=NOW + 60) == [ME.did]

    # (a) flip the authority — the ONE component a directory signature covers.
    assert wba.verify_directory_response("evil.example", served, body,
                                         now=NOW + 60) == []

    # (b) bump `created` by one second. The base is rebuilt from the RECEIVED params
    # text, so a single digit anywhere in it invalidates the signature.
    bumped = signed(sig_input.replace("created=%d" % NOW, "created=%d" % (NOW + 1)), sig)
    assert bumped["Signature-Input"] != sig_input, "the tamper must actually apply"
    assert wba.verify_directory_response(authority, bumped, body, now=NOW + 60) == []

    # (c) drop the covered component. Without `@authority` the same bytes would prove the
    # same thing on every domain — i.e. prove nothing — so it is refused outright.
    dropped = signed(sig_input.replace('("@authority")', "()"), sig)
    assert wba.verify_directory_response(authority, dropped, body, now=NOW + 60) == []

    # The same three, on the request side, where a component can be dropped from a set.
    headers = wba.request_headers(ME, "https://shop.example/rpc", created=NOW)
    directory = wba.directory_jwks(ME.did)
    assert wba.verify_request(headers, authority="shop.example", jwks=directory,
                              now=NOW + 10) == ME.did
    less = dict(headers)
    less["Signature-Input"] = headers["Signature-Input"].replace(
        '("@authority" "signature-agent")', '("@authority")')
    assert less["Signature-Input"] != headers["Signature-Input"]
    assert wba.verify_request(less, authority="shop.example", jwks=directory,
                              now=NOW + 10) is None
    swapped = dict(headers, **{"Signature-Agent": '"https://evil.example/z6MkOther"'})
    assert wba.verify_request(swapped, authority="shop.example", jwks=directory,
                              now=NOW + 10) is None
    # A covered header that vanishes cannot be resolved, so the entry is unusable.
    missing = {k: v for k, v in headers.items() if k != "Signature-Agent"}
    assert wba.verify_request(missing, authority="shop.example", jwks=directory,
                              now=NOW + 10) is None
    print("OK: authority flip / created bump / dropped component all fail closed")


def test_attack_windows() -> None:
    print("\n=== 2-3: ATTACK expired-window / created-in-future / window-too-long ===")
    authority = "muretai.example"
    body, sig_input, sig = wba.directory_response(ME, authority, created=NOW)
    served = signed(sig_input, sig)

    # expired: a signature is dead the instant `expires` is reached.
    assert wba.verify_directory_response(authority, served, body,
                                         now=NOW + wba.DIR_SIG_WINDOW) == []
    assert wba.verify_directory_response(authority, served, body,
                                         now=NOW + wba.DIR_SIG_WINDOW - 1) == [ME.did]

    # created in the future: tolerated only up to CLOCK_SKEW, and that tolerance is
    # applied to `created` ALONE — accepting a passed `expires` would extend a
    # signature's life, which is the direction that costs security.
    ahead = wba.directory_response(ME, authority, created=NOW + wba.CLOCK_SKEW + 60)
    assert wba.verify_directory_response(authority, signed(ahead[1], ahead[2]),
                                         ahead[0], now=NOW) == []
    near = wba.directory_response(ME, authority, created=NOW + wba.CLOCK_SKEW - 60)
    assert wba.verify_directory_response(authority, signed(near[1], near[2]),
                                         near[0], now=NOW) == [ME.did]

    # window too long: a signature that lives nearly forever is a permanent bearer proof.
    long_ = wba.directory_response(ME, authority, created=NOW,
                                   window=wba.DEPOSIT_SIG_WINDOW + 60)
    assert wba.verify_directory_response(authority, signed(long_[1], long_[2]),
                                         long_[0], now=NOW + 60) == []
    at_cap = wba.directory_response(ME, authority, created=NOW,
                                    window=wba.DEPOSIT_SIG_WINDOW)
    assert wba.verify_directory_response(authority, signed(at_cap[1], at_cap[2]),
                                         at_cap[0], now=NOW + 60) == [ME.did]

    # The REQUEST ceiling is far tighter: these headers are a bearer credential while
    # they live, so a pair captured from a log must be useless within minutes.
    directory = wba.directory_jwks(ME.did)
    wide = wba.request_headers(ME, "https://shop.example/rpc", created=NOW,
                               window=wba.REQUEST_SIG_WINDOW + wba.CLOCK_SKEW + 1)
    assert wba.verify_request(wide, authority="shop.example", jwks=directory,
                              now=NOW + 10) is None
    edge = wba.request_headers(ME, "https://shop.example/rpc", created=NOW,
                               window=wba.REQUEST_SIG_WINDOW + wba.CLOCK_SKEW)
    assert wba.verify_request(edge, authority="shop.example", jwks=directory,
                              now=NOW + 10) == ME.did
    print("OK: expiry, future-dating and unbounded lifetimes are all refused")


def test_attack_keyid_not_in_directory() -> None:
    print("\n=== 2-4: ATTACK keyid-not-in-directory ===")
    authority = "muretai.example"
    other_keyid = wba.jwk_thumbprint(wba.jwk_from_did(OTHER.did))
    # A REAL signature by our key, announcing someone else's thumbprint. Neither half
    # of the pair (our key / their keyid) can be made to agree with the other.
    params = wba.signature_params(["@authority"], created=NOW, expires=NOW + 600,
                                  keyid=other_keyid, tag=wba.TAG_DIRECTORY)
    sig_input, sig = raw_sig(ME, (("@authority", authority),), params)
    assert wba.verify_directory_response(authority, signed(sig_input, sig),
                                         wba.directory_body(ME.did), now=NOW + 60) == []
    # Put the NAMED key in the body instead: now the keyid matches a key, but that key
    # did not make the signature.
    assert wba.verify_directory_response(authority, signed(sig_input, sig),
                                         wba.directory_body(OTHER.did),
                                         now=NOW + 60) == []
    # An entirely unknown keyid names nothing at all.
    unknown = wba.signature_params(["@authority"], created=NOW, expires=NOW + 600,
                                   keyid="not-a-thumbprint", tag=wba.TAG_DIRECTORY)
    u_in, u_sig = raw_sig(ME, (("@authority", authority),), unknown)
    assert wba.verify_directory_response(authority, signed(u_in, u_sig),
                                         wba.directory_body(ME.did), now=NOW + 60) == []
    # The same rule on the request side.
    r_params = wba.signature_params(["@authority"], created=NOW, expires=NOW + 60,
                                    keyid=other_keyid, tag=wba.TAG_REQUEST)
    r_in, r_sig = raw_sig(ME, (("@authority", "shop.example"),), r_params)
    assert wba.verify_request({"Signature-Input": r_in, "Signature": r_sig},
                              authority="shop.example",
                              jwks=wba.directory_jwks(ME.did), now=NOW + 10) is None
    print("OK: the keyid must name a key IN the directory and that key must have signed")


def test_attack_replayed_headers_on_another_body() -> None:
    print("\n=== 2-5: ATTACK replayed-headers-on-another-body ===")
    authority = "muretai.example"
    # A directory signature covers `@authority`, NOT the body — so the interesting
    # question is what stops A's headers being served over B's JWKS. The answer is the
    # keyid/key pairing, and this is where that gets proven.
    a_body, a_in, a_sig = wba.directory_response(ME, authority, created=NOW)
    b_body = wba.directory_body(OTHER.did)
    assert wba.verify_directory_response(authority, signed(a_in, a_sig), b_body,
                                         now=NOW + 60) == []
    # A directory mixing one honest key with a stolen one yields EXACTLY the honest DID:
    # unproven entries are dropped silently rather than poisoning the whole document.
    mixed = json.dumps({"keys": [wba.jwk_from_did(OTHER.did), wba.jwk_from_did(ME.did)]},
                       sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert wba.verify_directory_response(authority, signed(a_in, a_sig), mixed,
                                         now=NOW + 60) == [ME.did]
    assert a_body != mixed, "the mixed document really is a different body"
    # A body that is not a key directory at all proves nothing either.
    for junk in (b"{}", b'{"keys":{}}', b"[]", b"not json", b""):
        assert wba.verify_directory_response(authority, signed(a_in, a_sig), junk,
                                             now=NOW + 60) == []
    print("OK: replayed headers prove only the key that made them, in any document")


def test_attack_wrong_alg() -> None:
    print("\n=== 2-6: ATTACK wrong-alg ===")
    authority = "muretai.example"
    keyid = wba.jwk_thumbprint(wba.jwk_from_did(ME.did))
    # A real Ed25519 signature announcing a different algorithm. `alg` is CHECKED, never
    # TRUSTED — the verifier's policy decides the algorithm, not the message, which is
    # what closes the classic alg-confusion family. "EdDSA" is in the list on purpose: it
    # is the JOSE spelling of this very curve (shared/jws.ALG), and accepting it here
    # would be a silent registry mix-up rather than an obvious forgery.
    for lie in ("rsa-pss-sha512", "hmac-sha256", "EdDSA", "ed25519 "):
        params = wba.signature_params(["@authority"], created=NOW, expires=NOW + 600,
                                      keyid=keyid, tag=wba.TAG_DIRECTORY, alg=lie)
        sig_input, sig = raw_sig(ME, (("@authority", authority),), params)
        assert wba.verify_directory_response(authority, signed(sig_input, sig),
                                             wba.directory_body(ME.did),
                                             now=NOW + 60) == [], lie
    # An OMITTED alg is legal in this profile and must still prove possession — the check
    # is "not a DIFFERENT algorithm", not "an algorithm was named".
    omitted = ('("@authority");created=%d;expires=%d;keyid="%s";tag="%s"'
               % (NOW, NOW + 600, keyid, wba.TAG_DIRECTORY))
    o_in, o_sig = raw_sig(ME, (("@authority", authority),), omitted)
    assert wba.verify_directory_response(authority, signed(o_in, o_sig),
                                         wba.directory_body(ME.did),
                                         now=NOW + 60) == [ME.did]
    print("OK: only 'ed25519' (or nothing) is accepted; the JOSE spelling is not")


def test_attack_tag_confusion() -> None:
    print("\n=== 2-7: ATTACK tag-confusion (domain separation) ===")
    authority = "shop.example"
    directory = wba.directory_jwks(ME.did)
    request = wba.request_headers(ME, "https://%s/rpc" % authority, created=NOW)
    dir_body, dir_in, dir_sig = wba.directory_response(ME, authority, created=NOW)

    # Each proves what it IS for.
    assert wba.verify_request(request, authority=authority, jwks=directory,
                              now=NOW + 10) == ME.did
    assert wba.verify_directory_response(authority, signed(dir_in, dir_sig), dir_body,
                                         now=NOW + 10) == [ME.did]

    # A REQUEST signature offered as a directory self-attestation. Same key, same
    # authority, same instant — only the tag differs, and that is enough.
    as_directory = signed(request["Signature-Input"], request["Signature"],
                          **{"Signature-Agent": request["Signature-Agent"]})
    assert wba.verify_directory_response(authority, as_directory,
                                         wba.directory_body(ME.did), now=NOW + 10) == []

    # …and a DIRECTORY signature offered as request authentication.
    assert wba.verify_request({"Signature-Input": dir_in, "Signature": dir_sig},
                              authority=authority, jwks=directory, now=NOW + 10) is None

    # Rewriting the tag does not help: it is INSIDE the signed params.
    forged = dir_in.replace('tag="%s"' % wba.TAG_DIRECTORY,
                            'tag="%s"' % wba.TAG_REQUEST)
    assert forged != dir_in
    assert wba.verify_request({"Signature-Input": forged, "Signature": dir_sig},
                              authority=authority, jwks=directory, now=NOW + 10) is None
    print("OK: the two applications are non-interchangeable in both directions")


def test_attack_directory_over_redirect() -> None:
    print("\n=== 2-8: ATTACK directory-over-redirect ===")
    # The real shape of this attack: the attacker does NOT control the content served at
    # the victim-ish origin, only its redirect (an open redirector, a CDN misconfig, a
    # parked domain). Signing is free, so the attacker signs a directory for the HOP's
    # authority and serves it on a host they do own. If the fetcher followed the 302 and
    # kept deriving `@authority` from the URL it asked for, that signature would verify
    # and mint "hop.example operates <attacker DID>" out of nothing.
    state: Dict[str, str] = {}

    class Target(Quiet):
        def do_GET(self) -> None:                       # noqa: N802 (stdlib API)
            body, sig_input, sig = wba.directory_response(THIEF, state["hop"])
            self.send_response(200)
            self.send_header("Content-Type", wba.WBA_DIRECTORY_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Signature-Input", sig_input)
            self.send_header("Signature", sig)
            self.end_headers()
            self.wfile.write(body)

    class Hop(Quiet):
        def do_GET(self) -> None:                       # noqa: N802 (stdlib API)
            self.send_response(302)
            self.send_header("Location", state["target_url"])
            self.send_header("Content-Length", "0")
            self.end_headers()

    target_srv, target_host = serve(Target)
    hop_srv, hop_host = serve(Hop)
    state["hop"] = hop_host
    state["target_url"] = "http://%s%s" % (target_host, wba.WBA_DIRECTORY_PATH)
    try:
        with Env(MURETAI_WBA_ALLOW_HTTP="1"):
            # The forged document really IS valid for the hop's authority — so the ONLY
            # thing standing between it and a forged domain binding is refusing the 302.
            status, headers, body = http_get(target_srv.server_address[1])
            assert status == 200
            assert wba.verify_directory_response(hop_host, headers, body) == [THIEF.did]
            # Fetching the redirector must yield nothing at all.
            assert wba.verify_wba_directory("http://" + hop_host) == []
            # Nor does the forgery work when fetched honestly: asked directly, the target
            # origin answers with a signature bound to a name it is not.
            assert wba.verify_wba_directory("http://" + target_host) == []
    finally:
        for srv in (target_srv, hop_srv):
            srv.shutdown()
            srv.server_close()
    print("OK: a 302 answers about somewhere else, so it proves nothing here")


def test_attack_oversized_directory() -> None:
    print("\n=== 2-9: ATTACK oversized-directory ===")
    authority = "muretai.example"
    _, sig_input, sig = wba.directory_response(ME, authority, created=NOW)
    over = b"x" * (wba.MAX_DIRECTORY_BYTES + 1)
    assert wba.verify_directory_response(authority, signed(sig_input, sig), over,
                                         now=NOW + 60) == []
    # And a hostile origin cannot make the FETCHER chew through an endless stream: the
    # read is capped, and a body over the cap is an error, never a truncated document.
    class Flood(Quiet):
        def do_GET(self) -> None:                       # noqa: N802 (stdlib API)
            blob = b"x" * (wba.MAX_DIRECTORY_BYTES + 1)
            self.send_response(200)
            self.send_header("Content-Type", wba.WBA_DIRECTORY_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

    server, host = serve(Flood)
    try:
        with Env(MURETAI_WBA_ALLOW_HTTP="1"):
            assert wba.verify_wba_directory("http://" + host) == []
    finally:
        server.shutdown()
        server.server_close()
    print("OK: an oversized directory is refused locally and on the wire")


def test_fetch_policy() -> None:
    print("\n=== 2-10: fetch policy — plaintext, scheme and path are all refused ===")
    class Honest(Quiet):
        def do_GET(self) -> None:                       # noqa: N802 (stdlib API)
            if self.path != wba.WBA_DIRECTORY_PATH:
                self.send_error(404)
                return
            body, sig_input, sig = wba.directory_response(
                ME, "127.0.0.1:%d" % self.server.server_address[1])
            self.send_response(200)
            self.send_header("Content-Type", wba.WBA_DIRECTORY_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Signature-Input", sig_input)
            self.send_header("Signature", sig)
            self.end_headers()
            self.wfile.write(body)

    server, host = serve(Honest)
    try:
        # DEFAULT POLICY (no MURETAI_WBA_ALLOW_HTTP): plaintext is refused outright.
        # A signature nobody can forge is small comfort if the response never arrives —
        # anyone on the path can simply strip the directory.
        with Env(MURETAI_WBA_ALLOW_HTTP=None):
            assert wba.verify_wba_directory("http://" + host) == []
        # The escape hatch exists so a loopback stub can be its own subject, and here it
        # is exactly that.
        with Env(MURETAI_WBA_ALLOW_HTTP="1"):
            assert wba.verify_wba_directory("http://" + host) == [(host, ME.did)]
            # The resource is at a FIXED well-known location or it is not this resource.
            assert wba.verify_wba_directory("http://" + host + "/path") == []
            assert wba.verify_wba_directory("http://" + host + "?x=1") == []
            assert wba.verify_wba_directory("ftp://" + host) == []
            assert wba.verify_wba_directory("") == []
            assert wba.verify_wba_directory(None) == []
    finally:
        server.shutdown()
        server.server_close()
    print("OK: https-only by default; scheme/path/garbage all yield no proof")


# ============================================================ Part 3: node route


# ============================================================ Part 4: relay route


# ============================================================ Part 5: outbound hook


def test_request_vectors() -> None:
    """vectors/wba_vectors.json re-derived through verify_request, case by case.

    The vectors are the CROSS-IMPLEMENTATION pin: the JavaScript reference re-runs this
    same file through its own RFC 9421 subset, so a vector this module accepts and that
    one refuses (or vice versa) is a red suite, not a field report.
    This leg is what stops the FILE drifting from the Python module: the generator
    (tools/gen_wba_vectors.py) derives every case from the pinned fixture seed, and
    this test refuses a file the live verifier disagrees with."""
    print("\n=== 20: the frozen request-verification vectors, re-derived ===")
    doc = json.loads((ROOT.parent / "vectors" / "wba_vectors.json").read_text("utf-8"))
    assert doc["did"] == VECTOR_DID, "the vector identity drifted from the fixture"
    assert bytes.fromhex(doc["seed_hex"]) == SEED
    for case in doc["accept"]:
        got = wba.verify_request(case["headers"], authority=doc["authority"],
                                 jwks=doc["jwks"], now=doc["now"])
        assert got == case["expect_did"], (case["name"], got)
    for case in doc["reject"]:
        got = wba.verify_request(case["headers"], authority=doc["authority"],
                                 jwks=doc["jwks"], now=doc["now"])
        assert got is None, (case["name"], got)
    print(f"OK: {len(doc['accept'])} accepted, {len(doc['reject'])} refused — "
          f"file and module agree")


TESTS = (
    test_jwk_did_roundtrip,
    test_thumbprint,
    test_signature_base_vector,
    test_request_roundtrip_and_signature_agent,
    test_directory_roundtrip,
    test_enabled_flag,
    test_attack_copied_jwk_directory,
    test_attack_tampered_signature_base,
    test_attack_windows,
    test_attack_keyid_not_in_directory,
    test_attack_replayed_headers_on_another_body,
    test_attack_wrong_alg,
    test_attack_tag_confusion,
    test_attack_directory_over_redirect,
    test_attack_oversized_directory,
    test_fetch_policy,
    test_request_vectors,
)


if __name__ == "__main__":
    import shutil
    try:
        for test in TESTS:
            test()
        print("\nALL WEB BOT AUTH (T89) TESTS PASSED")
    finally:
        shutil.rmtree(KEYS, ignore_errors=True)
