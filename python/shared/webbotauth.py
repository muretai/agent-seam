"""
shared/webbotauth.py
The Web Bot Auth bridge (T89): the same Ed25519 key that IS a muretai DID, spoken in
the dialect the open web is standardising on for "which bot is this?".

Why this bridge is nearly free — the observation the whole feature rests on:
  A did:key is multibase(0xed01 ++ <32-byte Ed25519 public key>). A Web Bot Auth key
  is a JWK {"kty":"OKP","crv":"Ed25519","x": base64url(<the same 32 bytes>)}. Two
  spellings, one number. So `did:key <-> JWK` is a pure re-encoding with no ceremony,
  no registry and no second key to protect — and, more importantly, a
  SPEC-CONFORMANT WEB BOT AUTH KEY DIRECTORY IS ALREADY A DOMAIN -> DID PROOF. An
  operator who publishes `/.well-known/http-message-signatures-directory` because
  Cloudflare/Akamai asked them to has, without doing anything muretai-specific, also
  published "the agent behind did:key:z6Mk… is operated by this domain". We read that
  and convert it into a trust edge. (shared/domainbind.py, T88, is the same claim in
  the DIF/JOSE dialect; this module is the RFC 9421 one. Neither replaces the other:
  they are two ecosystems, and an operator will already be in one of them.)

Why proof-of-possession on the directory response is MANDATORY, not decoration:
  A public JWK is copyable. If we accepted a directory's mere CONTENT, anyone could
  paste a victim's JWK onto their own well-known path and we would record
  "evil.example operates did:key:z6Mk…<victim>" — a free, silent identity takeover of
  the most valuable agents on the network. The IETF profile therefore has the origin
  SIGN its own directory response with each advertised key, and `@authority` is inside
  that signature. A copied public key cannot produce that signature; only the holder
  of the private key can. So the rule below is absolute: a key in the directory with
  no valid signature OVER IT, BOUND TO THIS AUTHORITY, is SKIPPED. No signature, no
  claim — the response body is evidence of nothing on its own.

Why the signature-parameter ORDER is fixed wire:
  RFC 9421 does not sign a parsed structure; it signs the literal text of the
  `@signature-params` value. `;created=1;expires=2;keyid="k"` and
  `;keyid="k";created=1;expires=2` carry the same meaning and different bytes, so a
  signer and a verifier that disagree about order simply never validate anything.
  `signature_params()` is the single place that order is decided
  (created, expires, keyid, alg, tag) and it must not be "tidied". On the VERIFY side
  we do not re-serialize at all: `parse_signature_headers` keeps the exact received
  text of the params (`signature_params`) and the base is rebuilt from THAT, so a peer
  whose library orders or spaces things differently still verifies. Signing is
  canonical; verification is byte-faithful — the same split as shared/jws.py.

Why every redirect is refused:
  The directory is ORIGIN-BOUND by definition: the question asked is "what does
  example.com publish at its own well-known path?". A 302 answers a different
  question — it proves something about wherever it points, not about example.com.
  Following it would let any host that can be made to redirect (an open redirector,
  a CDN misconfiguration, a parked domain) launder another origin's directory into a
  proof about itself. Hence a dedicated opener local to this module that RAISES on
  redirect, rather than `neturl.opener()`, which follows them (guarded, but follows).

Scope, deliberately small: Ed25519 only, the two component sets Web Bot Auth actually
uses (`@authority`, `signature-agent`), a structured-field parser that understands our
subset and returns None for everything else. RFC 9421 in full (content digests,
`@query-param`, per-item parameters, byte-sequence dictionaries) is surface we would
have to defend for no gain here.

Pure standard library (+ shared/crypto, shared/jws). Network dependencies
(neturl/httputil/httpua) are imported lazily inside the one function that dials out,
so the wire/crypto half of this module stays importable anywhere.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shared import crypto, gateway, jws

# ---------------------------------------------------------------- wire constants

#: Where an origin publishes its bot keys (RFC 8615 well-known, per the IETF
#: web-bot-auth drafts). Path is fixed by the spec — never make it configurable.
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"

#: The media type that path must serve. Checked on fetch: a directory answered as
#: text/html is an error page or a captive portal, not a key directory.
WBA_DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json"

#: RFC 9421 `tag` — the APPLICATION a signature was made for. It is inside the signed
#: params, so it is what stops a signature minted to authenticate an outbound request
#: from being replayed as a directory self-attestation (and vice versa). Two tags, two
#: non-interchangeable meanings.
TAG_REQUEST = "web-bot-auth"
TAG_DIRECTORY = "http-message-signatures-directory"

#: The only `alg` we emit or accept. Lowercase "ed25519" here (RFC 9421's HTTP
#: signature algorithm registry) — NOT JOSE's "EdDSA" (shared/jws.ALG). Same curve,
#: two registries; mixing the spellings is a silent interop failure.
ALG = "ed25519"

#: How long a signature we MINT stays valid. A request signature is an authentication
#: of one call, so it is minutes; a directory response is cacheable, so it is hours and
#: is re-signed well before expiry (DIR_SIG_REFRESH) rather than at the last moment.
REQUEST_SIG_WINDOW = 300
DIR_SIG_WINDOW = 7200
DIR_SIG_REFRESH = 3600

#: The loosest lifetime we will ACCEPT on a directory signature. A verifier is stricter
#: than a signer is generous: an origin may legitimately serve a long-lived, cached
#: directory, but a signature that never expires is a permanent bearer proof, and a
#: leaked one would be unrevocable. A week is the ceiling.
DEPOSIT_SIG_WINDOW = 7 * 86400

#: Tolerance for the peer's clock being ahead of ours. Applied to `created` only:
#: accepting an `expires` that has passed would extend a signature's life, which is
#: the direction that costs security.
CLOCK_SKEW = 300

#: A key directory is a handful of 32-byte keys. 64 KiB is already absurd; the cap
#: exists so a hostile origin cannot make us read an endless stream.
MAX_DIRECTORY_BYTES = 65536

#: The loosest lifetime we accept on a REQUEST signature. Deliberately near our own
#: emission window: a request signature is a bearer credential for the duration of its
#: validity, so a header captured from a log should be useless within minutes. The
#: extra CLOCK_SKEW is headroom for a peer whose profile picks a slightly wider window.
_MAX_REQUEST_LIFETIME = REQUEST_SIG_WINDOW + CLOCK_SKEW

#: Refuse to even tokenize an absurd header. Bounds the parser's work on hostile input.
_MAX_HEADER_CHARS = 8192

_DEFAULT_PORT = {"http": 80, "https": 443}


def enabled() -> bool:
    """True when the Web Bot Auth bridge is switched on (``MURETAI_WBA=1``).

    Opt-in because it changes what we SEND (an extra pair of headers on outbound
    HTTP) and what we BELIEVE (a domain->DID edge from a third-party well-known
    path). Neither should start happening because a node upgraded."""
    return os.environ.get("MURETAI_WBA") == "1"


# ---------------------------------------------------------------- key layer

def jwk_from_public(public: bytes) -> Dict[str, str]:
    """A raw Ed25519 public key as an OKP JWK (RFC 8037).

    Exactly three members, in the RFC 7638 required set, so the dict IS its own
    thumbprint input — no `kid`, `use` or `alg` decoration. Anything extra would be
    a member some other implementation might or might not echo back, and every such
    difference is a chance for two parties to compute different thumbprints for the
    same key."""
    return {"crv": "Ed25519", "kty": "OKP", "x": jws.b64url(public)}


def public_from_jwk(jwk: Any) -> Optional[bytes]:
    """The 32 raw key bytes of an Ed25519 JWK, or None. Never raises.

    Strict, because this is the gate every untrusted directory entry passes through:
    `kty` must be OKP, `crv` must be Ed25519, and `x` must be UNPADDED base64url
    (jws.unb64url refuses "+", "/" and "=") decoding to exactly 32 bytes. A padded or
    standard-alphabet `x` is rejected rather than repaired — two spellings of one key
    would thumbprint differently, which is the ambiguity the whole proof rests on not
    having. Other key types (P-256, RSA) simply are not this network's identity."""
    try:
        if not isinstance(jwk, dict):
            return None
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return None
        x = jwk.get("x")
        if not isinstance(x, str):
            return None
        public = jws.unb64url(x)
        return public if len(public) == 32 else None
    except Exception:
        return None


def jwk_from_did(did: str) -> Dict[str, str]:
    """did:key -> OKP JWK. Raises ValueError on a non-Ed25519 did:key (mint side).

    Decoded via key_from_did so a P-256 identity is a policy refusal (this
    directory publishes Ed25519 JWKs only), not an Ed25519-only decode failure."""
    curve, pub = crypto.key_from_did(did)
    if curve != "ed25519":
        raise ValueError("not an ed25519 did:key")
    return jwk_from_public(pub)


def did_from_jwk(jwk: Any) -> Optional[str]:
    """OKP JWK -> did:key, or None for anything that is not an Ed25519 JWK.

    The other half of the identity: the same 32 bytes, re-encoded as multicodec
    0xed01 + multibase. This is the line where a Web Bot Auth fact becomes a muretai
    fact. Never raises."""
    public = public_from_jwk(jwk)
    return None if public is None else crypto.did_from_public(public)


def jwk_thumbprint(jwk: Any) -> str:
    """RFC 7638 JWK thumbprint (base64url sha256) — the `keyid` on the wire.

    The hash input is the JSON object of the REQUIRED members only, lexicographic,
    no whitespace: ``{"crv":"Ed25519","kty":"OKP","x":"…"}``. The RFC pins that
    construction precisely so that two implementations naming the same key always
    produce the same string; it is an identifier, never a secret, and never a
    substitute for verifying a signature.

    Raises ValueError on a non-Ed25519 JWK. Verify paths call it only on a JWK that
    already passed public_from_jwk, so on those paths it cannot raise."""
    public = public_from_jwk(jwk)
    if public is None:
        raise ValueError("not an Ed25519 OKP JWK")
    canonical = jwk_from_public(public)
    payload = json.dumps({k: canonical[k] for k in ("crv", "kty", "x")},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    return jws.b64url(hashlib.sha256(payload).digest())


def directory_jwks(did: str) -> Dict[str, List[Dict[str, str]]]:
    """The directory document for one DID: ``{"keys":[<jwk>]}``.

    A list because the format is built for rotation (publish the new key alongside the
    old one for an overlap window). A muretai node has exactly one identity key today,
    so it publishes one entry — but a consumer must handle N, and ours does."""
    return {"keys": [jwk_from_did(did)]}


def directory_body(did: str) -> bytes:
    """The exact bytes to SERVE for `did`. Deterministic (sort_keys + compact
    separators) so the same identity always serves byte-identical content — which
    keeps a cached copy and a fresh fetch comparable, and lets the same signature
    stay valid for the response it was made for."""
    return json.dumps(directory_jwks(did), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- RFC 9421 subset

def _sf_string(s: str) -> str:
    """Serialize a structured-field string: quoted, with `\\` and `"` escaped.

    The only two escapes RFC 8941 defines — there is no \\n, no \\u. A value that
    needs anything else is not representable and must not be smuggled through."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _authority(url: str) -> str:
    """The `@authority` derived component of `url`: lowercased host, plus `:port`
    ONLY when the port is not the scheme's default.

    The default-port rule is the whole point of having this function rather than
    `urlsplit().netloc`: `https://x` and `https://x:443` are the same origin, and a
    signer that spells it one way while the verifier spells it the other produces a
    signature that never validates — the failure mode neturl.origin() exists to
    prevent for relay URLs. Userinfo is dropped (it is not part of the authority a
    signature should cover) and an IPv6 literal keeps its brackets.

    Raises ValueError on a URL with no host: on the SIGN side that is a bug we want
    loud, and the one fetch path that calls it is wrapped in its own try/except."""
    parts = urllib.parse.urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = parts.hostname
    port = parts.port                       # raises ValueError on a malformed port
    if not host:
        raise ValueError("URL has no host: %r" % (url,))
    host = host.lower()
    if ":" in host:                         # IPv6 literal — urlsplit strips brackets
        host = "[%s]" % host
    if port is not None and port != _DEFAULT_PORT.get(scheme):
        return "%s:%d" % (host, port)
    return host


def authority_of(url: str) -> str:
    """PUBLIC name for `_authority` — the `@authority` derived component of `url`.

    Promoted (T107) so the Agent Entry tier and its docs can name the ONE authority
    derivation rather than re-deriving it: an entry verifying inbound Web Bot Auth
    binds `@authority` to its own canonical `base_url` via exactly this rule, never to
    a Host header (a client-settable header is not a fact about where we were
    reached). One definition, same reason `domainbind.valid_domain` is not copied."""
    return _authority(url)


def signature_params(components: Sequence[str], *, created: int, expires: int,
                     keyid: str, tag: str, alg: str = ALG) -> str:
    """The `@signature-params` value: the inner list of covered components plus the
    parameters, in the FIXED order created, expires, keyid, alg, tag.

    That order is wire, not style — see the module docstring. `created`/`expires` are
    INTEGER epoch seconds (`%d`): a float would serialize per-language and stop being
    interoperable, the same trap documented in shared/cardpub.py."""
    inner = " ".join(_sf_string(c) for c in components)
    return ("(%s);created=%d;expires=%d;keyid=%s;alg=%s;tag=%s"
            % (inner, int(created), int(expires),
               _sf_string(keyid), _sf_string(alg), _sf_string(tag)))


def signature_base(components: Sequence[Tuple[str, str]], params: str) -> bytes:
    """The exact bytes covered by the signature (RFC 9421 §2.5).

    One line per covered component — `"<lowercased name>": <value>` — then a final
    `"@signature-params": <params>` line, joined with LF and with NO trailing newline.
    The last line is what binds the signature to its own metadata: without it, an
    attacker could re-present the same signed component values under a different
    keyid/tag/expiry."""
    lines = ['%s: %s' % (_sf_string(str(name).lower()), value)
             for name, value in components]
    lines.append('%s: %s' % (_sf_string("@signature-params"), params))
    return "\n".join(lines).encode("utf-8")


def wba_sign(sign_bytes: Callable[[bytes], str],
             components: Sequence[Tuple[str, str]], *,
             created: int, expires: int, keyid: str, tag: str,
             alg: str = ALG, label: str = "sig1") -> Tuple[str, str]:
    """Sign a component set, returning ``(Signature-Input value, Signature value)``.

    `sign_bytes` is Identity.sign_bytes (bytes -> STANDARD padded base64), never key
    material — so a remote-signer identity works unchanged, exactly as in
    shared/jws.sign_compact and shared/orgbind.make_membership. Its output is already
    precisely RFC 8941 sf-binary content, so it goes between the colons verbatim
    rather than being decoded and re-encoded."""
    params = signature_params([name for name, _ in components], created=created,
                              expires=expires, keyid=keyid, tag=tag, alg=alg)
    base = signature_base(components, params)
    return "%s=%s" % (label, params), "%s=:%s:" % (label, sign_bytes(base))


def request_headers(identity, url: str, *, created: Optional[int] = None,
                    window: int = REQUEST_SIG_WINDOW,
                    signature_agent: Optional[str] = None) -> Dict[str, str]:
    """The three headers that authenticate ONE outbound HTTP request as this agent.

    Covers `@authority` (so the signature cannot be replayed against a different
    origin) and `signature-agent` (so the site is told where to look us up). The
    `signature-agent` value is our DID-addressed HP URL via gateway.did_site_url —
    the stable, location-independent address (see shared/gateway.py); a relay host
    would bake replaceable transport into a signed claim.

    The `signature-agent` COMPONENT value and the emitted `Signature-Agent` HEADER
    value are the same sf-string (quoted) on purpose: RFC 9421 covers a header by its
    field value as sent, so the two must be identical text or nothing verifies."""
    created = int(time.time()) if created is None else int(created)
    agent_url = signature_agent or gateway.did_site_url(identity.did)
    agent_sf = _sf_string(agent_url)
    components = (("@authority", _authority(url)), ("signature-agent", agent_sf))
    keyid = jwk_thumbprint(jwk_from_did(identity.did))
    sig_input, sig = wba_sign(identity.sign_bytes, components, created=created,
                              expires=created + int(window), keyid=keyid,
                              tag=TAG_REQUEST)
    return {"Signature-Input": sig_input, "Signature": sig,
            "Signature-Agent": agent_sf}


def directory_response(identity, authority: str, *,
                       created: Optional[int] = None,
                       window: int = DIR_SIG_WINDOW) -> Tuple[bytes, str, str]:
    """Build our own key directory: ``(body, Signature-Input, Signature)``.

    The response is signed over `@authority` with our own key — the proof of
    possession a fetcher demands (module docstring). `authority` is the host we are
    SERVED as, which is why it is a parameter rather than something this module can
    infer: a node behind a gateway or a CDN is reached under a name it does not
    otherwise know, and signing the wrong one produces a directory nobody can verify.

    `created` defaults to now; pass it when re-signing on a schedule so the refresh
    cadence (DIR_SIG_REFRESH) is the caller's to control."""
    created = int(time.time()) if created is None else int(created)
    body = directory_body(identity.did)
    keyid = jwk_thumbprint(jwk_from_did(identity.did))
    components = (("@authority", str(authority).strip().lower()),)
    sig_input, sig = wba_sign(identity.sign_bytes, components, created=created,
                              expires=created + int(window), keyid=keyid,
                              tag=TAG_DIRECTORY)
    return body, sig_input, sig


# ---------------------------------------------------------------- SF parsing
# A structured-field parser for OUR SUBSET ONLY. Every function below returns None
# rather than raising, and None means "I did not fully understand this" — which the
# callers treat as "no proof". Under-standing is safe; guessing is not.

_SF_KEY_FIRST = frozenset("abcdefghijklmnopqrstuvwxyz*")
_SF_KEY_REST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-.*")
_DIGITS = frozenset("0123456789")


def _skip_ows(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _parse_key(s: str, i: int) -> Optional[Tuple[str, int]]:
    """An RFC 8941 key (a dictionary label or a parameter name)."""
    if i >= len(s) or s[i] not in _SF_KEY_FIRST:
        return None
    j = i + 1
    while j < len(s) and s[j] in _SF_KEY_REST:
        j += 1
    return s[i:j], j


def _parse_sf_string(s: str, i: int) -> Optional[Tuple[str, int]]:
    """A quoted sf-string. Only `\\"` and `\\\\` are escapes; every other character
    must be printable ASCII. Rejecting the rest is what keeps one byte string from
    having two spellings."""
    if i >= len(s) or s[i] != '"':
        return None
    i += 1
    out: List[str] = []
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            i += 1
            if i >= len(s) or s[i] not in ('"', "\\"):
                return None
            out.append(s[i])
            i += 1
        elif ch == '"':
            return "".join(out), i + 1
        elif " " <= ch <= "~":
            out.append(ch)
            i += 1
        else:
            return None
    return None


def _parse_integer(s: str, i: int) -> Optional[Tuple[int, int]]:
    """An sf-integer (optional `-`, up to 15 digits). ASCII digits only — str.isdigit()
    would accept non-ASCII numerals that int() then happily converts."""
    j = i
    if j < len(s) and s[j] == "-":
        j += 1
    k = j
    while k < len(s) and s[k] in _DIGITS:
        k += 1
    if k == j or (k - j) > 15:
        return None
    return int(s[i:k]), k


def _parse_bare_item(s: str, i: int) -> Optional[Tuple[Any, int]]:
    """The only parameter value types in this profile: sf-string and sf-integer."""
    if i < len(s) and s[i] == '"':
        return _parse_sf_string(s, i)
    return _parse_integer(s, i)


def _parse_params(s: str, i: int) -> Optional[Tuple[Dict[str, Any], int]]:
    """`*( ";" *SP key [ "=" bare-item ] )`. A repeated name is REFUSED rather than
    last-wins: two `keyid`s is not a field we want to have an opinion about."""
    params: Dict[str, Any] = {}
    while i < len(s) and s[i] == ";":
        i += 1
        while i < len(s) and s[i] == " ":
            i += 1
        got = _parse_key(s, i)
        if got is None:
            return None
        name, i = got
        if name in params:
            return None
        if i < len(s) and s[i] == "=":
            val = _parse_bare_item(s, i + 1)
            if val is None:
                return None
            params[name], i = val
        else:
            params[name] = True             # a valueless parameter is boolean true
    return params, i


def _parse_inner_list(s: str, i: int) -> Optional[Tuple[List[str], int]]:
    """`"(" *SP [ sf-string *( 1*SP sf-string ) *SP ] ")"` — the covered components.

    Per-item parameters (`"@query";name="q"`) are refused: they change what a
    component MEANS, and a profile that does not implement them must not silently
    ignore them."""
    if i >= len(s) or s[i] != "(":
        return None
    i += 1
    items: List[str] = []
    while True:
        while i < len(s) and s[i] == " ":
            i += 1
        if i >= len(s):
            return None
        if s[i] == ")":
            return items, i + 1
        got = _parse_sf_string(s, i)
        if got is None:
            return None
        item, i = got
        if i < len(s) and s[i] not in " )":
            return None                     # includes ";" — per-item params
        items.append(item)


def _parse_signature_input(value: str) -> Optional[List[Dict[str, Any]]]:
    """Parse a `Signature-Input` value into entries, PRESERVING the raw text.

    `signature_params` holds the exact received characters of each entry's value
    (parens included). That is deliberate: RFC 9421 signs that text, so rebuilding it
    from the parsed structure would only work for peers who serialize exactly as we
    do. Slicing the original keeps parameter order, spacing and escaping intact for
    free."""
    s = value
    n = len(s)
    i = _skip_ows(s, 0)
    if i >= n:
        return None
    entries: List[Dict[str, Any]] = []
    while True:
        got_key = _parse_key(s, i)
        if got_key is None:
            return None
        label, i = got_key
        if i >= n or s[i] != "=":
            return None
        i += 1
        start = i
        got_list = _parse_inner_list(s, i)
        if got_list is None:
            return None
        components, i = got_list
        after_paren = i
        got_params = _parse_params(s, i)
        if got_params is None:
            return None
        params, i = got_params
        entries.append({
            "label": label,
            "components": components,
            "params": params,
            "params_raw": s[after_paren:i],
            "signature_params": s[start:i],
        })
        i = _skip_ows(s, i)
        if i >= n:
            return entries
        if s[i] != ",":
            return None
        i = _skip_ows(s, i + 1)
        if i >= n:
            return None                     # trailing comma


def _parse_signature(value: str) -> Optional[List[Tuple[str, bytes]]]:
    """Parse a `Signature` value: `label=:<standard base64>:` entries."""
    s = value
    n = len(s)
    i = _skip_ows(s, 0)
    if i >= n:
        return None
    out: List[Tuple[str, bytes]] = []
    while True:
        got = _parse_key(s, i)
        if got is None:
            return None
        label, i = got
        if i + 1 >= n or s[i] != "=" or s[i + 1] != ":":
            return None
        i += 2
        end = s.find(":", i)
        if end < 0:
            return None
        try:
            raw = base64.b64decode(s[i:end], validate=True)
        except Exception:
            return None
        i = end + 1
        if i < n and s[i] == ";":
            return None                     # parameters on a signature: out of profile
        out.append((label, raw))
        i = _skip_ows(s, i)
        if i >= n:
            return out
        if s[i] != ",":
            return None
        i = _skip_ows(s, i + 1)
        if i >= n:
            return None


def parse_signature_headers(sig_input: str, sig: str) -> Optional[List[Dict[str, Any]]]:
    """Parse a `(Signature-Input, Signature)` pair into verifiable entries, or None.

    Each entry is ``{"label", "components", "params", "params_raw",
    "signature_params", "sig"}``. `signature_params` is the EXACT received text of the
    `@signature-params` value and is what a verifier must feed to signature_base();
    `params_raw` is the same text from the closing paren onward, kept because a caller
    inspecting only the parameters should not have to re-slice.

    Strict by construction — duplicate labels, a label present in one header but not
    the other, per-item parameters, or an unexpected byte anywhere all return None.
    Every one of those is a case where two implementations could disagree about what
    was signed, and a signature nobody can pin down is not a signature. Never raises."""
    try:
        if not isinstance(sig_input, str) or not isinstance(sig, str):
            return None
        if len(sig_input) > _MAX_HEADER_CHARS or len(sig) > _MAX_HEADER_CHARS:
            return None
        entries = _parse_signature_input(sig_input)
        sigs = _parse_signature(sig)
        if entries is None or sigs is None:
            return None
        labels = [e["label"] for e in entries]
        if len(set(labels)) != len(labels):
            return None
        by_label: Dict[str, bytes] = {}
        for label, raw in sigs:
            if label in by_label:
                return None
            by_label[label] = raw
        if set(by_label) != set(labels):
            return None
        for entry in entries:
            entry["sig"] = by_label[entry["label"]]
        return entries
    except Exception:
        return None


# ---------------------------------------------------------------- verification

def _header(headers: Any, name: str) -> Optional[str]:
    """Case-insensitive header lookup that works for both an email.message.Message
    (what urllib hands back) and a plain dict (what a test or an in-process handler
    passes). HTTP field names are case-insensitive; a dict is not, and a verifier that
    silently missed `signature-input` because the peer lowercased it would fail closed
    for the wrong reason."""
    if headers is None:
        return None
    try:
        value = headers.get(name)
        if value is None:
            lowered = name.lower()
            for key, val in headers.items():
                if isinstance(key, str) and key.lower() == lowered:
                    return val if isinstance(val, str) else None
            return None
        return value if isinstance(value, str) else None
    except Exception:
        return None


def _component_values(components: Sequence[str], *, authority: str,
                      headers: Any) -> Optional[List[Tuple[str, str]]]:
    """Resolve each covered component to the value we will re-sign over, or None.

    `@authority` comes from the caller (the origin we actually asked / were reached
    at) — NEVER from the message, or the binding to the origin would be a claim the
    signer makes about itself. Every other derived component (`@method`, `@path`, …)
    is refused: this profile does not cover them, and pretending to would mean
    verifying a signature over something we did not check. A duplicate component is
    refused for the same reason a duplicate parameter is."""
    out: List[Tuple[str, str]] = []
    seen = set()
    for name in components:
        if not isinstance(name, str) or name != name.lower() or name in seen:
            return None
        seen.add(name)
        if name == "@authority":
            out.append((name, authority))
        elif name.startswith("@"):
            return None
        else:
            value = _header(headers, name)
            if value is None:
                return None
            out.append((name, value.strip()))
    return out


def _entry_verifies(entry: Dict[str, Any], *, keyid: str, tag: str, public: bytes,
                    authority: str, headers: Any, now: int,
                    max_lifetime: int) -> bool:
    """One parsed entry, checked end to end against one key. Order matters only for
    cost: the cheap policy checks run before the Ed25519 verification."""
    params = entry.get("params") or {}
    if params.get("keyid") != keyid or params.get("tag") != tag:
        return False
    alg = params.get("alg")
    if alg is not None and alg != ALG:
        return False
    created, expires = params.get("created"), params.get("expires")
    if not isinstance(created, int) or isinstance(created, bool):
        return False
    if not isinstance(expires, int) or isinstance(expires, bool):
        return False
    if created > now + CLOCK_SKEW or now >= expires:
        return False
    if expires <= created or (expires - created) > max_lifetime:
        return False
    components = entry.get("components") or []
    # Without @authority the signature says nothing about WHERE it was served, so the
    # same bytes would prove the same thing on every domain — i.e. prove nothing.
    if "@authority" not in components:
        return False
    pairs = _component_values(components, authority=authority, headers=headers)
    if pairs is None:
        return False
    base = signature_base(pairs, entry["signature_params"])
    return crypto.verify_raw(public, entry.get("sig") or b"", base)


def verify_directory_response(authority: str, headers: Any, body: bytes, *,
                              now: Optional[float] = None) -> List[str]:
    """The DIDs a key directory PROVES are operated by `authority`. Never raises.

    Every one of these must hold, or the key is skipped:
      * the body is within MAX_DIRECTORY_BYTES and parses to ``{"keys":[…]}``;
      * `Content-Type` is the directory media type (an HTML error page is not a
        directory, however well-formed the rest of the response looks);
      * the key is an Ed25519 OKP JWK;
      * SOME signature entry names that key's own RFC 7638 thumbprint as `keyid`,
        carries `tag=http-message-signatures-directory`, omits `alg` or says
        `ed25519`, is inside its validity window (with CLOCK_SKEW on `created` only)
        and lives no longer than DEPOSIT_SIG_WINDOW;
      * that entry's signature base — rebuilt from the components and the RECEIVED
        params text, with `@authority` bound to the host we asked — verifies under
        THAT key.

    The last two lines are the security of the whole feature: a public JWK is
    copyable, a signature over `@authority` is not. A key with no valid signature over
    it is dropped silently, so a directory mixing one honest key with ten stolen ones
    yields exactly one DID.

    Returns [] for "nothing proven" — which is also what every error returns, because
    to a caller they are the same fact."""
    try:
        if not isinstance(body, (bytes, bytearray)):
            return []
        if len(body) > MAX_DIRECTORY_BYTES:
            return []
        ctype = _header(headers, "Content-Type") or ""
        if not ctype.strip().lower().startswith(WBA_DIRECTORY_CONTENT_TYPE):
            return []
        authority = (authority or "").strip().lower()
        if not authority:
            return []
        document = json.loads(bytes(body).decode("utf-8"))
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            return []
        entries = parse_signature_headers(_header(headers, "Signature-Input") or "",
                                          _header(headers, "Signature") or "")
        if not entries:
            return []
        moment = int(time.time() if now is None else now)
        proven: List[str] = []
        for jwk in keys:
            public = public_from_jwk(jwk)
            if public is None:
                continue
            canonical = jwk_from_public(public)
            keyid = jwk_thumbprint(canonical)
            if not any(_entry_verifies(e, keyid=keyid, tag=TAG_DIRECTORY,
                                       public=public, authority=authority,
                                       headers=headers, now=moment,
                                       max_lifetime=DEPOSIT_SIG_WINDOW)
                       for e in entries):
                continue                    # copied key, no proof of possession
            did = crypto.did_from_public(public)
            if did not in proven:
                proven.append(did)
        return proven
    except Exception:
        return []


def verify_request(headers: Any, *, authority: str, jwks: Any,
                   now: Optional[float] = None) -> Optional[str]:
    """The DID that signed this inbound request, or None. Never raises.

    `jwks` is a directory document (``{"keys":[…]}``) already established as the
    peer's — normally one whose proof-of-possession verify_directory_response has
    checked. This function only answers "did the holder of one of THOSE keys sign
    THIS request, for this authority, as a web-bot-auth request?"; who the keys
    belong to was decided before it was called.

    The lifetime cap is tight (_MAX_REQUEST_LIFETIME) because these headers are a
    bearer credential while they live: anything that captures them — a proxy log, an
    error report — can replay them until they expire."""
    try:
        entries = parse_signature_headers(_header(headers, "Signature-Input") or "",
                                          _header(headers, "Signature") or "")
        if not entries:
            return None
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list):
            return None
        authority = (authority or "").strip().lower()
        if not authority:
            return None
        moment = int(time.time() if now is None else now)
        for jwk in keys:
            public = public_from_jwk(jwk)
            if public is None:
                continue
            keyid = jwk_thumbprint(jwk_from_public(public))
            for entry in entries:
                if _entry_verifies(entry, keyid=keyid, tag=TAG_REQUEST,
                                   public=public, authority=authority,
                                   headers=headers, now=moment,
                                   max_lifetime=_MAX_REQUEST_LIFETIME):
                    return crypto.did_from_public(public)
        return None
    except Exception:
        return None


# ---------------------------------------------------------------- fetch

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect instead of following it.

    Deliberately NOT neturl._GuardedRedirect: that one re-runs the SSRF guard and then
    follows, which is right for a peer endpoint but wrong here. The well-known
    directory is origin-bound — the question is what THIS origin publishes at THIS
    path, and a redirect answers about somewhere else. See the module docstring."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "web bot auth directory must not redirect (origin-bound resource)",
            headers, fp)


_directory_opener: Optional[urllib.request.OpenerDirector] = None


def _opener() -> urllib.request.OpenerDirector:
    """The module's own opener, built lazily and cached (mirrors neturl.opener())."""
    global _directory_opener
    if _directory_opener is None:
        _directory_opener = urllib.request.build_opener(_NoRedirect())
    return _directory_opener


def verify_wba_directory(domain: str, *, now: Optional[float] = None,
                         timeout: float = 10.0) -> List[Tuple[str, str]]:
    """Fetch `domain`'s key directory and return the ``(authority, did)`` pairs it
    PROVES. Never raises; ``[]`` means "no proof", which is also what every failure
    means — unreachable, redirecting, wrong media type, unsigned, or forged.

    `domain` is a bare authority (`example.com`, `example.com:8443`). A scheme may be
    prefixed and must be https; `http://` is accepted only when
    ``MURETAI_WBA_ALLOW_HTTP=1``, which exists so a loopback test can run without a
    certificate and must never be set in production — plaintext would let anyone on
    the path strip the directory (and a signature they cannot forge is small comfort
    if the response never arrives). A path is refused outright: the resource is at a
    fixed well-known location or it is not this resource.

    The returned first element is the AUTHORITY the proof is bound to (lowercased
    host, with a non-default port) — the same string the signature covers — not
    necessarily the exact text passed in."""
    try:
        from shared import httputil, httpua, neturl
    except Exception:
        return []
    try:
        if not isinstance(domain, str) or not domain.strip():
            return []
        raw = domain.strip().rstrip("/")
        if "://" in raw:
            scheme, _, rest = raw.partition("://")
            scheme = scheme.lower()
            if scheme not in ("http", "https"):
                return []
            if scheme == "http" and os.environ.get("MURETAI_WBA_ALLOW_HTTP") != "1":
                return []
        else:
            scheme, rest = "https", raw
        if not rest or "/" in rest or "?" in rest or "#" in rest:
            return []
        url = "%s://%s%s" % (scheme, rest, WBA_DIRECTORY_PATH)
        authority = _authority(url)
        # PUBLIC ADDRESSES ONLY — neturl.host_public, never the LAN-tolerant
        # host_dialable the message transport uses. This function is an EVIDENCE
        # fetch: `domain` reaches it from a stranger's Agent Card, so the request is
        # attacker-directed by construction, and host_dialable deliberately permits
        # loopback / RFC1918 / ULA because those are legitimate places to find a PEER.
        # Gating evidence on it would make this half of the verifier an internal
        # request generator while its twin (agent/domainverify.fetch_did_configuration)
        # is locked down — the two proof sources take the SAME attacker-supplied domain
        # and must therefore hold the SAME line. The insecure-fetch escape below is
        # test-only and mirrors the DIF source's, so loopback stubs stay reachable.
        if os.environ.get("MURETAI_WBA_ALLOW_HTTP") == "1":
            if not neturl.host_dialable(url):
                return []
        elif not neturl.host_public(url):
            return []
        request = urllib.request.Request(url, method="GET", headers={
            "User-Agent": httpua.USER_AGENT,
            "Accept": WBA_DIRECTORY_CONTENT_TYPE,
        })
        with _opener().open(request, timeout=timeout) as response:
            # `budget_s`: a WALL-CLOCK ceiling on the body, because `timeout=` is a PER-RECV
            # socket timeout and not a deadline. This URL is built from a domain a STRANGER
            # named (it reaches here through PROOF_SOURCES -> _probe_wba_directory from an
            # Agent Card), so the request is attacker-directed by construction: an origin
            # that answers its headers instantly and then dribbles one byte every
            # `timeout - eps` seconds resets that clock forever, and the read ends only at
            # MAX_DIRECTORY_BYTES — ~65537 x 10 s, i.e. DAYS for one fetch, on a call an
            # operator made with `./muretai domain verify`. This is the THIRD fetch on that
            # verification path; the two in agent/domainverify.py were given a budget and
            # this one was missed, which is the ordinary shape of this bug — a fix that
            # reaches one site and not its siblings.
            body = httputil.read_response(response, MAX_DIRECTORY_BYTES,
                                          budget_s=httputil.read_budget(timeout))
            headers = response.headers
        pairs: List[Tuple[str, str]] = []
        for did in verify_directory_response(authority, headers, body, now=now):
            pair = (authority, did)
            if pair not in pairs:
                pairs.append(pair)
        return pairs
    except Exception:
        return []


# ---------------------------------------------------------------- self-test

def _selftest() -> None:
    """Pin the wire. Run with ``python3 -m shared.webbotauth`` from the repo root.

    The worked example below is a FIXED VECTOR: a seed of bytes(range(32)) and two
    fixed timestamps produce exactly these three lines. If a change to this file makes
    that assertion fail, the change broke interoperability with every peer already
    speaking this profile — the vector is the contract, not the code."""
    import http.server
    import threading

    class _Ident:
        """The minimal Identity surface this module uses: `did` and `sign_bytes`."""

        def __init__(self, seed: bytes) -> None:
            self._seed = seed
            self.public = crypto.ed25519_public_from_seed(seed)
            self.did = crypto.did_from_public(self.public)

        def sign_bytes(self, message: bytes) -> str:
            return base64.b64encode(crypto.ed25519_sign(self._seed, message)).decode()

    seed = bytes(range(32))
    me = _Ident(seed)
    assert me.did == "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd", me.did

    # 1. JWK <-> DID roundtrip.
    jwk = jwk_from_did(me.did)
    assert jwk == {"crv": "Ed25519", "kty": "OKP",
                   "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}, jwk
    assert did_from_jwk(jwk) == me.did
    assert public_from_jwk(jwk) == me.public
    assert public_from_jwk({"kty": "EC", "crv": "P-256", "x": "aa"}) is None
    assert public_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": "AA"}) is None
    assert public_from_jwk("nope") is None
    print("ok  jwk <-> did roundtrip")

    # 2. RFC 7638 thumbprint.
    keyid = jwk_thumbprint(jwk)
    assert keyid == "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y", keyid
    print("ok  jwk thumbprint")

    # 3. The worked example, byte for byte.
    created, expires = 1754870400, 1754870700
    agent_sf = _sf_string(
        "https://muretai.net/z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd")
    components = (("@authority", "example.com"), ("signature-agent", agent_sf))
    params = signature_params([n for n, _ in components], created=created,
                              expires=expires, keyid=keyid, tag=TAG_REQUEST)
    base = signature_base(components, params)
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
    print("ok  signature base matches the pinned vector")

    # _authority: default ports dropped, non-default kept, host lowercased.
    assert _authority("https://Example.COM/x") == "example.com"
    assert _authority("https://example.com:443/x") == "example.com"
    assert _authority("http://example.com:80/x") == "example.com"
    assert _authority("https://example.com:8443/x") == "example.com:8443"
    assert _authority("http://[::1]:9000/x") == "[::1]:9000"
    print("ok  @authority canonicalization")

    # 4. Request sign -> verify roundtrip, plus the negatives.
    os.environ["MURETAI_PUBLIC_BASE"] = "https://muretai.net"
    headers = request_headers(me, "https://shop.example/rpc", created=created)
    directory = directory_jwks(me.did)
    assert verify_request(headers, authority="shop.example", jwks=directory,
                          now=created + 10) == me.did
    assert verify_request(headers, authority="other.example", jwks=directory,
                          now=created + 10) is None          # bound to the authority
    assert verify_request(headers, authority="shop.example", jwks=directory,
                          now=expires + 1) is None            # expired
    assert verify_request(headers, authority="shop.example",
                          jwks=directory_jwks(_Ident(bytes(range(32, 64))).did),
                          now=created + 10) is None           # someone else's key
    tampered = dict(headers)
    tampered["Signature-Agent"] = _sf_string("https://evil.example/z6MkOther")
    assert verify_request(tampered, authority="shop.example", jwks=directory,
                          now=created + 10) is None           # covered header changed
    lowercased = {k.lower(): v for k, v in headers.items()}
    assert verify_request(lowercased, authority="shop.example", jwks=directory,
                          now=created + 10) == me.did         # header case-insensitive
    print("ok  request sign -> verify_request roundtrip")

    # parse_signature_headers keeps the received text and rejects what it cannot pin.
    parsed = parse_signature_headers(headers["Signature-Input"], headers["Signature"])
    assert parsed and len(parsed) == 1
    entry = parsed[0]
    assert entry["label"] == "sig1"
    assert entry["components"] == ["@authority", "signature-agent"]
    assert entry["params"]["keyid"] == keyid and entry["params"]["tag"] == TAG_REQUEST
    assert entry["params"]["created"] == created
    assert entry["signature_params"] == headers["Signature-Input"].split("=", 1)[1]
    assert entry["params_raw"].startswith(";created=")
    assert len(entry["sig"]) == 64
    assert parse_signature_headers("sig1=()", "sig1=:AAAA:") is not None
    assert parse_signature_headers("sig1=(\"@authority\")", "sig2=:AAAA:") is None
    assert parse_signature_headers("sig1=(\"@authority\";x=1)", "sig1=:AAAA:") is None
    assert parse_signature_headers("sig1=(\"@authority\"", "sig1=:AAAA:") is None
    assert parse_signature_headers("sig1=(\"@authority\")", "sig1=:AAAA") is None
    assert parse_signature_headers("sig1=(\"a\"),sig1=(\"b\")",
                                   "sig1=:AAAA:,sig1=:AAAA:") is None
    print("ok  structured-field parser (strict)")

    # 5. Directory build -> verify roundtrip.
    body, sig_input, sig = directory_response(me, "muretai.net", created=created)
    assert body == directory_body(me.did)
    served = {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE + "; charset=utf-8",
              "Signature-Input": sig_input, "Signature": sig}
    assert verify_directory_response("muretai.net", served, body,
                                     now=created + 60) == [me.did]
    assert verify_directory_response("evil.example", served, body,
                                     now=created + 60) == []   # other origin
    assert verify_directory_response("muretai.net", served, body,
                                     now=created + DIR_SIG_WINDOW + 1) == []
    assert verify_directory_response(
        "muretai.net", {"Content-Type": "text/html",
                        "Signature-Input": sig_input, "Signature": sig},
        body, now=created + 60) == []                          # wrong media type
    assert verify_directory_response(
        "muretai.net", {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE}, body,
        now=created + 60) == []                                # unsigned
    assert verify_directory_response("muretai.net", served, b"x" * (
        MAX_DIRECTORY_BYTES + 1), now=created + 60) == []      # oversized
    print("ok  directory build -> verify roundtrip")

    # 6. THE attack: a copied public JWK, signed by whoever copied it.
    thief = _Ident(bytes(range(64, 96)))
    stolen = {"keys": [jwk_from_did(me.did)]}
    stolen_body = json.dumps(stolen, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    t_input, t_sig = wba_sign(
        thief.sign_bytes, (("@authority", "evil.example"),), created=created,
        expires=created + DIR_SIG_WINDOW,
        keyid=jwk_thumbprint(jwk_from_did(thief.did)), tag=TAG_DIRECTORY)
    stolen_headers = {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE,
                      "Signature-Input": t_input, "Signature": t_sig}
    assert verify_directory_response("evil.example", stolen_headers, stolen_body,
                                     now=created + 60) == []
    # …and unsigned entirely, and with our own signature lifted from our own origin.
    assert verify_directory_response(
        "evil.example", {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE},
        stolen_body, now=created + 60) == []
    assert verify_directory_response(
        "evil.example", {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE,
                         "Signature-Input": sig_input, "Signature": sig},
        stolen_body, now=created + 60) == []
    # The thief's OWN key on the thief's OWN domain still works — the rule is
    # proof-of-possession, not a blocklist.
    t_body, t_in2, t_sig2 = directory_response(thief, "evil.example", created=created)
    assert verify_directory_response(
        "evil.example", {"Content-Type": WBA_DIRECTORY_CONTENT_TYPE,
                         "Signature-Input": t_in2, "Signature": t_sig2},
        t_body, now=created + 60) == [thief.did]
    print("ok  a copied JWK proves nothing (proof-of-possession holds)")

    # 7. The live fetch path over loopback, including the redirect refusal.
    class _Quiet(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):                        # keep the test quiet
            return

    class _Handler(_Quiet):
        def do_GET(self):                                    # noqa: N802 (stdlib API)
            if self.path != WBA_DIRECTORY_PATH:
                self.send_error(404)
                return
            live_body, live_in, live_sig = directory_response(
                me, "127.0.0.1:%d" % self.server.server_address[1])
            self.send_response(200)
            self.send_header("Content-Type", WBA_DIRECTORY_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(live_body)))
            self.send_header("Signature-Input", live_in)
            self.send_header("Signature", live_sig)
            self.end_headers()
            self.wfile.write(live_body)

    class _Redirector(_Quiet):
        """An origin that answers the well-known path with a 302 at the honest
        origin's directory. Following it would mint a proof about the WRONG host."""

        def do_GET(self):                                    # noqa: N802 (stdlib API)
            self.send_response(302)
            self.send_header("Location", _Redirector.target)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = "127.0.0.1:%d" % server.server_address[1]
    _Redirector.target = "http://%s%s" % (host, WBA_DIRECTORY_PATH)
    hop = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=hop.serve_forever, daemon=True).start()
    hop_host = "127.0.0.1:%d" % hop.server_address[1]
    try:
        os.environ.pop("MURETAI_WBA_ALLOW_HTTP", None)
        assert verify_wba_directory("http://" + host) == []   # plaintext refused
        os.environ["MURETAI_WBA_ALLOW_HTTP"] = "1"
        assert verify_wba_directory("http://" + host) == [(host, me.did)]
        assert verify_wba_directory("http://" + hop_host) == []      # 302 refused
        assert verify_wba_directory("ftp://" + host) == []
        assert verify_wba_directory("http://" + host + "/path") == []
    finally:
        os.environ.pop("MURETAI_WBA_ALLOW_HTTP", None)
        for srv in (server, hop):
            srv.shutdown()
            srv.server_close()
    print("ok  verify_wba_directory over loopback (redirects refused)")

    print("all webbotauth self-tests passed")


if __name__ == "__main__":
    _selftest()
