"""
shared/domainbind.py
The DIF "Well-Known DID Configuration" Domain Linkage Credential, for did:key —
the DOMAIN → DID half of "this agent really is example.com".

Why DIF's format and not a muretai one:
  Every other signed artifact in this repo is ours end to end (introductions,
  org bindings, contact grants, card envelopes: crypto.canonical + base64). We
  could have minted a fifth. We deliberately did not. This attestation's whole
  value is that software we do NOT control believes it — a wallet, an
  Entra/Veramo/Credo verifier, a browser extension, some registry crawling
  /.well-known. Those already implement DIF's Well-Known DID Configuration
  (a JSON doc at a fixed path holding compact-JWS Domain Linkage Credentials),
  so conforming means a stranger's verifier accepts our domain proof with zero
  muretai-specific code, and our verifier accepts THEIR domain proof with zero
  vendor-specific code. Inventing a format here would have bought nothing and
  cost every future integration a bespoke parser. It is the same reasoning that
  put shared/jws.py in the tree: a narrow, deliberate concession to an outside
  format, not a new house style.

  What we do NOT concede is verification laxity. DIF's spec is a document
  format; the checks below are ours, and they are stricter than the spec's
  minimum (see the anti-substitution and origin rules).

Why `exp` is MANDATORY here even though DIF tolerates its absence:
  A domain is LEASED, not owned. Registrations lapse, subdomains get handed to a
  new team, a company sells a hostname. A permanent attestation outlives the
  lease, and the day someone else controls example.com our old credential is
  still a perfectly valid signature saying "this DID is example.com" — indefinite
  authority over a name we no longer hold, with no revocation channel that a
  third-party verifier is obliged to consult. Bounding every credential turns a
  permanent liability into a window: re-mint while you hold the name, and the
  claim dies on its own when you stop. So a credential with no `exp` is refused
  outright rather than treated as "valid forever".

Why iss == sub == vc.credentialSubject.id is enforced:
  A Domain Linkage Credential is a SELF-issued statement: the DID says something
  about itself, and the signature is checked against that DID's own key. If the
  three identifiers were allowed to differ, a credential legitimately issued by
  and about DID A could be re-presented as though it were about DID B — either by
  leaving `sub` pointing at A while the subject block names B, or the reverse —
  and a verifier that reads only one of the three fields would bind the domain to
  the wrong agent. Requiring all three to be the identical string means there is
  exactly one identifier in the document and no place to hide a second one.

Why origins are compared through neturl.origin:
  A host has many spellings that a byte comparison treats as different and DNS
  treats as the same: `https://EXAMPLE.com`, `https://example.com.`,
  `https://example.com:443`, `https://example.com/`, `https://u@example.com`.
  neturl.origin() collapses all of them to one canonical `scheme://host[:port]`,
  and we canonicalize BOTH sides — the credential's claimed origin and the origin
  we expect for the domain being checked — before comparing. One spelling per
  host means a credential minted for a look-alike spelling cannot slip past a
  caller that asked about the plain one.

DIRECTION — read this before trusting anything this module returns:
  It proves ONE edge only: the holder of `did` asserts it speaks for `domain`.
  That is not the same as the domain vouching for the DID; on its own it is a
  self-signed claim that anyone can mint about any domain. The proof only becomes
  meaningful once the document is actually FETCHED from that domain's
  /.well-known/did-configuration.json (the domain's server serving it is the
  domain's half of the statement) AND the DID's own Agent Card names the domain
  back. That reverse edge, the fetch, and the caching all live in
  agent/domainverify.py — this module is pure: no network, no filesystem, no
  clock beyond an injectable `now`, so it can be reasoned about and tested in
  isolation.

Pure standard library (+ shared/jws, shared/neturl).
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import time
from typing import Any, Callable

from shared import jws, neturl

#: Where a conforming document is served (RFC 8615 well-known URI). Fetching it is
#: agent/domainverify.py's job; this constant lives here so both sides name one path.
WELL_KNOWN_PATH = "/.well-known/did-configuration.json"

#: The two JSON-LD contexts a Domain Linkage Credential carries. Both are required
#: on the wire (and both are checked on the way in) because a DIF verifier keys its
#: schema off them — dropping one produces a document other stacks silently reject.
CONTEXT_VC = "https://www.w3.org/2018/credentials/v1"
CONTEXT_WELL_KNOWN = "https://identity.foundation/.well-known/did-configuration/v1"

TYPE_VC = "VerifiableCredential"
TYPE_DLC = "DomainLinkageCredential"

#: Hard cap on credentials READ from one fetched document. A domain hosts one
#: credential per agent that speaks for it, so this is the size of the largest fleet
#: a single domain can cover — and covering the fleet in ONE file the domain owner
#: edits is what makes per-agent revocation possible without any intermediate that
#: signs on the domain's behalf. 64 is bounded by the 64 KiB body cap anyway: a
#: credential is ~1.1 KB, so no more than ~60 fit.
#:
#: Raising it from the original 8 is only safe because verification is no longer
#: linear in the list — see `linked_dids`. The cost that mattered was measured, not
#: assumed: an Ed25519 verify is 0.14 ms with the `cryptography` backend but 191 ms
#: on the pure-Python one that ships by default, so verifying a whole hostile list
#: would have been an eleven-second stall for the price of one HTTP response.
MAX_LINKED_DIDS = 64

#: How many credentials claiming the SAME issuer we will actually verify for one
#: query. An honest document holds exactly one credential per DID; repeating an
#: issuer is only useful to a hostile document trying to defeat the O(1) filter in
#: `linked_dids` and force repeated signature verification. Two, not one, so a
#: duplicated or superseded entry left in a file does not silently break an honest
#: domain.
MAX_VERIFY_PER_QUERY = 2

#: RFC 1035 total length of a domain name. Applied to the host part only — an
#: optional ":<port>" is a dialling detail, not part of the name.
MAX_DOMAIN_LEN = 253

_DID_KEY_PREFIX = "did:key:"

#: The ONLY timestamp spelling allowed inside `vc`. W3C VC dates are ISO 8601; we
#: pin the exact strftime pattern so two minters never disagree by a fraction or a
#: numeric offset. Note the split of responsibilities in the payload: the JWT-level
#: `nbf`/`exp` are INTEGER epoch seconds (the values verifiers actually compare —
#: integers because a float in a signed payload is not reproducible outside Python,
#: see the warning in shared/cardpub.py), while these ISO strings are the
#: human/JSON-LD-facing echo of the same instants.
_ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"

#: Cheap upper bound on the raw input before any per-character work: the longest
#: legal name plus the longest legal ":<port>".
_MAX_INPUT_LEN = MAX_DOMAIN_LEN + len(":65535")

_LDH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

# Characters that betray a URL, an authority, or whitespace smuggling where a bare
# domain was expected. Checked explicitly (rather than left to the LDH label test)
# so that `https://example.com/x` is refused as "not a domain" instead of being
# mistaken for a weird label.
_NOT_IN_DOMAIN = ("/", "?", "#", "@", "\\", " ", "\t", "\r", "\n", "%", "[", "]")


def valid_domain(domain: str) -> bool:
    """True if `domain` is a bare, canonical LDH host with an optional ":<port>".

    Strict on purpose — this string is what an origin gets built from, and every
    laxity here is an origin two parties can spell differently:

      - ASCII LDH only, LOWERCASE: a-z, 0-9, '-'. Uppercase is rejected rather
        than folded, so `valid_domain` answers "is this the canonical spelling",
        and the one place case-folding is appropriate does it explicitly
        (`origin_for`).
      - Labels are 1..63 chars and may not start or end with '-'.
      - At least two labels: a single-label name ("localhost", "com") has no
        owner a verifier could hold responsible. Loopback testing uses the IPv4
        literal form (`127.0.0.1:8443`), which passes as four numeric labels.
      - Total host length <= MAX_DOMAIN_LEN, no trailing dot (the root dot is
        DNS-equal but byte-different, so we accept exactly one spelling).
      - No scheme, path, query, fragment, or userinfo — a bare host, nothing else.
      - An optional ":<port>", 1..65535, no leading zero. Ports exist here only
        because loopback test servers and staging boxes cannot use 443; a public
        deployment should have none.

    Non-ASCII is refused rather than IDNA-encoded: `.encode("idna")` differs
    between Python versions and disagrees with browsers on several scripts, and a
    silent transformation would mean the domain a caller typed and the domain we
    attested are not obviously the same string. Callers surface a "convert it to
    punycode yourself" hint instead. Never raises."""
    if not isinstance(domain, str) or not domain or len(domain) > _MAX_INPUT_LEN:
        return False
    if any(ch in domain for ch in _NOT_IN_DOMAIN):
        return False
    try:
        domain.encode("ascii")                 # IDN U-labels stop here
    except UnicodeEncodeError:
        return False
    host = domain
    if ":" in domain:
        host, _, port = domain.partition(":")
        # A second ':' (an unbracketed IPv6 literal) leaves a non-numeric tail and
        # is refused right here, which is why no bracket handling is needed.
        if not port.isdigit() or (len(port) > 1 and port.startswith("0")):
            return False
        if not 1 <= int(port) <= 65535:
            return False
    if not host or len(host) > MAX_DOMAIN_LEN or host.endswith("."):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not set(label) <= _LDH:
            return False
    return True


def origin_for(domain: str) -> str:
    """The https origin a Domain Linkage Credential binds to: "https://" + domain.

    Case is DNS-insignificant, so the input is lowercased BEFORE validation — that
    is the one canonicalization a caller is allowed to skip doing itself. Everything
    else must already be canonical (`valid_domain` decides), and an invalid domain
    raises ValueError instead of returning something unusable: this is the mint-side
    path, where failing loudly is right. https only — a domain proof carried over
    plaintext http proves nothing about the domain."""
    lowered = domain.strip().lower() if isinstance(domain, str) else ""
    if not valid_domain(lowered):
        raise ValueError(
            "not a bare LDH domain (ASCII a-z0-9-, >=2 labels, optional :port); "
            "convert an internationalized name to punycode first")
    return "https://" + lowered


def _iso(epoch: int) -> str:
    """UTC ISO 8601 with a literal Z, from an integer epoch second."""
    return time.strftime(_ISO_FMT, time.gmtime(epoch))


def _epoch(value: Any, field: str) -> int:
    """An integer epoch second, or ValueError.

    `bool` is rejected before `int` because `True` IS an int in Python and would
    canonicalize to `1` — a 1970 timestamp born from a type confusion. Floats are
    rejected for the interop reason in the module constants: a signed payload
    carrying a float is not reproducible by a non-Python verifier."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer epoch second")
    return value


def make_domain_linkage_jwt(did: str, domain: str, *,
                            sign_bytes: Callable[[bytes], str],
                            now: int, expires_at: int) -> str:
    """Mint the compact-JWS Domain Linkage Credential for (did, domain).

    `sign_bytes` is Identity.sign_bytes (bytes -> STANDARD base64 str), never key
    material, so a remote-signer identity with no local seed mints these unchanged.

    Refuses to mint what our own verifier would refuse: a non-did:key issuer (this
    is the self-certifying case — the verifier reads the key out of `iss`, so any
    DID method needing resolution is a different feature), an invalid domain, and
    an `expires_at` at or before `now` (a credential that is dead on arrival is a
    bug at the call site, not something to publish and let verifiers discover)."""
    if not isinstance(did, str) or not did.startswith(_DID_KEY_PREFIX):
        raise ValueError("domain linkage is minted for did:key issuers only")
    now = _epoch(now, "now")
    expires_at = _epoch(expires_at, "expires_at")
    if expires_at <= now:
        raise ValueError("expires_at must be strictly after now")
    origin = origin_for(domain)                # raises on an invalid domain
    payload = {
        "exp": expires_at,
        "iss": did,
        "nbf": now,
        "sub": did,
        "vc": {
            "@context": [CONTEXT_VC, CONTEXT_WELL_KNOWN],
            "credentialSubject": {"id": did, "origin": origin},
            "expirationDate": _iso(expires_at),
            "issuanceDate": _iso(now),
            "issuer": did,
            "type": [TYPE_VC, TYPE_DLC],
        },
    }
    return jws.sign_compact(payload, did=did, sign_bytes=sign_bytes)


def make_did_configuration(jwts: list) -> dict:
    """Wrap credentials into the document served at WELL_KNOWN_PATH.

    Raises ValueError on a non-list, a non-string entry, or more than
    MAX_LINKED_DIDS entries — publishing a document whose tail our own reader caps
    away would be a silent, one-sided failure: the operator sees eight DIDs in the
    file and a verifier sees fewer, with nothing anywhere saying why."""
    if not isinstance(jwts, list):
        raise ValueError("linked_dids must be a list of compact JWS strings")
    if len(jwts) > MAX_LINKED_DIDS:
        raise ValueError(f"at most {MAX_LINKED_DIDS} linked DIDs per domain")
    for token in jwts:
        if not isinstance(token, str) or not token:
            raise ValueError("every linked DID entry must be a compact JWS string")
    return {"@context": CONTEXT_WELL_KNOWN, "linked_dids": list(jwts)}


def verify_domain_linkage_jwt(token: str, *, domain: str,
                              now: float | None = None,
                              expected_did: str | None = None) -> dict | None:
    """{"did", "origin", "nbf", "exp"} iff the credential really binds `domain`, else None.

    Every one of these must hold; any failure, and any malformed input at all,
    returns None. It NEVER raises — a caller treats None as "no proof", the same
    posture as jws.verify_compact / orgbind.verify_membership:

      1. It parses as a compact JWS and `iss` is a did:key string. `iss` is read
         UNVERIFIED here for the one legitimate reason: it names the key to check.
      2. jws.verify_compact(token, iss) passes — the DID's OWN key signed these
         exact bytes, and the header said `alg: EdDSA` (alg is policy, never the
         token's choice; that is what stops the alg:"none" family).
      3. iss == sub == vc.credentialSubject.id, all three the identical string.
         See the module docstring: this is the anti-substitution rule.
      4. `vc` is an object; TYPE_DLC is in its `type` LIST and both contexts are in
         its `@context` LIST. Both are required to be lists rather than accepted as
         bare strings, because `"DomainLinkageCredential" in "DomainLinkageCredentialX"`
         is True — a string would turn a membership test into a substring test.
      5. The claimed origin and the origin expected for `domain` are equal AFTER
         neturl.origin() canonicalizes both.
      6. `nbf` and `exp` are true ints (bools rejected — see _epoch) and
         nbf <= now <= exp. `exp` missing is a refusal, not "valid forever".

    `now` defaults to time.time(); pass it to test or to evaluate a document as of
    a fetch time. `expected_did`, when given, pins the issuer, so a document that
    legitimately links several DIDs cannot answer a question about one of them with
    a credential about another.

    Returns the CANONICAL origin, not the string as written in the credential:
    downstream code (an Agent Card cross-check, a cache key) must compare one
    spelling, and handing back the attacker-chosen spelling would re-open exactly
    the hole rule 5 closes."""
    try:
        parsed = jws.decode_unverified(token)
        if parsed is None:
            return None
        iss = parsed[1].get("iss")
        if not isinstance(iss, str) or not iss.startswith(_DID_KEY_PREFIX):
            return None
        if expected_did is not None and iss != expected_did:
            return None
        payload = jws.verify_compact(token, iss)
        if payload is None:
            return None
        # Past this line every value came out of the SIGNED bytes.
        if payload.get("sub") != iss:
            return None
        vc = payload.get("vc")
        if not isinstance(vc, dict):
            return None
        types = vc.get("type")
        if not isinstance(types, list) or TYPE_DLC not in types:
            return None
        contexts = vc.get("@context")
        if not isinstance(contexts, list):
            return None
        if CONTEXT_VC not in contexts or CONTEXT_WELL_KNOWN not in contexts:
            return None
        subject = vc.get("credentialSubject")
        if not isinstance(subject, dict) or subject.get("id") != iss:
            return None
        expected_origin = neturl.origin(origin_for(domain))
        claimed_origin = neturl.origin(subject.get("origin"))
        if not expected_origin or claimed_origin != expected_origin:
            return None
        nbf, exp = payload.get("nbf"), payload.get("exp")
        if isinstance(nbf, bool) or not isinstance(nbf, int):
            return None
        if isinstance(exp, bool) or not isinstance(exp, int):
            return None
        moment = time.time() if now is None else now
        if not nbf <= moment <= exp:
            return None
        return {"did": iss, "origin": claimed_origin, "nbf": nbf, "exp": exp}
    except Exception:
        return None


def linked_dids(doc: Any, *, domain: str, now: float | None = None,
                for_did: str | None = None) -> list:
    """Every credential in an UNTRUSTED fetched document that verifies for `domain`.

    `doc` is whatever came back from the domain's WELL_KNOWN_PATH — assume it is
    hostile. Non-dict, missing/non-list `linked_dids`, non-string entries and
    credentials that fail any check are dropped silently; at most MAX_LINKED_DIDS
    entries are examined. Returns [] rather than raising on anything malformed.

    Silent on purpose: this runs on remote input, so logging per-entry rejections
    would let a stranger write into our logs at will. A caller that needs to know
    whether a specific DID was linked asks for it directly
    (verify_domain_linkage_jwt with `expected_did`) instead of diffing this list.

    WHY `for_did` EXISTS, AND WHY IT IS THE ONLY WAY THE LIST MAY BE LARGE.
    A signature verification is the expensive operation in this file: measured at
    0.14 ms with the `cryptography` backend but **191 ms** on the pure-Python one,
    which is the zero-dependency default. Verifying every entry therefore hands a
    hostile domain a linear amplifier — 60 entries (all the 64 KiB body cap allows)
    would pin a pure-Python verifier for eleven seconds, and the document is written
    entirely by the party under suspicion.

    So when the caller already knows WHICH DID it is asking about — which is every
    real caller, because a verdict is always about one pair — we first parse each
    entry WITHOUT verifying (base64 + JSON, microseconds) and consider only those
    whose `iss` is that DID. An honest document holds exactly one such entry, so the
    cryptographic cost becomes O(1) in the length of the list. MAX_VERIFY_PER_QUERY
    then caps the pathological case where a hostile document repeats the same `iss`
    to force repeated verification.

    This is what lets MAX_LINKED_DIDS be large enough to hold an organization's whole
    fleet in one file, which is what makes per-agent revocation possible at all: the
    domain owner deletes one line from a file they already control, and that agent —
    and only that agent — stops verifying. No intermediate signs for anyone, so there
    is no bearer credential anywhere in the chain that its issuer cannot take back."""
    found: list = []
    try:
        if not isinstance(doc, dict):
            return []
        entries = doc.get("linked_dids")
        if not isinstance(entries, list):
            return []
        want = for_did if isinstance(for_did, str) and for_did else None
        verified = 0
        for entry in entries[:MAX_LINKED_DIDS]:
            if not isinstance(entry, str):
                continue
            if want is not None:
                # Cheap pre-filter on the UNVERIFIED issuer. Safe because nothing is
                # trusted from it: a lie here only costs the liar a skipped entry,
                # and every surviving entry is still fully verified below.
                payload = jws.payload_of(entry)
                if not isinstance(payload, dict) or payload.get("iss") != want:
                    continue
                if verified >= MAX_VERIFY_PER_QUERY:
                    break
                verified += 1
            claim = verify_domain_linkage_jwt(entry, domain=domain, now=now)
            if claim is not None:
                found.append(claim)
        return found
    except Exception:
        return []
