"""
test_neturl_origin.py — `shared/neturl.origin` is a security primitive; it must be total.

`origin()` is the one canonicalizer two independent security decisions rest on:

  * `agent/relayclient.listen_token` signs it and `relay._verify_listen_token` checks it,
    so a listener token is only valid at the relay it was minted for;
  * `Outbox.card_binds_to` compares it to decide whether a fetched Agent Card's signed
    `url` really names the host we dialled.

Both feed it values a REMOTE party chose. `card_binds_to` passes `card["url"]` straight
from a fetched card, so a card whose `url` was a list/int/dict reached `url.strip()` and
threw AttributeError out of the middle of a security decision — found by attacking T85
(2026-08-09). It failed CLOSED, so it was never a bypass, but an unhandled exception
inside the function an access check rests on is the wrong shape: the answer to "is this
a relay URL" for a list is "no", not a traceback. And `card_binds_to` is a public static
method other call sites will adopt, so the crash would have spread.

This file pins the two properties the callers actually depend on:

  1. TOTALITY — origin() returns a str for ANY input and never raises. If it can raise,
     a peer-chosen value can crash whichever check consults it next.
  2. CANONICALIZATION — the spellings a node really stores for the SAME relay must
     collapse to one string (or a node 401s forever), and two DIFFERENT endpoints must
     never collapse to one (or the binding is void).

Stdlib-only, no network.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM (the `agent-seam` repository, MIT): this suite travels with the bytes it
# checks, so it carries their licence. Its home is agent-seam; Muretai core vendors it verbatim
# at a pinned commit (shared/VENDOR.json there) and is AGPL-3.0-or-later around it.
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared import neturl   # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILURES.append(msg)
        print(f"  ✗ {msg}")
    else:
        print(f"  ✓ {msg}")


# --- 1: totality — a remote-chosen value must never raise ------------------------
print("=== 1: origin() is total (never raises, always returns str) ===")
# The exact shapes a hostile Agent Card can put in `url`: JSON gives dict/list/int/
# float/bool/None, and a hand-edited peers.json can give anything at all.
HOSTILE = [
    None, [], {}, 42, 0, -1, 3.14, True, False, b"https://x", bytearray(b"x"),
    ["https://x"], {"url": "https://x"}, (1, 2), set(), object(),
    "", " ", "\t\n", "https://", "://x", "//x", "x", "http://",
    "https://[", "https://]", "https://[::1", "http://x:99999", "http://x:-1",
    "http://x:0443", "https://user:pw@x", "https://@x", "https://x@@y",
    "ws://x", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x",
    "https://x\x00y", "https://x\ry", "https://x\ny", "https://x\ty",
    "https://" + "a" * 100_000, "%" * 1000, "https://%zz", "https://x/%",
    "https://x?a=1#b", "https://x/../../y", "HTTPS://X", "hTtP://X:80",
]
raised = []
for v in HOSTILE:
    try:
        got = neturl.origin(v)
    except Exception as e:                      # noqa: BLE001 — that is the point
        raised.append((repr(v)[:40], type(e).__name__, str(e)[:60]))
        continue
    if not isinstance(got, str):
        FAILURES.append(f"origin({v!r:.40}) returned {type(got).__name__}, not str")
check(not raised,
      f"no input raised (offenders: {raised})" if raised
      else "none of 47 hostile inputs raised; all returned str")

# The regression itself, stated plainly: this is the exact call card_binds_to makes.
for bad in ([], {"a": 1}, 42, None, True):
    check(neturl.origin(bad) == "",
          f"a card url of {type(bad).__name__} folds to '' (fail-closed, no AttributeError)")

# And the downstream guarantee: "" must never count as a match for anything.
check(neturl.origin("") == "" and neturl.origin(None) == "",
      "an absent url yields '' — callers must treat '' as 'no proof', never as equality")


# --- 2: the spellings that MUST collapse (or a node 401s forever) ----------------
print("\n=== 2: one relay, many spellings -> one origin ===")
SAME = [
    "https://muretai.com",
    "https://muretai.com/",
    "https://muretai.com:443",
    "https://muretai.com:443/",
    "https://muretai.com.",            # trailing DNS dot
    "HTTPS://Muretai.COM",
    "https://MURETAI.com/listen?did=x#f",
    "https://user:pw@muretai.com",
    "  https://muretai.com  ",
]
got = {neturl.origin(s) for s in SAME}
check(got == {"https://muretai.com"},
      f"9 spellings of the same relay all canonicalize to one string (got {got})")

check(neturl.origin("http://[::1]:9000") == "http://[::1]:9000",
      "an IPv6 literal keeps its brackets")
check(neturl.origin("http://x:80") == neturl.origin("http://x"),
      "http's default port is dropped")


# --- 3: the pairs that MUST NOT collapse (or the binding is void) ----------------
print("\n=== 3: different endpoints stay different ===")
DISTINCT = [
    ("https://muretai.com", "http://muretai.com", "scheme"),
    ("https://muretai.com", "https://www.muretai.com", "www subdomain"),
    ("https://muretai.com", "https://muretai.net", "TLD"),
    ("https://muretai.com", "https://muretai.com:8443", "port"),
    ("https://muretai.com", "https://evil.example", "host"),
    # userinfo must not smuggle a different host past the comparison
    ("https://muretai.com", "https://muretai.com@evil.example", "userinfo host"),
]
for a, b, why in DISTINCT:
    oa, ob = neturl.origin(a), neturl.origin(b)
    check(oa != ob or oa == "",
          f"{why}: {a!r} and {b!r} must not share an origin (got {oa!r} / {ob!r})")


print()
if FAILURES:
    print(f"❌ {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print(f"   - {f}")
    raise SystemExit(1)
print("ALL neturl.origin TESTS PASSED ✅")
