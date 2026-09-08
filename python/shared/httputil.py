"""
shared/httputil.py
HTTP request self-protection shared by every BaseHTTPRequestHandler in the
project (the blind relay, the node inbox, the dashboard, and the host bridges):
a bounded request-body read AND a per-request socket timeout.

WHY (body cap):
  Reading `rfile.read(Content-Length)` with no ceiling lets any client declare a
  huge Content-Length and make the server allocate that much memory — an
  unauthenticated out-of-memory DoS. It is most damaging on the small-RAM relay
  VM (which has a known overload-hang mode). Centralising the cap here means every
  server enforces the SAME limit and a single place governs it.

WHY (request timeout — slowloris):
  The body cap bounds ONE request's memory, but ThreadingHTTPServer still spawns a
  thread per connection and blocks in the header/body read with no deadline. A
  slowloris client opens a connection and dribbles bytes (or never finishes the
  request line/headers), pinning a thread — a slow-send DoS distinct from the
  big-body one. BaseHTTPRequestHandler.timeout (a class attribute) makes setup()
  call connection.settimeout(timeout): each socket recv/send then has a deadline,
  and handle_one_request already wraps the request in `except TimeoutError:` and
  discards the connection. So setting the handler timeout drops a stalled sender
  AND frees a thread whose response write stalls (e.g. the relay installer stream
  to a dead reader). It does NOT abort a long-poll's WAIT phase: while /listen
  blocks in a threading.Condition.wait it is not inside a socket call, so the
  socket timeout clock is not running — only the header read before the wait and
  the response write after it are bounded, which is exactly the read/idle phase we
  want to cap. The default is sized ABOVE the relay long-poll window anyway
  (see REQUEST_TIMEOUT) so there is margin either way.

  Stdlib-only on purpose: `shared/` must stay importable by the zero-dependency
  relay (it already imports shared/crypto.py, shared/protocol.py). No new deps.

USAGE (each handler keeps its own error-response style):
    class Handler(BaseHTTPRequestHandler):
        timeout = httputil.REQUEST_TIMEOUT     # slowloris read/idle deadline
        ...
    raw = httputil.read_body(self)
    if raw is httputil.BODY_TOO_LARGE:
        self._send(413, ...); return
    body = json.loads(raw) if raw else {}
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import os
import time

# Generous ceiling for a signed A2A message plus its sealed blob (both small).
# Env-overridable so an operator can raise it without a code change.
MAX_BODY_BYTES = int(os.environ.get("AGENTNET_MAX_BODY_BYTES", str(1024 * 1024)))

# Per-request socket timeout (seconds) for the read/idle phase of a connection —
# the anti-slowloris deadline. Applied as BaseHTTPRequestHandler.timeout, so it
# bounds each recv/send, NOT a long-poll's wait (see module docstring). 30s is
# comfortably above the relay's ~25s LISTEN_TIMEOUT so even if a future handler
# happened to read mid-long-poll there is margin. Env-overridable so an operator
# can tighten it under hostile traffic (or loosen it for a slow-link client).
REQUEST_TIMEOUT = float(
    os.environ.get("AGENTNET_HTTP_REQUEST_TIMEOUT", "30"))

# Sentinel returned when the declared Content-Length exceeds the cap: the caller
# answers 413 without ever allocating the oversized body. Identity-compared
# (`is`), never equal to any real body (bytes), so it is unambiguous.
BODY_TOO_LARGE = object()


# Ceiling for a RESPONSE we read from someone else. read_body caps what a peer sends
# US as a server; this caps what a peer sends back when WE are the client — a peer's
# agent card, an issuer's /revocations, a relay reply. Without it every outbound
# `r.read()` reads to EOF, so a single well-formed request to a host the attacker chose
# can be answered with an endless chunked stream and exhaust memory. Separate name and
# env var because the two directions have genuinely different tuning: an operator may
# raise the request cap for their own large payloads without also trusting peers to
# return more.
MAX_RESPONSE_BYTES = int(os.environ.get("AGENTNET_MAX_RESPONSE_BYTES",
                                        str(1024 * 1024)))


# How much we ask for per read when a wall-clock budget is in force. Small enough that the
# deadline is re-checked often, large enough that an honest body costs one or two syscalls.
_READ_CHUNK = 65536

# How much LONGER than the socket timeout a body read may take in total.
#
# WHY IT IS NOT 1.0 (i.e. why the budget is not simply the timeout). The two bound different
# things: `timeout=` is how long we will wait with NOTHING arriving, and the budget is how
# long the whole transfer may take. Setting them equal makes the budget add nothing for the
# stall case — one full stall already spends it — while imposing a THROUGHPUT FLOOR on an
# honest origin: at the domain verifier's numbers, 64 KiB in 6 s is ~11 KB/s, and an origin
# slower than that now reads as `domain-unavailable` and is CACHED as a failure for
# NEGATIVE_TTL. That is a false negative on the state an inbox gate consults, and it did not
# exist before the budget was added. A factor of 3 keeps the worst case bounded and firmly
# short (a trickle still dies in ~3 x timeout instead of days) while dropping the floor to
# ~3.6 KB/s for a full-size document — and the documents actually fetched on these paths are
# a few kilobytes, where the real floor is well under 1 KB/s.
READ_BUDGET_FACTOR = 3.0


def read_budget(timeout: float) -> float:
    """The wall-clock body budget that goes with a socket `timeout`. See the factor above."""
    return float(timeout) * READ_BUDGET_FACTOR


class ResponseTooLarge(ValueError):
    """A peer's response body ran past the caller's size cap.

    A ValueError subclass, so the `except ValueError` every existing caller already has
    keeps catching it unchanged. It exists so that ONE caller can tell "the body was too
    big" apart from "the body did not parse": the revocation reader (`agent/trust.py`)
    treats an oversize `/revocations` as REACHABLE-BUT-UNREADABLE — a verdict it must
    deny on, regardless of policy — while a garbled body stays UNDECIDABLE. Folding both
    into a bare ValueError made a signed list that merely grew past 1 MiB read as "the
    issuer is down", which under the default fail-open un-revoked everything that issuer
    had ever revoked."""


class ResponseTooSlow(TimeoutError, ValueError):
    """A peer's response body did not finish inside the caller's wall-clock budget.

    Derives from BOTH so that EVERY existing handler already catches it: the network
    callers wrap peer reads in `except (URLError, OSError)` (TimeoutError ⊂ OSError) and
    the card path adds `except ValueError` for the size cap. A new bare exception class
    here would have escaped both and turned a refusal into a traceback."""


def read_response(resp, max_bytes: int = MAX_RESPONSE_BYTES, *,
                  budget_s: float | None = None) -> bytes:
    """Read an HTTP RESPONSE body, capped at `max_bytes`. Raises ResponseTooLarge (a
    ValueError) past the cap.

    Reads `max_bytes + 1` and rejects on overflow rather than trusting Content-Length,
    so a chunked or Content-Length-lying response is bounded too — `resp.read(n)` is
    honoured for chunked bodies, which a header check would not be.

    WHY `budget_s` (the TRICKLE / slow-read attack):
      urllib's `timeout=` is a PER-RECV socket timeout, NOT a deadline on the exchange.
      A hostile origin that answers headers immediately and then dribbles ONE BYTE every
      `timeout - ε` seconds resets that clock forever: every recv succeeds, so nothing
      ever times out, and the read only ends at `max_bytes`. Measured against the T100
      open-door path: a 4 s timeout held the caller for 24 s, and at the production 20 s
      default with a byte every 19 s the same read runs for MONTHS. This is the mirror
      image of the slowloris the server side already defends against (see above) — same
      trick, aimed at a client that dialled an address a stranger chose.

      `budget_s` is a real wall-clock ceiling: the elapsed time is re-checked before each
      chunk, and `ResponseTooSlow` is raised once it is spent. `read1` is used when the
      response object has it, so a chunk returns as soon as ANY bytes are available — with
      plain `read(n)` a BufferedReader blocks until it has all n bytes, which is exactly
      how the trickle survives a per-recv timeout.

      RESIDUAL, on purpose: this bounds the BODY only. Time spent before the response
      headers arrive is inside urlopen/getresponse, where urllib exposes no deadline at
      all — an origin that trickles its HEADER bytes is still bounded only by the per-recv
      socket timeout (times _MAXHEADERS lines). Closing that would mean owning the socket
      and driving http.client through a selector, i.e. writing an HTTP client; the cheap
      mitigation, which the outbox does, is to pass a socket timeout no larger than the
      budget so the worst case stays near 2× budget.

    Default is None — behaviour is byte-identical to before for every caller that does not
    opt in."""
    if budget_s is None:
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ResponseTooLarge(f"response body exceeds {max_bytes} bytes")
        return data

    deadline = time.monotonic() + float(budget_s)
    read_some = getattr(resp, "read1", None)
    if read_some is None:
        # No `read1` => not a real HTTP response stream (a test double, an adapter). Chunking
        # such an object is unsafe: `read(n)` on a stateless stub returns the SAME bytes
        # forever and never reports EOF, so the loop below would spin to the size cap and
        # refuse a body it already had. Every real path here — urllib's HTTPResponse and
        # http.client's — implements read1, so this fallback costs the deadline nothing on
        # the wire; it only makes the helper total for objects that cannot be chunked.
        if time.monotonic() >= deadline:
            raise ResponseTooSlow(f"no time left in the {float(budget_s):.1f}s budget")
        data = resp.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ResponseTooLarge(f"response body exceeds {max_bytes} bytes")
        return data
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        if time.monotonic() >= deadline:
            raise ResponseTooSlow(
                f"response body did not arrive within {float(budget_s):.1f}s "
                f"(read {total} bytes so far)")
        chunk = read_some(min(_READ_CHUNK, max_bytes + 1 - total))
        if not chunk:
            break                              # EOF: the body is complete
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise ResponseTooLarge(f"response body exceeds {max_bytes} bytes")
    return b"".join(chunks)


def read_body(handler, max_bytes: int = MAX_BODY_BYTES):
    """Read a request body, capped at `max_bytes`.

    Returns the raw bytes, `b""` when there is no body, or the BODY_TOO_LARGE
    sentinel when the declared Content-Length exceeds the cap.

    A Content-Length that lies large is rejected BEFORE the read, so the oversized
    body is never allocated. A Content-Length that lies small merely truncates the
    sender's own body, which is safe (the JSON parse then fails and the caller
    answers 400). A missing/garbage Content-Length is treated as no body.
    """
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except (TypeError, ValueError):
        length = 0
    if length > max_bytes:
        return BODY_TOO_LARGE
    if length <= 0:
        return b""
    return handler.rfile.read(length)
