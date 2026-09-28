#!/usr/bin/env python3
"""The landing lease's CORE: pick a backend, run one verb through it, map the answer.

Stdlib only, Python 3.9+, and deliberately generic: this module knows nothing about who
signs a request, which key format a machine keeps, or where a node lives -- a caller hands
it a backend object that does. It can therefore be lifted into another repository as is.

    backend = none | do | command          ([lease] backend = "..." in a config file)

Only `do` (an HTTPS lease service, one JSON POST per verb) is built. `none` and `command`
are dispatch-only extension points: selecting either answers "not implemented in this
build" and makes no request. An unknown backend is a configuration error of its own.

The outcomes, and the exit code each maps to -- a backend returns an OUTCOME, never a code:

    ok           0   printed as key=value lines (held-by= / until= / epoch= ...)
    config       2   a client-side configuration error; nothing was sent
    unreachable  3   the backend could not be reached: ONE line on stderr, naming it
    held         4   someone else holds the lease (held-by= and until= on stdout)
    refused      5   ANY other refusal or unusable answer, its reason printed verbatim

There is no sixth outcome: an answer that was sent and never came back is retried once for
a take (a take by the live holder is a renew at the same epoch, so a lost grant is
recovered, not doubled) and is otherwise unreachable. "It did not answer" is never a
refusal, and a refusal is never reported as unreachable.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
from pathlib import Path
from typing import Callable, Dict, List, Optional

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_UNREACHABLE = 3
EXIT_HELD = 4
EXIT_REFUSED = 5

BACKENDS = ("none", "do", "command")
BUILT = ("do",)
DEFAULT_BACKEND = "do"
HTTP_TIMEOUT_S = 10.0
MAX_ANSWER = 64 * 1024


class ConfigError(Exception):
    """Exit 2: the client cannot even form a request."""


class Unreachable(Exception):
    """Exit 3. `sent` is True when the request left and no answer came back."""

    def __init__(self, where: str, why: str, sent: bool = False):
        super().__init__("%s: %s" % (where, why))
        self.where = where
        self.why = why
        self.sent = sent


class Outcome:
    def __init__(self, kind: str, fields: Optional[Dict[str, str]] = None, reason: str = ""):
        self.kind = kind
        self.fields = fields or {}
        self.reason = reason


# -- configuration ---------------------------------------------------------------------

def read_config(path: Optional[Path]) -> Dict[str, str]:
    """The [lease] section of a small TOML file: `key = "value"` (or a bare word) lines.
    A missing file is an empty configuration; an unreadable one is a ConfigError."""
    if path is None or not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ConfigError("the lease configuration %s is not a regular file" % path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError("cannot read the lease configuration %s (%s)" % (path, e))
    out: Dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.split("]", 1)[0][1:].strip()
            continue
        if section != "lease" or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if v[:1] in ("\"", "'") and v[0] in v[1:]:
            v = v[1:v.index(v[0], 1)]          # a quoted value may hold a '#'
        else:
            v = v.split("#", 1)[0].strip()
        out[k.strip()] = v
    return out


def select_backend(cfg: Dict[str, str]) -> str:
    name = (cfg.get("backend") or DEFAULT_BACKEND).strip()
    if name not in BACKENDS:
        raise ConfigError("unknown lease backend %r in [lease] backend (known: %s)"
                          % (name, ", ".join(BACKENDS)))
    return name


# -- the do backend's transport: one JSON POST ---------------------------------------------

def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> urllib.parse.SplitResult:
    """https://, or http:// to loopback only: the grant is unsigned, so it is trusted only
    over TLS to the configured endpoint. Refused before any connection is made."""
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme not in ("https", "http") or not u.hostname:
        raise ConfigError("the lease url %r is not an https:// URL" % url)
    if u.scheme == "http" and not _loopback(u.hostname):
        raise ConfigError("the lease url %r must be https:// (plain http:// is accepted only "
                          "for loopback: the grant is trusted only over TLS)" % url)
    return u


def where_of(u: urllib.parse.SplitResult) -> str:
    return "%s://%s" % (u.scheme, u.netloc)


def post_json(url: str, path: str, body: dict, timeout: float = HTTP_TIMEOUT_S):
    """POST body to url + path. Returns (status, parsed JSON or None, raw text).
    Raises Unreachable -- with sent=True when the request left and no answer arrived."""
    u = check_url(url)
    where = where_of(u)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=timeout)
    raw_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    full = (u.path.rstrip("/") + path) or "/"
    sent = False
    try:
        try:
            conn.request("POST", full, body=raw_body,
                         headers={"Content-Type": "application/json", "Accept": "application/json"})
            sent = True
            resp = conn.getresponse()
            raw = resp.read(MAX_ANSWER + 1)
        except (socket.timeout, TimeoutError) as e:
            raise Unreachable(where, "timed out after %.0fs" % timeout, sent=sent) from e
        except (http.client.RemoteDisconnected, http.client.BadStatusLine,
                http.client.IncompleteRead, ConnectionResetError, BrokenPipeError) as e:
            raise Unreachable(where, "the connection closed without an answer (%s)"
                              % type(e).__name__, sent=True) from e
        except (OSError, http.client.HTTPException) as e:
            raise Unreachable(where, str(getattr(e, "strerror", None) or e), sent=sent) from e
    finally:
        conn.close()
    text = raw[:MAX_ANSWER].decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return resp.status, parsed, text


def probe(url: str, path: str = "/health", timeout: float = 5.0) -> str:
    """One GET, for a doctor: '' when the service answered at all (any status), else why
    not. Never a POST: a probe must not take the lease."""
    try:
        u = check_url(url)
    except ConfigError as e:
        return str(e)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=timeout)
    try:
        conn.request("GET", (u.path.rstrip("/") + path) or "/")
        conn.getresponse().read(1024)
        return ""
    except (OSError, http.client.HTTPException) as e:
        return "%s is unreachable (%s)" % (u.netloc, getattr(e, "strerror", None) or e)
    finally:
        conn.close()


# -- answers --------------------------------------------------------------------------------

# What the backend says reaches a terminal and a landing receipt, so a value printed as a
# key=value field must be one token of printable ASCII, and `until` must be the ISO form.
TOKEN_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
ISO_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def printable(text: str, limit: int = 300) -> str:
    """The text with every character outside printable ASCII spelled as \\uXXXX, so a
    reason is shown verbatim without ever driving the terminal it is printed to."""
    return "".join(c if " " <= c <= "~" else "\\u%04x" % ord(c) for c in text[:limit])


def outcome_of(verb: str, status: int, body, raw: str, me: str) -> Outcome:
    """Map one answer to an outcome. Only a well-formed grant naming `me` is ok."""
    if not isinstance(body, dict):
        return Outcome("refused", reason="the lease backend's answer (HTTP %d) is not JSON: %s"
                       % (status, raw.strip()[:200] or "(empty)"))
    if body.get("ok") is not True:
        reason = body.get("reason")
        reason = reason if isinstance(reason, str) and reason else "HTTP %d without a reason" % status
        if reason == "held" and status == 409:
            holder, until = body.get("holder"), body.get("until")
            if (isinstance(holder, str) and TOKEN_RE.match(holder)
                    and isinstance(until, str) and ISO_RE.match(until)):
                return Outcome("held", {"held-by": holder, "until": until})
            return Outcome("refused", reason="held, but the answer names no usable holder / until")
        return Outcome("refused", reason=reason)
    if status != 200:
        return Outcome("refused", reason="the lease backend answered ok with HTTP %d" % status)
    epoch = body.get("epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        return Outcome("refused", reason="the grant carries no epoch")
    if verb == "release":
        if body.get("holder") is not None:
            return Outcome("refused", reason="the release answer still names a holder")
        return Outcome("ok", {"held-by": "none", "released-by": me, "epoch": str(epoch)})
    holder, until = body.get("holder"), body.get("until")
    if holder != me:
        return Outcome("refused", reason="the grant names another holder (%s), not this client"
                       % (holder if isinstance(holder, str) else "none"))
    if not isinstance(until, str) or not ISO_RE.match(until):
        return Outcome("refused", reason="the grant carries no usable until")
    fields = {"held-by": me, "until": until, "epoch": str(epoch)}
    sup = body.get("superseded")
    if isinstance(sup, dict) and isinstance(sup.get("holder"), str) and TOKEN_RE.match(sup["holder"]):
        fields["expired-lease-by"] = sup["holder"]
    return Outcome("ok", fields)


# -- running a verb -------------------------------------------------------------------------

class Backend:
    """What the core needs from a backend. `me` names the holder; `send(verb)` performs one
    request and returns (status, body, raw) or raises Unreachable / ConfigError."""

    me = ""

    def send(self, verb: str):  # pragma: no cover - interface
        raise NotImplementedError


def run(verb: str, backend: Backend) -> Outcome:
    attempts = 2 if verb == "take" else 1
    last: Optional[Unreachable] = None
    for _ in range(attempts):
        try:
            status, body, raw = backend.send(verb)
        except Unreachable as e:
            last = e
            if e.sent:
                continue          # a take whose grant was lost: the retry renews it
            break
        return outcome_of(verb, status, body, raw, backend.me)
    assert last is not None
    return Outcome("unreachable", reason="the lease backend at %s is unreachable: %s"
                   % (last.where, last.why))


def emit(prog: str, outcome: Outcome) -> int:
    """Print an outcome the way callers read it and return its exit code."""
    def err(msg: str) -> None:
        sys.stderr.write("%s: %s\n" % (prog, printable(" ".join(msg.split()), 600)))

    if outcome.kind == "ok":
        for k in ("held-by", "released-by", "until", "epoch", "expired-lease-by"):
            if k in outcome.fields:
                sys.stdout.write("%s=%s\n" % (k, outcome.fields[k]))
        return EXIT_OK
    if outcome.kind == "held":
        sys.stdout.write("held-by=%s\nuntil=%s\n" % (outcome.fields["held-by"], outcome.fields["until"]))
        err("the lease is held by %s until %s" % (outcome.fields["held-by"], outcome.fields["until"]))
        return EXIT_HELD
    if outcome.kind == "unreachable":
        err(outcome.reason)
        return EXIT_UNREACHABLE
    if outcome.kind == "config":
        err(outcome.reason)
        return EXIT_CONFIG
    err("the lease backend refused: %s" % outcome.reason)
    return EXIT_REFUSED


def dispatch(prog: str, verb: str, cfg: Dict[str, str],
             builders: Dict[str, Callable[[Dict[str, str]], Backend]]) -> int:
    """Select the configured backend, build it, run the verb, print, return the exit code."""
    try:
        name = select_backend(cfg)
        if name not in BUILT or name not in builders:
            raise ConfigError("the lease backend %r is not implemented in this build "
                              "(built: %s)" % (name, ", ".join(BUILT)))
        backend = builders[name](cfg)
        outcome = run(verb, backend)
    except ConfigError as e:
        outcome = Outcome("config", reason=str(e))
    return emit(prog, outcome)


def config_path(explicit: Optional[str], default: Path) -> Path:
    return Path(explicit) if explicit else default


def env_first(*names: str) -> str:
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return ""


__all__: List[str] = [
    "EXIT_OK", "EXIT_CONFIG", "EXIT_UNREACHABLE", "EXIT_HELD", "EXIT_REFUSED",
    "BACKENDS", "ConfigError", "Unreachable", "Outcome", "Backend",
    "read_config", "select_backend", "check_url", "post_json", "probe",
    "outcome_of", "run", "emit", "dispatch", "config_path", "env_first",
]
