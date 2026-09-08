"""
shared/peercompat.py
What version a node is RUNNING, and how that fact reaches an operator.

Why this exists. A node can be running code OLDER than the tree on its disk — a resident
listener that was never restarted after an update keeps executing the old process while every
surface reports the new marker. When the two ends of a conversation are split that way, the
newer sender seals a shape the older receiver cannot read, and the failure surfaces as a
DECRYPT error attributed to the relay. The relay is blind; it never opens a box. The receiver's
own listener and keys are fine, and it opens other peers' mail perfectly well. Nothing in
``connections`` or ``doctor`` mentions a version split, so the one fact that explains
everything is the one fact nobody is shown.

Four surfaces lie by omission in that situation, and this module is the one place that stops
them:

  * what a card / presence record ADVERTISES as the running process — the
    constants in ``shared/version.py``, NOT ``installed_version()``, which
    prefers a newer ``.release.json`` marker and therefore lets a stale process
    report the version it is not running;
  * whether a live process or listener is BEHIND the tree on disk, in the words
    doctor should say;
  * the sentence a dead-letter prints, which must name the LOCAL LISTENER and
    not the relay;
  * why a sealed item could not be opened, when the answer is "this build has
    no ML-KEM backend" rather than "wrong key" — ``cryptobox.open_box`` collapses
    every cause into ``None``, and an operator cannot act on ``None``.

Deliberately NOT here: a seal-degrade policy keyed on the peer's advertised seq. The shape an
older peer cannot read is gated at the MINT instead (see ``keystate.make_keystate``, which
omits the binding key unless it is asked for), and that fixes it for peers which advertise no
version at all. A second gate keyed on advertisement would be weaker than the first and would
let exactly those peers through.

Stdlib only; shared/ must not import agent/.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import os
import random
import time
import threading

import json
import unicodedata
from pathlib import Path
from typing import Any

from shared import version

#: The RUNNING process, read once at import. A process that has not been restarted
#: after an updater swap still holds the OLD constants here — which is exactly the
#: number a peer and doctor must see. Never `installed_*`.
RUNNING_SEQ = version.RELEASE_SEQ
RUNNING_VERSION = version.VERSION
RUNNING_CHANNEL = version.CHANNEL

#: The bounce an operator read as "the relay failed to decrypt". It did not; the
#: local listener could not open a box sealed to a key this process does not hold.
LISTENER_OPEN_FAILED = (
    "local listener could not open the sealed mailbox item "
    "(key-state or node-version split). The relay is blind and did not decrypt."
)

LISTENER_OPEN_FAILED_LOG = (
    "local listener could not open mailbox item {qid} (sealed to a key this "
    "process does not hold — usually a key-state or node-version split); "
    "dead-lettering. The relay is blind and did not decrypt."
)

LISTENER_OPEN_FAILED_REMEDY = (
    "The peer's LOCAL LISTENER (not the relay) could not open this item — "
    "usually a node-version or key-state split. Nothing was applied. Ask its "
    "operator to update, or to restart the resident process onto the tree "
    "already on disk."
)

#: What `open_box` returning None actually meant, when we can tell.
OPEN_FAIL_NO_PQ_BACKEND = (
    "this item is a hybrid (v2) sealed box and this build has no ML-KEM "
    "backend, so it can never be opened here — install/upgrade the optional "
    "`cryptography` package, or ask the sender to seal v1"
)
OPEN_FAIL_UNKNOWN = (
    "the sealed box did not open with this node's keys (wrong recipient, a "
    "rotated enc key, or a truncated item)"
)

#: DIDs whose cached sealing key a peer has told us it cannot open. Process-local and
#: deliberately NOT a database column -- see `mark_enc_stale`.
_ENC_STALE: set = set()
_ENC_STALE_MAX = 4096
_ENC_STALE_LOCK = threading.Lock()


def mark_enc_stale(did: str) -> None:
    """Remember that our cached sealing key for `did` is dead, so the next send re-resolves.

    A MARKER, and emphatically not a clear of `direct_trust.enc_pub`. Clearing the column
    was the first implementation and it opened a hole the schema had been shaped to close:
    `TrustStore.fill_coords` fills any row whose `enc_pub` is empty, and
    `Inbox._backfill_coords` calls it with `from_enc` taken from the RELAY'S CARRIER HINT,
    which rides outside the signature. Emptying the column made that precondition true --
    fifty lines later in the SAME message handler -- so a hostile relay could have answered
    a peer's genuine key rotation by writing ITS OWN key into our row and reading everything
    we sent afterwards. fill_coords' docstring warns about exactly that attack and says the
    database enforces it; the database can only enforce it while the column stays full.

    So the row keeps the old key until a SIGNED card replaces it. The stale key is
    unusable either way -- the peer cannot open what we seal with it -- and an unusable key
    is strictly safer than an empty slot an unauthenticated hint can fill.

    Process-local because that is where it is consumed and because it must not outlive the
    knowledge: a restart re-resolves anyway, and a marker persisted past the peer's next
    successful card fetch would keep re-fetching forever.
    """
    if not did:
        return
    with _ENC_STALE_LOCK:
        if len(_ENC_STALE) >= _ENC_STALE_MAX:
            _ENC_STALE.clear()      # worst case: one extra card fetch per peer
        _ENC_STALE.add(did)


def enc_is_stale(did: str) -> bool:
    with _ENC_STALE_LOCK:
        return did in _ENC_STALE


#: How often a peer whose key is marked stale may cost us a card fetch. The mark is only
#: cleared by a SUCCESSFUL fetch -- which is right, because a transient failure must not
#: lose the heal -- but that means a peer whose card cannot be fetched keeps the mark
#: forever, and without this every send to it would pay a `/card` round trip first. One
#: fetch a minute heals just as surely and cannot be turned into an amplifier.
ENC_RESOLVE_COOLDOWN = float(os.environ.get("AGENTNET_ENC_RESOLVE_COOLDOWN", "60"))
_ENC_TRIED: dict = {}


def should_retry_enc_resolve(did: str, *, clock=time.monotonic) -> bool:
    """May we spend a card fetch on this stale-marked peer right now? Consumes the slot."""
    now = clock()
    with _ENC_STALE_LOCK:
        last = _ENC_TRIED.get(did, 0.0)
        if last and (now - last) < ENC_RESOLVE_COOLDOWN:
            return False
        if len(_ENC_TRIED) >= _ENC_STALE_MAX:
            _ENC_TRIED.clear()
        _ENC_TRIED[did] = now
        return True


def clear_enc_stale(did: str) -> None:
    """Called once a fresh signed card has actually been resolved for this peer."""
    with _ENC_STALE_LOCK:
        _ENC_STALE.discard(did)
        _ENC_TRIED.pop(did, None)


def is_open_failure_bounce(text: str, auto: bool) -> bool:
    """Is this inbound message a peer telling us it could not OPEN our sealed box?

    `_nack` (agent/relayclient) bounces a signed DM whose body embeds
    `LISTENER_OPEN_FAILED` verbatim, so that constant is the marker. Matching the
    STRING rather than adding a metadata field is deliberate and is the whole point:
    a new field would only work when BOTH ends are new, and the pairs that need
    healing are precisely the ones that have already drifted apart. Every node that
    can produce this bounce today already produces this sentence.

    `auto` is required as well. Bounces are machine-generated and carry it; a human
    quoting the sentence back at us should not invalidate a key. It is not a
    security boundary -- a peer could set `auto` itself -- and it does not need to
    be, because the only thing this can invalidate is the sender's OWN cached key.
    A peer saying "I cannot open your boxes" is the one party entitled to say it.
    """
    return bool(auto) and isinstance(text, str) and LISTENER_OPEN_FAILED in text


SPLIT_OLDER = "older"
SPLIT_UNKNOWN = "unknown"
SPLIT_MATCH = "match"
SPLIT_NEWER = "newer"


#: The TTL handed to the updater when a peer looks newer. NEVER 0.
#:
#: `ttl=0` was the first implementation and it removed every brake at once. The cooldown
#: below lives in PROCESS globals, so a short-lived process -- `muretai dm`, one MCP
#: invocation -- starts clean and has no cooldown at all; and ttl=0 bypasses the updater's
#: `data/.last_update_check` stamp, which is the only brake that survives a process
#: boundary. A loop of `dm` calls would then ask the release origin once per message and
#: fire a fleet report each time. 300s still collapses the hourly window to five minutes,
#: while leaving the stamp doing the work only the stamp can do.
PEER_AHEAD_TTL = float(os.environ.get("AGENTNET_PEER_AHEAD_TTL", "300"))

#: How long between update checks triggered by a peer looking newer. A cooldown, not a
#: per-peer bound: fifty peers that are all ahead are one piece of news, not fifty.
AHEAD_COOLDOWN = float(os.environ.get("AGENTNET_PEER_AHEAD_COOLDOWN", "900"))

#: Spread, in seconds, before a peer-triggered check actually runs. A release is learned
#: by the whole fleet within minutes of each other -- every node meets a newer peer at
#: about the same time -- so without this they would all hit the release origin together.
#: `agent/relayclient.py` carries the same idea for reconnects, and says why: "so a fleet
#: recovering from one relay blip doesn't re-synchronise into a second."
#:
#: Uniform rather than that module's "equal jitter". Equal jitter keeps a minimum wait,
#: which is what a BACKOFF wants; here the point is only to decorrelate, and a node that
#: happens to draw zero should get its update immediately.
AHEAD_JITTER = float(os.environ.get("AGENTNET_PEER_AHEAD_JITTER", "60"))


def peer_is_ahead(adv: dict | None, *, our_seq: int = RUNNING_SEQ,
                  our_channel: str = RUNNING_CHANNEL) -> "int | None":
    """The peer's seq when their RUNNING build is newer than ours, else None.

    Same channel only. A beta peer is not news to a stable node -- their seq counts a
    different sequence, and treating it as ours would have every stable node chasing a
    release it must never install.

    The claim is the peer's own, signed into their card, and it is worth exactly what
    that makes it: a HINT ABOUT TIMING. It can move WHEN we ask our own release origin
    a question. It can never move WHAT we install -- that stays the signed manifest,
    the pinned release DID, the channel and the anti-rollback seq. A peer claiming seq
    999999 therefore costs one wasted poll, not a downgrade and not a foreign build.
    """
    if not isinstance(adv, dict):
        return None
    # FAIL CLOSED on an unknown channel. This read `or our_channel`, which made an ABSENT
    # channel indistinguishable from ours -- and absence is reachable, because
    # `advertised_from_card` only sets the key when the card carries a non-empty string. A
    # beta peer could therefore omit its channel and act on a stable node: not to install
    # anything (the apply is gated on our OWN channel), but enough to spend a poll and to
    # set the high-water mark below. Channel isolation that a peer can opt out of by
    # SAYING LESS is not isolation. Found by audit.
    ch = adv.get("node_channel")
    if not ch or str(ch) != str(our_channel):
        return None
    seq = parse_seq(adv.get("node_seq"))
    if seq is None or seq <= our_seq:
        return None
    return seq


class _AheadGate:
    """The in-process half of the brake on peer-triggered update checks.

    A class with an injectable clock rather than module globals, because that is how the
    other peer-driven limiters here are built (`agent/throttle.py`, `agent/roomguard.py`)
    and because their tests advance a fake clock instead of reaching in and rewriting
    module state. A limiter whose only test is "mutate the global" is a limiter whose
    expiry path never runs in CI.

    This is the SECOND layer. The first is the updater's on-disk stamp, which is the only
    one that means anything to a short-lived process; everything here resets when the
    process does.
    """

    def __init__(self, cooldown: float = AHEAD_COOLDOWN, clock=time.monotonic):
        self.cooldown = cooldown
        self._clock = clock
        self._lock = threading.Lock()
        self._last = 0.0        # when we last let a check through
        self._top = 0           # the highest peer seq we have already reacted to

    def allow(self, peer_seq: int) -> bool:
        """May a check run now for a peer advertising `peer_seq`? Consumes the allowance.

        Two brakes for two different abuses. The COOLDOWN bounds a busy node: an update
        check touches the release origin, and a node with fifty correspondents must not
        poll fifty times because it learned one fact fifty ways. The HIGH-WATER MARK
        bounds repetition: once we have reacted to seq N, another card advertising N is
        not new information, so a peer that cannot be updated -- or a liar sitting on one
        number -- cannot keep the poll running.
        """
        now = self._clock()
        with self._lock:
            if peer_seq <= self._top:
                return False
            if self._last and (now - self._last) < self.cooldown:
                return False
            self._last = now
            self._top = peer_seq
            return True

    def reset(self) -> None:
        """Forget everything. For tests and for a process that re-execs in place."""
        with self._lock:
            self._last = 0.0
            self._top = 0


_AHEAD_GATE = _AheadGate()


def should_check_for_update(peer_seq: int) -> bool:
    """Module-level front door to the shared gate; see `_AheadGate.allow`."""
    return _AHEAD_GATE.allow(peer_seq)


def ahead_jitter_delay() -> float:
    """Seconds to wait before a peer-triggered check, so a fleet does not synchronise."""
    return random.uniform(0.0, AHEAD_JITTER) if AHEAD_JITTER > 0 else 0.0


def parse_seq(value: Any) -> int | None:
    """A release sequence, or None when the peer advertised nothing usable.

    `True`/`False` are rejected explicitly: in Python they are ints, and a card
    is attacker-shaped input, so `{"seq": true}` would otherwise become seq 1."""
    if value is None or value is True or value is False:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _display_safe(value: Any) -> str:
    """A peer-chosen string, safe to print on an operator's terminal.

    `node` and `channel` come off a stranger's card and land on the `connections` line and in
    `doctor` — the screens an operator reads to decide whether a peer is trustworthy. Every
    sibling field on that same line (`expertise`, the peer's label) is already put through
    `agent/groupview.clean_name`; this one is not, and shared/ must not import agent/, so the
    strip lives here, at the ONE place a card's version block is parsed. Without it a peer
    chooses its own `node` string and can emit CR, ANSI escapes or direction marks to repaint
    or overwrite the very line that is supposed to be reporting on it. Control and format
    characters out (Cc/Cf, which covers CR, ESC and the bidi overrides), then bound the
    length: a version is a version."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch for ch in value if unicodedata.category(ch) not in ("Cc", "Cf"))
    return cleaned.strip()[:32]


def card_muretai_version_fields() -> dict[str, Any]:
    """The additive fields every card carries for THIS process.

    Top-level A2A `version` stays `installed_version()` (the marker semver, what
    the box is INSTALLED at). These three say what is actually executing, and the
    gap between them is the stale resident."""
    return {
        "seq": int(RUNNING_SEQ),
        "channel": str(RUNNING_CHANNEL),
        "node": str(RUNNING_VERSION),
    }


def advertised_from_card(card: dict | None) -> dict[str, Any]:
    """The running-process version a card advertises (muretai.seq/channel/node)."""
    if not isinstance(card, dict):
        return {}
    block = card.get("muretai")
    if not isinstance(block, dict):
        return {}
    out: dict[str, Any] = {}
    seq = parse_seq(block.get("seq"))
    if seq is not None:
        out["node_seq"] = seq
    node = _display_safe(block.get("node"))
    if node:
        out["node_version"] = node
    ch = _display_safe(block.get("channel"))
    if ch:
        out["node_channel"] = ch
    return out


def classify(our_seq: int, peer_seq: int | None) -> str:
    """How the peer's advertised seq sits relative to ours."""
    if peer_seq is None:
        return SPLIT_UNKNOWN
    if peer_seq < our_seq:
        return SPLIT_OLDER
    if peer_seq > our_seq:
        return SPLIT_NEWER
    return SPLIT_MATCH


def split_label(peer: dict | None, *, our_seq: int = RUNNING_SEQ) -> str | None:
    """One tag for `connections` / `doctor`, or None when the versions match.

    Unknown is reported, not excused: the incident's receiver advertised nothing,
    and "we cannot tell" is the fact the operator needed."""
    if not isinstance(peer, dict):
        return "node version unknown"
    seq = parse_seq(peer.get("node_seq"))
    kind = classify(our_seq, seq)
    if kind == SPLIT_MATCH:
        return None
    if kind == SPLIT_UNKNOWN:
        return "node version unknown"
    ver = peer.get("node_version") or ""
    extra = f" {ver}" if ver else ""
    side = "older than" if kind == SPLIT_OLDER else "newer than"
    return f"node seq {seq}{extra} ({side} this node, seq {our_seq})"


def tree_seq(root: Path | None = None) -> int:
    """Seq of the tree ON DISK (.release.json), ignoring AGENTNET_SEQ.

    `AGENTNET_SEQ` overrides `installed_seq()` so tests can say what a process
    CLAIMS; the stale-resident check must see the marker an updater swap wrote,
    never that override — otherwise the one check that catches a stale process
    can be silenced by the same env var a stale process might carry."""
    try:
        path = (root or version.install_root()) / version.MARKER_NAME
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            seq = parse_seq(data.get("seq"))
            if seq is not None:
                return seq
    except Exception:
        pass
    return int(version.RELEASE_SEQ)


def stale_resident_lines(warn: str, *, running_seq: int, disk_seq: int,
                         listener_seq: Any = None,
                         listener_active: bool = False) -> list[str]:
    """Doctor lines when a live process or listener is behind the tree on disk.

    Two signals, both load-bearing:
      * THIS process's RELEASE_SEQ is below the marker — doctor is itself the
        stale resident (the mcpb-local-test shape);
      * a live listener advertised a seq below the marker.
    A missing listener seq while running == disk is the whole current fleet
    until they update once. Do not cry wolf: say nothing."""
    out: list[str] = []
    ls = parse_seq(listener_seq)
    if running_seq < disk_seq:
        out.append(
            f"{warn}resident: this process is seq {running_seq}, the tree on disk "
            f"is seq {disk_seq} (.release.json) — restart the resident "
            f"(LaunchAgent / mcpb / systemd) so it loads the new tree.")
        return out
    if listener_active and ls is not None and ls < disk_seq:
        out.append(
            f"{warn}resident: the live listener is seq {ls}, the tree on disk is "
            f"seq {disk_seq} (.release.json) — restart the resident "
            f"(LaunchAgent / mcpb / systemd) so it drains on the new tree.")
    return out
