"""
shared/version.py
The single source of truth for a node's software version and release sequence.

Why this exists (design):
  The node version used to be a bare string literal in shared/protocol.py, and
  there was no notion of a *release sequence*. The secure auto-update layer (T25)
  needs two things every node and the build script must agree on:
    - VERSION      a human semver, exposed in the agent card / status.
    - RELEASE_SEQ  a MONOTONIC counter bumped by a human on EVERY release. It is
                   the anti-rollback knob: a node accepts a signed manifest only
                   if its seq is strictly greater than the installed seq, so a
                   signed-but-older release can never be replayed onto a node.
  Keeping both here (a stdlib-only module, zero-dependency core) means the running
  node, the dashboard, the updater, and make_dist.sh all read the same constants
  instead of drifting copies.

How a node reports its installed version/seq:
  installed_version()/installed_seq() resolve in priority order so a node that has
  AUTO-UPDATED reports the APPLIED release even before this module's constants are
  re-imported from the new tree:
    1. env override  (AGENTNET_VERSION / AGENTNET_SEQ)  — for tests.
    2. <install_root>/.release.json marker  — written by the updater after a swap.
    3. the module constants below  — the build-time baseline.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import json
import os
from pathlib import Path

# ---- build-time baseline (bump RELEASE_SEQ on EVERY release; see module docstring)
# TWO RULES OUT OF THAT HISTORY, because the code below depends on them.
#
# A SEQ NAMES EXACTLY ONE ARTIFACT. Bump `RELEASE_SEQ` for any cut whose bytes reach a node,
# even one whose runtime is byte-identical to the last — the moment two different trees have
# been served under one seq, anti-rollback means nothing, because a receiver comparing seqs
# cannot tell which of them it has. Re-serving different bytes under a published seq is the
# bug; the extra bump is the fix.
#
# THESE CONSTANTS DESCRIBE THE RUNNING PROCESS. `installed_version()` below reads a marker on
# disk, which is what the box is INSTALLED at — and a resident that was never restarted after
# an update reports the new marker while still executing the old code. Anything that tells a
# PEER what this process is (the card's `muretai` block, presence, doctor) must read the
# constants, never the marker. `shared/peercompat.py` is where that rule is enforced; the
# functions below exist to answer the other question, what is on disk.
VERSION = "0.2.54"
RELEASE_SEQ = 59
CHANNEL = "beta"

# The marker the updater writes into the live tree after a successful swap.
MARKER_NAME = ".release.json"


def install_root() -> Path:
    """The node's install/repo root (the directory that holds shared/, agent/,
    start_node.sh). shared/version.py lives one level under it."""
    return Path(__file__).resolve().parent.parent


def _marker(root: Path | None = None) -> dict:
    """Read the .release.json marker if present, else {}. Never raises."""
    try:
        path = (root or install_root()) / MARKER_NAME
        if path.exists():
            data = json.loads(path.read_text())
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _live_marker(root: Path | None = None) -> dict:
    """The marker, but ONLY if it describes this code or something newer.

    The marker exists for one direction: an in-place SWAP wrote a newer tree while an
    older process is still running — the marker lets that process report what is
    actually installed. The reverse direction is always stale: a marker with a seq
    BELOW this file's own constant was written for an older tree and survived a
    reinstall (`tar -x` over an existing dir deletes nothing). That exact staleness
    made four clean 0.2.31 reinstalls all report 0.2.28 — found not by us but by an
    external agent on the network (a QM deployment's agent) that refused to accept
    'version says X' at face value. A marker without a comparable seq is treated as
    stale too — precedence needs evidence."""
    m = _marker(root)
    try:
        if int(m.get("seq")) >= RELEASE_SEQ:
            return m
    except (TypeError, ValueError):
        pass
    return {}


def installed_version(root: Path | None = None) -> str:
    """This node's installed version (env override > live marker > constant)."""
    env = os.environ.get("AGENTNET_VERSION")
    if env:
        return env
    return str(_live_marker(root).get("version") or VERSION)


def installed_seq(root: Path | None = None) -> int:
    """This node's installed release sequence (env override > live marker > constant)."""
    env = os.environ.get("AGENTNET_SEQ")
    if env is not None:
        try:
            return int(env)
        except (TypeError, ValueError):
            pass
    try:
        return int(_live_marker(root).get("seq", RELEASE_SEQ))
    except (TypeError, ValueError):
        return RELEASE_SEQ


def installed_channel(root: Path | None = None) -> str:
    """This node's installed channel (live marker > constant). Note the channel a node
    *follows* is a config concern (shared/update_config.update_channel); this is
    just what the installed artifact was built as."""
    return str(_live_marker(root).get("channel") or CHANNEL)


def version_tuple(s: str) -> tuple[int, ...]:
    """Parse a dotted semver-ish string into an int tuple for ordering. Non-numeric
    or missing parts degrade to 0 so comparison never raises on odd input
    (e.g. "0.3.0-rc1" -> (0, 3, 0)). Used for the minVersion floor check."""
    out: list[int] = []
    for part in str(s).split("."):
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        out.append(int(num) if num else 0)
    return tuple(out)
