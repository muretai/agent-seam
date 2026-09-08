"""
shared/ownerstate.py
OwnerState — an owner's signed, monotonic-epoch REVOCATION LIST for its own device DIDs.

This is the missing half of the account layer (T102). A countersigned DeviceKeyBinding v2
(shared/keybinding.py) says "this device belongs to this owner"; nothing said "…and this
one no longer does". Until now the only way a merchant could cut off ONE device of a
customer's account was to drop the customer — a binding proves the owner CONSENTED to a
device, never that the device is a person, so there was nothing finer to withdraw —
because a `forget` removes standing from the DID it names and the account path hands it
straight back through a sibling. OwnerState is the owner's own statement, published under
the owner's DID, that a device is disowned — and a receiver that has pinned it refuses
that device while every other device of the same owner keeps working.

    {"typ": "muretai/ownerstate/1", "rootDid": <owner did>, "epoch": <int>,
     "revoked": [<device did>, …], "ts": <int>, "sig": <b64 owner over the signed fields>}

REVOCATION-ONLY, and that is a privacy ruling, not an omission: a published record naming
an owner's CURRENT devices would be a public deviceDid→owner reverse map for anyone who
knows a DID (which is public in every invite, card and message). Bindings stay
inline-presentation only — a receiver learns a device belongs to an owner because the
device SHOWS it, never because a directory lists it. So the published list contains only
the devices the owner has taken away, which the owner is deliberately telling the world.

Design mirrors its two shipped siblings on purpose:
  - `epoch` is the ONLY thing that orders two records (shared/keystate.epoch_of's reasoning:
    a wall clock cannot order two decisions made in the same second, and a clock corrected
    backwards makes the newer record look older — which is exactly the moment revocation
    matters, an owner disowning two devices after a theft). `ts` breaks a tie at most.
  - Monotonicity is the RESOLVER's job (agent/trust.pin_ownerstate), never the verifier's:
    the verifier has no pinned state to compare against, and a verifier that silently
    answered "invalid" for "older than what you hold" would conflate forgery with staleness.
  - INTEGER `ts`/`epoch`, enforced at the MINT point: Python's float repr is not
    reproducible cross-language, so a float here
    would be signed bytes only Python can verify.

Pure standard library (+ shared/crypto). Curve-agnostic via `crypto.verify`, so a P-256
(Secure Enclave / WebAuthn) owner root works wherever the optional `cryptography` backend
exists and degrades to False — never an exception — where it does not.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM: the bytes every implementation of this protocol must reproduce --
# canonical JSON, did:key, the signed payloads. This file's home is the `agent-seam`
# repository (MIT). Muretai core carries a verbatim copy, vendored at a pinned commit
# (shared/VENDOR.json there) inside a tree that is otherwise AGPL-3.0-or-later. A change is
# made in agent-seam and re-vendored; a copy edited in place is a drift its digests report.

from __future__ import annotations

import base64
from typing import Any, Callable

from shared import crypto

OWNERSTATE_TYP = "muretai/ownerstate/1"

#: Sanity ceiling on `epoch`, shared with shared/keystate.MAX_EPOCH's reasoning: it must fit
#: SQLite's INTEGER (a larger one raised an uncaught OverflowError inside the pin's binder),
#: and an owner revokes devices a handful of times in a lifetime.
MAX_EPOCH = 2 ** 31 - 1

#: How many device DIDs one OwnerState may NAME in `revoked`. Bounded at the MINT point, not
#: at the call sites — the invariant is a property of the RECORD ("an OwnerState is small
#: enough to publish, fetch and pin unconditionally"), and one producer that forgets is one
#: producer whose record the relay answers 413 to, at the one moment the owner needs it out.
#:
#: 64 is generous by construction rather than by guess: it is a device a year for a working
#: lifetime, and at ~62 bytes per did:key the full list is ~4 KiB — comfortably inside the
#: relay's 64 KiB per-record cap (`relay.MAX_CARD_BYTES`) even with a future `approvers`
#: field beside it.
#:
#: WHAT FALLS OFF, stated honestly (the same shape as keystate.MAX_REVOKED_OPS): the mint
#: keeps the LAST `MAX_REVOKED_DEVICES` entries of the deduplicated input and drops the rest,
#: so the most recently supplied revocations survive. A revocation that falls off is no longer
#: enforced by a receiver holding only this record — the disowned device becomes acceptable
#: again. That is why the cap is set far above any plausible device count, and why a tool that
#: MINTS one of these must warn loudly as the list approaches it: the correct answer at that
#: point is a new owner key, which invalidates every old binding at once, not a longer list.
#: An implementation that consumes these records inherits the same rule — a revocation list is
#: a bounded artifact, so absence from it is not proof that a device was never disowned.
MAX_REVOKED_DEVICES = 64

#: THE SIGNED FIELD LIST, as a module constant, because this record is designed to GROW — a
#: later version may add a field (an `approvers` list and a co-signature over it is the shape
#: already reserved by the size cap above). Two rules here make that possible without
#: invalidating a single record minted today:
#:   1. `_payload` covers exactly the declared fields THAT THE RECORD CARRIES, so appending a
#:      name to this tuple leaves an older record's signed bytes unchanged (it carries no
#:      such key) while covering the new field completely on every record that does.
#:   2. `verify_ownerstate` IGNORES unknown top-level keys, so a record minted by a newer
#:      publisher still verifies here on its declared fields (the T99 `chain` precedent: a
#:      sibling that rides alongside the signature is trusted by nobody and breaks nobody).
#: Neither rule weakens the signature: adding, removing or altering ANY declared field a
#: record carries changes the payload bytes and the signature fails.
_SIGNED_FIELDS = ("typ", "rootDid", "epoch", "revoked", "ts")


def _payload(fields: dict[str, Any]) -> bytes:
    """Canonical bytes the OWNER signs = the declared signed fields this record carries.

    `.get()`, never `[]` — the lesson recorded in shared/keystate._payload, which this
    module would otherwise repeat verbatim: a record MISSING a field is untrusted input, not
    a programming error, and indexing raised KeyError out of a verifier documented as total,
    through `relay._do_blind_dir_store`, and into the relay's socket handler (dropped
    connection + a traceback, from an unauthenticated POST). Here `POST /ownerstate` reaches
    this line the same way, so the same rule holds.

    `k in fields` is what makes the record EXTENSIBLE (see `_SIGNED_FIELDS`); it costs
    nothing in strictness, because a well-formedness check in `verify_ownerstate` already
    requires every field declared TODAY to be present and correctly typed."""
    return crypto.canonical({k: fields.get(k) for k in _SIGNED_FIELDS if k in fields})


def normalize_revoked(revoked: Any) -> list[str]:
    """The canonical `revoked` list: de-duplicated, BOUNDED, then sorted.

    Order of operations matters. De-duplication runs over the caller's order so "most
    recently supplied" is meaningful, the bound then keeps that TAIL (the newest
    revocations survive an overflow — see MAX_REVOKED_DEVICES), and only then is the
    result sorted, because the wire form must be canonical: two owners who revoked the
    same devices in a different order must mint the same bytes, and a verifier can then
    require the canonical form rather than accepting a re-ordered replay as a new record.

    Total on junk input: anything that is not a list of non-empty strings yields []."""
    if not isinstance(revoked, list):
        return []
    seen: list[str] = []
    for d in revoked:
        if isinstance(d, str) and d and d not in seen:
            seen.append(d)
    return sorted(seen[-MAX_REVOKED_DEVICES:])


def _require_int(value: Any, field: str) -> int:
    """The integer rule, ENFORCED at mint time (mirrors keybinding._require_int). `bool` is
    an `int` subtype in Python and would canonicalize as true/false; a float's repr is not
    reproducible outside Python. Either one signed here is an artifact no other language can
    verify. Raise, never coerce — a coercion would change the signed bytes under the caller
    (the 2026-07-17 message-timestamp flip, and keystate's `notBefore: 0.0`)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer (got {type(value).__name__}); "
                         f"float/bool values are not reproducible on the wire")
    return value


def make_ownerstate(root_did: str, *, epoch: int, revoked: list[str] | None,
                    ts: int, root_sign: Callable[[bytes], str]) -> dict:
    """Build a signed OwnerState. `root_sign(bytes) -> base64` is the OWNER key's signer
    (`Identity.sign_bytes` for an Ed25519 owner, or a Secure-Enclave callback for a P-256
    one); the owner's private key never passes through this module.

    `epoch` must advance for each published decision — it is the ONLY anti-rollback signal a
    receiver has. `revoked` is normalized (deduped, bounded, sorted) here, at the mint point,
    so every record on the wire is canonical whatever the caller passed."""
    if not isinstance(root_did, str) or not root_did:
        raise ValueError("rootDid must be a non-empty did:key string")
    fields: dict[str, Any] = {
        "typ": OWNERSTATE_TYP,
        "rootDid": root_did,
        "epoch": _require_int(epoch, "epoch"),
        "revoked": normalize_revoked(revoked or []),
        "ts": _require_int(ts, "ts"),
    }
    if not 0 <= fields["epoch"] <= MAX_EPOCH:
        raise ValueError(f"epoch must be between 0 and {MAX_EPOCH}")
    fields["sig"] = root_sign(_payload(fields))
    return fields


def _well_formed(rec: Any) -> bool:
    """Structural checks, all of them cheap and none of them cryptographic. Mirrors
    guardianset._well_formed, including its CANONICAL-FORM requirement: `revoked` must
    already be de-duplicated and sorted, so a re-ordered or padded copy of a genuine record
    is refused rather than quietly normalized into a second valid spelling of it."""
    if not isinstance(rec, dict):
        return False
    if rec.get("typ") != OWNERSTATE_TYP:
        return False
    root = rec.get("rootDid")
    if not isinstance(root, str) or not root:
        return False
    ep, ts = rec.get("epoch"), rec.get("ts")
    if isinstance(ep, bool) or not isinstance(ep, int) or not 0 <= ep <= MAX_EPOCH:
        return False
    # INTEGER ts on the VERIFY side too, unlike keystate — which must keep accepting the
    # floats older nodes already signed. This record type has no legacy: nothing has ever
    # published one, so the strict rule costs nobody and keeps the artifact reproducible in
    # every client from its first day.
    if isinstance(ts, bool) or not isinstance(ts, int):
        return False
    revoked = rec.get("revoked")
    if not isinstance(revoked, list) or len(revoked) > MAX_REVOKED_DEVICES:
        return False
    if any(not isinstance(d, str) or not d for d in revoked):
        return False
    return revoked == sorted(set(revoked))


def verify_ownerstate(rec: Any, expected_root_did: str | None = None) -> bool:
    """Verify an OwnerState (safe on untrusted input, NEVER raises):
      - well-formed, right `typ`, integer `epoch`/`ts`, canonical bounded `revoked`;
      - the signature covers exactly the declared signed fields the record carries;
      - the signer IS `rootDid` (a record is only ever authority over its own account);
      - `expected_root_did` matches when given (anti-substitution).
    Returns False on any failure — including a P-256 owner root on a node without the
    optional `cryptography` backend, which `crypto.verify` answers False for rather than
    raising (principle 1: a stdlib-only node degrades, it does not crash).

    UNKNOWN TOP-LEVEL KEYS ARE IGNORED, deliberately — see `_SIGNED_FIELDS`.

    Does NOT judge whether this record is NEWER than one you already hold. That is the
    resolver's question (`agent/trust.pin_ownerstate`), because only the resolver holds the
    pinned epoch — the same split shipped/keystate documents, and the reason a stale record
    is reported as "not adopted" rather than as "invalid"."""
    if not _well_formed(rec):
        return False
    root = rec["rootDid"]
    if expected_root_did is not None and root != expected_root_did:
        return False
    try:
        sig = base64.b64decode(rec["sig"])
    except Exception:
        return False
    return crypto.verify(root, sig, _payload(rec))


def epoch_of(rec: Any) -> int | None:
    """The DECISION COUNT an OwnerState-shaped record carries, or None if it carries none.

    Mirrors shared/keystate.epoch_of exactly (including its type strictness), so the relay
    slot, the pin and any resolver cannot drift on what "newer" means. Total on untrusted
    input: a non-dict, or a missing / non-int / bool / out-of-range epoch, all answer None,
    which callers read as "no ordering here" and fall back to whatever they did before."""
    if not isinstance(rec, dict):
        return None
    ep = rec.get("epoch")
    if not isinstance(ep, int) or isinstance(ep, bool) or not 0 <= ep <= MAX_EPOCH:
        return None
    return ep


def is_revoked(rec: Any, device_did: str) -> bool:
    """Does this OwnerState disown `device_did`? Total on untrusted input (a non-dict, a
    missing or malformed list, an empty DID all answer False).

    The CALLER must have verified the record (`verify_ownerstate`) and must have decided it
    is the one in force for that owner — this function reads a list, it does not judge
    authority. Kept separate for exactly that reason: the gate asks this question about a
    record it PINNED, never about one that arrived with the message."""
    if not isinstance(rec, dict) or not device_did:
        return False
    revoked = rec.get("revoked")
    return isinstance(revoked, list) and device_did in revoked
