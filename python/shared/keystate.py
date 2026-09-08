"""
shared/keystate.py
KeyState — a root-signed, monotonic-epoch delegation of a ROTATABLE operational
signing sub-key (and X25519 encryption sub-key) under a stable did:key controller.

This is the crypto core of key rotation + revocation (Increment 0 of the KeyState
design). It GENERALIZES shared/keybinding.make_device_binding (root -> device) by
adding: a monotonic `epoch`, a validity window, KERI-style PRE-ROTATION commitments
(`opNextHash` = a hash of the NEXT op key, revealed only at the next rotation), and an
op-key revocation list (`revokedOps`). The existing did:key is re-roled — with ZERO
wire change — as a long-term COLD controller / genesis root that signs the KeyState;
day-to-day wire signing is done by the delegated hot op-key, so a stolen op-key is
revoked by a higher-epoch KeyState while the DID (and every WoT edge keyed on it) stays
stable. See docs/SPECIFICATION.md and the plan.

Security properties this core provides (verified by test_l_keystate.py):
  - A party holding ONLY a hot op-key cannot mint a KeyState (that needs the cold root).
  - KERI pre-rotation: a rotation whose new opDid does not hash to the PRIOR KeyState's
    `opNextHash` is rejected — so a thief who somehow forced a rotation cannot choose the
    next key; only the owner (who holds the pre-committed next seed) can advance.
  - Monotonic epoch is the anti-rollback / anti-downgrade signal (a verifier pins the
    highest epoch it has seen and refuses a lower one).

Honest scope (Increment 0/1): this verifier accepts GENESIS-rooted KeyStates only
(`rootKey` == the DID's own key — no root rotation yet). Root pre-rotation (rootKey !=
the DID key, verified via a root lineage walk) is Increment 3. And because the DID *is*
the genesis key, theft of the genesis/root key is NOT revocable against peers who never
pinned a KeyState — that case is handled by social recovery / migration to a new DID
(later increments), never claimed here.

Pure standard library (+ shared/crypto). A P-256/Secure-Enclave cold root additionally
needs the optional `cryptography` backend (crypto.P256_AVAILABLE); an Ed25519 root works
in the zero-dependency core. Curve-agnostic verification degrades to False (never raises)
when a P-256 root is used without the backend — mirrors shared/keybinding.py.
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
from typing import Any, Callable

from shared import crypto

KEYSTATE_TYP = "muretai/keystate/1"

# Every field the ROOT signs, in a fixed list so the signed payload is stable and any
# later-increment field (enc/guardians/root-rotation) is covered by the signature from
# day one. crypto.canonical sorts keys, so order here is only for readability.
#: Sanity ceilings, NOT security controls — they bound attacker-driven work and keep a hostile
#: record from reaching a place that cannot represent it. `epoch` fits SQLite's INTEGER (a larger
#: one raised an uncaught OverflowError in the pin), and a root chain is a lifetime handful of
#: rotations, so a long one is padding rather than history.
MAX_EPOCH = 2 ** 31 - 1
MAX_ROOT_LINEAGE = 16
#: How many prior KeyStates a `keystateChain` may carry (T99). A chain is attacker-supplied and
#: is walked BEFORE any of it is trusted, so it needs a bound that is not "however many they
#: sent". Generous against real use — an identity that has rotated 64 times has rotated more in
#: its life than the whole fleet has to date — and cheap against abuse.
MAX_KEYSTATE_CHAIN = 64
#: Byte budget for a PUBLISHED KeyState record including its `chain` (see `with_chain`). Below the
#: relay's per-record cap (`relay.MAX_CARD_BYTES`, 64 KiB) so the publish cannot come back 413.
#:
#: SIZED, not guessed: a FULL history — `MAX_KEYSTATE_CHAIN` records, the head plus every link back
#: to it — must fit, because the byte trim drops the OLDEST links and a peer pinned before the
#: surviving tail can never be authorized again (`verify_succession` needs every intermediate). The
#: worst-case record is one with every optional field populated (`guardiansHash` from `guardians
#: set`, `encNextHash`) and a full `revokedOps`, ~900 bytes; 64 of those is ~57 KiB. At the previous
#: 56 KiB the trim fired on exactly that identity — measured 2026-08-12 at 57,045 bytes for 62 of
#: the 64 links — so the budget was the binding constraint on how far behind a peer could be. Keep
#: this comfortably above `MAX_KEYSTATE_CHAIN * 900`, and the trim stays the backstop it reads as.
MAX_CHAIN_BYTES = 60 * 1024
#: How many superseded op-keys a KeyState may NAME in `revokedOps`. The most recent ones are kept.
#:
#: This bound is what makes catching up across many rotations possible at all, and the reason is
#: arithmetic, not policy. `revokedOps` used to accumulate one op DID (~62 bytes) per rotation and
#: every link of a published `chain` carries its own copy, so a chain of N records cost O(N**2)
#: bytes. Measured 2026-08-12: at 30 rotations the record was 48 KiB, at 40 it blew the budget and
#: `with_chain` started dropping the OLDEST links — and a peer pinned before the surviving tail can
#: never be authorized again, because `verify_succession` needs every intermediate. The owner's
#: messages were then refused as "signed by a superseded operational key" forever, blaming the one
#: key that was not superseded. Bounding the list makes each record constant-size, so the cost of a
#: chain is linear and a peer can be dozens of rotations behind and still catch up.
#:
#: Nothing is lost that a verifier can otherwise obtain: the published chain names every retired
#: opDid in its own links, and a message signed by a retired key is refused because the pinned
#: KeyState's `opDid` is a different key (`inbox._confirm_op_key`), not because the key appears on
#: a list. `revokedOps` is the belt for a verifier holding ONLY the head record, and the keys that
#: matter there are the recent ones — an op-key retired more than a handful of rotations ago is
#: already unusable against any peer that pinned any newer state.
MAX_REVOKED_OPS = 4

_FIELDS_V1 = (
    "typ", "rootDid", "epoch", "rootKey", "rootNextHash",
    "opDid", "opNextHash", "encPub", "encNextHash",
    "guardiansHash", "revokedOps", "notBefore", "notAfter", "ts",
)
# T142 B2: `encPubPqHash` binds the unsigned sibling `encPubPq` (raw ML-KEM-768
# pub, head only). Old records omit the key and verify against `_FIELDS_V1`.
_FIELDS = _FIELDS_V1 + ("encPubPqHash",)


def commit(did_or_key: str) -> str:
    """The pre-rotation COMMITMENT to a next key: sha256 hex of its did:key string (a
    stable, canonical representation). At the next rotation the owner REVEALS that key
    and a verifier checks commit(revealed) == the prior KeyState's *NextHash. Committing
    to the did:key string (not raw bytes) keeps the reveal unambiguous and curve-agnostic."""
    return hashlib.sha256(did_or_key.encode("utf-8")).hexdigest()


def epoch_of(ks: Any) -> int | None:
    """The ROTATION COUNT a KeyState-shaped record carries, or None if it carries none.

    The one place that answers "how new is this key state?", so a directory, a pin and a
    resolver cannot drift on the definition. `epoch` is the only field with the authority to
    order two KeyStates: it is inside the root-signed payload, strictly incrementing, and
    minted by the owner's own key. `ts` cannot do that job — it is a wall clock truncated to
    whole seconds (`make_keystate` writes `int(ts)`), so two rotations in the same second are
    indistinguishable by it, and a clock corrected backwards makes a genuinely newer state
    look older. That is exactly when rotation matters most: a frightened owner rotating twice
    after a theft.

    Total on untrusted input (never raises): a non-dict, a missing / non-int / bool /
    out-of-range epoch all answer None, which callers read as "no rotation count here" and
    fall back to whatever they did before."""
    if not isinstance(ks, dict):
        return None
    ep = ks.get("epoch")
    if isinstance(ep, float) and ep.is_integer():
        ep = int(ep)
    if not isinstance(ep, int) or isinstance(ep, bool) or not 0 <= ep <= MAX_EPOCH:
        return None
    return ep


def with_chain(ks: dict, history: list[dict], *, max_bytes: int = MAX_CHAIN_BYTES) -> dict:
    """A PUBLISHABLE copy of `ks` carrying its own prior KeyStates as the unsigned sibling
    `chain` (ascending by epoch, this record's own epoch excluded).

    This is the producer half of T99. A peer that missed ONE rotation needs no chain (it holds
    `prev.opNextHash` itself), but a peer that missed two or more cannot authorize the jump
    without the intermediates — and the relay keeps exactly one record per DID, so they can
    never be fetched separately. Two rotations in a row is not an exotic case: it is what an
    owner does when a key is stolen and they are frightened. Without this, the second rotation
    lands in the directory and every peer more than one epoch behind refuses it forever.

    `chain` rides ALONGSIDE the signed fields and is therefore trusted by nobody: every element
    is independently root-signed and `verify_succession` walks the links. Trimmed oldest-first
    to `MAX_KEYSTATE_CHAIN` entries and to `max_bytes` of canonical JSON, because the record has
    to fit the relay's per-record cap; a peer further behind than the surviving tail gets the
    honest `refused` rather than a publish that no relay will take."""
    out = dict(ks)
    out.pop("chain", None)
    here = epoch_of(ks)
    if here is None:
        return out                            # nothing to be newer than: publish it bare
    tail = [e for e in history
            if epoch_of(e) is not None and epoch_of(e) < here]
    tail.sort(key=lambda e: epoch_of(e) or 0)
    tail = tail[-MAX_KEYSTATE_CHAIN:]
    tail = [_chain_link(e) for e in tail]
    while tail:
        out["chain"] = tail
        if len(crypto.canonical(out)) <= max_bytes:
            return out
        tail = tail[1:]                       # drop the oldest link and try again
    out.pop("chain", None)
    return out


def _chain_link(ks: dict) -> dict:
    """A published historical link: independently signed, without the raw ML-KEM
    public key. The signed `encPubPqHash` stays; only the live head carries
    `encPubPq` — a published card has a size budget, and the hash is what a verifier
    needs."""
    link = dict(ks)
    link.pop("encPubPq", None)
    link.pop("chain", None)
    return link


def pq_pub_hash(enc_pub_pq_hex: str) -> str:
    """sha256 of the raw ML-KEM-768 public key, 64 hex. Empty input -> empty hash."""
    if not enc_pub_pq_hex:
        return ""
    try:
        raw = bytes.fromhex(enc_pub_pq_hex)
    except Exception:
        return ""
    if len(raw) != 1184:
        return ""
    return hashlib.sha256(raw).hexdigest()


def attach_enc_pub_pq(ks: dict, enc_pub_pq_hex: str) -> dict:
    """Put the unsigned sibling on a freshly minted KeyState. No-op if the hash
    does not match the signed `encPubPqHash` (never publish an unbound key)."""
    if not enc_pub_pq_hex:
        ks.pop("encPubPq", None)
        return ks
    if pq_pub_hash(enc_pub_pq_hex) != (ks.get("encPubPqHash") or ""):
        ks.pop("encPubPq", None)
        return ks
    ks["encPubPq"] = enc_pub_pq_hex
    return ks


def verified_enc_pub_pq(ks: dict | None) -> str:
    """The ML-KEM-768 pub to seal to, or '' if missing/unbound/wrong hash.

    Fail closed: a present key whose hash does not match the signed binding is
    ignored (v1 box), never used."""
    if not isinstance(ks, dict):
        return ""
    raw = ks.get("encPubPq") or ""
    expected = ks.get("encPubPqHash") or ""
    if not raw or not expected:
        return ""
    if pq_pub_hash(raw) != expected:
        return ""
    return raw


def _did_pub_hex(did: str) -> str | None:
    """The hex of the raw public key a did:key encodes (ed25519 32-byte, or p256 33-byte
    compressed), or None if it can't be resolved. Never raises."""
    try:
        _curve, pub = crypto.key_from_did(did)
        return pub.hex()
    except Exception:
        return None


def _verify_pub_hex(pub_hex: str, sig: bytes, msg: bytes) -> bool:
    """Verify a signature against a raw public key given as hex. Reconstructs a
    did:key (multicodec from the reconstructed DID, not from length-dispatch in
    this module) and defers to crypto.verify. Never raises; False if p256 without
    the backend."""
    try:
        raw = bytes.fromhex(pub_hex)
    except Exception:
        return False
    return crypto.verify_raw(raw, sig, msg)


def _signed_names(fields: dict[str, Any]) -> tuple[str, ...]:
    """Which signed field list this record was minted under.

    A new field cannot be added to every historical KeyState: the signature
    covers the list that was signed. Presence of `encPubPqHash` (even empty)
    selects the T142 list; absence is a pre-B2 record. An attacker who ADDS
    the field to an old record changes the payload and the old sig fails.
    An attacker who STRIPS it from a new record verifies against V1 bytes
    the signer never produced, so that also fails."""
    if "encPubPqHash" in fields:
        return _FIELDS
    return _FIELDS_V1


def _payload(fields: dict[str, Any]) -> bytes:
    """Canonical bytes the ROOT signs = every field except `sig` (reuses the L2 encoder).

    `.get()`, not `[]`. A record MISSING a field is untrusted input, not a programming error, and
    indexing raised KeyError out of `verify_keystate` — whose own docstring promises "safe on
    untrusted input, never raises" and which `relay._do_blind_dir_store` calls behind a comment
    asserting the verifiers are "total by contract". Both were false: an unauthenticated
    `POST /keystate` carrying `{typ, rootDid, epoch, rootKey}` and a junk sig reached this line
    and took the exception all the way out to the relay's socket handler — client sees a dropped
    connection, relay logs a traceback (measured 2026-08-12).

    A missing field simply canonicalizes as None and fails the signature check, which is the
    correct answer: the signer signed a full field set, so a truncated record cannot match."""
    return crypto.canonical({k: fields.get(k) for k in _signed_names(fields)})


def make_keystate(root_did: str, *, epoch: int, op_did: str, op_next_hash: str,
                  ts: float, root_sign: Callable[[bytes], str],
                  root_key: str | None = None, root_next_hash: str = "",
                  enc_pub: str = "", enc_next_hash: str = "",
                  enc_pub_pq_hash: str = "",
                  guardians_hash: str = "", revoked_ops: list[str] | None = None,
                  not_before: float = 0.0, not_after: float | None = None) -> dict:
    """Build a signed KeyState. `root_sign(bytes)->base64` is the COLD root key's signer
    (Identity.sign_bytes for an Ed25519 root, or a Secure-Enclave callback for a P-256
    root); the root private key never passes through this module.

    `op_next_hash` = commit(next op did:key) pre-commits the NEXT rotation (KERI). At the
    genesis/armed epoch pass op_did == root_did. `root_key` defaults to the DID's own key
    (a genesis KeyState with no root rotation)."""
    if root_key is None:
        root_key = _did_pub_hex(root_did) or ""
    fields: dict[str, Any] = {
        "typ": KEYSTATE_TYP, "rootDid": root_did, "epoch": int(epoch),
        "rootKey": root_key, "rootNextHash": root_next_hash,
        "opDid": op_did, "opNextHash": op_next_hash,
        "encPub": enc_pub, "encNextHash": enc_next_hash,
        # Bounded at the MINT point, not at the call sites, because the invariant it protects
        # is a property of the RECORD ("every KeyState is constant-size, so a chain of them is
        # linear"), and one producer that forgets re-introduces the O(N**2) chain that made a
        # far-behind peer unrecoverable. The tail is kept: the newest burns are the useful ones.
        "guardiansHash": guardians_hash,
        "revokedOps": list(revoked_ops or [])[-MAX_REVOKED_OPS:],
        # INTEGER epoch seconds, not float. `not_before` defaults to 0.0, so the old
        # `float()` cast wrote a literal `0.0` into the signed bytes — and Python's
        # `0.0` is JavaScript's `0`, which makes every KeyState unverifiable outside
        # Python 100% of the time. Same defect and same remedy as the 2026-07-17
        # message-timestamp flip: mint the reproducible type, never coerce on verify.
        # `notAfter` is passed through as given (None or a caller value) and `ts` is
        # int for the same reason. See vectors/wire_vectors.json `timestampNote` —
        # "Never coerce inside a payload builder".
        "notBefore": int(not_before), "notAfter": not_after, "ts": int(ts),
    }
    # T142 B2, ONLY when a PQ key is actually being bound. `_signed_names` selects the
    # field list by PRESENCE, so writing the key unconditionally (even as "") moved every
    # freshly minted record onto the 15-field payload — and a verifier that predates B2
    # recomputes 14 fields, gets different bytes, and rejects the signature. That is not a
    # cosmetic mismatch: an unverifiable KeyState means the op-key delegation cannot be
    # resolved, so the receiver falls back to the root DID while the sender signed with the
    # op-key, and every message from that peer dies as -32001. Measured, not reasoned: a
    # verifier built before this field rejects every record a tree with it mints, while that
    # same tree accepts both shapes — the break is one-way, new-record-to-old-verifier.
    # Omitting the key when there is nothing to bind keeps a node without it byte-identical to
    # every release before this one. Emitting it is a FLAG DAY: every verifier that must accept
    # the record has to understand the field FIRST.
    if enc_pub_pq_hash:
        fields["encPubPqHash"] = enc_pub_pq_hash
    fields["sig"] = root_sign(_payload(fields))
    return fields


def verify_keystate(ks: dict, expected_root_did: str | None = None,
                    *, now: float | None = None, lineage: list | None = None) -> bool:
    """Verify a KeyState (safe on untrusted input, never raises):
      - well-formed with the right `typ` and an int epoch >= 0;
      - GENESIS-rooted: `rootKey` equals the DID's own key (root rotation is Increment 3);
      - the ROOT signature covers exactly the signed fields;
      - `expected_root_did` matches (anti-substitution), when given;
      - within the validity window when `now` is given.
    Returns False on any failure. Does NOT judge epoch monotonicity vs a pinned state —
    that anti-downgrade check belongs to the resolver (it needs the pinned epoch)."""
    try:
        if ks.get("typ") != KEYSTATE_TYP:
            return False
        root_did = ks["rootDid"]
        epoch = ks["epoch"]
        # An UPPER bound as well as a lower one. Unbounded, `epoch` is not just a lockout
        # weapon (see trust.pin_key_state) — 2**70 sails through here and then raises an
        # UNCAUGHT OverflowError inside SQLite's binder, and keydir.pull_and_pin has no guard,
        # so an operator directory pull crashes on a record any stranger can publish.
        # Whole-number floats (0.0, 1.0) are a legacy mint: older make_keystate wrote
        # JSON `0.0`, json.loads gives float, and isinstance(epoch, int) then dropped
        # a genuine root-signed record. Keep the original value in the signed payload
        # (canonical `0.0` ≠ `0`) and only use the int for the bounds check.
        if isinstance(epoch, float) and epoch.is_integer():
            epoch_n: int | float = int(epoch)
        else:
            epoch_n = epoch
        if (not isinstance(epoch_n, int) or isinstance(epoch_n, bool)
                or not 0 <= epoch_n <= MAX_EPOCH):
            return False
        if expected_root_did is not None and root_did != expected_root_did:
            return False
        # Resolve the DID's genesis key (the epoch-0 root).
        did_key = _did_pub_hex(root_did)
        if did_key is None:
            return False
        sig = base64.b64decode(ks["sig"])
    except Exception:
        return False
    # Authorize the rootKey. Common case: rootKey == the DID's own key (genesis root, no root
    # rotation). Root-rotated case (#5): rootKey != the DID key is accepted ONLY if `lineage`
    # proves it — a chain of root-rotation KeyStates where each new rootKey is the reveal of the
    # prior KeyState's rootNextHash, chaining back to the genesis DID key.
    if ks.get("rootKey") != did_key:
        if not _verify_root_lineage(root_did, ks, lineage):
            return False
    if not _verify_pub_hex(ks["rootKey"], sig, _payload(ks)):
        return False
    if now is not None:
        nb = ks.get("notBefore") or 0.0
        na = ks.get("notAfter")
        if now < nb:
            return False
        if na is not None and now > na:
            return False
    return True


def op_is_revoked(ks: dict, op_did: str) -> bool:
    """True if `op_did` is in this KeyState's revocation list (a burned op-key)."""
    return op_did in (ks.get("revokedOps") or [])


def op_dids_for_envelope(root_did: str, inline_keystate: dict | None,
                         pinned_keystate: dict | None, *, now: float) -> list[str]:
    """Bound candidate signing DIDs for THIS message, in try order.

    Inbox.verify tries each until the envelope signature matches. A single guess is not
    enough, and the failure is silent: a VERIFYING inline KeyState whose `opDid` is the root
    (an armed or legacy-genesis record) makes `op_did_for_envelope` answer the root, while the
    sender signed with the operating key. Nothing is malformed and no signature is forged —
    every message from that peer simply dies as -32001. Two peers can sit on opposite sides of
    that for as long as one of them keeps attaching the armed record.

    Candidates are only keys bound to `root_did`:
      1. a verifying inline KeyState that names a real op (not the root),
         unless the pin burned it;
      2. the pinned op (a prior verifying delegation), unless burned;
      3. the root itself (un-rotated default).

    An armed inline (`opDid == root`) does not hide a pinned real op, and
    a non-verifying inline does not add an unbound key. Pin *adoption*
    stays strictly-greater (`resolve_op_did` / `trust.pin_key_state`).
    Outbox reply-verify keeps `resolve_op_did` (no supersession check), which is why a
    host can hold a member record whose signature no longer matches the member's current
    key without either side noticing."""
    ks = inline_keystate
    pinned = pinned_keystate
    out: list[str] = []

    def _add(did: str) -> None:
        if did and did not in out:
            if isinstance(pinned, dict) and op_is_revoked(pinned, did) and did != (
                    pinned.get("opDid") or root_did):
                return
            out.append(did)

    if isinstance(ks, dict) and verify_keystate(ks, expected_root_did=root_did, now=now):
        op = ks.get("opDid") or ""
        if op and op != root_did:
            _add(op)
    if isinstance(pinned, dict):
        _add(pinned.get("opDid") or root_did)
    _add(root_did)
    return out or [root_did]


def op_did_for_envelope(root_did: str, inline_keystate: dict | None,
                        pinned_keystate: dict | None, *, now: float) -> str:
    """First candidate from `op_dids_for_envelope` (Inbox tries the full list)."""
    return op_dids_for_envelope(
        root_did, inline_keystate, pinned_keystate, now=now)[0]


def resolve_op_did(root_did: str, inline_keystate: dict | None,
                   pinned_keystate: dict | None, *, now: float) -> str:
    """The current OPERATIONAL signing DID for `root_did` — the key we treat
    as current for pin/store. Adopts a valid, non-downgrade inline KeyState over a
    pinned one, else the pinned opDid, else the root itself (an un-rotated signer signs
    with its root: the byte-identical default). Pure — the caller does any pinning.

    Which key signed THIS message is `op_did_for_envelope` (inbox verify). This
    function stays the pin-shaped rule: an equal-epoch fork cannot displace the
    pin. The SYNCHRONOUS reply verify (agent/outbox) still uses this, because
    that path has no post-signature supersession check — handing it the inline
    op of a same-epoch fork would accept a burned-key reply."""
    ks, pinned = inline_keystate, pinned_keystate
    authoritative = pinned_keystate       # what WE pulled and verified; its burn list is trusted
    if ks and verify_keystate(ks, expected_root_did=root_did, now=now):
        # STRICTLY greater, not >=. An inline KeyState at the SAME epoch as the pin is not an
        # upgrade — it is a fork, and adopting it let a same-epoch state with a DIFFERENT opDid
        # displace the one we pinned, resolving to a key we had already burned. (Measured
        # 2026-08-11: pinned epoch 1 -> op1; a replayed epoch-1 state naming op0 resolved to
        # op0.) If the content is identical, `>` and `>=` are the same no-op; if it differs,
        # keeping what we verified is the only safe answer. trust.pin_key_state has always
        # required strictly-greater — this brings the in-memory resolve in line with the store.
        # The ROOT RATCHET, mirrored from trust.pin_key_state (T96). A higher epoch is not
        # enough: `rootKey` is what authorizes a KeyState, and the genesis key authorizes one
        # at ANY epoch. So an inline state signed by a STOLEN GENESIS key out-epochs an
        # already-pinned root-ROTATED state, and this resolve — which never consults the
        # store — would hand back the thief's op key even though pin_key_state refuses it.
        # No lineage travels inline (there is no wire field for one), so the rule here is the
        # strict half: an inline state may not CHANGE the root key, only advance the epoch
        # under the same one. A genuine root rotation arrives through the pull + pin path.
        same_root = pinned is None or ks.get("rootKey") == pinned.get("rootKey")
        if pinned is None or (same_root
                              and int(ks.get("epoch", -1)) > int(pinned.get("epoch", -1))):
            pinned = ks
    op = (pinned.get("opDid") or root_did) if pinned else root_did
    # A burned key is never the answer. revokedOps is written by identity.rotate_op (it appends
    # the outgoing opDid) and was, until now, dead data — nothing consulted it. It is mostly
    # redundant with inbox._confirm_op_key's supersession check, and deliberately kept anyway:
    # that check does not run on the reply-verify path an OUTBOX takes (it resolves through
    # here with no pull and no supersession test), and a burn list is the only thing
    # that catches an owner who cycles back to a previously-retired op key.
    # Falling back to the authoritative opDid rather than raising keeps this function pure and
    # total; the caller's signature check then fails, which is the refusal we want.
    if authoritative is not None and op_is_revoked(authoritative, op):
        return authoritative.get("opDid") or root_did
    if pinned is not None and op_is_revoked(pinned, op):
        return root_did                   # a state that burns its OWN opDid authorizes nobody
    return op


def verify_rotation(prev: dict, new: dict, expected_root_did: str | None = None,
                    *, now: float | None = None) -> bool:
    """Verify that `new` is a valid DIRECT successor (epoch+1) of `prev` under the same
    root: both KeyStates verify, the epoch advances by exactly one, and the KERI
    pre-rotation binds — commit(new.opDid) == prev.opNextHash — so only the holder of the
    pre-committed next seed could have produced `new`. A resolver jumping more than one
    epoch walks this adjacently. Never raises."""
    try:
        if not verify_keystate(prev, expected_root_did):
            return False
        if not verify_keystate(new, expected_root_did or prev["rootDid"], now=now):
            return False
        if new["rootDid"] != prev["rootDid"]:
            return False
        if new["epoch"] != prev["epoch"] + 1:
            return False
        if not prev.get("opNextHash"):
            return False                      # prev did not pre-commit -> cannot rotate
        if commit(new["opDid"]) != prev["opNextHash"]:
            return False                      # KERI pre-rotation reveal mismatch
    except Exception:
        return False
    return True


def verify_succession(prev: dict, new: dict, chain: list | None = None,
                      expected_root_did: str | None = None,
                      *, now: float | None = None) -> bool:
    """Is `new` an authorized successor of the ALREADY-PINNED `prev`, across any epoch gap?

    This is the caller `verify_rotation` never had (T99). Pre-rotation could not be enforced
    because enforcing it needs adjacency, a peer offline across two rotations legitimately sees
    a larger jump, and the relay keeps only the newest KeyState so the intermediates could not be
    fetched. Enforcing it only when adjacent would have been theatre — an attacker names
    epoch+2 and skips the check.

    `chain` is the missing evidence, and it is not a new object type: it is this identity's own
    prior KeyStates, ascending. From it BOTH proofs fall out — the root lineage is the
    subsequence where `rootKey` changes, and the op chain is every adjacent pair.

    Unsigned, and safe unsigned: every element carries its own root signature, and every link is
    checked against its predecessor here. Adding, removing or reordering elements either breaks
    a link or produces a chain that fails to reach `new`.

    The rule:
        gap == 1  -> verify_rotation(prev, new)      # no chain needed; we HOLD prev
        gap  > 1  -> the chain must supply exactly the intermediates, each link verified
        gap  > 1 with no usable chain -> refuse

    Adjacency needs no chain at all because the verifier already holds `prev.opNextHash` — that
    asymmetry is what makes the strict rule affordable. Never raises.
    """
    try:
        gap = int(new["epoch"]) - int(prev["epoch"])
        if gap <= 0:
            return False                      # not a successor; anti-downgrade is the caller's
        if gap == 1:
            return verify_rotation(prev, new, expected_root_did, now=now)
        if not chain or not isinstance(chain, list) or len(chain) > MAX_KEYSTATE_CHAIN:
            return False
        # Take exactly the links between prev and new, in order. Anything else in the chain is
        # ignored rather than trusted — a caller may legitimately send its whole history.
        want = list(range(int(prev["epoch"]) + 1, int(new["epoch"])))
        by_epoch: dict = {}
        for e in chain:
            if not isinstance(e, dict):
                return False
            ep = e.get("epoch")
            if isinstance(ep, int) and not isinstance(ep, bool) and ep in want:
                if ep in by_epoch:
                    return False              # two different states for one epoch: a fork
                by_epoch[ep] = e
        if len(by_epoch) != len(want):
            return False                      # a hole in the chain proves nothing
        step = prev
        for ep in want:
            nxt = by_epoch[ep]
            if not verify_rotation(step, nxt, expected_root_did, now=now):
                return False
            step = nxt
        return verify_rotation(step, new, expected_root_did, now=now)
    except Exception:
        return False


# ---------------------------------------------------------------- root pre-rotation (#5)
def _verify_root_lineage(root_did: str, target: dict, lineage: list | None) -> bool:
    """Prove `target`'s rootKey (which is NOT the DID's genesis key) is authorized: `lineage`
    is the ordered chain of root KeyStates [genesis, root-rot_1, …] where genesis.rootKey is the
    DID key, each subsequent rootKey is the KERI reveal of the prior KeyState's rootNextHash, the
    epoch is monotonic, every entry is signed by its OWN rootKey, and the last rootKey == the
    target's. So a compromised-but-held root out-rotates to a pre-committed successor a thief
    (holding only the current root) cannot forge. Never raises."""
    if not lineage or len(lineage) > MAX_ROOT_LINEAGE:
        return False
    try:
        did_key = _did_pub_hex(root_did)
        seen: set = set()
        prev = None
        for ks in lineage:
            if ks.get("typ") != KEYSTATE_TYP or ks.get("rootDid") != root_did:
                return False
            # A link must REVEAL A NEW key. Nothing required one to actually change the root,
            # so a chain of links all re-stating the same rootKey verified — free length, and
            # free "depth" for any scheme that later counts it. A repeat is also a cycle.
            rk = ks.get("rootKey")
            if not isinstance(rk, str) or not rk or rk in seen:
                return False
            seen.add(rk)
            sig = base64.b64decode(ks["sig"])
            if not _verify_pub_hex(rk, sig, _payload(ks)):
                return False                  # each link is self-consistently root-signed
            if prev is None:
                if rk != did_key:
                    return False              # the chain must start at the genesis DID key
            else:
                if not prev.get("rootNextHash"):
                    return False
                this_root_did = crypto.did_from_public(bytes.fromhex(ks["rootKey"]))
                if commit(this_root_did) != prev["rootNextHash"]:
                    return False              # reveal must match the prior commitment
                if int(ks["epoch"]) <= int(prev["epoch"]):
                    return False              # monotonic
            prev = ks
        return prev is not None and prev["rootKey"] == target.get("rootKey")
    except Exception:
        return False


def make_root_rotation(prev: dict, new_root_seed: bytes, next_root_next_hash: str,
                       ts: float, *, op_did: str | None = None,
                       op_next_hash: str | None = None, enc_pub: str = "",
                       enc_next_hash: str = "", guardians_hash: str = "",
                       revoked_ops: list[str] | None = None) -> dict:
    """Out-rotate the ROOT: reveal the pre-committed next root (`new_root_seed`, whose did:key
    must match `prev`'s rootNextHash) and sign a higher-epoch KeyState under it, committing to a
    further next root (`next_root_next_hash`). The op-key is carried unchanged by default (a root
    rotation need not rotate the op-key). The DID is unchanged; a verifier accepts the new rootKey
    via the lineage (`verify_keystate(..., lineage=[genesis, …, this])`)."""
    new_root_pub = crypto.ed25519_public_from_seed(new_root_seed)
    new_root_hex = new_root_pub.hex()
    new_root_did = crypto.did_from_public(new_root_pub)
    if commit(new_root_did) != prev.get("rootNextHash"):
        raise ValueError("pre-rotation reveal does not match the prior rootNextHash")

    def _sign(msg: bytes) -> str:
        return base64.b64encode(crypto.ed25519_sign(new_root_seed, msg)).decode("ascii")

    return make_keystate(
        prev["rootDid"], epoch=int(prev["epoch"]) + 1,
        op_did=op_did if op_did is not None else prev["opDid"],
        op_next_hash=op_next_hash if op_next_hash is not None else prev["opNextHash"],
        root_key=new_root_hex, root_next_hash=next_root_next_hash,
        enc_pub=enc_pub, enc_next_hash=enc_next_hash,
        enc_pub_pq_hash=prev.get("encPubPqHash") or "",
        guardians_hash=guardians_hash,
        revoked_ops=revoked_ops, ts=ts, root_sign=_sign)
