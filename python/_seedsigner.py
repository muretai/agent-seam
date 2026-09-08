# SPDX-License-Identifier: MIT
"""python/_seedsigner.py — a seed-only signer for the tests that travelled from core.

Core's tests sign with `agent.identity.Identity`, the node's identity (key files, op keys,
enrolment). Nothing in a WIRE test needs any of that: it needs a DID and a way to sign bytes
with the seed behind it. This is the same stand-in core's single-file reference door ships
(`examples/agent_entry_reference.py::_SeedSigner`), minus the key-file persistence.
"""
from __future__ import annotations

import base64

from shared import crypto


class _SeedSigner:
    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self.public = crypto.ed25519_public_from_seed(seed)
        self.did = crypto.did_from_public(self.public)

    def sign(self, *, to_did: str, message_id: str, context_id: str | None,
             timestamp: float, text: str) -> str:
        return crypto.sign_envelope(self._seed, self.did, to_did, message_id,
                                    context_id, timestamp, text)

    def sign_bytes(self, message: bytes) -> str:
        return base64.b64encode(crypto.ed25519_sign(self._seed, message)).decode("ascii")
