"""
test_gateway.py — the canonical public HP base (shared/gateway, T39.2).

An HP's ADVERTISED URL must be the relay-independent gateway, not the relay it happens
to be stored on. Asserts the URL builder + the MURETAI_PUBLIC_BASE override.
"""
# SPDX-License-Identifier: MIT
# Part of the SEAM (the `agent-seam` repository, MIT): this suite travels with the bytes it
# checks, so it carries their licence. Its home is agent-seam; Muretai core vendors it verbatim
# at a pinned commit (shared/VENDOR.json there) and is AGPL-3.0-or-later around it.
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared import gateway

DID = "did:key:z6MkExample123"
ZK = "z6MkExample123"

# default base
os.environ.pop("MURETAI_PUBLIC_BASE", None)
assert gateway.public_base() == "https://muretai.net", gateway.public_base()
assert gateway.did_site_url(DID) == f"https://muretai.net/{ZK}", gateway.did_site_url(DID)
# in-site path (v2 multi-file / project folder) is preserved
assert gateway.did_site_url(DID, "/proj/") == f"https://muretai.net/{ZK}/proj/"
# zkey_of strips did:key: and passes a non-did through unchanged (placeholder-safe)
assert gateway.zkey_of(DID) == ZK
assert gateway.zkey_of("<your-key>") == "<your-key>"
print("OK: default gateway = muretai.net; did_site_url builds <base>/<zKey>[<path>]")

# env override (read dynamically, trailing slash tolerated)
os.environ["MURETAI_PUBLIC_BASE"] = "https://gw.example.test/"
assert gateway.public_base() == "https://gw.example.test", gateway.public_base()
assert gateway.did_site_url(DID) == f"https://gw.example.test/{ZK}"
# explicit base arg overrides both
assert gateway.did_site_url(DID, base="https://other.test") == f"https://other.test/{ZK}"
os.environ.pop("MURETAI_PUBLIC_BASE", None)
print("OK: MURETAI_PUBLIC_BASE override honored (dynamic, trailing-slash tolerant)")

print("\nALL GATEWAY TESTS PASSED")
