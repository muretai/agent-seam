# Provenance and licence

## Where these bytes come from

This repository is the home of the seam: `spec/seam.md`, the golden vectors, and the two
reference implementations. It starts at a single commit carrying the 0.2.1 tree. The files
were first written by the author inside a private node implementation of the same protocol
(AGPL-3.0), and were moved here, relicensed by their copyright holder, so that the byte
contract every implementation must reproduce could live on its own under one permissive
licence. Anything before that commit is the author's private development record and is not
part of what is published.

`python/test_wire_vectors.py`, `python/test_webbotauth.py` and `python/tools/gen_wba_vectors.py`
carry a path option (`AGENT_SEAM_VECTORS`, `AGENT_SEAM_WBA_OUT`) and a seed-only signer so that
they run against `vectors/` here with no node and no relay. `python/_seedsigner.py` is that
signer. Everything else is the implementation itself.

## Licence

MIT (`LICENSE`), for every file here. For the Python modules and the suites that travel with
them this is a **relicensing** by their copyright holder from the AGPL-3.0 under which the same
bytes are also carried privately: decided on 2026-09-06, with the understanding that a
permissive grant on these exact bytes cannot be withdrawn later. Every file carries
`SPDX-License-Identifier: MIT`.

`python/shared/crypto.py` embeds a pure-Python Ed25519 whose structure follows the reference
implementation printed as RFC 8032's code component (itself derived from D. J. Bernstein's
public-domain `ed25519.py`). The RFC's code component is offered under the Revised BSD licence;
neither term conflicts with MIT. The only third-party dependency anywhere is `cryptography`
(Apache-2.0 OR BSD-3-Clause), optional, needed for `cryptobox` and the P-256 legs.

## Vendoring (consumers pull; nothing here writes into another repository)

A consumer runs its own script against a checkout of this repository at a tag, copies what
`tools/manifest.json` says may be cut, and writes a record beside the copies:

```json
{ "from": "agent-seam", "ref": "v0.2.1", "commit": "<40 hex>", "version": "0.2.1",
  "date": "<YYYY-MM-DD>", "files": { "<local path>": { "source": "<path here>", "sha256": "<hex>" } } }
```

Its tests then hold the copies to those digests wherever they run, and — only when this
repository is checked out beside them — also check that `git show <commit>:<source>` still
produces the same bytes, so a pin cannot quietly name a commit it was not taken from.
README's "Who carries a copy" lists each consumer's command.
