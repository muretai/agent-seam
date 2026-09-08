# agent-seam

**The byte contract two programs that have never met authenticate each other with, as golden
vectors plus reference implementations in JavaScript and Python. Zero dependencies. MIT.**

Two programs that have never met can still prove who they are to each other, if they agree on
bytes: canonical JSON, `did:key`, six signed fields, a signed Agent Card envelope, device-key
binding, the Web Bot Auth verify side, a sealed box. That agreement is this repository. It is
not a library either side calls — it is the shape of what goes over the wire, written down
once, with vectors that say what is right and what must be refused.

The coupling is invisible and unforgiving. No dependency manager can see it, and when it breaks
nothing throws: signatures simply stop verifying, and the only diagnostic anyone gets is
"signature verification failed". So the contract lives on its own, belongs to no implementation,
and every implementation is held to it the same way.

**This repository is the home, not a copy.** The JavaScript and the Python reference are edited
here; everything that reproduces these bytes carries a pinned copy it took from here, and none
of them owns the contract.

- [`spec/seam.md`](spec/seam.md) — the contract, one section per vector group
- [`vectors/`](vectors/) — the golden vectors (`wire_vectors.json`, `wba_vectors.json`)
- [`js/seam.mjs`](js/seam.mjs) — the JavaScript reference, one file, `node:crypto` only
- [`python/shared/`](python/shared/) — the Python reference, 18 modules, stdlib only
  (`cryptography` optional)
- [`tools/manifest.json`](tools/manifest.json) — what this repository publishes and how a
  consumer cuts it; [`tools/check-manifest.mjs`](tools/check-manifest.mjs) keeps it exact

## Run

```sh
npm test               # manifest 11 · JS conformance 76
cd go && go run ./conformance   # Go:     OK — 41 checks
cd rust && cargo run --quiet --bin conformance   # Rust: OK — 41 checks
npm run test:py        # Python: closure · wire vectors 131 · web bot auth 5 accepted / 23 refused
                       #         · keybinding · cryptobox · gateway · neturl
```

Nothing dials out, nothing needs an account, and nothing here reads another checkout: this
repository's tests are its own. Python ≥ 3.9; `cryptography` is needed only for `cryptobox` and
the P-256 legs (both are skipped, not failed, without it).

Re-derive the golden files from the Python reference and diff them against the committed ones:

```sh
AGENT_SEAM_VECTORS=/tmp/wire.json python3 python/test_wire_vectors.py --regen && diff /tmp/wire.json vectors/wire_vectors.json
AGENT_SEAM_WBA_OUT=/tmp/wba.json python3 python/tools/gen_wba_vectors.py && diff /tmp/wba.json vectors/wba_vectors.json
```

Both diffs are empty: the Python reference is the generator of the bytes everything is held to.

## Coverage

| Vector group | JS (`js/conformance/run.mjs`) | Python (`python/test_wire_vectors.py`) | Go (`go/conformance`) | Rust (`rust/conformance`) |
|---|---|---|---|---|
| `canonical` | ✓ | ✓ | ✓ | ✓ |
| `numberHazards` | read, not executed (a signer rule) | ✓ | ✓ executed as refusals | ✓ executed as refusals |
| `did` | ✓ Ed25519, both directions | ✓ both curves | ✓ Ed25519, both directions | ✓ Ed25519, both directions |
| `envelope` | ✓ + round trip | ✓ | ✓ + round trip | ✓ + round trip |
| `reject.message` | ✓ | ✓ (+ `invite`, `claim`) | ✓ | ✓ |
| `cardpub` | ✓ payload + verify + anti-substitution | ✓ | — | — |
| `bindingV2` | ✓ accept + reject | ✓ | — | — |
| `ownerState` | — | ✓ 2 accepted + anti-substitution + 5 refused | — | — |
| `relay` | — | ✓ signatures, the `\|` join order, the origin binding | — | — |
| `binding` (v1), `domainLinkage`, `invite` | — | ✓ | — | — |
| Web Bot Auth (`wba_vectors.json`) | ✓ 5 + 23 | ✓ (`python/test_webbotauth.py`) | — | — |
| `cryptobox` | ✓ `open` + `encPub` | ✓ | — | — |

## This is where the bytes live

A change to the seam is made **here** — `js/seam.mjs` and the matching `python/shared/` module,
the vectors regenerated (`--regen` above), `spec/seam.md` updated — and committed, usually under
a tag. Consumers then re-vendor. The rule that keeps the copies honest is the same everywhere:

- a vendored file is edited only here and re-pulled by the consumer's own script;
- every vendored set sits beside a `VENDOR.json` recording the commit, the version and the
  sha256 of each file as written;
- the consumer's tests verify its copies against those digests **without** this repository
  present, and, only when a checkout of this repository is beside them, also verify that the
  recorded commit really produces those bytes (`git show <commit>:<path>`).

No script anywhere writes into another repository. `tools/manifest.json` says what a consumer may
cut — the block the door carries, the declarations it pins by name, the module list, the vector
files — and `npm test` proves the manifest describes `js/seam.mjs` exactly.

## Who carries a copy

| Consumer | What it vendors | Pin | Re-vendor |
|---|---|---|---|
| [`@muretai/agent-entry`](https://github.com/muretai/agent-entry) — the JS door, MIT | the block and the pinned declarations, spliced into its one file; `seam.mjs` and both vector files under `vendor/agent-seam/` | `vendor/agent-seam/VENDOR.json` | `npm run vendor:seam -- --ref <tag>` |
| The author's Python node implementation (AGPL-3.0, not public) | the 18 modules, the four verbatim suites, both vector files | a `VENDOR.json` beside them | its own vendor tool, at the tag |
| `@muretai/agent-site-checker` | `src/seam.mjs`, whole | the digest in `tests/check-seam.mjs` | `cp`, as its header says |
| `@muretai/agent-web-router` | `seam.mjs` and `test/wire_vectors.json` | the digests in `test/seam-twin.test.mjs` | `cp`, as its header says |
| `agent-entry-wordpress` — the PHP twin | `tests/wire_vectors.json` | `tests/VENDOR.json` | `cp` |
| Swift (`apple-agent-kit` SeamKit), Kotlin, the browser extension | `wire_vectors.json` | their own | `cp` |

`agent-entry-serverless` vendors the whole door from agent-entry, not this repository; the seam
reaches it inside the door.

## A gap this repository knows about

`canonical/key-ordering-unicode` is named "keys sort by CODE POINT, not by UTF-16 unit", and
its keys are `z`, `a`, `群`, `A`. Every one of those is inside the Basic Multilingual Plane,
where code-point order and UTF-16 code-unit order are the same — so the case cannot tell the
two apart, and no other case has a key outside the BMP either. An implementation that sorted
keys by UTF-16 code unit, which is exactly what a plain JavaScript `.sort()` does, would pass
all 131 checks and still disagree with Python the first time a signed object carried an emoji
or a rare CJK character as a KEY.

All three references here are correct — they were checked by hand against Python on
`{"\U00010000": 1, "\uFFFD": 2}`, and all three write `{"\uFFFD":2,"\U00010000":1}`. The gap is
in the vectors, not in the code, and it was found by writing the third implementation, which
is the argument for having one. Closing it means a new case in the generator and a new pin in
every consumer, so it is a deliberate change rather than a patch.

## Adding a language

The contract is `spec/seam.md` + `vectors/`; an implementation is one directory that re-derives
them. `go/` and `rust/` are the worked examples: each is one library file plus a runner that
reads `../vectors/wire_vectors.json` and prints `OK — N checks` / exits 1, and each was written
from the spec and the vectors alone. Go needs nothing but its standard library; Rust takes
`ed25519-dalek` for the signatures and `serde_json` with `arbitrary_precision` for reading the
vectors, because Rust ships neither, and `rust/Cargo.toml` says why in the file. Add a row to
`tools/manifest.json` `implementations[]` and a column to the coverage table above. Add a row to
`tools/manifest.json` `implementations[]` and a column to the coverage table above. A language
may implement a subset of groups; the table says which. Existing external implementations
already vendor the vectors, so moving one in is "copy the directory, point its runner at
`../vectors/`, add the row".

## Designed in, not built

- **npm publish** — `package.json` is complete (`@muretai/agent-seam`, exports `./js/seam.mjs`,
  the vectors and the manifest) and marked `"private": true` until the owner publishes. Once it
  is on npm, a JS consumer's vendored copy can become a dependency at the same pinned version.
- **pip** — the Python directory keeps the on-disk name `shared/` (a namespace package) so
  core's copies stay verbatim; a PyPI package would ship an `agentseam` shim that installs
  `sys.modules["shared"]`. Until then: `PYTHONPATH=python`.
- **The door imports `seam.mjs`** instead of carrying the block, assembled into one file at
  release time so the package stays a single dependency-free file.

## Name

The repository was created on 2026-09-06 as `agent-wire`; that name is held on npm by a
stranger's placeholder and on PyPI by an unrelated package, so on 2026-09-07 it became
`agent-seam` — the word the Swift (`SeamKit`) and Kotlin (`seam/`) implementations already use
for this layer. The vector file is still `wire_vectors.json`: every consumer pins that name.

## Not here

The door (discovery paths, the ladder of checks, the store, rate limits) — that is
[`agent-entry`](https://github.com/muretai/agent-entry). `depositToRelay`, the relay client. The
pay/v0 grant and receipt objects (an experimental line of the door; they join at graduation).
KeyState has no vector group yet (JS `verifyKeystate`/`resolveOpDid` is pinned by core's live
harness).

One thing is worth knowing: `python/shared/gateway.py` defaults to `muretai.com` / `muretai.net`
hosts unless `MURETAI_PUBLIC_BASE` / `MURETAI_INVITE_BASE` are set. Nothing in the runners dials
out; the network-capable helpers in `neturl`, `webbotauth` and `invite` are present because the
modules are whole, not because anything here calls them. `invite.py` installs its urllib opener
from the three functions that actually dial, never at import — a verifier embedded in somebody
else's tool must not silently re-configure their HTTP client.

## Licence

MIT — [`LICENSE`](LICENSE). The Python modules are published here by their copyright holder
under MIT; the same bytes are also carried, privately, under AGPL-3.0. See
[`PROVENANCE.md`](PROVENANCE.md).
