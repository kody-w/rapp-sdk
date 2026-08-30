# RAPP SDK

> The RAPP SDK is the developer surface for building agents, twins, and integrations on the RAPP platform.

Write a `*_agent.py`, ship a `.twin/`, or embed the Brainstem — the SDK is the front door.

---

Part of the **RAPP** platform — the Rapid Agent Prototype Platform.
Explore the ecosystem: [Installer](https://github.com/kody-w/rapp-installer) ·
[Flight Deck](https://github.com/kody-w/rapp-flight-deck) ·
[Rings](https://github.com/kody-w/rapp-rings) ·
[Twin](https://github.com/kody-w/rapp-twin)

## Status

Alpha. The documented imports are the compatibility boundary and follow
semantic versioning.

## Protocol foundation

The first public package surface is a Python 3.11+, standard-library-only core
for strict RAPP/1 frames and append-only specification chains:

```python
from rapp_sdk import SpecChain, build_spec_revision_frame

first = build_spec_revision_frame(
    revision="rev-1",
    text="# RAPP/1\n",
    utc="2026-08-30T00:00:00.000Z",
    stream_id="rappid:@example/spec:" + "0" * 64,
)
chain = SpecChain.from_frames([first])
selected = chain.resolve("head")        # immutable SpecRevision
normative_bytes = chain.materialize()   # always bytes
```

It provides strict I-JSON parsing, authority-compatible canonicalization,
domain-separated `H`/`Hb`, exact eleven-key frame construction and
verification, immutable historical specification resolution, and a
checksum-revalidating content-addressed cache. See
[`docs/spec-chain.md`](docs/spec-chain.md).

### Stable imports

- Protocol: `build_frame`, `verify_frame`, `verify_stream`, `canonicalize`,
  `strict_json_loads`, `H`, and `Hb`
- Specification chain: `SpecChain`, `SpecRevision`, `RevisionAddress`,
  `build_spec_revision_frame`
- Resolution: `ImmutableSource`, `GitHubRawSource`, `HTTPSFetcher`,
  `ContentAddressedCache`
- Errors: `RappSDKError`, `ProtocolError`, `SpecChainError`,
  `SpecResolutionError`, `CacheIntegrityError`

All public callables are typed, and the wheel includes a `py.typed` marker.
Importing `rapp_sdk` performs no I/O or runtime dependency discovery.

Run the no-network ergonomics example:

```console
PYTHONPATH=src python3 examples/spec_chain_smoke.py
```

Package smoke, when the standard build frontend is available:

```console
python3 -m build --wheel --no-isolation --outdir .build-artifacts
python3 -m pip install --no-deps --target .install-smoke \
  .build-artifacts/rapp_sdk-0.1.0-py3-none-any.whl
```

The default offline test suite includes a checksum-pinned authority fixture
and verifies all 14 frames plus the exact rev-13 normative bytes:

```console
python3 -m unittest discover -v
```

Run the separate optional reproducibility check against a local checkout with:

```console
RAPP1_AUTHORITY_ROOT=/path/to/rapp-1 \
  python3 tests/live_authority_refresh.py
```

## License

Released under the MIT License.

<sub>RAPP, RAPP Brainstem, Twin in Residence, RAPP Flight Deck, and the RAPP family of
names are trademarks of the RAPP project. First published 2026-07-18 as part of the RAPP ecosystem.</sub>
