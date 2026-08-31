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
from rapp_sdk import (
    KindFamilyRegistry,
    SpecChain,
    SpecResolver,
    StreamTrustPolicy,
    build_spec_revision_frame,
)

first = build_spec_revision_frame(
    revision="rev-1",
    text="# RAPP/1\n",
    utc="2026-08-30T00:00:00.000Z",
    stream_id="rappid:@example/spec:" + "0" * 64,
)
registry = KindFamilyRegistry(
    {"body.pulse": "body"},
    genesis_hashes={first["stream_id"]: first["frame_hash"]},
    verified=True,
)
trust = StreamTrustPolicy(
    stream_id=first["stream_id"],
    trusted_genesis_hash=first["frame_hash"],
)
chain = SpecChain.from_frames(
    [first],
    registry=registry,
    trust_policy=trust,
)
normative_bytes = SpecResolver(chain).read(chain.head)
```

It provides strict I-JSON parsing, full RFC 8785 binary64 canonicalization,
registered kind-family enforcement, immutable verified frames and streams,
external genesis/head trust policy, explicit historical resolution, and a
checksum-revalidating content-addressed cache. See
[`docs/spec-chain.md`](docs/spec-chain.md).

### Stable imports

- Protocol: `build_frame_mapping`, `check_frame`, `verify_frame`,
  `check_stream`, `verify_stream`, `KindFamilyRegistry`,
  `StreamTrustPolicy`, `VerifiedFrame`, and `VerifiedStream`
- Specification chain: `SpecChain`, `SpecRevision`, `RevisionAddress`,
  `build_spec_revision_frame`
- Resolution: `SpecResolver` and `RevisionSource`
- Reports: `Diagnostic` and `VerificationReport`
- Schema: `SPEC_REVISION_SCHEMA_ID`, `read_spec_revision_schema`
- Errors: `RappSDKError`, `ProtocolError`, `SpecChainError`,
  `SpecResolutionError`, `CacheIntegrityError`

All public callables are typed, and the wheel includes a `py.typed` marker.
Importing `rapp_sdk` performs no I/O or runtime dependency discovery.
Advanced hashes, protocol constants, local-only verification, GitHub/HTTPS
adapters, cache types, and limits live in the documented `rapp_sdk.protocol`,
`rapp_sdk.resolution`, and `rapp_sdk.spec_chain` submodules.

Run the no-network ergonomics example:

```console
PYTHONPATH=src python3 examples/spec_chain_smoke.py
```

Package smoke, when the standard build frontend is available:

```console
python3 -m build --no-isolation --outdir .build-artifacts
python3 tests/distribution_install_smoke.py \
  .build-artifacts/rapp_sdk-0.1.0-py3-none-any.whl \
  .build-artifacts/rapp_sdk-0.1.0.tar.gz
```

For interpreters whose standard `venv` omits setuptools, provide a local
site-packages directory containing the pinned setuptools 84.0.0 backend:

```console
RAPP_SDK_SETUPTOOLS_SITE=/path/to/local/site-packages \
  python3.14 tests/distribution_install_smoke.py \
  .build-artifacts/rapp_sdk-0.1.0-py3-none-any.whl \
  .build-artifacts/rapp_sdk-0.1.0.tar.gz
```

The gate copies only the pinned setuptools components into a temporary backend
overlay. Its bridge is active only while building the sdist, uses
`PIP_NO_INDEX=1`, and is removed before the isolated `-I` runtime probe.

The versioned payload schema is canonical inside the package:

```python
from rapp_sdk import read_spec_revision_schema

schema_bytes = read_spec_revision_schema()
```

The default offline test suite includes a checksum-pinned authority fixture
selected at owner-ratified rev-14. It verifies all 15 frames, the accepted
rev-14 frame/payload/normative/bootstrap hashes, and historical rev-13
resolution:

```console
python3 -m unittest discover -v
```

Run the separate optional reproducibility check against a local checkout with:

```console
RAPP1_AUTHORITY_ROOT=/path/to/rapp-1 \
  python3 tests/live_authority_refresh.py
```

## License

Released under the MIT License. See `THIRD_PARTY_NOTICES.md` for the
Apache-2.0-licensed JCS number-formatting lineage included in the stdlib-only
implementation.

<sub>RAPP, RAPP Brainstem, Twin in Residence, RAPP Flight Deck, and the RAPP family of
names are trademarks of the RAPP project. First published 2026-07-18 as part of the RAPP ecosystem.</sub>
