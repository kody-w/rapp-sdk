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
    SpecChain,
    SpecResolver,
    selected_authority_registry,
    selected_authority_trust_policy,
)

chain = SpecChain.from_jsonl(
    authority_chain_bytes,
    registry=selected_authority_registry(),
    trust_policy=selected_authority_trust_policy(),
)
normative_bytes = SpecResolver(chain).read(chain.head)
```

It provides strict I-JSON parsing, full RFC 8785 binary64 canonicalization,
registered kind-family enforcement, immutable verified frames and streams,
external genesis/head trust policy, explicit historical resolution, and a
checksum-revalidating content-addressed cache. See
[`docs/spec-chain.md`](docs/spec-chain.md).
The product-neutral collaboration extension is documented in
[`docs/projects.md`](docs/projects.md).

The SDK includes the closed `rapp-ring-yard/1` manifest: a deterministic
four-track by five-ring yard with explicit cell RAPPIDs, isolated paths,
content-addressed artifacts, fixed ports, probe contracts, bounded budgets,
and declared scheduler/plan limits. It describes all twenty cells without
starting any of them. See
[`docs/ring-yard-manifest.md`](docs/ring-yard-manifest.md).

### Stable imports

- Protocol: `build_frame_mapping`, `check_frame`, `verify_frame`,
  `check_stream`, `verify_stream`, `KindFamilyRegistry`,
  `StreamTrustPolicy`, `VerifiedFrame`, and `VerifiedStream`
- Selected authority: `selected_authority_checkpoint`,
  `selected_authority_registry`, and `selected_authority_trust_policy`
- Specification chain: `SpecChain`, `SpecRevision`, `RevisionAddress`,
  `build_spec_revision_frame`
- Resolution: `SpecResolver` and `RevisionSource`
- Ring yard: `RingYardManifest`, `build_default_ring_yard_manifest`,
  `check_ring_yard_manifest`, `check_ring_yard_manifest_semantics`,
  `verify_ring_yard_manifest`, `ports_for_cell`
- Reports: `Diagnostic` and `VerificationReport`
- Schema: `SPEC_REVISION_SCHEMA_ID`, `read_spec_revision_schema`,
  `RING_YARD_MANIFEST_SCHEMA_ID`, `read_ring_yard_manifest_schema`
- Errors: `RappSDKError`, `ProtocolError`, `SpecChainError`,
  `SpecResolutionError`, `CacheIntegrityError`, `RingManifestError`,
  `ProjectProtocolError`
- RAPP Projects: `ProjectActor`, `ProjectCheckpoint`,
  `PROJECT_EVENTS`, `PROJECT_FRAME_KIND`, `build_project_rappid`,
  `build_project_frame`, `verify_project_stream`,
  `build_project_egg_manifest`, `pack_project_egg`, `read_project_egg`,
  and `verify_project_egg_manifest`

All public callables are typed, and the wheel includes a `py.typed` marker.
Importing `rapp_sdk` performs no I/O or runtime dependency discovery.
Advanced hashes, protocol constants, local-only verification, GitHub/HTTPS
adapters, cache types, and limits live in the documented `rapp_sdk.protocol`,
`rapp_sdk.resolution`, and `rapp_sdk.spec_chain` submodules.

Run the no-network ergonomics example:

```console
PYTHONPATH=src python3 examples/spec_chain_smoke.py
```

Mandatory release gates:

```console
python3 -m unittest discover -v
python3 tests/schema_validator_smoke.py
python3 tests/ring_manifest_schema_smoke.py
PYTHONPATH=src python3 tests/doctest_smoke.py
python3 -m build --no-isolation --outdir .build-artifacts
python3 tests/distribution_install_smoke.py \
  .build-artifacts/rapp_sdk-0.2.0-py3-none-any.whl \
  .build-artifacts/rapp_sdk-0.2.0.tar.gz
```

For interpreters whose standard `venv` omits setuptools, provide a local
site-packages directory containing the pinned setuptools 84.0.0 backend:

```console
python3 -m pip install --target .setuptools-provider setuptools==84.0.0
RAPP_SDK_SETUPTOOLS_SITE=.setuptools-provider \
  python3.14 tests/distribution_install_smoke.py \
  .build-artifacts/rapp_sdk-0.2.0-py3-none-any.whl \
  .build-artifacts/rapp_sdk-0.2.0.tar.gz
```

Pull requests must pass the `protocol` matrix on Python 3.11 through 3.14,
the Python 3.14 `platform` jobs on macOS and Windows, and the exact
`distribution (3.14)` wheel/offline-sdist install gate before merge.

The gate derives the backend-only overlay from the pinned distribution's
`METADATA`, `top_level.txt`, and `RECORD`. Optional removed modules such as
`pkg_resources` are not assumed, unrelated provider packages are excluded,
and every copied file is RECORD-verified. The bridge is active only while
building the sdist, uses `PIP_NO_INDEX=1`, and is removed before the isolated
`-I` runtime probe.
Install validation dependencies with the pinned test extra; they are not
runtime dependencies:

```console
python3 -m pip install -e '.[test]'
```

The versioned payload schema is canonical inside the package:

```python
from rapp_sdk import read_spec_revision_schema

schema_bytes = read_spec_revision_schema()
```

The closed ring-yard schema is also a canonical package resource. Draft
2020-12 covers structure and locally expressible constraints; conforming
validation must also apply the bundled semantic report because standard JSON
Schema cannot compare arbitrary sibling values or enforce cross-cell
uniqueness and path non-overlap:

```python
from rapp_sdk import (
    check_ring_yard_manifest_semantics,
    read_ring_yard_manifest_schema,
)

ring_schema_bytes = read_ring_yard_manifest_schema()
semantic_report = check_ring_yard_manifest_semantics(decoded_manifest)
verified_manifest = semantic_report.require()
```

For untrusted JSON bytes, `check_ring_yard_manifest` performs strict parsing
and all semantic checks directly. The semantic report preserves original
scalar types, so integer-valued floats, booleans, and negative floating-point
zero are not canonicalized into integers. `jsonschema` remains a test-only
dependency.

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
