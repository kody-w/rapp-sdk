# RAPP/1 specification chains

RAPP/1 is selected from an append-only, verified RAPP/1 frame chain. A branch
head, a release page, or a mutable `SPEC.md` filename is discovery metadata,
not protocol authority. `SPEC.md` is a rendered view of the normative bytes
addressed by a selected chain frame.

## Stable revision addresses

Every revision frame has four useful selectors:

- `frame_hash`: the address of the complete frame wave;
- `payload_hash`: the address of the frame payload particle;
- `seq`: its position in the verified stream; and
- `payload.revision`: its human-readable label.

Frames remain independently resolvable by hash or sequence even when an early
legacy chain repeated a label for checkpoints that address the same normative
bytes. Reusing a label for different bytes is refused.

Consumers must verify the exact eleven-key RAPP/1 envelope, payload and frame
hashes, the single stream identifier, contiguous sequence, `prev`, `prev_wave`,
monotonic UTC, and signature requirements before using payload metadata.
Verification refuses forks and never repairs or reparents frames.
Producers must serialize appends so that each stream has exactly one writer;
competing children at one sequence are a refused fork, not a merge request.

## Public API and value semantics

`SpecChain` is the verified index. Create one with:

- `SpecChain.from_frames(..., registry=..., trust_policy=...)`;
- `SpecChain.from_jsonl(..., registry=..., trust_policy=...)`;
- `SpecChain.from_jsonl_text(..., registry=..., trust_policy=...)`; or
- `SpecChain.load(..., registry=..., trust_policy=...)`.

The chain is sequence-like and exposes immutable `SpecRevision` values.
`SpecRevision.address` is an immutable `RevisionAddress`. `to_dict()` returns a
fresh mutable wire dictionary, while `to_json_bytes()` and
`SpecChain.to_jsonl_bytes()` are deterministic canonical byte serializations.

`from_frames_local()` and `from_jsonl_local()` are the only APIs that accept
internal consistency without an external trust root. Their result is labeled
`local-untrusted` and `SpecResolver` refuses to use it as authority.

Trusted registries are not created with a Boolean. `KindFamilyRegistry.local()`
creates an explicit untrusted registry; `KindFamilyRegistry.from_checkpoint()`
derives a trusted registry from an authenticated `AuthorityCheckpoint`.
The package-selected rev-14 checkpoint binds the canonical repository,
protected ref, accepted merge commit, bootstrap hash, raw chain digest, every
sequence's frame hash, and the selected head. Its matching registry and policy
are available through `selected_authority_registry()` and
`selected_authority_trust_policy()`.

Resolution is deliberately separate and has no default network source:

```python
from rapp_sdk import SpecResolver
from rapp_sdk.resolution import GitHubRevisionSource

# Inline or cached bytes need no source.
spec_bytes = SpecResolver(chain).read(chain.head)

# A legacy uncached pointer needs an explicit adapter.
resolver = SpecResolver(chain, source=GitHubRevisionSource())
spec_bytes = resolver.read(chain.resolve(seq=13))
```

Selectors are keyword-only. Use `chain.head` for the head, or exactly one of
`revision=`, `seq=`, `frame_hash=`, and `payload_hash=` with `resolve()`.
There is no positional type/hash guessing.

`check_frame()` and `check_stream()` return one generic
`VerificationReport[T]`. `verify_frame()` and `verify_stream()` are raising
wrappers over `report.require()`. Every exception carries the same immutable
`Diagnostic`, separating code, operation, protocol step, location, context,
and remediation:

```python
from rapp_sdk import RappSDKError, check_stream

try:
    stream = check_stream(
        frames,
        registry=registry,
        trust_policy=trust_policy,
    ).require()
except RappSDKError as error:
    diagnostic = error.diagnostic.as_dict()
```

The stable code catalog is
`rapp_sdk.diagnostic_codes.DIAGNOSTIC_CODES`.

### Preview API migration

- `build_frame(...)` → `build_frame_mapping(...)` (`build_frame` remains an
  advanced submodule alias).
- `verify_frame()` now requires a verified `KindFamilyRegistry` and returns
  `VerifiedFrame`.
- `verify_stream()` additionally requires `StreamTrustPolicy` and returns
  `VerifiedStream`.
- `SpecChain.from_*()` requires registry/trust; use the explicitly named
  `*_local()` constructors only for non-authoritative inspection.
- `chain.materialize(...)` → `SpecResolver(chain, source=..., cache=...).read(...)`.
- `chain.resolve("rev-13")` → `chain.resolve(revision="rev-13")`; use
  `chain.head` directly for the head.
- Hash spaces, `H`/`Hb`, limits, local verification, transports, and cache
  types moved from the root namespace to their advanced submodules.

Importing the package is inert: it performs no filesystem access, network
access, environment reads, logging, or package-metadata discovery.

## Schema resource

The canonical payload schema ships at
`rapp_sdk/schemas/rapp-spec-revision-v1.schema.json`. Its stable semantic
identity is `urn:rapp:schema:spec-revision:1`; a mutable repository branch URL
is not used as normative identity.

```python
import json
from importlib.resources import files
from rapp_sdk import read_spec_revision_schema

resource = files("rapp_sdk").joinpath(
    "schemas/rapp-spec-revision-v1.schema.json"
)
assert resource.is_file()
assert resource.read_bytes() == read_spec_revision_schema()
schema = json.loads(read_spec_revision_schema())
```

There is no second editable presentation copy. Wheel and source-distribution
smoke tests install into separate virtual environments and require the
installed resource to parse and byte-match this canonical source.
The sdist smoke pins setuptools 84.0.0. If an interpreter's `venv` omits
setuptools, the test requires an explicit local provider path, exposes it only
through a backend-only overlay for the no-index build step, removes the bridge,
and then proves under `-I` that `rapp_sdk` and its distribution metadata
resolve inside the target venv.
The overlay closure is derived from the pinned setuptools distribution's
standard metadata and RECORD rather than a hardcoded package list.

## Offline authority parity

The source distribution carries a deterministic gzip fixture pinned to the
owner-ratified protected-main rev-14 merge commit recorded in its manifest.
The default `unittest` suite checks compressed and raw hashes, verifies all 15
chain frames, applies the content-addressed bootstrap policy and persisted
rev-14 head, resolves inline rev-14, resolves historical rev-13 through its
immutable pointer, and blocks network opening during the proof. No
environment variable or mutable URL is needed.

The general protocol canonicalizer supports the full round-trippable RFC 8785
binary64 domain. The selected authority policy additionally applies the
accepted bootstrap's stricter exact-integer profile to authority frames.

The non-discovered `tests/live_authority_refresh.py` utility provides the
separate optional reproducibility check against the same immutable commit in
a local authority checkout.

## Legacy pointer revisions

Existing authority frames carry source-neutral legacy locator fields:

- `canonical_repo`
- `commit`
- `normative_path`
- `normative_sha256`
- `normative_bytes`

The chain validates HTTPS, the immutable 40-hex commit, safe bounded POSIX
paths, size, and checksum without selecting a repository vendor.
`GitHubRevisionSource` alone interprets a compatible locator as:

```text
https://raw.githubusercontent.com/OWNER/REPOSITORY/COMMIT/PATH
```

That adapter allows HTTPS only, validates redirects and final hosts, and
applies byte ceilings. Other synchronous or future asynchronous source
adapters can consume the same immutable `ContentLocator` without changing
`SpecChain` or `SpecRevision`.

## Inline revisions

Future frames can carry the normative bytes directly:

```json
{
  "revision": "rev-14",
  "normative": {
    "media_type": "text/markdown; charset=utf-8",
    "text": "# RAPP/1\n",
    "sha256": "…64 lowercase hex…",
    "bytes": 9
  }
}
```

Inline bytes are preferred and verified before use. A frame may retain the
legacy pointer fields as redundant global resolution metadata, but their
digest and size must agree with the inline object.

## Cache and network behavior

`ContentAddressedCache` stores objects by raw SHA-256. Every read revalidates
size and checksum. Writes use a same-directory temporary file, file `fsync`,
atomic rename, and directory `fsync` where supported. A corrupt object is
refused rather than silently repaired.

On POSIX, every root/intermediate/leaf operation is descriptor-relative with
`O_DIRECTORY`/`O_NOFOLLOW`, stable identity checks, and directory `fsync`.
Windows rejects symlink/reparse components and revalidates identities around
opens and replacement. Platforms without a safe guarantee fail closed.

Inline, cached, and sourced normative content passes the same validator before
return: exact size/SHA-256, strict UTF-8, no UTF-8 BOM or leading U+FEFF, and
byte-identical UTF-8 round-trip.

```python
from rapp_sdk import SpecResolver
from rapp_sdk.resolution import ContentAddressedCache, GitHubRevisionSource

resolver = SpecResolver(
    chain,
    cache=ContentAddressedCache(".cache/rapp-sdk"),
    source=GitHubRevisionSource(),
)
spec_bytes = resolver.read(chain.head)
```

If an uncached legacy revision has no source, resolution fails with
`source-required`; no network transport is constructed or opened. Mutable
URLs can announce new frames, but never replace verified chain and trust
policy.
