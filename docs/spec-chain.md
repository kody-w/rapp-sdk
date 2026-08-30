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

- `SpecChain.from_frames(iterable)` for decoded mappings;
- `SpecChain.from_jsonl(bytes)` for an explicit UTF-8 byte boundary;
- `SpecChain.from_jsonl_text(str)` for an explicit text boundary; or
- `SpecChain.load(str | os.PathLike[str])` for a filesystem path.

The chain is sequence-like and exposes immutable `SpecRevision` values.
`SpecRevision.address` is an immutable `RevisionAddress`. `to_dict()` returns a
fresh mutable wire dictionary, while `to_json_bytes()`, `frame_bytes`, and
`SpecChain.to_jsonl_bytes()` are deterministic canonical byte serializations.
`materialize()` always returns verified bytes; decode only after checking the
revision's `media_type`.

Expected refusals derive from `RappSDKError`. Each has a stable `code`, an
operation or protocol `step`, immutable scalar `context`, deterministic
`repr`, and `as_dict()` for logging:

```python
from rapp_sdk import RappSDKError, SpecChain

try:
    chain = SpecChain.from_jsonl(untrusted_bytes)
except RappSDKError as error:
    diagnostic = error.as_dict()
```

Importing the package is inert: it performs no filesystem access, network
access, environment reads, logging, or package-metadata discovery.

## Offline authority parity

The source distribution carries a deterministic gzip fixture pinned to the
authority commit recorded in its manifest. The default `unittest` suite
checks the compressed and raw hashes, verifies every chain frame, resolves the
current revision through an injected immutable source, and blocks network
opening during the proof. No environment variable or mutable URL is needed.

The non-discovered `tests/live_authority_refresh.py` utility provides the
separate optional reproducibility check against the same immutable commit in
a local authority checkout.

## Legacy pointer revisions

Existing authority frames point to immutable GitHub objects with:

- `canonical_repo`
- `commit`
- `normative_path`
- `normative_sha256`
- `normative_bytes`

The commit must be exactly 40 lowercase hexadecimal characters. Paths must be
safe relative POSIX paths. For a repository
`https://github.com/OWNER/REPOSITORY`, the globally resolvable immutable object
URL is:

```text
https://raw.githubusercontent.com/OWNER/REPOSITORY/COMMIT/PATH
```

The SDK allows HTTPS only, validates redirects and final hosts, applies byte
ceilings, and verifies both the declared byte count and SHA-256 digest.

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

## Cache and offline behavior

`ContentAddressedCache` stores objects by raw SHA-256. Every read revalidates
size and checksum. Writes use a same-directory temporary file, file `fsync`,
atomic rename, and directory `fsync` where supported. A corrupt object is
refused rather than silently repaired. Offline resolution succeeds only for
verified inline or cached bytes.

```python
from rapp_sdk import ContentAddressedCache, SpecChain

chain = SpecChain.load("anchor/chain.jsonl")
revision = chain.resolve("head")
spec_bytes = chain.materialize(
    frame_hash=revision.frame_hash,
    cache=ContentAddressedCache(".cache/rapp-sdk"),
)
```

Mutable URLs such as an anchor chain on a default branch can announce new
frames. They do not replace verification of the chain and the immutable
addresses embedded in each frame.
