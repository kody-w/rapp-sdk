# Ring-yard manifest

`rapp-ring-yard/1` is the closed, portable description of one RAPP SDK ring
yard. It replaces the configuration that would otherwise be spread across
twenty hand-managed terminals. The model is declarative only: this frame does
not launch processes, run a scheduler, expose an API, or write evidence.

## Fixed topology

The manifest always has four tracks in this order:

1. `frontier-experimental`
2. `frontier`
3. `brainstem-experimental`
4. `brainstem-regular`

Every track always has five rings in this order:

1. `canary`
2. `nightly`
3. `alpha`
4. `beta`
5. `grail`

Cells are serialized in track-major order, so the topology contains exactly
twenty cells. Within each track, promotion is
Canary → Nightly → Alpha → Beta → Grail. A track's Grail is the only cell that
may seed the next track's Canary. `RingYardManifest.promotion_edges` exposes
the resulting nineteen edges deterministically.

## Explicit identity

Cell RAPPIDs are minted and persisted outside this model. They are never
derived from a track, ring, display name, path, or list position. The default
builder therefore requires exactly one of:

- a complete mapping for all twenty `(track, ring)` keys; or
- a caller-supplied mint callback, invoked once per cell in normative order.

Missing, malformed, or duplicate RAPPIDs are refused.

```python
from rapp_sdk import build_default_ring_yard_manifest

# Loaded from the application's durable identity registry.
rappids = persisted_twenty_cell_mapping

manifest = build_default_ring_yard_manifest(
    yard_identity="primary-yard",
    yard_root="/srv/rapp-ring-yard",
    artifact_digest="sha256:" + artifact_sha256,
    argv=("bin/rapp-cell", "--serve"),
    rappids=rappids,
)
manifest_bytes = manifest.to_json_bytes()
```

The yard root is an explicit absolute POSIX path. Every cell's home, state,
log, cache, and temporary directory is a normalized relative path resolved
only below that root. Paths use ASCII letters, digits, and
`._~!$&'()+,;=@-`, with `/` only as the segment separator. This makes JSON
Schema `maxLength` and the runtime byte bounds identical. Paths may not
traverse, be absolute where forbidden, duplicate another path, or contain
another declared path. There is no ambient current-directory interpretation.

Artifacts are content-addressed as `sha256:<64-lowercase-hex>`. `argv` is
non-empty, every argument is printable ASCII, and `argv[0]` is an
artifact-relative path containing `/`; it is never resolved through ambient
`PATH`. Each argument is at most 4096 bytes and the aggregate is at most 8192
bytes. The manifest intentionally has no mutable tag, branch, or "latest"
field.

## Deterministic ports and probes

Each cell reserves four named endpoints:

| Offset | Endpoint |
| ---: | --- |
| 0 | `gateway` |
| 1 | `broker` |
| 2 | `control` |
| 3 | `metrics` |

The normative formula is:

```text
24700 + trackSlot*32 + ringSlot*4 + endpointOffset
```

Five rings consume twenty ports in each thirty-two-port track block, leaving
twelve ports reserved for future compatible use. Runtime validation requires
the exact formula, the valid TCP port range, and global uniqueness.

Each cell also carries closed readiness, liveness, identity, and artifact
probe contracts. Identity probes must attest that cell's explicit RAPPID;
artifact probes must attest its immutable digest. Probe timeouts are bounded
by the cell's declared resource and lifecycle budgets.

## All cells exist; execution stays bounded

The manifest describes all twenty cells at once so that paths, identities,
artifacts, ports, probes, and promotion relationships are reconstructible
without terminal-local state. Description does not imply concurrent
execution.

The default scheduler policy declares:

- 4 global jobs
- 2 jobs per track
- 1 job per observer
- 2 jobs per subject
- a 256-entry ready queue

The closed directed plan has `20 * 19 = 380` peer jobs and twenty self-tests,
for 400 planned jobs. These are cardinalities, not running work. A later
execution layer can keep all cells addressable while enforcing the declared
limits.

## Parsing and schema

Use strict JSON bytes. Duplicate object keys, oversized input, unknown
members, missing cells, incorrect ordering or slots, unsafe paths, invalid
ports, mutable artifact references, implicit argv, malformed hashes/RAPPIDs,
and invalid budgets are refused.

```python
from rapp_sdk import (
    check_ring_yard_manifest,
    check_ring_yard_manifest_semantics,
    read_ring_yard_manifest_schema,
    verify_ring_yard_manifest,
)

report = check_ring_yard_manifest(manifest_bytes)
verified = report.require()
same_value = verify_ring_yard_manifest(manifest_bytes)
schema_bytes = read_ring_yard_manifest_schema()
semantic_report = check_ring_yard_manifest_semantics(decoded_manifest)
```

Verified values are frozen and slotted. Serialization is RFC 8785 canonical
JSON, and `manifest_sha256` is the SHA-256 of those deterministic bytes. The
packaged Draft 2020-12 schema is
`schemas/rapp-ring-yard-v1.schema.json`, with schema ID
`urn:rapp:schema:ring-yard-manifest:1`.

The schema is deliberately explicit that it is not sufficient by itself.
Draft 2020-12 validates the closed shape, exact topology and ports, individual
bounds, immutable hash syntax, true string ends, and the documented ASCII
subsets. A conforming validator **must also** call
`check_ring_yard_manifest_semantics` on the decoded object. That bundled,
stdlib-only report enforces constraints standard JSON Schema cannot express:

- unique RAPPIDs across cells;
- globally distinct, non-containing cell paths;
- identity and artifact probe values equal to their owning cell;
- probe timeout no greater than its interval or cell probe budget;
- lifecycle timeouts no greater than the job timeout;
- local scheduler limits no greater than the global limit, and a ready queue
  no smaller than that global limit;
- aggregate `argv` length no greater than 8192 ASCII bytes.

The semantic report snapshots JSON containers without rewriting scalar
values. Integer fields therefore require integers: booleans, integer-valued
floats, negative floating-point zero, and exponent-origin floating-point
values are refused rather than normalized by canonicalization. Deterministic
canonical bytes are produced only after the typed manifest has passed
validation.

For untrusted input, prefer `check_ring_yard_manifest(manifest_bytes)`. It
rejects duplicate JSON members and input-size violations before applying the
same semantic checks. `jsonschema` remains test-only and is not imported by
the SDK core.
