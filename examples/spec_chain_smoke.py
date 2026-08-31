"""Minimal trusted, no-network RAPP specification-chain workflow."""

from rapp_sdk import (
    KindFamilyRegistry,
    SpecChain,
    SpecResolver,
    StreamTrustPolicy,
    build_spec_revision_frame,
)

STREAM_ID = "rappid:@example/sdk-spec:" + "0" * 64

first = build_spec_revision_frame(
    revision="rev-1",
    text="# RAPP/1\n\nFirst revision.\n",
    utc="2026-08-30T00:00:00.000Z",
    stream_id=STREAM_ID,
)
registry = KindFamilyRegistry(
    {"body.pulse": "body"},
    genesis_hashes={STREAM_ID: first["frame_hash"]},
    verified=True,
)
trust = StreamTrustPolicy(
    stream_id=STREAM_ID,
    trusted_genesis_hash=first["frame_hash"],
)
first_chain = SpecChain.from_frames(
    [first],
    registry=registry,
    trust_policy=trust,
)
second = build_spec_revision_frame(
    revision="rev-2",
    text="# RAPP/1\n\nSecond revision.\n",
    utc="2026-08-30T00:00:01.000Z",
    head=first_chain.head.frame,
)

chain = SpecChain.from_frames(
    [first, second],
    registry=registry,
    trust_policy=trust,
)
reloaded = SpecChain.from_jsonl(
    chain.to_jsonl_bytes(),
    registry=registry,
    trust_policy=trust,
)
selected = reloaded.resolve(revision="rev-2")
normative_bytes = SpecResolver(reloaded).read(selected)

assert normative_bytes == b"# RAPP/1\n\nSecond revision.\n"
print(
    f"{selected.revision} seq={selected.seq} "
    f"frame={selected.frame_hash[:12]} bytes={len(normative_bytes)}"
)
