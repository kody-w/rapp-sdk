"""Minimal trusted, no-network RAPP specification-chain workflow."""

import hashlib

from rapp_sdk import (
    AuthorityCheckpoint,
    KindFamilyRegistry,
    SpecChain,
    SpecResolver,
    StreamTrustPolicy,
    build_spec_revision_frame,
    canonicalize,
)

STREAM_ID = "rappid:@example/sdk-spec:" + "0" * 64

first = build_spec_revision_frame(
    revision="rev-1",
    text="# RAPP/1\n\nFirst revision.\n",
    utc="2026-08-30T00:00:00.000Z",
    stream_id=STREAM_ID,
)


def demo_checkpoint(*frames: dict) -> AuthorityCheckpoint:
    selected = frames[-1]
    return AuthorityCheckpoint.from_authenticated(
        {
            "canonical_repository": "https://example.test/authority",
            "protected_ref": "refs/heads/main",
            "accepted_commit": "a" * 40,
            "bootstrap_profile_sha256": "b" * 64,
            "chain_sha256": hashlib.sha256(
                b"".join(canonicalize(frame) + b"\n" for frame in frames)
            ).hexdigest(),
            "stream_id": STREAM_ID,
            "genesis_frame_hash": frames[0]["frame_hash"],
            "selected_head": {
                "seq": selected["seq"],
                "frame_hash": selected["frame_hash"],
                "payload_hash": selected["payload_hash"],
            },
            "frame_hashes": [frame["frame_hash"] for frame in frames],
            "kind_families": {"body.pulse": "body"},
            "number_profile": "rfc8785-binary64",
        },
        authenticator=lambda evidence: True,  # Demo-only trust seam.
    )


first_checkpoint = demo_checkpoint(first)
registry = KindFamilyRegistry.from_checkpoint(first_checkpoint)
trust = StreamTrustPolicy.from_checkpoint(first_checkpoint)
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

checkpoint = demo_checkpoint(first, second)
registry = KindFamilyRegistry.from_checkpoint(checkpoint)
trust = StreamTrustPolicy.from_checkpoint(checkpoint)
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
