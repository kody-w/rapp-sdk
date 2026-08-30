"""Minimal no-network RAPP specification-chain workflow."""

from rapp_sdk import SpecChain, build_spec_revision_frame

STREAM_ID = "rappid:@example/sdk-spec:" + "0" * 64

first = build_spec_revision_frame(
    revision="rev-1",
    text="# RAPP/1\n\nFirst revision.\n",
    utc="2026-08-30T00:00:00.000Z",
    stream_id=STREAM_ID,
)
second = build_spec_revision_frame(
    revision="rev-2",
    text="# RAPP/1\n\nSecond revision.\n",
    utc="2026-08-30T00:00:01.000Z",
    head=first,
)

chain = SpecChain.from_frames([first, second])
reloaded = SpecChain.from_jsonl(chain.to_jsonl_bytes())
selected = reloaded.resolve("rev-2")
normative_bytes = reloaded.materialize(frame_hash=selected.frame_hash)

assert normative_bytes == b"# RAPP/1\n\nSecond revision.\n"
print(
    f"{selected.revision} seq={selected.seq} "
    f"frame={selected.frame_hash[:12]} bytes={len(normative_bytes)}"
)
