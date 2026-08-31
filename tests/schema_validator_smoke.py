"""Cross-check payload profile vectors with Draft 2020-12 jsonschema."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rapp_sdk import KindFamilyRegistry, SpecChain, SpecChainError
from rapp_sdk.protocol import build_frame_mapping
from rapp_sdk.schemas import read_spec_revision_schema

RID = "rappid:@example/schema-validator:" + "0" * 64
COMMIT = "a" * 40
CONTENT = b"spec"
SHA256 = hashlib.sha256(CONTENT).hexdigest()


def runtime_accepts(payload: dict) -> bool:
    frame = build_frame_mapping(
        "body.pulse",
        RID,
        0,
        "2026-08-30T00:00:00.000Z",
        payload,
        None,
    )
    registry = KindFamilyRegistry.local(
        {"body.pulse": "body"},
        genesis_hashes={RID: frame["frame_hash"]},
    )
    try:
        SpecChain.from_frames_local([frame], registry=registry)
    except SpecChainError:
        return False
    return True


def main() -> int:
    version = importlib.metadata.version("jsonschema")
    major, minor = (int(part) for part in version.split(".")[:2])
    if major != 4 or minor < 23:
        raise RuntimeError(f"jsonschema test dependency is outside pin: {version}")
    schema = json.loads(read_spec_revision_schema())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    pointer = {
        "revision": "rev-pointer",
        "canonical_repo": "https://example.com/specification",
        "commit": COMMIT,
        "normative_path": "SPEC.md",
        "normative_sha256": SHA256,
        "normative_bytes": "4",
    }
    inline = {
        "revision": "rev-inline",
        "normative": {
            "media_type": "text/plain; charset=utf-8",
            "text": "spec",
            "sha256": SHA256,
            "bytes": 4,
        },
    }
    accepted = [
        pointer,
        {**pointer, "normative_bytes": "1048576"},
        {**pointer, "normative_bytes": 1048576},
        {
            **pointer,
            "canonical_repo": "https://example.com:443/specification",
        },
        inline,
    ]
    rejected = []
    for repository in (
        "https://user@example.com/specification",
        "https://example.com:444/specification",
        "https://example.com/specification?ref=main",
        "https://example.com/specification#main",
        "https://example.com",
        "https://example.com//specification",
    ):
        rejected.append({**pointer, "canonical_repo": repository})
    rejected.append({**pointer, "normative_bytes": "1048577"})
    rejected.append({**pointer, "commit": "main"})
    rejected.append({**pointer, "normative_path": "../SPEC.md"})
    inline_string = copy.deepcopy(inline)
    inline_string["normative"]["bytes"] = "4"
    rejected.append(inline_string)
    for field in (
        "revision",
        "canonical_repo",
        "commit",
        "normative_path",
        "normative_sha256",
        "normative_bytes",
    ):
        trailing_lf = copy.deepcopy(pointer)
        trailing_lf[field] = str(trailing_lf[field]) + "\n"
        rejected.append(trailing_lf)
    media_type_lf = copy.deepcopy(inline)
    media_type_lf["normative"]["media_type"] += "\n"
    rejected.append(media_type_lf)
    inline_hash_lf = copy.deepcopy(inline)
    inline_hash_lf["normative"]["sha256"] += "\n"
    rejected.append(inline_hash_lf)

    for payload in accepted:
        if list(validator.iter_errors(payload)):
            raise AssertionError(f"validator rejected accepted payload: {payload}")
        if not runtime_accepts(payload):
            raise AssertionError(f"runtime rejected accepted payload: {payload}")
    for payload in rejected:
        if not list(validator.iter_errors(payload)):
            raise AssertionError(f"validator accepted rejected payload: {payload}")
        if runtime_accepts(payload):
            raise AssertionError(f"runtime accepted rejected payload: {payload}")
    print(
        f"schema/runtime parity: {len(accepted)} accepted, "
        f"{len(rejected)} rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
