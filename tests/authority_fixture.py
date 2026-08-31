"""Integrity-checked selected and historical RAPP/1 authority fixtures."""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path

from rapp_sdk import (
    KindFamilyRegistry,
    StreamTrustPolicy,
    selected_authority_checkpoint,
    selected_authority_registry,
    selected_authority_trust_policy,
    strict_json_loads,
)

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapp1-caf6ef27"
SELECTED_AUTHORITY_COMMIT = "caf6ef276cafa92aa744499af90dc1a28559941a"
SELECTED_FRAME_HASH = (
    "59629adab4e26d156f3d66ecfb766e08705919ea1d2adc92ba0ad2b17337dfc2"
)
SELECTED_PAYLOAD_HASH = (
    "c7549bbd3e133b833930e24e008817ea295734b870f41706455d3f45821aba3a"
)
SELECTED_SPEC_SHA256 = (
    "d345235be5bc698d78c5893285abd09f2e62a398f781123d1de8da313a01c7de"
)
SELECTED_BOOTSTRAP_SHA256 = (
    "1666e44acf532f854d4bf74868c9af9f9b362055692189ac858a7c8b52dcd5bb"
)
HISTORICAL_REV13_SHA256 = (
    "e5abd6a32801761fdd5c151a4f90fa4c989b545da02d3cd26dfc4765fab8409a"
)
_MANIFEST_SHA256 = (
    "15409ef9e95c93bb3ad67e6199f42a1b202dddaf673aa987d2023cdcc90012a0"
)
_CHAIN_SHA256 = (
    "6974a0bd5f6344f72b728efed0a154109be8769ef4d956a827701d9b222f6018"
)
_CHAIN_GZIP_SHA256 = (
    "f29c63a8469fda082e7ce330ac4fa3f3781369022b4f1caa06d78e384537a79f"
)
_SPEC_GZIP_SHA256 = (
    "11faa8bf14bff2fa03fa2fdad1a01700aa512517e2d477ac8fff6f51777b5f46"
)
_REV13_GZIP_SHA256 = (
    "bac83626f5f0e489c267da0d5a0cb8be539265225d52ce8af5c94dff7054f458"
)


def checked_fixture_bytes(name: str, sha256: str) -> bytes:
    data = (FIXTURE_ROOT / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise AssertionError(f"selected fixture checksum mismatch: {name}")
    return data


def checked_gzip_fixture(
    name: str,
    *,
    gzip_sha256: str,
    raw_sha256: str,
    raw_bytes: int,
) -> bytes:
    compressed = checked_fixture_bytes(name, gzip_sha256)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
        data = stream.read(raw_bytes + 1)
    if len(data) != raw_bytes:
        raise AssertionError(f"selected fixture byte count mismatch: {name}")
    if hashlib.sha256(data).hexdigest() != raw_sha256:
        raise AssertionError(f"selected fixture content mismatch: {name}")
    return data


def selected_fixture() -> tuple[dict, bytes, bytes, bytes, bytes]:
    manifest_bytes = checked_fixture_bytes("manifest.json", _MANIFEST_SHA256)
    manifest = strict_json_loads(manifest_bytes)
    if type(manifest) is not dict:
        raise AssertionError("selected fixture manifest is not an object")
    chain = checked_gzip_fixture(
        "chain.jsonl.gz",
        gzip_sha256=_CHAIN_GZIP_SHA256,
        raw_sha256=_CHAIN_SHA256,
        raw_bytes=196708,
    )
    spec = checked_gzip_fixture(
        "SPEC.md.gz",
        gzip_sha256=_SPEC_GZIP_SHA256,
        raw_sha256=SELECTED_SPEC_SHA256,
        raw_bytes=78183,
    )
    rev13 = checked_gzip_fixture(
        "rev-13-SPEC.md.gz",
        gzip_sha256=_REV13_GZIP_SHA256,
        raw_sha256=HISTORICAL_REV13_SHA256,
        raw_bytes=65569,
    )
    bootstrap = checked_fixture_bytes(
        "bootstrap.json",
        SELECTED_BOOTSTRAP_SHA256,
    )
    return manifest, chain, spec, rev13, bootstrap


def selected_policies(
    manifest: dict,
    bootstrap_bytes: bytes,
) -> tuple[KindFamilyRegistry, StreamTrustPolicy]:
    bootstrap = strict_json_loads(bootstrap_bytes)
    if type(bootstrap) is not dict:
        raise AssertionError("bootstrap profile is not an object")
    authority = bootstrap["authority"]
    canonicalization = bootstrap["canonicalization"]
    frame_profile = bootstrap["frame"]
    selected = manifest["selected"]
    if (
        canonicalization["input"] != "I-JSON exact-integer subset"
        or canonicalization["floating_point"] != "refused"
    ):
        raise AssertionError("bootstrap number profile is not recognized")
    checkpoint = selected_authority_checkpoint()
    if (
        checkpoint.accepted_commit != manifest["authority_merge_commit"]
        or checkpoint.bootstrap_profile_sha256 != SELECTED_BOOTSTRAP_SHA256
        or checkpoint.stream_id != authority["stream_id"]
        or checkpoint.selected_head.seq != selected["seq"]
        or checkpoint.selected_head.frame_hash != selected["frame_hash"]
        or checkpoint.kind_families != {frame_profile["kind"]: "body"}
    ):
        raise AssertionError("selected checkpoint differs from fixture authority")
    registry = selected_authority_registry()
    trust = selected_authority_trust_policy()
    return registry, trust


__all__ = (
    "HISTORICAL_REV13_SHA256",
    "SELECTED_AUTHORITY_COMMIT",
    "SELECTED_BOOTSTRAP_SHA256",
    "SELECTED_FRAME_HASH",
    "SELECTED_PAYLOAD_HASH",
    "SELECTED_SPEC_SHA256",
    "selected_fixture",
    "selected_policies",
)
