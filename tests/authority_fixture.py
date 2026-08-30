"""Integrity-checked access to the committed RAPP/1 authority fixture."""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path

from rapp_sdk import strict_json_loads

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapp1-bfa0706"
PINNED_AUTHORITY_COMMIT = "bfa0706a4dd448b98b59c68aece0761d625923cb"
PINNED_MANIFEST_SHA256 = (
    "27cbd6380a6a0dfdd2effb96c93c50322fb149306d60c9e32501c93694ea197d"
)
PINNED_CHAIN_SHA256 = (
    "e6c9583953acedcbb56604042dd3b5941ff8b8a4a999ae91ebfd73cdbb1d0f7c"
)
PINNED_CHAIN_GZIP_SHA256 = (
    "c5e51755a56ecdc57c3f92d789e3137246c92524d19531d8ad5991026befec3c"
)
PINNED_SPEC_SHA256 = (
    "e5abd6a32801761fdd5c151a4f90fa4c989b545da02d3cd26dfc4765fab8409a"
)
PINNED_SPEC_GZIP_SHA256 = (
    "bac83626f5f0e489c267da0d5a0cb8be539265225d52ce8af5c94dff7054f458"
)


def checked_fixture_bytes(name: str, sha256: str) -> bytes:
    data = (FIXTURE_ROOT / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise AssertionError(f"pinned fixture checksum mismatch: {name}")
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
        raise AssertionError(f"pinned fixture byte count mismatch: {name}")
    if hashlib.sha256(data).hexdigest() != raw_sha256:
        raise AssertionError(f"pinned fixture content mismatch: {name}")
    return data


def pinned_fixture() -> tuple[dict, bytes, bytes]:
    manifest_bytes = checked_fixture_bytes(
        "manifest.json",
        PINNED_MANIFEST_SHA256,
    )
    manifest = strict_json_loads(manifest_bytes)
    if type(manifest) is not dict:
        raise AssertionError("pinned fixture manifest is not an object")
    chain = checked_gzip_fixture(
        "chain.jsonl.gz",
        gzip_sha256=PINNED_CHAIN_GZIP_SHA256,
        raw_sha256=PINNED_CHAIN_SHA256,
        raw_bytes=104831,
    )
    spec = checked_gzip_fixture(
        "SPEC.md.gz",
        gzip_sha256=PINNED_SPEC_GZIP_SHA256,
        raw_sha256=PINNED_SPEC_SHA256,
        raw_bytes=65569,
    )
    return manifest, chain, spec


__all__ = (
    "PINNED_AUTHORITY_COMMIT",
    "PINNED_CHAIN_SHA256",
    "PINNED_SPEC_SHA256",
    "pinned_fixture",
)
