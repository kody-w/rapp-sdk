"""Owner-ratified selected RAPP/1 authority checkpoint."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib.resources import files

from ..protocol import (
    AuthorityCheckpoint,
    KindFamilyRegistry,
    StreamTrustPolicy,
    _AUTHORITY_CAPABILITY,
)
from ..protocol import strict_json_loads

SELECTED_AUTHORITY_RESOURCE = "selected-rev14.json"
SELECTED_AUTHORITY_RESOURCE_SHA256 = (
    "ed65a1e65122a70bf9de51fd71875dcd21ac688a406ddd546568026e00ae6eb7"
)


def read_selected_authority_checkpoint() -> bytes:
    """Return the exact language-neutral selected-authority document."""

    return files(__package__).joinpath(SELECTED_AUTHORITY_RESOURCE).read_bytes()


@lru_cache(maxsize=1)
def selected_authority_checkpoint() -> AuthorityCheckpoint:
    """Return the package-selected owner-ratified rev-14 checkpoint."""

    data = read_selected_authority_checkpoint()
    actual = hashlib.sha256(data).hexdigest()
    if actual != SELECTED_AUTHORITY_RESOURCE_SHA256:
        raise RuntimeError("selected authority resource checksum mismatch")
    document = strict_json_loads(data)
    if type(document) is not dict:
        raise RuntimeError("selected authority resource is not an object")
    return AuthorityCheckpoint._create(
        document,
        evidence_id=actual,
        capability=_AUTHORITY_CAPABILITY,
    )


def selected_authority_registry() -> KindFamilyRegistry:
    """Return the checkpoint-derived verified kind-family registry."""

    return KindFamilyRegistry.from_checkpoint(selected_authority_checkpoint())


def selected_authority_trust_policy() -> StreamTrustPolicy:
    """Return the checkpoint-derived full-snapshot trust policy."""

    return StreamTrustPolicy.from_checkpoint(selected_authority_checkpoint())


__all__ = (
    "SELECTED_AUTHORITY_RESOURCE",
    "SELECTED_AUTHORITY_RESOURCE_SHA256",
    "read_selected_authority_checkpoint",
    "selected_authority_checkpoint",
    "selected_authority_registry",
    "selected_authority_trust_policy",
)
