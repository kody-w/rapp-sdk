"""Versioned JSON Schema resources shipped with :mod:`rapp_sdk`."""

from __future__ import annotations

from importlib.resources import files

SPEC_REVISION_SCHEMA_ID = "urn:rapp:schema:spec-revision:1"
SPEC_REVISION_SCHEMA_RESOURCE = "rapp-spec-revision-v1.schema.json"
RING_YARD_MANIFEST_SCHEMA_ID = "urn:rapp:schema:ring-yard-manifest:1"
RING_YARD_MANIFEST_SCHEMA_RESOURCE = "rapp-ring-yard-v1.schema.json"


def read_spec_revision_schema() -> bytes:
    """Return the canonical specification-revision schema as UTF-8 bytes.

    Example:
        >>> import json
        >>> schema = json.loads(read_spec_revision_schema())
        >>> schema["$id"] == SPEC_REVISION_SCHEMA_ID
        True
    """

    return files(__package__).joinpath(SPEC_REVISION_SCHEMA_RESOURCE).read_bytes()


def read_ring_yard_manifest_schema() -> bytes:
    """Return the structural ring-yard schema as canonical UTF-8 bytes.

    Schema conformance also requires the stdlib-only semantic report exposed
    by :func:`rapp_sdk.check_ring_yard_manifest_semantics`.

    Example:
        >>> import json
        >>> schema = json.loads(read_ring_yard_manifest_schema())
        >>> schema["$id"] == RING_YARD_MANIFEST_SCHEMA_ID
        True
    """

    return files(__package__).joinpath(
        RING_YARD_MANIFEST_SCHEMA_RESOURCE
    ).read_bytes()


__all__ = (
    "RING_YARD_MANIFEST_SCHEMA_ID",
    "RING_YARD_MANIFEST_SCHEMA_RESOURCE",
    "SPEC_REVISION_SCHEMA_ID",
    "SPEC_REVISION_SCHEMA_RESOURCE",
    "read_ring_yard_manifest_schema",
    "read_spec_revision_schema",
)
