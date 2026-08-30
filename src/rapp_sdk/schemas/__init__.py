"""Versioned JSON Schema resources shipped with :mod:`rapp_sdk`."""

from __future__ import annotations

from importlib.resources import files

SPEC_REVISION_SCHEMA_ID = "urn:rapp:schema:spec-revision:1"
SPEC_REVISION_SCHEMA_RESOURCE = "rapp-spec-revision-v1.schema.json"


def read_spec_revision_schema() -> bytes:
    """Return the canonical specification-revision schema as UTF-8 bytes.

    Example:
        >>> import json
        >>> schema = json.loads(read_spec_revision_schema())
        >>> schema["$id"] == SPEC_REVISION_SCHEMA_ID
        True
    """

    return files(__package__).joinpath(SPEC_REVISION_SCHEMA_RESOURCE).read_bytes()


__all__ = (
    "SPEC_REVISION_SCHEMA_ID",
    "SPEC_REVISION_SCHEMA_RESOURCE",
    "read_spec_revision_schema",
)
