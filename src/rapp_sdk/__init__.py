"""Public RAPP SDK protocol and specification-chain API."""

from .protocol import (
    FRAME_KEYS,
    H,
    Hb,
    ProtocolError,
    build_frame,
    canonical,
    canonicalize,
    strict_json_loads,
    verify_frame,
    verify_stream,
)
from .spec_chain import (
    ByteFetcher,
    CacheIntegrityError,
    ContentAddressedCache,
    GitHubRawSource,
    HTTPSFetcher,
    ImmutableSource,
    MAX_CHAIN_BYTES,
    MAX_SPEC_BYTES,
    SpecChain,
    SpecChainError,
    SpecResolutionError,
    SpecRevision,
    build_spec_revision_frame,
)

__version__ = "0.1.0"

__all__ = [
    "ByteFetcher",
    "CacheIntegrityError",
    "ContentAddressedCache",
    "FRAME_KEYS",
    "GitHubRawSource",
    "H",
    "HTTPSFetcher",
    "Hb",
    "ImmutableSource",
    "MAX_CHAIN_BYTES",
    "MAX_SPEC_BYTES",
    "ProtocolError",
    "SpecChain",
    "SpecChainError",
    "SpecResolutionError",
    "SpecRevision",
    "build_frame",
    "build_spec_revision_frame",
    "canonical",
    "canonicalize",
    "strict_json_loads",
    "verify_frame",
    "verify_stream",
]
