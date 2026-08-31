"""Golden-path RAPP SDK API with no import-time I/O."""

from ._version import VERSION, __version__, __version_info__
from .authority import (
    selected_authority_checkpoint,
    selected_authority_registry,
    selected_authority_trust_policy,
)
from .errors import (
    CacheIntegrityError,
    ProtocolError,
    RappSDKError,
    SpecChainError,
    SpecResolutionError,
)
from .protocol import (
    AuthorityCheckpoint,
    PROTOCOL_VERSION,
    KindFamilyRegistry,
    PersistedHead,
    StreamTrustPolicy,
    VerifiedFrame,
    VerifiedStream,
    build_frame_mapping,
    canonicalize,
    check_frame,
    check_stream,
    strict_json_loads,
    verify_frame,
    verify_stream,
)
from .reports import Diagnostic, DiagnosticStatus, VerificationReport
from .resolution import RevisionSource, SpecResolver
from .schemas import SPEC_REVISION_SCHEMA_ID, read_spec_revision_schema
from .spec_chain import (
    ContentLocator,
    RevisionAddress,
    SpecChain,
    SpecRevision,
    build_spec_revision_frame,
)

__all__ = (
    "AuthorityCheckpoint",
    "CacheIntegrityError",
    "ContentLocator",
    "Diagnostic",
    "DiagnosticStatus",
    "KindFamilyRegistry",
    "PROTOCOL_VERSION",
    "PersistedHead",
    "ProtocolError",
    "RappSDKError",
    "RevisionAddress",
    "RevisionSource",
    "SPEC_REVISION_SCHEMA_ID",
    "SpecChain",
    "SpecChainError",
    "SpecResolver",
    "SpecResolutionError",
    "SpecRevision",
    "StreamTrustPolicy",
    "VERSION",
    "VerificationReport",
    "VerifiedFrame",
    "VerifiedStream",
    "__version__",
    "__version_info__",
    "build_frame_mapping",
    "build_spec_revision_frame",
    "canonicalize",
    "check_frame",
    "check_stream",
    "read_spec_revision_schema",
    "selected_authority_checkpoint",
    "selected_authority_registry",
    "selected_authority_trust_policy",
    "strict_json_loads",
    "verify_frame",
    "verify_stream",
)
