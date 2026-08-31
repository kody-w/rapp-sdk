"""Stable exceptions carrying immutable verification diagnostics."""

from __future__ import annotations

from typing import Mapping

from .reports import Diagnostic, DiagnosticScalar

ErrorContext = DiagnosticScalar
_PROTOCOL_STEPS = frozenset({"1", "1a", "2", "3", "4", "5", "6"})


class RappSDKError(ValueError):
    """Base class for expected SDK refusals."""

    operation = "sdk"

    def __init__(
        self,
        diagnostic: Diagnostic | str,
        message: str | None = None,
        *,
        step: str | None = None,
        context: Mapping[str, ErrorContext] | None = None,
        remediation: str | None = None,
    ) -> None:
        if isinstance(diagnostic, Diagnostic):
            if message is not None or step is not None or context or remediation:
                raise TypeError("a Diagnostic cannot be combined with legacy fields")
            value = diagnostic
        else:
            if message is None:
                raise TypeError("message is required with a diagnostic code")
            value = Diagnostic(
                code=diagnostic,
                operation=self.operation,
                message=message,
                protocol_step=step if step in _PROTOCOL_STEPS else None,
                location=None if step in _PROTOCOL_STEPS else step,
                context=context or {},
                remediation=remediation,
            )
        self.diagnostic = value
        super().__init__(value.message)

    @property
    def code(self) -> str:
        return self.diagnostic.code

    @property
    def message(self) -> str:
        return self.diagnostic.message

    @property
    def step(self) -> str | None:
        return self.diagnostic.protocol_step or self.diagnostic.location

    @property
    def context(self) -> Mapping[str, DiagnosticScalar]:
        return self.diagnostic.context

    def as_dict(self) -> dict[str, object]:
        return self.diagnostic.as_dict()

    def __str__(self) -> str:
        details = [f"code={self.code!r}", f"operation={self.diagnostic.operation!r}"]
        if self.diagnostic.protocol_step is not None:
            details.append(f"protocol_step={self.diagnostic.protocol_step!r}")
        if self.diagnostic.location is not None:
            details.append(f"location={self.diagnostic.location!r}")
        details.extend(f"{key}={value!r}" for key, value in self.context.items())
        return f"{self.message} ({', '.join(details)})"

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.diagnostic!r})"


class ProtocolError(RappSDKError):
    """A RAPP/1 JSON, frame, hash, registry, or stream refusal."""

    operation = "protocol"


class SpecChainError(RappSDKError):
    """A specification-chain structure or payload-profile refusal."""

    operation = "spec-chain"


class SpecResolutionError(SpecChainError):
    """A verified specification revision could not be resolved safely."""

    operation = "spec-resolution"


class CacheIntegrityError(SpecResolutionError):
    """A content-addressed cache object failed checksum revalidation."""


class RingManifestError(RappSDKError):
    """A RAPP ring-yard manifest failed closed validation."""

    operation = "ring-manifest"


class ProjectProtocolError(RappSDKError):
    """A RAPP Projects frame, checkpoint, or project egg was invalid."""

    operation = "projects"


__all__ = (
    "CacheIntegrityError",
    "ErrorContext",
    "ProtocolError",
    "ProjectProtocolError",
    "RappSDKError",
    "RingManifestError",
    "SpecChainError",
    "SpecResolutionError",
)
