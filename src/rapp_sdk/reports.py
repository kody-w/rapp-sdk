"""Immutable verification diagnostics and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Generic, Mapping, TypeVar

from .diagnostic_codes import DIAGNOSTIC_CODES

if TYPE_CHECKING:
    from .errors import RappSDKError

DiagnosticScalar = str | int | bool | None
T = TypeVar("T")
E = TypeVar("E", bound="RappSDKError")


class DiagnosticStatus(str, Enum):
    """Severity of one ordered verification diagnostic."""

    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One stable, machine-readable verification finding.

    >>> Diagnostic(
    ...     "source-required",
    ...     "spec-resolution",
    ...     "an explicit source is required",
    ... ).as_dict()["code"]
    'source-required'
    """

    code: str
    operation: str
    message: str
    status: DiagnosticStatus = DiagnosticStatus.ERROR
    protocol_step: str | None = None
    location: str | None = None
    context: Mapping[str, DiagnosticScalar] = field(default_factory=dict)
    remediation: str | None = None

    def __post_init__(self) -> None:
        if not self.code or not self.operation or not self.message:
            raise ValueError("diagnostic code, operation, and message are required")
        if self.code not in DIAGNOSTIC_CODES:
            raise ValueError(f"diagnostic code is not registered: {self.code}")
        if not isinstance(self.status, DiagnosticStatus):
            raise TypeError("diagnostic status must be DiagnosticStatus")
        for name, value in (
            ("protocol_step", self.protocol_step),
            ("location", self.location),
            ("remediation", self.remediation),
        ):
            if value is not None and type(value) is not str:
                raise TypeError(f"diagnostic {name} must be text or None")
        values = dict(self.context)
        if any(type(key) is not str for key in values):
            raise TypeError("diagnostic context keys must be text")
        if any(
            value is not None and type(value) not in (str, int, bool)
            for value in values.values()
        ):
            raise TypeError("diagnostic context values must be immutable scalars")
        object.__setattr__(
            self,
            "context",
            MappingProxyType(dict(sorted(values.items()))),
        )

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-ready diagnostic."""

        result: dict[str, object] = {
            "code": self.code,
            "operation": self.operation,
            "message": self.message,
            "status": self.status.value,
        }
        if self.protocol_step is not None:
            result["protocol_step"] = self.protocol_step
        if self.location is not None:
            result["location"] = self.location
        if self.context:
            result["context"] = dict(self.context)
        if self.remediation is not None:
            result["remediation"] = self.remediation
        return result


@dataclass(frozen=True, slots=True)
class VerificationReport(Generic[T]):
    """A verified value or ordered diagnostics explaining refusal.

    >>> VerificationReport(42).require()
    42
    """

    value: T | None
    diagnostics: tuple[Diagnostic, ...] = ()
    trusted: bool = False

    def __post_init__(self) -> None:
        diagnostics = tuple(self.diagnostics)
        if any(not isinstance(item, Diagnostic) for item in diagnostics):
            raise TypeError("diagnostics must contain only Diagnostic values")
        if type(self.trusted) is not bool:
            raise TypeError("trusted must be bool")
        object.__setattr__(self, "diagnostics", diagnostics)

    @property
    def ok(self) -> bool:
        """Whether verification produced a value."""

        return self.value is not None

    def require(self, error_type: type[E] | None = None) -> T:
        """Return the value or raise an SDK exception carrying the diagnostic."""

        if self.value is not None:
            return self.value
        from .errors import RappSDKError

        diagnostic = next(
            (
                item
                for item in reversed(self.diagnostics)
                if item.status is DiagnosticStatus.ERROR
            ),
            Diagnostic(
                code="verification-failed",
                operation="verification",
                message="verification failed without a diagnostic",
            ),
        )
        exception_type = error_type or RappSDKError
        raise exception_type(diagnostic)


__all__ = (
    "Diagnostic",
    "DiagnosticScalar",
    "DiagnosticStatus",
    "VerificationReport",
)
