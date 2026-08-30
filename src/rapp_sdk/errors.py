"""Stable public exceptions for the RAPP SDK."""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

ErrorContext = str | int | bool | None


class RappSDKError(ValueError):
    """Base class for expected, actionable SDK refusals.

    Attributes:
        code: Stable machine-readable error code.
        step: Protocol or operation stage that refused the input.
        context: Immutable, deterministically ordered diagnostic values.

    Example:
        >>> error = RappSDKError("invalid", "input refused", step="parse")
        >>> error.as_dict()["code"]
        'invalid'
    """

    __slots__ = ("code", "step", "context")

    def __init__(
        self,
        code: str,
        message: str,
        *,
        step: str | None = None,
        context: Mapping[str, ErrorContext] | None = None,
    ) -> None:
        if not isinstance(code, str) or not code:
            raise TypeError("code must be non-empty text")
        if not isinstance(message, str) or not message:
            raise TypeError("message must be non-empty text")
        if step is not None and not isinstance(step, str):
            raise TypeError("step must be text or None")
        values = dict(context or {})
        if any(not isinstance(key, str) for key in values):
            raise TypeError("error context keys must be text")
        if any(
            value is not None and type(value) not in (str, int, bool)
            for value in values.values()
        ):
            raise TypeError("error context values must be immutable scalars")
        self.code = code
        self.step = step
        self.context = MappingProxyType(dict(sorted(values.items())))
        super().__init__(message)

    @property
    def message(self) -> str:
        """Human-readable refusal reason without formatted context."""

        return self.args[0]

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-ready diagnostic object."""

        result: dict[str, object] = {
            "code": self.code,
            "message": self.message,
        }
        if self.step is not None:
            result["step"] = self.step
        if self.context:
            result["context"] = dict(self.context)
        return result

    def __str__(self) -> str:
        details = [f"code={self.code!r}"]
        if self.step is not None:
            details.append(f"step={self.step!r}")
        details.extend(f"{key}={value!r}" for key, value in self.context.items())
        return f"{self.message} ({', '.join(details)})"

    def __repr__(self) -> str:
        arguments = [
            repr(self.code),
            repr(self.message),
            f"step={self.step!r}",
            f"context={dict(self.context)!r}",
        ]
        return f"{type(self).__name__}({', '.join(arguments)})"


class ProtocolError(RappSDKError):
    """A RAPP/1 JSON, frame, hash, or stream validation refusal."""


class SpecChainError(RappSDKError):
    """A specification-chain structure or payload-profile refusal."""


class SpecResolutionError(SpecChainError):
    """A verified specification revision could not be resolved safely."""


class CacheIntegrityError(SpecResolutionError):
    """A content-addressed cache object failed checksum revalidation."""


__all__ = (
    "CacheIntegrityError",
    "ErrorContext",
    "ProtocolError",
    "RappSDKError",
    "SpecChainError",
    "SpecResolutionError",
)
