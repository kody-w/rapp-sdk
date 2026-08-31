"""Pure append-only specification-chain indexing over verified RAPP/1 streams."""

from __future__ import annotations

import hashlib
import os
import re
import time
import urllib.parse
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TypeAlias, overload

from .errors import ErrorContext, ProtocolError, SpecChainError
from .protocol import (
    DEFAULT_VERIFY_SECONDS,
    Frame,
    FrameMapping,
    JsonValue,
    KindFamilyRegistry,
    MAX_CANONICAL_BYTES,
    MAX_SAFE_INTEGER,
    MAX_STREAM_FRAMES,
    StreamTrustPolicy,
    VerifiedFrame,
    VerifiedStream,
    _check_stream,
    _validate_limits,
    build_frame_mapping,
    canonicalize,
    strict_json_loads,
)
from .reports import Diagnostic

MAX_CHAIN_BYTES = 8 * 1024 * 1024
MAX_SPEC_BYTES = MAX_CANONICAL_BYTES

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", re.ASCII)
_DECIMAL_BYTES_RE = re.compile(r"^(?:0|[1-9][0-9]*)$", re.ASCII)
_CANONICAL_REPOSITORY_RE = re.compile(
    r"^https://"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
    r"(?::443)?/"
    r"(?!/)(?!.*//)(?!.*(?:^|/)\.\.?(?:/|(?![\s\S])))"
    r"(?!.*[\\%?#\x00-\x20\x7f])(?:[^/]+/)*[^/]+$",
    re.ASCII,
)
_POINTER_KEYS = frozenset(
    {
        "canonical_repo",
        "commit",
        "normative_path",
        "normative_sha256",
        "normative_bytes",
    }
)

StrPath: TypeAlias = str | os.PathLike[str]


def _chain_diagnostic(
    code: str,
    message: str,
    *,
    location: str,
    context: Mapping[str, ErrorContext] | None = None,
    remediation: str | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        operation="spec-chain",
        message=message,
        location=location,
        context=context or {},
        remediation=remediation,
    )


def _chain_fail(
    code: str,
    message: str,
    *,
    location: str,
    context: Mapping[str, ErrorContext] | None = None,
    remediation: str | None = None,
) -> None:
    raise SpecChainError(
        _chain_diagnostic(
            code,
            message,
            location=location,
            context=context,
            remediation=remediation,
        )
    )


def _path_from(value: StrPath, *, name: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be str or os.PathLike[str]") from exc
    if not isinstance(raw, str):
        raise TypeError(f"{name} must resolve to text, not bytes")
    return Path(raw)


def _validate_https_repository(repository: JsonValue) -> str:
    if (
        type(repository) is not str
        or not 1 <= len(repository) <= 2048
        or _CANONICAL_REPOSITORY_RE.fullmatch(repository) is None
        or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in repository
        )
    ):
        _chain_fail(
            "invalid-repository",
            "canonical_repo must be a bounded HTTPS URL string",
            location="payload.canonical_repo",
        )
    try:
        parsed = urllib.parse.urlsplit(repository)
        port = parsed.port
    except ValueError as exc:
        raise SpecChainError(
            _chain_diagnostic(
                "invalid-repository",
                "canonical_repo is not a valid URL",
                location="payload.canonical_repo",
            )
        ) from exc
    if parsed.scheme != "https" or not parsed.hostname or port not in (None, 443):
        _chain_fail(
            "invalid-repository",
            "canonical_repo must be an HTTPS URL without credentials or query",
            location="payload.canonical_repo",
        )
    return repository


def _validate_commit(commit: JsonValue) -> str:
    if type(commit) is not str or _HEX40_RE.fullmatch(commit) is None:
        _chain_fail(
            "mutable-revision",
            "legacy pointers require an immutable 40-hex commit",
            location="payload.commit",
            context={"commit": commit if isinstance(commit, str) else None},
        )
    return commit


def _validate_path(path: JsonValue) -> str:
    if (
        type(path) is not str
        or not 1 <= len(path) <= 1024
        or "\\" in path
        or "%" in path
        or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in path
        )
    ):
        _chain_fail(
            "unsafe-path",
            "normative_path must be a 1-1024 character unescaped POSIX path",
            location="payload.normative_path",
            context={"path": path if isinstance(path, str) else None},
        )
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or str(candidate) != path
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(character in path for character in ("?", "#"))
    ):
        _chain_fail(
            "unsafe-path",
            "normative_path cannot be absolute, normalized, or traversing",
            location="payload.normative_path",
            context={"path": path},
        )
    return path


def _validate_sha256(value: JsonValue, *, location: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        _chain_fail(
            "invalid-spec-hash",
            "specification checksum must be 64 lowercase hex",
            location=location,
        )
    return value


def _legacy_size(value: JsonValue) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        size = int(value)
    elif type(value) is str and _DECIMAL_BYTES_RE.fullmatch(value):
        size = int(value)
    else:
        _chain_fail(
            "invalid-spec-size",
            "legacy normative_bytes must be an integer or decimal string",
            location="payload.normative_bytes",
        )
    if not 0 <= size <= MAX_SPEC_BYTES:
        _chain_fail(
            "spec-size-exceeded",
            f"normative_bytes exceeds {MAX_SPEC_BYTES} bytes",
            location="payload.normative_bytes",
        )
    return size


def _inline_size(value: JsonValue) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _chain_fail(
            "invalid-inline-size",
            "normative.bytes must be an integer",
            location="payload.normative.bytes",
        )
    size = int(value)
    if not 0 <= size <= MAX_SPEC_BYTES:
        _chain_fail(
            "spec-size-exceeded",
            f"normative.bytes exceeds {MAX_SPEC_BYTES} bytes",
            location="payload.normative.bytes",
        )
    return size


@dataclass(frozen=True, slots=True)
class RevisionAddress:
    """Stable selectors for one frame in a specification chain."""

    revision: str
    seq: int
    frame_hash: str
    payload_hash: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "revision": self.revision,
            "seq": self.seq,
            "frame_hash": self.frame_hash,
            "payload_hash": self.payload_hash,
        }

    def to_json_bytes(self) -> bytes:
        return canonicalize(self.as_dict())


@dataclass(frozen=True, slots=True)
class ContentLocator:
    """Source-neutral immutable content lookup hints."""

    scheme: str
    attributes: Mapping[str, str]

    def __post_init__(self) -> None:
        if type(self.scheme) is not str or not self.scheme:
            raise ValueError("locator scheme must be non-empty text")
        values = dict(self.attributes)
        if any(type(key) is not str or type(value) is not str for key, value in values.items()):
            raise TypeError("locator attributes must contain text pairs")
        object.__setattr__(
            self,
            "attributes",
            MappingProxyType(dict(sorted(values.items()))),
        )


@dataclass(frozen=True, slots=True, init=False)
class SpecRevision:
    """Immutable metadata for one verified specification revision."""

    address: RevisionAddress
    stream_id: str
    normative_sha256: str
    normative_bytes: int
    media_type: str
    locator: ContentLocator | None
    is_inline: bool
    frame: VerifiedFrame

    @classmethod
    def _create(
        cls,
        *,
        address: RevisionAddress,
        stream_id: str,
        normative_sha256: str,
        normative_bytes: int,
        media_type: str,
        locator: ContentLocator | None,
        is_inline: bool,
        frame: VerifiedFrame,
    ) -> SpecRevision:
        value = object.__new__(cls)
        object.__setattr__(value, "address", address)
        object.__setattr__(value, "stream_id", stream_id)
        object.__setattr__(value, "normative_sha256", normative_sha256)
        object.__setattr__(value, "normative_bytes", normative_bytes)
        object.__setattr__(value, "media_type", media_type)
        object.__setattr__(value, "locator", locator)
        object.__setattr__(value, "is_inline", is_inline)
        object.__setattr__(value, "frame", frame)
        return value

    @property
    def revision(self) -> str:
        return self.address.revision

    @property
    def seq(self) -> int:
        return self.address.seq

    @property
    def frame_hash(self) -> str:
        return self.address.frame_hash

    @property
    def payload_hash(self) -> str:
        return self.address.payload_hash

    def to_dict(self) -> Frame:
        return self.frame.to_dict()

    def to_json_bytes(self) -> bytes:
        return self.frame.to_json_bytes()

    def inline_bytes(self) -> bytes | None:
        payload = self.frame.to_dict()["payload"]
        if type(payload) is not dict:
            raise RuntimeError("verified revision payload is not an object")
        normative = payload.get("normative")
        if normative is None:
            return None
        if type(normative) is not dict or type(normative.get("text")) is not str:
            _chain_fail(
                "invalid-inline-normative",
                "verified inline normative object is malformed",
                location=f"frame[{self.seq}].payload.normative",
            )
        data = normative["text"].encode("utf-8")
        if len(data) != self.normative_bytes:
            _chain_fail(
                "inline-size-mismatch",
                "verified inline bytes no longer match their length",
                location=f"frame[{self.seq}].payload.normative",
            )
        if hashlib.sha256(data).hexdigest() != self.normative_sha256:
            _chain_fail(
                "inline-hash-mismatch",
                "verified inline bytes no longer match their checksum",
                location=f"frame[{self.seq}].payload.normative",
            )
        return data


def _profile_revision(frame: VerifiedFrame) -> SpecRevision:
    wire = frame.to_dict()
    payload = wire["payload"]
    if type(payload) is not dict:
        raise RuntimeError("verified frame payload is not an object")
    revision = payload.get("revision")
    if type(revision) is not str or _REVISION_RE.fullmatch(revision) is None:
        _chain_fail(
            "invalid-revision",
            "payload.revision must be a stable revision label",
            location=f"frame[{frame.seq}].payload.revision",
        )

    pointer_fields = _POINTER_KEYS.intersection(payload)
    has_pointer = bool(pointer_fields)
    if has_pointer and pointer_fields != _POINTER_KEYS:
        _chain_fail(
            "incomplete-pointer",
            "legacy pointer fields must be present as a complete set",
            location=f"frame[{frame.seq}].payload",
            context={"missing": ",".join(sorted(_POINTER_KEYS - pointer_fields))},
        )
    normative = payload.get("normative")
    if normative is None and not has_pointer:
        _chain_fail(
            "missing-normative",
            "revision needs inline normative bytes or a legacy pointer",
            location=f"frame[{frame.seq}].payload",
        )

    locator: ContentLocator | None = None
    pointer_sha: str | None = None
    pointer_size: int | None = None
    if has_pointer:
        repository = _validate_https_repository(payload["canonical_repo"])
        commit = _validate_commit(payload["commit"])
        path = _validate_path(payload["normative_path"])
        pointer_sha = _validate_sha256(
            payload["normative_sha256"],
            location=f"frame[{frame.seq}].payload.normative_sha256",
        )
        pointer_size = _legacy_size(payload["normative_bytes"])
        locator = ContentLocator(
            scheme="rapp-legacy-repository-v1",
            attributes={
                "repository": repository,
                "commit": commit,
                "path": path,
            },
        )

    inline_bytes: bytes | None = None
    if normative is not None:
        if type(normative) is not dict or set(normative) != {
            "media_type",
            "text",
            "sha256",
            "bytes",
        }:
            _chain_fail(
                "invalid-inline-normative",
                "normative must contain exactly media_type,text,sha256,bytes",
                location=f"frame[{frame.seq}].payload.normative",
            )
        media_type = normative["media_type"]
        if (
            type(media_type) is not str
            or not 1 <= len(media_type) <= 127
            or any(
                ord(character) < 0x20 or ord(character) > 0x7E
                for character in media_type
            )
        ):
            _chain_fail(
                "invalid-media-type",
                "normative.media_type must be printable ASCII",
                location=f"frame[{frame.seq}].payload.normative.media_type",
            )
        text = normative["text"]
        if type(text) is not str:
            _chain_fail(
                "invalid-inline-text",
                "normative.text must be a string",
                location=f"frame[{frame.seq}].payload.normative.text",
            )
        try:
            inline_bytes = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SpecChainError(
                _chain_diagnostic(
                    "invalid-inline-text",
                    "normative.text is not valid Unicode",
                    location=f"frame[{frame.seq}].payload.normative.text",
                )
            ) from exc
        inline_sha = _validate_sha256(
            normative["sha256"],
            location=f"frame[{frame.seq}].payload.normative.sha256",
        )
        inline_size = _inline_size(normative["bytes"])
        if len(inline_bytes) != inline_size:
            _chain_fail(
                "inline-size-mismatch",
                "normative.text byte count does not match normative.bytes",
                location=f"frame[{frame.seq}].payload.normative",
            )
        if hashlib.sha256(inline_bytes).hexdigest() != inline_sha:
            _chain_fail(
                "inline-hash-mismatch",
                "normative.text checksum does not match normative.sha256",
                location=f"frame[{frame.seq}].payload.normative",
            )
        if has_pointer and (inline_sha != pointer_sha or inline_size != pointer_size):
            _chain_fail(
                "normative-metadata-conflict",
                "inline and legacy normative metadata disagree",
                location=f"frame[{frame.seq}].payload",
            )
        normative_sha = inline_sha
        normative_size = inline_size
    else:
        media_type = "text/markdown; charset=utf-8"
        if pointer_sha is None or pointer_size is None:
            raise RuntimeError("legacy pointer metadata is incomplete")
        normative_sha = pointer_sha
        normative_size = pointer_size

    return SpecRevision._create(
        address=RevisionAddress(
            revision=revision,
            seq=frame.seq,
            frame_hash=frame.frame_hash,
            payload_hash=frame.payload_hash,
        ),
        stream_id=frame.stream_id,
        normative_sha256=normative_sha,
        normative_bytes=normative_size,
        media_type=media_type,
        locator=locator,
        is_inline=inline_bytes is not None,
        frame=frame,
    )


def _jsonl_frames(
    octets: bytes,
    *,
    deadline: float,
    max_frames: int,
) -> Iterator[Frame]:
    if not octets:
        raise ProtocolError(
            Diagnostic(
                code="empty-stream",
                operation="parse-chain",
                message="specification chain is empty",
                location="chain",
            )
        )
    start = 0
    count = 0
    length = len(octets)
    while start < length:
        if count >= max_frames:
            raise ProtocolError(
                Diagnostic(
                    code="frame-count-exceeded",
                    operation="parse-chain",
                    message=f"chain exceeds {max_frames} frames",
                    location=f"line[{count + 1}]",
                    context={"max_frames": max_frames},
                )
            )
        if time.monotonic() >= deadline:
            raise ProtocolError(
                Diagnostic(
                    code="verification-time-exceeded",
                    operation="parse-chain",
                    message="chain parsing exceeded its time budget",
                    location=f"line[{count + 1}]",
                )
            )
        newline = octets.find(b"\n", start)
        end = length if newline < 0 else newline
        line = octets[start:end]
        if line.endswith(b"\r"):
            line = line[:-1]
        if b"\r" in line:
            raise ProtocolError(
                Diagnostic(
                    code="invalid-line-ending",
                    operation="parse-chain",
                    message="chain contains a bare carriage return",
                    location=f"line[{count + 1}]",
                )
            )
        if not line.strip():
            raise ProtocolError(
                Diagnostic(
                    code="blank-chain-line",
                    operation="parse-chain",
                    message="chain contains a blank line",
                    location=f"line[{count + 1}]",
                )
            )
        try:
            value = strict_json_loads(line, max_bytes=MAX_CANONICAL_BYTES)
        except ProtocolError as exc:
            diagnostic = exc.diagnostic
            raise ProtocolError(
                Diagnostic(
                    code=diagnostic.code,
                    operation=diagnostic.operation,
                    message=diagnostic.message,
                    protocol_step=diagnostic.protocol_step,
                    location=f"line[{count + 1}]",
                    context=diagnostic.context,
                    remediation=diagnostic.remediation,
                )
            ) from exc
        if type(value) is not dict:
            raise ProtocolError(
                Diagnostic(
                    code="non-object-frame",
                    operation="parse-chain",
                    message="chain line is not a JSON object",
                    location=f"line[{count + 1}]",
                )
            )
        yield value
        count += 1
        if newline < 0:
            break
        start = newline + 1
    if octets.endswith(b"\n") and start < length:
        raise RuntimeError("unreachable JSONL cursor state")


_SPEC_CHAIN_CAPABILITY = object()


class SpecChain:
    """Immutable revision index over a trusted or explicit local stream."""

    __slots__ = (
        "_stream",
        "_revisions",
        "_by_revision",
        "_by_seq",
        "_by_frame_hash",
        "_by_payload_hash",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use a verified SpecChain.from_* constructor")

    @classmethod
    def _create(
        cls,
        stream: VerifiedStream,
        *,
        deadline: float,
        capability: object,
    ) -> SpecChain:
        if capability is not _SPEC_CHAIN_CAPABILITY:
            raise PermissionError("SpecChain construction capability required")
        revisions: list[SpecRevision] = []
        for frame in stream.frames:
            if time.monotonic() >= deadline:
                _chain_fail(
                    "verification-time-exceeded",
                    "specification profile validation exceeded its time budget",
                    location=f"frame[{frame.seq}]",
                )
            revisions.append(_profile_revision(frame))
        revision_tuple = tuple(revisions)
        value = object.__new__(cls)
        value._stream = stream
        value._revisions = revision_tuple
        by_revision: dict[str, list[SpecRevision]] = {}
        if len({item.payload_hash for item in revision_tuple}) != len(
            revision_tuple
        ):
            _chain_fail(
                "duplicate-payload",
                "payload_hash is repeated in the specification stream",
                location="chain",
            )
        value._by_seq = MappingProxyType(
            {item.seq: item for item in revision_tuple}
        )
        value._by_frame_hash = MappingProxyType(
            {item.frame_hash: item for item in revision_tuple}
        )
        value._by_payload_hash = MappingProxyType(
            {item.payload_hash: item for item in revision_tuple}
        )
        for item in revision_tuple:
            aliases = by_revision.setdefault(item.revision, [])
            if aliases:
                same_legacy_bytes = (
                    not item.is_inline
                    and all(not prior.is_inline for prior in aliases)
                    and all(
                        prior.normative_sha256 == item.normative_sha256
                        and prior.normative_bytes == item.normative_bytes
                        for prior in aliases
                    )
                )
                if not same_legacy_bytes:
                    _chain_fail(
                        "duplicate-revision",
                        "revision label addresses different normative bytes",
                        location=f"frame[{item.seq}].payload.revision",
                        context={"revision": item.revision},
                    )
            aliases.append(item)
        value._by_revision = MappingProxyType(
            {key: tuple(values) for key, values in by_revision.items()}
        )
        return value

    @classmethod
    def _from_frames(
        cls,
        frames: Iterable[FrameMapping],
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy | None,
        local: bool,
        expected_stream_id: str | None,
        max_frames: int,
        max_seconds: float,
        deadline: float | None = None,
    ) -> SpecChain:
        absolute_deadline = (
            _validate_limits(max_frames, max_seconds)
            if deadline is None
            else deadline
        )
        report = _check_stream(
            frames,
            registry=registry,
            trust_policy=trust_policy,
            local=local,
            expected_stream_id=expected_stream_id,
            signature_verifier=None,
            max_frames=max_frames,
            max_seconds=max_seconds,
            _deadline=absolute_deadline,
        )
        try:
            stream = report.require(ProtocolError)
        except ProtocolError as exc:
            raise SpecChainError(exc.diagnostic) from exc
        return cls._create(
            stream,
            deadline=absolute_deadline,
            capability=_SPEC_CHAIN_CAPABILITY,
        )

    @classmethod
    def from_frames(
        cls,
        frames: Iterable[FrameMapping],
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy,
        expected_stream_id: str | None = None,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        return cls._from_frames(
            frames,
            registry=registry,
            trust_policy=trust_policy,
            local=False,
            expected_stream_id=expected_stream_id,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_frames_local(
        cls,
        frames: Iterable[FrameMapping],
        *,
        registry: KindFamilyRegistry,
        expected_stream_id: str | None = None,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        return cls._from_frames(
            frames,
            registry=registry,
            trust_policy=None,
            local=True,
            expected_stream_id=expected_stream_id,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def _from_jsonl(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy | None,
        local: bool,
        expected_stream_id: str | None,
        max_bytes: int,
        max_frames: int,
        max_seconds: float,
        deadline: float | None = None,
    ) -> SpecChain:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SpecChain.from_jsonl accepts bytes")
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        absolute_deadline = (
            _validate_limits(max_frames, max_seconds)
            if deadline is None
            else deadline
        )
        octets = bytes(data)
        if len(octets) > max_bytes:
            _chain_fail(
                "chain-size-exceeded",
                f"chain exceeds {max_bytes} bytes",
                location="chain",
                context={"actual_bytes": len(octets), "max_bytes": max_bytes},
            )
        if (
            not local
            and trust_policy is not None
            and trust_policy.checkpoint is not None
        ):
            actual_chain_sha256 = hashlib.sha256(octets).hexdigest()
            expected_chain_sha256 = trust_policy.checkpoint.chain_sha256
            if actual_chain_sha256 != expected_chain_sha256:
                _chain_fail(
                    "authority-snapshot-mismatch",
                    "JSONL bytes do not match the authenticated checkpoint",
                    location="chain",
                    context={
                        "actual_sha256": actual_chain_sha256,
                        "expected_sha256": expected_chain_sha256,
                    },
                )
        return cls._from_frames(
            _jsonl_frames(
                octets,
                deadline=absolute_deadline,
                max_frames=max_frames,
            ),
            registry=registry,
            trust_policy=trust_policy,
            local=local,
            expected_stream_id=expected_stream_id,
            max_frames=max_frames,
            max_seconds=max_seconds,
            deadline=absolute_deadline,
        )

    @classmethod
    def from_jsonl(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        return cls._from_jsonl(
            data,
            registry=registry,
            trust_policy=trust_policy,
            local=False,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_jsonl_text(
        cls,
        text: str,
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        if type(text) is not str:
            raise TypeError("SpecChain.from_jsonl_text accepts text")
        try:
            data = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SpecChainError(
                _chain_diagnostic(
                    "invalid-utf8",
                    "JSONL text contains an unpaired surrogate",
                    location="chain",
                )
            ) from exc
        return cls.from_jsonl(
            data,
            registry=registry,
            trust_policy=trust_policy,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_jsonl_local(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        registry: KindFamilyRegistry,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        return cls._from_jsonl(
            data,
            registry=registry,
            trust_policy=None,
            local=True,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_jsonl_text_local(
        cls,
        text: str,
        *,
        registry: KindFamilyRegistry,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        if type(text) is not str:
            raise TypeError("SpecChain.from_jsonl_text_local accepts text")
        try:
            data = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SpecChainError(
                _chain_diagnostic(
                    "invalid-utf8",
                    "JSONL text contains an unpaired surrogate",
                    location="chain",
                )
            ) from exc
        return cls.from_jsonl_local(
            data,
            registry=registry,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_frames=max_frames,
            max_seconds=max_seconds,
        )

    @classmethod
    def load(
        cls,
        path: StrPath,
        *,
        registry: KindFamilyRegistry,
        trust_policy: StreamTrustPolicy,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_frames: int = MAX_STREAM_FRAMES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> SpecChain:
        deadline = _validate_limits(max_frames, max_seconds)
        source = _path_from(path, name="path")
        size = source.stat().st_size
        if size > max_bytes:
            _chain_fail(
                "chain-size-exceeded",
                f"chain exceeds {max_bytes} bytes",
                location=str(source),
                context={"actual_bytes": size, "max_bytes": max_bytes},
            )
        with source.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        return cls._from_jsonl(
            data,
            registry=registry,
            trust_policy=trust_policy,
            local=False,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_frames=max_frames,
            max_seconds=max_seconds,
            deadline=deadline,
        )

    def __len__(self) -> int:
        return len(self._revisions)

    def __iter__(self) -> Iterator[SpecRevision]:
        return iter(self._revisions)

    @overload
    def __getitem__(self, index: int) -> SpecRevision: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[SpecRevision, ...]: ...

    def __getitem__(
        self,
        index: int | slice,
    ) -> SpecRevision | tuple[SpecRevision, ...]:
        return self._revisions[index]

    @property
    def trusted(self) -> bool:
        return self._stream.trusted

    @property
    def trust_label(self) -> str:
        return self._stream.trust_label

    @property
    def revisions(self) -> tuple[SpecRevision, ...]:
        return self._revisions

    @property
    def head(self) -> SpecRevision:
        return self._revisions[-1]

    @property
    def stream_id(self) -> str:
        return self._stream.head.stream_id

    def to_jsonl_bytes(self) -> bytes:
        return self._stream.to_jsonl_bytes()

    def contains(self, revision: SpecRevision) -> bool:
        return self._by_frame_hash.get(revision.frame_hash) is revision

    def resolve(
        self,
        *,
        revision: str | None = None,
        seq: int | None = None,
        frame_hash: str | None = None,
        payload_hash: str | None = None,
    ) -> SpecRevision:
        supplied = sum(
            value is not None
            for value in (revision, seq, frame_hash, payload_hash)
        )
        if supplied != 1:
            raise ValueError("provide exactly one keyword selector")
        if revision is not None:
            if type(revision) is not str:
                raise TypeError("revision must be text")
            matches = self._by_revision.get(revision)
            if not matches:
                _chain_fail(
                    "unknown-revision",
                    "revision label is not present",
                    location="selector.revision",
                    context={"revision": revision},
                )
            return matches[-1]
        if seq is not None:
            if type(seq) is not int or not 0 <= seq <= MAX_SAFE_INTEGER:
                raise ValueError("seq selector must be uint53")
            selected = self._by_seq.get(seq)
            location = "selector.seq"
        elif frame_hash is not None:
            if type(frame_hash) is not str or _HEX64_RE.fullmatch(frame_hash) is None:
                raise ValueError("frame_hash selector must be 64 lowercase hex")
            selected = self._by_frame_hash.get(frame_hash)
            location = "selector.frame_hash"
        else:
            if (
                type(payload_hash) is not str
                or _HEX64_RE.fullmatch(payload_hash) is None
            ):
                raise ValueError("payload_hash selector must be 64 lowercase hex")
            selected = self._by_payload_hash.get(payload_hash)
            location = "selector.payload_hash"
        if selected is None:
            _chain_fail(
                "unknown-revision",
                "selector does not match a revision",
                location=location,
            )
        return selected


def build_spec_revision_frame(
    *,
    revision: str,
    text: str,
    utc: str,
    head: VerifiedFrame | None = None,
    stream_id: str | None = None,
    kind: str = "body.pulse",
    media_type: str = "text/markdown; charset=utf-8",
    payload_extra: Mapping[str, JsonValue] | None = None,
) -> Frame:
    """Build a mutable self-contained revision wire mapping."""

    if type(revision) is not str or _REVISION_RE.fullmatch(revision) is None:
        _chain_fail(
            "invalid-revision",
            "revision label is invalid",
            location="revision",
        )
    if type(text) is not str:
        raise TypeError("text must be a string")
    if (
        type(media_type) is not str
        or not 1 <= len(media_type) <= 127
        or any(
            ord(character) < 0x20 or ord(character) > 0x7E
            for character in media_type
        )
    ):
        _chain_fail(
            "invalid-media-type",
            "media_type must be printable ASCII",
            location="media_type",
        )
    try:
        normative_bytes = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SpecChainError(
            _chain_diagnostic(
                "invalid-inline-text",
                "text is not valid Unicode",
                location="text",
            )
        ) from exc
    if len(normative_bytes) > MAX_SPEC_BYTES:
        _chain_fail(
            "spec-size-exceeded",
            f"normative text exceeds {MAX_SPEC_BYTES} bytes",
            location="text",
        )
    extra = dict(payload_extra or {})
    if {"revision", "normative"}.intersection(extra):
        _chain_fail(
            "reserved-payload-key",
            "payload_extra cannot replace revision or normative",
            location="payload_extra",
        )
    payload: dict[str, JsonValue] = {
        **extra,
        "revision": revision,
        "normative": {
            "media_type": media_type,
            "text": text,
            "sha256": hashlib.sha256(normative_bytes).hexdigest(),
            "bytes": len(normative_bytes),
        },
    }
    if head is None:
        if stream_id is None:
            raise ValueError("stream_id is required for a genesis revision")
        seq = 0
        prev = None
        prev_wave = None
    else:
        if not isinstance(head, VerifiedFrame):
            raise TypeError("head must be VerifiedFrame or None")
        if stream_id is not None and stream_id != head.stream_id:
            _chain_fail(
                "stream-binding-mismatch",
                "explicit stream_id does not match head",
                location="stream_id",
            )
        stream_id = head.stream_id
        if head.seq >= MAX_SAFE_INTEGER:
            _chain_fail(
                "seq-exhausted",
                "head cannot be extended",
                location="head.seq",
            )
        if utc < head.utc:
            _chain_fail(
                "utc-regression",
                "revision utc is earlier than the supplied head",
                location="utc",
            )
        seq = head.seq + 1
        prev = head.payload_hash
        prev_wave = head.frame_hash if head.family == "swarm" else None
    return build_frame_mapping(
        kind,
        stream_id,
        seq,
        utc,
        payload,
        prev,
        prev_wave=prev_wave,
    )


__all__ = (
    "ContentLocator",
    "MAX_CHAIN_BYTES",
    "MAX_SPEC_BYTES",
    "RevisionAddress",
    "SpecChain",
    "SpecRevision",
    "StrPath",
    "build_spec_revision_frame",
)
