"""Append-only RAPP/1 specification-chain loading and resolution."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Iterable, Iterator, Mapping, Set
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol, TypeAlias, overload

from ._version import __version__
from .errors import (
    CacheIntegrityError,
    ErrorContext,
    ProtocolError,
    SpecChainError,
    SpecResolutionError,
)

from .protocol import (
    DEFAULT_VERIFY_SECONDS,
    Frame,
    FrameMapping,
    JsonValue,
    MAX_CANONICAL_BYTES,
    MAX_SAFE_INTEGER,
    _validate_frame_integrity,
    build_frame,
    canonicalize,
    strict_json_loads,
    verify_stream,
)

MAX_CHAIN_BYTES = 8 * 1024 * 1024
MAX_SPEC_BYTES = MAX_CANONICAL_BYTES
DEFAULT_FETCH_SECONDS = 30.0
DEFAULT_ALLOWED_FETCH_HOSTS = frozenset({"raw.githubusercontent.com"})

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", re.ASCII)
_GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$", re.ASCII)
_DECIMAL_BYTES_RE = re.compile(r"^(?:0|[1-9][0-9]*)$", re.ASCII)
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
RevisionSelector: TypeAlias = str | int


class ByteFetcher(Protocol):
    """Fetch exact bytes from a validated HTTPS URL."""

    def fetch(self, url: str, *, max_bytes: int) -> bytes:
        """Return at most ``max_bytes`` response bytes."""


class ImmutableSource(Protocol):
    """Resolve exact bytes from an immutable repository object."""

    def fetch(
        self,
        repository: str,
        commit: str,
        path: str,
        *,
        max_bytes: int,
    ) -> bytes:
        """Return bytes for one immutable repository path."""


class _ResponseHeaders(Protocol):
    def get(self, name: str) -> str | None:
        """Return one response header."""


class _HTTPResponse(Protocol):
    status: int
    headers: _ResponseHeaders

    def __enter__(self) -> "_HTTPResponse": ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...

    def geturl(self) -> str: ...

    def read(self, amount: int) -> bytes: ...


class _URLOpener(Protocol):
    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> _HTTPResponse: ...


def _chain_fail(
    code: str,
    message: str,
    *,
    step: str = "spec",
    context: Mapping[str, ErrorContext] | None = None,
) -> None:
    raise SpecChainError(code, message, step=step, context=context)


def _path_from(value: StrPath, *, name: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be str or os.PathLike[str]") from exc
    if not isinstance(raw, str):
        raise TypeError(f"{name} must resolve to text, not bytes")
    return Path(raw)


def _validate_https_url(url: str, allowed_hosts: Set[str]) -> None:
    if not isinstance(url, str):
        raise TypeError("URL must be text")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
        raise SpecResolutionError(
            "unsafe-url",
            "URL contains control characters or whitespace",
            step="fetch",
        )
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SpecResolutionError(
            "unsafe-url",
            "URL is not structurally valid",
            step="fetch",
            context={"url": url},
        ) from exc
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise SpecResolutionError(
            "unsafe-url",
            "fetch URL or redirect is outside the allowed HTTPS hosts",
            step="fetch",
            context={"url": url},
        )


class _RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        super().__init__()
        self._allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        target = urllib.parse.urljoin(req.full_url, newurl)
        _validate_https_url(target, self._allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, target)


class HTTPSFetcher:
    """Bounded HTTPS transport with an allowlist and redirect validation.

    The default transport accepts only ``raw.githubusercontent.com`` over
    HTTPS. Pass a custom ``ByteFetcher`` to ``GitHubRawSource`` for tests or
    non-network environments instead of weakening this policy.
    """

    __slots__ = ("_allowed_hosts", "_timeout", "_opener")

    def __init__(
        self,
        *,
        allowed_hosts: Collection[str] = DEFAULT_ALLOWED_FETCH_HOSTS,
        timeout: float = DEFAULT_FETCH_SECONDS,
        opener: _URLOpener | None = None,
    ) -> None:
        if isinstance(allowed_hosts, (str, bytes)):
            raise TypeError("allowed_hosts must be a collection of text hostnames")
        if not allowed_hosts:
            raise ValueError("allowed_hosts cannot be empty")
        if any(not isinstance(host, str) for host in allowed_hosts):
            raise TypeError("allowed_hosts must contain text hostnames")
        normalized = frozenset(host.lower() for host in allowed_hosts)
        if any(not host or "/" in host for host in normalized):
            raise ValueError("allowed_hosts contains an invalid hostname")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be finite and positive")
        self._allowed_hosts = normalized
        self._timeout = float(timeout)
        self._opener = opener or urllib.request.build_opener(
            _RestrictedRedirectHandler(normalized)
        )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Immutable set of accepted request, redirect, and final hosts."""

        return self._allowed_hosts

    @property
    def timeout(self) -> float:
        """Network timeout in seconds."""

        return self._timeout

    def __repr__(self) -> str:
        return (
            f"HTTPSFetcher(allowed_hosts={sorted(self.allowed_hosts)!r}, "
            f"timeout={self.timeout!r})"
        )

    def fetch(self, url: str, *, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        _validate_https_url(url, self.allowed_hosts)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": f"rapp-sdk-spec-chain/{__version__}",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                final_url = response.geturl()
                _validate_https_url(final_url, self.allowed_hosts)
                status = getattr(response, "status", 200)
                if status != 200:
                    raise SpecResolutionError(
                        "fetch-status",
                        f"immutable source returned HTTP {status}",
                        step="fetch",
                        context={"status": status, "url": final_url},
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        announced = int(content_length)
                    except ValueError as exc:
                        raise SpecResolutionError(
                            "invalid-content-length",
                            "source returned an invalid Content-Length",
                            step="fetch",
                            context={"url": final_url},
                        ) from exc
                    if announced < 0 or announced > max_bytes:
                        raise SpecResolutionError(
                            "fetch-size-exceeded",
                            f"source exceeds {max_bytes} bytes",
                            step="fetch",
                            context={
                                "announced_bytes": announced,
                                "max_bytes": max_bytes,
                                "url": final_url,
                            },
                        )
                data = response.read(max_bytes + 1)
        except SpecResolutionError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            raise SpecResolutionError(
                "fetch-failed",
                f"immutable source is unavailable: {exc}",
                step="fetch",
                context={"url": url},
            ) from exc
        if len(data) > max_bytes:
            raise SpecResolutionError(
                "fetch-size-exceeded",
                f"source exceeds {max_bytes} bytes",
                step="fetch",
                context={
                    "actual_bytes": len(data),
                    "max_bytes": max_bytes,
                    "url": url,
                },
            )
        return data


def _github_coordinates(repository: str) -> tuple[str, str]:
    if type(repository) is not str:
        raise SpecChainError(
            "invalid-repository",
            "canonical_repo must be text",
            step="profile",
        )
    try:
        parsed = urllib.parse.urlsplit(repository)
        port = parsed.port
    except ValueError as exc:
        raise SpecChainError(
            "invalid-repository", "canonical_repo is not a valid URL", step="profile"
        ) from exc
    parts = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or len(parts) != 3
        or parts[0] != ""
        or not _GITHUB_NAME_RE.fullmatch(parts[1])
        or not _GITHUB_NAME_RE.fullmatch(parts[2])
        or parts[2].endswith(".git")
    ):
        raise SpecChainError(
            "invalid-repository",
            "canonical_repo must be an HTTPS github.com owner/repository URL",
            step="profile",
        )
    return parts[1], parts[2]


def _validate_commit(commit: Any) -> str:
    if type(commit) is not str or _HEX40_RE.fullmatch(commit) is None:
        _chain_fail(
            "mutable-revision",
            "legacy pointers require an immutable 40-hex commit",
            step="profile",
            context={"commit": commit if isinstance(commit, str) else None},
        )
    return commit


def _validate_path(path: Any) -> str:
    if (
        type(path) is not str
        or not 1 <= len(path) <= 1024
        or "\\" in path
        or "%" in path
    ):
        _chain_fail(
            "unsafe-path",
            "normative_path must be a 1-1024 character unescaped POSIX path",
            step="profile",
            context={"path": path if isinstance(path, str) else None},
        )
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or str(candidate) != path
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(character in path for character in ("\x00", "?", "#"))
    ):
        _chain_fail(
            "unsafe-path",
            "normative_path cannot be absolute, normalized, or traversing",
            step="profile",
            context={"path": path},
        )
    return path


def _validate_sha256(value: Any, *, field: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        _chain_fail(
            "invalid-spec-hash",
            f"{field} must be 64 lowercase hex",
            step="profile",
        )
    return value


def _validate_spec_size(value: Any, *, field: str) -> int:
    if type(value) is int and not isinstance(value, bool):
        size = value
    elif type(value) is str and _DECIMAL_BYTES_RE.fullmatch(value):
        size = int(value)
    else:
        _chain_fail(
            "invalid-spec-size",
            f"{field} must be a non-negative decimal byte count",
            step="profile",
        )
    if not 0 <= size <= MAX_SPEC_BYTES:
        _chain_fail(
            "spec-size-exceeded",
            f"{field} exceeds the {MAX_SPEC_BYTES}-byte specification limit",
            step="profile",
        )
    return size


class GitHubRawSource:
    """Resolve immutable GitHub paths through ``raw.githubusercontent.com``."""

    __slots__ = ("_fetcher",)

    def __init__(self, fetcher: ByteFetcher | None = None) -> None:
        self._fetcher = fetcher or HTTPSFetcher()

    @property
    def fetcher(self) -> ByteFetcher:
        """Injected bounded byte transport."""

        return self._fetcher

    def __repr__(self) -> str:
        fetcher_type = type(self.fetcher)
        qualified = f"{fetcher_type.__module__}.{fetcher_type.__qualname__}"
        return f"GitHubRawSource(fetcher_type={qualified!r})"

    @staticmethod
    def raw_url(repository: str, commit: str, path: str) -> str:
        """Return a validated immutable raw GitHub URL."""

        owner, repo = _github_coordinates(repository)
        immutable_commit = _validate_commit(commit)
        safe_path = _validate_path(path)
        quoted_path = urllib.parse.quote(safe_path, safe="/-._~")
        return (
            f"https://raw.githubusercontent.com/{owner}/{repo}/"
            f"{immutable_commit}/{quoted_path}"
        )

    def fetch(
        self,
        repository: str,
        commit: str,
        path: str,
        *,
        max_bytes: int,
    ) -> bytes:
        """Fetch one immutable path through the injected bounded transport."""

        return self.fetcher.fetch(
            self.raw_url(repository, commit, path),
            max_bytes=max_bytes,
        )


class ContentAddressedCache:
    """Checksum-revalidating cache with durable atomic object writes.

    ``root`` must be a text path. Cache reads never trust filenames alone:
    byte length and SHA-256 are revalidated on every access.
    """

    __slots__ = ("_root",)

    def __init__(self, root: StrPath) -> None:
        self._root = _path_from(root, name="root")

    @property
    def root(self) -> Path:
        """Cache root as a text-backed :class:`pathlib.Path`."""

        return self._root

    def __repr__(self) -> str:
        return f"ContentAddressedCache(root={str(self.root)!r})"

    def path_for(self, sha256: str) -> Path:
        """Return the deterministic on-disk path for a SHA-256 object."""

        digest = _validate_sha256(sha256, field="cache sha256")
        return self.root / "sha256" / digest[:2] / digest[2:]

    @staticmethod
    def _validate_bytes(data: bytes, sha256: str, expected_bytes: int) -> None:
        if (
            type(expected_bytes) is not int
            or not 0 <= expected_bytes <= MAX_SPEC_BYTES
        ):
            raise ValueError(
                f"expected_bytes must be an integer from 0 to {MAX_SPEC_BYTES}"
            )
        if len(data) != expected_bytes:
            raise CacheIntegrityError(
                "cached-size-mismatch",
                "cached object byte count does not match its address metadata",
                step="cache",
                context={
                    "actual_bytes": len(data),
                    "expected_bytes": expected_bytes,
                    "sha256": sha256,
                },
            )
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != sha256:
            raise CacheIntegrityError(
                "cached-hash-mismatch",
                "cached object checksum does not match its address",
                step="cache",
                context={
                    "actual_sha256": actual_sha256,
                    "expected_sha256": sha256,
                },
            )

    def get(self, sha256: str, expected_bytes: int) -> bytes | None:
        """Return a revalidated object, or ``None`` when it is absent."""

        path = self.path_for(sha256)
        if not os.path.lexists(path):
            return None
        if path.is_symlink() or not path.is_file():
            raise CacheIntegrityError(
                "unsafe-cache-object",
                "cache object is not a regular non-symlink file",
                step="cache",
            )
        with path.open("rb") as stream:
            data = stream.read(expected_bytes + 1)
        self._validate_bytes(data, sha256, expected_bytes)
        return data

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def put(self, data: bytes, sha256: str, expected_bytes: int) -> Path:
        """Atomically persist already-verified bytes and return their path."""

        if not isinstance(data, bytes):
            raise TypeError("cache data must be bytes")
        self._validate_bytes(data, sha256, expected_bytes)
        path = self.path_for(sha256)
        existing = self.get(sha256, expected_bytes)
        if existing is not None:
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.parent / (
            f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self.get(sha256, expected_bytes)
        return path


@dataclass(frozen=True, slots=True)
class RevisionAddress:
    """Stable selectors for one frame in a verified specification chain."""

    revision: str
    seq: int
    frame_hash: str
    payload_hash: str

    def as_dict(self) -> dict[str, str | int]:
        """Return a deterministic JSON-ready address."""

        return {
            "revision": self.revision,
            "seq": self.seq,
            "frame_hash": self.frame_hash,
            "payload_hash": self.payload_hash,
        }

    def to_json_bytes(self) -> bytes:
        """Serialize the address as canonical UTF-8 JSON bytes."""

        return canonicalize(self.as_dict())


@dataclass(frozen=True, slots=True)
class SpecRevision:
    """Immutable metadata and canonical frame bytes for one spec revision.

    ``to_dict()`` returns a fresh mutable wire object. ``frame_bytes`` and
    ``to_json_bytes()`` expose the deterministic canonical representation.
    """

    revision: str
    seq: int
    frame_hash: str
    payload_hash: str
    stream_id: str
    normative_sha256: str
    normative_bytes: int
    media_type: str
    repository: str | None
    commit: str | None
    path: str | None
    is_inline: bool
    _frame_bytes: bytes = field(repr=False, compare=False)

    @property
    def address(self) -> RevisionAddress:
        """Return all stable selectors as an immutable value object."""

        return RevisionAddress(
            revision=self.revision,
            seq=self.seq,
            frame_hash=self.frame_hash,
            payload_hash=self.payload_hash,
        )

    @property
    def frame_bytes(self) -> bytes:
        """Canonical UTF-8 JSON bytes for the complete eleven-key frame."""

        return self._frame_bytes

    @property
    def frame(self) -> Frame:
        """Return a fresh mutable wire-frame dictionary.

        This compatibility property is equivalent to ``to_dict()``.
        """

        return self.to_dict()

    def to_dict(self) -> Frame:
        """Parse and return a fresh copy of the verified frame."""

        value = strict_json_loads(self._frame_bytes)
        if type(value) is not dict:
            raise RuntimeError("stored frame bytes are not a JSON object")
        return value

    def to_json_bytes(self) -> bytes:
        """Return canonical UTF-8 JSON bytes for the verified frame."""

        return self._frame_bytes

    @property
    def global_url(self) -> str | None:
        if self.repository is None or self.commit is None or self.path is None:
            return None
        return GitHubRawSource.raw_url(self.repository, self.commit, self.path)

    def _inline_bytes(self) -> bytes | None:
        normative = self.to_dict()["payload"].get("normative")
        if normative is None:
            return None
        return normative["text"].encode("utf-8")


def _profile_revision(frame: Frame) -> SpecRevision:
    payload = frame["payload"]
    revision = payload.get("revision")
    if type(revision) is not str or _REVISION_RE.fullmatch(revision) is None:
        _chain_fail(
            "invalid-revision",
            "payload.revision must be a short stable revision label",
            step="profile",
        )

    pointer_fields = _POINTER_KEYS.intersection(payload)
    has_pointer = bool(pointer_fields)
    if has_pointer and pointer_fields != _POINTER_KEYS:
        missing = sorted(_POINTER_KEYS - pointer_fields)
        _chain_fail(
            "incomplete-pointer",
            f"legacy pointer is missing fields: {missing}",
            step="profile",
        )

    normative = payload.get("normative")
    if normative is None and not has_pointer:
        _chain_fail(
            "missing-normative",
            "spec revision must contain an inline normative object or legacy pointer",
            step="profile",
        )

    pointer_sha: str | None = None
    pointer_size: int | None = None
    if has_pointer:
        _github_coordinates(payload["canonical_repo"])
        _validate_commit(payload["commit"])
        _validate_path(payload["normative_path"])
        pointer_sha = _validate_sha256(
            payload["normative_sha256"], field="normative_sha256"
        )
        pointer_size = _validate_spec_size(
            payload["normative_bytes"], field="normative_bytes"
        )

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
                step="profile",
            )
        media_type = normative["media_type"]
        if (
            type(media_type) is not str
            or not 1 <= len(media_type) <= 127
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in media_type)
        ):
            _chain_fail(
                "invalid-media-type",
                "normative.media_type must be 1-127 printable ASCII characters",
                step="profile",
            )
        if type(normative["text"]) is not str:
            _chain_fail(
                "invalid-inline-text",
                "normative.text must be a UTF-8 JSON string",
                step="profile",
            )
        try:
            inline_bytes = normative["text"].encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SpecChainError(
                "invalid-inline-text",
                "normative.text is not valid Unicode",
                step="profile",
            ) from exc
        inline_sha = _validate_sha256(
            normative["sha256"], field="normative.sha256"
        )
        inline_size = _validate_spec_size(
            normative["bytes"], field="normative.bytes"
        )
        if len(inline_bytes) != inline_size:
            _chain_fail(
                "inline-size-mismatch",
                "normative.text byte count does not match normative.bytes",
                step="profile",
            )
        if hashlib.sha256(inline_bytes).hexdigest() != inline_sha:
            _chain_fail(
                "inline-hash-mismatch",
                "normative.text checksum does not match normative.sha256",
                step="profile",
            )
        if has_pointer and (inline_sha != pointer_sha or inline_size != pointer_size):
            _chain_fail(
                "normative-metadata-conflict",
                "inline and legacy normative metadata disagree",
                step="profile",
            )
        normative_sha = inline_sha
        normative_size = inline_size
    else:
        media_type = "text/markdown; charset=utf-8"
        normative_sha = pointer_sha
        normative_size = pointer_size

    if normative_sha is None or normative_size is None:
        _chain_fail(
            "missing-normative",
            "spec revision has no complete normative address",
            step="profile",
        )
    return SpecRevision(
        revision=revision,
        seq=frame["seq"],
        frame_hash=frame["frame_hash"],
        payload_hash=frame["payload_hash"],
        stream_id=frame["stream_id"],
        normative_sha256=normative_sha,
        normative_bytes=normative_size,
        media_type=media_type,
        repository=payload.get("canonical_repo"),
        commit=payload.get("commit"),
        path=payload.get("normative_path"),
        is_inline=normative is not None,
        _frame_bytes=canonicalize(frame),
    )


class SpecChain:
    """Immutable index over a verified linear specification chain.

    Construct from in-memory frames with ``from_frames()``, from UTF-8 JSONL
    bytes with ``from_jsonl()``, or from a text path with ``load()``.

    Example:
        >>> first = build_spec_revision_frame(
        ...     revision="rev-1",
        ...     text="# RAPP/1\\n",
        ...     utc="2026-08-30T00:00:00.000Z",
        ...     stream_id="rappid:@example/spec:" + "0" * 64,
        ... )
        >>> chain = SpecChain.from_frames([first])
        >>> chain.head.revision
        'rev-1'
        >>> chain.materialize()
        b'# RAPP/1\\n'
    """

    __slots__ = (
        "_revisions",
        "_by_revision",
        "_by_seq",
        "_by_frame_hash",
        "_by_payload_hash",
    )
    _revisions: tuple[SpecRevision, ...]
    _by_revision: Mapping[str, tuple[SpecRevision, ...]]
    _by_seq: Mapping[int, SpecRevision]
    _by_frame_hash: Mapping[str, SpecRevision]
    _by_payload_hash: Mapping[str, SpecRevision]

    def __init__(
        self,
        frames: Iterable[FrameMapping],
        *,
        expected_stream_id: str | None = None,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> None:
        supplied_frames = tuple(frames)
        try:
            verified = verify_stream(
                supplied_frames,
                expected_stream_id=expected_stream_id,
                max_seconds=max_seconds,
            )
        except ProtocolError as exc:
            raise SpecChainError(
                exc.code,
                f"invalid specification chain: {exc.message}",
                step=exc.step,
                context=exc.context,
            ) from exc
        revisions = tuple(_profile_revision(frame) for frame in verified)
        by_revision: dict[str, list[SpecRevision]] = {}
        by_seq: dict[int, SpecRevision] = {}
        by_frame_hash: dict[str, SpecRevision] = {}
        by_payload_hash: dict[str, SpecRevision] = {}
        for revision in revisions:
            if revision.seq in by_seq:
                _chain_fail(
                    "duplicate-seq",
                    f"duplicate seq {revision.seq}",
                    context={"seq": revision.seq},
                )
            if revision.frame_hash in by_frame_hash:
                _chain_fail("duplicate-frame", "duplicate frame_hash")
            if revision.payload_hash in by_payload_hash:
                _chain_fail("duplicate-payload", "duplicate payload_hash")
            aliases = by_revision.setdefault(revision.revision, [])
            if aliases:
                same_legacy_bytes = (
                    not revision.is_inline
                    and all(not prior.is_inline for prior in aliases)
                    and all(
                        prior.normative_sha256 == revision.normative_sha256
                        and prior.normative_bytes == revision.normative_bytes
                        for prior in aliases
                    )
                )
                if not same_legacy_bytes:
                    _chain_fail(
                        "duplicate-revision",
                        f"revision label {revision.revision!r} addresses different bytes",
                        context={"revision": revision.revision},
                    )
            aliases.append(revision)
            by_seq[revision.seq] = revision
            by_frame_hash[revision.frame_hash] = revision
            by_payload_hash[revision.payload_hash] = revision
        self._revisions = revisions
        self._by_revision = MappingProxyType(
            {label: tuple(values) for label, values in by_revision.items()}
        )
        self._by_seq = MappingProxyType(by_seq)
        self._by_frame_hash = MappingProxyType(by_frame_hash)
        self._by_payload_hash = MappingProxyType(by_payload_hash)

    @classmethod
    def from_frames(
        cls,
        frames: Iterable[FrameMapping],
        *,
        expected_stream_id: str | None = None,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> "SpecChain":
        """Verify an iterable of decoded frame mappings in chain order."""

        return cls(
            frames,
            expected_stream_id=expected_stream_id,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_jsonl(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> "SpecChain":
        """Parse and verify UTF-8 JSONL bytes.

        Text is intentionally not accepted here. Use ``from_jsonl_text()`` for
        a deliberate UTF-8 text boundary or ``load()`` for a path.
        """

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SpecChain.from_jsonl accepts bytes")
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        octets = bytes(data)
        if len(octets) > max_bytes:
            _chain_fail(
                "chain-size-exceeded",
                f"chain exceeds {max_bytes} bytes",
                step="size",
                context={"actual_bytes": len(octets), "max_bytes": max_bytes},
            )
        if not octets:
            _chain_fail("empty-chain", "specification chain is empty")
        ended_with_lf = octets.endswith(b"\n")
        lines = octets.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        if not lines:
            _chain_fail("empty-chain", "specification chain is empty")
        frames: list[Frame] = []
        for number, raw_line in enumerate(lines, start=1):
            lf_terminated = number < len(lines) or ended_with_lf
            has_crlf = raw_line.endswith(b"\r") and lf_terminated
            line = raw_line[:-1] if has_crlf else raw_line
            if b"\r" in line:
                _chain_fail(
                    "invalid-line-ending",
                    f"chain line {number} contains a bare carriage return",
                    step="jsonl",
                    context={"line": number},
                )
            if not line.strip():
                _chain_fail(
                    "blank-chain-line",
                    f"chain line {number} is blank",
                    step="jsonl",
                )
            try:
                value = strict_json_loads(line, max_bytes=MAX_CANONICAL_BYTES)
            except ProtocolError as exc:
                raise SpecChainError(
                    exc.code,
                    f"invalid chain line {number}: {exc.message}",
                    step=exc.step or "jsonl",
                    context={**dict(exc.context), "line": number},
                ) from exc
            if type(value) is not dict:
                _chain_fail(
                    "non-object-frame",
                    f"chain line {number} is not a JSON object",
                    step="jsonl",
                )
            frames.append(value)
        return cls(
            tuple(frames),
            expected_stream_id=expected_stream_id,
            max_seconds=max_seconds,
        )

    @classmethod
    def from_jsonl_text(
        cls,
        text: str,
        *,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> "SpecChain":
        """Encode text as strict UTF-8, then parse and verify its JSONL."""

        if not isinstance(text, str):
            raise TypeError("SpecChain.from_jsonl_text accepts text")
        try:
            data = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SpecChainError(
                "invalid-utf8",
                "JSONL text contains an unpaired surrogate",
                step="jsonl",
            ) from exc
        return cls.from_jsonl(
            data,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_seconds=max_seconds,
        )

    @classmethod
    def load(
        cls,
        path: StrPath,
        *,
        expected_stream_id: str | None = None,
        max_bytes: int = MAX_CHAIN_BYTES,
        max_seconds: float = DEFAULT_VERIFY_SECONDS,
    ) -> "SpecChain":
        """Read and verify a chain from a text ``str``/``PathLike`` path."""

        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        source = _path_from(path, name="path")
        source_size = source.stat().st_size
        if source_size > max_bytes:
            _chain_fail(
                "chain-size-exceeded",
                f"chain exceeds {max_bytes} bytes",
                step="size",
                context={
                    "actual_bytes": source_size,
                    "max_bytes": max_bytes,
                    "path": str(source),
                },
            )
        with source.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        return cls.from_jsonl(
            data,
            expected_stream_id=expected_stream_id,
            max_bytes=max_bytes,
            max_seconds=max_seconds,
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
        self, index: int | slice
    ) -> SpecRevision | tuple[SpecRevision, ...]:
        return self._revisions[index]

    def __repr__(self) -> str:
        return (
            f"SpecChain(stream_id={self.stream_id!r}, revisions={len(self)}, "
            f"head_seq={self.head.seq}, head_frame_hash={self.head.frame_hash!r})"
        )

    @property
    def revisions(self) -> tuple[SpecRevision, ...]:
        """All verified revisions in ascending sequence order."""

        return self._revisions

    @property
    def head(self) -> SpecRevision:
        """The highest verified revision."""

        return self._revisions[-1]

    @property
    def stream_id(self) -> str:
        """The single stream identifier shared by every revision."""

        return self.head.stream_id

    def to_jsonl_bytes(self) -> bytes:
        """Serialize every frame as deterministic canonical UTF-8 JSONL."""

        return b"".join(
            revision.to_json_bytes() + b"\n" for revision in self._revisions
        )

    def resolve(
        self,
        selector: RevisionSelector | None = None,
        *,
        revision: str | None = None,
        seq: int | None = None,
        frame_hash: str | None = None,
        payload_hash: str | None = None,
        head: bool = False,
    ) -> SpecRevision:
        """Resolve one revision by label, sequence, hash, or ``"head"``.

        With no selector, the verified head is returned. A 64-hex positional
        selector checks ``frame_hash`` first and then ``payload_hash``.
        """

        if selector is not None and type(selector) not in (str, int):
            raise TypeError("selector must be text, int, or None")
        if type(head) is not bool:
            raise TypeError("head must be bool")
        for name, value in (
            ("revision", revision),
            ("frame_hash", frame_hash),
            ("payload_hash", payload_hash),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be text or None")
        for name, value in (
            ("frame_hash", frame_hash),
            ("payload_hash", payload_hash),
        ):
            if value is not None and _HEX64_RE.fullmatch(value) is None:
                raise SpecResolutionError(
                    "invalid-selector",
                    f"{name} must be 64 lowercase hex",
                    step="resolve",
                    context={name: value},
                )
        supplied = sum(
            value is not None
            for value in (selector, revision, seq, frame_hash, payload_hash)
        ) + int(head)
        if supplied == 0:
            head = True
        elif supplied != 1:
            raise ValueError("provide exactly one revision selector")
        if head or selector == "head":
            return self.head
        if selector is not None:
            if type(selector) is int:
                seq = selector
            elif _HEX64_RE.fullmatch(selector):
                result = self._by_frame_hash.get(selector)
                if result is None:
                    result = self._by_payload_hash.get(selector)
                if result is None:
                    raise SpecResolutionError(
                        "unknown-revision",
                        "no frame or payload hash matches the selector",
                        step="resolve",
                        context={"selector": selector},
                    )
                return result
            else:
                revision = selector
        if revision is not None:
            matches = self._by_revision.get(revision)
            if not matches:
                raise SpecResolutionError(
                    "unknown-revision",
                    f"unknown revision label {revision!r}",
                    step="resolve",
                    context={"revision": revision},
                )
            return matches[-1]
        if seq is not None:
            if type(seq) is not int or not 0 <= seq <= MAX_SAFE_INTEGER:
                raise ValueError("seq selector must be a uint53 integer")
            result = self._by_seq.get(seq)
        elif frame_hash is not None:
            result = self._by_frame_hash.get(frame_hash)
        else:
            result = self._by_payload_hash.get(payload_hash or "")
        if result is None:
            raise SpecResolutionError(
                "unknown-revision",
                "no specification revision matches the selector",
                step="resolve",
                context={
                    "seq": seq,
                    "frame_hash": frame_hash,
                    "payload_hash": payload_hash,
                },
            )
        return result

    def materialize(
        self,
        selector: RevisionSelector | None = None,
        *,
        revision: str | None = None,
        seq: int | None = None,
        frame_hash: str | None = None,
        payload_hash: str | None = None,
        source: ImmutableSource | None = None,
        cache: ContentAddressedCache | None = None,
        offline: bool = False,
    ) -> bytes:
        """Return verified normative bytes for one revision.

        The return type is always ``bytes``. Decode explicitly only after
        checking ``SpecRevision.media_type``. Inline bytes are preferred,
        followed by a verified cache object, then an immutable source fetch.
        """

        if type(offline) is not bool:
            raise TypeError("offline must be bool")
        selected = self.resolve(
            selector,
            revision=revision,
            seq=seq,
            frame_hash=frame_hash,
            payload_hash=payload_hash,
        )
        inline = selected._inline_bytes()
        if inline is not None:
            if cache is not None:
                cache.put(
                    inline,
                    selected.normative_sha256,
                    selected.normative_bytes,
                )
            return inline
        if cache is not None:
            cached = cache.get(
                selected.normative_sha256,
                selected.normative_bytes,
            )
            if cached is not None:
                return cached
        if offline:
            raise SpecResolutionError(
                "uncached-revision",
                "revision is unavailable while offline and absent from cache",
                step="resolve",
                context={
                    "frame_hash": selected.frame_hash,
                    "revision": selected.revision,
                    "seq": selected.seq,
                },
            )
        immutable_source = source or GitHubRawSource()
        repository = selected.repository
        commit = selected.commit
        path = selected.path
        if repository is None or commit is None or path is None:
            raise SpecResolutionError(
                "incomplete-pointer",
                "selected legacy revision has no complete immutable pointer",
                step="resolve",
            )
        data = immutable_source.fetch(
            repository,
            commit,
            path,
            max_bytes=selected.normative_bytes,
        )
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise SpecResolutionError(
                "invalid-source-response",
                "immutable source did not return bytes",
                step="fetch",
            )
        data = bytes(data)
        if len(data) != selected.normative_bytes:
            raise SpecResolutionError(
                "normative-size-mismatch",
                "resolved specification byte count does not match the frame",
                step="verify",
                context={
                    "actual_bytes": len(data),
                    "expected_bytes": selected.normative_bytes,
                    "frame_hash": selected.frame_hash,
                },
            )
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != selected.normative_sha256:
            raise SpecResolutionError(
                "normative-hash-mismatch",
                "resolved specification checksum does not match the frame",
                step="verify",
                context={
                    "actual_sha256": actual_sha256,
                    "expected_sha256": selected.normative_sha256,
                    "frame_hash": selected.frame_hash,
                },
            )
        if cache is not None:
            cache.put(
                data,
                selected.normative_sha256,
                selected.normative_bytes,
            )
        return data


def build_spec_revision_frame(
    *,
    revision: str,
    text: str,
    utc: str,
    head: SpecRevision | FrameMapping | None = None,
    stream_id: str | None = None,
    kind: str = "body.pulse",
    media_type: str = "text/markdown; charset=utf-8",
    payload_extra: Mapping[str, JsonValue] | None = None,
) -> Frame:
    """Build a self-contained specification revision extending ``head``.

    ``text`` is encoded as strict UTF-8 and embedded with its raw SHA-256 and
    byte count. The caller must serialize concurrent appends; a supplied head
    is validated but never repaired or reparented.

    Example:
        >>> frame = build_spec_revision_frame(
        ...     revision="rev-1",
        ...     text="# RAPP/1\\n",
        ...     utc="2026-08-30T00:00:00.000Z",
        ...     stream_id="rappid:@example/spec:" + "0" * 64,
        ... )
        >>> frame["payload"]["normative"]["bytes"]
        9
    """

    if type(revision) is not str or _REVISION_RE.fullmatch(revision) is None:
        _chain_fail("invalid-revision", "revision label is invalid", step="build")
    if type(text) is not str:
        raise TypeError("text must be a string")
    if (
        type(media_type) is not str
        or not 1 <= len(media_type) <= 127
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in media_type)
    ):
        _chain_fail("invalid-media-type", "media_type is invalid", step="build")
    try:
        normative_bytes = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SpecChainError(
            "invalid-inline-text",
            "text is not valid Unicode",
            step="build",
        ) from exc
    if len(normative_bytes) > MAX_SPEC_BYTES:
        _chain_fail(
            "spec-size-exceeded",
            f"normative text exceeds {MAX_SPEC_BYTES} bytes",
            step="build",
        )
    extra = dict(payload_extra or {})
    if {"revision", "normative"}.intersection(extra):
        _chain_fail(
            "reserved-payload-key",
            "payload_extra cannot replace revision or normative",
            step="build",
        )
    payload = {
        **extra,
        "revision": revision,
        "normative": {
            "media_type": media_type,
            "text": text,
            "sha256": hashlib.sha256(normative_bytes).hexdigest(),
            "bytes": len(normative_bytes),
        },
    }
    if isinstance(head, SpecRevision):
        head_frame = head.frame
    elif head is None:
        head_frame = None
    else:
        head_frame = dict(head)
    if head_frame is None:
        if stream_id is None:
            raise ValueError("stream_id is required for a genesis revision")
        seq = 0
        prev = None
        prev_wave = None
    else:
        try:
            head_frame, head_family = _validate_frame_integrity(
                head_frame,
            )
        except ProtocolError as exc:
            raise SpecChainError(
                exc.code,
                f"invalid revision head: {exc.message}",
                step=exc.step,
                context=exc.context,
            ) from exc
        if stream_id is not None and stream_id != head_frame.get("stream_id"):
            _chain_fail(
                "stream-id-mismatch",
                "explicit stream_id does not match head",
                step="build",
            )
        stream_id = head_frame["stream_id"]
        if head_frame["seq"] >= MAX_SAFE_INTEGER:
            _chain_fail("seq-exhausted", "head cannot be extended", step="build")
        seq = head_frame["seq"] + 1
        prev = head_frame["payload_hash"]
        prev_wave = (
            head_frame["frame_hash"] if head_family == "swarm" else None
        )
    try:
        frame = build_frame(
            kind,
            stream_id,
            seq,
            utc,
            payload,
            prev,
            prev_wave=prev_wave,
        )
    except ProtocolError as exc:
        raise SpecChainError(
            exc.code,
            f"invalid specification revision: {exc.message}",
            step=exc.step,
            context=exc.context,
        ) from exc
    if head_frame is not None and frame["utc"] < head_frame["utc"]:
        _chain_fail(
            "utc-regression",
            "revision utc is earlier than the supplied head",
            step="build",
        )
    try:
        canonicalize(frame, max_bytes=MAX_CANONICAL_BYTES)
    except ProtocolError as exc:
        raise SpecChainError(
            exc.code,
            f"invalid specification revision: {exc.message}",
            step=exc.step,
            context=exc.context,
        ) from exc
    _profile_revision(frame)
    return frame


__all__ = (
    "ByteFetcher",
    "CacheIntegrityError",
    "ContentAddressedCache",
    "DEFAULT_ALLOWED_FETCH_HOSTS",
    "DEFAULT_FETCH_SECONDS",
    "GitHubRawSource",
    "HTTPSFetcher",
    "ImmutableSource",
    "MAX_CHAIN_BYTES",
    "MAX_SPEC_BYTES",
    "RevisionAddress",
    "RevisionSelector",
    "SpecChain",
    "SpecChainError",
    "SpecResolutionError",
    "SpecRevision",
    "StrPath",
    "build_spec_revision_frame",
)
