"""Explicit specification resolution, cache, and HTTPS source adapters."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping, Set
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from ._version import __version__
from .errors import CacheIntegrityError, SpecResolutionError
from .reports import Diagnostic
from .spec_chain import (
    ContentLocator,
    MAX_SPEC_BYTES,
    SpecChain,
    SpecRevision,
    StrPath,
)

DEFAULT_FETCH_SECONDS = 30.0
DEFAULT_ALLOWED_FETCH_HOSTS = frozenset({"raw.githubusercontent.com"})
_GITHUB_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$",
    re.ASCII,
)


def _resolution_error(
    code: str,
    message: str,
    *,
    location: str,
    context: Mapping[str, str | int | bool | None] | None = None,
    remediation: str | None = None,
) -> SpecResolutionError:
    return SpecResolutionError(
        Diagnostic(
            code=code,
            operation="spec-resolution",
            message=message,
            location=location,
            context=context or {},
            remediation=remediation,
        )
    )


class ByteFetcher(Protocol):
    """Fetch exact bytes from a validated HTTPS URL."""

    def fetch(self, url: str, *, max_bytes: int) -> bytes:
        """Return no more than ``max_bytes`` bytes."""


class RevisionSource(Protocol):
    """Synchronous source contract independent of repository vendors."""

    def read(self, locator: ContentLocator, *, max_bytes: int) -> bytes:
        """Read exact bytes described by a source-neutral locator."""


class _ResponseHeaders(Protocol):
    def get(self, name: str) -> str | None: ...


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


def _validate_https_url(url: str, allowed_hosts: Set[str]) -> None:
    if type(url) is not str:
        raise TypeError("URL must be text")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
        raise _resolution_error(
            "unsafe-url",
            "URL contains control characters or whitespace",
            location="url",
        )
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise _resolution_error(
            "unsafe-url",
            "URL is not structurally valid",
            location="url",
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
        raise _resolution_error(
            "unsafe-url",
            "URL or redirect is outside the allowed HTTPS hosts",
            location="url",
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
    """Bounded HTTPS transport with immutable host policy."""

    __slots__ = ("_allowed_hosts", "_timeout", "_opener")

    def __init__(
        self,
        *,
        allowed_hosts: Collection[str] = DEFAULT_ALLOWED_FETCH_HOSTS,
        timeout: float = DEFAULT_FETCH_SECONDS,
        opener: _URLOpener | None = None,
    ) -> None:
        if isinstance(allowed_hosts, (str, bytes)):
            raise TypeError("allowed_hosts must be a collection")
        if not allowed_hosts:
            raise ValueError("allowed_hosts cannot be empty")
        if any(type(host) is not str for host in allowed_hosts):
            raise TypeError("allowed_hosts must contain text")
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
        return self._allowed_hosts

    @property
    def timeout(self) -> float:
        return self._timeout

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
                    raise _resolution_error(
                        "fetch-status",
                        f"immutable source returned HTTP {status}",
                        location="source",
                        context={"status": status, "url": final_url},
                    )
                announced_text = response.headers.get("Content-Length")
                if announced_text is not None:
                    try:
                        announced = int(announced_text)
                    except ValueError as exc:
                        raise _resolution_error(
                            "invalid-content-length",
                            "source returned an invalid Content-Length",
                            location="source",
                        ) from exc
                    if announced < 0 or announced > max_bytes:
                        raise _resolution_error(
                            "fetch-size-exceeded",
                            "source exceeds its byte cap",
                            location="source",
                            context={
                                "announced_bytes": announced,
                                "max_bytes": max_bytes,
                            },
                        )
                data = response.read(max_bytes + 1)
        except SpecResolutionError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            raise _resolution_error(
                "fetch-failed",
                f"immutable source is unavailable: {exc}",
                location="source",
            ) from exc
        if len(data) > max_bytes:
            raise _resolution_error(
                "fetch-size-exceeded",
                "source exceeds its byte cap",
                location="source",
                context={"actual_bytes": len(data), "max_bytes": max_bytes},
            )
        return data


def _github_coordinates(repository: str) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(repository)
        port = parsed.port
    except ValueError as exc:
        raise _resolution_error(
            "invalid-repository",
            "repository is not a valid URL",
            location="locator.repository",
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
        or _GITHUB_NAME_RE.fullmatch(parts[1]) is None
        or _GITHUB_NAME_RE.fullmatch(parts[2]) is None
        or parts[2].endswith(".git")
    ):
        raise _resolution_error(
            "invalid-repository",
            "GitHub source requires an HTTPS github.com owner/repository URL",
            location="locator.repository",
        )
    return parts[1], parts[2]


def _github_path(path: str) -> str:
    if (
        not 1 <= len(path) <= 1024
        or "\\" in path
        or "%" in path
        or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in path
        )
    ):
        raise _resolution_error(
            "unsafe-path",
            "GitHub path is not a safe bounded POSIX path",
            location="locator.path",
        )
    candidate = PurePosixPath(path)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or str(candidate) != path
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or "?" in path
        or "#" in path
    ):
        raise _resolution_error(
            "unsafe-path",
            "GitHub path is absolute, normalized, or traversing",
            location="locator.path",
        )
    return path


class GitHubRevisionSource:
    """Interpret legacy repository locators as immutable GitHub raw URLs."""

    __slots__ = ("_fetcher",)

    def __init__(self, fetcher: ByteFetcher | None = None) -> None:
        self._fetcher = fetcher or HTTPSFetcher()

    @property
    def fetcher(self) -> ByteFetcher:
        return self._fetcher

    @staticmethod
    def raw_url(locator: ContentLocator) -> str:
        if locator.scheme != "rapp-legacy-repository-v1":
            raise _resolution_error(
                "unsupported-locator",
                "GitHub source cannot interpret this locator scheme",
                location="locator.scheme",
            )
        repository = locator.attributes.get("repository")
        commit = locator.attributes.get("commit")
        path = locator.attributes.get("path")
        if repository is None or commit is None or path is None:
            raise _resolution_error(
                "incomplete-locator",
                "legacy locator is missing repository, commit, or path",
                location="locator",
            )
        owner, repo = _github_coordinates(repository)
        if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
            raise _resolution_error(
                "mutable-revision",
                "GitHub source requires an immutable 40-hex commit",
                location="locator.commit",
            )
        quoted = urllib.parse.quote(_github_path(path), safe="/-._~")
        return (
            f"https://raw.githubusercontent.com/{owner}/{repo}/"
            f"{commit}/{quoted}"
        )

    def read(self, locator: ContentLocator, *, max_bytes: int) -> bytes:
        return self.fetcher.fetch(self.raw_url(locator), max_bytes=max_bytes)


class ContentAddressedCache:
    """Checksum-revalidating cache with atomic durable writes."""

    __slots__ = ("_root",)

    def __init__(self, root: StrPath) -> None:
        raw = os.fspath(root)
        if not isinstance(raw, str):
            raise TypeError("cache root must resolve to text")
        self._root = Path(raw)

    @property
    def root(self) -> Path:
        return self._root

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(
            character not in "0123456789abcdef" for character in sha256
        ):
            raise ValueError("cache sha256 must be 64 lowercase hex")
        return self.root / "sha256" / sha256[:2] / sha256[2:]

    @staticmethod
    def _validate(data: bytes, sha256: str, expected_bytes: int) -> None:
        if (
            type(expected_bytes) is not int
            or not 0 <= expected_bytes <= MAX_SPEC_BYTES
        ):
            raise ValueError("expected_bytes is outside the specification limit")
        if len(data) != expected_bytes:
            raise CacheIntegrityError(
                Diagnostic(
                    code="cached-size-mismatch",
                    operation="cache",
                    message="cached byte count does not match metadata",
                    location="cache-object",
                    context={
                        "actual_bytes": len(data),
                        "expected_bytes": expected_bytes,
                    },
                )
            )
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha256:
            raise CacheIntegrityError(
                Diagnostic(
                    code="cached-hash-mismatch",
                    operation="cache",
                    message="cached checksum does not match its address",
                    location="cache-object",
                    context={"actual_sha256": actual, "expected_sha256": sha256},
                )
            )

    def get(self, sha256: str, expected_bytes: int) -> bytes | None:
        path = self.path_for(sha256)
        if not os.path.lexists(path):
            return None
        if path.is_symlink() or not path.is_file():
            raise CacheIntegrityError(
                Diagnostic(
                    code="unsafe-cache-object",
                    operation="cache",
                    message="cache object is not a regular non-symlink file",
                    location=str(path),
                )
            )
        with path.open("rb") as stream:
            data = stream.read(expected_bytes + 1)
        self._validate(data, sha256, expected_bytes)
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
        if type(data) is not bytes:
            raise TypeError("cache data must be bytes")
        self._validate(data, sha256, expected_bytes)
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


class SpecResolver:
    """Resolve content only from trusted chains and explicitly supplied sources."""

    __slots__ = ("_chain", "_source", "_cache")

    def __init__(
        self,
        chain: SpecChain,
        *,
        source: RevisionSource | None = None,
        cache: ContentAddressedCache | None = None,
    ) -> None:
        if not isinstance(chain, SpecChain):
            raise TypeError("chain must be SpecChain")
        self._chain = chain
        self._source = source
        self._cache = cache

    @property
    def chain(self) -> SpecChain:
        return self._chain

    def read(self, revision: SpecRevision) -> bytes:
        """Return verified normative bytes without implicit network access."""

        if not isinstance(revision, SpecRevision):
            raise TypeError("revision must be SpecRevision")
        if not self.chain.contains(revision):
            raise _resolution_error(
                "foreign-revision",
                "revision does not belong to this chain",
                location="revision",
            )
        if not self.chain.trusted:
            raise _resolution_error(
                "untrusted-chain",
                "authoritative content cannot be read from a local-only chain",
                location="chain",
                remediation="verify the chain with StreamTrustPolicy",
            )
        inline = revision.inline_bytes()
        if inline is not None:
            if self._cache is not None:
                self._cache.put(
                    inline,
                    revision.normative_sha256,
                    revision.normative_bytes,
                )
            return inline
        if self._cache is not None:
            cached = self._cache.get(
                revision.normative_sha256,
                revision.normative_bytes,
            )
            if cached is not None:
                return cached
        if self._source is None:
            raise _resolution_error(
                "source-required",
                "legacy revision is uncached and no RevisionSource was supplied",
                location="source",
                remediation="construct SpecResolver with an explicit source",
            )
        if revision.locator is None:
            raise _resolution_error(
                "missing-locator",
                "legacy revision has no content locator",
                location="revision.locator",
            )
        data = self._source.read(
            revision.locator,
            max_bytes=revision.normative_bytes,
        )
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise _resolution_error(
                "invalid-source-response",
                "RevisionSource did not return bytes",
                location="source",
            )
        resolved = bytes(data)
        if len(resolved) != revision.normative_bytes:
            raise _resolution_error(
                "normative-size-mismatch",
                "resolved byte count does not match the revision",
                location="source",
                context={
                    "actual_bytes": len(resolved),
                    "expected_bytes": revision.normative_bytes,
                },
            )
        actual = hashlib.sha256(resolved).hexdigest()
        if actual != revision.normative_sha256:
            raise _resolution_error(
                "normative-hash-mismatch",
                "resolved checksum does not match the revision",
                location="source",
                context={
                    "actual_sha256": actual,
                    "expected_sha256": revision.normative_sha256,
                },
            )
        if self._cache is not None:
            self._cache.put(
                resolved,
                revision.normative_sha256,
                revision.normative_bytes,
            )
        return resolved


__all__ = (
    "ByteFetcher",
    "ContentAddressedCache",
    "DEFAULT_ALLOWED_FETCH_HOSTS",
    "DEFAULT_FETCH_SECONDS",
    "GitHubRevisionSource",
    "HTTPSFetcher",
    "RevisionSource",
    "SpecResolver",
)
