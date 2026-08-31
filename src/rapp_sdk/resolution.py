"""Explicit specification resolution, cache, and HTTPS source adapters."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping, Set
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from ._version import __version__
from .errors import CacheIntegrityError, SpecChainError, SpecResolutionError
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


def _validate_normative_text(
    data: bytes | bytearray | memoryview,
    *,
    sha256: str,
    expected_bytes: int,
    location: str,
) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("normative content must be bytes")
    octets = bytes(data)
    if len(octets) != expected_bytes:
        raise _resolution_error(
            "normative-size-mismatch",
            "normative byte count does not match metadata",
            location=location,
            context={
                "actual_bytes": len(octets),
                "expected_bytes": expected_bytes,
            },
        )
    actual = hashlib.sha256(octets).hexdigest()
    if actual != sha256:
        raise _resolution_error(
            "normative-hash-mismatch",
            "normative checksum does not match metadata",
            location=location,
            context={"actual_sha256": actual, "expected_sha256": sha256},
        )
    if octets.startswith(b"\xef\xbb\xbf"):
        raise _resolution_error(
            "normative-bom",
            "normative text must not begin with a UTF-8 BOM",
            location=location,
        )
    try:
        text = octets.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _resolution_error(
            "invalid-normative-utf8",
            "normative content is not strict UTF-8",
            location=location,
        ) from exc
    if text.startswith("\ufeff"):
        raise _resolution_error(
            "normative-bom",
            "normative text must not begin with U+FEFF",
            location=location,
        )
    if text.encode("utf-8") != octets:
        raise _resolution_error(
            "normative-roundtrip-mismatch",
            "normative text does not round-trip to identical UTF-8 bytes",
            location=location,
        )
    return octets


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


@dataclass(frozen=True, slots=True)
class _DirectoryHandle:
    fd: int
    identity: tuple[int, int]
    parent_fd: int | None
    name: str | None


class ContentAddressedCache:
    """Race-resistant content cache with no-follow component traversal."""

    __slots__ = ("_root",)

    def __init__(self, root: StrPath) -> None:
        raw = os.fspath(root)
        if not isinstance(raw, str):
            raise TypeError("cache root must resolve to text")
        self._root = Path(os.path.abspath(raw))

    @property
    def root(self) -> Path:
        return self._root

    def path_for(self, sha256: str) -> Path:
        self._validate_address(sha256)
        return self.root / "sha256" / sha256[:2] / sha256[2:]

    @staticmethod
    def _validate_address(sha256: str) -> None:
        if len(sha256) != 64 or any(
            character not in "0123456789abcdef" for character in sha256
        ):
            raise ValueError("cache sha256 must be 64 lowercase hex")

    @staticmethod
    def _validate_size(expected_bytes: int) -> None:
        if (
            type(expected_bytes) is not int
            or not 0 <= expected_bytes <= MAX_SPEC_BYTES
        ):
            raise ValueError("expected_bytes is outside the specification limit")

    @staticmethod
    def _unsafe(message: str, location: str) -> CacheIntegrityError:
        return CacheIntegrityError(
            Diagnostic(
                code="unsafe-cache-object",
                operation="cache",
                message=message,
                location=location,
            )
        )

    @staticmethod
    def _identity(descriptor: int) -> tuple[int, int]:
        metadata = os.fstat(descriptor)
        if metadata.st_ino == 0:
            raise ContentAddressedCache._unsafe(
                "filesystem does not expose stable object identity",
                "cache",
            )
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _directory_flags() -> int:
        required = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required):
            raise ContentAddressedCache._unsafe(
                "platform lacks safe no-follow directory traversal",
                "cache",
            )
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    @classmethod
    def _open_directory_at(
        cls,
        parent_fd: int,
        name: str,
        *,
        create: bool,
    ) -> int | None:
        try:
            return os.open(
                name,
                cls._directory_flags(),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            if not create:
                return None
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
                return os.open(
                    name,
                    cls._directory_flags(),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise cls._unsafe(
                    f"cannot safely create cache directory: {exc}",
                    name,
                ) from exc
        except OSError as exc:
            raise cls._unsafe(
                f"cache directory is unsafe or inaccessible: {exc}",
                name,
            ) from exc

    def _open_posix_chain(
        self,
        sha256: str,
        *,
        create: bool,
    ) -> list[_DirectoryHandle] | None:
        flags = self._directory_flags()
        handles: list[_DirectoryHandle] = []
        try:
            anchor = os.open(os.path.sep, flags)
            handles.append(
                _DirectoryHandle(anchor, self._identity(anchor), None, None)
            )
            components = list(self.root.parts[1:]) + ["sha256", sha256[:2]]
            parent_fd = anchor
            for name in components:
                descriptor = self._open_directory_at(
                    parent_fd,
                    name,
                    create=create,
                )
                if descriptor is None:
                    self._close_handles(handles)
                    return None
                handles.append(
                    _DirectoryHandle(
                        descriptor,
                        self._identity(descriptor),
                        parent_fd,
                        name,
                    )
                )
                parent_fd = descriptor
            self._revalidate_posix(handles)
            return handles
        except Exception:
            self._close_handles(handles)
            raise

    @classmethod
    def _revalidate_posix(
        cls,
        handles: list[_DirectoryHandle],
    ) -> None:
        for handle in handles:
            if cls._identity(handle.fd) != handle.identity:
                raise cls._unsafe("cache directory identity changed", "cache")
            if handle.parent_fd is None or handle.name is None:
                continue
            reopened = cls._open_directory_at(
                handle.parent_fd,
                handle.name,
                create=False,
            )
            if reopened is None:
                raise cls._unsafe("cache directory disappeared", handle.name)
            try:
                if cls._identity(reopened) != handle.identity:
                    raise cls._unsafe(
                        "cache directory was replaced during access",
                        handle.name,
                    )
            finally:
                os.close(reopened)

    @staticmethod
    def _close_handles(handles: list[_DirectoryHandle]) -> None:
        for handle in reversed(handles):
            try:
                os.close(handle.fd)
            except OSError:
                pass

    @classmethod
    def _read_posix_leaf(
        cls,
        directory_fd: int,
        name: str,
        *,
        maximum: int,
    ) -> bytes | None:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise cls._unsafe(
                f"cache leaf is unsafe or inaccessible: {exc}",
                name,
            ) from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise cls._unsafe("cache leaf is not a regular file", name)
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            stable = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if not stable:
                raise cls._unsafe("cache leaf changed during read", name)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _get_posix(
        self,
        sha256: str,
        expected_bytes: int,
    ) -> bytes | None:
        handles = self._open_posix_chain(sha256, create=False)
        if handles is None:
            return None
        try:
            self._revalidate_posix(handles)
            data = self._read_posix_leaf(
                handles[-1].fd,
                sha256[2:],
                maximum=expected_bytes,
            )
            self._revalidate_posix(handles)
            if data is None:
                return None
            return _validate_normative_text(
                data,
                sha256=sha256,
                expected_bytes=expected_bytes,
                location="cache",
            )
        finally:
            self._close_handles(handles)

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("cache write made no progress")
            written += count

    def _put_posix(
        self,
        data: bytes,
        sha256: str,
        expected_bytes: int,
    ) -> Path:
        handles = self._open_posix_chain(sha256, create=True)
        if handles is None:
            raise self._unsafe("cache directory creation failed", "cache")
        directory_fd = handles[-1].fd
        leaf = sha256[2:]
        temporary = f".{leaf}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        temporary_fd: int | None = None
        installed = False
        try:
            self._revalidate_posix(handles)
            existing = self._read_posix_leaf(
                directory_fd,
                leaf,
                maximum=expected_bytes,
            )
            if existing is not None:
                _validate_normative_text(
                    existing,
                    sha256=sha256,
                    expected_bytes=expected_bytes,
                    location="cache",
                )
                return self.path_for(sha256)
            temporary_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            self._write_all(temporary_fd, data)
            os.fsync(temporary_fd)
            metadata = os.fstat(temporary_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(data):
                raise self._unsafe("temporary cache object is invalid", temporary)
            os.close(temporary_fd)
            temporary_fd = None
            self._revalidate_posix(handles)
            try:
                leaf_metadata = os.stat(
                    leaf,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                leaf_metadata = None
            if leaf_metadata is not None:
                raise self._unsafe(
                    "cache leaf appeared during atomic write",
                    leaf,
                )
            os.replace(
                temporary,
                leaf,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            installed = True
            try:
                self._revalidate_posix(handles)
            except Exception:
                os.unlink(leaf, dir_fd=directory_fd)
                installed = False
                raise
            os.fsync(directory_fd)
            verified = self._read_posix_leaf(
                directory_fd,
                leaf,
                maximum=expected_bytes,
            )
            if verified is None:
                raise self._unsafe("cache leaf disappeared after replace", leaf)
            _validate_normative_text(
                verified,
                sha256=sha256,
                expected_bytes=expected_bytes,
                location="cache",
            )
            return self.path_for(sha256)
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            if not installed:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    pass
            self._close_handles(handles)

    @staticmethod
    def _windows_identity(path: Path) -> tuple[int, int]:
        metadata = path.lstat()
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or (reparse and attributes & reparse):
            raise ContentAddressedCache._unsafe(
                "cache path contains a symlink or reparse point",
                str(path),
            )
        if metadata.st_ino == 0:
            raise ContentAddressedCache._unsafe(
                "filesystem cannot guarantee stable cache identity",
                str(path),
            )
        return metadata.st_dev, metadata.st_ino

    def _windows_directories(
        self,
        sha256: str,
        *,
        create: bool,
    ) -> list[tuple[Path, tuple[int, int]]] | None:
        directories: list[tuple[Path, tuple[int, int]]] = []
        current = Path(self.root.anchor)
        for part in self.root.parts[1:] + ("sha256", sha256[:2]):
            current = current / part
            if not current.exists():
                if not create:
                    return None
                current.mkdir()
            identity = self._windows_identity(current)
            if not current.is_dir():
                raise self._unsafe("cache component is not a directory", str(current))
            directories.append((current, identity))
        return directories

    @classmethod
    def _revalidate_windows(
        cls,
        directories: list[tuple[Path, tuple[int, int]]],
    ) -> None:
        for path, identity in directories:
            if cls._windows_identity(path) != identity:
                raise cls._unsafe("cache directory identity changed", str(path))

    def _get_windows(self, sha256: str, expected_bytes: int) -> bytes | None:
        directories = self._windows_directories(sha256, create=False)
        if directories is None:
            return None
        self._revalidate_windows(directories)
        path = self.path_for(sha256)
        if not os.path.lexists(path):
            return None
        identity = self._windows_identity(path)
        descriptor = os.open(path, os.O_RDONLY)
        try:
            if self._identity(descriptor) != identity:
                raise self._unsafe("cache leaf changed before open", str(path))
            chunks: list[bytes] = []
            remaining = expected_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if self._identity(descriptor) != identity:
                raise self._unsafe("cache leaf changed during read", str(path))
        finally:
            os.close(descriptor)
        self._revalidate_windows(directories)
        return _validate_normative_text(
            b"".join(chunks),
            sha256=sha256,
            expected_bytes=expected_bytes,
            location="cache",
        )

    def _put_windows(
        self,
        data: bytes,
        sha256: str,
        expected_bytes: int,
    ) -> Path:
        directories = self._windows_directories(sha256, create=True)
        if directories is None:
            raise self._unsafe("cache directory creation failed", "cache")
        self._revalidate_windows(directories)
        path = self.path_for(sha256)
        if path.exists() or os.path.lexists(path):
            existing = self._get_windows(sha256, expected_bytes)
            if existing is None:
                raise self._unsafe("cache leaf cannot be opened safely", str(path))
            return path
        temporary = path.with_name(
            f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self._windows_identity(temporary)
            self._revalidate_windows(directories)
            if os.path.lexists(path):
                raise self._unsafe(
                    "cache leaf appeared during atomic write",
                    str(path),
                )
            os.replace(temporary, path)
            installed_identity = self._windows_identity(path)
            try:
                self._revalidate_windows(directories)
                verified = self._get_windows(sha256, expected_bytes)
                if verified is None:
                    raise self._unsafe(
                        "cache leaf disappeared after replacement",
                        str(path),
                    )
                if self._windows_identity(path) != installed_identity:
                    raise self._unsafe(
                        "cache leaf identity changed after validation",
                        str(path),
                    )
                self._revalidate_windows(directories)
                return path
            except Exception as validation_error:
                try:
                    if (
                        os.path.lexists(path)
                        and self._windows_identity(path) == installed_identity
                    ):
                        path.unlink()
                    self._revalidate_windows(directories)
                except Exception as cleanup_error:
                    raise self._unsafe(
                        "cannot safely remove failed cache replacement",
                        str(path),
                    ) from cleanup_error
                raise
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def get(self, sha256: str, expected_bytes: int) -> bytes | None:
        self._validate_address(sha256)
        self._validate_size(expected_bytes)
        if os.name == "posix":
            return self._get_posix(sha256, expected_bytes)
        if os.name == "nt":
            return self._get_windows(sha256, expected_bytes)
        raise self._unsafe("platform has no safe cache implementation", "cache")

    def put(self, data: bytes, sha256: str, expected_bytes: int) -> Path:
        if type(data) is not bytes:
            raise TypeError("cache data must be bytes")
        self._validate_address(sha256)
        self._validate_size(expected_bytes)
        validated = _validate_normative_text(
            data,
            sha256=sha256,
            expected_bytes=expected_bytes,
            location="cache",
        )
        if os.name == "posix":
            return self._put_posix(validated, sha256, expected_bytes)
        if os.name == "nt":
            return self._put_windows(validated, sha256, expected_bytes)
        raise self._unsafe("platform has no safe cache implementation", "cache")


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
        try:
            selected = self.chain.resolve(frame_hash=revision.frame_hash)
        except (SpecChainError, ValueError) as exc:
            raise _resolution_error(
                "foreign-revision",
                "revision does not belong to this chain",
                location="revision",
            ) from exc
        if selected.address != revision.address:
            raise _resolution_error(
                "foreign-revision",
                "revision address does not match this chain",
                location="revision",
            )
        revision = selected
        if not self.chain.trusted:
            raise _resolution_error(
                "untrusted-chain",
                "authoritative content cannot be read from a local-only chain",
                location="chain",
                remediation="verify the chain with StreamTrustPolicy",
            )
        inline = revision.inline_bytes()
        if inline is not None:
            validated = _validate_normative_text(
                inline,
                sha256=revision.normative_sha256,
                expected_bytes=revision.normative_bytes,
                location="inline",
            )
            if self._cache is not None:
                self._cache.put(
                    validated,
                    revision.normative_sha256,
                    revision.normative_bytes,
                )
            return validated
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
        resolved = _validate_normative_text(
            data,
            sha256=revision.normative_sha256,
            expected_bytes=revision.normative_bytes,
            location="source",
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
