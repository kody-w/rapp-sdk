from __future__ import annotations

import hashlib
import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

from rapp_sdk import CacheIntegrityError, ContentLocator, SpecResolutionError
from rapp_sdk.resolution import (
    ContentAddressedCache,
    GitHubRevisionSource,
    HTTPSFetcher,
)

REPOSITORY = "https://github.com/example/specification"
COMMIT = "a" * 40


class FakeResponse:
    def __init__(self, data: bytes, final_url: str):
        self._data = data
        self._url = final_url
        self.status = 200
        self.headers = {"Content-Length": str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, amount: int) -> bytes:
        return self._data[:amount]


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response

    def open(self, request, *, timeout):
        return self.response


def locator(*, commit: str = COMMIT, path: str = "SPEC.md") -> ContentLocator:
    return ContentLocator(
        scheme="rapp-legacy-repository-v1",
        attributes={
            "repository": REPOSITORY,
            "commit": commit,
            "path": path,
        },
    )


class ResolutionSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(__file__).resolve().parent / ".scratch-cache"
        shutil.rmtree(self.scratch, ignore_errors=True)
        self.scratch.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_https_fetcher_rechecks_redirect_final_scheme_and_host(self) -> None:
        expected = (
            "https://raw.githubusercontent.com/example/specification/"
            f"{COMMIT}/SPEC.md"
        )
        for final_url in (
            expected.replace("https:", "http:"),
            expected.replace("raw.githubusercontent.com", "example.com"),
        ):
            with self.subTest(final_url=final_url):
                fetcher = HTTPSFetcher(
                    opener=FakeOpener(FakeResponse(b"ok", final_url))
                )
                with self.assertRaises(SpecResolutionError) as raised:
                    fetcher.fetch(expected, max_bytes=2)
                self.assertEqual(raised.exception.code, "unsafe-url")

    def test_github_source_rejects_mutable_commit_and_unsafe_path(self) -> None:
        with self.assertRaises(SpecResolutionError) as mutable:
            GitHubRevisionSource.raw_url(locator(commit="main"))
        self.assertEqual(mutable.exception.code, "mutable-revision")
        with self.assertRaises(SpecResolutionError) as traversal:
            GitHubRevisionSource.raw_url(locator(path="../SPEC.md"))
        self.assertEqual(traversal.exception.code, "unsafe-path")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor traversal")
    def test_cache_rejects_symlinked_root_intermediate_and_leaf(self) -> None:
        data = b"safe text\n"
        digest = hashlib.sha256(data).hexdigest()
        outside = self.scratch / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_bytes(b"outside")

        root_link = self.scratch / "root-link"
        root_link.symlink_to(outside, target_is_directory=True)
        root_cache = ContentAddressedCache(root_link)
        with self.assertRaises(CacheIntegrityError):
            root_cache.get(digest, len(data))
        with self.assertRaises(CacheIntegrityError):
            root_cache.put(data, digest, len(data))

        intermediate_root = self.scratch / "intermediate"
        intermediate_root.mkdir()
        (intermediate_root / "sha256").symlink_to(
            outside,
            target_is_directory=True,
        )
        intermediate_cache = ContentAddressedCache(intermediate_root)
        with self.assertRaises(CacheIntegrityError):
            intermediate_cache.get(digest, len(data))
        with self.assertRaises(CacheIntegrityError):
            intermediate_cache.put(data, digest, len(data))

        leaf_cache = ContentAddressedCache(self.scratch / "leaf")
        leaf = leaf_cache.put(data, digest, len(data))
        leaf.unlink()
        leaf.symlink_to(marker)
        with self.assertRaises(CacheIntegrityError):
            leaf_cache.get(digest, len(data))
        with self.assertRaises(CacheIntegrityError):
            leaf_cache.put(data, digest, len(data))

        self.assertEqual(marker.read_bytes(), b"outside")
        self.assertEqual(list(outside.iterdir()), [marker])

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor traversal")
    def test_cache_swap_race_never_writes_outside_root(self) -> None:
        data = b"safe text\n"
        digest = hashlib.sha256(data).hexdigest()
        root = self.scratch / "cache"
        outside = self.scratch / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_bytes(b"outside")
        cache = ContentAddressedCache(root)
        real_replace = os.replace
        swapped = False

        def swap_then_replace(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                prefix = cache.path_for(digest).parent
                moved = root / "moved-prefix"
                prefix.rename(moved)
                prefix.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_replace(*args, **kwargs)

        with mock.patch(
            "rapp_sdk.resolution.os.replace",
            side_effect=swap_then_replace,
        ), self.assertRaises(CacheIntegrityError):
            cache.put(data, digest, len(data))

        moved_leaf = root / "moved-prefix" / digest[2:]
        self.assertFalse(moved_leaf.exists())
        self.assertEqual(marker.read_bytes(), b"outside")
        self.assertEqual(list(outside.iterdir()), [marker])

    def test_windows_replacement_seam_reopens_validates_and_cleans(self) -> None:
        data = b"safe text\n"
        replacement = b"evil text\n"
        self.assertEqual(len(data), len(replacement))
        digest = hashlib.sha256(data).hexdigest()
        cache = ContentAddressedCache(self.scratch / "windows-cache")
        real_replace = os.replace

        def replace_then_corrupt(*args, **kwargs):
            result = real_replace(*args, **kwargs)
            cache.path_for(digest).write_bytes(replacement)
            return result

        with mock.patch(
            "rapp_sdk.resolution.os.replace",
            side_effect=replace_then_corrupt,
        ), self.assertRaises(SpecResolutionError) as raised:
            cache._put_windows(data, digest, len(data))
        self.assertEqual(
            raised.exception.code,
            "normative-hash-mismatch",
        )
        self.assertFalse(cache.path_for(digest).exists())


if __name__ == "__main__":
    unittest.main()
