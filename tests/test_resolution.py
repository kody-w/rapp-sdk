from __future__ import annotations

import unittest

from rapp_sdk import ContentLocator, SpecResolutionError
from rapp_sdk.resolution import GitHubRevisionSource, HTTPSFetcher

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


if __name__ == "__main__":
    unittest.main()
