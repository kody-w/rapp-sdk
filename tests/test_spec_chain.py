from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import unittest
from pathlib import Path

from rapp_sdk.protocol import H, PARTICLE_SPACE, WAVE_SPACE, canonicalize
from rapp_sdk.spec_chain import (
    CacheIntegrityError,
    ContentAddressedCache,
    GitHubRawSource,
    HTTPSFetcher,
    SpecChain,
    SpecChainError,
    SpecResolutionError,
    build_spec_revision_frame,
)

STREAM_ID = (
    "rappid:@example/spec-chain:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
REPOSITORY = "https://github.com/example/specification"
COMMIT = "a" * 40


def as_jsonl(*frames: dict) -> bytes:
    return b"\n".join(
        json.dumps(frame, ensure_ascii=False).encode("utf-8") for frame in frames
    ) + b"\n"


def rehash(frame: dict) -> None:
    frame["payload_hash"] = H(PARTICLE_SPACE, frame["payload"])
    preimage = {
        key: value
        for key, value in frame.items()
        if key not in {"frame_hash", "sig"}
    }
    frame["frame_hash"] = H(WAVE_SPACE, preimage)


def pointer_frame(
    *,
    revision: str = "rev-1",
    content: bytes = b"# RAPP/1\n",
    commit: str = COMMIT,
    path: str = "SPEC.md",
) -> dict:
    from rapp_sdk.protocol import build_frame

    return build_frame(
        "body.pulse",
        STREAM_ID,
        0,
        "2026-08-30T00:00:00.000Z",
        {
            "revision": revision,
            "canonical_repo": REPOSITORY,
            "commit": commit,
            "normative_path": path,
            "normative_sha256": hashlib.sha256(content).hexdigest(),
            "normative_bytes": str(len(content)),
        },
        None,
    )


class MappingSource:
    def __init__(self, content: bytes):
        self.content = content
        self.calls: list[tuple[str, str, str, int]] = []

    def fetch(
        self,
        repository: str,
        commit: str,
        path: str,
        *,
        max_bytes: int,
    ) -> bytes:
        self.calls.append((repository, commit, path, max_bytes))
        return self.content


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

    def open(self, request, timeout):
        return self.response


class SpecChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(__file__).resolve().parent / ".scratch"
        if self.scratch.exists():
            import shutil

            shutil.rmtree(self.scratch)
        self.scratch.mkdir()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.scratch, ignore_errors=True)

    def test_legacy_pointer_resolves_and_caches_offline(self) -> None:
        content = b"# RAPP/1\n"
        chain = SpecChain.from_jsonl(as_jsonl(pointer_frame(content=content)))
        source = MappingSource(content)
        cache = ContentAddressedCache(self.scratch / "cache")
        resolved = chain.materialize("head", source=source, cache=cache)
        self.assertEqual(resolved, content)
        self.assertEqual(len(source.calls), 1)
        self.assertEqual(chain.materialize("rev-1", cache=cache, offline=True), content)
        self.assertEqual(chain.resolve(0).frame_hash, chain.head.frame_hash)
        self.assertEqual(
            chain.resolve(frame_hash=chain.head.frame_hash).revision,
            "rev-1",
        )
        self.assertEqual(
            chain.resolve(payload_hash=chain.head.payload_hash).revision,
            "rev-1",
        )

    def test_inline_revision_is_preferred_without_fetch(self) -> None:
        revision = build_spec_revision_frame(
            revision="rev-1",
            text="# Inline\n",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=STREAM_ID,
        )
        chain = SpecChain.from_jsonl(as_jsonl(revision))
        source = MappingSource(b"wrong")
        self.assertEqual(chain.materialize(source=source), b"# Inline\n")
        self.assertEqual(source.calls, [])

    def test_normative_text_pointer_and_cache_mutations_fail(self) -> None:
        inline = build_spec_revision_frame(
            revision="rev-inline",
            text="trusted",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=STREAM_ID,
        )
        inline["payload"]["normative"]["text"] = "mutated"
        rehash(inline)
        with self.assertRaisesRegex(SpecChainError, "checksum"):
            SpecChain.from_jsonl(as_jsonl(inline))

        content = b"trusted pointer"
        chain = SpecChain.from_jsonl(as_jsonl(pointer_frame(content=content)))
        with self.assertRaisesRegex(SpecResolutionError, "checksum"):
            chain.materialize(source=MappingSource(b"x" * len(content)))

        cache = ContentAddressedCache(self.scratch / "cache")
        chain.materialize(source=MappingSource(content), cache=cache)
        cache.path_for(chain.head.normative_sha256).write_bytes(
            b"x" * len(content)
        )
        with self.assertRaises(CacheIntegrityError):
            chain.materialize(cache=cache, offline=True)

    def test_uncached_offline_revision_fails(self) -> None:
        chain = SpecChain.from_jsonl(as_jsonl(pointer_frame()))
        with self.assertRaisesRegex(SpecResolutionError, "offline"):
            chain.materialize(offline=True)

    def test_duplicate_key_oversize_branch_and_unsafe_path_fail(self) -> None:
        with self.assertRaisesRegex(SpecChainError, "duplicate"):
            SpecChain.from_jsonl(
                b'{"spec":"rapp/1","spec":"rapp/1"}\n'
            )
        encoded = as_jsonl(pointer_frame())
        with self.assertRaisesRegex(SpecChainError, "exceeds"):
            SpecChain.from_jsonl(encoded, max_bytes=len(encoded) - 1)
        for commit, path in (("main", "SPEC.md"), (COMMIT, "../SPEC.md")):
            with self.subTest(commit=commit, path=path):
                candidate = pointer_frame(commit=commit, path=path)
                with self.assertRaises(SpecChainError):
                    SpecChain.from_jsonl(as_jsonl(candidate))

    def test_revision_label_cannot_address_different_bytes(self) -> None:
        first = build_spec_revision_frame(
            revision="rev-1",
            text="one",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=STREAM_ID,
        )
        second = build_spec_revision_frame(
            revision="rev-1",
            text="two",
            utc="2026-08-30T00:00:01.000Z",
            head=first,
        )
        with self.assertRaisesRegex(SpecChainError, "different bytes"):
            SpecChain.from_jsonl(as_jsonl(first, second))

    def test_legacy_same_byte_revision_checkpoints_remain_compatible(self) -> None:
        content = b"stable"
        first = pointer_frame(revision="rev-legacy", content=content)
        second = copy.deepcopy(first)
        second["seq"] = 1
        second["utc"] = "2026-08-30T00:00:01.000Z"
        second["prev"] = first["payload_hash"]
        second["payload"]["commit"] = "b" * 40
        rehash(second)
        chain = SpecChain.from_jsonl(as_jsonl(first, second))
        self.assertEqual(chain.resolve("rev-legacy").seq, 1)
        self.assertEqual(chain.resolve(first["frame_hash"]).seq, 0)

    def test_github_url_is_immutable_and_redirect_result_is_rechecked(self) -> None:
        expected = (
            "https://raw.githubusercontent.com/example/specification/"
            f"{COMMIT}/SPEC.md"
        )
        self.assertEqual(
            GitHubRawSource.raw_url(REPOSITORY, COMMIT, "SPEC.md"),
            expected,
        )
        for final_url in (
            expected.replace("https:", "http:"),
            expected.replace("raw.githubusercontent.com", "example.com"),
        ):
            with self.subTest(final_url=final_url):
                fetcher = HTTPSFetcher(
                    opener=FakeOpener(FakeResponse(b"ok", final_url))
                )
                with self.assertRaisesRegex(SpecResolutionError, "allowed HTTPS"):
                    fetcher.fetch(expected, max_bytes=2)

    def test_self_contained_frame_stays_within_protocol_limit(self) -> None:
        built = build_spec_revision_frame(
            revision="rev-2",
            text="hello",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=STREAM_ID,
        )
        self.assertLessEqual(len(canonicalize(built)), 1024 * 1024)

    def test_builder_refuses_a_corrupt_or_regressing_head(self) -> None:
        head = build_spec_revision_frame(
            revision="rev-1",
            text="one",
            utc="2026-08-30T00:00:01.000Z",
            stream_id=STREAM_ID,
        )
        corrupt = copy.deepcopy(head)
        corrupt["payload_hash"] = "0" * 64
        with self.assertRaisesRegex(SpecChainError, "payload_hash"):
            build_spec_revision_frame(
                revision="rev-2",
                text="two",
                utc="2026-08-30T00:00:02.000Z",
                head=corrupt,
            )
        with self.assertRaisesRegex(SpecChainError, "earlier"):
            build_spec_revision_frame(
                revision="rev-2",
                text="two",
                utc="2026-08-30T00:00:00.000Z",
                head=head,
            )


class LocalGitSource:
    def __init__(self, root: Path):
        self.root = root

    def fetch(
        self,
        repository: str,
        commit: str,
        path: str,
        *,
        max_bytes: int,
    ) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.root), "show", f"{commit}:{path}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if len(result.stdout) > max_bytes:
            raise AssertionError("local immutable object exceeded declared limit")
        return result.stdout


class CurrentAuthorityCompatibilityTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("RAPP1_AUTHORITY_ROOT"),
        "set RAPP1_AUTHORITY_ROOT to run immutable authority compatibility",
    )
    def test_current_authority_chain_and_spec(self) -> None:
        root = Path(os.environ["RAPP1_AUTHORITY_ROOT"])
        authority_commit = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
        self.assertEqual(
            authority_commit,
            "bfa0706a4dd448b98b59c68aece0761d625923cb",
        )
        chain = SpecChain.load(root / "anchor" / "chain.jsonl")
        self.assertEqual(len(chain), 14)
        self.assertEqual(chain.head.revision, "rev-13")
        self.assertEqual(chain.head.seq, 13)
        self.assertEqual(
            chain.head.frame_hash,
            "bbcee75ebbbf82d11d8ffd666fdda34c8233642de6d6e4f45910d43a24a001e3",
        )
        self.assertEqual(
            chain.head.payload_hash,
            "78a89c06509b5100494b9c7e0f551acdc6209fd90aded734321f3580b0f07051",
        )
        self.assertEqual(
            chain.head.global_url,
            "https://raw.githubusercontent.com/kody-w/rapp-1/"
            "5e30f66396f4cd125bce5718b1fef92d8d3ddab8/SPEC.md",
        )
        spec = chain.materialize("head", source=LocalGitSource(root))
        self.assertEqual(len(spec), 65569)
        self.assertEqual(len(spec), chain.head.normative_bytes)
        self.assertEqual(
            hashlib.sha256(spec).hexdigest(),
            "e5abd6a32801761fdd5c151a4f90fa4c989b545da02d3cd26dfc4765fab8409a",
        )
        self.assertEqual(
            hashlib.sha256(spec).hexdigest(),
            chain.head.normative_sha256,
        )
        self.assertEqual(spec, (root / "SPEC.md").read_bytes())


if __name__ == "__main__":
    unittest.main()
