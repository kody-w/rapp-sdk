from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

from rapp_sdk import (
    AuthorityCheckpoint,
    ContentLocator,
    KindFamilyRegistry,
    SpecChain,
    SpecChainError,
    SpecResolver,
    SpecResolutionError,
    SpecRevision,
    StreamTrustPolicy,
    build_frame_mapping,
    build_spec_revision_frame,
    canonicalize,
    read_spec_revision_schema,
    strict_json_loads,
)
from rapp_sdk.protocol import H, PARTICLE_SPACE, WAVE_SPACE
from rapp_sdk.resolution import (
    ContentAddressedCache,
    GitHubRevisionSource,
)
from tests.authority_fixture import (
    HISTORICAL_REV13_SHA256,
    SELECTED_AUTHORITY_COMMIT,
    SELECTED_BOOTSTRAP_SHA256,
    SELECTED_FRAME_HASH,
    SELECTED_PAYLOAD_HASH,
    SELECTED_SPEC_SHA256,
    selected_fixture,
    selected_policies,
)

RID = "rappid:@example/spec-chain:" + "1" * 64
REPOSITORY = "https://github.com/example/specification"
COMMIT = "a" * 40
UTC0 = "2026-08-30T00:00:00.000Z"
UTC1 = "2026-08-30T00:00:01.000Z"


def jsonl(*frames: dict) -> bytes:
    return b"".join(canonicalize(frame) + b"\n" for frame in frames)


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
    repository: str = REPOSITORY,
    integer_size: bool = False,
) -> dict:
    size: int | str = len(content) if integer_size else str(len(content))
    return build_frame_mapping(
        "body.pulse",
        RID,
        0,
        UTC0,
        {
            "revision": revision,
            "canonical_repo": repository,
            "commit": commit,
            "normative_path": path,
            "normative_sha256": hashlib.sha256(content).hexdigest(),
            "normative_bytes": size,
        },
        None,
    )


def policies(*frames: dict) -> tuple[KindFamilyRegistry, StreamTrustPolicy]:
    selected = frames[-1]
    checkpoint = AuthorityCheckpoint.from_authenticated(
        {
            "canonical_repository": "https://example.test/authority",
            "protected_ref": "refs/heads/main",
            "accepted_commit": "a" * 40,
            "bootstrap_profile_sha256": "b" * 64,
            "chain_sha256": hashlib.sha256(jsonl(*frames)).hexdigest(),
            "stream_id": frames[0]["stream_id"],
            "genesis_frame_hash": frames[0]["frame_hash"],
            "selected_head": {
                "seq": selected["seq"],
                "frame_hash": selected["frame_hash"],
                "payload_hash": selected["payload_hash"],
            },
            "frame_hashes": [frame["frame_hash"] for frame in frames],
            "kind_families": {"body.pulse": "body"},
            "number_profile": "rfc8785-binary64",
        },
        authenticator=lambda evidence: True,
    )
    return (
        KindFamilyRegistry.from_checkpoint(checkpoint),
        StreamTrustPolicy.from_checkpoint(checkpoint),
    )


def local_registry(first: dict) -> KindFamilyRegistry:
    return KindFamilyRegistry.local(
        {"body.pulse": "body"},
        genesis_hashes={first["stream_id"]: first["frame_hash"]},
    )


def trusted_chain(*frames: dict) -> SpecChain:
    registry, trust = policies(*frames)
    return SpecChain.from_frames(
        frames,
        registry=registry,
        trust_policy=trust,
    )


class MappingRevisionSource:
    def __init__(self, content: bytes):
        self.content = content
        self.calls: list[tuple[ContentLocator, int]] = []

    def read(self, locator: ContentLocator, *, max_bytes: int) -> bytes:
        self.calls.append((locator, max_bytes))
        return self.content


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

    def test_explicit_resolver_handles_pointer_cache_and_inline_bytes(self) -> None:
        content = b"# Pointer\n"
        chain = trusted_chain(pointer_frame(content=content))
        source = MappingRevisionSource(content)
        cache = ContentAddressedCache(self.scratch / "cache")
        resolver = SpecResolver(chain, source=source, cache=cache)
        self.assertEqual(resolver.read(chain.head), content)
        self.assertEqual(len(source.calls), 1)
        self.assertEqual(
            SpecResolver(chain, cache=cache).read(chain.head),
            content,
        )

        inline = build_spec_revision_frame(
            revision="rev-inline",
            text="# Inline\n",
            utc=UTC0,
            stream_id=RID,
        )
        inline_chain = trusted_chain(inline)
        self.assertEqual(
            SpecResolver(inline_chain).read(inline_chain.head),
            b"# Inline\n",
        )

    def test_no_source_never_opens_network_and_local_chain_cannot_resolve(self) -> None:
        pointer = pointer_frame()
        chain = trusted_chain(pointer)
        with mock.patch(
            "urllib.request.OpenerDirector.open",
            side_effect=AssertionError("network access is forbidden"),
        ), mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("network access is forbidden"),
        ):
            with self.assertRaises(SpecResolutionError) as raised:
                SpecResolver(chain).read(chain.head)
        self.assertEqual(raised.exception.code, "source-required")
        self.assertIn(
            "explicit source",
            raised.exception.diagnostic.remediation,
        )

        local = SpecChain.from_frames_local(
            [pointer],
            registry=local_registry(pointer),
        )
        self.assertFalse(local.trusted)
        with self.assertRaises(SpecResolutionError) as untrusted:
            SpecResolver(local).read(local.head)
        self.assertEqual(untrusted.exception.code, "untrusted-chain")

    def test_revision_forgery_cannot_replace_internal_content(self) -> None:
        inline = build_spec_revision_frame(
            revision="rev-inline",
            text="trusted",
            utc=UTC0,
            stream_id=RID,
        )
        inline_chain = trusted_chain(inline)
        with self.assertRaises((TypeError, ValueError)):
            dataclasses.replace(
                inline_chain.head,
                _inline_bytes=b"EVIL",
            )

        forged = object.__new__(SpecRevision)
        for name, value in (
            ("address", inline_chain.head.address),
            ("stream_id", RID),
            ("normative_sha256", "0" * 64),
            ("normative_bytes", 4),
            ("media_type", "text/plain"),
            ("locator", None),
            ("is_inline", True),
            ("frame", None),
        ):
            object.__setattr__(forged, name, value)
        self.assertEqual(
            SpecResolver(inline_chain).read(forged),
            b"trusted",
        )

        pointer_chain = trusted_chain(pointer_frame())
        pointer_forgery = object.__new__(SpecRevision)
        for name, value in (
            ("address", pointer_chain.head.address),
            ("stream_id", RID),
            ("normative_sha256", hashlib.sha256(b"EVIL").hexdigest()),
            ("normative_bytes", 4),
            ("media_type", "text/plain"),
            ("locator", None),
            ("is_inline", True),
            ("frame", None),
        ):
            object.__setattr__(pointer_forgery, name, value)
        with self.assertRaises(SpecResolutionError) as source_required:
            SpecResolver(pointer_chain).read(pointer_forgery)
        self.assertEqual(source_required.exception.code, "source-required")

    def test_direct_constructor_cannot_splice_unrelated_revisions(self) -> None:
        first = trusted_chain(
            build_spec_revision_frame(
                revision="rev-first",
                text="first",
                utc=UTC0,
                stream_id=RID,
            )
        )
        other = trusted_chain(
            build_spec_revision_frame(
                revision="rev-other",
                text="other",
                utc=UTC0,
                stream_id=RID,
            )
        )
        with self.assertRaisesRegex(TypeError, "from_"):
            SpecChain(first._stream, (other.head,))

    def test_selector_api_is_keyword_only_and_labels_are_explicit(self) -> None:
        content = b"stable"
        first = pointer_frame(revision="rev-legacy", content=content)
        first_chain = trusted_chain(first)
        second = build_frame_mapping(
            "body.pulse",
            RID,
            1,
            UTC1,
            {
                **first["payload"],
                "commit": "b" * 40,
            },
            first["payload_hash"],
        )
        chain = trusted_chain(first, second)
        self.assertEqual(chain.head.seq, 1)
        self.assertEqual(chain.resolve(revision="rev-legacy").seq, 1)
        self.assertEqual(chain.resolve(seq=0).frame_hash, first_chain.head.frame_hash)
        self.assertEqual(
            chain.resolve(frame_hash=first["frame_hash"]).seq,
            0,
        )
        self.assertEqual(
            chain.resolve(payload_hash=second["payload_hash"]).seq,
            1,
        )
        with self.assertRaises(TypeError):
            chain.resolve("rev-legacy")
        with self.assertRaises(ValueError):
            chain.resolve()
        with self.assertRaises(ValueError):
            chain.resolve(revision="rev-legacy", seq=1)

    def test_schema_and_runtime_profiles_match(self) -> None:
        schema = json.loads(read_spec_revision_schema())
        inline_bytes_schema = schema["properties"]["normative"]["properties"][
            "bytes"
        ]
        self.assertEqual(inline_bytes_schema["type"], "integer")
        self.assertEqual(
            schema["properties"]["normative_path"]["maxLength"],
            1024,
        )
        path_pattern = re.compile(
            schema["properties"]["normative_path"]["pattern"]
        )
        repository_pattern = re.compile(
            schema["properties"]["canonical_repo"]["pattern"]
        )
        legacy_types = schema["properties"]["normative_bytes"]["oneOf"]
        self.assertEqual(
            {entry["type"] for entry in legacy_types},
            {"integer", "string"},
        )
        string_size_schema = next(
            entry for entry in legacy_types if entry["type"] == "string"
        )
        size_pattern = re.compile(string_size_schema["pattern"])
        for accepted in ("0", "1", "999999", "1000000", "1048576"):
            self.assertIsNotNone(size_pattern.fullmatch(accepted))
        for rejected in ("00", "1048577", "9999999", "-1"):
            self.assertIsNone(size_pattern.fullmatch(rejected))

        for integer_size in (False, True):
            with self.subTest(integer_size=integer_size):
                self.assertEqual(
                    trusted_chain(
                        pointer_frame(integer_size=integer_size)
                    ).head.normative_bytes,
                    9,
                )

        invalid_inline = build_spec_revision_frame(
            revision="rev-1",
            text="text",
            utc=UTC0,
            stream_id=RID,
        )
        invalid_inline["payload"]["normative"]["bytes"] = "4"
        rehash(invalid_inline)
        with self.assertRaises(SpecChainError) as inline_error:
            trusted_chain(invalid_inline)
        self.assertEqual(inline_error.exception.code, "invalid-inline-size")

        with self.assertRaises(SpecChainError) as long_path:
            trusted_chain(pointer_frame(path="a" * 1025))
        self.assertEqual(long_path.exception.code, "unsafe-path")
        oversized_pointer = pointer_frame()
        oversized_pointer["payload"]["normative_bytes"] = "1048577"
        rehash(oversized_pointer)
        with self.assertRaises(SpecChainError) as oversized:
            trusted_chain(oversized_pointer)
        self.assertEqual(oversized.exception.code, "spec-size-exceeded")
        for unsafe in ("a//b", "a/../b", "a/", "a b"):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(path_pattern.fullmatch(unsafe))
                with self.assertRaises(SpecChainError):
                    trusted_chain(pointer_frame(path=unsafe))
        self.assertIsNotNone(path_pattern.fullmatch("specs/RAPP-1.md"))
        self.assertIsNotNone(
            repository_pattern.fullmatch("https://example.com/specification")
        )
        self.assertIsNone(
            repository_pattern.fullmatch("HTTPS://example.com/specification")
        )
        with self.assertRaises(SpecChainError):
            trusted_chain(
                pointer_frame(
                    repository="HTTPS://example.com/specification"
                )
            )
        for unsafe_repository in (
            "https://user@example.com/specification",
            "https://example.com:444/specification",
            "https://example.com/specification?ref=main",
            "https://example.com/specification#main",
            "https://example.com",
            "https://example.com//specification",
        ):
            with self.subTest(repository=unsafe_repository):
                self.assertIsNone(
                    repository_pattern.fullmatch(unsafe_repository)
                )
                with self.assertRaises(SpecChainError):
                    trusted_chain(
                        pointer_frame(repository=unsafe_repository)
                    )

    def test_jsonl_scanning_is_deadline_and_memory_bounded(self) -> None:
        first = pointer_frame()
        registry = local_registry(first)
        with self.assertRaises(SpecChainError) as timed:
            SpecChain.from_jsonl_local(
                jsonl(first),
                registry=registry,
                max_seconds=0,
            )
        self.assertEqual(
            timed.exception.code,
            "verification-time-exceeded",
        )
        with self.assertRaises(SpecChainError) as capped:
            SpecChain.from_jsonl_local(
                jsonl(first) + b"not-json\n",
                registry=registry,
                max_frames=1,
            )
        self.assertEqual(capped.exception.code, "frame-count-exceeded")

        adversarial = b"\n" * 2_000_000
        tracemalloc.start()
        try:
            with self.assertRaises(SpecChainError) as blank:
                SpecChain.from_jsonl_local(
                    adversarial,
                    registry=registry,
                )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(blank.exception.code, "blank-chain-line")
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_normative_and_cache_mutations_fail(self) -> None:
        inline = build_spec_revision_frame(
            revision="rev-inline",
            text="trusted",
            utc=UTC0,
            stream_id=RID,
        )
        inline["payload"]["normative"]["text"] = "mutated"
        rehash(inline)
        with self.assertRaises(SpecChainError) as text_error:
            trusted_chain(inline)
        self.assertEqual(text_error.exception.code, "inline-hash-mismatch")

        content = b"trusted pointer"
        chain = trusted_chain(pointer_frame(content=content))
        with self.assertRaises(SpecResolutionError) as pointer_error:
            SpecResolver(
                chain,
                source=MappingRevisionSource(b"x" * len(content)),
            ).read(chain.head)
        self.assertEqual(pointer_error.exception.code, "normative-hash-mismatch")

        cache = ContentAddressedCache(self.scratch / "cache")
        SpecResolver(
            chain,
            source=MappingRevisionSource(content),
            cache=cache,
        ).read(chain.head)
        cache.path_for(chain.head.normative_sha256).write_bytes(
            b"x" * len(content)
        )
        with self.assertRaises(SpecResolutionError) as cache_error:
            SpecResolver(chain, cache=cache).read(chain.head)
        self.assertEqual(cache_error.exception.code, "normative-hash-mismatch")

    def test_normative_text_validation_covers_inline_cache_and_source(self) -> None:
        inline_bom = build_spec_revision_frame(
            revision="rev-bom",
            text="\ufeffinline",
            utc=UTC0,
            stream_id=RID,
        )
        inline_chain = trusted_chain(inline_bom)
        with self.assertRaises(SpecResolutionError) as inline_error:
            SpecResolver(inline_chain).read(inline_chain.head)
        self.assertEqual(inline_error.exception.code, "normative-bom")
        with self.assertRaises(SpecChainError):
            build_spec_revision_frame(
                revision="rev-invalid",
                text="\ud800",
                utc=UTC0,
                stream_id=RID,
            )

        for content, code in (
            (b"\xff", "invalid-normative-utf8"),
            (b"\xef\xbb\xbfsource", "normative-bom"),
        ):
            with self.subTest(path="source", code=code):
                chain = trusted_chain(pointer_frame(content=content))
                with self.assertRaises(SpecResolutionError) as source_error:
                    SpecResolver(
                        chain,
                        source=MappingRevisionSource(content),
                    ).read(chain.head)
                self.assertEqual(source_error.exception.code, code)

            with self.subTest(path="cache", code=code):
                chain = trusted_chain(pointer_frame(content=content))
                cache = ContentAddressedCache(self.scratch / f"cache-{code}")
                cache_path = cache.path_for(chain.head.normative_sha256)
                cache_path.parent.mkdir(parents=True)
                cache_path.write_bytes(content)
                with self.assertRaises(SpecResolutionError) as cache_error:
                    SpecResolver(chain, cache=cache).read(chain.head)
                self.assertEqual(cache_error.exception.code, code)

    def test_github_interpretation_is_isolated_in_source_adapter(self) -> None:
        chain = trusted_chain(pointer_frame())
        locator = chain.head.locator
        self.assertIsNotNone(locator)
        self.assertEqual(
            GitHubRevisionSource.raw_url(locator),
            "https://raw.githubusercontent.com/example/specification/"
            f"{COMMIT}/SPEC.md",
        )
        generic = trusted_chain(
            pointer_frame(repository="https://example.com/specification")
        )
        self.assertEqual(
            generic.head.locator.attributes["repository"],
            "https://example.com/specification",
        )
        with self.assertRaises(SpecResolutionError) as unsupported:
            GitHubRevisionSource.raw_url(generic.head.locator)
        self.assertEqual(unsupported.exception.code, "invalid-repository")
        unsafe = ContentLocator(
            scheme="rapp-legacy-repository-v1",
            attributes={
                "repository": REPOSITORY,
                "commit": COMMIT,
                "path": "../SPEC.md",
            },
        )
        with self.assertRaises(SpecResolutionError) as traversal:
            GitHubRevisionSource.raw_url(unsafe)
        self.assertEqual(traversal.exception.code, "unsafe-path")


class SelectedAuthorityCompatibilityTests(unittest.TestCase):
    def test_rev14_selected_and_rev13_historical_resolution_offline(self) -> None:
        manifest, chain_bytes, spec_bytes, rev13_bytes, bootstrap = (
            selected_fixture()
        )
        registry, trust = selected_policies(manifest, bootstrap)
        historical_source = MappingRevisionSource(rev13_bytes)
        with mock.patch(
            "urllib.request.OpenerDirector.open",
            side_effect=AssertionError("network access is forbidden"),
        ), mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("network access is forbidden"),
        ):
            chain = SpecChain.from_jsonl(
                chain_bytes,
                registry=registry,
                trust_policy=trust,
            )
            selected = SpecResolver(chain).read(chain.head)
            rev13 = chain.resolve(revision="rev-13")
            historical = SpecResolver(
                chain,
                source=historical_source,
            ).read(rev13)

        self.assertTrue(chain.trusted)
        self.assertEqual(len(chain), 15)
        self.assertEqual([item.seq for item in chain], list(range(15)))
        self.assertEqual(
            hashlib.sha256(chain_bytes).hexdigest(),
            manifest["chain"]["sha256"],
        )
        actual = [
            {
                "seq": item.seq,
                "revision": item.revision,
                "frame_hash": item.frame_hash,
                "payload_hash": item.payload_hash,
                "normative_sha256": item.normative_sha256,
                "normative_bytes": item.normative_bytes,
            }
            for item in chain
        ]
        self.assertEqual(actual, manifest["frames"])
        self.assertEqual(manifest["authority_merge_commit"], SELECTED_AUTHORITY_COMMIT)
        self.assertEqual(chain.head.revision, "rev-14")
        self.assertEqual(chain.head.seq, 14)
        self.assertEqual(chain.head.frame_hash, SELECTED_FRAME_HASH)
        self.assertEqual(chain.head.payload_hash, SELECTED_PAYLOAD_HASH)
        self.assertEqual(chain.head.normative_bytes, 78183)
        self.assertEqual(chain.head.normative_sha256, SELECTED_SPEC_SHA256)
        self.assertEqual(selected, spec_bytes)
        self.assertEqual(
            hashlib.sha256(selected).hexdigest(),
            SELECTED_SPEC_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(bootstrap).hexdigest(),
            SELECTED_BOOTSTRAP_SHA256,
        )
        bootstrap_profile = json.loads(bootstrap)
        self.assertEqual(
            bootstrap_profile["schema"],
            "rapp-anchor-bootstrap/1",
        )
        self.assertEqual(
            bootstrap_profile["authority"]["protected_ref"],
            "refs/heads/main",
        )
        self.assertEqual(
            registry.registry_id,
            registry.checkpoint.evidence_id,
        )
        self.assertEqual(trust.prior_head.seq, 14)
        self.assertEqual(trust.prior_head.frame_hash, SELECTED_FRAME_HASH)
        self.assertEqual(trust.number_profile, "exact-integer")
        self.assertEqual(rev13.seq, 13)
        self.assertEqual(rev13.normative_bytes, 65569)
        self.assertEqual(rev13.normative_sha256, HISTORICAL_REV13_SHA256)
        self.assertEqual(historical, rev13_bytes)
        self.assertEqual(
            historical_source.calls[0][0].attributes["commit"],
            "5e30f66396f4cd125bce5718b1fef92d8d3ddab8",
        )
        self.assertEqual(
            historical_source.calls[0][0].attributes["path"],
            "SPEC.md",
        )
        self.assertEqual(historical_source.calls[0][1], 65569)

    def test_selected_policy_refuses_rev13_stale_prefix(self) -> None:
        manifest, chain_bytes, _, _, bootstrap = selected_fixture()
        registry, trust = selected_policies(manifest, bootstrap)
        stale_prefix = b"\n".join(chain_bytes.splitlines()[:14]) + b"\n"
        with self.assertRaises(SpecChainError) as stale:
            SpecChain.from_jsonl(
                stale_prefix,
                registry=registry,
                trust_policy=trust,
            )
        self.assertEqual(
            stale.exception.code,
            "authority-snapshot-mismatch",
        )

    def test_checkpoint_rejects_mutated_history_with_same_rev14_head(self) -> None:
        manifest, chain_bytes, _, _, bootstrap = selected_fixture()
        registry, trust = selected_policies(manifest, bootstrap)
        frames = [
            strict_json_loads(line)
            for line in chain_bytes.splitlines()
        ]
        frames[12]["payload"]["checkpoint_attack"] = True
        rehash(frames[12])
        frames[13]["prev"] = frames[12]["payload_hash"]
        rehash(frames[13])
        self.assertEqual(frames[14]["frame_hash"], SELECTED_FRAME_HASH)
        with self.assertRaises(SpecChainError) as mismatch:
            SpecChain.from_frames(
                frames,
                registry=registry,
                trust_policy=trust,
            )
        self.assertEqual(
            mismatch.exception.code,
            "authority-snapshot-mismatch",
        )


if __name__ == "__main__":
    unittest.main()
