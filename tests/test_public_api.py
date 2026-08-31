from __future__ import annotations

import dataclasses
import hashlib
import inspect
import io
import json
import shutil
import subprocess
import sys
import tomllib
import unittest
from contextlib import redirect_stdout
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import get_type_hints

import rapp_sdk
from rapp_sdk.diagnostic_codes import (
    DIAGNOSTIC_CATALOG_VERSION,
    DIAGNOSTIC_CODES,
)
from rapp_sdk import (
    AuthorityCheckpoint,
    CacheIntegrityError,
    ContentLocator,
    Diagnostic,
    KindFamilyRegistry,
    PersistedHead,
    ProtocolError,
    RappSDKError,
    RING_YARD_MANIFEST_SCHEMA_ID,
    RevisionAddress,
    RingManifestError,
    RingYardManifest,
    SPEC_REVISION_SCHEMA_ID,
    SpecChain,
    SpecChainError,
    SpecResolver,
    SpecResolutionError,
    SpecRevision,
    StreamTrustPolicy,
    VerificationReport,
    VerifiedFrame,
    VerifiedStream,
    build_frame_mapping,
    build_default_ring_yard_manifest,
    build_spec_revision_frame,
    canonicalize,
    check_frame,
    check_ring_yard_manifest,
    check_ring_yard_manifest_semantics,
    check_stream,
    ports_for_cell,
    read_ring_yard_manifest_schema,
    read_spec_revision_schema,
    selected_authority_checkpoint,
    selected_authority_registry,
    selected_authority_trust_policy,
    strict_json_loads,
    verify_frame,
    verify_ring_yard_manifest,
    verify_stream,
)

ROOT = Path(__file__).resolve().parents[1]
RID = "rappid:@example/public-api:" + "0" * 64
ROOT_EXPORTS = (
    "AuthorityCheckpoint",
    "CacheIntegrityError",
    "ContentLocator",
    "Diagnostic",
    "DiagnosticStatus",
    "KindFamilyRegistry",
    "PROTOCOL_VERSION",
    "PROJECT_EGG_SCHEMA",
    "PROJECT_EGG_VARIANT",
    "PROJECT_EVENTS",
    "PROJECT_FRAME_KIND",
    "PROJECT_FRAME_KINDS",
    "PersistedHead",
    "ProtocolError",
    "ProjectActor",
    "ProjectCheckpoint",
    "ProjectProtocolError",
    "RappSDKError",
    "RING_YARD_MANIFEST_SCHEMA_ID",
    "RevisionAddress",
    "RevisionSource",
    "RingManifestError",
    "RingYardManifest",
    "SPEC_REVISION_SCHEMA_ID",
    "SpecChain",
    "SpecChainError",
    "SpecResolver",
    "SpecResolutionError",
    "SpecRevision",
    "StreamTrustPolicy",
    "VERSION",
    "VerificationReport",
    "VerifiedFrame",
    "VerifiedStream",
    "__version__",
    "__version_info__",
    "build_frame_mapping",
    "build_default_ring_yard_manifest",
    "build_project_egg_manifest",
    "build_project_frame",
    "build_project_rappid",
    "pack_project_egg",
    "project_egg_address",
    "build_spec_revision_frame",
    "canonicalize",
    "check_frame",
    "check_ring_yard_manifest",
    "check_ring_yard_manifest_semantics",
    "check_stream",
    "ports_for_cell",
    "read_ring_yard_manifest_schema",
    "read_spec_revision_schema",
    "project_kind_registry",
    "read_project_egg",
    "selected_authority_checkpoint",
    "selected_authority_registry",
    "selected_authority_trust_policy",
    "strict_json_loads",
    "verify_frame",
    "verify_ring_yard_manifest",
    "validate_project_payload",
    "verify_project_egg_manifest",
    "verify_project_stream",
    "verify_stream",
)


def inline_chain() -> tuple[SpecChain, KindFamilyRegistry, StreamTrustPolicy]:
    first = build_spec_revision_frame(
        revision="rev-1",
        text="one",
        utc="2026-08-30T00:00:00.000Z",
        stream_id=RID,
    )
    first_checkpoint = AuthorityCheckpoint.from_authenticated(
        checkpoint_document(first),
        authenticator=lambda evidence: True,
    )
    registry = KindFamilyRegistry.from_checkpoint(first_checkpoint)
    trust = StreamTrustPolicy.from_checkpoint(first_checkpoint)
    first_chain = SpecChain.from_frames(
        [first],
        registry=registry,
        trust_policy=trust,
    )
    second = build_spec_revision_frame(
        revision="rev-2",
        text="two",
        utc="2026-08-30T00:00:01.000Z",
        head=first_chain.head.frame,
    )
    checkpoint = AuthorityCheckpoint.from_authenticated(
        checkpoint_document(first, second),
        authenticator=lambda evidence: True,
    )
    registry = KindFamilyRegistry.from_checkpoint(checkpoint)
    trust = StreamTrustPolicy.from_checkpoint(checkpoint)
    return (
        SpecChain.from_frames(
            [first, second],
            registry=registry,
            trust_policy=trust,
        ),
        registry,
        trust,
    )


def checkpoint_document(*frames: dict) -> dict:
    selected = frames[-1]
    return {
        "canonical_repository": "https://example.test/authority",
        "protected_ref": "refs/heads/main",
        "accepted_commit": "a" * 40,
        "bootstrap_profile_sha256": "b" * 64,
        "chain_sha256": hashlib.sha256(
            b"".join(canonicalize(frame) + b"\n" for frame in frames)
        ).hexdigest(),
        "stream_id": RID,
        "genesis_frame_hash": frames[0]["frame_hash"],
        "selected_head": {
            "seq": selected["seq"],
            "frame_hash": selected["frame_hash"],
            "payload_hash": selected["payload_hash"],
        },
        "frame_hashes": [frame["frame_hash"] for frame in frames],
        "kind_families": {"body.pulse": "body"},
        "number_profile": "rfc8785-binary64",
    }


class PublicAPITests(unittest.TestCase):
    def test_root_exports_and_versions_are_literal_snapshots(self) -> None:
        self.assertEqual(rapp_sdk.__all__, ROOT_EXPORTS)
        self.assertEqual(len(ROOT_EXPORTS), len(set(ROOT_EXPORTS)))
        for name in ROOT_EXPORTS:
            self.assertTrue(hasattr(rapp_sdk, name), name)
        for advanced in (
            "FRAME_KEYS",
            "H",
            "Hb",
            "HTTPSFetcher",
            "ContentAddressedCache",
            "MAX_CHAIN_BYTES",
            "PARTICLE_SPACE",
        ):
            self.assertNotIn(advanced, rapp_sdk.__all__)

        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(rapp_sdk.__version__, metadata["project"]["version"])
        self.assertEqual(rapp_sdk.VERSION, rapp_sdk.__version_info__)
        self.assertEqual(rapp_sdk.__version_info__, (0, 2, 0))
        self.assertEqual(rapp_sdk.PROTOCOL_VERSION, "rapp/1")
        self.assertTrue(files("rapp_sdk").joinpath("py.typed").is_file())

    def test_diagnostic_code_catalog_is_stable(self) -> None:
        self.assertEqual(DIAGNOSTIC_CATALOG_VERSION, "2")
        self.assertEqual(len(DIAGNOSTIC_CODES), 139)
        self.assertEqual(DIAGNOSTIC_CODES, tuple(sorted(DIAGNOSTIC_CODES)))
        self.assertEqual(
            hashlib.sha256(
                ("\n".join(DIAGNOSTIC_CODES) + "\n").encode()
            ).hexdigest(),
            "3c896a2723b822a6b595c359ca02bbfff35869add07fe93add80152f9add55ee",
        )

    def test_golden_callables_are_fully_annotated(self) -> None:
        callables = (
            AuthorityCheckpoint.from_authenticated,
            KindFamilyRegistry.local,
            KindFamilyRegistry.from_checkpoint,
            canonicalize,
            strict_json_loads,
            build_frame_mapping,
            ports_for_cell,
            build_default_ring_yard_manifest,
            check_ring_yard_manifest,
            check_ring_yard_manifest_semantics,
            verify_ring_yard_manifest,
            check_frame,
            verify_frame,
            check_stream,
            verify_stream,
            build_spec_revision_frame,
            read_spec_revision_schema,
            read_ring_yard_manifest_schema,
            selected_authority_checkpoint,
            selected_authority_registry,
            selected_authority_trust_policy,
            SpecChain.from_frames,
            SpecChain.from_frames_local,
            SpecChain.from_jsonl,
            SpecChain.from_jsonl_local,
            SpecChain.resolve,
            SpecResolver.read,
            RingYardManifest.from_json_bytes,
            RingYardManifest.to_json_bytes,
        )
        for function in callables:
            with self.subTest(function=function.__qualname__):
                signature = inspect.signature(function)
                self.assertIsNot(
                    signature.return_annotation,
                    inspect.Signature.empty,
                )
                for parameter in signature.parameters.values():
                    if parameter.name in {"self", "cls"}:
                        continue
                    self.assertIsNot(
                        parameter.annotation,
                        inspect.Signature.empty,
                        parameter.name,
                    )
                self.assertTrue(get_type_hints(function))

    def test_golden_signatures_and_defaults_are_stable(self) -> None:
        snapshots = {
            AuthorityCheckpoint.from_authenticated: (
                "(document: 'Mapping[str, JsonValue]', *, "
                "authenticator: 'Callable[[bytes], bool]') -> "
                "'AuthorityCheckpoint'"
            ),
            KindFamilyRegistry.local: (
                "(kind_families: 'Mapping[str, str]', "
                "*, genesis_hashes: 'Mapping[str, str] | None' = None, "
                "registry_id: 'str | None' = None) -> "
                "'KindFamilyRegistry'"
            ),
            KindFamilyRegistry.from_checkpoint: (
                "(checkpoint: 'AuthorityCheckpoint') -> "
                "'KindFamilyRegistry'"
            ),
            StreamTrustPolicy: (
                "(stream_id: 'str', trusted_genesis_hash: 'str', "
                "prior_head: 'PersistedHead | None' = None, "
                "approved_re_genesis_hashes: 'frozenset[str]' = "
                "frozenset(), number_profile: 'str' = "
                "'rfc8785-binary64', checkpoint: "
                "'AuthorityCheckpoint | None' = None) -> None"
            ),
            build_frame_mapping: (
                "(kind: 'str', stream_id: 'str', seq: 'int', utc: 'str', "
                "payload: 'Mapping[str, JsonValue]', prev: 'str | None', *, "
                "prev_wave: 'str | None' = None, sig: 'str | None' = None) "
                "-> 'Frame'"
            ),
            ports_for_cell: (
                "(*, track_slot: 'int', ring_slot: 'int') -> 'CellPorts'"
            ),
            build_default_ring_yard_manifest: (
                "(*, yard_identity: 'str', yard_root: 'str', "
                "artifact_digest: 'str', argv: 'Sequence[str]', "
                "rappids: 'Mapping[CellKey, str] | None' = None, "
                "mint_rappid: 'MintRappid | None' = None, "
                "scheduler: 'SchedulerPolicy | None' = None, "
                "budgets: 'ResourceBudgets | None' = None) -> "
                "'RingYardManifest'"
            ),
            check_ring_yard_manifest: (
                "(data: 'bytes | bytearray | memoryview', *, "
                "max_bytes: 'int' = 524288) -> "
                "'VerificationReport[RingYardManifest]'"
            ),
            check_ring_yard_manifest_semantics: (
                "(document: 'Mapping[str, JsonValue]', *, "
                "max_bytes: 'int' = 524288) -> "
                "'VerificationReport[RingYardManifest]'"
            ),
            verify_ring_yard_manifest: (
                "(data: 'bytes | bytearray | memoryview', *, "
                "max_bytes: 'int' = 524288) -> 'RingYardManifest'"
            ),
            check_frame: (
                "(frame: 'FrameMapping', *, registry: 'KindFamilyRegistry', "
                "head: 'VerifiedFrame | None' = None, "
                "expected_stream_id: 'str | None' = None, "
                "signature_verifier: 'SignatureVerifier | None' = None) -> "
                "'VerificationReport[VerifiedFrame]'"
            ),
            check_stream: (
                "(frames: 'Iterable[FrameMapping]', *, "
                "registry: 'KindFamilyRegistry', "
                "trust_policy: 'StreamTrustPolicy', "
                "expected_stream_id: 'str | None' = None, "
                "signature_verifier: 'SignatureVerifier | None' = None, "
                "max_frames: 'int' = 100000, max_seconds: 'float' = 5.0) -> "
                "'VerificationReport[VerifiedStream]'"
            ),
            SpecChain.from_frames: (
                "(frames: 'Iterable[FrameMapping]', *, "
                "registry: 'KindFamilyRegistry', "
                "trust_policy: 'StreamTrustPolicy', "
                "expected_stream_id: 'str | None' = None, "
                "max_frames: 'int' = 100000, max_seconds: 'float' = 5.0) -> "
                "'SpecChain'"
            ),
            SpecChain.resolve: (
                "(self, *, revision: 'str | None' = None, "
                "seq: 'int | None' = None, "
                "frame_hash: 'str | None' = None, "
                "payload_hash: 'str | None' = None) -> 'SpecRevision'"
            ),
            SpecResolver: (
                "(chain: 'SpecChain', *, source: 'RevisionSource | None' = "
                "None, cache: 'ContentAddressedCache | None' = None) -> 'None'"
            ),
            SpecResolver.read: "(self, revision: 'SpecRevision') -> 'bytes'",
            RingYardManifest.from_json_bytes: (
                "(data: 'bytes | bytearray | memoryview', *, "
                "max_bytes: 'int' = 524288) -> 'RingYardManifest'"
            ),
            RingYardManifest.to_json_bytes: (
                "(self, *, max_bytes: 'int' = 524288) -> 'bytes'"
            ),
        }
        for function, expected in snapshots.items():
            with self.subTest(function=function.__qualname__):
                self.assertEqual(str(inspect.signature(function)), expected)

    def test_immutable_model_fields_are_stable(self) -> None:
        snapshots = {
            Diagnostic: (
                "code",
                "operation",
                "message",
                "status",
                "protocol_step",
                "location",
                "context",
                "remediation",
            ),
            AuthorityCheckpoint: (
                "canonical_repository",
                "protected_ref",
                "accepted_commit",
                "bootstrap_profile_sha256",
                "chain_sha256",
                "stream_id",
                "genesis_frame_hash",
                "selected_head",
                "selected_payload_hash",
                "frame_hashes",
                "kind_families",
                "number_profile",
                "evidence_id",
            ),
            KindFamilyRegistry: (
                "kind_families",
                "genesis_hashes",
                "registry_id",
                "checkpoint",
            ),
            PersistedHead: ("seq", "frame_hash"),
            StreamTrustPolicy: (
                "stream_id",
                "trusted_genesis_hash",
                "prior_head",
                "approved_re_genesis_hashes",
                "number_profile",
                "checkpoint",
            ),
            VerifiedFrame: (
                "spec",
                "kind",
                "stream_id",
                "family",
                "seq",
                "utc",
                "payload",
                "payload_hash",
                "frame_hash",
                "prev",
                "prev_wave",
                "sig",
                "_number_origins",
                "_canonical_bytes",
            ),
            VerifiedStream: (
                "frames",
                "trusted",
                "trust_label",
                "genesis_hash",
            ),
            RevisionAddress: (
                "revision",
                "seq",
                "frame_hash",
                "payload_hash",
            ),
            ContentLocator: ("scheme", "attributes"),
            SpecRevision: (
                "address",
                "stream_id",
                "normative_sha256",
                "normative_bytes",
                "media_type",
                "locator",
                "is_inline",
                "frame",
            ),
            RingYardManifest: (
                "spec",
                "yard",
                "control_plane",
                "cells",
            ),
        }
        for model, expected in snapshots.items():
            with self.subTest(model=model.__name__):
                self.assertEqual(
                    tuple(field.name for field in dataclasses.fields(model)),
                    expected,
                )
                self.assertTrue(model.__dataclass_params__.frozen)
                self.assertTrue(hasattr(model, "__slots__"))

    def test_schema_is_canonical_package_resource(self) -> None:
        resource = files("rapp_sdk").joinpath(
            "schemas/rapp-spec-revision-v1.schema.json"
        )
        self.assertTrue(resource.is_file())
        source_bytes = resource.read_bytes()
        self.assertEqual(read_spec_revision_schema(), source_bytes)
        self.assertEqual(
            hashlib.sha256(source_bytes).hexdigest(),
            "d102762ba503da1825806c8298d19afc80fa8603c57846e5a64d9a74e85b7081",
        )
        self.assertEqual(
            json.loads(source_bytes)["$id"],
            SPEC_REVISION_SCHEMA_ID,
        )
        ring_resource = files("rapp_sdk").joinpath(
            "schemas/rapp-ring-yard-v1.schema.json"
        )
        self.assertTrue(ring_resource.is_file())
        ring_bytes = ring_resource.read_bytes()
        self.assertEqual(read_ring_yard_manifest_schema(), ring_bytes)
        self.assertEqual(
            hashlib.sha256(ring_bytes).hexdigest(),
            "c8e59626c05ee4a0733729d4ec0334ca65cfab875325af1fea2040c600829cf2",
        )
        self.assertEqual(
            json.loads(ring_bytes)["$id"],
            RING_YARD_MANIFEST_SCHEMA_ID,
        )
        self.assertEqual(
            json.loads(ring_bytes)["x-rapp-semantic-validator"],
            {
                "required": True,
                "api": "rapp_sdk.check_ring_yard_manifest_semantics",
                "bytes_api": "rapp_sdk.check_ring_yard_manifest",
            },
        )

    def test_selected_authority_is_checkpoint_derived(self) -> None:
        resource = files("rapp_sdk").joinpath(
            "authority/selected-rev14.json"
        )
        self.assertTrue(resource.is_file())
        checkpoint = selected_authority_checkpoint()
        registry = selected_authority_registry()
        trust = selected_authority_trust_policy()
        self.assertEqual(
            checkpoint.accepted_commit,
            "caf6ef276cafa92aa744499af90dc1a28559941a",
        )
        self.assertEqual(
            checkpoint.canonical_repository,
            "https://github.com/kody-w/rapp-1",
        )
        self.assertEqual(checkpoint.protected_ref, "refs/heads/main")
        self.assertEqual(
            checkpoint.bootstrap_profile_sha256,
            "1666e44acf532f854d4bf74868c9af9f9b362055692189ac858a7c8b52dcd5bb",
        )
        self.assertIs(registry.checkpoint, checkpoint)
        self.assertIs(trust.checkpoint, checkpoint)
        self.assertTrue(registry.verified)
        self.assertEqual(len(checkpoint.frame_hashes), 15)
        with self.assertRaises(TypeError):
            KindFamilyRegistry(
                {"body.pulse": "body"},
                verified=True,
            )
        self.assertFalse(
            KindFamilyRegistry.local({"body.pulse": "body"}).verified
        )

    def test_checkpoint_authenticates_exact_snapshot_and_integer_origin(self) -> None:
        frame = build_spec_revision_frame(
            revision="rev-checkpoint",
            text="checkpoint",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=RID,
        )
        document = checkpoint_document(frame)

        def mutate_after_authentication(evidence: bytes) -> bool:
            document["selected_head"]["seq"] = 99
            document["kind_families"]["body.pulse"] = "swarm"
            return True

        checkpoint = AuthorityCheckpoint.from_authenticated(
            document,
            authenticator=mutate_after_authentication,
        )
        self.assertEqual(checkpoint.selected_head.seq, 0)
        self.assertEqual(checkpoint.kind_families["body.pulse"], "body")

        for invalid in (0.5, "0", False):
            with self.subTest(invalid=invalid):
                bad = checkpoint_document(frame)
                bad["selected_head"]["seq"] = invalid
                with self.assertRaisesRegex(ValueError, "exact JSON uint53"):
                    AuthorityCheckpoint.from_authenticated(
                        bad,
                        authenticator=lambda evidence: True,
                    )

        exponent = canonicalize(checkpoint_document(frame)).replace(
            b'"seq":0',
            b'"seq":0e0',
            1,
        )
        exponent_document = strict_json_loads(exponent)
        with self.assertRaisesRegex(ValueError, "exact JSON uint53"):
            AuthorityCheckpoint.from_authenticated(
                exponent_document,
                authenticator=lambda evidence: True,
            )

    def test_report_diagnostic_and_exception_are_one_model(self) -> None:
        first = build_spec_revision_frame(
            revision="rev-1",
            text="trusted",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=RID,
        )
        registry = KindFamilyRegistry.from_checkpoint(
            AuthorityCheckpoint.from_authenticated(
                checkpoint_document(first),
                authenticator=lambda evidence: True,
            )
        )
        first["payload"]["normative"]["text"] = "mutated"
        report = check_frame(first, registry=registry)
        self.assertIsInstance(report, VerificationReport)
        self.assertFalse(report.ok)
        diagnostic = report.diagnostics[-1]
        self.assertIsInstance(diagnostic, Diagnostic)
        self.assertIsInstance(diagnostic.context, MappingProxyType)
        self.assertEqual(diagnostic.protocol_step, "2")
        with self.assertRaises(ProtocolError) as raised:
            report.require(ProtocolError)
        self.assertIs(raised.exception.diagnostic, diagnostic)
        self.assertEqual(raised.exception.as_dict(), diagnostic.as_dict())
        with self.assertRaises(TypeError):
            diagnostic.context["new"] = "value"

    def test_chain_and_resolver_golden_path(self) -> None:
        chain, registry, trust = inline_chain()
        self.assertTrue(chain.trusted)
        self.assertEqual(chain.resolve(revision="rev-2"), chain.head)
        self.assertEqual(SpecResolver(chain).read(chain.head), b"two")
        encoded = chain.to_jsonl_bytes()
        reloaded = SpecChain.from_jsonl(
            encoded,
            registry=registry,
            trust_policy=trust,
        )
        self.assertEqual(reloaded.to_jsonl_bytes(), encoded)
        self.assertEqual(reloaded.head.address, chain.head.address)
        with self.assertRaises(TypeError):
            chain.resolve("rev-2")

    def test_error_hierarchy_remains_narrow(self) -> None:
        self.assertTrue(issubclass(ProtocolError, RappSDKError))
        self.assertTrue(issubclass(SpecChainError, RappSDKError))
        self.assertFalse(issubclass(SpecChainError, ProtocolError))
        self.assertTrue(issubclass(SpecResolutionError, SpecChainError))
        self.assertTrue(issubclass(CacheIntegrityError, SpecResolutionError))
        self.assertTrue(issubclass(RingManifestError, RappSDKError))
        self.assertFalse(issubclass(RingManifestError, ProtocolError))

    def test_import_is_quiet_and_has_no_filesystem_side_effects(self) -> None:
        scratch = ROOT / "tests" / ".scratch-import"
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir()
        self.addCleanup(shutil.rmtree, scratch, ignore_errors=True)
        command = (
            "import sys;"
            f"sys.path.insert(0,{str(ROOT / 'src')!r});"
            "import rapp_sdk"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-c", command],
            cwd=scratch,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_documented_ergonomics_example_runs_without_network(self) -> None:
        namespace = {"__name__": "__main__"}
        output = io.StringIO()
        with redirect_stdout(output):
            exec(
                compile(
                    (ROOT / "examples" / "spec_chain_smoke.py").read_bytes(),
                    "examples/spec_chain_smoke.py",
                    "exec",
                ),
                namespace,
            )
        self.assertIn("rev-2 seq=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
