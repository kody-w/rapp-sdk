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
    CacheIntegrityError,
    ContentLocator,
    Diagnostic,
    KindFamilyRegistry,
    PersistedHead,
    ProtocolError,
    RappSDKError,
    RevisionAddress,
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
    build_spec_revision_frame,
    canonicalize,
    check_frame,
    check_stream,
    read_spec_revision_schema,
    strict_json_loads,
    verify_frame,
    verify_stream,
)

ROOT = Path(__file__).resolve().parents[1]
RID = "rappid:@example/public-api:" + "0" * 64
ROOT_EXPORTS = (
    "CacheIntegrityError",
    "ContentLocator",
    "Diagnostic",
    "DiagnosticStatus",
    "KindFamilyRegistry",
    "PROTOCOL_VERSION",
    "PersistedHead",
    "ProtocolError",
    "RappSDKError",
    "RevisionAddress",
    "RevisionSource",
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
    "build_spec_revision_frame",
    "canonicalize",
    "check_frame",
    "check_stream",
    "read_spec_revision_schema",
    "strict_json_loads",
    "verify_frame",
    "verify_stream",
)


def inline_chain() -> tuple[SpecChain, KindFamilyRegistry, StreamTrustPolicy]:
    first = build_spec_revision_frame(
        revision="rev-1",
        text="one",
        utc="2026-08-30T00:00:00.000Z",
        stream_id=RID,
    )
    registry = KindFamilyRegistry(
        {"body.pulse": "body"},
        genesis_hashes={RID: first["frame_hash"]},
        verified=True,
    )
    trust = StreamTrustPolicy(
        stream_id=RID,
        trusted_genesis_hash=first["frame_hash"],
    )
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
    return (
        SpecChain.from_frames(
            [first, second],
            registry=registry,
            trust_policy=trust,
        ),
        registry,
        trust,
    )


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
        self.assertEqual(rapp_sdk.__version_info__, (0, 1, 0))
        self.assertEqual(rapp_sdk.PROTOCOL_VERSION, "rapp/1")
        self.assertTrue(files("rapp_sdk").joinpath("py.typed").is_file())

    def test_diagnostic_code_catalog_is_stable(self) -> None:
        self.assertEqual(DIAGNOSTIC_CATALOG_VERSION, "1")
        self.assertEqual(len(DIAGNOSTIC_CODES), 99)
        self.assertEqual(DIAGNOSTIC_CODES, tuple(sorted(DIAGNOSTIC_CODES)))
        self.assertEqual(
            hashlib.sha256(
                ("\n".join(DIAGNOSTIC_CODES) + "\n").encode()
            ).hexdigest(),
            "959f62aea1d40461be0dfe6e4e9f50e36c37194f5861ab929c3b6a8a507171a4",
        )

    def test_golden_callables_are_fully_annotated(self) -> None:
        callables = (
            canonicalize,
            strict_json_loads,
            build_frame_mapping,
            check_frame,
            verify_frame,
            check_stream,
            verify_stream,
            build_spec_revision_frame,
            read_spec_revision_schema,
            SpecChain.from_frames,
            SpecChain.from_frames_local,
            SpecChain.from_jsonl,
            SpecChain.from_jsonl_local,
            SpecChain.resolve,
            SpecResolver.read,
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
            KindFamilyRegistry: (
                "(kind_families: 'Mapping[str, str]', "
                "genesis_hashes: 'Mapping[str, str]' = <factory>, "
                "verified: 'bool' = False, "
                "registry_id: 'str | None' = None) -> None"
            ),
            StreamTrustPolicy: (
                "(stream_id: 'str', trusted_genesis_hash: 'str', "
                "prior_head: 'PersistedHead | None' = None, "
                "approved_re_genesis_hashes: 'frozenset[str]' = "
                "frozenset()) -> None"
            ),
            build_frame_mapping: (
                "(kind: 'str', stream_id: 'str', seq: 'int', utc: 'str', "
                "payload: 'Mapping[str, JsonValue]', prev: 'str | None', *, "
                "prev_wave: 'str | None' = None, sig: 'str | None' = None) "
                "-> 'Frame'"
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
            KindFamilyRegistry: (
                "kind_families",
                "genesis_hashes",
                "verified",
                "registry_id",
            ),
            PersistedHead: ("seq", "frame_hash"),
            StreamTrustPolicy: (
                "stream_id",
                "trusted_genesis_hash",
                "prior_head",
                "approved_re_genesis_hashes",
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
                "_inline_bytes",
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
            "939283dc97c0f0da5201b557314d6da35ac0805ec62f946877eb1a0d36080f24",
        )
        self.assertEqual(
            json.loads(source_bytes)["$id"],
            SPEC_REVISION_SCHEMA_ID,
        )

    def test_report_diagnostic_and_exception_are_one_model(self) -> None:
        first = build_spec_revision_frame(
            revision="rev-1",
            text="trusted",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=RID,
        )
        registry = KindFamilyRegistry(
            {"body.pulse": "body"},
            genesis_hashes={RID: first["frame_hash"]},
            verified=True,
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
