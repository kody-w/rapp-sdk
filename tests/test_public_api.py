from __future__ import annotations

import dataclasses
import inspect
import io
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
from rapp_sdk import (
    CacheIntegrityError,
    ContentAddressedCache,
    HTTPSFetcher,
    ProtocolError,
    RappSDKError,
    RevisionAddress,
    SpecChain,
    SpecChainError,
    SpecResolutionError,
    SpecRevision,
    build_frame,
    build_spec_revision_frame,
    canonicalize,
    strict_json_loads,
    verify_frame,
    verify_stream,
)

ROOT = Path(__file__).resolve().parents[1]
STREAM_ID = "rappid:@example/public-api:" + "0" * 64


def inline_chain() -> SpecChain:
    first = build_spec_revision_frame(
        revision="rev-1",
        text="one",
        utc="2026-08-30T00:00:00.000Z",
        stream_id=STREAM_ID,
    )
    second = build_spec_revision_frame(
        revision="rev-2",
        text="two",
        utc="2026-08-30T00:00:01.000Z",
        head=first,
    )
    return SpecChain.from_frames([first, second])


class PublicAPITests(unittest.TestCase):
    def test_export_surface_and_version_are_stable(self) -> None:
        self.assertIsInstance(rapp_sdk.__all__, tuple)
        self.assertEqual(len(rapp_sdk.__all__), len(set(rapp_sdk.__all__)))
        for name in rapp_sdk.__all__:
            self.assertTrue(hasattr(rapp_sdk, name), name)
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(rapp_sdk.__version__, metadata["project"]["version"])
        self.assertEqual(rapp_sdk.VERSION, rapp_sdk.__version_info__)
        self.assertEqual(rapp_sdk.__version_info__, (0, 1, 0))
        self.assertTrue(files("rapp_sdk").joinpath("py.typed").is_file())
        self.assertTrue(issubclass(ProtocolError, RappSDKError))
        self.assertTrue(issubclass(SpecChainError, RappSDKError))
        self.assertFalse(issubclass(SpecChainError, ProtocolError))
        self.assertTrue(issubclass(SpecResolutionError, SpecChainError))
        self.assertTrue(issubclass(CacheIntegrityError, SpecResolutionError))

    def test_public_callables_have_parameter_and_return_annotations(self) -> None:
        callables = (
            canonicalize,
            strict_json_loads,
            build_frame,
            verify_frame,
            verify_stream,
            build_spec_revision_frame,
            SpecChain.from_frames,
            SpecChain.from_jsonl,
            SpecChain.from_jsonl_text,
            SpecChain.load,
            SpecChain.resolve,
            SpecChain.materialize,
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

    def test_error_diagnostics_are_actionable_and_immutable(self) -> None:
        frame = build_spec_revision_frame(
            revision="rev-1",
            text="trusted",
            utc="2026-08-30T00:00:00.000Z",
            stream_id=STREAM_ID,
        )
        frame["payload"]["normative"]["text"] = "mutated"
        with self.assertRaises(ProtocolError) as raised:
            verify_frame(frame)
        error = raised.exception
        self.assertIsInstance(error, RappSDKError)
        self.assertEqual(error.code, "payload-hash-mismatch")
        self.assertEqual(error.step, "2")
        self.assertIsInstance(error.context, MappingProxyType)
        self.assertIn("expected_payload_hash", error.context)
        self.assertEqual(error.as_dict()["code"], error.code)
        equivalent = ProtocolError(
            error.code,
            error.message,
            step=error.step,
            context=dict(reversed(error.context.items())),
        )
        self.assertEqual(repr(error), repr(equivalent))
        with self.assertRaises(TypeError):
            error.context["new"] = "value"

    def test_revision_values_and_serialization_are_immutable(self) -> None:
        chain = inline_chain()
        revision = chain.head
        with self.assertRaises(AttributeError):
            chain.stream_id = "other"
        self.assertIsInstance(revision, SpecRevision)
        self.assertIsInstance(revision.address, RevisionAddress)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            revision.seq = 99
        with self.assertRaises(dataclasses.FrozenInstanceError):
            revision.address.seq = 99

        mutable_frame = revision.to_dict()
        mutable_frame["seq"] = 99
        self.assertEqual(revision.to_dict()["seq"], 1)
        self.assertEqual(revision.frame_bytes, revision.to_json_bytes())
        self.assertEqual(
            revision.address.to_json_bytes(),
            canonicalize(revision.address.as_dict()),
        )
        encoded = chain.to_jsonl_bytes()
        reloaded = SpecChain.from_jsonl(encoded)
        self.assertEqual(reloaded.to_jsonl_bytes(), encoded)
        self.assertEqual(repr(chain), repr(reloaded))

    def test_bytes_text_and_path_boundaries_are_explicit(self) -> None:
        encoded = inline_chain().to_jsonl_bytes()
        self.assertEqual(
            SpecChain.from_jsonl_text(encoded.decode("utf-8")).head.revision,
            "rev-2",
        )
        self.assertEqual(
            SpecChain.from_jsonl(encoded.replace(b"\n", b"\r\n")).head.revision,
            "rev-2",
        )
        with self.assertRaisesRegex(RappSDKError, "carriage return"):
            SpecChain.from_jsonl(encoded.replace(b"\n", b"\r"))
        with self.assertRaises(TypeError):
            SpecChain.from_jsonl(encoded.decode("utf-8"))
        with self.assertRaises(TypeError):
            SpecChain.from_jsonl_text(encoded)
        with self.assertRaises(TypeError):
            SpecChain.load(b"chain.jsonl")
        with self.assertRaises(TypeError):
            ContentAddressedCache(b"cache")

    def test_network_and_cache_configuration_is_read_only(self) -> None:
        fetcher = HTTPSFetcher()
        self.assertEqual(
            fetcher.allowed_hosts,
            frozenset({"raw.githubusercontent.com"}),
        )
        with self.assertRaises(AttributeError):
            fetcher.timeout = 1.0
        cache = ContentAddressedCache("cache")
        with self.assertRaises(AttributeError):
            cache.root = Path("elsewhere")

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
