"""Install wheel and sdist artifacts in isolated venvs and verify resources."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "src" / "rapp_sdk" / "schemas" / (
    "rapp-spec-revision-v1.schema.json"
)
WORK = ROOT / ".distribution-smoke"

PROBE = r"""
import hashlib
import importlib.metadata
import io
import json
import runpy
import sys
import urllib.request
from contextlib import redirect_stdout
from importlib.resources import files
from pathlib import Path

import rapp_sdk
from rapp_sdk import (
    KindFamilyRegistry,
    SPEC_REVISION_SCHEMA_ID,
    SpecChain,
    SpecResolutionError,
    SpecResolver,
    StreamTrustPolicy,
    VerifiedFrame,
    build_frame_mapping,
    build_spec_revision_frame,
    check_frame,
    read_spec_revision_schema,
)

source = Path(sys.argv[1]).read_bytes()
resource = files("rapp_sdk").joinpath(
    "schemas/rapp-spec-revision-v1.schema.json"
)
assert resource.is_file(), resource
installed = resource.read_bytes()
assert installed == source
assert read_spec_revision_schema() == source
assert hashlib.sha256(installed).hexdigest() == sys.argv[2]
assert json.loads(installed)["$id"] == SPEC_REVISION_SCHEMA_ID
assert SPEC_REVISION_SCHEMA_ID == "urn:rapp:schema:spec-revision:1"
assert importlib.metadata.version("rapp-sdk") == rapp_sdk.__version__
example = Path(sys.prefix) / "share" / "rapp-sdk" / "examples" / (
    "spec_chain_smoke.py"
)
assert example.is_file(), example
assert example.read_bytes() == Path(sys.argv[3]).read_bytes()
output = io.StringIO()
with redirect_stdout(output):
    runpy.run_path(str(example), run_name="__main__")
assert "rev-2 seq=1" in output.getvalue()

stream_id = "rappid:@example/distribution:" + "0" * 64
inline = build_spec_revision_frame(
    revision="rev-smoke",
    text="installed",
    utc="2026-08-30T00:00:00.000Z",
    stream_id=stream_id,
)
registry = KindFamilyRegistry(
    {"body.pulse": "body"},
    genesis_hashes={stream_id: inline["frame_hash"]},
    verified=True,
)
trust = StreamTrustPolicy(
    stream_id=stream_id,
    trusted_genesis_hash=inline["frame_hash"],
)
report = check_frame(inline, registry=registry)
assert report.ok
verified = report.require()
assert isinstance(verified, VerifiedFrame)
try:
    verified.payload["mutation"] = True
except TypeError:
    pass
else:
    raise AssertionError("verified payload is mutable")
chain = SpecChain.from_frames(
    [inline],
    registry=registry,
    trust_policy=trust,
)
assert SpecResolver(chain).read(chain.head) == b"installed"

pointer_bytes = b"pointer"
pointer = build_frame_mapping(
    "body.pulse",
    stream_id,
    0,
    "2026-08-30T00:00:00.000Z",
    {
        "revision": "rev-pointer",
        "canonical_repo": "https://github.com/example/specification",
        "commit": "a" * 40,
        "normative_path": "SPEC.md",
        "normative_sha256": hashlib.sha256(pointer_bytes).hexdigest(),
        "normative_bytes": len(pointer_bytes),
    },
    None,
)
pointer_registry = KindFamilyRegistry(
    {"body.pulse": "body"},
    genesis_hashes={stream_id: pointer["frame_hash"]},
    verified=True,
)
pointer_trust = StreamTrustPolicy(
    stream_id=stream_id,
    trusted_genesis_hash=pointer["frame_hash"],
)
pointer_chain = SpecChain.from_frames(
    [pointer],
    registry=pointer_registry,
    trust_policy=pointer_trust,
)
def forbidden_open(*args, **kwargs):
    raise AssertionError("network must not open")

urllib.request.OpenerDirector.open = forbidden_open
try:
    SpecResolver(pointer_chain).read(pointer_chain.head)
except SpecResolutionError as error:
    assert error.code == "source-required"
else:
    raise AssertionError("resolver opened or accepted an implicit source")
"""


def _python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _run(command: list[str], *, environment: dict[str, str]) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed: {command!r}\n{result.stdout}\n{result.stderr}"
        )


def _kind(path: Path) -> str:
    if path.name.endswith(".whl"):
        return "wheel"
    if path.name.endswith(".tar.gz"):
        return "sdist"
    raise ValueError(f"unsupported distribution artifact: {path}")


def main(arguments: list[str] | None = None) -> int:
    paths = [Path(value).resolve() for value in (arguments or sys.argv[1:])]
    by_kind = {_kind(path): path for path in paths}
    if set(by_kind) != {"wheel", "sdist"}:
        print("provide exactly one wheel and one .tar.gz sdist", file=sys.stderr)
        return 2

    source_hash = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
    shutil.rmtree(WORK, ignore_errors=True)
    try:
        temporary = WORK / "tmp"
        temporary.mkdir(parents=True)
        environment = os.environ.copy()
        environment.update(
            {
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INDEX": "1",
                "TEMP": str(temporary),
                "TMP": str(temporary),
                "TMPDIR": str(temporary),
            }
        )
        for kind in ("wheel", "sdist"):
            isolated = WORK / kind
            venv.EnvBuilder(with_pip=True, clear=True).create(isolated)
            python = _python(isolated)
            _run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-build-isolation",
                    "--no-deps",
                    "--no-compile",
                    str(by_kind[kind]),
                ],
                environment=environment,
            )
            _run(
                [
                    str(python),
                    "-I",
                    "-B",
                    "-c",
                    PROBE,
                    str(SCHEMA),
                    source_hash,
                    str(ROOT / "examples" / "spec_chain_smoke.py"),
                ],
                environment=environment,
            )
            print(f"{kind}: installed API, example, and resources verified")
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
