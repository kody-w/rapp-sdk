"""Install wheel and sdist artifacts in isolated venvs and verify resources."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import venv
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "src" / "rapp_sdk" / "schemas" / (
    "rapp-spec-revision-v1.schema.json"
)
RING_SCHEMA = ROOT / "src" / "rapp_sdk" / "schemas" / (
    "rapp-ring-yard-v1.schema.json"
)
WORK = ROOT / ".distribution-smoke"
PINNED_SETUPTOOLS_VERSION = "84.0.0"

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
    AuthorityCheckpoint,
    KindFamilyRegistry,
    RING_YARD_MANIFEST_SCHEMA_ID,
    SPEC_REVISION_SCHEMA_ID,
    SpecChain,
    SpecResolutionError,
    SpecResolver,
    StreamTrustPolicy,
    VerifiedFrame,
    build_frame_mapping,
    build_default_ring_yard_manifest,
    build_spec_revision_frame,
    canonicalize,
    check_frame,
    check_ring_yard_manifest_semantics,
    read_ring_yard_manifest_schema,
    read_spec_revision_schema,
    selected_authority_checkpoint,
    selected_authority_registry,
    selected_authority_trust_policy,
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
ring_source = Path(sys.argv[3]).read_bytes()
ring_resource = files("rapp_sdk").joinpath(
    "schemas/rapp-ring-yard-v1.schema.json"
)
assert ring_resource.is_file(), ring_resource
ring_installed = ring_resource.read_bytes()
assert ring_installed == ring_source
assert read_ring_yard_manifest_schema() == ring_source
assert hashlib.sha256(ring_installed).hexdigest() == sys.argv[4]
assert json.loads(ring_installed)["$id"] == RING_YARD_MANIFEST_SCHEMA_ID
assert json.loads(ring_installed)["x-rapp-semantic-validator"] == {
    "required": True,
    "api": "rapp_sdk.check_ring_yard_manifest_semantics",
    "bytes_api": "rapp_sdk.check_ring_yard_manifest",
}
assert RING_YARD_MANIFEST_SCHEMA_ID == (
    "urn:rapp:schema:ring-yard-manifest:1"
)
authority_resource = files("rapp_sdk").joinpath(
    "authority/selected-rev14.json"
)
assert authority_resource.is_file()
selected_checkpoint = selected_authority_checkpoint()
assert selected_checkpoint.accepted_commit == (
    "caf6ef276cafa92aa744499af90dc1a28559941a"
)
assert selected_authority_registry().checkpoint is selected_checkpoint
assert selected_authority_trust_policy().checkpoint is selected_checkpoint
distribution = importlib.metadata.distribution("rapp-sdk")
assert distribution.version == rapp_sdk.__version__
environment_root = Path(sys.argv[6]).resolve()
assert Path(rapp_sdk.__file__).resolve().is_relative_to(environment_root)
assert Path(distribution.locate_file("")).resolve().is_relative_to(
    environment_root
)
example = Path(sys.prefix) / "share" / "rapp-sdk" / "examples" / (
    "spec_chain_smoke.py"
)
assert example.is_file(), example
assert example.read_bytes() == Path(sys.argv[5]).read_bytes()
ring_doc = Path(sys.prefix) / "share" / "rapp-sdk" / "docs" / (
    "ring-yard-manifest.md"
)
assert ring_doc.is_file(), ring_doc
output = io.StringIO()
with redirect_stdout(output):
    runpy.run_path(str(example), run_name="__main__")
assert "rev-2 seq=1" in output.getvalue()

tracks = (
    "frontier-experimental",
    "frontier",
    "brainstem-experimental",
    "brainstem-regular",
)
rings = ("canary", "nightly", "alpha", "beta", "grail")
rappids = {
    (track, ring): f"rappid:@example/distribution-cell:{index:064x}"
    for index, (track, ring) in enumerate(
        (track, ring)
        for track in tracks
        for ring in rings
    )
}
yard = build_default_ring_yard_manifest(
    yard_identity="distribution-yard",
    yard_root="/srv/rapp-ring-yard",
    artifact_digest="sha256:" + "a" * 64,
    argv=("bin/rapp-cell",),
    rappids=rappids,
)
assert len(yard.cells) == 20
assert yard.peer_job_count == 380
assert yard.self_test_count == 20
assert yard.planned_job_count == 400
assert type(yard).from_json_bytes(yard.to_json_bytes()) == yard
assert check_ring_yard_manifest_semantics(yard.as_dict()).require() == yard
invalid_numeric_yard = yard.as_dict()
invalid_numeric_yard["cells"][0]["track_slot"] = 0.0
assert not check_ring_yard_manifest_semantics(invalid_numeric_yard).ok


def checkpoint(*frames):
    selected = frames[-1]
    return AuthorityCheckpoint.from_authenticated(
        {
            "canonical_repository": "https://example.test/authority",
            "protected_ref": "refs/heads/main",
            "accepted_commit": "a" * 40,
            "bootstrap_profile_sha256": "b" * 64,
            "chain_sha256": hashlib.sha256(
                b"".join(canonicalize(frame) + b"\n" for frame in frames)
            ).hexdigest(),
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


stream_id = "rappid:@example/distribution:" + "0" * 64
inline = build_spec_revision_frame(
    revision="rev-smoke",
    text="installed",
    utc="2026-08-30T00:00:00.000Z",
    stream_id=stream_id,
)
inline_checkpoint = checkpoint(inline)
registry = KindFamilyRegistry.from_checkpoint(inline_checkpoint)
trust = StreamTrustPolicy.from_checkpoint(inline_checkpoint)
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
pointer_checkpoint = checkpoint(pointer)
pointer_registry = KindFamilyRegistry.from_checkpoint(pointer_checkpoint)
pointer_trust = StreamTrustPolicy.from_checkpoint(pointer_checkpoint)
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


@dataclass(frozen=True, slots=True)
class BackendInfo:
    version: str
    location: Path
    backend_location: Path


def _python(environment: Path) -> Path:
    if os.name == "nt":
        candidates = (environment / "Scripts" / "python.exe",)
    else:
        candidates = (
            environment / "bin" / "python",
            environment / "bin" / "python3",
            environment / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}",
            environment / "bin" / "𝜋thon",
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"venv has no Python executable: {environment}")


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=capture,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed: {command!r}\n{result.stdout}\n{result.stderr}"
        )
    return result


def _setuptools_info(
    python: Path,
    *,
    environment: dict[str, str],
) -> BackendInfo | None:
    script = (
        "import json,pathlib,setuptools,setuptools.build_meta;"
        "print(json.dumps({'version':setuptools.__version__,"
        "'location':str(pathlib.Path(setuptools.__file__).resolve().parents[1]),"
        "'backend':str(pathlib.Path(setuptools.build_meta.__file__).resolve())}))"
    )
    result = subprocess.run(
        [str(python), "-I", "-B", "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        return None
    value = json.loads(result.stdout)
    return BackendInfo(
        value["version"],
        Path(value["location"]),
        Path(value["backend"]),
    )


def _select_backend_site(
    bundled: BackendInfo | None,
    provider_site: Path | None,
) -> Path | None:
    if bundled is not None:
        if bundled.version != PINNED_SETUPTOOLS_VERSION:
            if provider_site is None:
                raise RuntimeError(
                    "isolated venv setuptools version is not pinned and no "
                    f"provider was supplied: {bundled.version}"
                )
        else:
            return None
    if provider_site is None:
        raise RuntimeError(
            "sdist venv has no setuptools; provide --setuptools-site or "
            "RAPP_SDK_SETUPTOOLS_SITE"
        )
    return provider_site.resolve()


def _site_packages(
    python: Path,
    *,
    environment: dict[str, str],
) -> Path:
    result = _run(
        [
            str(python),
            "-I",
            "-B",
            "-c",
            "import sysconfig;print(sysconfig.get_paths()['purelib'])",
        ],
        environment=environment,
    )
    return Path(result.stdout.strip())


def _bridge_sdist_backend(
    python: Path,
    *,
    provider_site: Path | None,
    environment: dict[str, str],
) -> Path | None:
    provider = _select_backend_site(
        _setuptools_info(python, environment=environment),
        provider_site,
    )
    if provider is None:
        return None
    selected = _backend_overlay(provider)
    bridge = _site_packages(python, environment=environment) / (
        "rapp_sdk_build_backend.pth"
    )
    bridge.write_text(
        f"import sys; sys.path.insert(0, {str(selected)!r})\n",
        encoding="utf-8",
    )
    injected = _setuptools_info(python, environment=environment)
    if (
        injected is None
        or injected.version != PINNED_SETUPTOOLS_VERSION
        or injected.location.resolve() != selected
        or not injected.backend_location.resolve().is_relative_to(selected)
    ):
        raise RuntimeError("pinned setuptools provider was not activated")
    return bridge


def _backend_overlay(provider_site: Path) -> Path:
    overlay = WORK / f"setuptools-{PINNED_SETUPTOOLS_VERSION}"
    shutil.rmtree(overlay, ignore_errors=True)
    dist_info = provider_site / (
        f"setuptools-{PINNED_SETUPTOOLS_VERSION}.dist-info"
    )
    metadata = dist_info / "METADATA"
    record = dist_info / "RECORD"
    top_level = dist_info / "top_level.txt"
    for required in (metadata, record, top_level):
        if not required.is_file():
            raise RuntimeError(
                f"setuptools provider is missing required metadata: {required}"
            )
    metadata_text = metadata.read_text(encoding="utf-8")
    if (
        "\nName: setuptools\n" not in f"\n{metadata_text}"
        or f"\nVersion: {PINNED_SETUPTOOLS_VERSION}\n"
        not in f"\n{metadata_text}"
    ):
        raise RuntimeError("setuptools provider metadata does not match the pin")
    package_roots = {
        line.strip()
        for line in top_level.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if "setuptools" not in package_roots:
        raise RuntimeError("setuptools provider does not own setuptools package")
    if any(
        not name.replace("_", "").isalnum()
        for name in package_roots
    ):
        raise RuntimeError("setuptools provider has an unsafe top-level package")
    allowed_roots = package_roots | {dist_info.name}
    overlay.mkdir(parents=True)
    copied = 0
    try:
        with record.open(newline="", encoding="utf-8") as stream:
            for row in csv.reader(stream):
                relative = PurePosixPath(row[0])
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not relative.parts
                ):
                    raise RuntimeError(
                        f"unsafe setuptools RECORD path: {row[0]}"
                    )
                if relative.parts[0] not in allowed_roots:
                    continue
                if "__pycache__" in relative.parts or relative.suffix == ".pyc":
                    continue
                source = provider_site.joinpath(*relative.parts)
                if not source.is_file():
                    raise RuntimeError(
                        f"setuptools RECORD file is missing: {source}"
                    )
                _validate_record_entry(
                    source,
                    row,
                    record_path=f"{dist_info.name}/RECORD",
                )
                destination = overlay.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                copied += 1
        if copied == 0 or not (overlay / "setuptools" / "build_meta.py").is_file():
            raise RuntimeError("setuptools build_meta closure is incomplete")
    except Exception:
        shutil.rmtree(overlay, ignore_errors=True)
        raise
    return overlay


def _validate_record_entry(
    source: Path,
    row: list[str],
    *,
    record_path: str,
) -> None:
    if len(row) != 3:
        raise RuntimeError(f"invalid setuptools RECORD row: {row!r}")
    digest_text, size_text = row[1], row[2]
    data = source.read_bytes()
    is_record = row[0] == record_path
    if is_record:
        if digest_text or size_text:
            raise RuntimeError("setuptools RECORD must be self-unhashed")
        return
    if not digest_text or not size_text:
        raise RuntimeError(
            f"setuptools RECORD entry lacks hash or size: {row[0]}"
        )
    if not size_text.isdecimal() or len(data) != int(size_text):
        raise RuntimeError(f"setuptools RECORD size mismatch: {source}")
    try:
        algorithm, encoded = digest_text.split("=", 1)
    except ValueError as exc:
        raise RuntimeError(
            f"invalid setuptools RECORD digest: {source}"
        ) from exc
    if algorithm != "sha256":
        raise RuntimeError(f"unsupported setuptools RECORD hash: {algorithm}")
    try:
        expected = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except ValueError as exc:
        raise RuntimeError(
            f"invalid setuptools RECORD digest: {source}"
        ) from exc
    if base64.urlsafe_b64encode(expected).rstrip(b"=").decode() != encoded:
        raise RuntimeError(f"noncanonical setuptools RECORD digest: {source}")
    if hashlib.sha256(data).digest() != expected:
        raise RuntimeError(f"setuptools RECORD hash mismatch: {source}")


def _kind(path: Path) -> str:
    if path.name.endswith(".whl"):
        return "wheel"
    if path.name.endswith(".tar.gz"):
        return "sdist"
    raise ValueError(f"unsupported distribution artifact: {path}")


def _arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--setuptools-site",
        type=Path,
        default=(
            Path(os.environ["RAPP_SDK_SETUPTOOLS_SITE"])
            if os.environ.get("RAPP_SDK_SETUPTOOLS_SITE")
            else None
        ),
        help=(
            "site-packages containing setuptools "
            f"{PINNED_SETUPTOOLS_VERSION} for sdist builds"
        ),
    )
    parser.add_argument("artifacts", nargs=2)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = _arguments(arguments or sys.argv[1:])
    paths = [Path(value).resolve() for value in options.artifacts]
    by_kind = {_kind(path): path for path in paths}
    if set(by_kind) != {"wheel", "sdist"}:
        print("provide exactly one wheel and one .tar.gz sdist", file=sys.stderr)
        return 2

    source_hash = hashlib.sha256(SCHEMA.read_bytes()).hexdigest()
    ring_source_hash = hashlib.sha256(RING_SCHEMA.read_bytes()).hexdigest()
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
            bridge = None
            if kind == "sdist":
                bridge = _bridge_sdist_backend(
                    python,
                    provider_site=options.setuptools_site,
                    environment=environment,
                )
            try:
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
            finally:
                if bridge is not None:
                    bridge.unlink()
            _run(
                [
                    str(python),
                    "-I",
                    "-B",
                    "-c",
                    PROBE,
                    str(SCHEMA),
                    source_hash,
                    str(RING_SCHEMA),
                    ring_source_hash,
                    str(ROOT / "examples" / "spec_chain_smoke.py"),
                    str(isolated),
                ],
                environment=environment,
            )
            print(f"{kind}: installed API, example, docs, and resources verified")
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
