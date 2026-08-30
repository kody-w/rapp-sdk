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
import json
import sys
from importlib.resources import files
from pathlib import Path

import rapp_sdk
from rapp_sdk import (
    SPEC_REVISION_SCHEMA_ID,
    SPEC_REVISION_SCHEMA_RESOURCE,
    read_spec_revision_schema,
)

source = Path(sys.argv[1]).read_bytes()
resource = files("rapp_sdk").joinpath(
    f"schemas/{SPEC_REVISION_SCHEMA_RESOURCE}"
)
assert resource.is_file(), resource
installed = resource.read_bytes()
assert installed == source
assert read_spec_revision_schema() == source
assert hashlib.sha256(installed).hexdigest() == sys.argv[2]
assert json.loads(installed)["$id"] == SPEC_REVISION_SCHEMA_ID
assert SPEC_REVISION_SCHEMA_ID == "urn:rapp:schema:spec-revision:1"
assert importlib.metadata.version("rapp-sdk") == rapp_sdk.__version__
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
                ],
                environment=environment,
            )
            print(f"{kind}: installed schema resource verified")
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
