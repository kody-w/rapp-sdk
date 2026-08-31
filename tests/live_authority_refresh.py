"""Optionally prove the committed fixture from a local authority checkout."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authority_fixture import (
    SELECTED_AUTHORITY_COMMIT,
    selected_fixture,
)


def main() -> int:
    location = (
        sys.argv[1]
        if len(sys.argv) == 2
        else os.environ.get("RAPP1_AUTHORITY_ROOT")
    )
    if not location:
        print("usage: live_authority_refresh.py AUTHORITY_CHECKOUT", file=sys.stderr)
        return 2
    root = Path(location)
    manifest, selected_chain, selected_spec, rev13_spec, bootstrap = (
        selected_fixture()
    )
    live_chain = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{SELECTED_AUTHORITY_COMMIT}:anchor/chain.jsonl",
        ]
    )
    live_spec = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{SELECTED_AUTHORITY_COMMIT}:SPEC.md",
        ]
    )
    live_bootstrap = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{SELECTED_AUTHORITY_COMMIT}:"
            f"{manifest['selected']['bootstrap_profile_path']}",
        ]
    )
    historical = manifest["historical"]["rev-13"]
    live_rev13 = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{historical['pointer_commit']}:{historical['pointer_path']}",
        ]
    )
    if (
        live_chain != selected_chain
        or live_spec != selected_spec
        or live_bootstrap != bootstrap
        or live_rev13 != rev13_spec
    ):
        print("selected fixture differs from immutable authority", file=sys.stderr)
        return 1
    print(f"fixture reproduced from {SELECTED_AUTHORITY_COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
