"""Optionally prove the committed fixture from a local authority checkout."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from authority_fixture import PINNED_AUTHORITY_COMMIT, pinned_fixture


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
    _, pinned_chain, pinned_spec = pinned_fixture()
    live_chain = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{PINNED_AUTHORITY_COMMIT}:anchor/chain.jsonl",
        ]
    )
    live_spec = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{PINNED_AUTHORITY_COMMIT}:SPEC.md",
        ]
    )
    if live_chain != pinned_chain or live_spec != pinned_spec:
        print("pinned fixture differs from the authority commit", file=sys.stderr)
        return 1
    print(f"fixture reproduced from {PINNED_AUTHORITY_COMMIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
