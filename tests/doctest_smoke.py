"""Run the public module doctests through package imports."""

from __future__ import annotations

import doctest

from rapp_sdk import protocol, reports, ring_manifest, schemas


def main() -> int:
    failed = 0
    attempted = 0
    for module in (protocol, reports, ring_manifest, schemas):
        result = doctest.testmod(module)
        failed += result.failed
        attempted += result.attempted
    print(f"doctest: {attempted} attempted, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
