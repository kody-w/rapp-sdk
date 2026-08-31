"""Cross-check the ring-yard schema and mandatory semantic report."""

from __future__ import annotations

import copy
import importlib.metadata
import json
import sys
from collections.abc import Callable
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rapp_sdk import (
    build_default_ring_yard_manifest,
    check_ring_yard_manifest,
    check_ring_yard_manifest_semantics,
    read_ring_yard_manifest_schema,
    strict_json_loads,
)
from rapp_sdk.ring_manifest import RINGS, TRACKS

Document = dict[str, object]
Mutation = Callable[[Document], None]


def source_document() -> Document:
    rappids = {
        (track, ring): f"rappid:@example/schema-cell:{index:064x}"
        for index, (track, ring) in enumerate(
            (track, ring)
            for track in TRACKS
            for ring in RINGS
        )
    }
    return build_default_ring_yard_manifest(
        yard_identity="schema-yard",
        yard_root="/srv/rapp-ring-yard",
        artifact_digest="sha256:" + "a" * 64,
        argv=("bin/rapp-cell",),
        rappids=rappids,
    ).as_dict()


def changed(mutation: Mutation) -> Document:
    document = copy.deepcopy(source_document())
    mutation(document)
    return document


def schema_accepts(
    validator: Draft202012Validator,
    document: Document,
) -> bool:
    return not list(validator.iter_errors(document))


def encode_document(document: Document) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def runtime_accepts(document: Document) -> bool:
    return bytes_accept(encode_document(document))


def semantic_accepts(document: Document) -> bool:
    return check_ring_yard_manifest_semantics(document).ok


def bytes_accept(data: bytes) -> bool:
    return check_ring_yard_manifest(data).ok


def cells(document: Document) -> list[Document]:
    return document["cells"]  # type: ignore[return-value]


def main() -> int:
    version = importlib.metadata.version("jsonschema")
    major, minor = (int(part) for part in version.split(".")[:2])
    if major != 4 or minor < 23:
        raise RuntimeError(f"jsonschema test dependency is outside pin: {version}")
    schema = json.loads(read_ring_yard_manifest_schema())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    semantic_contract = schema["x-rapp-semantic-validator"]
    if semantic_contract != {
        "required": True,
        "api": "rapp_sdk.check_ring_yard_manifest_semantics",
        "bytes_api": "rapp_sdk.check_ring_yard_manifest",
    }:
        raise AssertionError("schema does not declare its semantic companion")

    patterns: list[str] = []

    def collect_patterns(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "pattern":
                    patterns.append(child)
                else:
                    collect_patterns(child)
        elif isinstance(value, list):
            for child in value:
                collect_patterns(child)

    collect_patterns(schema)
    if any(pattern.endswith("$") or "(?:/|$)" in pattern for pattern in patterns):
        raise AssertionError("schema contains a newline-tolerant end anchor")

    accepted = {
        "default": source_document(),
        "path-512-ascii": changed(
            lambda value: cells(value)[0]["paths"].__setitem__(  # type: ignore[union-attr]
                "home",
                "x" * 512,
            )
        ),
        "root-1024-ascii": changed(
            lambda value: value["yard"].__setitem__(  # type: ignore[union-attr]
                "root",
                "/" + "r" * 1023,
            )
        ),
        "argv-4096-ascii": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["bin/rapp-cell", "a" * 4096],
            )
        ),
        "executable-4096-ascii": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["b/" + "x" * 4094],
            )
        ),
        "argv-aggregate-8192-ascii": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                [
                    "bin/rapp-cell",
                    "a" * 4096,
                    "b" * (8192 - len("bin/rapp-cell") - 4096),
                ],
            )
        ),
    }
    strict_integer_document = strict_json_loads(
        encode_document(source_document())
    )
    if type(strict_integer_document) is not dict:
        raise AssertionError("strict parser did not produce a manifest object")
    accepted["strict-parsed-valid-integers"] = strict_integer_document

    schema_rejected = {
        "unknown-key": changed(lambda value: value.__setitem__("unknown", True)),
        "missing-cell": changed(lambda value: cells(value).pop()),
        "wrong-slot": changed(
            lambda value: cells(value)[0].__setitem__("ring_slot", 1)
        ),
        "wrong-port": changed(
            lambda value: cells(value)[0]["ports"].__setitem__(  # type: ignore[union-attr]
                "gateway",
                24704,
            )
        ),
        "unsafe-path": changed(
            lambda value: cells(value)[0]["paths"].__setitem__(  # type: ignore[union-attr]
                "home",
                "../home",
            )
        ),
        "unsafe-root": changed(
            lambda value: value["yard"].__setitem__("root", "/../yard")  # type: ignore[union-attr]
        ),
        "unsafe-probe": changed(
            lambda value: cells(value)[0]["probes"]["readiness"].__setitem__(  # type: ignore[index,union-attr]
                "path",
                "/../ready",
            )
        ),
        "mutable-artifact": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "digest",
                "latest",
            )
        ),
        "implicit-argv": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["rapp-cell"],
            )
        ),
        "invalid-budget": changed(
            lambda value: cells(value)[0]["budgets"].__setitem__(  # type: ignore[union-attr]
                "memory_bytes",
                0,
            )
        ),
        "invalid-plan": changed(
            lambda value: value["control_plane"]["plan"].__setitem__(  # type: ignore[index,union-attr]
                "total_jobs",
                399,
            )
        ),
        "track-slot-bool": changed(
            lambda value: cells(value)[0].__setitem__("track_slot", True)
        ),
        "port-bool": changed(
            lambda value: cells(value)[0]["ports"].__setitem__(  # type: ignore[union-attr]
                "gateway",
                True,
            )
        ),
        "scheduler-bool": changed(
            lambda value: value["control_plane"]["scheduler"].__setitem__(  # type: ignore[index,union-attr]
                "global_jobs",
                True,
            )
        ),
        "budget-bool": changed(
            lambda value: cells(value)[0]["budgets"].__setitem__(  # type: ignore[union-attr]
                "memory_bytes",
                True,
            )
        ),
        "probe-timeout-bool": changed(
            lambda value: cells(value)[0]["probes"]["readiness"].__setitem__(  # type: ignore[index,union-attr]
                "timeout_ms",
                True,
            )
        ),
        "plan-bool": changed(
            lambda value: value["control_plane"]["plan"].__setitem__(  # type: ignore[index,union-attr]
                "peer_jobs",
                True,
            )
        ),
        "yard-identity-trailing-lf": changed(
            lambda value: value["yard"].__setitem__(  # type: ignore[union-attr]
                "identity",
                "schema-yard\n",
            )
        ),
        "rappid-trailing-lf": changed(
            lambda value: cells(value)[0].__setitem__(
                "rappid",
                cells(value)[0]["rappid"] + "\n",  # type: ignore[operator]
            )
        ),
        "digest-trailing-lf": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "digest",
                "sha256:" + "a" * 64 + "\n",
            )
        ),
        "expected-rappid-trailing-lf": changed(
            lambda value: cells(value)[0]["probes"]["identity"].__setitem__(  # type: ignore[index,union-attr]
                "expected_rappid",
                cells(value)[0]["rappid"] + "\n",  # type: ignore[operator]
            )
        ),
        "expected-digest-trailing-lf": changed(
            lambda value: cells(value)[0]["probes"]["artifact"].__setitem__(  # type: ignore[index,union-attr]
                "expected_digest",
                "sha256:" + "a" * 64 + "\n",
            )
        ),
        "root-trailing-lf": changed(
            lambda value: value["yard"].__setitem__(  # type: ignore[union-attr]
                "root",
                "/srv/rapp-ring-yard\n",
            )
        ),
        "path-trailing-lf": changed(
            lambda value: cells(value)[0]["paths"].__setitem__(  # type: ignore[union-attr]
                "home",
                "cells/home\n",
            )
        ),
        "argv-trailing-lf": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["bin/rapp-cell", "--serve\n"],
            )
        ),
        "probe-path-trailing-lf": changed(
            lambda value: cells(value)[0]["probes"]["readiness"].__setitem__(  # type: ignore[index,union-attr]
                "path",
                "/readyz\n",
            )
        ),
        "path-multibyte-boundary": changed(
            lambda value: cells(value)[0]["paths"].__setitem__(  # type: ignore[union-attr]
                "home",
                "x" * 511 + "é",
            )
        ),
        "root-multibyte-boundary": changed(
            lambda value: value["yard"].__setitem__(  # type: ignore[union-attr]
                "root",
                "/" + "r" * 1022 + "é",
            )
        ),
        "argv-multibyte-boundary": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["bin/rapp-cell", "a" * 4095 + "é"],
            )
        ),
        "executable-multibyte-boundary": changed(
            lambda value: cells(value)[0]["artifact"].__setitem__(  # type: ignore[union-attr]
                "argv",
                ["b/" + "x" * 4093 + "é"],
            )
        ),
    }

    def duplicate_rappid(value: Document) -> None:
        cells(value)[1]["rappid"] = cells(value)[0]["rappid"]

    def reused_path(value: Document) -> None:
        cells(value)[1]["paths"]["home"] = cells(value)[0]["paths"]["home"]  # type: ignore[index]

    def nested_path(value: Document) -> None:
        cells(value)[1]["paths"]["home"] = (  # type: ignore[index]
            cells(value)[0]["paths"]["home"] + "/nested"  # type: ignore[operator]
        )

    def identity_mismatch(value: Document) -> None:
        cells(value)[0]["probes"]["identity"]["expected_rappid"] = (  # type: ignore[index]
            cells(value)[1]["rappid"]
        )

    def artifact_mismatch(value: Document) -> None:
        cells(value)[0]["probes"]["artifact"]["expected_digest"] = (  # type: ignore[index]
            "sha256:" + "b" * 64
        )

    def readiness_over_budget(value: Document) -> None:
        cells(value)[0]["probes"]["readiness"]["timeout_ms"] = 5001  # type: ignore[index]
        cells(value)[0]["probes"]["readiness"]["interval_ms"] = 6000  # type: ignore[index]

    def readiness_over_interval(value: Document) -> None:
        cells(value)[0]["probes"]["readiness"]["timeout_ms"] = 2001  # type: ignore[index]
        cells(value)[0]["probes"]["readiness"]["interval_ms"] = 2000  # type: ignore[index]

    def lifecycle_over_job(value: Document, field: str) -> None:
        cells(value)[0]["budgets"]["job_timeout_ms"] = 500  # type: ignore[index]
        cells(value)[0]["budgets"][field] = 1000  # type: ignore[index]

    def per_track_over_global(value: Document) -> None:
        scheduler = value["control_plane"]["scheduler"]  # type: ignore[index]
        scheduler["global_jobs"] = 1
        scheduler["per_track_jobs"] = 2

    def ready_queue_under_global(value: Document) -> None:
        scheduler = value["control_plane"]["scheduler"]  # type: ignore[index]
        scheduler["global_jobs"] = 4
        scheduler["ready_queue"] = 3

    def argv_over_aggregate(value: Document) -> None:
        cells(value)[0]["artifact"]["argv"] = [  # type: ignore[index]
            "bin/rapp-cell",
            "a" * 4096,
            "b" * 4096,
        ]

    def track_slot_float(value: Document) -> None:
        cells(value)[0]["track_slot"] = 0.0

    def port_float(value: Document) -> None:
        cells(value)[0]["ports"]["gateway"] = 24700.0  # type: ignore[index]

    def scheduler_float(value: Document) -> None:
        value["control_plane"]["scheduler"]["global_jobs"] = 4.0  # type: ignore[index]

    def budget_float(value: Document) -> None:
        cells(value)[0]["budgets"]["memory_bytes"] = 536870912.0  # type: ignore[index]

    def probe_timeout_float(value: Document) -> None:
        cells(value)[0]["probes"]["readiness"]["timeout_ms"] = 1000.0  # type: ignore[index]

    def plan_float(value: Document) -> None:
        value["control_plane"]["plan"]["peer_jobs"] = 380.0  # type: ignore[index]

    def negative_zero_float(value: Document) -> None:
        cells(value)[0]["track_slot"] = -0.0

    semantic_only = {
        "duplicate-cell-rappids": changed(duplicate_rappid),
        "reused-cross-cell-path": changed(reused_path),
        "nested-cross-cell-path": changed(nested_path),
        "identity-probe-mismatch": changed(identity_mismatch),
        "artifact-probe-mismatch": changed(artifact_mismatch),
        "readiness-timeout-over-budget": changed(readiness_over_budget),
        "readiness-timeout-over-interval": changed(readiness_over_interval),
        "startup-timeout-over-job": changed(
            lambda value: lifecycle_over_job(value, "startup_timeout_ms")
        ),
        "probe-timeout-over-job": changed(
            lambda value: lifecycle_over_job(value, "probe_timeout_ms")
        ),
        "shutdown-timeout-over-job": changed(
            lambda value: lifecycle_over_job(value, "shutdown_timeout_ms")
        ),
        "per-track-over-global": changed(per_track_over_global),
        "ready-queue-under-global": changed(ready_queue_under_global),
        "argv-over-aggregate": changed(argv_over_aggregate),
        "track-slot-integral-float": changed(track_slot_float),
        "port-integral-float": changed(port_float),
        "scheduler-integral-float": changed(scheduler_float),
        "budget-integral-float": changed(budget_float),
        "probe-timeout-integral-float": changed(probe_timeout_float),
        "plan-integral-float": changed(plan_float),
        "negative-zero-float": changed(negative_zero_float),
    }

    for name, document in accepted.items():
        if not schema_accepts(validator, document):
            raise AssertionError(f"schema rejected accepted vector: {name}")
        if not semantic_accepts(document):
            raise AssertionError(f"semantic API rejected accepted vector: {name}")
        if not runtime_accepts(document):
            raise AssertionError(f"bytes API rejected accepted vector: {name}")

    for name, document in schema_rejected.items():
        if schema_accepts(validator, document):
            raise AssertionError(f"schema accepted structural refusal: {name}")
        if semantic_accepts(document):
            raise AssertionError(f"semantic API accepted structural refusal: {name}")
        if runtime_accepts(document):
            raise AssertionError(f"bytes API accepted structural refusal: {name}")

    for name, document in semantic_only.items():
        if not schema_accepts(validator, document):
            raise AssertionError(
                f"runtime-only vector unexpectedly became schema-invalid: {name}"
            )
        if semantic_accepts(document):
            raise AssertionError(f"semantic API accepted runtime refusal: {name}")
        if runtime_accepts(document):
            raise AssertionError(f"bytes API accepted runtime refusal: {name}")

    exponent_bytes = encode_document(source_document()).replace(
        b'"track_slot":0',
        b'"track_slot":0e0',
        1,
    )
    exponent_document = strict_json_loads(exponent_bytes)
    if type(exponent_document) is not dict:
        raise AssertionError("strict parser did not produce exponent object")
    if not schema_accepts(validator, exponent_document):
        raise AssertionError("schema rejected exponent-origin integer value")
    if semantic_accepts(exponent_document):
        raise AssertionError("semantic API accepted exponent-origin integer value")
    if bytes_accept(exponent_bytes):
        raise AssertionError("bytes API accepted exponent-origin integer value")

    print(
        "ring schema/runtime parity: "
        f"{len(accepted)} accepted, "
        f"{len(schema_rejected)} schema refusals, "
        f"{len(semantic_only) + 1} mandatory semantic refusals"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
