from __future__ import annotations

import copy
import dataclasses
import inspect
import json
import unittest
from typing import get_type_hints

from rapp_sdk import (
    RingManifestError,
    RingYardManifest,
    build_default_ring_yard_manifest,
    canonicalize,
    check_ring_yard_manifest,
    check_ring_yard_manifest_semantics,
    ports_for_cell,
    verify_ring_yard_manifest,
)
from rapp_sdk.ring_manifest import (
    BASE_PORT,
    CELL_COUNT,
    DEFAULT_RESOURCE_BUDGETS,
    DEFAULT_SCHEDULER_POLICY,
    ENDPOINT_OFFSETS,
    PEER_JOB_COUNT,
    PLANNED_JOB_COUNT,
    RINGS,
    RING_PORT_STRIDE,
    SELF_TEST_COUNT,
    TRACKS,
    TRACK_PORT_STRIDE,
    ArtifactContract,
    ArtifactProbe,
    CellPaths,
    CellPorts,
    ControlPlaneSettings,
    IdentityProbe,
    PlanCardinality,
    ProbeContracts,
    PromotionEdge,
    ResourceBudgets,
    RingCell,
    SchedulerPolicy,
    ServiceProbe,
    YardIdentity,
)

ARTIFACT_DIGEST = "sha256:" + "a" * 64


def rappid_mapping() -> dict[tuple[str, str], str]:
    return {
        (track, ring): (
            f"rappid:@example/ring-cell:{index:064x}"
        )
        for index, (track, ring) in enumerate(
            (track, ring)
            for track in TRACKS
            for ring in RINGS
        )
    }


def manifest() -> RingYardManifest:
    return build_default_ring_yard_manifest(
        yard_identity="yard-1",
        yard_root="/srv/rapp-ring-yard",
        artifact_digest=ARTIFACT_DIGEST,
        argv=("bin/rapp-cell", "--serve"),
        rappids=rappid_mapping(),
    )


def document() -> dict:
    return manifest().as_dict()


def refuse(value: dict, code: str | None = None) -> RingManifestError:
    report = check_ring_yard_manifest(canonicalize(value))
    if report.ok:
        raise AssertionError("invalid manifest was accepted")
    with unittest.TestCase().assertRaises(RingManifestError) as raised:
        report.require(RingManifestError)
    if code is not None:
        unittest.TestCase().assertEqual(raised.exception.code, code)
    return raised.exception


class RingManifestTests(unittest.TestCase):
    def test_exact_twenty_cell_layout_and_promotion_edges(self) -> None:
        value = manifest()
        self.assertEqual(CELL_COUNT, 20)
        self.assertEqual(
            tuple(
                (cell.track, cell.track_slot, cell.ring, cell.ring_slot)
                for cell in value.cells
            ),
            tuple(
                (track, track_slot, ring, ring_slot)
                for track_slot, track in enumerate(TRACKS)
                for ring_slot, ring in enumerate(RINGS)
            ),
        )
        self.assertEqual(len(value.promotion_edges), 19)
        self.assertEqual(
            value.promotion_edges[:4],
            (
                PromotionEdge(
                    "frontier-experimental",
                    "canary",
                    "frontier-experimental",
                    "nightly",
                ),
                PromotionEdge(
                    "frontier-experimental",
                    "nightly",
                    "frontier-experimental",
                    "alpha",
                ),
                PromotionEdge(
                    "frontier-experimental",
                    "alpha",
                    "frontier-experimental",
                    "beta",
                ),
                PromotionEdge(
                    "frontier-experimental",
                    "beta",
                    "frontier-experimental",
                    "grail",
                ),
            ),
        )
        cross_track = tuple(
            edge
            for edge in value.promotion_edges
            if edge.source_track != edge.target_track
        )
        self.assertEqual(
            cross_track,
            tuple(
                PromotionEdge(TRACKS[index], "grail", TRACKS[index + 1], "canary")
                for index in range(len(TRACKS) - 1)
            ),
        )

    def test_normative_port_formula_names_and_reserved_space(self) -> None:
        value = manifest()
        self.assertEqual(
            ENDPOINT_OFFSETS,
            (("gateway", 0), ("broker", 1), ("control", 2), ("metrics", 3)),
        )
        all_ports = []
        for cell in value.cells:
            expected_base = (
                BASE_PORT
                + cell.track_slot * TRACK_PORT_STRIDE
                + cell.ring_slot * RING_PORT_STRIDE
            )
            self.assertEqual(
                cell.ports.as_dict(),
                {
                    name: expected_base + offset
                    for name, offset in ENDPOINT_OFFSETS
                },
            )
            all_ports.extend(cell.ports.as_dict().values())
        self.assertEqual(len(all_ports), 80)
        self.assertEqual(len(set(all_ports)), 80)
        for track_slot in range(len(TRACKS) - 1):
            used_end = BASE_PORT + track_slot * TRACK_PORT_STRIDE + 19
            next_start = BASE_PORT + (track_slot + 1) * TRACK_PORT_STRIDE
            self.assertEqual(next_start - used_end - 1, 12)
        self.assertEqual(
            ports_for_cell(track_slot=3, ring_slot=4).metrics,
            24815,
        )

    def test_plan_counts_and_default_scheduler_are_explicit(self) -> None:
        value = manifest()
        self.assertEqual(PEER_JOB_COUNT, 20 * 19)
        self.assertEqual(SELF_TEST_COUNT, 20)
        self.assertEqual(PLANNED_JOB_COUNT, 400)
        self.assertEqual(value.peer_job_count, 380)
        self.assertEqual(value.self_test_count, 20)
        self.assertEqual(value.planned_job_count, 400)
        self.assertEqual(
            value.control_plane.scheduler,
            DEFAULT_SCHEDULER_POLICY,
        )
        self.assertEqual(
            value.control_plane.scheduler.as_dict(),
            {
                "global_jobs": 4,
                "per_track_jobs": 2,
                "per_observer_jobs": 1,
                "per_subject_jobs": 2,
                "ready_queue": 256,
            },
        )

    def test_identity_is_caller_supplied_complete_and_unique(self) -> None:
        arguments = {
            "yard_identity": "yard-1",
            "yard_root": "/srv/rapp-ring-yard",
            "artifact_digest": ARTIFACT_DIGEST,
            "argv": ("bin/rapp-cell",),
        }
        with self.assertRaises(RingManifestError) as missing:
            build_default_ring_yard_manifest(**arguments)
        self.assertEqual(missing.exception.code, "missing-rappids")

        incomplete = rappid_mapping()
        incomplete.pop(next(iter(incomplete)))
        with self.assertRaises(RingManifestError) as incomplete_error:
            build_default_ring_yard_manifest(
                **arguments,
                rappids=incomplete,
            )
        self.assertEqual(incomplete_error.exception.code, "missing-rappids")

        with self.assertRaises(RingManifestError) as both:
            build_default_ring_yard_manifest(
                **arguments,
                rappids=rappid_mapping(),
                mint_rappid=lambda track, ring: "unused",
            )
        self.assertEqual(both.exception.code, "missing-rappids")

        calls = []
        minted = rappid_mapping()

        def mint(track: str, ring: str) -> str:
            calls.append((track, ring))
            return minted[(track, ring)]

        value = build_default_ring_yard_manifest(
            **arguments,
            mint_rappid=mint,
        )
        self.assertEqual(
            calls,
            [(track, ring) for track in TRACKS for ring in RINGS],
        )
        self.assertEqual(
            tuple(cell.rappid for cell in value.cells),
            tuple(minted[key] for key in calls),
        )

        duplicate = rappid_mapping()
        keys = list(duplicate)
        duplicate[keys[1]] = duplicate[keys[0]]
        with self.assertRaises(RingManifestError) as duplicate_error:
            build_default_ring_yard_manifest(
                **arguments,
                rappids=duplicate,
            )
        self.assertEqual(duplicate_error.exception.code, "duplicate-rappid")

    def test_immutable_values_and_deterministic_serialization_hash(self) -> None:
        first = manifest()
        reverse_mapping = dict(reversed(list(rappid_mapping().items())))
        second = build_default_ring_yard_manifest(
            yard_identity="yard-1",
            yard_root="/srv/rapp-ring-yard",
            artifact_digest=ARTIFACT_DIGEST,
            argv=("bin/rapp-cell", "--serve"),
            rappids=reverse_mapping,
        )
        self.assertEqual(first.to_json_bytes(), second.to_json_bytes())
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)
        self.assertEqual(
            RingYardManifest.from_json_bytes(first.to_json_bytes()),
            first,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.cells[0].rappid = "forbidden"
        with self.assertRaises(TypeError):
            first.cells[0] = first.cells[1]
        with self.assertRaises(TypeError):
            first.cells[0].artifact.argv[0] = "forbidden"

    def test_strict_json_report_exception_and_input_bound(self) -> None:
        value = manifest()
        duplicate = value.to_json_bytes().replace(
            b'\"spec\":\"rapp-ring-yard/1\"',
            b'\"spec\":\"rapp-ring-yard/1\",\"spec\":\"rapp-ring-yard/1\"',
            1,
        )
        report = check_ring_yard_manifest(duplicate)
        self.assertFalse(report.ok)
        self.assertEqual(report.diagnostics[0].code, "duplicate-key")
        with self.assertRaises(RingManifestError) as duplicate_error:
            verify_ring_yard_manifest(duplicate)
        self.assertEqual(duplicate_error.exception.code, "duplicate-key")
        bounded = check_ring_yard_manifest(value.to_json_bytes(), max_bytes=8)
        self.assertFalse(bounded.ok)
        self.assertEqual(bounded.diagnostics[0].code, "input-size-exceeded")

    def test_schema_companion_semantic_report_is_mandatory_and_typed(self) -> None:
        source = document()
        report = check_ring_yard_manifest_semantics(source)
        self.assertTrue(report.ok)
        self.assertEqual(report.require(), manifest())

        source["cells"][1]["rappid"] = source["cells"][0]["rappid"]
        rejected = check_ring_yard_manifest_semantics(source)
        self.assertFalse(rejected.ok)
        self.assertEqual(rejected.diagnostics[0].code, "duplicate-rappid")
        with self.assertRaises(TypeError):
            check_ring_yard_manifest_semantics([])  # type: ignore[arg-type]

    def test_semantic_validation_preserves_original_numeric_types(self) -> None:
        valid = document()
        valid_bytes = json.dumps(
            valid,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertTrue(check_ring_yard_manifest_semantics(valid).ok)
        self.assertTrue(check_ring_yard_manifest(valid_bytes).ok)

        cases = (
            ("track-slot-float", ("cells", 0, "track_slot"), 0.0),
            ("port-float", ("cells", 0, "ports", "gateway"), 24700.0),
            (
                "scheduler-float",
                ("control_plane", "scheduler", "global_jobs"),
                4.0,
            ),
            (
                "budget-float",
                ("cells", 0, "budgets", "memory_bytes"),
                536870912.0,
            ),
            (
                "probe-timeout-float",
                ("cells", 0, "probes", "readiness", "timeout_ms"),
                1000.0,
            ),
            (
                "plan-float",
                ("control_plane", "plan", "peer_jobs"),
                380.0,
            ),
            ("negative-zero", ("cells", 0, "track_slot"), -0.0),
            ("boolean", ("cells", 0, "track_slot"), True),
        )
        for name, path, replacement in cases:
            value = document()
            target = value
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = replacement
            encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
            with self.subTest(name=name):
                self.assertFalse(
                    check_ring_yard_manifest_semantics(value).ok
                )
                self.assertFalse(check_ring_yard_manifest(encoded).ok)

        exponent_bytes = valid_bytes.replace(
            b'"track_slot":0',
            b'"track_slot":0e0',
            1,
        )
        exponent_document = json.loads(exponent_bytes)
        self.assertFalse(
            check_ring_yard_manifest_semantics(exponent_document).ok
        )
        self.assertFalse(check_ring_yard_manifest(exponent_bytes).ok)

    def test_closed_shape_topology_and_order_refusals(self) -> None:
        value = document()
        value["unknown"] = True
        refuse(value, "invalid-manifest-shape")

        value = document()
        value["cells"][0]["unknown"] = True
        refuse(value, "invalid-manifest-shape")

        value = document()
        value["spec"] = "rapp-ring-yard/latest"
        refuse(value, "invalid-manifest-version")

        value = document()
        value["cells"].pop()
        refuse(value, "invalid-topology")

        value = document()
        value["cells"][0], value["cells"][1] = value["cells"][1], value["cells"][0]
        refuse(value, "invalid-topology")

        value = document()
        value["cells"][0]["track_slot"] = 1
        refuse(value, "invalid-topology")

        value = document()
        value["control_plane"]["plan"]["peer_jobs"] = 379
        refuse(value, "invalid-plan-cardinality")

    def test_path_refusals_cover_absolute_traversal_and_overlap(self) -> None:
        for path in ("/absolute/home", "../home", "cells//home", "cells/./home"):
            value = document()
            value["cells"][0]["paths"]["home"] = path
            with self.subTest(path=path):
                refuse(value, "unsafe-manifest-path")

        value = document()
        value["yard"]["root"] = "relative/root"
        refuse(value, "invalid-yard")

        value = document()
        value["yard"]["root"] = "//srv/rapp-ring-yard"
        refuse(value, "invalid-yard")

        value = document()
        value["yard"]["root"] = "/srv/räpp-ring-yard"
        refuse(value, "invalid-yard")

        value = document()
        value["cells"][0]["paths"]["home"] = "x" * 511 + "é"
        refuse(value, "unsafe-manifest-path")

        value = document()
        value["cells"][1]["paths"]["home"] = value["cells"][0]["paths"]["home"]
        refuse(value, "overlapping-path")

        value = document()
        value["cells"][1]["paths"]["home"] = (
            value["cells"][0]["paths"]["home"] + "/nested"
        )
        refuse(value, "overlapping-path")

    def test_port_refusals_cover_range_formula_and_overlap(self) -> None:
        value = document()
        value["cells"][0]["ports"]["gateway"] = 70000
        refuse(value, "invalid-port")

        value = document()
        value["cells"][0]["ports"]["gateway"] = 25000
        refuse(value, "invalid-port")

        value = document()
        value["cells"][1]["ports"]["gateway"] = value["cells"][0]["ports"]["gateway"]
        refuse(value, "duplicate-port")

    def test_artifact_argv_and_rappid_refusals(self) -> None:
        for digest in ("main", "sha256:" + "A" * 64, "sha512:" + "a" * 64):
            value = document()
            value["cells"][0]["artifact"]["digest"] = digest
            with self.subTest(digest=digest):
                refuse(value, "mutable-artifact")

        value = document()
        value["cells"][0]["artifact"]["tag"] = "latest"
        refuse(value, "invalid-manifest-shape")

        value = document()
        value["cells"][0]["artifact"]["argv"] = []
        refuse(value, "invalid-argv")

        value = document()
        value["cells"][0]["artifact"]["argv"] = ["rapp-cell"]
        refuse(value, "invalid-argv")

        value = document()
        value["cells"][0]["artifact"]["argv"] = [
            "bin/rapp-cell",
            "a" * 4095 + "é",
        ]
        refuse(value, "invalid-argv")

        value = document()
        value["cells"][0]["artifact"]["argv"] = [
            "bin/rapp-cell",
            "a" * 4096,
            "b" * 4096,
        ]
        refuse(value, "invalid-argv")

        value = document()
        value["cells"][0]["rappid"] = "frontier-canary"
        refuse(value, "invalid-rappid")

        value = document()
        value["cells"][1]["rappid"] = value["cells"][0]["rappid"]
        refuse(value, "duplicate-rappid")

    def test_probe_budget_and_scheduler_refusals(self) -> None:
        value = document()
        value["cells"][0]["probes"]["identity"]["expected_rappid"] = (
            value["cells"][1]["rappid"]
        )
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["probes"]["artifact"]["expected_digest"] = (
            "sha256:" + "b" * 64
        )
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["probes"]["readiness"]["path"] = "/../ready"
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["probes"]["readiness"]["path"] = "/" + "a" * 513
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["probes"]["readiness"]["timeout_ms"] = 6000
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["probes"]["readiness"]["timeout_ms"] = 2001
        value["cells"][0]["probes"]["readiness"]["interval_ms"] = 2000
        refuse(value, "invalid-probe")

        value = document()
        value["cells"][0]["budgets"]["memory_bytes"] = 0
        refuse(value, "invalid-budget")

        value = document()
        value["cells"][0]["budgets"]["job_timeout_ms"] = 100
        refuse(value, "invalid-budget")

        value = document()
        value["control_plane"]["scheduler"]["global_jobs"] = 0
        refuse(value, "invalid-scheduler")

        value = document()
        value["control_plane"]["scheduler"]["per_track_jobs"] = 5
        refuse(value, "invalid-scheduler")

        value = document()
        value["control_plane"]["scheduler"]["ready_queue"] = 1
        refuse(value, "invalid-scheduler")

    def test_public_models_are_frozen_slotted_and_typed(self) -> None:
        models = (
            YardIdentity,
            SchedulerPolicy,
            PlanCardinality,
            ControlPlaneSettings,
            CellPaths,
            ArtifactContract,
            CellPorts,
            ServiceProbe,
            IdentityProbe,
            ArtifactProbe,
            ProbeContracts,
            ResourceBudgets,
            RingCell,
            PromotionEdge,
            RingYardManifest,
        )
        for model in models:
            with self.subTest(model=model.__name__):
                self.assertTrue(model.__dataclass_params__.frozen)
                self.assertTrue(hasattr(model, "__slots__"))
                self.assertTrue(get_type_hints(model))

        callables = (
            ports_for_cell,
            build_default_ring_yard_manifest,
            check_ring_yard_manifest,
            check_ring_yard_manifest_semantics,
            verify_ring_yard_manifest,
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
                    )
                self.assertTrue(get_type_hints(function))

        self.assertEqual(DEFAULT_RESOURCE_BUDGETS.probe_timeout_ms, 5000)


if __name__ == "__main__":
    unittest.main()
