"""Closed, immutable ``rapp-ring-yard/1`` manifest values.

The module describes topology and bounded execution policy only. It does not
launch processes, schedule jobs, expose an API, or persist evidence.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TypeAlias

from .errors import ProtocolError, RingManifestError
from .protocol import JsonValue, canonicalize, strict_json_loads
from .reports import Diagnostic, VerificationReport

RING_YARD_SPEC = "rapp-ring-yard/1"
MAX_RING_YARD_MANIFEST_BYTES = 512 * 1024
BASE_PORT = 24700
TRACK_PORT_STRIDE = 32
RING_PORT_STRIDE = 4
TRACKS = (
    "frontier-experimental",
    "frontier",
    "brainstem-experimental",
    "brainstem-regular",
)
RINGS = ("canary", "nightly", "alpha", "beta", "grail")
ENDPOINT_OFFSETS = (
    ("gateway", 0),
    ("broker", 1),
    ("control", 2),
    ("metrics", 3),
)
CELL_COUNT = len(TRACKS) * len(RINGS)
PEER_JOB_COUNT = CELL_COUNT * (CELL_COUNT - 1)
SELF_TEST_COUNT = CELL_COUNT
PLANNED_JOB_COUNT = PEER_JOB_COUNT + SELF_TEST_COUNT

_LABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_RAPPID_RE = re.compile(
    rf"rappid:@{_LABEL}/{_LABEL}:[0-9a-f]{{64}}",
    re.ASCII,
)
_YARD_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_PATH_SEGMENT = r"[A-Za-z0-9._~!$&'()+,;=@-]+"
_RELATIVE_PATH_RE = re.compile(
    rf"(?!\.\.?(?:/|\Z))(?!.*(?:^|/)\.\.?(?:/|\Z))"
    rf"{_PATH_SEGMENT}(?:/{_PATH_SEGMENT})*",
    re.ASCII,
)
_ABSOLUTE_PATH_RE = re.compile(
    rf"/(?!\.\.?(?:/|\Z))(?!.*(?:^|/)\.\.?(?:/|\Z))"
    rf"{_PATH_SEGMENT}(?:/{_PATH_SEGMENT})*",
    re.ASCII,
)
_ASCII_ARGUMENT_RE = re.compile(r"[\x20-\x7e]+", re.ASCII)
_PROBE_PATH_RE = re.compile(
    r"/(?!/)(?!.*//)(?!\.\.?(?:/|\Z))(?!.*(?:^|/)\.\.?(?:/|\Z))"
    r"[A-Za-z0-9._~/-]+",
    re.ASCII,
)
_CELL_KEYS = frozenset(
    {
        "track",
        "track_slot",
        "ring",
        "ring_slot",
        "rappid",
        "paths",
        "artifact",
        "ports",
        "probes",
        "budgets",
    }
)
CellKey: TypeAlias = tuple[str, str]
MintRappid: TypeAlias = Callable[[str, str], str]


def _diagnostic(
    code: str,
    message: str,
    *,
    location: str,
    context: Mapping[str, str | int | bool | None] | None = None,
    remediation: str | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        operation="ring-manifest",
        message=message,
        location=location,
        context=context or {},
        remediation=remediation,
    )


def _fail(
    code: str,
    message: str,
    *,
    location: str,
    context: Mapping[str, str | int | bool | None] | None = None,
    remediation: str | None = None,
) -> None:
    raise RingManifestError(
        _diagnostic(
            code,
            message,
            location=location,
            context=context,
            remediation=remediation,
        )
    )


def _integer(
    value: object,
    *,
    location: str,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(code, "value must be an integer", location=location)
    result = int(value)
    if not minimum <= result <= maximum:
        _fail(
            code,
            f"value must be between {minimum} and {maximum}",
            location=location,
            context={"value": result},
        )
    return result


def _text(
    value: object,
    *,
    location: str,
    minimum: int = 1,
    maximum: int,
    code: str,
) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        _fail(
            code,
            f"value must be {minimum}-{maximum} characters of text",
            location=location,
        )
    if "\x00" in value:
        _fail(code, "NUL is forbidden", location=location)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise RingManifestError(
            _diagnostic(
                code,
                "text must be valid Unicode",
                location=location,
            )
        ) from exc
    if len(encoded) > maximum:
        _fail(
            code,
            f"UTF-8 value cannot exceed {maximum} bytes",
            location=location,
        )
    return value


def _closed_object(
    value: object,
    *,
    keys: frozenset[str],
    location: str,
) -> dict[str, JsonValue]:
    if type(value) is not dict:
        _fail(
            "invalid-manifest-shape",
            "value must be a JSON object",
            location=location,
        )
    actual = frozenset(value)
    if actual != keys:
        _fail(
            "invalid-manifest-shape",
            "object members do not match the closed manifest shape",
            location=location,
            context={
                "missing": ",".join(sorted(keys - actual)) or None,
                "unknown": ",".join(sorted(actual - keys)) or None,
            },
        )
    return value


def _snapshot_json(
    value: object,
    *,
    active: set[int] | None = None,
    depth: int = 0,
) -> JsonValue:
    """Detach JSON containers without changing immutable scalar types."""

    if depth > 64:
        _fail(
            "invalid-manifest-shape",
            "manifest nesting exceeds 64 containers",
            location="manifest",
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if active is None:
        active = set()
    if type(value) is list:
        identity = id(value)
        if identity in active:
            _fail(
                "invalid-manifest-shape",
                "manifest contains a cyclic array",
                location="manifest",
            )
        active.add(identity)
        try:
            return [
                _snapshot_json(item, active=active, depth=depth + 1)
                for item in value
            ]
        finally:
            active.remove(identity)
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            _fail(
                "invalid-manifest-shape",
                "manifest contains a cyclic object",
                location="manifest",
            )
        if any(type(key) is not str for key in value):
            _fail(
                "invalid-manifest-shape",
                "manifest object keys must be strings",
                location="manifest",
            )
        active.add(identity)
        try:
            return {
                key: _snapshot_json(item, active=active, depth=depth + 1)
                for key, item in value.items()
            }
        finally:
            active.remove(identity)
    _fail(
        "invalid-manifest-shape",
        "manifest contains a non-JSON value",
        location="manifest",
    )


def _relative_path(
    value: object,
    *,
    location: str,
    maximum: int = 512,
) -> str:
    path = _text(
        value,
        location=location,
        maximum=maximum,
        code="unsafe-manifest-path",
    )
    if _RELATIVE_PATH_RE.fullmatch(path) is None:
        _fail(
            "unsafe-manifest-path",
            "relative paths must use the documented ASCII POSIX subset",
            location=location,
        )
    return path


def _absolute_root(value: object, *, location: str) -> str:
    path = _text(
        value,
        location=location,
        maximum=1024,
        code="invalid-yard",
    )
    if _ABSOLUTE_PATH_RE.fullmatch(path) is None:
        _fail(
            "invalid-yard",
            "yard root must use the documented absolute ASCII POSIX subset",
            location=location,
        )
    return path


def _rappid(value: object, *, location: str) -> str:
    if type(value) is not str or _RAPPID_RE.fullmatch(value) is None:
        _fail(
            "invalid-rappid",
            "RAPPID must be an explicitly minted canonical rappid",
            location=location,
        )
    return value


def _digest(value: object, *, location: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        _fail(
            "mutable-artifact",
            "artifact must be identified only by sha256:<64-lowercase-hex>",
            location=location,
        )
    return value


def _probe_path(value: object, *, location: str) -> str:
    path = _text(
        value,
        location=location,
        maximum=512,
        code="invalid-probe",
    )
    if _PROBE_PATH_RE.fullmatch(path) is None:
        _fail(
            "invalid-probe",
            "probe path must be a normalized absolute HTTP path",
            location=location,
        )
    parts = PurePosixPath(path).parts
    if any(part in {".", ".."} for part in parts):
        _fail(
            "invalid-probe",
            "probe path must not traverse",
            location=location,
        )
    return path


def _endpoint(value: object, *, location: str) -> str:
    endpoints = frozenset(name for name, _ in ENDPOINT_OFFSETS)
    if type(value) is not str or value not in endpoints:
        _fail(
            "invalid-probe",
            "probe endpoint must name a reserved cell endpoint",
            location=location,
        )
    return value


@dataclass(frozen=True, slots=True)
class YardIdentity:
    """One explicit yard identity and absolute resolution root."""

    identity: str
    root: str

    def __post_init__(self) -> None:
        if type(self.identity) is not str or _YARD_ID_RE.fullmatch(self.identity) is None:
            _fail(
                "invalid-yard",
                "yard identity must be a bounded lowercase label",
                location="yard.identity",
            )
        object.__setattr__(
            self,
            "root",
            _absolute_root(self.root, location="yard.root"),
        )

    def as_dict(self) -> dict[str, JsonValue]:
        return {"identity": self.identity, "root": self.root}


@dataclass(frozen=True, slots=True)
class SchedulerPolicy:
    """Concurrency limits declared by the control plane."""

    global_jobs: int
    per_track_jobs: int
    per_observer_jobs: int
    per_subject_jobs: int
    ready_queue: int

    def __post_init__(self) -> None:
        global_jobs = _integer(
            self.global_jobs,
            location="control_plane.scheduler.global_jobs",
            minimum=1,
            maximum=1024,
            code="invalid-scheduler",
        )
        per_track_jobs = _integer(
            self.per_track_jobs,
            location="control_plane.scheduler.per_track_jobs",
            minimum=1,
            maximum=1024,
            code="invalid-scheduler",
        )
        per_observer_jobs = _integer(
            self.per_observer_jobs,
            location="control_plane.scheduler.per_observer_jobs",
            minimum=1,
            maximum=1024,
            code="invalid-scheduler",
        )
        per_subject_jobs = _integer(
            self.per_subject_jobs,
            location="control_plane.scheduler.per_subject_jobs",
            minimum=1,
            maximum=1024,
            code="invalid-scheduler",
        )
        ready_queue = _integer(
            self.ready_queue,
            location="control_plane.scheduler.ready_queue",
            minimum=1,
            maximum=1_000_000,
            code="invalid-scheduler",
        )
        if any(
            value > global_jobs
            for value in (per_track_jobs, per_observer_jobs, per_subject_jobs)
        ):
            _fail(
                "invalid-scheduler",
                "local concurrency limits cannot exceed global_jobs",
                location="control_plane.scheduler",
            )
        if ready_queue < global_jobs:
            _fail(
                "invalid-scheduler",
                "ready_queue cannot be smaller than global_jobs",
                location="control_plane.scheduler.ready_queue",
            )
        for name, value in (
            ("global_jobs", global_jobs),
            ("per_track_jobs", per_track_jobs),
            ("per_observer_jobs", per_observer_jobs),
            ("per_subject_jobs", per_subject_jobs),
            ("ready_queue", ready_queue),
        ):
            object.__setattr__(self, name, value)

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "global_jobs": self.global_jobs,
            "per_track_jobs": self.per_track_jobs,
            "per_observer_jobs": self.per_observer_jobs,
            "per_subject_jobs": self.per_subject_jobs,
            "ready_queue": self.ready_queue,
        }


@dataclass(frozen=True, slots=True)
class PlanCardinality:
    """Closed directed plan counts; no jobs are executed by this model."""

    peer_jobs: int = PEER_JOB_COUNT
    self_tests: int = SELF_TEST_COUNT
    total_jobs: int = PLANNED_JOB_COUNT

    def __post_init__(self) -> None:
        for name, expected in (
            ("peer_jobs", PEER_JOB_COUNT),
            ("self_tests", SELF_TEST_COUNT),
            ("total_jobs", PLANNED_JOB_COUNT),
        ):
            object.__setattr__(
                self,
                name,
                _integer(
                    getattr(self, name),
                    location=f"control_plane.plan.{name}",
                    minimum=expected,
                    maximum=expected,
                    code="invalid-plan-cardinality",
                ),
            )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "peer_jobs": self.peer_jobs,
            "self_tests": self.self_tests,
            "total_jobs": self.total_jobs,
        }


@dataclass(frozen=True, slots=True)
class ControlPlaneSettings:
    """Reconstructible scheduling and planning settings."""

    scheduler: SchedulerPolicy
    plan: PlanCardinality

    def __post_init__(self) -> None:
        if not isinstance(self.scheduler, SchedulerPolicy):
            raise TypeError("scheduler must be SchedulerPolicy")
        if not isinstance(self.plan, PlanCardinality):
            raise TypeError("plan must be PlanCardinality")

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "scheduler": self.scheduler.as_dict(),
            "plan": self.plan.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class CellPaths:
    """Five isolated paths resolved only below the yard root."""

    home: str
    state: str
    log: str
    cache: str
    tmp: str

    def __post_init__(self) -> None:
        for name in ("home", "state", "log", "cache", "tmp"):
            object.__setattr__(
                self,
                name,
                _relative_path(
                    getattr(self, name),
                    location=f"paths.{name}",
                ),
            )
        values = tuple(getattr(self, name) for name in ("home", "state", "log", "cache", "tmp"))
        if len(values) != len(set(values)):
            _fail(
                "overlapping-path",
                "cell paths must be distinct",
                location="paths",
            )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "home": self.home,
            "state": self.state,
            "log": self.log,
            "cache": self.cache,
            "tmp": self.tmp,
        }


@dataclass(frozen=True, slots=True)
class ArtifactContract:
    """One immutable artifact digest and explicit non-PATH argv."""

    digest: str
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest(self.digest, location="artifact.digest"),
        )
        if isinstance(self.argv, str):
            _fail(
                "invalid-argv",
                "artifact argv must be a non-empty array",
                location="artifact.argv",
            )
        try:
            argv = tuple(self.argv)
        except TypeError as exc:
            raise RingManifestError(
                _diagnostic(
                    "invalid-argv",
                    "artifact argv must be a non-empty array",
                    location="artifact.argv",
                )
            ) from exc
        if not 1 <= len(argv) <= 64:
            _fail(
                "invalid-argv",
                "artifact argv must contain 1-64 arguments",
                location="artifact.argv",
            )
        for index, argument in enumerate(argv):
            _text(
                argument,
                location=f"artifact.argv[{index}]",
                maximum=4096,
                code="invalid-argv",
            )
            if _ASCII_ARGUMENT_RE.fullmatch(argument) is None:
                _fail(
                    "invalid-argv",
                    "argv arguments must use printable ASCII",
                    location=f"artifact.argv[{index}]",
                )
        executable = _relative_path(
            argv[0],
            location="artifact.argv[0]",
            maximum=4096,
        )
        if "/" not in executable:
            _fail(
                "invalid-argv",
                "argv[0] must be artifact-relative and cannot use ambient PATH",
                location="artifact.argv[0]",
            )
        if sum(len(argument.encode("utf-8")) for argument in argv) > 8192:
            _fail(
                "invalid-argv",
                "artifact argv cannot exceed 8192 UTF-8 bytes",
                location="artifact.argv",
            )
        object.__setattr__(self, "argv", argv)

    def as_dict(self) -> dict[str, JsonValue]:
        return {"digest": self.digest, "argv": list(self.argv)}


@dataclass(frozen=True, slots=True)
class CellPorts:
    """Four deterministic endpoint ports for one cell."""

    gateway: int
    broker: int
    control: int
    metrics: int

    def __post_init__(self) -> None:
        for name in ("gateway", "broker", "control", "metrics"):
            object.__setattr__(
                self,
                name,
                _integer(
                    getattr(self, name),
                    location=f"ports.{name}",
                    minimum=1,
                    maximum=65535,
                    code="invalid-port",
                ),
            )
        values = (self.gateway, self.broker, self.control, self.metrics)
        if len(values) != len(set(values)):
            _fail(
                "duplicate-port",
                "cell endpoint ports must be unique",
                location="ports",
            )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "gateway": self.gateway,
            "broker": self.broker,
            "control": self.control,
            "metrics": self.metrics,
        }


def ports_for_cell(*, track_slot: int, ring_slot: int) -> CellPorts:
    """Return the normative ports for one topology slot.

    >>> ports_for_cell(track_slot=0, ring_slot=0).as_dict()
    {'gateway': 24700, 'broker': 24701, 'control': 24702, 'metrics': 24703}
    """

    track = _integer(
        track_slot,
        location="track_slot",
        minimum=0,
        maximum=len(TRACKS) - 1,
        code="invalid-topology",
    )
    ring = _integer(
        ring_slot,
        location="ring_slot",
        minimum=0,
        maximum=len(RINGS) - 1,
        code="invalid-topology",
    )
    base = BASE_PORT + track * TRACK_PORT_STRIDE + ring * RING_PORT_STRIDE
    values = {name: base + offset for name, offset in ENDPOINT_OFFSETS}
    return CellPorts(**values)


@dataclass(frozen=True, slots=True)
class ServiceProbe:
    """Readiness or liveness HTTP probe declaration."""

    endpoint: str
    path: str
    timeout_ms: int
    interval_ms: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "endpoint",
            _endpoint(self.endpoint, location="probe.endpoint"),
        )
        object.__setattr__(
            self,
            "path",
            _probe_path(self.path, location="probe.path"),
        )
        timeout = _integer(
            self.timeout_ms,
            location="probe.timeout_ms",
            minimum=1,
            maximum=60_000,
            code="invalid-probe",
        )
        interval = _integer(
            self.interval_ms,
            location="probe.interval_ms",
            minimum=1,
            maximum=3_600_000,
            code="invalid-probe",
        )
        if timeout > interval:
            _fail(
                "invalid-probe",
                "probe timeout cannot exceed probe interval",
                location="probe",
            )
        object.__setattr__(self, "timeout_ms", timeout)
        object.__setattr__(self, "interval_ms", interval)

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "endpoint": self.endpoint,
            "path": self.path,
            "timeout_ms": self.timeout_ms,
            "interval_ms": self.interval_ms,
        }


@dataclass(frozen=True, slots=True)
class IdentityProbe:
    """Identity attestation probe declaration."""

    endpoint: str
    path: str
    timeout_ms: int
    expected_rappid: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "endpoint",
            _endpoint(self.endpoint, location="probe.endpoint"),
        )
        object.__setattr__(
            self,
            "path",
            _probe_path(self.path, location="probe.path"),
        )
        object.__setattr__(
            self,
            "timeout_ms",
            _integer(
                self.timeout_ms,
                location="probe.timeout_ms",
                minimum=1,
                maximum=60_000,
                code="invalid-probe",
            ),
        )
        object.__setattr__(
            self,
            "expected_rappid",
            _rappid(
                self.expected_rappid,
                location="probe.expected_rappid",
            ),
        )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "endpoint": self.endpoint,
            "path": self.path,
            "timeout_ms": self.timeout_ms,
            "expected_rappid": self.expected_rappid,
        }


@dataclass(frozen=True, slots=True)
class ArtifactProbe:
    """Artifact digest attestation probe declaration."""

    endpoint: str
    path: str
    timeout_ms: int
    expected_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "endpoint",
            _endpoint(self.endpoint, location="probe.endpoint"),
        )
        object.__setattr__(
            self,
            "path",
            _probe_path(self.path, location="probe.path"),
        )
        object.__setattr__(
            self,
            "timeout_ms",
            _integer(
                self.timeout_ms,
                location="probe.timeout_ms",
                minimum=1,
                maximum=60_000,
                code="invalid-probe",
            ),
        )
        object.__setattr__(
            self,
            "expected_digest",
            _digest(
                self.expected_digest,
                location="probe.expected_digest",
            ),
        )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "endpoint": self.endpoint,
            "path": self.path,
            "timeout_ms": self.timeout_ms,
            "expected_digest": self.expected_digest,
        }


@dataclass(frozen=True, slots=True)
class ProbeContracts:
    """Readiness, liveness, identity, and artifact probe contracts."""

    readiness: ServiceProbe
    liveness: ServiceProbe
    identity: IdentityProbe
    artifact: ArtifactProbe

    def __post_init__(self) -> None:
        if not isinstance(self.readiness, ServiceProbe):
            raise TypeError("readiness must be ServiceProbe")
        if not isinstance(self.liveness, ServiceProbe):
            raise TypeError("liveness must be ServiceProbe")
        if not isinstance(self.identity, IdentityProbe):
            raise TypeError("identity must be IdentityProbe")
        if not isinstance(self.artifact, ArtifactProbe):
            raise TypeError("artifact must be ArtifactProbe")

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "readiness": self.readiness.as_dict(),
            "liveness": self.liveness.as_dict(),
            "identity": self.identity.as_dict(),
            "artifact": self.artifact.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class ResourceBudgets:
    """Bounded resource and lifecycle time budgets for one cell."""

    cpu_millis: int
    memory_bytes: int
    storage_bytes: int
    startup_timeout_ms: int
    probe_timeout_ms: int
    shutdown_timeout_ms: int
    job_timeout_ms: int

    def __post_init__(self) -> None:
        bounds = {
            "cpu_millis": (1, 64_000),
            "memory_bytes": (1_048_576, 1_099_511_627_776),
            "storage_bytes": (1_048_576, 17_592_186_044_416),
            "startup_timeout_ms": (1, 600_000),
            "probe_timeout_ms": (1, 60_000),
            "shutdown_timeout_ms": (1, 120_000),
            "job_timeout_ms": (1, 86_400_000),
        }
        for name, (minimum, maximum) in bounds.items():
            object.__setattr__(
                self,
                name,
                _integer(
                    getattr(self, name),
                    location=f"budgets.{name}",
                    minimum=minimum,
                    maximum=maximum,
                    code="invalid-budget",
                ),
            )
        if any(
            timeout > self.job_timeout_ms
            for timeout in (
                self.startup_timeout_ms,
                self.probe_timeout_ms,
                self.shutdown_timeout_ms,
            )
        ):
            _fail(
                "invalid-budget",
                "lifecycle timeouts cannot exceed job_timeout_ms",
                location="budgets",
            )

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "cpu_millis": self.cpu_millis,
            "memory_bytes": self.memory_bytes,
            "storage_bytes": self.storage_bytes,
            "startup_timeout_ms": self.startup_timeout_ms,
            "probe_timeout_ms": self.probe_timeout_ms,
            "shutdown_timeout_ms": self.shutdown_timeout_ms,
            "job_timeout_ms": self.job_timeout_ms,
        }


@dataclass(frozen=True, slots=True)
class RingCell:
    """One immutable cell in the fixed four-by-five yard."""

    track: str
    track_slot: int
    ring: str
    ring_slot: int
    rappid: str
    paths: CellPaths
    artifact: ArtifactContract
    ports: CellPorts
    probes: ProbeContracts
    budgets: ResourceBudgets

    def __post_init__(self) -> None:
        if type(self.track) is not str or self.track not in TRACKS:
            _fail(
                "invalid-topology",
                "cell track is not part of the closed topology",
                location="cell.track",
            )
        if type(self.ring) is not str or self.ring not in RINGS:
            _fail(
                "invalid-topology",
                "cell ring is not part of the closed topology",
                location="cell.ring",
            )
        track_slot = _integer(
            self.track_slot,
            location="cell.track_slot",
            minimum=0,
            maximum=len(TRACKS) - 1,
            code="invalid-topology",
        )
        ring_slot = _integer(
            self.ring_slot,
            location="cell.ring_slot",
            minimum=0,
            maximum=len(RINGS) - 1,
            code="invalid-topology",
        )
        if TRACKS[track_slot] != self.track or RINGS[ring_slot] != self.ring:
            _fail(
                "invalid-topology",
                "track/ring names must match their normative slots",
                location="cell",
            )
        object.__setattr__(self, "track_slot", track_slot)
        object.__setattr__(self, "ring_slot", ring_slot)
        object.__setattr__(
            self,
            "rappid",
            _rappid(self.rappid, location="cell.rappid"),
        )
        for name, expected in (
            ("paths", CellPaths),
            ("artifact", ArtifactContract),
            ("ports", CellPorts),
            ("probes", ProbeContracts),
            ("budgets", ResourceBudgets),
        ):
            if not isinstance(getattr(self, name), expected):
                raise TypeError(f"{name} must be {expected.__name__}")
        if self.ports != ports_for_cell(
            track_slot=track_slot,
            ring_slot=ring_slot,
        ):
            _fail(
                "invalid-port",
                "cell ports do not match the normative port formula",
                location="cell.ports",
            )
        if self.probes.identity.expected_rappid != self.rappid:
            _fail(
                "invalid-probe",
                "identity probe must attest the cell RAPPID",
                location="cell.probes.identity.expected_rappid",
            )
        if self.probes.artifact.expected_digest != self.artifact.digest:
            _fail(
                "invalid-probe",
                "artifact probe must attest the immutable artifact digest",
                location="cell.probes.artifact.expected_digest",
            )
        for name, probe in (
            ("readiness", self.probes.readiness),
            ("liveness", self.probes.liveness),
            ("identity", self.probes.identity),
            ("artifact", self.probes.artifact),
        ):
            if probe.timeout_ms > self.budgets.probe_timeout_ms:
                _fail(
                    "invalid-probe",
                    "probe timeout exceeds the cell probe budget",
                    location=f"cell.probes.{name}.timeout_ms",
                )

    @property
    def key(self) -> CellKey:
        return (self.track, self.ring)

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "track": self.track,
            "track_slot": self.track_slot,
            "ring": self.ring,
            "ring_slot": self.ring_slot,
            "rappid": self.rappid,
            "paths": self.paths.as_dict(),
            "artifact": self.artifact.as_dict(),
            "ports": self.ports.as_dict(),
            "probes": self.probes.as_dict(),
            "budgets": self.budgets.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class PromotionEdge:
    """One allowed directed promotion edge."""

    source_track: str
    source_ring: str
    target_track: str
    target_ring: str


@dataclass(frozen=True, slots=True)
class RingYardManifest:
    """A verified, deterministic twenty-cell ring-yard manifest."""

    spec: str
    yard: YardIdentity
    control_plane: ControlPlaneSettings
    cells: tuple[RingCell, ...]

    def __post_init__(self) -> None:
        if self.spec != RING_YARD_SPEC:
            _fail(
                "invalid-manifest-version",
                f"manifest spec must be {RING_YARD_SPEC}",
                location="spec",
            )
        if not isinstance(self.yard, YardIdentity):
            raise TypeError("yard must be YardIdentity")
        if not isinstance(self.control_plane, ControlPlaneSettings):
            raise TypeError("control_plane must be ControlPlaneSettings")
        try:
            cells = tuple(self.cells)
        except TypeError as exc:
            raise RingManifestError(
                _diagnostic(
                    "invalid-topology",
                    "cells must be an ordered array",
                    location="cells",
                )
            ) from exc
        if len(cells) != CELL_COUNT or any(
            not isinstance(cell, RingCell) for cell in cells
        ):
            _fail(
                "invalid-topology",
                "manifest must contain exactly 20 typed cells",
                location="cells",
                context={"cell_count": len(cells)},
            )
        expected = tuple(
            (track, track_slot, ring, ring_slot)
            for track_slot, track in enumerate(TRACKS)
            for ring_slot, ring in enumerate(RINGS)
        )
        actual = tuple(
            (cell.track, cell.track_slot, cell.ring, cell.ring_slot)
            for cell in cells
        )
        if actual != expected:
            _fail(
                "invalid-topology",
                "cells must use the normative track-major order and slots",
                location="cells",
            )
        rappids = tuple(cell.rappid for cell in cells)
        if len(rappids) != len(set(rappids)):
            _fail(
                "duplicate-rappid",
                "every cell must have a unique explicitly minted RAPPID",
                location="cells",
            )
        ports = tuple(
            port
            for cell in cells
            for port in (
                cell.ports.gateway,
                cell.ports.broker,
                cell.ports.control,
                cell.ports.metrics,
            )
        )
        if len(ports) != len(set(ports)):
            _fail(
                "duplicate-port",
                "endpoint ports must be unique across all cells",
                location="cells",
            )
        paths = tuple(
            (cell.key, name, getattr(cell.paths, name))
            for cell in cells
            for name in ("home", "state", "log", "cache", "tmp")
        )
        for index, (_, _, left) in enumerate(paths):
            left_parts = PurePosixPath(left).parts
            for _, _, right in paths[index + 1 :]:
                right_parts = PurePosixPath(right).parts
                shorter = min(len(left_parts), len(right_parts))
                if left_parts[:shorter] == right_parts[:shorter]:
                    _fail(
                        "overlapping-path",
                        "cell paths must not duplicate or contain one another",
                        location="cells.paths",
                        context={"left": left, "right": right},
                    )
        object.__setattr__(self, "cells", cells)

    @property
    def promotion_edges(self) -> tuple[PromotionEdge, ...]:
        """Return the nineteen normative progression and cross-track edges."""

        edges: list[PromotionEdge] = []
        for track_slot, track in enumerate(TRACKS):
            for ring_slot in range(len(RINGS) - 1):
                edges.append(
                    PromotionEdge(
                        track,
                        RINGS[ring_slot],
                        track,
                        RINGS[ring_slot + 1],
                    )
                )
            if track_slot + 1 < len(TRACKS):
                edges.append(
                    PromotionEdge(
                        track,
                        RINGS[-1],
                        TRACKS[track_slot + 1],
                        RINGS[0],
                    )
                )
        return tuple(edges)

    @property
    def peer_job_count(self) -> int:
        return self.control_plane.plan.peer_jobs

    @property
    def self_test_count(self) -> int:
        return self.control_plane.plan.self_tests

    @property
    def planned_job_count(self) -> int:
        return self.control_plane.plan.total_jobs

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "spec": self.spec,
            "yard": self.yard.as_dict(),
            "control_plane": self.control_plane.as_dict(),
            "cells": [cell.as_dict() for cell in self.cells],
        }

    def to_json_bytes(
        self,
        *,
        max_bytes: int = MAX_RING_YARD_MANIFEST_BYTES,
    ) -> bytes:
        """Return deterministic RFC 8785 canonical manifest bytes."""

        return canonicalize(self.as_dict(), max_bytes=max_bytes)

    @classmethod
    def from_json_bytes(
        cls,
        data: bytes | bytearray | memoryview,
        *,
        max_bytes: int = MAX_RING_YARD_MANIFEST_BYTES,
    ) -> RingYardManifest:
        """Parse and require a closed manifest from strict JSON bytes."""

        return verify_ring_yard_manifest(data, max_bytes=max_bytes)


DEFAULT_SCHEDULER_POLICY = SchedulerPolicy(4, 2, 1, 2, 256)
DEFAULT_RESOURCE_BUDGETS = ResourceBudgets(
    cpu_millis=1000,
    memory_bytes=536_870_912,
    storage_bytes=2_147_483_648,
    startup_timeout_ms=60_000,
    probe_timeout_ms=5_000,
    shutdown_timeout_ms=10_000,
    job_timeout_ms=3_600_000,
)


def _service_probe(value: JsonValue, *, location: str) -> ServiceProbe:
    document = _closed_object(
        value,
        keys=frozenset({"endpoint", "path", "timeout_ms", "interval_ms"}),
        location=location,
    )
    return ServiceProbe(
        document["endpoint"],
        document["path"],
        document["timeout_ms"],
        document["interval_ms"],
    )


def _identity_probe(value: JsonValue, *, location: str) -> IdentityProbe:
    document = _closed_object(
        value,
        keys=frozenset(
            {"endpoint", "path", "timeout_ms", "expected_rappid"}
        ),
        location=location,
    )
    return IdentityProbe(
        document["endpoint"],
        document["path"],
        document["timeout_ms"],
        document["expected_rappid"],
    )


def _artifact_probe(value: JsonValue, *, location: str) -> ArtifactProbe:
    document = _closed_object(
        value,
        keys=frozenset(
            {"endpoint", "path", "timeout_ms", "expected_digest"}
        ),
        location=location,
    )
    return ArtifactProbe(
        document["endpoint"],
        document["path"],
        document["timeout_ms"],
        document["expected_digest"],
    )


def _cell(value: JsonValue, *, index: int) -> RingCell:
    location = f"cells[{index}]"
    document = _closed_object(value, keys=_CELL_KEYS, location=location)
    paths = _closed_object(
        document["paths"],
        keys=frozenset({"home", "state", "log", "cache", "tmp"}),
        location=f"{location}.paths",
    )
    artifact = _closed_object(
        document["artifact"],
        keys=frozenset({"digest", "argv"}),
        location=f"{location}.artifact",
    )
    if type(artifact["argv"]) is not list:
        _fail(
            "invalid-argv",
            "artifact argv must be a JSON array",
            location=f"{location}.artifact.argv",
        )
    ports = _closed_object(
        document["ports"],
        keys=frozenset({"gateway", "broker", "control", "metrics"}),
        location=f"{location}.ports",
    )
    probes = _closed_object(
        document["probes"],
        keys=frozenset({"readiness", "liveness", "identity", "artifact"}),
        location=f"{location}.probes",
    )
    budgets = _closed_object(
        document["budgets"],
        keys=frozenset(
            {
                "cpu_millis",
                "memory_bytes",
                "storage_bytes",
                "startup_timeout_ms",
                "probe_timeout_ms",
                "shutdown_timeout_ms",
                "job_timeout_ms",
            }
        ),
        location=f"{location}.budgets",
    )
    return RingCell(
        track=document["track"],
        track_slot=document["track_slot"],
        ring=document["ring"],
        ring_slot=document["ring_slot"],
        rappid=document["rappid"],
        paths=CellPaths(**paths),
        artifact=ArtifactContract(
            artifact["digest"],
            tuple(artifact["argv"]),
        ),
        ports=CellPorts(**ports),
        probes=ProbeContracts(
            readiness=_service_probe(
                probes["readiness"],
                location=f"{location}.probes.readiness",
            ),
            liveness=_service_probe(
                probes["liveness"],
                location=f"{location}.probes.liveness",
            ),
            identity=_identity_probe(
                probes["identity"],
                location=f"{location}.probes.identity",
            ),
            artifact=_artifact_probe(
                probes["artifact"],
                location=f"{location}.probes.artifact",
            ),
        ),
        budgets=ResourceBudgets(**budgets),
    )


def _manifest(value: JsonValue) -> RingYardManifest:
    document = _closed_object(
        value,
        keys=frozenset({"spec", "yard", "control_plane", "cells"}),
        location="manifest",
    )
    yard = _closed_object(
        document["yard"],
        keys=frozenset({"identity", "root"}),
        location="yard",
    )
    control_plane = _closed_object(
        document["control_plane"],
        keys=frozenset({"scheduler", "plan"}),
        location="control_plane",
    )
    scheduler = _closed_object(
        control_plane["scheduler"],
        keys=frozenset(
            {
                "global_jobs",
                "per_track_jobs",
                "per_observer_jobs",
                "per_subject_jobs",
                "ready_queue",
            }
        ),
        location="control_plane.scheduler",
    )
    plan = _closed_object(
        control_plane["plan"],
        keys=frozenset({"peer_jobs", "self_tests", "total_jobs"}),
        location="control_plane.plan",
    )
    if type(document["cells"]) is not list:
        _fail(
            "invalid-topology",
            "cells must be an ordered JSON array",
            location="cells",
        )
    seen_ports: set[int] = set()
    seen_rappids: set[str] = set()
    for cell in document["cells"]:
        if type(cell) is not dict:
            continue
        rappid = cell.get("rappid")
        if type(rappid) is str:
            if rappid in seen_rappids:
                _fail(
                    "duplicate-rappid",
                    "every cell must have a unique explicitly minted RAPPID",
                    location="cells",
                )
            seen_rappids.add(rappid)
        if type(cell.get("ports")) is not dict:
            continue
        for port in cell["ports"].values():
            if isinstance(port, int) and not isinstance(port, bool):
                if int(port) in seen_ports:
                    _fail(
                        "duplicate-port",
                        "endpoint ports must be unique across all cells",
                        location="cells.ports",
                        context={"port": int(port)},
                    )
                seen_ports.add(int(port))
    cells = tuple(
        _cell(cell, index=index)
        for index, cell in enumerate(document["cells"])
    )
    return RingYardManifest(
        spec=document["spec"],
        yard=YardIdentity(**yard),
        control_plane=ControlPlaneSettings(
            SchedulerPolicy(**scheduler),
            PlanCardinality(**plan),
        ),
        cells=cells,
    )


def check_ring_yard_manifest(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = MAX_RING_YARD_MANIFEST_BYTES,
) -> VerificationReport[RingYardManifest]:
    """Parse and validate strict JSON bytes without raising content errors."""

    try:
        value = strict_json_loads(data, max_bytes=max_bytes)
        manifest = _manifest(value)
    except RingManifestError as exc:
        return VerificationReport(None, (exc.diagnostic,))
    except ProtocolError as exc:
        diagnostic = exc.diagnostic
        return VerificationReport(
            None,
            (
                Diagnostic(
                    code=diagnostic.code,
                    operation="ring-manifest",
                    message=diagnostic.message,
                    protocol_step=diagnostic.protocol_step,
                    location=diagnostic.location or "manifest",
                    context=diagnostic.context,
                    remediation=diagnostic.remediation,
                ),
            ),
        )
    return VerificationReport(manifest)


def check_ring_yard_manifest_semantics(
    document: Mapping[str, JsonValue],
    *,
    max_bytes: int = MAX_RING_YARD_MANIFEST_BYTES,
) -> VerificationReport[RingYardManifest]:
    """Apply the mandatory semantic companion to the packaged JSON Schema.

    Draft 2020-12 cannot express cross-cell uniqueness, cross-field equality,
    relative numeric bounds, or aggregate argv byte limits. Call this function
    after schema validation of a decoded JSON object, or use
    :func:`check_ring_yard_manifest` directly for untrusted JSON bytes.
    Validation uses a detached container snapshot that preserves scalar types;
    canonical serialization and its size check occur only after validation.
    """

    if not isinstance(document, Mapping):
        raise TypeError("ring-yard semantic validation accepts a mapping")
    try:
        snapshot = _snapshot_json(dict(document))
        manifest = _manifest(snapshot)
        canonicalize(manifest.as_dict(), max_bytes=max_bytes)
    except RingManifestError as exc:
        return VerificationReport(None, (exc.diagnostic,))
    except ProtocolError as exc:
        diagnostic = exc.diagnostic
        return VerificationReport(
            None,
            (
                Diagnostic(
                    code=diagnostic.code,
                    operation="ring-manifest",
                    message=diagnostic.message,
                    protocol_step=diagnostic.protocol_step,
                    location=diagnostic.location or "manifest",
                    context=diagnostic.context,
                    remediation=diagnostic.remediation,
                ),
            ),
        )
    return VerificationReport(manifest)


def verify_ring_yard_manifest(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = MAX_RING_YARD_MANIFEST_BYTES,
) -> RingYardManifest:
    """Return a verified manifest or raise :class:`RingManifestError`."""

    return check_ring_yard_manifest(data, max_bytes=max_bytes).require(
        RingManifestError
    )


def build_default_ring_yard_manifest(
    *,
    yard_identity: str,
    yard_root: str,
    artifact_digest: str,
    argv: Sequence[str],
    rappids: Mapping[CellKey, str] | None = None,
    mint_rappid: MintRappid | None = None,
    scheduler: SchedulerPolicy | None = None,
    budgets: ResourceBudgets | None = None,
) -> RingYardManifest:
    """Build the normative layout using caller-owned cell identities.

    Exactly one of ``rappids`` or ``mint_rappid`` is required. The SDK never
    derives identity from track, ring, path, or display text.
    """

    if (rappids is None) == (mint_rappid is None):
        _fail(
            "missing-rappids",
            "provide exactly one complete RAPPID mapping or mint callback",
            location="rappids",
        )
    coordinates = tuple(
        (track, ring)
        for track in TRACKS
        for ring in RINGS
    )
    if rappids is not None:
        provided = dict(rappids)
        if frozenset(provided) != frozenset(coordinates):
            _fail(
                "missing-rappids",
                "RAPPID mapping must contain exactly the 20 topology keys",
                location="rappids",
                context={
                    "expected": CELL_COUNT,
                    "provided": len(provided),
                },
            )
        identities = {key: provided[key] for key in coordinates}
    else:
        assert mint_rappid is not None
        identities = {
            key: mint_rappid(*key)
            for key in coordinates
        }
    artifact = ArtifactContract(artifact_digest, tuple(argv))
    selected_scheduler = scheduler or DEFAULT_SCHEDULER_POLICY
    selected_budgets = budgets or DEFAULT_RESOURCE_BUDGETS
    if not isinstance(selected_scheduler, SchedulerPolicy):
        raise TypeError("scheduler must be SchedulerPolicy or None")
    if not isinstance(selected_budgets, ResourceBudgets):
        raise TypeError("budgets must be ResourceBudgets or None")
    cells = []
    for track_slot, track in enumerate(TRACKS):
        for ring_slot, ring in enumerate(RINGS):
            rappid = identities[(track, ring)]
            prefix = f"cells/{track}/{ring}"
            cells.append(
                RingCell(
                    track=track,
                    track_slot=track_slot,
                    ring=ring,
                    ring_slot=ring_slot,
                    rappid=rappid,
                    paths=CellPaths(
                        home=f"{prefix}/home",
                        state=f"{prefix}/state",
                        log=f"{prefix}/log",
                        cache=f"{prefix}/cache",
                        tmp=f"{prefix}/tmp",
                    ),
                    artifact=artifact,
                    ports=ports_for_cell(
                        track_slot=track_slot,
                        ring_slot=ring_slot,
                    ),
                    probes=ProbeContracts(
                        readiness=ServiceProbe(
                            "gateway",
                            "/readyz",
                            1000,
                            2000,
                        ),
                        liveness=ServiceProbe(
                            "gateway",
                            "/livez",
                            1000,
                            10_000,
                        ),
                        identity=IdentityProbe(
                            "control",
                            "/identity",
                            1000,
                            rappid,
                        ),
                        artifact=ArtifactProbe(
                            "control",
                            "/artifact",
                            1000,
                            artifact.digest,
                        ),
                    ),
                    budgets=selected_budgets,
                )
            )
    return RingYardManifest(
        spec=RING_YARD_SPEC,
        yard=YardIdentity(yard_identity, yard_root),
        control_plane=ControlPlaneSettings(
            selected_scheduler,
            PlanCardinality(),
        ),
        cells=tuple(cells),
    )


__all__ = (
    "ArtifactContract",
    "ArtifactProbe",
    "BASE_PORT",
    "CELL_COUNT",
    "CellKey",
    "CellPaths",
    "CellPorts",
    "ControlPlaneSettings",
    "DEFAULT_RESOURCE_BUDGETS",
    "DEFAULT_SCHEDULER_POLICY",
    "ENDPOINT_OFFSETS",
    "IdentityProbe",
    "MAX_RING_YARD_MANIFEST_BYTES",
    "MintRappid",
    "PEER_JOB_COUNT",
    "PLANNED_JOB_COUNT",
    "PlanCardinality",
    "ProbeContracts",
    "PromotionEdge",
    "RINGS",
    "RING_PORT_STRIDE",
    "RING_YARD_SPEC",
    "ResourceBudgets",
    "RingCell",
    "RingYardManifest",
    "SELF_TEST_COUNT",
    "SchedulerPolicy",
    "ServiceProbe",
    "TRACKS",
    "TRACK_PORT_STRIDE",
    "YardIdentity",
    "build_default_ring_yard_manifest",
    "check_ring_yard_manifest",
    "check_ring_yard_manifest_semantics",
    "ports_for_cell",
    "verify_ring_yard_manifest",
)
