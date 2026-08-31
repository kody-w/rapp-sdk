"""Typed RAPP Projects protocol helpers built on the strict RAPP/1 core."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from .errors import ProjectProtocolError
from .protocol import (
    Frame,
    FrameMapping,
    JsonObject,
    JsonValue,
    KindFamilyRegistry,
    VerifiedStream,
    H,
    Hb,
    build_frame_mapping,
    canonicalize,
    strict_json_loads,
    verify_stream_local,
)

PROJECT_FRAME_KIND = "body.pulse"
PROJECT_FRAME_KINDS = (PROJECT_FRAME_KIND,)
PROJECT_EVENTS = (
    "project.genesis",
    "work.punchin",
    "work.heartbeat",
    "work.checkpoint",
    "work.status",
    "work.handoff",
    "work.takeover",
    "work.punchout",
    "cell.policy",
    "cell.cycle",
    "cell.absorb",
    "project.verify",
)
PROJECT_EGG_SCHEMA = "rapp/1-egg"
PROJECT_EGG_VARIANT = "organism"
IRREVERSIBLE_ACTION_CLASSES = frozenset(
    {"send", "sign", "pay", "purchase", "delete_external", "publish_remote"}
)
MAX_PROJECT_EGG_BYTES = 64 * 1024 * 1024
MAX_PROJECT_EGG_ENTRIES = 10_000
MAX_PROJECT_EGG_ENTRY_BYTES = 32 * 1024 * 1024
_LABEL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
    r"[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
    re.ASCII,
)
_RAPPID = re.compile(
    r"^rappid:@(?P<owner>[a-z0-9]+(?:-[a-z0-9]+)*)/"
    r"(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*):(?P<tail>[0-9a-f]{64})$",
    re.ASCII,
)

_REQUIRED = {
    "project.genesis": (
        "project", "title", "goal", "owner", "origin", "visibility",
    ),
    "work.punchin": (
        "project", "actor", "location", "intent", "role",
        "lease_expires_utc",
    ),
    "work.heartbeat": (
        "project", "actor", "lease_expires_utc", "status",
    ),
    "work.checkpoint": (
        "project", "actor", "summary", "completed", "in_progress",
        "next_action", "resume", "workspace", "commands", "artifacts",
    ),
    "work.status": (
        "project", "actor", "location", "status", "artifacts",
        "blockers", "next_action", "pct",
    ),
    "work.handoff": (
        "project", "from_actor", "to_actor", "document", "open_questions",
    ),
    "work.takeover": (
        "project", "from_actor", "to_actor", "location", "reason",
        "expired_lease_frame_hash", "lease_expires_utc",
    ),
    "work.punchout": (
        "project", "actor", "outcome", "receipts", "summary",
    ),
    "cell.absorb": (
        "project", "actor", "source", "adopted", "rejected",
        "summary", "receipts",
    ),
    "cell.policy": (
        "project", "actor", "cadence_seconds", "may", "never",
        "budgets", "stop_conditions", "human_gates", "next_wakeup_utc",
    ),
    "cell.cycle": (
        "project", "actor", "cycle", "observations", "proposed",
        "applied", "rejected", "action_classes", "elapsed_seconds",
        "receipts", "next_wakeup_utc",
    ),
    "project.verify": (
        "project", "verdict", "broken_receipts", "verified_frames",
        "head_frame_hash",
    ),
}


def _error(code: str, message: str, **context: object) -> ProjectProtocolError:
    return ProjectProtocolError(
        code,
        message,
        context={
            key: value
            for key, value in context.items()
            if value is None or isinstance(value, (str, int, bool))
        },
    )


def _label(
    value: str,
    field_name: str,
    *,
    maximum: int = 100,
) -> str:
    if (
        not isinstance(value, str)
        or not _LABEL.fullmatch(value)
        or len(value.encode("utf-8")) > maximum
    ):
        raise _error(
            "invalid-project-label",
            f"{field_name} is not a RAPP label",
            field=field_name,
            value=str(value),
        )
    return value


def _string(value: object, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise _error(
            "invalid-project-field",
            f"{field_name} must be a non-empty string",
            field=field_name,
        )
    return value


def _strings(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) for item in value
    ):
        raise _error(
            "invalid-project-field",
            f"{field_name} must be an array of strings",
            field=field_name,
        )
    return tuple(value)


def _mapping(value: object, field_name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise _error(
            "invalid-project-field",
            f"{field_name} must be an object",
            field=field_name,
        )
    return value


def _integer(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = 2**53 - 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise _error(
            "invalid-project-field",
            f"{field_name} must be an integer in range",
            field=field_name,
        )
    return value


def _utc(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise _error(
            "invalid-project-utc",
            f"{field_name} must use fixed RAPP UTC form",
            field=field_name,
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise _error(
            "invalid-project-utc",
            f"{field_name} is not a calendar-valid UTC timestamp",
            field=field_name,
        ) from exc
    return value


def _hash(value: object, field_name: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise _error(
            "invalid-project-head",
            f"{field_name} must be 64 lowercase hex",
            field=field_name,
        )
    return value


def _actor(value: object, field_name: str) -> ProjectActor:
    actor = _mapping(value, field_name)
    model = actor.get("model")
    host = actor.get("host")
    if model is not None and not isinstance(model, str):
        raise _error(
            "invalid-project-actor",
            f"{field_name}.model must be a string",
        )
    if host is not None and not isinstance(host, str):
        raise _error(
            "invalid-project-actor",
            f"{field_name}.host must be a string",
        )
    return ProjectActor(
        id=_string(actor.get("id"), f"{field_name}.id"),
        runtime=_string(actor.get("runtime"), f"{field_name}.runtime"),
        session_id=_string(
            actor.get("session_id"),
            f"{field_name}.session_id",
        ),
        capabilities=_strings(
            actor.get("capabilities"),
            f"{field_name}.capabilities",
        ),
        model=model,
        host=host,
    )


def _receipts(value: object, field_name: str) -> tuple[Mapping[str, JsonValue], ...]:
    if not isinstance(value, (list, tuple)):
        raise _error(
            "invalid-project-field",
            f"{field_name} must be an array",
            field=field_name,
        )
    rows = []
    for index, item in enumerate(value):
        row = _mapping(item, f"{field_name}[{index}]")
        path = _string(row.get("path"), f"{field_name}[{index}].path")
        scope = row.get("scope")
        if scope is not None and scope != "project":
            raise _error(
                "invalid-project-field",
                f"{field_name}[{index}].scope must be project when present",
            )
        if scope == "project":
            _safe_entry(path)
        digest = row.get("sha256")
        if digest is not None:
            _hash(digest, f"{field_name}[{index}].sha256")
        rows.append(row)
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class ProjectActor:
    id: str
    runtime: str
    session_id: str
    capabilities: tuple[str, ...] = ()
    model: str | None = None
    host: str | None = None

    def __post_init__(self) -> None:
        _string(self.id, "actor.id")
        _string(self.runtime, "actor.runtime")
        _string(self.session_id, "actor.session_id")
        _strings(self.capabilities, "actor.capabilities")
        if self.model is not None:
            _string(self.model, "actor.model")
        if self.host is not None:
            _string(self.host, "actor.host")

    def as_payload(self) -> JsonObject:
        payload: JsonObject = {
            "id": self.id,
            "runtime": self.runtime,
            "session_id": self.session_id,
            "capabilities": list(self.capabilities),
        }
        if self.model is not None:
            payload["model"] = self.model
        if self.host is not None:
            payload["host"] = self.host
        return payload


@dataclass(frozen=True, slots=True)
class ProjectCheckpoint:
    summary: str
    completed: tuple[str, ...]
    in_progress: str
    next_action: str
    resume_prompt: str
    cwd: str
    repository: str
    branch: str
    head: str
    dirty_paths: tuple[str, ...]
    commands: tuple[str, ...]
    artifacts: tuple[JsonValue, ...]

    def __post_init__(self) -> None:
        for field_name in (
            "summary", "in_progress", "next_action", "resume_prompt",
            "cwd", "repository", "branch", "head",
        ):
            _string(getattr(self, field_name), field_name, allow_empty=False)
        _strings(self.completed, "completed")
        _strings(self.dirty_paths, "dirty_paths")
        _strings(self.commands, "commands")

    def as_payload(self) -> JsonObject:
        return {
            "summary": self.summary,
            "completed": list(self.completed),
            "in_progress": self.in_progress,
            "next_action": self.next_action,
            "resume": {"prompt": self.resume_prompt},
            "workspace": {
                "cwd": self.cwd,
                "repository": self.repository,
                "branch": self.branch,
                "head": self.head,
                "dirty_paths": list(self.dirty_paths),
            },
            "commands": list(self.commands),
            "artifacts": list(self.artifacts),
        }


def build_project_rappid(owner: str, slug: str, entropy: bytes) -> str:
    owner = _label(owner, "owner", maximum=39)
    slug = _label(slug, "slug", maximum=100)
    if not isinstance(entropy, bytes) or not entropy:
        raise _error(
            "invalid-project-entropy",
            "entropy must be non-empty bytes",
        )
    tail = hashlib.sha256(b"rapp/1:rappid\n" + entropy).hexdigest()
    return f"rappid:@{owner}/{slug}:{tail}"


def validate_project_payload(kind: str, payload: Mapping[str, JsonValue]) -> None:
    if kind not in PROJECT_EVENTS:
        raise _error(
            "unknown-project-kind",
            "kind is not registered by RAPP Projects",
            kind=kind,
        )
    if not isinstance(payload, Mapping):
        raise _error(
            "invalid-project-payload",
            "payload must be an object",
            kind=kind,
        )
    missing = [
        field_name for field_name in _REQUIRED[kind]
        if field_name not in payload
    ]
    if missing:
        raise _error(
            "missing-project-field",
            "project payload is missing required fields",
            kind=kind,
            missing=",".join(missing),
        )
    _label(_string(payload["project"], "project"), "project", maximum=100)

    if kind == "project.genesis":
        for field_name in ("title", "goal", "owner", "origin"):
            _string(payload[field_name], field_name)
        if payload["visibility"] not in ("local", "team", "public"):
            raise _error(
                "invalid-project-visibility",
                "visibility must be local, team, or public",
            )
        return

    if "actor" in payload:
        _actor(payload["actor"], "actor")

    if kind == "work.punchin":
        for field_name in ("location", "intent", "role"):
            _string(payload[field_name], field_name)
        _utc(payload["lease_expires_utc"], "lease_expires_utc")
    elif kind == "work.heartbeat":
        _string(payload["status"], "status")
        _utc(payload["lease_expires_utc"], "lease_expires_utc")
    elif kind == "work.checkpoint":
        for field_name in ("summary", "in_progress", "next_action"):
            _string(payload[field_name], field_name)
        _strings(payload["completed"], "completed")
        resume = _mapping(payload["resume"], "resume")
        _string(resume.get("prompt"), "resume.prompt")
        workspace = _mapping(payload["workspace"], "workspace")
        for field_name in ("cwd", "repository", "branch", "head"):
            _string(workspace.get(field_name), f"workspace.{field_name}")
        _strings(workspace.get("dirty_paths"), "workspace.dirty_paths")
        _strings(payload["commands"], "commands")
        _receipts(payload["artifacts"], "artifacts")
    elif kind == "work.status":
        for field_name in ("location", "status", "next_action"):
            _string(payload[field_name], field_name)
        _receipts(payload["artifacts"], "artifacts")
        _strings(payload["blockers"], "blockers")
        _integer(payload["pct"], "pct", maximum=100)
    elif kind == "work.handoff":
        _actor(payload["from_actor"], "from_actor")
        _actor(payload["to_actor"], "to_actor")
        _receipts([payload["document"]], "document")
        _strings(payload["open_questions"], "open_questions")
    elif kind == "work.takeover":
        from_actor = payload["from_actor"]
        if from_actor != {}:
            _actor(from_actor, "from_actor")
        _actor(payload["to_actor"], "to_actor")
        for field_name in ("location", "reason"):
            _string(payload[field_name], field_name)
        _hash(
            payload["expired_lease_frame_hash"],
            "expired_lease_frame_hash",
            nullable=True,
        )
        _utc(payload["lease_expires_utc"], "lease_expires_utc")
    elif kind == "work.punchout":
        if payload["outcome"] not in ("done", "blocked", "abandoned"):
            raise _error(
                "invalid-project-field",
                "outcome must be done, blocked, or abandoned",
                field="outcome",
            )
        _receipts(payload["receipts"], "receipts")
        _string(payload["summary"], "summary", allow_empty=True)
    elif kind == "cell.absorb":
        source = _mapping(payload["source"], "source")
        _string(source.get("uri"), "source.uri")
        _hash(source.get("sha256"), "source.sha256")
        _string(source.get("license"), "source.license")
        if not _strings(payload["adopted"], "adopted"):
            raise _error(
                "invalid-project-field",
                "adopted must contain at least one item",
                field="adopted",
            )
        _strings(payload["rejected"], "rejected")
        _string(payload["summary"], "summary")
        _receipts(payload["receipts"], "receipts")
    elif kind == "cell.policy":
        _integer(payload["cadence_seconds"], "cadence_seconds", minimum=1)
        _strings(payload["may"], "may")
        _strings(payload["never"], "never")
        budgets = _mapping(payload["budgets"], "budgets")
        _integer(budgets.get("max_cycles"), "budgets.max_cycles", minimum=1)
        _integer(
            budgets.get("max_seconds_per_cycle"),
            "budgets.max_seconds_per_cycle",
            minimum=1,
        )
        _strings(payload["stop_conditions"], "stop_conditions")
        _strings(payload["human_gates"], "human_gates")
        _utc(payload["next_wakeup_utc"], "next_wakeup_utc")
    elif kind == "cell.cycle":
        _integer(payload["cycle"], "cycle", minimum=1)
        for field_name in (
            "observations", "proposed", "applied", "rejected",
            "action_classes",
        ):
            _strings(payload[field_name], field_name)
        _integer(payload["elapsed_seconds"], "elapsed_seconds")
        _receipts(payload["receipts"], "receipts")
        _utc(payload["next_wakeup_utc"], "next_wakeup_utc")
    elif kind == "project.verify":
        if payload["verdict"] not in ("pass", "fail"):
            raise _error(
                "invalid-project-field",
                "verdict must be pass or fail",
                field="verdict",
            )
        if not isinstance(payload["broken_receipts"], (list, tuple)):
            raise _error(
                "invalid-project-field",
                "broken_receipts must be an array",
                field="broken_receipts",
            )
        _integer(payload["verified_frames"], "verified_frames")
        _hash(payload["head_frame_hash"], "head_frame_hash")


def build_project_frame(
    kind: str,
    stream_id: str,
    seq: int,
    utc: str,
    payload: Mapping[str, JsonValue],
    prev: str | None,
) -> Frame:
    validate_project_payload(kind, payload)
    payload_object = dict(payload)
    if "event" in payload_object and payload_object["event"] != kind:
        raise _error(
            "invalid-project-payload",
            "payload event does not match the requested project event",
        )
    payload_object["event"] = kind
    return build_frame_mapping(
        PROJECT_FRAME_KIND,
        stream_id,
        seq,
        utc,
        payload_object,
        prev,
    )


def project_kind_registry(
    *,
    stream_id: str | None = None,
    genesis_frame_hash: str | None = None,
) -> KindFamilyRegistry:
    genesis = {}
    if stream_id is not None or genesis_frame_hash is not None:
        if stream_id is None or genesis_frame_hash is None:
            raise _error(
                "incomplete-project-trust",
                "stream_id and genesis_frame_hash must be supplied together",
            )
        genesis[stream_id] = genesis_frame_hash
    return KindFamilyRegistry.local(
        {PROJECT_FRAME_KIND: "body"},
        genesis_hashes=genesis,
        registry_id="rapp-projects/protocol/1",
    )


def verify_project_stream(
    frames: list[FrameMapping] | tuple[FrameMapping, ...],
    expected_stream_id: str,
) -> VerifiedStream:
    if not frames:
        raise _error(
            "empty-project-stream",
            "project stream must contain a genesis frame",
        )
    registry = project_kind_registry()
    try:
        verified = verify_stream_local(
            frames,
            registry=registry,
            expected_stream_id=expected_stream_id,
        )
    except Exception as exc:
        if isinstance(exc, ProjectProtocolError):
            raise
        raise
    first = frames[0]
    first_payload = first.get("payload")
    if (
        not isinstance(first_payload, Mapping)
        or first_payload.get("event") != "project.genesis"
    ):
        raise _error(
            "invalid-project-payload",
            "project stream must begin with project.genesis",
        )
    if any(
        isinstance(frame.get("payload"), Mapping)
        and frame["payload"].get("event") == "project.genesis"
        for frame in frames[1:]
    ):
        raise _error(
            "invalid-project-payload",
            "project.genesis may appear only at sequence zero",
        )
    genesis_payload = first_payload
    if not isinstance(genesis_payload, Mapping):
        raise _error(
            "invalid-project-payload",
            "project genesis payload must be an object",
        )
    project = _label(
        _string(genesis_payload.get("project"), "project"),
        "project",
        maximum=100,
    )
    match = _RAPPID.fullmatch(expected_stream_id)
    if match is None:
        raise _error(
            "invalid-project-label",
            "expected_stream_id is not a RAPPID",
        )
    if match.group("slug") != project:
        raise _error(
            "invalid-project-label",
            "project genesis does not match the RAPPID slug",
            project=project,
            slug=match.group("slug"),
        )
    for frame in frames:
        payload = frame.get("payload")
        if not isinstance(payload, Mapping):
            raise _error(
                "invalid-project-payload",
                "project frame payload must be an object",
            )
        event = payload.get("event")
        if not isinstance(event, str):
            raise _error(
                "invalid-project-payload",
                "project frame payload must declare an event",
            )
        validate_project_payload(event, payload)
        if not isinstance(payload, Mapping) or payload.get("project") != project:
            raise _error(
                "invalid-project-payload",
                "every frame payload must name the genesis project",
                project=project,
            )
    _validate_project_transitions(frames)
    return verified


def _actor_key(value: object) -> tuple[object, object, object] | None:
    if not isinstance(value, Mapping):
        return None
    return (
        value.get("id"),
        value.get("runtime"),
        value.get("session_id"),
    )


def _transition_error(message: str, *, seq: object) -> ProjectProtocolError:
    return _error(
        "invalid-project-payload",
        message,
        seq=seq if isinstance(seq, int) else str(seq),
    )


def _validate_project_transitions(
    frames: list[FrameMapping] | tuple[FrameMapping, ...],
) -> None:
    actor: Mapping[str, JsonValue] | None = None
    lease: str | None = None
    lease_frame_hash: str | None = None
    policy: Mapping[str, JsonValue] | None = None
    cycles = 0

    def require_owner(frame: FrameMapping, *, active: bool = True) -> None:
        nonlocal actor, lease
        payload = frame["payload"]
        candidate = payload.get("actor")
        if actor is None or _actor_key(candidate) != _actor_key(actor):
            raise _transition_error(
                "frame actor does not own the project lease",
                seq=frame.get("seq"),
            )
        if active and (
            lease is None or lease <= str(frame.get("utc"))
        ):
            raise _transition_error(
                "frame requires an active, unexpired lease",
                seq=frame.get("seq"),
            )

    for frame in frames[1:]:
        payload = frame["payload"]
        kind = str(payload["event"])
        frame_utc = str(frame["utc"])
        if kind == "work.punchin":
            candidate = payload["actor"]
            if actor is not None and _actor_key(candidate) != _actor_key(actor):
                raise _transition_error(
                    "foreign punchin requires work.takeover or work.handoff",
                    seq=frame.get("seq"),
                )
            actor = candidate
            lease = str(payload["lease_expires_utc"])
            if lease <= frame_utc:
                raise _transition_error(
                    "punchin lease must expire after the frame",
                    seq=frame.get("seq"),
                )
            lease_frame_hash = str(frame["frame_hash"])
        elif kind == "work.heartbeat":
            require_owner(frame, active=True)
            actor = payload["actor"]
            lease = str(payload["lease_expires_utc"])
            if lease <= frame_utc:
                raise _transition_error(
                    "heartbeat lease must expire after the frame",
                    seq=frame.get("seq"),
                )
            lease_frame_hash = str(frame["frame_hash"])
        elif kind in ("work.checkpoint", "work.status", "cell.absorb"):
            require_owner(frame)
        elif kind == "work.handoff":
            if actor is None or _actor_key(payload["from_actor"]) != _actor_key(actor):
                raise _transition_error(
                    "handoff source does not own the active lease",
                    seq=frame.get("seq"),
                )
            if lease is None or lease <= frame_utc:
                raise _transition_error(
                    "handoff requires an active lease",
                    seq=frame.get("seq"),
                )
            actor = payload["to_actor"]
            lease = None
            lease_frame_hash = None
        elif kind == "work.takeover":
            if actor is not None:
                if lease is None:
                    raise _transition_error(
                        "handoff ownership requires punchin, not takeover",
                        seq=frame.get("seq"),
                    )
                if lease > frame_utc:
                    raise _transition_error(
                        "takeover occurred before lease expiry",
                        seq=frame.get("seq"),
                    )
            expected_from = actor or {}
            if payload["from_actor"] != expected_from:
                raise _transition_error(
                    "takeover from_actor does not match current ownership",
                    seq=frame.get("seq"),
                )
            expected_receipt = lease_frame_hash if actor is not None else None
            if payload["expired_lease_frame_hash"] != expected_receipt:
                raise _transition_error(
                    "takeover lease receipt does not match current lease frame",
                    seq=frame.get("seq"),
                )
            actor = payload["to_actor"]
            lease = str(payload["lease_expires_utc"])
            if lease <= frame_utc:
                raise _transition_error(
                    "takeover lease must expire after the frame",
                    seq=frame.get("seq"),
                )
            lease_frame_hash = str(frame["frame_hash"])
        elif kind == "work.punchout":
            require_owner(frame)
            actor = None
            lease = None
            lease_frame_hash = None
        elif kind == "cell.policy":
            require_owner(frame)
            may = set(payload["may"])
            never = set(payload["never"])
            if may & IRREVERSIBLE_ACTION_CLASSES:
                raise _transition_error(
                    "cell policy allows an irreversible action",
                    seq=frame.get("seq"),
                )
            if not IRREVERSIBLE_ACTION_CLASSES.issubset(never):
                raise _transition_error(
                    "cell policy does not forbid every irreversible action",
                    seq=frame.get("seq"),
                )
            policy = payload
        elif kind == "cell.cycle":
            require_owner(frame)
            if policy is None:
                raise _transition_error(
                    "cell cycle has no policy",
                    seq=frame.get("seq"),
                )
            cycles += 1
            if payload["cycle"] != cycles:
                raise _transition_error(
                    "cell cycle number is not contiguous",
                    seq=frame.get("seq"),
                )
            budgets = policy["budgets"]
            if cycles > budgets["max_cycles"]:
                raise _transition_error(
                    "cell cycle budget exceeded",
                    seq=frame.get("seq"),
                )
            if payload["elapsed_seconds"] > budgets["max_seconds_per_cycle"]:
                raise _transition_error(
                    "cell cycle time budget exceeded",
                    seq=frame.get("seq"),
                )
            classes = set(payload["action_classes"])
            if not classes.issubset(set(policy["may"])):
                raise _transition_error(
                    "cell cycle action is outside policy may",
                    seq=frame.get("seq"),
                )
            if classes & set(policy["never"]):
                raise _transition_error(
                    "cell cycle used a forbidden action",
                    seq=frame.get("seq"),
                )


def _entry_hash(value: bytes) -> str:
    return Hb("rapp/1:egg", value)


def project_egg_address(manifest: Mapping[str, JsonValue]) -> str:
    """Return the normative RAPP/1 egg-manifest address."""

    return H(
        "rapp/1:egg-manifest",
        {key: value for key, value in manifest.items() if key != "sig"},
    )


def _safe_entry(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise _error(
            "unsafe-project-egg-path",
            "project egg path is not a safe relative POSIX path",
            path=str(path),
        )
    return path


def build_project_egg_manifest(
    *,
    project: str,
    rappid: str,
    head_frame_hash: str,
    visibility: str,
    contents: Mapping[str, bytes],
    created_utc: str,
) -> JsonObject:
    _label(project, "project", maximum=100)
    match = _RAPPID.fullmatch(_string(rappid, "rappid"))
    if match is None or match.group("slug") != project:
        raise _error(
            "invalid-project-label",
            "rappid must be valid and its slug must equal project",
        )
    if not _HEX64.fullmatch(head_frame_hash):
        raise _error(
            "invalid-project-head",
            "head_frame_hash must be 64 lowercase hex",
        )
    if visibility not in ("local", "team", "public"):
        raise _error(
            "invalid-project-visibility",
            "visibility must be local, team, or public",
        )
    _utc(created_utc, "created_utc")
    if len(contents) > MAX_PROJECT_EGG_ENTRIES:
        raise _error(
            "project-egg-entry-set",
            "project egg contains too many entries",
        )
    total_bytes = 0
    for value in contents.values():
        if not isinstance(value, bytes):
            raise _error(
                "invalid-project-egg-entry",
                "project egg values must be bytes",
            )
        total_bytes += len(value)
    if total_bytes > MAX_PROJECT_EGG_BYTES:
        raise _error(
            "invalid-project-egg-entry",
            "project egg contents exceed the size limit",
        )
    for required_path in ("rappid.json", "soul.md"):
        if required_path not in contents:
            raise _error(
                "project-egg-entry-set",
                f"organism egg must include {required_path}",
            )
    rows = []
    for path, value in sorted(
        contents.items(),
        key=lambda item: item[0].encode("utf-8"),
    ):
        path = _safe_entry(path)
        if path == "manifest.json":
            raise _error(
                "project-egg-entry-set",
                "manifest.json must not appear in contents",
            )
        if not isinstance(value, bytes):
            raise _error(
                "invalid-project-egg-entry",
                "project egg values must be bytes",
                path=path,
            )
        if len(value) > MAX_PROJECT_EGG_ENTRY_BYTES:
            raise _error(
                "invalid-project-egg-entry",
                "project egg entry exceeds the size limit",
                path=path,
            )
        rows.append({
            "path": path,
            "hash": _entry_hash(value),
        })
    return {
        "schema": PROJECT_EGG_SCHEMA,
        "variant": PROJECT_EGG_VARIANT,
        "rappid": rappid,
        "created_utc": created_utc,
        "contents": rows,
        "payload": {
            "protocol": "rapp-projects/1",
            "cell": True,
            "project": project,
            "head_frame_hash": head_frame_hash,
            "visibility": visibility,
        },
        "sig": None,
    }


def verify_project_egg_manifest(
    manifest: Mapping[str, JsonValue],
    contents: Mapping[str, bytes],
) -> None:
    required_keys = {
        "schema", "variant", "rappid", "created_utc",
        "contents", "payload", "sig",
    }
    if set(manifest) != required_keys:
        raise _error(
            "invalid-project-egg-schema",
            "project egg manifest key set is invalid",
        )
    if manifest.get("schema") != PROJECT_EGG_SCHEMA:
        raise _error(
            "invalid-project-egg-schema",
            "project egg schema is not supported",
        )
    if manifest.get("variant") != PROJECT_EGG_VARIANT:
        raise _error(
            "invalid-project-egg-schema",
            "project egg must use the registered organism variant",
        )
    if manifest.get("sig") is not None:
        raise _error(
            "invalid-project-egg-schema",
            "project egg signatures are not supported by this local profile",
        )
    payload = _mapping(manifest.get("payload"), "payload")
    if set(payload) != {
        "protocol", "cell", "project", "head_frame_hash", "visibility",
    }:
        raise _error(
            "invalid-project-egg-schema",
            "project egg payload key set is invalid",
        )
    if payload.get("protocol") != "rapp-projects/1" or payload.get("cell") is not True:
        raise _error(
            "invalid-project-egg-schema",
            "project egg payload does not identify RAPP Projects",
        )
    project = _label(
        _string(payload.get("project"), "payload.project"),
        "project",
        maximum=100,
    )
    rappid = _string(manifest.get("rappid"), "rappid")
    match = _RAPPID.fullmatch(rappid)
    if match is None or match.group("slug") != project:
        raise _error(
            "invalid-project-label",
            "manifest rappid and project disagree",
        )
    head_frame_hash = _hash(
        payload.get("head_frame_hash"),
        "payload.head_frame_hash",
    )
    if payload.get("visibility") not in ("local", "team", "public"):
        raise _error(
            "invalid-project-visibility",
            "manifest visibility is invalid",
        )
    _utc(manifest.get("created_utc"), "created_utc")
    rows = manifest.get("contents")
    if not isinstance(rows, (list, tuple)):
        raise _error(
            "invalid-project-egg-schema",
            "manifest contents must be an array",
        )
    expected = {}
    paths_in_order = []
    for index, value in enumerate(rows):
        row = _mapping(value, f"contents[{index}]")
        if set(row) != {"path", "hash"}:
            raise _error(
                "invalid-project-egg-schema",
                "egg content rows must contain exactly path and hash",
            )
        path = _safe_entry(_string(row.get("path"), f"contents[{index}].path"))
        if path == "manifest.json":
            raise _error(
                "project-egg-entry-set",
                "manifest.json must not appear in contents",
            )
        if path in expected:
            raise _error(
                "project-egg-entry-set",
                "manifest contains duplicate paths",
                path=path,
            )
        _hash(row.get("hash"), f"contents[{index}].hash")
        expected[path] = row
        paths_in_order.append(path)
    if paths_in_order != sorted(paths_in_order, key=lambda path: path.encode("utf-8")):
        raise _error(
            "project-egg-entry-set",
            "project egg contents are not sorted by UTF-8 path bytes",
        )
    if set(expected) != set(contents):
        raise _error(
            "project-egg-entry-set",
            "project egg entries do not match the manifest",
        )
    for path, value in contents.items():
        row = expected[_safe_entry(path)]
        if row.get("hash") != _entry_hash(value):
            raise _error(
                "project-egg-integrity",
                "project egg entry failed content verification",
                path=path,
            )
    for required_path in ("rappid.json", "soul.md"):
        if required_path not in contents:
            raise _error(
                "project-egg-entry-set",
                f"organism egg is missing {required_path}",
            )
    try:
        identity = strict_json_loads(contents["rappid.json"])
    except Exception as exc:
        raise _error(
            "invalid-project-egg-entry",
            "rappid.json is invalid",
        ) from exc
    if not isinstance(identity, Mapping) or identity.get("rappid") != rappid:
        raise _error(
            "project-egg-integrity",
            "manifest rappid does not match rappid.json",
        )
    try:
        soul = contents["soul.md"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error(
            "invalid-project-egg-entry",
            "soul.md is not UTF-8",
        ) from exc
    if not soul.strip():
        raise _error(
            "invalid-project-egg-entry",
            "soul.md is empty",
        )
    frame_pattern = re.compile(
        r"^frames/(?P<seq>[0-9]{20})-"
        r"(?P<hash>[0-9a-f]{64})\.json$",
        re.ASCII,
    )
    frame_rows = []
    for path, value in contents.items():
        frame_match = frame_pattern.fullmatch(path)
        if frame_match is None:
            if path.startswith("frames/"):
                raise _error(
                    "project-egg-integrity",
                    "project egg contains a noncanonical frame path",
                    path=path,
                )
            continue
        try:
            frame = strict_json_loads(value)
        except Exception as exc:
            raise _error(
                "invalid-project-egg-entry",
                "project egg frame is invalid JSON",
                path=path,
            ) from exc
        if not isinstance(frame, Mapping):
            raise _error(
                "invalid-project-egg-entry",
                "project egg frame is not an object",
                path=path,
            )
        if (
            frame.get("seq") != int(frame_match.group("seq"))
            or frame.get("frame_hash") != frame_match.group("hash")
        ):
            raise _error(
                "project-egg-integrity",
                "project egg frame filename does not match its frame",
                path=path,
            )
        frame_rows.append(frame)
    frame_rows.sort(key=lambda frame: int(frame["seq"]))
    if not frame_rows:
        raise _error(
            "project-egg-entry-set",
            "project egg contains no authoritative frames",
        )
    verified = verify_project_stream(frame_rows, rappid)
    if verified.head.frame_hash != head_frame_hash:
        raise _error(
            "project-egg-integrity",
            "manifest head does not match the verified project stream",
        )
    genesis_payload = frame_rows[0]["payload"]
    if genesis_payload["visibility"] != payload["visibility"]:
        raise _error(
            "project-egg-integrity",
            "manifest visibility does not match project genesis",
        )
    for frame in frame_rows:
        frame_payload = frame["payload"]
        if frame_payload.get("event") != "work.handoff":
            continue
        receipt = frame_payload.get("document")
        if not isinstance(receipt, Mapping) or receipt.get("scope") != "project":
            raise _error(
                "project-egg-integrity",
                "handoff document must use a project-relative receipt",
            )
        document_path = _safe_entry(
            _string(receipt.get("path"), "handoff.document.path")
        )
        document_bytes = contents.get(document_path)
        if document_bytes is None:
            raise _error(
                "project-egg-entry-set",
                "project egg is missing a referenced handoff document",
                path=document_path,
            )
        digest = hashlib.sha256(document_bytes).hexdigest()
        if receipt.get("sha256") != digest or receipt.get("bytes") != len(
            document_bytes
        ):
            raise _error(
                "project-egg-integrity",
                "handoff document does not match its frame receipt",
                path=document_path,
            )


def pack_project_egg(
    manifest: Mapping[str, JsonValue],
    contents: Mapping[str, bytes],
) -> bytes:
    """Pack a deterministic, stored-ZIP RAPP/1 organism egg."""

    verify_project_egg_manifest(manifest, contents)
    manifest_bytes = canonicalize(dict(manifest))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        def write(path: str, value: bytes) -> None:
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.flag_bits |= 0x800
            archive.writestr(info, value)

        write("manifest.json", manifest_bytes)
        for row in manifest["contents"]:
            path = str(row["path"])
            write(path, contents[path])
    return buffer.getvalue()


def read_project_egg(
    blob: bytes,
) -> tuple[Mapping[str, JsonValue], dict[str, bytes]]:
    """Read and verify a deterministic RAPP/1 project organism egg."""

    if not isinstance(blob, bytes) or len(blob) > MAX_PROJECT_EGG_BYTES:
        raise _error(
            "invalid-project-egg-entry",
            "project egg exceeds the size limit",
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise _error(
            "invalid-project-egg-entry",
            "project egg is not a ZIP archive",
        ) from exc
    infos = archive.infolist()
    if len(infos) > MAX_PROJECT_EGG_ENTRIES + 1:
        raise _error(
            "project-egg-entry-set",
            "project egg contains too many entries",
        )
    names = [info.filename for info in infos]
    if not names or names[0] != "manifest.json" or len(names) != len(set(names)):
        raise _error(
            "project-egg-entry-set",
            "project egg entry order or uniqueness is invalid",
        )
    for info in infos:
        _safe_entry(info.filename)
        if info.compress_type != zipfile.ZIP_STORED:
            raise _error(
                "project-egg-integrity",
                "project egg entries must use stored compression",
                path=info.filename,
            )
        if info.file_size > MAX_PROJECT_EGG_ENTRY_BYTES:
            raise _error(
                "invalid-project-egg-entry",
                "project egg entry exceeds the size limit",
                path=info.filename,
            )
        if info.date_time != (1980, 1, 1, 0, 0, 0) or info.extra:
            raise _error(
                "project-egg-integrity",
                "project egg ZIP metadata is not deterministic",
                path=info.filename,
            )
    if archive.comment:
        raise _error(
            "project-egg-integrity",
            "project egg ZIP comments are not allowed",
        )
    try:
        manifest = strict_json_loads(archive.read("manifest.json"))
    except Exception as exc:
        raise _error(
            "invalid-project-egg-entry",
            "project egg manifest is invalid",
        ) from exc
    if not isinstance(manifest, Mapping):
        raise _error(
            "invalid-project-egg-entry",
            "project egg manifest is not an object",
        )
    if archive.read("manifest.json") != canonicalize(dict(manifest)):
        raise _error(
            "project-egg-integrity",
            "manifest.json is not canonical RAPP bytes",
        )
    contents = {
        name: archive.read(name) for name in names if name != "manifest.json"
    }
    expected_order = [
        "manifest.json",
        *[str(row["path"]) for row in manifest.get("contents", [])],
    ]
    if names != expected_order:
        raise _error(
            "project-egg-entry-set",
            "archive entry order does not match manifest contents order",
        )
    verify_project_egg_manifest(manifest, contents)
    return manifest, contents


__all__ = (
    "PROJECT_EGG_SCHEMA",
    "PROJECT_EGG_VARIANT",
    "PROJECT_EVENTS",
    "PROJECT_FRAME_KIND",
    "PROJECT_FRAME_KINDS",
    "MAX_PROJECT_EGG_BYTES",
    "MAX_PROJECT_EGG_ENTRIES",
    "MAX_PROJECT_EGG_ENTRY_BYTES",
    "ProjectActor",
    "ProjectCheckpoint",
    "build_project_egg_manifest",
    "build_project_frame",
    "build_project_rappid",
    "pack_project_egg",
    "project_egg_address",
    "project_kind_registry",
    "read_project_egg",
    "validate_project_payload",
    "verify_project_egg_manifest",
    "verify_project_stream",
)
