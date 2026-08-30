"""Strict, stdlib-only RAPP/1 frame primitives.

Canonicalization and frame checks are adapted from the MIT-licensed RAPP/1
authority reference implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

SPEC = "rapp/1"
PARTICLE_SPACE = "rapp/1:particle"
WAVE_SPACE = "rapp/1:wave"
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_STREAM_FRAMES = 100_000
MAX_SAFE_INTEGER = (1 << 53) - 1
DEFAULT_VERIFY_SECONDS = 5.0

FRAME_KEYS = frozenset(
    {
        "spec",
        "kind",
        "stream_id",
        "seq",
        "utc",
        "payload",
        "payload_hash",
        "frame_hash",
        "prev",
        "prev_wave",
        "sig",
    }
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_LABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_KIND_RE = re.compile(rf"^(?P<left>{_LABEL})\.(?P<right>{_LABEL})$", re.ASCII)
_RAPPID_RE = re.compile(
    rf"^rappid:@(?P<owner>{_LABEL})/(?P<slug>{_LABEL}):(?P<tail>[0-9a-f]{{64}})$",
    re.ASCII,
)
_MEMORY_STREAM_RE = re.compile(
    rf"^(?P<rappid>rappid:@{_LABEL}/{_LABEL}:[0-9a-f]{{64}}):"
    rf"(?P<instance>{_LABEL})$",
    re.ASCII,
)
_UTC_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"\.(?P<millisecond>[0-9]{3})Z$",
    re.ASCII,
)
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$", re.ASCII)

JsonValue = Any
SignatureVerifier = Callable[[Mapping[str, JsonValue]], bool | tuple[bool, str]]


class ProtocolError(ValueError):
    """A fail-closed protocol validation error."""

    def __init__(self, code: str, message: str, *, step: str | None = None):
        super().__init__(message)
        self.code = code
        self.step = step


def _fail(code: str, message: str, *, step: str = "1") -> None:
    raise ProtocolError(code, message, step=step)


def _has_lone_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_json_value(value: JsonValue) -> None:
    stack: list[tuple[JsonValue, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            _fail(
                "depth-exceeded",
                f"JSON nesting depth exceeds {MAX_JSON_DEPTH}",
            )
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if abs(current) > MAX_SAFE_INTEGER:
                _fail(
                    "integer-not-ijson",
                    "integer is outside the interoperable I-JSON range",
                )
            continue
        if type(current) is float:
            _fail("float-forbidden", "RAPP/1 canonical JSON forbids floats")
        if type(current) is str:
            if _has_lone_surrogate(current):
                _fail("lone-surrogate", "unpaired UTF-16 surrogate is forbidden")
            continue
        if type(current) is list:
            stack.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if type(key) is not str:
                    _fail(
                        "non-string-key",
                        "JSON object member names must be strings",
                    )
                if _has_lone_surrogate(key):
                    _fail(
                        "lone-surrogate",
                        "unpaired UTF-16 surrogate in member name",
                    )
                stack.append((item, depth + 1))
            continue
        _fail(
            "non-json-type",
            f"value of type {type(current).__name__} is not JSON",
        )


def _canonical_text(value: JsonValue) -> str:
    if value is None or type(value) is bool or type(value) is int:
        return json.dumps(value)
    if type(value) is str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) is list:
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if type(value) is dict:
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _canonical_text(value[key])
                for key in keys
            )
            + "}"
        )
    _fail("non-json-type", "value is outside the canonical JSON domain")


def canonicalize(
    value: JsonValue, *, max_bytes: int = MAX_CANONICAL_BYTES
) -> bytes:
    """Return authority-compatible canonical UTF-8 JSON bytes."""

    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    _validate_json_value(value)
    encoded = _canonical_text(value).encode("utf-8")
    if len(encoded) > max_bytes:
        _fail(
            "canonical-size-exceeded",
            f"canonical JSON exceeds {max_bytes} bytes",
        )
    return encoded


def canonical(value: JsonValue, *, max_bytes: int = MAX_CANONICAL_BYTES) -> str:
    """Return canonical JSON text."""

    return canonicalize(value, max_bytes=max_bytes).decode("utf-8")


def _object_from_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-key", f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    value = int(token)
    if abs(value) > MAX_SAFE_INTEGER:
        _fail(
            "integer-not-ijson",
            "integer is outside the interoperable I-JSON range",
        )
    return value


def _reject_float(token: str) -> None:
    _fail("float-forbidden", f"RAPP/1 canonical JSON forbids float token {token!r}")


def _reject_constant(token: str) -> None:
    _fail("non-finite-number", f"non-finite JSON number is forbidden: {token}")


def strict_json_loads(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> JsonValue:
    """Parse strict UTF-8 I-JSON, refusing duplicate keys and floats."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("strict_json_loads accepts UTF-8 bytes")
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    octets = bytes(data)
    if len(octets) > max_bytes:
        _fail("input-size-exceeded", f"JSON input exceeds {max_bytes} bytes")
    if octets.startswith(b"\xef\xbb\xbf"):
        _fail("utf8-bom", "a UTF-8 byte-order mark is forbidden")
    try:
        text = octets.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError(
            "invalid-utf8", "input is not strict UTF-8", step="1"
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError(
            "invalid-json", "input is not valid JSON", step="1"
        ) from exc
    canonicalize(value, max_bytes=max_bytes)
    return value


def _hash_prefix(space: str) -> bytes:
    if type(space) is not str:
        raise TypeError("hash space must be text")
    try:
        encoded = space.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            "invalid-hash-space", "hash space must be ASCII"
        ) from exc
    if b"\n" in encoded:
        _fail("invalid-hash-space", "hash space cannot contain LF")
    return encoded + b"\n"


def H(space: str, value: JsonValue) -> str:
    """Hash a canonical JSON value with a domain separator."""

    return hashlib.sha256(_hash_prefix(space) + canonicalize(value)).hexdigest()


def Hb(space: str, data: bytes | bytearray | memoryview) -> str:
    """Hash exact bytes with a domain separator."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Hb requires bytes")
    return hashlib.sha256(_hash_prefix(space) + bytes(data)).hexdigest()


def _validate_label(value: str, *, field: str, maximum: int) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or re.fullmatch(_LABEL, value, re.ASCII) is None
    ):
        _fail(
            f"invalid-{field}",
            f"{field} must be 1-{maximum} lowercase alphanumeric/hyphen characters",
        )


def _stream_family(stream_id: JsonValue) -> str:
    if type(stream_id) is not str:
        _fail("invalid-stream-id", "stream_id must be a string")
    if stream_id.startswith("net:"):
        _validate_label(stream_id[4:], field="swarm-stream", maximum=64)
        return "swarm"
    memory = _MEMORY_STREAM_RE.fullmatch(stream_id)
    if memory is not None:
        rappid = memory.group("rappid")
        instance = memory.group("instance")
        _validate_rappid(rappid)
        _validate_label(instance, field="memory-instance", maximum=64)
        return "memory"
    _validate_rappid(stream_id)
    return "body"


def _validate_rappid(value: str) -> None:
    if type(value) is not str:
        _fail("invalid-stream-id", "RAPPID must be a string")
    match = _RAPPID_RE.fullmatch(value)
    if match is None:
        _fail("invalid-stream-id", "stream_id does not match a RAPP/1 stream form")
    _validate_label(match.group("owner"), field="owner", maximum=39)
    _validate_label(match.group("slug"), field="slug", maximum=100)


def _validate_kind(value: JsonValue) -> None:
    if type(value) is not str:
        _fail("invalid-kind", "kind must be a string")
    match = _KIND_RE.fullmatch(value)
    if match is None:
        _fail("invalid-kind", "kind does not match the RAPP/1 grammar")
    _validate_label(match.group("left"), field="kind-label", maximum=64)
    _validate_label(match.group("right"), field="kind-label", maximum=64)


def _validate_utc(value: JsonValue) -> None:
    if type(value) is not str or len(value.encode("utf-8", errors="ignore")) != 24:
        _fail("invalid-utc", "utc must use the fixed 24-byte RAPP form")
    match = _UTC_RE.fullmatch(value)
    if match is None or match.group("second") == "60":
        _fail("invalid-utc", "utc does not match the fixed RAPP form")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProtocolError(
            "invalid-utc", "utc is not a calendar-valid date-time", step="1"
        ) from exc


def _validate_hash(value: JsonValue, *, field: str, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        _fail(
            "invalid-hash",
            f"{field} must be 64 lowercase hex or allowed null",
        )


def _decode_b64url(value: str) -> bytes:
    if (
        "=" in value
        or _B64URL_RE.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        _fail("invalid-signature", "JWS values must use canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except ValueError as exc:
        raise ProtocolError(
            "invalid-signature", "JWS contains invalid base64url", step="1"
        ) from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        _fail("invalid-signature", "JWS base64url is not canonical")
    return decoded


def _validate_signature_shape(sig: JsonValue) -> None:
    if sig is None:
        return
    if type(sig) is not str:
        _fail("invalid-signature", "sig must be null or a detached JWS string")
    parts = sig.split(".")
    if len(parts) != 3 or parts[1] != "":
        _fail("invalid-signature", "sig must use detached compact JWS serialization")
    header_octets = _decode_b64url(parts[0])
    _decode_b64url(parts[2])
    header = strict_json_loads(header_octets)
    if type(header) is not dict or set(header) != {"alg", "b64", "crit", "kid"}:
        _fail(
            "invalid-signature",
            "JWS protected header must contain exactly alg,b64,crit,kid",
        )
    if header["alg"] not in {"EdDSA", "ES256"}:
        _fail("invalid-signature", "JWS alg must be EdDSA or ES256")
    if header["b64"] is not False or header["crit"] != ["b64"]:
        _fail("invalid-signature", "JWS must use b64=false and crit=['b64']")
    _validate_rappid(header["kid"])
    if canonicalize(header) != header_octets:
        _fail("invalid-signature", "JWS protected header must be canonical JSON")


def _frame_copy(frame: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    if not isinstance(frame, Mapping):
        _fail("invalid-frame", "frame must be an object")
    return dict(frame)


def _validate_frame_integrity(
    frame_value: Mapping[str, JsonValue],
    *,
    expected_stream_id: str | None = None,
) -> tuple[dict[str, JsonValue], str]:
    frame = _frame_copy(frame_value)
    if set(frame) != FRAME_KEYS:
        missing = sorted(FRAME_KEYS - set(frame))
        extra = sorted(set(frame) - FRAME_KEYS)
        _fail(
            "invalid-frame-shape",
            f"frame must have exactly eleven keys; missing={missing}, extra={extra}",
        )
    canonicalize(frame)
    if frame["spec"] != SPEC:
        _fail("invalid-spec", "spec must equal 'rapp/1'")
    _validate_kind(frame["kind"])
    family = _stream_family(frame["stream_id"])
    if (
        type(frame["seq"]) is not int
        or not 0 <= frame["seq"] <= MAX_SAFE_INTEGER
    ):
        _fail("invalid-seq", "seq must be a uint53 integer")
    _validate_utc(frame["utc"])
    if type(frame["payload"]) is not dict:
        _fail("invalid-payload", "payload must be an object")
    _validate_hash(frame["payload_hash"], field="payload_hash")
    _validate_hash(frame["frame_hash"], field="frame_hash")
    _validate_hash(frame["prev"], field="prev", nullable=True)
    _validate_hash(frame["prev_wave"], field="prev_wave", nullable=True)
    _validate_signature_shape(frame["sig"])
    if expected_stream_id is not None and frame["stream_id"] != expected_stream_id:
        _fail(
            "stream-id-mismatch",
            "frame stream_id does not match the stream of record",
            step="1a",
        )
    if frame["payload_hash"] != H(PARTICLE_SPACE, frame["payload"]):
        _fail("payload-hash-mismatch", "payload_hash mismatch", step="2")
    wave_preimage = {
        key: value
        for key, value in frame.items()
        if key not in {"frame_hash", "sig"}
    }
    if frame["frame_hash"] != H(WAVE_SPACE, wave_preimage):
        _fail("frame-hash-mismatch", "frame_hash mismatch", step="3")
    return frame, family


def _verify_signature(
    frame: Mapping[str, JsonValue],
    family: str,
    signature_verifier: SignatureVerifier | None,
) -> None:
    if family == "swarm" and frame["sig"] is None:
        _fail("unsigned-swarm-frame", "swarm frames must be signed", step="6")
    if frame["sig"] is not None:
        if signature_verifier is None:
            _fail(
                "signature-unverified",
                "a signature verifier is required for signed frames",
                step="6",
            )
        verdict = signature_verifier(frame)
        if isinstance(verdict, tuple):
            if len(verdict) != 2:
                _fail(
                    "signature-verifier-error",
                    "signature verifier returned an invalid tuple",
                    step="6",
                )
            ok, reason = verdict
        else:
            ok, reason = verdict, "signature verifier rejected the frame"
        if type(ok) is not bool or type(reason) is not str:
            _fail(
                "signature-verifier-error",
                "signature verifier returned an invalid result",
                step="6",
            )
        if ok is not True:
            _fail("signature-invalid", reason, step="6")


def build_frame(
    kind: str,
    stream_id: str,
    seq: int,
    utc: str,
    payload: Mapping[str, JsonValue],
    prev: str | None,
    *,
    prev_wave: str | None = None,
    sig: str | None = None,
) -> dict[str, JsonValue]:
    """Build an exact eleven-key RAPP/1 frame."""

    if not isinstance(payload, Mapping):
        _fail("invalid-payload", "payload must be an object")
    payload_object = dict(payload)
    payload_hash = H(PARTICLE_SPACE, payload_object)
    frame: dict[str, JsonValue] = {
        "spec": SPEC,
        "kind": kind,
        "stream_id": stream_id,
        "seq": seq,
        "utc": utc,
        "payload": payload_object,
        "payload_hash": payload_hash,
        "prev": prev,
        "prev_wave": prev_wave,
        "sig": sig,
    }
    wave_preimage = dict(frame)
    wave_preimage.pop("sig")
    frame["frame_hash"] = H(WAVE_SPACE, wave_preimage)
    _, family = _validate_frame_integrity(frame)
    if seq == 0 and prev_wave is not None:
        _fail(
            "invalid-genesis-wave",
            "genesis prev_wave must be null",
            step="5",
        )
    if family != "swarm" and prev_wave is not None:
        _fail(
            "invalid-prev-wave",
            "prev_wave must be null outside swarm streams",
            step="5",
        )
    if family == "swarm" and sig is None:
        _fail("unsigned-swarm-frame", "swarm frames must be signed", step="6")
    return frame


def verify_frame(
    frame: Mapping[str, JsonValue],
    *,
    head: Mapping[str, JsonValue] | None = None,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> dict[str, JsonValue]:
    """Verify one frame against its predecessor, refusing every mismatch."""

    candidate, family = _validate_frame_integrity(
        frame,
        expected_stream_id=expected_stream_id,
    )
    if head is None:
        if candidate["seq"] != 0 or candidate["prev"] is not None:
            _fail(
                "invalid-genesis",
                "genesis must have seq=0 and prev=null",
                step="4",
            )
        if candidate["prev_wave"] is not None:
            _fail(
                "invalid-genesis-wave",
                "genesis prev_wave must be null",
                step="5",
            )
        _verify_signature(candidate, family, signature_verifier)
        return candidate

    predecessor, predecessor_family = _validate_frame_integrity(
        head,
        expected_stream_id=expected_stream_id or candidate["stream_id"],
    )
    if predecessor_family != family or predecessor["stream_id"] != candidate["stream_id"]:
        _fail(
            "stream-id-mismatch",
            "frame and predecessor are from different streams",
            step="1a",
        )
    if candidate["seq"] != predecessor["seq"] + 1:
        _fail("noncontiguous-seq", "seq does not extend the predecessor", step="4")
    if candidate["prev"] != predecessor["payload_hash"]:
        _fail(
            "previous-payload-mismatch",
            "prev does not equal predecessor payload_hash",
            step="4",
        )
    if candidate["utc"] < predecessor["utc"]:
        _fail("utc-regression", "utc is earlier than predecessor utc", step="4")
    if family == "swarm":
        if candidate["prev_wave"] != predecessor["frame_hash"]:
            _fail(
                "previous-wave-mismatch",
                "prev_wave does not equal predecessor frame_hash",
                step="5",
            )
    elif candidate["prev_wave"] is not None:
        _fail(
            "invalid-prev-wave",
            "prev_wave must be null outside swarm streams",
            step="5",
        )
    _verify_signature(candidate, family, signature_verifier)
    return candidate


def verify_stream(
    frames: Iterable[Mapping[str, JsonValue]],
    *,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
    max_frames: int = MAX_STREAM_FRAMES,
    max_seconds: float = DEFAULT_VERIFY_SECONDS,
) -> tuple[dict[str, JsonValue], ...]:
    """Verify a linear, single-writer stream in supplied chain order."""

    if type(max_frames) is not int or max_frames <= 0:
        raise ValueError("max_frames must be a positive integer")
    if (
        type(max_seconds) not in (int, float)
        or not math.isfinite(max_seconds)
        or max_seconds < 0
    ):
        raise ValueError("max_seconds must be finite and non-negative")
    deadline = time.monotonic() + max_seconds
    verified: list[dict[str, JsonValue]] = []
    seen_seq: set[int] = set()
    seen_frame_hash: set[str] = set()
    head: dict[str, JsonValue] | None = None
    stream_id = expected_stream_id
    for count, frame in enumerate(frames, start=1):
        if time.monotonic() >= deadline:
            _fail(
                "verification-time-exceeded",
                "stream verification exceeded its time budget",
                step="time",
            )
        if count > max_frames:
            _fail(
                "frame-count-exceeded",
                f"stream exceeds {max_frames} frames",
                step="size",
            )
        supplied = _frame_copy(frame)
        seq = supplied.get("seq")
        frame_hash = supplied.get("frame_hash")
        if type(seq) is int and seq in seen_seq:
            _fail("duplicate-seq", f"duplicate or forked seq {seq}", step="4")
        if type(frame_hash) is str and frame_hash in seen_frame_hash:
            _fail("duplicate-frame", "duplicate frame_hash", step="3")
        if stream_id is None and type(supplied.get("stream_id")) is str:
            stream_id = supplied["stream_id"]
        candidate = verify_frame(
            supplied,
            head=head,
            expected_stream_id=stream_id,
            signature_verifier=signature_verifier,
        )
        seen_seq.add(candidate["seq"])
        seen_frame_hash.add(candidate["frame_hash"])
        verified.append(candidate)
        head = candidate
    if not verified:
        _fail("empty-stream", "stream contains no frames", step="4")
    if time.monotonic() >= deadline:
        _fail(
            "verification-time-exceeded",
            "stream verification exceeded its time budget",
            step="time",
        )
    return tuple(verified)


__all__ = [
    "DEFAULT_VERIFY_SECONDS",
    "FRAME_KEYS",
    "H",
    "Hb",
    "MAX_CANONICAL_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_SAFE_INTEGER",
    "MAX_STREAM_FRAMES",
    "PARTICLE_SPACE",
    "ProtocolError",
    "SPEC",
    "WAVE_SPACE",
    "build_frame",
    "canonical",
    "canonicalize",
    "strict_json_loads",
    "verify_frame",
    "verify_stream",
]
