"""Strict RAPP/1 canonicalization, immutable frames, and verification reports.

The RFC 8785 number preparation follows the current RAPP authority, while the
stdlib-only number formatter mirrors the ECMA-262/JCS algorithm used by that
authority's pinned RFC 8785 implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import TypeAlias

from .errors import ErrorContext, ProtocolError
from .reports import (
    Diagnostic,
    DiagnosticStatus,
    VerificationReport,
)

PROTOCOL_VERSION = "rapp/1"
SPEC = PROTOCOL_VERSION
PARTICLE_SPACE = "rapp/1:particle"
WAVE_SPACE = "rapp/1:wave"
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_STREAM_FRAMES = 100_000
MAX_SAFE_INTEGER = (1 << 53) - 1
DEFAULT_VERIFY_SECONDS = 5.0
NUMBER_PROFILE_BINARY64 = "rfc8785-binary64"
NUMBER_PROFILE_EXACT_INTEGER = "exact-integer"

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
_REGENESIS_KINDS = {
    "body.re-genesis": "body",
    "memory.re-genesis": "memory",
    "swarm.re-genesis": "swarm",
}

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = (
    JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]
Frame: TypeAlias = dict[str, JsonValue]
FrameMapping: TypeAlias = Mapping[str, JsonValue]
FrozenJsonValue: TypeAlias = (
    JsonScalar
    | tuple["FrozenJsonValue", ...]
    | Mapping[str, "FrozenJsonValue"]
)
SignatureVerifier = Callable[[FrameMapping], bool | tuple[bool, str]]


class _ParsedInteger(int):
    def __new__(cls, value: int, token: str) -> _ParsedInteger:
        instance = int.__new__(cls, value)
        instance.token = token
        return instance


class _ParsedFloat(float):
    def __new__(cls, value: float, token: str) -> _ParsedFloat:
        instance = float.__new__(cls, value)
        instance.token = token
        return instance


def _diagnostic(
    code: str,
    message: str,
    *,
    operation: str,
    protocol_step: str | None = None,
    location: str | None = None,
    context: Mapping[str, ErrorContext] | None = None,
    remediation: str | None = None,
    status: DiagnosticStatus = DiagnosticStatus.ERROR,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        operation=operation,
        message=message,
        status=status,
        protocol_step=protocol_step,
        location=location,
        context=context or {},
        remediation=remediation,
    )


def _raise(
    code: str,
    message: str,
    *,
    operation: str,
    protocol_step: str | None = None,
    location: str | None = None,
    context: Mapping[str, ErrorContext] | None = None,
    remediation: str | None = None,
) -> None:
    raise ProtocolError(
        _diagnostic(
            code,
            message,
            operation=operation,
            protocol_step=protocol_step,
            location=location,
            context=context,
            remediation=remediation,
        )
    )


def _has_lone_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _number_text(value: float) -> str:
    """Return ECMA-262/JCS shortest binary64 text."""

    if not math.isfinite(value):
        _raise(
            "number-not-finite",
            "non-finite numbers are forbidden",
            operation="canonicalize",
        )
    if value == 0:
        return "0"
    if value < 0:
        return "-" + _number_text(-value)

    rendered = str(value)
    exponent_text = ""
    exponent = 0
    marker = rendered.find("e")
    if marker > 0:
        exponent_text = rendered[marker:]
        if exponent_text[2:3] == "0":
            exponent_text = exponent_text[:2] + exponent_text[3:]
        rendered = rendered[:marker]
        exponent = int(exponent_text[1:])

    first = rendered
    dot = ""
    last = ""
    marker = rendered.find(".")
    if marker > 0:
        dot = "."
        first = rendered[:marker]
        last = rendered[marker + 1 :]
    if last == "0":
        dot = ""
        last = ""

    if 0 < exponent < 21:
        first += last
        last = ""
        dot = ""
        exponent_text = ""
        zeros = exponent - len(first)
        while zeros >= 0:
            zeros -= 1
            first += "0"
    elif -7 < exponent < 0:
        last = first + last
        first = "0"
        dot = "."
        exponent_text = ""
        zeros = exponent
        while zeros < -1:
            zeros += 1
            last = "0" + last
    return f"{first}{dot}{last}{exponent_text}"


def _validate_number_token(token: str) -> float:
    try:
        binary64 = float(token)
    except (OverflowError, ValueError) as exc:
        raise ProtocolError(
            _diagnostic(
                "number-not-binary64",
                "number token does not map to IEEE-754 binary64",
                operation="parse-json",
                context={"token": token},
            )
        ) from exc
    if not math.isfinite(binary64):
        _raise(
            "number-not-finite",
            "number token maps to a non-finite value",
            operation="parse-json",
            context={"token": token},
        )
    canonical = _number_text(binary64)
    try:
        if Decimal(token) != Decimal(canonical):
            _raise(
                "number-not-roundtrip",
                "number changes mathematical value through binary64",
                operation="parse-json",
                context={"canonical": canonical, "token": token},
                remediation="encode the exact value as a string",
            )
    except InvalidOperation as exc:
        raise ProtocolError(
            _diagnostic(
                "number-not-binary64",
                "number token is outside the JSON number domain",
                operation="parse-json",
                context={"token": token},
            )
        ) from exc
    return binary64


def _prepare_json(value: JsonValue, depth: int = 1) -> JsonValue:
    if depth > MAX_JSON_DEPTH:
        _raise(
            "depth-exceeded",
            f"JSON nesting depth exceeds {MAX_JSON_DEPTH}",
            operation="canonicalize",
            context={"actual_depth": depth, "max_depth": MAX_JSON_DEPTH},
        )
    if value is None or type(value) is bool:
        return value
    if isinstance(value, _ParsedInteger):
        integer = int(value)
        binary64 = _validate_number_token(value.token)
        return (
            integer
            if -MAX_SAFE_INTEGER <= integer <= MAX_SAFE_INTEGER
            else binary64
        )
    if type(value) is int:
        binary64 = _validate_number_token(str(value))
        return value if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER else binary64
    if isinstance(value, _ParsedFloat):
        if not math.isfinite(value):
            _raise(
                "number-not-finite",
                "non-finite numbers are forbidden",
                operation="canonicalize",
            )
        return float(value)
    if type(value) is float:
        if not math.isfinite(value):
            _raise(
                "number-not-finite",
                "non-finite numbers are forbidden",
                operation="canonicalize",
            )
        return value
    if type(value) is str:
        if _has_lone_surrogate(value):
            _raise(
                "lone-surrogate",
                "unpaired UTF-16 surrogate is forbidden",
                operation="canonicalize",
            )
        return value
    if type(value) is list:
        return [
            _prepare_json(
                item,
                depth + 1 if type(item) in (dict, list) else depth,
            )
            for item in value
        ]
    if type(value) is dict:
        prepared: JsonObject = {}
        for key, item in value.items():
            if type(key) is not str:
                _raise(
                    "non-string-key",
                    "JSON object member names must be strings",
                    operation="canonicalize",
                )
            if _has_lone_surrogate(key):
                _raise(
                    "lone-surrogate",
                    "unpaired UTF-16 surrogate in member name",
                    operation="canonicalize",
                )
            prepared[key] = _prepare_json(
                item,
                depth + 1 if type(item) in (dict, list) else depth,
            )
        return prepared
    _raise(
        "non-json-type",
        f"value of type {type(value).__name__} is not JSON",
        operation="canonicalize",
    )


def _canonical_text(value: JsonValue) -> str:
    if value is None or type(value) is bool or type(value) is int:
        return json.dumps(value)
    if type(value) is float:
        return _number_text(value)
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
    _raise(
        "non-json-type",
        "value is outside the canonical JSON domain",
        operation="canonicalize",
    )


def canonicalize(
    value: JsonValue,
    *,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> bytes:
    """Return RFC 8785/JCS canonical UTF-8 bytes.

    >>> canonicalize({"n": [0.1, -0.0, 9007199254740992]})
    b'{"n":[0.1,0,9007199254740992]}'
    """

    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    encoded = _canonical_text(_prepare_json(value)).encode("utf-8")
    if len(encoded) > max_bytes:
        _raise(
            "canonical-size-exceeded",
            f"canonical JSON exceeds {max_bytes} bytes",
            operation="canonicalize",
            context={"actual_bytes": len(encoded), "max_bytes": max_bytes},
        )
    return encoded


def canonical(
    value: JsonValue,
    *,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> str:
    """Return RFC 8785/JCS canonical JSON text."""

    return canonicalize(value, max_bytes=max_bytes).decode("utf-8")


def _object_from_pairs(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            _raise(
                "duplicate-key",
                f"duplicate JSON object member: {key!r}",
                operation="parse-json",
                context={"key": key},
            )
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    _validate_number_token(token)
    return _ParsedInteger(int(token), token)


def _parse_float(token: str) -> float:
    return _ParsedFloat(_validate_number_token(token), token)


def _reject_constant(token: str) -> None:
    _raise(
        "number-not-finite",
        f"non-finite JSON number is forbidden: {token}",
        operation="parse-json",
        context={"token": token},
    )


def strict_json_loads(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = MAX_CANONICAL_BYTES,
) -> JsonValue:
    """Parse strict UTF-8 I-JSON with binary64 round-trip validation."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("strict_json_loads accepts UTF-8 bytes")
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    octets = bytes(data)
    if len(octets) > max_bytes:
        _raise(
            "input-size-exceeded",
            f"JSON input exceeds {max_bytes} bytes",
            operation="parse-json",
            context={"actual_bytes": len(octets), "max_bytes": max_bytes},
        )
    if octets.startswith(b"\xef\xbb\xbf"):
        _raise(
            "utf8-bom",
            "a UTF-8 byte-order mark is forbidden",
            operation="parse-json",
        )
    try:
        text = octets.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError(
            _diagnostic(
                "invalid-utf8",
                "input is not strict UTF-8",
                operation="parse-json",
            )
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError(
            _diagnostic(
                "invalid-json",
                "input is not valid JSON",
                operation="parse-json",
            )
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
            _diagnostic(
                "invalid-hash-space",
                "hash space must be ASCII",
                operation="hash",
            )
        ) from exc
    if b"\n" in encoded:
        _raise(
            "invalid-hash-space",
            "hash space cannot contain LF",
            operation="hash",
        )
    return encoded + b"\n"


def H(space: str, value: JsonValue) -> str:
    """Hash a canonical JSON value with a domain separator."""

    return hashlib.sha256(_hash_prefix(space) + canonicalize(value)).hexdigest()


def Hb(space: str, data: bytes | bytearray | memoryview) -> str:
    """Hash exact bytes with a domain separator."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Hb requires bytes")
    return hashlib.sha256(_hash_prefix(space) + bytes(data)).hexdigest()


def _validate_label(value: str, *, field_name: str, maximum: int) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or re.fullmatch(_LABEL, value, re.ASCII) is None
    ):
        _raise(
            "invalid-label",
            f"{field_name} violates the RAPP/1 label grammar",
            operation="check-frame",
            protocol_step="1",
            context={"field": field_name},
        )


def _validate_rappid(value: JsonValue) -> None:
    if type(value) is not str:
        _raise(
            "invalid-stream-id",
            "RAPPID must be a string",
            operation="check-frame",
            protocol_step="1",
        )
    match = _RAPPID_RE.fullmatch(value)
    if match is None:
        _raise(
            "invalid-stream-id",
            "stream_id does not match a RAPP/1 stream form",
            operation="check-frame",
            protocol_step="1",
        )
    _validate_label(match.group("owner"), field_name="owner", maximum=39)
    _validate_label(match.group("slug"), field_name="slug", maximum=100)


def _stream_family(stream_id: JsonValue) -> str:
    if type(stream_id) is not str:
        _raise(
            "invalid-stream-id",
            "stream_id must be a string",
            operation="check-frame",
            protocol_step="1",
        )
    if stream_id.startswith("net:"):
        _validate_label(
            stream_id[4:],
            field_name="swarm-stream",
            maximum=64,
        )
        return "swarm"
    memory = _MEMORY_STREAM_RE.fullmatch(stream_id)
    if memory is not None:
        _validate_rappid(memory.group("rappid"))
        _validate_label(
            memory.group("instance"),
            field_name="memory-instance",
            maximum=64,
        )
        return "memory"
    _validate_rappid(stream_id)
    return "body"


def _validate_kind(value: JsonValue) -> None:
    if type(value) is not str:
        _raise(
            "invalid-kind",
            "kind must be a string",
            operation="check-frame",
            protocol_step="1",
        )
    match = _KIND_RE.fullmatch(value)
    if match is None:
        _raise(
            "invalid-kind",
            "kind does not match the RAPP/1 grammar",
            operation="check-frame",
            protocol_step="1",
        )
    _validate_label(match.group("left"), field_name="kind-label", maximum=64)
    _validate_label(match.group("right"), field_name="kind-label", maximum=64)


def _validate_utc(value: JsonValue) -> None:
    if type(value) is not str or len(value.encode("utf-8", errors="ignore")) != 24:
        _raise(
            "invalid-utc",
            "utc must use the fixed 24-byte RAPP form",
            operation="check-frame",
            protocol_step="1",
        )
    match = _UTC_RE.fullmatch(value)
    if match is None or match.group("second") == "60":
        _raise(
            "invalid-utc",
            "utc does not match the fixed RAPP form",
            operation="check-frame",
            protocol_step="1",
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProtocolError(
            _diagnostic(
                "invalid-utc",
                "utc is not a calendar-valid date-time",
                operation="check-frame",
                protocol_step="1",
            )
        ) from exc


def _validate_hash(
    value: JsonValue,
    *,
    field_name: str,
    nullable: bool = False,
) -> None:
    if nullable and value is None:
        return
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        _raise(
            "invalid-hash",
            f"{field_name} must be 64 lowercase hex or allowed null",
            operation="check-frame",
            protocol_step="1",
            context={"field": field_name},
        )


def _decode_b64url(value: str) -> bytes:
    if (
        "=" in value
        or _B64URL_RE.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        _raise(
            "invalid-signature",
            "JWS values must use canonical unpadded base64url",
            operation="check-frame",
            protocol_step="1",
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except ValueError as exc:
        raise ProtocolError(
            _diagnostic(
                "invalid-signature",
                "JWS contains invalid base64url",
                operation="check-frame",
                protocol_step="1",
            )
        ) from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        _raise(
            "invalid-signature",
            "JWS base64url is not canonical",
            operation="check-frame",
            protocol_step="1",
        )
    return decoded


def _validate_signature_shape(sig: JsonValue) -> None:
    if sig is None:
        return
    if type(sig) is not str:
        _raise(
            "invalid-signature",
            "sig must be null or a detached JWS string",
            operation="check-frame",
            protocol_step="1",
        )
    parts = sig.split(".")
    if len(parts) != 3 or parts[1] != "":
        _raise(
            "invalid-signature",
            "sig must use detached compact JWS serialization",
            operation="check-frame",
            protocol_step="1",
        )
    header_octets = _decode_b64url(parts[0])
    signature = _decode_b64url(parts[2])
    if not signature:
        _raise(
            "invalid-signature",
            "detached JWS signature cannot be empty",
            operation="check-frame",
            protocol_step="1",
        )
    header = strict_json_loads(header_octets)
    if type(header) is not dict or set(header) != {"alg", "b64", "crit", "kid"}:
        _raise(
            "invalid-signature",
            "JWS header must contain exactly alg,b64,crit,kid",
            operation="check-frame",
            protocol_step="1",
        )
    if header["alg"] not in {"EdDSA", "ES256"}:
        _raise(
            "invalid-signature",
            "JWS alg must be EdDSA or ES256",
            operation="check-frame",
            protocol_step="1",
        )
    if header["b64"] is not False or header["crit"] != ["b64"]:
        _raise(
            "invalid-signature",
            "JWS must use b64=false and crit=['b64']",
            operation="check-frame",
            protocol_step="1",
        )
    _validate_rappid(header["kid"])
    if canonicalize(header) != header_octets:
        _raise(
            "invalid-signature",
            "JWS protected header must be canonical JSON",
            operation="check-frame",
            protocol_step="1",
        )


def _validate_regenesis_shape(frame: Frame) -> None:
    kind = frame["kind"]
    if kind not in _REGENESIS_KINDS:
        return
    if frame["seq"] != 0 or frame["prev"] is not None or frame["prev_wave"] is not None:
        _raise(
            "invalid-re-genesis",
            "re-genesis must be a new seq=0 genesis",
            operation="check-frame",
            protocol_step="1",
        )
    if frame["sig"] is None:
        _raise(
            "invalid-re-genesis",
            "re-genesis requires a signature",
            operation="check-frame",
            protocol_step="1",
        )
    payload = frame["payload"]
    if type(payload) is not dict or set(payload) != {"migrated_from"}:
        _raise(
            "invalid-re-genesis",
            "re-genesis payload must contain exactly migrated_from",
            operation="check-frame",
            protocol_step="1",
        )
    migrated = payload["migrated_from"]
    if type(migrated) is not dict or set(migrated) != {
        "stream_id",
        "terminal_seal",
        "terminal_seq",
    }:
        _raise(
            "invalid-re-genesis",
            "migrated_from has an invalid shape",
            operation="check-frame",
            protocol_step="1",
        )
    _stream_family(migrated["stream_id"])
    _validate_hash(migrated["terminal_seal"], field_name="terminal_seal")
    if (
        type(migrated["terminal_seq"]) not in (int, _ParsedInteger)
        or not 0 <= migrated["terminal_seq"] <= MAX_SAFE_INTEGER
    ):
        _raise(
            "invalid-re-genesis",
            "migrated_from.terminal_seq must be uint53",
            operation="check-frame",
            protocol_step="1",
        )


def _require_nfc_payload_keys(value: JsonValue) -> None:
    if type(value) is dict:
        for key, child in value.items():
            if unicodedata.normalize("NFC", key) != key:
                _raise(
                    "invalid-payload",
                    "producer payload keys must use Unicode NFC",
                    operation="build-frame",
                    protocol_step="1",
                )
            _require_nfc_payload_keys(child)
    elif type(value) is list:
        for child in value:
            _require_nfc_payload_keys(child)


def _freeze_json(value: JsonValue) -> FrozenJsonValue:
    if isinstance(value, _ParsedInteger):
        return int(value)
    if isinstance(value, _ParsedFloat):
        return float(value)
    if type(value) is dict:
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class NumberOrigin:
    """Original payload number kind and token, retained across canonicalization."""

    location: str
    kind: str
    value: int | float
    token: str | None


def _number_origins(
    value: JsonValue,
    *,
    location: str = "payload",
) -> tuple[NumberOrigin, ...]:
    origins: list[NumberOrigin] = []

    def visit(item: JsonValue, path: str) -> None:
        if isinstance(item, _ParsedInteger):
            origins.append(NumberOrigin(path, "integer", int(item), item.token))
        elif isinstance(item, _ParsedFloat):
            origins.append(NumberOrigin(path, "float", float(item), item.token))
        elif type(item) is int:
            origins.append(NumberOrigin(path, "integer", item, None))
        elif type(item) is float:
            origins.append(NumberOrigin(path, "float", item, None))
        elif type(item) is list:
            for index, child in enumerate(item):
                visit(child, f"{path}/{index}")
        elif type(item) is dict:
            for key in sorted(item):
                escaped = key.replace("~", "~0").replace("/", "~1")
                visit(item[key], f"{path}/{escaped}")

    visit(value, location)
    return tuple(origins)


@dataclass(frozen=True, slots=True)
class PersistedHead:
    """Previously trusted stream head used for rollback/fork refusal."""

    seq: int
    frame_hash: str

    def __post_init__(self) -> None:
        if type(self.seq) is not int or not 0 <= self.seq <= MAX_SAFE_INTEGER:
            raise ValueError("persisted head seq must be uint53")
        if _HEX64_RE.fullmatch(self.frame_hash) is None:
            raise ValueError("persisted head frame_hash must be 64 lowercase hex")


_AUTHORITY_CAPABILITY = object()


def _exact_integer_origin(value: JsonValue) -> bool:
    if isinstance(value, _ParsedInteger):
        return re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value.token) is not None
    return type(value) is int


@dataclass(frozen=True, slots=True, init=False)
class AuthorityCheckpoint:
    """Authenticated authority snapshot binding all accepted frame hashes."""

    canonical_repository: str
    protected_ref: str
    accepted_commit: str
    bootstrap_profile_sha256: str
    chain_sha256: str
    stream_id: str
    genesis_frame_hash: str
    selected_head: PersistedHead
    selected_payload_hash: str
    frame_hashes: tuple[str, ...]
    kind_families: Mapping[str, str]
    number_profile: str
    evidence_id: str

    @classmethod
    def from_authenticated(
        cls,
        document: Mapping[str, JsonValue],
        *,
        authenticator: Callable[[bytes], bool],
    ) -> AuthorityCheckpoint:
        """Construct only after an external authenticator accepts the document."""

        if not callable(authenticator):
            raise TypeError("authenticator must be callable")
        original_selected = document.get("selected_head")
        exact_seq_origin = (
            type(original_selected) is dict
            and _exact_integer_origin(original_selected.get("seq"))
        )
        evidence = canonicalize(dict(document))
        if authenticator(evidence) is not True:
            raise ValueError("authority checkpoint authentication failed")
        snapshot = strict_json_loads(evidence)
        if type(snapshot) is not dict:
            raise ValueError("authenticated checkpoint is not an object")
        return cls._create(
            snapshot,
            evidence_id=hashlib.sha256(evidence).hexdigest(),
            capability=_AUTHORITY_CAPABILITY,
            exact_seq_origin=exact_seq_origin,
        )

    @classmethod
    def _create(
        cls,
        document: Mapping[str, JsonValue],
        *,
        evidence_id: str,
        capability: object,
        exact_seq_origin: bool | None = None,
    ) -> AuthorityCheckpoint:
        if capability is not _AUTHORITY_CAPABILITY:
            raise PermissionError("authority checkpoint capability required")
        selected = document.get("selected_head")
        kinds = document.get("kind_families")
        hashes = document.get("frame_hashes")
        if (
            type(selected) is not dict
            or type(kinds) is not dict
            or type(hashes) is not list
        ):
            raise ValueError("authority checkpoint document has an invalid shape")
        value = object.__new__(cls)
        scalar_fields = (
            "canonical_repository",
            "protected_ref",
            "accepted_commit",
            "bootstrap_profile_sha256",
            "chain_sha256",
            "stream_id",
            "genesis_frame_hash",
            "number_profile",
        )
        for name in scalar_fields:
            item = document.get(name)
            if type(item) is not str:
                raise TypeError(f"authority checkpoint {name} must be text")
            object.__setattr__(value, name, item)
        selected_seq = selected["seq"]
        if (
            not _exact_integer_origin(selected_seq)
            or exact_seq_origin is False
            or not 0 <= selected_seq <= MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "authority checkpoint selected_head.seq must be an exact "
                "JSON uint53 integer"
            )
        object.__setattr__(
            value,
            "selected_head",
            PersistedHead(
                seq=int(selected_seq),
                frame_hash=selected["frame_hash"],
            ),
        )
        object.__setattr__(
            value,
            "selected_payload_hash",
            selected["payload_hash"],
        )
        frame_hashes = tuple(hashes)
        if not frame_hashes:
            raise ValueError("authority checkpoint frame_hashes cannot be empty")
        for frame_hash in frame_hashes:
            _validate_hash(frame_hash, field_name="checkpoint_frame_hash")
        object.__setattr__(value, "frame_hashes", frame_hashes)
        kind_families = dict(kinds)
        if any(
            type(kind) is not str or family not in {"body", "memory", "swarm"}
            for kind, family in kind_families.items()
        ):
            raise ValueError("authority checkpoint kind family is invalid")
        object.__setattr__(
            value,
            "kind_families",
            MappingProxyType(dict(sorted(kind_families.items()))),
        )
        object.__setattr__(value, "evidence_id", evidence_id)
        if len(value.accepted_commit) != 40 or any(
            character not in "0123456789abcdef"
            for character in value.accepted_commit
        ):
            raise ValueError("authority checkpoint commit must be 40 lowercase hex")
        for digest in (
            value.bootstrap_profile_sha256,
            value.chain_sha256,
            value.genesis_frame_hash,
            value.selected_payload_hash,
            value.evidence_id,
        ):
            _validate_hash(digest, field_name="checkpoint_digest")
        _stream_family(value.stream_id)
        if value.frame_hashes[0] != value.genesis_frame_hash:
            raise ValueError("authority checkpoint genesis is not frame zero")
        if value.frame_hashes[value.selected_head.seq] != value.selected_head.frame_hash:
            raise ValueError("authority checkpoint selected head is inconsistent")
        if value.number_profile not in {
            NUMBER_PROFILE_BINARY64,
            NUMBER_PROFILE_EXACT_INTEGER,
        }:
            raise ValueError("authority checkpoint number profile is unsupported")
        return value


@dataclass(frozen=True, slots=True, init=False)
class KindFamilyRegistry:
    """Kind-family bindings that are local or checkpoint-authenticated."""

    kind_families: Mapping[str, str]
    genesis_hashes: Mapping[str, str]
    registry_id: str | None
    checkpoint: AuthorityCheckpoint | None

    @classmethod
    def local(
        cls,
        kind_families: Mapping[str, str],
        *,
        genesis_hashes: Mapping[str, str] | None = None,
        registry_id: str | None = None,
    ) -> KindFamilyRegistry:
        return cls._create(
            kind_families,
            genesis_hashes or {},
            registry_id=registry_id,
            checkpoint=None,
        )

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: AuthorityCheckpoint,
    ) -> KindFamilyRegistry:
        if not isinstance(checkpoint, AuthorityCheckpoint):
            raise TypeError("checkpoint must be AuthorityCheckpoint")
        return cls._create(
            checkpoint.kind_families,
            {checkpoint.stream_id: checkpoint.genesis_frame_hash},
            registry_id=checkpoint.evidence_id,
            checkpoint=checkpoint,
        )

    @classmethod
    def _create(
        cls,
        kind_families: Mapping[str, str],
        genesis_hashes: Mapping[str, str],
        *,
        registry_id: str | None,
        checkpoint: AuthorityCheckpoint | None,
    ) -> KindFamilyRegistry:
        value = object.__new__(cls)
        kinds = dict(kind_families)
        genesis = dict(genesis_hashes)
        if any(
            type(kind) is not str or family not in {"body", "memory", "swarm"}
            for kind, family in kinds.items()
        ):
            raise ValueError("kind_families contains an invalid binding")
        for stream_id, frame_hash in genesis.items():
            _stream_family(stream_id)
            _validate_hash(frame_hash, field_name="genesis_hash")
        object.__setattr__(
            value,
            "kind_families",
            MappingProxyType(dict(sorted(kinds.items()))),
        )
        object.__setattr__(
            value,
            "genesis_hashes",
            MappingProxyType(dict(sorted(genesis.items()))),
        )
        object.__setattr__(value, "registry_id", registry_id)
        object.__setattr__(value, "checkpoint", checkpoint)
        return value

    @property
    def verified(self) -> bool:
        return self.checkpoint is not None


@dataclass(frozen=True, slots=True)
class StreamTrustPolicy:
    """Immutable external trust root for one stream."""

    stream_id: str
    trusted_genesis_hash: str
    prior_head: PersistedHead | None = None
    approved_re_genesis_hashes: frozenset[str] = frozenset()
    number_profile: str = NUMBER_PROFILE_BINARY64
    checkpoint: AuthorityCheckpoint | None = None

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: AuthorityCheckpoint,
    ) -> StreamTrustPolicy:
        if not isinstance(checkpoint, AuthorityCheckpoint):
            raise TypeError("checkpoint must be AuthorityCheckpoint")
        return cls(
            stream_id=checkpoint.stream_id,
            trusted_genesis_hash=checkpoint.genesis_frame_hash,
            prior_head=checkpoint.selected_head,
            number_profile=checkpoint.number_profile,
            checkpoint=checkpoint,
        )

    def __post_init__(self) -> None:
        _stream_family(self.stream_id)
        if self.prior_head is not None and not isinstance(
            self.prior_head,
            PersistedHead,
        ):
            raise TypeError("prior_head must be PersistedHead or None")
        if self.number_profile not in {
            NUMBER_PROFILE_BINARY64,
            NUMBER_PROFILE_EXACT_INTEGER,
        }:
            raise ValueError("number_profile is not supported")
        if self.checkpoint is not None and not isinstance(
            self.checkpoint,
            AuthorityCheckpoint,
        ):
            raise TypeError("checkpoint must be AuthorityCheckpoint or None")
        _validate_hash(
            self.trusted_genesis_hash,
            field_name="trusted_genesis_hash",
        )
        approved = frozenset(self.approved_re_genesis_hashes)
        for frame_hash in approved:
            _validate_hash(frame_hash, field_name="approved_re_genesis_hash")
        object.__setattr__(self, "approved_re_genesis_hashes", approved)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedFrame:
    """Immutable, canonical-byte-backed RAPP/1 frame.

    ``payload`` is recursively read-only. ``to_dict()`` is the explicit
    mutable wire boundary.
    """

    spec: str
    kind: str
    stream_id: str
    family: str
    seq: int
    utc: str
    payload: Mapping[str, FrozenJsonValue] = field(repr=False, compare=False)
    payload_hash: str
    frame_hash: str
    prev: str | None
    prev_wave: str | None
    sig: str | None = field(repr=False)
    _number_origins: tuple[NumberOrigin, ...] = field(repr=False, compare=False)
    _canonical_bytes: bytes = field(repr=False, compare=True)

    @classmethod
    def _create(
        cls,
        *,
        spec: str,
        kind: str,
        stream_id: str,
        family: str,
        seq: int,
        utc: str,
        payload: JsonObject,
        payload_hash: str,
        frame_hash: str,
        prev: str | None,
        prev_wave: str | None,
        sig: str | None,
        number_origins: tuple[NumberOrigin, ...],
        canonical_bytes: bytes,
    ) -> VerifiedFrame:
        value = object.__new__(cls)
        object.__setattr__(value, "spec", spec)
        object.__setattr__(value, "kind", kind)
        object.__setattr__(value, "stream_id", stream_id)
        object.__setattr__(value, "family", family)
        object.__setattr__(value, "seq", seq)
        object.__setattr__(value, "utc", utc)
        object.__setattr__(value, "payload", _freeze_json(payload))
        object.__setattr__(value, "payload_hash", payload_hash)
        object.__setattr__(value, "frame_hash", frame_hash)
        object.__setattr__(value, "prev", prev)
        object.__setattr__(value, "prev_wave", prev_wave)
        object.__setattr__(value, "sig", sig)
        object.__setattr__(value, "_number_origins", tuple(number_origins))
        object.__setattr__(value, "_canonical_bytes", bytes(canonical_bytes))
        return value

    def to_dict(self) -> Frame:
        """Return a fresh mutable wire mapping."""

        value = strict_json_loads(self._canonical_bytes)
        if type(value) is not dict:
            raise RuntimeError("verified frame bytes are not a JSON object")
        return value

    def to_json_bytes(self) -> bytes:
        """Return deterministic RFC 8785 frame bytes."""

        return self._canonical_bytes


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStream:
    """Immutable verified stream with explicit trust labeling."""

    frames: tuple[VerifiedFrame, ...]
    trusted: bool
    trust_label: str
    genesis_hash: str

    @classmethod
    def _create(
        cls,
        *,
        frames: tuple[VerifiedFrame, ...],
        trusted: bool,
        trust_label: str,
    ) -> VerifiedStream:
        if not frames:
            raise ValueError("verified stream cannot be empty")
        if any(not isinstance(frame, VerifiedFrame) for frame in frames):
            raise TypeError("verified stream frames must be VerifiedFrame")
        value = object.__new__(cls)
        object.__setattr__(value, "frames", tuple(frames))
        object.__setattr__(value, "trusted", trusted)
        object.__setattr__(value, "trust_label", trust_label)
        object.__setattr__(value, "genesis_hash", frames[0].frame_hash)
        return value

    @property
    def head(self) -> VerifiedFrame:
        return self.frames[-1]

    def __len__(self) -> int:
        return len(self.frames)

    def __iter__(self) -> Iterator[VerifiedFrame]:
        return iter(self.frames)

    def to_jsonl_bytes(self) -> bytes:
        return b"".join(frame.to_json_bytes() + b"\n" for frame in self.frames)


def _verified_frame(frame: Frame, family: str) -> VerifiedFrame:
    payload = frame["payload"]
    if type(payload) is not dict:
        raise RuntimeError("validated payload is not an object")
    return VerifiedFrame._create(
        spec=frame["spec"],
        kind=frame["kind"],
        stream_id=frame["stream_id"],
        family=family,
        seq=int(frame["seq"]),
        utc=frame["utc"],
        payload=payload,
        payload_hash=frame["payload_hash"],
        frame_hash=frame["frame_hash"],
        prev=frame["prev"],
        prev_wave=frame["prev_wave"],
        sig=frame["sig"],
        number_origins=_number_origins(payload),
        canonical_bytes=canonicalize(frame),
    )


def _intrinsic_frame(
    frame_value: FrameMapping,
    *,
    registry: KindFamilyRegistry,
    expected_stream_id: str | None,
    location: str,
    allow_local_registry: bool = False,
) -> VerificationReport[VerifiedFrame]:
    try:
        if not isinstance(frame_value, Mapping):
            _raise(
                "invalid-frame",
                "frame must be an object",
                operation="check-frame",
                protocol_step="1",
                location=location,
            )
        frame = dict(frame_value)
        if set(frame) != FRAME_KEYS:
            missing = sorted(FRAME_KEYS - set(frame))
            extra = sorted(set(frame) - FRAME_KEYS)
            _raise(
                "invalid-frame-shape",
                "frame must have exactly eleven keys",
                operation="check-frame",
                protocol_step="1",
                location=location,
                context={
                    "extra": ",".join(extra),
                    "missing": ",".join(missing),
                },
            )
        if frame["spec"] != SPEC:
            _raise(
                "invalid-spec",
                "spec must equal 'rapp/1'",
                operation="check-frame",
                protocol_step="1",
                location=location,
            )
        _validate_kind(frame["kind"])
        family = _stream_family(frame["stream_id"])
        if (
            type(frame["seq"]) not in (int, _ParsedInteger)
            or not 0 <= frame["seq"] <= MAX_SAFE_INTEGER
        ):
            _raise(
                "invalid-seq",
                "seq must be a uint53 integer",
                operation="check-frame",
                protocol_step="1",
                location=location,
            )
        _validate_utc(frame["utc"])
        if type(frame["payload"]) is not dict:
            _raise(
                "invalid-payload",
                "payload must be an object",
                operation="check-frame",
                protocol_step="1",
                location=location,
            )
        _validate_hash(frame["payload_hash"], field_name="payload_hash")
        _validate_hash(frame["frame_hash"], field_name="frame_hash")
        _validate_hash(frame["prev"], field_name="prev", nullable=True)
        _validate_hash(
            frame["prev_wave"],
            field_name="prev_wave",
            nullable=True,
        )
        _validate_signature_shape(frame["sig"])
        _validate_regenesis_shape(frame)
        try:
            canonicalize(frame)
        except ProtocolError as exc:
            diagnostic = exc.diagnostic
            raise ProtocolError(
                Diagnostic(
                    code=diagnostic.code,
                    operation="check-frame",
                    message=diagnostic.message,
                    protocol_step="1",
                    location=location,
                    context=diagnostic.context,
                    remediation=diagnostic.remediation,
                )
            ) from exc
        if not registry.verified and not allow_local_registry:
            _raise(
                "registry-unverified",
                "kind-family registry is not authenticated",
                operation="check-frame",
                protocol_step="1",
                location=location,
                remediation="supply an externally verified registry snapshot",
            )
        registered_family = registry.kind_families.get(frame["kind"])
        if registered_family is None:
            _raise(
                "unregistered-kind",
                "kind is absent from the verified registry",
                operation="check-frame",
                protocol_step="1",
                location=location,
                context={"kind": frame["kind"]},
            )
        if registered_family != family:
            _raise(
                "kind-stream-mismatch",
                "registered kind family does not match stream family",
                operation="check-frame",
                protocol_step="1",
                location=location,
                context={
                    "kind": frame["kind"],
                    "registered_family": registered_family,
                    "stream_family": family,
                },
            )
        if expected_stream_id is not None and frame["stream_id"] != expected_stream_id:
            _raise(
                "stream-binding-mismatch",
                "frame stream_id does not match the stream of record",
                operation="check-frame",
                protocol_step="1a",
                location=location,
                context={
                    "actual_stream_id": frame["stream_id"],
                    "expected_stream_id": expected_stream_id,
                },
            )
        expected_payload_hash = H(PARTICLE_SPACE, frame["payload"])
        if frame["payload_hash"] != expected_payload_hash:
            _raise(
                "payload-hash-mismatch",
                "payload_hash mismatch",
                operation="check-frame",
                protocol_step="2",
                location=location,
                context={
                    "actual_payload_hash": frame["payload_hash"],
                    "expected_payload_hash": expected_payload_hash,
                },
            )
        wave_preimage = {
            key: value
            for key, value in frame.items()
            if key not in {"frame_hash", "sig"}
        }
        expected_frame_hash = H(WAVE_SPACE, wave_preimage)
        if frame["frame_hash"] != expected_frame_hash:
            _raise(
                "frame-hash-mismatch",
                "frame_hash mismatch",
                operation="check-frame",
                protocol_step="3",
                location=location,
                context={
                    "actual_frame_hash": frame["frame_hash"],
                    "expected_frame_hash": expected_frame_hash,
                },
            )
        return VerificationReport(_verified_frame(frame, family))
    except ProtocolError as exc:
        diagnostic = exc.diagnostic
        if diagnostic.location is None:
            diagnostic = Diagnostic(
                code=diagnostic.code,
                operation=diagnostic.operation,
                message=diagnostic.message,
                status=diagnostic.status,
                protocol_step=diagnostic.protocol_step,
                location=location,
                context=diagnostic.context,
                remediation=diagnostic.remediation,
            )
        return VerificationReport(None, (diagnostic,))


def _link_diagnostic(
    frame: VerifiedFrame,
    *,
    head: VerifiedFrame | None,
    location: str,
) -> Diagnostic | None:
    if head is None:
        if frame.seq != 0 or frame.prev is not None:
            return _diagnostic(
                "invalid-genesis",
                "genesis must have seq=0 and prev=null",
                operation="check-frame",
                protocol_step="4",
                location=location,
            )
        if frame.prev_wave is not None:
            return _diagnostic(
                "invalid-genesis-wave",
                "genesis prev_wave must be null",
                operation="check-frame",
                protocol_step="5",
                location=location,
            )
        return None
    if frame.stream_id != head.stream_id:
        return _diagnostic(
            "cross-stream-chain",
            "frame and predecessor are from different streams",
            operation="check-frame",
            protocol_step="4",
            location=location,
        )
    if frame.seq != head.seq + 1:
        return _diagnostic(
            "noncontiguous-seq",
            "seq does not extend the predecessor",
            operation="check-frame",
            protocol_step="4",
            location=location,
            context={"actual_seq": frame.seq, "expected_seq": head.seq + 1},
        )
    if frame.prev != head.payload_hash:
        return _diagnostic(
            "previous-payload-mismatch",
            "prev does not equal predecessor payload_hash",
            operation="check-frame",
            protocol_step="4",
            location=location,
            context={"actual_prev": frame.prev, "expected_prev": head.payload_hash},
        )
    if frame.utc < head.utc:
        return _diagnostic(
            "utc-regression",
            "utc is earlier than predecessor utc",
            operation="check-frame",
            protocol_step="4",
            location=location,
        )
    if frame.family == "swarm":
        if frame.prev_wave != head.frame_hash:
            return _diagnostic(
                "previous-wave-mismatch",
                "prev_wave does not equal predecessor frame_hash",
                operation="check-frame",
                protocol_step="5",
                location=location,
            )
    elif frame.prev_wave is not None:
        return _diagnostic(
            "invalid-prev-wave",
            "prev_wave must be null outside swarm streams",
            operation="check-frame",
            protocol_step="5",
            location=location,
        )
    return None


def _signature_diagnostic(
    frame: VerifiedFrame,
    *,
    signature_verifier: SignatureVerifier | None,
    location: str,
) -> Diagnostic | None:
    if frame.family == "swarm" and frame.sig is None:
        return _diagnostic(
            "unsigned-swarm-frame",
            "swarm frames must be signed",
            operation="check-frame",
            protocol_step="6",
            location=location,
        )
    if frame.sig is None:
        return None
    if signature_verifier is None:
        return _diagnostic(
            "signature-unverified",
            "a signature verifier is required for signed frames",
            operation="check-frame",
            protocol_step="6",
            location=location,
        )
    verdict = signature_verifier(frame.to_dict())
    if isinstance(verdict, tuple):
        if len(verdict) != 2:
            return _diagnostic(
                "signature-verifier-error",
                "signature verifier returned an invalid tuple",
                operation="check-frame",
                protocol_step="6",
                location=location,
            )
        ok, reason = verdict
    else:
        ok, reason = verdict, "signature verifier rejected the frame"
    if type(ok) is not bool or type(reason) is not str:
        return _diagnostic(
            "signature-verifier-error",
            "signature verifier returned an invalid result",
            operation="check-frame",
            protocol_step="6",
            location=location,
        )
    if not ok:
        return _diagnostic(
            "signature-invalid",
            reason or "signature verifier rejected the frame",
            operation="check-frame",
            protocol_step="6",
            location=location,
        )
    return None


def check_frame(
    frame: FrameMapping,
    *,
    registry: KindFamilyRegistry,
    head: VerifiedFrame | None = None,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> VerificationReport[VerifiedFrame]:
    """Return an immutable verified frame or an ordered refusal report.

    Shape, types, registry family, particle, and wave are always checked
    before chain/fork decisions.
    """

    if not isinstance(registry, KindFamilyRegistry):
        raise TypeError("registry must be KindFamilyRegistry")
    if head is not None and not isinstance(head, VerifiedFrame):
        raise TypeError("head must be VerifiedFrame or None")
    report = _intrinsic_frame(
        frame,
        registry=registry,
        expected_stream_id=expected_stream_id,
        location="frame",
    )
    if report.value is None:
        return report
    linked = _link_diagnostic(report.value, head=head, location="frame")
    if linked is not None:
        return VerificationReport(None, (linked,))
    signature = _signature_diagnostic(
        report.value,
        signature_verifier=signature_verifier,
        location="frame",
    )
    if signature is not None:
        return VerificationReport(None, (signature,))
    return report


def check_frame_local(
    frame: FrameMapping,
    *,
    registry: KindFamilyRegistry,
    head: VerifiedFrame | None = None,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> VerificationReport[VerifiedFrame]:
    """Verify one frame with an explicitly local/untrusted registry."""

    if not isinstance(registry, KindFamilyRegistry):
        raise TypeError("registry must be KindFamilyRegistry")
    if registry.verified:
        raise ValueError("check_frame_local requires a local registry")
    report = _intrinsic_frame(
        frame,
        registry=registry,
        expected_stream_id=expected_stream_id,
        location="frame",
        allow_local_registry=True,
    )
    if report.value is None:
        return report
    linked = _link_diagnostic(report.value, head=head, location="frame")
    if linked is not None:
        return VerificationReport(None, (linked,))
    signature = _signature_diagnostic(
        report.value,
        signature_verifier=signature_verifier,
        location="frame",
    )
    if signature is not None:
        return VerificationReport(None, (signature,))
    return VerificationReport(
        report.value,
        (
            _diagnostic(
                "local-untrusted",
                "frame is valid only under a local registry",
                operation="check-frame",
                location="frame",
                status=DiagnosticStatus.WARNING,
            ),
        ),
    )


def verify_frame(
    frame: FrameMapping,
    *,
    registry: KindFamilyRegistry,
    head: VerifiedFrame | None = None,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> VerifiedFrame:
    """Raising wrapper over :func:`check_frame`."""

    return check_frame(
        frame,
        registry=registry,
        head=head,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
    ).require(ProtocolError)


def verify_frame_local(
    frame: FrameMapping,
    *,
    registry: KindFamilyRegistry,
    head: VerifiedFrame | None = None,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> VerifiedFrame:
    """Raising wrapper for explicitly local frame verification."""

    return check_frame_local(
        frame,
        registry=registry,
        head=head,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
    ).require(ProtocolError)


def _validate_limits(max_frames: int, max_seconds: float) -> float:
    if type(max_frames) is not int or max_frames <= 0:
        raise ValueError("max_frames must be a positive integer")
    if (
        type(max_seconds) not in (int, float)
        or not math.isfinite(max_seconds)
        or max_seconds < 0
    ):
        raise ValueError("max_seconds must be finite and non-negative")
    return time.monotonic() + max_seconds


def _deadline_diagnostic(deadline: float) -> Diagnostic | None:
    if time.monotonic() >= deadline:
        return _diagnostic(
            "verification-time-exceeded",
            "stream verification exceeded its time budget",
            operation="check-stream",
            location="stream",
        )
    return None


def _trust_diagnostic(
    stream: VerifiedStream,
    *,
    registry: KindFamilyRegistry,
    trust_policy: StreamTrustPolicy,
) -> Diagnostic | None:
    checkpoint = trust_policy.checkpoint
    if checkpoint is None or registry.checkpoint is None:
        return _diagnostic(
            "authority-checkpoint-required",
            "trusted verification requires a checkpoint-derived registry and policy",
            operation="trust-stream",
            location="checkpoint",
        )
    if registry.checkpoint.evidence_id != checkpoint.evidence_id:
        return _diagnostic(
            "authority-checkpoint-mismatch",
            "registry and trust policy derive from different checkpoints",
            operation="trust-stream",
            location="checkpoint",
        )
    if (
        trust_policy.stream_id != checkpoint.stream_id
        or trust_policy.trusted_genesis_hash != checkpoint.genesis_frame_hash
        or trust_policy.prior_head != checkpoint.selected_head
        or trust_policy.number_profile != checkpoint.number_profile
    ):
        return _diagnostic(
            "authority-checkpoint-mismatch",
            "trust policy does not preserve its checkpoint bindings",
            operation="trust-stream",
            location="checkpoint",
        )
    if stream.head.stream_id != trust_policy.stream_id:
        return _diagnostic(
            "trust-stream-mismatch",
            "trust policy names a different stream",
            operation="trust-stream",
            location="stream",
        )
    registered_genesis = registry.genesis_hashes.get(stream.head.stream_id)
    if registered_genesis != trust_policy.trusted_genesis_hash:
        return _diagnostic(
            "registry-genesis-mismatch",
            "verified registry does not bind the trusted genesis",
            operation="trust-stream",
            location="stream",
            context={
                "registered_genesis": registered_genesis,
                "trusted_genesis": trust_policy.trusted_genesis_hash,
            },
        )
    genesis = stream.frames[0]
    if genesis.frame_hash != trust_policy.trusted_genesis_hash:
        return _diagnostic(
            "trusted-genesis-mismatch",
            "stream genesis does not match the trusted genesis",
            operation="trust-stream",
            location="frame[0]",
            context={
                "actual_genesis": genesis.frame_hash,
                "trusted_genesis": trust_policy.trusted_genesis_hash,
            },
        )
    if genesis.kind in _REGENESIS_KINDS:
        if genesis.frame_hash not in trust_policy.approved_re_genesis_hashes:
            return _diagnostic(
                "unapproved-re-genesis",
                "re-genesis is not explicitly approved by trust policy",
                operation="trust-stream",
                location="frame[0]",
            )
    if trust_policy.number_profile == NUMBER_PROFILE_EXACT_INTEGER:
        for index, frame in enumerate(stream.frames):
            if _violates_exact_integer(frame):
                return _diagnostic(
                    "trust-number-profile-mismatch",
                    "stream contains numbers forbidden by trust policy",
                    operation="trust-stream",
                    location=f"frame[{index}]",
                    context={
                        "number_location": next(
                            origin.location
                            for origin in frame._number_origins
                            if origin.kind == "float"
                            or (
                                origin.kind == "integer"
                                and not -MAX_SAFE_INTEGER
                                <= origin.value
                                <= MAX_SAFE_INTEGER
                            )
                        )
                    },
                    remediation="use only uint53/int53 numbers in this authority",
                )
    prior = trust_policy.prior_head
    if prior is not None and stream.head.seq < prior.seq:
        return _diagnostic(
            "head-rollback",
            "presented stream head is older than the persisted trusted head",
            operation="trust-stream",
            location="stream",
            context={
                "persisted_seq": prior.seq,
                "presented_seq": stream.head.seq,
            },
        )
    if prior is not None:
        known = stream.frames[prior.seq]
        if known.frame_hash != prior.frame_hash:
            return _diagnostic(
                "known-head-conflict",
                "known sequence has a conflicting frame hash",
                operation="trust-stream",
                location=f"frame[{prior.seq}]",
                context={
                    "actual_frame_hash": known.frame_hash,
                    "persisted_frame_hash": prior.frame_hash,
                    "seq": prior.seq,
                },
            )
    frame_hashes = tuple(frame.frame_hash for frame in stream.frames)
    if frame_hashes != checkpoint.frame_hashes:
        return _diagnostic(
            "authority-snapshot-mismatch",
            "verified stream does not match the checkpoint frame snapshot",
            operation="trust-stream",
            location="stream",
        )
    if (
        stream.head.seq != checkpoint.selected_head.seq
        or stream.head.frame_hash != checkpoint.selected_head.frame_hash
        or stream.head.payload_hash != checkpoint.selected_payload_hash
    ):
        return _diagnostic(
            "authority-snapshot-mismatch",
            "stream head does not match the checkpoint selection",
            operation="trust-stream",
            location="stream.head",
        )
    return None


def _violates_exact_integer(frame: VerifiedFrame) -> bool:
    return any(
        origin.kind == "float"
        or (
            origin.kind == "integer"
            and not -MAX_SAFE_INTEGER <= origin.value <= MAX_SAFE_INTEGER
        )
        for origin in frame._number_origins
    )


def _check_stream(
    frames: Iterable[FrameMapping],
    *,
    registry: KindFamilyRegistry,
    trust_policy: StreamTrustPolicy | None,
    local: bool,
    expected_stream_id: str | None,
    signature_verifier: SignatureVerifier | None,
    max_frames: int,
    max_seconds: float,
    _deadline: float | None = None,
) -> VerificationReport[VerifiedStream]:
    if not isinstance(registry, KindFamilyRegistry):
        raise TypeError("registry must be KindFamilyRegistry")
    deadline = (
        _validate_limits(max_frames, max_seconds)
        if _deadline is None
        else _deadline
    )
    iterator = iter(frames)
    verified: list[VerifiedFrame] = []
    seen_seq: dict[int, str] = {}
    frames_by_seq: dict[int, VerifiedFrame] = {}
    seen_hashes: set[str] = set()
    stream_id = expected_stream_id
    while True:
        timed_out = _deadline_diagnostic(deadline)
        if timed_out is not None:
            return VerificationReport(None, (timed_out,))
        try:
            raw = next(iterator)
        except StopIteration:
            break
        except ProtocolError as exc:
            return VerificationReport(None, (exc.diagnostic,))
        index = len(verified)
        if index >= max_frames:
            return VerificationReport(
                None,
                (
                    _diagnostic(
                        "frame-count-exceeded",
                        f"stream exceeds {max_frames} frames",
                        operation="check-stream",
                        location=f"frame[{index}]",
                        context={"max_frames": max_frames},
                    ),
                ),
            )
        location = f"frame[{index}]"
        intrinsic = _intrinsic_frame(
            raw,
            registry=registry,
            expected_stream_id=stream_id,
            location=location,
            allow_local_registry=local,
        )
        if intrinsic.value is None:
            return VerificationReport(None, intrinsic.diagnostics)
        candidate = intrinsic.value
        if stream_id is None:
            stream_id = candidate.stream_id
        previous_hash = seen_seq.get(candidate.seq)
        if previous_hash is not None:
            predecessor = (
                frames_by_seq.get(candidate.seq - 1)
                if candidate.seq > 0
                else None
            )
            linked = _link_diagnostic(
                candidate,
                head=predecessor,
                location=location,
            )
            if linked is not None:
                return VerificationReport(None, (linked,))
            signature = _signature_diagnostic(
                candidate,
                signature_verifier=signature_verifier,
                location=location,
            )
            if signature is not None:
                return VerificationReport(None, (signature,))
            if previous_hash == candidate.frame_hash:
                diagnostic = _diagnostic(
                    "duplicate-frame",
                    "duplicate frame at an existing sequence",
                    operation="check-stream",
                    protocol_step="4",
                    location=location,
                    context={"seq": candidate.seq},
                )
            else:
                diagnostic = _diagnostic(
                    "fork-detected",
                    "competing valid frames occupy the same sequence",
                    operation="check-stream",
                    protocol_step="4",
                    location=location,
                    context={"seq": candidate.seq},
                )
            return VerificationReport(
                None,
                (diagnostic,),
            )
        if candidate.frame_hash in seen_hashes:
            return VerificationReport(
                None,
                (
                    _diagnostic(
                        "duplicate-frame",
                        "duplicate frame_hash detected",
                        operation="check-stream",
                        protocol_step="3",
                        location=location,
                    ),
                ),
            )
        linked = _link_diagnostic(
            candidate,
            head=verified[-1] if verified else None,
            location=location,
        )
        if linked is not None:
            return VerificationReport(None, (linked,))
        signature = _signature_diagnostic(
            candidate,
            signature_verifier=signature_verifier,
            location=location,
        )
        if signature is not None:
            return VerificationReport(None, (signature,))
        seen_seq[candidate.seq] = candidate.frame_hash
        frames_by_seq[candidate.seq] = candidate
        seen_hashes.add(candidate.frame_hash)
        verified.append(candidate)
    if not verified:
        return VerificationReport(
            None,
            (
                _diagnostic(
                    "empty-stream",
                    "stream contains no frames",
                    operation="check-stream",
                    location="stream",
                ),
            ),
        )
    timed_out = _deadline_diagnostic(deadline)
    if timed_out is not None:
        return VerificationReport(None, (timed_out,))
    untrusted = VerifiedStream._create(
        frames=tuple(verified),
        trusted=False,
        trust_label="local-untrusted",
    )
    if local:
        warning = _diagnostic(
            "local-untrusted",
            "stream is internally valid but has no external trust root",
            operation="check-stream",
            location="stream",
            remediation="verify with an authenticated StreamTrustPolicy",
            status=DiagnosticStatus.WARNING,
        )
        return VerificationReport(untrusted, (warning,), trusted=False)
    if trust_policy is None:
        return VerificationReport(
            None,
            (
                _diagnostic(
                    "trust-policy-required",
                    "authoritative stream verification requires a trust policy",
                    operation="trust-stream",
                    location="stream",
                ),
            ),
        )
    trusted_stream = VerifiedStream._create(
        frames=untrusted.frames,
        trusted=True,
        trust_label="trusted",
    )
    trust_failure = _trust_diagnostic(
        trusted_stream,
        registry=registry,
        trust_policy=trust_policy,
    )
    if trust_failure is not None:
        return VerificationReport(None, (trust_failure,))
    return VerificationReport(trusted_stream, trusted=True)


def check_stream(
    frames: Iterable[FrameMapping],
    *,
    registry: KindFamilyRegistry,
    trust_policy: StreamTrustPolicy,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
    max_frames: int = MAX_STREAM_FRAMES,
    max_seconds: float = DEFAULT_VERIFY_SECONDS,
) -> VerificationReport[VerifiedStream]:
    """Verify a stream against registry and immutable external trust."""

    if not isinstance(trust_policy, StreamTrustPolicy):
        raise TypeError("trust_policy must be StreamTrustPolicy")
    return _check_stream(
        frames,
        registry=registry,
        trust_policy=trust_policy,
        local=False,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
        max_frames=max_frames,
        max_seconds=max_seconds,
    )


def check_stream_local(
    frames: Iterable[FrameMapping],
    *,
    registry: KindFamilyRegistry,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
    max_frames: int = MAX_STREAM_FRAMES,
    max_seconds: float = DEFAULT_VERIFY_SECONDS,
    _deadline: float | None = None,
) -> VerificationReport[VerifiedStream]:
    """Verify internal consistency and label the result local/untrusted."""

    if not isinstance(registry, KindFamilyRegistry):
        raise TypeError("registry must be KindFamilyRegistry")
    if registry.verified:
        raise ValueError("check_stream_local requires a local registry")
    return _check_stream(
        frames,
        registry=registry,
        trust_policy=None,
        local=True,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
        max_frames=max_frames,
        max_seconds=max_seconds,
        _deadline=_deadline,
    )


def verify_stream(
    frames: Iterable[FrameMapping],
    *,
    registry: KindFamilyRegistry,
    trust_policy: StreamTrustPolicy,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
    max_frames: int = MAX_STREAM_FRAMES,
    max_seconds: float = DEFAULT_VERIFY_SECONDS,
) -> VerifiedStream:
    """Raising wrapper over :func:`check_stream`."""

    return check_stream(
        frames,
        registry=registry,
        trust_policy=trust_policy,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
        max_frames=max_frames,
        max_seconds=max_seconds,
    ).require(ProtocolError)


def verify_stream_local(
    frames: Iterable[FrameMapping],
    *,
    registry: KindFamilyRegistry,
    expected_stream_id: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
    max_frames: int = MAX_STREAM_FRAMES,
    max_seconds: float = DEFAULT_VERIFY_SECONDS,
) -> VerifiedStream:
    """Raising wrapper for explicitly local/untrusted verification."""

    return check_stream_local(
        frames,
        registry=registry,
        expected_stream_id=expected_stream_id,
        signature_verifier=signature_verifier,
        max_frames=max_frames,
        max_seconds=max_seconds,
    ).require(ProtocolError)


def build_frame_mapping(
    kind: str,
    stream_id: str,
    seq: int,
    utc: str,
    payload: Mapping[str, JsonValue],
    prev: str | None,
    *,
    prev_wave: str | None = None,
    sig: str | None = None,
) -> Frame:
    """Build a mutable eleven-key wire mapping without assigning trust."""

    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    payload_object = dict(payload)
    _require_nfc_payload_keys(payload_object)
    payload_hash = H(PARTICLE_SPACE, payload_object)
    frame: Frame = {
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
    canonicalize(frame)
    return frame


build_frame = build_frame_mapping


__all__ = (
    "AuthorityCheckpoint",
    "DEFAULT_VERIFY_SECONDS",
    "FRAME_KEYS",
    "Frame",
    "FrameMapping",
    "FrozenJsonValue",
    "H",
    "Hb",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "KindFamilyRegistry",
    "MAX_CANONICAL_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_SAFE_INTEGER",
    "MAX_STREAM_FRAMES",
    "NUMBER_PROFILE_BINARY64",
    "NUMBER_PROFILE_EXACT_INTEGER",
    "NumberOrigin",
    "PARTICLE_SPACE",
    "PROTOCOL_VERSION",
    "PersistedHead",
    "ProtocolError",
    "SPEC",
    "SignatureVerifier",
    "StreamTrustPolicy",
    "VerifiedFrame",
    "VerifiedStream",
    "WAVE_SPACE",
    "build_frame",
    "build_frame_mapping",
    "canonical",
    "canonicalize",
    "check_frame",
    "check_frame_local",
    "check_stream",
    "check_stream_local",
    "strict_json_loads",
    "verify_frame",
    "verify_frame_local",
    "verify_stream",
    "verify_stream_local",
)
