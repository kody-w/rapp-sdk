from __future__ import annotations

import copy
import json
import unittest

from rapp_sdk.protocol import (
    FRAME_KEYS,
    H,
    ProtocolError,
    WAVE_SPACE,
    build_frame,
    canonical,
    strict_json_loads,
    verify_frame,
    verify_stream,
)

STREAM_ID = (
    "rappid:@example/spec-chain:"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


def frame(
    seq: int,
    payload: dict,
    *,
    head: dict | None = None,
    utc: str | None = None,
) -> dict:
    return build_frame(
        "body.pulse",
        STREAM_ID,
        seq,
        utc or f"2026-08-30T00:00:{seq:02d}.000Z",
        payload,
        None if head is None else head["payload_hash"],
    )


def rewave(value: dict) -> None:
    preimage = {
        key: item
        for key, item in value.items()
        if key not in {"frame_hash", "sig"}
    }
    value["frame_hash"] = H(WAVE_SPACE, preimage)


class CanonicalTests(unittest.TestCase):
    def test_authority_compatible_utf16_key_order(self) -> None:
        value = {"\ue000": 1, "\U00010000": 2, "a": [True, None, "é"]}
        self.assertEqual(
            canonical(value),
            '{"a":[true,null,"é"],"𐀀":2,"\ue000":1}',
        )

    def test_strict_json_refuses_duplicates_floats_and_bad_utf8(self) -> None:
        probes = [
            b'{"a":1,"a":2}',
            b'{"a":1.0}',
            b'{"a":9007199254740992}',
            b"\xef\xbb\xbf{}",
            b'{"a":"\xff"}',
            b'{"a":"\\ud800"}',
        ]
        for probe in probes:
            with self.subTest(probe=probe), self.assertRaises(ProtocolError):
                strict_json_loads(probe)

    def test_depth_limit(self) -> None:
        value = b"[" * 65 + b"0" + b"]" * 65
        with self.assertRaisesRegex(ProtocolError, "depth"):
            strict_json_loads(value)


class FrameTests(unittest.TestCase):
    def test_builder_emits_exact_envelope_and_verifies_chain(self) -> None:
        genesis = frame(0, {"revision": "rev-1"})
        second = frame(1, {"revision": "rev-2"}, head=genesis)
        self.assertEqual(set(genesis), FRAME_KEYS)
        self.assertEqual(verify_frame(genesis), genesis)
        self.assertEqual(verify_frame(second, head=genesis), second)
        self.assertEqual(verify_stream([genesis, second]), (genesis, second))

    def test_extra_key_is_refused(self) -> None:
        genesis = frame(0, {})
        genesis["extra"] = None
        with self.assertRaisesRegex(ProtocolError, "eleven keys"):
            verify_frame(genesis)

    def test_payload_wave_and_prev_mutations_fail(self) -> None:
        genesis = frame(0, {"value": "original"})
        second = frame(1, {"value": "next"}, head=genesis)

        corrupt_payload = copy.deepcopy(genesis)
        corrupt_payload["payload"]["value"] = "changed"
        with self.assertRaisesRegex(ProtocolError, "payload_hash"):
            verify_frame(corrupt_payload)

        corrupt_wave = copy.deepcopy(genesis)
        corrupt_wave["frame_hash"] = "f" * 64
        with self.assertRaisesRegex(ProtocolError, "frame_hash"):
            verify_frame(corrupt_wave)

        corrupt_prev = copy.deepcopy(second)
        corrupt_prev["prev"] = "0" * 64
        rewave(corrupt_prev)
        with self.assertRaisesRegex(ProtocolError, "prev"):
            verify_frame(corrupt_prev, head=genesis)

    def test_duplicate_seq_fork_is_refused(self) -> None:
        genesis = frame(0, {"value": "root"})
        left = frame(1, {"value": "left"}, head=genesis)
        right = frame(1, {"value": "right"}, head=genesis)
        with self.assertRaisesRegex(ProtocolError, "duplicate"):
            verify_stream([genesis, left, right])

    def test_time_budget_is_enforced(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "time budget"):
            verify_stream([frame(0, {})], max_seconds=0)

    def test_json_round_trip_is_deterministic(self) -> None:
        genesis = frame(0, {"z": 1, "a": "two"})
        decoded = strict_json_loads(
            json.dumps(genesis, ensure_ascii=False).encode("utf-8")
        )
        self.assertEqual(verify_frame(decoded), genesis)


if __name__ == "__main__":
    unittest.main()
