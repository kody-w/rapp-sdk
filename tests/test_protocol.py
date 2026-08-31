from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import math
import unittest

from rapp_sdk import (
    AuthorityCheckpoint,
    DiagnosticStatus,
    KindFamilyRegistry,
    PersistedHead,
    ProtocolError,
    StreamTrustPolicy,
    VerifiedFrame,
    VerifiedStream,
    build_frame_mapping,
    canonicalize,
    check_frame,
    check_stream,
    verify_frame,
    verify_stream,
)
from rapp_sdk.protocol import (
    H,
    MAX_CANONICAL_BYTES,
    PARTICLE_SPACE,
    WAVE_SPACE,
    strict_json_loads,
)

RID = "rappid:@example/protocol:" + "1" * 64
OTHER_RID = "rappid:@example/other:" + "2" * 64
UTC0 = "2026-08-30T00:00:00.000Z"
UTC1 = "2026-08-30T00:00:01.000Z"
UTC2 = "2026-08-30T00:00:02.000Z"


def registry(
    first: dict,
    *,
    kinds: dict[str, str] | None = None,
) -> KindFamilyRegistry:
    return authority(first, kinds=kinds)[0]


def genesis(payload: dict | None = None) -> dict:
    return build_frame_mapping(
        "body.pulse",
        RID,
        0,
        UTC0,
        payload or {},
        None,
    )


def successor(head: dict, payload: dict, *, utc: str = UTC1) -> dict:
    return build_frame_mapping(
        "body.pulse",
        RID,
        head["seq"] + 1,
        utc,
        payload,
        head["payload_hash"],
    )


def trust(first: dict, prior: PersistedHead | None = None) -> StreamTrustPolicy:
    policy = authority(first)[1]
    return (
        dataclasses.replace(policy, prior_head=prior)
        if prior is not None
        else policy
    )


def authority(
    *frames: dict,
    kinds: dict[str, str] | None = None,
    number_profile: str = "rfc8785-binary64",
) -> tuple[KindFamilyRegistry, StreamTrustPolicy]:
    selected = frames[-1]
    document = {
        "canonical_repository": "https://example.test/authority",
        "protected_ref": "refs/heads/main",
        "accepted_commit": "a" * 40,
        "bootstrap_profile_sha256": "b" * 64,
        "chain_sha256": hashlib.sha256(jsonl(*frames)).hexdigest(),
        "stream_id": frames[0]["stream_id"],
        "genesis_frame_hash": frames[0]["frame_hash"],
        "selected_head": {
            "seq": selected["seq"],
            "frame_hash": selected["frame_hash"],
            "payload_hash": selected["payload_hash"],
        },
        "frame_hashes": [frame["frame_hash"] for frame in frames],
        "kind_families": (
            {
            "body.pulse": "body",
            "body.re-genesis": "body",
            "memory.chat-turn": "memory",
            "swarm.echo": "swarm",
            }
            if kinds is None
            else kinds
        ),
        "number_profile": number_profile,
    }
    checkpoint = AuthorityCheckpoint.from_authenticated(
        document,
        authenticator=lambda evidence: True,
    )
    return (
        KindFamilyRegistry.from_checkpoint(checkpoint),
        StreamTrustPolicy.from_checkpoint(checkpoint),
    )


def jsonl(*frames: dict) -> bytes:
    return b"".join(canonicalize(frame) + b"\n" for frame in frames)


def jws() -> str:
    header = {
        "alg": "EdDSA",
        "b64": False,
        "crit": ["b64"],
        "kid": RID,
    }
    protected = base64.urlsafe_b64encode(canonicalize(header)).rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"\x01" * 64).rstrip(b"=")
    return f"{protected.decode()}..{signature.decode()}"


class CanonicalizationTests(unittest.TestCase):
    def test_rfc8785_authority_vector(self) -> None:
        value = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": "€$\x0f\nA'B\"\\\"/",
            "literals": [None, True, False],
        }
        self.assertEqual(
            canonicalize(value),
            (
                b'{"literals":[null,true,false],"numbers":[333333333.3333333,'
                b'1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\n'
                b'A\'B\\"\\\\\\"/"}'
            ),
        )

    def test_binary64_numbers_and_exponent_thresholds(self) -> None:
        vectors = {
            b"0.1": b"0.1",
            b"0.10000000000000000": b"0.1",
            b"-0.0": b"0",
            b"-0": b"0",
            b"1e3": b"1000",
            b"9007199254740992": b"9007199254740992",
            b"-9007199254740992": b"-9007199254740992",
            b"333333333.3333333": b"333333333.3333333",
            b"1e20": b"100000000000000000000",
            b"1e21": b"1e+21",
            b"1e-6": b"0.000001",
            b"1e-7": b"1e-7",
            b"5e-324": b"5e-324",
            b"1.7976931348623157e308": b"1.7976931348623157e+308",
        }
        for raw, expected in vectors.items():
            with self.subTest(raw=raw):
                self.assertEqual(
                    canonicalize(strict_json_loads(raw)),
                    expected,
                )

    def test_non_roundtrippable_and_nonfinite_numbers_are_refused(self) -> None:
        for raw in (
            b"9007199254740993",
            b"-9007199254740993",
            b"333333333.33333329",
            b"1e999",
            b"1e-999",
            b"NaN",
            b"Infinity",
        ):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                strict_json_loads(raw)
        for value in (math.inf, -math.inf, math.nan, 9007199254740993):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                canonicalize(value)

    def test_programmatic_boundaries_and_independent_hash(self) -> None:
        value = {"n": [0.1, -0.0, 9007199254740992]}
        expected = b'{"n":[0.1,0,9007199254740992]}'
        self.assertEqual(canonicalize(value), expected)
        self.assertEqual(
            H(PARTICLE_SPACE, value),
            "37738598ea3e4d2eee32a623716253a1470c4f125e1eb7103e327ae7249b7a0d",
        )

    def test_depth_64_is_accepted_and_65_refused(self) -> None:
        depth_64 = b"[" * 64 + b"0" + b"]" * 64
        depth_65 = b"[" * 65 + b"0" + b"]" * 65
        self.assertEqual(canonicalize(strict_json_loads(depth_64)), depth_64)
        with self.assertRaisesRegex(ProtocolError, "depth"):
            strict_json_loads(depth_65)

    def test_strict_json_and_size_boundaries_remain_fail_closed(self) -> None:
        for raw in (
            b'{"x":1,"x":2}',
            b"\xef\xbb\xbf{}",
            b'{"x":"\\ud800"}',
            b'"\xff"',
        ):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                strict_json_loads(raw)
        exact = b'"' + b"a" * (MAX_CANONICAL_BYTES - 2) + b'"'
        too_large = b'"' + b"a" * (MAX_CANONICAL_BYTES - 1) + b'"'
        self.assertEqual(len(canonicalize(strict_json_loads(exact))), len(exact))
        with self.assertRaises(ProtocolError):
            strict_json_loads(too_large)


class VerificationTests(unittest.TestCase):
    def test_verified_frame_and_stream_are_immutable(self) -> None:
        first = genesis({"nested": {"items": [1, 0.1]}})
        policy = registry(first)
        verified = verify_frame(first, registry=policy)
        self.assertIsInstance(verified, VerifiedFrame)
        with self.assertRaises(TypeError):
            verified.payload["new"] = True
        with self.assertRaises(TypeError):
            verified.payload["nested"]["new"] = True
        mutable = verified.to_dict()
        mutable["payload"]["nested"]["items"][0] = 99
        self.assertEqual(verified.to_dict()["payload"]["nested"]["items"][0], 1)

        stream = verify_stream(
            [first],
            registry=policy,
            trust_policy=trust(first),
        )
        self.assertIsInstance(stream, VerifiedStream)
        self.assertTrue(stream.trusted)
        self.assertEqual(stream.head, verified)

    def test_registry_rejects_unknown_and_family_mismatch_at_step_one(self) -> None:
        first = genesis()
        unverified = check_frame(
            first,
            registry=KindFamilyRegistry.local(
                {"body.pulse": "body"},
                genesis_hashes={RID: first["frame_hash"]},
            ),
        )
        self.assertEqual(
            unverified.diagnostics[-1].code,
            "registry-unverified",
        )
        unknown = check_frame(
            first,
            registry=registry(first, kinds={}),
        )
        self.assertFalse(unknown.ok)
        self.assertEqual(unknown.diagnostics[-1].code, "unregistered-kind")
        self.assertEqual(unknown.diagnostics[-1].protocol_step, "1")

        wrong_family = build_frame_mapping(
            "swarm.echo",
            RID,
            0,
            UTC0,
            {},
            None,
        )
        mismatch = check_frame(
            wrong_family,
            registry=registry(
                first,
                kinds={"swarm.echo": "swarm"},
            ),
        )
        self.assertEqual(mismatch.diagnostics[-1].code, "kind-stream-mismatch")
        self.assertEqual(mismatch.diagnostics[-1].protocol_step, "1")

    def test_uint53_applies_to_seq_not_general_payload_numbers(self) -> None:
        first = genesis({"binary64_integer": 9007199254740992})
        verified = verify_frame(
            first,
            registry=registry(first),
        )
        self.assertEqual(
            verified.to_dict()["payload"]["binary64_integer"],
            9007199254740992,
        )
        invalid_seq = build_frame_mapping(
            "body.pulse",
            RID,
            9007199254740992,
            UTC0,
            {},
            None,
        )
        report = check_frame(
            invalid_seq,
            registry=registry(first),
        )
        self.assertEqual(report.diagnostics[-1].code, "invalid-seq")
        self.assertEqual(report.diagnostics[-1].protocol_step, "1")

    def test_malformed_duplicate_is_shape_error_before_fork_classification(self) -> None:
        first = genesis()
        malformed_cases = []
        extra = copy.deepcopy(first)
        extra["extra"] = True
        malformed_cases.append((extra, "invalid-frame-shape"))
        float_seq = copy.deepcopy(first)
        float_seq["seq"] = 0.0
        float_seq["frame_hash"] = H(
            WAVE_SPACE,
            {
                key: value
                for key, value in float_seq.items()
                if key not in {"frame_hash", "sig"}
            },
        )
        malformed_cases.append((float_seq, "invalid-seq"))
        for malformed, code in malformed_cases:
            with self.subTest(code=code):
                report = check_stream(
                    [first, malformed],
                    registry=registry(first),
                    trust_policy=trust(first),
                )
                self.assertFalse(report.ok)
                self.assertEqual(report.diagnostics[-1].code, code)
                self.assertEqual(report.diagnostics[-1].protocol_step, "1")

    def test_particle_wave_and_previous_link_fail_in_protocol_order(self) -> None:
        first = genesis({"value": "first"})
        policy = registry(first)
        verified_first = verify_frame(first, registry=policy)

        particle = copy.deepcopy(first)
        particle["payload"]["value"] = "changed"
        self.assertEqual(
            check_frame(particle, registry=policy).diagnostics[-1].protocol_step,
            "2",
        )

        wave = copy.deepcopy(first)
        wave["frame_hash"] = "f" * 64
        self.assertEqual(
            check_frame(wave, registry=policy).diagnostics[-1].protocol_step,
            "3",
        )

        linked = successor(first, {"value": "second"})
        linked["prev"] = "0" * 64
        linked["frame_hash"] = H(
            WAVE_SPACE,
            {
                key: value
                for key, value in linked.items()
                if key not in {"frame_hash", "sig"}
            },
        )
        previous = check_frame(
            linked,
            registry=policy,
            head=verified_first,
        )
        self.assertEqual(previous.diagnostics[-1].protocol_step, "4")

    def test_genuine_fork_returns_report_and_protocol_error(self) -> None:
        first = genesis()
        left = successor(first, {"branch": "left"})
        right = successor(first, {"branch": "right"})
        policy, trusted = authority(first, left)
        report = check_stream(
            [first, left, right],
            registry=policy,
            trust_policy=trusted,
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.diagnostics[-1].code, "fork-detected")
        with self.assertRaises(ProtocolError) as raised:
            verify_stream(
                [first, left, right],
                registry=policy,
                trust_policy=trusted,
            )
        self.assertEqual(raised.exception.code, "fork-detected")

    def test_invalid_competing_child_is_not_classified_as_fork(self) -> None:
        first = genesis()
        left = successor(first, {"branch": "left"})
        policy, trusted = authority(first, left)

        wrong_prev = successor(first, {"branch": "wrong-prev"})
        wrong_prev["prev"] = "0" * 64
        wrong_prev["frame_hash"] = H(
            WAVE_SPACE,
            {
                key: value
                for key, value in wrong_prev.items()
                if key not in {"frame_hash", "sig"}
            },
        )
        wrong_prev_report = check_stream(
            [first, left, wrong_prev],
            registry=policy,
            trust_policy=trusted,
        )
        self.assertEqual(
            wrong_prev_report.diagnostics[-1].code,
            "previous-payload-mismatch",
        )

        bad_signature = build_frame_mapping(
            "body.pulse",
            RID,
            1,
            UTC1,
            {"branch": "bad-signature"},
            first["payload_hash"],
            sig=jws(),
        )
        bad_signature_report = check_stream(
            [first, left, bad_signature],
            registry=policy,
            trust_policy=trusted,
            signature_verifier=lambda frame: (False, "bad signature"),
        )
        self.assertEqual(
            bad_signature_report.diagnostics[-1].code,
            "signature-invalid",
        )
        self.assertEqual(
            bad_signature_report.diagnostics[-1].protocol_step,
            "6",
        )

    def test_replacement_genesis_stale_prefix_and_known_conflict_are_refused(
        self,
    ) -> None:
        first = genesis()
        second = successor(first, {"branch": "trusted"})
        policy, trusted = authority(first, second)
        prior = PersistedHead(seq=1, frame_hash=second["frame_hash"])

        replacement = genesis({"replacement": True})
        replaced = check_stream(
            [replacement],
            registry=policy,
            trust_policy=trusted,
        )
        self.assertEqual(
            replaced.diagnostics[-1].code,
            "trusted-genesis-mismatch",
        )

        stale = check_stream(
            [first],
            registry=policy,
            trust_policy=dataclasses.replace(trusted, prior_head=prior),
        )
        self.assertEqual(stale.diagnostics[-1].code, "head-rollback")

        competing = successor(first, {"branch": "competing"})
        conflict = check_stream(
            [first, competing],
            registry=policy,
            trust_policy=dataclasses.replace(trusted, prior_head=prior),
        )
        self.assertEqual(conflict.diagnostics[-1].code, "known-head-conflict")

    def test_re_genesis_requires_explicit_approval(self) -> None:
        reset = build_frame_mapping(
            "body.re-genesis",
            RID,
            0,
            UTC2,
            {
                "migrated_from": {
                    "stream_id": RID,
                    "terminal_seal": "a" * 64,
                    "terminal_seq": 7,
                }
            },
            None,
            sig=jws(),
        )
        policy, reset_trust = authority(
            reset,
            kinds={"body.re-genesis": "body"},
        )
        unapproved = check_stream(
            [reset],
            registry=policy,
            trust_policy=reset_trust,
            signature_verifier=lambda frame: True,
        )
        self.assertEqual(
            unapproved.diagnostics[-1].code,
            "unapproved-re-genesis",
        )

        approved = verify_stream(
            [reset],
            registry=policy,
            trust_policy=dataclasses.replace(
                reset_trust,
                approved_re_genesis_hashes=frozenset({reset["frame_hash"]}),
            ),
            signature_verifier=lambda frame: True,
        )
        self.assertTrue(approved.trusted)

    def test_trust_policy_can_apply_bootstrap_exact_integer_profile(self) -> None:
        first = genesis({"binary64": 0.1})
        policy, binary64_trust = authority(first)
        self.assertTrue(
            verify_stream(
                [first],
                registry=policy,
                trust_policy=binary64_trust,
            ).trusted
        )
        exact_registry, exact_trust = authority(
            first,
            number_profile="exact-integer",
        )
        exact_integer = check_stream(
            [first],
            registry=exact_registry,
            trust_policy=exact_trust,
        )
        self.assertEqual(
            exact_integer.diagnostics[-1].code,
            "trust-number-profile-mismatch",
        )
        for token, value in (
            (b"1.0", 1),
            (b"1e0", 1),
            (b"1e3", 1000),
            (b"10e2", 1000),
        ):
            with self.subTest(token=token):
                raw_frame = genesis({"value": value})
                raw = canonicalize(raw_frame).replace(
                    b'"value":' + canonicalize(value),
                    b'"value":' + token,
                    1,
                )
                parsed = strict_json_loads(raw)
                general_registry, general_trust = authority(parsed)
                self.assertTrue(
                    verify_stream(
                        [parsed],
                        registry=general_registry,
                        trust_policy=general_trust,
                    ).trusted
                )
                token_registry, token_trust = authority(
                    parsed,
                    number_profile="exact-integer",
                )
                exact = check_stream(
                    [parsed],
                    registry=token_registry,
                    trust_policy=token_trust,
                )
                self.assertEqual(
                    exact.diagnostics[-1].code,
                    "trust-number-profile-mismatch",
                )

    def test_infinite_iterator_and_zero_time_are_bounded(self) -> None:
        first = genesis()
        produced = 0

        def frames():
            nonlocal produced
            head = first
            while True:
                produced += 1
                yield head
                head = successor(
                    head,
                    {"seq": head["seq"] + 1},
                    utc=f"2026-08-30T00:00:{head['seq'] + 1:02d}.000Z",
                )

        from rapp_sdk.protocol import check_stream_local

        bounded = check_stream_local(
            frames(),
            registry=KindFamilyRegistry.local(
                {"body.pulse": "body"},
                genesis_hashes={RID: first["frame_hash"]},
            ),
            max_frames=8,
            max_seconds=1,
        )
        self.assertFalse(bounded.ok)
        self.assertEqual(bounded.diagnostics[-1].code, "frame-count-exceeded")
        self.assertLessEqual(produced, 9)

        timed = check_stream(
            [first],
            registry=registry(first),
            trust_policy=trust(first),
            max_seconds=0,
        )
        self.assertEqual(
            timed.diagnostics[-1].code,
            "verification-time-exceeded",
        )

    def test_report_and_exception_share_one_diagnostic(self) -> None:
        first = genesis()
        corrupt = copy.deepcopy(first)
        corrupt["payload"]["changed"] = True
        report = check_frame(
            corrupt,
            registry=registry(first),
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.diagnostics[-1].status, DiagnosticStatus.ERROR)
        with self.assertRaises(ProtocolError) as raised:
            report.require(ProtocolError)
        self.assertIs(raised.exception.diagnostic, report.diagnostics[-1])

    def test_local_verification_is_explicitly_untrusted(self) -> None:
        first = genesis()
        from rapp_sdk.protocol import check_stream_local

        report = check_stream_local(
            [first],
            registry=KindFamilyRegistry.local(
                {"body.pulse": "body"},
                genesis_hashes={RID: first["frame_hash"]},
            ),
        )
        self.assertTrue(report.ok)
        self.assertFalse(report.trusted)
        self.assertEqual(report.value.trust_label, "local-untrusted")
        self.assertEqual(report.diagnostics[-1].code, "local-untrusted")
        self.assertEqual(
            report.diagnostics[-1].status,
            DiagnosticStatus.WARNING,
        )


if __name__ == "__main__":
    unittest.main()
