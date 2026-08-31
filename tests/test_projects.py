from __future__ import annotations

import hashlib
import json
import unittest

from rapp_sdk import (
    PROJECT_FRAME_KINDS,
    PROJECT_EVENTS,
    PROJECT_FRAME_KIND,
    ProtocolError,
    ProjectActor,
    ProjectCheckpoint,
    ProjectProtocolError,
    build_project_frame,
    build_project_rappid,
    build_project_egg_manifest,
    pack_project_egg,
    project_egg_address,
    read_project_egg,
    verify_project_egg_manifest,
    verify_project_stream,
)


class ProjectProtocolTests(unittest.TestCase):
    def test_actor_and_checkpoint_payloads_are_typed(self) -> None:
        actor = ProjectActor(
            id="claude-code",
            runtime="claude-code",
            session_id="session",
            capabilities=("files", "tests"),
        )
        checkpoint = ProjectCheckpoint(
            summary="Halfway",
            completed=("schema",),
            in_progress="store",
            next_action="finish store",
            resume_prompt="Continue the store.",
            cwd="/workspace",
            repository="https://github.com/example/project",
            branch="feature",
            head="a" * 40,
            dirty_paths=("src/store.py",),
            commands=("python -m unittest",),
            artifacts=(),
        )
        self.assertEqual(actor.as_payload()["runtime"], "claude-code")
        self.assertEqual(
            checkpoint.as_payload()["workspace"]["dirty_paths"],
            ["src/store.py"],
        )

    def test_build_and_verify_project_stream(self) -> None:
        stream = build_project_rappid("example", "project", b"seed")
        first = build_project_frame(
            "project.genesis",
            stream,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "project",
                "title": "Project",
                "goal": "Test",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        second = build_project_frame(
            "work.punchin",
            stream,
            1,
            "2026-08-31T00:00:01.000Z",
            {
                "project": "project",
                "actor": ProjectActor(
                    id="copilot",
                    runtime="copilot-cli",
                    session_id="s1",
                    capabilities=("shell",),
                ).as_payload(),
                "location": "/workspace",
                "intent": "test",
                "role": "builder",
                "lease_expires_utc": "2026-08-31T01:00:00.000Z",
            },
            first["payload_hash"],
        )
        verified = verify_project_stream([first, second], stream)
        self.assertEqual(verified.head.seq, 1)

    def test_unknown_kind_is_refused(self) -> None:
        with self.assertRaises(ProjectProtocolError):
            build_project_frame(
                "work.magic",
                build_project_rappid("example", "bad", b"seed"),
                0,
                "2026-08-31T00:00:00.000Z",
                {},
                None,
            )

    def test_project_egg_manifest_detects_tamper(self) -> None:
        rappid = build_project_rappid("example", "example", b"seed")
        frame = build_project_frame(
            "project.genesis",
            rappid,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "example",
                "title": "Example",
                "goal": "Test",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        filename = f"frames/{frame['seq']:020d}-{frame['frame_hash']}.json"
        created = "2026-08-31T00:00:00.000Z"
        contents = {
            "rappid.json": json.dumps({"rappid": rappid}).encode(),
            "soul.md": b"# Example project cell\n",
            filename: json.dumps(frame).encode(),
        }
        manifest = build_project_egg_manifest(
            project="example",
            rappid=rappid,
            head_frame_hash=frame["frame_hash"],
            visibility="local",
            contents=contents,
            created_utc=created,
        )
        verify_project_egg_manifest(manifest, contents)
        with self.assertRaises(ProjectProtocolError):
            verify_project_egg_manifest(
                manifest,
                {**contents, filename: b"changed\n"},
            )
        changed = dict(manifest)
        changed["payload"] = dict(manifest["payload"])
        changed["payload"]["visibility"] = "public"
        self.assertNotEqual(
            project_egg_address(changed),
            project_egg_address(manifest),
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_egg_manifest(changed, contents)
        changed = dict(manifest)
        changed["payload"] = dict(manifest["payload"])
        changed["payload"]["project"] = "renamed"
        with self.assertRaises(ProjectProtocolError):
            verify_project_egg_manifest(changed, contents)
        first = pack_project_egg(manifest, contents)
        second = pack_project_egg(manifest, contents)
        self.assertEqual(first, second)
        unpacked_manifest, unpacked_contents = read_project_egg(first)
        self.assertEqual(unpacked_manifest, manifest)
        self.assertEqual(unpacked_contents, contents)

    def test_kind_set_is_stable(self) -> None:
        self.assertEqual(PROJECT_FRAME_KINDS, ("body.pulse",))
        self.assertEqual(PROJECT_FRAME_KIND, "body.pulse")
        self.assertEqual(len(PROJECT_EVENTS), 12)
        self.assertIn("cell.absorb", PROJECT_EVENTS)
        self.assertIn("cell.policy", PROJECT_EVENTS)
        self.assertIn("cell.cycle", PROJECT_EVENTS)

    def test_stream_requires_one_matching_genesis(self) -> None:
        stream = build_project_rappid("example", "alpha", b"seed")
        punchin = build_project_frame(
            "work.punchin",
            stream,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "alpha",
                "actor": ProjectActor(
                    id="a",
                    runtime="a",
                    session_id="s",
                ).as_payload(),
                "location": "/tmp",
                "intent": "work",
                "role": "builder",
                "lease_expires_utc": "2026-08-31T01:00:00.000Z",
            },
            None,
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_stream([punchin], stream)

    def test_payload_types_and_rappid_lengths_are_strict(self) -> None:
        with self.assertRaises(ProjectProtocolError):
            build_project_rappid("a" * 40, "alpha", b"seed")
        stream = build_project_rappid("example", "alpha", b"seed")
        with self.assertRaises(ProjectProtocolError):
            build_project_frame(
                "project.genesis",
                stream,
                0,
                "2026-08-31T00:00:00.000Z",
                {
                    "project": 1,
                    "title": True,
                    "goal": [],
                    "owner": {},
                    "origin": None,
                    "visibility": "wrong",
                },
                None,
            )

    def test_imported_stream_cannot_bypass_lease_or_cell_policy(self) -> None:
        stream = build_project_rappid("example", "alpha", b"seed")
        actor_a = ProjectActor(
            id="a",
            runtime="runtime-a",
            session_id="a1",
        )
        actor_b = ProjectActor(
            id="b",
            runtime="runtime-b",
            session_id="b1",
        )
        genesis = build_project_frame(
            "project.genesis",
            stream,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "alpha",
                "title": "Alpha",
                "goal": "Test transitions",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        punchin = build_project_frame(
            "work.punchin",
            stream,
            1,
            "2026-08-31T00:00:01.000Z",
            {
                "project": "alpha",
                "actor": actor_a.as_payload(),
                "location": "/tmp",
                "intent": "work",
                "role": "builder",
                "lease_expires_utc": "2026-08-31T01:00:00.000Z",
            },
            genesis["payload_hash"],
        )
        foreign_status = build_project_frame(
            "work.status",
            stream,
            2,
            "2026-08-31T00:00:02.000Z",
            {
                "project": "alpha",
                "actor": actor_b.as_payload(),
                "location": "/tmp",
                "status": "working",
                "artifacts": [],
                "blockers": [],
                "next_action": "continue",
                "pct": 10,
            },
            punchin["payload_hash"],
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_stream([genesis, punchin, foreign_status], stream)

        unsafe_policy = build_project_frame(
            "cell.policy",
            stream,
            2,
            "2026-08-31T00:00:02.000Z",
            {
                "project": "alpha",
                "actor": actor_a.as_payload(),
                "cadence_seconds": 60,
                "may": ["read", "pay"],
                "never": [],
                "budgets": {
                    "max_cycles": 3,
                    "max_seconds_per_cycle": 30,
                },
                "stop_conditions": [],
                "human_gates": [],
                "next_wakeup_utc": "2026-08-31T00:01:02.000Z",
            },
            punchin["payload_hash"],
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_stream([genesis, punchin, unsafe_policy], stream)

    def test_malformed_frame_and_wrong_takeover_receipt_fail_cleanly(self) -> None:
        stream = build_project_rappid("example", "alpha", b"seed")
        actor = ProjectActor(id="a", runtime="a", session_id="s")
        genesis = build_project_frame(
            "project.genesis",
            stream,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "alpha",
                "title": "Alpha",
                "goal": "Test",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        punchin = build_project_frame(
            "work.punchin",
            stream,
            1,
            "2026-08-31T00:00:01.000Z",
            {
                "project": "alpha",
                "actor": actor.as_payload(),
                "location": "/tmp",
                "intent": "work",
                "role": "builder",
                "lease_expires_utc": "2026-08-31T00:00:02.000Z",
            },
            genesis["payload_hash"],
        )
        malformed = dict(punchin)
        malformed.pop("utc")
        with self.assertRaises(ProtocolError):
            verify_project_stream([genesis, malformed], stream)
        takeover = build_project_frame(
            "work.takeover",
            stream,
            2,
            "2026-08-31T00:00:03.000Z",
            {
                "project": "alpha",
                "from_actor": actor.as_payload(),
                "to_actor": ProjectActor(
                    id="b", runtime="b", session_id="s2"
                ).as_payload(),
                "location": "/tmp",
                "reason": "expired",
                "expired_lease_frame_hash": "f" * 64,
                "lease_expires_utc": "2026-08-31T01:00:03.000Z",
            },
            punchin["payload_hash"],
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_stream([genesis, punchin, takeover], stream)
        heartbeat = build_project_frame(
            "work.heartbeat",
            stream,
            2,
            "2026-08-31T00:00:02.000Z",
            {
                "project": "alpha",
                "actor": actor.as_payload(),
                "lease_expires_utc": "2026-08-31T00:00:01.500Z",
                "status": "revive",
            },
            punchin["payload_hash"],
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_stream([genesis, punchin, heartbeat], stream)

    def test_noncanonical_frame_entry_is_refused(self) -> None:
        rappid = build_project_rappid("example", "nested", b"seed")
        frame = build_project_frame(
            "project.genesis",
            rappid,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "nested",
                "title": "Nested",
                "goal": "Reject nested frame paths",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        created = "2026-08-31T00:00:00.000Z"
        contents = {
            "rappid.json": json.dumps({"rappid": rappid}).encode(),
            "soul.md": b"# Nested project cell\n",
            "frames/sub/frame.json": json.dumps(frame).encode(),
        }
        manifest = build_project_egg_manifest(
            project="nested",
            rappid=rappid,
            head_frame_hash=frame["frame_hash"],
            visibility="local",
            contents=contents,
            created_utc=created,
        )
        with self.assertRaises(ProjectProtocolError):
            verify_project_egg_manifest(manifest, contents)

    def test_handoff_receipt_is_bound_to_archived_bytes(self) -> None:
        rappid = build_project_rappid("example", "handoff", b"seed")
        first_actor = ProjectActor(id="a", runtime="a", session_id="s1")
        second_actor = ProjectActor(id="b", runtime="b", session_id="s2")
        genesis = build_project_frame(
            "project.genesis",
            rappid,
            0,
            "2026-08-31T00:00:00.000Z",
            {
                "project": "handoff",
                "title": "Handoff",
                "goal": "Bind bytes",
                "owner": "example",
                "origin": "test",
                "visibility": "local",
            },
            None,
        )
        punchin = build_project_frame(
            "work.punchin",
            rappid,
            1,
            "2026-08-31T00:00:01.000Z",
            {
                "project": "handoff",
                "actor": first_actor.as_payload(),
                "location": "/tmp",
                "intent": "handoff",
                "role": "builder",
                "lease_expires_utc": "2026-08-31T01:00:00.000Z",
            },
            genesis["payload_hash"],
        )
        document = b"# Handoff\n"
        document_path = "docs/notes/handoff.md"
        handoff = build_project_frame(
            "work.handoff",
            rappid,
            2,
            "2026-08-31T00:00:02.000Z",
            {
                "project": "handoff",
                "from_actor": first_actor.as_payload(),
                "to_actor": second_actor.as_payload(),
                "document": {
                    "path": document_path,
                    "scope": "project",
                    "sha256": hashlib.sha256(document).hexdigest(),
                    "bytes": len(document),
                },
                "open_questions": [],
            },
            punchin["payload_hash"],
        )
        created = "2026-08-31T00:00:03.000Z"
        contents = {
            "rappid.json": json.dumps({"rappid": rappid}).encode(),
            "soul.md": b"# Project cell\n",
            document_path: document,
        }
        for frame in (genesis, punchin, handoff):
            name = f"frames/{frame['seq']:020d}-{frame['frame_hash']}.json"
            contents[name] = json.dumps(frame).encode()
        manifest = build_project_egg_manifest(
            project="handoff",
            rappid=rappid,
            head_frame_hash=handoff["frame_hash"],
            visibility="local",
            contents=contents,
            created_utc=created,
        )
        verify_project_egg_manifest(manifest, contents)
        with self.assertRaises(ProjectProtocolError):
            verify_project_egg_manifest(
                manifest,
                {**contents, document_path: b"tampered"},
            )


if __name__ == "__main__":
    unittest.main()
