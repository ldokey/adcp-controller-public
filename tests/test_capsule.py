from __future__ import annotations

import sqlite3
import unittest

from adcp.canonical import canonical_sha256
from adcp.capsule import (
    CapsuleRole,
    build_context_capsule,
    build_evaluator_capsule,
    build_maker_capsule,
)
from adcp.domain import StoreError
from _helpers import COMMIT_A, COMMIT_B, HASH_A, HASH_B, StoreFixture


def maker_fields() -> dict[str, object]:
    return {
        "slice": {"id": "C2"},
        "current_task": {"name": "context primitives"},
        "contract_fingerprint": HASH_A,
        "authority_fingerprint": HASH_B,
        "source_root": "/source",
        "branch": "wcp-06-mvp-a",
        "base_commit": COMMIT_A,
        "current_commit": COMMIT_B,
        "acceptance_criteria": ["AC-10"],
        "constraints": ["stdlib-only"],
        "risk": "NORMAL",
        "environment": "TEST",
        "allowed_actions": ["write-allowed-files"],
        "forbidden_actions": ["runner"],
        "relevant_authority_refs": ["WCP-06B"],
        "relevant_authority_excerpts": [{"ref": "WCP-06B", "text": "frozen"}],
    }


def evaluator_fields() -> dict[str, object]:
    return {
        "frozen_contract": {"id": "WCP-06C2"},
        "acceptance_criteria": ["AC-10"],
        "base_commit": COMMIT_A,
        "result_commit": COMMIT_B,
        "changed_file_manifest": ["src/adcp/capsule.py"],
        "diff": "diff --git ...",
        "deterministic_verification_result": {"verdict": "PASS"},
        "relevant_authority_refs": ["WCP-06B"],
        "relevant_authority_excerpts": [{"ref": "WCP-06B", "text": "frozen"}],
    }


class CapsuleTests(unittest.TestCase):
    def test_capsule_same_content_same_fingerprint(self) -> None:
        first = build_maker_capsule(maker_fields())
        reordered = dict(reversed(list(maker_fields().items())))
        second = build_maker_capsule(reordered)
        self.assertEqual(first.canonical_json, second.canonical_json)
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_capsule_role_changes_fingerprint(self) -> None:
        content = {"same": "content"}
        maker = build_context_capsule(CapsuleRole.MAKER, content)
        evaluator = build_context_capsule(CapsuleRole.EVALUATOR, content)
        self.assertNotEqual(maker.fingerprint, evaluator.fingerprint)

    def test_capsule_version_changes_fingerprint(self) -> None:
        first = build_context_capsule("MAKER", {"same": "content"}, capsule_version=1)
        second = build_context_capsule("MAKER", {"same": "content"}, capsule_version=2)
        self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_maker_capsule_structured_feedback_only(self) -> None:
        fields = maker_fields()
        fields["previous_structured_rework_feedback"] = "free-form transcript"
        with self.assertRaisesRegex(ValueError, "STRUCTURED_REWORK_FEEDBACK_REQUIRED"):
            build_maker_capsule(fields)
        fields["previous_structured_rework_feedback"] = {"issues": [{"code": "R1"}]}
        capsule = build_maker_capsule(fields)
        self.assertIn("previous_structured_rework_feedback", capsule.content)

    def test_evaluator_capsule_rejects_maker_reasoning(self) -> None:
        fields = evaluator_fields()
        fields["maker_reasoning"] = "hidden reasoning"
        with self.assertRaises(TypeError):
            build_evaluator_capsule(fields)

    def test_evaluator_capsule_rejects_maker_transcript(self) -> None:
        fields = evaluator_fields()
        fields["maker_transcript"] = "session transcript"
        with self.assertRaises(TypeError):
            build_evaluator_capsule(fields)

    def test_capsule_fingerprint_excludes_database_identity(self) -> None:
        capsule = build_context_capsule("MAKER", {"task": "same"})
        self.assertNotIn("context_snapshot_id", capsule.canonical_json)
        self.assertNotIn("execution_id", capsule.canonical_json)

    def test_capsule_content_requires_json_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "CAPSULE_CONTENT_OBJECT_REQUIRED"):
            build_context_capsule("MAKER", ["not", "an", "object"])  # type: ignore[arg-type]


class ContextSnapshotTests(StoreFixture, unittest.TestCase):
    def test_context_snapshot_register_and_read(self) -> None:
        self.create()
        capsule = build_maker_capsule(maker_fields())
        registered = self.store.register_context_snapshot(
            "snapshot-1", "execution-1", "MAKER", 1, capsule
        )
        fetched = self.store.get_context_snapshot("snapshot-1")
        self.assertEqual(registered["fingerprint"], capsule.fingerprint)
        self.assertEqual(fetched["canonical_json"], capsule.canonical_json)

    def test_context_snapshot_same_fingerprint_replay(self) -> None:
        self.create()
        capsule = build_maker_capsule(maker_fields())
        first = self.store.register_context_snapshot(
            "snapshot-1", "execution-1", "MAKER", 1, capsule
        )
        second = self.store.register_context_snapshot(
            "snapshot-2", "execution-1", "MAKER", 1, capsule
        )
        self.assertEqual(first["context_snapshot_id"], second["context_snapshot_id"])
        self.assertEqual(1, self.store.connection.execute("SELECT count(*) FROM context_snapshot").fetchone()[0])

    def test_context_snapshot_fingerprint_conflict_rejected(self) -> None:
        self.create()
        capsule = build_maker_capsule(maker_fields())
        self.store.connection.execute(
            "INSERT INTO context_snapshot VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "collision",
                "execution-1",
                "MAKER",
                1,
                capsule.fingerprint,
                '{"different":true}',
                "2026-08-11T01:02:03.456789+00:00",
            ),
        )
        with self.assertRaisesRegex(StoreError, "CONTEXT_FINGERPRINT_CONFLICT"):
            self.store.register_context_snapshot(
                "snapshot-1", "execution-1", "MAKER", 1, capsule
            )

    def test_context_snapshot_remains_database_immutable(self) -> None:
        self.create()
        capsule = build_maker_capsule(maker_fields())
        self.store.register_context_snapshot(
            "snapshot-1", "execution-1", "MAKER", 1, capsule
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_RECORD"):
            self.store.connection.execute(
                "UPDATE context_snapshot SET canonical_json = '{}' WHERE context_snapshot_id = 'snapshot-1'"
            )


if __name__ == "__main__":
    unittest.main()
