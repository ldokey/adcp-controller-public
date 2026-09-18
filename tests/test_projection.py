from __future__ import annotations

import unittest

from adcp.projection import (
    InMemoryProjectionTarget,
    ProjectionService,
    ProjectionTargetUnavailable,
    build_projection,
)
from tests._helpers import ControllerFixture


class ProjectionTests(ControllerFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create_controller_execution()

    def test_projection_is_canonical_and_hash_stable(self) -> None:
        _, commit, _ = self.reach_accepted()

        first = build_projection(self.store, "execution-1")
        second = build_projection(self.store, "execution-1")

        self.assertEqual(first, second)
        self.assertEqual(first.payload["result_commit"], commit)
        self.assertEqual(first.payload["execution_state"], "ACCEPTED")
        self.assertEqual(first.payload["evidence_manifest_hash"], self.store.connection.execute(
            "SELECT manifest_sha256 FROM evidence_manifest WHERE execution_id = ?",
            ("execution-1",),
        ).fetchone()[0])
        self.assertEqual(len(first.projection_payload_hash), 64)
        self.assertEqual(len(first.projection_identity), 64)

    def test_projection_reads_machine_state_from_store_only(self) -> None:
        self.reach_accepted()
        target = InMemoryProjectionTarget()
        service = ProjectionService(self.store, target)
        expected = service.project("execution-1")
        target.values["execution-1"][1]["execution_state"] = "READY"

        rebuilt = build_projection(self.store, "execution-1")

        self.assertEqual(rebuilt, expected)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "ACCEPTED")

    def test_projection_retry_is_idempotent_after_lost_response(self) -> None:
        self.reach_accepted()
        target = InMemoryProjectionTarget()
        target.lose_response_once = True
        service = ProjectionService(self.store, target)

        with self.assertRaises(ProjectionTargetUnavailable):
            service.project("execution-1")
        first_identity = target.values["execution-1"][0]
        projected = service.project("execution-1")

        self.assertEqual(projected.projection_identity, first_identity)
        records = list(self.store.connection.execute("SELECT * FROM projection_record"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "SUCCEEDED")
        self.assertEqual(records[0]["attempt_count"], 2)

    def test_projection_failure_does_not_rollback_accepted(self) -> None:
        self.reach_accepted()
        manifest_before = self.store.connection.execute(
            "SELECT manifest_sha256 FROM evidence_manifest WHERE execution_id = ?",
            ("execution-1",),
        ).fetchone()[0]
        target = InMemoryProjectionTarget()
        target.fail_writes = 1

        with self.assertRaises(ProjectionTargetUnavailable):
            ProjectionService(self.store, target).project("execution-1")

        self.assertEqual(self.store.get_execution("execution-1")["state"], "ACCEPTED")
        self.assertEqual(self.store.connection.execute(
            "SELECT manifest_sha256 FROM evidence_manifest WHERE execution_id = ?",
            ("execution-1",),
        ).fetchone()[0], manifest_before)
        self.assertEqual(self.store.connection.execute(
            "SELECT status FROM projection_record"
        ).fetchone()[0], "FAILED")
        self.assertNotIn("execution-1", target.values)


if __name__ == "__main__":
    unittest.main()
