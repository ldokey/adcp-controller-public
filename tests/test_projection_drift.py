from __future__ import annotations

import unittest

from adcp.projection import (
    InMemoryProjectionTarget,
    ProjectionDrift,
    ProjectionService,
    build_projection,
    compare_projection,
)
from tests._helpers import ControllerFixture


class ProjectionDriftTests(ControllerFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create_controller_execution()
        self.reach_accepted()
        self.target = InMemoryProjectionTarget()
        self.service = ProjectionService(self.store, self.target)
        self.expected = build_projection(self.store, "execution-1")

    def test_projection_missing_or_mismatch_detected_as_drift(self) -> None:
        missing = compare_projection(self.expected, self.target)
        self.assertEqual(
            missing.classification, ProjectionDrift.PROJECTION_MISSING_OR_STALE
        )
        self.assertTrue(missing.blocks_cutover)

        self.service.project("execution-1")
        self.target.values["execution-1"][1]["projection_version"] = 0
        stale = compare_projection(self.expected, self.target)
        self.assertEqual(
            stale.classification, ProjectionDrift.PROJECTION_MISSING_OR_STALE
        )

        self.target.values["execution-1"] = (
            self.expected.projection_identity,
            self.expected.as_dict(),
        )
        self.target.values["execution-1"][1]["risk"] = "HIGH"
        mismatch = compare_projection(self.expected, self.target)
        self.assertEqual(
            mismatch.classification, ProjectionDrift.PROJECTION_CONTENT_MISMATCH
        )

    def test_projection_target_unavailable_is_non_authoritative_blocker(self) -> None:
        self.target.available = False

        report = compare_projection(self.expected, self.target)

        self.assertEqual(
            report.classification, ProjectionDrift.PROJECTION_TARGET_UNAVAILABLE
        )
        self.assertTrue(report.blocks_cutover)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "ACCEPTED")

    def test_reconciliation_repairs_drift_idempotently(self) -> None:
        first = self.service.reconcile("execution-1")
        self.target.values["execution-1"][1]["approval_status"] = "corrupt"
        repaired = self.service.reconcile("execution-1")
        second = self.service.reconcile("execution-1")

        self.assertEqual(first.classification, ProjectionDrift.NO_DRIFT)
        self.assertEqual(repaired.classification, ProjectionDrift.NO_DRIFT)
        self.assertEqual(second.classification, ProjectionDrift.NO_DRIFT)
        self.assertEqual(
            len(list(self.store.connection.execute("SELECT * FROM projection_record"))),
            1,
        )


if __name__ == "__main__":
    unittest.main()
