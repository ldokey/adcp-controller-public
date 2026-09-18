from __future__ import annotations

import unittest

from adcp.projection import (
    InMemoryProjectionTarget,
    ProjectionDrift,
    ProjectionService,
    compare_projection,
)
from adcp.recovery import RecoveryAction, RecoveryManager
from tests._helpers import ControllerFixture


class EndToEndIntegrationTests(ControllerFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create_controller_execution()

    def projection_boundary(self):
        target = InMemoryProjectionTarget()
        service = ProjectionService(self.store, target)
        recovery = RecoveryManager(self.store, self.controller, projection=service)
        return target, service, recovery

    def test_end_to_end_happy_path(self) -> None:
        self.reach_accepted()
        target, service, recovery = self.projection_boundary()

        decision = recovery.resume_once("execution-1")
        expected = service.project("execution-1")

        self.assertEqual(decision.action, RecoveryAction.PROJECTED)
        self.assertEqual(
            compare_projection(expected, target).classification,
            ProjectionDrift.NO_DRIFT,
        )

    def test_end_to_end_rework_path(self) -> None:
        _, _, first_evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(
            first_evaluator,
            verdict="REWORK_REQUIRED",
            result={"verdict": "REWORK_REQUIRED"},
        )
        _, commit = self.complete_maker_attempt(marker="reworked")
        self.record_verification(commit)
        second_evaluator = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )
        self.complete_evaluator_sealed(
            second_evaluator, verdict="PASS", result={"verdict": "PASS"}
        )
        self.controller.accept("execution-1")
        target, _, recovery = self.projection_boundary()

        recovery.resume_once("execution-1")

        self.assertEqual(self.store.get_execution("execution-1")["maker_rework_count"], 1)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt WHERE role = 'MAKER'"
        ).fetchone()[0], 2)
        self.assertIn("execution-1", target.values)

    def test_end_to_end_blocked_infrastructure_path(self) -> None:
        _, _, evaluator = self.reach_evaluating()
        self.controller.fail_evaluator(
            evaluator, failure_code="EVALUATOR_RATE_LIMIT"
        )
        target, _, recovery = self.projection_boundary()

        decision = recovery.resume_once("execution-1")

        self.assertEqual(decision.action, RecoveryAction.TERMINAL)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "BLOCKED")
        self.assertEqual(self.store.get_execution("execution-1")["maker_rework_count"], 0)
        self.assertEqual(target.values, {})

    def test_end_to_end_approval_path(self) -> None:
        _, _, evaluator = self.reach_evaluating()
        binding = self.complete_evaluator_sealed(
            evaluator,
            verdict="PASS",
            result={"verdict": "PASS"},
            approval_required=True,
        )
        assert binding is not None
        self.controller.resolve_approval(
            "execution-1", binding, approved=True
        )
        target, _, recovery = self.projection_boundary()

        accepted = recovery.resume_once("execution-1", approval_required=True)
        projected = recovery.resume_once("execution-1", approval_required=True)

        self.assertEqual(accepted.action, RecoveryAction.ACCEPTED)
        self.assertEqual(projected.action, RecoveryAction.PROJECTED)
        self.assertIsNotNone(self.store.get_approval(binding.approval_id)["consumed_at"])
        self.assertIn("execution-1", target.values)

    def test_end_to_end_crash_resume_path(self) -> None:
        _, commit = self.complete_maker_attempt(marker="resume")
        recovery_without_projection = RecoveryManager(self.store, self.controller)
        self.persist_verification_result(commit)

        scheduled = recovery_without_projection.resume_once("execution-1")
        evaluator = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )
        self.persist_evaluation_result(evaluator)
        accepted = recovery_without_projection.resume_once("execution-1")
        target, _, recovery = self.projection_boundary()
        projected = recovery.resume_once("execution-1")

        self.assertEqual(scheduled.action, RecoveryAction.SCHEDULE_EVALUATOR)
        self.assertEqual(accepted.action, RecoveryAction.ACCEPTED)
        self.assertEqual(projected.action, RecoveryAction.PROJECTED)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM verification_result"
        ).fetchone()[0], 1)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM evaluation_result"
        ).fetchone()[0], 1)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM evidence_manifest"
        ).fetchone()[0], 1)
        self.assertIn("execution-1", target.values)


if __name__ == "__main__":
    unittest.main()
