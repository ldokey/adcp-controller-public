from __future__ import annotations

import unittest
from unittest.mock import patch

from adcp.controller import ApprovalBinding, ControllerError
from adcp.domain import RiskLevel, StoreError, operation_key, timestamp
from _helpers import ControllerFixture


class ControllerRetryTests(ControllerFixture, unittest.TestCase):
    def reach_high_verification_failure(self):
        self.create_controller_execution(risk=RiskLevel.HIGH)
        run, result_commit = self.complete_maker_attempt(marker="high-initial")
        self.record_verification(result_commit, verdict="FAIL")
        row = self.store.get_execution("execution-1")
        self.assertEqual(
            ("BLOCKED", "VERIFYING", "VERIFICATION_FAILED", 0, 0),
            (
                row["state"], row["resume_state"], row["blocker_code"],
                row["maker_rework_count"], row["max_auto_reworks"],
            ),
        )
        return run, result_commit

    def approve_high_rework(self):
        binding = self.controller.request_high_rework_approval("execution-1")
        self.controller.resolve_approval("execution-1", binding, approved=True)
        return binding

    def test_human_authorized_high_rework_is_explicit_single_use_and_requires_fresh_verification(self) -> None:
        _, old_result = self.reach_high_verification_failure()
        binding = self.controller.request_high_rework_approval("execution-1")
        with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_APPROVAL_REQUIRED"):
            self.controller.authorize_high_rework("execution-1", binding)
        self.controller.resolve_approval("execution-1", binding, approved=True)
        authorized = self.controller.authorize_high_rework("execution-1", binding)
        self.assertEqual(
            ("REWORK_READY", 0, 0),
            (authorized["state"], authorized["maker_rework_count"], authorized["max_auto_reworks"]),
        )

        with patch.object(
            self.controller.worktrees, "create",
            side_effect=AssertionError("automatic HIGH caller provisioned a candidate"),
        ) as create_candidate:
            with self.assertRaisesRegex(ControllerError, "HUMAN_HIGH_REWORK_APPROVAL_REQUIRED"):
                self.controller.begin_maker("execution-1", self.maker_capsule())
        create_candidate.assert_not_called()
        self.assertEqual(
            ("REWORK_READY", 0),
            (self.store.get_execution("execution-1")["state"],
             self.store.get_execution("execution-1")["maker_rework_count"]),
        )

        run = self.controller.begin_human_authorized_high_rework(
            "execution-1", self.maker_capsule(), binding
        )
        attempt = self.store.get_agent_attempt(run.attempt_id)
        approval = self.store.get_approval(binding.approval_id)
        self.assertEqual(2, attempt["attempt_no"])
        self.assertEqual("MAKER_RUNNING", self.store.get_execution("execution-1")["state"])
        self.assertEqual(0, self.store.get_execution("execution-1")["maker_rework_count"])
        self.assertIsNotNone(approval["consumed_at"])

        (run.candidate.path / "tracked.txt").write_text("high-rework-2\n", encoding="utf-8")
        new_result = self.controller.complete_maker(run, commit_message="human high rework")
        self.assertNotEqual(old_result, new_result)
        self.assertEqual(
            old_result,
            __import__("subprocess").run(
                ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD^"],
                check=True, capture_output=True, text=True,
            ).stdout.strip(),
        )
        row = self.store.get_execution("execution-1")
        self.assertEqual(("VERIFYING", new_result), (row["state"], row["result_commit"]))
        self.assertFalse(self.store.has_verification_pass(
            "execution-1", new_result, row["contract_fingerprint"], row["authority_fingerprint"]
        ))
        with self.assertRaisesRegex(ControllerError, "EVALUATOR_STATE_INVALID"):
            self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        self.record_verification(new_result, verdict="PASS")
        evaluator = self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        self.assertEqual(1, self.store.get_agent_attempt(evaluator)["attempt_no"])

    def test_high_rework_approval_rejects_stale_mismatched_or_consumed_binding(self) -> None:
        cases = ("wrong-ref", "new-evidence", "wrong-state", "wrong-result", "consumed")
        for case in cases:
            with self.subTest(case=case):
                if case != cases[0]:
                    self.tearDown()
                    self.setUp()
                _, old_result = self.reach_high_verification_failure()
                binding = self.approve_high_rework()
                if case == "wrong-ref":
                    forged = ApprovalBinding(binding.approval_id, "f" * 64)
                    with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_APPROVAL_STALE"):
                        self.controller.authorize_high_rework("execution-1", forged)
                    with self.assertRaisesRegex(StoreError, "EXECUTION_NOT_FOUND"):
                        self.controller.authorize_high_rework("wrong-execution", binding)
                elif case == "new-evidence":
                    self.persist_verification_result(old_result, verdict="FAIL")
                    with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_APPROVAL_STALE"):
                        self.controller.authorize_high_rework("execution-1", binding)
                elif case == "wrong-state":
                    self.controller._transition(
                        "execution-1",
                        __import__("adcp.domain", fromlist=["ExecutionState"]).ExecutionState.VERIFYING,
                        reason="TEST_RESUME",
                    )
                    with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_STATE_INVALID"):
                        self.controller.authorize_high_rework("execution-1", binding)
                elif case == "wrong-result":
                    self.store.connection.execute(
                        "UPDATE slice_execution SET result_commit=? WHERE execution_id=?",
                        (self.base_commit, "execution-1"),
                    )
                    with self.assertRaisesRegex(
                        ControllerError, "HIGH_REWORK_ATTEMPT_TOPOLOGY_INVALID"
                    ):
                        self.controller.authorize_high_rework("execution-1", binding)
                else:
                    self.controller.authorize_high_rework("execution-1", binding)
                    self.store.connection.execute(
                        "UPDATE approval_request SET consumed_at=? WHERE approval_id=?",
                        (timestamp(self.store._now()), binding.approval_id),
                    )
                    with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_APPROVAL_CONSUMED"):
                        self.controller.begin_human_authorized_high_rework(
                            "execution-1", self.maker_capsule(), binding
                        )

    def test_high_rework_allows_only_one_human_maker_rework_per_execution(self) -> None:
        self.reach_high_verification_failure()
        binding = self.approve_high_rework()
        self.controller.authorize_high_rework("execution-1", binding)
        run = self.controller.begin_human_authorized_high_rework(
            "execution-1", self.maker_capsule(), binding
        )
        (run.candidate.path / "tracked.txt").write_text("second-result\n", encoding="utf-8")
        second_result = self.controller.complete_maker(run, commit_message="second maker result")
        self.record_verification(second_result, verdict="FAIL")
        with self.assertRaisesRegex(ControllerError, "HIGH_REWORK_ATTEMPT_TOPOLOGY_INVALID"):
            self.controller.request_high_rework_approval("execution-1")
        row = self.store.get_execution("execution-1")
        self.assertEqual((0, 0), (row["maker_rework_count"], row["max_auto_reworks"]))

    def test_high_rework_schedule_rejects_stale_state_and_fencing(self) -> None:
        self.reach_high_verification_failure()
        binding = self.approve_high_rework()
        row = self.controller.authorize_high_rework("execution-1", binding)
        with self.assertRaisesRegex(StoreError, "STALE_STATE_VERSION"):
            self.store.schedule_human_authorized_rework(
                "execution-1", row["state_version"] - 1,
                operation_key("stale-human-high-rework", {}),
                approval_id=binding.approval_id, authority_ref=binding.authority_ref,
                lease_owner="controller-test", lease_generation=row["lease_generation"],
            )
        self.clock.advance(61)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.schedule_human_authorized_rework(
                "execution-1", row["state_version"],
                operation_key("expired-human-high-rework", {}),
                approval_id=binding.approval_id, authority_ref=binding.authority_ref,
                lease_owner="controller-test", lease_generation=row["lease_generation"],
            )
        current = self.store.get_execution("execution-1")
        self.assertEqual(("REWORK_READY", 0), (current["state"], current["maker_rework_count"]))
        self.assertIsNone(self.store.get_approval(binding.approval_id)["consumed_at"])

    def test_rework_required_consumes_budget_only_when_scheduled(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="REWORK_REQUIRED", result={"feedback": []})
        row = self.store.get_execution("execution-1")
        self.assertEqual(("REWORK_READY", 0), (row["state"], row["maker_rework_count"]))
        self.controller.begin_maker("execution-1", self.maker_capsule())
        row = self.store.get_execution("execution-1")
        self.assertEqual(("MAKER_RUNNING", 1), (row["state"], row["maker_rework_count"]))

    def test_stale_state_version_prevents_rework_transition(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="REWORK_REQUIRED", result={})
        row = self.store.get_execution("execution-1")
        with self.assertRaisesRegex(StoreError, "STALE_STATE_VERSION"):
            self.store.schedule_rework(
                "execution-1", row["state_version"] - 1,
                operation_key("stale-rework", {}), lease_owner="controller-test",
                lease_generation=row["lease_generation"],
            )
        self.assertEqual(("REWORK_READY", 0),
                         (self.store.get_execution("execution-1")["state"],
                          self.store.get_execution("execution-1")["maker_rework_count"]))

    def test_low_normal_rework_ceiling_two(self) -> None:
        for risk in (RiskLevel.LOW, RiskLevel.NORMAL):
            with self.subTest(risk=risk):
                self.tearDown()
                self.setUp()
                self.create_controller_execution(risk=risk)
                _, commit, evaluator = self.reach_evaluating()
                self.complete_evaluator_sealed(evaluator, verdict="REWORK_REQUIRED", result={})
                for number in (1, 2):
                    run = self.controller.begin_maker("execution-1", self.maker_capsule())
                    (run.candidate.path / "tracked.txt").write_text(f"rework-{number}\n", encoding="utf-8")
                    commit = self.controller.complete_maker(run, commit_message=f"rework {number}")
                    self.record_verification(commit)
                    evaluator = self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
                    self.complete_evaluator_sealed(evaluator, verdict="REWORK_REQUIRED", result={})
                row = self.store.get_execution("execution-1")
                self.assertEqual(("DESIGN_ESCALATION", 2, 2),
                                 (row["state"], row["maker_rework_count"], row["max_auto_reworks"]))

    def test_high_automatic_rework_zero(self) -> None:
        self.create_controller_execution(risk=RiskLevel.HIGH)
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="REWORK_REQUIRED", result={})
        row = self.store.get_execution("execution-1")
        self.assertEqual(("DESIGN_ESCALATION", 0, 0),
                         (row["state"], row["maker_rework_count"], row["max_auto_reworks"]))

    def test_environment_and_evidence_blocks_do_not_consume_rework(self) -> None:
        for verdict in ("BLOCKED_ENVIRONMENT", "BLOCKED_EVIDENCE"):
            with self.subTest(verdict=verdict):
                self.tearDown()
                self.setUp()
                self.create_controller_execution()
                _, _, evaluator = self.reach_evaluating()
                self.complete_evaluator_sealed(evaluator, verdict=verdict, result={})
                row = self.store.get_execution("execution-1")
                self.assertEqual(("BLOCKED", 0, verdict),
                                 (row["state"], row["maker_rework_count"], row["blocker_code"]))

    def test_design_review_required_escalates_immediately(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="DESIGN_REVIEW_REQUIRED", result={})
        row = self.store.get_execution("execution-1")
        self.assertEqual(("DESIGN_ESCALATION", 0), (row["state"], row["maker_rework_count"]))

    def test_evaluator_infrastructure_failure_does_not_consume_rework(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.controller.fail_evaluator(evaluator, failure_code="EVALUATOR_TIMEOUT")
        row = self.store.get_execution("execution-1")
        self.assertEqual(("BLOCKED", 0, "EVALUATOR_TIMEOUT"),
                         (row["state"], row["maker_rework_count"], row["blocker_code"]))


if __name__ == "__main__":
    unittest.main()
