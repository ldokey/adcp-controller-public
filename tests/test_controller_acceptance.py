from __future__ import annotations

import unittest

from adcp.controller import ApprovalBinding, ControllerError
from adcp.domain import StoreError, operation_key
from _helpers import ControllerFixture


class ControllerAcceptanceTests(ControllerFixture, unittest.TestCase):
    def approval_ready(self):
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        binding = self.complete_evaluator_sealed(
            evaluator, verdict="PASS", result={"summary": "pass"}, approval_required=True
        )
        assert binding is not None
        return binding

    def test_approval_required_waits(self) -> None:
        binding = self.approval_ready()
        row = self.store.get_execution("execution-1")
        self.assertEqual("WAITING_APPROVAL", row["state"])
        self.assertEqual("PENDING", self.store.get_approval(binding.approval_id)["status"])
        with self.assertRaisesRegex(ControllerError, "ACCEPTANCE_STATE_INVALID"):
            self.controller.accept("execution-1", approval=binding)

    def test_stale_or_wrong_approval_rejected(self) -> None:
        binding = self.approval_ready()
        with self.assertRaisesRegex(StoreError, "STALE_APPROVAL"):
            self.controller.resolve_approval(
                "execution-1", ApprovalBinding(binding.approval_id, "stale"), approved=True
            )
        self.controller.create_execution(self.controller_spec("execution-2", "slice-2"))
        with self.assertRaisesRegex(StoreError, "APPROVAL_EXECUTION_MISMATCH"):
            self.controller.resolve_approval("execution-2", binding, approved=True)

    def controller_spec(self, execution_id: str, slice_id: str):
        from adcp.domain import Environment, ExecutionCreate, RiskLevel
        from _helpers import HASH_A, HASH_B

        return ExecutionCreate(
            execution_id=execution_id, slice_id=slice_id, risk_level=RiskLevel.NORMAL,
            environment=Environment.TEST, contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B, source_root=str(self.repo), branch="main",
            base_commit=self.base_commit,
        )

    def test_approval_consumed_once_and_acceptance_idempotent(self) -> None:
        binding = self.approval_ready()
        self.controller.resolve_approval("execution-1", binding, approved=True)
        accepted = self.controller.accept("execution-1", approval=binding)
        version = accepted["state_version"]
        event_count = len(self.store.events("execution-1"))
        replay = self.controller.accept("execution-1", approval=binding)
        self.assertEqual((version, event_count), (replay["state_version"], len(self.store.events("execution-1"))))
        self.assertIsNotNone(self.store.get_approval(binding.approval_id)["consumed_at"])
        with self.assertRaisesRegex(StoreError, "APPROVAL_ALREADY_CONSUMED"):
            self.store.resolve_approval(
                binding.approval_id, execution_id="execution-1",
                authority_ref=binding.authority_ref, approved=True,
            )
        accepted_events = [event for event in self.store.events("execution-1") if event["event_type"] == "ACCEPTED"]
        self.assertEqual(1, len(accepted_events))

    def test_acceptance_is_atomic_on_approval_binding_failure(self) -> None:
        binding = self.approval_ready()
        self.controller.resolve_approval("execution-1", binding, approved=True)
        wrong = ApprovalBinding(binding.approval_id, "wrong-authority")
        with self.assertRaisesRegex(StoreError, "APPROVAL_BINDING_MISMATCH"):
            self.controller.accept("execution-1", approval=wrong)
        self.assertEqual("EVALUATING", self.store.get_execution("execution-1")["state"])
        self.assertIsNone(self.store.get_approval(binding.approval_id)["consumed_at"])
        self.assertEqual(0, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])

    def test_approval_is_stale_after_state_version_changes(self) -> None:
        binding = self.approval_ready()
        self.controller.resolve_approval("execution-1", binding, approved=True)
        row = self.store.get_execution("execution-1")
        released = self.store.release_lease(
            "execution-1", row["state_version"], operation_key("release-after-approval", {}),
            "controller-test", row["lease_generation"],
        )
        self.store.acquire_lease(
            "execution-1", released["state_version"], operation_key("reacquire-after-approval", {}),
            "controller-test",
        )
        with self.assertRaisesRegex(StoreError, "APPROVAL_BINDING_MISMATCH"):
            self.controller.accept("execution-1", approval=binding)
        self.assertIsNone(self.store.get_approval(binding.approval_id)["consumed_at"])
        self.assertEqual(0, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])

    def test_acceptance_revalidates_current_cross_row_bindings(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="PASS", result={})
        self.store.connection.execute(
            "UPDATE slice_execution SET authority_fingerprint = ? WHERE execution_id = 'execution-1'",
            ("c" * 64,),
        )
        with self.assertRaisesRegex(ControllerError, "ACCEPTANCE_EVIDENCE_REQUIRED"):
            self.controller.accept("execution-1")
        self.assertEqual("EVALUATING", self.store.get_execution("execution-1")["state"])
        self.assertEqual(0, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])

    def test_stale_fencing_token_prevents_acceptance_without_partial_rows(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="PASS", result={})
        self.clock.advance(61)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.controller.accept("execution-1")
        self.assertEqual("EVALUATING", self.store.get_execution("execution-1")["state"])
        self.assertEqual(0, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
