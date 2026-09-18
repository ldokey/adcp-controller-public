from __future__ import annotations

import unittest

from adcp.domain import (
    ActorRole,
    BLOCKED_RESUME_STATES,
    ExecutionState,
    StoreError,
    TRANSITIONS,
    operation_key,
)
from _helpers import StoreFixture


class TransitionTests(StoreFixture, unittest.TestCase):
    def transition(self, version: int, target: ExecutionState, **kwargs):
        payload = {"version": version, "target": target.value, **{k: str(v) for k, v in kwargs.items()}}
        return self.store.transition(
            "execution-1",
            version,
            operation_key("state-transition", payload),
            target,
            actor_role=ActorRole.CONTROLLER,
            actor_id="controller-1",
            lease_owner="owner-1",
            lease_generation=1,
            **kwargs,
        )

    def test_exact_transition_topology(self) -> None:
        expected = {
            "READY": {"MAKER_RUNNING", "BLOCKED", "CANCELLED"},
            "MAKER_RUNNING": {"VERIFYING", "BLOCKED", "DESIGN_ESCALATION", "CANCELLED"},
            "VERIFYING": {"EVALUATING", "REWORK_READY", "DESIGN_ESCALATION", "BLOCKED", "CANCELLED"},
            "EVALUATING": {"ACCEPTED", "REWORK_READY", "DESIGN_ESCALATION", "WAITING_APPROVAL", "BLOCKED", "CANCELLED"},
            "REWORK_READY": {"MAKER_RUNNING", "BLOCKED", "CANCELLED"},
            "WAITING_APPROVAL": {"EVALUATING", "DESIGN_ESCALATION", "CANCELLED"},
            "BLOCKED": set(),
            "DESIGN_ESCALATION": set(),
            "ACCEPTED": set(),
            "CANCELLED": set(),
        }
        actual = {
            state.value: {target.value for target in targets}
            for state, targets in TRANSITIONS.items()
        }
        self.assertEqual(expected, actual)
        self.assertEqual(
            {"READY", "VERIFYING", "EVALUATING", "REWORK_READY"},
            {state.value for state in BLOCKED_RESUME_STATES},
        )

    def test_valid_topology_and_terminal_state(self) -> None:
        self.create()
        self.acquire()
        row = self.transition(1, ExecutionState.MAKER_RUNNING)
        row = self.transition(2, ExecutionState.VERIFYING)
        row = self.transition(3, ExecutionState.EVALUATING)
        row = self.transition(4, ExecutionState.ACCEPTED)
        self.assertEqual("ACCEPTED", row["state"])
        self.assertIsNotNone(row["accepted_at"])
        with self.assertRaisesRegex(StoreError, "INVALID_TRANSITION"):
            self.store.acquire_lease(
                "execution-1", 5, operation_key("lease", {"terminal": True}), "owner-2"
            )

    def test_invalid_transition_rolls_back_state_and_evidence(self) -> None:
        self.create()
        self.acquire()
        before = len(self.store.events("execution-1"))
        with self.assertRaisesRegex(StoreError, "INVALID_TRANSITION"):
            self.transition(1, ExecutionState.EVALUATING)
        row = self.store.get_execution("execution-1")
        self.assertEqual(("READY", 1), (row["state"], row["state_version"]))
        self.assertEqual(before, len(self.store.events("execution-1")))

    def test_blocked_resume_state_is_structural_and_consumed(self) -> None:
        self.create()
        self.acquire()
        blocked = self.transition(
            1,
            ExecutionState.BLOCKED,
            resume_state=ExecutionState.READY,
            blocker_code="ENVIRONMENT",
        )
        self.assertEqual("READY", blocked["resume_state"])
        resumed = self.transition(2, ExecutionState.READY)
        self.assertIsNone(resumed["resume_state"])
        self.assertIsNone(resumed["blocker_code"])

    def test_invalid_blocked_resume_state_rejected(self) -> None:
        self.create()
        self.acquire()
        with self.assertRaisesRegex(StoreError, "INVALID_TRANSITION"):
            self.transition(
                1,
                ExecutionState.BLOCKED,
                resume_state=ExecutionState.MAKER_RUNNING,
                blocker_code="BAD",
            )

    def test_waiting_approval_resume_contract(self) -> None:
        self.create()
        self.acquire()
        self.transition(1, ExecutionState.MAKER_RUNNING)
        self.transition(2, ExecutionState.VERIFYING)
        self.transition(3, ExecutionState.EVALUATING)
        with self.assertRaisesRegex(StoreError, "INVALID_TRANSITION"):
            self.transition(
                4,
                ExecutionState.WAITING_APPROVAL,
                resume_state=ExecutionState.READY,
            )
        waiting = self.transition(
            4,
            ExecutionState.WAITING_APPROVAL,
            resume_state=ExecutionState.EVALUATING,
        )
        self.assertEqual("EVALUATING", waiting["resume_state"])


if __name__ == "__main__":
    unittest.main()
