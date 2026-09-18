from __future__ import annotations

import unittest

from adcp.domain import ActorRole, ExecutionState, StoreError, operation_key
from _helpers import StoreFixture


class CasTests(StoreFixture, unittest.TestCase):
    def test_stale_state_version_rejected_without_event(self) -> None:
        self.create()
        self.acquire()
        before = len(self.store.events("execution-1"))
        with self.assertRaisesRegex(StoreError, "STALE_STATE_VERSION"):
            self.store.transition(
                "execution-1",
                0,
                operation_key("transition", {"stale": True}),
                ExecutionState.MAKER_RUNNING,
                actor_role=ActorRole.CONTROLLER,
                actor_id="controller-1",
                lease_owner="owner-1",
                lease_generation=1,
            )
        self.assertEqual(before, len(self.store.events("execution-1")))

    def test_each_semantic_increment_has_exactly_one_event(self) -> None:
        self.create()
        self.acquire()
        self.store.transition(
            "execution-1",
            1,
            operation_key("transition", {"target": "MAKER_RUNNING"}),
            ExecutionState.MAKER_RUNNING,
            actor_role=ActorRole.MAKER,
            actor_id="attempt-1",
            lease_owner="owner-1",
            lease_generation=1,
        )
        row = self.store.get_execution("execution-1")
        events = self.store.events("execution-1")
        self.assertEqual(row["state_version"] + 1, len(events))
        self.assertEqual(list(range(row["state_version"] + 1)), [e["to_state_version"] for e in events])


if __name__ == "__main__":
    unittest.main()
