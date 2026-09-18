from __future__ import annotations

import unittest

from adcp.domain import ActorRole, ExecutionState, StoreError, operation_key
from _helpers import COMMIT_B, StoreFixture


class IdempotencyTests(StoreFixture, unittest.TestCase):
    def test_create_same_key_same_payload_replays_without_duplicate(self) -> None:
        spec = self.spec()
        key = operation_key("create-execution", {"execution_id": "execution-1"})
        first = self.store.create_execution(spec, key)
        second = self.store.create_execution(spec, key)
        self.assertEqual(first["execution_id"], second["execution_id"])
        self.assertEqual(1, len(self.store.events("execution-1")))

    def test_create_same_key_different_payload_conflicts(self) -> None:
        key = operation_key("create-execution", {"stable": "key"})
        self.store.create_execution(self.spec(), key)
        with self.assertRaisesRegex(StoreError, "IDEMPOTENCY_CONFLICT"):
            self.store.create_execution(self.spec("execution-2", "slice-2"), key)

    def test_transition_replay_and_conflict_do_not_duplicate_event(self) -> None:
        self.create()
        self.acquire()
        key = operation_key("transition", {"stable": "key"})
        kwargs = dict(
            actor_role=ActorRole.MAKER,
            actor_id="attempt-1",
            lease_owner="owner-1",
            lease_generation=1,
        )
        first = self.store.transition(
            "execution-1", 1, key, ExecutionState.MAKER_RUNNING, **kwargs
        )
        second = self.store.transition(
            "execution-1", 1, key, ExecutionState.MAKER_RUNNING, **kwargs
        )
        self.assertEqual(first["state_version"], second["state_version"])
        self.assertEqual(3, len(self.store.events("execution-1")))
        with self.assertRaisesRegex(StoreError, "IDEMPOTENCY_CONFLICT"):
            self.store.transition(
                "execution-1", 1, key, ExecutionState.BLOCKED,
                resume_state=ExecutionState.READY,
                blocker_code="DIFFERENT",
                **kwargs,
            )
        self.assertEqual(3, len(self.store.events("execution-1")))

    def test_lease_acquisition_and_release_replay(self) -> None:
        self.create()
        acquire_key = operation_key("lease", {"key": "acquire"})
        first = self.store.acquire_lease("execution-1", 0, acquire_key, "owner-1")
        second = self.store.acquire_lease("execution-1", 0, acquire_key, "owner-1")
        self.assertEqual(first["state_version"], second["state_version"])
        release_key = operation_key("lease", {"key": "release"})
        first = self.store.release_lease("execution-1", 1, release_key, "owner-1", 1)
        second = self.store.release_lease("execution-1", 1, release_key, "owner-1", 1)
        self.assertEqual(first["state_version"], second["state_version"])
        self.assertEqual(3, len(self.store.events("execution-1")))

    def test_result_commit_registration_replay_conflict_and_duplicate_event(self) -> None:
        self.create()
        self.acquire()
        key = operation_key("result-commit", {"stable": "key"})
        kwargs = dict(lease_owner="owner-1", lease_generation=1, actor_id="attempt-1")
        first = self.store.register_result_commit(
            "execution-1", 1, key, COMMIT_B, **kwargs
        )
        second = self.store.register_result_commit(
            "execution-1", 1, key, COMMIT_B, **kwargs
        )
        self.assertEqual(COMMIT_B, second["result_commit"])
        self.assertEqual(first["state_version"], second["state_version"])
        self.assertEqual(3, len(self.store.events("execution-1")))
        with self.assertRaisesRegex(StoreError, "IDEMPOTENCY_CONFLICT"):
            self.store.register_result_commit(
                "execution-1", 1, key, "3" * 40, **kwargs
            )
        self.assertEqual(3, len(self.store.events("execution-1")))


if __name__ == "__main__":
    unittest.main()
