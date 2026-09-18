from __future__ import annotations

import unittest

from adcp.domain import ActorRole, ExecutionState, StoreError, operation_key
from _helpers import StoreFixture


class FencingTests(StoreFixture, unittest.TestCase):
    def test_initial_acquisition_heartbeat_and_release(self) -> None:
        self.create()
        acquired = self.acquire()
        self.assertEqual(("owner-1", 1, 1), (acquired["lease_owner"], acquired["lease_generation"], acquired["state_version"]))
        event_count = len(self.store.events("execution-1"))
        expiry = acquired["lease_expires_at"]
        self.clock.advance(10)
        heartbeat = self.store.heartbeat("execution-1", 1, "owner-1", 1)
        self.assertEqual(1, heartbeat["state_version"])
        self.assertEqual(1, heartbeat["lease_generation"])
        self.assertGreater(heartbeat["lease_expires_at"], expiry)
        self.assertEqual(event_count, len(self.store.events("execution-1")))
        released = self.store.release_lease(
            "execution-1",
            1,
            operation_key("lease-release", {"execution_id": "execution-1"}),
            "owner-1",
            1,
        )
        self.assertIsNone(released["lease_owner"])
        self.assertEqual((1, 2), (released["lease_generation"], released["state_version"]))

    def test_active_lease_is_held(self) -> None:
        self.create()
        self.acquire()
        with self.assertRaisesRegex(StoreError, "LEASE_HELD"):
            self.store.acquire_lease(
                "execution-1",
                1,
                operation_key("lease-acquisition", {"owner": "owner-2"}),
                "owner-2",
            )

    def test_expiry_reacquisition_fences_stale_owner_and_generation(self) -> None:
        self.create()
        self.acquire()
        self.clock.advance(61)
        reacquired = self.store.acquire_lease(
            "execution-1",
            1,
            operation_key("lease-acquisition", {"owner": "owner-2"}),
            "owner-2",
        )
        self.assertEqual(("owner-2", 2, 2), (reacquired["lease_owner"], reacquired["lease_generation"], reacquired["state_version"]))
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.heartbeat("execution-1", 2, "owner-1", 1)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.transition(
                "execution-1",
                2,
                operation_key("transition", {"stale-generation": True}),
                ExecutionState.MAKER_RUNNING,
                actor_role=ActorRole.MAKER,
                actor_id="attempt-old",
                lease_owner="owner-2",
                lease_generation=1,
            )

    def test_expired_heartbeat_and_release_fail_closed(self) -> None:
        self.create()
        self.acquire()
        self.clock.advance(61)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.heartbeat("execution-1", 1, "owner-1", 1)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.release_lease(
                "execution-1", 1, operation_key("release", {"expired": True}), "owner-1", 1
            )

    def test_ttl_bounds(self) -> None:
        self.create()
        for ttl in (14, 301):
            with self.assertRaisesRegex(StoreError, "INVALID_LEASE_TTL"):
                self.store.acquire_lease(
                    "execution-1", 0, operation_key("lease", {"ttl": ttl}), "owner", ttl
                )


if __name__ == "__main__":
    unittest.main()
