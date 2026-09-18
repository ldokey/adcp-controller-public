from __future__ import annotations

import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from adcp.domain import StoreError
from adcp.store.sqlite import ControlStore
from tests._helpers import FakeClock


SLICE_FINGERPRINT = "a" * 64
ROLLBACK_FINGERPRINT = "b" * 64
CUTOVER_ID = "adcp-cut-3-isolated"
SWITCH_OPERATION_KEY = "c" * 64
ROLLBACK_OPERATION_KEY = "d" * 64


class AuthorityTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = FakeClock()
        self.store = ControlStore(self.root / "control.sqlite3", clock=self.clock)
        initial = self.store.get_control_authority_state()
        self.authority, replayed = self.store.reconcile_transitional_authority(
            initial["authority_generation"],
            SLICE_FINGERPRINT,
            ROLLBACK_FINGERPRINT,
        )
        self.assertFalse(replayed)
        self.assertEqual(1, self.authority["authority_generation"])

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def switch_arguments(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "expected_generation": 1,
            "expected_slice_snapshot_fingerprint": SLICE_FINGERPRINT,
            "expected_rollback_snapshot_fingerprint": ROLLBACK_FINGERPRINT,
            "cutover_id": CUTOVER_ID,
            "human_decision_ref": "human-cutover-go-evidence",
            "operation_key": SWITCH_OPERATION_KEY,
        }
        arguments.update(overrides)
        return arguments

    def rollback_arguments(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "expected_generation": 2,
            "expected_slice_snapshot_fingerprint": SLICE_FINGERPRINT,
            "expected_rollback_snapshot_fingerprint": ROLLBACK_FINGERPRINT,
            "cutover_id": CUTOVER_ID,
            "rollback_authorization_ref": "human-cut-4-rollback-authorization",
            "operation_key": ROLLBACK_OPERATION_KEY,
        }
        arguments.update(overrides)
        return arguments

    def assert_authority_unchanged(self, before: sqlite3.Row) -> None:
        self.assertEqual(tuple(before), tuple(self.store.get_control_authority_state()))

    def switch(self) -> sqlite3.Row:
        row, replayed = self.store.switch_control_authority(**self.switch_arguments())
        self.assertFalse(replayed)
        return row

    def test_schema_has_v3_event_and_replacement_guards(self) -> None:
        tables = {
            row[0]
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        triggers = {
            row[0]
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
            )
        }
        self.assertIn("authority_transition_event", tables)
        self.assertNotIn("control_authority_state_e1_switch_forbidden", triggers)
        self.assertTrue(
            {
                "authority_transition_event_state_guard",
                "authority_transition_event_apply",
                "control_authority_state_transition_guard",
                "authority_transition_event_immutable_update",
                "authority_transition_event_immutable_delete",
            }.issubset(triggers)
        )

    def test_direct_authority_switch_is_rejected_without_event(self) -> None:
        before = self.store.get_control_authority_state()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "AUTHORITY_TRANSITION_EVENT_REQUIRED"
        ):
            self.store.connection.execute(
                """UPDATE control_authority_state
                      SET mode = 'CONTROL_STORE_AUTHORITY',
                          authority_generation = authority_generation + 1,
                          cutover_id = ?, switched_at = 'direct', updated_at = 'direct'
                    WHERE singleton_id = 'GLOBAL'""",
                (CUTOVER_ID,),
            )
        self.assert_authority_unchanged(before)
        self.assertEqual(0, len(self.store.authority_transition_events()))

    def test_eventless_reconciliation_is_forbidden_after_forward_switch(self) -> None:
        switched = self.switch()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "AUTHORITY_TRANSITION_EVENT_REQUIRED"
        ):
            self.store.connection.execute(
                """UPDATE control_authority_state
                      SET authority_generation = authority_generation + 1,
                          slice_snapshot_fingerprint = ?, updated_at = 'direct'
                    WHERE singleton_id = 'GLOBAL'""",
                ("f" * 64,),
            )
        self.assertEqual(tuple(switched), tuple(self.store.get_control_authority_state()))
        self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_raw_invalid_event_insert_is_atomic(self) -> None:
        before = self.store.get_control_authority_state()
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "AUTHORITY_TRANSITION_STATE_MISMATCH"
        ):
            self.store.connection.execute(
                """INSERT INTO authority_transition_event(
                    event_id, operation_key, cutover_id, event_type, from_mode, to_mode,
                    from_generation, to_generation, slice_snapshot_fingerprint,
                    rollback_snapshot_fingerprint, human_decision_ref, created_at
                ) VALUES ('raw-invalid', ?, ?, 'AUTHORITY_SWITCH',
                          'TRANSITIONAL_AUTHORITY', 'CONTROL_STORE_AUTHORITY',
                          0, 1, ?, ?, 'human-ref', 'raw-time')""",
                ("e" * 64, CUTOVER_ID, SLICE_FINGERPRINT, ROLLBACK_FINGERPRINT),
            )
        self.assert_authority_unchanged(before)
        self.assertEqual(0, len(self.store.authority_transition_events()))

    def test_valid_forward_switch_is_atomic_and_exact_replay_is_non_mutating(self) -> None:
        row = self.switch()
        events = self.store.authority_transition_events()
        self.assertEqual(1, len(events))
        event = events[0]
        self.assertEqual("AUTHORITY_SWITCH", event["event_type"])
        self.assertEqual(("TRANSITIONAL_AUTHORITY", "CONTROL_STORE_AUTHORITY"),
                         (event["from_mode"], event["to_mode"]))
        self.assertEqual((1, 2), (event["from_generation"], event["to_generation"]))
        self.assertEqual("CONTROL_STORE_AUTHORITY", row["mode"])
        self.assertEqual(2, row["authority_generation"])
        self.assertEqual(CUTOVER_ID, row["cutover_id"])
        self.assertEqual(SLICE_FINGERPRINT, row["slice_snapshot_fingerprint"])
        self.assertEqual(ROLLBACK_FINGERPRINT, row["rollback_snapshot_fingerprint"])
        self.assertEqual(event["created_at"], row["switched_at"])
        self.assertEqual(event["created_at"], row["updated_at"])

        self.clock.advance(60)
        replay, replayed = self.store.switch_control_authority(**self.switch_arguments())
        self.assertTrue(replayed)
        self.assertEqual(tuple(row), tuple(replay))
        self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_forward_generation_and_fingerprint_guards_leave_no_partial_event(self) -> None:
        cases = (
            ("STALE_AUTHORITY_GENERATION", {"expected_generation": 0}),
            (
                "SLICE_SNAPSHOT_FINGERPRINT_MISMATCH",
                {"expected_slice_snapshot_fingerprint": "1" * 64},
            ),
            (
                "ROLLBACK_SNAPSHOT_FINGERPRINT_MISMATCH",
                {"expected_rollback_snapshot_fingerprint": "2" * 64},
            ),
        )
        for index, (code, overrides) in enumerate(cases):
            with self.subTest(code=code):
                before = self.store.get_control_authority_state()
                with self.assertRaisesRegex(StoreError, code):
                    self.store.switch_control_authority(
                        **self.switch_arguments(
                            operation_key=f"{index + 7:064x}", **overrides
                        )
                    )
                self.assert_authority_unchanged(before)
                self.assertEqual(0, len(self.store.authority_transition_events()))

    def test_forward_requires_explicit_nonempty_human_decision_ref(self) -> None:
        before = self.store.get_control_authority_state()
        arguments = self.switch_arguments()
        arguments.pop("human_decision_ref")
        with self.assertRaises(TypeError):
            self.store.switch_control_authority(**arguments)
        with self.assertRaisesRegex(StoreError, "HUMAN_DECISION_REF_REQUIRED"):
            self.store.switch_control_authority(
                **self.switch_arguments(human_decision_ref="   ")
            )
        self.assert_authority_unchanged(before)
        self.assertEqual(0, len(self.store.authority_transition_events()))

    def test_second_distinct_switch_and_conflicting_replay_are_rejected(self) -> None:
        switched = self.switch()
        with self.assertRaisesRegex(StoreError, "AUTHORITY_MODE_CONFLICT"):
            self.store.switch_control_authority(
                **self.switch_arguments(operation_key="e" * 64)
            )
        with self.assertRaisesRegex(StoreError, "IDEMPOTENCY_CONFLICT"):
            self.store.switch_control_authority(
                **self.switch_arguments(human_decision_ref="different-human-ref")
            )
        self.assertEqual(tuple(switched), tuple(self.store.get_control_authority_state()))
        self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_valid_rollback_is_atomic_and_retains_authorization_evidence(self) -> None:
        self.switch()
        self.clock.advance(1)
        row, replayed = self.store.rollback_control_authority(**self.rollback_arguments())
        self.assertFalse(replayed)
        events = self.store.authority_transition_events()
        self.assertEqual(2, len(events))
        event = events[1]
        self.assertEqual("AUTHORITY_ROLLBACK", event["event_type"])
        self.assertEqual(CUTOVER_ID, event["cutover_id"])
        self.assertEqual(
            "human-cut-4-rollback-authorization", event["human_decision_ref"]
        )
        self.assertEqual(("CONTROL_STORE_AUTHORITY", "TRANSITIONAL_AUTHORITY"),
                         (event["from_mode"], event["to_mode"]))
        self.assertEqual((2, 3), (event["from_generation"], event["to_generation"]))
        self.assertEqual("TRANSITIONAL_AUTHORITY", row["mode"])
        self.assertEqual(3, row["authority_generation"])
        self.assertIsNone(row["cutover_id"])
        self.assertIsNone(row["switched_at"])
        self.assertEqual(SLICE_FINGERPRINT, row["slice_snapshot_fingerprint"])
        self.assertEqual(ROLLBACK_FINGERPRINT, row["rollback_snapshot_fingerprint"])
        self.assertEqual(event["created_at"], row["updated_at"])

        replay, replayed = self.store.rollback_control_authority(**self.rollback_arguments())
        self.assertTrue(replayed)
        self.assertEqual(tuple(row), tuple(replay))
        self.assertEqual(2, len(self.store.authority_transition_events()))

    def test_rollback_guards_leave_switch_state_and_event_unchanged(self) -> None:
        switched = self.switch()
        cases = (
            ("STALE_AUTHORITY_GENERATION", {"expected_generation": 1}),
            (
                "SLICE_SNAPSHOT_FINGERPRINT_MISMATCH",
                {"expected_slice_snapshot_fingerprint": "1" * 64},
            ),
            (
                "ROLLBACK_SNAPSHOT_FINGERPRINT_MISMATCH",
                {"expected_rollback_snapshot_fingerprint": "2" * 64},
            ),
            ("CUTOVER_ID_MISMATCH", {"cutover_id": "wrong-cutover"}),
        )
        for index, (code, overrides) in enumerate(cases):
            with self.subTest(code=code):
                with self.assertRaisesRegex(StoreError, code):
                    self.store.rollback_control_authority(
                        **self.rollback_arguments(
                            operation_key=f"{index + 4:064x}", **overrides
                        )
                    )
                self.assertEqual(
                    tuple(switched), tuple(self.store.get_control_authority_state())
                )
                self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_rollback_requires_explicit_nonempty_authorization(self) -> None:
        switched = self.switch()
        arguments = self.rollback_arguments()
        arguments.pop("rollback_authorization_ref")
        with self.assertRaises(TypeError):
            self.store.rollback_control_authority(**arguments)
        with self.assertRaisesRegex(StoreError, "HUMAN_DECISION_REF_REQUIRED"):
            self.store.rollback_control_authority(
                **self.rollback_arguments(rollback_authorization_ref="")
            )
        self.assertEqual(tuple(switched), tuple(self.store.get_control_authority_state()))
        self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_second_distinct_rollback_is_rejected_without_generation_increment(self) -> None:
        self.switch()
        rolled_back, _ = self.store.rollback_control_authority(**self.rollback_arguments())
        with self.assertRaisesRegex(StoreError, "AUTHORITY_MODE_CONFLICT"):
            self.store.rollback_control_authority(
                **self.rollback_arguments(operation_key="e" * 64)
            )
        self.assertEqual(tuple(rolled_back), tuple(self.store.get_control_authority_state()))
        self.assertEqual(2, len(self.store.authority_transition_events()))

    def test_authority_events_are_immutable(self) -> None:
        self.switch()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AUTHORITY_EVENT"):
            self.store.connection.execute(
                "UPDATE authority_transition_event SET human_decision_ref = 'mutated'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AUTHORITY_EVENT"):
            self.store.connection.execute("DELETE FROM authority_transition_event")
        self.assertEqual(1, len(self.store.authority_transition_events()))

    def test_sqlite_integrity_and_foreign_keys_are_clean(self) -> None:
        self.switch()
        self.store.rollback_control_authority(**self.rollback_arguments())
        self.assertEqual("ok", self.store.connection.execute("PRAGMA integrity_check").fetchone()[0])
        self.assertEqual([], list(self.store.connection.execute("PRAGMA foreign_key_check")))


if __name__ == "__main__":
    unittest.main()
