from __future__ import annotations

from datetime import datetime, timedelta, timezone
import multiprocessing
import os
from pathlib import Path
import sqlite3
import unittest

from adcp.domain import StoreError, operation_key
from adcp.store.sqlite import ControlStore
from _helpers import StoreFixture


def _process_acquire_worker(
    database_path: str,
    ready_queue,
    start_event,
    result_queue,
    owner_id: str,
    writer_class: str,
    track: str,
) -> None:
    try:
        with ControlStore(database_path) as store:
            ready_queue.put(("READY", owner_id))
            if not start_event.wait(15):
                result_queue.put(("ERR", owner_id, "START_TIMEOUT"))
                return
            row = store.acquire_global_production_writer(
                operation_key=operation_key(
                    "global-writer-process-acquire",
                    {"owner_id": owner_id, "writer_class": writer_class, "track": track},
                ),
                owner_id=owner_id,
                owner_execution_id=f"execution-{owner_id}",
                change_id=f"CHANGE-{owner_id}",
                slice_id=f"SLICE-{owner_id}",
                writer_class=writer_class,
                owner_session_role="PROCESS_RACE",
                track=track,
                repository_or_runtime=f"/isolated/{track}",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
            )
            result_queue.put(("OK", owner_id, row["fencing_token"]))
    except StoreError as error:
        result_queue.put(("ERR", owner_id, error.code))
    except BaseException as error:  # pragma: no cover - evidence if process plumbing itself breaks
        result_queue.put(("EXC", owner_id, type(error).__name__, str(error)))


def _process_crash_after_event_insert(database_path: str, ready_queue, start_event) -> None:
    with ControlStore(database_path) as store:
        ready_queue.put("READY")
        if not start_event.wait(15):
            os._exit(92)

        def crash(stage: str) -> None:
            if stage == "after_event_insert":
                os._exit(91)

        store.acquire_global_production_writer(
            operation_key=operation_key("global-writer-crash", {"case": "after-event"}),
            owner_id="crash-owner",
            change_id="CRASH-CHANGE",
            writer_class="DEPLOYMENT",
            owner_session_role="CRASH_TEST",
            track="CONTROL",
            repository_or_runtime="/isolated/crash",
            operation_class="DEPLOY",
            target="GLOBAL_PRODUCTION",
            _fault_injector=crash,
        )
    os._exit(93)


class GlobalProductionWriterTests(StoreFixture, unittest.TestCase):
    def acquire_global(
        self,
        *,
        owner_id: str = "owner-a",
        writer_class: str = "CLEANER",
        track: str = "CLEANER",
        change_id: str = "CHANGE-A",
        attempt: int = 1,
        ttl_seconds: int = 60,
        owner_execution_id: str | None = None,
        slice_id: str | None = None,
        operation: str = "global-writer-acquire",
    ):
        return self.store.acquire_global_production_writer(
            operation_key=operation_key(
                operation,
                {
                    "owner_id": owner_id,
                    "writer_class": writer_class,
                    "track": track,
                    "change_id": change_id,
                    "attempt": attempt,
                },
            ),
            owner_id=owner_id,
            owner_execution_id=owner_execution_id,
            change_id=change_id,
            slice_id=slice_id,
            writer_class=writer_class,
            owner_session_role="GPT_REMOTE_TEST",
            track=track,
            repository_or_runtime=f"/isolated/{track.lower()}",
            operation_class="PRODUCTION_WRITE",
            target="GLOBAL_PRODUCTION",
            ttl_seconds=ttl_seconds,
            control_decision_ref="CONTROL/GLOBAL-PRODUCTION-WRITER-LEASE-01A",
        )

    def _set_global_writer_held_direct(
        self,
        *,
        acquired_at: str | None,
        expires_at: str | None,
        heartbeat_at: str | None,
        updated_at: str,
    ) -> None:
        self.store.connection.execute(
            """UPDATE global_production_writer_lease
                  SET state='HELD',
                      owner_id='A', owner_execution_id='execution-A',
                      change_id='CHANGE-A', slice_id='SLICE-A', writer_class='CORE',
                      owner_session_role='TEMPORAL_TEST', track='CORE',
                      repository_or_runtime='/isolated/temporal',
                      operation_class='PRODUCTION_WRITE', target='GLOBAL_PRODUCTION',
                      fencing_token=7, acquired_at=?, expires_at=?, heartbeat_at=?, updated_at=?
                WHERE resource_key='GLOBAL_PRODUCTION'""",
            (acquired_at, expires_at, heartbeat_at, updated_at),
        )

    def _restore_temporal_fields(self, row: sqlite3.Row) -> None:
        self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self.store.connection.execute(
                """UPDATE global_production_writer_lease
                      SET acquired_at=?, expires_at=?, heartbeat_at=?, updated_at=?
                    WHERE resource_key='GLOBAL_PRODUCTION'""",
                (row["acquired_at"], row["expires_at"], row["heartbeat_at"], row["updated_at"]),
            )
        finally:
            self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")

    def _schema_accepts_global_writer_timestamp(self, value: str) -> bool:
        accepted = self.store.connection.execute(
            """SELECT length(?) > 0
                      AND julianday(?) IS NOT NULL
                      AND substr(?, -6) = '+00:00'""",
            (value, value, value),
        ).fetchone()[0]
        return bool(accepted)

    def _authority_sensitive_operations(self, label: str):
        return {
            "get": lambda: self.store.get_global_production_writer_lease(),
            "assert": lambda: self.store.assert_current_global_writer("A", 7),
            "heartbeat": lambda: self.store.heartbeat_global_production_writer("A", 7),
            "release": lambda: self.store.release_global_production_writer(
                operation_key=operation_key(f"{label}-release", {"owner": "A"}),
                owner_id="A",
                fencing_token=7,
            ),
            "force_revoke": lambda: self.store.force_revoke_global_production_writer(
                operation_key=operation_key(f"{label}-revoke", {"owner": "A"}),
                reason="timestamp representation corruption proof",
                control_decision_ref="CONTROL/TIMESTAMP-LANGUAGE-CORRUPTION",
                expected_owner_id="A",
                expected_fencing_token=7,
            ),
            "acquire_takeover": lambda: self.store.acquire_global_production_writer(
                operation_key=operation_key(f"{label}-acquire", {"owner": "B"}),
                owner_id="B",
                change_id="CHANGE-B",
                writer_class="CORE",
                owner_session_role="TIMESTAMP_LANGUAGE_TEST",
                track="CORE",
                repository_or_runtime="/isolated/timestamp-language-b",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
            ),
        }

    def _assert_schema_rejects_and_bypassed_state_fails_closed(
        self, label: str, timestamps: tuple[str, str, str, str]
    ) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._set_global_writer_held_direct(
                acquired_at=timestamps[0],
                expires_at=timestamps[1],
                heartbeat_at=timestamps[2],
                updated_at=timestamps[3],
            )
        self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self._set_global_writer_held_direct(
                acquired_at=timestamps[0],
                expires_at=timestamps[1],
                heartbeat_at=timestamps[2],
                updated_at=timestamps[3],
            )
        finally:
            self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")

        for operation_name, operation in self._authority_sensitive_operations(label).items():
            with self.subTest(case=label, operation=operation_name):
                with self.assertRaisesRegex(
                    StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"
                ):
                    operation()

    def _run_two_process_acquire_race(self, database_path: Path, contenders):
        context = multiprocessing.get_context("spawn")
        ready_queue = context.Queue()
        result_queue = context.Queue()
        start_event = context.Event()
        processes = [
            context.Process(
                target=_process_acquire_worker,
                args=(str(database_path), ready_queue, start_event, result_queue, *contender),
            )
            for contender in contenders
        ]
        for process in processes:
            process.start()
        ready = [ready_queue.get(timeout=15) for _ in processes]
        self.assertEqual(len(processes), len(ready))
        start_event.set()
        results = [result_queue.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(15)
            self.assertFalse(process.is_alive())
            self.assertEqual(0, process.exitcode)
        return results

    def test_singleton_initial_state_and_nullable_context_contract(self) -> None:
        row = self.store.get_global_production_writer_lease()
        self.assertEqual(("GLOBAL_PRODUCTION", "FREE", 0), (
            row["resource_key"], row["state"], row["fencing_token"]
        ))
        self.assertIsNone(row["owner_execution_id"])
        self.assertIsNone(row["slice_id"])
        acquired = self.acquire_global(owner_execution_id=None, slice_id=None)
        self.assertEqual(("HELD", 1, None, None), (
            acquired["state"], acquired["fencing_token"],
            acquired["owner_execution_id"], acquired["slice_id"],
        ))

    def test_active_owner_blocks_all_writer_classes_and_tracks(self) -> None:
        first = self.acquire_global(writer_class="CLEANER", track="CLEANER")
        self.assertEqual(1, first["fencing_token"])
        for index, label in enumerate(("CORE", "GMAIL", "CALENDAR", "DEPLOYMENT"), start=2):
            with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_HELD"):
                self.acquire_global(
                    owner_id=f"owner-{label.lower()}",
                    writer_class=label,
                    track=label,
                    change_id=f"CHANGE-{label}",
                    attempt=index,
                )
        current = self.store.get_global_production_writer_lease()
        self.assertEqual(("owner-a", 1), (current["owner_id"], current["fencing_token"]))
        self.assertEqual(1, len(self.store.global_production_writer_events()))

    def test_cross_process_free_acquire_has_exactly_one_winner(self) -> None:
        path = self.root / "cross-process-free.sqlite3"
        with ControlStore(path):
            pass
        results = self._run_two_process_acquire_race(
            path,
            [
                ("process-cleaner", "CLEANER", "CLEANER"),
                ("process-gmail", "GMAIL", "GMAIL"),
            ],
        )
        winners = [result for result in results if result[0] == "OK"]
        losers = [result for result in results if result[0] == "ERR"]
        self.assertEqual(1, len(winners), results)
        self.assertEqual(1, winners[0][2])
        self.assertEqual(1, len(losers), results)
        self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", losers[0][2])
        with ControlStore(path) as store:
            row = store.get_global_production_writer_lease()
            self.assertEqual(("HELD", 1, winners[0][1]), (
                row["state"], row["fencing_token"], row["owner_id"]
            ))
            events = store.global_production_writer_events()
            self.assertEqual(1, len(events))
            self.assertEqual(("ACQUIRE", 0, 1), (
                events[0]["event_type"], events[0]["from_fencing_token"],
                events[0]["to_fencing_token"],
            ))
            loser_owner = losers[0][1]
            with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
                store.assert_current_global_writer(loser_owner, 1)
            with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
                store.heartbeat_global_production_writer(loser_owner, 1)
            with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
                store.release_global_production_writer(
                    operation_key=operation_key(
                        "cross-process-loser-release", {"owner_id": loser_owner}
                    ),
                    owner_id=loser_owner,
                    fencing_token=1,
                )
            after_loser = store.get_global_production_writer_lease()
            self.assertEqual((winners[0][1], 1), (
                after_loser["owner_id"], after_loser["fencing_token"]
            ))
            self.assertEqual(1, len(store.global_production_writer_events()))

    def test_release_preserves_token_and_new_acquire_mints_next_generation(self) -> None:
        acquired = self.acquire_global()
        released = self.store.release_global_production_writer(
            operation_key=operation_key("global-writer-release", {"attempt": 1}),
            owner_id="owner-a",
            fencing_token=acquired["fencing_token"],
        )
        self.assertEqual(("FREE", 1), (released["state"], released["fencing_token"]))
        second = self.acquire_global(
            owner_id="owner-b", writer_class="CORE", track="CORE",
            change_id="CHANGE-B", attempt=2,
        )
        self.assertEqual(2, second["fencing_token"])
        self.assertEqual(
            [("ACQUIRE", 0, 1), ("RELEASE", 1, 1), ("ACQUIRE", 1, 2)],
            [
                (event["event_type"], event["from_fencing_token"], event["to_fencing_token"])
                for event in self.store.global_production_writer_events()
            ],
        )

    def test_heartbeat_keeps_token_extends_expiry_and_emits_no_event(self) -> None:
        for ttl in (14, 301):
            with self.assertRaisesRegex(StoreError, "INVALID_LEASE_TTL"):
                self.acquire_global(ttl_seconds=ttl, attempt=ttl)
        acquired = self.acquire_global(ttl_seconds=60)
        expiry = acquired["expires_at"]
        self.clock.advance(20)
        heartbeat = self.store.heartbeat_global_production_writer("owner-a", 1, 60)
        self.assertEqual(1, heartbeat["fencing_token"])
        self.assertGreater(heartbeat["expires_at"], expiry)
        self.assertEqual(1, len(self.store.global_production_writer_events()))
        self.clock.advance(61)
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_LEASE_EXPIRED"):
            self.store.heartbeat_global_production_writer("owner-a", 1)
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_LEASE_EXPIRED"):
            self.store.release_global_production_writer(
                operation_key=operation_key("expired-release", {"owner": "owner-a"}),
                owner_id="owner-a",
                fencing_token=1,
            )

    def test_assert_current_distinguishes_not_held_owner_token_and_expiry(self) -> None:
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_NOT_HELD"):
            self.store.assert_current_global_writer("owner-a", 0)
        self.acquire_global()
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.assert_current_global_writer("owner-a", 0)
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
            self.store.assert_current_global_writer("owner-b", 1)
        self.clock.advance(61)
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_LEASE_EXPIRED"):
            self.store.assert_current_global_writer("owner-a", 1)

    def test_expired_takeover_mints_exactly_next_token_and_fences_old_owner(self) -> None:
        first = self.acquire_global()
        self.clock.advance(61)
        second = self.acquire_global(
            owner_id="owner-b", writer_class="CORE", track="CORE",
            change_id="CHANGE-B", attempt=2,
        )
        self.assertEqual(first["fencing_token"] + 1, second["fencing_token"])
        self.assertEqual("EXPIRED_TAKEOVER", self.store.global_production_writer_events()[-1]["event_type"])
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.assert_current_global_writer("owner-a", 1)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.heartbeat_global_production_writer("owner-a", 1)
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.release_global_production_writer(
                operation_key=operation_key("stale-release", {"owner": "owner-a"}),
                owner_id="owner-a",
                fencing_token=1,
            )
        current = self.store.assert_current_global_writer("owner-b", 2)
        self.assertEqual("owner-b", current["owner_id"])

    def test_cross_process_expired_takeover_race_has_one_winner(self) -> None:
        path = self.root / "cross-process-expired.sqlite3"
        past = datetime.now(timezone.utc) - timedelta(minutes=2)
        with ControlStore(path, clock=lambda: past) as store:
            row = store.acquire_global_production_writer(
                operation_key=operation_key("expired-seed", {"owner": "expired-owner"}),
                owner_id="expired-owner",
                change_id="EXPIRED-SEED",
                writer_class="CLEANER",
                owner_session_role="SEED",
                track="CLEANER",
                repository_or_runtime="/isolated/seed",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
                ttl_seconds=15,
            )
            self.assertEqual(1, row["fencing_token"])
        results = self._run_two_process_acquire_race(
            path,
            [
                ("takeover-core", "CORE", "CORE"),
                ("takeover-calendar", "CALENDAR", "CALENDAR"),
            ],
        )
        winners = [result for result in results if result[0] == "OK"]
        losers = [result for result in results if result[0] == "ERR"]
        self.assertEqual(1, len(winners), results)
        self.assertEqual(2, winners[0][2])
        self.assertEqual(1, len(losers), results)
        self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", losers[0][2])
        with ControlStore(path) as store:
            current = store.get_global_production_writer_lease()
            self.assertEqual(("HELD", 2, winners[0][1]), (
                current["state"], current["fencing_token"], current["owner_id"]
            ))
            events = store.global_production_writer_events()
            self.assertEqual(["ACQUIRE", "EXPIRED_TAKEOVER"], [e["event_type"] for e in events])
            self.assertEqual((1, 2), (events[-1]["from_fencing_token"], events[-1]["to_fencing_token"]))

    def test_force_revoke_requires_fresh_expected_owner_token_and_control_evidence(self) -> None:
        self.acquire_global()
        with self.assertRaisesRegex(StoreError, "INVALID_INPUT"):
            self.store.force_revoke_global_production_writer(
                operation_key=operation_key("force-invalid", {"case": 1}),
                reason="",
                control_decision_ref="CONTROL-1",
                expected_owner_id="owner-a",
                expected_fencing_token=1,
            )
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.force_revoke_global_production_writer(
                operation_key=operation_key("force-stale", {"case": 1}),
                reason="operator emergency",
                control_decision_ref="CONTROL-1",
                expected_owner_id="owner-a",
                expected_fencing_token=0,
            )
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
            self.store.force_revoke_global_production_writer(
                operation_key=operation_key("force-owner", {"case": 1}),
                reason="operator emergency",
                control_decision_ref="CONTROL-1",
                expected_owner_id="owner-b",
                expected_fencing_token=1,
            )
        current = self.store.assert_current_global_writer("owner-a", 1)
        self.assertEqual(1, current["fencing_token"])
        revoked = self.store.force_revoke_global_production_writer(
            operation_key=operation_key("force-valid", {"case": 1}),
            reason="operator emergency",
            control_decision_ref="CONTROL/GLOBAL-WRITER-REVOKE-1",
            expected_owner_id="owner-a",
            expected_fencing_token=1,
        )
        self.assertEqual(("FREE", 2), (revoked["state"], revoked["fencing_token"]))
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.assert_current_global_writer("owner-a", 1)
        event = self.store.global_production_writer_events()[-1]
        self.assertEqual(("FORCE_REVOKE", 1, 2), (
            event["event_type"], event["from_fencing_token"], event["to_fencing_token"]
        ))
        self.assertEqual("CONTROL/GLOBAL-WRITER-REVOKE-1", event["control_decision_ref"])
        third = self.acquire_global(
            owner_id="owner-c", writer_class="DEPLOYMENT", track="DEPLOYMENT",
            change_id="CHANGE-C", attempt=3,
        )
        self.assertEqual(3, third["fencing_token"])

    def test_acquire_and_release_operation_replay_is_convergent_and_conflicts_fail(self) -> None:
        acquire_key = operation_key("gpw-idempotent-acquire", {"request": 1})
        kwargs = dict(
            operation_key=acquire_key,
            owner_id="owner-idempotent",
            change_id="CHANGE-IDEMPOTENT",
            writer_class="CORE",
            owner_session_role="IDEMPOTENCY_TEST",
            track="CORE",
            repository_or_runtime="/isolated/idempotent",
            operation_class="PRODUCTION_WRITE",
            target="GLOBAL_PRODUCTION",
        )
        first = self.store.acquire_global_production_writer(**kwargs)
        second = self.store.acquire_global_production_writer(**kwargs)
        self.assertEqual((1, 1), (first["fencing_token"], second["fencing_token"]))
        self.assertEqual(1, len(self.store.global_production_writer_events()))
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT"):
            self.store.acquire_global_production_writer(**{**kwargs, "writer_class": "GMAIL"})

        release_key = operation_key("gpw-idempotent-release", {"request": 1})
        released = self.store.release_global_production_writer(
            operation_key=release_key,
            owner_id="owner-idempotent",
            fencing_token=1,
            reason="normal completion",
        )
        replay = self.store.release_global_production_writer(
            operation_key=release_key,
            owner_id="owner-idempotent",
            fencing_token=1,
            reason="normal completion",
        )
        self.assertEqual(("FREE", 1), (replay["state"], replay["fencing_token"]))
        self.assertEqual(2, len(self.store.global_production_writer_events()))
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT"):
            self.store.release_global_production_writer(
                operation_key=release_key,
                owner_id="owner-idempotent",
                fencing_token=1,
                reason="different semantics",
            )
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE"):
            self.store.acquire_global_production_writer(**kwargs)
        self.assertEqual(1, released["fencing_token"])

    def test_force_revoke_replay_does_not_mint_extra_generation(self) -> None:
        self.acquire_global()
        revoke_key = operation_key("gpw-force-replay", {"request": 1})
        kwargs = dict(
            operation_key=revoke_key,
            reason="emergency revoke",
            control_decision_ref="CONTROL-REVOKE-REPLAY",
            expected_owner_id="owner-a",
            expected_fencing_token=1,
        )
        first = self.store.force_revoke_global_production_writer(**kwargs)
        second = self.store.force_revoke_global_production_writer(**kwargs)
        self.assertEqual((2, 2), (first["fencing_token"], second["fencing_token"]))
        self.assertEqual(2, len(self.store.global_production_writer_events()))

    def test_state_and_event_rollback_together_on_injected_faults(self) -> None:
        def fail_after_state(stage: str) -> None:
            if stage == "after_state_update":
                raise RuntimeError("injected-after-state")

        with self.assertRaisesRegex(RuntimeError, "injected-after-state"):
            self.store.acquire_global_production_writer(
                operation_key=operation_key("gpw-atomic", {"stage": "state"}),
                owner_id="atomic-owner",
                change_id="ATOMIC",
                writer_class="CORE",
                owner_session_role="ATOMIC_TEST",
                track="CORE",
                repository_or_runtime="/isolated/atomic",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
                _fault_injector=fail_after_state,
            )
        self.assertEqual(("FREE", 0), (
            self.store.get_global_production_writer_lease()["state"],
            self.store.get_global_production_writer_lease()["fencing_token"],
        ))
        self.assertEqual([], self.store.global_production_writer_events())

        def fail_after_event(stage: str) -> None:
            if stage == "after_event_insert":
                raise RuntimeError("injected-after-event")

        with self.assertRaisesRegex(RuntimeError, "injected-after-event"):
            self.store.acquire_global_production_writer(
                operation_key=operation_key("gpw-atomic", {"stage": "event"}),
                owner_id="atomic-owner",
                change_id="ATOMIC",
                writer_class="CORE",
                owner_session_role="ATOMIC_TEST",
                track="CORE",
                repository_or_runtime="/isolated/atomic",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
                _fault_injector=fail_after_event,
            )
        self.assertEqual(("FREE", 0), (
            self.store.get_global_production_writer_lease()["state"],
            self.store.get_global_production_writer_lease()["fencing_token"],
        ))
        self.assertEqual([], self.store.global_production_writer_events())

    def test_release_and_force_revoke_roll_back_state_and_event_together(self) -> None:
        acquired = self.acquire_global()

        def fail_after_state(stage: str) -> None:
            if stage == "after_state_update":
                raise RuntimeError("release-after-state")

        with self.assertRaisesRegex(RuntimeError, "release-after-state"):
            self.store.release_global_production_writer(
                operation_key=operation_key("gpw-release-atomic", {"stage": "state"}),
                owner_id="owner-a",
                fencing_token=acquired["fencing_token"],
                _fault_injector=fail_after_state,
            )
        held = self.store.assert_current_global_writer("owner-a", 1)
        self.assertEqual(("HELD", 1), (held["state"], held["fencing_token"]))
        self.assertEqual(["ACQUIRE"], [
            event["event_type"] for event in self.store.global_production_writer_events()
        ])

        def fail_after_event(stage: str) -> None:
            if stage == "after_event_insert":
                raise RuntimeError("release-after-event")

        with self.assertRaisesRegex(RuntimeError, "release-after-event"):
            self.store.release_global_production_writer(
                operation_key=operation_key("gpw-release-atomic", {"stage": "event"}),
                owner_id="owner-a",
                fencing_token=1,
                _fault_injector=fail_after_event,
            )
        held = self.store.assert_current_global_writer("owner-a", 1)
        self.assertEqual(("HELD", 1), (held["state"], held["fencing_token"]))
        self.assertEqual(["ACQUIRE"], [
            event["event_type"] for event in self.store.global_production_writer_events()
        ])

        def revoke_after_state(stage: str) -> None:
            if stage == "after_state_update":
                raise RuntimeError("revoke-after-state")

        with self.assertRaisesRegex(RuntimeError, "revoke-after-state"):
            self.store.force_revoke_global_production_writer(
                operation_key=operation_key("gpw-revoke-atomic", {"stage": "state"}),
                reason="atomicity test",
                control_decision_ref="CONTROL/ATOMICITY",
                expected_owner_id="owner-a",
                expected_fencing_token=1,
                _fault_injector=revoke_after_state,
            )
        held = self.store.assert_current_global_writer("owner-a", 1)
        self.assertEqual(("HELD", 1), (held["state"], held["fencing_token"]))
        self.assertEqual(["ACQUIRE"], [
            event["event_type"] for event in self.store.global_production_writer_events()
        ])

        def revoke_after_event(stage: str) -> None:
            if stage == "after_event_insert":
                raise RuntimeError("revoke-after-event")

        with self.assertRaisesRegex(RuntimeError, "revoke-after-event"):
            self.store.force_revoke_global_production_writer(
                operation_key=operation_key("gpw-revoke-atomic", {"stage": "event"}),
                reason="atomicity test",
                control_decision_ref="CONTROL/ATOMICITY",
                expected_owner_id="owner-a",
                expected_fencing_token=1,
                _fault_injector=revoke_after_event,
            )
        held = self.store.assert_current_global_writer("owner-a", 1)
        self.assertEqual(("HELD", 1), (held["state"], held["fencing_token"]))
        self.assertEqual(["ACQUIRE"], [
            event["event_type"] for event in self.store.global_production_writer_events()
        ])

    def test_process_crash_before_commit_recovers_free_consistent_state(self) -> None:
        path = self.root / "process-crash.sqlite3"
        with ControlStore(path):
            pass
        context = multiprocessing.get_context("spawn")
        ready_queue = context.Queue()
        start_event = context.Event()
        process = context.Process(
            target=_process_crash_after_event_insert,
            args=(str(path), ready_queue, start_event),
        )
        process.start()
        self.assertEqual("READY", ready_queue.get(timeout=15))
        start_event.set()
        process.join(15)
        self.assertFalse(process.is_alive())
        self.assertEqual(91, process.exitcode)
        with ControlStore(path) as store:
            row = store.get_global_production_writer_lease()
            self.assertEqual(("FREE", 0), (row["state"], row["fencing_token"]))
            self.assertEqual([], store.global_production_writer_events())
            self.assertEqual("ok", store.connection.execute("PRAGMA integrity_check").fetchone()[0])

    def test_immutable_events_singleton_and_monotonic_trigger_reject_direct_tamper(self) -> None:
        acquired = self.acquire_global()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_GLOBAL_PRODUCTION_WRITER_EVENT"):
            self.store.connection.execute(
                "UPDATE global_production_writer_event SET reason='tamper' WHERE event_seq=1"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_GLOBAL_PRODUCTION_WRITER_EVENT"):
            self.store.connection.execute("DELETE FROM global_production_writer_event WHERE event_seq=1")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "GLOBAL_PRODUCTION_WRITER_SINGLETON_DELETE_FORBIDDEN"):
            self.store.connection.execute(
                "DELETE FROM global_production_writer_lease WHERE resource_key='GLOBAL_PRODUCTION'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "GLOBAL_PRODUCTION_WRITER_FENCING_DECREMENT_FORBIDDEN"):
            self.store.connection.execute(
                "UPDATE global_production_writer_lease SET fencing_token=0 WHERE resource_key='GLOBAL_PRODUCTION'"
            )
        self.assertEqual(1, acquired["fencing_token"])

    def test_schema_and_store_timestamp_representation_languages_are_aligned(self) -> None:
        cases = {
            "CANONICAL_MICRO": ("2026-08-28T22:00:00.123456+00:00", True),
            "UTC_SECONDS": ("2026-08-28T22:00:00+00:00", True),
            "UTC_Z": ("2026-08-28T22:00:00Z", False),
            "NONZERO_OFFSET": ("2026-08-28T22:00:00+09:00", False),
            "NAIVE_ISO": ("2026-08-28T22:00:00", False),
            "MALFORMED_TEXT": ("not-a-timestamp", False),
            "NANO_FRACTION": ("2026-08-28T22:00:00.123456789+00:00", True),
            "BASIC_ISO": ("20260828T220000+00:00", False),
            "COMMA_FRACTION": ("2026-08-28T22:00:00,123456+00:00", False),
            # Schema v6 delegates representation parsing to SQLite julianday(), so
            # these SQLite spellings are intentionally part of its accepted language.
            "SPACE_SEPARATOR": ("2026-08-28 22:00:00.123456+00:00", True),
            "MULTI_T": ("2026-08-28TT22:00:00.123456+00:00", True),
        }
        for label, (value, expected) in cases.items():
            with self.subTest(case=label):
                schema_accepts = self._schema_accepts_global_writer_timestamp(value)
                self.assertEqual(expected, schema_accepts)
                if expected:
                    self.store._global_writer_timestamp(value, label)
                    store_accepts = True
                else:
                    with self.assertRaisesRegex(
                        StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"
                    ):
                        self.store._global_writer_timestamp(value, label)
                    store_accepts = False
                self.assertEqual(schema_accepts, store_accepts)

    def test_fractional_precision_contract_matches_schema_julianday_semantics(self) -> None:
        for digits in (0, 1, 3, 6, 7, 9, 12):
            fraction = "" if digits == 0 else "." + ("1" * digits)
            value = f"2026-08-28T22:00:00{fraction}+00:00"
            with self.subTest(fraction_digits=digits):
                self.assertTrue(self._schema_accepts_global_writer_timestamp(value))
                self.store._global_writer_timestamp(value, "fraction")

        # SQLite's Schema v6 comparison rounds these adjacent microseconds to the
        # same julianday value. Store validation must use that same authority
        # semantics rather than Python's distinct microsecond datetimes.
        schema_equal = (
            "2026-08-28T21:34:00.0000000+00:00",
            "2026-08-28T22:34:00.9999999+00:00",
            "2026-08-28T22:00:00.123456+00:00",
            "2026-08-28T22:00:00.123457+00:00",
        )
        self._set_global_writer_held_direct(
            acquired_at=schema_equal[0], expires_at=schema_equal[1],
            heartbeat_at=schema_equal[2], updated_at=schema_equal[3],
        )
        self.assertEqual("HELD", self.store.get_global_production_writer_lease()["state"])

        schema_distinct = (
            "2026-08-28T21:34:00.0000000+00:00",
            "2026-08-28T22:34:00.9999999+00:00",
            "2026-08-28T22:00:00.123499+00:00",
            "2026-08-28T22:00:00.123500+00:00",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self._set_global_writer_held_direct(
                acquired_at=schema_distinct[0], expires_at=schema_distinct[1],
                heartbeat_at=schema_distinct[2], updated_at=schema_distinct[3],
            )
        self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self._set_global_writer_held_direct(
                acquired_at=schema_distinct[0], expires_at=schema_distinct[1],
                heartbeat_at=schema_distinct[2], updated_at=schema_distinct[3],
            )
        finally:
            self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"):
            self.store.get_global_production_writer_lease()

    def test_basic_iso_schema_rejection_also_fails_closed_in_store(self) -> None:
        self._assert_schema_rejects_and_bypassed_state_fails_closed(
            "basic-iso",
            (
                "20260828T213400+00:00",
                "20260828T223400+00:00",
                "20260828T220000+00:00",
                "20260828T220000+00:00",
            ),
        )

    def test_comma_fraction_schema_rejection_also_fails_closed_in_store(self) -> None:
        self._assert_schema_rejects_and_bypassed_state_fails_closed(
            "comma-fraction",
            (
                "2026-08-28T21:34:00,123456+00:00",
                "2026-08-28T22:34:00,123456+00:00",
                "2026-08-28T22:00:00,123456+00:00",
                "2026-08-28T22:00:00,123456+00:00",
            ),
        )

    def test_store_generated_global_writer_timestamps_are_schema_canonical(self) -> None:
        rows = [self.store.get_global_production_writer_lease()]
        acquired = self.acquire_global(ttl_seconds=60)
        rows.append(acquired)
        self.clock.advance(20)
        rows.append(self.store.heartbeat_global_production_writer("owner-a", 1, 60))
        rows.append(self.store.release_global_production_writer(
            operation_key=operation_key("timestamp-language-release", {"owner": "owner-a"}),
            owner_id="owner-a", fencing_token=1,
        ))
        for row in rows:
            for field in ("acquired_at", "expires_at", "heartbeat_at", "updated_at"):
                value = row[field]
                if value is None:
                    continue
                with self.subTest(state=row["state"], field=field, value=value):
                    self.assertRegex(
                        value, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$"
                    )
                    self.assertTrue(self._schema_accepts_global_writer_timestamp(value))
                    self.store._global_writer_timestamp(value, field)

    def test_original_temporal_exploit_is_rejected_by_schema_checks(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._set_global_writer_held_direct(
                acquired_at="2026-08-28T21:34:00+00:00",
                expires_at="2026-08-28T22:34:00+00:00",
                heartbeat_at="2099-01-01T00:00:00+00:00",
                updated_at="2020-01-01T00:00:00+00:00",
            )
        row = self.store.get_global_production_writer_lease()
        self.assertEqual(("FREE", 0), (row["state"], row["fencing_token"]))

    def test_original_temporal_exploit_fails_closed_when_checks_are_bypassed(self) -> None:
        self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self._set_global_writer_held_direct(
                acquired_at="2026-08-28T21:34:00+00:00",
                expires_at="2026-08-28T22:34:00+00:00",
                heartbeat_at="2099-01-01T00:00:00+00:00",
                updated_at="2020-01-01T00:00:00+00:00",
            )
        finally:
            self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")

        operations = {
            "get": lambda: self.store.get_global_production_writer_lease(),
            "assert": lambda: self.store.assert_current_global_writer("A", 7),
            "heartbeat": lambda: self.store.heartbeat_global_production_writer("A", 7),
            "release": lambda: self.store.release_global_production_writer(
                operation_key=operation_key("temporal-malformed-release", {"owner": "A"}),
                owner_id="A",
                fencing_token=7,
            ),
            "force_revoke": lambda: self.store.force_revoke_global_production_writer(
                operation_key=operation_key("temporal-malformed-revoke", {"owner": "A"}),
                reason="corruption proof",
                control_decision_ref="CONTROL/TEMPORAL-CORRUPTION",
                expected_owner_id="A",
                expected_fencing_token=7,
            ),
            "acquire_takeover": lambda: self.store.acquire_global_production_writer(
                operation_key=operation_key("temporal-malformed-acquire", {"owner": "B"}),
                owner_id="B",
                change_id="CHANGE-B",
                writer_class="CORE",
                owner_session_role="TEMPORAL_TEST",
                track="CORE",
                repository_or_runtime="/isolated/temporal-b",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
            ),
        }
        for label, operation in operations.items():
            with self.subTest(operation=label):
                with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"):
                    operation()

    def test_invalid_temporal_matrix_is_rejected_by_schema_checks(self) -> None:
        acquired = self.acquire_global()
        baseline = dict(acquired)
        invalid_cases = {
            "heartbeat_after_expiry": {
                "heartbeat_at": "2026-08-11T01:03:04.456789+00:00",
                "updated_at": "2026-08-11T01:03:04.456789+00:00",
            },
            "updated_before_acquired": {
                "heartbeat_at": "2026-08-11T01:02:02.456789+00:00",
                "updated_at": "2026-08-11T01:02:02.456789+00:00",
            },
            "updated_before_heartbeat": {
                "heartbeat_at": "2026-08-11T01:02:13.456789+00:00",
                "updated_at": "2026-08-11T01:02:08.456789+00:00",
            },
            "expiry_not_after_acquire": {"expires_at": baseline["acquired_at"]},
            "missing_required_timestamp": {"acquired_at": None},
            "unparseable_timestamp": {"heartbeat_at": "not-a-timestamp"},
            "naive_timestamp": {"acquired_at": "2026-08-11T01:02:03.456789"},
        }
        for label, changes in invalid_cases.items():
            values = {field: baseline[field] for field in (
                "acquired_at", "expires_at", "heartbeat_at", "updated_at"
            )}
            values.update(changes)
            with self.subTest(case=label):
                with self.assertRaises((sqlite3.IntegrityError, sqlite3.OperationalError)):
                    self.store.connection.execute(
                        """UPDATE global_production_writer_lease
                              SET acquired_at=?, expires_at=?, heartbeat_at=?, updated_at=?
                            WHERE resource_key='GLOBAL_PRODUCTION'""",
                        (values["acquired_at"], values["expires_at"], values["heartbeat_at"], values["updated_at"]),
                    )

    def test_invalid_temporal_matrix_fails_closed_when_checks_are_bypassed(self) -> None:
        acquired = self.acquire_global()
        baseline = dict(acquired)
        invalid_cases = {
            "heartbeat_after_expiry": {
                "heartbeat_at": "2026-08-11T01:03:04.456789+00:00",
                "updated_at": "2026-08-11T01:03:04.456789+00:00",
            },
            "updated_before_acquired": {
                "heartbeat_at": "2026-08-11T01:02:02.456789+00:00",
                "updated_at": "2026-08-11T01:02:02.456789+00:00",
            },
            "updated_before_heartbeat": {
                "heartbeat_at": "2026-08-11T01:02:13.456789+00:00",
                "updated_at": "2026-08-11T01:02:08.456789+00:00",
            },
            "expiry_not_after_acquire": {"expires_at": baseline["acquired_at"]},
            "missing_required_timestamp": {"acquired_at": None},
            "unparseable_timestamp": {"heartbeat_at": "not-a-timestamp"},
            "naive_timestamp": {"acquired_at": "2026-08-11T01:02:03.456789"},
        }
        for label, changes in invalid_cases.items():
            values = {field: baseline[field] for field in (
                "acquired_at", "expires_at", "heartbeat_at", "updated_at"
            )}
            values.update(changes)
            with self.subTest(case=label):
                self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
                try:
                    self.store.connection.execute(
                        """UPDATE global_production_writer_lease
                              SET acquired_at=?, expires_at=?, heartbeat_at=?, updated_at=?
                            WHERE resource_key='GLOBAL_PRODUCTION'""",
                        (values["acquired_at"], values["expires_at"], values["heartbeat_at"], values["updated_at"]),
                    )
                finally:
                    self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")
                with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"):
                    self.store.get_global_production_writer_lease()
                self._restore_temporal_fields(acquired)

    def test_valid_temporal_matrix_initial_heartbeat_and_preexpiry(self) -> None:
        initial = self.acquire_global(ttl_seconds=60)
        initial_acquired = datetime.fromisoformat(initial["acquired_at"])
        initial_heartbeat = datetime.fromisoformat(initial["heartbeat_at"])
        initial_updated = datetime.fromisoformat(initial["updated_at"])
        initial_expires = datetime.fromisoformat(initial["expires_at"])
        self.assertTrue(initial_acquired <= initial_heartbeat == initial_updated < initial_expires)

        self.clock.advance(20)
        heartbeat = self.store.heartbeat_global_production_writer("owner-a", 1, 60)
        acquired_at = datetime.fromisoformat(heartbeat["acquired_at"])
        heartbeat_at = datetime.fromisoformat(heartbeat["heartbeat_at"])
        updated_at = datetime.fromisoformat(heartbeat["updated_at"])
        expires_at = datetime.fromisoformat(heartbeat["expires_at"])
        self.assertTrue(acquired_at <= heartbeat_at == updated_at < expires_at)

        self.clock.advance(59)
        preexpiry = self.store.get_global_production_writer_lease()
        self.assertEqual("HELD", preexpiry["state"])
        self.assertEqual(1, self.store.assert_current_global_writer("owner-a", 1)["fencing_token"])

    def test_free_state_temporal_representation_after_initial_release_and_force_revoke(self) -> None:
        def assert_free(row: sqlite3.Row, token: int) -> None:
            self.assertEqual(("FREE", token), (row["state"], row["fencing_token"]))
            for field in ("acquired_at", "expires_at", "heartbeat_at"):
                self.assertIsNone(row[field])
            self.assertTrue(row["updated_at"].endswith("+00:00"))
            datetime.fromisoformat(row["updated_at"])

        assert_free(self.store.get_global_production_writer_lease(), 0)
        acquired = self.acquire_global()
        released = self.store.release_global_production_writer(
            operation_key=operation_key("temporal-free-release", {"owner": "owner-a"}),
            owner_id="owner-a",
            fencing_token=acquired["fencing_token"],
        )
        assert_free(released, 1)
        second = self.acquire_global(
            owner_id="owner-b", writer_class="CORE", track="CORE",
            change_id="CHANGE-B", attempt=2,
        )
        revoked = self.store.force_revoke_global_production_writer(
            operation_key=operation_key("temporal-free-revoke", {"owner": "owner-b"}),
            reason="free state regression",
            control_decision_ref="CONTROL/TEMPORAL-FREE",
            expected_owner_id="owner-b",
            expected_fencing_token=second["fencing_token"],
        )
        assert_free(revoked, 3)

    def test_malformed_singleton_row_fails_closed_even_if_fixture_bypasses_checks(self) -> None:
        self.store.connection.execute("PRAGMA ignore_check_constraints=ON")
        self.store.connection.execute(
            "UPDATE global_production_writer_lease SET state='HELD' WHERE resource_key='GLOBAL_PRODUCTION'"
        )
        self.store.connection.execute("PRAGMA ignore_check_constraints=OFF")
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"):
            self.store.get_global_production_writer_lease()
        with self.assertRaisesRegex(StoreError, "GLOBAL_PRODUCTION_WRITER_STATE_INVALID"):
            self.store.assert_current_global_writer("phantom", 0)

    def test_control_store_unavailable_never_grants_authority(self) -> None:
        self.store.connection.close()
        with self.assertRaisesRegex(StoreError, "CONTROL_STORE_ERROR"):
            self.store.assert_current_global_writer("owner-a", 0)
        with self.assertRaisesRegex(StoreError, "CONTROL_STORE_ERROR"):
            self.store.acquire_global_production_writer(
                operation_key=operation_key("gpw-unavailable", {"request": 1}),
                owner_id="owner-a",
                change_id="UNAVAILABLE",
                writer_class="CORE",
                owner_session_role="UNAVAILABLE_TEST",
                track="CORE",
                repository_or_runtime="/isolated/unavailable",
                operation_class="PRODUCTION_WRITE",
                target="GLOBAL_PRODUCTION",
            )

    def test_external_target_fencing_limit_is_explicit_in_assert_contract(self) -> None:
        contract = ControlStore.assert_current_global_writer.__doc__ or ""
        self.assertIn("not target-native fencing", contract)
        self.assertIn("immediately before", contract)
        self.assertIn("TOCTOU", contract)


if __name__ == "__main__":
    unittest.main()
