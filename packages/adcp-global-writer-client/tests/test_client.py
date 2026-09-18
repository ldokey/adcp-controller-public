from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import multiprocessing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from _fixtures import create_schema
from adcp_global_writer_client import (
    GlobalWriterClientError,
    GlobalWriterControlClient,
    GlobalWriterLeaseClient,
    client_build_identity,
)
import adcp_global_writer_client.schema_contract as schema_contract
from adcp_global_writer_client.store import GlobalWriterStore


def key(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def acquire(owner: str, label: str) -> dict[str, object]:
    return {
        "operation_key": key("acquire:" + label),
        "owner_id": owner,
        "change_id": "CHANGE-" + owner,
        "writer_class": "CORE",
        "owner_session_role": "THIN_CLIENT_TEST",
        "track": "CORE",
        "repository_or_runtime": "source-commit:" + "1" * 40,
        "operation_class": "PRODUCTION_WRITE",
        "target": "GLOBAL_PRODUCTION",
        "ttl_seconds": 60,
    }


def _process_acquire_worker(
    database_path: str,
    ready_queue,
    start_event,
    result_queue,
    owner: str,
) -> None:
    try:
        with GlobalWriterLeaseClient(database_path) as client:
            ready_queue.put(("READY", owner))
            if not start_event.wait(15):
                result_queue.put(("ERR", owner, "START_TIMEOUT"))
                return
            row = client.acquire(**acquire(owner, "process-race-" + owner))
            result_queue.put(("OK", owner, row["fencing_token"]))
    except GlobalWriterClientError as error:
        result_queue.put(("ERR", owner, error.code))
    except BaseException as error:
        result_queue.put(("EXC", owner, type(error).__name__, str(error)))


class ThinClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "v6.sqlite3"
        create_schema(self.db, 6)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_schema_contract_tamper_is_detected_before_authority_use(self) -> None:
        v6 = schema_contract.generated.SCHEMA_PROFILES[0]
        weakened = (v6[0], v6[1], v6[2], v6[3], v6[4], v6[5][:-1], v6[6])
        with patch.object(
            schema_contract.generated,
            "SCHEMA_PROFILES",
            (weakened, *schema_contract.generated.SCHEMA_PROFILES[1:]),
        ):
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                client_build_identity()
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                GlobalWriterLeaseClient(self.db)

        with patch.object(schema_contract, "EXPECTED_SCHEMA_CONTRACT_IDENTITY", "sha256:" + "0" * 64):
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                client_build_identity()

        v8 = schema_contract.generated.SCHEMA_PROFILES[2]
        corrupted_v8 = (v8[0], v8[1], v8[2], v8[3], v8[4], v8[5], v8[6][:-1])
        with patch.object(
            schema_contract.generated,
            "SCHEMA_PROFILES",
            (*schema_contract.generated.SCHEMA_PROFILES[:2], corrupted_v8, *schema_contract.generated.SCHEMA_PROFILES[3:]),
        ):
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                client_build_identity()

        v9 = schema_contract.generated.SCHEMA_PROFILES[3]
        corrupted_v9 = (v9[0], v9[1], v9[2], v9[3], v9[4], v9[5], v9[6][:-1])
        with patch.object(
            schema_contract.generated,
            "SCHEMA_PROFILES",
            (*schema_contract.generated.SCHEMA_PROFILES[:3], corrupted_v9, *schema_contract.generated.SCHEMA_PROFILES[4:]),
        ):
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                client_build_identity()

        v10 = schema_contract.generated.SCHEMA_PROFILES[4]
        corrupted_v10 = (v10[0], v10[1], v10[2], v10[3], v10[4], v10[5], v10[6][:-1])
        with patch.object(
            schema_contract.generated,
            "SCHEMA_PROFILES",
            (*schema_contract.generated.SCHEMA_PROFILES[:4], corrupted_v10),
        ):
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                client_build_identity()

    def test_schema5_fails_closed_without_any_mutation(self) -> None:
        old = self.root / "v5.sqlite3"
        create_schema(old, 5)
        before = old.read_bytes()
        connection = sqlite3.connect(old)
        try:
            before_objects = connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY"):
            GlobalWriterLeaseClient(old)
        connection = sqlite3.connect(old)
        try:
            after_objects = connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        finally:
            connection.close()
        self.assertEqual(before, old.read_bytes())
        self.assertEqual(before_objects, after_objects)
        self.assertFalse(any("global_production_writer" in row[1] for row in after_objects))

    def test_public_lifecycle_and_fencing(self) -> None:
        with GlobalWriterLeaseClient(self.db) as client:
            self.assertEqual("FREE", client.get()["state"])
            row = client.acquire(**acquire("A", "life"))
            self.assertEqual(1, row["fencing_token"])
            self.assertEqual(1, client.assert_current("A", 1)["fencing_token"])
            self.assertEqual(1, client.heartbeat("A", 1, 120)["fencing_token"])
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_HELD"):
                client.acquire(**acquire("B", "held"))
            with self.assertRaises(GlobalWriterClientError):
                client.assert_current("B", 1)
            released = client.release(operation_key=key("release:life"), owner_id="A", fencing_token=1)
            self.assertEqual("FREE", released["state"])
            with self.assertRaises(GlobalWriterClientError):
                client.assert_current("A", 1)


    def test_cross_process_acquire_exclusivity(self) -> None:
        context = multiprocessing.get_context("spawn")
        ready_queue = context.Queue()
        result_queue = context.Queue()
        start_event = context.Event()
        processes = [
            context.Process(
                target=_process_acquire_worker,
                args=(str(self.db), ready_queue, start_event, result_queue, owner),
            )
            for owner in ("A", "B")
        ]
        for process in processes:
            process.start()
        try:
            ready = [ready_queue.get(timeout=15) for _ in processes]
            self.assertEqual({("READY", "A"), ("READY", "B")}, set(ready))
            start_event.set()
            results = [result_queue.get(timeout=15) for _ in processes]
            winners = [result for result in results if result[0] == "OK"]
            losers = [result for result in results if result[0] == "ERR"]
            self.assertEqual(1, len(winners), results)
            self.assertEqual(1, len(losers), results)
            self.assertEqual("GLOBAL_PRODUCTION_WRITER_HELD", losers[0][2])
            self.assertEqual(1, winners[0][2])
        finally:
            start_event.set()
            for process in processes:
                process.join(15)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            for process in processes:
                self.assertEqual(0, process.exitcode)

    def test_expired_takeover_and_stale_owner(self) -> None:
        old = lambda: datetime(2020, 1, 1, tzinfo=timezone.utc)
        with GlobalWriterLeaseClient(self.db, _clock=old) as client:
            client.acquire(**acquire("A", "old"))
        with GlobalWriterLeaseClient(self.db) as client:
            takeover = client.acquire(**acquire("B", "takeover"))
            self.assertEqual(2, takeover["fencing_token"])
            self.assertEqual("B", takeover["owner_id"])
            with self.assertRaises(GlobalWriterClientError):
                client.assert_current("A", 1)

    def test_operation_key_binds_semantic_payload(self) -> None:
        kwargs = acquire("A", "idem")
        with GlobalWriterLeaseClient(self.db) as client:
            first = client.acquire(**kwargs)
            second = client.acquire(**kwargs)
            self.assertEqual(dict(first), dict(second))
            changed = dict(kwargs)
            changed["writer_class"] = "GMAIL"
            with self.assertRaisesRegex(GlobalWriterClientError, "IDEMPOTENCY_CONFLICT"):
                client.acquire(**changed)

    def test_force_revoke_is_control_only(self) -> None:
        with GlobalWriterLeaseClient(self.db) as ordinary:
            self.assertFalse(hasattr(ordinary, "force_revoke"))
            ordinary.acquire(**acquire("A", "revoke"))
        with GlobalWriterControlClient(self.db) as control:
            row = control.force_revoke(
                operation_key=key("force-revoke"),
                reason="control decision",
                control_decision_ref="CONTROL/R1",
                expected_owner_id="A",
                expected_fencing_token=1,
            )
            self.assertEqual(2, row["fencing_token"])
            with self.assertRaises(GlobalWriterClientError):
                control.assert_current("A", 1)

    def _corrupt_held(self, acquired: str, expires: str, heartbeat: str, updated: str) -> None:
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                """UPDATE global_production_writer_lease
                      SET state='HELD', owner_id='A', owner_execution_id='exec-A', change_id='CHANGE-A',
                          slice_id='SLICE-A', writer_class='CORE', owner_session_role='TEST', track='CORE',
                          repository_or_runtime='source-commit:1111111111111111111111111111111111111111',
                          operation_class='PRODUCTION_WRITE', target='GLOBAL_PRODUCTION', fencing_token=7,
                          acquired_at=?, expires_at=?, heartbeat_at=?, updated_at=?
                    WHERE resource_key='GLOBAL_PRODUCTION'""",
                (acquired, expires, heartbeat, updated),
            )
            connection.commit()
        finally:
            connection.close()

    def _assert_persisted_corruption_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            GlobalWriterClientError,
            "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID|GLOBAL_PRODUCTION_WRITER_STATE_INVALID",
        ):
            GlobalWriterLeaseClient(self.db)

    def test_basic_iso_constraint_bypass_fails_closed(self) -> None:
        self._corrupt_held(
            "20260828T213400+00:00", "20260828T223400+00:00",
            "20260828T220000+00:00", "20260828T220000+00:00",
        )
        self._assert_persisted_corruption_fails_closed()

    def test_comma_fraction_constraint_bypass_fails_closed(self) -> None:
        self._corrupt_held(
            "2026-08-28T21:34:00,123456+00:00",
            "2026-08-28T22:34:00,123456+00:00",
            "2026-08-28T22:00:00,123456+00:00",
            "2026-08-28T22:00:00,123456+00:00",
        )
        self._assert_persisted_corruption_fails_closed()

    def test_impossible_temporal_state_constraint_bypass_fails_closed(self) -> None:
        self._corrupt_held(
            "2026-08-28T21:34:00.000000+00:00",
            "2026-08-28T22:34:00.000000+00:00",
            "2099-01-01T00:00:00.000000+00:00",
            "2020-01-01T00:00:00.000000+00:00",
        )
        self._assert_persisted_corruption_fails_closed()

    def test_bad_migration_checksum_and_missing_history_fail_closed(self) -> None:
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE schema_migration SET checksum=? WHERE version=6", ("0" * 64,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
            GlobalWriterLeaseClient(self.db)

        missing = self.root / "missing-migration.sqlite3"
        create_schema(missing, 6)
        connection = sqlite3.connect(missing)
        try:
            connection.execute("DELETE FROM schema_migration WHERE version=4")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
            GlobalWriterLeaseClient(missing)

    def test_missing_authority_objects_fail_closed(self) -> None:
        for kind, name in (
            ("TRIGGER", "global_production_writer_lease_fencing_monotonic"),
            ("TRIGGER", "global_production_writer_event_immutable_delete"),
            ("INDEX", "uq_slice_execution_open"),
        ):
            path = self.root / (name + ".sqlite3")
            create_schema(path, 6)
            connection = sqlite3.connect(path)
            try:
                connection.execute(f"DROP {kind} {name}")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
                GlobalWriterLeaseClient(path)

    def test_partial_v6_and_future_schema_fail_closed(self) -> None:
        partial = self.root / "partial.sqlite3"
        create_schema(partial, 6)
        connection = sqlite3.connect(partial)
        try:
            connection.execute("DELETE FROM schema_migration WHERE version=6")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY"):
            GlobalWriterLeaseClient(partial)

        future = self.root / "future.sqlite3"
        create_schema(future, 10)
        connection = sqlite3.connect(future)
        try:
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(11,'0011_future',?,?)",
                ("0" * 64, "2026-08-29T00:00:00.000000+00:00"),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
            GlobalWriterLeaseClient(future)

    def test_fencing_trigger_removal_and_token_rollback_exploit_is_closed(self) -> None:
        with GlobalWriterLeaseClient(self.db) as client:
            self.assertEqual(1, client.acquire(**acquire("A", "rollback"))["fencing_token"])
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("DROP TRIGGER global_production_writer_lease_fencing_monotonic")
            connection.execute(
                "UPDATE global_production_writer_lease SET fencing_token=0 WHERE resource_key='GLOBAL_PRODUCTION'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
            GlobalWriterLeaseClient(self.db)

    def test_schema_tamper_after_open_is_revalidated_before_authority(self) -> None:
        client = GlobalWriterLeaseClient(self.db)
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("DROP TRIGGER global_production_writer_event_immutable_update")
            connection.commit()
        finally:
            connection.close()
        try:
            with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID"):
                client.get()
        finally:
            client.close()

    def test_state_event_atomicity_fault_injection(self) -> None:
        with GlobalWriterStore(self.db) as store:
            before = dict(store.get())
            self.assertEqual([], store.events())
            def fail(point: str) -> None:
                if point == "after_state_update":
                    raise RuntimeError("injected")
            with self.assertRaisesRegex(RuntimeError, "injected"):
                store.acquire(**acquire("A", "fault"), _fault_injector=fail)
            self.assertEqual(before, dict(store.get()))
            self.assertEqual([], store.events())


if __name__ == "__main__":
    unittest.main()
