from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import multiprocessing
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from _fixtures import create_schema
from adcp.store.migrations import MIGRATIONS, _execute_statements, migrate
from adcp_global_writer_client import (
    GlobalWriterClientError,
    GlobalWriterControlClient,
    GlobalWriterLeaseClient,
    client_build_identity,
)
from adcp_global_writer_client.schema_contract import verify_client_schema_contract, verify_schema_contract
from adcp_global_writer_client.store import GlobalWriterStore

V6_ID = "sha256:047dd3c4cb1449bd428c0c8519f2baf29e876a9a96e5427767a577f5d5be94dd"
V7_ID = "sha256:e2b33ffa88badf3abba475110234f1e885a121d860ed00039ec294ed5bfa5c62"
V8_ID = "sha256:eb020317a18e1f12f1316d311f22d26e45a1dc11f5d45e3b16dc39aed162508a"
V9_ID = "sha256:0f0bf3c32f0cf4af5b047bc6afdf2a61940df2a1e2a8395463f9183e678e3b6b"
V10_ID = "sha256:1bfa57994e2ea90b11146d32839ca6a8875ad94bb0eea9128fb3b8fb3c5ce7e9"
LEGACY_DUAL_ID = "sha256:966387cc5ea17df6e6bdb89993c32f0c72d59fdaf33ebfaaba1b5e31e81a1e56"
V678_ID = "sha256:b5601f47b0447e5ad47a7a1d5cee7d20692c96b5105b925ed71cd4ddfe98ba6b"
V6789_ID = "sha256:1deb066c05c1cfec1b5945e8e2b31bfd212eb80bd4021b0696ee1ee93364a0f6"
V678910_ID = "sha256:288a69e75d8bd4399bbac1973a8632d54a79c0052debec79636a184b715db2a5"


def key(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def acquire(owner: str, label: str) -> dict[str, object]:
    return {
        "operation_key": key("acquire:" + label),
        "owner_id": owner,
        "change_id": "CHANGE-" + owner,
        "writer_class": "CORE",
        "owner_session_role": "V6V7_PARITY",
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


class ProtocolParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _fixture(self, version: int, label: str) -> Path:
        path = self.root / f"{label}-v{version}.sqlite3"
        create_schema(path, version)
        return path

    def _rejects(self, path: Path, code: str = "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID") -> None:
        with self.assertRaisesRegex(GlobalWriterClientError, code):
            GlobalWriterLeaseClient(path)

    def test_exact_finite_contract_and_build_identity(self) -> None:
        contract = verify_client_schema_contract()
        self.assertEqual(2, contract.thin_contract_format_version)
        self.assertEqual((6, 7, 8, 9, 10), contract.supported_dcs_schema_versions)
        self.assertEqual(V678910_ID, contract.schema_contract_identity)
        self.assertNotEqual(V6789_ID, contract.schema_contract_identity)
        self.assertNotEqual(V678_ID, contract.schema_contract_identity)
        self.assertNotEqual(LEGACY_DUAL_ID, contract.schema_contract_identity)
        self.assertEqual((6, 7, 8, 9, 10), tuple(p.schema_version for p in contract.profiles))
        self.assertEqual((V6_ID, V7_ID, V8_ID, V9_ID, V10_ID), tuple(p.profile_identity for p in contract.profiles))
        self.assertEqual((16, 17, 18, 27, 27), tuple(len(p.expected_tables) for p in contract.profiles))
        self.assertEqual((12, 13, 14, 17, 17), tuple(len(p.expected_indexes) for p in contract.profiles))
        self.assertEqual((43, 49, 52, 78, 78), tuple(len(p.expected_triggers) for p in contract.profiles))
        self.assertEqual((71, 79, 84, 122, 122), tuple(len(p.expected_object_fingerprints) for p in contract.profiles))
        identity = client_build_identity()
        self.assertEqual("0.5.0", identity.version)
        self.assertEqual(2, identity.thin_contract_format_version)
        self.assertEqual((6, 7, 8, 9, 10), identity.supported_dcs_schema_versions)
        self.assertEqual(V678910_ID, identity.schema_contract_identity)

    def test_canonical_v6_and_v7_are_both_accepted(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                with GlobalWriterLeaseClient(self._fixture(version, "canonical")) as client:
                    self.assertEqual("FREE", client.get()["state"])

    def test_legacy_production_migration_contract_remains_exact_v6_v7(self) -> None:
        contract = verify_schema_contract()
        self.assertEqual((6, 7), contract.supported_dcs_schema_versions)
        self.assertEqual(LEGACY_DUAL_ID, contract.schema_contract_identity)
        self.assertEqual((6, 7), tuple(profile.schema_version for profile in contract.profiles))
        self.assertEqual((V6_ID, V7_ID), tuple(profile.profile_identity for profile in contract.profiles))
        for unsupported in (8, 9, 10):
            with self.subTest(unsupported=unsupported):
                with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_WRITER_CLIENT_SCHEMA_CONTRACT_INVALID"):
                    contract.profile_for_version(unsupported)

    def test_canonical_v8_is_accepted_as_its_exact_profile(self) -> None:
        path = self._fixture(8, "canonical")
        with GlobalWriterLeaseClient(path) as client:
            self.assertEqual("FREE", client.get()["state"])
        profile = verify_client_schema_contract().profile_for_version(8)
        self.assertEqual(V8_ID, profile.profile_identity)
        self.assertIn("typed_postgres_operation_receipt_event", profile.expected_tables)
        self.assertIn("idx_typed_postgres_receipt_operation", profile.expected_indexes)
        self.assertIn("typed_postgres_operation_receipt_event_immutable_update", profile.expected_triggers)

    def test_canonical_v9_is_accepted_as_its_exact_profile(self) -> None:
        path = self._fixture(9, "canonical")
        with GlobalWriterLeaseClient(path) as client:
            self.assertEqual("FREE", client.get()["state"])
        profile = verify_client_schema_contract().profile_for_version(9)
        self.assertEqual(V9_ID, profile.profile_identity)
        self.assertIn("candidate_content_binding", profile.expected_tables)
        self.assertIn("idx_candidate_binding_execution", profile.expected_indexes)
        self.assertIn("candidate_content_binding_immutable_update", profile.expected_triggers)

    def test_canonical_v10_is_accepted_as_exact_receipt_kind_extension(self) -> None:
        path = self._fixture(10, "canonical")
        with GlobalWriterLeaseClient(path) as client:
            self.assertEqual("FREE", client.get()["state"])
        contract = verify_client_schema_contract()
        profile9 = contract.profile_for_version(9)
        profile10 = contract.profile_for_version(10)
        self.assertEqual(V10_ID, profile10.profile_identity)
        v9 = {(kind, name): digest for kind, name, digest in profile9.expected_object_fingerprints}
        v10 = {(kind, name): digest for kind, name, digest in profile10.expected_object_fingerprints}
        self.assertEqual(set(v9), set(v10))
        self.assertEqual(
            {("table", "typed_postgres_operation_receipt_event")},
            {key for key in v9 if v9[key] != v10[key]},
        )
        self.assertEqual(
            v9[("index", "idx_typed_postgres_receipt_operation")],
            v10[("index", "idx_typed_postgres_receipt_operation")],
        )
        for trigger in (
            "typed_postgres_operation_receipt_event_immutable_update",
            "typed_postgres_operation_receipt_event_immutable_delete",
            "typed_postgres_operation_receipt_event_final_requires_prepared",
        ):
            self.assertEqual(v9[("trigger", trigger)], v10[("trigger", trigger)])

    def test_v8_v9_v10_writer_lifecycle_and_event_semantics_match(self) -> None:
        snapshots = []
        for version in (8, 9, 10):
            path = self._fixture(version, "v8-v9-v10-parity")
            with GlobalWriterLeaseClient(path) as client:
                request = acquire("A", f"v8-v9-v10-parity-{version}")
                request["slice_id"] = "DEPLOYMENT-A"
                held = client.acquire(**request)
                token = held["fencing_token"]
                self.assertEqual(1, token)
                self.assertEqual(dict(held), dict(client.acquire(**request)))
                conflict = dict(request)
                conflict["slice_id"] = "DEPLOYMENT-B"
                with self.assertRaisesRegex(
                    GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT"
                ):
                    client.acquire(**conflict)
                self.assertEqual(token, client.assert_current("A", token)["fencing_token"])
                self.assertEqual(token, client.heartbeat("A", token, 120)["fencing_token"])
                released = client.release(
                    operation_key=key(f"v8-v9-v10-parity-release-{version}"),
                    owner_id="A",
                    fencing_token=token,
                )
                with GlobalWriterStore(path) as store:
                    events = [dict(row) for row in store.events()]
                    self.assertEqual(2, len(events))
                    event_semantics = tuple(
                        (row["event_type"], row["from_fencing_token"], row["to_fencing_token"])
                        for row in events
                    )
                snapshots.append((held["state"], released["state"], token, released["fencing_token"], event_semantics))
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(("HELD", "FREE", 1, 1), snapshots[0][:4])

    def test_identical_writer_lifecycle_semantics_on_v6_and_v7(self) -> None:
        snapshots = []
        for version in (6, 7):
            path = self._fixture(version, "lifecycle")
            with GlobalWriterLeaseClient(path) as client:
                self.assertEqual("FREE", client.get()["state"])
                request = acquire("A", f"life-{version}")
                held = client.acquire(**request)
                token = held["fencing_token"]
                self.assertEqual(1, token)
                self.assertEqual(held, client.acquire(**request))
                with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_HELD"):
                    client.acquire(**acquire("B", f"held-{version}"))
                current = client.assert_current("A", token)
                heartbeat = client.heartbeat("A", token, 120)
                released = client.release(
                    operation_key=key(f"release-{version}"), owner_id="A", fencing_token=token
                )
                with self.assertRaises(GlobalWriterClientError):
                    client.assert_current("A", token)
                snapshots.append(
                    (
                        held["state"], current["state"], heartbeat["state"],
                        released["state"], held["fencing_token"], released["fencing_token"],
                    )
                )
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(("HELD", "HELD", "HELD", "FREE", 1, 1), snapshots[0])

    def test_full_lifecycle_security_matrix_on_v6_and_v7(self) -> None:
        snapshots = []
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "full-matrix")
                with GlobalWriterLeaseClient(path) as client:
                    self.assertEqual("FREE", client.get()["state"])
                    request = acquire("A", f"matrix-{version}")
                    held = client.acquire(**request)
                    token = held["fencing_token"]
                    self.assertEqual(1, token)

                    replay = client.acquire(**request)
                    self.assertEqual(dict(held), dict(replay))
                    conflict = dict(request)
                    conflict["writer_class"] = "GMAIL"
                    with self.assertRaisesRegex(
                        GlobalWriterClientError,
                        "GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT",
                    ):
                        client.acquire(**conflict)

                    self.assertEqual(token, client.assert_current("A", token)["fencing_token"])
                    self.assertEqual(token, client.heartbeat("A", token, 120)["fencing_token"])
                    with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
                        client.assert_current("B", token)
                    with self.assertRaisesRegex(GlobalWriterClientError, "STALE_FENCING_TOKEN"):
                        client.assert_current("A", token + 1)

                    released = client.release(
                        operation_key=key(f"release-matrix-{version}"),
                        owner_id="A",
                        fencing_token=token,
                    )
                    self.assertEqual("FREE", released["state"])
                    with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_NOT_HELD"):
                        client.assert_current("A", token)
                    snapshots.append((held["state"], released["state"], token))
        self.assertEqual([("HELD", "FREE", 1), ("HELD", "FREE", 1)], snapshots)

    def test_cross_process_one_winner_exclusivity_on_v6_and_v7(self) -> None:
        context = multiprocessing.get_context("spawn")
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "process-race")
                ready_queue = context.Queue()
                result_queue = context.Queue()
                start_event = context.Event()
                processes = [
                    context.Process(
                        target=_process_acquire_worker,
                        args=(str(path), ready_queue, start_event, result_queue, owner),
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

    def test_expired_takeover_and_stale_rejection_on_v6_and_v7(self) -> None:
        expired_clock = lambda: datetime(2020, 1, 1, tzinfo=timezone.utc)
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "takeover")
                with GlobalWriterLeaseClient(path, _clock=expired_clock) as client:
                    first = client.acquire(**acquire("A", f"expired-{version}"))
                    self.assertEqual(1, first["fencing_token"])
                with GlobalWriterLeaseClient(path) as client:
                    takeover = client.acquire(**acquire("B", f"takeover-{version}"))
                    self.assertEqual(2, takeover["fencing_token"])
                    self.assertEqual("B", takeover["owner_id"])
                    with self.assertRaisesRegex(GlobalWriterClientError, "STALE_FENCING_TOKEN"):
                        client.assert_current("A", 1)
                    with self.assertRaisesRegex(GlobalWriterClientError, "GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH"):
                        client.assert_current("A", 2)

    def test_force_revoke_control_only_on_v6_and_v7(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "force-revoke")
                with GlobalWriterLeaseClient(path) as ordinary:
                    self.assertFalse(hasattr(ordinary, "force_revoke"))
                    ordinary.acquire(**acquire("A", f"revoke-{version}"))
                with GlobalWriterControlClient(path) as control:
                    revoked = control.force_revoke(
                        operation_key=key(f"force-revoke-{version}"),
                        reason="control decision",
                        control_decision_ref=f"CONTROL/V{version}",
                        expected_owner_id="A",
                        expected_fencing_token=1,
                    )
                    self.assertEqual("FREE", revoked["state"])
                    self.assertEqual(2, revoked["fencing_token"])
                    with self.assertRaisesRegex(GlobalWriterClientError, "STALE_FENCING_TOKEN"):
                        control.assert_current("A", 1)

    def test_malformed_persisted_lease_state_fails_closed_on_supported_versions(self) -> None:
        for version in (6, 7, 8, 9, 10):
            with self.subTest(version=version):
                path = self._fixture(version, "malformed-state")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    connection.execute(
                        "UPDATE global_production_writer_lease "
                        "SET state='HELD', owner_id='A', change_id='CHANGE-A', writer_class='CORE', "
                        "owner_session_role='TEST', track='CORE', "
                        "repository_or_runtime='source-commit:1111111111111111111111111111111111111111', "
                        "operation_class='PRODUCTION_WRITE', target='GLOBAL_PRODUCTION', "
                        "acquired_at='2026-09-01T00:00:00.000000+00:00', "
                        "expires_at='2026-09-01T00:10:00.000000+00:00', "
                        "heartbeat_at='2099-01-01T00:00:00.000000+00:00', "
                        "updated_at='2020-01-01T00:00:00.000000+00:00' "
                        "WHERE resource_key='GLOBAL_PRODUCTION'"
                    )
                self._rejects(path)

    def test_transaction_rollback_fault_injection_on_v6_and_v7(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "fault-rollback")
                with GlobalWriterStore(path) as store:
                    before = dict(store.get())
                    self.assertEqual([], store.events())

                    def fail(point: str) -> None:
                        if point == "after_state_update":
                            raise RuntimeError("injected")

                    with self.assertRaisesRegex(RuntimeError, "injected"):
                        store.acquire(**acquire("A", f"fault-{version}"), _fault_injector=fail)
                    self.assertEqual(before, dict(store.get()))
                    self.assertEqual([], store.events())

    def test_v7_specific_0007_missing_objects_fail_closed(self) -> None:
        objects = (
            ("TABLE", "evaluator_artifact_seal"),
            ("INDEX", "idx_evaluator_artifact_seal_binding"),
            ("TRIGGER", "evaluator_artifact_seal_immutable_update"),
        )
        for kind, name in objects:
            with self.subTest(kind=kind, name=name):
                path = self._fixture(7, f"missing-0007-{kind.lower()}")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(f"DROP {kind} {name}")
                self._rejects(path)

    def test_v7_specific_0007_mutated_object_fingerprints_fail_closed(self) -> None:
        objects = (
            ("table", "evaluator_artifact_seal"),
            ("index", "idx_evaluator_artifact_seal_binding"),
            ("trigger", "evaluator_artifact_seal_immutable_update"),
        )
        for kind, name in objects:
            with self.subTest(kind=kind, name=name):
                path = self._fixture(7, f"mutated-0007-{kind}")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("PRAGMA writable_schema=ON")
                    connection.execute(
                        "UPDATE sqlite_schema SET sql=sql||' /*tampered*/' WHERE type=? AND name=?",
                        (kind, name),
                    )
                self._rejects(path)

    def test_integrity_check_failure_rejected_on_v6_and_v7(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "integrity-failure")
                with closing(sqlite3.connect(path)) as connection, connection:
                    roots = dict(
                        connection.execute(
                            "SELECT name,rootpage FROM sqlite_schema "
                            "WHERE type='table' AND name IN "
                            "('global_production_writer_lease','global_production_writer_event')"
                        )
                    )
                    connection.execute("PRAGMA writable_schema=ON")
                    connection.execute(
                        "UPDATE sqlite_schema SET rootpage=? WHERE name='global_production_writer_lease'",
                        (roots["global_production_writer_event"],),
                    )
                with closing(sqlite3.connect(path)) as connection:
                    self.assertNotEqual([("ok",)], connection.execute("PRAGMA integrity_check").fetchall())
                with self.assertRaisesRegex(
                    GlobalWriterClientError,
                    "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID: integrity_check failed",
                ):
                    GlobalWriterLeaseClient(path)

    def test_foreign_key_check_violation_rejected_on_v6_and_v7(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "fk-failure")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("PRAGMA foreign_keys=OFF")
                    connection.execute(
                        "INSERT INTO approval_request("
                        "approval_id,idempotency_key,execution_id,approval_type,required,status,"
                        "authority_ref,requested_at"
                        ") VALUES(?,?,?,?,?,?,?,?)",
                        (
                            f"bad-approval-v{version}",
                            "f" * 64,
                            "missing-execution",
                            "TEST",
                            1,
                            "PENDING",
                            "TEST/FK",
                            "2026-09-01T00:00:00.000000+00:00",
                        ),
                    )
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual([("ok",)], connection.execute("PRAGMA integrity_check").fetchall())
                    self.assertTrue(connection.execute("PRAGMA foreign_key_check").fetchall())
                with self.assertRaisesRegex(
                    GlobalWriterClientError,
                    "GLOBAL_WRITER_CLIENT_SCHEMA_INVALID: foreign_key_check failed",
                ):
                    GlobalWriterLeaseClient(path)

    def test_empty_schema_registry_is_not_ready(self) -> None:
        path = self._fixture(6, "empty-registry")
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("DELETE FROM schema_migration")
        self._rejects(path, "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY")

    def test_missing_schema_registry_table_is_not_ready(self) -> None:
        path = self._fixture(6, "missing-registry")
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("DROP TABLE schema_migration")
        self._rejects(path, "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY")

    def test_v5_and_canonical_prefix_fail_not_ready_without_migration(self) -> None:
        for version in (0, 1, 2, 3, 4, 5):
            with self.subTest(version=version):
                path = self._fixture(version, "old")
                before = path.read_bytes()
                self._rejects(path, "GLOBAL_WRITER_CLIENT_SCHEMA_NOT_READY")
                self.assertEqual(before, path.read_bytes())

    def test_fake_0007_fake_v8_and_v9_contract_tamper_fail_closed(self) -> None:
        fake = self._fixture(6, "fake0007")
        with closing(sqlite3.connect(fake)) as connection, connection:
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(7,'0007_fake',?,?)",
                ("7" * 64, "2026-09-01T00:00:00.000000+00:00"),
            )
        self._rejects(fake)

        fake_v8 = self._fixture(7, "fake-v8")
        with closing(sqlite3.connect(fake_v8)) as connection, connection:
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(8,'0008_future',?,?)",
                ("8" * 64, "2026-09-01T00:00:00.000000+00:00"),
            )
        self._rejects(fake_v8)

        for label, mutation in (
            ("bad-checksum", "UPDATE schema_migration SET checksum='" + "9" * 64 + "' WHERE version=9"),
            ("wrong-name", "UPDATE schema_migration SET name='0009_wrong' WHERE version=9"),
            ("missing-9", "DELETE FROM schema_migration WHERE version=9"),
            ("noncontiguous", "DELETE FROM schema_migration WHERE version=8"),
        ):
            path = self._fixture(9, label)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute(mutation)
            self._rejects(path)

        future = self._fixture(10, "v11")
        with closing(sqlite3.connect(future)) as connection, connection:
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(11,'0011_future',?,?)",
                ("0" * 64, "2026-09-01T00:00:00.000000+00:00"),
            )
        self._rejects(future)

    def test_v9_required_candidate_object_removal_or_change_fails_closed(self) -> None:
        missing = self._fixture(9, "v9-missing-candidate-table")
        with closing(sqlite3.connect(missing)) as connection, connection:
            connection.execute("DROP TABLE candidate_commit_closure")
        self._rejects(missing)

        changed = self._fixture(9, "v9-changed-candidate-table")
        with closing(sqlite3.connect(changed)) as connection, connection:
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute(
                "UPDATE sqlite_schema SET sql=sql||' /*tampered*/' "
                "WHERE type='table' AND name='candidate_content_binding'"
            )
            connection.execute("PRAGMA writable_schema=OFF")
        self._rejects(changed)

    def test_disposable_v8_to_v9_preserves_live_gpw_state_and_reopens(self) -> None:
        path = self._fixture(8, "disposable-migrate")
        with GlobalWriterLeaseClient(path) as client:
            held = client.acquire(**acquire("A", "disposable-migrate"))
            self.assertEqual("HELD", held["state"])
            self.assertEqual(1, held["fencing_token"])
        with GlobalWriterStore(path) as store:
            before_state = dict(store.get())
            before_events = [dict(row) for row in store.events()]

        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            result = migrate(connection, target_version=9)
            self.assertEqual(8, result.previous_version)
            self.assertEqual(9, result.version)
            self.assertTrue(result.applied)
            self.assertEqual([("ok",)], connection.execute("PRAGMA integrity_check").fetchall())
            self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())

        with GlobalWriterLeaseClient(path) as client:
            reopened = client.get()
            self.assertEqual("HELD", reopened["state"])
            self.assertEqual("A", reopened["owner_id"])
            self.assertEqual(1, reopened["fencing_token"])
            self.assertEqual(1, client.assert_current("A", 1)["fencing_token"])
        with GlobalWriterStore(path) as store:
            self.assertEqual(before_state, dict(store.get()))
            self.assertEqual(before_events, [dict(row) for row in store.events()])

    def test_v8_missing_receipt_ledger_fails_closed(self) -> None:
        path = self._fixture(8, "v8-missing-ledger")
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("DROP TABLE typed_postgres_operation_receipt_event")
        self._rejects(path)

    def test_v8_wrong_receipt_constraint_fails_closed(self) -> None:
        path = self._fixture(8, "v8-wrong-constraint")
        with closing(sqlite3.connect(path)) as connection, connection:
            sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' "
                "AND name='typed_postgres_operation_receipt_event'"
            ).fetchone()[0]
            self.assertIn("receipt_version = 1", sql)
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute(
                "UPDATE sqlite_schema SET sql=replace(sql, 'receipt_version = 1', "
                "'receipt_version IN (1,2)') WHERE type='table' "
                "AND name='typed_postgres_operation_receipt_event'"
            )
            connection.execute("PRAGMA writable_schema=OFF")
        self._rejects(path)

    def test_partial_v7_both_directions_fail_closed(self) -> None:
        objects_only = self._fixture(6, "partial-v7-objects")
        with closing(sqlite3.connect(objects_only)) as connection, connection:
            _execute_statements(connection, MIGRATIONS[6].sql)
        self._rejects(objects_only)

        row_only = self._fixture(6, "partial-v7-row")
        migration = MIGRATIONS[6]
        with closing(sqlite3.connect(row_only)) as connection, connection:
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, "2026-09-01T00:00:00.000000+00:00"),
            )
        self._rejects(row_only)

    def test_v6_v7_object_tamper_fails_closed(self) -> None:
        for version in (6, 7):
            with self.subTest(version=version):
                path = self._fixture(version, "tamper")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("DROP TRIGGER global_production_writer_lease_fencing_monotonic")
                    connection.execute(
                        """CREATE TRIGGER global_production_writer_lease_fencing_monotonic
                           BEFORE UPDATE OF fencing_token ON global_production_writer_lease
                           BEGIN SELECT 1; END"""
                    )
                self._rejects(path)

    def test_extra_table_index_trigger_or_view_fails_closed(self) -> None:
        mutations = {
            "table": "CREATE TABLE unauthorized_table(id INTEGER)",
            "index": "CREATE INDEX unauthorized_index ON schema_migration(name)",
            "trigger": "CREATE TRIGGER unauthorized_trigger AFTER INSERT ON schema_migration BEGIN SELECT 1; END",
            "view": "CREATE VIEW unauthorized_view AS SELECT version FROM schema_migration",
        }
        for version in (6, 7, 8, 9, 10):
            for kind, sql in mutations.items():
                with self.subTest(version=version, kind=kind):
                    path = self._fixture(version, f"extra-{kind}")
                    with closing(sqlite3.connect(path)) as connection, connection:
                        connection.execute(sql)
                    self._rejects(path)

    def test_missing_or_changed_migration_history_fails_closed(self) -> None:
        for version in (6, 7, 8, 9, 10):
            with self.subTest(version=version):
                path = self._fixture(version, "history")
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute("UPDATE schema_migration SET checksum=? WHERE version=6", ("0" * 64,))
                self._rejects(path)

    def test_no_migration_capability_is_exposed(self) -> None:
        path = self._fixture(6, "surface")
        with GlobalWriterLeaseClient(path) as client:
            for forbidden in (
                "migrate", "migration", "backup", "restore", "execute", "executemany",
                "create_table", "drop_table", "schema_registry", "apply_migration",
            ):
                self.assertFalse(hasattr(client, forbidden), forbidden)

    def test_v8_v9_v10_schema_recognition_adds_no_receipt_or_postgres_mutation_authority(self) -> None:
        forbidden = (
            "typed_postgres_operation_receipt_events",
            "get_typed_postgres_operation_receipt_event",
            "append_typed_postgres_operation_receipt_event",
            "execute_authorized_sql_file",
            "transition_database_owner",
            "apply_role_password_from_protected_file",
            "provision_cleaner_app_principal",
        )
        for version in (8, 9, 10):
            path = self._fixture(version, f"v{version}-surface")
            with GlobalWriterLeaseClient(path) as ordinary:
                for name in forbidden:
                    self.assertFalse(hasattr(ordinary, name), name)
            with GlobalWriterControlClient(path) as control:
                for name in forbidden:
                    self.assertFalse(hasattr(control, name), name)


if __name__ == "__main__":
    unittest.main()
