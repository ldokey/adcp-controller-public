from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


THIN_SOURCE = Path(__file__).resolve().parents[1] / "packages/adcp-global-writer-client/src"
if str(THIN_SOURCE) not in sys.path:
    sys.path.insert(0, str(THIN_SOURCE))

from adcp.store import migrations
from adcp_global_writer_client import GlobalWriterControlClient
import adcp.production_migration_orchestrator as subject
from adcp.production_migration_orchestrator import (
    ExecutionContext,
    EXPECTED_WRITER_CODES,
    ProductionMigrationError,
    ProductionMigrationOrchestrator,
    RuntimeWriter,
    canonical_table_fingerprint,
    capture_preservation_baseline,
    create_immutable_backup,
    verify_immutable_backup,
)


def create_v6(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(migrations.SCHEMA_MIGRATION_SQL)
        for migration in migrations.MIGRATIONS[:6]:
            migrations._execute_statements(connection, migration.sql)
            connection.execute(
                "INSERT INTO schema_migration VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, "2026-08-31T00:00:00.000000+00:00"),
            )
        connection.commit()
    finally:
        connection.close()


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
        self.mono = 100.0

    def now(self):
        return self.value

    def monotonic(self):
        return self.mono

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.value += timedelta(seconds=seconds)


class FakeQuiescence:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events if events is not None else []
        self.writers = {
            (code, code.lower()): RuntimeWriter(
                code, code.lower(), "PROPERTYAI" if code <= "W07" else "ADCP", "ACTIVE"
            )
            for code in sorted(EXPECTED_WRITER_CODES)
        }
        self.quiesce_failure: tuple[str, str] | None = None
        self.reactivated: list[tuple[str, str]] = []

    def discover(self):
        self.events.append("discover")
        return tuple(self.writers.values())

    def quiesce(self, writer):
        self.events.append("quiesce:" + writer.service_code)
        if writer.identity != self.quiesce_failure:
            self.writers[writer.identity] = replace(writer, state="QUIESCED")

    def inspect(self, writer):
        self.events.append("inspect:" + writer.service_code)
        return self.writers[writer.identity]

    def reactivate(self, writer):
        self.events.append("reactivate:" + writer.service_code)
        self.reactivated.append(writer.identity)
        self.writers[writer.identity] = replace(writer, state="ACTIVE")


class RecordingClient:
    def __init__(
        self,
        inner,
        events,
        schema_version,
        acquire_records,
        transaction_flag=None,
        heartbeat_override=None,
    ):
        self.inner = inner
        self.events = events
        self.schema_version = schema_version
        self.acquire_records = acquire_records
        self.transaction_flag = transaction_flag
        self.heartbeat_override = heartbeat_override

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def acquire(self, **kwargs):
        self.events.append(f"acquire:v{self.schema_version}")
        row = self.inner.acquire(**kwargs)
        self.acquire_records.append({"request": dict(kwargs), "row": dict(row)})
        return row

    def assert_current(self, owner, token):
        self.events.append(f"assert:v{self.schema_version}")
        return self.inner.assert_current(owner, token)

    def heartbeat(self, owner, token, ttl):
        self.events.append(f"heartbeat:v{self.schema_version}")
        if self.transaction_flag is not None and self.transaction_flag[0]:
            raise AssertionError("heartbeat during migration transaction")
        row = self.inner.heartbeat(owner, token, ttl)
        return self.heartbeat_override(row) if self.heartbeat_override else row

    def release(self, **kwargs):
        self.events.append(f"release:v{self.schema_version}")
        return self.inner.release(**kwargs)

    def close(self):
        self.events.append(f"close:v{self.schema_version}")
        return self.inner.close()


class FrozenMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "canonical-v6.sqlite3"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        create_v6(self.database)
        self.clock = FakeClock()
        self.events: list[str] = []
        self.acquire_records: list[dict[str, dict[str, object]]] = []
        self.quiescence = FakeQuiescence(self.events)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def context(self, **changes) -> ExecutionContext:
        values = dict(
            dcs_path=self.database,
            evidence_root=self.evidence,
            accepted_git_head="1" * 40,
            accepted_git_tree="2" * 40,
            authority_ref="FROZEN/ADCP-V6V7-01A",
            owner_execution_id="migration-execution-01a",
            background_heartbeat=False,
        )
        values.update(changes)
        return ExecutionContext(**values)

    def factory(self, *, transaction_flag=None, heartbeat_override=None, fail_version=None):
        def build(path, clock):
            version = subject._read_schema_version(path)
            if version == fail_version:
                raise RuntimeError("injected rebind failure")
            inner = GlobalWriterControlClient(path, _clock=clock)
            return RecordingClient(
                inner,
                self.events,
                version,
                self.acquire_records,
                transaction_flag,
                heartbeat_override,
            )
        return build

    def execute(self, **changes):
        options = dict(
            context=self.context(), authority=lambda: {"generation": 7},
            quiescence=self.quiescence, clock=self.clock, client_factory=self.factory(),
            owner_id_factory=lambda: "frozen-owner",
        )
        options.update(changes)
        return ProductionMigrationOrchestrator(**options).run()

    # 01
    def test_frozen_01_canonical_v6_to_v7_success(self):
        result = self.execute()
        self.assertEqual((6, 7, 0), (result.previous_version, result.version, result.production_effect))

    # 02
    def test_frozen_02_v6_fresh_acquire_binds_owner_and_fence(self):
        result = self.execute()
        self.assertEqual(("frozen-owner", "migration-execution-01a", 1),
                         (result.owner_id, result.owner_execution_id, result.fencing_token))
        self.assertIn("acquire:v6", self.events)

    def test_f01_acquire_uses_exact_frozen_lease_metadata_and_dcs_target(self):
        self.execute()
        self.assertEqual(1, len(self.acquire_records))
        record = self.acquire_records[0]
        expected_target = str(self.database.resolve())
        self.assertEqual(
            {
                "writer_class": "ADCP_PRODUCTION_MIGRATION_ORCHESTRATOR",
                "operation_class": "PRODUCTION_SCHEMA_MIGRATION",
                "target": expected_target,
            },
            {field: record["request"][field] for field in ("writer_class", "operation_class", "target")},
        )
        self.assertEqual(
            {
                "resource_key": "GLOBAL_PRODUCTION",
                "writer_class": "ADCP_PRODUCTION_MIGRATION_ORCHESTRATOR",
                "operation_class": "PRODUCTION_SCHEMA_MIGRATION",
                "target": expected_target,
            },
            {
                field: record["row"][field]
                for field in ("resource_key", "writer_class", "operation_class", "target")
            },
        )

    # 03
    def test_frozen_03_fresh_v7_rebind_asserts_same_owner_and_fence(self):
        self.execute()
        self.assertIn("assert:v7", self.events)
        self.assertNotIn("acquire:v7", self.events)

    # 04
    def test_frozen_04_v7_heartbeat_resumes(self):
        self.execute()
        self.assertIn("heartbeat:v7", self.events)

    # 05
    def test_frozen_05_lease_acquired_before_quiesce(self):
        self.execute()
        self.assertLess(self.events.index("acquire:v6"), self.events.index("quiesce:W01"))


    def test_conflicting_gpw_event_during_quiescence_stable_verification_fails_closed(self):
        outer = self
        class EventInjectingQuiescence(FakeQuiescence):
            def __init__(self, events):
                super().__init__(events)
                self.injected = False
            def quiesce(self, writer):
                super().quiesce(writer)
                if self.injected:
                    return
                self.injected = True
                connection = sqlite3.connect(outer.database)
                connection.row_factory = sqlite3.Row
                try:
                    latest = connection.execute(
                        "SELECT * FROM global_production_writer_event ORDER BY event_seq DESC LIMIT 1"
                    ).fetchone()
                    assert latest is not None
                    connection.execute(
                        """INSERT INTO global_production_writer_event(
                            event_id,operation_key,resource_key,event_type,
                            from_fencing_token,to_fencing_token,
                            prior_owner_id,prior_owner_execution_id,prior_change_id,prior_slice_id,
                            prior_writer_class,prior_owner_session_role,prior_track,
                            prior_repository_or_runtime,prior_operation_class,prior_target,
                            new_owner_id,new_owner_execution_id,new_change_id,new_slice_id,
                            new_writer_class,new_owner_session_role,new_track,
                            new_repository_or_runtime,new_operation_class,new_target,
                            reason,control_decision_ref,request_json,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            "fixture-conflicting-release", "f" * 64, "GLOBAL_PRODUCTION", "RELEASE",
                            latest["to_fencing_token"], latest["to_fencing_token"],
                            latest["new_owner_id"], latest["new_owner_execution_id"],
                            latest["new_change_id"], latest["new_slice_id"], latest["new_writer_class"],
                            latest["new_owner_session_role"], latest["new_track"],
                            latest["new_repository_or_runtime"], latest["new_operation_class"],
                            latest["new_target"], None, None, None, None, None, None, None, None, None, None,
                            "fixture conflict", None, "{}", "2026-09-01T00:00:01.000000+00:00",
                        ),
                    )
                    connection.commit()
                finally:
                    connection.close()

        quiescence = EventInjectingQuiescence(self.events)
        with self.assertRaisesRegex(ProductionMigrationError, "GLOBAL_WRITER_EVENT_CONFLICT"):
            self.execute(quiescence=quiescence)
        self.assertFalse(any(event.startswith("reactivate:") for event in self.events))

    # 06
    def test_frozen_06_all_expected_writers_accounted(self):
        result = self.execute()
        self.assertEqual(9, len(result.quiesced_identities))
        self.assertEqual(EXPECTED_WRITER_CODES, {code for code, _ in result.quiesced_identities})

    # 07
    def test_frozen_07_unknown_writer_fails_closed(self):
        unknown = RuntimeWriter("WX", "unknown", "PROPERTYAI", "ACTIVE")
        self.quiescence.writers[unknown.identity] = unknown
        with self.assertRaisesRegex(ProductionMigrationError, "UNKNOWN_OR_UNCLASSIFIED_WRITER"):
            self.execute()
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)
        self.assertFalse(any(event.startswith("reactivate:") for event in self.events))

    # 08
    def test_frozen_08_quiescence_failure_rejected(self):
        self.quiescence.quiesce_failure = ("W04", "w04")
        with self.assertRaisesRegex(ProductionMigrationError, "WRITER_QUIESCENCE_FAILED"):
            self.execute()

    # 09
    def test_frozen_09_conflicting_writer_rejected(self):
        key = ("W03", "w03")
        self.quiescence.writers[key] = replace(self.quiescence.writers[key], conflicting=True)
        with self.assertRaisesRegex(ProductionMigrationError, "CONFLICTING_WRITER"):
            self.execute()

    # 10
    def test_frozen_10_stale_writer_rejected(self):
        key = ("W02", "w02")
        self.quiescence.writers[key] = replace(self.quiescence.writers[key], identity_validation="STALE")
        with self.assertRaisesRegex(ProductionMigrationError, "STALE_WRITER_IDENTITY"):
            self.execute()

    # 11
    def test_frozen_11_final_fencing_assert_precedes_migration(self):
        def primitive(connection, *, backup_root):
            self.events.append("migrate")
            return migrations.migrate(connection, backup_root=backup_root)
        self.execute(migrate_primitive=primitive)
        self.assertEqual("assert:v6", self.events[self.events.index("migrate") - 2])
        self.assertEqual("close:v6", self.events[self.events.index("migrate") - 1])

    def held_backup(self):
        client = GlobalWriterControlClient(self.database, _clock=self.clock.now)
        row = client.acquire(
            operation_key="a" * 64, owner_id="backup-owner", owner_execution_id="backup-execution",
            change_id=subject.CHANGE_ID, slice_id="backup-execution", writer_class="TEST",
            owner_session_role="TEST", track="TEST", repository_or_runtime="isolated",
            operation_class="BACKUP", target="isolated-backup-fixture", ttl_seconds=300,
        )
        return client, row

    # 12
    def test_frozen_12_immutable_backup_validates(self):
        client, row = self.held_backup()
        try:
            evidence = create_immutable_backup(
                self.context(), owner_id="backup-owner", owner_execution_id="backup-execution",
                fencing_token=row["fencing_token"], now=self.clock.now(),
            )
            verify_immutable_backup(evidence)
        finally:
            client.close()

    def test_f02_backup_manifest_and_directories_fsync_before_migration(self):
        sequence: list[tuple[str, str]] = []
        original_file_fsync = subject._fsync_file
        original_directory_fsync = subject._fsync_directory

        def file_fsync(path, failure_code):
            sequence.append(("file", Path(path).name))
            return original_file_fsync(path, failure_code)

        def directory_fsync(path):
            sequence.append(("directory", str(Path(path))))
            return original_directory_fsync(path)

        def primitive(connection, *, backup_root):
            sequence.append(("migration", "begin"))
            return migrations.migrate(connection, backup_root=backup_root)

        with patch.object(subject, "_fsync_file", side_effect=file_fsync), patch.object(
            subject, "_fsync_directory", side_effect=directory_fsync
        ):
            result = self.execute(migrate_primitive=primitive)

        self.assertEqual(
            [
                ("file", "canonical-v6.sqlite3.bak"),
                ("file", "manifest.json"),
                ("directory", str(result.backup.evidence_directory)),
                ("directory", str(self.evidence)),
                ("migration", "begin"),
            ],
            sequence,
        )

    def _assert_file_fsync_failure_prevents_migration(self, failure_code: str) -> None:
        original = subject._fsync_file
        migration_calls: list[str] = []

        def fail_selected(path, code):
            if code == failure_code:
                raise ProductionMigrationError(code, "injected")
            return original(path, code)

        def primitive(connection, *, backup_root):
            migration_calls.append("migration")
            return migrations.migrate(connection, backup_root=backup_root)

        with patch.object(subject, "_fsync_file", side_effect=fail_selected):
            with self.assertRaisesRegex(ProductionMigrationError, failure_code):
                self.execute(migrate_primitive=primitive)
        self.assertEqual([], migration_calls)
        self.assertEqual([], self.quiescence.reactivated)
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertTrue(any(self.evidence.iterdir()), "ambiguous evidence must not be cleaned up")

    def test_f02_backup_file_fsync_failure_fails_closed_before_migration(self):
        self._assert_file_fsync_failure_prevents_migration("BACKUP_FILE_FSYNC_FAILED")

    def test_f02_manifest_fsync_failure_fails_closed_before_migration(self):
        self._assert_file_fsync_failure_prevents_migration("BACKUP_MANIFEST_FSYNC_FAILED")

    def test_f02_directory_fsync_failure_fails_closed_before_migration(self):
        migration_calls: list[str] = []

        def primitive(connection, *, backup_root):
            migration_calls.append("migration")
            return migrations.migrate(connection, backup_root=backup_root)

        with patch.object(
            subject,
            "_fsync_directory",
            side_effect=ProductionMigrationError("BACKUP_DIRECTORY_FSYNC_FAILED", "injected"),
        ):
            with self.assertRaisesRegex(ProductionMigrationError, "BACKUP_DIRECTORY_FSYNC_FAILED"):
                self.execute(migrate_primitive=primitive)
        self.assertEqual([], migration_calls)
        self.assertEqual([], self.quiescence.reactivated)
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertTrue(any(self.evidence.iterdir()), "ambiguous evidence must not be cleaned up")

    def test_f_ie_01_parent_evidence_root_fsync_failure_keeps_writers_quiesced(self):
        migration_calls: list[str] = []
        directory_calls = [0]
        original = subject._fsync_directory

        def fail_parent(path):
            directory_calls[0] += 1
            if directory_calls[0] == 2:
                raise ProductionMigrationError("BACKUP_DIRECTORY_FSYNC_FAILED", "injected parent")
            return original(path)

        def primitive(connection, *, backup_root):
            migration_calls.append("migration")
            return migrations.migrate(connection, backup_root=backup_root)

        with patch.object(subject, "_fsync_directory", side_effect=fail_parent):
            with self.assertRaisesRegex(ProductionMigrationError, "BACKUP_DIRECTORY_FSYNC_FAILED"):
                self.execute(migrate_primitive=primitive)
        self.assertEqual(2, directory_calls[0])
        self.assertEqual([], migration_calls)
        self.assertEqual([], self.quiescence.reactivated)
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertTrue(any(self.evidence.iterdir()), "failed evidence must be preserved")

    def test_f_ie_01_post_quiescence_pre_transaction_failure_keeps_writers_quiesced(self):
        migration_calls: list[str] = []

        def primitive(connection, *, backup_root):
            migration_calls.append("migration")
            return migrations.migrate(connection, backup_root=backup_root)

        with patch.object(
            subject,
            "verify_immutable_backup",
            side_effect=ProductionMigrationError("INJECTED_BACKUP_VALIDATION_FAILURE", "injected"),
        ):
            with self.assertRaisesRegex(ProductionMigrationError, "INJECTED_BACKUP_VALIDATION_FAILURE"):
                self.execute(migrate_primitive=primitive)

        self.assertEqual([], migration_calls)
        self.assertEqual([], self.quiescence.reactivated)
        self.assertTrue(all(writer.state == "QUIESCED" for writer in self.quiescence.writers.values()))
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertTrue(any(self.evidence.iterdir()), "failed evidence must be preserved")
        self.assertIn("release:v6", self.events, "lease release remains separate from writer restart")
        self.assertFalse(any(event.startswith("reactivate:") for event in self.events))

    # 13
    def test_frozen_13_existing_evidence_collision_fails(self):
        client, row = self.held_backup()
        try:
            create_immutable_backup(self.context(), owner_id="backup-owner", owner_execution_id="backup-execution",
                                    fencing_token=row["fencing_token"], now=self.clock.now())
            with self.assertRaisesRegex(ProductionMigrationError, "BACKUP_EVIDENCE_COLLISION"):
                create_immutable_backup(self.context(), owner_id="backup-owner", owner_execution_id="backup-execution",
                                        fencing_token=row["fencing_token"], now=self.clock.now())
        finally:
            client.close()

    # 14
    def test_frozen_14_historical_backups_are_never_pruned(self):
        historical = [self.root / f"control.sqlite3.v6.old-{index}.bak" for index in range(7)]
        for path in historical:
            path.write_bytes(b"historical")
        self.execute()
        self.assertTrue(all(path.read_bytes() == b"historical" for path in historical))

    # 15
    def test_frozen_15_backup_tamper_detected(self):
        client, row = self.held_backup()
        try:
            evidence = create_immutable_backup(self.context(), owner_id="backup-owner",
                                               owner_execution_id="backup-execution",
                                               fencing_token=row["fencing_token"], now=self.clock.now())
            os.chmod(evidence.backup_path, 0o600)
            with evidence.backup_path.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaisesRegex(ProductionMigrationError, "BACKUP_FILE_TAMPERED"):
                verify_immutable_backup(evidence)
        finally:
            client.close()

    # 16
    def test_frozen_16_source_symlink_identity_rejected(self):
        link = self.root / "alias.sqlite3"
        link.symlink_to(self.database)
        with self.assertRaisesRegex(ProductionMigrationError, "CANONICAL_DCS_PATH_INVALID"):
            self.execute(context=self.context(dcs_path=link))

    # 17
    def test_frozen_17_exact_v1_through_v6_registry_required(self):
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE schema_migration SET checksum=? WHERE version=6", ("0" * 64,))
        connection.commit(); connection.close()
        with self.assertRaises(Exception):
            self.execute()

    def _migration_rows(self, predicate: str = ""):
        connection = sqlite3.connect(self.database)
        try:
            columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(schema_migration)"))
            rows = tuple(connection.execute(
                "SELECT * FROM schema_migration " + predicate + " ORDER BY version"
            ))
            return columns, rows
        finally:
            connection.close()

    def test_f03_success_exactly_preserves_all_old_columns_and_appends_canonical_0007(self):
        before_columns, before_rows = self._migration_rows("WHERE version BETWEEN 1 AND 6")
        self.execute()
        after_columns, after_rows = self._migration_rows()
        self.assertEqual(before_columns, after_columns)
        self.assertEqual(before_rows, after_rows[:6])
        self.assertEqual(tuple(range(1, 8)), tuple(row[0] for row in after_rows))
        self.assertEqual(
            (7, subject.MIGRATION_NAME, subject.MIGRATION_CHECKSUM),
            after_rows[6][:3],
        )
        self.assertIsInstance(after_rows[6][3], str)
        self.assertTrue(after_rows[6][3])

    def _assert_old_registry_attack_rejected(
        self,
        statement: str,
        parameters=(),
        *,
        expected_code: str,
    ) -> None:
        attack_calls: list[str] = []

        def attack_after_exact_v7_rebind(row):
            if subject._read_schema_version(self.database) == 7 and not attack_calls:
                connection = sqlite3.connect(self.database, isolation_level=None)
                try:
                    connection.execute(statement, parameters)
                finally:
                    connection.close()
                attack_calls.append("mutated")
            return row

        with self.assertRaisesRegex(ProductionMigrationError, expected_code):
            self.execute(client_factory=self.factory(heartbeat_override=attack_after_exact_v7_rebind))
        self.assertEqual(["mutated"], attack_calls)
        self.assertIn("heartbeat:v7", self.events)
        self.assertEqual(7, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)

    def test_f03_applied_at_only_attack_is_rejected(self):
        self._assert_old_registry_attack_rejected(
            "UPDATE schema_migration SET applied_at=? WHERE version=1",
            ("2099-01-01T00:00:00.000000+00:00",),
            expected_code="MIGRATION_REGISTRY_0001_0006_CHANGED",
        )
        self.assertEqual(
            "2099-01-01T00:00:00.000000+00:00",
            self._migration_rows("WHERE version=1")[1][0][3],
        )

    def test_f03_old_name_attack_is_rejected(self):
        self._assert_old_registry_attack_rejected(
            "UPDATE schema_migration SET name=? WHERE version=2",
            ("forged_0002_name",),
            expected_code="MIGRATION_REGISTRY_MISMATCH",
        )

    def test_f03_old_checksum_attack_is_rejected(self):
        self._assert_old_registry_attack_rejected(
            "UPDATE schema_migration SET checksum=? WHERE version=3",
            ("f" * 64,),
            expected_code="MIGRATION_REGISTRY_MISMATCH",
        )

    def test_f03_old_row_deletion_attack_is_rejected(self):
        self._assert_old_registry_attack_rejected(
            "DELETE FROM schema_migration WHERE version=4",
            expected_code="MIGRATION_REGISTRY_MISMATCH",
        )

    # 18
    def test_frozen_18_integrity_failure_is_hard_error(self):
        with patch.object(subject, "_validate_profile_connection",
                          side_effect=ProductionMigrationError("SQLITE_INTEGRITY_FAILED")):
            with self.assertRaisesRegex(ProductionMigrationError, "SQLITE_INTEGRITY_FAILED"):
                capture_preservation_baseline(self.database, 6)

    # 19
    def test_frozen_19_foreign_key_failure_is_hard_error(self):
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO context_snapshot VALUES('orphan','missing','MAKER',1,?,'{}','now')",
            ("a" * 64,),
        )
        connection.commit(); connection.close()
        with self.assertRaises(Exception):
            self.execute()

    # 20
    def test_frozen_20_insufficient_pre_begin_horizon(self):
        def short(row):
            return {**row, "expires_at": (self.clock.now() + timedelta(seconds=239)).isoformat(timespec="microseconds")}
        with self.assertRaisesRegex(ProductionMigrationError, "LEASE_HORIZON_INSUFFICIENT"):
            self.execute(client_factory=self.factory(heartbeat_override=short))
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)

    # 21
    def test_frozen_21_under_30_second_budget_succeeds(self):
        def primitive(connection, *, backup_root):
            result = migrations.migrate(connection, backup_root=backup_root)
            self.clock.advance(29.999)
            return result
        self.assertEqual(7, self.execute(migrate_primitive=primitive).version)

    # 22
    def test_frozen_22_at_30_second_budget_fails_after_preserving_v7(self):
        def primitive(connection, *, backup_root):
            result = migrations.migrate(connection, backup_root=backup_root)
            self.clock.advance(30)
            return result
        with self.assertRaisesRegex(ProductionMigrationError, "MIGRATION_TRANSACTION_BUDGET_EXCEEDED"):
            self.execute(migrate_primitive=primitive)
        self.assertEqual(7, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)

    # 23
    def test_frozen_23_no_heartbeat_during_sqlite_transaction(self):
        flag = [False]
        def primitive(connection, *, backup_root):
            flag[0] = True
            try:
                return migrations.migrate(connection, backup_root=backup_root)
            finally:
                flag[0] = False
        self.execute(migrate_primitive=primitive, client_factory=self.factory(transaction_flag=flag))

    # 24
    def test_frozen_24_pre_begin_failure_remains_v6(self):
        missing = self.root / "missing-evidence-root"
        with self.assertRaisesRegex(ProductionMigrationError, "EVIDENCE_ROOT_NOT_PRECREATED"):
            self.execute(context=self.context(evidence_root=missing))
        self.assertEqual(6, subject._read_schema_version(self.database))

    # 25
    def test_frozen_25_transaction_rollback_remains_exact_v6(self):
        before = capture_preservation_baseline(self.database, 6)
        def rollback(connection, *, backup_root):
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE global_production_writer_lease SET updated_at=updated_at")
            connection.execute("ROLLBACK")
            raise RuntimeError("injected rollback")
        with self.assertRaisesRegex(ProductionMigrationError, "ACCEPTED_MIGRATION_FAILED"):
            self.execute(migrate_primitive=rollback)
        after = capture_preservation_baseline(self.database, 6)
        # Lease lifecycle can change during safe release; every other table is exact.
        for table in set(before.tables) - {"global_production_writer_lease", "global_production_writer_event"}:
            self.assertEqual(before.tables[table], after.tables[table])
        self.assertEqual([], self.quiescence.reactivated)
        self.assertTrue(all(writer.state == "QUIESCED" for writer in self.quiescence.writers.values()))
        self.assertIn("release:v6", self.events, "rollback lease release is separate from writer restart")

    def test_f_ie_01_transaction_rollback_failure_never_reactivates_writers(self):
        migration_calls = [0]
        before = capture_preservation_baseline(self.database, 6)

        def rollback(connection, *, backup_root):
            migration_calls[0] += 1
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE global_production_writer_lease SET updated_at=updated_at")
            connection.execute("ROLLBACK")
            raise RuntimeError("f-ie-01 injected rollback")

        with self.assertRaisesRegex(ProductionMigrationError, "ACCEPTED_MIGRATION_FAILED"):
            self.execute(migrate_primitive=rollback)

        after = capture_preservation_baseline(self.database, 6)
        self.assertEqual(1, migration_calls[0])
        self.assertEqual(6, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)
        self.assertTrue(all(writer.state == "QUIESCED" for writer in self.quiescence.writers.values()))
        self.assertGreaterEqual(self.events.count("assert:v6"), 2, "fresh v6 authority rebind/inspection must occur")
        self.assertNotIn("acquire:v7", self.events)
        self.assertIn("release:v6", self.events, "provable rollback lease release remains permitted")
        for table in set(before.tables) - {"global_production_writer_lease", "global_production_writer_event"}:
            self.assertEqual(before.tables[table], after.tables[table])

    # 26
    def test_frozen_26_post_rollback_fresh_v6_rebind_and_inspection(self):
        def rollback(connection, *, backup_root):
            raise RuntimeError("rollback")
        with self.assertRaises(ProductionMigrationError):
            self.execute(migrate_primitive=rollback)
        self.assertGreaterEqual(self.events.count("assert:v6"), 2)

    # 27
    def test_frozen_27_post_commit_validation_failure_leaves_v7_frozen(self):
        with patch.object(ProductionMigrationOrchestrator, "_post_migration_validation",
                          side_effect=ProductionMigrationError("INJECTED_POST_VALIDATION", phase="POST_COMMIT", schema_version=7)):
            with self.assertRaisesRegex(ProductionMigrationError, "INJECTED_POST_VALIDATION"):
                self.execute()
        self.assertEqual(7, subject._read_schema_version(self.database))
        self.assertEqual([], self.quiescence.reactivated)

    # 28
    def test_frozen_28_post_commit_fencing_ambiguity_has_no_reacquire_or_release(self):
        with self.assertRaisesRegex(ProductionMigrationError, "POST_TRANSACTION_FENCING_AMBIGUOUS"):
            self.execute(client_factory=self.factory(fail_version=7))
        self.assertEqual(7, subject._read_schema_version(self.database))
        self.assertNotIn("acquire:v7", self.events)
        self.assertNotIn("release:v7", self.events)

    # 29
    def test_frozen_29_authority_generation_drift_rejected(self):
        calls = [0]
        def authority():
            calls[0] += 1
            return {"generation": 1 if calls[0] == 1 else 2}
        with self.assertRaisesRegex(ProductionMigrationError, "AUTHORITY_SOURCE_DRIFT"):
            self.execute(authority=authority)

    # 30
    def test_frozen_30_all_v6_tables_fingerprinted_and_preserved(self):
        before = capture_preservation_baseline(self.database, 6)
        result = self.execute()
        self.assertEqual(16, result.preserved_table_count)
        self.assertEqual(16, len(before.tables))

    # 31
    def test_frozen_31_authority_and_cutover_preserved(self):
        before = capture_preservation_baseline(self.database, 6).authority
        self.execute()
        after = capture_preservation_baseline(self.database, 7).authority
        self.assertEqual(before, after)

    # 32
    def test_frozen_32_global_writer_history_and_fence_preserved_by_transaction(self):
        result = self.execute()
        connection = sqlite3.connect(self.database)
        rows = connection.execute("SELECT event_type,to_fencing_token FROM global_production_writer_event ORDER BY event_seq").fetchall()
        connection.close()
        self.assertEqual([("ACQUIRE", result.fencing_token), ("RELEASE", result.fencing_token)], rows)

    # 33
    def test_frozen_33_r4_binding_tables_are_in_preservation_set(self):
        names = capture_preservation_baseline(self.database, 6).tables
        for name in ("slice_execution", "agent_attempt", "context_snapshot", "verification_result", "control_authority_state"):
            self.assertIn(name, names)

    # 34
    def test_frozen_34_evaluation_result_preservation_is_explicit(self):
        before = capture_preservation_baseline(self.database, 6).tables["evaluation_result"]
        self.execute()
        after = capture_preservation_baseline(self.database, 7).tables["evaluation_result"]
        self.assertEqual(before, after)

    # 35
    def test_frozen_35_no_legacy_attested_or_r4_recovery_paths(self):
        source = Path(subject.__file__).read_text(encoding="utf-8")
        self.assertNotIn("LEGACY_ATTESTED", source)
        self.assertNotIn("R4_RECOVERY", source)
        self.assertNotIn("INSERT INTO evaluation_result", source)

    # 36
    def test_frozen_36_exact_artifact_seal_objects_zero_semantic_rows(self):
        self.execute()
        connection = sqlite3.connect(self.database)
        profile, _, _ = subject._validate_profile_connection(connection, 7)
        count = connection.execute("SELECT count(*) FROM evaluator_artifact_seal").fetchone()[0]
        connection.close()
        self.assertIn("evaluator_artifact_seal", profile.expected_tables)
        self.assertEqual(0, count)

    # 37
    def test_frozen_37_reactivate_only_previously_active_c_validated_identities(self):
        key = ("W01", "w01")
        self.quiescence.writers[key] = replace(self.quiescence.writers[key], state="QUIESCED")
        self.execute()
        self.assertNotIn(key, self.quiescence.reactivated)
        self.assertEqual(8, len(self.quiescence.reactivated))

    # 38
    def test_frozen_38_controlled_simulation_ends_lease_free_with_zero_production_effect(self):
        result = self.execute()
        self.assertEqual(("FREE", 0), (result.final_lease_state, result.production_effect))

    def test_dynamic_write_capable_runtime_is_quiesced_when_classified(self):
        dynamic = RuntimeWriter("DYNAMIC_CLEANER", "pid-42", "DYNAMIC", "ACTIVE")
        self.quiescence.writers[dynamic.identity] = dynamic
        result = self.execute()
        self.assertIn(dynamic.identity, result.quiesced_identities)

    def test_manifest_binds_git_migration_authority_and_all_fingerprints(self):
        result = self.execute()
        document = json.loads(result.backup.manifest_path.read_text())
        self.assertEqual("1" * 40, document["accepted_git_head"])
        self.assertEqual(subject.MIGRATION_CHECKSUM, document["migration_checksum"])
        self.assertEqual(
            ["version", "name", "checksum", "applied_at"],
            document["migration_registry"]["columns"],
        )
        self.assertEqual(6, len(document["migration_registry"]["rows"]))
        self.assertEqual(16, len(document["table_fingerprints"]))

    def test_backup_manifest_and_directory_host_guards_are_read_only(self):
        result = self.execute()
        self.assertEqual(0, result.backup.backup_path.stat().st_mode & 0o222)
        self.assertEqual(0, result.backup.manifest_path.stat().st_mode & 0o222)
        self.assertEqual(0, result.backup.evidence_directory.stat().st_mode & 0o222)

    def test_typed_fingerprint_distinguishes_integer_text_and_binary(self):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE x(a,b,c)")
        connection.execute("INSERT INTO x VALUES(1,'1',x'31')")
        first = canonical_table_fingerprint(connection, "x")
        connection.execute("UPDATE x SET a='1', b=1")
        second = canonical_table_fingerprint(connection, "x")
        connection.close()
        self.assertNotEqual(first.sha256, second.sha256)

    def test_migration_primitive_is_called_only_with_backup_root_none(self):
        calls = []
        def primitive(connection, **kwargs):
            calls.append(kwargs)
            return migrations.migrate(connection, **kwargs)
        self.execute(migrate_primitive=primitive)
        self.assertEqual([{"backup_root": None}], calls)

    def test_starting_v7_is_rejected_without_mutation(self):
        connection = sqlite3.connect(self.database, isolation_level=None)
        migrations.migrate(connection, backup_root=None)
        connection.close()
        with self.assertRaisesRegex(ProductionMigrationError, "STARTING_SCHEMA_V6_REQUIRED"):
            self.execute()

    def test_canonical_production_requires_separate_authorization_context(self):
        with self.assertRaisesRegex(ProductionMigrationError, "CANONICAL_PRODUCTION_AUTHORIZATION_REQUIRED"):
            self.execute(context=self.context(canonical_production_path=self.database))


if __name__ == "__main__":
    unittest.main()
