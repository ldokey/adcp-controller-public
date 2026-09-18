from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from adcp.canonical import canonical_json, canonical_sha256
from adcp.domain import StoreError
from adcp.store.migrations import (
    EXPECTED_INDEXES,
    EXPECTED_TABLES,
    EXPECTED_TRIGGERS,
    MIGRATION_1_SQL,
    MIGRATION_1_CHECKSUM,
    MIGRATION_2_CHECKSUM,
    MIGRATION_2_NAME,
    MIGRATION_2_SQL,
    MIGRATION_3_CHECKSUM,
    MIGRATION_3_NAME,
    MIGRATION_3_SQL,
    MIGRATION_4_CHECKSUM,
    MIGRATION_4_NAME,
    MIGRATION_4_SQL,
    MIGRATION_5_CHECKSUM,
    MIGRATION_5_NAME,
    MIGRATION_5_SQL,
    MIGRATION_6_CHECKSUM,
    MIGRATION_6_NAME,
    MIGRATION_6_SQL,
    MIGRATION_7_CHECKSUM,
    MIGRATION_7_NAME,
    MIGRATION_7_SQL,
    MIGRATION_8_CHECKSUM,
    MIGRATION_8_NAME,
    MIGRATION_8_SQL,
    MIGRATION_9_CHECKSUM,
    MIGRATION_9_NAME,
    MIGRATION_9_SQL,
    MIGRATION_10_CHECKSUM,
    MIGRATION_10_NAME,
    MIGRATION_10_SQL,
    MIGRATION_CHECKSUM,
    MIGRATION_NAME,
    MIGRATIONS,
    SCHEMA_MIGRATION_SQL,
    migration_checksum,
    schema_profile_identity,
    validate_schema,
)
from adcp.store.migrations import migrate
from adcp.store.sqlite import connect


class MigrationTests(unittest.TestCase):
    def configured_connection(self, path: Path) -> sqlite3.Connection:
        return connect(path)

    def insert_typed_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        operation_type: str,
        phase: str = "PREPARED",
        principal_identity: str = "fixture-principal",
        fencing_token: int = 17,
    ) -> None:
        final = phase == "FINAL"
        connection.execute(
            """INSERT INTO typed_postgres_operation_receipt_event(
                receipt_id,receipt_version,change_id,control_decision_ref,deployment_id,
                operation_id,operation_type,receipt_phase,target_service,target_database,
                principal_identity,credential_reference,artifact_path,artifact_sha256,
                request_fingerprint,before_state_fingerprint,after_state_fingerprint,
                effect_status,w08_fencing_token,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"receipt-{operation_id}-{phase.lower()}", 1, "TK43", "DL82",
                f"deployment-{operation_id}", operation_id, operation_type, phase,
                "com.propertyai.postgresql-cleaner", "propertyai_cleaner_prod",
                principal_identity, "credential-ref", "/tmp/fixture.sql", "a" * 64,
                "b" * 64, "c" * 64, "d" * 64 if final else None,
                "APPLIED" if final else "PENDING", fencing_token,
                "2026-09-12T00:00:00.000000+00:00",
            ),
        )

    def create_v2_five_slice_store(self, connection: sqlite3.Connection) -> None:
        connection.execute(SCHEMA_MIGRATION_SQL)
        connection.executescript(MIGRATION_1_SQL)
        connection.executescript(MIGRATION_2_SQL)
        connection.execute(
            "INSERT INTO schema_migration VALUES (1, ?, ?, 'v1-applied')",
            (MIGRATION_NAME, MIGRATION_1_CHECKSUM),
        )
        connection.execute(
            "INSERT INTO schema_migration VALUES (2, ?, ?, 'v2-applied')",
            (MIGRATION_2_NAME, MIGRATION_2_CHECKSUM),
        )
        connection.execute("BEGIN IMMEDIATE")
        for index in range(5):
            slice_id = f"slice-{index}"
            connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, -1, 0, 'V2_FIXTURE', '{}', 'v2-created')""",
                (f"{index + 1:064x}", slice_id),
            )
            connection.execute(
                """INSERT INTO slice_control_state(
                    slice_id, stage, status, authority_fingerprint, migration_class,
                    execution_eligibility, defer_reason, logical_source_root,
                    state_version, created_at, updated_at
                ) VALUES (?, 'S1', 'WAITING', ?, 'DEFER_PREREQUISITE',
                          'INELIGIBLE_UNTIL_PREREQUISITE', 'fixture', ?, 0,
                          'v2-created', 'v2-created')""",
                (slice_id, f"{index + 10:064x}", f"/isolated/{slice_id}"),
            )
        connection.execute("COMMIT")
        connection.execute(
            """UPDATE control_authority_state
                  SET authority_generation = 1,
                      slice_snapshot_fingerprint = ?,
                      rollback_snapshot_fingerprint = ?,
                      updated_at = 'v2-updated'
                WHERE singleton_id = 'GLOBAL'""",
            ("a" * 64, "b" * 64),
        )

    def promote_fixture_to_v3(self, connection: sqlite3.Connection) -> None:
        connection.executescript(MIGRATION_3_SQL)
        connection.execute(
            "INSERT INTO schema_migration VALUES (3, ?, ?, 'v3-applied')",
            (MIGRATION_3_NAME, MIGRATION_3_CHECKSUM),
        )
        now = "2026-08-14T00:00:00.000000+00:00"
        connection.execute(
            """INSERT INTO slice_execution(
                execution_id, create_idempotency_key, slice_id, risk_level, environment,
                state, state_version, contract_fingerprint, authority_fingerprint,
                source_root, branch, base_commit, result_commit, max_auto_reworks,
                current_actor_role, created_at, updated_at
            ) VALUES (
                'bound-execution', ?, 'bound-slice', 'NORMAL', 'TEST', 'READY', 0,
                ?, ?, '/isolated/repository', 'accepted-branch', ?, ?, 2,
                'CONTROLLER', ?, ?
            )""",
            ("6" * 64, "7" * 64, "8" * 64, "9" * 40, "a" * 40, now, now),
        )
        connection.execute(
            """INSERT INTO transition_event(
                event_id, execution_id, operation_key, event_type, from_state, to_state,
                from_state_version, to_state_version, actor_role, actor_id,
                lease_generation, reason_code, metadata_json, created_at
            ) VALUES (
                'bound-created', 'bound-execution', ?, 'EXECUTION_CREATED', NULL, 'READY',
                -1, 0, 'CONTROLLER', 'fixture', 0, 'EXECUTION_CREATED', '{}', ?
            )""",
            ("b" * 64, now),
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT INTO slice_control_event(
                operation_key, slice_id, from_state_version, to_state_version,
                reason_code, metadata_json, created_at
            ) VALUES (?, 'bound-slice', -1, 0, 'V3_BOUND_FIXTURE', '{}', ?)""",
            ("d" * 64, now),
        )
        connection.execute(
            """INSERT INTO slice_control_state(
                slice_id, stage, status, authority_fingerprint, migration_class,
                execution_eligibility, defer_reason, logical_source_root,
                repository_toplevel, branch, base_commit, implementation_result_commit,
                current_branch_head, active_execution_id, state_version, created_at, updated_at
            ) VALUES (
                'bound-slice', 'S8', 'CLOSED', ?, 'MIGRATE_AS_READY_CURRENT_STATE',
                'ELIGIBLE_BOUND', NULL, '/logical/repository', '/isolated/repository',
                'accepted-branch', ?, ?, ?, 'bound-execution', 0, ?, ?
            )""",
            ("e" * 64, "9" * 40, "a" * 40, "f" * 40, now, now),
        )
        connection.execute(
            """INSERT INTO slice_control_event(
                operation_key, slice_id, from_state_version, to_state_version,
                reason_code, metadata_json, created_at
            ) VALUES (?, 'phase1-slice', -1, 0, 'V3_DEFER_FIXTURE', '{}', ?)""",
            ("1" * 64, now),
        )
        connection.execute(
            """INSERT INTO slice_control_state(
                slice_id, stage, status, authority_fingerprint, migration_class,
                execution_eligibility, defer_reason, logical_source_root,
                repository_toplevel, branch, state_version, created_at, updated_at
            ) VALUES (
                'phase1-slice', 'S4', 'WAITING', ?, 'DEFER_BINDING',
                'INELIGIBLE_UNTIL_PREFLIGHT', 'deferred', '/logical/phase1',
                NULL, 'phase1-branch', 0, ?, ?
            )""",
            ("2" * 64, now, now),
        )
        connection.execute("COMMIT")

    def promote_fixture_to_v4(self, connection: sqlite3.Connection) -> None:
        self.promote_fixture_to_v3(connection)
        connection.executescript(MIGRATION_4_SQL)
        connection.execute(
            "INSERT INTO schema_migration VALUES (4, ?, ?, 'v4-applied')",
            (MIGRATION_4_NAME, MIGRATION_4_CHECKSUM),
        )
        now = "2026-08-17T00:00:00.000000+00:00"
        execution_id = "v4-prebound-execution"
        slice_id = "v4-prebound-slice"
        source_root = "/isolated/v4-prebound-repository"
        worktree_path = "/isolated/v4-prebound-worktree"
        branch = "v4-prebound-branch"
        base_commit = "1" * 40
        contract_fingerprint = "2" * 64
        authority_fingerprint = "3" * 64
        context_id = "v4-prebound-maker-context"
        context_envelope = {
            "capsule_version": 1,
            "role": "MAKER",
            "content": {
                "slice": {"slice_id": slice_id},
                "contract_fingerprint": contract_fingerprint,
                "authority_fingerprint": authority_fingerprint,
                "source_root": worktree_path,
                "branch": branch,
                "base_commit": base_commit,
                "current_commit": base_commit,
                "risk": "NORMAL",
                "environment": "TEST",
            },
        }
        context_fingerprint = canonical_sha256(context_envelope)
        binding = {
            "execution_id": execution_id,
            "slice_id": slice_id,
            "repository_toplevel": source_root,
            "worktree_path": worktree_path,
            "branch": branch,
            "base_commit": base_commit,
            "contract_fingerprint": contract_fingerprint,
            "authority_fingerprint": authority_fingerprint,
            "risk_level": "NORMAL",
            "environment": "TEST",
            "packet_ref": "v4-fixture",
            "context_snapshot_id": context_id,
            "context_fingerprint": context_fingerprint,
            "branch_created": True,
            "worktree_created": True,
        }
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT INTO slice_execution(
                execution_id, create_idempotency_key, slice_id, risk_level, environment,
                state, state_version, contract_fingerprint, authority_fingerprint,
                source_root, branch, base_commit, max_auto_reworks, current_actor_role,
                created_at, updated_at
            ) VALUES (?, ?, ?, 'NORMAL', 'TEST', 'READY', 0, ?, ?, ?, ?, ?, 2,
                      'CONTROLLER', ?, ?)""",
            (
                execution_id, "4" * 64, slice_id, contract_fingerprint,
                authority_fingerprint, source_root, branch, base_commit, now, now,
            ),
        )
        connection.execute(
            """INSERT INTO transition_event(
                event_id, execution_id, operation_key, event_type, from_state, to_state,
                from_state_version, to_state_version, actor_role, actor_id,
                lease_generation, reason_code, metadata_json, created_at
            ) VALUES ('v4-prebound-created', ?, ?, 'EXECUTION_CREATED', NULL, 'READY',
                      -1, 0, 'CONTROLLER', 'fixture', 0, 'EXECUTION_CREATED', '{}', ?)""",
            (execution_id, "4" * 64, now),
        )
        connection.execute(
            """INSERT INTO context_snapshot(
                context_snapshot_id, execution_id, role, capsule_version,
                fingerprint, canonical_json, created_at
            ) VALUES (?, ?, 'MAKER', 1, ?, ?, ?)""",
            (
                context_id, execution_id, context_fingerprint,
                canonical_json(context_envelope), now,
            ),
        )
        connection.execute(
            """INSERT INTO slice_control_event(
                operation_key, slice_id, from_state_version, to_state_version,
                reason_code, metadata_json, created_at
            ) VALUES (?, ?, -1, 0, 'PREEXECUTION_BIND', ?, ?)""",
            (
                "5" * 64, slice_id,
                canonical_json({
                    "reason_code": "PREEXECUTION_BIND", "target": {}, "metadata": binding
                }),
                now,
            ),
        )
        connection.execute(
            """INSERT INTO slice_control_state(
                slice_id, stage, status, authority_fingerprint, migration_class,
                execution_eligibility, defer_reason, logical_source_root,
                repository_toplevel, branch, base_commit, implementation_result_commit,
                current_branch_head, active_execution_id, state_version, created_at, updated_at
            ) VALUES (?, 'S4', 'WAITING', ?, 'DEFER_BINDING',
                      'ELIGIBLE_PREEXECUTION_BOUND', NULL, '/logical/v4-prebound',
                      ?, ?, ?, NULL, ?, ?, 0, ?, ?)""",
            (
                slice_id, "6" * 64, source_root, branch, base_commit, base_commit,
                execution_id, now, now,
            ),
        )
        connection.execute("COMMIT")

    def promote_fixture_to_v5(self, connection: sqlite3.Connection) -> None:
        self.promote_fixture_to_v4(connection)
        connection.executescript(MIGRATION_5_SQL)
        connection.execute(
            "INSERT INTO schema_migration VALUES (5, ?, ?, 'v5-applied')",
            (MIGRATION_5_NAME, MIGRATION_5_CHECKSUM),
        )

    def promote_fixture_to_v6(self, connection: sqlite3.Connection) -> None:
        self.promote_fixture_to_v5(connection)
        connection.executescript(MIGRATION_6_SQL)
        connection.execute(
            "INSERT INTO schema_migration VALUES (6, ?, ?, 'v6-applied')",
            (MIGRATION_6_NAME, MIGRATION_6_CHECKSUM),
        )

    def test_empty_database_initializes_directly_to_v7(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            result = migrate(connection, backup_root=Path(temporary) / "backups")
            self.assertTrue(result.applied)
            self.assertEqual((0, 7), (result.previous_version, result.version))
            objects = list(
                connection.execute(
                    "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                )
            )
            by_type = {
                kind: {name for row_kind, name in objects if row_kind == kind}
                for kind in ("table", "index", "trigger")
            }
            self.assertEqual(EXPECTED_TABLES, by_type["table"])
            self.assertTrue(EXPECTED_INDEXES.issubset(by_type["index"]))
            self.assertEqual(EXPECTED_TRIGGERS, by_type["trigger"])
            rows = list(connection.execute("SELECT * FROM schema_migration ORDER BY version"))
            self.assertEqual(
                [
                    (1, MIGRATION_NAME, MIGRATION_1_CHECKSUM),
                    (2, MIGRATION_2_NAME, MIGRATION_2_CHECKSUM),
                    (3, MIGRATION_3_NAME, MIGRATION_3_CHECKSUM),
                    (4, MIGRATION_4_NAME, MIGRATION_4_CHECKSUM),
                    (5, MIGRATION_5_NAME, MIGRATION_5_CHECKSUM),
                    (6, MIGRATION_6_NAME, MIGRATION_6_CHECKSUM),
                    (7, MIGRATION_7_NAME, MIGRATION_7_CHECKSUM),
                ],
                [tuple(row[:3]) for row in rows],
            )
            authority = connection.execute("SELECT * FROM control_authority_state").fetchone()
            self.assertEqual(("GLOBAL", "TRANSITIONAL_AUTHORITY", 0), tuple(authority[:3]))
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            connection.close()

    def test_recognized_version_zero_store_migrates_and_backs_up(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            connection.execute(SCHEMA_MIGRATION_SQL)
            result = migrate(
                connection,
                backup_root=root / "backups",
                now=datetime(2026, 8, 11, tzinfo=timezone.utc),
            )
            self.assertTrue(result.applied)
            self.assertIsNotNone(result.backup_path)
            self.assertRegex(
                result.backup_path.name,
                rf"^control\.sqlite3\.v0\.20260811T000000000000Z\.{MIGRATION_CHECKSUM[:12]}\.bak$",
            )
            backup = sqlite3.connect(result.backup_path)
            self.assertEqual("ok", backup.execute("PRAGMA integrity_check").fetchone()[0])
            backup.close()
            connection.close()

    def test_successful_migration_retains_newest_five_backups(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            backups = root / "backups"
            backups.mkdir()
            for index in range(7):
                (backups / f"control.sqlite3.v0.20260101T00000000000{index}Z.{'0' * 12}.bak").write_bytes(b"old")
            connection = self.configured_connection(root / "control.sqlite3")
            connection.execute(SCHEMA_MIGRATION_SQL)
            result = migrate(
                connection,
                backup_root=backups,
                now=datetime(2026, 8, 11, tzinfo=timezone.utc),
            )
            retained = sorted(backups.glob("*.bak"), reverse=True)
            self.assertEqual(5, len(retained))
            self.assertIn(result.backup_path, retained)
            connection.close()

    def test_failed_migration_leaves_recognized_version_zero_store(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "control.sqlite3"
            connection = self.configured_connection(path)
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_sql=MIGRATION_1_SQL + "\nNOT VALID SQL;")
            objects = list(
                connection.execute(
                    "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                )
            )
            self.assertEqual([("table", "schema_migration")], [tuple(row) for row in objects])
            self.assertEqual(0, connection.execute("SELECT count(*) FROM schema_migration").fetchone()[0])
            connection.close()

    def test_version_zero_store_retries_migration_deterministically(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "control.sqlite3"
            connection = self.configured_connection(path)
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_sql=MIGRATION_1_SQL + "\nBROKEN;")
            result = migrate(connection)
            self.assertTrue(result.applied)
            self.assertEqual(MIGRATION_CHECKSUM, connection.execute("SELECT checksum FROM schema_migration").fetchone()[0])
            connection.close()

    def test_version_seven_replay_is_noop(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            first = migrate(connection)
            applied_at = connection.execute("SELECT applied_at FROM schema_migration").fetchone()[0]
            second = migrate(connection)
            self.assertTrue(first.applied)
            self.assertFalse(second.applied)
            self.assertEqual(applied_at, connection.execute("SELECT applied_at FROM schema_migration").fetchone()[0])
            connection.close()

    def test_v4_to_v7_preserves_v5_v6_and_adds_seal_schema(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v4(connection)
            data_before = {
                table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                for table in (
                    "slice_execution", "transition_event", "context_snapshot",
                    "slice_control_state", "slice_control_event",
                )
            }
            objects_before = {
                kind: {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type=? AND name NOT LIKE 'sqlite_%'",
                    (kind,),
                )}
                for kind in ("table", "index", "trigger")
            }
            trigger_before = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='slice_control_state_rebinding_forbidden'"
            ).fetchone()[0]

            result = migrate(
                connection, backup_root=root / "backups",
                now=datetime(2026, 8, 17, tzinfo=timezone.utc),
            )

            self.assertEqual((4, 7, True), (
                result.previous_version, result.version, result.applied
            ))
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], [row[0] for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )])
            for table, rows in data_before.items():
                self.assertEqual(rows, [tuple(row) for row in connection.execute(
                    f"SELECT * FROM {table}"
                )])
            objects_after = {
                kind: {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type=? AND name NOT LIKE 'sqlite_%'",
                    (kind,),
                )}
                for kind in ("table", "index", "trigger")
            }
            self.assertTrue(objects_before["table"].issubset(objects_after["table"]))
            self.assertTrue(objects_before["index"].issubset(objects_after["index"]))
            self.assertIn("global_production_writer_lease", objects_after["table"])
            self.assertIn("global_production_writer_event", objects_after["table"])
            self.assertIn("global_production_writer_event_immutable_update", objects_after["trigger"])
            trigger_after = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='slice_control_state_rebinding_forbidden'"
            ).fetchone()[0]
            self.assertNotEqual(trigger_before, trigger_after)
            self.assertIn("PREEXECUTION_RELEASE", trigger_after)
            writer = connection.execute(
                "SELECT resource_key, state, fencing_token FROM global_production_writer_lease"
            ).fetchone()
            self.assertEqual(("GLOBAL_PRODUCTION", "FREE", 0), tuple(writer))
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            self.assertIsNotNone(result.backup_path)
            connection.close()

    def test_v5_to_v7_preserves_existing_state_and_seeds_global_writer(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v5(connection)
            preserved_tables = (
                "slice_execution",
                "transition_event",
                "context_snapshot",
                "slice_control_state",
                "slice_control_event",
                "control_authority_state",
            )
            before = {
                table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                for table in preserved_tables
            }

            result = migrate(
                connection,
                backup_root=root / "backups",
                now=datetime(2026, 8, 29, tzinfo=timezone.utc),
            )

            self.assertEqual((5, 7, True), (
                result.previous_version, result.version, result.applied
            ))
            for table, rows in before.items():
                self.assertEqual(
                    rows, [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")],
                    table,
                )
            writer = connection.execute(
                "SELECT * FROM global_production_writer_lease"
            ).fetchone()
            self.assertEqual(("GLOBAL_PRODUCTION", "FREE", 0), (
                writer["resource_key"], writer["state"], writer["fencing_token"]
            ))
            self.assertEqual(0, connection.execute(
                "SELECT count(*) FROM global_production_writer_event"
            ).fetchone()[0])
            writer_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='global_production_writer_lease'"
            ).fetchone()[0]
            self.assertIn("julianday(acquired_at) IS NOT NULL", writer_sql)
            self.assertIn("julianday(heartbeat_at) = julianday(updated_at)", writer_sql)
            self.assertIn("julianday(updated_at) < julianday(expires_at)", writer_sql)
            self.assertIn("substr(updated_at, -6) = '+00:00'", writer_sql)
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], [row[0] for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )])
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            self.assertIsNotNone(result.backup_path)
            backup = sqlite3.connect(result.backup_path)
            try:
                self.assertEqual(5, backup.execute(
                    "SELECT max(version) FROM schema_migration"
                ).fetchone()[0])
                for table, rows in before.items():
                    self.assertEqual(
                        rows, [tuple(row) for row in backup.execute(f"SELECT * FROM {table}")],
                        table,
                    )
            finally:
                backup.close()
            second = migrate(connection)
            self.assertFalse(second.applied)
            self.assertEqual(7, second.version)
            connection.close()

    def test_failed_v6_migration_rolls_back_to_exact_v5_state(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v5(connection)
            preserved_tables = (
                "slice_execution", "transition_event", "context_snapshot",
                "slice_control_state", "slice_control_event", "control_authority_state",
            )
            before = {
                table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                for table in preserved_tables
            }
            objects_before = {
                (row[0], row[1]) for row in connection.execute(
                    "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                )
            }

            with self.assertRaises(sqlite3.OperationalError):
                migrate(
                    connection,
                    backup_root=root / "backups",
                    migration_6_sql=MIGRATION_6_SQL + "\nBROKEN;",
                )

            self.assertEqual([1, 2, 3, 4, 5], [row[0] for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )])
            for table, rows in before.items():
                self.assertEqual(
                    rows, [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")],
                    table,
                )
            objects_after = {
                (row[0], row[1]) for row in connection.execute(
                    "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(objects_before, objects_after)
            self.assertNotIn("global_production_writer_lease", {name for _, name in objects_after})
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            connection.close()

    def test_v6_to_v7_adds_immutable_evaluator_artifact_seal_without_history_rewrite(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v6(connection)
            history_before = [tuple(row) for row in connection.execute(
                "SELECT version,name,checksum,applied_at FROM schema_migration ORDER BY version"
            )]
            result = migrate(connection, backup_root=root / "backups")
            self.assertEqual((6, 7, True), (result.previous_version, result.version, result.applied))
            history_after = [tuple(row) for row in connection.execute(
                "SELECT version,name,checksum,applied_at FROM schema_migration ORDER BY version"
            )]
            self.assertEqual(history_before, history_after[:6])
            self.assertEqual((7, MIGRATION_7_NAME, MIGRATION_7_CHECKSUM), history_after[6][:3])
            self.assertIsNotNone(connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='evaluator_artifact_seal'"
            ).fetchone())
            for trigger in (
                "evaluator_artifact_seal_immutable_update",
                "evaluator_artifact_seal_immutable_delete",
                "evaluation_result_require_artifact_seal_insert",
            ):
                self.assertIsNotNone(connection.execute(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?", (trigger,)
                ).fetchone())
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            connection.close()

    def test_checksum_mismatch_and_version_ahead_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "a.sqlite3")
            migrate(connection)
            connection.execute("UPDATE schema_migration SET checksum = ?", ("0" * 64,))
            with self.assertRaisesRegex(StoreError, "MIGRATION_CHECKSUM_MISMATCH"):
                migrate(connection)
            connection.close()

            ahead = self.configured_connection(Path(temporary) / "b.sqlite3")
            ahead.execute(SCHEMA_MIGRATION_SQL)
            ahead.execute(
                "INSERT INTO schema_migration VALUES (11, 'future', ?, 'now')", ("f" * 64,)
            )
            with self.assertRaisesRegex(StoreError, "MIGRATION_VERSION_AHEAD"):
                migrate(ahead)
            ahead.close()

    def test_unrecognized_database_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            connection.execute("CREATE TABLE foreign_application(id INTEGER)")
            with self.assertRaisesRegex(StoreError, "UNRECOGNIZED_DATABASE"):
                migrate(connection)
            connection.close()

    def test_connection_policy(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            self.assertIsNone(connection.isolation_level)
            self.assertIs(connection.row_factory, sqlite3.Row)
            self.assertEqual(1, connection.execute("PRAGMA foreign_keys").fetchone()[0])
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(5000, connection.execute("PRAGMA busy_timeout").fetchone()[0])
            self.assertEqual(1, connection.execute("PRAGMA synchronous").fetchone()[0])
            connection.close()

    def test_canonical_checksum_normalizes_line_endings(self) -> None:
        self.assertEqual(migration_checksum(" A;\r\n"), migration_checksum("A;\n"))

    def test_frozen_v1_v2_v3_and_v4_checksums_are_deterministic(self) -> None:
        self.assertEqual(
            "8f5d1e0d2c9fe9f457aa26bf16a0963131a64a2a6a71d7fdf71490f74acd516c",
            MIGRATION_1_CHECKSUM,
        )
        self.assertEqual(
            "29b79d1d91841015955dd1cc2678a51765a79fced08aa741c4bd99cc658fac5f",
            MIGRATION_2_CHECKSUM,
        )
        self.assertEqual(
            "8a3714a074d314e09e9fbe03d714b2d4a43497ef1653436dcb79bd55668cde46",
            MIGRATION_3_CHECKSUM,
        )
        self.assertEqual(
            "2d95ec8f895fa26b4db70d6b961893f527916ec80e68df8c08c0c7c2749eceb5",
            MIGRATION_4_CHECKSUM,
        )
        self.assertEqual(migration_checksum(MIGRATION_5_SQL), MIGRATION_5_CHECKSUM)
        self.assertEqual(migration_checksum(MIGRATION_6_SQL), MIGRATION_6_CHECKSUM)
        self.assertEqual(migration_checksum(MIGRATION_7_SQL), MIGRATION_7_CHECKSUM)

    def test_registry_preserves_history_and_appends_v8_v9_v10(self) -> None:
        self.assertEqual(10, len(MIGRATIONS))
        self.assertEqual(
            (1, MIGRATION_NAME, MIGRATION_1_CHECKSUM),
            (MIGRATIONS[0].version, MIGRATIONS[0].name, MIGRATIONS[0].checksum),
        )
        self.assertEqual(
            (2, MIGRATION_2_NAME, MIGRATION_2_CHECKSUM),
            (MIGRATIONS[1].version, MIGRATIONS[1].name, MIGRATIONS[1].checksum),
        )
        self.assertEqual(
            (3, MIGRATION_3_NAME, MIGRATION_3_CHECKSUM),
            (MIGRATIONS[2].version, MIGRATIONS[2].name, MIGRATIONS[2].checksum),
        )
        self.assertEqual(
            (4, MIGRATION_4_NAME, MIGRATION_4_CHECKSUM),
            (MIGRATIONS[3].version, MIGRATIONS[3].name, MIGRATIONS[3].checksum),
        )
        self.assertEqual(
            (5, MIGRATION_5_NAME, MIGRATION_5_CHECKSUM),
            (MIGRATIONS[4].version, MIGRATIONS[4].name, MIGRATIONS[4].checksum),
        )
        self.assertEqual(
            (6, MIGRATION_6_NAME, MIGRATION_6_CHECKSUM),
            (MIGRATIONS[5].version, MIGRATIONS[5].name, MIGRATIONS[5].checksum),
        )
        self.assertEqual(
            (7, MIGRATION_7_NAME, MIGRATION_7_CHECKSUM),
            (MIGRATIONS[6].version, MIGRATIONS[6].name, MIGRATIONS[6].checksum),
        )
        self.assertEqual(
            (8, MIGRATION_8_NAME, MIGRATION_8_CHECKSUM),
            (MIGRATIONS[7].version, MIGRATIONS[7].name, MIGRATIONS[7].checksum),
        )
        self.assertEqual(
            (9, MIGRATION_9_NAME, MIGRATION_9_CHECKSUM),
            (MIGRATIONS[8].version, MIGRATIONS[8].name, MIGRATIONS[8].checksum),
        )
        self.assertEqual(
            (10, MIGRATION_10_NAME, MIGRATION_10_CHECKSUM),
            (MIGRATIONS[9].version, MIGRATIONS[9].name, MIGRATIONS[9].checksum),
        )
        self.assertEqual(migration_checksum(MIGRATION_8_SQL), MIGRATION_8_CHECKSUM)
        self.assertEqual(migration_checksum(MIGRATION_9_SQL), MIGRATION_9_CHECKSUM)
        self.assertEqual(migration_checksum(MIGRATION_10_SQL), MIGRATION_10_CHECKSUM)
        self.assertEqual(
            "dcdfd8a9c0e06e8f0c11490c8fd4e080fa6aab6c22e1b9126f98eeb07675faa3",
            MIGRATION_8_CHECKSUM,
        )
        self.assertEqual(
            "e24ca5e65af98e3a2e8130670509dd61acdceeafe3ada6ef3d5a911c52cb0872",
            MIGRATION_9_CHECKSUM,
        )

    def test_v9_to_v10_rebuild_preserves_receipts_and_exact_ledger_contract(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            migrate(connection, target_version=9)
            self.assertEqual(
                "sha256:0f0bf3c32f0cf4af5b047bc6afdf2a61940df2a1e2a8395463f9183e678e3b6b",
                schema_profile_identity(connection, 9),
            )
            history_before = [
                tuple(row) for row in connection.execute(
                    "SELECT version,name,checksum FROM schema_migration ORDER BY version"
                )
            ]
            object_names = (
                "typed_postgres_operation_receipt_event",
                "idx_typed_postgres_receipt_operation",
                "typed_postgres_operation_receipt_event_immutable_update",
                "typed_postgres_operation_receipt_event_immutable_delete",
                "typed_postgres_operation_receipt_event_final_requires_prepared",
            )
            placeholders = ",".join("?" for _ in object_names)
            objects_before = {
                (row[0], row[1]): row[2]
                for row in connection.execute(
                    f"SELECT type,name,sql FROM sqlite_schema WHERE name IN ({placeholders}) ORDER BY type,name",
                    object_names,
                )
            }
            old_types = (
                "EXECUTE_AUTHORIZED_SQL_FILE",
                "TRANSITION_DATABASE_OWNER",
                "APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",
            )
            for index, operation_type in enumerate(old_types, start=1):
                operation_id = f"old-operation-{index}"
                self.insert_typed_receipt(
                    connection, operation_id=operation_id, operation_type=operation_type,
                    fencing_token=100 + index,
                )
                self.insert_typed_receipt(
                    connection, operation_id=operation_id, operation_type=operation_type,
                    phase="FINAL", fencing_token=100 + index,
                )
            rows_before = [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM typed_postgres_operation_receipt_event ORDER BY event_seq"
                )
            ]
            max_old_event_seq = rows_before[-1][0]

            result = migrate(connection, target_version=10)
            self.assertEqual((9, 10, True), (result.previous_version, result.version, result.applied))
            self.assertEqual(
                rows_before,
                [tuple(row) for row in connection.execute(
                    "SELECT * FROM typed_postgres_operation_receipt_event ORDER BY event_seq"
                )],
            )
            history_after = [
                tuple(row) for row in connection.execute(
                    "SELECT version,name,checksum FROM schema_migration ORDER BY version"
                )
            ]
            self.assertEqual(history_before, history_after[:9])
            self.assertEqual(list(range(1, 11)), [row[0] for row in history_after])
            self.assertEqual((10, MIGRATION_10_NAME, MIGRATION_10_CHECKSUM), history_after[9])

            objects_after = {
                (row[0], row[1]): row[2]
                for row in connection.execute(
                    f"SELECT type,name,sql FROM sqlite_schema WHERE name IN ({placeholders}) ORDER BY type,name",
                    object_names,
                )
            }
            self.assertNotEqual(
                objects_before[("table", "typed_postgres_operation_receipt_event")],
                objects_after[("table", "typed_postgres_operation_receipt_event")],
            )
            self.assertIn(
                "PROVISION_CLEANER_APP_PRINCIPAL",
                objects_after[("table", "typed_postgres_operation_receipt_event")],
            )
            for key in objects_before:
                if key[0] != "table":
                    self.assertEqual(objects_before[key], objects_after[key], key)

            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "TYPED_POSTGRES_FINAL_PREPARED_BINDING_REQUIRED"
            ):
                self.insert_typed_receipt(
                    connection, operation_id="new-operation",
                    operation_type="PROVISION_CLEANER_APP_PRINCIPAL", phase="FINAL",
                )
            self.insert_typed_receipt(
                connection, operation_id="new-operation",
                operation_type="PROVISION_CLEANER_APP_PRINCIPAL",
            )
            new_seq = connection.execute(
                "SELECT event_seq FROM typed_postgres_operation_receipt_event WHERE operation_id='new-operation'"
            ).fetchone()[0]
            self.assertGreater(new_seq, max_old_event_seq)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "TYPED_POSTGRES_FINAL_PREPARED_BINDING_REQUIRED"
            ):
                self.insert_typed_receipt(
                    connection, operation_id="new-operation",
                    operation_type="PROVISION_CLEANER_APP_PRINCIPAL", phase="FINAL",
                    principal_identity="wrong-principal",
                )
            self.insert_typed_receipt(
                connection, operation_id="new-operation",
                operation_type="PROVISION_CLEANER_APP_PRINCIPAL", phase="FINAL",
            )
            with self.assertRaises(sqlite3.IntegrityError):
                self.insert_typed_receipt(
                    connection, operation_id="unknown-operation", operation_type="UNKNOWN_OPERATION",
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT"
            ):
                connection.execute(
                    "UPDATE typed_postgres_operation_receipt_event SET change_id='changed' WHERE operation_id='new-operation'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT"
            ):
                connection.execute(
                    "DELETE FROM typed_postgres_operation_receipt_event WHERE operation_id='new-operation'"
                )

            validate_schema(connection, target_version=10)
            self.assertEqual(["ok"], [row[0] for row in connection.execute("PRAGMA integrity_check")])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            self.assertEqual(
                "sha256:1bfa57994e2ea90b11146d32839ca6a8875ad94bb0eea9128fb3b8fb3c5ce7e9",
                schema_profile_identity(connection, 10),
            )
            replay = migrate(connection, target_version=10)
            self.assertEqual((10, 10, False), (replay.previous_version, replay.version, replay.applied))
            connection.close()

    def test_failed_v10_rebuild_rolls_back_to_exact_v9_schema_and_rows(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            migrate(connection, target_version=9)
            self.insert_typed_receipt(
                connection, operation_id="rollback-old", operation_type="EXECUTE_AUTHORIZED_SQL_FILE"
            )
            before_history = [
                tuple(row) for row in connection.execute(
                    "SELECT version,name,checksum,applied_at FROM schema_migration ORDER BY version"
                )
            ]
            before_rows = [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM typed_postgres_operation_receipt_event ORDER BY event_seq"
                )
            ]
            before_objects = [
                tuple(row) for row in connection.execute(
                    "SELECT type,name,sql FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
                )
            ]
            with self.assertRaises(sqlite3.DatabaseError):
                migrate(
                    connection, target_version=10,
                    migration_10_sql=MIGRATION_10_SQL + "\nBROKEN;",
                )
            self.assertEqual(
                before_history,
                [tuple(row) for row in connection.execute(
                    "SELECT version,name,checksum,applied_at FROM schema_migration ORDER BY version"
                )],
            )
            self.assertEqual(
                before_rows,
                [tuple(row) for row in connection.execute(
                    "SELECT * FROM typed_postgres_operation_receipt_event ORDER BY event_seq"
                )],
            )
            self.assertEqual(
                before_objects,
                [tuple(row) for row in connection.execute(
                    "SELECT type,name,sql FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
                )],
            )
            self.assertEqual(9, connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0])
            self.assertEqual(
                "sha256:0f0bf3c32f0cf4af5b047bc6afdf2a61940df2a1e2a8395463f9183e678e3b6b",
                schema_profile_identity(connection, 9),
            )
            connection.close()

    def test_representative_v1_data_and_history_are_preserved_by_v7(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            connection.execute(SCHEMA_MIGRATION_SQL)
            connection.executescript(MIGRATION_1_SQL)
            connection.execute(
                "INSERT INTO schema_migration VALUES (1, ?, ?, '2026-08-11T00:00:00+00:00')",
                (MIGRATION_NAME, MIGRATION_1_CHECKSUM),
            )
            now = "2026-08-11T01:02:03.456789+00:00"
            connection.execute(
                """INSERT INTO slice_execution(
                    execution_id, create_idempotency_key, slice_id, risk_level, environment,
                    state, state_version, contract_fingerprint, authority_fingerprint,
                    source_root, branch, base_commit, max_auto_reworks, current_actor_role,
                    created_at, updated_at
                ) VALUES ('v1-execution', ?, 'v1-slice', 'NORMAL', 'TEST', 'READY', 0,
                          ?, ?, '/tmp/v1-repo', 'v1-branch', ?, 2, 'CONTROLLER', ?, ?)""",
                ("1" * 64, "2" * 64, "3" * 64, "4" * 40, now, now),
            )
            connection.execute(
                """INSERT INTO transition_event(
                    event_id, execution_id, operation_key, event_type, from_state, to_state,
                    from_state_version, to_state_version, actor_role, actor_id,
                    lease_generation, reason_code, metadata_json, created_at
                ) VALUES ('v1-event', 'v1-execution', ?, 'EXECUTION_CREATED', NULL, 'READY',
                          -1, 0, 'CONTROLLER', 'fixture', 0, 'EXECUTION_CREATED', '{}', ?)""",
                ("5" * 64, now),
            )
            execution_before = tuple(
                connection.execute("SELECT * FROM slice_execution").fetchone()
            )
            event_before = tuple(connection.execute("SELECT * FROM transition_event").fetchone())

            result = migrate(
                connection,
                backup_root=root / "backups",
                now=datetime(2026, 8, 13, tzinfo=timezone.utc),
            )

            self.assertEqual((1, 7, True), (result.previous_version, result.version, result.applied))
            self.assertEqual(execution_before, tuple(connection.execute("SELECT * FROM slice_execution").fetchone()))
            self.assertEqual(event_before, tuple(connection.execute("SELECT * FROM transition_event").fetchone()))
            self.assertEqual(1, connection.execute("SELECT count(*) FROM slice_execution").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT count(*) FROM transition_event").fetchone()[0])
            self.assertEqual(7, connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0])
            self.assertIsNotNone(result.backup_path)
            connection.close()

    def test_v2_five_slice_and_authority_state_are_preserved_by_v7(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            history_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM schema_migration ORDER BY version"
                )
            ]
            slices_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ]
            events_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_event ORDER BY event_seq"
                )
            ]
            authority_before = tuple(
                connection.execute("SELECT * FROM control_authority_state").fetchone()
            )
            trigger_before = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
                )
            }
            self.assertIn("control_authority_state_e1_switch_forbidden", trigger_before)

            result = migrate(
                connection,
                backup_root=root / "backups",
                now=datetime(2026, 8, 13, tzinfo=timezone.utc),
            )

            self.assertEqual((2, 7, True), (result.previous_version, result.version, result.applied))
            self.assertEqual(
                history_before,
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM schema_migration WHERE version <= 2 ORDER BY version"
                    )
                ],
            )
            self.assertEqual(
                slices_before,
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM slice_control_state ORDER BY slice_id"
                    )
                ],
            )
            self.assertEqual(
                events_before,
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM slice_control_event ORDER BY event_seq"
                    )
                ],
            )
            self.assertEqual(
                authority_before,
                tuple(connection.execute("SELECT * FROM control_authority_state").fetchone()),
            )
            triggers_after = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
                )
            }
            self.assertNotIn("control_authority_state_e1_switch_forbidden", triggers_after)
            self.assertTrue(
                {
                    "authority_transition_event_state_guard",
                    "authority_transition_event_apply",
                    "control_authority_state_transition_guard",
                }.issubset(triggers_after)
            )
            self.assertEqual(5, connection.execute("SELECT count(*) FROM slice_control_state").fetchone()[0])
            connection.close()

    def test_failed_v3_migration_leaves_v2_data_unchanged(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            slices_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ]
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_3_sql=MIGRATION_3_SQL + "\nBROKEN;")
            self.assertEqual(
                [1, 2],
                [row[0] for row in connection.execute("SELECT version FROM schema_migration")],
            )
            self.assertEqual(
                slices_before,
                [
                    tuple(row)
                    for row in connection.execute(
                        "SELECT * FROM slice_control_state ORDER BY slice_id"
                    )
                ],
            )
            self.assertIn(
                "control_authority_state_e1_switch_forbidden",
                {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'trigger'"
                    )
                },
            )
            connection.close()

    def test_v3_to_v7_rehearsal_preserves_rows_events_and_restore_backup(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            connection = self.configured_connection(root / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v3(connection)
            slices_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ]
            events_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_event ORDER BY event_seq"
                )
            ]
            executions_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_execution ORDER BY execution_id"
                )
            ]

            result = migrate(
                connection,
                backup_root=root / "backups",
                now=datetime(2026, 8, 15, tzinfo=timezone.utc),
            )

            self.assertEqual((3, 7, True), (
                result.previous_version, result.version, result.applied
            ))
            self.assertEqual(slices_before, [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ])
            self.assertEqual(events_before, [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM slice_control_event ORDER BY event_seq"
                )
            ])
            self.assertEqual(executions_before, [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM slice_execution ORDER BY execution_id"
                )
            ])
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            self.assertIsNotNone(result.backup_path)
            backup = sqlite3.connect(result.backup_path)
            try:
                self.assertEqual(3, backup.execute(
                    "SELECT max(version) FROM schema_migration"
                ).fetchone()[0])
                self.assertEqual(slices_before, [
                    tuple(row) for row in backup.execute(
                        "SELECT * FROM slice_control_state ORDER BY slice_id"
                    )
                ])
                self.assertEqual(events_before, [
                    tuple(row) for row in backup.execute(
                        "SELECT * FROM slice_control_event ORDER BY event_seq"
                    )
                ])
                self.assertEqual("ok", backup.execute("PRAGMA integrity_check").fetchone()[0])
                self.assertEqual([], list(backup.execute("PRAGMA foreign_key_check")))
            finally:
                backup.close()
            connection.close()

    def test_failed_v4_rebuild_rolls_back_to_exact_v3_state(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v3(connection)
            slices_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ]
            events_before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM slice_control_event ORDER BY event_seq"
                )
            ]
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_4_sql=MIGRATION_4_SQL + "\nBROKEN;")
            self.assertEqual([1, 2, 3], [
                row[0] for row in connection.execute(
                    "SELECT version FROM schema_migration ORDER BY version"
                )
            ])
            self.assertEqual(slices_before, [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM slice_control_state ORDER BY slice_id"
                )
            ])
            self.assertEqual(events_before, [
                tuple(row) for row in connection.execute(
                    "SELECT * FROM slice_control_event ORDER BY event_seq"
                )
            ])
            self.assertNotIn(
                "ELIGIBLE_PREEXECUTION_BOUND",
                connection.execute(
                    "SELECT sql FROM sqlite_schema WHERE name='slice_control_state'"
                ).fetchone()[0],
            )
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            connection.close()

    def test_failed_v5_trigger_revision_rolls_back_to_exact_v4_state(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            self.create_v2_five_slice_store(connection)
            self.promote_fixture_to_v4(connection)
            rows_before = {
                table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                for table in (
                    "slice_execution", "transition_event", "slice_control_state",
                    "slice_control_event",
                )
            }
            trigger_before = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='slice_control_state_rebinding_forbidden'"
            ).fetchone()[0]
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_5_sql=MIGRATION_5_SQL + "\nBROKEN;")
            self.assertEqual([1, 2, 3, 4], [row[0] for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )])
            for table, rows in rows_before.items():
                self.assertEqual(rows, [tuple(row) for row in connection.execute(
                    f"SELECT * FROM {table}"
                )])
            self.assertEqual(trigger_before, connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='slice_control_state_rebinding_forbidden'"
            ).fetchone()[0])
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            connection.close()

    def test_failed_v2_migration_leaves_v1_data_unchanged(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self.configured_connection(Path(temporary) / "control.sqlite3")
            connection.execute(SCHEMA_MIGRATION_SQL)
            connection.executescript(MIGRATION_1_SQL)
            connection.execute(
                "INSERT INTO schema_migration VALUES (1, ?, ?, 'now')",
                (MIGRATION_NAME, MIGRATION_1_CHECKSUM),
            )
            with self.assertRaises(sqlite3.OperationalError):
                migrate(connection, migration_2_sql=MIGRATION_2_SQL + "\nBROKEN;")
            self.assertEqual([1], [row[0] for row in connection.execute("SELECT version FROM schema_migration")])
            self.assertNotIn(
                "slice_control_state",
                {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")},
            )
            connection.close()


if __name__ == "__main__":
    unittest.main()
