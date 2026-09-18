from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from adcp.dcs_v7_v8_adoption import (
    V7_SCHEMA_PROFILE,
    V8_SCHEMA_PROFILE,
    run_v7_to_v8_adoption,
)
from adcp.domain import StoreError
from adcp.store.migrations import (
    MIGRATION_8_CHECKSUM,
    MIGRATION_8_NAME,
    MIGRATION_8_SQL,
    MIGRATIONS,
    Migration,
    expected_schema_object_fingerprints,
    migrate,
    migrate_to_v7,
    pending_migrations,
    schema_profile_identity,
)
from adcp.store.sqlite import connect


class DcsV7ToV8AdoptionTests(unittest.TestCase):
    def _connection(self, root: Path, name: str = "control.sqlite3") -> sqlite3.Connection:
        return connect(root / name)

    def _exact_v7(self, root: Path, name: str = "control.sqlite3") -> sqlite3.Connection:
        connection = self._connection(root, name)
        result = migrate(connection)
        self.assertEqual((0, 7, True), (result.previous_version, result.version, result.applied))
        self.assertEqual(V7_SCHEMA_PROFILE, schema_profile_identity(connection, 7))
        return connection

    def test_target_selector_enforces_exact_ceiling_and_future_proofs_schema9(self) -> None:
        self.assertEqual((7,), tuple(item.version for item in pending_migrations(6, 7)))
        self.assertEqual((8,), tuple(item.version for item in pending_migrations(7, 8)))
        self.assertEqual((7, 8), tuple(item.version for item in pending_migrations(6, 8)))
        future = MIGRATIONS + (Migration(9, "0009_future", "CREATE TABLE future(id INTEGER);", "f" * 64),)
        self.assertEqual((7, 8), tuple(item.version for item in pending_migrations(6, 8, migrations=future)))
        self.assertEqual((), tuple(item.version for item in pending_migrations(8, 8, migrations=future)))

    def test_default_current_authority_stays_v7_and_never_applies_v8(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self._exact_v7(Path(temporary))
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name='typed_postgres_operation_receipt_event'"
            ).fetchone())
            self.assertEqual([1, 2, 3, 4, 5, 6, 7], [row[0] for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )])
            connection.close()

    def test_exact_v7_to_v8_applies_only_8_and_second_run_is_exact_noop(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self._exact_v7(Path(temporary))
            before = [tuple(row) for row in connection.execute(
                "SELECT version,name,checksum FROM schema_migration ORDER BY version"
            )]
            first = run_v7_to_v8_adoption(connection)
            self.assertEqual((7, 8, True, "APPLIED_EXACT"), (
                first.previous_version, first.version, first.applied, first.status
            ))
            self.assertEqual(V8_SCHEMA_PROFILE, first.schema_profile_identity)
            after = [tuple(row) for row in connection.execute(
                "SELECT version,name,checksum FROM schema_migration ORDER BY version"
            )]
            self.assertEqual(before, after[:7])
            self.assertEqual((8, MIGRATION_8_NAME, MIGRATION_8_CHECKSUM), after[7])
            second = run_v7_to_v8_adoption(connection)
            self.assertEqual((8, 8, False, "ALREADY_APPLIED_EXACT"), (
                second.previous_version, second.version, second.applied, second.status
            ))
            self.assertEqual(V8_SCHEMA_PROFILE, schema_profile_identity(connection, 8))
            connection.close()

    def test_frozen_v7_target_rejects_schema8_without_downgrade_or_success(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self._exact_v7(Path(temporary))
            run_v7_to_v8_adoption(connection)
            before = connection.total_changes
            with self.assertRaisesRegex(StoreError, "FAIL_CLOSED_TARGET_VERSION_OVERSHOOT"):
                migrate_to_v7(connection)
            self.assertEqual(8, connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0])
            self.assertEqual(before, connection.total_changes)
            self.assertEqual(V8_SCHEMA_PROFILE, schema_profile_identity(connection, 8))
            connection.close()

    def test_invalid_source_versions_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            v6 = self._connection(root, "v6.sqlite3")
            migrate(v6, target_version=6)
            with self.assertRaisesRegex(StoreError, "V7_TO_V8_ADOPTION_SOURCE_VERSION_INVALID"):
                run_v7_to_v8_adoption(v6)
            v6.close()

            v9 = self._connection(root, "v9.sqlite3")
            v9.execute("CREATE TABLE schema_migration(version INTEGER, name TEXT, checksum TEXT, applied_at TEXT)")
            v9.execute("INSERT INTO schema_migration VALUES(9,'future',?, 'now')", ("f" * 64,))
            with self.assertRaisesRegex(StoreError, "V7_TO_V8_ADOPTION_SOURCE_VERSION_INVALID"):
                run_v7_to_v8_adoption(v9)
            v9.close()

            unknown = self._connection(root, "unknown.sqlite3")
            with self.assertRaisesRegex(StoreError, "V7_TO_V8_ADOPTION_SCHEMA_UNREADABLE"):
                run_v7_to_v8_adoption(unknown)
            unknown.close()

    def test_version8_with_partial_profile_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            connection = self._exact_v7(Path(temporary))
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(8,?,?,?)",
                (MIGRATION_8_NAME, MIGRATION_8_CHECKSUM, "partial"),
            )
            with self.assertRaisesRegex(StoreError, "V7_TO_V8_ADOPTION_PROFILE_MISMATCH"):
                run_v7_to_v8_adoption(connection)
            connection.close()

    def test_migration8_failure_is_atomic_and_reopens_as_exact_v7(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "atomic.sqlite3"
            connection = self._exact_v7(root, path.name)
            with self.assertRaises(sqlite3.OperationalError):
                migrate(
                    connection,
                    target_version=8,
                    migration_8_sql=MIGRATION_8_SQL + "\nBROKEN;",
                )
            self.assertEqual(7, connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0])
            self.assertEqual(V7_SCHEMA_PROFILE, schema_profile_identity(connection, 7))
            connection.close()
            reopened = connect(path)
            self.assertEqual(7, reopened.execute("SELECT max(version) FROM schema_migration").fetchone()[0])
            self.assertEqual(V7_SCHEMA_PROFILE, schema_profile_identity(reopened, 7))
            reopened.close()

    def test_v7_to_v8_is_additive_and_existing_object_fingerprints_are_identical(self) -> None:
        v7 = {(kind, name): digest for kind, name, digest in expected_schema_object_fingerprints(7)}
        v8 = {(kind, name): digest for kind, name, digest in expected_schema_object_fingerprints(8)}
        self.assertEqual(set(), set(v7) - set(v8))
        self.assertEqual(set(), {key for key in set(v7) & set(v8) if v7[key] != v8[key]})
        self.assertEqual(
            {
                ("table", "typed_postgres_operation_receipt_event"),
                ("index", "idx_typed_postgres_receipt_operation"),
                ("trigger", "typed_postgres_operation_receipt_event_immutable_update"),
                ("trigger", "typed_postgres_operation_receipt_event_immutable_delete"),
                ("trigger", "typed_postgres_operation_receipt_event_final_requires_prepared"),
            },
            set(v8) - set(v7),
        )


if __name__ == "__main__":
    unittest.main()
