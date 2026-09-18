from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
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
import adcp.production_migration_cli as cli


def create_v6(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(migrations.SCHEMA_MIGRATION_SQL)
    for migration in migrations.MIGRATIONS[:6]:
        migrations._execute_statements(connection, migration.sql)
        connection.execute(
            "INSERT INTO schema_migration VALUES(?,?,?,?)",
            (migration.version, migration.name, migration.checksum, "2026-09-01T00:00:00.000000+00:00"),
        )
    connection.commit()
    connection.close()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProductionMigrationCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source-v6.sqlite3"
        self.clone = self.root / "clone.sqlite3"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        create_v6(self.source)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def call(self, argv):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def clone_args(self):
        return [
            "clone-dry-run", "--source", str(self.source), "--clone", str(self.clone),
            "--evidence-root", str(self.evidence), "--accepted-git-head", "1" * 40,
            "--accepted-git-tree", "2" * 40, "--authority-ref", "FROZEN/CLI-01A",
        ]

    def test_validate_exact_v6_is_read_only(self):
        before = digest(self.source)
        code, output, error = self.call(["validate", "--database", str(self.source)])
        self.assertEqual((0, ""), (code, error))
        self.assertEqual("VALID", json.loads(output)["status"])
        self.assertEqual(before, digest(self.source))

    def test_validate_exact_v7_is_read_only(self):
        connection = sqlite3.connect(self.source, isolation_level=None)
        migrations.migrate(connection, backup_root=None)
        connection.close()
        code, output, _ = self.call(["validate", "--database", str(self.source)])
        self.assertEqual(0, code)
        self.assertEqual(7, json.loads(output)["schema_version"])

    def test_clone_dry_run_runs_only_on_create_new_clone(self):
        code, output, error = self.call(self.clone_args())
        result = json.loads(output)
        self.assertEqual((0, "", "PASS_CLONE_DRY_RUN", 7),
                         (code, error, result["status"], result["schema_version"]))
        connection = sqlite3.connect(self.source)
        source_version = connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
        connection.close()
        self.assertEqual(6, source_version)

    def test_clone_collision_is_create_new_only_failure(self):
        self.clone.write_bytes(b"existing")
        code, _, error = self.call(self.clone_args())
        self.assertEqual(2, code)
        self.assertEqual(b"existing", self.clone.read_bytes())
        self.assertIn("FileExistsError", error)

    def test_clone_source_and_target_cannot_be_equal(self):
        args = self.clone_args()
        args[args.index("--clone") + 1] = str(self.source)
        code, _, error = self.call(args)
        self.assertEqual(2, code)
        self.assertIn("CLONE_SOURCE_TARGET_EQUAL", error)

    def test_canonical_production_source_is_forbidden_for_clone_execution(self):
        with patch.object(cli, "CANONICAL_PRODUCTION_CONTROL_STORE", self.source):
            code, _, error = self.call(self.clone_args())
        self.assertEqual(2, code)
        self.assertIn("CANONICAL_PRODUCTION_CLI_EXECUTION_FORBIDDEN", error)

    def test_unsupported_schema_validation_fails(self):
        connection = sqlite3.connect(self.source)
        connection.execute("DELETE FROM schema_migration WHERE version=6")
        connection.commit(); connection.close()
        code, _, error = self.call(["validate", "--database", str(self.source)])
        self.assertEqual(2, code)
        self.assertIn("SUPPORTED_SCHEMA_V6_OR_V7_REQUIRED", error)

    def test_cli_has_no_sql_backup_restore_or_migration_selector(self):
        parser = cli._parser()
        help_text = parser.format_help()
        for forbidden in ("--sql", "--backup-root", "--restore", "--migration"):
            self.assertNotIn(forbidden, help_text)

    def test_clone_simulation_reports_zero_production_effect_and_free_lease(self):
        code, output, _ = self.call(self.clone_args())
        result = json.loads(output)
        self.assertEqual((0, 0, "FREE"), (code, result["production_effect"], result["lease_state"]))

    def test_clone_migration_never_creates_generic_backup_directory(self):
        code, _, _ = self.call(self.clone_args())
        self.assertEqual(0, code)
        self.assertFalse((self.clone.parent / "backups").exists())
        self.assertFalse((self.clone.parent / "_backup").exists())


if __name__ == "__main__":
    unittest.main()
