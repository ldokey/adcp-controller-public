from __future__ import annotations

import sqlite3
from pathlib import Path

from adcp.store.migrations import MIGRATIONS, SCHEMA_MIGRATION_SQL, _execute_statements

_FIXED_APPLIED_AT = "2026-08-29T00:00:00.000000+00:00"


def create_schema(path: Path, version: int) -> None:
    if not 0 <= version <= len(MIGRATIONS):
        raise ValueError(version)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(SCHEMA_MIGRATION_SQL)
        for migration in MIGRATIONS[:version]:
            _execute_statements(connection, migration.sql)
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, _FIXED_APPLIED_AT),
            )
        connection.commit()
    finally:
        connection.close()
