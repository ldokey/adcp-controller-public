"""Exact DCS schema-v7 to schema-v8 adoption boundary.

This module is intentionally not a "latest schema" upgrader.  It accepts only
exact canonical v7 as a mutation source and exact canonical v8 as an already-
applied state, then delegates the single authorized migration to the bounded
Core migration primitive with target_version=8.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from adcp.domain import StoreError
from adcp.store.migrations import (
    MIGRATION_8_NAME,
    MIGRATIONS,
    migrate,
    pending_migrations,
    schema_profile_identity,
)

EXPECTED_CURRENT_SCHEMA = 7
TARGET_SCHEMA = 8
V7_SCHEMA_PROFILE = "sha256:e2b33ffa88badf3abba475110234f1e885a121d860ed00039ec294ed5bfa5c62"
V8_SCHEMA_PROFILE = "sha256:eb020317a18e1f12f1316d311f22d26e45a1dc11f5d45e3b16dc39aed162508a"


@dataclass(frozen=True)
class DcsV7ToV8AdoptionResult:
    previous_version: int
    version: int
    applied: bool
    status: str
    schema_profile_identity: str
    backup_path: Path | None


def _schema_version(connection: sqlite3.Connection) -> int:
    try:
        rows = list(connection.execute("SELECT version FROM schema_migration ORDER BY version"))
    except sqlite3.Error as error:
        raise StoreError("V7_TO_V8_ADOPTION_SCHEMA_UNREADABLE", str(error)) from error
    if not rows:
        raise StoreError("V7_TO_V8_ADOPTION_SOURCE_VERSION_INVALID", "actual=0")
    return int(rows[-1][0])


def _require_profile(connection: sqlite3.Connection, version: int, expected_identity: str) -> str:
    try:
        identity = schema_profile_identity(connection, version)
    except StoreError as error:
        raise StoreError(
            "V7_TO_V8_ADOPTION_PROFILE_MISMATCH",
            f"version={version}:{error}",
        ) from error
    if identity != expected_identity:
        raise StoreError(
            "V7_TO_V8_ADOPTION_PROFILE_MISMATCH",
            f"version={version},expected={expected_identity},actual={identity}",
        )
    return identity


def run_v7_to_v8_adoption(
    connection: sqlite3.Connection,
    *,
    backup_root: Path | None = None,
) -> DcsV7ToV8AdoptionResult:
    """Adopt exact canonical DCS v7 to exact canonical v8, and nothing else."""

    current_version = _schema_version(connection)
    if current_version == TARGET_SCHEMA:
        identity = _require_profile(connection, TARGET_SCHEMA, V8_SCHEMA_PROFILE)
        return DcsV7ToV8AdoptionResult(
            current_version,
            current_version,
            False,
            "ALREADY_APPLIED_EXACT",
            identity,
            None,
        )
    if current_version != EXPECTED_CURRENT_SCHEMA:
        raise StoreError(
            "V7_TO_V8_ADOPTION_SOURCE_VERSION_INVALID",
            f"expected={EXPECTED_CURRENT_SCHEMA},actual={current_version}",
        )

    _require_profile(connection, EXPECTED_CURRENT_SCHEMA, V7_SCHEMA_PROFILE)
    selected = pending_migrations(current_version, TARGET_SCHEMA)
    if tuple(migration.version for migration in selected) != (TARGET_SCHEMA,):
        raise StoreError(
            "V7_TO_V8_ADOPTION_SELECTION_INVALID",
            repr(tuple(migration.version for migration in selected)),
        )
    if selected[0].name != MIGRATION_8_NAME or selected[0] != MIGRATIONS[7]:
        raise StoreError("V7_TO_V8_ADOPTION_MIGRATION_8_AUTHORITY_MISMATCH")

    result = migrate(connection, backup_root=backup_root, target_version=TARGET_SCHEMA)
    if result.previous_version != EXPECTED_CURRENT_SCHEMA or result.version != TARGET_SCHEMA:
        raise StoreError(
            "FAIL_CLOSED_TARGET_VERSION_OVERSHOOT",
            f"previous={result.previous_version},actual={result.version},target={TARGET_SCHEMA}",
        )
    identity = _require_profile(connection, TARGET_SCHEMA, V8_SCHEMA_PROFILE)
    return DcsV7ToV8AdoptionResult(
        result.previous_version,
        result.version,
        result.applied,
        "APPLIED_EXACT",
        identity,
        result.backup_path,
    )


__all__ = [
    "DcsV7ToV8AdoptionResult",
    "EXPECTED_CURRENT_SCHEMA",
    "TARGET_SCHEMA",
    "V7_SCHEMA_PROFILE",
    "V8_SCHEMA_PROFILE",
    "run_v7_to_v8_adoption",
]
