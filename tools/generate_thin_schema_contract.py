from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

THIN_CONTRACT_FORMAT_VERSION = 2
SUPPORTED_DCS_SCHEMA_VERSIONS = (6, 7, 8, 9, 10)
FROZEN_MIGRATION_LINEAGE = (
    (1, "0001_mvp_a_control_store", "8f5d1e0d2c9fe9f457aa26bf16a0963131a64a2a6a71d7fdf71490f74acd516c"),
    (2, "0002_slice_control_state", "29b79d1d91841015955dd1cc2678a51765a79fced08aa741c4bd99cc658fac5f"),
    (3, "0003_authority_transition_control", "8a3714a074d314e09e9fbe03d714b2d4a43497ef1653436dcb79bd55668cde46"),
    (4, "0004_deferred_preexecution_binding", "2d95ec8f895fa26b4db70d6b961893f527916ec80e68df8c08c0c7c2749eceb5"),
    (5, "0005_prebound_release_invariant", "e872acac22c59b5a585e3b224300ab20a9e890bcd73342e0ab35282bf4b29eb3"),
    (6, "0006_global_production_writer_lease", "55eecd199ba5e6963cc72d42b4c19bf59f3fe02ee6df3d4ac0f8bd73f45952c0"),
    (7, "0007_evaluator_artifact_seal", "e2488288c73cfb0572430eb38bfd4279b98ddaf4b5eb81468d0b7a666c495596"),
    (8, "0008_typed_postgres_operation_receipt_event", "dcdfd8a9c0e06e8f0c11490c8fd4e080fa6aab6c22e1b9126f98eeb07675faa3"),
    (9, "0009_uncommitted_candidate_review", "e24ca5e65af98e3a2e8130670509dd61acdceeafe3ada6ef3d5a911c52cb0872"),
    (10, "0010_typed_postgres_operation_receipt_provision_principal", "fa241b5205b014bca2524ef35018c319050d560cbcf2c79d004a9d587dc78d6f"),
)
FROZEN_PROFILE_IDENTITIES = {
    6: "sha256:047dd3c4cb1449bd428c0c8519f2baf29e876a9a96e5427767a577f5d5be94dd",
    7: "sha256:e2b33ffa88badf3abba475110234f1e885a121d860ed00039ec294ed5bfa5c62",
    8: "sha256:eb020317a18e1f12f1316d311f22d26e45a1dc11f5d45e3b16dc39aed162508a",
    9: "sha256:0f0bf3c32f0cf4af5b047bc6afdf2a61940df2a1e2a8395463f9183e678e3b6b",
    10: "sha256:1bfa57994e2ea90b11146d32839ca6a8875ad94bb0eea9128fb3b8fb3c5ce7e9",
}
FROZEN_SCHEMA_CONTRACT_IDENTITY = (
    "sha256:288a69e75d8bd4399bbac1973a8632d54a79c0052debec79636a184b715db2a5"
)
V8_EXPECTED_ADDED_OBJECTS = frozenset(
    {
        ("table", "typed_postgres_operation_receipt_event"),
        ("index", "idx_typed_postgres_receipt_operation"),
        ("trigger", "typed_postgres_operation_receipt_event_immutable_update"),
        ("trigger", "typed_postgres_operation_receipt_event_immutable_delete"),
        ("trigger", "typed_postgres_operation_receipt_event_final_requires_prepared"),
    }
)
V10_EXPECTED_CHANGED_OBJECTS = frozenset({("table", "typed_postgres_operation_receipt_event")})

V9_EXPECTED_ADDED_OBJECTS = frozenset(
    {
        ("index", "idx_candidate_binding_execution"),
        ("index", "idx_candidate_evaluation_binding"),
        ("index", "idx_candidate_verification_binding"),
        ("table", "approval_candidate_binding"),
        ("table", "candidate_commit_closure"),
        ("table", "candidate_commit_intent"),
        ("table", "candidate_content_binding"),
        ("table", "candidate_evaluation_result"),
        ("table", "candidate_evaluator_artifact_seal"),
        ("table", "candidate_evaluator_attempt"),
        ("table", "candidate_provenance"),
        ("table", "candidate_verification_result"),
        ("trigger", "approval_candidate_binding_immutable_delete"),
        ("trigger", "approval_candidate_binding_immutable_update"),
        ("trigger", "candidate_closure_exact_binding"),
        ("trigger", "candidate_commit_closure_immutable_delete"),
        ("trigger", "candidate_commit_closure_immutable_update"),
        ("trigger", "candidate_commit_intent_immutable_delete"),
        ("trigger", "candidate_commit_intent_immutable_update"),
        ("trigger", "candidate_content_binding_immutable_delete"),
        ("trigger", "candidate_content_binding_immutable_update"),
        ("trigger", "candidate_evaluation_exact_attempt"),
        ("trigger", "candidate_evaluation_requires_post_seal"),
        ("trigger", "candidate_evaluation_result_immutable_delete"),
        ("trigger", "candidate_evaluation_result_immutable_update"),
        ("trigger", "candidate_evaluator_artifact_seal_immutable_delete"),
        ("trigger", "candidate_evaluator_artifact_seal_immutable_update"),
        ("trigger", "candidate_evaluator_delete_forbidden"),
        ("trigger", "candidate_evaluator_identity_immutable"),
        ("trigger", "candidate_evaluator_terminal_once"),
        ("trigger", "candidate_provenance_immutable_delete"),
        ("trigger", "candidate_provenance_immutable_update"),
        ("trigger", "candidate_provenance_same_execution"),
        ("trigger", "candidate_seal_exact_attempt"),
        ("trigger", "candidate_seal_post_requires_pre"),
        ("trigger", "candidate_verification_exact_binding"),
        ("trigger", "candidate_verification_result_immutable_delete"),
        ("trigger", "candidate_verification_result_immutable_update"),
    }
)
_FIXED_APPLIED_AT = "1970-01-01T00:00:00.000000+00:00"


def _identity(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _schema_object_fingerprint(sql: str) -> str:
    normalized = sql.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _load_migration_authority(source_root: Path) -> tuple[tuple[Any, ...], str, Any]:
    source_root = source_root.expanduser().resolve(strict=True)
    sys.path.insert(0, os.fspath(source_root / "src"))
    try:
        from adcp.store.migrations import (  # type: ignore[import-not-found]
            MIGRATIONS,
            SCHEMA_MIGRATION_SQL,
            _execute_statements,
        )
    finally:
        sys.path.pop(0)
    migrations = tuple(MIGRATIONS)
    lineage = tuple((item.version, item.name, item.checksum) for item in migrations)
    if lineage != FROZEN_MIGRATION_LINEAGE:
        raise SystemExit("accepted Core migration lineage drifted from frozen 0001..0010 authority")
    return migrations, SCHEMA_MIGRATION_SQL, _execute_statements


def _materialize_profile(
    migrations: tuple[Any, ...], schema_migration_sql: str, execute_statements: Any, schema_version: int
) -> dict[str, Any]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(schema_migration_sql)
        history: list[list[Any]] = []
        for migration in migrations[:schema_version]:
            execute_statements(connection, migration.sql)
            connection.execute(
                "INSERT INTO schema_migration(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                (migration.version, migration.name, migration.checksum, _FIXED_APPLIED_AT),
            )
            history.append([migration.version, migration.name, migration.checksum])
        rows = list(
            connection.execute(
                "SELECT type,name,sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view') "
                "ORDER BY type,name"
            )
        )
    finally:
        connection.close()

    views = sorted(name for kind, name, _ in rows if kind == "view")
    if views:
        raise SystemExit(f"unexpected canonical views for schema v{schema_version}: {','.join(views)}")

    fingerprints: list[list[str]] = []
    for kind, name, sql in rows:
        if not isinstance(sql, str):
            raise SystemExit(f"missing canonical SQL for {kind}:{name}")
        fingerprints.append([kind, name, _schema_object_fingerprint(sql)])

    return {
        "schema_version": schema_version,
        "migration_history": history,
        "expected_tables": sorted(name for kind, name, _ in rows if kind == "table"),
        "expected_indexes": sorted(name for kind, name, _ in rows if kind == "index"),
        "expected_triggers": sorted(name for kind, name, _ in rows if kind == "trigger"),
        "expected_object_fingerprints": fingerprints,
    }


def _load_contract(source_root: Path) -> dict[str, Any]:
    migrations, schema_migration_sql, execute_statements = _load_migration_authority(source_root)
    profiles: list[dict[str, Any]] = []
    for schema_version in SUPPORTED_DCS_SCHEMA_VERSIONS:
        payload = _materialize_profile(
            migrations, schema_migration_sql, execute_statements, schema_version
        )
        profile_identity = _identity(payload)
        if profile_identity != FROZEN_PROFILE_IDENTITIES[schema_version]:
            raise SystemExit(f"schema v{schema_version} profile identity does not match frozen authority")
        profiles.append({"profile_identity": profile_identity, **payload})

    v7, v8 = profiles[1], profiles[2]
    if v8["migration_history"][:7] != v7["migration_history"]:
        raise SystemExit("schema v8 does not preserve the exact frozen v7 migration prefix")
    v7_objects = {
        (kind, name): digest for kind, name, digest in v7["expected_object_fingerprints"]
    }
    v8_objects = {
        (kind, name): digest for kind, name, digest in v8["expected_object_fingerprints"]
    }
    added = frozenset(v8_objects) - frozenset(v7_objects)
    removed = frozenset(v7_objects) - frozenset(v8_objects)
    changed = {
        key for key in frozenset(v7_objects) & frozenset(v8_objects)
        if v7_objects[key] != v8_objects[key]
    }
    if added != V8_EXPECTED_ADDED_OBJECTS or removed or changed:
        raise SystemExit("schema v7->v8 delta is not the exact additive typed PostgreSQL receipt ledger")

    v8, v9 = profiles[2], profiles[3]
    if v9["migration_history"][:8] != v8["migration_history"]:
        raise SystemExit("schema v9 does not preserve the exact frozen v8 migration prefix")
    v8_objects = {
        (kind, name): digest for kind, name, digest in v8["expected_object_fingerprints"]
    }
    v9_objects = {
        (kind, name): digest for kind, name, digest in v9["expected_object_fingerprints"]
    }
    added = frozenset(v9_objects) - frozenset(v8_objects)
    removed = frozenset(v8_objects) - frozenset(v9_objects)
    changed = {
        key for key in frozenset(v8_objects) & frozenset(v9_objects)
        if v8_objects[key] != v9_objects[key]
    }
    if added != V9_EXPECTED_ADDED_OBJECTS or removed or changed:
        raise SystemExit("schema v8->v9 delta is not the exact additive candidate-review authority")

    v9, v10 = profiles[3], profiles[4]
    if v10["migration_history"][:9] != v9["migration_history"]:
        raise SystemExit("schema v10 does not preserve the exact frozen v9 migration prefix")
    v9_objects = {
        (kind, name): digest for kind, name, digest in v9["expected_object_fingerprints"]
    }
    v10_objects = {
        (kind, name): digest for kind, name, digest in v10["expected_object_fingerprints"]
    }
    added = frozenset(v10_objects) - frozenset(v9_objects)
    removed = frozenset(v9_objects) - frozenset(v10_objects)
    changed = {
        key for key in frozenset(v9_objects) & frozenset(v10_objects)
        if v9_objects[key] != v10_objects[key]
    }
    if added or removed or changed != V10_EXPECTED_CHANGED_OBJECTS:
        raise SystemExit("schema v9->v10 delta is not the exact receipt operation-kind extension")

    payload = {
        "contract_format_version": THIN_CONTRACT_FORMAT_VERSION,
        "supported_dcs_schema_versions": list(SUPPORTED_DCS_SCHEMA_VERSIONS),
        "profiles": profiles,
    }
    identity = _identity(payload)
    if identity != FROZEN_SCHEMA_CONTRACT_IDENTITY:
        raise SystemExit("schema contract identity does not match frozen v6/v7/v8/v9/v10 authority")
    return {"payload": payload, "identity": identity}


def _render(contract: dict[str, Any]) -> str:
    payload = contract["payload"]
    profiles = []
    for profile in payload["profiles"]:
        profiles.append(
            (
                profile["schema_version"],
                profile["profile_identity"],
                tuple(tuple(item) for item in profile["migration_history"]),
                tuple(profile["expected_tables"]),
                tuple(profile["expected_indexes"]),
                tuple(profile["expected_triggers"]),
                tuple(tuple(item) for item in profile["expected_object_fingerprints"]),
            )
        )
    return "\n".join(
        [
            '"""Generated exact canonical ADCP Core schema-v6/v7/v8/v9/v10 thin-client contract."""',
            "",
            f"THIN_CONTRACT_FORMAT_VERSION = {THIN_CONTRACT_FORMAT_VERSION!r}",
            f"SUPPORTED_DCS_SCHEMA_VERSIONS = {SUPPORTED_DCS_SCHEMA_VERSIONS!r}",
            f"SCHEMA_CONTRACT_IDENTITY = {contract['identity']!r}",
            f"SCHEMA_PROFILES = {tuple(profiles)!r}",
            "",
        ]
    )


def generate(source_root: Path, output: Path) -> dict[str, Any]:
    contract = _load_contract(source_root)
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    data = _render(contract).encode("utf-8")
    temp = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temp.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)
    result = {
        "thin_contract_format_version": THIN_CONTRACT_FORMAT_VERSION,
        "supported_dcs_schema_versions": list(SUPPORTED_DCS_SCHEMA_VERSIONS),
        "schema_profile_identities": {
            str(profile["schema_version"]): profile["profile_identity"]
            for profile in contract["payload"]["profiles"]
        },
        "schema_contract_identity": contract["identity"],
    }
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate exact v6+v7+v8+v9+v10 Thin Client schema authority contract from ADCP Core"
    )
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    generate(args.source_root, args.output)


if __name__ == "__main__":
    main()
