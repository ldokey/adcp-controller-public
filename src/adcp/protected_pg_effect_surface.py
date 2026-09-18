"""Closed-world read-only PostgreSQL effect-surface snapshot for PropertyAI.

This module owns the P0-A semantics.  It accepts no public query/target/credential
inputs and executes exactly one aggregate SELECT through the frozen Cleaner
worker login.  PostgreSQL itself enforces the read-only transaction and the
worker SET ROLE boundary before the SELECT can execute.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, TextIO

from adcp import postgres_control as pg


SCHEMA_VERSION = 1
PRIVILEGE_CONTRACT = "W07_FROZEN_V221"
EXPECTED_SESSION_USER = pg.CLEANER_WORKER_LOGIN_ROLE
EXPECTED_CURRENT_USER = pg.ApprovedPostgresRole.ASYNC_WORKER.value
EXPECTED_DATABASE = pg.CLEANER_DATABASE
TRUSTED_CHILD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PROCESS_TIMEOUT_SECONDS = 8.0
MAX_STDOUT_BYTES = 64 * 1024

KNOWN_OUTBOX_STATES = (
    "PENDING",
    "RUNNING",
    "FAILED_RETRYABLE",
    "PENDING_RECONCILIATION",
    "SUCCEEDED",
    "DEAD_LETTER",
    "CANCELLED",
)

# Exact public protocol emitted by the Controller implementation and its sealed
# bootstrap. Unknown/future tokens are never allowed to cross the boundary.
PROTECTED_PG_EFFECT_SURFACE_REASON_CODES = (
    "OK",
    "COUNT_SHAPE_INVALID",
    "UNEXPECTED_STATUS",
    "OBSERVED_AT_INVALID",
    "IDENTITY_MISMATCH",
    "TRANSACTION_NOT_READ_ONLY",
    "PRIVILEGE_CONTRACT_MISMATCH",
    "COUNT_OVERLAP_INVARIANT_INVALID",
    "POSTGRES_TIMEOUT",
    "BINDING_VALIDATION_FAILED",
    "MALFORMED_SNAPSHOT",
    "POSTGRES_READ_FAILED",
    "OUTPUT_LIMIT",
    "SENSITIVE_OUTPUT_DETECTED",
    "INTERNAL_READ_FAILURE",
    "PUBLIC_INPUT_REJECTED",
    "SOURCE_ORIGIN_MISMATCH",
    "ENTRYPOINT_IDENTITY_MISMATCH",
    "CONTROLLER_ROOT_MISMATCH",
    "CONTROLLER_HEAD_MISMATCH",
    "CONTROLLER_DIRTY",
    "SOURCE_SHADOW_MISMATCH",
    "BOOTSTRAP_INTERNAL_FAILURE",
)
_REASON_CODE_SET = frozenset(PROTECTED_PG_EFFECT_SURFACE_REASON_CODES)

_EXPECTED_WORKER_FUNCTIONS = (
    "propertyai.claim_business_scheduled_actions(text,integer,integer)",
    "propertyai.complete_business_scheduled_action(uuid,text,bigint)",
    "propertyai.fail_business_scheduled_action(uuid,text,bigint,text,integer)",
    "propertyai.claim_integration_outbox(text,integer,integer)",
    "propertyai.complete_integration_outbox(uuid,text,bigint,text)",
    "propertyai.fail_integration_outbox(uuid,text,bigint,text,integer)",
    "propertyai.mark_outbox_pending_reconciliation(uuid,text,bigint,text,text)",
    "propertyai.resolve_outbox_reconciliation(uuid,bigint,text,text,text,integer)",
)

_EXPECTED_RESOURCE_BINDING_UPDATE_COLUMNS = (
    "external_resource_id",
    "external_uid",
    "sync_status",
    "last_applied_aggregate_version",
    "external_version",
    "last_synced_at",
    "updated_at",
)

_STATUS_VALUES_SQL = ",".join(f"('{value}')" for value in KNOWN_OUTBOX_STATES)
_FUNCTION_VALUES_SQL = ",\n      ".join(
    f"('{signature}'::text)" for signature in _EXPECTED_WORKER_FUNCTIONS
)
_UPDATE_COLUMN_VALUES_SQL = ",".join(
    f"('{column}'::text)" for column in _EXPECTED_RESOURCE_BINDING_UPDATE_COLUMNS
)

# This is the only SQL statement executable by this capability.  Target function
# names occur only as string literals passed to to_regprocedure for ACL proof;
# none of the worker mutation functions is invoked.
FIXED_AGGREGATE_SELECT = f"""
WITH
known_status(status) AS (
  VALUES {_STATUS_VALUES_SQL}
),
expected_function(signature) AS (
  VALUES
      {_FUNCTION_VALUES_SQL}
),
expected_function_oid AS (
  SELECT signature, pg_catalog.to_regprocedure(signature) AS oid
  FROM expected_function
),
expected_update_column(column_name) AS (
  VALUES {_UPDATE_COLUMN_VALUES_SQL}
),
role_proof AS (
  SELECT
    (
      SELECT count(*) = 1 AND bool_and(
        r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
        AND NOT r.rolcreatedb AND NOT r.rolcreaterole
        AND NOT r.rolreplication AND NOT r.rolbypassrls
      )
      FROM pg_catalog.pg_roles r
      WHERE r.rolname = 'propertyai_cleaner_worker'
    ) AS worker_role_ok,
    (
      SELECT count(*) = 1 AND bool_and(
        NOT r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper
        AND NOT r.rolcreatedb AND NOT r.rolcreaterole
        AND NOT r.rolreplication AND NOT r.rolbypassrls
      )
      FROM pg_catalog.pg_roles r
      WHERE r.rolname = 'propertyai_async_worker'
    ) AS capability_role_ok
),
membership_proof AS (
  SELECT count(*) = 1 AND bool_and(
    granted.rolname = 'propertyai_async_worker'
    AND member.rolname = 'propertyai_cleaner_worker'
    AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option
    AND grantor.rolsuper
  ) AS ok
  FROM pg_catalog.pg_auth_members m
  JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
  JOIN pg_catalog.pg_roles member ON member.oid = m.member
  JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor
  WHERE granted.rolname IN ('propertyai_async_worker','propertyai_cleaner_worker')
     OR member.rolname IN ('propertyai_async_worker','propertyai_cleaner_worker')
),
worker_oid AS (
  SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'propertyai_cleaner_worker'
),
capability_oid AS (
  SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'propertyai_async_worker'
),
worker_direct_acl_proof AS (
  SELECT
    NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_namespace n
      CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) a
      WHERE n.nspname = 'propertyai' AND a.grantee = (SELECT oid FROM worker_oid)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a
      WHERE n.nspname = 'propertyai' AND a.grantee = (SELECT oid FROM worker_oid)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_attribute att
      JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a
      WHERE n.nspname = 'propertyai' AND a.grantee = (SELECT oid FROM worker_oid)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
      WHERE n.nspname = 'propertyai' AND a.grantee = (SELECT oid FROM worker_oid)
    ) AS ok
),
ownership_separation_proof AS (
  SELECT
    NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_namespace n
      WHERE n.nspowner IN ((SELECT oid FROM worker_oid),(SELECT oid FROM capability_oid))
    )
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class c
      WHERE c.relowner IN ((SELECT oid FROM worker_oid),(SELECT oid FROM capability_oid))
    )
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc p
      WHERE p.proowner IN ((SELECT oid FROM worker_oid),(SELECT oid FROM capability_oid))
    )
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_database d
      WHERE d.datdba IN ((SELECT oid FROM worker_oid),(SELECT oid FROM capability_oid))
    ) AS ok
),
effective_schema_acl AS (
  SELECT a.grantee, a.privilege_type, a.is_grantable
  FROM pg_catalog.pg_namespace n
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
  ) a
  WHERE n.nspname = 'propertyai'
    AND (a.grantee = (SELECT oid FROM capability_oid) OR a.grantee = 0)
),
effective_relation_acl AS (
  SELECT c.oid AS relation_oid, c.relname, c.relkind,
         a.grantee, a.privilege_type, a.is_grantable
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))
  ) a
  WHERE n.nspname = 'propertyai'
    AND c.relkind IN ('r','p','v','m','f')
    AND (a.grantee = (SELECT oid FROM capability_oid) OR a.grantee = 0)
),
effective_column_acl AS (
  SELECT c.relname, att.attname, a.grantee, a.privilege_type, a.is_grantable
  FROM pg_catalog.pg_attribute att
  JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(att.attacl, pg_catalog.acldefault('c', c.relowner))
  ) a
  WHERE n.nspname = 'propertyai'
    AND att.attnum > 0 AND NOT att.attisdropped
    AND (a.grantee = (SELECT oid FROM capability_oid) OR a.grantee = 0)
),
effective_function_acl AS (
  SELECT p.oid, a.grantee, a.privilege_type, a.is_grantable
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
  ) a
  WHERE n.nspname = 'propertyai'
    AND (a.grantee = (SELECT oid FROM capability_oid) OR a.grantee = 0)
),
effective_sequence_acl AS (
  SELECT c.oid, a.grantee, a.privilege_type, a.is_grantable
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(c.relacl, pg_catalog.acldefault('s', c.relowner))
  ) a
  WHERE n.nspname = 'propertyai' AND c.relkind = 'S'
    AND (a.grantee = (SELECT oid FROM capability_oid) OR a.grantee = 0)
),
capability_privilege_proof AS (
  SELECT
    (SELECT count(*) = 1 AND bool_and(
       grantee = (SELECT oid FROM capability_oid)
       AND privilege_type = 'USAGE' AND NOT is_grantable)
       FROM effective_schema_acl)
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'propertyai' AND c.relkind IN ('r','p','v','m','f')
        AND NOT EXISTS (
          SELECT 1 FROM effective_relation_acl a
          WHERE a.relation_oid = c.oid
            AND a.grantee = (SELECT oid FROM capability_oid)
            AND a.privilege_type = 'SELECT' AND NOT a.is_grantable
        )
    )
    AND NOT EXISTS (
      SELECT 1 FROM effective_relation_acl a
      WHERE a.grantee <> (SELECT oid FROM capability_oid)
         OR a.is_grantable
         OR (a.privilege_type <> 'SELECT'
             AND NOT (a.relname = 'integration_resource_binding' AND a.privilege_type = 'INSERT'))
    )
    AND EXISTS (
      SELECT 1 FROM effective_relation_acl
      WHERE grantee = (SELECT oid FROM capability_oid)
        AND relname = 'integration_outbox' AND privilege_type = 'SELECT' AND NOT is_grantable
    )
    AND NOT EXISTS (
      SELECT 1 FROM effective_relation_acl
      WHERE relname = 'integration_outbox' AND privilege_type <> 'SELECT'
    )
    AND EXISTS (
      SELECT 1 FROM effective_relation_acl
      WHERE grantee = (SELECT oid FROM capability_oid)
        AND relname = 'integration_resource_binding' AND privilege_type = 'INSERT' AND NOT is_grantable
    )
    AND (SELECT count(*) = {len(_EXPECTED_RESOURCE_BINDING_UPDATE_COLUMNS)} FROM effective_column_acl)
    AND NOT EXISTS (
      SELECT 1 FROM effective_column_acl a
      WHERE a.grantee <> (SELECT oid FROM capability_oid)
         OR a.relname <> 'integration_resource_binding'
         OR a.privilege_type <> 'UPDATE'
         OR a.is_grantable
         OR NOT EXISTS (SELECT 1 FROM expected_update_column e WHERE e.column_name = a.attname)
    )
    AND NOT EXISTS (
      SELECT 1 FROM expected_update_column e
      WHERE NOT EXISTS (
        SELECT 1 FROM effective_column_acl a
        WHERE a.relname = 'integration_resource_binding'
          AND a.grantee = (SELECT oid FROM capability_oid)
          AND a.attname = e.column_name AND a.privilege_type = 'UPDATE' AND NOT a.is_grantable
      )
    )
    AND NOT EXISTS (SELECT 1 FROM expected_function_oid WHERE oid IS NULL)
    AND (SELECT count(*) = {len(_EXPECTED_WORKER_FUNCTIONS)} FROM expected_function_oid)
    AND (SELECT count(*) = {len(_EXPECTED_WORKER_FUNCTIONS)} FROM effective_function_acl)
    AND NOT EXISTS (
      SELECT 1 FROM effective_function_acl a
      WHERE a.grantee <> (SELECT oid FROM capability_oid)
         OR a.privilege_type <> 'EXECUTE' OR a.is_grantable
         OR NOT EXISTS (SELECT 1 FROM expected_function_oid e WHERE e.oid = a.oid)
    )
    AND NOT EXISTS (
      SELECT 1 FROM expected_function_oid e
      WHERE NOT EXISTS (
        SELECT 1 FROM effective_function_acl a
        WHERE a.oid = e.oid
          AND a.grantee = (SELECT oid FROM capability_oid)
          AND a.privilege_type = 'EXECUTE' AND NOT a.is_grantable
      )
    )
    AND NOT EXISTS (SELECT 1 FROM effective_sequence_acl)
    AS ok
),
status_snapshot AS (
  SELECT
    count(*) FILTER (WHERE o.outbox_status = 'RUNNING')::bigint AS claimed_running_count,
    count(*) FILTER (WHERE o.outbox_status IN ('PENDING','FAILED_RETRYABLE'))::bigint AS pending_outbox_effect_count,
    count(*) FILTER (WHERE o.outbox_status = 'PENDING_RECONCILIATION')::bigint AS reconciliation_required_count,
    count(*) FILTER (WHERE o.outbox_status = 'PENDING_RECONCILIATION' AND o.external_effect_id IS NULL)::bigint AS result_unknown_effect_count,
    count(*) FILTER (WHERE o.outbox_status = 'DEAD_LETTER')::bigint AS other_actionable_effect_count,
    count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM known_status k WHERE k.status = o.outbox_status))::bigint AS unexpected_status_count
  FROM propertyai.integration_outbox o
),
privilege_proof AS (
  SELECT
    r.worker_role_ok AND r.capability_role_ok
    AND m.ok AND w.ok AND s.ok AND c.ok AS ok
  FROM role_proof r
  CROSS JOIN membership_proof m
  CROSS JOIN worker_direct_acl_proof w
  CROSS JOIN ownership_separation_proof s
  CROSS JOIN capability_privilege_proof c
)
SELECT pg_catalog.json_build_object(
  'observed_at', pg_catalog.transaction_timestamp(),
  'claimed_running_count', ss.claimed_running_count,
  'pending_outbox_effect_count', ss.pending_outbox_effect_count,
  'reconciliation_required_count', ss.reconciliation_required_count,
  'result_unknown_effect_count', ss.result_unknown_effect_count,
  'other_actionable_effect_count', ss.other_actionable_effect_count,
  'unexpected_status_count', ss.unexpected_status_count,
  'database_name', pg_catalog.current_database(),
  'session_user', session_user::text,
  'current_user', current_user::text,
  'transaction_read_only', pg_catalog.current_setting('transaction_read_only'),
  'privilege_contract_ok', pp.ok
)::text
FROM status_snapshot ss
CROSS JOIN privilege_proof pp;
""".strip()

FIXED_AGGREGATE_SELECT_SHA256 = hashlib.sha256(
    FIXED_AGGREGATE_SELECT.encode("utf-8")
).hexdigest()


@dataclass(frozen=True)
class ControllerSourceIdentity:
    commit: str
    tree: str
    source_clean: bool
    entrypoint: str = "protected_pg_effect_surface_entrypoint.py"


@dataclass(frozen=True)
class _WorkerBinding:
    psql_path: Path
    host: str
    port: int
    database: str
    login_role: str
    effective_role: str
    pgpass_path: Path
    pgpass_fingerprint: tuple[int, int, int, int, int]
    secret_for_redaction: str


def _public_result(
    *,
    read_status: str,
    reason_code: str,
    source_identity: ControllerSourceIdentity,
    observed_at: str | None = None,
    counts: Mapping[str, int | None] | None = None,
    unexpected_status_count: int | None = None,
    database_name: str | None = None,
    session_user: str | None = None,
    current_user: str | None = None,
    transaction_read_only: str | None = None,
    privilege_contract: str | None = None,
) -> dict[str, Any]:
    count_values = counts or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "read_status": read_status,
        "reason_code": reason_code,
        "observed_at": observed_at,
        "claimed_running_count": count_values.get("claimed_running_count"),
        "pending_outbox_effect_count": count_values.get("pending_outbox_effect_count"),
        "reconciliation_required_count": count_values.get("reconciliation_required_count"),
        "result_unknown_effect_count": count_values.get("result_unknown_effect_count"),
        "other_actionable_effect_count": count_values.get("other_actionable_effect_count"),
        "unexpected_status_count": unexpected_status_count,
        "database_name": database_name,
        "session_user": session_user,
        "current_user": current_user,
        "controller_source_identity": {
            "commit": source_identity.commit,
            "tree": source_identity.tree,
            "source_clean": source_identity.source_clean,
            "entrypoint": source_identity.entrypoint,
        },
        "transaction_read_only": transaction_read_only,
        "privilege_contract": privilege_contract,
        "sensitive_payload_output": "NO",
        "mutation_exercised": "NO",
    }


def _unknown(reason_code: str, source_identity: ControllerSourceIdentity) -> dict[str, Any]:
    if reason_code not in _REASON_CODE_SET or reason_code == "OK":
        reason_code = "INTERNAL_READ_FAILURE"
    return _public_result(
        read_status="UNKNOWN",
        reason_code=reason_code,
        source_identity=source_identity,
    )


def _strip_sql_string_literals(sql: str) -> str:
    """Replace quoted SQL literal contents so lexical checks inspect executable tokens."""

    result: list[str] = []
    index = 0
    in_literal = False
    while index < len(sql):
        char = sql[index]
        if not in_literal:
            if char == "'":
                in_literal = True
                result.append("''")
            else:
                result.append(char)
            index += 1
            continue
        if char == "'" and index + 1 < len(sql) and sql[index + 1] == "'":
            index += 2
            continue
        if char == "'":
            in_literal = False
        index += 1
    if in_literal:
        raise RuntimeError("P0A_FIXED_SQL_LITERAL_UNTERMINATED")
    return "".join(result)


def _assert_fixed_sql_read_only() -> None:
    executable = _strip_sql_string_literals(FIXED_AGGREGATE_SELECT).upper()
    forbidden_patterns = (
        r"\bINSERT\b",
        r"\bUPDATE\b",
        r"\bDELETE\b",
        r"\bMERGE\b",
        r"\bCREATE\b",
        r"\bALTER\b",
        r"\bDROP\b",
        r"\bTRUNCATE\b",
        r"\bCALL\b",
        r"\bDO\b",
        r"\bCOPY\b",
        r"\bLOCK\b",
        r"\bNOTIFY\b",
        r"\bNEXTVAL\s*\(",
        r"\bSETVAL\s*\(",
        r"\bPG_ADVISORY_[A-Z_]*\s*\(",
        r"\bFOR\s+UPDATE\b",
    )
    for pattern in forbidden_patterns:
        if re.search(pattern, executable):
            raise RuntimeError("P0A_FIXED_SQL_MUTATION_TOKEN_FORBIDDEN")
    if executable.count(";") != 1 or not executable.rstrip().endswith(";"):
        raise RuntimeError("P0A_FIXED_SQL_STATEMENT_COUNT_INVALID")
    if not executable.lstrip().startswith("WITH"):
        raise RuntimeError("P0A_FIXED_SQL_SHAPE_INVALID")


_assert_fixed_sql_read_only()


def _resolve_worker_binding() -> _WorkerBinding:
    if any(key.startswith("PG") for key in os.environ):
        raise pg.TypedPostgresError("POSTGRES_WORKER_AMBIENT_CREDENTIAL_FORBIDDEN")
    policy = pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    pg._validate_psql_binary(policy)
    material = pg._validate_credential(
        policy,
        pg.CredentialReference.WORKER_PGPASS,
        reveal_text=True,
    )
    secret = pg._password_from_credential(policy, material)
    if material.spec.role != EXPECTED_SESSION_USER:
        raise pg.TypedPostgresError("POSTGRES_WORKER_CREDENTIAL_ROLE_MISMATCH")
    return _WorkerBinding(
        psql_path=policy.psql_path,
        host=policy.host,
        port=policy.port,
        database=EXPECTED_DATABASE,
        login_role=EXPECTED_SESSION_USER,
        effective_role=EXPECTED_CURRENT_USER,
        pgpass_path=material.spec.path,
        pgpass_fingerprint=material.fingerprint,
        secret_for_redaction=secret,
    )


def _execute_fixed_snapshot(binding: _WorkerBinding) -> str:
    pg._revalidate_path_fingerprint(
        binding.pgpass_path,
        binding.pgpass_fingerprint,
        code_prefix="POSTGRES_CREDENTIAL_FILE",
    )
    argv = [
        str(binding.psql_path),
        "-X",
        "--no-psqlrc",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "--tuples-only",
        "--no-align",
        f"--host={binding.host}",
        f"--port={binding.port}",
        f"--dbname={binding.database}",
        f"--username={binding.login_role}",
    ]
    env = {
        "PATH": TRUSTED_CHILD_PATH,
        "LC_ALL": "C",
        "PGREQUIREAUTH": "scram-sha-256",
        "PGCONNECT_TIMEOUT": "10",
        "PGPASSFILE": str(binding.pgpass_path),
        "PGOPTIONS": (
            "-c default_transaction_read_only=on "
            f"-c role={binding.effective_role}"
        ),
    }
    completed = subprocess.run(
        argv,
        input=(FIXED_AGGREGATE_SELECT + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        shell=False,
        env=env,
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError("P0A_POSTGRES_READ_FAILED")
    if len(completed.stdout) > MAX_STDOUT_BYTES:
        raise RuntimeError("P0A_POSTGRES_OUTPUT_LIMIT")
    # Never expose stderr or secret-bearing material.  stdout is expected to be
    # exactly the aggregate JSON row and is validated before any field is copied.
    stdout = completed.stdout.decode("utf-8", errors="strict")
    if binding.secret_for_redaction and binding.secret_for_redaction in stdout:
        raise RuntimeError("P0A_SENSITIVE_OUTPUT_DETECTED")
    return stdout


def _parse_snapshot(stdout: str) -> Mapping[str, Any]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("P0A_SNAPSHOT_CARDINALITY_INVALID")
    value = json.loads(lines[0])
    if not isinstance(value, dict):
        raise ValueError("P0A_SNAPSHOT_SHAPE_INVALID")
    expected_keys = {
        "observed_at",
        "claimed_running_count",
        "pending_outbox_effect_count",
        "reconciliation_required_count",
        "result_unknown_effect_count",
        "other_actionable_effect_count",
        "unexpected_status_count",
        "database_name",
        "session_user",
        "current_user",
        "transaction_read_only",
        "privilege_contract_ok",
    }
    if set(value) != expected_keys:
        raise ValueError("P0A_SNAPSHOT_FIELDS_INVALID")
    return value


def _validated_read_result(
    snapshot: Mapping[str, Any], source_identity: ControllerSourceIdentity
) -> dict[str, Any]:
    count_fields = (
        "claimed_running_count",
        "pending_outbox_effect_count",
        "reconciliation_required_count",
        "result_unknown_effect_count",
        "other_actionable_effect_count",
    )
    if any(type(snapshot.get(field)) is not int or int(snapshot[field]) < 0 for field in count_fields):
        return _unknown("COUNT_SHAPE_INVALID", source_identity)
    unexpected = snapshot.get("unexpected_status_count")
    if type(unexpected) is not int or unexpected < 0:
        return _unknown("COUNT_SHAPE_INVALID", source_identity)
    if unexpected != 0:
        return _public_result(
            read_status="UNKNOWN",
            reason_code="UNEXPECTED_STATUS",
            source_identity=source_identity,
            observed_at=(snapshot.get("observed_at") if isinstance(snapshot.get("observed_at"), str) else None),
            unexpected_status_count=unexpected,
            database_name=(snapshot.get("database_name") if isinstance(snapshot.get("database_name"), str) else None),
            session_user=(snapshot.get("session_user") if isinstance(snapshot.get("session_user"), str) else None),
            current_user=(snapshot.get("current_user") if isinstance(snapshot.get("current_user"), str) else None),
            transaction_read_only=(snapshot.get("transaction_read_only") if isinstance(snapshot.get("transaction_read_only"), str) else None),
            privilege_contract=(PRIVILEGE_CONTRACT if snapshot.get("privilege_contract_ok") is True else None),
        )
    observed_at = snapshot.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at:
        return _unknown("OBSERVED_AT_INVALID", source_identity)
    if (
        snapshot.get("database_name") != EXPECTED_DATABASE
        or snapshot.get("session_user") != EXPECTED_SESSION_USER
        or snapshot.get("current_user") != EXPECTED_CURRENT_USER
    ):
        return _unknown("IDENTITY_MISMATCH", source_identity)
    if snapshot.get("transaction_read_only") != "on":
        return _unknown("TRANSACTION_NOT_READ_ONLY", source_identity)
    if snapshot.get("privilege_contract_ok") is not True:
        return _unknown("PRIVILEGE_CONTRACT_MISMATCH", source_identity)
    if int(snapshot["result_unknown_effect_count"]) > int(snapshot["reconciliation_required_count"]):
        return _unknown("COUNT_OVERLAP_INVARIANT_INVALID", source_identity)
    counts = {field: int(snapshot[field]) for field in count_fields}
    return _public_result(
        read_status="READ",
        reason_code="OK",
        source_identity=source_identity,
        observed_at=observed_at,
        counts=counts,
        unexpected_status_count=0,
        database_name=EXPECTED_DATABASE,
        session_user=EXPECTED_SESSION_USER,
        current_user=EXPECTED_CURRENT_USER,
        transaction_read_only="on",
        privilege_contract=PRIVILEGE_CONTRACT,
    )


def read_propertyai_pg_effect_surface(
    *, source_identity: ControllerSourceIdentity
) -> dict[str, Any]:
    try:
        binding = _resolve_worker_binding()
        return _validated_read_result(
            _parse_snapshot(_execute_fixed_snapshot(binding)),
            source_identity,
        )
    except subprocess.TimeoutExpired:
        return _unknown("POSTGRES_TIMEOUT", source_identity)
    except (pg.TypedPostgresError, OSError):
        return _unknown("BINDING_VALIDATION_FAILED", source_identity)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        return _unknown("MALFORMED_SNAPSHOT", source_identity)
    except RuntimeError as error:
        safe = str(error)
        reason = {
            "P0A_POSTGRES_READ_FAILED": "POSTGRES_READ_FAILED",
            "P0A_POSTGRES_OUTPUT_LIMIT": "OUTPUT_LIMIT",
            "P0A_SENSITIVE_OUTPUT_DETECTED": "SENSITIVE_OUTPUT_DETECTED",
        }.get(safe, "INTERNAL_READ_FAILURE")
        return _unknown(reason, source_identity)


def main(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    source_identity: ControllerSourceIdentity,
) -> int:
    if input_stream.read().strip():
        result = _unknown("PUBLIC_INPUT_REJECTED", source_identity)
    else:
        result = read_propertyai_pg_effect_surface(source_identity=source_identity)
    output_stream.write(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    )
    return 0


__all__ = [
    "ControllerSourceIdentity",
    "FIXED_AGGREGATE_SELECT_SHA256",
    "KNOWN_OUTBOX_STATES",
    "PRIVILEGE_CONTRACT",
    "PROTECTED_PG_EFFECT_SURFACE_REASON_CODES",
    "main",
    "read_propertyai_pg_effect_surface",
]
