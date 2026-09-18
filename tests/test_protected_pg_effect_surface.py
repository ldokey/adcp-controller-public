from __future__ import annotations

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess

import pytest

from adcp import protected_pg_effect_surface as surface


SOURCE = surface.ControllerSourceIdentity("a" * 40, "b" * 40, True)


def _snapshot(**updates):
    value = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "claimed_running_count": 1,
        "pending_outbox_effect_count": 2,
        "reconciliation_required_count": 3,
        "result_unknown_effect_count": 1,
        "other_actionable_effect_count": 4,
        "unexpected_status_count": 0,
        "database_name": "propertyai_cleaner_prod",
        "session_user": "propertyai_cleaner_worker",
        "current_user": "propertyai_async_worker",
        "transaction_read_only": "on",
        "privilege_contract_ok": True,
    }
    value.update(updates)
    return value


def _binding(tmp_path: Path, *, secret: str = "fixture-secret") -> surface._WorkerBinding:
    pgpass = tmp_path / "worker.pgpass"
    pgpass.write_text("fixture", encoding="utf-8")
    return surface._WorkerBinding(
        psql_path=Path("/fixture/psql"),
        host="127.0.0.1",
        port=5432,
        database="propertyai_cleaner_prod",
        login_role="propertyai_cleaner_worker",
        effective_role="propertyai_async_worker",
        pgpass_path=pgpass,
        pgpass_fingerprint=(1, 2, 3, 4, 5),
        secret_for_redaction=secret,
    )


def test_reason_code_protocol_is_an_exact_closed_set():
    assert surface.PROTECTED_PG_EFFECT_SURFACE_REASON_CODES == (
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
    for reason in surface.PROTECTED_PG_EFFECT_SURFACE_REASON_CODES:
        if reason == "OK":
            assert surface._validated_read_result(_snapshot(), SOURCE)["reason_code"] == "OK"
        else:
            assert surface._unknown(reason, SOURCE)["reason_code"] == reason
    assert surface._unknown("FUTURE_VALID_LOOKING_REASON", SOURCE)["reason_code"] == "INTERNAL_READ_FAILURE"
    assert surface._unknown("bad-reason", SOURCE)["reason_code"] == "INTERNAL_READ_FAILURE"


def test_frozen_seven_state_classification_matrix_is_encoded_once():
    assert surface.KNOWN_OUTBOX_STATES == (
        "PENDING",
        "RUNNING",
        "FAILED_RETRYABLE",
        "PENDING_RECONCILIATION",
        "SUCCEEDED",
        "DEAD_LETTER",
        "CANCELLED",
    )
    sql = surface.FIXED_AGGREGATE_SELECT
    assert "o.outbox_status = 'RUNNING'" in sql
    assert "o.outbox_status IN ('PENDING','FAILED_RETRYABLE')" in sql
    assert sql.count("o.outbox_status = 'PENDING_RECONCILIATION'") == 2
    assert "o.external_effect_id IS NULL" in sql
    assert "o.outbox_status = 'DEAD_LETTER'" in sql
    assert "NOT EXISTS (SELECT 1 FROM known_status" in sql
    assert "'SUCCEEDED'" in sql and "'CANCELLED'" in sql


def test_reconciliation_unknown_is_a_subset_and_not_additive():
    result = surface._validated_read_result(
        _snapshot(reconciliation_required_count=5, result_unknown_effect_count=2), SOURCE
    )
    assert result["read_status"] == "READ"
    assert result["reconciliation_required_count"] == 5
    assert result["result_unknown_effect_count"] == 2

    invalid = surface._validated_read_result(
        _snapshot(reconciliation_required_count=1, result_unknown_effect_count=2), SOURCE
    )
    assert invalid["read_status"] == "UNKNOWN"
    assert invalid["reason_code"] == "COUNT_OVERLAP_INVARIANT_INVALID"
    assert invalid["reconciliation_required_count"] is None
    assert invalid["result_unknown_effect_count"] is None


def test_unexpected_status_makes_whole_count_snapshot_unknown():
    result = surface._validated_read_result(_snapshot(unexpected_status_count=1), SOURCE)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "UNEXPECTED_STATUS"
    assert result["unexpected_status_count"] == 1
    for field in (
        "claimed_running_count",
        "pending_outbox_effect_count",
        "reconciliation_required_count",
        "result_unknown_effect_count",
        "other_actionable_effect_count",
    ):
        assert result[field] is None


def test_single_fixed_select_snapshot_and_db_time_contract():
    sql = surface.FIXED_AGGREGATE_SELECT
    surface._assert_fixed_sql_read_only()
    assert sql.count(";") == 1
    assert "transaction_timestamp()" in sql
    assert "current_setting('transaction_read_only')" in sql
    assert "current_database()" in sql
    assert "session_user::text" in sql
    assert "current_user::text" in sql
    assert "FROM propertyai.integration_outbox o" in sql
    assert surface.FIXED_AGGREGATE_SELECT_SHA256


def test_fixed_sql_has_no_mutation_advisory_sequence_or_effect_function_execution():
    executable = surface._strip_sql_string_literals(surface.FIXED_AGGREGATE_SELECT).upper()
    for token in (
        " INSERT ", " UPDATE ", " DELETE ", " ALTER ", " CREATE ", " DROP ",
        " TRUNCATE ", " CALL ", " DO ", " FOR UPDATE", "PG_ADVISORY_", "NEXTVAL(", "SETVAL(",
    ):
        assert token not in f" {executable} "
    # Mutation-capable W07 function names occur only as catalog signature strings.
    assert "to_regprocedure(signature)" in surface.FIXED_AGGREGATE_SELECT
    assert "claim_integration_outbox(" not in executable.lower()
    assert "resolve_outbox_reconciliation(" not in executable.lower()


def test_privilege_contract_covers_role_membership_separation_public_defaults_and_grant_options():
    sql = surface.FIXED_AGGREGATE_SELECT
    for evidence in (
        "rolcanlogin", "rolinherit", "rolsuper", "rolcreatedb", "rolcreaterole",
        "rolreplication", "rolbypassrls", "pg_auth_members", "grantor.rolsuper",
        "worker_direct_acl_proof", "ownership_separation_proof", "effective_relation_acl",
        "effective_column_acl", "effective_function_acl", "effective_sequence_acl",
        "a.is_grantable", "integration_outbox", "integration_resource_binding",
    ):
        assert evidence in sql
    for object_type in ("n", "r", "c", "f", "s"):
        assert f"pg_catalog.acldefault('{object_type}'," in sql
    assert sql.count("OR a.grantee = 0") == 5
    assert sql.count("a.grantee <> (SELECT oid FROM capability_oid)") >= 3
    for signature in surface._EXPECTED_WORKER_FUNCTIONS:
        assert signature in sql
    for column in surface._EXPECTED_RESOURCE_BINDING_UPDATE_COLUMNS:
        assert column in sql


def test_public_and_default_acl_exposure_is_explicitly_rejected_by_the_frozen_contract():
    sql = surface.FIXED_AGGREGATE_SELECT
    # PUBLIC is PostgreSQL ACL grantee oid 0. Every effective ACL CTE includes it,
    # while the frozen proof only accepts the capability role on allowed grants.
    for cte in (
        "effective_schema_acl",
        "effective_relation_acl",
        "effective_column_acl",
        "effective_function_acl",
        "effective_sequence_acl",
    ):
        assert cte in sql
    assert "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))" in sql
    assert "FROM effective_function_acl a\n      WHERE a.grantee <> (SELECT oid FROM capability_oid)" in sql
    assert "AND NOT EXISTS (SELECT 1 FROM effective_sequence_acl)" in sql
    assert "FROM effective_schema_acl" in sql
    assert "grantee = (SELECT oid FROM capability_oid)" in sql


def test_psql_execution_uses_fixed_worker_target_shell_false_minimal_env_and_one_select(monkeypatch, tmp_path):
    binding = _binding(tmp_path)
    monkeypatch.setattr(surface.pg, "_revalidate_path_fingerprint", lambda *a, **k: None)
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-flow")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, b'{"ok":true}\n', b"")

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    assert surface._execute_fixed_snapshot(binding) == '{"ok":true}\n'
    assert captured["shell"] is False
    assert captured["input"] == (surface.FIXED_AGGREGATE_SELECT + "\n").encode()
    assert captured["argv"] == [
        "/fixture/psql", "-X", "--no-psqlrc", "--no-password", "--set=ON_ERROR_STOP=1",
        "--tuples-only", "--no-align", "--host=127.0.0.1", "--port=5432",
        "--dbname=propertyai_cleaner_prod", "--username=propertyai_cleaner_worker",
    ]
    assert captured["env"] == {
        "PATH": surface.TRUSTED_CHILD_PATH,
        "LC_ALL": "C",
        "PGREQUIREAUTH": "scram-sha-256",
        "PGCONNECT_TIMEOUT": "10",
        "PGPASSFILE": str(binding.pgpass_path),
        "PGOPTIONS": "-c default_transaction_read_only=on -c role=propertyai_async_worker",
    }
    assert "UNRELATED_SECRET" not in captured["env"]


def test_ambient_pg_environment_is_fail_closed_before_credential_resolution(monkeypatch):
    monkeypatch.setenv("PGHOST", "attacker-controlled")
    with pytest.raises(Exception) as exc:
        surface._resolve_worker_binding()
    assert "POSTGRES_WORKER_AMBIENT_CREDENTIAL_FORBIDDEN" in str(exc.value)


def test_identity_read_only_and_full_privilege_drift_are_unknown():
    cases = [
        (_snapshot(session_user="wrong"), "IDENTITY_MISMATCH"),
        (_snapshot(current_user="wrong"), "IDENTITY_MISMATCH"),
        (_snapshot(database_name="wrong"), "IDENTITY_MISMATCH"),
        (_snapshot(transaction_read_only="off"), "TRANSACTION_NOT_READ_ONLY"),
        (_snapshot(privilege_contract_ok=False), "PRIVILEGE_CONTRACT_MISMATCH"),
    ]
    for snapshot, reason in cases:
        result = surface._validated_read_result(snapshot, SOURCE)
        assert result["read_status"] == "UNKNOWN"
        assert result["reason_code"] == reason
        assert result["claimed_running_count"] is None


def test_malformed_partial_controller_rows_are_unknown(monkeypatch):
    monkeypatch.setattr(surface, "_resolve_worker_binding", lambda: object())
    monkeypatch.setattr(surface, "_execute_fixed_snapshot", lambda _binding: '{"observed_at":"x"}\n')
    result = surface.read_propertyai_pg_effect_surface(source_identity=SOURCE)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "MALFORMED_SNAPSHOT"


def test_timeout_is_unknown(monkeypatch):
    monkeypatch.setattr(surface, "_resolve_worker_binding", lambda: object())

    def timeout(_binding):
        raise subprocess.TimeoutExpired("psql", 8)

    monkeypatch.setattr(surface, "_execute_fixed_snapshot", timeout)
    result = surface.read_propertyai_pg_effect_surface(source_identity=SOURCE)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "POSTGRES_TIMEOUT"


def test_row_secret_payload_and_raw_stderr_never_leave_public_result(monkeypatch, tmp_path):
    secret = "DO-NOT-LEAK-PASSWORD"
    binding = _binding(tmp_path, secret=secret)
    monkeypatch.setattr(surface, "_resolve_worker_binding", lambda: binding)
    monkeypatch.setattr(surface.pg, "_revalidate_path_fingerprint", lambda *a, **k: None)

    def failed(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            1,
            b"",
            ("payload destination_ref external_effect_id " + secret).encode(),
        )

    monkeypatch.setattr(surface.subprocess, "run", failed)
    result = surface.read_propertyai_pg_effect_surface(source_identity=SOURCE)
    encoded = json.dumps(result, sort_keys=True)
    assert result["read_status"] == "UNKNOWN"
    assert result["reason_code"] == "POSTGRES_READ_FAILED"
    for forbidden in (secret, "destination_ref", "external_effect_id", "payload destination_ref"):
        assert forbidden not in encoded
    assert result["sensitive_payload_output"] == "NO"
    assert result["mutation_exercised"] == "NO"


def test_public_entrypoint_accepts_no_input(monkeypatch):
    called = False

    def fake_read(*, source_identity):
        nonlocal called
        called = True
        return surface._validated_read_result(_snapshot(), source_identity)

    monkeypatch.setattr(surface, "read_propertyai_pg_effect_surface", fake_read)
    output = io.StringIO()
    surface.main(io.StringIO('{"sql":"select secret"}'), output, source_identity=SOURCE)
    value = json.loads(output.getvalue())
    assert value["read_status"] == "UNKNOWN"
    assert value["reason_code"] == "PUBLIC_INPUT_REJECTED"
    assert called is False
    assert value["claimed_running_count"] is None


def test_success_output_contract_contains_only_sanitized_fields():
    result = surface._validated_read_result(_snapshot(), SOURCE)
    assert result == {
        "schema_version": 1,
        "read_status": "READ",
        "reason_code": "OK",
        "observed_at": result["observed_at"],
        "claimed_running_count": 1,
        "pending_outbox_effect_count": 2,
        "reconciliation_required_count": 3,
        "result_unknown_effect_count": 1,
        "other_actionable_effect_count": 4,
        "unexpected_status_count": 0,
        "database_name": "propertyai_cleaner_prod",
        "session_user": "propertyai_cleaner_worker",
        "current_user": "propertyai_async_worker",
        "controller_source_identity": {
            "commit": "a" * 40,
            "tree": "b" * 40,
            "source_clean": True,
            "entrypoint": "protected_pg_effect_surface_entrypoint.py",
        },
        "transaction_read_only": "on",
        "privilege_contract": "W07_FROZEN_V221",
        "sensitive_payload_output": "NO",
        "mutation_exercised": "NO",
    }
    forbidden = {
        "sql", "host", "port", "credential", "pgpass", "payload", "outbox_id",
        "aggregate_id", "destination_ref", "idempotency_key", "lease_owner",
        "external_effect_id", "last_error", "stderr",
    }
    assert forbidden.isdisjoint(result)
