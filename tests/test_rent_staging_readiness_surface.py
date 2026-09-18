from __future__ import annotations

from datetime import datetime, timezone
import inspect
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

import pytest

from adcp import rent_staging_readiness_surface as surface


SOURCE = surface.ControllerSourceIdentity("a" * 40, "b" * 40, True)


def _role_facts():
    return {
        role: {
            "exists": True,
            "can_login": True,
            "inherit": surface.EXPECTED_ROLE_INHERIT[role],
            "superuser": False,
            "create_db": False,
            "create_role": False,
            "replication": False,
            "bypass_rls": False,
            "database_connect": True,
            "contract_match": True,
        }
        for role in surface.EXPECTED_ROLES
    }


def _catalog(**updates):
    value = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "postgres_version": "18.6",
        "database_name": "propertyai_rent_staging",
        "session_user": "propertyai_flyway",
        "current_user": "propertyai_owner",
        "transaction_read_only": "on",
        "flyway_history_exists": False,
        "user_table_count": 0,
        "business_schema_count": 0,
        "role_facts": _role_facts(),
    }
    value.update(updates)
    return value


def _history():
    return [
        {
            "installed_rank": index,
            "version": version,
            "script": f"V{version}__fixed.sql",
            "checksum": checksum,
            "success": True,
        }
        for index, (version, checksum) in enumerate(surface.EXPECTED_MIGRATIONS, start=1)
    ]


def _secret_semantics():
    return {
        name: {
            "exists_and_private": "YES",
            "target_match": "YES",
            "role_match": "YES",
        }
        for name in surface.FIXED_SECRET_REFERENCES
    }


def _binding(password: str = "canary-secret"):
    return surface._DatabaseBinding(
        psql_path=Path("/fixed/psql"),
        host="127.0.0.1",
        port=55433,
        database="propertyai_rent_staging",
        user="propertyai_flyway",
        password=password,
    )


def test_public_schema_no_args_and_fixed_target_cannot_be_overridden(monkeypatch):
    signature = inspect.signature(surface.read_propertyai_rent_staging_readiness_surface)
    assert tuple(signature.parameters) == ("source_identity",)
    assert surface.TARGET_ID == "propertyai-rent-persistent-staging-pg18-55433"
    assert surface.EXPECTED_DATABASE == "propertyai_rent_staging"
    called = False

    def fake_read(*, source_identity):
        nonlocal called
        called = True
        return surface._unknown("DATABASE_READ_FAILED", source_identity)

    monkeypatch.setattr(surface, "read_propertyai_rent_staging_readiness_surface", fake_read)
    output = io.StringIO()
    surface.main(io.StringIO('{"target":"other","sql":"select 1"}'), output, source_identity=SOURCE)
    value = json.loads(output.getvalue())
    assert value["snapshot_status"] == "UNKNOWN"
    assert value["reason_code"] == "PUBLIC_INPUT_REJECTED"
    assert value["target_id"] == surface.TARGET_ID
    assert called is False


def test_read_only_transaction_is_server_forced_and_sql_is_fixed_select_allowlist():
    assert surface._fixed_env(password="x")["PGOPTIONS"] == (
        "-c role=propertyai_owner -c default_transaction_read_only=on -c statement_timeout=5000"
    )
    surface._assert_fixed_select_allowlist()
    assert len(surface.FIXED_SELECT_ALLOWLIST) == 3
    for sql in surface.FIXED_SELECT_ALLOWLIST:
        executable = surface._strip_sql_string_literals(sql).upper()
        assert executable.count(";") == 1
        assert executable.lstrip().startswith(("SELECT", "WITH"))
        for token in (
            " INSERT ", " UPDATE ", " DELETE ", " MERGE ", " CREATE ", " ALTER ",
            " DROP ", " TRUNCATE ", " CALL ", " COPY ", " FOR UPDATE",
            "PG_ADVISORY_", "NEXTVAL(", "SETVAL(",
        ):
            assert token not in f" {executable} "


def test_fixed_select_executor_rejects_non_allowlisted_sql():
    with pytest.raises(RuntimeError):
        surface._execute_fixed_select(_binding(), "SELECT 1;")


def test_generated_business_count_sql_is_valid_and_executable_on_disposable_postgres():
    initdb = Path(shutil.which("initdb") or "/opt/homebrew/opt/postgresql@18/bin/initdb")
    if not initdb.is_file():
        pytest.fail("PostgreSQL initdb is required for fixed SQL validation")
    pg_bin = initdb.parent
    with tempfile.TemporaryDirectory(prefix="rent-w5-fixed-sql-") as raw_root:
        root = Path(raw_root)
        data = root / "data"
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root)}
        subprocess.run(
            [
                str(pg_bin / "initdb"), "-D", str(data), "--auth=trust", "--no-locale",
                "-U", "rent_w5_sql_test", "-c", "shared_memory_type=mmap",
                "-c", "dynamic_shared_memory_type=mmap",
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        subprocess.run(
            [
                str(pg_bin / "pg_ctl"), "-D", str(data), "-l", str(root / "server.log"),
                "-o", f"-F -k {root} -c listen_addresses=''", "-w", "start",
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        try:
            schema_sql = [
                "CREATE SCHEMA propertyai;",
                "CREATE TABLE propertyai.organization (organization_id bigint PRIMARY KEY, data_environment text NOT NULL);",
            ]
            schema_sql.extend(
                f"CREATE TABLE propertyai.{table} (organization_id bigint NOT NULL);"
                for table in surface._BUSINESS_TABLES
            )
            subprocess.run(
                [
                    str(pg_bin / "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                    "-h", str(root), "-U", "rent_w5_sql_test", "-d", "postgres",
                ],
                input=("\n".join(schema_sql) + "\n").encode(),
                check=True,
                capture_output=True,
                env=env,
            )
            executed = subprocess.run(
                [
                    str(pg_bin / "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                    "-h", str(root), "-U", "rent_w5_sql_test", "-d", "postgres",
                ],
                input=(surface.FIXED_BUSINESS_COUNT_SELECT + "\n").encode(),
                check=True,
                capture_output=True,
                env=env,
            )
            result = json.loads(executed.stdout.decode().strip())
            assert result == {
                "real_rent_business_rows": 0,
                "fixture_rows": 0,
                "synthetic_financial_rows": 0,
            }
        finally:
            subprocess.run(
                [str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                check=False,
                capture_output=True,
                env=env,
            )


def test_fixed_catalog_select_enforces_exact_canonical_direct_role_graph():
    initdb = Path(shutil.which("initdb") or "/opt/homebrew/opt/postgresql@18/bin/initdb")
    if not initdb.is_file():
        pytest.fail("PostgreSQL initdb is required for fixed catalog SQL validation")
    pg_bin = initdb.parent
    with tempfile.TemporaryDirectory(prefix="rent-w5-role-sql-") as raw_root:
        root = Path(raw_root)
        data = root / "data"
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root)}
        subprocess.run(
            [
                str(pg_bin / "initdb"), "-D", str(data), "--auth=trust", "--no-locale",
                "-U", "rent_w5_sql_admin", "-c", "shared_memory_type=mmap",
                "-c", "dynamic_shared_memory_type=mmap",
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        subprocess.run(
            [
                str(pg_bin / "pg_ctl"), "-D", str(data), "-l", str(root / "server.log"),
                "-o", f"-F -k {root} -c listen_addresses=''", "-w", "start",
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        try:
            def admin_sql(sql: str) -> None:
                subprocess.run(
                    [
                        str(pg_bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1",
                        "-h", str(root), "-U", "rent_w5_sql_admin", "-d", "postgres",
                    ],
                    input=(sql.rstrip() + "\n").encode(),
                    check=True,
                    capture_output=True,
                    env=env,
                )

            role_sql = """
CREATE ROLE propertyai_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_migrator NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_flyway LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_app_runtime NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_rent_runtime NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_rent_scheduler NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_rent_staging_web LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_rent_staging_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_readonly NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_async_worker NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE propertyai_membership_probe NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT propertyai_owner TO propertyai_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT propertyai_migrator TO propertyai_flyway WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT propertyai_rent_runtime TO propertyai_rent_staging_web;
GRANT propertyai_app_runtime TO propertyai_rent_staging_web;
GRANT propertyai_rent_scheduler TO propertyai_rent_staging_worker;
CREATE SCHEMA propertyai AUTHORIZATION propertyai_owner;
"""
            admin_sql(role_sql)
            reader_env = dict(env)
            reader_env["PGOPTIONS"] = (
                "-c role=propertyai_owner -c default_transaction_read_only=on "
                "-c statement_timeout=5000"
            )

            def read_catalog() -> dict[str, object]:
                executed = subprocess.run(
                    [
                        str(pg_bin / "psql"), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                        "-h", str(root), "-U", "propertyai_flyway", "-d", "postgres",
                    ],
                    input=(surface.FIXED_CATALOG_SELECT + "\n").encode(),
                    check=True,
                    capture_output=True,
                    env=reader_env,
                )
                return json.loads(executed.stdout.decode().rsplit("|", 1)[0])

            def assert_canonical(catalog: dict[str, object]) -> None:
                role_facts = catalog["role_facts"]
                assert catalog["session_user"] == "propertyai_flyway"
                assert catalog["current_user"] == "propertyai_owner"
                assert role_facts["propertyai_flyway"]["contract_match"] is True
                assert role_facts["propertyai_flyway"]["inherit"] is False
                assert role_facts["propertyai_rent_staging_web"]["contract_match"] is True
                assert role_facts["propertyai_rent_staging_worker"]["contract_match"] is True

            assert_canonical(read_catalog())

            adversarial_cases = (
                (
                    "web_extra_propertyai_readonly",
                    "GRANT propertyai_readonly TO propertyai_rent_staging_web;",
                    "propertyai_rent_staging_web",
                    "REVOKE propertyai_readonly FROM propertyai_rent_staging_web;",
                ),
                (
                    "worker_extra_propertyai_async_worker",
                    "GRANT propertyai_async_worker TO propertyai_rent_staging_worker;",
                    "propertyai_rent_staging_worker",
                    "REVOKE propertyai_async_worker FROM propertyai_rent_staging_worker;",
                ),
                (
                    "flyway_extra_set_enabled_propertyai_readonly",
                    (
                        "GRANT propertyai_readonly TO propertyai_flyway "
                        "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;"
                    ),
                    "propertyai_flyway",
                    "REVOKE propertyai_readonly FROM propertyai_flyway;",
                ),
                (
                    "unexpected_role_with_distinct_membership_options",
                    (
                        "GRANT propertyai_membership_probe TO propertyai_rent_staging_worker "
                        "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;"
                    ),
                    "propertyai_rent_staging_worker",
                    "REVOKE propertyai_membership_probe FROM propertyai_rent_staging_worker;",
                ),
            )
            for case_name, grant_sql, checked_role, revoke_sql in adversarial_cases:
                admin_sql(grant_sql)
                adversarial = read_catalog()
                assert (
                    adversarial["role_facts"][checked_role]["contract_match"] is False
                ), case_name
                admin_sql(revoke_sql)
                assert_canonical(read_catalog())

            admin_sql(
                """
REVOKE propertyai_rent_runtime FROM propertyai_rent_staging_web;
GRANT propertyai_rent_runtime TO propertyai_rent_staging_web
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
"""
            )
            option_drift = read_catalog()
            assert (
                option_drift["role_facts"]["propertyai_rent_staging_web"]["contract_match"]
                is False
            )
            admin_sql(
                """
REVOKE propertyai_rent_runtime FROM propertyai_rent_staging_web;
GRANT propertyai_rent_runtime TO propertyai_rent_staging_web;
"""
            )
            assert_canonical(read_catalog())
        finally:
            subprocess.run(
                [str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                check=False,
                capture_output=True,
                env=env,
            )


def test_database_observations_share_one_repeatable_read_snapshot(monkeypatch):
    calls = []
    first_epoch = _catalog(observed_at="2026-09-17T13:00:00+00:00")
    second_epoch = _catalog(observed_at="2026-09-17T13:01:00+00:00")

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        epoch = first_epoch if len(calls) == 1 else second_epoch
        stdout = (
            json.dumps(epoch, separators=(",", ":"))
            + surface._PSQL_FIELD_SEPARATOR
            + "false"
            + surface._PSQL_RECORD_SEPARATOR
            + "[]"
            + surface._PSQL_RECORD_SEPARATOR
            + "{}"
            + surface._PSQL_RECORD_SEPARATOR
        ).encode()
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    catalog, history, business_counts = surface._execute_fixed_snapshot(_binding())
    assert len(calls) == 1
    script = calls[0][1]["input"].decode()
    assert script.count("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;") == 1
    assert script.count("COMMIT;") == 1
    assert surface.FIXED_HISTORY_SELECT in script
    assert surface.FIXED_BUSINESS_COUNT_SELECT in script
    assert catalog["observed_at"] == first_epoch["observed_at"]
    assert catalog["observed_at"] != second_epoch["observed_at"]
    result = surface._validated_snapshot(
        catalog=catalog,
        history=history,
        business_counts=business_counts,
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "PASS"
    assert len(calls) == 1


def test_fixed_snapshot_parser_accepts_multiline_history_record():
    catalog = _catalog(observed_at="2026-09-17T13:00:00+00:00")
    catalog["flyway_history_exists"] = True
    history = [
        {
            "installed_rank": index,
            "version": version,
            "script": f"V{version}__test.sql",
            "checksum": checksum,
            "success": True,
        }
        for index, (version, checksum) in enumerate(surface.EXPECTED_MIGRATIONS, start=1)
    ]
    history_text = json.dumps(history, indent=1)
    counts = {
        "real_rent_business_rows": 0,
        "fixture_rows": 0,
        "synthetic_financial_rows": 0,
    }
    stdout = (
        json.dumps(catalog, separators=(",", ":"))
        + surface._PSQL_FIELD_SEPARATOR
        + "true"
        + surface._PSQL_RECORD_SEPARATOR
        + history_text
        + surface._PSQL_RECORD_SEPARATOR
        + json.dumps(counts, separators=(",", ":"))
        + surface._PSQL_RECORD_SEPARATOR
    )
    parsed_catalog, parsed_history, parsed_counts = surface._parse_fixed_snapshot(stdout)
    assert parsed_catalog == catalog
    assert parsed_history == history
    assert parsed_counts == counts


def test_service_reader_uses_only_fixed_label(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            argv,
            0,
            b"state = running\npid = 12345\n",
            b"",
        )

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    state, pid = surface._read_fixed_service_state()
    assert (state, pid) == ("RUNNING", 12345)
    assert captured["argv"] == [
        "/bin/launchctl",
        "print",
        f"gui/{surface.os.getuid()}/com.propertyai.postgresql-rent-staging",
    ]
    assert captured["shell"] is False


def test_service_inspection_error_returns_unknown_and_cannot_be_normalized_to_pass(monkeypatch):
    raw_error = b"permission denied while inspecting runtime-private-detail"

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 5, b"", raw_error)

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    result = surface.read_propertyai_rent_staging_readiness_surface(source_identity=SOURCE)
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "SERVICE_READ_FAILED"
    assert result["service_state"] == "UNKNOWN"
    assert result["service_pid"] == "UNKNOWN"
    encoded = json.dumps(result, sort_keys=True)
    assert raw_error.decode() not in encoded
    assert "runtime-private-detail" not in encoded


def test_confirmed_launchd_not_loaded_is_not_running_and_preserves_readiness_contract(monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            113,
            b"",
            b"Could not find service; not loaded",
        )

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    state, pid = surface._read_fixed_service_state()
    assert (state, pid) == ("NOT_RUNNING", "UNKNOWN")
    result = surface._validated_snapshot(
        catalog=_catalog(),
        history=[],
        business_counts={},
        service_state=state,
        service_pid=pid,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "PASS"
    assert result["service_state"] == "NOT_RUNNING"


def test_database_identity_mismatch_fails_closed():
    result = surface._validated_snapshot(
        catalog=_catalog(database_name="other"),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "DATABASE_IDENTITY_MISMATCH"
    assert result["flyway_history_rows"] == "UNKNOWN"
    assert result["real_rent_business_rows"] == "UNKNOWN"


def test_db_failure_returns_unknown_not_zero(monkeypatch):
    monkeypatch.setattr(surface, "_read_fixed_service_state", lambda: ("RUNNING", 111))
    monkeypatch.setattr(surface, "_resolve_secret_references", lambda: (_secret_semantics(), _binding()))

    def failed(*_args, **_kwargs):
        raise RuntimeError("DATABASE_READ_FAILED")

    monkeypatch.setattr(surface, "_execute_fixed_snapshot", failed)
    result = surface.read_propertyai_rent_staging_readiness_surface(source_identity=SOURCE)
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "DATABASE_READ_FAILED"
    for field in (
        "flyway_history_rows", "user_table_count", "business_schema_count",
        "real_rent_business_rows", "fixture_rows", "synthetic_financial_rows",
    ):
        assert result[field] == "UNKNOWN"


def test_current_user_mismatch_returns_database_identity_unknown():
    result = surface._validated_snapshot(
        catalog=_catalog(current_user="propertyai_flyway"),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "DATABASE_IDENTITY_MISMATCH"


def test_role_permission_failure_returns_unknown():
    roles = _role_facts()
    roles["propertyai_rent_staging_worker"]["superuser"] = True
    result = surface._validated_snapshot(
        catalog=_catalog(role_facts=roles),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "ROLE_PERMISSION_MISMATCH"
    assert result["role_facts"]["propertyai_rent_staging_worker"]["superuser"] == "UNKNOWN"


def test_role_membership_contract_failure_returns_unknown():
    roles = _role_facts()
    roles["propertyai_flyway"]["contract_match"] = False
    result = surface._validated_snapshot(
        catalog=_catalog(role_facts=roles),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "ROLE_PERMISSION_MISMATCH"


def test_secret_reference_content_never_serialized_and_roles_are_sanitized(monkeypatch, tmp_path):
    root = tmp_path / "secret-refs"
    root.mkdir()
    canary = "DO-NOT-SERIALIZE-CANARY"
    files = {
        "flyway-secret.conf": (
            "flyway.url=jdbc:postgresql://127.0.0.1:55433/propertyai_rent_staging\n"
            "flyway.user=propertyai_flyway\n"
            f"flyway.password={canary}\n"
        ),
        "web.dsn": f"host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=propertyai_rent_staging_web password={canary}",
        "session.dsn": f"host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=propertyai_rent_staging_web password={canary}",
        "worker.dsn": f"host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=propertyai_rent_staging_worker password={canary}",
    }
    for name, content in files.items():
        path = root / name
        path.write_text(content, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setattr(surface, "SECRET_REFERENCE_ROOT", root)
    semantics, binding = surface._resolve_secret_references()
    assert binding.password == canary
    assert binding.user == "propertyai_flyway"
    assert semantics == _secret_semantics()
    assert canary not in json.dumps(semantics, sort_keys=True)
    assert set(semantics) == set(surface.FIXED_SECRET_REFERENCES)


def test_secret_target_or_role_mismatch_is_not_accepted(monkeypatch, tmp_path):
    root = tmp_path / "secret-refs"
    root.mkdir()
    valid = {
        "flyway-secret.conf": "flyway.url=jdbc:postgresql://127.0.0.1:55433/propertyai_rent_staging\nflyway.user=propertyai_flyway\nflyway.password=x\n",
        "web.dsn": "host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=wrong password=x",
        "session.dsn": "host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=propertyai_rent_staging_web password=x",
        "worker.dsn": "host=127.0.0.1 port=55433 dbname=propertyai_rent_staging user=propertyai_rent_staging_worker password=x",
    }
    for name, content in valid.items():
        path = root / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
    monkeypatch.setattr(surface, "SECRET_REFERENCE_ROOT", root)
    with pytest.raises(RuntimeError, match="SECRET_REFERENCE_INVALID"):
        surface._resolve_secret_references()


def test_expected_migration_history_and_business_counts_are_sanitized():
    result = surface._validated_snapshot(
        catalog=_catalog(
            flyway_history_exists=True,
            user_table_count=42,
            business_schema_count=1,
        ),
        history=_history(),
        business_counts={
            "real_rent_business_rows": 0,
            "fixture_rows": 12,
            "synthetic_financial_rows": 7,
        },
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "PASS"
    assert result["migration_history_class"] == "EXPECTED"
    assert result["flyway_history_rows"] == 12
    assert result["real_rent_business_rows"] == 0
    assert result["fixture_rows"] == 12
    assert result["synthetic_financial_rows"] == 7
    assert result["secret_output"] == "NONE"


def test_fresh_history_is_explicit_not_invented_expected():
    result = surface._validated_snapshot(
        catalog=_catalog(flyway_history_exists=False, user_table_count=0),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "PASS"
    assert result["migration_history_class"] == "FRESH"
    assert result["flyway_history_rows"] == 0


def test_migration_checksum_drift_fails_closed():
    history = _history()
    history[-1]["checksum"] += 1
    result = surface._validated_snapshot(
        catalog=_catalog(flyway_history_exists=True, user_table_count=42),
        history=history,
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "MIGRATION_MISMATCH"
    assert result["flyway_history_rows"] == "UNKNOWN"


def test_malformed_partial_snapshot_fails_closed(monkeypatch):
    monkeypatch.setattr(surface, "_read_fixed_service_state", lambda: ("RUNNING", 111))
    monkeypatch.setattr(surface, "_resolve_secret_references", lambda: (_secret_semantics(), _binding()))
    monkeypatch.setattr(
        surface,
        "_execute_fixed_snapshot",
        lambda *_args: ({"observed_at": "partial"}, [], {}),
    )
    result = surface.read_propertyai_rent_staging_readiness_surface(source_identity=SOURCE)
    assert result["snapshot_status"] == "UNKNOWN"
    assert result["reason_code"] == "MALFORMED_SNAPSHOT"
    assert result["database_identity"] == "UNKNOWN"
    assert result["fixture_rows"] == "UNKNOWN"


def test_no_unrelated_role_or_raw_row_fields_are_exposed():
    result = surface._validated_snapshot(
        catalog=_catalog(),
        history=[],
        business_counts={},
        service_state="RUNNING",
        service_pid=111,
        secret_semantics=_secret_semantics(),
        source_identity=SOURCE,
    )
    encoded = json.dumps(result, sort_keys=True)
    for forbidden in (
        "password=", "postgresql://", "token", "guest", "resident_name", "party_id",
        "contract_id", "receivable_id", "movement_id", "row_payload",
    ):
        assert forbidden not in encoded.lower()
    assert set(result["role_facts"]) == set(surface.EXPECTED_ROLES)
    assert "propertyai_cleaner_worker" not in encoded


def test_fixed_database_execution_has_no_shell_and_no_ambient_environment(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, b'{"ok":true}\n', b"")

    monkeypatch.setattr(surface.subprocess, "run", fake_run)
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-flow")
    output = surface._execute_fixed_select(_binding(), surface.FIXED_CATALOG_SELECT)
    assert output == '{"ok":true}\n'
    assert captured["shell"] is False
    assert captured["argv"][-5:] == [
        "--tuples-only", "--no-align", "--host=127.0.0.1", "--port=55433",
        "--dbname=propertyai_rent_staging", "--username=propertyai_flyway",
    ][-5:]
    assert captured["env"]["PGPASSWORD"] == "canary-secret"
    assert "UNRELATED_SECRET" not in captured["env"]
    assert captured["input"] == (surface.FIXED_CATALOG_SELECT + "\n").encode()
