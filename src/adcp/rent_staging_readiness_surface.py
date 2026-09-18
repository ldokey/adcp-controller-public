"""Closed-world read-only readiness snapshot for the fixed Rent staging target.

The public capability owns exactly one target, service label, database, credential
set, role set and SQL allowlist. Caller input never influences SQL, paths, host,
port, database, credential, role, executable or service identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
from typing import Any, Mapping, TextIO
from urllib.parse import unquote, urlparse


SCHEMA_VERSION = 1
READER_CONTRACT_VERSION = "RENT_W5_STAGING_READINESS_V1"
TARGET_ID = "propertyai-rent-persistent-staging-pg18-55433"
EXPECTED_DATABASE = "propertyai_rent_staging"
FIXED_HOST = "127.0.0.1"
FIXED_PORT = 55433
FIXED_SERVICE_LABEL = "com.propertyai.postgresql-rent-staging"
FIXED_PSQL = Path("/opt/homebrew/Cellar/postgresql@18/18.6/bin/psql")
FIXED_LAUNCHCTL = Path("/bin/launchctl")
SECRET_REFERENCE_ROOT = Path(
    "/Users/kate/DKATE/propertyai-runtime/postgres/rent-staging-pg18/secret-refs"
)
FIXED_SECRET_REFERENCES = (
    "flyway-secret.conf",
    "web.dsn",
    "session.dsn",
    "worker.dsn",
)
EXPECTED_REFERENCE_ROLES = {
    "flyway-secret.conf": "propertyai_flyway",
    "web.dsn": "propertyai_rent_staging_web",
    "session.dsn": "propertyai_rent_staging_web",
    "worker.dsn": "propertyai_rent_staging_worker",
}
EXPECTED_ROLES = (
    "propertyai_flyway",
    "propertyai_rent_staging_web",
    "propertyai_rent_staging_worker",
)
EXPECTED_ROLE_INHERIT = {
    "propertyai_flyway": False,
    "propertyai_rent_staging_web": True,
    "propertyai_rent_staging_worker": True,
}
TRUSTED_CHILD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PROCESS_TIMEOUT_SECONDS = 8.0
MAX_STDOUT_BYTES = 64 * 1024
_PSQL_FIELD_SEPARATOR = "\x1f"
_PSQL_RECORD_SEPARATOR = "\x00"

# Exact 12-migration artifact contract for the bound Product source.
EXPECTED_MIGRATIONS = (
    ("20260904.101", 1183079582),
    ("20260904.102", -929617548),
    ("20260904.103", -926192525),
    ("20260904.104", 238888746),
    ("20260904.105", 306727252),
    ("20260904.106", -1394079808),
    ("20260904.107", 1216413105),
    ("20260904.108", 748018122),
    ("20260904.109", 1167950689),
    ("20260904.110", 1470762549),
    ("20260904.111", 694200330),
    ("20260904.112", 327457375),
)

REASON_CODES = (
    "OK",
    "PUBLIC_INPUT_REJECTED",
    "SERVICE_READ_FAILED",
    "SECRET_REFERENCE_INVALID",
    "DATABASE_READ_FAILED",
    "DATABASE_IDENTITY_MISMATCH",
    "TRANSACTION_NOT_READ_ONLY",
    "MIGRATION_MISMATCH",
    "ROLE_PERMISSION_MISMATCH",
    "MALFORMED_SNAPSHOT",
    "OUTPUT_LIMIT",
    "SENSITIVE_OUTPUT_DETECTED",
    "INTERNAL_READ_FAILURE",
    "SOURCE_ORIGIN_MISMATCH",
    "ENTRYPOINT_IDENTITY_MISMATCH",
    "CONTROLLER_ROOT_MISMATCH",
    "CONTROLLER_HEAD_MISMATCH",
    "CONTROLLER_DIRTY",
    "SOURCE_SHADOW_MISMATCH",
    "BOOTSTRAP_INTERNAL_FAILURE",
)
_REASON_CODE_SET = frozenset(REASON_CODES)


@dataclass(frozen=True)
class ControllerSourceIdentity:
    commit: str
    tree: str
    source_clean: bool
    entrypoint: str = "rent_staging_readiness_surface_entrypoint.py"


@dataclass(frozen=True)
class _DatabaseBinding:
    psql_path: Path
    host: str
    port: int
    database: str
    user: str
    password: str


def _unknown_role_facts() -> dict[str, dict[str, str]]:
    return {
        role: {
            "exists": "UNKNOWN",
            "can_login": "UNKNOWN",
            "inherit": "UNKNOWN",
            "superuser": "UNKNOWN",
            "create_db": "UNKNOWN",
            "create_role": "UNKNOWN",
            "replication": "UNKNOWN",
            "bypass_rls": "UNKNOWN",
            "database_connect": "UNKNOWN",
            "expected_attributes_match": "UNKNOWN",
        }
        for role in EXPECTED_ROLES
    }


def _unknown_secret_semantics() -> dict[str, dict[str, str]]:
    return {
        name: {
            "exists_and_private": "UNKNOWN",
            "target_match": "UNKNOWN",
            "role_match": "UNKNOWN",
        }
        for name in FIXED_SECRET_REFERENCES
    }


def _public_result(
    *,
    snapshot_status: str,
    reason_code: str,
    source_identity: ControllerSourceIdentity,
    observed_at: str | None = None,
    service_state: str = "UNKNOWN",
    service_pid: int | str = "UNKNOWN",
    postgres_version: str = "UNKNOWN",
    database_identity: str = "UNKNOWN",
    database_target_match: str = "UNKNOWN",
    migration_history_class: str = "UNKNOWN",
    flyway_history_rows: int | str = "UNKNOWN",
    user_table_count: int | str = "UNKNOWN",
    business_schema_count: int | str = "UNKNOWN",
    real_rent_business_rows: int | str = "UNKNOWN",
    fixture_rows: int | str = "UNKNOWN",
    synthetic_financial_rows: int | str = "UNKNOWN",
    role_facts: Mapping[str, Mapping[str, str]] | None = None,
    secret_reference_semantics: Mapping[str, Mapping[str, str]] | None = None,
    transaction_read_only: str = "UNKNOWN",
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "reader_contract_version": READER_CONTRACT_VERSION,
        "snapshot_status": snapshot_status,
        "reason_code": reason_code,
        "observed_at": observed_at,
        "target_id": TARGET_ID,
        "service_label": FIXED_SERVICE_LABEL,
        "service_state": service_state,
        "service_pid": service_pid,
        "postgres_version": postgres_version,
        "database_identity": database_identity,
        "database_target_match": database_target_match,
        "migration_history_class": migration_history_class,
        "flyway_history_rows": flyway_history_rows,
        "user_table_count": user_table_count,
        "business_schema_count": business_schema_count,
        "real_rent_business_rows": real_rent_business_rows,
        "fixture_rows": fixture_rows,
        "synthetic_financial_rows": synthetic_financial_rows,
        "role_facts": dict(role_facts or _unknown_role_facts()),
        "secret_reference_semantics": dict(
            secret_reference_semantics or _unknown_secret_semantics()
        ),
        "controller_source_identity": {
            "commit": source_identity.commit,
            "tree": source_identity.tree,
            "source_clean": source_identity.source_clean,
            "entrypoint": source_identity.entrypoint,
        },
        "transaction_read_only": transaction_read_only,
        "secret_output": "NONE",
        "mutation_exercised": "NO",
    }


def _unknown(
    reason_code: str,
    source_identity: ControllerSourceIdentity,
    *,
    service_state: str = "UNKNOWN",
    service_pid: int | str = "UNKNOWN",
    secret_reference_semantics: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    if reason_code not in _REASON_CODE_SET or reason_code == "OK":
        reason_code = "INTERNAL_READ_FAILURE"
    return _public_result(
        snapshot_status="UNKNOWN",
        reason_code=reason_code,
        source_identity=source_identity,
        service_state=service_state,
        service_pid=service_pid,
        secret_reference_semantics=secret_reference_semantics,
    )


def _fixed_env(*, password: str | None = None) -> dict[str, str]:
    env = {
        "PATH": TRUSTED_CHILD_PATH,
        "LC_ALL": "C",
        "PGREQUIREAUTH": "scram-sha-256",
        "PGCONNECT_TIMEOUT": "5",
        "PGOPTIONS": (
            "-c role=propertyai_owner "
            "-c default_transaction_read_only=on -c statement_timeout=5000"
        ),
    }
    if password is not None:
        env["PGPASSWORD"] = password
    return env


def _read_fixed_service_state() -> tuple[str, int | str]:
    try:
        completed = subprocess.run(
            [str(FIXED_LAUNCHCTL), "print", f"gui/{os.getuid()}/{FIXED_SERVICE_LABEL}"],
            capture_output=True,
            check=False,
            shell=False,
            env={"PATH": TRUSTED_CHILD_PATH, "LC_ALL": "C"},
            timeout=PROCESS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("SERVICE_READ_FAILED") from error
    if len(completed.stdout) > MAX_STDOUT_BYTES or len(completed.stderr) > MAX_STDOUT_BYTES:
        raise RuntimeError("OUTPUT_LIMIT")
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
        error_text = completed.stderr.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise RuntimeError("SERVICE_READ_FAILED") from error
    known_not_loaded = (
        completed.returncode == 113
        and (
            "not loaded" in error_text.lower()
            or "could not find service" in error_text.lower()
            or "could not find service" in text.lower()
        )
    )
    if completed.returncode != 0:
        if known_not_loaded:
            return "NOT_RUNNING", "UNKNOWN"
        raise RuntimeError("SERVICE_READ_FAILED")
    state_match = re.search(r"(?m)^\s*state\s*=\s*(.+?)\s*$", text)
    pid_match = re.search(r"(?m)^\s*pid\s*=\s*(\d+)\s*$", text)
    if state_match is None:
        raise RuntimeError("SERVICE_READ_FAILED")
    declared_state = state_match.group(1).strip().lower()
    if declared_state == "running":
        if pid_match is None or int(pid_match.group(1)) <= 0:
            raise RuntimeError("SERVICE_READ_FAILED")
        return "RUNNING", int(pid_match.group(1))
    if declared_state in {"inactive", "not running"}:
        return "NOT_RUNNING", "UNKNOWN"
    raise RuntimeError("SERVICE_READ_FAILED")


def _read_private_regular(path: Path) -> str:
    if path.parent != SECRET_REFERENCE_ROOT or path.name not in FIXED_SECRET_REFERENCES:
        raise ValueError("SECRET_REFERENCE_PATH_INVALID")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("SECRET_REFERENCE_NOT_REGULAR")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("SECRET_REFERENCE_MODE_INVALID")
    text = path.read_text(encoding="utf-8")
    if not text or "\x00" in text:
        raise ValueError("SECRET_REFERENCE_CONTENT_INVALID")
    return text


def _parse_dsn(text: str) -> dict[str, str]:
    if text != text.strip():
        raise ValueError("DSN_WHITESPACE_INVALID")
    if text.startswith(("postgres://", "postgresql://")):
        parsed = urlparse(text)
        if parsed.scheme not in {"postgres", "postgresql"} or parsed.hostname is None:
            raise ValueError("DSN_INVALID")
        return {
            "host": parsed.hostname,
            "port": str(parsed.port or 5432),
            "dbname": parsed.path.lstrip("/"),
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
        }
    values: dict[str, str] = {}
    for token in shlex.split(text):
        if "=" not in token:
            raise ValueError("DSN_INVALID")
        key, value = token.split("=", 1)
        if key in values:
            raise ValueError("DSN_DUPLICATE_KEY")
        values[key] = value
    return {
        "host": values.get("host", ""),
        "port": values.get("port", "5432"),
        "dbname": values.get("dbname", values.get("database", "")),
        "user": values.get("user", ""),
        "password": values.get("password", ""),
    }


def _parse_flyway_secret(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw.lstrip().startswith("#"):
            continue
        if "=" not in raw:
            raise ValueError("FLYWAY_SECRET_INVALID")
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip()
    url = values.get("flyway.url", "")
    prefix = "jdbc:postgresql://"
    if not url.startswith(prefix):
        raise ValueError("FLYWAY_URL_INVALID")
    parsed = urlparse("postgresql://" + url[len(prefix):])
    if parsed.hostname is None:
        raise ValueError("FLYWAY_URL_INVALID")
    return {
        "host": parsed.hostname,
        "port": str(parsed.port or 5432),
        "dbname": parsed.path.lstrip("/"),
        "user": values.get("flyway.user", ""),
        "password": values.get("flyway.password", ""),
    }


def _target_and_role_match(info: Mapping[str, str], expected_role: str) -> tuple[str, str]:
    target_match = "YES" if (
        info.get("host") == FIXED_HOST
        and info.get("port") == str(FIXED_PORT)
        and info.get("dbname") == EXPECTED_DATABASE
    ) else "NO"
    role_match = "YES" if info.get("user") == expected_role else "NO"
    return target_match, role_match


def _resolve_secret_references() -> tuple[dict[str, dict[str, str]], _DatabaseBinding]:
    semantics: dict[str, dict[str, str]] = {}
    flyway_info: dict[str, str] | None = None
    for name in FIXED_SECRET_REFERENCES:
        try:
            text = _read_private_regular(SECRET_REFERENCE_ROOT / name)
            info = _parse_flyway_secret(text) if name == "flyway-secret.conf" else _parse_dsn(text)
            target_match, role_match = _target_and_role_match(
                info, EXPECTED_REFERENCE_ROLES[name]
            )
            semantics[name] = {
                "exists_and_private": "YES",
                "target_match": target_match,
                "role_match": role_match,
            }
            if name == "flyway-secret.conf":
                flyway_info = info
        except (OSError, UnicodeError, ValueError):
            semantics[name] = {
                "exists_and_private": "NO",
                "target_match": "UNKNOWN",
                "role_match": "UNKNOWN",
            }
    expected_ok = {
        "exists_and_private": "YES",
        "target_match": "YES",
        "role_match": "YES",
    }
    if any(semantics.get(name) != expected_ok for name in FIXED_SECRET_REFERENCES):
        raise RuntimeError("SECRET_REFERENCE_INVALID")
    if flyway_info is None or not flyway_info.get("password"):
        raise RuntimeError("SECRET_REFERENCE_INVALID")
    return semantics, _DatabaseBinding(
        psql_path=FIXED_PSQL,
        host=FIXED_HOST,
        port=FIXED_PORT,
        database=EXPECTED_DATABASE,
        user=EXPECTED_REFERENCE_ROLES["flyway-secret.conf"],
        password=flyway_info["password"],
    )


FIXED_CATALOG_SELECT = """
WITH fixed_roles(role_name) AS (
  VALUES
    ('propertyai_flyway'::text),
    ('propertyai_rent_staging_web'::text),
    ('propertyai_rent_staging_worker'::text)
), expected_direct_memberships(member_role,granted_role,admin_option,inherit_option,set_option) AS (
  VALUES
    ('propertyai_flyway'::text,'propertyai_migrator'::text,false,false,true),
    ('propertyai_migrator'::text,'propertyai_owner'::text,false,false,true),
    ('propertyai_rent_staging_web'::text,'propertyai_rent_runtime'::text,false,true,true),
    ('propertyai_rent_staging_web'::text,'propertyai_app_runtime'::text,false,true,true),
    ('propertyai_rent_staging_worker'::text,'propertyai_rent_scheduler'::text,false,true,true)
), actual_direct_memberships AS (
  SELECT member_role.rolname::text AS member_role,
         granted_role.rolname::text AS granted_role,
         m.admin_option,
         m.inherit_option,
         m.set_option
  FROM pg_catalog.pg_auth_members m
  JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=m.roleid
  JOIN pg_catalog.pg_roles member_role ON member_role.oid=m.member
  WHERE member_role.rolname IN (
    'propertyai_flyway',
    'propertyai_migrator',
    'propertyai_rent_staging_web',
    'propertyai_rent_staging_worker'
  )
), exact_direct_membership AS (
  SELECT candidate.member_role,
         (
           SELECT COALESCE(
             pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_array(
                 actual.granted_role,
                 actual.admin_option,
                 actual.inherit_option,
                 actual.set_option
               )
               ORDER BY actual.granted_role,
                        actual.admin_option,
                        actual.inherit_option,
                        actual.set_option
             ),
             '[]'::pg_catalog.jsonb
           )
           FROM actual_direct_memberships actual
           WHERE actual.member_role=candidate.member_role
         ) = (
           SELECT COALESCE(
             pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_array(
                 expected.granted_role,
                 expected.admin_option,
                 expected.inherit_option,
                 expected.set_option
               )
               ORDER BY expected.granted_role,
                        expected.admin_option,
                        expected.inherit_option,
                        expected.set_option
             ),
             '[]'::pg_catalog.jsonb
           )
           FROM expected_direct_memberships expected
           WHERE expected.member_role=candidate.member_role
         ) AS contract_match
  FROM (
    VALUES
      ('propertyai_flyway'::text),
      ('propertyai_migrator'::text),
      ('propertyai_rent_staging_web'::text),
      ('propertyai_rent_staging_worker'::text)
  ) AS candidate(member_role)
), role_facts AS (
  SELECT f.role_name,
         (r.oid IS NOT NULL) AS exists,
         COALESCE(r.rolcanlogin,false) AS can_login,
         COALESCE(r.rolinherit,false) AS inherit,
         COALESCE(r.rolsuper,false) AS superuser,
         COALESCE(r.rolcreatedb,false) AS create_db,
         COALESCE(r.rolcreaterole,false) AS create_role,
         COALESCE(r.rolreplication,false) AS replication,
         COALESCE(r.rolbypassrls,false) AS bypass_rls,
         CASE WHEN r.oid IS NULL THEN false
              ELSE pg_catalog.has_database_privilege(f.role_name,pg_catalog.current_database(),'CONNECT')
         END AS database_connect,
         CASE f.role_name
           WHEN 'propertyai_flyway' THEN
             COALESCE((
               SELECT exact.contract_match
               FROM exact_direct_membership exact
               WHERE exact.member_role='propertyai_flyway'
             ),false)
             AND COALESCE((
               SELECT exact.contract_match
               FROM exact_direct_membership exact
               WHERE exact.member_role='propertyai_migrator'
             ),false)
           WHEN 'propertyai_rent_staging_web' THEN
             COALESCE((
               SELECT exact.contract_match
               FROM exact_direct_membership exact
               WHERE exact.member_role='propertyai_rent_staging_web'
             ),false)
           WHEN 'propertyai_rent_staging_worker' THEN
             COALESCE((
               SELECT exact.contract_match
               FROM exact_direct_membership exact
               WHERE exact.member_role='propertyai_rent_staging_worker'
             ),false)
           ELSE false
         END AS contract_match
  FROM fixed_roles f LEFT JOIN pg_catalog.pg_roles r ON r.rolname=f.role_name
)
SELECT pg_catalog.json_build_object(
  'observed_at',pg_catalog.transaction_timestamp(),
  'postgres_version',pg_catalog.split_part(pg_catalog.current_setting('server_version'),' ',1),
  'database_name',pg_catalog.current_database(),
  'session_user',session_user::text,
  'current_user',current_user::text,
  'transaction_read_only',pg_catalog.current_setting('transaction_read_only'),
  'flyway_history_exists',pg_catalog.to_regclass('propertyai.flyway_schema_history') IS NOT NULL,
  'user_table_count',(SELECT count(*)::bigint FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast'),
  'business_schema_count',(SELECT count(*)::bigint FROM pg_catalog.pg_namespace WHERE nspname='propertyai'),
  'role_facts',(SELECT pg_catalog.json_object_agg(role_name,pg_catalog.json_build_object('exists',exists,'can_login',can_login,'inherit',inherit,'superuser',superuser,'create_db',create_db,'create_role',create_role,'replication',replication,'bypass_rls',bypass_rls,'database_connect',database_connect,'contract_match',contract_match)) FROM role_facts)
)::text AS catalog_json,
CASE WHEN pg_catalog.to_regclass('propertyai.flyway_schema_history') IS NOT NULL
     THEN 'true' ELSE 'false' END AS flyway_history_exists;
""".strip()

FIXED_HISTORY_SELECT = """
SELECT COALESCE(pg_catalog.json_agg(x ORDER BY x.installed_rank),'[]'::json)::text
FROM (
  SELECT installed_rank::bigint,version::text,script::text,checksum::bigint,success::boolean
  FROM propertyai.flyway_schema_history
) x;
""".strip()

_BUSINESS_TABLES = (
    "finance_ledger_scope",
    "finance_command",
    "rent_resident",
    "rent_contract",
    "rent_contract_history",
    "rent_contract_party",
    "rent_contract_resident",
    "rent_term_revision",
    "rent_billing_period",
    "rent_occupancy",
    "finance_account",
    "finance_receivable",
    "finance_receivable_line",
    "finance_receivable_adjustment",
    "finance_movement",
    "finance_movement_revision",
    "finance_funding_source",
    "finance_allocation",
    "finance_source_return",
    "rent_auth_session",
)
_FINANCIAL_TABLES = tuple(name for name in _BUSINESS_TABLES if name.startswith("finance_"))


def _row_count_expression(tables: tuple[str, ...], *, test: bool) -> str:
    predicate = "o.data_environment='TEST'" if test else "o.data_environment<>'TEST'"
    return " + ".join(
        f"(SELECT count(*) FROM propertyai.{table} t JOIN propertyai.organization o ON o.organization_id=t.organization_id WHERE {predicate})"
        for table in tables
    ) or "0"


FIXED_BUSINESS_COUNT_SELECT = f"""
SELECT pg_catalog.json_build_object(
  'real_rent_business_rows',({_row_count_expression(_BUSINESS_TABLES, test=False)})::bigint,
  'fixture_rows',({_row_count_expression(_BUSINESS_TABLES, test=True)})::bigint,
  'synthetic_financial_rows',({_row_count_expression(_FINANCIAL_TABLES, test=True)})::bigint
)::text;
""".strip()

FIXED_SELECT_ALLOWLIST = (
    FIXED_CATALOG_SELECT,
    FIXED_HISTORY_SELECT,
    FIXED_BUSINESS_COUNT_SELECT,
)


def _strip_sql_string_literals(sql: str) -> str:
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
        raise RuntimeError("FIXED_SQL_LITERAL_UNTERMINATED")
    return "".join(result)


def _assert_fixed_select_allowlist() -> None:
    forbidden_patterns = (
        r"\bINSERT\b", r"\bUPDATE\b", r"\bDELETE\b", r"\bMERGE\b",
        r"\bCREATE\b", r"\bALTER\b", r"\bDROP\b", r"\bTRUNCATE\b",
        r"\bCALL\b", r"\bDO\b", r"\bCOPY\b", r"\bLOCK\b", r"\bNOTIFY\b",
        r"\bNEXTVAL\s*\(", r"\bSETVAL\s*\(", r"\bPG_ADVISORY_[A-Z_]*\s*\(",
        r"\bFOR\s+UPDATE\b",
    )
    for sql in FIXED_SELECT_ALLOWLIST:
        executable = _strip_sql_string_literals(sql).upper()
        if executable.count(";") != 1 or not executable.rstrip().endswith(";"):
            raise RuntimeError("FIXED_SQL_STATEMENT_COUNT_INVALID")
        if not executable.lstrip().startswith(("SELECT", "WITH")):
            raise RuntimeError("FIXED_SQL_SHAPE_INVALID")
        for pattern in forbidden_patterns:
            if re.search(pattern, executable):
                raise RuntimeError("FIXED_SQL_MUTATION_TOKEN_FORBIDDEN")


_assert_fixed_select_allowlist()


def _execute_fixed_select(binding: _DatabaseBinding, sql: str) -> str:
    if sql not in FIXED_SELECT_ALLOWLIST:
        raise RuntimeError("INTERNAL_READ_FAILURE")
    argv = [
        str(binding.psql_path), "-X", "--no-psqlrc", "--no-password",
        "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align",
        f"--host={binding.host}", f"--port={binding.port}",
        f"--dbname={binding.database}", f"--username={binding.user}",
    ]
    completed = subprocess.run(
        argv,
        input=(sql + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        shell=False,
        env=_fixed_env(password=binding.password),
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError("DATABASE_READ_FAILED")
    if len(completed.stdout) > MAX_STDOUT_BYTES:
        raise RuntimeError("OUTPUT_LIMIT")
    stdout = completed.stdout.decode("utf-8", errors="strict")
    if binding.password and binding.password in stdout:
        raise RuntimeError("SENSITIVE_OUTPUT_DETECTED")
    return stdout


def _fixed_snapshot_script() -> str:
    catalog_for_gset = FIXED_CATALOG_SELECT.rstrip()
    if not catalog_for_gset.endswith(";"):
        raise RuntimeError("INTERNAL_READ_FAILURE")
    catalog_for_gset = catalog_for_gset[:-1]
    return "\n".join(
        (
            "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;",
            catalog_for_gset,
            r"\gset snapshot_",
            FIXED_CATALOG_SELECT,
            r"\if :snapshot_flyway_history_exists",
            FIXED_HISTORY_SELECT,
            FIXED_BUSINESS_COUNT_SELECT,
            r"\else",
            "SELECT '[]'::text;",
            "SELECT '{}'::text;",
            r"\endif",
            "COMMIT;",
        )
    )


def _parse_fixed_snapshot(stdout: str) -> tuple[Any, Any, Any]:
    records = [
        record.strip("\r\n")
        for record in stdout.split(_PSQL_RECORD_SEPARATOR)
        if record.strip()
    ]
    if len(records) != 3:
        raise ValueError("SNAPSHOT_CARDINALITY_INVALID")
    catalog_fields = records[0].split(_PSQL_FIELD_SEPARATOR)
    if len(catalog_fields) != 2 or catalog_fields[1] not in {"true", "false"}:
        raise ValueError("CATALOG_CONTROL_INVALID")
    catalog = json.loads(catalog_fields[0])
    history = json.loads(records[1])
    business_counts = json.loads(records[2])
    if (
        not isinstance(catalog, dict)
        or type(catalog.get("flyway_history_exists")) is not bool
        or catalog["flyway_history_exists"] != (catalog_fields[1] == "true")
    ):
        raise ValueError("CATALOG_CONTROL_INVALID")
    return catalog, history, business_counts


def _execute_fixed_snapshot(binding: _DatabaseBinding) -> tuple[Any, Any, Any]:
    _assert_fixed_select_allowlist()
    argv = [
        str(binding.psql_path), "-X", "--no-psqlrc", "--no-password",
        "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--quiet",
        f"--field-separator={_PSQL_FIELD_SEPARATOR}",
        "--record-separator-zero",
        f"--host={binding.host}", f"--port={binding.port}",
        f"--dbname={binding.database}", f"--username={binding.user}",
    ]
    completed = subprocess.run(
        argv,
        input=(_fixed_snapshot_script() + "\n").encode("utf-8"),
        capture_output=True,
        check=False,
        shell=False,
        env=_fixed_env(password=binding.password),
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RuntimeError("DATABASE_READ_FAILED")
    if len(completed.stdout) > MAX_STDOUT_BYTES:
        raise RuntimeError("OUTPUT_LIMIT")
    stdout = completed.stdout.decode("utf-8", errors="strict")
    if binding.password and binding.password in stdout:
        raise RuntimeError("SENSITIVE_OUTPUT_DETECTED")
    return _parse_fixed_snapshot(stdout)


def _single_json(stdout: str) -> Any:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("SNAPSHOT_CARDINALITY_INVALID")
    return json.loads(lines[0])


def _yes_no(value: Any) -> str:
    if type(value) is not bool:
        raise ValueError("BOOLEAN_INVALID")
    return "YES" if value else "NO"


def _validate_role_facts(raw: Any) -> dict[str, dict[str, str]]:
    if not isinstance(raw, dict) or set(raw) != set(EXPECTED_ROLES):
        raise ValueError("ROLE_FACTS_SHAPE_INVALID")
    result: dict[str, dict[str, str]] = {}
    for role in EXPECTED_ROLES:
        value = raw[role]
        expected_keys = {
            "exists", "can_login", "inherit", "superuser", "create_db", "create_role",
            "replication", "bypass_rls", "database_connect", "contract_match",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ValueError("ROLE_FACTS_SHAPE_INVALID")
        facts = {key: _yes_no(value[key]) for key in expected_keys if key != "contract_match"}
        contract_match = _yes_no(value["contract_match"])
        expected = (
            facts["exists"] == "YES" and facts["can_login"] == "YES"
            and facts["inherit"] == ("YES" if EXPECTED_ROLE_INHERIT[role] else "NO")
            and facts["superuser"] == "NO"
            and facts["create_db"] == "NO" and facts["create_role"] == "NO"
            and facts["replication"] == "NO" and facts["bypass_rls"] == "NO"
            and facts["database_connect"] == "YES" and contract_match == "YES"
        )
        facts["expected_attributes_match"] = "YES" if expected else "NO"
        result[role] = facts
    return result


def _classify_history(raw: Any, *, history_exists: bool, user_table_count: int) -> tuple[str, int]:
    if not history_exists:
        return ("FRESH", 0) if user_table_count == 0 else ("MISMATCH", 0)
    if not isinstance(raw, list):
        raise ValueError("HISTORY_SHAPE_INVALID")
    rows: list[tuple[str, int, bool]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {
            "installed_rank", "version", "script", "checksum", "success"
        }:
            raise ValueError("HISTORY_ROW_INVALID")
        if (
            type(item["installed_rank"]) is not int
            or not isinstance(item["version"], str)
            or not isinstance(item["script"], str)
            or type(item["checksum"]) is not int
            or type(item["success"]) is not bool
        ):
            raise ValueError("HISTORY_ROW_INVALID")
        rows.append((item["version"], item["checksum"], item["success"]))
    expected = [(version, checksum, True) for version, checksum in EXPECTED_MIGRATIONS]
    return ("EXPECTED" if rows == expected else "MISMATCH", len(rows))


def _validated_snapshot(
    *,
    catalog: Any,
    history: Any,
    business_counts: Any,
    service_state: str,
    service_pid: int | str,
    secret_semantics: Mapping[str, Mapping[str, str]],
    source_identity: ControllerSourceIdentity,
) -> dict[str, Any]:
    expected_catalog_keys = {
        "observed_at", "postgres_version", "database_name", "session_user", "current_user",
        "transaction_read_only", "flyway_history_exists", "user_table_count",
        "business_schema_count", "role_facts",
    }
    if not isinstance(catalog, dict) or set(catalog) != expected_catalog_keys:
        raise ValueError("CATALOG_SHAPE_INVALID")
    if (
        not isinstance(catalog["observed_at"], str)
        or not isinstance(catalog["postgres_version"], str)
        or type(catalog["flyway_history_exists"]) is not bool
        or type(catalog["user_table_count"]) is not int
        or type(catalog["business_schema_count"]) is not int
        or catalog["user_table_count"] < 0
        or catalog["business_schema_count"] < 0
    ):
        raise ValueError("CATALOG_VALUE_INVALID")
    if (
        catalog["database_name"] != EXPECTED_DATABASE
        or catalog["session_user"] != EXPECTED_REFERENCE_ROLES["flyway-secret.conf"]
        or catalog["current_user"] != "propertyai_owner"
    ):
        return _unknown("DATABASE_IDENTITY_MISMATCH", source_identity)
    if catalog["transaction_read_only"] != "on":
        return _unknown("TRANSACTION_NOT_READ_ONLY", source_identity)
    role_facts = _validate_role_facts(catalog["role_facts"])
    if any(value["expected_attributes_match"] != "YES" for value in role_facts.values()):
        return _unknown("ROLE_PERMISSION_MISMATCH", source_identity)
    migration_class, history_rows = _classify_history(
        history,
        history_exists=catalog["flyway_history_exists"],
        user_table_count=catalog["user_table_count"],
    )
    if migration_class == "MISMATCH":
        return _unknown("MIGRATION_MISMATCH", source_identity)
    counts = {
        "real_rent_business_rows": 0,
        "fixture_rows": 0,
        "synthetic_financial_rows": 0,
    }
    if migration_class == "EXPECTED":
        if not isinstance(business_counts, dict) or set(business_counts) != set(counts):
            raise ValueError("BUSINESS_COUNTS_SHAPE_INVALID")
        for key in counts:
            if type(business_counts[key]) is not int or business_counts[key] < 0:
                raise ValueError("BUSINESS_COUNT_INVALID")
            counts[key] = business_counts[key]
    version = catalog["postgres_version"]
    if re.fullmatch(r"\d+(?:\.\d+){0,2}(?:[A-Za-z0-9._+-]*)?", version) is None or len(version) > 32:
        raise ValueError("POSTGRES_VERSION_INVALID")
    try:
        datetime.fromisoformat(catalog["observed_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("OBSERVED_AT_INVALID") from error
    return _public_result(
        snapshot_status="PASS",
        reason_code="OK",
        source_identity=source_identity,
        observed_at=catalog["observed_at"],
        service_state=service_state,
        service_pid=service_pid,
        postgres_version=version,
        database_identity=EXPECTED_DATABASE,
        database_target_match="YES",
        migration_history_class=migration_class,
        flyway_history_rows=history_rows,
        user_table_count=catalog["user_table_count"],
        business_schema_count=catalog["business_schema_count"],
        real_rent_business_rows=counts["real_rent_business_rows"],
        fixture_rows=counts["fixture_rows"],
        synthetic_financial_rows=counts["synthetic_financial_rows"],
        role_facts=role_facts,
        secret_reference_semantics=secret_semantics,
        transaction_read_only="on",
    )


def read_propertyai_rent_staging_readiness_surface(
    *, source_identity: ControllerSourceIdentity
) -> dict[str, Any]:
    service_state = "UNKNOWN"
    service_pid: int | str = "UNKNOWN"
    secret_semantics: Mapping[str, Mapping[str, str]] | None = None
    try:
        service_state, service_pid = _read_fixed_service_state()
        secret_semantics, binding = _resolve_secret_references()
        catalog, history, business_counts = _execute_fixed_snapshot(binding)
        return _validated_snapshot(
            catalog=catalog,
            history=history,
            business_counts=business_counts,
            service_state=service_state,
            service_pid=service_pid,
            secret_semantics=secret_semantics,
            source_identity=source_identity,
        )
    except subprocess.TimeoutExpired:
        return _unknown("DATABASE_READ_FAILED", source_identity)
    except RuntimeError as error:
        reason = str(error)
        if reason not in _REASON_CODE_SET:
            reason = "INTERNAL_READ_FAILURE"
        return _unknown(
            reason,
            source_identity,
            service_state=service_state,
            service_pid=service_pid,
            secret_reference_semantics=secret_semantics,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return _unknown(
            "MALFORMED_SNAPSHOT",
            source_identity,
            service_state=service_state,
            service_pid=service_pid,
            secret_reference_semantics=secret_semantics,
        )


def main(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    source_identity: ControllerSourceIdentity,
) -> int:
    if input_stream.read().strip():
        result = _unknown("PUBLIC_INPUT_REJECTED", source_identity)
    else:
        result = read_propertyai_rent_staging_readiness_surface(
            source_identity=source_identity
        )
    output_stream.write(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    )
    return 0


__all__ = [
    "ControllerSourceIdentity",
    "EXPECTED_MIGRATIONS",
    "EXPECTED_REFERENCE_ROLES",
    "EXPECTED_ROLES",
    "FIXED_BUSINESS_COUNT_SELECT",
    "FIXED_CATALOG_SELECT",
    "FIXED_HISTORY_SELECT",
    "FIXED_SECRET_REFERENCES",
    "FIXED_SELECT_ALLOWLIST",
    "FIXED_SERVICE_LABEL",
    "READER_CONTRACT_VERSION",
    "REASON_CODES",
    "TARGET_ID",
    "main",
    "read_propertyai_rent_staging_readiness_surface",
]
