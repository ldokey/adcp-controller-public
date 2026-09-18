"""Typed, fail-closed PostgreSQL Production control primitives.

This module deliberately does not extend the generic remote-command surface.  It
models the small set of PostgreSQL intents needed by the PropertyAI Cleaner
PostgreSQL authority recovery and executes them under the already accepted W08
controlled-deployment lease.

Caller supplied SQL, shell commands and argv extensions are intentionally absent
from the public request types.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
import sqlite3
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping

from adcp.production_control import (
    DeploymentEffectEvidence,
    DeploymentStep,
    ProductionControlError,
    ProductionMutationAuthority,
    GitSourceAuthority,
    assert_git_source_binding,
    run_controlled_deployment,
)
from adcp.domain import StoreError
from adcp.postgres_approval_evidence import (
    ExpectedProductionOperationApprovalBinding,
    PostgresApprovalEvidenceError,
    ProtectedApprovalEvidenceSource,
    ProductionOperationApprovalEvidenceV1,
    controller_git_identity,
    resolve_production_operation_approval_evidence,
)
from adcp.store.sqlite import CANONICAL_PRODUCTION_CONTROL_STORE, ControlStore
from adcp.store.migrations import validate_schema


# Typed PostgreSQL depends on the migration-8 receipt/global-writer contract.
# Migration 9 is additive and migration 10 only widens the receipt operation-kind
# constraint; existing operations remain exact across this finite set.
SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS = frozenset({8, 9, 10})
CURRENT_ADOPTED_TYPED_POSTGRES_OPERATIONAL_SCHEMA = 8  # compatibility alias for v8 fixtures

PROJECT_CODE = "CHAT.PROJ.HQ"
CANONICAL_CONTROLLER_SOURCE_ROOT = Path("/Users/kate/DKATE/adcp-controller")
CANONICAL_TYPED_POSTGRES_APPROVAL_EVIDENCE_ROOT = Path(
    "/Users/kate/DKATE/adcp-runtime/approval-evidence/typed-postgres"
)
CANONICAL_APPROVAL_EVIDENCE_OWNER_UID = 501


CLEANER_TARGET_SERVICE = "com.propertyai.postgresql-cleaner"
CLEANER_DATABASE = "propertyai_cleaner_prod"
CLEANER_DBA_ROLE = "propertyai_dba"
CLEANER_OWNER_ROLE = "propertyai_owner"
CANONICAL_FLYWAY_LOGIN_ROLE = "propertyai_flyway"
CANONICAL_FLYWAY_GROUP_ROLE = "propertyai_migrator"
STAGE_B_LOGIN_ROLE = "propertyai_stage_b_migration"
CLEANER_APP_LOGIN_ROLE = "propertyai_cleaner_app"
CLEANER_WORKER_LOGIN_ROLE = "propertyai_cleaner_worker"
PROPERTYAI_SCHEMA = "propertyai"

BOOTSTRAP_SQL_PATH = "db/v2_2_1/bootstrap/001__privileged_roles_schema.sql"
BOOTSTRAP_SQL_SHA256 = "ebe11796f9d3946b9d0634aea73f20835a906c339b073542b9b06a07cdb50edc"

CANONICAL_CLEANER_SOURCE_ROOT = Path(
    "/Users/kate/PropertyAI/worktrees/p0-cleaner-postgres-authority-cutover-01-bi01"
)
CANONICAL_CLEANER_SOURCE_HEAD = "1c222aa63d8a58217914ac4ddb1569f63ccbebf6"
CANONICAL_PSQL = Path("/opt/homebrew/Cellar/postgresql@18/18.6/bin/psql")
CANONICAL_SOCKET_DIR = Path(
    "/Users/kate/DKATE/propertyai-runtime/postgres/cleaner-prod-pg18/socket"
)
# HQ canonical endpoint decision V1: protected credentials are already bound to
# this exact TCP endpoint.  The historical socket directory remains a named
# regression constant only; the sealed executor never uses it as connection
# authority.
CANONICAL_HOST = "127.0.0.1"
CANONICAL_DATA_DIRECTORY = Path(
    "/Users/kate/DKATE/propertyai-runtime/postgres/cleaner-prod-pg18/data"
)
CANONICAL_SERVER_VERSION = "18.6"
CANONICAL_SERVER_VERSION_NUM = 180006
CANONICAL_SECRET_DIR = Path(
    "/Users/kate/PropertyAI/openclaw-workspace/secrets/postgres/cleaner-prod"
)
CANONICAL_SECRET_OWNER_UID = 501
CANONICAL_PORT = 5432


class TypedPostgresError(ProductionControlError):
    """A fail-closed typed PostgreSQL control error."""


class CredentialReference(str, Enum):
    DBA_PGPASS = "cleaner-prod/dba.pgpass"
    FLYWAY_PASSWORD = "cleaner-prod/flyway-password"
    STAGE_B_PGPASS = "cleaner-prod/stage-b.pgpass"
    APP_PGPASS = "cleaner-prod/app.pgpass"
    WORKER_PGPASS = "cleaner-prod/worker.pgpass"


class _CredentialKind(str, Enum):
    PGPASS = "PGPASS"
    RAW_PASSWORD = "RAW_PASSWORD"


class ApprovedPostgresRole(str, Enum):
    DBA = CLEANER_DBA_ROLE
    OWNER = CLEANER_OWNER_ROLE
    MIGRATOR = CANONICAL_FLYWAY_GROUP_ROLE
    FLYWAY = CANONICAL_FLYWAY_LOGIN_ROLE
    APP_RUNTIME = "propertyai_app_runtime"
    ASYNC_WORKER = "propertyai_async_worker"
    READONLY = "propertyai_readonly"
    STAGE_B = STAGE_B_LOGIN_ROLE
    CLEANER_APP = CLEANER_APP_LOGIN_ROLE
    CLEANER_WORKER = CLEANER_WORKER_LOGIN_ROLE


class CatalogReadbackOperation(str, Enum):
    DATABASE_EXISTENCE = "DATABASE_EXISTENCE"
    DATABASE_OWNER = "DATABASE_OWNER"
    SCHEMA_EXISTENCE = "SCHEMA_EXISTENCE"
    ROLE_EXISTENCE = "ROLE_EXISTENCE"
    ROLE_ATTRIBUTES = "ROLE_ATTRIBUTES"
    ROLE_MEMBERSHIPS = "ROLE_MEMBERSHIPS"
    FLYWAY_MIGRATION_STATE = "FLYWAY_MIGRATION_STATE"
    STAGE_B_ROLE_EXISTENCE = "STAGE_B_ROLE_EXISTENCE"
    ACTIVE_CONNECTIONS_BY_ROLE = "ACTIVE_CONNECTIONS_BY_ROLE"
    AUTHORITY_EPOCH_BASELINE = "AUTHORITY_EPOCH_BASELINE"
    DOMAIN_EVENT_BASELINE = "DOMAIN_EVENT_BASELINE"
    BUSINESS_SCHEDULED_ACTION_BASELINE = "BUSINESS_SCHEDULED_ACTION_BASELINE"
    INTEGRATION_OUTBOX_BASELINE = "INTEGRATION_OUTBOX_BASELINE"
    SCHEMA10_PRINCIPAL_PREFLIGHT = "SCHEMA10_PRINCIPAL_PREFLIGHT"


class TypedOperationType(str, Enum):
    PROVISION_CLEANER_APP_PRINCIPAL = "PROVISION_CLEANER_APP_PRINCIPAL"
    EXECUTE_AUTHORIZED_SQL_FILE = "EXECUTE_AUTHORIZED_SQL_FILE"
    TRANSITION_DATABASE_OWNER = "TRANSITION_DATABASE_OWNER"
    APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE = "APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE"


@dataclass(frozen=True)
class _CredentialSpec:
    reference: CredentialReference
    path: Path
    kind: _CredentialKind
    role: str


@dataclass(frozen=True)
class _CleanerProductionPostgresPolicy:
    source_root: Path
    expected_source_head: str
    approved_bootstrap_path: str
    approved_bootstrap_sha256: str
    psql_path: Path
    socket_dir: Path
    host: str
    port: int
    data_directory: Path
    server_version: str
    server_version_num: int
    secret_dir: Path
    expected_secret_owner_uid: int
    credentials: Mapping[CredentialReference, _CredentialSpec]


@dataclass(frozen=True)
class _ExecuteAuthorizedSqlFileIntent:
    target_service: str
    database: str
    execution_role: str
    sql_file_path: str
    expected_sql_sha256: str
    credential_reference: CredentialReference
    operation_id: str


@dataclass(frozen=True)
class CatalogReadbackRequest:
    operation: CatalogReadbackOperation
    role: ApprovedPostgresRole | None = None


@dataclass(frozen=True)
class _TransitionDatabaseOwnerIntent:
    target_service: str
    database: str
    expected_current_owner: str
    new_owner: str
    operation_id: str


@dataclass(frozen=True)
class _ApplyRolePasswordFromProtectedFileIntent:
    role: ApprovedPostgresRole
    credential_file_reference: CredentialReference
    expected_file_owner_uid: int
    expected_file_mode: int
    operation_id: str


class PasswordCredentialOperation(str, Enum):
    FLYWAY = "APPLY_FLYWAY_PASSWORD"
    STAGE_B = "APPLY_STAGE_B_PASSWORD"
    CLEANER_APP = "APPLY_CLEANER_APP_PASSWORD"
    CLEANER_WORKER = "APPLY_CLEANER_WORKER_PASSWORD"


@dataclass(frozen=True)
class ExecuteAuthorizedSqlFileRequest:
    """Authority-free request for the one canonical Cleaner bootstrap artifact."""

    operation_id: str


@dataclass(frozen=True)
class ProvisionCleanerAppPrincipalRequest:
    """Select only the sealed DL-81 principal; no caller-supplied authority."""

    operation_id: str


@dataclass(frozen=True)
class TransitionDatabaseOwnerRequest:
    """Authority-free request for the canonical DBA -> owner transition."""

    operation_id: str


@dataclass(frozen=True)
class ApplyRolePasswordFromProtectedFileRequest:
    """Select a named sealed password operation without supplying role/credential authority."""

    operation: PasswordCredentialOperation
    operation_id: str


@dataclass(frozen=True)
class SanitizedProcessResult:
    exit_status: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class TypedPostgresOperationReceipt:
    receipt_version: int
    change_id: str
    control_decision_ref: str
    deployment_id: str
    operation_id: str
    operation_type: str
    receipt_phase: str
    target_service: str
    target_database: str | None
    principal_identity: str | None
    credential_reference: str | None
    artifact_path: str | None
    artifact_sha256: str | None
    request_fingerprint: str
    before_state_fingerprint: str
    after_state_fingerprint: str | None
    effect_status: str
    w08_fencing_token: int
    created_at: str


@dataclass(frozen=True)
class _ReceiptIntent:
    change_id: str
    control_decision_ref: str
    deployment_id: str
    operation_id: str
    operation_type: TypedOperationType
    target_service: str
    target_database: str | None
    principal_identity: str | None
    credential_reference: CredentialReference | None
    artifact_path: str | None
    artifact_sha256: str | None
    request_fingerprint: str


@dataclass(frozen=True)
class _CredentialMaterial:
    spec: _CredentialSpec
    bytes_value: bytes
    text_value: str | None
    fingerprint: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _ArtifactMaterial:
    relative_path: str
    absolute_path: Path
    sha256: str
    bytes_value: bytes
    fingerprint: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _TypedEffectResult:
    operation_type: TypedOperationType
    status: str
    before_state: Mapping[str, Any]
    process: SanitizedProcessResult | None
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    credential_reference: CredentialReference | None = None


_CANONICAL_BOOTSTRAP_ROLES = (
    ApprovedPostgresRole.OWNER.value,
    ApprovedPostgresRole.MIGRATOR.value,
    ApprovedPostgresRole.FLYWAY.value,
    ApprovedPostgresRole.APP_RUNTIME.value,
    ApprovedPostgresRole.ASYNC_WORKER.value,
    ApprovedPostgresRole.READONLY.value,
)


def _canonical_cleaner_postgres_policy() -> _CleanerProductionPostgresPolicy:
    """Return the frozen Cleaner Production PostgreSQL execution policy.

    The function has no caller-controlled paths, principals, SQL or argv.
    """

    credentials = {
        CredentialReference.DBA_PGPASS: _CredentialSpec(
            CredentialReference.DBA_PGPASS,
            CANONICAL_SECRET_DIR / "dba.pgpass",
            _CredentialKind.PGPASS,
            CLEANER_DBA_ROLE,
        ),
        CredentialReference.FLYWAY_PASSWORD: _CredentialSpec(
            CredentialReference.FLYWAY_PASSWORD,
            CANONICAL_SECRET_DIR / "flyway-password",
            _CredentialKind.RAW_PASSWORD,
            CANONICAL_FLYWAY_LOGIN_ROLE,
        ),
        CredentialReference.STAGE_B_PGPASS: _CredentialSpec(
            CredentialReference.STAGE_B_PGPASS,
            CANONICAL_SECRET_DIR / "stage-b.pgpass",
            _CredentialKind.PGPASS,
            STAGE_B_LOGIN_ROLE,
        ),
        CredentialReference.APP_PGPASS: _CredentialSpec(
            CredentialReference.APP_PGPASS,
            CANONICAL_SECRET_DIR / "app.pgpass",
            _CredentialKind.PGPASS,
            CLEANER_APP_LOGIN_ROLE,
        ),
        CredentialReference.WORKER_PGPASS: _CredentialSpec(
            CredentialReference.WORKER_PGPASS,
            CANONICAL_SECRET_DIR / "worker.pgpass",
            _CredentialKind.PGPASS,
            CLEANER_WORKER_LOGIN_ROLE,
        ),
    }
    return _CleanerProductionPostgresPolicy(
        source_root=CANONICAL_CLEANER_SOURCE_ROOT,
        expected_source_head=CANONICAL_CLEANER_SOURCE_HEAD,
        approved_bootstrap_path=BOOTSTRAP_SQL_PATH,
        approved_bootstrap_sha256=BOOTSTRAP_SQL_SHA256,
        psql_path=CANONICAL_PSQL,
        socket_dir=CANONICAL_SOCKET_DIR,
        host=CANONICAL_HOST,
        port=CANONICAL_PORT,
        data_directory=CANONICAL_DATA_DIRECTORY,
        server_version=CANONICAL_SERVER_VERSION,
        server_version_num=CANONICAL_SERVER_VERSION_NUM,
        secret_dir=CANONICAL_SECRET_DIR,
        expected_secret_owner_uid=CANONICAL_SECRET_OWNER_UID,
        credentials=credentials,
    )


def _validate_sealed_canonical_policy(policy: _CleanerProductionPostgresPolicy) -> None:
    expected_credentials = {
        CredentialReference.DBA_PGPASS: _CredentialSpec(
            CredentialReference.DBA_PGPASS, CANONICAL_SECRET_DIR / "dba.pgpass", _CredentialKind.PGPASS, CLEANER_DBA_ROLE
        ),
        CredentialReference.FLYWAY_PASSWORD: _CredentialSpec(
            CredentialReference.FLYWAY_PASSWORD, CANONICAL_SECRET_DIR / "flyway-password", _CredentialKind.RAW_PASSWORD, CANONICAL_FLYWAY_LOGIN_ROLE
        ),
        CredentialReference.STAGE_B_PGPASS: _CredentialSpec(
            CredentialReference.STAGE_B_PGPASS, CANONICAL_SECRET_DIR / "stage-b.pgpass", _CredentialKind.PGPASS, STAGE_B_LOGIN_ROLE
        ),
        CredentialReference.APP_PGPASS: _CredentialSpec(
            CredentialReference.APP_PGPASS, CANONICAL_SECRET_DIR / "app.pgpass", _CredentialKind.PGPASS, CLEANER_APP_LOGIN_ROLE
        ),
        CredentialReference.WORKER_PGPASS: _CredentialSpec(
            CredentialReference.WORKER_PGPASS, CANONICAL_SECRET_DIR / "worker.pgpass", _CredentialKind.PGPASS, CLEANER_WORKER_LOGIN_ROLE
        ),
    }
    expected = (
        CANONICAL_CLEANER_SOURCE_ROOT, CANONICAL_CLEANER_SOURCE_HEAD,
        BOOTSTRAP_SQL_PATH, BOOTSTRAP_SQL_SHA256, CANONICAL_PSQL,
        CANONICAL_SOCKET_DIR, CANONICAL_HOST, CANONICAL_PORT, CANONICAL_DATA_DIRECTORY,
        CANONICAL_SERVER_VERSION, CANONICAL_SERVER_VERSION_NUM, CANONICAL_SECRET_DIR,
        CANONICAL_SECRET_OWNER_UID, expected_credentials,
    )
    actual = (
        policy.source_root, policy.expected_source_head, policy.approved_bootstrap_path,
        policy.approved_bootstrap_sha256, policy.psql_path, policy.socket_dir,
        policy.host, policy.port, policy.data_directory, policy.server_version,
        policy.server_version_num, policy.secret_dir, policy.expected_secret_owner_uid,
        dict(policy.credentials),
    )
    if actual != expected:
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID")


def _validate_operation_id(operation_id: str) -> None:
    if not operation_id or len(operation_id) > 200:
        raise TypedPostgresError("TYPED_POSTGRES_OPERATION_ID_INVALID")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:/" for ch in operation_id):
        raise TypedPostgresError("TYPED_POSTGRES_OPERATION_ID_INVALID")


def _request_field_names(request_type: type) -> set[str]:
    return {field.name for field in fields(request_type)}


def _validate_no_generic_escape_fields(request: object) -> None:
    forbidden = {
        "sql", "raw_sql", "command", "shell_command", "argv", "extra_argv", "password",
        "host", "port", "socket", "socket_path", "psql", "psql_path", "executable",
        "pgpassfile", "credential_file",
    }
    overlap = _request_field_names(type(request)) & forbidden
    if overlap:
        raise TypedPostgresError("TYPED_POSTGRES_GENERIC_ESCAPE_FIELD_FORBIDDEN", ",".join(sorted(overlap)))


def _mode(mode: int) -> int:
    return stat.S_IMODE(mode)


def _fingerprint(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _ensure_plain_file_no_symlink(path: Path, *, code_prefix: str) -> os.stat_result:
    try:
        lst = path.lstat()
    except OSError as error:
        raise TypedPostgresError(f"{code_prefix}_UNAVAILABLE") from error
    if stat.S_ISLNK(lst.st_mode):
        raise TypedPostgresError(f"{code_prefix}_SYMLINK_FORBIDDEN")
    if not stat.S_ISREG(lst.st_mode):
        raise TypedPostgresError(f"{code_prefix}_NOT_REGULAR_FILE")
    return lst


def _ensure_directory_no_symlink(path: Path, *, expected_mode: int, expected_uid: int, code_prefix: str) -> None:
    try:
        lst = path.lstat()
    except OSError as error:
        raise TypedPostgresError(f"{code_prefix}_UNAVAILABLE") from error
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
        raise TypedPostgresError(f"{code_prefix}_INVALID")
    if _mode(lst.st_mode) != expected_mode:
        raise TypedPostgresError(f"{code_prefix}_MODE_INVALID")
    if lst.st_uid != expected_uid:
        raise TypedPostgresError(f"{code_prefix}_OWNER_INVALID")


def _read_pinned_file(path: Path, *, code_prefix: str) -> tuple[bytes, tuple[int, int, int, int, int]]:
    before = _ensure_plain_file_no_symlink(path, code_prefix=code_prefix)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise TypedPostgresError(f"{code_prefix}_OPEN_REJECTED") from error
    try:
        opened = os.fstat(fd)
        if _fingerprint(opened) != _fingerprint(before):
            raise TypedPostgresError(f"{code_prefix}_SUBSTITUTION_DETECTED")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(fd)
        if _fingerprint(after_read) != _fingerprint(opened):
            raise TypedPostgresError(f"{code_prefix}_MUTATED_DURING_VALIDATION")
        return b"".join(chunks), _fingerprint(opened)
    finally:
        os.close(fd)


def _revalidate_path_fingerprint(path: Path, expected: tuple[int, int, int, int, int], *, code_prefix: str) -> None:
    current = _ensure_plain_file_no_symlink(path, code_prefix=code_prefix)
    if _fingerprint(current) != expected:
        raise TypedPostgresError(f"{code_prefix}_MUTATED_AFTER_VALIDATION")


def _resolve_artifact(policy: _CleanerProductionPostgresPolicy, request: _ExecuteAuthorizedSqlFileIntent) -> _ArtifactMaterial:
    _validate_no_generic_escape_fields(request)
    _validate_operation_id(request.operation_id)
    if request.target_service != CLEANER_TARGET_SERVICE:
        raise TypedPostgresError("POSTGRES_TARGET_SERVICE_NOT_APPROVED")
    if request.database != CLEANER_DATABASE:
        raise TypedPostgresError("POSTGRES_DATABASE_NOT_APPROVED")
    if request.execution_role != CLEANER_DBA_ROLE:
        raise TypedPostgresError("POSTGRES_EXECUTION_PRINCIPAL_NOT_APPROVED")
    if request.sql_file_path != policy.approved_bootstrap_path:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_NOT_APPROVED")
    if request.expected_sql_sha256 != policy.approved_bootstrap_sha256:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_HASH_NOT_APPROVED")
    if request.credential_reference is not CredentialReference.DBA_PGPASS:
        raise TypedPostgresError("POSTGRES_EXECUTION_CREDENTIAL_NOT_APPROVED")

    assert_git_source_binding(policy.source_root, policy.expected_source_head, require_clean=True)
    root = policy.source_root.resolve(strict=True)
    relative = Path(request.sql_file_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_PATH_INVALID")
    current = root
    for part in relative.parts:
        current = current / part
        try:
            lst = current.lstat()
        except OSError as error:
            raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_UNAVAILABLE") from error
        if stat.S_ISLNK(lst.st_mode):
            raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_SYMLINK_FORBIDDEN")
    absolute = root / relative
    payload, pinned = _read_pinned_file(absolute, code_prefix="POSTGRES_SQL_ARTIFACT")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != request.expected_sql_sha256:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_HASH_MISMATCH")
    _revalidate_path_fingerprint(absolute, pinned, code_prefix="POSTGRES_SQL_ARTIFACT")
    return _ArtifactMaterial(request.sql_file_path, absolute, digest, payload, pinned)


def _credential_spec(policy: _CleanerProductionPostgresPolicy, reference: CredentialReference) -> _CredentialSpec:
    spec = policy.credentials.get(reference)
    if spec is None:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_REFERENCE_NOT_APPROVED")
    if spec.path.parent != policy.secret_dir:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_PATH_POLICY_INVALID")
    return spec


def _validate_credential(
    policy: _CleanerProductionPostgresPolicy,
    reference: CredentialReference,
    *,
    expected_mode: int = 0o600,
    expected_uid: int | None = None,
    reveal_text: bool = False,
) -> _CredentialMaterial:
    spec = _credential_spec(policy, reference)
    owner_uid = policy.expected_secret_owner_uid if expected_uid is None else expected_uid
    if owner_uid != policy.expected_secret_owner_uid:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_EXPECTED_OWNER_NOT_APPROVED")
    if expected_mode != 0o600:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_EXPECTED_MODE_NOT_APPROVED")
    _ensure_directory_no_symlink(
        policy.secret_dir,
        expected_mode=0o700,
        expected_uid=policy.expected_secret_owner_uid,
        code_prefix="POSTGRES_SECRET_DIRECTORY",
    )
    before = _ensure_plain_file_no_symlink(spec.path, code_prefix="POSTGRES_CREDENTIAL_FILE")
    if before.st_uid != owner_uid:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_FILE_OWNER_INVALID")
    if _mode(before.st_mode) != expected_mode:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_FILE_MODE_INVALID")
    payload, pinned = _read_pinned_file(spec.path, code_prefix="POSTGRES_CREDENTIAL_FILE")
    if not payload:
        raise TypedPostgresError("POSTGRES_CREDENTIAL_FILE_EMPTY")
    _revalidate_path_fingerprint(spec.path, pinned, code_prefix="POSTGRES_CREDENTIAL_FILE")
    text: str | None = None
    if reveal_text:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            if reference is CredentialReference.WORKER_PGPASS:
                raise TypedPostgresError("POSTGRES_CREDENTIAL_FILE_ENCODING_INVALID") from None
            raise TypedPostgresError("POSTGRES_CREDENTIAL_FILE_ENCODING_INVALID") from error
    return _CredentialMaterial(spec, payload, text, pinned)


def _parse_pgpass_password(
    text: str, *, expected_host: str, expected_database: str, expected_role: str, expected_port: int
) -> str:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if len(lines) != 1:
        raise TypedPostgresError("POSTGRES_PGPASS_ENTRY_COUNT_INVALID")
    fields_: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in lines[0]:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":" and len(fields_) < 4:
            fields_.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if escaped:
        buf.append("\\")
    fields_.append("".join(buf))
    if len(fields_) != 5:
        raise TypedPostgresError("POSTGRES_PGPASS_FORMAT_INVALID")
    host, port, database, role, password = fields_
    if (
        host != expected_host
        or port != str(expected_port)
        or database not in {expected_database, "*"}
        or role != expected_role
    ):
        raise TypedPostgresError("POSTGRES_PGPASS_BINDING_MISMATCH")
    return _validate_password_text(password)


def _validate_password_text(value: str) -> str:
    value = value.rstrip("\r\n")
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise TypedPostgresError("POSTGRES_PASSWORD_MATERIAL_INVALID")
    return value


def _password_from_credential(policy: _CleanerProductionPostgresPolicy, material: _CredentialMaterial) -> str:
    if material.text_value is None:
        raise TypedPostgresError("POSTGRES_PASSWORD_MATERIAL_NOT_LOADED")
    if material.spec.kind is _CredentialKind.RAW_PASSWORD:
        return _validate_password_text(material.text_value)
    if material.spec.kind is _CredentialKind.PGPASS:
        if material.spec.reference is CredentialReference.WORKER_PGPASS:
            prefix = f"{policy.host}:{policy.port}:{CLEANER_DATABASE}:{CLEANER_WORKER_LOGIN_ROLE}:"
            if not material.text_value.startswith(prefix) or len(material.text_value.splitlines()) != 1:
                raise TypedPostgresError("POSTGRES_WORKER_PGPASS_BINDING_MISMATCH")
        return _parse_pgpass_password(
            material.text_value,
            expected_host=policy.host,
            expected_database=CLEANER_DATABASE,
            expected_role=material.spec.role,
            expected_port=policy.port,
        )
    raise TypedPostgresError("POSTGRES_CREDENTIAL_KIND_UNSUPPORTED")


def _sql_literal(value: str) -> str:
    if "\x00" in value:
        raise TypedPostgresError("POSTGRES_SQL_LITERAL_INVALID")
    return "'" + value.replace("'", "''") + "'"


def _sql_identifier(value: str) -> str:
    approved = {
        CLEANER_DATABASE,
        CLEANER_DBA_ROLE,
        CLEANER_OWNER_ROLE,
        CANONICAL_FLYWAY_LOGIN_ROLE,
        CANONICAL_FLYWAY_GROUP_ROLE,
        STAGE_B_LOGIN_ROLE,
        CLEANER_APP_LOGIN_ROLE,
        CLEANER_WORKER_LOGIN_ROLE,
        PROPERTYAI_SCHEMA,
    }
    if value not in approved:
        raise TypedPostgresError("POSTGRES_IDENTIFIER_NOT_APPROVED")
    return '"' + value.replace('"', '""') + '"'


def _sanitize_output(value: bytes, *, secrets: tuple[str, ...] = ()) -> str:
    text = value.decode("utf-8", errors="replace")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text[:65536]


def _validate_psql_binary(policy: _CleanerProductionPostgresPolicy) -> None:
    try:
        lst = policy.psql_path.lstat()
    except OSError as error:
        raise TypedPostgresError("POSTGRES_PSQL_BINARY_UNAVAILABLE") from error
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise TypedPostgresError("POSTGRES_PSQL_BINARY_INVALID")
    if not os.access(policy.psql_path, os.X_OK):
        raise TypedPostgresError("POSTGRES_PSQL_BINARY_NOT_EXECUTABLE")


def _spawn_psql(
    policy: _CleanerProductionPostgresPolicy,
    *,
    database: str,
    execution_role: str,
    stdin_sql: bytes,
    credential: _CredentialMaterial,
    connection_secret: str,
    secrets_to_redact: tuple[str, ...] = (),
    read_only: bool = False,
) -> SanitizedProcessResult:
    """Run the one sealed psql binary against the one sealed TCP endpoint."""

    _revalidate_path_fingerprint(
        credential.spec.path, credential.fingerprint, code_prefix="POSTGRES_CREDENTIAL_FILE"
    )
    argv = [
        str(policy.psql_path),
        "-X",
        "--no-psqlrc",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "--tuples-only",
        "--no-align",
        f"--host={policy.host}",
        f"--port={policy.port}",
        f"--dbname={database}",
        f"--username={execution_role}",
    ]
    env = os.environ.copy()
    if execution_role == CLEANER_WORKER_LOGIN_ROLE:
        env = {key: value for key, value in env.items() if not key.startswith("PG")}
        env["PGREQUIREAUTH"] = "scram-sha-256"
        env["PGCONNECT_TIMEOUT"] = "10"
    env["PGPASSFILE"] = str(credential.spec.path)
    if read_only:
        # Catalog execution must prove server-enforced read-only behavior.
        # Replace, rather than extend, inherited PGOPTIONS so the caller cannot
        # weaken the sealed setting.
        env["PGOPTIONS"] = "-c default_transaction_read_only=on"
    if not read_only:
        from adcp.cleaner_worker_control import _revalidate_worker_pg_dispatch
        _revalidate_worker_pg_dispatch()
    completed = subprocess.run(
        argv, input=stdin_sql, capture_output=True, check=False, shell=False, env=env
    )
    all_secrets = tuple(secret for secret in (connection_secret, *secrets_to_redact) if secret)
    return SanitizedProcessResult(
        int(completed.returncode),
        _sanitize_output(completed.stdout, secrets=all_secrets),
        _sanitize_output(completed.stderr, secrets=all_secrets),
    )


def _validate_canonical_postgres_authority(
    policy: _CleanerProductionPostgresPolicy,
    credential: _CredentialMaterial,
    connection_secret: str,
    *,
    read_only: bool = False,
) -> Mapping[str, Any]:
    """Bind TCP reachability to the frozen Cleaner Production cluster identity."""

    sql = (
        "SELECT json_build_object("
        "'server_version', current_setting('server_version'), "
        "'server_version_num', current_setting('server_version_num')::int, "
        "'database', current_database(), "
        "'server_addr', host(inet_server_addr()), "
        "'server_port', inet_server_port(), "
        "'data_directory', current_setting('data_directory')"
        ")::text;\n"
    ).encode("utf-8")
    result = _spawn_psql(
        policy, database=CLEANER_DATABASE, execution_role=CLEANER_DBA_ROLE,
        stdin_sql=sql, credential=credential, connection_secret=connection_secret,
        read_only=read_only,
    )
    if result.exit_status != 0:
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID")
    try:
        identity = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID") from error
    expected = {
        "database": CLEANER_DATABASE,
        "server_addr": policy.host,
        "server_port": policy.port,
        "data_directory": str(policy.data_directory),
        "server_version_num": policy.server_version_num,
    }
    if not isinstance(identity, dict) or any(identity.get(k) != v for k, v in expected.items()):
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID")
    version = identity.get("server_version")
    if not isinstance(version, str) or version.split(" ", 1)[0] != policy.server_version:
        raise TypedPostgresError("POSTGRES_CANONICAL_AUTHORITY_INVALID")
    return {key: identity[key] for key in (*expected.keys(), "server_version")}


def _run_psql(
    policy: _CleanerProductionPostgresPolicy,
    *,
    database: str,
    execution_role: str,
    stdin_sql: bytes,
    connection_credential: CredentialReference = CredentialReference.DBA_PGPASS,
    secrets_to_redact: tuple[str, ...] = (),
    read_only: bool = False,
) -> SanitizedProcessResult:
    if database not in {CLEANER_DATABASE, "postgres"}:
        raise TypedPostgresError("POSTGRES_DATABASE_NOT_APPROVED")
    if execution_role != CLEANER_DBA_ROLE:
        raise TypedPostgresError("POSTGRES_EXECUTION_PRINCIPAL_NOT_APPROVED")
    _validate_psql_binary(policy)
    credential = _validate_credential(policy, connection_credential, reveal_text=True)
    if credential.spec.kind is not _CredentialKind.PGPASS or credential.spec.role != CLEANER_DBA_ROLE:
        raise TypedPostgresError("POSTGRES_CONNECTION_CREDENTIAL_NOT_APPROVED")
    connection_secret = _password_from_credential(policy, credential)
    _validate_canonical_postgres_authority(
        policy, credential, connection_secret, read_only=read_only
    )
    if not read_only:
        from adcp.cleaner_worker_control import _revalidate_worker_pg_dispatch
        _revalidate_worker_pg_dispatch()
    return _spawn_psql(
        policy, database=database, execution_role=execution_role, stdin_sql=stdin_sql,
        credential=credential, connection_secret=connection_secret, secrets_to_redact=secrets_to_redact,
        read_only=read_only,
    )


def _json_query(
    policy: _CleanerProductionPostgresPolicy,
    *,
    database: str,
    sql: str,
) -> Mapping[str, Any]:
    result = _run_psql(
        policy,
        database=database,
        execution_role=CLEANER_DBA_ROLE,
        stdin_sql=(sql.rstrip(";\n") + ";\n").encode("utf-8"),
        read_only=True,
    )
    if result.exit_status != 0:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_FAILED", result.stderr[:2048])
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_CARDINALITY_INVALID")
    try:
        parsed = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_JSON_INVALID") from error
    if not isinstance(parsed, dict):
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_SHAPE_INVALID")
    return parsed


def _role_required(request: CatalogReadbackRequest) -> str:
    if request.role is None:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_ROLE_REQUIRED")
    if type(request.role) is not ApprovedPostgresRole:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_ROLE_INVALID")
    return request.role.value


def _table_baseline(policy: _CleanerProductionPostgresPolicy, table: str) -> Mapping[str, Any]:
    approved = {
        "authority_epoch",
        "domain_event",
        "business_scheduled_action",
        "integration_outbox",
    }
    if table not in approved:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_TABLE_NOT_APPROVED")
    regclass = f"{PROPERTYAI_SCHEMA}.{table}"
    exists = _json_query(
        policy,
        database=CLEANER_DATABASE,
        sql=(
            "SELECT json_build_object('exists', to_regclass("
            + _sql_literal(regclass)
            + ") IS NOT NULL)::text"
        ),
    )
    if not bool(exists.get("exists")):
        return {"exists": False, "count": 0}
    return _json_query(
        policy,
        database=CLEANER_DATABASE,
        sql=f"SELECT json_build_object('exists', true, 'count', count(*))::text FROM propertyai.{table}",
    )


def _query_postgres_catalog(
    policy: _CleanerProductionPostgresPolicy,
    request: CatalogReadbackRequest,
) -> Mapping[str, Any]:
    """Execute one bounded, typed, read-only PostgreSQL catalog readback."""

    _validate_no_generic_escape_fields(request)
    if type(request.operation) is not CatalogReadbackOperation:
        raise TypedPostgresError("POSTGRES_TYPED_READBACK_OPERATION_UNSUPPORTED")
    op = request.operation
    if op is CatalogReadbackOperation.DATABASE_EXISTENCE:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        return _json_query(
            policy,
            database="postgres",
            sql=(
                "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_catalog.pg_database "
                f"WHERE datname={_sql_literal(CLEANER_DATABASE)}))::text"
            ),
        )
    if op is CatalogReadbackOperation.DATABASE_OWNER:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        return _json_query(
            policy,
            database="postgres",
            sql=(
                "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_catalog.pg_database "
                f"WHERE datname={_sql_literal(CLEANER_DATABASE)}), 'owner', "
                "(SELECT pg_catalog.pg_get_userbyid(datdba)::text FROM pg_catalog.pg_database "
                f"WHERE datname={_sql_literal(CLEANER_DATABASE)} LIMIT 1))::text"
            ),
        )
    if op is CatalogReadbackOperation.SCHEMA_EXISTENCE:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        return _json_query(
            policy,
            database=CLEANER_DATABASE,
            sql=(
                "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_catalog.pg_namespace "
                f"WHERE nspname={_sql_literal(PROPERTYAI_SCHEMA)}), 'owner', "
                "(SELECT pg_catalog.pg_get_userbyid(nspowner)::text FROM pg_catalog.pg_namespace "
                f"WHERE nspname={_sql_literal(PROPERTYAI_SCHEMA)} LIMIT 1))::text"
            ),
        )
    if op in {CatalogReadbackOperation.ROLE_EXISTENCE, CatalogReadbackOperation.ROLE_ATTRIBUTES}:
        role = _role_required(request)
        if op is CatalogReadbackOperation.ROLE_EXISTENCE:
            return _json_query(
                policy,
                database="postgres",
                sql=(
                    "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_catalog.pg_roles "
                    f"WHERE rolname={_sql_literal(role)}))::text"
                ),
            )
        return _json_query(
            policy,
            database="postgres",
            sql=(
                "SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)}), 'role', "
                "(SELECT rolname::text FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'can_login', "
                "(SELECT rolcanlogin FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'inherit', "
                "(SELECT rolinherit FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'superuser', "
                "(SELECT rolsuper FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'create_db', "
                "(SELECT rolcreatedb FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'create_role', "
                "(SELECT rolcreaterole FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'replication', "
                "(SELECT rolreplication FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1), 'bypass_rls', "
                "(SELECT rolbypassrls FROM pg_catalog.pg_roles "
                f"WHERE rolname={_sql_literal(role)} LIMIT 1))::text"
            ),
        )
    if op is CatalogReadbackOperation.ROLE_MEMBERSHIPS:
        role = _role_required(request)
        return _json_query(
            policy,
            database="postgres",
            sql=(
                "SELECT json_build_object('role', " + _sql_literal(role) + ", 'exists', "
                "EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=" + _sql_literal(role) + "), "
                "'memberships', COALESCE((SELECT json_agg(json_build_object("
                "'granted_role', target.rolname, 'inherit', m.inherit_option, "
                "'set', m.set_option, 'admin', m.admin_option) ORDER BY target.rolname) "
                "FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles member ON member.oid=m.member "
                "JOIN pg_catalog.pg_roles target ON target.oid=m.roleid "
                "WHERE member.rolname=" + _sql_literal(role) + "), '[]'::json))::text"
            ),
        )
    if op is CatalogReadbackOperation.FLYWAY_MIGRATION_STATE:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        exists = _json_query(
            policy,
            database=CLEANER_DATABASE,
            sql=(
                "SELECT json_build_object('exists', to_regclass('propertyai.flyway_schema_history') IS NOT NULL)::text"
            ),
        )
        if not bool(exists.get("exists")):
            return {"exists": False, "count": 0, "checksums": []}
        return _json_query(
            policy,
            database=CLEANER_DATABASE,
            sql=(
                "SELECT json_build_object('exists', true, 'count', count(*), 'checksums', "
                "COALESCE(json_agg(json_build_object('version', version, 'checksum', checksum) "
                "ORDER BY installed_rank), '[]'::json))::text FROM propertyai.flyway_schema_history"
            ),
        )
    if op is CatalogReadbackOperation.STAGE_B_ROLE_EXISTENCE:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        return _query_postgres_catalog(
            policy,
            CatalogReadbackRequest(CatalogReadbackOperation.ROLE_EXISTENCE, ApprovedPostgresRole.STAGE_B),
        )
    if op is CatalogReadbackOperation.ACTIVE_CONNECTIONS_BY_ROLE:
        role = _role_required(request)
        return _json_query(
            policy,
            database="postgres",
            sql=(
                "SELECT json_build_object('role', " + _sql_literal(role) + ", 'active_connections', count(*))::text "
                "FROM pg_catalog.pg_stat_activity "
                f"WHERE usename={_sql_literal(role)}"
            ),
        )
    if op is CatalogReadbackOperation.AUTHORITY_EPOCH_BASELINE:
        return _table_baseline(policy, "authority_epoch")
    if op is CatalogReadbackOperation.DOMAIN_EVENT_BASELINE:
        return _table_baseline(policy, "domain_event")
    if op is CatalogReadbackOperation.BUSINESS_SCHEDULED_ACTION_BASELINE:
        return _table_baseline(policy, "business_scheduled_action")
    if op is CatalogReadbackOperation.INTEGRATION_OUTBOX_BASELINE:
        return _table_baseline(policy, "integration_outbox")
    if op is CatalogReadbackOperation.SCHEMA10_PRINCIPAL_PREFLIGHT:
        if request.role is not None:
            raise TypedPostgresError("POSTGRES_TYPED_READBACK_ARGUMENT_INVALID")
        app_runtime = ApprovedPostgresRole.APP_RUNTIME.value
        cleaner_app = CLEANER_APP_LOGIN_ROLE
        result = _json_query(
            policy,
            database=CLEANER_DATABASE,
            sql=(
                "SELECT json_build_object("
                "'transaction_read_only', current_setting('transaction_read_only'), "
                "'app_runtime', (SELECT json_build_object("
                "'role', r.rolname, 'can_login', r.rolcanlogin, 'inherit', r.rolinherit, "
                "'superuser', r.rolsuper, 'create_db', r.rolcreatedb, "
                "'create_role', r.rolcreaterole, 'replication', r.rolreplication, "
                "'bypass_rls', r.rolbypassrls) FROM pg_catalog.pg_roles r WHERE r.rolname="
                + _sql_literal(app_runtime)
                + "), 'cleaner_app_exists', EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname="
                + _sql_literal(cleaner_app)
                + "), 'memberships', COALESCE((SELECT json_agg(json_build_object("
                "'granted_role', target.rolname, 'member_role', member.rolname, "
                "'inherit', m.inherit_option, 'set', m.set_option, 'admin', m.admin_option) "
                "ORDER BY target.rolname, member.rolname) FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles target ON target.oid=m.roleid "
                "JOIN pg_catalog.pg_roles member ON member.oid=m.member WHERE "
                "target.rolname IN ("
                + _sql_literal(app_runtime)
                + ","
                + _sql_literal(cleaner_app)
                + ") OR member.rolname IN ("
                + _sql_literal(app_runtime)
                + ","
                + _sql_literal(cleaner_app)
                + ")), '[]'::json))::text"
            ),
        )
        expected_runtime = {
            "role": app_runtime,
            "can_login": False,
            "inherit": False,
            "superuser": False,
            "create_db": False,
            "create_role": False,
            "replication": False,
            "bypass_rls": False,
        }
        if result.get("transaction_read_only") != "on":
            raise TypedPostgresError("POSTGRES_SCHEMA10_PREFLIGHT_NOT_READ_ONLY")
        if result.get("app_runtime") != expected_runtime:
            raise TypedPostgresError("POSTGRES_SCHEMA10_PREFLIGHT_APP_RUNTIME_MISMATCH")
        if bool(result.get("cleaner_app_exists")):
            raise TypedPostgresError("POSTGRES_SCHEMA10_PREFLIGHT_CLEANER_APP_PRESENT")
        if result.get("memberships") != []:
            raise TypedPostgresError("POSTGRES_SCHEMA10_PREFLIGHT_MEMBERSHIP_PRESENT")
        return {**result, "preflight_profile": "TK43_DL85_SCHEMA10_PRINCIPAL_PREFLIGHT_V1", "status": "PASS"}
    raise TypedPostgresError("POSTGRES_TYPED_READBACK_OPERATION_UNSUPPORTED")


def _approval_evidence_source() -> ProtectedApprovalEvidenceSource:
    return ProtectedApprovalEvidenceSource(
        CANONICAL_TYPED_POSTGRES_APPROVAL_EVIDENCE_ROOT,
        CANONICAL_APPROVAL_EVIDENCE_OWNER_UID,
    )


def _controller_source_identity(entrypoint: str) -> tuple[str, str, str]:
    commit, tree = controller_git_identity(CANONICAL_CONTROLLER_SOURCE_ROOT)
    return commit, tree, entrypoint


def _resolve_public_operation_approval(
    *,
    change_id: str,
    gate_or_control_id: str,
    control_decision_ref: str,
    operation_kind: str,
    authorized_effect_scope: tuple[str, ...],
    entrypoint: str,
    target_identity: Mapping[str, Any],
    operation_artifact_identity: Mapping[str, Any] | None,
) -> ProductionOperationApprovalEvidenceV1:
    if not isinstance(gate_or_control_id, str) or not gate_or_control_id:
        raise TypedPostgresError("TYPED_POSTGRES_GATE_OR_CONTROL_ID_REQUIRED")
    _validate_control_identifiers(change_id, control_decision_ref, "approval-binding")
    try:
        commit, tree, public_entrypoint = _controller_source_identity(entrypoint)
        return resolve_production_operation_approval_evidence(
            _approval_evidence_source(),
            control_decision_ref=control_decision_ref,
            expected=ExpectedProductionOperationApprovalBinding(
                project_code=PROJECT_CODE,
                change_id=change_id,
                gate_or_control_id=gate_or_control_id,
                operation_kind=operation_kind,
                authorized_effect_scope=authorized_effect_scope,
                controller_commit=commit,
                controller_tree=tree,
                controller_entrypoint=public_entrypoint,
                target_identity=target_identity,
                operation_artifact_identity=operation_artifact_identity,
            ),
        )
    except PostgresApprovalEvidenceError as error:
        raise TypedPostgresError(error.code, error.detail) from error


def query_postgres_catalog(
    request: CatalogReadbackRequest,
    *,
    change_id: str | None = None,
    gate_or_control_id: str | None = None,
    control_decision_ref: str | None = None,
) -> Mapping[str, Any]:
    """Production readback bound to exact HQ approval and sealed Cleaner authority."""

    if not isinstance(change_id, str) or not isinstance(control_decision_ref, str):
        raise TypedPostgresError("TYPED_POSTGRES_APPROVAL_BINDING_REQUIRED")
    if not isinstance(gate_or_control_id, str):
        raise TypedPostgresError("TYPED_POSTGRES_GATE_OR_CONTROL_ID_REQUIRED")
    if type(request) is not CatalogReadbackRequest or type(request.operation) is not CatalogReadbackOperation:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    target = {
        "database": CLEANER_DATABASE,
        "catalog_operation": request.operation.value,
        "role": request.role.value if type(request.role) is ApprovedPostgresRole else None,
        "read_only": True,
        "catalog_profile": (
            "TK43_DL85_SCHEMA10_PRINCIPAL_PREFLIGHT_V1"
            if request.operation is CatalogReadbackOperation.SCHEMA10_PRINCIPAL_PREFLIGHT
            else None
        ),
    }
    _resolve_public_operation_approval(
        change_id=change_id, gate_or_control_id=gate_or_control_id,
        control_decision_ref=control_decision_ref,
        operation_kind="QUERY_POSTGRES_CATALOG",
        authorized_effect_scope=("READ_POSTGRES_CATALOG",),
        entrypoint="query_postgres_catalog", target_identity=target,
        operation_artifact_identity=None,
    )
    policy = _canonical_cleaner_postgres_policy()
    _validate_sealed_canonical_policy(policy)
    return _query_postgres_catalog(policy, request)


def _bootstrap_state(policy: _CleanerProductionPostgresPolicy) -> Mapping[str, Any]:
    roles = ",".join(_sql_literal(role) for role in _CANONICAL_BOOTSTRAP_ROLES)
    sql = f"""
SELECT json_build_object(
  'schema_owner', (SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname='propertyai'),
  'btree_gist', EXISTS(SELECT 1 FROM pg_catalog.pg_extension WHERE extname='btree_gist'),
  'roles', COALESCE((
    SELECT json_agg(json_build_object(
      'role', rolname, 'can_login', rolcanlogin, 'inherit', rolinherit,
      'superuser', rolsuper, 'create_db', rolcreatedb, 'create_role', rolcreaterole,
      'replication', rolreplication, 'bypass_rls', rolbypassrls
    ) ORDER BY rolname)
    FROM pg_catalog.pg_roles WHERE rolname IN ({roles})
  ), '[]'::json),
  'memberships', COALESCE((
    SELECT json_agg(json_build_object(
      'granted_role', target.rolname, 'member_role', member.rolname,
      'inherit', m.inherit_option, 'set', m.set_option, 'admin', m.admin_option,
      'grantor_superuser', grantor.rolsuper
    ) ORDER BY target.rolname, member.rolname)
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles target ON target.oid=m.roleid
    JOIN pg_catalog.pg_roles member ON member.oid=m.member
    JOIN pg_catalog.pg_roles grantor ON grantor.oid=m.grantor
    WHERE target.rolname IN ({roles}) OR member.rolname IN ({roles})
  ), '[]'::json)
)::text
"""
    return _json_query(policy, database=CLEANER_DATABASE, sql=sql)


def _bootstrap_is_fresh(state: Mapping[str, Any]) -> bool:
    return state.get("schema_owner") is None and state.get("roles") == [] and state.get("memberships") == [] and not bool(state.get("btree_gist"))


def _bootstrap_is_exact(state: Mapping[str, Any]) -> bool:
    if state.get("schema_owner") != CLEANER_OWNER_ROLE or not bool(state.get("btree_gist")):
        return False
    roles = state.get("roles")
    memberships = state.get("memberships")
    if not isinstance(roles, list) or not isinstance(memberships, list):
        return False
    expected_roles = {}
    for role in _CANONICAL_BOOTSTRAP_ROLES:
        expected_roles[role] = {
            "role": role,
            "can_login": role == CANONICAL_FLYWAY_LOGIN_ROLE,
            "inherit": False,
            "superuser": False,
            "create_db": False,
            "create_role": False,
            "replication": False,
            "bypass_rls": False,
        }
    actual_roles = {row.get("role"): row for row in roles if isinstance(row, dict)}
    if actual_roles != expected_roles:
        return False
    expected_memberships = {
        (CLEANER_OWNER_ROLE, CANONICAL_FLYWAY_GROUP_ROLE): (False, True, False, True),
        (CANONICAL_FLYWAY_GROUP_ROLE, CANONICAL_FLYWAY_LOGIN_ROLE): (False, True, False, True),
    }
    actual_memberships: dict[tuple[str, str], tuple[bool, bool, bool, bool]] = {}
    for row in memberships:
        if not isinstance(row, dict):
            return False
        key = (str(row.get("granted_role")), str(row.get("member_role")))
        actual_memberships[key] = (
            bool(row.get("inherit")),
            bool(row.get("set")),
            bool(row.get("admin")),
            bool(row.get("grantor_superuser")),
        )
    return actual_memberships == expected_memberships


def _state_fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_request_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _canonical_request_value(v) for k, v in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, tuple):
        return [_canonical_request_value(v) for v in value]
    return value


def _request_fingerprint(
    *, change_id: str, control_decision_ref: str, deployment_id: str,
    operation_type: TypedOperationType, target_service: str, target_database: str | None,
    principal_identity: str | None, credential_reference: CredentialReference | None,
    artifact_path: str | None, artifact_sha256: str | None, request: object,
    expected_before_identity: Mapping[str, Any], desired_after_identity: Mapping[str, Any],
) -> str:
    request_fields = {
        field.name: _canonical_request_value(getattr(request, field.name))
        for field in fields(type(request))
    }
    material = {
        "receipt_version": 1, "change_id": change_id,
        "control_decision_ref": control_decision_ref, "deployment_id": deployment_id,
        "operation_id": deployment_id, "operation_type": operation_type.value,
        "target_service": target_service, "target_database": target_database,
        "principal_identity": principal_identity,
        "credential_reference": credential_reference.value if credential_reference else None,
        "artifact_path": artifact_path, "artifact_sha256": artifact_sha256,
        "request": request_fields,
        "expected_before_identity": _canonical_request_value(expected_before_identity),
        "desired_after_identity": _canonical_request_value(desired_after_identity),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _receipt_from_row(row: Mapping[str, Any]) -> TypedPostgresOperationReceipt:
    return TypedPostgresOperationReceipt(
        receipt_version=int(row["receipt_version"]), change_id=str(row["change_id"]),
        control_decision_ref=str(row["control_decision_ref"]), deployment_id=str(row["deployment_id"]),
        operation_id=str(row["operation_id"]), operation_type=str(row["operation_type"]),
        receipt_phase=str(row["receipt_phase"]), target_service=str(row["target_service"]),
        target_database=row["target_database"], principal_identity=row["principal_identity"],
        credential_reference=row["credential_reference"], artifact_path=row["artifact_path"],
        artifact_sha256=row["artifact_sha256"], request_fingerprint=str(row["request_fingerprint"]),
        before_state_fingerprint=str(row["before_state_fingerprint"]),
        after_state_fingerprint=row["after_state_fingerprint"], effect_status=str(row["effect_status"]),
        w08_fencing_token=int(row["w08_fencing_token"]), created_at=str(row["created_at"]),
    )


def _validate_control_identifiers(change_id: str, control_decision_ref: str, operation_id: str) -> None:
    if not isinstance(change_id, str) or not change_id:
        raise TypedPostgresError("TYPED_POSTGRES_CHANGE_ID_REQUIRED")
    if not isinstance(control_decision_ref, str) or not control_decision_ref:
        raise TypedPostgresError("TYPED_POSTGRES_CONTROL_DECISION_REF_REQUIRED")
    _validate_operation_id(operation_id)


def _safe_error_code(error: BaseException) -> str:
    return error.code if isinstance(error, StoreError) else type(error).__name__


def _assert_current_typed_authority(
    store: ControlStore, authority: ProductionMutationAuthority, *, change_id: str, deployment_id: str,
) -> int:
    authority.revalidate()
    row = store.get_global_production_writer_lease()
    if (
        row["state"] != "HELD"
        or row["writer_class"] != "W08_CONTROLLED_PRODUCTION_DEPLOYMENT"
        or row["change_id"] != change_id
        or row["slice_id"] != deployment_id
    ):
        raise TypedPostgresError("TYPED_POSTGRES_W08_RECEIPT_AUTHORITY_MISSING")
    store.assert_current_global_writer(str(row["owner_id"]), int(row["fencing_token"]))
    return int(row["fencing_token"])


def _append_receipt(
    store: ControlStore, intent: _ReceiptIntent, *, phase: str,
    before_state_fingerprint: str, after_state_fingerprint: str | None,
    effect_status: str, fencing_token: int,
) -> TypedPostgresOperationReceipt:
    row = store.append_typed_postgres_operation_receipt_event(
        receipt_version=1, change_id=intent.change_id,
        control_decision_ref=intent.control_decision_ref, deployment_id=intent.deployment_id,
        operation_id=intent.operation_id, operation_type=intent.operation_type.value,
        receipt_phase=phase, target_service=intent.target_service,
        target_database=intent.target_database, principal_identity=intent.principal_identity,
        credential_reference=(intent.credential_reference.value if intent.credential_reference else None),
        artifact_path=intent.artifact_path, artifact_sha256=intent.artifact_sha256,
        request_fingerprint=intent.request_fingerprint,
        before_state_fingerprint=before_state_fingerprint,
        after_state_fingerprint=after_state_fingerprint, effect_status=effect_status,
        w08_fencing_token=fencing_token,
        created_at=datetime.now(timezone.utc).isoformat(timespec="microseconds"),
    )
    return _receipt_from_row(row)


def _persist_prepared_receipt(
    store: ControlStore, authority: ProductionMutationAuthority,
    intent: _ReceiptIntent, before_state: Mapping[str, Any],
) -> TypedPostgresOperationReceipt:
    token = _assert_current_typed_authority(
        store, authority, change_id=intent.change_id, deployment_id=intent.deployment_id
    )
    try:
        receipt = _append_receipt(
            store, intent, phase="PREPARED",
            before_state_fingerprint=_state_fingerprint(before_state),
            after_state_fingerprint=None, effect_status="PENDING", fencing_token=token,
        )
    except BaseException as error:
        raise TypedPostgresError(
            "TYPED_POSTGRES_PRE_EFFECT_RECEIPT_DURABILITY_FAILED", _safe_error_code(error)
        ) from error
    _assert_current_typed_authority(
        store, authority, change_id=intent.change_id, deployment_id=intent.deployment_id
    )
    return receipt


class EffectSuccessReceiptFailureReconciliationRequired(TypedPostgresError):
    def __init__(self, metadata: Mapping[str, Any]) -> None:
        self.metadata = dict(metadata)
        super().__init__(
            "EFFECT_SUCCESS_RECEIPT_FAILURE_RECONCILIATION_REQUIRED",
            json.dumps(self.metadata, sort_keys=True, separators=(",", ":")),
        )


def _validate_effect_postcondition(effect: _TypedEffectResult, after: Mapping[str, Any]) -> str:
    if effect.process is not None and effect.process.exit_status != 0:
        raise TypedPostgresError(
            "TYPED_POSTGRES_EFFECT_FAILED_WITH_FACTUAL_STATE",
            json.dumps({"after_state_fingerprint": _state_fingerprint(after), "exit_status": effect.process.exit_status}, sort_keys=True),
        )
    if effect.operation_type is TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE:
        from adcp.cleaner_worker_control import WORKER_SQL_PATH, WORKER_SQL_SHA256, _validate_worker_state
        if (effect.artifact_path, effect.artifact_sha256) == (WORKER_SQL_PATH, WORKER_SQL_SHA256):
            _validate_worker_state(after, final=True)
        elif effect.artifact_path != BOOTSTRAP_SQL_PATH:
            raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_NOT_APPROVED")
        elif not _bootstrap_is_exact(after):
            raise TypedPostgresError("POSTGRES_BOOTSTRAP_POSTCONDITION_MISMATCH")
    elif effect.operation_type is TypedOperationType.TRANSITION_DATABASE_OWNER:
        if after.get("owner") != CLEANER_OWNER_ROLE or not bool(after.get("exists")):
            raise TypedPostgresError("POSTGRES_DATABASE_OWNER_POSTCONDITION_MISMATCH")
    elif effect.operation_type is TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE:
        if not bool(after.get("exists")) or after.get("role") not in {
            CANONICAL_FLYWAY_LOGIN_ROLE, STAGE_B_LOGIN_ROLE, CLEANER_APP_LOGIN_ROLE, CLEANER_WORKER_LOGIN_ROLE
        }:
            raise TypedPostgresError("POSTGRES_ROLE_PASSWORD_POSTCONDITION_MISMATCH")
        if after.get("role") == CLEANER_WORKER_LOGIN_ROLE:
            from adcp.cleaner_worker_control import _validate_worker_login_proof
            _validate_worker_login_proof(after)
    elif effect.operation_type is TypedOperationType.PROVISION_CLEANER_APP_PRINCIPAL:
        _validate_cleaner_principal_state(after, final=True)
    else:
        raise TypedPostgresError("TYPED_POSTGRES_OPERATION_TYPE_INVALID")
    return "NOOP_EXACT" if effect.status == "NOOP_EXACT" else "APPLIED"


def _persist_final_receipt(
    store: ControlStore, authority: ProductionMutationAuthority,
    intent: _ReceiptIntent, evidence: tuple[DeploymentEffectEvidence, ...],
) -> TypedPostgresOperationReceipt:
    if len(evidence) != 1 or not isinstance(evidence[0].effect_result, _TypedEffectResult):
        raise TypedPostgresError("TYPED_POSTGRES_EVIDENCE_SHAPE_INVALID")
    effect = evidence[0].effect_result
    after = evidence[0].readback
    if not isinstance(after, Mapping):
        raise TypedPostgresError("TYPED_POSTGRES_FACTUAL_READBACK_INVALID")
    effect_status = _validate_effect_postcondition(effect, after)
    after_fp = _state_fingerprint(after)
    before_fp = _state_fingerprint(effect.before_state)
    token = _assert_current_typed_authority(
        store, authority, change_id=intent.change_id, deployment_id=intent.deployment_id
    )
    try:
        return _append_receipt(
            store, intent, phase="FINAL", before_state_fingerprint=before_fp,
            after_state_fingerprint=after_fp, effect_status=effect_status, fencing_token=token,
        )
    except BaseException as error:
        raise EffectSuccessReceiptFailureReconciliationRequired({
            "change_id": intent.change_id,
            "control_decision_ref": intent.control_decision_ref,
            "deployment_id": intent.deployment_id,
            "operation_id": intent.operation_id,
            "operation_type": intent.operation_type.value,
            "w08_fencing_token": token,
            "effect_confirmed": True,
            "after_state_fingerprint": after_fp,
            "receipt_durability_failure": _safe_error_code(error),
        }) from error


def _replay_receipt_if_present(
    store: ControlStore, intent: _ReceiptIntent, *, factual_readback, final_validator,
) -> TypedPostgresOperationReceipt | None:
    try:
        state = store.typed_postgres_operation_receipt_state(intent.operation_id, intent.request_fingerprint)
    except StoreError as error:
        if error.code == "TYPED_POSTGRES_OPERATION_REQUEST_CONFLICT":
            raise TypedPostgresError("TYPED_POSTGRES_OPERATION_REQUEST_CONFLICT") from error
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_READ_FAILED", error.code) from error
    if state["state"] == "ABSENT":
        return None
    if state["state"] == "PREPARED_ONLY":
        raise TypedPostgresError("CONTROLLED_DEPLOYMENT_RECONCILIATION_REQUIRED", intent.operation_id)
    final = state["final"]
    if final is None:
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_STATE_INVALID")
    after = factual_readback()
    if not isinstance(after, Mapping) or _state_fingerprint(after) != final["after_state_fingerprint"]:
        raise TypedPostgresError("TYPED_POSTGRES_FINAL_FACTUAL_STATE_RECONCILIATION_REQUIRED")
    final_validator(after)
    return _receipt_from_row(final)


def _execute_authorized_sql_file(
    store: ControlStore,
    *,
    change_id: str,
    authority: ProductionMutationAuthority,
    policy: _CleanerProductionPostgresPolicy,
    request: _ExecuteAuthorizedSqlFileIntent,
    control_decision_ref: str = "TYPED/PG/TEST",
    start_heartbeat: bool = True,
) -> TypedPostgresOperationReceipt:
    _validate_control_identifiers(change_id, control_decision_ref, request.operation_id)
    _validate_no_generic_escape_fields(request)
    if request.target_service != CLEANER_TARGET_SERVICE:
        raise TypedPostgresError("POSTGRES_TARGET_SERVICE_NOT_APPROVED")
    if request.database != CLEANER_DATABASE:
        raise TypedPostgresError("POSTGRES_DATABASE_NOT_APPROVED")
    if request.execution_role != CLEANER_DBA_ROLE:
        raise TypedPostgresError("POSTGRES_EXECUTION_PRINCIPAL_NOT_APPROVED")
    if request.sql_file_path != policy.approved_bootstrap_path:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_NOT_APPROVED")
    if request.expected_sql_sha256 != policy.approved_bootstrap_sha256:
        raise TypedPostgresError("POSTGRES_SQL_ARTIFACT_HASH_NOT_APPROVED")
    if request.credential_reference is not CredentialReference.DBA_PGPASS:
        raise TypedPostgresError("POSTGRES_EXECUTION_CREDENTIAL_NOT_APPROVED")
    request_fp = _request_fingerprint(
        change_id=change_id, control_decision_ref=control_decision_ref,
        deployment_id=request.operation_id,
        operation_type=TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE,
        target_service=CLEANER_TARGET_SERVICE, target_database=CLEANER_DATABASE,
        principal_identity=CLEANER_DBA_ROLE,
        credential_reference=CredentialReference.DBA_PGPASS,
        artifact_path=request.sql_file_path, artifact_sha256=request.expected_sql_sha256,
        request=request,
        expected_before_identity={"allowed": ["FRESH", "EXACT_CANONICAL_BOOTSTRAP"]},
        desired_after_identity={"schema_owner": CLEANER_OWNER_ROLE, "bootstrap_sha256": request.expected_sql_sha256},
    )
    intent = _ReceiptIntent(
        change_id, control_decision_ref, request.operation_id, request.operation_id,
        TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE, CLEANER_TARGET_SERVICE,
        CLEANER_DATABASE, CLEANER_DBA_ROLE, CredentialReference.DBA_PGPASS,
        request.sql_file_path, request.expected_sql_sha256, request_fp,
    )

    def validate_final(state: Mapping[str, Any]) -> None:
        if not _bootstrap_is_exact(state):
            raise TypedPostgresError("POSTGRES_BOOTSTRAP_IDEMPOTENCY_READBACK_MISMATCH")

    replay = _replay_receipt_if_present(
        store, intent, factual_readback=lambda: _bootstrap_state(policy), final_validator=validate_final
    )
    if replay is not None:
        return replay

    receipt_box: list[TypedPostgresOperationReceipt] = []

    def effect() -> _TypedEffectResult:
        artifact = _resolve_artifact(policy, request)
        _validate_credential(policy, request.credential_reference)
        _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        before = _bootstrap_state(policy)
        if not _bootstrap_is_fresh(before) and not _bootstrap_is_exact(before):
            raise TypedPostgresError("POSTGRES_BOOTSTRAP_PARTIAL_STATE_REJECTED", _state_fingerprint(before))
        _persist_prepared_receipt(store, authority, intent, before)
        if _bootstrap_is_exact(before):
            return _TypedEffectResult(
                TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE, "NOOP_EXACT", before, None,
                artifact.relative_path, artifact.sha256, request.credential_reference,
            )
        _revalidate_path_fingerprint(
            artifact.absolute_path, artifact.fingerprint, code_prefix="POSTGRES_SQL_ARTIFACT"
        )
        process = _run_psql(
            policy, database=request.database, execution_role=request.execution_role,
            stdin_sql=artifact.bytes_value, connection_credential=request.credential_reference,
        )
        return _TypedEffectResult(
            TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE, "APPLIED", before, process,
            artifact.relative_path, artifact.sha256, request.credential_reference,
        )

    evidence = run_controlled_deployment(
        store, change_id=change_id, deployment_id=request.operation_id, authority=authority,
        steps=(DeploymentStep("TYPED_POSTGRES_BOOTSTRAP", effect, lambda _result: _bootstrap_state(policy)),),
        persist_result=lambda items: receipt_box.append(
            _persist_final_receipt(store, authority, intent, items)
        ),
        control_decision_ref=control_decision_ref, start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or len(receipt_box) != 1:
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_MISSING")
    return receipt_box[0]


def _canonical_typed_postgres_control_store() -> ControlStore:
    """Open only an exact finite supported canonical DCS schema, never migrate it."""

    try:
        uri = CANONICAL_PRODUCTION_CONTROL_STORE.resolve(strict=False).as_uri() + "?mode=ro&immutable=1"
        readonly = sqlite3.connect(uri, uri=True)
        try:
            row = readonly.execute("SELECT max(version) FROM schema_migration").fetchone()
            version = None if row is None else row[0]
            if version not in SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS:
                raise TypedPostgresError(
                    "TYPED_POSTGRES_CONTROL_STORE_SCHEMA_UNSUPPORTED", str(version)
                )
            try:
                validate_schema(readonly, target_version=int(version))
            except StoreError as error:
                raise TypedPostgresError(
                    "TYPED_POSTGRES_CONTROL_STORE_SCHEMA_PROFILE_INVALID", error.code
                ) from error
        finally:
            readonly.close()
    except TypedPostgresError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise TypedPostgresError("TYPED_POSTGRES_CONTROL_STORE_SCHEMA_UNREADABLE") from error
    return ControlStore(
        CANONICAL_PRODUCTION_CONTROL_STORE,
        migrate_schema=False,
        require_schema_version=int(version),
        global_writer_guard_required=True,
    )


def _canonical_typed_postgres_source_authority(
    policy: _CleanerProductionPostgresPolicy,
) -> GitSourceAuthority:
    return GitSourceAuthority(
        policy.source_root, policy.expected_source_head, require_clean=True
    )


def execute_authorized_sql_file(
    *,
    change_id: str,
    request: ExecuteAuthorizedSqlFileRequest,
    control_decision_ref: str,
    gate_or_control_id: str | None = None,
) -> TypedPostgresOperationReceipt:
    """Execute the sealed Cleaner bootstrap under canonical source/store authority."""

    if type(request) is not ExecuteAuthorizedSqlFileRequest:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    policy = _canonical_cleaner_postgres_policy()
    _validate_sealed_canonical_policy(policy)
    _resolve_public_operation_approval(
        change_id=change_id, gate_or_control_id=gate_or_control_id or "",
        control_decision_ref=control_decision_ref,
        operation_kind=TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE.value,
        authorized_effect_scope=("EXECUTE_EXACT_SQL_ARTIFACT",),
        entrypoint="execute_authorized_sql_file",
        target_identity={
            "database": CLEANER_DATABASE, "execution_role": CLEANER_DBA_ROLE,
            "sql_artifact_path": policy.approved_bootstrap_path,
        },
        operation_artifact_identity={"sha256": policy.approved_bootstrap_sha256},
    )
    intent = _ExecuteAuthorizedSqlFileIntent(
        target_service=CLEANER_TARGET_SERVICE,
        database=CLEANER_DATABASE,
        execution_role=CLEANER_DBA_ROLE,
        sql_file_path=policy.approved_bootstrap_path,
        expected_sql_sha256=policy.approved_bootstrap_sha256,
        credential_reference=CredentialReference.DBA_PGPASS,
        operation_id=request.operation_id,
    )
    authority = _canonical_typed_postgres_source_authority(policy)
    with _canonical_typed_postgres_control_store() as store:
        return _execute_authorized_sql_file(
            store,
            change_id=change_id,
            authority=authority,
            policy=policy,
            request=intent,
            control_decision_ref=control_decision_ref,
            start_heartbeat=True,
        )


def _transition_database_owner(
    store: ControlStore,
    *,
    change_id: str,
    authority: ProductionMutationAuthority,
    policy: _CleanerProductionPostgresPolicy,
    request: _TransitionDatabaseOwnerIntent,
    control_decision_ref: str = "TYPED/PG/TEST",
    start_heartbeat: bool = True,
) -> TypedPostgresOperationReceipt:
    _validate_control_identifiers(change_id, control_decision_ref, request.operation_id)
    _validate_no_generic_escape_fields(request)
    if request.target_service != CLEANER_TARGET_SERVICE or request.database != CLEANER_DATABASE:
        raise TypedPostgresError("POSTGRES_OWNER_TRANSITION_TARGET_NOT_APPROVED")
    if request.expected_current_owner != CLEANER_DBA_ROLE or request.new_owner != CLEANER_OWNER_ROLE:
        raise TypedPostgresError("POSTGRES_OWNER_TRANSITION_POLICY_NOT_APPROVED")
    request_fp = _request_fingerprint(
        change_id=change_id, control_decision_ref=control_decision_ref,
        deployment_id=request.operation_id,
        operation_type=TypedOperationType.TRANSITION_DATABASE_OWNER,
        target_service=CLEANER_TARGET_SERVICE, target_database=CLEANER_DATABASE,
        principal_identity=CLEANER_DBA_ROLE,
        credential_reference=CredentialReference.DBA_PGPASS,
        artifact_path=None, artifact_sha256=None, request=request,
        expected_before_identity={"database_owner": CLEANER_DBA_ROLE},
        desired_after_identity={"database_owner": CLEANER_OWNER_ROLE},
    )
    intent = _ReceiptIntent(
        change_id, control_decision_ref, request.operation_id, request.operation_id,
        TypedOperationType.TRANSITION_DATABASE_OWNER, CLEANER_TARGET_SERVICE,
        CLEANER_DATABASE, CLEANER_DBA_ROLE, CredentialReference.DBA_PGPASS,
        None, None, request_fp,
    )

    def owner_state() -> Mapping[str, Any]:
        return _query_postgres_catalog(policy, CatalogReadbackRequest(CatalogReadbackOperation.DATABASE_OWNER))

    def validate_final(state: Mapping[str, Any]) -> None:
        if not bool(state.get("exists")) or state.get("owner") != CLEANER_OWNER_ROLE:
            raise TypedPostgresError("POSTGRES_DATABASE_OWNER_POSTCONDITION_MISMATCH")

    replay = _replay_receipt_if_present(
        store, intent, factual_readback=owner_state, final_validator=validate_final
    )
    if replay is not None:
        return replay

    receipt_box: list[TypedPostgresOperationReceipt] = []

    def effect() -> _TypedEffectResult:
        _validate_credential(policy, CredentialReference.DBA_PGPASS)
        _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        before = owner_state()
        owner = before.get("owner")
        if not bool(before.get("exists")) or owner not in {CLEANER_DBA_ROLE, CLEANER_OWNER_ROLE}:
            raise TypedPostgresError("POSTGRES_DATABASE_OWNER_COMPARE_BEFORE_MISMATCH", _state_fingerprint(before))
        _persist_prepared_receipt(store, authority, intent, before)
        if owner == CLEANER_OWNER_ROLE:
            return _TypedEffectResult(
                TypedOperationType.TRANSITION_DATABASE_OWNER, "NOOP_EXACT", before, None,
                credential_reference=CredentialReference.DBA_PGPASS,
            )
        sql = (
            "ALTER DATABASE " + _sql_identifier(CLEANER_DATABASE)
            + " OWNER TO " + _sql_identifier(CLEANER_OWNER_ROLE) + ";\n"
        ).encode("utf-8")
        process = _run_psql(
            policy, database="postgres", execution_role=CLEANER_DBA_ROLE,
            stdin_sql=sql, connection_credential=CredentialReference.DBA_PGPASS,
        )
        return _TypedEffectResult(
            TypedOperationType.TRANSITION_DATABASE_OWNER, "APPLIED", before, process,
            credential_reference=CredentialReference.DBA_PGPASS,
        )

    evidence = run_controlled_deployment(
        store, change_id=change_id, deployment_id=request.operation_id, authority=authority,
        steps=(DeploymentStep("TYPED_POSTGRES_DATABASE_OWNER", effect, lambda _result: owner_state()),),
        persist_result=lambda items: receipt_box.append(
            _persist_final_receipt(store, authority, intent, items)
        ),
        control_decision_ref=control_decision_ref, start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or len(receipt_box) != 1:
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_MISSING")
    return receipt_box[0]


def transition_database_owner(
    *,
    change_id: str,
    request: TransitionDatabaseOwnerRequest,
    control_decision_ref: str,
    gate_or_control_id: str | None = None,
) -> TypedPostgresOperationReceipt:
    """Perform only the canonical Cleaner DBA -> owner transition."""

    if type(request) is not TransitionDatabaseOwnerRequest:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    policy = _canonical_cleaner_postgres_policy()
    _validate_sealed_canonical_policy(policy)
    _resolve_public_operation_approval(
        change_id=change_id, gate_or_control_id=gate_or_control_id or "",
        control_decision_ref=control_decision_ref,
        operation_kind=TypedOperationType.TRANSITION_DATABASE_OWNER.value,
        authorized_effect_scope=("TRANSITION_DATABASE_OWNER",),
        entrypoint="transition_database_owner",
        target_identity={
            "database": CLEANER_DATABASE, "from_owner": CLEANER_DBA_ROLE,
            "to_owner": CLEANER_OWNER_ROLE,
        },
        operation_artifact_identity=None,
    )
    intent = _TransitionDatabaseOwnerIntent(
        target_service=CLEANER_TARGET_SERVICE,
        database=CLEANER_DATABASE,
        expected_current_owner=CLEANER_DBA_ROLE,
        new_owner=CLEANER_OWNER_ROLE,
        operation_id=request.operation_id,
    )
    authority = _canonical_typed_postgres_source_authority(policy)
    with _canonical_typed_postgres_control_store() as store:
        return _transition_database_owner(
            store,
            change_id=change_id,
            authority=authority,
            policy=policy,
            request=intent,
            control_decision_ref=control_decision_ref,
            start_heartbeat=True,
        )


def _apply_role_password_from_protected_file(
    store: ControlStore,
    *,
    change_id: str,
    authority: ProductionMutationAuthority,
    policy: _CleanerProductionPostgresPolicy,
    request: _ApplyRolePasswordFromProtectedFileIntent,
    control_decision_ref: str = "TYPED/PG/TEST",
    start_heartbeat: bool = True,
) -> TypedPostgresOperationReceipt:
    _validate_control_identifiers(change_id, control_decision_ref, request.operation_id)
    _validate_no_generic_escape_fields(request)
    allowed = {
        ApprovedPostgresRole.FLYWAY: CredentialReference.FLYWAY_PASSWORD,
        ApprovedPostgresRole.STAGE_B: CredentialReference.STAGE_B_PGPASS,
        ApprovedPostgresRole.CLEANER_APP: CredentialReference.APP_PGPASS,
        ApprovedPostgresRole.CLEANER_WORKER: CredentialReference.WORKER_PGPASS,
    }
    if type(request.role) is not ApprovedPostgresRole or request.role not in allowed:
        raise TypedPostgresError("POSTGRES_PASSWORD_ROLE_NOT_APPROVED")
    if request.credential_file_reference is not allowed[request.role]:
        raise TypedPostgresError("POSTGRES_PASSWORD_CREDENTIAL_BINDING_MISMATCH")
    if request.expected_file_owner_uid != policy.expected_secret_owner_uid or request.expected_file_mode != 0o600:
        raise TypedPostgresError("POSTGRES_PASSWORD_CREDENTIAL_EXPECTATION_NOT_APPROVED")
    if request.role is ApprovedPostgresRole.CLEANER_WORKER:
        if any(key.startswith("PG") for key in os.environ):
            raise TypedPostgresError("POSTGRES_WORKER_AMBIENT_CREDENTIAL_FORBIDDEN")
        if store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0] != 10:
            raise TypedPostgresError("POSTGRES_WORKER_REQUIRES_SCHEMA10")
        validate_schema(store.connection, target_version=10)
    request_fp = _request_fingerprint(
        change_id=change_id, control_decision_ref=control_decision_ref,
        deployment_id=request.operation_id,
        operation_type=TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE,
        target_service=CLEANER_TARGET_SERVICE, target_database=CLEANER_DATABASE,
        principal_identity=request.role.value,
        credential_reference=request.credential_file_reference,
        artifact_path=None, artifact_sha256=None, request=request,
        expected_before_identity={"role": request.role.value, "exists": True},
        desired_after_identity={
            "role": request.role.value,
            "credential_reference": request.credential_file_reference.value,
        },
    )
    intent = _ReceiptIntent(
        change_id, control_decision_ref, request.operation_id, request.operation_id,
        TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE,
        CLEANER_TARGET_SERVICE, CLEANER_DATABASE, request.role.value,
        request.credential_file_reference, None, None, request_fp,
    )

    def role_state() -> Mapping[str, Any]:
        return _query_postgres_catalog(
            policy, CatalogReadbackRequest(CatalogReadbackOperation.ROLE_ATTRIBUTES, request.role)
        )

    def validate_final(state: Mapping[str, Any]) -> None:
        if not bool(state.get("exists")) or state.get("role") != request.role.value:
            raise TypedPostgresError("POSTGRES_ROLE_PASSWORD_POSTCONDITION_MISMATCH")
        if request.role is ApprovedPostgresRole.CLEANER_WORKER:
            from adcp.cleaner_worker_control import _validate_worker_login_proof
            _validate_worker_login_proof(state)

    def post_password_state() -> Mapping[str, Any]:
        if request.role is ApprovedPostgresRole.CLEANER_WORKER:
            from adcp.cleaner_worker_control import _worker_login_proof
            return _worker_login_proof(policy)
        return role_state()

    replay = _replay_receipt_if_present(
        store, intent, factual_readback=post_password_state, final_validator=validate_final
    )
    if replay is not None:
        return replay

    receipt_box: list[TypedPostgresOperationReceipt] = []

    def effect() -> _TypedEffectResult:
        connection = _validate_credential(policy, CredentialReference.DBA_PGPASS)
        material = _validate_credential(
            policy, request.credential_file_reference,
            expected_mode=request.expected_file_mode,
            expected_uid=request.expected_file_owner_uid,
            reveal_text=True,
        )
        _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        before = role_state()
        if not bool(before.get("exists")):
            raise TypedPostgresError("POSTGRES_PASSWORD_TARGET_ROLE_ABSENT", _state_fingerprint(before))
        if request.role is ApprovedPostgresRole.CLEANER_WORKER:
            from adcp.cleaner_worker_control import _worker_state, _validate_worker_state
            _validate_worker_state(_worker_state(policy), final=True)
        _persist_prepared_receipt(store, authority, intent, before)
        secret_value = _password_from_credential(policy, material)
        _revalidate_path_fingerprint(
            connection.spec.path, connection.fingerprint, code_prefix="POSTGRES_CREDENTIAL_FILE"
        )
        _revalidate_path_fingerprint(
            material.spec.path, material.fingerprint, code_prefix="POSTGRES_CREDENTIAL_FILE"
        )
        statement = (
            "SET standard_conforming_strings = on;\nALTER ROLE "
            + _sql_identifier(request.role.value)
            + " PASSWORD " + _sql_literal(secret_value) + ";\n"
        ).encode("utf-8")
        if request.role is ApprovedPostgresRole.CLEANER_WORKER:
            from adcp.cleaner_worker_control import _worker_pg_mutation
            with _worker_pg_mutation(store,authority,change_id,request.operation_id):
                process = _run_psql(
                    policy, database="postgres", execution_role=CLEANER_DBA_ROLE,
                    stdin_sql=statement, connection_credential=CredentialReference.DBA_PGPASS,
                    secrets_to_redact=(secret_value,),
                )
        else:
            process = _run_psql(
                policy, database="postgres", execution_role=CLEANER_DBA_ROLE,
                stdin_sql=statement, connection_credential=CredentialReference.DBA_PGPASS,
                secrets_to_redact=(secret_value,),
            )
        secret_value = ""
        statement = b""
        return _TypedEffectResult(
            TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE, "APPLIED", before, process,
            credential_reference=request.credential_file_reference,
        )

    evidence = run_controlled_deployment(
        store, change_id=change_id, deployment_id=request.operation_id, authority=authority,
        steps=(DeploymentStep("TYPED_POSTGRES_ROLE_PASSWORD", effect, lambda _result: post_password_state()),),
        persist_result=lambda items: receipt_box.append(
            _persist_final_receipt(store, authority, intent, items)
        ),
        control_decision_ref=control_decision_ref, start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or len(receipt_box) != 1:
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_MISSING")
    return receipt_box[0]


def apply_role_password_from_protected_file(
    *,
    change_id: str,
    request: ApplyRolePasswordFromProtectedFileRequest,
    control_decision_ref: str,
    gate_or_control_id: str | None = None,
) -> TypedPostgresOperationReceipt:
    """Apply one sealed credential operation without caller-supplied role/path authority."""

    if type(request) is not ApplyRolePasswordFromProtectedFileRequest:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    policy = _canonical_cleaner_postgres_policy()
    _validate_sealed_canonical_policy(policy)
    sealed = {
        PasswordCredentialOperation.FLYWAY: (
            ApprovedPostgresRole.FLYWAY, CredentialReference.FLYWAY_PASSWORD
        ),
        PasswordCredentialOperation.STAGE_B: (
            ApprovedPostgresRole.STAGE_B, CredentialReference.STAGE_B_PGPASS
        ),
        PasswordCredentialOperation.CLEANER_APP: (
            ApprovedPostgresRole.CLEANER_APP, CredentialReference.APP_PGPASS
        ),
        PasswordCredentialOperation.CLEANER_WORKER: (
            ApprovedPostgresRole.CLEANER_WORKER, CredentialReference.WORKER_PGPASS
        ),
    }
    if type(request.operation) is not PasswordCredentialOperation or request.operation not in sealed:
        raise TypedPostgresError("POSTGRES_PASSWORD_OPERATION_NOT_APPROVED")
    role, credential = sealed[request.operation]
    worker_source = (
        _controller_source_identity("apply_role_password_from_protected_file")[:2]
        if role is ApprovedPostgresRole.CLEANER_WORKER else None
    )
    target_identity={
        "database": CLEANER_DATABASE, "role": role.value,
        "credential_reference": credential.value,
        **({"operation_id": request.operation_id} if role is ApprovedPostgresRole.CLEANER_WORKER else {}),
    }
    approval = _resolve_public_operation_approval(
        change_id=change_id, gate_or_control_id=gate_or_control_id or "",
        control_decision_ref=control_decision_ref,
        operation_kind=TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE.value,
        authorized_effect_scope=("APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",),
        entrypoint="apply_role_password_from_protected_file",
        target_identity=target_identity,
        operation_artifact_identity=None,
    )
    intent = _ApplyRolePasswordFromProtectedFileIntent(
        role=role,
        credential_file_reference=credential,
        expected_file_owner_uid=policy.expected_secret_owner_uid,
        expected_file_mode=0o600,
        operation_id=request.operation_id,
    )
    if role is ApprovedPostgresRole.CLEANER_WORKER:
        if _controller_source_identity("apply_role_password_from_protected_file")[:2] != worker_source:
            raise TypedPostgresError("WORKER_APPROVAL_SOURCE_CHANGED")
        commit, _tree = worker_source
        from adcp.cleaner_worker_control import _WorkerAuthority
        binding=ExpectedProductionOperationApprovalBinding(
            project_code=PROJECT_CODE,change_id=change_id,gate_or_control_id=gate_or_control_id or "",
            operation_kind=TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE.value,
            authorized_effect_scope=("APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",),
            controller_commit=commit,controller_tree=_tree,
            controller_entrypoint="apply_role_password_from_protected_file",
            target_identity=target_identity,operation_artifact_identity=None)
        authority = _WorkerAuthority(CANONICAL_CONTROLLER_SOURCE_ROOT,commit,_tree,
                                     approval.evidence_sha256,binding,control_decision_ref)
    else:
        authority = _canonical_typed_postgres_source_authority(policy)
    with _canonical_typed_postgres_control_store() as store:
        return _apply_role_password_from_protected_file(
            store,
            change_id=change_id,
            authority=authority,
            policy=policy,
            request=intent,
            control_decision_ref=control_decision_ref,
            start_heartbeat=True,
        )



def _cleaner_principal_expected_state() -> dict[str, Any]:
    def role(name: str, login: bool) -> dict[str, Any]:
        return {
            "role": name, "can_login": login, "inherit": False,
            "superuser": False, "create_db": False, "create_role": False,
            "replication": False, "bypass_rls": False,
        }
    return {
        "database": CLEANER_DATABASE,
        "principal": {**role(CLEANER_APP_LOGIN_ROLE, True), "password_unset": True},
        "app_runtime": role(ApprovedPostgresRole.APP_RUNTIME.value, False),
        "memberships": [{
            "granted_role": ApprovedPostgresRole.APP_RUNTIME.value,
            "member_role": CLEANER_APP_LOGIN_ROLE,
            "inherit": False, "set": True, "admin": False,
        }],
    }


def _cleaner_principal_state_sql() -> str:
    # Only a boolean password-presence fact leaves pg_authid. No password value
    # is selected, accepted as input, or included in approval/effect scope.
    def role_sql(name: str, principal: bool = False) -> str:
        password = ", 'password_unset', r.rolpassword IS NULL" if principal else ""
        return (
            "(SELECT jsonb_build_object('role', r.rolname, 'can_login', r.rolcanlogin, "
            "'inherit', r.rolinherit, 'superuser', r.rolsuper, 'create_db', r.rolcreatedb, "
            "'create_role', r.rolcreaterole, 'replication', r.rolreplication, "
            "'bypass_rls', r.rolbypassrls" + password + ") FROM pg_catalog."
            + ("pg_authid" if principal else "pg_roles") + " r WHERE r.rolname="
            + _sql_literal(name) + ")"
        )
    return (
        "SELECT jsonb_build_object('database', current_database(), 'principal', "
        + role_sql(CLEANER_APP_LOGIN_ROLE, True) + ", 'app_runtime', "
        + role_sql(ApprovedPostgresRole.APP_RUNTIME.value)
        + ", 'memberships', COALESCE((SELECT jsonb_agg(jsonb_build_object("
        "'granted_role', g.rolname, 'member_role', u.rolname, 'inherit', m.inherit_option, "
        "'set', m.set_option, 'admin', m.admin_option) ORDER BY g.rolname,u.rolname,m.grantor) "
        "FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid=m.roleid "
        "JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE "
        "u.rolname IN ('propertyai_cleaner_app','propertyai_app_runtime') "
        "OR g.rolname='propertyai_cleaner_app'), '[]'::jsonb))"
    )


def _cleaner_principal_state(policy: _CleanerProductionPostgresPolicy) -> Mapping[str, Any]:
    return _json_query(policy, database=CLEANER_DATABASE, sql=_cleaner_principal_state_sql())


def _validate_cleaner_principal_state(state: Mapping[str, Any], *, final: bool = False) -> str:
    expected = _cleaner_principal_expected_state()
    # Canonical JSON comparison preserves boolean types (True must not equal 1).
    if set(state) != set(expected) or state.get("database") != CLEANER_DATABASE:
        raise TypedPostgresError("POSTGRES_CLEANER_PRINCIPAL_TARGET_MISMATCH")
    if _state_fingerprint({"role": state["app_runtime"]}) != _state_fingerprint({"role": expected["app_runtime"]}):
        raise TypedPostgresError("POSTGRES_CLEANER_APP_RUNTIME_WRONG_STATE")
    principal = state["principal"]
    if principal is not None and _state_fingerprint({"role": principal}) != _state_fingerprint({"role": expected["principal"]}):
        raise TypedPostgresError("POSTGRES_CLEANER_PRINCIPAL_PROTECTED_ATTRIBUTES_MISMATCH")
    memberships = state["memberships"]
    if _state_fingerprint({"memberships": memberships}) == _state_fingerprint({"memberships": expected["memberships"]}):
        if principal is not None:
            return "NOOP_EXACT"
    elif memberships == [] and not final:
        return "CREATE_EXACT" if principal is None else "COMPLETE_MEMBERSHIP"
    raise TypedPostgresError("POSTGRES_CLEANER_PRINCIPAL_MEMBERSHIP_OR_POSTCONDITION_MISMATCH")


def _cleaner_principal_transaction(before: Mapping[str, Any]) -> bytes:
    mode = _validate_cleaner_principal_state(before)
    expected = _cleaner_principal_expected_state()
    # One DO statement is one PostgreSQL transaction. RAISE rolls back both DDL
    # statements; compare-before and factual postcondition execute in that same
    # transaction, before PostgreSQL may commit it. No repair statements exist.
    query = _cleaner_principal_state_sql().removeprefix("SELECT ")
    before_json = _sql_literal(json.dumps(before, sort_keys=True, separators=(",", ":")))
    after_json = _sql_literal(json.dumps(expected, sort_keys=True, separators=(",", ":")))
    create = (
        "CREATE ROLE propertyai_cleaner_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        "NOREPLICATION NOBYPASSRLS NOINHERIT;\n"
        if mode == "CREATE_EXACT" else ""
    )
    grant = (
        "GRANT propertyai_app_runtime TO propertyai_cleaner_app "
        "WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n"
        if mode != "NOOP_EXACT" else ""
    )
    return (
        "DO $dl81$ DECLARE observed jsonb; BEGIN\n"
        "IF current_setting('transaction_isolation') <> 'read committed' THEN "
        "RAISE EXCEPTION 'POSTGRES_CLEANER_PRINCIPAL_TRANSACTION_ISOLATION_MISMATCH'; END IF;\n"
        "SET LOCAL lock_timeout = '5s';\n"
        # Freeze role/membership writers through compare, DDL, and postcondition.
        # In particular, GRANT cannot repair a conflicting concurrent insertion.
        "LOCK TABLE pg_catalog.pg_authid, pg_catalog.pg_auth_members "
        "IN SHARE ROW EXCLUSIVE MODE;\nSELECT " + query + " INTO observed;\n"
        "IF observed IS DISTINCT FROM " + before_json + "::jsonb THEN "
        "RAISE EXCEPTION 'POSTGRES_CLEANER_PRINCIPAL_COMPARE_BEFORE_MISMATCH'; END IF;\n"
        + create + grant + "SELECT " + query + " INTO observed;\n"
        "IF observed IS DISTINCT FROM " + after_json + "::jsonb THEN "
        "RAISE EXCEPTION 'POSTGRES_CLEANER_PRINCIPAL_POSTCONDITION_MISMATCH'; END IF;\n"
        "END; $dl81$;\n"
    ).encode("utf-8")


def _provision_cleaner_app_principal(
    store: ControlStore, *, change_id: str, authority: ProductionMutationAuthority,
    policy: _CleanerProductionPostgresPolicy, request: ProvisionCleanerAppPrincipalRequest,
    control_decision_ref: str = "TYPED/PG/TEST", start_heartbeat: bool = True,
) -> TypedPostgresOperationReceipt:
    if type(request) is not ProvisionCleanerAppPrincipalRequest:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    _validate_control_identifiers(change_id, control_decision_ref, request.operation_id)
    # Must precede replay readback, W08 acquisition, PREPARED, and all PG access.
    version = store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
    if type(version) is not int or version != 10:
        raise TypedPostgresError("POSTGRES_CLEANER_PRINCIPAL_REQUIRES_SCHEMA_10")
    validate_schema(store.connection, target_version=10)
    kind = TypedOperationType.PROVISION_CLEANER_APP_PRINCIPAL
    expected = _cleaner_principal_expected_state()
    request_fp = _request_fingerprint(
        change_id=change_id, control_decision_ref=control_decision_ref,
        deployment_id=request.operation_id, operation_type=kind,
        target_service=CLEANER_TARGET_SERVICE, target_database=CLEANER_DATABASE,
        principal_identity=CLEANER_APP_LOGIN_ROLE, credential_reference=None,
        artifact_path=None, artifact_sha256=None, request=request,
        expected_before_identity={"allowed": ["CREATE_EXACT", "COMPLETE_MEMBERSHIP", "NOOP_EXACT"]},
        desired_after_identity=expected,
    )
    intent = _ReceiptIntent(
        change_id, control_decision_ref, request.operation_id, request.operation_id,
        kind, CLEANER_TARGET_SERVICE, CLEANER_DATABASE, CLEANER_APP_LOGIN_ROLE,
        None, None, None, request_fp,
    )
    replay = _replay_receipt_if_present(
        store, intent, factual_readback=lambda: _cleaner_principal_state(policy),
        final_validator=lambda state: _validate_cleaner_principal_state(state, final=True),
    )
    if replay is not None:
        return replay
    receipts: list[TypedPostgresOperationReceipt] = []

    def effect() -> _TypedEffectResult:
        _validate_credential(policy, CredentialReference.DBA_PGPASS)
        _assert_current_typed_authority(store, authority, change_id=change_id, deployment_id=request.operation_id)
        before = _cleaner_principal_state(policy)
        mode = _validate_cleaner_principal_state(before)
        sql = _cleaner_principal_transaction(before)
        _persist_prepared_receipt(store, authority, intent, before)
        process = _run_psql(
            policy, database=CLEANER_DATABASE, execution_role=CLEANER_DBA_ROLE,
            stdin_sql=sql, connection_credential=CredentialReference.DBA_PGPASS,
        )
        return _TypedEffectResult(kind, "NOOP_EXACT" if mode == "NOOP_EXACT" else "APPLIED", before, process)

    evidence = run_controlled_deployment(
        store, change_id=change_id, deployment_id=request.operation_id, authority=authority,
        steps=(DeploymentStep(kind.value, effect, lambda _result: _cleaner_principal_state(policy)),),
        persist_result=lambda items: receipts.append(_persist_final_receipt(store, authority, intent, items)),
        control_decision_ref=control_decision_ref, start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or len(receipts) != 1:
        raise TypedPostgresError("TYPED_POSTGRES_RECEIPT_MISSING")
    return receipts[0]


def provision_cleaner_app_principal(
    *, change_id: str, request: ProvisionCleanerAppPrincipalRequest,
    control_decision_ref: str, gate_or_control_id: str | None = None,
) -> TypedPostgresOperationReceipt:
    """Provision exactly the DL-81 login and membership under DL-35 approval."""
    if type(request) is not ProvisionCleanerAppPrincipalRequest:
        raise TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    policy = _canonical_cleaner_postgres_policy()
    _validate_sealed_canonical_policy(policy)
    target = _cleaner_principal_expected_state()
    # Password is not an authorized effect or caller-controlled approval scope.
    del target["principal"]["password_unset"]
    _resolve_public_operation_approval(
        change_id=change_id, gate_or_control_id=gate_or_control_id or "",
        control_decision_ref=control_decision_ref,
        operation_kind=TypedOperationType.PROVISION_CLEANER_APP_PRINCIPAL.value,
        authorized_effect_scope=("CREATE_EXACT_CLEANER_APP_PRINCIPAL", "CREATE_EXACT_CLEANER_APP_MEMBERSHIP"),
        entrypoint="provision_cleaner_app_principal", target_identity=target,
        operation_artifact_identity=None,
    )
    authority = _canonical_typed_postgres_source_authority(policy)
    with _canonical_typed_postgres_control_store() as store:
        return _provision_cleaner_app_principal(
            store, change_id=change_id, authority=authority, policy=policy,
            request=request, control_decision_ref=control_decision_ref,
        )


__all__ = [
    "ProvisionCleanerAppPrincipalRequest",
    "provision_cleaner_app_principal",
    "ApplyRolePasswordFromProtectedFileRequest",
    "ApprovedPostgresRole",
    "BOOTSTRAP_SQL_PATH",
    "BOOTSTRAP_SQL_SHA256",
    "CANONICAL_DATA_DIRECTORY",
    "CANONICAL_HOST",
    "CANONICAL_PORT",
    "CANONICAL_SERVER_VERSION",
    "CANONICAL_FLYWAY_GROUP_ROLE",
    "CANONICAL_FLYWAY_LOGIN_ROLE",
    "CatalogReadbackOperation",
    "CatalogReadbackRequest",
    "CLEANER_DATABASE",
    "CLEANER_DBA_ROLE",
    "CLEANER_APP_LOGIN_ROLE",
    "CLEANER_OWNER_ROLE",
    "CLEANER_TARGET_SERVICE",
    "CredentialReference",
    "PasswordCredentialOperation",
    "ExecuteAuthorizedSqlFileRequest",
    "STAGE_B_LOGIN_ROLE",
    "SanitizedProcessResult",
    "TransitionDatabaseOwnerRequest",
    "EffectSuccessReceiptFailureReconciliationRequired",
    "TypedPostgresError",
    "SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS",
    "TypedPostgresOperationReceipt",
    "apply_role_password_from_protected_file",
    "execute_authorized_sql_file",
    "query_postgres_catalog",
    "transition_database_owner",
]
