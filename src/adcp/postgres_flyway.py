"""Approval-bound, migrate-only Flyway execution for the Cleaner Production database.

This module is intentionally narrower than a command runner.  The public request
contains only an operation identity; database, Flyway command, executable,
configuration, callbacks, migration source, credentials and target are all sealed
by Control-owned policy plus DL-35 approval evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import subprocess
from typing import Any, Callable

from adcp.postgres_approval_evidence import (
    ExpectedProductionOperationApprovalBinding,
    PostgresApprovalEvidenceError,
    ProductionOperationApprovalEvidenceV1,
    ProtectedApprovalEvidenceSource,
    controller_git_identity,
    resolve_production_operation_approval_evidence,
)
from adcp.postgres_control import (
    CANONICAL_APPROVAL_EVIDENCE_OWNER_UID,
    CANONICAL_CONTROLLER_SOURCE_ROOT,
    CANONICAL_HOST,
    CANONICAL_PORT,
    CLEANER_DATABASE,
    CLEANER_TARGET_SERVICE,
    PROJECT_CODE,
    SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS,
    _assert_current_typed_authority,
    _canonical_typed_postgres_control_store,
)
from adcp.production_control import (
    CompositeProductionAuthority,
    DeploymentStep,
    GitSourceAuthority,
    ProductionControlError,
    ProductionMutationAuthority,
    run_controlled_deployment,
)
from adcp.store.migrations import validate_schema
from adcp.store.sqlite import ControlStore


FLYWAY_OPERATION_KIND = "EXECUTE_FLYWAY_MIGRATIONS"
FLYWAY_OPERATION = "MIGRATE_ONLY"
EXPECTED_FLYWAY_VERSION = "13.5.0"
FLYWAY_LOGIN_ROLE = "propertyai_flyway"

FROZEN_DB_SOURCE_ROOT = Path("/Users/kate/PropertyAI/worktrees/p0-cleaner-multi-job-db-review")
FROZEN_DB_SOURCE_COMMIT = "12f27baf46bd19140301724f87845a8f278e568f"
FROZEN_DB_SOURCE_TREE = "e4873bc01c06f59a086a94e32c49e440301c9023"

CANONICAL_FLYWAY_RUNTIME_ROOT = Path("/Users/kate/DKATE/adcp-runtime")
CANONICAL_FLYWAY_EXECUTABLE = Path(
    "/Users/kate/DKATE/adcp-runtime/artifacts/flyway/13.5.0/flyway"
)
CANONICAL_FLYWAY_EXECUTABLE_REF = Path(
    "/Users/kate/DKATE/adcp-runtime/artifacts/flyway/13.5.0/executable-ref.json"
)
CANONICAL_FLYWAY_CREDENTIAL = Path(
    "/Users/kate/PropertyAI/openclaw-workspace/secrets/postgres/cleaner-prod/flyway-password"
)
CANONICAL_FLYWAY_CREDENTIAL_ROOT = CANONICAL_FLYWAY_CREDENTIAL.parent
CANONICAL_FLYWAY_APPROVAL_EVIDENCE_ROOT = Path(
    "/Users/kate/DKATE/adcp-runtime/approval-evidence/typed-postgres"
)

FLYWAY_CONFIG_PATH = "db/v2_2_1/flyway/flyway.conf"
FLYWAY_CONFIG_SHA256 = "17c5a5aa446439f37e9265d0ff47d4ea3b4f2f37753d661850774fc20be5a13f"
FLYWAY_CALLBACK_PATH = "db/v2_2_1/flyway/callbacks/afterConnect.sql"
FLYWAY_CALLBACK_SHA256 = "9f8e01f984afd581ac17385ca2e28ef5e059dd7027efc09907acba3bfbd54a3b"
FLYWAY_CALLBACK_CONFIG_PATH = "db/v2_2_1/flyway/callbacks/afterConnect.sql.conf"
FLYWAY_CALLBACK_CONFIG_SHA256 = "ccae2afbc9a64f8c1a5ff83d8c7a7abf1da96d2c2abfa1f3eb01e162f0653354"


@dataclass(frozen=True)
class FrozenMigration:
    version: str
    path: str
    sha256: str


FROZEN_MIGRATIONS = (
    FrozenMigration(
        "20260904.101",
        "db/v2_2_1/migration/V20260904.101__v221_migrator_preflight.sql",
        "adfa518b0439faa4cca9743b5d196db1cec12dd620f06a21052727752e870797",
    ),
    FrozenMigration(
        "20260904.102",
        "db/v2_2_1/migration/V20260904.102__v221_org_identity_command.sql",
        "5fd64fb3712ae239df8e466e3fd5d5142f7d6523cd015357aa7f210e2609c6fa",
    ),
    FrozenMigration(
        "20260904.103",
        "db/v2_2_1/migration/V20260904.103__v221_reservation_cleaning.sql",
        "6e5e440b16aff135bc8c42256f3dedf9b6dafede6fb0448d1fd5c1a0889432d6",
    ),
    FrozenMigration(
        "20260904.104",
        "db/v2_2_1/migration/V20260904.104__v221_offer_assignment.sql",
        "b161a1be5f3f435c584acfe59fe2723e4d9fbccec7f9cc3631a178755cd3d068",
    ),
    FrozenMigration(
        "20260904.105",
        "db/v2_2_1/migration/V20260904.105__v221_exception_audit.sql",
        "079dc2c9371ce07c2d88a0bcb8818a58e7184b328b3d49e86e44d6874ad2af5f",
    ),
    FrozenMigration(
        "20260904.106",
        "db/v2_2_1/migration/V20260904.106__v221_async_projection.sql",
        "ce3142b095c2d6667ba0bdbf1099d0a1111c425eb04af4481735463e2ac77006",
    ),
    FrozenMigration(
        "20260904.107",
        "db/v2_2_1/migration/V20260904.107__v221_invariant_guards_functions.sql",
        "b19f6ef90d19595feef99956469abba9d10306f1ed437e4ba24adafa512d3409",
    ),
    FrozenMigration(
        "20260904.108",
        "db/v2_2_1/migration/V20260904.108__v221_privileges_views.sql",
        "adf5cb7b342e248db163ae254a5479255f1d8c1edd09329fcdadece09df57714",
    ),
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _migration_manifest(migrations: tuple[FrozenMigration, ...]) -> list[dict[str, str]]:
    return [
        {"version": item.version, "path": item.path, "sha256": item.sha256}
        for item in migrations
    ]


def _migration_manifest_sha256(migrations: tuple[FrozenMigration, ...]) -> str:
    return hashlib.sha256(_canonical_json(_migration_manifest(migrations)).encode("utf-8")).hexdigest()


FROZEN_MIGRATION_MANIFEST_SHA256 = _migration_manifest_sha256(FROZEN_MIGRATIONS)
MIGRATION_SET_IDENTITY = f"V2.2.1:{FROZEN_MIGRATION_MANIFEST_SHA256}"


class FlywayControlError(ProductionControlError):
    """Fail-closed error for the exact C3A Flyway operation."""


@dataclass(frozen=True)
class ExecuteAuthorizedFlywayMigrationsRequest:
    """Authority-free request for exactly one sealed MIGRATE operation."""

    operation_id: str


@dataclass(frozen=True)
class FlywayExecutableRefV1:
    reference_path: str
    reference_sha256: str
    executable_path: str
    executable_sha256: str
    flyway_version: str
    version_marker_path: str
    version_marker_sha256: str
    fingerprint: tuple[int, int, int, int, int]
    executable_fingerprint: tuple[int, int, int, int, int]
    version_marker_fingerprint: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _CredentialMetadata:
    path: Path
    fingerprint: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class _FlywayExecutionPolicy:
    controller_source_root: Path
    source_root: Path
    source_commit: str
    source_tree: str
    migrations: tuple[FrozenMigration, ...]
    migration_manifest_sha256: str
    flyway_config_path: str
    flyway_config_sha256: str
    callback_path: str
    callback_sha256: str
    callback_config_path: str
    callback_config_sha256: str
    runtime_root: Path
    executable_ref_path: Path
    executable_path: Path
    credential_root: Path
    credential_path: Path
    expected_owner_uid: int
    approval_evidence_root: Path
    target_database: str
    target_service: str
    host: str
    port: int
    login_role: str
    flyway_version: str


@dataclass(frozen=True)
class _ProcessResult:
    exit_status: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class FlywayExecutionReceiptV1:
    operation_kind: str
    target_database: str
    flyway_version: str
    executable_sha256: str
    controller_commit: str
    controller_tree: str
    frozen_db_commit: str
    frozen_db_tree: str
    migration_manifest_sha256: str
    attempted_versions: tuple[str, ...]
    flyway_exit_status: int
    execution_start_timestamp: str
    execution_end_timestamp: str
    approval_evidence_sha256: str
    writer_fencing_token: int
    stdout_sanitized_summary: str
    stderr_sanitized_summary: str


class FlywayExecutionFailed(FlywayControlError):
    def __init__(self, receipt: FlywayExecutionReceiptV1) -> None:
        self.receipt = receipt
        super().__init__("FLYWAY_MIGRATE_FAILED", f"exit_status={receipt.flyway_exit_status}")


VersionReader = Callable[[FlywayExecutableRefV1, _FlywayExecutionPolicy], str]
MigrationRunner = Callable[[FlywayExecutableRefV1, _FlywayExecutionPolicy, str], _ProcessResult]


def _canonical_policy() -> _FlywayExecutionPolicy:
    return _FlywayExecutionPolicy(
        controller_source_root=CANONICAL_CONTROLLER_SOURCE_ROOT,
        source_root=FROZEN_DB_SOURCE_ROOT,
        source_commit=FROZEN_DB_SOURCE_COMMIT,
        source_tree=FROZEN_DB_SOURCE_TREE,
        migrations=FROZEN_MIGRATIONS,
        migration_manifest_sha256=FROZEN_MIGRATION_MANIFEST_SHA256,
        flyway_config_path=FLYWAY_CONFIG_PATH,
        flyway_config_sha256=FLYWAY_CONFIG_SHA256,
        callback_path=FLYWAY_CALLBACK_PATH,
        callback_sha256=FLYWAY_CALLBACK_SHA256,
        callback_config_path=FLYWAY_CALLBACK_CONFIG_PATH,
        callback_config_sha256=FLYWAY_CALLBACK_CONFIG_SHA256,
        runtime_root=CANONICAL_FLYWAY_RUNTIME_ROOT,
        executable_ref_path=CANONICAL_FLYWAY_EXECUTABLE_REF,
        executable_path=CANONICAL_FLYWAY_EXECUTABLE,
        credential_root=CANONICAL_FLYWAY_CREDENTIAL_ROOT,
        credential_path=CANONICAL_FLYWAY_CREDENTIAL,
        expected_owner_uid=CANONICAL_APPROVAL_EVIDENCE_OWNER_UID,
        approval_evidence_root=CANONICAL_FLYWAY_APPROVAL_EVIDENCE_ROOT,
        target_database=CLEANER_DATABASE,
        target_service=CLEANER_TARGET_SERVICE,
        host=CANONICAL_HOST,
        port=CANONICAL_PORT,
        login_role=FLYWAY_LOGIN_ROLE,
        flyway_version=EXPECTED_FLYWAY_VERSION,
    )


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _fingerprint(meta: os.stat_result) -> tuple[int, int, int, int, int]:
    return (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(*args: str, root: Path, text: bool = True) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise FlywayControlError("FLYWAY_SOURCE_GIT_READ_FAILED", " ".join(args)) from error


def _git_identity(root: Path, expected_commit: str, expected_tree: str) -> None:
    try:
        GitSourceAuthority(root, expected_commit, require_clean=True).revalidate()
    except ProductionControlError as error:
        raise FlywayControlError("FLYWAY_FROZEN_SOURCE_AUTHORITY_INVALID", error.code) from error
    tree = _git("rev-parse", "HEAD^{tree}", root=root).stdout.strip()
    if tree != expected_tree:
        raise FlywayControlError("FLYWAY_FROZEN_SOURCE_TREE_MISMATCH")


def _git_object_bytes(root: Path, commit: str, relative_path: str) -> bytes:
    result = _git("show", f"{commit}:{relative_path}", root=root, text=False)
    return bytes(result.stdout)


def _worktree_file(root: Path, relative_path: str, expected_sha256: str, code: str) -> None:
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise FlywayControlError(f"{code}_PATH_INVALID")
    path = root.joinpath(*relative.parts)
    try:
        meta = path.lstat()
    except OSError as error:
        raise FlywayControlError(f"{code}_MISSING") from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise FlywayControlError(f"{code}_INVALID")
    if _sha256_bytes(path.read_bytes()) != expected_sha256:
        raise FlywayControlError(f"{code}_WORKTREE_HASH_MISMATCH")


def _validate_frozen_source(policy: _FlywayExecutionPolicy) -> None:
    _git_identity(policy.source_root, policy.source_commit, policy.source_tree)
    if _migration_manifest_sha256(policy.migrations) != policy.migration_manifest_sha256:
        raise FlywayControlError("FLYWAY_MIGRATION_MANIFEST_BINDING_MISMATCH")
    expected_paths = tuple(item.path for item in policy.migrations)
    listed = tuple(
        line
        for line in _git(
            "ls-tree", "-r", "--name-only", policy.source_commit,
            "--", "db/v2_2_1/migration", root=policy.source_root,
        ).stdout.splitlines()
        if line
    )
    if listed != expected_paths:
        raise FlywayControlError("FLYWAY_MIGRATION_SET_MISMATCH")
    seen_versions: list[str] = []
    for item in policy.migrations:
        if not re.fullmatch(r"20260904\.10[1-8]", item.version):
            raise FlywayControlError("FLYWAY_MIGRATION_VERSION_INVALID")
        seen_versions.append(item.version)
        object_bytes = _git_object_bytes(policy.source_root, policy.source_commit, item.path)
        if _sha256_bytes(object_bytes) != item.sha256:
            raise FlywayControlError("FLYWAY_MIGRATION_GIT_OBJECT_HASH_MISMATCH", item.version)
        _worktree_file(policy.source_root, item.path, item.sha256, "FLYWAY_MIGRATION")
    if tuple(seen_versions) != tuple(item.version for item in FROZEN_MIGRATIONS):
        raise FlywayControlError("FLYWAY_MIGRATION_VERSION_ORDER_MISMATCH")

    frozen_files = (
        (policy.flyway_config_path, policy.flyway_config_sha256, "FLYWAY_CONFIG"),
        (policy.callback_path, policy.callback_sha256, "FLYWAY_CALLBACK"),
        (policy.callback_config_path, policy.callback_config_sha256, "FLYWAY_CALLBACK_CONFIG"),
    )
    for relative_path, expected_sha, code in frozen_files:
        object_bytes = _git_object_bytes(policy.source_root, policy.source_commit, relative_path)
        if _sha256_bytes(object_bytes) != expected_sha:
            raise FlywayControlError(f"{code}_GIT_OBJECT_HASH_MISMATCH")
        _worktree_file(policy.source_root, relative_path, expected_sha, code)


def _require_protected_chain(root: Path, path: Path, expected_uid: int, *, root_mode: int) -> None:
    root_abs = Path(os.path.abspath(root))
    path_abs = Path(os.path.abspath(path))
    try:
        path_abs.relative_to(root_abs)
    except ValueError as error:
        raise FlywayControlError("FLYWAY_PROTECTED_PATH_OUTSIDE_ROOT") from error

    try:
        root_meta = root_abs.lstat()
    except OSError as error:
        raise FlywayControlError("FLYWAY_PROTECTED_ROOT_UNAVAILABLE") from error
    if (
        stat.S_ISLNK(root_meta.st_mode)
        or not stat.S_ISDIR(root_meta.st_mode)
        or root_meta.st_uid != expected_uid
        or stat.S_IMODE(root_meta.st_mode) != root_mode
    ):
        raise FlywayControlError("FLYWAY_PROTECTED_ROOT_UNSAFE")

    current = root_abs
    for part in path_abs.relative_to(root_abs).parts:
        current = current / part
        try:
            meta = current.lstat()
        except OSError as error:
            raise FlywayControlError("FLYWAY_PROTECTED_PATH_UNAVAILABLE", str(current)) from error
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid != expected_uid:
            raise FlywayControlError("FLYWAY_PROTECTED_PATH_UNSAFE", str(current))
        if stat.S_IMODE(meta.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise FlywayControlError("FLYWAY_PROTECTED_PATH_UNSAFE", str(current))


def _read_protected_regular_file(
    root: Path,
    path: Path,
    expected_uid: int,
    *,
    root_mode: int,
    exact_mode: int | None = None,
    executable: bool = False,
    max_bytes: int = 1 << 20,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    _require_protected_chain(root, path, expected_uid, root_mode=root_mode)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise FlywayControlError("FLYWAY_PROTECTED_FILE_INVALID", str(path))
    mode = stat.S_IMODE(before.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise FlywayControlError("FLYWAY_PROTECTED_FILE_MODE_INVALID", str(path))
    if executable and mode & 0o111 == 0:
        raise FlywayControlError("FLYWAY_EXECUTABLE_MODE_INVALID")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise FlywayControlError("FLYWAY_PROTECTED_FILE_WRITABLE_BY_UNTRUSTED", str(path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise FlywayControlError("FLYWAY_PROTECTED_FILE_OPEN_REJECTED", str(path)) from error
    try:
        opened = os.fstat(fd)
        if _fingerprint(opened) != _fingerprint(before):
            raise FlywayControlError("FLYWAY_PROTECTED_FILE_SUBSTITUTION_DETECTED", str(path))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise FlywayControlError("FLYWAY_PROTECTED_FILE_TOO_LARGE", str(path))
        after = os.fstat(fd)
        if _fingerprint(after) != _fingerprint(opened):
            raise FlywayControlError("FLYWAY_PROTECTED_FILE_MUTATED_DURING_READ", str(path))
    finally:
        os.close(fd)
    current = path.lstat()
    if _fingerprint(current) != _fingerprint(before):
        raise FlywayControlError("FLYWAY_PROTECTED_FILE_MUTATED_AFTER_READ", str(path))
    return b"".join(chunks), _fingerprint(before)


def _load_executable_ref(
    policy: _FlywayExecutionPolicy, *, validate_distribution: bool = True
) -> FlywayExecutableRefV1:
    raw, ref_fp = _read_protected_regular_file(
        policy.runtime_root,
        policy.executable_ref_path,
        policy.expected_owner_uid,
        root_mode=0o700,
        exact_mode=0o600,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_MALFORMED") from error
    required = {
        "schema_version", "reference_kind", "executable_path", "executable_sha256",
        "flyway_version", "version_marker_path", "version_marker_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_SCHEMA_INVALID")
    if payload.get("schema_version") != 1 or payload.get("reference_kind") != "FLYWAY_EXECUTABLE_REF_V1":
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_SCHEMA_INVALID")
    if payload.get("executable_path") != str(policy.executable_path):
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_PATH_MISMATCH")
    if payload.get("flyway_version") != policy.flyway_version:
        raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_MISMATCH")
    executable_sha = payload.get("executable_sha256")
    marker_sha = payload.get("version_marker_sha256")
    if not _is_lower_hex(executable_sha, 64) or not _is_lower_hex(marker_sha, 64):
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_HASH_INVALID")

    marker_path_raw = payload.get("version_marker_path")
    if not isinstance(marker_path_raw, str):
        raise FlywayControlError("FLYWAY_VERSION_MARKER_PATH_INVALID")
    marker_path = Path(marker_path_raw)
    expected_marker = policy.executable_path.parent / "lib" / "flyway" / f"flyway-commandline-{policy.flyway_version}.jar"
    if marker_path != expected_marker:
        raise FlywayControlError("FLYWAY_VERSION_MARKER_PATH_MISMATCH")
    if not validate_distribution:
        # Pre-approval: read only the protected Control-owned identity projection.
        # Actual executable/marker bytes are intentionally deferred until W08 is held.
        return FlywayExecutableRefV1(
            reference_path=str(policy.executable_ref_path),
            reference_sha256=_sha256_bytes(raw),
            executable_path=str(policy.executable_path),
            executable_sha256=executable_sha,
            flyway_version=policy.flyway_version,
            version_marker_path=str(marker_path),
            version_marker_sha256=marker_sha,
            fingerprint=ref_fp,
            executable_fingerprint=(0, 0, 0, 0, 0),
            version_marker_fingerprint=(0, 0, 0, 0, 0),
        )

    executable_bytes, executable_fp = _read_protected_regular_file(
        policy.runtime_root,
        policy.executable_path,
        policy.expected_owner_uid,
        root_mode=0o700,
        executable=True,
        max_bytes=4 << 20,
    )
    if _sha256_bytes(executable_bytes) != executable_sha:
        raise FlywayControlError("FLYWAY_EXECUTABLE_SHA256_MISMATCH")
    marker_bytes, marker_fp = _read_protected_regular_file(
        policy.runtime_root,
        marker_path,
        policy.expected_owner_uid,
        root_mode=0o700,
        max_bytes=64 << 20,
    )
    if _sha256_bytes(marker_bytes) != marker_sha:
        raise FlywayControlError("FLYWAY_VERSION_MARKER_SHA256_MISMATCH")
    if marker_path.name != f"flyway-commandline-{policy.flyway_version}.jar":
        raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_READBACK_MISMATCH")
    bundled_java = policy.executable_path.parent / "jre" / "bin" / "java"
    _read_protected_regular_file(
        policy.runtime_root,
        bundled_java,
        policy.expected_owner_uid,
        root_mode=0o700,
        executable=True,
        max_bytes=8 << 20,
    )
    return FlywayExecutableRefV1(
        reference_path=str(policy.executable_ref_path),
        reference_sha256=_sha256_bytes(raw),
        executable_path=str(policy.executable_path),
        executable_sha256=executable_sha,
        flyway_version=policy.flyway_version,
        version_marker_path=str(marker_path),
        version_marker_sha256=marker_sha,
        fingerprint=ref_fp,
        executable_fingerprint=executable_fp,
        version_marker_fingerprint=marker_fp,
    )


def _revalidate_executable_ref(policy: _FlywayExecutionPolicy, approved: FlywayExecutableRefV1) -> None:
    current = _load_executable_ref(policy)
    comparable = (
        current.reference_path, current.reference_sha256, current.executable_path,
        current.executable_sha256, current.flyway_version, current.version_marker_path,
        current.version_marker_sha256,
    )
    wanted = (
        approved.reference_path, approved.reference_sha256, approved.executable_path,
        approved.executable_sha256, approved.flyway_version, approved.version_marker_path,
        approved.version_marker_sha256,
    )
    if comparable != wanted:
        raise FlywayControlError("FLYWAY_EXECUTABLE_REF_CHANGED_AFTER_APPROVAL")


def _validate_credential_metadata(policy: _FlywayExecutionPolicy) -> _CredentialMetadata:
    _require_protected_chain(
        policy.credential_root,
        policy.credential_path,
        policy.expected_owner_uid,
        root_mode=0o700,
    )
    before = policy.credential_path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != policy.expected_owner_uid
    ):
        raise FlywayControlError("FLYWAY_CREDENTIAL_METADATA_UNSAFE")
    return _CredentialMetadata(policy.credential_path, _fingerprint(before))


def _read_credential_secret(policy: _FlywayExecutionPolicy, metadata: _CredentialMetadata) -> str:
    raw, fingerprint = _read_protected_regular_file(
        policy.credential_root,
        policy.credential_path,
        policy.expected_owner_uid,
        root_mode=0o700,
        exact_mode=0o600,
        max_bytes=65536,
    )
    if fingerprint != metadata.fingerprint:
        raise FlywayControlError("FLYWAY_CREDENTIAL_CHANGED_AFTER_VALIDATION")
    try:
        secret = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise FlywayControlError("FLYWAY_CREDENTIAL_ENCODING_INVALID") from error
    if not secret or "\x00" in secret:
        raise FlywayControlError("FLYWAY_CREDENTIAL_CONTENT_INVALID")
    return secret


def _validate_effect_policy(policy: _FlywayExecutionPolicy) -> None:
    """Reject semantic expansion even on internal/test call paths."""

    if policy.target_database != CLEANER_DATABASE or policy.target_service != CLEANER_TARGET_SERVICE:
        raise FlywayControlError("FLYWAY_TARGET_DATABASE_NOT_APPROVED")
    if policy.login_role != FLYWAY_LOGIN_ROLE:
        raise FlywayControlError("FLYWAY_LOGIN_ROLE_NOT_APPROVED")
    if policy.flyway_version != EXPECTED_FLYWAY_VERSION:
        raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_MISMATCH")
    if policy.flyway_config_path != FLYWAY_CONFIG_PATH:
        raise FlywayControlError("FLYWAY_CONFIG_PATH_NOT_APPROVED")
    if policy.callback_path != FLYWAY_CALLBACK_PATH or policy.callback_config_path != FLYWAY_CALLBACK_CONFIG_PATH:
        raise FlywayControlError("FLYWAY_CALLBACK_PATH_NOT_APPROVED")
    versions = tuple(item.version for item in policy.migrations)
    if versions != tuple(item.version for item in FROZEN_MIGRATIONS):
        raise FlywayControlError("FLYWAY_MIGRATION_VERSION_ORDER_MISMATCH")
    if any(PurePosixPath(item.path).parent.as_posix() != "db/v2_2_1/migration" for item in policy.migrations):
        raise FlywayControlError("FLYWAY_MIGRATION_ROOT_NOT_APPROVED")


def _validate_store_schema(store: ControlStore) -> int:
    try:
        row = store.connection.execute("SELECT max(version) AS version FROM schema_migration").fetchone()
        version = None if row is None else row["version"]
    except sqlite3.Error as error:
        raise FlywayControlError("FLYWAY_DCS_SCHEMA_UNREADABLE") from error
    if version not in SUPPORTED_TYPED_POSTGRES_OPERATIONAL_SCHEMAS:
        raise FlywayControlError("FLYWAY_DCS_SCHEMA_UNSUPPORTED", str(version))
    try:
        validate_schema(store.connection, target_version=int(version))
    except BaseException as error:
        code = getattr(error, "code", type(error).__name__)
        raise FlywayControlError("FLYWAY_DCS_SCHEMA_PROFILE_INVALID", str(code)) from error
    return int(version)


def _validate_operation_id(value: object) -> None:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise FlywayControlError("FLYWAY_OPERATION_ID_INVALID")


def _approval_target_identity(policy: _FlywayExecutionPolicy) -> dict[str, Any]:
    return {
        "target_service": policy.target_service,
        "database": policy.target_database,
        "flyway_operation": FLYWAY_OPERATION,
        "login_role": policy.login_role,
        "host": policy.host,
        "port": policy.port,
    }


def _approval_artifact_identity(
    policy: _FlywayExecutionPolicy,
    executable_ref: FlywayExecutableRefV1,
) -> dict[str, Any]:
    return {
        "flyway_executable_ref": {
            "kind": "FLYWAY_EXECUTABLE_REF_V1",
            "path": executable_ref.reference_path,
            "sha256": executable_ref.reference_sha256,
            "executable_path": executable_ref.executable_path,
            "executable_sha256": executable_ref.executable_sha256,
            "version": executable_ref.flyway_version,
            "version_marker_path": executable_ref.version_marker_path,
            "version_marker_sha256": executable_ref.version_marker_sha256,
        },
        "frozen_db_source": {
            "commit": policy.source_commit,
            "tree": policy.source_tree,
        },
        "migration_set": {
            "identity": f"V2.2.1:{policy.migration_manifest_sha256}",
            "manifest_sha256": policy.migration_manifest_sha256,
            "migrations": _migration_manifest(policy.migrations),
        },
        "flyway_config": {
            "path": policy.flyway_config_path,
            "sha256": policy.flyway_config_sha256,
        },
        "callback": {
            "path": policy.callback_path,
            "sha256": policy.callback_sha256,
            "config_path": policy.callback_config_path,
            "config_sha256": policy.callback_config_sha256,
        },
        "credential_ref": {
            "principal": policy.login_role,
            "path": str(policy.credential_path),
        },
    }


def _approval_source(policy: _FlywayExecutionPolicy) -> ProtectedApprovalEvidenceSource:
    return ProtectedApprovalEvidenceSource(policy.approval_evidence_root, policy.expected_owner_uid)


def _resolve_approval(
    policy: _FlywayExecutionPolicy,
    *,
    change_id: str,
    gate_or_control_id: str,
    control_decision_ref: str,
    executable_ref: FlywayExecutableRefV1,
) -> tuple[ProductionOperationApprovalEvidenceV1, str, str]:
    if not isinstance(change_id, str) or not change_id:
        raise FlywayControlError("FLYWAY_CHANGE_ID_REQUIRED")
    if not isinstance(gate_or_control_id, str) or not gate_or_control_id:
        raise FlywayControlError("FLYWAY_GATE_OR_CONTROL_ID_REQUIRED")
    if not isinstance(control_decision_ref, str) or not control_decision_ref:
        raise FlywayControlError("FLYWAY_CONTROL_DECISION_REF_REQUIRED")
    try:
        controller_commit, controller_tree = controller_git_identity(policy.controller_source_root)
        evidence = resolve_production_operation_approval_evidence(
            _approval_source(policy),
            control_decision_ref=control_decision_ref,
            expected=ExpectedProductionOperationApprovalBinding(
                project_code=PROJECT_CODE,
                change_id=change_id,
                gate_or_control_id=gate_or_control_id,
                operation_kind=FLYWAY_OPERATION_KIND,
                authorized_effect_scope=("EXECUTE_EXACT_FLYWAY_MIGRATE",),
                controller_commit=controller_commit,
                controller_tree=controller_tree,
                controller_entrypoint="execute_authorized_flyway_migrations",
                target_identity=_approval_target_identity(policy),
                operation_artifact_identity=_approval_artifact_identity(policy, executable_ref),
            ),
        )
    except PostgresApprovalEvidenceError as error:
        raise FlywayControlError(error.code, error.detail) from error
    return evidence, controller_commit, controller_tree


def _sanitize(value: str, secret: str) -> str:
    scrubbed = value.replace(secret, "<redacted>") if secret else value
    if len(scrubbed) > 4096:
        return scrubbed[:4096] + "<truncated>"
    return scrubbed


def _read_distribution_version(
    executable_ref: FlywayExecutableRefV1,
    policy: _FlywayExecutionPolicy,
) -> str:
    """Read version from the protected distribution marker without starting Flyway."""

    marker = Path(executable_ref.version_marker_path).name
    match = re.fullmatch(r"flyway-commandline-(\d+\.\d+\.\d+)\.jar", marker)
    if match is None:
        raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_READBACK_INVALID")
    version = match.group(1)
    if version != policy.flyway_version:
        raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_READBACK_MISMATCH")
    return version


def _run_migrate(
    executable_ref: FlywayExecutableRefV1,
    policy: _FlywayExecutionPolicy,
    secret: str,
) -> _ProcessResult:
    blocked_environment = {
        "PGPASSWORD",
        "PGPASSFILE",
        "CLASSPATH",
        "JAVA_ARGS",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("FLYWAY_") and key not in blocked_environment
    }
    # The launcher has a protected bundled JRE, so no caller-controlled PATH is
    # needed to select Java or Bash.  Keep only immutable system utility roots.
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    env["FLYWAY_PASSWORD"] = secret
    argv = [
        executable_ref.executable_path,
        f"-configFiles={policy.flyway_config_path}",
        f"-url=jdbc:postgresql://{policy.host}:{policy.port}/{policy.target_database}",
        f"-user={policy.login_role}",
        "migrate",
    ]
    try:
        completed = subprocess.run(
            argv,
            cwd=policy.source_root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FlywayControlError("FLYWAY_MIGRATE_PROCESS_FAILED_TO_COMPLETE") from error
    return _ProcessResult(
        completed.returncode,
        _sanitize(completed.stdout, secret),
        _sanitize(completed.stderr, secret),
    )


def _validate_approval_summary(
    evidence: ProductionOperationApprovalEvidenceV1 | None,
    *,
    change_id: str,
) -> ProductionOperationApprovalEvidenceV1:
    if type(evidence) is not ProductionOperationApprovalEvidenceV1:
        raise FlywayControlError("FLYWAY_APPROVAL_EVIDENCE_REQUIRED")
    if evidence.project_code != PROJECT_CODE or evidence.change_id != change_id:
        raise FlywayControlError("FLYWAY_APPROVAL_EVIDENCE_CONTEXT_MISMATCH")
    if evidence.operation_kind != FLYWAY_OPERATION_KIND:
        raise FlywayControlError("FLYWAY_APPROVAL_OPERATION_KIND_MISMATCH")
    return evidence


def _execute_authorized_flyway_migrations(
    store: ControlStore,
    *,
    change_id: str,
    control_decision_ref: str,
    request: ExecuteAuthorizedFlywayMigrationsRequest,
    policy: _FlywayExecutionPolicy,
    authority: ProductionMutationAuthority,
    approval_evidence: ProductionOperationApprovalEvidenceV1 | None,
    controller_commit: str,
    controller_tree: str,
    approved_executable_ref: FlywayExecutableRefV1,
    version_reader: VersionReader = _read_distribution_version,
    migration_runner: MigrationRunner = _run_migrate,
    start_heartbeat: bool = True,
) -> FlywayExecutionReceiptV1:
    if type(request) is not ExecuteAuthorizedFlywayMigrationsRequest:
        raise FlywayControlError("FLYWAY_PUBLIC_REQUEST_INVALID")
    if set(field.name for field in fields(request)) != {"operation_id"}:
        raise FlywayControlError("FLYWAY_PUBLIC_REQUEST_ESCAPE_FIELD_REJECTED")
    _validate_operation_id(request.operation_id)
    if not isinstance(change_id, str) or not change_id:
        raise FlywayControlError("FLYWAY_CHANGE_ID_REQUIRED")
    if not isinstance(control_decision_ref, str) or not control_decision_ref:
        raise FlywayControlError("FLYWAY_CONTROL_DECISION_REF_REQUIRED")
    evidence = _validate_approval_summary(approval_evidence, change_id=change_id)
    _validate_effect_policy(policy)
    _validate_store_schema(store)

    receipt_box: list[FlywayExecutionReceiptV1] = []

    def effect() -> FlywayExecutionReceiptV1:
        # W08 has already been acquired by run_controlled_deployment.  Revalidate it
        # explicitly before any external executable or credential read.
        fencing_token = _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        _revalidate_executable_ref(policy, approved_executable_ref)
        _validate_frozen_source(policy)
        credential = _validate_credential_metadata(policy)
        version = version_reader(approved_executable_ref, policy)
        if version != policy.flyway_version:
            raise FlywayControlError("FLYWAY_EXECUTABLE_VERSION_READBACK_MISMATCH")
        # Close TOCTOU windows after all non-secret artifact checks and immediately
        # before materializing credential contents / starting Flyway.
        fencing_token = _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        _revalidate_executable_ref(policy, approved_executable_ref)
        credential = _validate_credential_metadata(policy)
        secret = _read_credential_secret(policy, credential)
        fencing_token = _assert_current_typed_authority(
            store, authority, change_id=change_id, deployment_id=request.operation_id
        )
        started = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        try:
            process = migration_runner(approved_executable_ref, policy, secret)
        finally:
            secret = ""
        ended = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        receipt = FlywayExecutionReceiptV1(
            operation_kind=FLYWAY_OPERATION_KIND,
            target_database=policy.target_database,
            flyway_version=version,
            executable_sha256=approved_executable_ref.executable_sha256,
            controller_commit=controller_commit,
            controller_tree=controller_tree,
            frozen_db_commit=policy.source_commit,
            frozen_db_tree=policy.source_tree,
            migration_manifest_sha256=policy.migration_manifest_sha256,
            attempted_versions=tuple(item.version for item in policy.migrations),
            flyway_exit_status=process.exit_status,
            execution_start_timestamp=started,
            execution_end_timestamp=ended,
            approval_evidence_sha256=evidence.evidence_sha256,
            writer_fencing_token=fencing_token,
            stdout_sanitized_summary=process.stdout,
            stderr_sanitized_summary=process.stderr,
        )
        if process.exit_status != 0:
            raise FlywayExecutionFailed(receipt)
        return receipt

    def persist_result(items: tuple[Any, ...]) -> None:
        if len(items) != 1 or type(items[0].effect_result) is not FlywayExecutionReceiptV1:
            raise FlywayControlError("FLYWAY_EXECUTION_RECEIPT_MISSING")
        receipt_box.append(items[0].effect_result)

    execution = run_controlled_deployment(
        store,
        change_id=change_id,
        deployment_id=request.operation_id,
        authority=authority,
        steps=(DeploymentStep("TYPED_POSTGRES_FLYWAY_MIGRATE", effect, lambda result: {
            "operation_kind": result.operation_kind,
            "target_database": result.target_database,
            "exit_status": result.flyway_exit_status,
            "migration_manifest_sha256": result.migration_manifest_sha256,
        }),),
        persist_result=persist_result,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    )
    if len(execution) != 1 or len(receipt_box) != 1:
        raise FlywayControlError("FLYWAY_EXECUTION_RECEIPT_MISSING")
    return receipt_box[0]


def execute_authorized_flyway_migrations(
    *,
    change_id: str,
    request: ExecuteAuthorizedFlywayMigrationsRequest,
    control_decision_ref: str,
    gate_or_control_id: str,
) -> FlywayExecutionReceiptV1:
    """Run only the frozen V2.2.1 Flyway MIGRATE operation after exact approval binding."""

    if type(request) is not ExecuteAuthorizedFlywayMigrationsRequest:
        raise FlywayControlError("FLYWAY_PUBLIC_REQUEST_INVALID")
    _validate_operation_id(request.operation_id)
    policy = _canonical_policy()
    # The executable reference is a fixed Control-owned input, not caller authority.
    # Its exact identity is incorporated into DL-35 evidence before any W08 lease.
    executable_ref = _load_executable_ref(policy, validate_distribution=False)
    evidence, controller_commit, controller_tree = _resolve_approval(
        policy,
        change_id=change_id,
        gate_or_control_id=gate_or_control_id,
        control_decision_ref=control_decision_ref,
        executable_ref=executable_ref,
    )
    authority = CompositeProductionAuthority((
        GitSourceAuthority(policy.controller_source_root, controller_commit, require_clean=True),
        GitSourceAuthority(policy.source_root, policy.source_commit, require_clean=True),
    ))
    with _canonical_typed_postgres_control_store() as store:
        return _execute_authorized_flyway_migrations(
            store,
            change_id=change_id,
            control_decision_ref=control_decision_ref,
            request=request,
            policy=policy,
            authority=authority,
            approval_evidence=evidence,
            controller_commit=controller_commit,
            controller_tree=controller_tree,
            approved_executable_ref=executable_ref,
            start_heartbeat=True,
        )


__all__ = [
    "ExecuteAuthorizedFlywayMigrationsRequest",
    "FlywayControlError",
    "FlywayExecutionFailed",
    "FlywayExecutionReceiptV1",
    "FLYWAY_OPERATION_KIND",
    "FROZEN_DB_SOURCE_COMMIT",
    "FROZEN_DB_SOURCE_TREE",
    "FROZEN_MIGRATIONS",
    "FROZEN_MIGRATION_MANIFEST_SHA256",
    "execute_authorized_flyway_migrations",
]
