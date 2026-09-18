"""Fail-closed production Control Store preparation boundary.

The public entrypoint is intentionally bound to the canonical production
runtime.  Tests exercise the same implementation through private injected
paths; the operator CLI cannot select that seam.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from typing import Any, Callable, Mapping

from adcp.canonical import canonical_json, canonical_sha256
from adcp.cutover import (
    AUTHORITY_MODE,
    CP_SLICE_ID,
    CutoverError,
    GitBindingEvidence,
    MigrationManifest,
    SeedEligibility,
    classify_seed_eligibility,
    control_snapshot_material,
    control_state_target,
    frozen_cut1_manifest,
    inspect_git_binding,
)
from adcp.domain import (
    ActorRole,
    Environment,
    ExecutionCreate,
    RiskLevel,
    StoreError,
    operation_key,
    timestamp,
    utc_now,
)
from adcp.store.migrations import SCHEMA_VERSION, validate_schema
from adcp.store.sqlite import CONTROL_STATE_INPUT_FIELDS, ControlStore, DEFAULT_RUNTIME_ROOT


CANONICAL_SOURCE_ROOT = Path("/Users/kate/DKATE/adcp-controller")
CANONICAL_BRANCH = "wcp-06-mvp-a"
CANONICAL_PRODUCTION_RUNTIME_ROOT = DEFAULT_RUNTIME_ROOT
CANONICAL_PRODUCTION_CONTROL_STORE = DEFAULT_RUNTIME_ROOT / "control.sqlite3"
PRODUCTION_IMPORT_EXECUTION_ID = "production-import-cp-01a-2-v1"
ROLLBACK_DIRECTORY_NAME = "rollback"
ABSENT_STORE_MANIFEST_NAME = "ABSENT_STORE.rollback.json"
ABSENT_STORE_EVIDENCE_VERSION = 1
FORBIDDEN_PRODUCTION_IDENTITY_TERMS = ("cut1-", "cut2-", "rehearsal", "test")


@dataclass(frozen=True)
class AcceptedADCPBinding:
    repository_toplevel: str
    branch: str
    head: str
    clean: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository_toplevel": self.repository_toplevel,
            "branch": self.branch,
            "head": self.head,
            "clean": self.clean,
        }


@dataclass(frozen=True)
class ProductionPreparationResult:
    runtime_root: Path
    control_store: Path
    execution_id: str
    schema_version: int
    slice_count: int
    slice_snapshot_fingerprint: str
    rollback_snapshot_fingerprint: str
    authority_generation: int
    authority_mode: str
    cutover_id: str | None
    switched_at: str | None
    sqlite_integrity: str
    replayed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime_root": str(self.runtime_root),
            "control_store": str(self.control_store),
            "execution_id": self.execution_id,
            "schema_version": self.schema_version,
            "slice_count": self.slice_count,
            "slice_snapshot_fingerprint": self.slice_snapshot_fingerprint,
            "rollback_snapshot_fingerprint": self.rollback_snapshot_fingerprint,
            "authority_generation": self.authority_generation,
            "authority_mode": self.authority_mode,
            "cutover_id": self.cutover_id,
            "switched_at": self.switched_at,
            "sqlite_integrity": self.sqlite_integrity,
            "replayed": self.replayed,
        }


@dataclass(frozen=True)
class _PreparationPaths:
    runtime_root: Path
    control_store: Path

    @property
    def rollback_directory(self) -> Path:
        return self.runtime_root / ROLLBACK_DIRECTORY_NAME

    @property
    def absent_store_manifest(self) -> Path:
        return self.rollback_directory / ABSENT_STORE_MANIFEST_NAME


def _git(path: Path, *args: str) -> str:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if result.returncode:
        raise CutoverError("ADCP_BINDING_INSPECTION_FAILED", result.stderr.strip())
    return result.stdout.strip()


def inspect_accepted_adcp_binding(accepted_head: str) -> AcceptedADCPBinding:
    """Verify the human-accepted ADCP revision without changing Git state."""

    invalid_character = any(
        character not in "0123456789abcdef" for character in accepted_head
    )
    if len(accepted_head) != 40 or invalid_character:
        raise CutoverError("ACCEPTED_ADCP_HEAD_INVALID")
    source = CANONICAL_SOURCE_ROOT.resolve(strict=True)
    top = Path(_git(source, "rev-parse", "--show-toplevel")).resolve(strict=True)
    branch = _git(source, "symbolic-ref", "--short", "-q", "HEAD")
    head = _git(source, "rev-parse", "HEAD")
    clean = not _git(source, "status", "--porcelain", "--untracked-files=all")
    binding = AcceptedADCPBinding(str(top), branch, head, clean)
    expected = AcceptedADCPBinding(
        str(CANONICAL_SOURCE_ROOT.resolve(strict=False)),
        CANONICAL_BRANCH,
        accepted_head,
        True,
    )
    if binding != expected:
        raise CutoverError("ACCEPTED_ADCP_BINDING_DRIFT", canonical_json(binding.as_dict()))
    return binding


def _require_canonical_paths(paths: _PreparationPaths) -> None:
    runtime = paths.runtime_root.expanduser()
    store = paths.control_store.expanduser()
    if not runtime.is_absolute() or not store.is_absolute():
        raise CutoverError("CANONICAL_PRODUCTION_PATH_REQUIRED")
    canonical_runtime = CANONICAL_PRODUCTION_RUNTIME_ROOT.resolve(strict=False)
    canonical_store = CANONICAL_PRODUCTION_CONTROL_STORE.resolve(strict=False)
    if (
        runtime.resolve(strict=False) != canonical_runtime
        or store.resolve(strict=False) != canonical_store
    ):
        raise CutoverError("CANONICAL_PRODUCTION_PATH_REQUIRED")
    if runtime != CANONICAL_PRODUCTION_RUNTIME_ROOT or store != CANONICAL_PRODUCTION_CONTROL_STORE:
        raise CutoverError("CANONICAL_PRODUCTION_PATH_REQUIRED")


def _validate_production_identity(identity: str) -> None:
    lowered = identity.lower()
    if any(term in lowered for term in FORBIDDEN_PRODUCTION_IDENTITY_TERMS):
        raise CutoverError("PRODUCTION_IMPORT_IDENTITY_FORBIDDEN", identity)


def _expected_targets(manifest: MigrationManifest) -> tuple[dict[str, Any], ...]:
    return tuple(
        control_state_target(
            entry,
            active_execution_id=(
                PRODUCTION_IMPORT_EXECUTION_ID if entry.slice_id == CP_SLICE_ID else None
            ),
        )
        for entry in manifest.slices
    )


def _expected_snapshot(manifest: MigrationManifest) -> dict[str, Any]:
    return control_snapshot_material(
        ({**target, "state_version": 0} for target in _expected_targets(manifest))
    )


def _absence_payload(
    paths: _PreparationPaths,
    manifest: MigrationManifest,
    accepted_adcp_binding: AcceptedADCPBinding,
    observed_at: str,
) -> dict[str, Any]:
    snapshot = _expected_snapshot(manifest)
    return {
        "evidence_type": "ABSENT_STORE",
        "evidence_version": ABSENT_STORE_EVIDENCE_VERSION,
        "timestamp": observed_at,
        "runtime_root": str(paths.runtime_root),
        "control_store_path": str(paths.control_store),
        "pre_write_runtime_exists": False,
        "pre_write_control_store_exists": False,
        "accepted_adcp_binding": accepted_adcp_binding.as_dict(),
        "schema_target": SCHEMA_VERSION,
        "migration_manifest_fingerprint": manifest.fingerprint,
        "cp_manifest_entry_fingerprint": manifest.entry(CP_SLICE_ID).snapshot_fingerprint,
        "target_control_snapshot_fingerprint": snapshot["snapshot_fingerprint"],
    }


def _write_absence_evidence(path: Path, payload: Mapping[str, Any]) -> str:
    fingerprint = canonical_sha256(payload)
    document = {**dict(payload), "rollback_fingerprint": fingerprint}
    encoded = (canonical_json(document) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return fingerprint


def _reserve_control_store(path: Path) -> None:
    """Atomically claim the absent DB path without opening pre-existing state."""

    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise CutoverError("UNEXPECTED_PREEXISTING_STORE_STATE") from error
    except OSError as error:
        raise CutoverError("PRODUCTION_STORE_RESERVATION_FAILED", str(error)) from error
    else:
        os.close(descriptor)


def _read_absence_evidence(
    paths: _PreparationPaths,
    manifest: MigrationManifest,
    accepted_adcp_binding: AcceptedADCPBinding,
) -> tuple[dict[str, Any], str]:
    try:
        raw = paths.absent_store_manifest.read_text(encoding="utf-8")
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CutoverError("ABSENT_STORE_EVIDENCE_INVALID", str(error)) from error
    if not isinstance(document, dict) or "rollback_fingerprint" not in document:
        raise CutoverError("ABSENT_STORE_EVIDENCE_INVALID")
    payload = {key: value for key, value in document.items() if key != "rollback_fingerprint"}
    fingerprint = canonical_sha256(payload)
    if document["rollback_fingerprint"] != fingerprint:
        raise CutoverError("ABSENT_STORE_FINGERPRINT_MISMATCH")
    timestamp_value = payload.get("timestamp")
    if not isinstance(timestamp_value, str) or not timestamp_value:
        raise CutoverError("ABSENT_STORE_EVIDENCE_INVALID", "timestamp")
    expected = _absence_payload(paths, manifest, accepted_adcp_binding, timestamp_value)
    if payload != expected:
        raise CutoverError("ABSENT_STORE_BINDING_CONFLICT")
    if raw != canonical_json(document) + "\n":
        raise CutoverError("ABSENT_STORE_EVIDENCE_NOT_CANONICAL")
    return document, fingerprint


def _assert_expected_runtime_shape(paths: _PreparationPaths) -> None:
    if paths.runtime_root.is_symlink() or paths.control_store.is_symlink():
        raise CutoverError("PRODUCTION_PATH_SYMLINK_FORBIDDEN")
    try:
        runtime_entries = {entry.name for entry in paths.runtime_root.iterdir()}
    except OSError as error:
        raise CutoverError("PRODUCTION_RUNTIME_INSPECTION_FAILED", str(error)) from error
    if runtime_entries != {paths.control_store.name, ROLLBACK_DIRECTORY_NAME}:
        raise CutoverError("UNEXPECTED_PREEXISTING_RUNTIME_STATE")
    try:
        rollback_entries = {entry.name for entry in paths.rollback_directory.iterdir()}
    except OSError as error:
        raise CutoverError("UNEXPECTED_PREEXISTING_RUNTIME_STATE", str(error)) from error
    if rollback_entries != {ABSENT_STORE_MANIFEST_NAME}:
        raise CutoverError("UNEXPECTED_PREEXISTING_RUNTIME_STATE")
    if not paths.control_store.is_file() or not paths.absent_store_manifest.is_file():
        raise CutoverError("UNEXPECTED_PREEXISTING_RUNTIME_STATE")


def _readonly_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA query_only = ON")
    return connection


def _validate_prepared_store(
    paths: _PreparationPaths,
    manifest: MigrationManifest,
    rollback_fingerprint: str,
    *,
    replayed: bool,
) -> ProductionPreparationResult:
    expected_targets = {target["slice_id"]: target for target in _expected_targets(manifest)}
    expected_snapshot = _expected_snapshot(manifest)
    connection = _readonly_connection(paths.control_store)
    try:
        validate_schema(connection)
        versions = [row[0] for row in connection.execute(
            "SELECT version FROM schema_migration ORDER BY version"
        )]
        if versions != list(range(1, SCHEMA_VERSION + 1)):
            raise CutoverError("PRODUCTION_SCHEMA_VERSION_CONFLICT", repr(versions))

        executions = list(connection.execute("SELECT * FROM slice_execution"))
        if len(executions) != 1:
            raise CutoverError("PRODUCTION_EXECUTION_SET_CONFLICT", str(len(executions)))
        execution = executions[0]
        cp = manifest.entry(CP_SLICE_ID)
        expected_execution = {
            "execution_id": PRODUCTION_IMPORT_EXECUTION_ID,
            "slice_id": CP_SLICE_ID,
            "risk_level": RiskLevel.NORMAL.value,
            "environment": Environment.PRODUCTION.value,
            "state": "READY",
            "contract_fingerprint": canonical_sha256({"contract_url": cp.contract_url}),
            "authority_fingerprint": cp.snapshot_fingerprint,
            "source_root": str(Path(cp.repository_toplevel).resolve(strict=True)),
            "branch": cp.branch,
            "base_commit": cp.base_commit,
            "result_commit": cp.implementation_result_commit,
            "lease_owner": None,
            "lease_expires_at": None,
        }
        if any(execution[field] != value for field, value in expected_execution.items()):
            raise CutoverError("PRODUCTION_EXECUTION_BINDING_CONFLICT")
        _validate_production_identity(execution["execution_id"])

        transition_events = list(connection.execute(
            "SELECT * FROM transition_event WHERE execution_id = ? ORDER BY event_seq",
            (PRODUCTION_IMPORT_EXECUTION_ID,),
        ))
        if len(transition_events) != 4:
            raise CutoverError("PRODUCTION_IMPORT_EVENT_HISTORY_CONFLICT")
        for event in transition_events:
            _validate_production_identity(event["actor_id"])

        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM slice_control_state ORDER BY slice_id"
        )]
        if len(rows) != 5 or set(expected_targets) != {row["slice_id"] for row in rows}:
            raise CutoverError("CONTROL_STATE_SLICE_COUNT_INVALID", str(len(rows)))
        for row in rows:
            target = expected_targets[row["slice_id"]]
            if row["state_version"] != 0 or any(
                row[field] != target[field] for field in CONTROL_STATE_INPUT_FIELDS
            ):
                raise CutoverError("PRODUCTION_CONTROL_STATE_CONFLICT", row["slice_id"])

        control_events = list(connection.execute(
            "SELECT * FROM slice_control_event ORDER BY event_seq"
        ))
        if len(control_events) != 5 or any(
            event["from_state_version"] != -1 or event["to_state_version"] != 0
            for event in control_events
        ):
            raise CutoverError("PRODUCTION_CONTROL_EVENT_HISTORY_CONFLICT")

        snapshot = control_snapshot_material(rows)
        if snapshot["snapshot_fingerprint"] != expected_snapshot["snapshot_fingerprint"]:
            raise CutoverError("PRODUCTION_SNAPSHOT_FINGERPRINT_CONFLICT")
        authority_rows = list(connection.execute("SELECT * FROM control_authority_state"))
        if len(authority_rows) != 1:
            raise CutoverError("AUTHORITY_SINGLETON_CONFLICT")
        authority = authority_rows[0]
        expected_authority = {
            "singleton_id": "GLOBAL",
            "mode": AUTHORITY_MODE,
            "authority_generation": 1,
            "cutover_id": None,
            "slice_snapshot_fingerprint": snapshot["snapshot_fingerprint"],
            "rollback_snapshot_fingerprint": rollback_fingerprint,
            "switched_at": None,
        }
        if any(authority[field] != value for field, value in expected_authority.items()):
            raise CutoverError("PRODUCTION_AUTHORITY_STATE_CONFLICT")
        integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
        if integrity != ["ok"]:
            raise CutoverError("PRODUCTION_SQLITE_INTEGRITY_FAILED", repr(integrity))
        if list(connection.execute("PRAGMA foreign_key_check")):
            raise CutoverError("PRODUCTION_SQLITE_FOREIGN_KEY_FAILED")
        return ProductionPreparationResult(
            paths.runtime_root,
            paths.control_store,
            PRODUCTION_IMPORT_EXECUTION_ID,
            SCHEMA_VERSION,
            len(rows),
            snapshot["snapshot_fingerprint"],
            rollback_fingerprint,
            authority["authority_generation"],
            authority["mode"],
            authority["cutover_id"],
            authority["switched_at"],
            integrity[0],
            replayed,
        )
    except (sqlite3.DatabaseError, StoreError) as error:
        raise CutoverError("PRODUCTION_STORE_VALIDATION_FAILED", str(error)) from error
    finally:
        connection.close()


def _import_cp(
    store: ControlStore,
    manifest: MigrationManifest,
    cp_binding: GitBindingEvidence,
) -> None:
    entry = manifest.entry(CP_SLICE_ID)
    decision = classify_seed_eligibility(entry, cp_binding)
    if decision.eligibility is not SeedEligibility.ELIGIBLE:
        raise CutoverError("PRODUCTION_IMPORT_INELIGIBLE", decision.reason)
    _validate_production_identity(PRODUCTION_IMPORT_EXECUTION_ID)
    importer = "production-preparation-importer"
    row = store.create_execution(
        ExecutionCreate(
            execution_id=PRODUCTION_IMPORT_EXECUTION_ID,
            slice_id=entry.slice_id,
            risk_level=RiskLevel.NORMAL,
            environment=Environment.PRODUCTION,
            contract_fingerprint=canonical_sha256({"contract_url": entry.contract_url}),
            authority_fingerprint=entry.snapshot_fingerprint,
            source_root=entry.repository_toplevel,
            branch=entry.branch,
            base_commit=entry.base_commit,
        ),
        operation_key(
            "production-import-create", {"entry_fingerprint": entry.snapshot_fingerprint}
        ),
    )
    row = store.acquire_lease(
        PRODUCTION_IMPORT_EXECUTION_ID,
        row["state_version"],
        operation_key(
            "production-import-lease", {"entry_fingerprint": entry.snapshot_fingerprint}
        ),
        importer,
    )
    row = store.register_result_commit(
        PRODUCTION_IMPORT_EXECUTION_ID,
        row["state_version"],
        operation_key(
            "production-import-result", {"entry_fingerprint": entry.snapshot_fingerprint}
        ),
        entry.implementation_result_commit,
        lease_owner=importer,
        lease_generation=row["lease_generation"],
        actor_role=ActorRole.CONTROLLER,
        actor_id=importer,
    )
    store.release_lease(
        PRODUCTION_IMPORT_EXECUTION_ID,
        row["state_version"],
        operation_key(
            "production-import-release", {"entry_fingerprint": entry.snapshot_fingerprint}
        ),
        importer,
        row["lease_generation"],
    )


def _prepare_production_at(
    paths: _PreparationPaths,
    manifest: MigrationManifest,
    cp_binding: GitBindingEvidence,
    accepted_adcp_binding: AcceptedADCPBinding,
    *,
    clock: Callable[[], datetime] = utc_now,
) -> ProductionPreparationResult:
    """Private injected-path seam used only for isolated validation."""

    manifest.validate()
    if len(manifest.slices) != 5:
        raise CutoverError("MANIFEST_SLICE_COUNT_INVALID")
    runtime_exists = paths.runtime_root.exists() or paths.runtime_root.is_symlink()
    store_exists = paths.control_store.exists() or paths.control_store.is_symlink()
    if runtime_exists:
        if not store_exists:
            raise CutoverError("UNEXPECTED_PREEXISTING_RUNTIME_STATE")
        _assert_expected_runtime_shape(paths)
        _, rollback_fingerprint = _read_absence_evidence(
            paths, manifest, accepted_adcp_binding
        )
        return _validate_prepared_store(
            paths, manifest, rollback_fingerprint, replayed=True
        )
    if store_exists:
        raise CutoverError("UNEXPECTED_PREEXISTING_STORE_STATE")

    paths.runtime_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    paths.rollback_directory.mkdir(mode=0o700, exist_ok=False)
    payload = _absence_payload(
        paths,
        manifest,
        accepted_adcp_binding,
        timestamp(clock()),
    )
    rollback_fingerprint = _write_absence_evidence(paths.absent_store_manifest, payload)
    _reserve_control_store(paths.control_store)

    store = ControlStore(
        paths.control_store,
        backup_root=paths.runtime_root / "backups",
        clock=clock,
        # Explicit 01C bootstrap boundary: authority objects do not exist until this
        # migration completes, so recursive GLOBAL_PRODUCTION guarding is impossible.
        allow_canonical_production_bootstrap=True,
        global_writer_guard_required=False,
    )
    try:
        _import_cp(store, manifest, cp_binding)
        for target in _expected_targets(manifest):
            store.reconcile_slice_control_state(
                target,
                -1,
                operation_key(
                    "production-control-state-import",
                    {
                        "slice_id": target["slice_id"],
                        "authority_fingerprint": target["authority_fingerprint"],
                    },
                ),
                reason_code="PRODUCTION_PREPARATION_IMPORT",
                metadata={"manifest_fingerprint": manifest.fingerprint},
            )
        rows = [dict(row) for row in store.slice_control_states()]
        snapshot = control_snapshot_material(rows)
        authority = store.get_control_authority_state()
        store.reconcile_transitional_authority(
            authority["authority_generation"],
            snapshot["snapshot_fingerprint"],
            rollback_fingerprint,
        )
    except StoreError as error:
        raise CutoverError("PRODUCTION_PREPARATION_FAILED", error.code) from error
    finally:
        store.close()
    _assert_expected_runtime_shape(paths)
    _, observed_rollback_fingerprint = _read_absence_evidence(
        paths, manifest, accepted_adcp_binding
    )
    return _validate_prepared_store(
        paths, manifest, observed_rollback_fingerprint, replayed=False
    )


def prepare_canonical_production(accepted_adcp_head: str) -> ProductionPreparationResult:
    """Prepare only the canonical production store after an explicit human gate."""

    paths = _PreparationPaths(
        CANONICAL_PRODUCTION_RUNTIME_ROOT,
        CANONICAL_PRODUCTION_CONTROL_STORE,
    )
    _require_canonical_paths(paths)
    accepted_binding = inspect_accepted_adcp_binding(accepted_adcp_head)
    manifest = frozen_cut1_manifest()
    cp_binding = inspect_git_binding(manifest.entry(CP_SLICE_ID))
    return _prepare_production_at(paths, manifest, cp_binding, accepted_binding)


__all__ = [
    "ABSENT_STORE_MANIFEST_NAME",
    "AcceptedADCPBinding",
    "CANONICAL_PRODUCTION_CONTROL_STORE",
    "CANONICAL_PRODUCTION_RUNTIME_ROOT",
    "PRODUCTION_IMPORT_EXECUTION_ID",
    "ProductionPreparationResult",
    "inspect_accepted_adcp_binding",
    "prepare_canonical_production",
]
