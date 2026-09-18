"""Sealed TK-43/DL-85 Production DCS schema-9 -> schema-10 support.

This module deliberately exposes no arbitrary schema, DCS path, lease identity,
writer set, runtime artifact, or migration selector.  The public path is the one
canonical DL-85 transition only.  Production invocation remains separately
authorized; importing this module performs no Production effect.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import stat
from typing import Any, Callable, Mapping
from uuid import uuid4

from adcp.domain import StoreError, operation_key
from adcp.production_dcs_v8_adoption import (
    DcsWriterInventory,
    DcsWriterInventoryEntry,
    ProductionDcsV8AdoptionError,
    _LaunchdWriterAuthority,
    _QuiescenceToken,
    _entry_before_class,
    _inventory_fingerprint,
    _stable_inventory_fingerprint,
)
from adcp.runtime_artifact_attestation import RuntimeArtifactAttestation, attest_runtime_artifact
from adcp.store import migrations
from adcp.store.migrations import schema_profile_identity, validate_schema
from adcp.store.sqlite import CANONICAL_PRODUCTION_CONTROL_STORE, ControlStore


PROJECT_CODE = "CHAT.PROJ.HQ"
CHANGE_ID = "P0-CLEANER-POSTGRES-AUTHORITY-CUTOVER-01"
DL85_CONTROL_DECISION_REF = (
    "CHAT.PROJ.HQ:DECISION:TK43_DL84_SCHEMA10_OPERATIONAL_MACHINERY_CLOSURE:V1"
)
SCHEMA9 = 9
SCHEMA10 = 10
SCHEMA9_PROFILE = "sha256:0f0bf3c32f0cf4af5b047bc6afdf2a61940df2a1e2a8395463f9183e678e3b6b"
SCHEMA10_PROFILE = "sha256:1bfa57994e2ea90b11146d32839ca6a8875ad94bb0eea9128fb3b8fb3c5ce7e9"
MIGRATION10_NAME = "0010_typed_postgres_operation_receipt_provision_principal"
MIGRATION10_CHECKSUM = "fa241b5205b014bca2524ef35018c319050d560cbcf2c79d004a9d587dc78d6f"
CANONICAL_DCS_PATH = CANONICAL_PRODUCTION_CONTROL_STORE
CANONICAL_BACKUP_ROOT = Path("/Users/kate/DKATE/adcp-runtime/schema9-to10-backups")
CANONICAL_RUNTIME_IDENTITY_ROOT = Path(
    "/Users/kate/DKATE/adcp-runtime/propertyai-global-writer-runtime"
)
V04_VERSION = "0.4.0"
V04_SOURCE = "23ce586dd369a60ac7bbbd24b33175deb05a402d"
V04_BUILD_ID = "adcp-global-writer-client@0.4.0+g23ce586dd369"
V04_CLIENT_BUILD = (
    f"{V04_BUILD_ID}|source={V04_SOURCE}|artifact=source-commit:{V04_SOURCE}"
)
V04_SHA256 = "0057f94b4b7a64ff76046737815852c601fb4d567e2ddb3eb988531a4c084426"
V04_WHEEL = Path(
    "/Users/kate/DKATE/adcp-runtime/artifacts/adcp-global-writer-client/0.4.0/"
    + V04_SHA256
    + "/adcp_global_writer_client-0.4.0-py3-none-any.whl"
)
V05_VERSION = "0.5.0"
V05_SOURCE = "4e3bd2691b2ed58eccb65c32ad127467c89a6ebb"
V05_BUILD_ID = "adcp-global-writer-client@0.5.0+g4e3bd2691b2e"
V05_CLIENT_BUILD = (
    f"{V05_BUILD_ID}|source={V05_SOURCE}|artifact=source-commit:{V05_SOURCE}"
)
V05_SHA256 = "365e39886a6169b20d358e3dd331825ef6c8187987055f83cb04fae453e0c61e"
V05_WHEEL = Path(
    "/Users/kate/DKATE/adcp-runtime/artifacts/adcp-global-writer-client/0.5.0/"
    + V05_SHA256
    + "/adcp_global_writer_client-0.5.0-py3-none-any.whl"
)
EXPECTED_WRITERS = {
    "W01": "PROPERTYAI_W01_GMAIL_INGEST_PROJECTION",
    "W02": "PROPERTYAI_W02_OPS_TELEGRAM_MUTATION",
    "W03": "PROPERTYAI_W03_CLEANER_TELEGRAM_MUTATION",
    "W04": "PROPERTYAI_W04_CLEANING_OPERATIONS_DISPATCH",
    "W05": "PROPERTYAI_W05_CLEANING_COMPLETION_DISPATCH",
    "W06": "PROPERTYAI_W06_HEALTH_RECOVERY_MAINTENANCE",
}
PRODUCTION_PRODUCT_COMMIT = "1496d9ea5f4b91df2958d948970e859f790fa7f5"
W08_TTL_SECONDS = 300
_W08_CONSTRUCTOR_SEAL = object()
_MIGRATION_EXECUTION_SEAL = object()


def _attest_schema9_10_runtime_artifact(
    entry: DcsWriterInventoryEntry, schema_version: int
) -> RuntimeArtifactAttestation:
    """Fresh sealed thin-client artifact attestation shared by schema9/10 restore paths."""

    if schema_version not in {SCHEMA9, SCHEMA10}:
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_SCHEMA_INVALID", str(schema_version)
        )
    if entry.client.version == V05_VERSION:
        wheel, sha, version, build, source = (
            V05_WHEEL, V05_SHA256, V05_VERSION, V05_BUILD_ID, V05_SOURCE
        )
    elif entry.client.version == V04_VERSION and schema_version == SCHEMA9:
        wheel, sha, version, build, source = (
            V04_WHEEL, V04_SHA256, V04_VERSION, V04_BUILD_ID, V04_SOURCE
        )
    else:
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_CLIENT_INVALID", entry.writer_id
        )
    if not entry.program_arguments:
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_INTERPRETER_MISSING", entry.writer_id
        )
    if entry.plist_path is None:
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_PLIST_MISSING", entry.writer_id
        )
    try:
        document = plistlib.loads(entry.plist_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_PLIST_INVALID", entry.writer_id
        ) from error
    env = document.get("EnvironmentVariables") or {}
    if not isinstance(env, Mapping):
        raise ProductionSchema10OperationalError(
            "SCHEMA10_ATTEST_ENV_INVALID", entry.writer_id
        )
    facts: dict[str, Any] = {
        "writer": entry.writer_id,
        "label": entry.launchd_label,
        "interpreter": entry.program_arguments[0],
    }
    if entry.runtime_state == "ACTIVE":
        facts["incarnation"] = entry.process_incarnation_id
    return attest_runtime_artifact(
        accepted_wheel_path=wheel,
        expected_wheel_sha256=sha,
        interpreter_path=entry.program_arguments[0],
        expected_version=version,
        expected_build_id=build,
        expected_source_commit=source,
        required_dcs_schema=schema_version,
        startup_environment={
            str(k): str(v)
            for k, v in env.items()
            if isinstance(k, str) and isinstance(v, str)
        },
        startup_working_directory=entry.working_directory,
        binding_facts=facts,
    )


class ProductionSchema10OperationalError(RuntimeError):
    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        evidence_payload: Mapping[str, Any] | None = None,
        serialization_failures: tuple[Mapping[str, str], ...] = (),
    ) -> None:
        # DL-93 terminal boundary: error construction is itself part of the
        # non-recursive recovery surface.  Any evidence-normalization defect is
        # contained here and the complete RuntimeError message is byte-bounded.
        inherited_payload = None
        inherited_failures: tuple[Mapping[str, str], ...] = ()
        constructor_failure = None
        try:
            safe_code = code if type(code) is str else _terminal_safe_scalar(code)
            if type(detail) in {
                _EvidenceDetail, _TerminalEvidenceFallback, _TerminalEvidenceEmergency
            }:
                detail_text = str.__str__(detail)
                try:
                    inherited_payload = object.__getattribute__(detail, "evidence_payload")
                except BaseException:
                    inherited_payload = None
                try:
                    inherited_failures = _terminal_failure_tuple(
                        object.__getattribute__(detail, "serialization_failures")
                    )
                except BaseException:
                    inherited_failures = ()
            else:
                detail_text = _terminal_safe_detail_text(detail)

            if evidence_payload is not None:
                safe_payload = _terminal_payload_dict(evidence_payload)
            elif inherited_payload is not None:
                safe_payload = _terminal_payload_dict(inherited_payload)
            else:
                safe_payload = None
            explicit_failures = _terminal_failure_tuple(serialization_failures)
            safe_failures = (
                explicit_failures if len(explicit_failures) > 0 else inherited_failures
            )
        except BaseException as error:
            constructor_failure = error
            safe_code = code if type(code) is str else "SCHEMA10_TERMINAL_ERROR"
            detail_text = detail if type(detail) is str else "<terminal-detail-unavailable>"
            safe_payload = {
                "terminal_error_constructor_failure": {
                    "exception_type": _safe_type_name(error),
                    "detail": _safe_exception_text(error),
                }
            }
            safe_failures = ()

        try:
            safe_code, detail_text, message = _bounded_error_components(safe_code, detail_text)
        except BaseException:
            safe_code = "SCHEMA10_TERMINAL_ERROR"
            detail_text = "<terminal-message-bounding-failed>"
            message = safe_code + ": " + detail_text
        if constructor_failure is not None and type(safe_payload) is dict:
            safe_payload.setdefault("terminal_error_constructor_contained", True)
        self.code = safe_code
        self.detail = detail_text
        self.evidence_payload = safe_payload
        self.serialization_failures = safe_failures
        RuntimeError.__init__(self, message)


@dataclass(frozen=True)
class Schema10BackupEvidence:
    operation_id: str
    source_path: str
    source_device: int
    source_inode: int
    source_sha256: str
    source_size: int
    backup_path: str
    backup_sha256: str
    backup_size: int
    manifest_path: str
    backup_identity: str
    schema_profile: str


@dataclass(frozen=True)
class Schema10W08RebindEvidence:
    operation_id: str
    owner_id: str
    owner_execution_id: str
    fencing_token: int
    schema_version: int
    schema_profile: str
    heartbeat_same_identity: bool
    acquire_event_seq: int


@dataclass(frozen=True)
class Schema10WriterQuiescenceEvidence:
    operation_id: str
    inventory_fingerprint: str
    stable_inventory_fingerprint: str
    before_classes: tuple[tuple[str, str], ...]
    quiesce_order: tuple[str, ...]


@dataclass(frozen=True)
class Schema10AuthorizedProjectionEvidence:
    operation_id: str
    target_client_build: str
    per_writer_sha256: tuple[tuple[str, str], ...]
    projection_identity: str


@dataclass(frozen=True)
class Schema10WriterRestoreEvidence:
    operation_id: str
    schema_version: int
    inventory_fingerprint: str
    stable_inventory_fingerprint: str
    all_clients_support_schema: bool
    owner_id: str | None
    owner_execution_id: str | None
    fencing_token: int | None


@dataclass(frozen=True)
class _SchemaState:
    version: int
    profile: str
    history: tuple[tuple[int, str, str], ...]
    integrity: str
    foreign_key_violations: int


@dataclass(frozen=True)
class _AtomicFailureEvidence:
    operation: str
    exception_type: str
    detail: str


@dataclass(frozen=True)
class _ProjectionObservationOutcome:
    observation_attempted: bool
    path_exists: str
    read_bytes_status: str
    stat_status: str
    hash_status: str
    observed_bytes_hash: str | None
    observed_mode: int | None
    observed_size: int | None
    read_failure: _AtomicFailureEvidence | None
    stat_failure: _AtomicFailureEvidence | None
    hash_failure: _AtomicFailureEvidence | None
    observation_complete: bool
    state: str


@dataclass(frozen=True)
class _DirectoryDurabilityOutcome:
    open_status: str
    fsync_status: str
    close_status: str
    open_failure: _AtomicFailureEvidence | None = None
    fsync_failure: _AtomicFailureEvidence | None = None
    close_failure: _AtomicFailureEvidence | None = None

    @property
    def fsync_complete(self) -> bool:
        return self.fsync_status == "SUCCESS"

    @property
    def operation_complete(self) -> bool:
        return (
            self.open_status == "SUCCESS"
            and self.fsync_status == "SUCCESS"
            and self.close_status == "SUCCESS"
        )


def _atomic_failure_payload(
    failure: _AtomicFailureEvidence | None,
) -> Mapping[str, str] | None:
    if failure is None:
        return None
    return {
        "operation": failure.operation,
        "exception_type": failure.exception_type,
        "detail": failure.detail,
    }


def _projection_observation_payload(
    outcome: _ProjectionObservationOutcome,
) -> Mapping[str, Any]:
    absent = outcome.state == "ABSENT"
    return {
        "observation_attempted": "YES" if outcome.observation_attempted else "NO",
        "path_exists": outcome.path_exists,
        "read_bytes": outcome.read_bytes_status,
        "stat": outcome.stat_status,
        "hash": outcome.hash_status,
        "observed_bytes_hash": (
            outcome.observed_bytes_hash
            if outcome.observed_bytes_hash is not None
            else (None if absent else "UNKNOWN")
        ),
        "observed_mode": (
            outcome.observed_mode
            if outcome.observed_mode is not None
            else (None if absent else "UNKNOWN")
        ),
        "observed_size": (
            outcome.observed_size
            if outcome.observed_size is not None
            else (None if absent else "UNKNOWN")
        ),
        "read_failure": _atomic_failure_payload(outcome.read_failure),
        "stat_failure": _atomic_failure_payload(outcome.stat_failure),
        "hash_failure": _atomic_failure_payload(outcome.hash_failure),
        "observation_complete": "YES" if outcome.observation_complete else "NO",
        "state": outcome.state,
        # Compatibility aliases retained for existing reconciliation consumers.
        "exists": (
            True
            if outcome.path_exists == "YES"
            else (False if outcome.path_exists == "NO" else None)
        ),
        "sha256": (
            outcome.observed_bytes_hash
            if outcome.observed_bytes_hash is not None
            else (None if absent else "UNKNOWN")
        ),
        "mode": (
            outcome.observed_mode
            if outcome.observed_mode is not None
            else (None if absent else "UNKNOWN")
        ),
        "size": (
            outcome.observed_size
            if outcome.observed_size is not None
            else (None if absent else "UNKNOWN")
        ),
    }


def _directory_durability_payload(
    outcome: _DirectoryDurabilityOutcome | None,
) -> Mapping[str, Any] | None:
    if outcome is None:
        return None
    return {
        "open": outcome.open_status,
        "fsync": outcome.fsync_status,
        "close": outcome.close_status,
        "fsync_complete": outcome.fsync_complete,
        "operation_complete": outcome.operation_complete,
        "open_failure": _atomic_failure_payload(outcome.open_failure),
        "fsync_failure": _atomic_failure_payload(outcome.fsync_failure),
        "close_failure": _atomic_failure_payload(outcome.close_failure),
    }


@dataclass(frozen=True)
class _TempStreamOutcome:
    open_status: str
    write_status: str
    flush_status: str
    fsync_status: str
    close_status: str
    open_failure: _AtomicFailureEvidence | None = None
    write_failure: _AtomicFailureEvidence | None = None
    flush_failure: _AtomicFailureEvidence | None = None
    fsync_failure: _AtomicFailureEvidence | None = None
    close_failure: _AtomicFailureEvidence | None = None

    @property
    def primary_failure(self) -> _AtomicFailureEvidence | None:
        return _first_non_none(
            self.open_failure,
            self.write_failure,
            self.flush_failure,
            self.fsync_failure,
            self.close_failure,
        )

    @property
    def operation_complete(self) -> bool:
        return (
            self.open_status == "SUCCESS"
            and self.write_status == "SUCCESS"
            and self.flush_status == "SUCCESS"
            and self.fsync_status == "SUCCESS"
            and self.close_status == "SUCCESS"
        )


def _temp_stream_payload(
    outcome: _TempStreamOutcome | None,
) -> Mapping[str, Any] | None:
    if outcome is None:
        return None
    return {
        "open": outcome.open_status,
        "write": outcome.write_status,
        "flush": outcome.flush_status,
        "fsync": outcome.fsync_status,
        "close": outcome.close_status,
        "operation_complete": outcome.operation_complete,
        "open_failure": _atomic_failure_payload(outcome.open_failure),
        "write_failure": _atomic_failure_payload(outcome.write_failure),
        "flush_failure": _atomic_failure_payload(outcome.flush_failure),
        "fsync_failure": _atomic_failure_payload(outcome.fsync_failure),
        "close_failure": _atomic_failure_payload(outcome.close_failure),
    }


class _DirectoryDurabilityFailure(ProductionSchema10OperationalError):
    def __init__(
        self,
        outcome: _DirectoryDurabilityOutcome,
        primary_cause: BaseException | None = None,
        close_cause: BaseException | None = None,
    ) -> None:
        self.outcome = outcome
        self.primary_cause = primary_cause
        self.close_cause = close_cause
        self.cause = _first_non_none(primary_cause, close_cause)
        payload = _directory_durability_payload(outcome) or {}
        prior_failures, _ = _collect_error_serialization_failures(primary_cause, close_cause)
        try:
            detail = _serialize_evidence_payload(
                payload,
                operation="DIRECTORY_DURABILITY_SERIALIZATION",
                force_failsafe=len(prior_failures) > 0,
                prior_failures=prior_failures,
            )
        except BaseException as reporting_error:
            detail = _independent_reporting_detail(
                "DIRECTORY_DURABILITY_REPORTING",
                payload,
                reporting_error,
                prior_failures=prior_failures,
            )
        super().__init__("SCHEMA10_DIRECTORY_DURABILITY_FAILED", detail)


@dataclass(frozen=True)
class _AtomicWriteOutcome:
    destination_replaced: bool
    durability_complete: bool
    failed_operation: str | None = None
    primary_failure: _AtomicFailureEvidence | None = None
    cleanup_failure: _AtomicFailureEvidence | None = None
    directory_outcome: _DirectoryDurabilityOutcome | None = None
    secondary_failures: tuple[_AtomicFailureEvidence, ...] = ()
    temp_path: str | None = None
    temp_residual_state: str = "NONE"
    temp_residual_observation_failure: _AtomicFailureEvidence | None = None
    temp_stream_outcome: _TempStreamOutcome | None = None
    chmod_status: str = "NOT_ATTEMPTED"

    @property
    def operation_complete(self) -> bool:
        return self.primary_failure is None and not self.secondary_failures


def _atomic_write_outcome_payload(outcome: _AtomicWriteOutcome) -> Mapping[str, Any]:
    return {
        "destination_replaced": outcome.destination_replaced,
        "durability_complete": outcome.durability_complete,
        "operation_complete": outcome.operation_complete,
        "failed_operation": outcome.failed_operation,
        "primary_failure": _atomic_failure_payload(outcome.primary_failure),
        "secondary_failures": [
            _atomic_failure_payload(failure) for failure in outcome.secondary_failures
        ],
        "temp_stream": _temp_stream_payload(outcome.temp_stream_outcome),
        "chmod": outcome.chmod_status,
        "directory_durability": _directory_durability_payload(outcome.directory_outcome),
        "cleanup_failure": _atomic_failure_payload(outcome.cleanup_failure),
        "temp_residual_state": {
            "path": outcome.temp_path,
            "state": outcome.temp_residual_state,
            "observation_failure": _atomic_failure_payload(
                outcome.temp_residual_observation_failure
            ),
        },
    }


class _AtomicWriteFailure(ProductionSchema10OperationalError):
    def __init__(
        self,
        outcome: _AtomicWriteOutcome,
        primary_cause: BaseException | None = None,
        cleanup_cause: BaseException | None = None,
        secondary_causes: tuple[BaseException, ...] = (),
        evidence_causes: tuple[BaseException, ...] = (),
    ) -> None:
        self.outcome = outcome
        self.primary_cause = primary_cause
        self.cleanup_cause = cleanup_cause
        self.secondary_causes = secondary_causes
        self.evidence_causes = evidence_causes
        secondary_cause = secondary_causes[0] if len(secondary_causes) > 0 else None
        self.cause = _first_non_none(primary_cause, secondary_cause, cleanup_cause)
        payload = _atomic_write_outcome_payload(outcome)
        prior_failures, _ = _collect_error_serialization_failures(
            *evidence_causes, primary_cause, cleanup_cause, *secondary_causes
        )
        try:
            detail = _serialize_evidence_payload(
                payload,
                operation="ATOMIC_WRITE_FAILURE_SERIALIZATION",
                force_failsafe=len(prior_failures) > 0,
                prior_failures=prior_failures,
            )
        except BaseException as reporting_error:
            detail = _independent_reporting_detail(
                "ATOMIC_WRITE_FAILURE_REPORTING",
                payload,
                reporting_error,
                prior_failures=prior_failures,
            )
        super().__init__("SCHEMA10_ATOMIC_WRITE_FAILED", detail)


class _AtomicWriteReportingFailure(RuntimeError):
    """Carries exact write facts and prior evidence when typed reporting itself fails."""

    def __init__(
        self,
        outcome: _AtomicWriteOutcome,
        reporting_error: BaseException,
        serialization_failures: tuple[Mapping[str, str], ...] = (),
    ) -> None:
        self.outcome = outcome
        self.reporting_error = reporting_error
        self.serialization_failures = serialization_failures
        self.evidence_payload = {
            "serialization_failures": list(serialization_failures),
            "serialization_failure": (
                serialization_failures[0] if len(serialization_failures) > 0 else None
            ),
        }
        RuntimeError.__init__(self, "SCHEMA10_ATOMIC_WRITE_REPORTING_FAILED")


@dataclass(frozen=True)
class _AbsenceRestorationOutcome:
    unlink_status: str = "NOT_ATTEMPTED"
    unlink_failure: _AtomicFailureEvidence | None = None
    directory_outcome: _DirectoryDurabilityOutcome | None = None
    directory_failure: _AtomicFailureEvidence | None = None

    @property
    def durability_complete(self) -> bool:
        return (
            self.unlink_status == "SUCCESS"
            and self.directory_outcome is not None
            and self.directory_outcome.fsync_complete
        )


def _absence_restoration_payload(
    outcome: _AbsenceRestorationOutcome | None,
) -> Mapping[str, Any] | None:
    if outcome is None:
        return None
    return {
        "unlink": outcome.unlink_status,
        "unlink_failure": _atomic_failure_payload(outcome.unlink_failure),
        "directory_durability": _directory_durability_payload(outcome.directory_outcome),
        "directory_failure": _atomic_failure_payload(outcome.directory_failure),
        "durability_complete": outcome.durability_complete,
    }


@dataclass
class _ProjectionEntryState:
    writer_id: str
    path: Path
    existed: bool
    payload: bytes | None
    mode: int | None
    payload_sha256: str | None
    source_payload: bytes
    target_payload: bytes
    target_sha256: str
    entry_was_already_target: bool = False
    write_attempted: bool = False
    destination_replaced: bool = False
    post_replace_durability_complete: bool = False
    failed_post_replace_operation: str | None = None
    changed_by_invocation: bool = False
    last_write_outcome: _AtomicWriteOutcome | None = None
    compensation_attempted: bool = False
    restoration_write_outcome: _AtomicWriteOutcome | None = None
    absence_restoration_outcome: _AbsenceRestorationOutcome | None = None
    reconciliation_observations: list[Mapping[str, Any]] = field(default_factory=list)


class _EvidenceDetail(str):
    """Terminal-safe evidence text plus an already-normalized primitive snapshot."""

    def __new__(
        cls,
        text: str,
        evidence_payload: Mapping[str, Any],
        serialization_failures: tuple[Mapping[str, str], ...] = (),
    ):
        # Callers normalize before construction.  Keeping this constructor free of
        # recursive normalization prevents a reporting-constructor failure from
        # re-entering the same evidence machinery.
        exact_text = text if type(text) is str else "<terminal-detail-invalid>"
        value = str.__new__(cls, exact_text)
        value.evidence_payload = evidence_payload if type(evidence_payload) is dict else {}
        value.serialization_failures = (
            serialization_failures if type(serialization_failures) is tuple else ()
        )
        return value


class _TerminalEvidenceFallback(str):
    """Independent carrier used only if the primary detail constructor fails."""

    def __new__(
        cls,
        text: str,
        evidence_payload: Mapping[str, Any],
        serialization_failures: tuple[Mapping[str, str], ...] = (),
    ):
        exact_text = text if type(text) is str else "<terminal-detail-fallback>"
        value = str.__new__(cls, exact_text)
        value.evidence_payload = evidence_payload if type(evidence_payload) is dict else {}
        value.serialization_failures = (
            serialization_failures if type(serialization_failures) is tuple else ()
        )
        return value


class _TerminalEvidenceEmergency(str):
    """Third carrier whose instance is built by str.__new__ directly."""


class _TerminalRecoverySurfaceError(ProductionSchema10OperationalError):
    """Final independent typed surface; never calls the ordinary evidence pipeline."""

    def __init__(
        self,
        detail: str,
        evidence_payload: dict[str, Any],
        serialization_failures: tuple[Mapping[str, str], ...],
    ) -> None:
        code = "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED"
        exact_detail = _emergency_exact_text(detail, TERMINAL_EVIDENCE_MAX_BYTES - 64)
        prefix = code + ": "
        prefix_bytes = str.encode(prefix, "utf-8", "strict")
        exact_detail = _emergency_exact_text(
            exact_detail, TERMINAL_EVIDENCE_MAX_BYTES - len(prefix_bytes)
        )
        self.code = code
        self.detail = exact_detail
        self.evidence_payload = evidence_payload if type(evidence_payload) is dict else {}
        self.serialization_failures = (
            serialization_failures if type(serialization_failures) is tuple else ()
        )
        RuntimeError.__init__(self, prefix + exact_detail)


TERMINAL_EVIDENCE_MAX_BYTES = 32768
_TERMINAL_MAX_DEPTH = 20
_TERMINAL_MAX_NODES = 4096
_TERMINAL_MAX_SCALAR_BYTES = 8192
_TERMINAL_MAX_KEY_BYTES = 512
_TERMINAL_MAX_CONTAINER_ITEMS = 256
_TERMINAL_TRUNCATION_MARKER = "<DL93_TRUNCATED>"
_TERMINAL_IDENTITY_RESERVE_KEY = "__terminal_identity_reserve__"
_TERMINAL_PRIORITY_KEYS = (
    "original_operation_error", "outer_compensation_error",
    "unexpected_compensation_error", "terminal_recovery_builder_failure",
    "terminal_snapshot_failure", "terminal_attach_failure",
    "critical_error_identity", "writer_id", "required_reconciliation_action",
    "destination_state", "destination_replaced", "compensation_restoration",
    "restore_primary_failure", "serialization_failure",
    "serialization_fallback_failure", "serialization_failures",
    "exception_type", "code", "operation", "critical",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _first_non_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _safe_type_name(value: Any) -> str:
    cls = type(value)
    try:
        module = type.__getattribute__(cls, "__module__")
    except BaseException:
        module = "<module-unavailable>"
    try:
        qualname = type.__getattribute__(cls, "__qualname__")
    except BaseException:
        qualname = "<qualname-unavailable>"
    if type(module) is not str:
        module = "<module-unavailable>"
    if type(qualname) is not str:
        qualname = "<qualname-unavailable>"
    return module + "." + qualname


def _emergency_exact_text(value: Any, max_bytes: int) -> str:
    """Minimal builtin-only normalizer reserved for the independent final surface."""
    try:
        if type(value) is not str:
            value = "<terminal-emergency-text-unavailable>"
        raw = str.encode(value, "utf-8", "backslashreplace")
        if len(raw) > max_bytes:
            marker = b"<DL93_EMERGENCY_TRUNCATED>"
            keep = max(0, max_bytes - len(marker))
            raw = raw[:keep] + marker[: max_bytes - keep]
        return bytes.decode(raw, "utf-8", "ignore")
    except BaseException:
        return "<terminal-emergency-text-unavailable>"


def _normalize_exact_string(value: str) -> str:
    """Return a plain UTF-8 encodable builtin str without calling subclass hooks."""
    if type(value) is not str:
        return "<untrusted-string-subclass:" + _safe_type_name(value) + ">"
    try:
        raw = str.encode(value, "utf-8", "backslashreplace")
        return bytes.decode(raw, "utf-8", "strict")
    except BaseException:
        return "<string-normalization-failed>"


def _encoded_utf8(value: str) -> bytes:
    if type(value) is not str:
        raise TypeError("terminal renderer must return exact builtin str")
    return str.encode(value, "utf-8", "strict")


def _truncate_exact_text(value: str, max_bytes: int) -> str:
    text = _normalize_exact_string(value)
    encoded = _encoded_utf8(text)
    if len(encoded) <= max_bytes:
        return text
    marker = _TERMINAL_TRUNCATION_MARKER
    marker_bytes = _encoded_utf8(marker)
    if max_bytes <= len(marker_bytes):
        return bytes.decode(marker_bytes[:max_bytes], "utf-8", "ignore")
    prefix = encoded[: max_bytes - len(marker_bytes)]
    safe_prefix = bytes.decode(prefix, "utf-8", "ignore")
    result = safe_prefix + marker
    # UTF-8 boundary contraction can only shrink, but enforce the invariant anyway.
    while len(_encoded_utf8(result)) > max_bytes and safe_prefix != "":
        safe_prefix = safe_prefix[:-1]
        result = safe_prefix + marker
    return result


def _terminal_safe_scalar(value: Any) -> str:
    # No scalar representation is allowed to escape this terminal boundary.
    try:
        if value is None:
            return "null"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if type(value) is str:
            return _truncate_exact_text(value, _TERMINAL_MAX_SCALAR_BYTES)
        if type(value) is int:
            try:
                rendered = int.__repr__(value)
            except BaseException:
                try:
                    bits = int.bit_length(value)
                    rendered_bits = int.__repr__(bits)
                except BaseException:
                    rendered_bits = "unknown"
                return "<int-unrenderable bits=" + rendered_bits + ">"
            return _truncate_exact_text(rendered, _TERMINAL_MAX_SCALAR_BYTES)
        if type(value) is float:
            try:
                return _truncate_exact_text(float.__repr__(value), _TERMINAL_MAX_SCALAR_BYTES)
            except BaseException:
                return "<float-unrenderable>"
        if type(value) is bytes:
            try:
                return (
                    "<bytes len="
                    + int.__repr__(bytes.__len__(value))
                    + " sha256="
                    + hashlib.sha256(value).hexdigest()
                    + ">"
                )
            except BaseException:
                return "<bytes-unrenderable>"
        return "<" + _safe_type_name(value) + ">"
    except BaseException:
        try:
            return "<scalar-unavailable:" + _safe_type_name(value) + ">"
        except BaseException:
            return "<scalar-unavailable>"


def _exception_type_name(error: BaseException) -> str:
    return _safe_type_name(error)


def _safe_exception_text(error: BaseException) -> str:
    try:
        rendered = str(error)
    except BaseException as render_error:
        return (
            "<exception-detail-unavailable; error_type="
            + _exception_type_name(error)
            + "; render_failure="
            + _exception_type_name(render_error)
            + ">"
        )
    if type(rendered) is not str:
        return "<exception-detail-invalid; error_type=" + _exception_type_name(error) + ">"
    return _truncate_exact_text(rendered, _TERMINAL_MAX_SCALAR_BYTES)


def _safe_scalar_text(value: Any) -> str:
    return _terminal_safe_scalar(value)


def _safe_failure_payload(operation: str, error: BaseException) -> Mapping[str, str]:
    safe_operation = operation if type(operation) is str else _terminal_safe_scalar(operation)
    return {
        "operation": safe_operation,
        "exception_type": _exception_type_name(error),
        "detail": _safe_exception_text(error),
    }


def _terminal_identity_reserve(value: Any) -> dict[str, str]:
    """Extract critical scalar identity before recursive node budgets can discard it."""
    reserve: dict[str, str] = {}
    if type(value) is not dict:
        return reserve
    items = list(dict.items(value))

    def exact_get(container: Any, wanted: str) -> tuple[bool, Any]:
        if type(container) is not dict:
            return False, None
        for key, item in dict.items(container):
            if type(key) is str and key == wanted:
                return True, item
        return False, None

    def add(path: str, item: Any) -> None:
        # Containers are intentionally not traversed here.  One hostile/noisy field
        # can never consume the reservation budget for a sibling identity field.
        if type(item) in {dict, list, tuple}:
            return
        reserve[path] = _truncate_exact_text(_terminal_safe_scalar(item), 768)

    for field in (
        "critical_error_identity", "writer_id", "required_reconciliation_action",
        "exception_type", "code", "operation", "destination_replaced",
    ):
        found, item = exact_get(value, field)
        if found:
            add("$." + field, item)

    for container_key in (
        "original_operation_error", "outer_compensation_error",
        "unexpected_compensation_error", "terminal_recovery_builder_failure",
        "terminal_snapshot_failure", "terminal_attach_failure",
        "serialization_failure", "serialization_fallback_failure",
    ):
        found, container = exact_get(value, container_key)
        if not found or type(container) is not dict:
            continue
        for field in ("exception_type", "code", "operation"):
            nested_found, item = exact_get(container, field)
            if nested_found:
                add("$." + container_key + "." + field, item)

    found, destination = exact_get(value, "destination_state")
    if found and type(destination) is dict:
        nested_found, item = exact_get(destination, "replaced")
        if nested_found:
            add("$.destination_state.replaced", item)

    found, restoration = exact_get(value, "compensation_restoration")
    if found and type(restoration) is dict:
        for field in ("restore_destination_replaced", "required_reconciliation_action"):
            nested_found, item = exact_get(restoration, field)
            if nested_found:
                add("$.compensation_restoration." + field, item)
        nested_found, primary = exact_get(restoration, "restore_primary_failure")
        if nested_found and type(primary) is dict:
            for field in ("exception_type", "code", "operation"):
                leaf_found, item = exact_get(primary, field)
                if leaf_found:
                    add("$.compensation_restoration.restore_primary_failure." + field, item)
    return reserve


def _terminal_snapshot(value: Any, *, _depth: int = 0, _counter: list[int] | None = None) -> Any:
    """Normalize evidence to exact builtin primitives/containers only."""
    if _counter is None:
        _counter = [0]
    _counter[0] += 1
    if _counter[0] > _TERMINAL_MAX_NODES:
        return _TERMINAL_TRUNCATION_MARKER + ":max-nodes"
    if _depth > _TERMINAL_MAX_DEPTH:
        return _TERMINAL_TRUNCATION_MARKER + ":max-depth"
    if value is None or value is True or value is False:
        return value
    if type(value) is str:
        return _truncate_exact_text(value, _TERMINAL_MAX_SCALAR_BYTES)
    if type(value) is int or type(value) is float:
        return value
    if type(value) is bytes:
        return _terminal_safe_scalar(value)
    if type(value) is dict:
        result: dict[str, Any] = {}
        processed: set[str] = set()
        item_count = 0

        def add_item(key: Any, item: Any) -> bool:
            nonlocal item_count
            if item_count >= _TERMINAL_MAX_CONTAINER_ITEMS:
                result["__terminal_truncated__"] = True
                return False
            if type(key) is str:
                safe_key = _truncate_exact_text(key, _TERMINAL_MAX_KEY_BYTES)
            else:
                safe_key = "<key:" + _terminal_safe_scalar(key) + ">"
            if safe_key in result:
                suffix = 2
                candidate = safe_key + "#" + int.__repr__(suffix)
                while candidate in result:
                    suffix += 1
                    candidate = safe_key + "#" + int.__repr__(suffix)
                safe_key = candidate
            result[safe_key] = _terminal_snapshot(
                item, _depth=_depth + 1, _counter=_counter
            )
            item_count += 1
            if _counter[0] > _TERMINAL_MAX_NODES:
                result["__terminal_truncated__"] = True
                return False
            return True

        # Iterate exact dict storage once.  Membership lookup against a dict that
        # contains hostile custom keys can execute user-defined equality hooks;
        # priority ordering therefore compares only exact builtin str keys.
        items = list(dict.items(value))
        for priority_key in _TERMINAL_PRIORITY_KEYS:
            for key, item in items:
                if type(key) is str and key == priority_key:
                    processed.add(priority_key)
                    if not add_item(key, item):
                        return result
                    break
        for key, item in items:
            if type(key) is str and key in processed:
                continue
            if not add_item(key, item):
                break
        return result
    if type(value) is list:
        result_list: list[Any] = []
        length = list.__len__(value)
        limit = min(length, _TERMINAL_MAX_CONTAINER_ITEMS)
        for index in range(limit):
            result_list.append(
                _terminal_snapshot(
                    list.__getitem__(value, index),
                    _depth=_depth + 1,
                    _counter=_counter,
                )
            )
            if _counter[0] > _TERMINAL_MAX_NODES:
                result_list.append(_TERMINAL_TRUNCATION_MARKER + ":max-nodes")
                break
        if length > limit:
            result_list.append(_TERMINAL_TRUNCATION_MARKER + ":max-items")
        return result_list
    if type(value) is tuple:
        result_tuple: list[Any] = []
        length = tuple.__len__(value)
        limit = min(length, _TERMINAL_MAX_CONTAINER_ITEMS)
        for index in range(limit):
            result_tuple.append(
                _terminal_snapshot(
                    tuple.__getitem__(value, index),
                    _depth=_depth + 1,
                    _counter=_counter,
                )
            )
            if _counter[0] > _TERMINAL_MAX_NODES:
                result_tuple.append(_TERMINAL_TRUNCATION_MARKER + ":max-nodes")
                break
        if length > limit:
            result_tuple.append(_TERMINAL_TRUNCATION_MARKER + ":max-items")
        return result_tuple
    return "<opaque:" + _safe_type_name(value) + ">"

def _terminal_payload_dict(value: Any) -> dict[str, Any]:
    reserve = _terminal_identity_reserve(value)
    snapshot = _terminal_snapshot(value)
    if type(snapshot) is dict:
        result = snapshot
    else:
        result = {"terminal_payload": snapshot}
    if len(reserve) > 0:
        # This key sorts before ordinary JSON keys and is added after recursive
        # snapshotting, so node truncation and final prefix contraction cannot
        # starve critical identity.
        result[_TERMINAL_IDENTITY_RESERVE_KEY] = reserve
    return result


def _terminal_failure_tuple(value: Any) -> tuple[Mapping[str, str], ...]:
    if type(value) is not tuple and type(value) is not list:
        return ()
    length = tuple.__len__(value) if type(value) is tuple else list.__len__(value)
    result: list[Mapping[str, str]] = []
    for index in range(length):
        item = (
            tuple.__getitem__(value, index)
            if type(value) is tuple
            else list.__getitem__(value, index)
        )
        snap = _terminal_snapshot(item)
        if type(snap) is dict:
            operation = dict.get(snap, "operation")
            exception_type = dict.get(snap, "exception_type")
            detail = dict.get(snap, "detail")
            result.append(
                {
                    "operation": operation if type(operation) is str else "UNKNOWN",
                    "exception_type": exception_type if type(exception_type) is str else "UNKNOWN",
                    "detail": detail if type(detail) is str else "",
                }
            )
    return tuple(result)


def _emergency_exact_dict_get(value: Any, wanted: str) -> tuple[bool, Any]:
    """Lookup an exact builtin str key without hashing/equality on hostile keys."""
    if type(value) is not dict or type(wanted) is not str:
        return False, None
    try:
        items = list(dict.items(value))
    except BaseException:
        return False, None
    for key, item in items:
        if type(key) is not str:
            continue
        try:
            if str.__eq__(key, wanted) is True:
                return True, item
        except BaseException:
            continue
    return False, None


def _emergency_failure_tuple(value: Any) -> tuple[Mapping[str, str], ...]:
    """Builtin-only failure capture used after ordinary terminal machinery fails."""
    if type(value) not in {tuple, list}:
        return ()
    length = tuple.__len__(value) if type(value) is tuple else list.__len__(value)
    result: list[Mapping[str, str]] = []
    for index in range(length):
        item = (
            tuple.__getitem__(value, index)
            if type(value) is tuple
            else list.__getitem__(value, index)
        )
        if type(item) is not dict:
            continue
        _, operation = _emergency_exact_dict_get(item, "operation")
        _, exception_type = _emergency_exact_dict_get(item, "exception_type")
        _, detail = _emergency_exact_dict_get(item, "detail")
        result.append(
            {
                "operation": (
                    _emergency_exact_text(operation, _TERMINAL_MAX_SCALAR_BYTES)
                    if type(operation) is str
                    else "UNKNOWN"
                ),
                "exception_type": (
                    _emergency_exact_text(exception_type, _TERMINAL_MAX_SCALAR_BYTES)
                    if type(exception_type) is str
                    else "UNKNOWN"
                ),
                "detail": (
                    _emergency_exact_text(detail, _TERMINAL_MAX_SCALAR_BYTES)
                    if type(detail) is str
                    else ""
                ),
            }
        )
    return tuple(result)


def _emergency_terminal_detail_text(
    operation: Any,
    working: Any,
    failures: Any,
    *,
    header: str = "DL93_TERMINAL_EMERGENCY_DETAIL_V2",
) -> str:
    """Render identity first using only exact builtin containers and strings."""
    safe_operation = (
        _emergency_exact_text(operation, 768)
        if type(operation) is str
        else "TERMINAL_EMERGENCY"
    )
    lines = [header, "operation=" + safe_operation]
    if type(working) is dict:
        found, reserve = _emergency_exact_dict_get(working, _TERMINAL_IDENTITY_RESERVE_KEY)
        if found and type(reserve) is dict:
            for path, value in list(dict.items(reserve)):
                if type(path) is str and type(value) is str:
                    lines.append(
                        _emergency_exact_text(path, 768)
                        + "="
                        + _emergency_exact_text(value, 768)
                    )
        for key in ("critical_error_identity", "writer_id", "required_reconciliation_action"):
            found, value = _emergency_exact_dict_get(working, key)
            if found and type(value) is str:
                lines.append("$." + key + "=" + _emergency_exact_text(value, 768))
        for key in (
            "original_operation_error",
            "outer_compensation_error",
            "unexpected_compensation_error",
            "terminal_recovery_builder_failure",
            "terminal_snapshot_failure",
            "terminal_attach_failure",
        ):
            found, nested = _emergency_exact_dict_get(working, key)
            if not found or type(nested) is not dict:
                continue
            for field in ("exception_type", "code", "operation"):
                leaf_found, value = _emergency_exact_dict_get(nested, field)
                if leaf_found and type(value) is str:
                    lines.append(
                        "$." + key + "." + field + "="
                        + _emergency_exact_text(value, 768)
                    )
    exact_failures = _emergency_failure_tuple(failures)
    for index in range(min(tuple.__len__(exact_failures), 64)):
        failure = tuple.__getitem__(exact_failures, index)
        _, failure_operation = _emergency_exact_dict_get(failure, "operation")
        _, failure_type = _emergency_exact_dict_get(failure, "exception_type")
        lines.append(
            "failure[" + int.__repr__(index) + "]="
            + (failure_operation if type(failure_operation) is str else "UNKNOWN")
            + "/"
            + (failure_type if type(failure_type) is str else "UNKNOWN")
        )
    return _emergency_exact_text("\n".join(lines), TERMINAL_EVIDENCE_MAX_BYTES)


def _emergency_append_failure(
    working: dict[str, Any],
    failures: list[Mapping[str, str]],
    operation: str,
    error: BaseException,
) -> None:
    failure = {
        "operation": operation if type(operation) is str else "TERMINAL_EMERGENCY",
        "exception_type": _safe_type_name(error),
        "detail": _emergency_exact_text(_safe_exception_text(error), _TERMINAL_MAX_SCALAR_BYTES),
    }
    failures.append(failure)
    found, existing = _emergency_exact_dict_get(working, "serialization_failures")
    if found and type(existing) is list:
        list.append(existing, failure)
    else:
        working["serialization_failures"] = list(failures)
    found_first, _ = _emergency_exact_dict_get(working, "serialization_failure")
    if not found_first:
        working["serialization_failure"] = failures[0]


def _make_terminal_emergency_detail(
    text: Any,
    working: Any,
    failures: Any,
) -> _TerminalEvidenceEmergency:
    exact_text = _emergency_exact_text(text, TERMINAL_EVIDENCE_MAX_BYTES)
    exact_working = working if type(working) is dict else {
        "terminal_emergency_payload_unavailable": True
    }
    exact_failures = failures if type(failures) is tuple else ()
    # Call str.__new__ directly; a broken/monkeypatched fallback carrier constructor
    # is not re-entered here.
    value = str.__new__(_TerminalEvidenceEmergency, exact_text)
    value.evidence_payload = exact_working
    value.serialization_failures = exact_failures
    return value


def _build_evidence_detail(
    text: str,
    working: dict[str, Any],
    failures: list[Mapping[str, str]] | tuple[Mapping[str, str], ...],
) -> _EvidenceDetail | _TerminalEvidenceFallback | _TerminalEvidenceEmergency:
    """Construct evidence without ever re-entering a failed carrier constructor."""
    safe_text = _bounded_terminal_text(text if type(text) is str else "<terminal-detail-invalid>")
    safe_failures = _terminal_failure_tuple(failures)
    try:
        return _EvidenceDetail(safe_text, working, safe_failures)
    except BaseException as constructor_error:
        failure = _safe_failure_payload("EVIDENCE_DETAIL_CONSTRUCTION", constructor_error)
        merged = list(safe_failures)
        merged.append(failure)
        if "serialization_failure" not in working:
            working["serialization_failure"] = failure
        existing = dict.get(working, "serialization_failures")
        if type(existing) is list:
            existing.append(failure)
        else:
            working["serialization_failures"] = list(merged)
        try:
            fallback_text = _terminal_last_resort_text(
                "EVIDENCE_DETAIL_CONSTRUCTION", working, tuple(merged)
            )
        except BaseException:
            fallback_text = "DL93_TERMINAL_CARRIER_FALLBACK_V1"
        try:
            return _TerminalEvidenceFallback(fallback_text, working, tuple(merged))
        except BaseException as fallback_constructor_error:
            fallback_failure = {
                "operation": "TERMINAL_FALLBACK_CONSTRUCTION",
                "exception_type": _safe_type_name(fallback_constructor_error),
                "detail": "fallback carrier construction failed",
            }
            merged.append(fallback_failure)
            working["serialization_failures"] = list(merged)
            if "serialization_failure" not in working:
                working["serialization_failure"] = merged[0]
            emergency_text = _emergency_terminal_detail_text(
                "TERMINAL_FALLBACK_CONSTRUCTION", working, tuple(merged)
            )
            return _make_terminal_emergency_detail(
                emergency_text, working, tuple(merged)
            )


def _independent_reporting_detail(
    operation: str,
    payload: Mapping[str, Any],
    reporting_error: BaseException,
    *,
    prior_failures: tuple[Mapping[str, str], ...] = (),
) -> _TerminalEvidenceFallback:
    """Last reporting path that never calls the failed serializer again."""
    try:
        working = _terminal_payload_dict(payload)
    except BaseException as snapshot_error:
        working = {
            "terminal_reporting_payload_unavailable": True,
            "terminal_snapshot_failure": _safe_failure_payload(
                operation + "_SNAPSHOT", snapshot_error
            ),
        }
    failures = list(_terminal_failure_tuple(prior_failures))
    failure = _safe_failure_payload(operation, reporting_error)
    failures.append(failure)
    working["terminal_reporting_failure"] = failure
    working["serialization_failures"] = list(failures)
    if "serialization_failure" not in working:
        working["serialization_failure"] = failures[0]
    try:
        text = _terminal_last_resort_text(operation, working, tuple(failures))
    except BaseException:
        text = "DL93_TERMINAL_LAST_RESORT_V1\noperation=" + (
            operation if type(operation) is str else "TERMINAL_REPORTING"
        )
        text = _bounded_terminal_text(text)
    try:
        return _TerminalEvidenceFallback(text, working, tuple(failures))
    except BaseException as carrier_error:
        failures.append({
            "operation": "INDEPENDENT_REPORTING_CARRIER",
            "exception_type": _safe_type_name(carrier_error),
            "detail": "independent fallback carrier construction failed",
        })
        working["serialization_failures"] = list(failures)
        emergency_text = _emergency_terminal_detail_text(
            "INDEPENDENT_REPORTING_CARRIER", working, tuple(failures)
        )
        return _make_terminal_emergency_detail(
            emergency_text, working, tuple(failures)
        )


def _bounded_error_components(code: Any, detail: Any) -> tuple[str, str, str]:
    """Bound the complete typed exception message, not only its detail payload."""
    safe_code = (
        _truncate_exact_text(code, _TERMINAL_MAX_SCALAR_BYTES)
        if type(code) is str
        else _terminal_safe_scalar(code)
    )
    safe_detail = _terminal_safe_detail_text(detail)
    if safe_detail == "":
        return safe_code, "", _truncate_exact_text(safe_code, TERMINAL_EVIDENCE_MAX_BYTES)
    prefix = safe_code + ": "
    prefix_bytes = _encoded_utf8(prefix)
    if len(prefix_bytes) >= TERMINAL_EVIDENCE_MAX_BYTES:
        bounded_code = _truncate_exact_text(safe_code, TERMINAL_EVIDENCE_MAX_BYTES)
        return bounded_code, "", bounded_code
    detail_budget = TERMINAL_EVIDENCE_MAX_BYTES - len(prefix_bytes)
    bounded_detail = _truncate_exact_text(safe_detail, detail_budget)
    message = prefix + bounded_detail
    if len(_encoded_utf8(message)) > TERMINAL_EVIDENCE_MAX_BYTES:
        # Defensive contraction; exact builtin UTF-8 only.
        message = _bounded_terminal_text(message)
        if message.startswith(prefix):
            bounded_detail = message[len(prefix):]
        else:
            bounded_detail = ""
            safe_code = message
    return safe_code, bounded_detail, message


def _terminal_safe_detail_text(detail: Any) -> str:
    if type(detail) is str:
        return _truncate_exact_text(detail, TERMINAL_EVIDENCE_MAX_BYTES)
    if detail is None:
        return ""
    # One normalization-time dynamic hook is allowed, but it is fully contained.
    try:
        rendered = str(detail)
    except BaseException as render_error:
        return (
            "<detail-unavailable; detail_type="
            + _safe_type_name(detail)
            + "; render_failure="
            + _safe_type_name(render_error)
            + ">"
        )
    if type(rendered) is not str:
        return "<detail-invalid:" + _safe_type_name(detail) + ">"
    return _truncate_exact_text(rendered, TERMINAL_EVIDENCE_MAX_BYTES)


def _safe_object_attribute(value: Any, name: str) -> tuple[Any | None, Mapping[str, str] | None]:
    try:
        result = object.__getattribute__(value, name)
    except BaseException as error:
        return None, _safe_failure_payload("ATTRIBUTE_GET:" + name, error)
    return result, None


def _safe_error_attached_payload(
    error: BaseException | None,
) -> tuple[dict[str, Any] | None, tuple[Mapping[str, str], ...]]:
    if error is None:
        return None, ()
    raw, failure = _safe_object_attribute(error, "evidence_payload")
    failures = () if failure is None else (failure,)
    if raw is None:
        return None, failures
    snapshot = _terminal_snapshot(raw)
    if type(snapshot) is dict:
        return snapshot, failures
    return None, failures


def _safe_error_serialization_failures(
    error: BaseException | None,
) -> tuple[tuple[Mapping[str, str], ...], tuple[Mapping[str, str], ...]]:
    if error is None:
        return (), ()
    raw, failure = _safe_object_attribute(error, "serialization_failures")
    access_failures = () if failure is None else (failure,)
    return _terminal_failure_tuple(raw), access_failures


def _collect_error_serialization_failures(
    *errors: BaseException | None,
) -> tuple[tuple[Mapping[str, str], ...], tuple[Mapping[str, str], ...]]:
    failures: list[Mapping[str, str]] = []
    access_failures: list[Mapping[str, str]] = []
    for error in errors:
        current, access = _safe_error_serialization_failures(error)
        for item in current:
            if item not in failures:
                failures.append(item)
        for item in access:
            if item not in access_failures:
                access_failures.append(item)
    return tuple(failures), tuple(access_failures)


def _exception_evidence_payload(error: BaseException | None) -> Mapping[str, Any] | None:
    if error is None:
        return None
    raw_code, code_failure = _safe_object_attribute(error, "code")
    if type(raw_code) is str:
        code: Any = _truncate_exact_text(raw_code, _TERMINAL_MAX_SCALAR_BYTES)
    elif raw_code is None:
        code = None
    else:
        code = _terminal_safe_scalar(raw_code)
    payload: dict[str, Any] = {
        "exception_type": _exception_type_name(error),
        "code": code,
        "detail": _safe_exception_text(error),
    }
    if code_failure is not None:
        payload["attribute_access_failures"] = [code_failure]
    return payload


def _record_serialization_failure(
    working: dict[str, Any],
    failures: list[Mapping[str, str]],
    failure: Mapping[str, str],
    *,
    fallback: bool = False,
) -> None:
    safe_failure = _terminal_payload_dict(failure)
    normalized = {
        "operation": dict.get(safe_failure, "operation", "UNKNOWN"),
        "exception_type": dict.get(safe_failure, "exception_type", "UNKNOWN"),
        "detail": dict.get(safe_failure, "detail", ""),
    }
    failures.append(normalized)
    existing = dict.get(working, "serialization_failures")
    if type(existing) is list:
        list.append(existing, normalized)
    else:
        working["serialization_failures"] = [normalized]
    if "serialization_failure" not in working:
        working["serialization_failure"] = normalized
    if fallback and "serialization_fallback_failure" not in working:
        working["serialization_fallback_failure"] = normalized


def _terminal_identity_lines(snapshot: dict[str, Any]) -> list[str]:
    """Render critical identity first so truncation can never starve it."""
    lines: list[str] = []
    reserved = dict.get(snapshot, _TERMINAL_IDENTITY_RESERVE_KEY)
    if type(reserved) is dict:
        for path, value in sorted(dict.items(reserved)):
            if type(path) is str and type(value) is str:
                lines.append(path + "=" + _truncate_exact_text(value, 768))

    def add(path: str, value: Any) -> None:
        rendered = _truncate_exact_text(_terminal_safe_scalar(value), 768)
        lines.append(path + "=" + rendered)

    for key in ("critical_error_identity", "writer_id", "required_reconciliation_action"):
        value = dict.get(snapshot, key)
        if value is not None and type(value) not in {dict, list}:
            add("$." + key, value)
    for key in (
        "original_operation_error",
        "outer_compensation_error",
        "unexpected_compensation_error",
        "terminal_recovery_builder_failure",
        "terminal_snapshot_failure",
        "terminal_attach_failure",
    ):
        evidence = dict.get(snapshot, key)
        if type(evidence) is not dict:
            continue
        for field in ("exception_type", "code", "operation"):
            value = dict.get(evidence, field)
            if value is not None and type(value) not in {dict, list}:
                add("$." + key + "." + field, value)
    destination = dict.get(snapshot, "destination_state")
    if type(destination) is dict:
        replaced = dict.get(destination, "replaced")
        if replaced is not None:
            add("$.destination_state.replaced", replaced)
    return lines[:32]


def _critical_terminal_lines(snapshot: dict[str, Any]) -> list[str]:
    priority = {
        "exception_type",
        "code",
        "operation",
        "writer_id",
        "required_reconciliation_action",
        "destination_replaced",
        "restore_destination_replaced",
        "serialization_failure",
        "serialization_fallback_failure",
        "critical_error_identity",
    }
    lines: list[str] = []

    def walk(node: Any, path: str, depth: int) -> None:
        if depth > _TERMINAL_MAX_DEPTH or len(lines) >= 128:
            return
        if type(node) is dict:
            for key in sorted(dict.keys(node)):
                item = dict.__getitem__(node, key)
                child = path + "." + key
                if key in priority and type(item) not in {dict, list}:
                    lines.append(
                        child
                        + "="
                        + _truncate_exact_text(_terminal_safe_scalar(item), 768)
                    )
                walk(item, child, depth + 1)
        elif type(node) is list:
            for index in range(min(list.__len__(node), 32)):
                walk(
                    list.__getitem__(node, index),
                    path + "[" + int.__repr__(index) + "]",
                    depth + 1,
                )

    walk(snapshot, "$", 0)
    return lines


def _bounded_terminal_text(text: str) -> str:
    safe = _normalize_exact_string(text)
    encoded = _encoded_utf8(safe)
    if len(encoded) <= TERMINAL_EVIDENCE_MAX_BYTES:
        return safe
    marker = "\n$.__truncated__=true"
    marker_bytes = _encoded_utf8(marker)
    prefix_budget = TERMINAL_EVIDENCE_MAX_BYTES - len(marker_bytes)
    prefix = bytes.decode(encoded[:prefix_budget], "utf-8", "ignore")
    result = prefix + marker
    while len(_encoded_utf8(result)) > TERMINAL_EVIDENCE_MAX_BYTES and prefix != "":
        prefix = prefix[:-1]
        result = prefix + marker
    return result


def _terminal_fallback_text(
    snapshot: dict[str, Any], failures: tuple[Mapping[str, str], ...]
) -> str:
    """Independent non-JSON renderer with identity-reserved prefix."""
    lines = ["DL93_TERMINAL_EVIDENCE_V1"]
    identity_lines = _terminal_identity_lines(snapshot)
    lines.extend(identity_lines)
    seen = set(identity_lines)
    for line in _critical_terminal_lines(snapshot):
        if line not in seen:
            lines.append(line)
            seen.add(line)
    budget = _TERMINAL_MAX_NODES

    def walk(node: Any, path: str, depth: int) -> None:
        nonlocal budget
        if budget <= 0:
            return
        if depth > _TERMINAL_MAX_DEPTH:
            lines.append(path + "=" + _TERMINAL_TRUNCATION_MARKER + ":max-depth")
            budget -= 1
            return
        if type(node) is dict:
            for key in sorted(dict.keys(node)):
                if budget <= 0:
                    break
                walk(dict.__getitem__(node, key), path + "." + key, depth + 1)
            return
        if type(node) is list:
            for index in range(list.__len__(node)):
                if budget <= 0:
                    break
                walk(
                    list.__getitem__(node, index),
                    path + "[" + int.__repr__(index) + "]",
                    depth + 1,
                )
            return
        lines.append(path + "=" + _terminal_safe_scalar(node))
        budget -= 1

    walk(snapshot, "$", 0)
    if budget <= 0:
        lines.append("$.__truncated_nodes__=true")
    return _bounded_terminal_text("\n".join(lines))


def _terminal_last_resort_text(
    operation: str,
    snapshot: dict[str, Any],
    failures: tuple[Mapping[str, str], ...],
) -> str:
    """Acyclic final renderer; never calls canonical or fallback renderers."""
    lines = [
        "DL93_TERMINAL_LAST_RESORT_V1",
        "operation=" + _truncate_exact_text(_terminal_safe_scalar(operation), 768),
    ]
    try:
        lines.extend(_terminal_identity_lines(snapshot))
        lines.extend(_critical_terminal_lines(snapshot)[:64])
    except BaseException:
        lines.append("critical_snapshot=<unavailable>")
    for index in range(min(len(failures), 32)):
        failure = failures[index]
        op = dict.get(failure, "operation", "UNKNOWN") if type(failure) is dict else "UNKNOWN"
        et = (
            dict.get(failure, "exception_type", "UNKNOWN")
            if type(failure) is dict
            else "UNKNOWN"
        )
        lines.append(
            "failure["
            + int.__repr__(index)
            + "].operation="
            + _truncate_exact_text(_terminal_safe_scalar(op), 768)
        )
        lines.append(
            "failure["
            + int.__repr__(index)
            + "].exception_type="
            + _truncate_exact_text(_terminal_safe_scalar(et), 768)
        )
    return _bounded_terminal_text("\n".join(lines))


def _serialize_evidence_payload(
    payload: Mapping[str, Any],
    *,
    operation: str,
    force_failsafe: bool = False,
    prior_failures: tuple[Mapping[str, str], ...] = (),
) -> _EvidenceDetail:
    working = _terminal_payload_dict(payload)
    failures = list(_terminal_failure_tuple(prior_failures))
    existing = dict.get(working, "serialization_failures")
    for prior in _terminal_failure_tuple(existing if type(existing) is list else ()):
        if prior not in failures:
            failures.append(prior)
    existing_first = dict.get(working, "serialization_failure")
    if type(existing_first) is dict:
        prior_first = _terminal_failure_tuple([existing_first])
        if len(prior_first) == 1 and prior_first[0] not in failures:
            failures.append(prior_first[0])
    if len(failures) > 0:
        working["serialization_failures"] = list(failures)
        # Preserve the earliest serialization failure as the stable compatibility
        # alias; later failures are append-only in serialization_failures.
        if "serialization_failure" not in working:
            working["serialization_failure"] = failures[0]

    safe_operation = operation if type(operation) is str else _terminal_safe_scalar(operation)
    if force_failsafe is False:
        try:
            text = _canonical_json(working)
            if type(text) is not str:
                raise TypeError("canonical serializer returned non-builtin str")
            encoded = _encoded_utf8(text)
            if len(encoded) <= TERMINAL_EVIDENCE_MAX_BYTES:
                return _build_evidence_detail(text, working, failures)
            working["terminal_truncation"] = {
                "reason": "FINAL_ENCODED_BYTE_BUDGET",
                "canonical_encoded_bytes": len(encoded),
                "max_bytes": TERMINAL_EVIDENCE_MAX_BYTES,
            }
        except BaseException as canonical_error:
            _record_serialization_failure(
                working,
                failures,
                _safe_failure_payload(safe_operation, canonical_error),
            )

    try:
        text = _terminal_fallback_text(working, tuple(failures))
        if type(text) is not str:
            raise TypeError("terminal fallback returned non-builtin str")
        bounded = _bounded_terminal_text(text)
        if len(_encoded_utf8(bounded)) > TERMINAL_EVIDENCE_MAX_BYTES:
            raise RuntimeError("terminal fallback byte bound violated")
        return _build_evidence_detail(bounded, working, failures)
    except BaseException as fallback_error:
        _record_serialization_failure(
            working,
            failures,
            _safe_failure_payload(safe_operation + "_TERMINAL_FALLBACK", fallback_error),
            fallback=True,
        )
        try:
            text = _terminal_last_resort_text(safe_operation, working, tuple(failures))
        except BaseException as last_resort_error:
            _emergency_append_failure(
                working,
                failures,
                safe_operation + "_TERMINAL_LAST_RESORT",
                last_resort_error,
            )
            emergency_text = _emergency_terminal_detail_text(
                safe_operation, working, tuple(failures)
            )
            return _make_terminal_emergency_detail(
                emergency_text, working, tuple(failures)
            )
        return _build_evidence_detail(text, working, failures)


def _failsafe_evidence_text(value: Mapping[str, Any]) -> str:
    """Compatibility alias for callers/tests; now consumes a primitive snapshot."""
    snapshot = _terminal_payload_dict(value)
    return _terminal_fallback_text(snapshot, ())

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _validate_operation_id(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ProductionSchema10OperationalError("SCHEMA10_OPERATION_ID_INVALID")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:/" for ch in value):
        raise ProductionSchema10OperationalError("SCHEMA10_OPERATION_ID_INVALID")


def _expected_profile(version: int) -> str:
    if version == SCHEMA9:
        return SCHEMA9_PROFILE
    if version == SCHEMA10:
        return SCHEMA10_PROFILE
    raise ProductionSchema10OperationalError("SCHEMA10_UNSUPPORTED_SCHEMA", str(version))


def _read_schema_version(path: Path) -> int:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as error:
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_UNREADABLE") from error
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute("SELECT max(version) FROM schema_migration").fetchone()
        return int(row[0] or 0)
    except sqlite3.Error as error:
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_UNREADABLE") from error
    finally:
        connection.close()


def _inspect_schema(path: Path, version: int) -> _SchemaState:
    expected_profile = _expected_profile(version)
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as error:
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_UNREADABLE") from error
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = tuple(
            (int(v), str(n), str(c))
            for v, n, c in connection.execute(
                "SELECT version,name,checksum FROM schema_migration ORDER BY version"
            )
        )
        if tuple(item[0] for item in rows) != tuple(range(1, version + 1)):
            raise ProductionSchema10OperationalError(
                "SCHEMA10_MIGRATION_HISTORY_INVALID", repr(tuple(item[0] for item in rows))
            )
        observed_version = rows[-1][0] if rows else 0
        if observed_version != version:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_SCHEMA_VERSION_MISMATCH", f"{observed_version}!={version}"
            )
        try:
            validate_schema(connection, target_version=version)
            profile = schema_profile_identity(connection, version)
        except StoreError as error:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_SCHEMA_PROFILE_INVALID", error.code
            ) from error
        integrity_rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        fk_rows = list(connection.execute("PRAGMA foreign_key_check"))
        if integrity_rows != ["ok"]:
            raise ProductionSchema10OperationalError("SCHEMA10_DCS_INTEGRITY_FAILED")
        if fk_rows:
            raise ProductionSchema10OperationalError("SCHEMA10_DCS_FOREIGN_KEY_FAILED")
        if profile != expected_profile:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_SCHEMA_PROFILE_INVALID", profile
            )
        return _SchemaState(version, profile, rows, "ok", 0)
    finally:
        connection.close()


def _w08_row(path: Path) -> Mapping[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM global_production_writer_lease WHERE resource_key='GLOBAL_PRODUCTION'"
        ).fetchone()
        if row is None:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_STATE_UNREADABLE")
        return dict(row)
    finally:
        connection.close()


def _require_w08_free(path: Path) -> Mapping[str, Any]:
    row = _w08_row(path)
    occupied = any(
        row.get(name) not in (None, "")
        for name in (
            "owner_id", "owner_execution_id", "change_id", "slice_id", "writer_class",
            "owner_session_role", "track", "repository_or_runtime", "operation_class", "target",
        )
    )
    if row.get("state") != "FREE" or occupied:
        raise ProductionSchema10OperationalError("SCHEMA10_W08_NOT_FREE")
    return row


def _fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> _DirectoryDurabilityOutcome:
    """Sync one directory while preserving open/fsync/close as distinct facts."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except BaseException as open_error:
        outcome = _DirectoryDurabilityOutcome(
            open_status="FAIL",
            fsync_status="NOT_ATTEMPTED",
            close_status="NOT_ATTEMPTED",
            open_failure=_atomic_failure_evidence("DIRECTORY_OPEN", open_error),
        )
        raise _DirectoryDurabilityFailure(outcome, primary_cause=open_error) from open_error

    fsync_error: BaseException | None = None
    close_error: BaseException | None = None
    try:
        os.fsync(fd)
    except BaseException as error:
        fsync_error = error
    try:
        os.close(fd)
    except BaseException as error:
        close_error = error

    outcome = _DirectoryDurabilityOutcome(
        open_status="SUCCESS",
        fsync_status="FAIL" if fsync_error is not None else "SUCCESS",
        close_status="FAIL" if close_error is not None else "SUCCESS",
        fsync_failure=(
            _atomic_failure_evidence("DIRECTORY_FSYNC", fsync_error)
            if fsync_error is not None
            else None
        ),
        close_failure=(
            _atomic_failure_evidence("DIRECTORY_CLOSE", close_error)
            if close_error is not None
            else None
        ),
    )
    if fsync_error is not None or close_error is not None:
        typed = _DirectoryDurabilityFailure(
            outcome,
            primary_cause=fsync_error,
            close_cause=close_error,
        )
        raise typed from _first_non_none(fsync_error, close_error)
    return outcome


def _create_schema9_to10_immutable_backup(
    path: Path,
    evidence_root: Path,
    operation_id: str,
    *,
    now: datetime | None = None,
) -> Schema10BackupEvidence:
    _validate_operation_id(operation_id)
    source_path = path.expanduser()
    try:
        source_lstat = source_path.lstat()
    except OSError as error:
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_PATH_INVALID") from error
    if stat.S_ISLNK(source_lstat.st_mode) or not stat.S_ISREG(source_lstat.st_mode):
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_PATH_INVALID")
    resolved = source_path.resolve(strict=True)
    state = _inspect_schema(resolved, SCHEMA9)
    _require_w08_free(resolved)
    before = resolved.stat()
    source_sha_before, source_size_before = _sha256_file(resolved)
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="microseconds")
    seed = {
        "format": "TK43_DL85_SCHEMA9_TO10_BACKUP_V1",
        "operation_id": operation_id,
        "source": str(resolved),
        "device": before.st_dev,
        "inode": before.st_ino,
        "source_sha256": source_sha_before,
        "schema_profile": state.profile,
        "created_at": stamp,
    }
    identity_seed = _sha256_bytes(_canonical_json(seed).encode("utf-8"))
    evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = evidence_root / f"schema9-to10-{identity_seed}"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_CREATE_NEW_COLLISION") from error
    backup_path = directory / "canonical-schema9.sqlite3.bak"
    manifest_path = directory / "manifest.json"
    fd = os.open(backup_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    source = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True, timeout=5.0)
    destination = sqlite3.connect(backup_path)
    try:
        source.execute("PRAGMA query_only=ON")
        validate_schema(source, target_version=SCHEMA9)
        source.backup(destination)
        destination.commit()
    finally:
        destination.close()
        source.close()
    os.chmod(backup_path, stat.S_IRUSR)
    _fsync_file(backup_path)
    backup_state = _inspect_schema(backup_path, SCHEMA9)
    backup_sha, backup_size = _sha256_file(backup_path)
    after = resolved.stat()
    source_sha_after, source_size_after = _sha256_file(resolved)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or (source_sha_before, source_size_before) != (source_sha_after, source_size_after)
    ):
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_SOURCE_CHANGED")
    _require_w08_free(resolved)
    payload = {
        **seed,
        "source_size": source_size_after,
        "backup_path": str(backup_path),
        "backup_sha256": backup_sha,
        "backup_size": backup_size,
        "source_schema": SCHEMA9,
        "target_schema": SCHEMA10,
        "migration10_name": MIGRATION10_NAME,
        "migration10_checksum": MIGRATION10_CHECKSUM,
        "migration_history": [list(row) for row in state.history],
        "source_integrity": state.integrity,
        "source_foreign_key_violations": state.foreign_key_violations,
        "backup_schema_profile": backup_state.profile,
        "backup_integrity": backup_state.integrity,
        "backup_foreign_key_violations": backup_state.foreign_key_violations,
        "create_new_only": True,
        "overwrite": False,
        "prune": False,
        "retention_delete": False,
    }
    backup_identity = _sha256_bytes(_canonical_json(payload).encode("utf-8"))
    document = {**payload, "backup_identity": backup_identity}
    encoded = (_canonical_json(document) + "\n").encode("utf-8")
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(manifest_path, stat.S_IRUSR)
    _fsync_file(manifest_path)
    os.chmod(directory, stat.S_IRUSR | stat.S_IXUSR)
    _fsync_directory(directory)
    _fsync_directory(evidence_root)
    evidence = Schema10BackupEvidence(
        operation_id=operation_id,
        source_path=str(resolved),
        source_device=before.st_dev,
        source_inode=before.st_ino,
        source_sha256=source_sha_after,
        source_size=source_size_after,
        backup_path=str(backup_path),
        backup_sha256=backup_sha,
        backup_size=backup_size,
        manifest_path=str(manifest_path),
        backup_identity=backup_identity,
        schema_profile=state.profile,
    )
    verify_schema9_to10_immutable_backup(evidence)
    return evidence


def verify_schema9_to10_immutable_backup(evidence: Schema10BackupEvidence) -> None:
    if type(evidence) is not Schema10BackupEvidence:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_EVIDENCE_INVALID")
    backup = Path(evidence.backup_path)
    manifest = Path(evidence.manifest_path)
    try:
        backup_lstat = backup.lstat()
        manifest_lstat = manifest.lstat()
    except OSError as error:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_MANIFEST_INVALID") from error
    if (
        stat.S_ISLNK(backup_lstat.st_mode)
        or stat.S_ISLNK(manifest_lstat.st_mode)
        or not stat.S_ISREG(backup_lstat.st_mode)
        or not stat.S_ISREG(manifest_lstat.st_mode)
    ):
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_MANIFEST_INVALID")
    try:
        raw = manifest.read_text(encoding="utf-8")
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_MANIFEST_INVALID") from error
    if not isinstance(document, dict) or raw != _canonical_json(document) + "\n":
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_MANIFEST_INVALID")
    identity = document.get("backup_identity")
    payload = {k: v for k, v in document.items() if k != "backup_identity"}
    if identity != evidence.backup_identity or identity != _sha256_bytes(_canonical_json(payload).encode("utf-8")):
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_IDENTITY_MISMATCH")
    expected_binding = {
        "operation_id": evidence.operation_id,
        "source": evidence.source_path,
        "device": evidence.source_device,
        "inode": evidence.source_inode,
        "source_sha256": evidence.source_sha256,
        "source_size": evidence.source_size,
        "backup_path": evidence.backup_path,
        "backup_sha256": evidence.backup_sha256,
        "backup_size": evidence.backup_size,
        "schema_profile": evidence.schema_profile,
        "source_schema": SCHEMA9,
        "target_schema": SCHEMA10,
        "migration10_name": MIGRATION10_NAME,
        "migration10_checksum": MIGRATION10_CHECKSUM,
        "create_new_only": True,
        "overwrite": False,
        "prune": False,
        "retention_delete": False,
    }
    if any(document.get(key) != value for key, value in expected_binding.items()):
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_EVIDENCE_BINDING_MISMATCH")
    sha, size = _sha256_file(backup)
    if sha != evidence.backup_sha256 or size != evidence.backup_size:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_BYTES_CHANGED")
    state = _inspect_schema(backup, SCHEMA9)
    if state.profile != evidence.schema_profile:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_PROFILE_MISMATCH")
    if backup.stat().st_mode & 0o222 or manifest.stat().st_mode & 0o222:
        raise ProductionSchema10OperationalError("SCHEMA10_BACKUP_NOT_IMMUTABLE")


def create_schema9_to10_immutable_backup(operation_id: str) -> Schema10BackupEvidence:
    """Create exactly one canonical schema-9 recovery backup; never prune or overwrite."""
    return _create_schema9_to10_immutable_backup(
        CANONICAL_DCS_PATH, CANONICAL_BACKUP_ROOT, operation_id
    )


def _expected_lease_context(operation_id: str, owner_id: str, attempt_id: str) -> Mapping[str, Any]:
    return {
        "state": "HELD",
        "owner_id": owner_id,
        "owner_execution_id": attempt_id,
        "change_id": CHANGE_ID,
        "slice_id": operation_id,
        "writer_class": "W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
        "owner_session_role": "TK43_DL85_SCHEMA10_ADOPTION",
        "track": "CLEANER_POSTGRES_AUTHORITY_CUTOVER",
        "repository_or_runtime": "ADCP_CONTROL_DCS",
        "operation_class": "DCS_SCHEMA_V9_TO_V10_MIGRATION",
        "target": "GLOBAL_PRODUCTION",
    }


class Schema10HeldW08:
    """One exact W08 lease; no context-manager auto-release exists by design."""

    def __init__(
        self,
        *,
        _seal: object,
        path: Path,
        operation_id: str,
        backup: Schema10BackupEvidence,
        store: ControlStore,
        owner_id: str,
        owner_execution_id: str,
        fencing_token: int,
        acquire_event_seq: int,
        release_operation_key: str,
    ) -> None:
        if _seal is not _W08_CONSTRUCTOR_SEAL:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_DIRECT_CONSTRUCTION_FORBIDDEN")
        self._path = path
        self.operation_id = operation_id
        self.backup = backup
        self._store = store
        self.owner_id = owner_id
        self.owner_execution_id = owner_execution_id
        self.fencing_token = fencing_token
        self.acquire_event_seq = acquire_event_seq
        self._release_operation_key = release_operation_key
        self._schema_version = SCHEMA9
        self._rebound = False
        self._released = False
        self._closed = False
        self._writer_restore_proof: tuple[int, str] | None = None

    @property
    def schema_version(self) -> int:
        return self._schema_version

    def _assert_identity(self) -> Mapping[str, Any]:
        if self._released or self._closed:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_NOT_ACTIVE")
        try:
            row = dict(
                self._store.assert_current_global_writer(self.owner_id, self.fencing_token)
            )
        except StoreError as error:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_AUTHORITY_LOST", error.code) from error
        expected = _expected_lease_context(
            self.operation_id, self.owner_id, self.owner_execution_id
        )
        if any(row.get(k) != v for k, v in expected.items()):
            raise ProductionSchema10OperationalError("SCHEMA10_W08_IDENTITY_MISMATCH")
        if int(row.get("fencing_token", -1)) != self.fencing_token:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_FENCE_CHANGED")
        return row

    def assert_event_guard(self) -> None:
        rows = self._store.global_production_writer_events()
        conflicts = [row for row in rows if int(row["event_seq"]) > self.acquire_event_seq]
        if conflicts:
            first = conflicts[0]
            raise ProductionSchema10OperationalError(
                "SCHEMA10_W08_EVENT_CONFLICT", f"{first['event_type']}:{first['event_seq']}"
            )

    def assert_current(self) -> int:
        self._assert_identity()
        self.assert_event_guard()
        return self.fencing_token

    def heartbeat(self) -> Schema10W08RebindEvidence:
        self.assert_current()
        try:
            row = dict(
                self._store.heartbeat_global_production_writer(
                    self.owner_id, self.fencing_token, W08_TTL_SECONDS
                )
            )
        except StoreError as error:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_HEARTBEAT_FAILED", error.code) from error
        if row.get("owner_execution_id") != self.owner_execution_id or int(row.get("fencing_token", -1)) != self.fencing_token:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_HEARTBEAT_IDENTITY_CHANGED")
        self.assert_event_guard()
        state = _inspect_schema(self._path, self._schema_version)
        return Schema10W08RebindEvidence(
            self.operation_id, self.owner_id, self.owner_execution_id, self.fencing_token,
            self._schema_version, state.profile, True, self.acquire_event_seq,
        )

    def _apply_exact_migration10(self, *, _seal: object) -> _SchemaState:
        """Execute migration 10 only after the sealed writer-preparation gate."""
        if _seal is not _MIGRATION_EXECUTION_SEAL:
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PREPARATION_REQUIRED")
        if self._schema_version != SCHEMA9 or self._rebound:
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PHASE_INVALID")
        if (
            migrations.MIGRATION_10_NAME != MIGRATION10_NAME
            or migrations.MIGRATION_10_CHECKSUM != MIGRATION10_CHECKSUM
            or migrations.REGISTERED_SCHEMA_VERSION != SCHEMA10
        ):
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_BINDING_DRIFT")
        self.assert_current()
        _inspect_schema(self._path, SCHEMA9)
        before_lease = self._assert_identity()
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            migrations.migrate(connection, backup_root=None, target_version=SCHEMA10)
        except BaseException as error:
            connection.close()
            try:
                observed = _inspect_schema(self._path, SCHEMA9)
            except BaseException:
                try:
                    observed10 = _inspect_schema(self._path, SCHEMA10)
                except BaseException as reconcile_error:
                    self.close_without_release()
                    raise ProductionSchema10OperationalError(
                        "SCHEMA10_MIGRATION_EFFECT_AMBIGUOUS_RECONCILIATION_REQUIRED"
                    ) from reconcile_error
                self._schema_version = SCHEMA10
                self._store.close()
                self._closed = True
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_MIGRATION_COMMITTED_DESPITE_ERROR_REBIND_REQUIRED",
                    observed10.profile,
                ) from error
            raise ProductionSchema10OperationalError(
                "SCHEMA10_MIGRATION_ROLLED_BACK", observed.profile
            ) from error
        finally:
            try:
                connection.close()
            except BaseException:
                pass
        state = _inspect_schema(self._path, SCHEMA10)
        # Never use the stale schema-9 handle for a post-generation assertion.
        self._store.close()
        self._closed = True
        self._schema_version = SCHEMA10
        # Durable identity must still be present byte-for-byte in the DCS.
        after_lease = _w08_row(self._path)
        for key, value in _expected_lease_context(
            self.operation_id, self.owner_id, self.owner_execution_id
        ).items():
            if after_lease.get(key) != value:
                raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_CHANGED_W08_IDENTITY", key)
        if int(after_lease.get("fencing_token", -1)) != self.fencing_token:
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_CHANGED_W08_FENCE")
        for key in ("owner_id", "owner_execution_id", "change_id", "slice_id", "writer_class", "operation_class", "fencing_token"):
            if after_lease.get(key) != before_lease.get(key):
                raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_CHANGED_W08_IDENTITY", key)
        return state

    def rebind_schema10(self) -> Schema10W08RebindEvidence:
        if self._schema_version != SCHEMA10:
            raise ProductionSchema10OperationalError("SCHEMA10_REBIND_REQUIRES_SCHEMA10")
        _inspect_schema(self._path, SCHEMA10)
        if not self._closed:
            self._store.close()
        try:
            self._store = ControlStore(
                self._path,
                migrate_schema=False,
                require_schema_version=SCHEMA10,
                global_writer_guard_required=False,
            )
        except BaseException as error:
            self._closed = True
            raise ProductionSchema10OperationalError("SCHEMA10_W08_REBIND_FAILED", type(error).__name__) from error
        self._closed = False
        self._assert_identity()
        self.assert_event_guard()
        self._rebound = True
        return self.heartbeat()

    def _mark_writer_restore_proven(self, evidence: Schema10WriterRestoreEvidence) -> None:
        if type(evidence) is not Schema10WriterRestoreEvidence:
            raise ProductionSchema10OperationalError("SCHEMA10_RELEASE_RESTORE_EVIDENCE_REQUIRED")
        if evidence.operation_id != self.operation_id or evidence.schema_version not in {SCHEMA9, SCHEMA10}:
            raise ProductionSchema10OperationalError("SCHEMA10_RELEASE_RESTORE_EVIDENCE_MISMATCH")
        if (
            evidence.owner_id != self.owner_id
            or evidence.owner_execution_id != self.owner_execution_id
            or evidence.fencing_token != self.fencing_token
            or not evidence.all_clients_support_schema
        ):
            raise ProductionSchema10OperationalError("SCHEMA10_RELEASE_RESTORE_FENCE_MISMATCH")
        self._writer_restore_proof = (evidence.schema_version, evidence.stable_inventory_fingerprint)

    def _release(self, expected_schema: int) -> Mapping[str, Any]:
        if self._writer_restore_proof is None or self._writer_restore_proof[0] != expected_schema:
            raise ProductionSchema10OperationalError("SCHEMA10_RELEASE_RESTORE_PROOF_MISSING")
        if expected_schema == SCHEMA10 and not self._rebound:
            raise ProductionSchema10OperationalError("SCHEMA10_RELEASE_BEFORE_REBIND_FORBIDDEN")
        _inspect_schema(self._path, expected_schema)
        self.assert_current()
        try:
            row = dict(
                self._store.release_global_production_writer(
                    operation_key=self._release_operation_key,
                    owner_id=self.owner_id,
                    fencing_token=self.fencing_token,
                    reason="TK43_DL85_SCHEMA10_ADOPTION_RELEASED",
                    control_decision_ref=DL85_CONTROL_DECISION_REF,
                )
            )
        except StoreError as error:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_RELEASE_FAILED", error.code) from error
        events = self._store.global_production_writer_events()
        post = [event for event in events if int(event["event_seq"]) > self.acquire_event_seq]
        if len(post) != 1 or post[0]["event_type"] != "RELEASE":
            raise ProductionSchema10OperationalError("SCHEMA10_W08_RELEASE_EVENT_INVALID")
        if row.get("state") != "FREE" or int(row.get("fencing_token", -1)) != self.fencing_token:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_RELEASE_READBACK_INVALID")
        self._released = True
        self._store.close()
        self._closed = True
        free = _require_w08_free(self._path)
        if int(free.get("fencing_token", -1)) != self.fencing_token:
            raise ProductionSchema10OperationalError("SCHEMA10_W08_FREE_FENCE_MISMATCH")
        return {"state": "FREE", "fencing_token": self.fencing_token, "release_event_seq": int(post[0]["event_seq"])}

    def release_after_schema10_writer_restore(self) -> Mapping[str, Any]:
        return self._release(SCHEMA10)

    def release_pre_migration_after_schema9_restore(self) -> Mapping[str, Any]:
        return self._release(SCHEMA9)

    def close_without_release(self) -> None:
        if not self._closed:
            self._store.close()
            self._closed = True
        # Deliberately never release here.  Durable W08 remains HELD.


def _acquire_schema9_w08(
    path: Path,
    operation_id: str,
    backup: Schema10BackupEvidence,
) -> Schema10HeldW08:
    _validate_operation_id(operation_id)
    if type(backup) is not Schema10BackupEvidence or backup.operation_id != operation_id:
        raise ProductionSchema10OperationalError("SCHEMA10_W08_BACKUP_BINDING_REQUIRED")
    source_path = path.expanduser()
    try:
        source_lstat = source_path.lstat()
    except OSError as error:
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_PATH_INVALID") from error
    if stat.S_ISLNK(source_lstat.st_mode) or not stat.S_ISREG(source_lstat.st_mode):
        raise ProductionSchema10OperationalError("SCHEMA10_DCS_PATH_INVALID")
    resolved = source_path.resolve(strict=True)
    if backup.source_path != str(resolved):
        raise ProductionSchema10OperationalError("SCHEMA10_W08_BACKUP_SOURCE_MISMATCH")
    verify_schema9_to10_immutable_backup(backup)
    # A second acquire attempt against an already-held lease is a lease
    # substitution attempt first; report that boundary before the expected
    # byte drift caused by the first ACQUIRE event itself.
    _require_w08_free(resolved)
    current_stat = resolved.stat()
    current_sha, current_size = _sha256_file(resolved)
    if (
        current_stat.st_dev != backup.source_device
        or current_stat.st_ino != backup.source_inode
        or current_sha != backup.source_sha256
        or current_size != backup.source_size
    ):
        raise ProductionSchema10OperationalError("SCHEMA10_W08_BACKUP_SOURCE_IDENTITY_STALE")
    state = _inspect_schema(resolved, SCHEMA9)
    if state.profile != backup.schema_profile:
        raise ProductionSchema10OperationalError("SCHEMA10_W08_BACKUP_SOURCE_PROFILE_STALE")
    _require_w08_free(resolved)
    attempt = uuid4().hex
    owner_id = f"TK43_DL85_SCHEMA10:{attempt}"
    semantic = {
        "change_id": CHANGE_ID,
        "operation_id": operation_id,
        "attempt_id": attempt,
        "backup_identity": backup.backup_identity,
        "from_schema": SCHEMA9,
        "to_schema": SCHEMA10,
    }
    acquire_key = operation_key("tk43-dl85-schema10-w08-acquire", semantic)
    release_key = operation_key("tk43-dl85-schema10-w08-release", semantic)
    store = ControlStore(
        resolved,
        migrate_schema=False,
        require_schema_version=SCHEMA9,
        global_writer_guard_required=False,
    )
    try:
        row = dict(
            store.acquire_global_production_writer(
                operation_key=acquire_key,
                owner_id=owner_id,
                owner_execution_id=attempt,
                change_id=CHANGE_ID,
                slice_id=operation_id,
                writer_class="W08_CONTROLLED_PRODUCTION_DEPLOYMENT",
                owner_session_role="TK43_DL85_SCHEMA10_ADOPTION",
                track="CLEANER_POSTGRES_AUTHORITY_CUTOVER",
                repository_or_runtime="ADCP_CONTROL_DCS",
                operation_class="DCS_SCHEMA_V9_TO_V10_MIGRATION",
                target="GLOBAL_PRODUCTION",
                ttl_seconds=W08_TTL_SECONDS,
                control_decision_ref=DL85_CONTROL_DECISION_REF,
            )
        )
    except StoreError as error:
        store.close()
        raise ProductionSchema10OperationalError("SCHEMA10_W08_ACQUIRE_FAILED", error.code) from error
    expected = _expected_lease_context(operation_id, owner_id, attempt)
    if any(row.get(k) != v for k, v in expected.items()) or int(row.get("fencing_token", -1)) <= 0:
        store.close()
        raise ProductionSchema10OperationalError("SCHEMA10_W08_ACQUIRE_IDENTITY_INVALID")
    events = store.global_production_writer_events()
    if not events:
        store.close()
        raise ProductionSchema10OperationalError("SCHEMA10_W08_ACQUIRE_EVENT_MISSING")
    event = events[-1]
    if (
        event["event_type"] != "ACQUIRE"
        or event["new_owner_id"] != owner_id
        or int(event["to_fencing_token"]) != int(row["fencing_token"])
    ):
        store.close()
        raise ProductionSchema10OperationalError("SCHEMA10_W08_ACQUIRE_EVENT_INVALID")
    held = Schema10HeldW08(
        _seal=_W08_CONSTRUCTOR_SEAL,
        path=resolved,
        operation_id=operation_id,
        backup=backup,
        store=store,
        owner_id=owner_id,
        owner_execution_id=attempt,
        fencing_token=int(row["fencing_token"]),
        acquire_event_seq=int(event["event_seq"]),
        release_operation_key=release_key,
    )
    held.assert_current()
    return held


def acquire_schema9_w08(operation_id: str, backup: Schema10BackupEvidence) -> Schema10HeldW08:
    """Acquire the one canonical W08 against exact schema 9 and the exact backup."""
    return _acquire_schema9_w08(CANONICAL_DCS_PATH, operation_id, backup)


def _authorized_document_bytes(document: Mapping[str, Any]) -> bytes:
    return (_canonical_json(dict(document)) + "\n").encode("utf-8")


def _validate_authorized_document(writer_id: str, document: Mapping[str, Any]) -> None:
    if writer_id not in EXPECTED_WRITERS:
        raise ProductionSchema10OperationalError("SCHEMA10_WRITER_SET_INVALID", writer_id)
    if document.get("service_code") != EXPECTED_WRITERS[writer_id]:
        raise ProductionSchema10OperationalError("SCHEMA10_WRITER_SERVICE_CODE_MISMATCH", writer_id)
    if document.get("product_build_commit") != PRODUCTION_PRODUCT_COMMIT:
        raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PRODUCT_IDENTITY_MISMATCH", writer_id)
    source = PRODUCTION_PRODUCT_COMMIT
    artifact = f"source-commit:{source}"
    expected_product = f"product:PropertyAI@g{source[:12]}|source={source}|artifact={artifact}"
    if (
        document.get("product_build_identity") != expected_product
        or document.get("source_root_or_artifact_identity") != artifact
    ):
        raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PRODUCT_IDENTITY_MISMATCH", writer_id)


def _atomic_failure_evidence(operation: str, error: BaseException) -> _AtomicFailureEvidence:
    return _AtomicFailureEvidence(
        operation=operation,
        exception_type=_exception_type_name(error),
        detail=_safe_exception_text(error),
    )


def _observe_temp_residual(
    temp: Path,
) -> tuple[str, _AtomicFailureEvidence | None]:
    try:
        temp.lstat()
    except FileNotFoundError:
        return "ABSENT", None
    except BaseException as error:
        return "UNKNOWN", _atomic_failure_evidence("TEMP_RESIDUAL_LSTAT", error)
    return "PRESENT", None


def _write_temp_stream(
    fd: int, payload: bytes
) -> tuple[_TempStreamOutcome, BaseException | None, BaseException | None]:
    """Write one temp stream without allowing close to mask an earlier failure."""
    open_status = "NOT_ATTEMPTED"
    write_status = "NOT_ATTEMPTED"
    flush_status = "NOT_ATTEMPTED"
    fsync_status = "NOT_ATTEMPTED"
    close_status = "NOT_ATTEMPTED"
    open_error: BaseException | None = None
    write_error: BaseException | None = None
    flush_error: BaseException | None = None
    fsync_error: BaseException | None = None
    close_error: BaseException | None = None
    stream = None

    try:
        stream = os.fdopen(fd, "wb", closefd=True)
        open_status = "SUCCESS"
    except BaseException as error:
        open_status = "FAIL"
        open_error = error
        # fdopen did not take ownership. Explicit descriptor cleanup is folded into
        # the close phase so even this edge cannot escape the typed outcome.
        try:
            os.close(fd)
            close_status = "SUCCESS"
        except BaseException as descriptor_close_error:
            close_status = "FAIL"
            close_error = descriptor_close_error

    if stream is not None:
        try:
            written = stream.write(payload)
            if written != len(payload):
                raise OSError(
                    f"short temp write: expected={len(payload)} actual={written}"
                )
            write_status = "SUCCESS"
        except BaseException as error:
            write_status = "FAIL"
            write_error = error

        if write_error is None:
            try:
                stream.flush()
                flush_status = "SUCCESS"
            except BaseException as error:
                flush_status = "FAIL"
                flush_error = error

        if write_error is None and flush_error is None:
            try:
                os.fsync(stream.fileno())
                fsync_status = "SUCCESS"
            except BaseException as error:
                fsync_status = "FAIL"
                fsync_error = error

        try:
            stream.close()
            close_status = "SUCCESS"
        except BaseException as error:
            close_status = "FAIL"
            close_error = error

    outcome = _TempStreamOutcome(
        open_status=open_status,
        write_status=write_status,
        flush_status=flush_status,
        fsync_status=fsync_status,
        close_status=close_status,
        open_failure=(
            _atomic_failure_evidence("TEMP_STREAM_OPEN", open_error)
            if open_error is not None
            else None
        ),
        write_failure=(
            _atomic_failure_evidence("TEMP_WRITE", write_error)
            if write_error is not None
            else None
        ),
        flush_failure=(
            _atomic_failure_evidence("TEMP_FLUSH", flush_error)
            if flush_error is not None
            else None
        ),
        fsync_failure=(
            _atomic_failure_evidence("TEMP_FSYNC", fsync_error)
            if fsync_error is not None
            else None
        ),
        close_failure=(
            _atomic_failure_evidence("TEMP_STREAM_CLOSE", close_error)
            if close_error is not None
            else None
        ),
    )
    primary_error = _first_non_none(open_error, write_error, flush_error, fsync_error, close_error)
    return outcome, primary_error, close_error


def _atomic_write_exact(path: Path, payload: bytes, mode: int) -> _AtomicWriteOutcome:
    """Atomically replace one projection file and preserve every write/cleanup fact."""
    temp = path.parent / f".{path.name}.dl85-{uuid4().hex}.tmp"
    destination_replaced = False
    durability_complete = False
    chmod_status = "NOT_ATTEMPTED"
    operation = "TEMP_CREATE"
    primary_error: BaseException | None = None
    temp_close_error: BaseException | None = None
    directory_close_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    directory_outcome: _DirectoryDurabilityOutcome | None = None
    directory_error_for_evidence: _DirectoryDurabilityFailure | None = None
    temp_stream_outcome: _TempStreamOutcome | None = None
    temp_residual_state = "NONE"
    temp_residual_observation_failure: _AtomicFailureEvidence | None = None

    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        temp_stream_outcome, primary_error, temp_close_error = _write_temp_stream(fd, payload)
        if temp_stream_outcome.primary_failure is not None:
            operation = temp_stream_outcome.primary_failure.operation
        else:
            operation = "DESTINATION_REPLACE"
            os.replace(temp, path)
            destination_replaced = True
            operation = "DESTINATION_CHMOD"
            try:
                os.chmod(path, mode)
                chmod_status = "SUCCESS"
            except BaseException:
                chmod_status = "FAIL"
                raise
            operation = "DIRECTORY_FSYNC"
            try:
                directory_outcome = _fsync_directory(path.parent)
                durability_complete = True
            except _DirectoryDurabilityFailure as directory_error:
                directory_error_for_evidence = directory_error
                directory_outcome = directory_error.outcome
                durability_complete = directory_outcome.fsync_complete
                if directory_outcome.open_failure is not None:
                    operation = "DIRECTORY_OPEN"
                    primary_error = _first_non_none(directory_error.primary_cause, directory_error)
                elif directory_outcome.fsync_failure is not None:
                    operation = "DIRECTORY_FSYNC"
                    primary_error = _first_non_none(directory_error.primary_cause, directory_error)
                if directory_outcome.close_failure is not None:
                    directory_close_error = _first_non_none(directory_error.close_cause, directory_error)
                    if primary_error is None:
                        operation = "DIRECTORY_CLOSE"
    except BaseException as error:
        primary_error = error

    try:
        temp.unlink()
    except FileNotFoundError:
        pass
    except BaseException as error:
        cleanup_error = error
        temp_residual_state, temp_residual_observation_failure = _observe_temp_residual(temp)

    if temp_stream_outcome is not None and temp_stream_outcome.primary_failure is not None:
        primary_failure = temp_stream_outcome.primary_failure
    elif (
        primary_error is not None
        and directory_outcome is not None
        and operation == "DIRECTORY_OPEN"
        and directory_outcome.open_failure is not None
    ):
        primary_failure = directory_outcome.open_failure
    elif (
        primary_error is not None
        and directory_outcome is not None
        and operation == "DIRECTORY_FSYNC"
        and directory_outcome.fsync_failure is not None
    ):
        primary_failure = directory_outcome.fsync_failure
    else:
        primary_failure = (
            _atomic_failure_evidence(operation, primary_error)
            if primary_error is not None
            else None
        )

    cleanup_failure = (
        _atomic_failure_evidence("TEMP_CLEANUP", cleanup_error)
        if cleanup_error is not None
        else None
    )
    secondary_failures: list[_AtomicFailureEvidence] = []
    if (
        temp_stream_outcome is not None
        and temp_stream_outcome.close_failure is not None
        and temp_stream_outcome.primary_failure is not temp_stream_outcome.close_failure
    ):
        secondary_failures.append(temp_stream_outcome.close_failure)
    if directory_outcome is not None and directory_outcome.close_failure is not None:
        secondary_failures.append(directory_outcome.close_failure)
    if cleanup_failure is not None:
        secondary_failures.append(cleanup_failure)

    failed_operation = (
        primary_failure.operation
        if primary_failure is not None
        else (secondary_failures[0].operation if secondary_failures else None)
    )
    outcome = _AtomicWriteOutcome(
        destination_replaced=destination_replaced,
        durability_complete=durability_complete,
        failed_operation=failed_operation,
        primary_failure=primary_failure,
        cleanup_failure=cleanup_failure,
        directory_outcome=directory_outcome,
        secondary_failures=tuple(secondary_failures),
        temp_path=str(temp) if cleanup_error is not None else None,
        temp_residual_state=temp_residual_state,
        temp_residual_observation_failure=temp_residual_observation_failure,
        temp_stream_outcome=temp_stream_outcome,
        chmod_status=chmod_status,
    )
    if primary_failure is not None or secondary_failures:
        secondary_causes = tuple(
            error
            for error in (
                temp_close_error
                if (
                    temp_stream_outcome is not None
                    and temp_stream_outcome.close_failure is not None
                    and temp_stream_outcome.primary_failure is not temp_stream_outcome.close_failure
                )
                else None,
                directory_close_error,
            )
            if error is not None
        )
        evidence_causes = (
            (directory_error_for_evidence,)
            if directory_error_for_evidence is not None
            else ()
        )
        prior_reporting_failures, _ = _collect_error_serialization_failures(
            *evidence_causes, primary_error, cleanup_error, *secondary_causes
        )
        try:
            typed = _AtomicWriteFailure(
                outcome,
                primary_error,
                cleanup_error,
                secondary_causes=secondary_causes,
                evidence_causes=evidence_causes,
            )
        except BaseException as reporting_error:
            # Exact mutation facts and already-created serialization evidence survive
            # even if the typed reporting constructor itself fails after os.replace.
            reporting_failure = {
                "operation": "ATOMIC_WRITE_TYPED_CONSTRUCTION",
                "exception_type": _safe_type_name(reporting_error),
                "detail": "atomic typed reporting construction failed",
            }
            carried = tuple(prior_reporting_failures) + (reporting_failure,)
            raise _AtomicWriteReportingFailure(
                outcome, reporting_error, carried
            ) from reporting_error
        raise typed from _first_non_none(
            primary_error, temp_close_error, directory_close_error, cleanup_error
        )
    return outcome


def _record_projection_write_outcome(
    state: _ProjectionEntryState, outcome: _AtomicWriteOutcome
) -> None:
    state.last_write_outcome = outcome
    state.destination_replaced = outcome.destination_replaced
    state.post_replace_durability_complete = outcome.durability_complete
    state.failed_post_replace_operation = (
        outcome.failed_operation if outcome.destination_replaced and outcome.failed_operation else None
    )
    state.changed_by_invocation = (
        outcome.destination_replaced and not state.entry_was_already_target
    )


def _write_projection_entry(state: _ProjectionEntryState, mode: int) -> _AtomicWriteOutcome:
    state.write_attempted = True
    try:
        outcome = _atomic_write_exact(state.path, state.target_payload, mode)
    except (_AtomicWriteFailure, _AtomicWriteReportingFailure) as error:
        _record_projection_write_outcome(state, error.outcome)
        raise
    _record_projection_write_outcome(state, outcome)
    return outcome


def _observe_projection_state(path: Path) -> _ProjectionObservationOutcome:
    """Observe destination state without allowing evidence-gathering errors to escape."""
    stat_status = "NOT_ATTEMPTED"
    read_status = "NOT_ATTEMPTED"
    hash_status = "NOT_ATTEMPTED"
    stat_failure: _AtomicFailureEvidence | None = None
    read_failure: _AtomicFailureEvidence | None = None
    hash_failure: _AtomicFailureEvidence | None = None
    observed_mode: int | None = None
    observed_size: int | None = None
    observed_hash: str | None = None
    stat_proved_present = False

    try:
        metadata = path.stat()
        stat_status = "SUCCESS"
        stat_proved_present = True
        observed_mode = stat.S_IMODE(metadata.st_mode)
        observed_size = metadata.st_size
    except FileNotFoundError:
        # FileNotFound is a successful semantic observation of absence. Avoid a
        # second read that could turn a known absence into a misleading error.
        return _ProjectionObservationOutcome(
            observation_attempted=True,
            path_exists="NO",
            read_bytes_status="NOT_ATTEMPTED",
            stat_status="SUCCESS",
            hash_status="NOT_ATTEMPTED",
            observed_bytes_hash=None,
            observed_mode=None,
            observed_size=None,
            read_failure=None,
            stat_failure=None,
            hash_failure=None,
            observation_complete=True,
            state="ABSENT",
        )
    except BaseException as error:
        stat_status = "FAIL"
        stat_failure = _atomic_failure_evidence("OBSERVATION_STAT", error)

    read_saw_absence = False
    payload: bytes | None = None
    try:
        payload = path.read_bytes()
        read_status = "SUCCESS"
        if observed_size is None:
            observed_size = len(payload)
    except FileNotFoundError as error:
        read_status = "FAIL"
        read_saw_absence = True
        read_failure = _atomic_failure_evidence("OBSERVATION_READ_BYTES", error)
    except BaseException as error:
        read_status = "FAIL"
        read_failure = _atomic_failure_evidence("OBSERVATION_READ_BYTES", error)

    if payload is not None:
        try:
            observed_hash = _sha256_bytes(payload)
            hash_status = "SUCCESS"
        except BaseException as error:
            hash_status = "FAIL"
            hash_failure = _atomic_failure_evidence("OBSERVATION_HASH", error)

    if stat_proved_present and read_saw_absence:
        path_exists = "UNKNOWN"
    elif stat_proved_present or read_status == "SUCCESS":
        path_exists = "YES"
    else:
        path_exists = "UNKNOWN"

    complete = (
        path_exists == "YES"
        and stat_status == "SUCCESS"
        and read_status == "SUCCESS"
        and hash_status == "SUCCESS"
    )
    return _ProjectionObservationOutcome(
        observation_attempted=True,
        path_exists=path_exists,
        read_bytes_status=read_status,
        stat_status=stat_status,
        hash_status=hash_status,
        observed_bytes_hash=observed_hash,
        observed_mode=observed_mode,
        observed_size=observed_size,
        read_failure=read_failure,
        stat_failure=stat_failure,
        hash_failure=hash_failure,
        observation_complete=complete,
        state="PRESENT" if complete else "OBSERVATION_UNKNOWN",
    )


def _observed_projection_state(path: Path) -> Mapping[str, Any]:
    return _projection_observation_payload(_observe_projection_state(path))


def _capture_projection_observation(state: _ProjectionEntryState) -> Mapping[str, Any]:
    observation = dict(_observed_projection_state(state.path))
    state.reconciliation_observations.append(observation)
    return observation


def _compensation_restoration_payload(
    state: _ProjectionEntryState,
    *,
    restore_readback_state: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    outcome = state.restoration_write_outcome
    absence = state.absence_restoration_outcome
    stream = outcome.temp_stream_outcome if outcome is not None else None
    directory = (
        outcome.directory_outcome
        if outcome is not None
        else (absence.directory_outcome if absence is not None else None)
    )
    if outcome is not None:
        primary_failure = outcome.primary_failure
        secondary_failures = list(outcome.secondary_failures)
        durability_complete = outcome.durability_complete
    else:
        primary_failure = None
        secondary_failures: list[_AtomicFailureEvidence] = []
        durability_complete = False
        if absence is not None:
            primary_failure = _first_non_none(
                absence.unlink_failure,
                absence.directory_failure,
                directory.open_failure if directory is not None else None,
                directory.fsync_failure if directory is not None else None,
            )
            if directory is not None and directory.close_failure is not None:
                if primary_failure is not directory.close_failure:
                    secondary_failures.append(directory.close_failure)
            durability_complete = absence.durability_complete
    return {
        "restore_attempted": state.compensation_attempted,
        "restore_kind": (
            "EXISTING_ENTRY_ATOMIC_REPLACE" if state.existed else "ABSENT_ENTRY_UNLINK"
        ),
        "restore_destination_replaced": (
            False if outcome is None else outcome.destination_replaced
        ),
        "restore_file_content_synced": (
            "NOT_ATTEMPTED" if stream is None else stream.fsync_status
        ),
        "restore_chmod_outcome": (
            "NOT_ATTEMPTED" if outcome is None else outcome.chmod_status
        ),
        "restore_directory_fsync_outcome": (
            "NOT_ATTEMPTED" if directory is None else directory.fsync_status
        ),
        "restore_directory_close_outcome": (
            "NOT_ATTEMPTED" if directory is None else directory.close_status
        ),
        "restore_temp_cleanup_outcome": (
            "NOT_ATTEMPTED"
            if outcome is None
            else ("FAIL" if outcome.cleanup_failure is not None else "SUCCESS")
        ),
        "restore_durability_complete": durability_complete,
        "restore_primary_failure": _atomic_failure_payload(primary_failure),
        "restore_secondary_failures": [
            _atomic_failure_payload(failure) for failure in secondary_failures
        ],
        "restore_temp_stream": (
            None if outcome is None else _temp_stream_payload(outcome.temp_stream_outcome)
        ),
        "restore_directory_durability": _directory_durability_payload(directory),
        "restore_absence_outcome": _absence_restoration_payload(absence),
        "restore_readback_state": (
            dict(restore_readback_state)
            if restore_readback_state is not None
            else _capture_projection_observation(state)
        ),
    }


def _projection_reconciliation_payload(
    state: _ProjectionEntryState,
    *,
    guard_failure: str | None,
    required_action: str,
    failed_operation: str | None = None,
    operation_directory_outcome: _DirectoryDurabilityOutcome | None = None,
    original_operation_error: BaseException | None = None,
    compensation_error: BaseException | None = None,
    reconciliation_observation: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    observation = (
        dict(reconciliation_observation)
        if reconciliation_observation is not None
        else _capture_projection_observation(state)
    )
    if not state.reconciliation_observations or state.reconciliation_observations[-1] != observation:
        state.reconciliation_observations.append(observation)
    observation_history = [dict(item) for item in state.reconciliation_observations]
    return {
        "writer_id": state.writer_id,
        "path": str(state.path),
        "entry_state_before": {
            "existed": state.existed,
            "sha256": state.payload_sha256,
            "mode": state.mode,
        },
        "attempted_target_state": {"sha256": state.target_sha256},
        "write_attempted": state.write_attempted,
        "destination_replaced": state.destination_replaced,
        "post_replace_durability_complete": state.post_replace_durability_complete,
        "changed_by_invocation": state.changed_by_invocation,
        "current_observed_state": observation,
        "reconciliation_observation_history": observation_history,
        "destination_state": {
            "replaced": state.destination_replaced,
            "changed_by_invocation": state.changed_by_invocation,
            "durability_complete": state.post_replace_durability_complete,
            "observed": observation,
        },
        "primary_write_state": (
            {"status": "NOT_RECORDED"}
            if state.last_write_outcome is None
            else (
                {"status": "COMPLETE"}
                if state.last_write_outcome.primary_failure is None
                else {
                    "status": "FAILED",
                    "operation": state.last_write_outcome.primary_failure.operation,
                    "exception_type": state.last_write_outcome.primary_failure.exception_type,
                    "detail": state.last_write_outcome.primary_failure.detail,
                }
            )
        ),
        "temp_stream_state": (
            None
            if state.last_write_outcome is None
            else _temp_stream_payload(state.last_write_outcome.temp_stream_outcome)
        ),
        "cleanup_state": (
            {"status": "NOT_RECORDED"}
            if state.last_write_outcome is None
            else (
                {"status": "COMPLETE_OR_BENIGN_ABSENT"}
                if state.last_write_outcome.cleanup_failure is None
                else {
                    "status": "FAILED",
                    "operation": state.last_write_outcome.cleanup_failure.operation,
                    "exception_type": state.last_write_outcome.cleanup_failure.exception_type,
                    "detail": state.last_write_outcome.cleanup_failure.detail,
                }
            )
        ),
        "directory_durability_state": (
            None
            if state.last_write_outcome is None
            else _directory_durability_payload(state.last_write_outcome.directory_outcome)
        ),
        "secondary_failures": (
            []
            if state.last_write_outcome is None
            else [
                _atomic_failure_payload(failure)
                for failure in state.last_write_outcome.secondary_failures
            ]
        ),
        "operation_directory_durability_state": _directory_durability_payload(
            operation_directory_outcome
        ),
        "temp_residual_state": (
            {"path": None, "state": "NOT_RECORDED", "observation_failure": None}
            if state.last_write_outcome is None
            else {
                "path": state.last_write_outcome.temp_path,
                "state": state.last_write_outcome.temp_residual_state,
                "observation_failure": _atomic_failure_payload(
                    state.last_write_outcome.temp_residual_observation_failure
                ),
            }
        ),
        "compensation_restoration": _compensation_restoration_payload(
            state, restore_readback_state=observation
        ),
        "original_operation_error": _exception_evidence_payload(original_operation_error),
        "compensation_error": _exception_evidence_payload(compensation_error),
        "failed_post_replace_operation": (
            failed_operation if failed_operation is not None else state.failed_post_replace_operation
        ),
        "authority_event_guard_failure": guard_failure,
        "required_reconciliation_action": required_action,
    }


def _projection_reconciliation_detail(
    state: _ProjectionEntryState,
    *,
    guard_failure: str | None,
    required_action: str,
    failed_operation: str | None = None,
    operation_directory_outcome: _DirectoryDurabilityOutcome | None = None,
    original_operation_error: BaseException | None = None,
    compensation_error: BaseException | None = None,
    reconciliation_observation: Mapping[str, Any] | None = None,
) -> str:
    payload = _projection_reconciliation_payload(
        state,
        guard_failure=guard_failure,
        required_action=required_action,
        failed_operation=failed_operation,
        operation_directory_outcome=operation_directory_outcome,
        original_operation_error=original_operation_error,
        compensation_error=compensation_error,
        reconciliation_observation=reconciliation_observation,
    )
    prior_failures, access_failures = _collect_error_serialization_failures(
        original_operation_error, compensation_error
    )
    if len(access_failures) > 0:
        payload = dict(payload)
        payload["serialization_failure_attribute_access"] = list(access_failures)
    return _serialize_evidence_payload(
        payload,
        operation="RECONCILIATION_SERIALIZATION",
        force_failsafe=len(prior_failures) > 0,
        prior_failures=prior_failures,
    )


def _state_has_recovery_evidence(state: _ProjectionEntryState) -> bool:
    return (
        state.write_attempted is True
        or state.last_write_outcome is not None
        or state.changed_by_invocation is True
        or state.compensation_attempted is True
        or state.restoration_write_outcome is not None
        or state.absence_restoration_outcome is not None
        or len(state.reconciliation_observations) > 0
    )


def _terminal_observation_from_state(state: _ProjectionEntryState) -> Mapping[str, Any]:
    if len(state.reconciliation_observations) > 0:
        snapshot = _terminal_snapshot(state.reconciliation_observations[-1])
        if type(snapshot) is dict:
            return snapshot
    return {
        "observation_attempted": "NO",
        "path_exists": "UNKNOWN",
        "read_bytes": "NOT_ATTEMPTED",
        "stat": "NOT_ATTEMPTED",
        "hash": "NOT_ATTEMPTED",
        "observation_complete": "NO",
        "state": "OBSERVATION_UNKNOWN",
        "sha256": "UNKNOWN",
        "mode": "UNKNOWN",
        "size": "UNKNOWN",
    }


def _terminal_compensation_restoration_snapshot(
    state: _ProjectionEntryState,
) -> Mapping[str, Any]:
    outcome = state.restoration_write_outcome
    absence = state.absence_restoration_outcome
    stream = outcome.temp_stream_outcome if outcome is not None else None
    directory = (
        outcome.directory_outcome
        if outcome is not None
        else (absence.directory_outcome if absence is not None else None)
    )
    primary_failure = None
    secondary_failures: list[_AtomicFailureEvidence] = []
    durability_complete = False
    if outcome is not None:
        primary_failure = outcome.primary_failure
        secondary_failures = list(outcome.secondary_failures)
        durability_complete = outcome.durability_complete
    elif absence is not None:
        primary_failure = _first_non_none(
            absence.unlink_failure,
            absence.directory_failure,
            directory.open_failure if directory is not None else None,
            directory.fsync_failure if directory is not None else None,
        )
        if directory is not None and directory.close_failure is not None:
            if primary_failure is not directory.close_failure:
                secondary_failures.append(directory.close_failure)
        durability_complete = absence.durability_complete
    return {
        "restore_attempted": state.compensation_attempted,
        "restore_kind": "EXISTING_ENTRY_ATOMIC_REPLACE" if state.existed else "ABSENT_ENTRY_UNLINK",
        "restore_destination_replaced": False if outcome is None else outcome.destination_replaced,
        "restore_file_content_synced": "NOT_ATTEMPTED" if stream is None else stream.fsync_status,
        "restore_chmod_outcome": "NOT_ATTEMPTED" if outcome is None else outcome.chmod_status,
        "restore_directory_fsync_outcome": "NOT_ATTEMPTED" if directory is None else directory.fsync_status,
        "restore_directory_close_outcome": "NOT_ATTEMPTED" if directory is None else directory.close_status,
        "restore_temp_cleanup_outcome": (
            "NOT_ATTEMPTED" if outcome is None else ("FAIL" if outcome.cleanup_failure is not None else "SUCCESS")
        ),
        "restore_durability_complete": durability_complete,
        "restore_primary_failure": _atomic_failure_payload(primary_failure),
        "restore_secondary_failures": [_atomic_failure_payload(item) for item in secondary_failures],
        "restore_temp_stream": None if outcome is None else _temp_stream_payload(outcome.temp_stream_outcome),
        "restore_directory_durability": _directory_durability_payload(directory),
        "restore_absence_outcome": _absence_restoration_payload(absence),
        "restore_readback_state": _terminal_observation_from_state(state),
    }


def _terminal_projection_state_snapshot(
    state: _ProjectionEntryState,
    *,
    required_action: str,
) -> Mapping[str, Any]:
    observation = _terminal_observation_from_state(state)
    history = _terminal_snapshot(state.reconciliation_observations)
    if type(history) is not list:
        history = []
    try:
        path_text = str(state.path)
    except BaseException:
        path_text = "<path-unavailable>"
    if type(path_text) is not str:
        path_text = "<path-unavailable>"
    return {
        "writer_id": state.writer_id if type(state.writer_id) is str else _terminal_safe_scalar(state.writer_id),
        "path": _truncate_exact_text(path_text, _TERMINAL_MAX_SCALAR_BYTES),
        "entry_state_before": {
            "existed": state.existed,
            "sha256": state.payload_sha256,
            "mode": state.mode,
        },
        "attempted_target_state": {"sha256": state.target_sha256},
        "write_attempted": state.write_attempted,
        "destination_replaced": state.destination_replaced,
        "post_replace_durability_complete": state.post_replace_durability_complete,
        "changed_by_invocation": state.changed_by_invocation,
        "current_observed_state": observation,
        "reconciliation_observation_history": history,
        "destination_state": {
            "replaced": state.destination_replaced,
            "changed_by_invocation": state.changed_by_invocation,
            "durability_complete": state.post_replace_durability_complete,
            "observed": observation,
        },
        "compensation_restoration": _terminal_compensation_restoration_snapshot(state),
        "failed_post_replace_operation": state.failed_post_replace_operation,
        "required_reconciliation_action": required_action,
        "terminal_snapshot_source": "DL93_NON_RECURSIVE_STATE_SNAPSHOT",
    }


def _generic_projection_recovery_payload(
    states: list[_ProjectionEntryState],
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    compensation_status: str,
) -> Mapping[str, Any]:
    """Acyclic recovery: never re-enters the canonical reconciliation builder."""
    structured: list[Mapping[str, Any]] = []
    attached, attribute_failures = _safe_error_attached_payload(compensation_error)
    compensation_writer = dict.get(attached, "writer_id") if type(attached) is dict else None
    for state in states:
        if not _state_has_recovery_evidence(state):
            continue
        if type(attached) is dict and compensation_writer == state.writer_id:
            structured.append(attached)
            continue
        structured.append(
            _terminal_projection_state_snapshot(
                state,
                required_action=(
                    "RECOVERY_COMPLETED_REVIEW_ORIGINAL_FAILURE"
                    if compensation_status == "SUCCEEDED"
                    else "RECONCILE_UNEXPECTED_COMPENSATION_FAILURE"
                ),
            )
        )
    result: dict[str, Any] = dict(structured[0]) if len(structured) == 1 else {}
    result.update(
        {
            "original_operation_error": _exception_evidence_payload(original_operation_error),
            "outer_compensation_error": _exception_evidence_payload(compensation_error),
            "unexpected_compensation_error": (
                _exception_evidence_payload(compensation_error)
                if compensation_error is not None
                else None
            ),
            "compensation_status": compensation_status,
            "structured_reconciliation": structured,
            "accumulated_evidence_is_monotonic": True,
            "generic_recovery_recursive": False,
        }
    )
    prior_failures, serialization_access_failures = _collect_error_serialization_failures(
        original_operation_error, compensation_error
    )
    combined_attribute_failures = list(attribute_failures)
    for item in serialization_access_failures:
        if item not in combined_attribute_failures:
            combined_attribute_failures.append(item)
    if len(prior_failures) > 0:
        result["serialization_failures"] = list(prior_failures)
        result["serialization_failure"] = prior_failures[0]
    if len(combined_attribute_failures) > 0:
        result["evidence_attribute_failures"] = combined_attribute_failures
    return result


def _generic_projection_recovery_detail(
    states: list[_ProjectionEntryState],
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    compensation_status: str = "FAILED",
) -> str:
    payload = _generic_projection_recovery_payload(
        states,
        original_operation_error=original_operation_error,
        compensation_error=compensation_error,
        compensation_status=compensation_status,
    )
    prior_failures, attribute_failures = _collect_error_serialization_failures(
        original_operation_error, compensation_error
    )
    if len(attribute_failures) > 0:
        payload = dict(payload)
        payload["serialization_failure_attribute_access"] = list(attribute_failures)
    return _serialize_evidence_payload(
        payload,
        operation="GENERIC_RECOVERY_SERIALIZATION",
        force_failsafe=len(prior_failures) > 0,
        prior_failures=prior_failures,
    )


def _attach_projection_recovery_evidence(
    error: BaseException,
    payload: Mapping[str, Any],
    *,
    prior_errors: tuple[BaseException | None, ...] = (),
) -> ProductionSchema10OperationalError:
    prior_failures, attribute_failures = _collect_error_serialization_failures(
        *prior_errors, error
    )
    safe_payload = _terminal_payload_dict(payload)
    if len(attribute_failures) > 0:
        existing = dict.get(safe_payload, "evidence_attribute_failures")
        if type(existing) is list:
            existing.extend(attribute_failures)
        else:
            safe_payload["evidence_attribute_failures"] = list(attribute_failures)
    detail = _serialize_evidence_payload(
        safe_payload,
        operation="OUTER_RECOVERY_SERIALIZATION",
        force_failsafe=len(prior_failures) > 0,
        prior_failures=prior_failures,
    )
    if isinstance(error, ProductionSchema10OperationalError):
        try:
            bounded_code, bounded_detail, message = _bounded_error_components(
                error.code, str.__str__(detail)
            )
            error.code = bounded_code
            error.detail = bounded_detail
            error.evidence_payload = detail.evidence_payload
            error.serialization_failures = detail.serialization_failures
            error.args = (message,)
            return error
        except BaseException:
            pass
    return ProductionSchema10OperationalError(
        "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
        detail,
    )


def _terminal_recovery_payload_after_builder_failure(
    states: list[_ProjectionEntryState],
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    compensation_status: str,
    builder_error: BaseException,
) -> Mapping[str, Any]:
    structured: list[Mapping[str, Any]] = []
    for state in states:
        if _state_has_recovery_evidence(state):
            structured.append(
                _terminal_projection_state_snapshot(
                    state,
                    required_action="DL93_TERMINAL_RECOVERY_BUILDER_FAILED_RECONCILE",
                )
            )
    return {
        "original_operation_error": _exception_evidence_payload(original_operation_error),
        "outer_compensation_error": _exception_evidence_payload(compensation_error),
        "terminal_recovery_builder_failure": _exception_evidence_payload(builder_error),
        "compensation_status": compensation_status,
        "structured_reconciliation": structured,
        "accumulated_evidence_is_monotonic": True,
        "generic_recovery_recursive": False,
    }


def _emergency_exception_identity(error: BaseException | None) -> dict[str, str] | None:
    if error is None:
        return None
    result = {"exception_type": _safe_type_name(error)}
    try:
        code = object.__getattribute__(error, "code")
    except BaseException:
        code = None
    if type(code) is str:
        result["code"] = _emergency_exact_text(code, 768)
    detail = None
    try:
        raw_detail = object.__getattribute__(error, "detail")
    except BaseException:
        raw_detail = None
    if type(raw_detail) is str:
        detail = raw_detail
    else:
        try:
            args = object.__getattribute__(error, "args")
            if type(args) is tuple and tuple.__len__(args) > 0:
                first_arg = tuple.__getitem__(args, 0)
                if type(first_arg) is str:
                    detail = first_arg
        except BaseException:
            detail = None
    if type(detail) is str:
        result["detail"] = _emergency_exact_text(detail, _TERMINAL_MAX_SCALAR_BYTES)
    return result


def _emergency_existing_serialization_failures(
    error: BaseException | None,
) -> tuple[Mapping[str, str], ...]:
    if error is None:
        return ()
    try:
        raw = object.__getattribute__(error, "serialization_failures")
    except BaseException:
        return ()
    return _emergency_failure_tuple(raw)


def _emergency_payload_serialization_failures(
    payload: Mapping[str, Any] | None,
) -> tuple[Mapping[str, str], ...]:
    if type(payload) is not dict:
        return ()
    found, raw = _emergency_exact_dict_get(payload, "serialization_failures")
    if found:
        failures = _emergency_failure_tuple(raw)
        if tuple.__len__(failures) > 0:
            return failures
    found, first = _emergency_exact_dict_get(payload, "serialization_failure")
    if found and type(first) is dict:
        return _emergency_failure_tuple([first])
    return ()


def _terminal_surface_bypass(
    detail: str,
    payload: dict[str, Any],
    failures: tuple[Mapping[str, str], ...],
) -> ProductionSchema10OperationalError:
    """Constructor-bypass path that preserves the already-rendered identity-bearing detail."""
    code = "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED"
    prefix = code + ": "
    prefix_bytes = str.encode(prefix, "utf-8", "strict")
    bounded_detail = _emergency_exact_text(
        detail, TERMINAL_EVIDENCE_MAX_BYTES - len(prefix_bytes)
    )
    message = prefix + bounded_detail
    value = RuntimeError.__new__(_TerminalRecoverySurfaceError, message)
    RuntimeError.__init__(value, message)
    value.code = code
    value.detail = bounded_detail
    value.evidence_payload = payload
    value.serialization_failures = failures
    return value


def _absolute_terminal_surface(
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    terminal_error: BaseException,
    surface_error: BaseException,
    operation: str,
    recovery_payload: Mapping[str, Any] | None,
    prior_failures: tuple[Mapping[str, str], ...],
) -> ProductionSchema10OperationalError:
    """Non-recursive final allocation if independent-surface assembly itself fails."""
    original_identity = _emergency_exception_identity(original_operation_error) or {
        "exception_type": "builtins.BaseException"
    }
    compensation_identity = _emergency_exception_identity(compensation_error)
    terminal_identity = _emergency_exception_identity(terminal_error)
    surface_identity = _emergency_exception_identity(surface_error)
    accumulated_failures: list[Mapping[str, str]] = []
    for failure in _emergency_payload_serialization_failures(recovery_payload):
        accumulated_failures.append(failure)
    for failure in prior_failures:
        accumulated_failures.append(failure)
    for error in (original_operation_error, compensation_error, terminal_error):
        for failure in _emergency_existing_serialization_failures(error):
            accumulated_failures.append(failure)
    accumulated_failures.append(
        {
            "operation": "INDEPENDENT_TERMINAL_SURFACE_INTERNAL",
            "exception_type": _safe_type_name(surface_error),
            "detail": "independent terminal surface assembly failed",
        }
    )
    failures = tuple(accumulated_failures)
    payload: dict[str, Any] = {}
    if type(recovery_payload) is dict:
        for key, item in list(dict.items(recovery_payload)):
            if type(key) is str:
                payload[key] = item
    found_original, prior_original = _emergency_exact_dict_get(
        payload, "original_operation_error"
    )
    if not found_original:
        payload["original_operation_error"] = original_identity
        prior_original = original_identity
    else:
        payload["terminal_original_operation_identity"] = original_identity
    found_compensation, _ = _emergency_exact_dict_get(
        payload, "outer_compensation_error"
    )
    if not found_compensation:
        payload["outer_compensation_error"] = compensation_identity
    else:
        payload["terminal_outer_compensation_identity"] = compensation_identity
    payload["terminal_surface"] = "DL93_ABSOLUTE_TERMINAL_SURFACE_V1"
    payload["terminal_surface_failure"] = terminal_identity
    payload["terminal_surface_internal_failure"] = surface_identity
    payload["terminal_surface_operation"] = (
        operation if type(operation) is str else "INDEPENDENT_TERMINAL_SURFACE"
    )
    payload["serialization_failures"] = list(failures)
    payload["serialization_failure"] = failures[0]
    payload["accumulated_evidence_is_monotonic"] = True
    payload["generic_recovery_recursive"] = False
    lines = [
        "DL93_ABSOLUTE_TERMINAL_SURFACE_V1",
        "original_exception_type=" + original_identity["exception_type"],
    ]
    found_code, original_code = _emergency_exact_dict_get(original_identity, "code")
    if found_code and type(original_code) is str:
        lines.append("original_code=" + original_code)
    if type(prior_original) is dict:
        found_prior_code, prior_code = _emergency_exact_dict_get(prior_original, "code")
        if found_prior_code and type(prior_code) is str:
            lines.append("preserved_original_code=" + _emergency_exact_text(prior_code, 768))
        found_prior_detail, prior_detail = _emergency_exact_dict_get(prior_original, "detail")
        if found_prior_detail and type(prior_detail) is str:
            lines.append(
                "preserved_original_detail="
                + _emergency_exact_text(prior_detail, _TERMINAL_MAX_SCALAR_BYTES)
            )
    if type(terminal_identity) is dict:
        _, terminal_type = _emergency_exact_dict_get(terminal_identity, "exception_type")
        if type(terminal_type) is str:
            lines.append("terminal_exception_type=" + terminal_type)
    lines.append("surface_exception_type=" + _safe_type_name(surface_error))
    detail = _emergency_exact_text("\n".join(lines), TERMINAL_EVIDENCE_MAX_BYTES - 64)
    return _terminal_surface_bypass(detail, payload, failures)


def _independent_terminal_surface(
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    terminal_error: BaseException,
    operation: str,
    recovery_payload: Mapping[str, Any] | None = None,
) -> ProductionSchema10OperationalError:
    """Acyclic final surface: no ordinary snapshot/serializer/detail carrier is called."""
    failures: list[Mapping[str, str]] = []
    try:
        for failure in _emergency_payload_serialization_failures(recovery_payload):
            failures.append(failure)
        for error in (original_operation_error, compensation_error, terminal_error):
            for failure in _emergency_existing_serialization_failures(error):
                failures.append(failure)
        terminal_failure = {
            "operation": (
                operation if type(operation) is str else "INDEPENDENT_TERMINAL_SURFACE"
            ),
            "exception_type": _safe_type_name(terminal_error),
            "detail": "terminal evidence machinery failure contained",
        }
        failures.append(terminal_failure)

        # Recovery payload is already primitive evidence assembled before the attach
        # failure. Preserve all exact-string-keyed fields instead of rebuilding it.
        payload: dict[str, Any] = {}
        if type(recovery_payload) is dict:
            for key, item in list(dict.items(recovery_payload)):
                if type(key) is str:
                    payload[key] = item

        original_identity = _emergency_exception_identity(original_operation_error) or {
            "exception_type": "builtins.BaseException"
        }
        compensation_identity = _emergency_exception_identity(compensation_error)
        terminal_identity = _emergency_exception_identity(terminal_error) or {
            "exception_type": "builtins.BaseException"
        }
        found_original, prior_original = _emergency_exact_dict_get(
            payload, "original_operation_error"
        )
        if not found_original:
            payload["original_operation_error"] = original_identity
            prior_original = original_identity
        else:
            payload["terminal_original_operation_identity"] = original_identity
        found_compensation, _ = _emergency_exact_dict_get(
            payload, "outer_compensation_error"
        )
        if not found_compensation:
            payload["outer_compensation_error"] = compensation_identity
        else:
            payload["terminal_outer_compensation_identity"] = compensation_identity
        payload["terminal_surface"] = "DL93_INDEPENDENT_TERMINAL_SURFACE_V1"
        payload["terminal_surface_failure"] = terminal_identity
        payload["serialization_failures"] = list(failures)
        payload["serialization_failure"] = failures[0]
        payload["accumulated_evidence_is_monotonic"] = True
        payload["generic_recovery_recursive"] = False
        if operation == "TERMINAL_ATTACH":
            payload["terminal_attach_failure"] = terminal_identity

        _, original_type = _emergency_exact_dict_get(original_identity, "exception_type")
        lines = [
            "DL93_INDEPENDENT_TERMINAL_SURFACE_V1",
            "original_exception_type="
            + (original_type if type(original_type) is str else "builtins.BaseException"),
        ]
        found_code, original_code = _emergency_exact_dict_get(original_identity, "code")
        if found_code and type(original_code) is str:
            lines.append("original_code=" + original_code)
        if type(prior_original) is dict:
            found_prior_code, prior_code = _emergency_exact_dict_get(
                prior_original, "code"
            )
            if found_prior_code and type(prior_code) is str:
                lines.append(
                    "preserved_original_code=" + _emergency_exact_text(prior_code, 768)
                )
            found_prior_detail, prior_detail = _emergency_exact_dict_get(
                prior_original, "detail"
            )
            if found_prior_detail and type(prior_detail) is str:
                lines.append(
                    "preserved_original_detail="
                    + _emergency_exact_text(prior_detail, _TERMINAL_MAX_SCALAR_BYTES)
                )
        if type(compensation_identity) is dict:
            _, compensation_type = _emergency_exact_dict_get(
                compensation_identity, "exception_type"
            )
            if type(compensation_type) is str:
                lines.append("compensation_exception_type=" + compensation_type)
        _, terminal_type = _emergency_exact_dict_get(terminal_identity, "exception_type")
        lines.append(
            "terminal_exception_type="
            + (terminal_type if type(terminal_type) is str else "builtins.BaseException")
        )
        for index in range(min(len(failures), 64)):
            failure = failures[index]
            _, failure_operation = _emergency_exact_dict_get(failure, "operation")
            _, failure_type = _emergency_exact_dict_get(failure, "exception_type")
            lines.append(
                "serialization_failure[" + int.__repr__(index) + "]="
                + (failure_operation if type(failure_operation) is str else "UNKNOWN")
                + "/"
                + (failure_type if type(failure_type) is str else "UNKNOWN")
            )
        detail = _emergency_exact_text(
            "\n".join(lines), TERMINAL_EVIDENCE_MAX_BYTES - 64
        )
        exact_failures = tuple(failures)
        try:
            return _TerminalRecoverySurfaceError(detail, payload, exact_failures)
        except BaseException:
            return _terminal_surface_bypass(detail, payload, exact_failures)
    except BaseException as surface_error:
        return _absolute_terminal_surface(
            original_operation_error=original_operation_error,
            compensation_error=compensation_error,
            terminal_error=terminal_error,
            surface_error=surface_error,
            operation=operation,
            recovery_payload=recovery_payload,
            prior_failures=tuple(failures),
        )


def _surface_projection_recovery(
    states: list[_ProjectionEntryState],
    *,
    original_operation_error: BaseException,
    compensation_error: BaseException | None,
    compensation_status: str,
) -> ProductionSchema10OperationalError:
    """Final typed boundary with exactly one independent-surface transition."""
    payload: Mapping[str, Any] | None = None
    terminal_error: BaseException | None = None
    terminal_operation = "TERMINAL_OUTER_GUARD"
    try:
        try:
            payload = _generic_projection_recovery_payload(
                states,
                original_operation_error=original_operation_error,
                compensation_error=compensation_error,
                compensation_status=compensation_status,
            )
        except BaseException as builder_error:
            try:
                payload = _terminal_recovery_payload_after_builder_failure(
                    states,
                    original_operation_error=original_operation_error,
                    compensation_error=compensation_error,
                    compensation_status=compensation_status,
                    builder_error=builder_error,
                )
            except BaseException as snapshot_error:
                try:
                    payload = {
                        "terminal_recovery_builder_failure": _safe_failure_payload(
                            "TERMINAL_RECOVERY_BUILDER", builder_error
                        ),
                        "terminal_snapshot_failure": _safe_failure_payload(
                            "TERMINAL_RECOVERY_SNAPSHOT", snapshot_error
                        ),
                        "original_operation_error": _exception_evidence_payload(
                            original_operation_error
                        ),
                        "outer_compensation_error": _exception_evidence_payload(
                            compensation_error
                        ),
                        "compensation_status": compensation_status,
                        "accumulated_evidence_is_monotonic": True,
                        "generic_recovery_recursive": False,
                    }
                except BaseException as fallback_payload_error:
                    terminal_error = fallback_payload_error
                    terminal_operation = "TERMINAL_RECOVERY_FALLBACK"
        if terminal_error is None:
            try:
                return _attach_projection_recovery_evidence(
                    compensation_error
                    if compensation_error is not None
                    else original_operation_error,
                    payload if payload is not None else {},
                    prior_errors=(original_operation_error, compensation_error),
                )
            except BaseException as attach_error:
                terminal_error = attach_error
                terminal_operation = "TERMINAL_ATTACH"
    except BaseException as outer_error:
        terminal_error = outer_error
        terminal_operation = "TERMINAL_OUTER_GUARD"

    if terminal_error is None:
        terminal_error = RuntimeError("terminal recovery reached impossible empty failure state")
    return _independent_terminal_surface(
        original_operation_error=original_operation_error,
        compensation_error=compensation_error,
        terminal_error=terminal_error,
        operation=terminal_operation,
        recovery_payload=payload,
    )


def _capture_projection_entry_state(
    *,
    writer_id: str,
    path: Path,
    source_payload: bytes,
    target_payload: bytes,
) -> _ProjectionEntryState:
    if path.is_symlink():
        raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id)
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except FileNotFoundError:
        return _ProjectionEntryState(
            writer_id=writer_id,
            path=path,
            existed=False,
            payload=None,
            mode=None,
            payload_sha256=None,
            source_payload=source_payload,
            target_payload=target_payload,
            target_sha256=_sha256_bytes(target_payload),
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id)
    return _ProjectionEntryState(
        writer_id=writer_id,
        path=path,
        existed=True,
        payload=raw,
        mode=stat.S_IMODE(metadata.st_mode),
        payload_sha256=_sha256_bytes(raw),
        source_payload=source_payload,
        target_payload=target_payload,
        target_sha256=_sha256_bytes(target_payload),
        entry_was_already_target=(raw == target_payload),
    )


def _compensate_projection_entries(
    states: list[_ProjectionEntryState],
    *,
    assert_effect_authority: Callable[[], Any] | None,
    original_operation_error: BaseException | None = None,
) -> None:
    """Restore only entries actually replaced by this invocation under a fresh guard."""
    for state in reversed(states):
        if not state.changed_by_invocation:
            continue
        path = state.path
        try:
            current = path.read_bytes()
        except FileNotFoundError as error:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_MISSING",
                    original_operation_error=original_operation_error,
                    compensation_error=error,
                ),
            ) from error
        except BaseException as error:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_OBSERVATION_UNKNOWN",
                    original_operation_error=original_operation_error,
                    compensation_error=error,
                ),
            ) from error
        if current != state.target_payload:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_DRIFT",
                    original_operation_error=original_operation_error,
                ),
            )
        if assert_effect_authority is None:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN",
                _projection_reconciliation_detail(
                    state,
                    guard_failure="NO_EFFECT_AUTHORITY_GUARD",
                    required_action="NO_WRITE_MANUAL_RECONCILIATION",
                    original_operation_error=original_operation_error,
                ),
            )
        try:
            assert_effect_authority()
        except BaseException as guard_error:
            guard_payload = _exception_evidence_payload(guard_error)
            if guard_payload is None:
                guard_payload = {}
            code = guard_payload.get("code")
            if code is None or code == "":
                code = _exception_type_name(guard_error)
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_COMPENSATION_FORBIDDEN",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=(code if isinstance(code, str) else _safe_scalar_text(code)),
                    required_action="NO_WRITE_MANUAL_RECONCILIATION",
                    original_operation_error=original_operation_error,
                    compensation_error=guard_error,
                ),
            ) from guard_error
        # Close the guard-to-effect compare window before the compensation mutation.
        try:
            current_after_guard = path.read_bytes()
        except FileNotFoundError as error:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_MISSING_AFTER_GUARD",
                    original_operation_error=original_operation_error,
                    compensation_error=error,
                ),
            ) from error
        except BaseException as error:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_OBSERVATION_UNKNOWN_AFTER_GUARD",
                    original_operation_error=original_operation_error,
                    compensation_error=error,
                ),
            ) from error
        if current_after_guard != state.target_payload:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                _projection_reconciliation_detail(
                    state,
                    guard_failure=None,
                    required_action="RECONCILE_CHANGED_ENTRY_DRIFT_AFTER_GUARD",
                    original_operation_error=original_operation_error,
                ),
            )
        if state.existed:
            if state.payload is None or state.mode is None:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        required_action="RECONCILE_INVALID_ENTRY_SNAPSHOT",
                        original_operation_error=original_operation_error,
                    ),
                )
            state.compensation_attempted = True
            try:
                restore_outcome = _atomic_write_exact(path, state.payload, state.mode)
            except (_AtomicWriteFailure, _AtomicWriteReportingFailure) as restore_error:
                state.restoration_write_outcome = restore_error.outcome
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        failed_operation=(
                            "COMPENSATION_" + (restore_error.outcome.failed_operation if restore_error.outcome.failed_operation is not None else "UNKNOWN")
                        ),
                        required_action="VERIFY_COMPENSATION_DURABILITY_BEFORE_RETRY",
                        original_operation_error=original_operation_error,
                        compensation_error=restore_error,
                    ),
                ) from restore_error
            state.restoration_write_outcome = restore_outcome
            restore_observation = _capture_projection_observation(state)
            restore_is_exact = (
                restore_observation["observation_complete"] == "YES"
                and restore_observation["path_exists"] == "YES"
                and restore_observation["sha256"] == state.payload_sha256
                and restore_observation["mode"] == state.mode
                and restore_observation["size"] == len(state.payload)
            )
            if not restore_is_exact:
                required_action = (
                    "RECONCILE_EXACT_RESTORE_FAILED"
                    if restore_observation["observation_complete"] == "YES"
                    else "RECONCILE_EXACT_RESTORE_OBSERVATION_UNKNOWN"
                )
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        required_action=required_action,
                        original_operation_error=original_operation_error,
                        reconciliation_observation=restore_observation,
                    ),
                )
        else:
            operation = "COMPENSATION_UNLINK"
            state.compensation_attempted = True
            state.absence_restoration_outcome = _AbsenceRestorationOutcome()
            try:
                path.unlink()
            except BaseException as restore_error:
                state.absence_restoration_outcome = replace(
                    state.absence_restoration_outcome,
                    unlink_status="FAIL",
                    unlink_failure=_atomic_failure_evidence(operation, restore_error),
                )
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        failed_operation=operation,
                        required_action="VERIFY_ABSENCE_COMPENSATION_DURABILITY_BEFORE_RETRY",
                        original_operation_error=original_operation_error,
                        compensation_error=restore_error,
                    ),
                ) from restore_error
            state.absence_restoration_outcome = replace(
                state.absence_restoration_outcome, unlink_status="SUCCESS"
            )
            try:
                directory_outcome = _fsync_directory(path.parent)
            except _DirectoryDurabilityFailure as restore_error:
                state.absence_restoration_outcome = replace(
                    state.absence_restoration_outcome,
                    directory_outcome=restore_error.outcome,
                )
                directory_failure = _first_non_none(
                    restore_error.outcome.open_failure,
                    restore_error.outcome.fsync_failure,
                    restore_error.outcome.close_failure,
                )
                failed = (
                    "COMPENSATION_" + directory_failure.operation
                    if directory_failure is not None
                    else "COMPENSATION_DIRECTORY_DURABILITY"
                )
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        failed_operation=failed,
                        operation_directory_outcome=restore_error.outcome,
                        required_action="VERIFY_ABSENCE_COMPENSATION_DURABILITY_BEFORE_RETRY",
                        original_operation_error=original_operation_error,
                        compensation_error=restore_error,
                    ),
                ) from restore_error
            except BaseException as restore_error:
                state.absence_restoration_outcome = replace(
                    state.absence_restoration_outcome,
                    directory_failure=_atomic_failure_evidence(
                        "COMPENSATION_DIRECTORY_FSYNC", restore_error
                    ),
                )
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        failed_operation="COMPENSATION_DIRECTORY_FSYNC",
                        required_action="VERIFY_ABSENCE_COMPENSATION_DURABILITY_BEFORE_RETRY",
                        original_operation_error=original_operation_error,
                        compensation_error=restore_error,
                    ),
                ) from restore_error
            state.absence_restoration_outcome = replace(
                state.absence_restoration_outcome, directory_outcome=directory_outcome
            )
            absence_observation = _capture_projection_observation(state)
            absence_restored = (
                absence_observation["observation_complete"] == "YES"
                and absence_observation["state"] == "ABSENT"
                and absence_observation["path_exists"] == "NO"
            )
            if not absence_restored:
                required_action = (
                    "RECONCILE_ABSENCE_RESTORE_FAILED"
                    if absence_observation["observation_complete"] == "YES"
                    else "RECONCILE_ABSENCE_RESTORE_OBSERVATION_UNKNOWN"
                )
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_RECOVERY_REQUIRED",
                    _projection_reconciliation_detail(
                        state,
                        guard_failure=None,
                        required_action=required_action,
                        original_operation_error=original_operation_error,
                        reconciliation_observation=absence_observation,
                    ),
                )


def _transition_authorized_projection(
    root: Path,
    *,
    from_build: str,
    to_build: str,
    operation_id: str,
    assert_effect_authority: Callable[[], Any] | None = None,
    expected_entry_payloads: Mapping[str, bytes] | None = None,
    validate_after_transition: Callable[[], Any] | None = None,
) -> Schema10AuthorizedProjectionEvidence:
    _validate_operation_id(operation_id)
    root_path = root.expanduser()
    try:
        root_lstat = root_path.lstat()
    except OSError as error:
        raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_ROOT_INVALID") from error
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_ROOT_INVALID")
    resolved = root_path.resolve(strict=True)
    states: list[_ProjectionEntryState] = []
    for writer_id in sorted(EXPECTED_WRITERS):
        path = resolved / f"{writer_id}.authorized.json"
        if path.is_symlink() or not path.is_file():
            # Capture absence explicitly even though the sealed production projection
            # cannot synthesize a missing authority entry.
            _capture_projection_entry_state(
                writer_id=writer_id,
                path=path,
                source_payload=b"",
                target_payload=b"",
            )
            raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id)
        raw = path.read_bytes()
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id) from error
        if not isinstance(document, dict) or raw != _authorized_document_bytes(document):
            raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_NONCANONICAL", writer_id)
        _validate_authorized_document(writer_id, document)
        build = document.get("global_writer_client_build")
        if build not in {from_build, to_build}:
            raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_CLIENT_BUILD_UNEXPECTED", writer_id)
        source_document = dict(document)
        source_document["global_writer_client_build"] = from_build
        target_document = dict(document)
        target_document["global_writer_client_build"] = to_build
        state = _capture_projection_entry_state(
            writer_id=writer_id,
            path=path,
            source_payload=_authorized_document_bytes(source_document),
            target_payload=_authorized_document_bytes(target_document),
        )
        if not state.existed or state.payload is None:
            raise ProductionSchema10OperationalError("SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id)
        expected = expected_entry_payloads.get(writer_id) if expected_entry_payloads is not None else None
        if expected_entry_payloads is not None and expected != state.payload:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_ENTRY_STATE_CHANGED", writer_id
            )
        if state.payload not in {state.source_payload, state.target_payload}:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_COMPARE_BEFORE_MISMATCH", writer_id
            )
        states.append(state)

    # Freeze all deterministic return evidence before the first possible file effect.
    # A serialization defect therefore cannot occur after destination mutation.
    expected_per_writer = [(state.writer_id, state.target_sha256) for state in states]
    identity_seed = {
        "operation_id": operation_id,
        "to_build": to_build,
        "files": expected_per_writer,
    }
    try:
        encoded_identity_seed = _canonical_json(identity_seed).encode("utf-8")
    except BaseException as serialization_error:
        failure = _safe_failure_payload(
            "PROJECTION_IDENTITY_SERIALIZATION", serialization_error
        )
        detail = _serialize_evidence_payload(
            {
                "operation_id": operation_id,
                "to_build": to_build,
                "files": expected_per_writer,
                "serialization_failure": failure,
                "required_reconciliation_action": "NO_WRITE_SERIALIZATION_FAILURE",
            },
            operation="PROJECTION_IDENTITY_SERIALIZATION_FAILSAFE",
            force_failsafe=True,
        )
        raise ProductionSchema10OperationalError(
            "SCHEMA10_AUTHORIZED_EVIDENCE_SERIALIZATION_FAILED", detail
        ) from serialization_error
    identity = "sha256:" + _sha256_bytes(encoded_identity_seed)

    try:
        for state in states:
            current = state.path.read_bytes()
            if current == state.target_payload:
                # This invocation did not mutate a pre-existing target entry.
                continue
            if current != state.source_payload:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_COMPARE_BEFORE_MISMATCH", state.writer_id
                )
            if assert_effect_authority is not None:
                assert_effect_authority()
                if state.path.read_bytes() != state.source_payload:
                    raise ProductionSchema10OperationalError(
                        "SCHEMA10_AUTHORIZED_COMPARE_BEFORE_MISMATCH", state.writer_id
                    )
            assert state.mode is not None
            _write_projection_entry(state, state.mode)
            if assert_effect_authority is not None:
                assert_effect_authority()
        observed_per_writer = []
        for state in states:
            current = state.path.read_bytes()
            if current != state.target_payload:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_POSTCONDITION_FAILED", state.writer_id
                )
            observed_per_writer.append((state.writer_id, _sha256_bytes(current)))
        if observed_per_writer != expected_per_writer:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_AUTHORIZED_POSTCONDITION_FAILED",
                "EVIDENCE_DIGEST_MISMATCH",
            )
        if validate_after_transition is not None:
            validate_after_transition()
    except BaseException as error:
        try:
            _compensate_projection_entries(
                states,
                assert_effect_authority=assert_effect_authority,
                original_operation_error=error,
            )
        except BaseException as compensation_error:
            surfaced = _surface_projection_recovery(
                states,
                original_operation_error=error,
                compensation_error=compensation_error,
                compensation_status="FAILED",
            )
            raise surfaced from error

        # Preserve an existing typed boundary/code, but make completed compensation
        # evidence queryable. Raw failures are converted to the sealed recovery type.
        if (
            isinstance(error, ProductionSchema10OperationalError)
            and not any(_state_has_recovery_evidence(state) for state in states)
        ):
            raise
        surfaced = _surface_projection_recovery(
            states,
            original_operation_error=error,
            compensation_error=None,
            compensation_status="SUCCEEDED",
        )
        if surfaced is error:
            raise
        raise surfaced from error

    return Schema10AuthorizedProjectionEvidence(
        operation_id, to_build, tuple(expected_per_writer), identity
    )


def _static_writer_identity(entry: DcsWriterInventoryEntry) -> tuple[str, ...]:
    stable = entry.stable_identity
    return stable[:6] + stable[7:]


class Schema10WriterTransition:
    """Sealed W01-W06 quiesce/materialization/recovery adapter for DL-85."""

    def __init__(self, operation_id: str) -> None:
        _validate_operation_id(operation_id)
        self.operation_id = operation_id
        self._authority = _LaunchdWriterAuthority(
            runtime_artifact_attestation=self._attest_artifact
        )
        self._original_token: _QuiescenceToken | None = None
        self._v05_token: _QuiescenceToken | None = None
        self._backup: Schema10BackupEvidence | None = None
        self._state = "INITIAL"

    def _require_exact_inventory(self, inventory: DcsWriterInventory, version: str) -> None:
        by_id = {entry.writer_id: entry for entry in inventory.entries}
        if set(by_id) != set(EXPECTED_WRITERS):
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_SET_INVALID")
        source = V04_SOURCE if version == V04_VERSION else V05_SOURCE
        expected_build = V04_CLIENT_BUILD if version == V04_VERSION else V05_CLIENT_BUILD
        for writer_id, entry in by_id.items():
            if entry.service_code != EXPECTED_WRITERS[writer_id]:
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_SERVICE_CODE_MISMATCH", writer_id)
            if (
                entry.product_build_commit != PRODUCTION_PRODUCT_COMMIT
                or entry.client.version != version
                or entry.client.source_commit != source
                or entry.client.build_identity != expected_build
            ):
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_CLIENT_IDENTITY_MISMATCH", writer_id)

    def quiesce(self) -> Schema10WriterQuiescenceEvidence:
        if self._state != "INITIAL":
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)
        inventory = self._authority.discover()
        self._require_exact_inventory(inventory, V04_VERSION)
        token = self._authority.quiesce(inventory)
        self._authority.verify_quiesced(token)
        self._original_token = token
        self._state = "QUIESCED_V04"
        classes = tuple((entry.writer_id, _entry_before_class(entry)) for entry in inventory.entries)
        order = tuple(
            entry.writer_id
            for entry in sorted(
                (entry for entry in inventory.entries if _entry_before_class(entry) in {"A", "B"}),
                key=lambda entry: (0 if _entry_before_class(entry) == "B" else 1, entry.writer_id),
            )
        )
        return Schema10WriterQuiescenceEvidence(
            self.operation_id,
            inventory.fingerprint,
            _stable_inventory_fingerprint(inventory.entries),
            classes,
            order,
        )

    def apply_v05_authorized_projection(self) -> Schema10AuthorizedProjectionEvidence:
        if self._state not in {"QUIESCED_V04", "AUTHORIZED_V05"} or self._original_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)
        if self._state == "QUIESCED_V04":
            self._authority.verify_quiesced(self._original_token)
        evidence = _transition_authorized_projection(
            CANONICAL_RUNTIME_IDENTITY_ROOT,
            from_build=V04_CLIENT_BUILD,
            to_build=V05_CLIENT_BUILD,
            operation_id=self.operation_id,
        )
        self._state = "AUTHORIZED_V05"
        return evidence

    def _attest_artifact(self, entry: DcsWriterInventoryEntry, schema_version: int) -> RuntimeArtifactAttestation:
        return _attest_schema9_10_runtime_artifact(entry, schema_version)

    def bind_installed_v05(self) -> Schema10WriterQuiescenceEvidence:
        if self._state not in {"AUTHORIZED_V05", "BOUND_V05"} or self._original_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)
        fresh = self._authority.discover()
        self._require_exact_inventory(fresh, V05_VERSION)
        if any(entry.state != "INACTIVE" or entry.load_state != "UNLOADED" or entry.enabled_state != "DISABLED" for entry in fresh.entries):
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_NOT_QUIESCED_AFTER_V05")
        original_by_id = {entry.writer_id: entry for entry in self._original_token.before.entries}
        fresh_by_id = {entry.writer_id: entry for entry in fresh.entries}
        if any(_static_writer_identity(fresh_by_id[w]) != _static_writer_identity(original_by_id[w]) for w in EXPECTED_WRITERS):
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_STATIC_IDENTITY_CHANGED")
        rebound_entries: list[DcsWriterInventoryEntry] = []
        for writer_id in sorted(EXPECTED_WRITERS):
            original = original_by_id[writer_id]
            current = fresh_by_id[writer_id]
            before_class = _entry_before_class(original)
            rebound = replace(
                current,
                state="ACTIVE" if before_class == "A" else "INACTIVE",
                pid=original.pid if before_class == "A" else None,
                before_class=before_class,
            )
            self._attest_artifact(rebound, SCHEMA10)
            rebound_entries.append(rebound)
        entries = tuple(rebound_entries)
        inventory = DcsWriterInventory(entries, _inventory_fingerprint(entries))
        token = _QuiescenceToken(
            before=inventory,
            quiesced_stable_identities=tuple(entry.stable_identity for entry in fresh.entries),
            before_classes=tuple((entry.writer_id, _entry_before_class(entry)) for entry in entries),
        )
        self._authority.verify_quiesced(token)
        self._v05_token = token
        self._state = "BOUND_V05"
        return Schema10WriterQuiescenceEvidence(
            self.operation_id,
            inventory.fingerprint,
            _stable_inventory_fingerprint(entries),
            token.before_classes,
            tuple(
                entry.writer_id
                for entry in sorted(
                    (entry for entry in entries if _entry_before_class(entry) in {"A", "B"}),
                    key=lambda entry: (0 if _entry_before_class(entry) == "B" else 1, entry.writer_id),
                )
            ),
        )

    def create_schema9_backup(self) -> Schema10BackupEvidence:
        if self._state == "BACKED_UP" and self._backup is not None:
            verify_schema9_to10_immutable_backup(self._backup)
            return self._backup
        if self._state != "BOUND_V05" or self._v05_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)
        self._authority.verify_quiesced(self._v05_token)
        evidence = create_schema9_to10_immutable_backup(self.operation_id)
        self._backup = evidence
        self._state = "BACKED_UP"
        return evidence

    def _assert_exact_v05_quiesced(self) -> None:
        if self._v05_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PREPARATION_REQUIRED")
        fresh = self._authority.discover()
        self._require_exact_inventory(fresh, V05_VERSION)
        if any(
            entry.state != "INACTIVE"
            or entry.load_state != "UNLOADED"
            or entry.enabled_state != "DISABLED"
            for entry in fresh.entries
        ):
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_NOT_QUIESCED_AFTER_V05")
        expected_stable = _stable_inventory_fingerprint(self._v05_token.before.entries)
        if _stable_inventory_fingerprint(fresh.entries) != expected_stable:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_STATIC_IDENTITY_CHANGED")
        self._authority.verify_quiesced(self._v05_token)

    def apply_exact_migration10(self, held: Schema10HeldW08) -> _SchemaState:
        """Cross 9 -> 10 only after exact v0.5 install/quiescence and backup proof."""
        if (
            self._state != "BACKED_UP"
            or self._v05_token is None
            or self._backup is None
        ):
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PREPARATION_REQUIRED")
        if (
            type(held) is not Schema10HeldW08
            or held.operation_id != self.operation_id
            or held.backup != self._backup
        ):
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PREPARATION_BINDING_MISMATCH")
        if held.schema_version != SCHEMA9:
            raise ProductionSchema10OperationalError("SCHEMA10_MIGRATION_PHASE_INVALID")
        held.assert_current()
        self._assert_exact_v05_quiesced()
        try:
            result = held._apply_exact_migration10(_seal=_MIGRATION_EXECUTION_SEAL)
        except BaseException:
            if held.schema_version == SCHEMA10:
                self._state = "MIGRATED_SCHEMA10"
            raise
        self._state = "MIGRATED_SCHEMA10"
        return result

    def _validate_restored(self, token: _QuiescenceToken, schema_version: int) -> DcsWriterInventory:
        observed = self._authority.verify_resumed(token)
        expected_classes = {entry.writer_id: _entry_before_class(entry) for entry in token.before.entries}
        observed_classes = {entry.writer_id: _entry_before_class(entry) for entry in observed.entries}
        if observed_classes != expected_classes:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_RESTORE_CLASS_MISMATCH")
        for entry in observed.entries:
            if not entry.client.supports_schema(schema_version):
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_RESTORE_SCHEMA_UNSUPPORTED", entry.writer_id)
            expected_active = expected_classes[entry.writer_id] == "A"
            if (entry.state == "ACTIVE") != expected_active:
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_RESTORE_STATE_MISMATCH", entry.writer_id)
        return observed

    def _schema10_restore_evidence(
        self, held: Schema10HeldW08, observed: DcsWriterInventory
    ) -> Schema10WriterRestoreEvidence:
        evidence = Schema10WriterRestoreEvidence(
            self.operation_id,
            SCHEMA10,
            observed.fingerprint,
            _stable_inventory_fingerprint(observed.entries),
            True,
            held.owner_id,
            held.owner_execution_id,
            held.fencing_token,
        )
        held._mark_writer_restore_proven(evidence)
        self._state = "RESTORED_SCHEMA10"
        return evidence

    def _is_exact_quiesced_v05_baseline(self) -> bool:
        if self._v05_token is None:
            return False
        try:
            fresh = self._authority.discover()
            self._require_exact_inventory(fresh, V05_VERSION)
        except BaseException:
            return False
        if any(
            entry.state != "INACTIVE"
            or entry.load_state != "UNLOADED"
            or entry.enabled_state != "DISABLED"
            for entry in fresh.entries
        ):
            return False
        return (
            _stable_inventory_fingerprint(fresh.entries)
            == _stable_inventory_fingerprint(self._v05_token.before.entries)
        )

    def restore_schema10_same_fence(self, held: Schema10HeldW08) -> Schema10WriterRestoreEvidence:
        if self._state not in {
            "MIGRATED_SCHEMA10",
            "SCHEMA10_RESTORE_RECONCILIATION_REQUIRED",
        } or self._v05_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)
        if type(held) is not Schema10HeldW08 or held.operation_id != self.operation_id:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_W08_BINDING_MISMATCH")
        if held.schema_version != SCHEMA10:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_RESTORE_REQUIRES_SCHEMA10")
        held.assert_current()

        if self._state == "SCHEMA10_RESTORE_RECONCILIATION_REQUIRED":
            # A prior call may have completed some or all launchd effects before failing.
            # First prove the observed state; never replay effects across an ambiguous state.
            try:
                observed = self._validate_restored(self._v05_token, SCHEMA10)
            except BaseException as reconcile_error:
                if not self._is_exact_quiesced_v05_baseline():
                    held.assert_current()
                    raise ProductionSchema10OperationalError(
                        "SCHEMA10_WRITER_RESTORE_PARTIAL_EFFECT_RECONCILIATION_REQUIRED",
                        type(reconcile_error).__name__,
                    ) from reconcile_error
                # The failed call had no durable restore effect. Re-enter from the exact
                # v0.5 quiesced baseline under the same held fence only.
                self._state = "MIGRATED_SCHEMA10"
            else:
                held.assert_current()
                return self._schema10_restore_evidence(held, observed)

        try:
            self._authority.resume_fenced(
                self._v05_token,
                schema_version=SCHEMA10,
                assert_current=held.assert_current,
                assert_event_guard=held.assert_event_guard,
            )
            held.assert_current()
            observed = self._validate_restored(self._v05_token, SCHEMA10)
            held.assert_current()
        except BaseException as error:
            self._state = "SCHEMA10_RESTORE_RECONCILIATION_REQUIRED"
            # No release call exists on this failure path; W08 remains durable. A
            # later call must reconcile the observed effect before any replay.
            raise ProductionSchema10OperationalError(
                "SCHEMA10_WRITER_RESTORE_FAILED_W08_RETAINED", type(error).__name__
            ) from error
        return self._schema10_restore_evidence(held, observed)

    def _capture_exact_v04_rollback_entry_state(self) -> Mapping[str, bytes]:
        """Resolve exact v0.4 startup bytes without consulting projection matching.

        A pre-schema10 rollback can legitimately enter here after the exact v0.4
        runtime has been restored while the authoritative projection still names
        v0.5. Calling discover() in that transient state is itself invalid, so this
        capture uses the production startup resolver and physical launchd evidence
        directly, then freezes the exact projection bytes for compare-before-write.
        """
        token = self._original_token
        if type(token) is not _QuiescenceToken:
            raise ProductionSchema10OperationalError(
                "SCHEMA10_WRITER_ROLLBACK_TOKEN_INVALID"
            )
        projection_payloads: dict[str, bytes] = {}
        seen: set[str] = set()
        for entry in token.before.entries:
            writer_id = entry.writer_id
            if writer_id not in EXPECTED_WRITERS or writer_id in seen:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_SET_INVALID", writer_id
                )
            seen.add(writer_id)
            if entry.plist_path is None or entry.authorized_identity_path is None:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_ENTRY_STATE_INVALID", writer_id
                )
            try:
                plist_bytes = entry.plist_path.read_bytes()
                document = plistlib.loads(plist_bytes)
            except (OSError, plistlib.InvalidFileException) as error:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_ENTRY_STATE_INVALID", writer_id
                ) from error
            if not isinstance(document, Mapping):
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_ENTRY_STATE_INVALID", writer_id
                )
            arguments = document.get("ProgramArguments")
            if (
                not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(value, str) or not value for value in arguments)
            ):
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_ENTRY_STATE_INVALID", writer_id
                )
            physical = self._authority._launch_state(entry.launchd_label, tuple(arguments))
            enabled = self._authority._enabled_state(entry.launchd_label)
            if (
                physical.runtime_state != "INACTIVE"
                or physical.load_state != "UNLOADED"
                or enabled != "DISABLED"
            ):
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_RUNTIME_NOT_QUIESCED", writer_id
                )
            startup = self._authority._resolve_inactive_startup_authority(
                document=document,
                writer_id=writer_id,
                label=entry.launchd_label,
            )
            if (
                startup.resolved_propertyai_source_commit != PRODUCTION_PRODUCT_COMMIT
                or startup.thin_client_version != V04_VERSION
                or startup.thin_client_build_id != V04_BUILD_ID
                or startup.thin_client_source_commit != V04_SOURCE
                or startup.thin_client_artifact_identity != f"source-commit:{V04_SOURCE}"
                or startup.client_build_identity != V04_CLIENT_BUILD
                or startup.supported_dcs_schema_versions != (6, 7, 8, 9)
            ):
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_CLIENT_IDENTITY_MISMATCH", writer_id
                )
            try:
                authorized_bytes = entry.authorized_identity_path.read_bytes()
                authorized = json.loads(authorized_bytes)
            except (OSError, json.JSONDecodeError) as error:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_FILE_INVALID", writer_id
                ) from error
            if (
                not isinstance(authorized, dict)
                or authorized_bytes != _authorized_document_bytes(authorized)
            ):
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_FILE_NONCANONICAL", writer_id
                )
            _validate_authorized_document(writer_id, authorized)
            if authorized.get("global_writer_client_build") not in {
                V04_CLIENT_BUILD,
                V05_CLIENT_BUILD,
            }:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_CLIENT_BUILD_UNEXPECTED", writer_id
                )
            # Re-read both surfaces to bind the capture to exact invocation-entry
            # bytes; drift between startup resolution and projection mutation fails.
            if entry.plist_path.read_bytes() != plist_bytes:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_STARTUP_AUTHORITY_CHANGED", writer_id
                )
            if entry.authorized_identity_path.read_bytes() != authorized_bytes:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_AUTHORIZED_ENTRY_STATE_CHANGED", writer_id
                )
            projection_payloads[writer_id] = authorized_bytes
        if seen != set(EXPECTED_WRITERS):
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_SET_INVALID")
        return projection_payloads

    def rollback_to_v04_before_schema10(
        self, held: Schema10HeldW08 | None = None
    ) -> Schema10WriterRestoreEvidence:
        if self._original_token is None:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_ROLLBACK_TOKEN_MISSING")
        if _read_schema_version(CANONICAL_DCS_PATH) != SCHEMA9:
            raise ProductionSchema10OperationalError("SCHEMA10_V04_ROLLBACK_REQUIRES_SCHEMA9")
        _inspect_schema(CANONICAL_DCS_PATH, SCHEMA9)
        if self._state not in {"AUTHORIZED_V05", "BOUND_V05", "BACKED_UP"}:
            raise ProductionSchema10OperationalError("SCHEMA10_WRITER_PHASE_INVALID", self._state)

        held_identity: tuple[str, str, int] | None = None
        if held is not None:
            if (
                type(held) is not Schema10HeldW08
                or held.operation_id != self.operation_id
                or held.schema_version != SCHEMA9
            ):
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_ROLLBACK_W08_MISMATCH")
            try:
                held_path = held._path.expanduser().resolve(strict=True)
                canonical_path = CANONICAL_DCS_PATH.expanduser().resolve(strict=True)
            except OSError as error:
                raise ProductionSchema10OperationalError(
                    "SCHEMA10_WRITER_ROLLBACK_W08_MISMATCH"
                ) from error
            if held_path != canonical_path:
                raise ProductionSchema10OperationalError("SCHEMA10_WRITER_ROLLBACK_W08_MISMATCH")
            held_identity = (held.owner_id, held.owner_execution_id, held.fencing_token)
            held.assert_current()
            held.assert_event_guard()

        # Capture exact invocation-entry runtime + projection state without calling
        # discover(): runtime v0.4 with projection v0.5 is a legitimate transient
        # rollback state, but authoritative discovery must never observe it.
        entry_projection = self._capture_exact_v04_rollback_entry_state()

        if held is None:
            baseline_events = self._global_event_cursor_free()

            def guard() -> int:
                _inspect_schema(CANONICAL_DCS_PATH, SCHEMA9)
                _require_w08_free(CANONICAL_DCS_PATH)
                if self._global_event_cursor_free() != baseline_events:
                    raise ProductionSchema10OperationalError(
                        "SCHEMA10_WRITER_FREE_GUARD_EVENT_CHANGED"
                    )
                return 0

            owner_id = owner_execution_id = None
            fence = None
        else:
            assert held_identity is not None

            def guard() -> int:
                if (held.owner_id, held.owner_execution_id, held.fencing_token) != held_identity:
                    raise ProductionSchema10OperationalError(
                        "SCHEMA10_WRITER_ROLLBACK_W08_MISMATCH"
                    )
                _inspect_schema(CANONICAL_DCS_PATH, SCHEMA9)
                fence_now = held.assert_current()
                held.assert_event_guard()
                return fence_now

            owner_id, owner_execution_id, fence = held_identity

        # Revalidate immediately before the first possible projection write.  The
        # projection helper repeats this guard before and after each file effect so
        # authority/event drift cannot be silently crossed by a multi-file rewrite.
        guard()
        def validate_aligned_v04() -> None:
            # This callback runs only after every projection entry is exact v0.4,
            # so the real Production discovery contract never observes mixed
            # runtime/projection identity. Any failure is compensated by the same
            # exact-entry, freshly guarded transition transaction.
            current = self._authority.discover()
            self._require_exact_inventory(current, V04_VERSION)
            self._authority.verify_quiesced(self._original_token)
            guard()

        _transition_authorized_projection(
            CANONICAL_RUNTIME_IDENTITY_ROOT,
            from_build=V05_CLIENT_BUILD,
            to_build=V04_CLIENT_BUILD,
            operation_id=self.operation_id,
            assert_effect_authority=guard,
            expected_entry_payloads=entry_projection,
            validate_after_transition=validate_aligned_v04,
        )
        guard()

        self._authority.resume_fenced(
            self._original_token,
            schema_version=SCHEMA9,
            assert_current=guard,
            assert_event_guard=guard,
        )
        observed = self._validate_restored(self._original_token, SCHEMA9)
        guard()

        self._state = "ROLLED_BACK_V04_SCHEMA9"
        evidence = Schema10WriterRestoreEvidence(
            self.operation_id,
            SCHEMA9,
            observed.fingerprint,
            _stable_inventory_fingerprint(observed.entries),
            True,
            owner_id,
            owner_execution_id,
            fence,
        )
        if held is not None:
            held._mark_writer_restore_proven(evidence)
        return evidence

    @staticmethod
    def _global_event_cursor_free() -> int:
        _require_w08_free(CANONICAL_DCS_PATH)
        connection = sqlite3.connect(f"file:{CANONICAL_DCS_PATH}?mode=ro", uri=True)
        try:
            row = connection.execute("SELECT max(event_seq) FROM global_production_writer_event").fetchone()
            return int(row[0] or 0)
        finally:
            connection.close()


def prepare_schema10_writer_transition(operation_id: str) -> Schema10WriterTransition:
    return Schema10WriterTransition(operation_id)


__all__ = [
    "CANONICAL_DCS_PATH",
    "CHANGE_ID",
    "DL85_CONTROL_DECISION_REF",
    "MIGRATION10_CHECKSUM",
    "MIGRATION10_NAME",
    "TERMINAL_EVIDENCE_MAX_BYTES",
    "ProductionSchema10OperationalError",
    "SCHEMA9_PROFILE",
    "SCHEMA10_PROFILE",
    "Schema10AuthorizedProjectionEvidence",
    "Schema10BackupEvidence",
    "Schema10HeldW08",
    "Schema10W08RebindEvidence",
    "Schema10WriterQuiescenceEvidence",
    "Schema10WriterRestoreEvidence",
    "Schema10WriterTransition",
    "V04_BUILD_ID",
    "V04_SHA256",
    "V04_SOURCE",
    "V04_VERSION",
    "V04_WHEEL",
    "V05_BUILD_ID",
    "V05_SHA256",
    "V05_SOURCE",
    "V05_VERSION",
    "V05_WHEEL",
    "acquire_schema9_w08",
    "create_schema9_to10_immutable_backup",
    "prepare_schema10_writer_transition",
    "verify_schema9_to10_immutable_backup",
]
