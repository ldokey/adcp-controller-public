"""Sealed Controller capability for a future Cleaner PostgreSQL cutover.

The module intentionally exposes no arbitrary SQL, launchd label, plist, or runtime
configuration mutation.  It composes the accepted W08 lease, the existing exact
launchd authority, and the canonical Cleaner PostgreSQL control policy.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol

from adcp.postgres_control import (
    CLEANER_DATABASE,
    CLEANER_DBA_ROLE,
    _canonical_cleaner_postgres_policy,
    _json_query,
    _run_psql,
)
from adcp.production_control import (
    DeploymentStep,
    ProductionMutationAuthority,
    revalidate_current_controlled_deployment_lease,
    run_controlled_deployment,
)
from adcp.production_schema10_operational import _attest_schema9_10_runtime_artifact
from adcp.production_dcs_v8_adoption import (
    DcsWriterInventory,
    DcsWriterInventoryEntry,
    _LaunchdWriterAuthority,
    _QuiescenceToken,
    _AUTHORIZED_THIN_STARTUP_V10,
    _entry_before_class,
    _parse_client_identity,
    _service_config_fingerprint,
)
from adcp.store.sqlite import ControlStore


_CLEANER_SCOPE = "CLEANER_SCHEDULING"
_REQUIRED_WRITERS = ("W06", "W01", "W03", "W04", "W05")
_OPTIONAL_WRITERS = ("W07",)
_FIXED_LABELS = {
    "W01": "com.propertyai.gmail-readonly",
    "W03": "com.propertyai.telegram-cleaner",
    "W04": "com.propertyai.cleaning-operations",
    "W05": "com.propertyai.cleaning-completion",
    "W06": "com.propertyai.health-monitor",
    "W07": "com.propertyai.cleaner-pg-outbox",
}
_RUNTIME_SOURCE = {
    "W01": Path("gmail_ingest/com.propertyai.gmail-readonly.plist"),
    "W03": Path("telegram_approval/com.propertyai.telegram-cleaner.plist"),
    "W06": Path("health_monitor/com.propertyai.health-monitor.plist"),
    "W07": Path("propertyai_core/runtime/com.propertyai.cleaner-pg-outbox.plist"),
}
_AUTHORITY_ENV = "PROPERTYAI_CLEANER_AUTHORITY"
_INGRESS_ENV = "PROPERTYAI_CLEANER_PG_INGRESS_ENABLED"
_EPOCH_ENV = "PROPERTYAI_CLEANER_AUTHORITY_EPOCH"
_TOPOLOGY_ENV = "PROPERTYAI_CLEANER_RUNTIME_TOPOLOGY"
_CUTOVER_SENTINEL = "REPLACE_AT_CUTOVER"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_DL98_PRODUCT_COMMIT = "ebd7f756e35610c3ce5a8e33e71fc610e3c84f00"
_TELEGRAM_T1_W07_PRODUCT_COMMIT = "f90303f95cf4df772c7a89dd90cf589fa6620f27"
_TELEGRAM_T1_W07_PRODUCT_TREE = "b808f01b67d381a99480084e20d5bc4996df71ad"
_TELEGRAM_T1_W07_BUILD_IDENTITY_SHA256 = (
    "49869435dd22bf611e671ee7965e6c4a80e03d566cb785a7eba3181a3bdde439"
)
_W07_PRIOR_PRODUCT_COMMIT = "9e50c7306752961f18ee4d0ef0ecb5a7f0dea6c7"
_W07_PRIOR_PRODUCT_TREE = "fcae62d0796db47953d191867fa3f04afced4219"
_W07_CURRENT_PRODUCT_COMMIT = "1ab6715b413d5befe1e93c7628efe49f9d6e76c2"
_W07_CURRENT_PRODUCT_TREE = "fcd421e8c3055fdc1786b2037d54a69d7b819644"
_W07_ACCEPTED_PREDECESSOR_TREES = {
    _W07_PRIOR_PRODUCT_COMMIT: _W07_PRIOR_PRODUCT_TREE,
    _W07_CURRENT_PRODUCT_COMMIT: _W07_CURRENT_PRODUCT_TREE,
}
_POST_CUTOVER_ACTIVE_WRITERS = ("W03", "W07")
_POST_CUTOVER_SCHEDULED_WRITERS = ("W01", "W06")
_POST_CUTOVER_RETIRED_WRITERS = ("W04", "W05")
_W07_SERVICE_CODE = "PROPERTYAI_W07_CORE_OUTBOX_REPLAY"
_POST_CUTOVER_SERVICE_CODES = {
    "W01": "PROPERTYAI_W01_GMAIL_INGEST_PROJECTION",
    "W03": "PROPERTYAI_W03_CLEANER_TELEGRAM_MUTATION",
    "W06": "PROPERTYAI_W06_HEALTH_RECOVERY_MAINTENANCE",
    "W07": _W07_SERVICE_CODE,
}
_STARTUP_PRODUCT_ROOT_ENV = "ADCP_GLOBAL_WRITER_AUTHORIZED_PRODUCT_ROOT"
_STARTUP_PRODUCT_COMMIT_ENV = "ADCP_GLOBAL_WRITER_EXPECTED_PRODUCT_COMMIT"
_DCS_PATH_ENV = "PROPERTYAI_GLOBAL_WRITER_DCS_PATH"
_RUNTIME_IDENTITY_PATH_ENV = "PROPERTYAI_GLOBAL_WRITER_RUNTIME_IDENTITY_PATH"
_AUTHORIZED_IDENTITY_PATH_ENV = "PROPERTYAI_GLOBAL_WRITER_AUTHORIZED_IDENTITY_PATH"
_W07_CREDENTIAL_ENV = "PROPERTYAI_CLEANER_POSTGRES_WORKER_CREDENTIAL_REF"
_W07_CREDENTIAL_REF = "cleaner-prod/worker.pgpass"
_SEALED_STARTUP_ENV = frozenset(
    {
        _STARTUP_PRODUCT_ROOT_ENV,
        _STARTUP_PRODUCT_COMMIT_ENV,
        _DCS_PATH_ENV,
        _RUNTIME_IDENTITY_PATH_ENV,
        _AUTHORIZED_IDENTITY_PATH_ENV,
        _W07_CREDENTIAL_ENV,
    }
)


class CleanerCutoverControlError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _wire_w07_runtime_artifact_attestor(authority: Any) -> None:
    """Seal the accepted fresh schema9/10 attestor onto the real W07 authority only."""

    if type(authority) is not _LaunchdWriterAuthority:
        return
    provider = authority.runtime_artifact_attestation
    if provider is None:
        authority.runtime_artifact_attestation = _attest_schema9_10_runtime_artifact
        return
    if provider is not _attest_schema9_10_runtime_artifact:
        raise CleanerCutoverControlError("CLEANER_W07_RUNTIME_ARTIFACT_ATTESTOR_INVALID")


class CleanerAuthorityMode(str, Enum):
    LEGACY = "LEGACY"
    POSTGRES = "POSTGRES"


class CleanerRuntimeTopology(str, Enum):
    PRE_CUTOVER = "PRE_CUTOVER"
    POST_CUTOVER_PG = "POST_CUTOVER_PG"


@dataclass(frozen=True)
class CleanerRuntimeTuple:
    authority: CleanerAuthorityMode
    pg_ingress_enabled: bool
    authority_epoch: int
    topology: CleanerRuntimeTopology

    def __post_init__(self) -> None:
        if isinstance(self.authority_epoch, bool) or not isinstance(self.authority_epoch, int) or self.authority_epoch < 0:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_EPOCH_INVALID")
        valid = (
            self.authority is CleanerAuthorityMode.LEGACY
            and self.pg_ingress_enabled is False
            and self.topology is CleanerRuntimeTopology.PRE_CUTOVER
        ) or (
            self.authority is CleanerAuthorityMode.POSTGRES
            and self.pg_ingress_enabled is True
            and self.topology is CleanerRuntimeTopology.POST_CUTOVER_PG
        )
        if not valid:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_TUPLE_INVALID")


@dataclass(frozen=True)
class CleanerEpochTransition:
    current_epoch: int
    target_epoch: int

    def __post_init__(self) -> None:
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (self.current_epoch, self.target_epoch)):
            raise CleanerCutoverControlError("CLEANER_EPOCH_VALUE_INVALID")
        if self.target_epoch != self.current_epoch + 1:
            raise CleanerCutoverControlError("CLEANER_EPOCH_SUCCESSOR_REQUIRED")


@dataclass(frozen=True)
class CleanerCutbackReconciliationInventory:
    """Factual reconciliation summary required before future LEGACY eligibility.

    The counts are evidence summaries, not authority. ``inventory_evidence_ref``
    must identify the separately-reviewed exact inventory containing the factual
    PG/external effect identities.  A zero count is valid when the inventory
    factually proves absence.
    """

    postgres_business_commits_since_ponr: int
    command_receipts: int
    outbox_pending: int
    outbox_claimed: int
    outbox_completed: int
    outbox_failed: int
    outbox_pending_reconciliation: int
    notion_effects: int
    calendar_effects: int
    telegram_effects: int
    inventory_evidence_ref: str

    def __post_init__(self) -> None:
        counts = (
            self.postgres_business_commits_since_ponr,
            self.command_receipts,
            self.outbox_pending,
            self.outbox_claimed,
            self.outbox_completed,
            self.outbox_failed,
            self.outbox_pending_reconciliation,
            self.notion_effects,
            self.calendar_effects,
            self.telegram_effects,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise CleanerCutoverControlError("CLEANER_CUTBACK_INVENTORY_COUNT_INVALID")
        if (
            not self.inventory_evidence_ref
            or self.inventory_evidence_ref != self.inventory_evidence_ref.strip()
        ):
            raise CleanerCutoverControlError("CLEANER_CUTBACK_INVENTORY_EVIDENCE_REF_REQUIRED")


@dataclass(frozen=True)
class CleanerEmergencyCutbackRequest:
    """Source-only sealed inputs for a future, separately-authorized cutback gate."""

    request_id: str
    current_epoch: int
    target_epoch: int
    control_authority_ref: str
    reconciliation_acceptance_ref: str
    reconciliation_accepted: bool
    inventory: CleanerCutbackReconciliationInventory

    def __post_init__(self) -> None:
        for value, code in (
            (self.request_id, "CLEANER_CUTBACK_REQUEST_ID_REQUIRED"),
            (self.control_authority_ref, "CLEANER_CUTBACK_CONTROL_AUTHORITY_REQUIRED"),
            (
                self.reconciliation_acceptance_ref,
                "CLEANER_CUTBACK_RECONCILIATION_ACCEPTANCE_REF_REQUIRED",
            ),
        ):
            if not value or value != value.strip():
                raise CleanerCutoverControlError(code)
        # DL-79: decrement, reuse, and skip-forward are all rejected here.
        CleanerEpochTransition(self.current_epoch, self.target_epoch)
        if self.reconciliation_accepted is not True:
            raise CleanerCutoverControlError("CLEANER_CUTBACK_RECONCILIATION_NOT_ACCEPTED")


@dataclass(frozen=True)
class CleanerEmergencyCutbackSourcePrepared:
    """Pure source capability receipt; never performs a Production effect."""

    request_id: str
    authority_scope: str
    current_epoch: int
    target_epoch: int
    control_authority_ref: str
    reconciliation_acceptance_ref: str
    inventory_evidence_ref: str
    reconciliation_accepted: bool = True
    writer_fence_required: bool = True
    legacy_reactivation_allowed: bool = False
    automatic_legacy_failback: bool = False
    separate_production_effect_gate_required: bool = True


def prepare_cleaner_emergency_cutback_source(
    request: CleanerEmergencyCutbackRequest,
) -> CleanerEmergencyCutbackSourcePrepared:
    """Validate DL-79 source prerequisites without fencing or reactivating anything.

    This function deliberately has no store, W08, DCS, launchd, PostgreSQL, or
    epoch-port parameter.  It cannot mutate an epoch or runtime.  Its only output
    states that a *future* Production gate must still fence writers, revalidate
    authority, reconcile the exact inventory, advance N->N+1, and separately
    authorize LEGACY reactivation.  Epoch advancement alone therefore never makes
    cutback eligible.
    """

    # Re-run the successor check at the source boundary even though the frozen
    # request validated it at construction time.
    CleanerEpochTransition(request.current_epoch, request.target_epoch)
    if request.reconciliation_accepted is not True:
        raise CleanerCutoverControlError("CLEANER_CUTBACK_RECONCILIATION_NOT_ACCEPTED")
    return CleanerEmergencyCutbackSourcePrepared(
        request_id=request.request_id,
        authority_scope=_CLEANER_SCOPE,
        current_epoch=request.current_epoch,
        target_epoch=request.target_epoch,
        control_authority_ref=request.control_authority_ref,
        reconciliation_acceptance_ref=request.reconciliation_acceptance_ref,
        inventory_evidence_ref=request.inventory.inventory_evidence_ref,
    )


@dataclass(frozen=True)
class CleanerRuntimeSnapshot:
    inventory: DcsWriterInventory
    selected_writer_ids: tuple[str, ...]
    prior_plists: tuple[tuple[str, Path, bytes, str], ...]
    w07_authorized_identity_path: Path | None = None
    prior_w07_authorized_identity: bytes | None = None
    prior_w07_authorized_identity_sha256: str | None = None
    prior_authorized_identities: tuple[tuple[str, Path, bytes | None, str | None], ...] = ()


@dataclass(frozen=True)
class CleanerCutoverPrepared:
    current_epoch: int
    target_epoch: int
    runtime_tuple: CleanerRuntimeTuple
    selected_writer_ids: tuple[str, ...]
    plist_sha256: tuple[tuple[str, str], ...]
    autonomous_business_execution_effective: bool = False


@dataclass(frozen=True)
class CleanerCutoverActivated:
    current_epoch: int
    target_epoch: int
    runtime_tuple: CleanerRuntimeTuple
    selected_writer_ids: tuple[str, ...]
    plist_sha256: tuple[tuple[str, str], ...]
    w07_authorized_identity_sha256: str
    physical_readback: Mapping[str, Any]
    first_business_command_executed: bool = False


@dataclass(frozen=True)
class CleanerCutoverReconciliationEvidence:
    operation_id: str
    stage: str
    current_epoch: int
    target_epoch: int
    epoch_advanced: bool
    selected_writer_ids: tuple[str, ...]
    prior_plist_sha256: tuple[tuple[str, str], ...]
    safe_quiescence_attempted: bool
    safe_quiescence_confirmed: bool
    failure_type: str


class CleanerCutoverReconciliationRequired(CleanerCutoverControlError):
    def __init__(self, evidence: CleanerCutoverReconciliationEvidence) -> None:
        self.evidence = evidence
        super().__init__(
            "CLEANER_CUTOVER_RECONCILIATION_REQUIRED",
            f"stage={evidence.stage},epoch={evidence.current_epoch}->{evidence.target_epoch}",
        )


class CleanerEpochPort(Protocol):
    def read_current(self) -> int: ...
    def advance(self, transition: CleanerEpochTransition) -> int: ...


class CleanerRuntimePort(Protocol):
    def validate_activation_binding(self) -> None: ...
    def quiesce_for_cutover(self) -> CleanerRuntimeSnapshot: ...
    def materialize_postgres_runtime(self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple) -> tuple[tuple[str, str], ...]: ...
    def restore_pre_cutover(self, snapshot: CleanerRuntimeSnapshot) -> None: ...
    def readback_prepared(self, runtime: CleanerRuntimeTuple) -> Mapping[str, Any]: ...
    def materialize_w07_authorized_identity(self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple) -> str: ...
    def activate_postgres_runtime(self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple, w07_authorized_identity_sha256: str) -> Mapping[str, Any]: ...
    def readback_effective(self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple, w07_authorized_identity_sha256: str) -> Mapping[str, Any]: ...
    def quiesce_after_failed_activation(self, snapshot: CleanerRuntimeSnapshot) -> None: ...
    def reconcile_post_cas_staged(self, runtime: CleanerRuntimeTuple) -> tuple[CleanerRuntimeSnapshot, str]: ...


class CanonicalCleanerEpochPort:
    """Fixed canonical Cleaner epoch reader/CAS updater; no caller SQL or scope."""

    def __init__(self, *, policy=None) -> None:
        self._policy = _canonical_cleaner_postgres_policy() if policy is None else policy

    def read_current(self) -> int:
        row = _json_query(
            self._policy,
            database=CLEANER_DATABASE,
            sql=(
                "SELECT json_build_object('scope', scope_code, 'epoch', current_epoch)::text "
                "FROM propertyai.authority_epoch WHERE scope_code = 'CLEANER_SCHEDULING'"
            ),
        )
        if (
            row.get("scope") != _CLEANER_SCOPE
            or type(row.get("epoch")) is not int
            or row["epoch"] < 0
        ):
            raise CleanerCutoverControlError("CLEANER_EPOCH_READBACK_INVALID")
        return int(row["epoch"])

    def advance(self, transition: CleanerEpochTransition) -> int:
        if type(transition) is not CleanerEpochTransition:
            raise CleanerCutoverControlError("CLEANER_EPOCH_TRANSITION_INVALID")
        current_epoch, target_epoch = transition.current_epoch, transition.target_epoch
        if type(current_epoch) is not int or type(target_epoch) is not int:
            raise CleanerCutoverControlError("CLEANER_EPOCH_VALUE_INVALID")
        transition = CleanerEpochTransition(current_epoch, target_epoch)
        # A mutation is legal only as one effect inside the accepted W08 runner.
        revalidate_current_controlled_deployment_lease()
        current = self.read_current()
        if current != transition.current_epoch:
            raise CleanerCutoverControlError("CLEANER_EPOCH_CURRENT_DRIFT")
        sql = (
            "WITH updated AS ("
            " UPDATE propertyai.authority_epoch"
            f" SET current_epoch = {transition.target_epoch}, updated_at = clock_timestamp()"
            " WHERE scope_code = 'CLEANER_SCHEDULING'"
            f" AND current_epoch = {transition.current_epoch}"
            " RETURNING scope_code, current_epoch"
            ") SELECT json_build_object('scope', scope_code, 'epoch', current_epoch)::text FROM updated;\n"
        ).encode("utf-8")
        result = _run_psql(
            self._policy,
            database=CLEANER_DATABASE,
            execution_role=CLEANER_DBA_ROLE,
            stdin_sql=sql,
        )
        if result.exit_status != 0:
            raise CleanerCutoverControlError("CLEANER_EPOCH_CAS_FAILED")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise CleanerCutoverControlError("CLEANER_EPOCH_CAS_NOT_APPLIED")
        try:
            row = json.loads(lines[0])
        except json.JSONDecodeError as error:
            raise CleanerCutoverControlError("CLEANER_EPOCH_CAS_READBACK_INVALID") from error
        if (
            not isinstance(row, dict)
            or type(row.get("epoch")) is not int
            or row != {"scope": _CLEANER_SCOPE, "epoch": transition.target_epoch}
        ):
            raise CleanerCutoverControlError("CLEANER_EPOCH_CAS_READBACK_INVALID")
        if self.read_current() != transition.target_epoch:
            raise CleanerCutoverControlError("CLEANER_EPOCH_CAS_READBACK_INVALID")
        return transition.target_epoch


class LaunchdCleanerRuntimePort:
    """Cleaner-only adapter over the accepted exact launchd writer authority.

    All writer IDs and labels are fixed in this module. W02 is never selected.
    Runtime plist installation happens only while selected services are disabled
    and unloaded, so intermediate filesystem bytes are never accepted effective
    Cleaner configurations.
    """

    def __init__(
        self,
        authority: _LaunchdWriterAuthority,
        *,
        product_release_root: str | Path,
        product_commit: str,
        runtime_environment: Mapping[str, Mapping[str, str]],
        dcs_schema_version: int,
    ) -> None:
        _wire_w07_runtime_artifact_attestor(authority)
        self.authority = authority
        self.product_release_root = Path(product_release_root).resolve(strict=True)
        if not self.product_release_root.is_dir() or _HEX40.fullmatch(product_commit) is None:
            raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_BINDING_INVALID")
        try:
            head = subprocess.run(
                ["git", "-C", os.fspath(self.product_release_root), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            tracked_status = subprocess.run(
                ["git", "-C", os.fspath(self.product_release_root), "status", "--porcelain", "--untracked-files=no"],
                check=True, capture_output=True, text=True, timeout=10,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_GIT_UNRESOLVED") from error
        if head != product_commit or tracked_status:
            raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_BINDING_DRIFT")
        self.product_commit = product_commit
        if dcs_schema_version not in {8, 9, 10}:
            raise CleanerCutoverControlError("CLEANER_DCS_SCHEMA_VERSION_UNSUPPORTED")
        self.dcs_schema_version = dcs_schema_version
        self.runtime_environment = {key: dict(value) for key, value in runtime_environment.items()}
        unexpected = set(self.runtime_environment) - set(_RUNTIME_SOURCE)
        if unexpected:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_WRITER_NOT_APPROVED", ",".join(sorted(unexpected)))

    def _inventory_entry(self, inventory: DcsWriterInventory, writer_id: str) -> DcsWriterInventoryEntry:
        matches = [entry for entry in inventory.entries if entry.writer_id == writer_id]
        if len(matches) != 1 or matches[0].launchd_label != _FIXED_LABELS[writer_id]:
            raise CleanerCutoverControlError("CLEANER_WRITER_IDENTITY_INVALID", writer_id)
        return matches[0]

    def validate_activation_binding(self) -> None:
        accepted_w07_product = self.product_commit in {
            _DL98_PRODUCT_COMMIT,
            _TELEGRAM_T1_W07_PRODUCT_COMMIT,
        }
        if not accepted_w07_product or self.dcs_schema_version != 10:
            raise CleanerCutoverControlError("CLEANER_W07_RUNTIME_AUTHORITY_REQUIRED")
        try:
            commit_tree = subprocess.run(
                [
                    "git", "-C", os.fspath(self.product_release_root),
                    "rev-parse", "HEAD", "HEAD^{tree}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.splitlines()
            tracked_status = subprocess.run(
                [
                    "git", "-C", os.fspath(self.product_release_root), "status",
                    "--porcelain", "--untracked-files=no",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_GIT_UNRESOLVED") from error
        if not commit_tree or commit_tree[0] != self.product_commit or tracked_status:
            raise CleanerCutoverControlError("CLEANER_PRODUCT_SOURCE_BINDING_DRIFT")
        if self.product_commit == _TELEGRAM_T1_W07_PRODUCT_COMMIT:
            if commit_tree != [
                _TELEGRAM_T1_W07_PRODUCT_COMMIT,
                _TELEGRAM_T1_W07_PRODUCT_TREE,
            ]:
                raise CleanerCutoverControlError("CLEANER_W07_PRODUCT_TREE_DRIFT")
            identity_path = (
                self.product_release_root
                / "propertyai_core"
                / "_global_writer_build_identity.py"
            )
            if (
                identity_path.is_symlink()
                or not identity_path.is_file()
                or hashlib.sha256(identity_path.read_bytes()).hexdigest()
                != _TELEGRAM_T1_W07_BUILD_IDENTITY_SHA256
            ):
                raise CleanerCutoverControlError("CLEANER_W07_BUILD_IDENTITY_DRIFT")

    def _fence_one(self, entry: DcsWriterInventoryEntry) -> None:
        revalidate_current_controlled_deployment_lease()
        _path, arguments = self.authority._service_definition_for_entry(entry)
        target = f"gui/{self.authority.uid}/{entry.launchd_label}"
        if self.authority._launchctl("disable", target).returncode != 0:
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_FAILED", entry.writer_id)
        if self.authority._enabled_state(entry.launchd_label) != "DISABLED":
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_READBACK_FAILED", entry.writer_id)
        revalidate_current_controlled_deployment_lease()
        result = self.authority._launchctl("bootout", target)
        if result.returncode not in {0, 113}:
            # launchd may reject bootout for an already absent service. The
            # command error is never proof of success: require fresh physical
            # absence and then the normal stable proof (including process scan).
            revalidate_current_controlled_deployment_lease()
            observed = self.authority._launch_state(entry.launchd_label, arguments)
            if (
                observed.runtime_state != "INACTIVE"
                or observed.load_state != "UNLOADED"
                or observed.pid_field is not None
                or observed.pid_liveness
                or observed.pid_service_ownership
                or not observed.pid_probe_resolved
            ):
                raise CleanerCutoverControlError("CLEANER_WRITER_BOOTOUT_FAILED", entry.writer_id)
        self.authority._wait_for_stable_nonrunning(
            ((entry, arguments),),
            deadline=__import__("time").monotonic() + 10.0,
            assert_current=revalidate_current_controlled_deployment_lease,
        )

    def quiesce_for_cutover(self) -> CleanerRuntimeSnapshot:
        inventory = self.authority.discover()
        by_id = {entry.writer_id: entry for entry in inventory.entries}
        missing = [writer for writer in _REQUIRED_WRITERS if writer not in by_id]
        if missing:
            raise CleanerCutoverControlError("CLEANER_REQUIRED_WRITER_MISSING", ",".join(missing))
        selected = _REQUIRED_WRITERS + tuple(writer for writer in _OPTIONAL_WRITERS if writer in by_id)
        prior: list[tuple[str, Path, bytes, str]] = []
        for writer in selected:
            entry = self._inventory_entry(inventory, writer)
            path, _args = self.authority._service_definition_for_entry(entry)
            raw = path.read_bytes()
            prior.append((writer, path, raw, hashlib.sha256(raw).hexdigest()))
        authorized_prior: list[tuple[str, Path, bytes | None, str | None]] = []
        for writer in (*_POST_CUTOVER_SCHEDULED_WRITERS, *_POST_CUTOVER_ACTIVE_WRITERS):
            path = self.authority.runtime_root / f"{writer}.authorized.json"
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_TARGET_INVALID", writer)
            raw = path.read_bytes() if path.exists() else None
            authorized_prior.append(
                (writer, path, raw, hashlib.sha256(raw).hexdigest() if raw is not None else None)
            )
        w07_prior = next(item for item in authorized_prior if item[0] == "W07")
        snapshot = CleanerRuntimeSnapshot(
            inventory,
            tuple(selected),
            tuple(prior),
            w07_prior[1],
            w07_prior[2],
            w07_prior[3],
            tuple(authorized_prior),
        )
        try:
            # Explicit architectural order: W06 fence first, then Cleaner business/effect writers.
            self._fence_one(by_id["W06"])
            for writer in selected:
                if writer != "W06":
                    self._fence_one(by_id[writer])
            after = self.authority.discover()
            after_by_id = {entry.writer_id: entry for entry in after.entries}
            for writer in selected:
                entry = after_by_id.get(writer)
                if entry is None or entry.state != "INACTIVE" or entry.load_state != "UNLOADED" or entry.enabled_state != "DISABLED":
                    raise CleanerCutoverControlError("CLEANER_WRITER_QUIESCENCE_READBACK_FAILED", writer)
            # W02 must remain outside this transition; its stable identity and state may not change.
            before_w02 = by_id.get("W02")
            after_w02 = after_by_id.get("W02")
            if before_w02 is not None and (after_w02 is None or after_w02.stable_identity != before_w02.stable_identity or after_w02.state != before_w02.state):
                raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")
            return snapshot
        except BaseException:
            # Any partial physical fence is reverted under the still-current W08 lease.
            self.restore_pre_cutover(snapshot)
            raise

    @staticmethod
    def _atomic_replace(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.dl77-", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _render(self, writer_id: str, runtime: CleanerRuntimeTuple) -> bytes:
        source = (self.product_release_root / _RUNTIME_SOURCE[writer_id]).resolve(strict=True)
        if self.product_release_root not in source.parents:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_SOURCE_OUTSIDE_PRODUCT", writer_id)
        try:
            doc = plistlib.loads(source.read_bytes())
        except (OSError, plistlib.InvalidFileException) as error:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_SOURCE_PLIST_INVALID", writer_id) from error
        if not isinstance(doc, dict) or doc.get("Label") != _FIXED_LABELS[writer_id]:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_SOURCE_LABEL_INVALID", writer_id)
        env = doc.get("EnvironmentVariables")
        if not isinstance(env, dict):
            env = {}
        supplied = self.runtime_environment.get(writer_id, {})
        if set(supplied) & _SEALED_STARTUP_ENV:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_SEALED_ENV_OVERRIDE", writer_id)
        unexpected = set(supplied) - set(env)
        if unexpected:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_ENV_KEY_NOT_APPROVED", f"{writer_id}:{sorted(unexpected)}")
        env.update(supplied)
        if writer_id == "W07":
            if env.get(_W07_CREDENTIAL_ENV) != _W07_CREDENTIAL_REF or any(
                key.startswith("PROPERTYAI_CLEANER_POSTGRES_APP_") for key in env
            ):
                raise CleanerCutoverControlError("CLEANER_W07_WORKER_CREDENTIAL_BINDING_INVALID")
        if writer_id in {"W01", "W03"}:
            env[_AUTHORITY_ENV] = runtime.authority.value
            env[_INGRESS_ENV] = "true" if runtime.pg_ingress_enabled else "false"
            env[_EPOCH_ENV] = str(runtime.authority_epoch)
        if writer_id in {"W06", "W07"}:
            if _TOPOLOGY_ENV not in env:
                raise CleanerCutoverControlError("CLEANER_RUNTIME_TOPOLOGY_KEY_MISSING", writer_id)
            env[_TOPOLOGY_ENV] = runtime.topology.value
        env[_STARTUP_PRODUCT_ROOT_ENV] = os.fspath(self.product_release_root)
        env[_STARTUP_PRODUCT_COMMIT_ENV] = self.product_commit
        env[_DCS_PATH_ENV] = os.fspath(self.authority.dcs_path)
        env[_RUNTIME_IDENTITY_PATH_ENV] = os.fspath(
            self.authority.runtime_root / f"{writer_id}.runtime.json"
        )
        env[_AUTHORIZED_IDENTITY_PATH_ENV] = os.fspath(
            self.authority.runtime_root / f"{writer_id}.authorized.json"
        )
        if any(isinstance(v, str) and _CUTOVER_SENTINEL in v for v in env.values()):
            raise CleanerCutoverControlError("CLEANER_RUNTIME_PLACEHOLDER_REMAINS", writer_id)
        rendered = dict(doc)
        rendered["WorkingDirectory"] = os.fspath(self.product_release_root)
        rendered["EnvironmentVariables"] = env
        return plistlib.dumps(rendered, fmt=plistlib.FMT_XML, sort_keys=True)

    def materialize_postgres_runtime(self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple) -> tuple[tuple[str, str], ...]:
        if runtime.authority is not CleanerAuthorityMode.POSTGRES:
            raise CleanerCutoverControlError("CLEANER_POSTGRES_RUNTIME_REQUIRED")
        prior_paths = {writer: path for writer, path, _raw, _sha in snapshot.prior_plists}
        outputs: list[tuple[str, str]] = []
        # W01/W03 are materialized while both remain physically non-effective.
        for writer in ("W01", "W03", "W06"):
            revalidate_current_controlled_deployment_lease()
            payload = self._render(writer, runtime)
            path = prior_paths[writer]
            self._atomic_replace(path, payload)
            if path.read_bytes() != payload:
                raise CleanerCutoverControlError("CLEANER_RUNTIME_PLIST_READBACK_DRIFT", writer)
            outputs.append((writer, hashlib.sha256(payload).hexdigest()))
        # W07 may be absent from the pre-cutover DCS inventory, but a future
        # POST_CUTOVER_PG topology is not executable without an accepted exact runtime source.
        w07_source = self.product_release_root / _RUNTIME_SOURCE["W07"]
        if not w07_source.is_file():
            raise CleanerCutoverControlError("CLEANER_W07_RUNTIME_SOURCE_MISSING")
        target = self.authority.launch_agents_root / f"{_FIXED_LABELS['W07']}.plist"
        if "W07" not in snapshot.selected_writer_ids and target.exists():
            raise CleanerCutoverControlError("CLEANER_W07_UNMANAGED_RUNTIME_TARGET_PRESENT")
        # A brand-new label has no entry in ``launchctl print-disabled``.  Register
        # the fixed W07 label as disabled before its plist becomes discoverable;
        # strict inventory must never infer an absent override as either state.
        revalidate_current_controlled_deployment_lease()
        launch_target = f"gui/{self.authority.uid}/{_FIXED_LABELS['W07']}"
        if self.authority._launchctl("disable", launch_target).returncode != 0:
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_FAILED", "W07")
        if self.authority._enabled_state(_FIXED_LABELS["W07"]) != "DISABLED":
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_READBACK_FAILED", "W07")
        payload = self._render("W07", runtime)
        self._atomic_replace(target, payload)
        if target.read_bytes() != payload:
            raise CleanerCutoverControlError("CLEANER_RUNTIME_PLIST_READBACK_DRIFT", "W07")
        outputs.append(("W07", hashlib.sha256(payload).hexdigest()))
        return tuple(outputs)

    def reconcile_post_cas_staged(
        self, runtime: CleanerRuntimeTuple
    ) -> tuple[CleanerRuntimeSnapshot, str]:
        """Rebind one exact post-CAS staged DL-98 state for forward activation.

        This recovery never advances or restores an epoch and accepts only the
        fixed Product/DCS10 PostgreSQL tuple.  It exists for the narrow case in
        which CAS and staging completed but activation did not begin.
        """
        if (
            self.product_commit != _DL98_PRODUCT_COMMIT
            or self.dcs_schema_version != 10
            or runtime
            != CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES,
                True,
                2,
                CleanerRuntimeTopology.POST_CUTOVER_PG,
            )
        ):
            raise CleanerCutoverControlError("CLEANER_DL98_POST_CAS_RECOVERY_TUPLE_INVALID")
        revalidate_current_controlled_deployment_lease()
        target = self.authority.launch_agents_root / f"{_FIXED_LABELS['W07']}.plist"
        if not target.is_file() or target.is_symlink():
            raise CleanerCutoverControlError("CLEANER_POST_CAS_STAGED_W07_MISSING")
        launch_target = f"gui/{self.authority.uid}/{_FIXED_LABELS['W07']}"
        if self.authority._launchctl("disable", launch_target).returncode != 0:
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_FAILED", "W07")
        if self.authority._enabled_state(_FIXED_LABELS["W07"]) != "DISABLED":
            raise CleanerCutoverControlError("CLEANER_WRITER_DISABLE_READBACK_FAILED", "W07")

        observed = self.authority.discover()
        by_id = {entry.writer_id: entry for entry in observed.entries}
        if len(by_id) != len(observed.entries) or set(by_id) != {
            "W01", "W02", "W03", "W04", "W05", "W06", "W07"
        }:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_WRITER_SET_INVALID")
        for writer in ("W01", "W03", "W04", "W05", "W06", "W07"):
            entry = by_id[writer]
            if (entry.state, entry.load_state, entry.enabled_state) != (
                "INACTIVE", "UNLOADED", "DISABLED"
            ):
                raise CleanerCutoverControlError(
                    "CLEANER_POST_CAS_RECOVERY_NOT_QUIESCED", writer
                )
        w02 = by_id["W02"]
        if (w02.state, w02.load_state, w02.enabled_state) != (
            "ACTIVE", "LOADED", "ENABLED"
        ):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")

        def exact_bytes(path: Path, code: str) -> tuple[bytes, str]:
            if path.is_symlink() or not path.is_file():
                raise CleanerCutoverControlError(code, path.name)
            raw = path.read_bytes()
            return raw, hashlib.sha256(raw).hexdigest()

        prior_plists_list = []
        for writer in ("W06", "W01", "W03", "W04", "W05", "W07"):
            path = self.authority.launch_agents_root / f"{_FIXED_LABELS[writer]}.plist"
            raw, sha = exact_bytes(path, "CLEANER_POST_CAS_STAGED_PLIST_INVALID")
            prior_plists_list.append((writer, path, raw, sha))
        prior_plists = tuple(prior_plists_list)
        authorized_list = []
        for writer in ("W01", "W06", "W03", "W07"):
            path = self.authority.runtime_root / f"{writer}.authorized.json"
            raw, sha = exact_bytes(path, "CLEANER_POST_CAS_STAGED_AUTHORITY_INVALID")
            authorized_list.append((writer, path, raw, sha))
        authorized = tuple(authorized_list)
        snapshot = CleanerRuntimeSnapshot(
            observed,
            ("W06", "W01", "W03", "W04", "W05", "W07"),
            prior_plists,
            self.authority.runtime_root / "W07.authorized.json",
            authorized[-1][2],
            authorized[-1][3],
            authorized,
        )
        self.readback_prepared(runtime)
        return snapshot, str(authorized[-1][3])

    def restore_pre_cutover(self, snapshot: CleanerRuntimeSnapshot) -> None:
        """Restore exact pre-PONR plist bytes and physical launchd topology under W08.

        Epoch is deliberately NOT decremented or reused.  A/B/C physical before-classes
        are restored by the accepted launchd authority; W02 remains outside the transition.
        """
        for writer, path, raw, expected_sha in snapshot.prior_plists:
            revalidate_current_controlled_deployment_lease()
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                raise CleanerCutoverControlError("CLEANER_PRE_PONR_SNAPSHOT_CORRUPT", writer)
            self._atomic_replace(path, raw)
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
                raise CleanerCutoverControlError("CLEANER_PRE_PONR_RESTORE_READBACK_DRIFT", writer)

        for writer, path, raw, expected_sha in snapshot.prior_authorized_identities:
            revalidate_current_controlled_deployment_lease()
            if raw is None:
                if path.exists():
                    path.unlink()
                continue
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_SNAPSHOT_CORRUPT", writer)
            self._atomic_replace(path, raw)
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha:
                raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_RESTORE_DRIFT", writer)

        # A newly staged W07 file did not exist in the accepted PRE topology. Remove only
        # that exact managed target; an unmanaged pre-existing target is rejected earlier.
        if "W07" not in snapshot.selected_writer_ids:
            target = self.authority.launch_agents_root / f"{_FIXED_LABELS['W07']}.plist"
            if target.exists():
                revalidate_current_controlled_deployment_lease()
                target.unlink()

        before_by_id = {entry.writer_id: entry for entry in snapshot.inventory.entries}
        selected_entries = tuple(before_by_id[writer] for writer in snapshot.selected_writer_ids)
        selected_inventory = DcsWriterInventory(
            selected_entries,
            hashlib.sha256(
                json.dumps(
                    [entry.stable_identity for entry in selected_entries],
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        token = _QuiescenceToken(
            before=selected_inventory,
            quiesced_stable_identities=tuple(entry.stable_identity for entry in selected_entries),
            before_classes=tuple((entry.writer_id, _entry_before_class(entry)) for entry in selected_entries),
        )
        self.authority.resume_fenced(
            token,
            schema_version=self.dcs_schema_version,
            assert_current=revalidate_current_controlled_deployment_lease,
            assert_event_guard=revalidate_current_controlled_deployment_lease,
        )
        revalidate_current_controlled_deployment_lease()
        observed = self.authority.discover()
        observed_by_id = {entry.writer_id: entry for entry in observed.entries}
        for expected in selected_entries:
            actual = observed_by_id.get(expected.writer_id)
            if (
                actual is None
                or actual.stable_identity != expected.stable_identity
                or _entry_before_class(actual) != _entry_before_class(expected)
            ):
                raise CleanerCutoverControlError(
                    "CLEANER_PRE_PONR_TOPOLOGY_RESTORE_FAILED", expected.writer_id
                )
        before_w02 = before_by_id.get("W02")
        after_w02 = observed_by_id.get("W02")
        if before_w02 is not None and (
            after_w02 is None
            or after_w02.stable_identity != before_w02.stable_identity
            or after_w02.state != before_w02.state
        ):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")

    def readback_prepared(self, runtime: CleanerRuntimeTuple) -> Mapping[str, Any]:
        values: dict[str, Any] = {"runtime": runtime, "writers": {}, "physical": {}}
        prepared_docs: dict[str, Mapping[str, Any]] = {}
        for writer in ("W01", "W03", "W06", "W07"):
            path = self.authority.launch_agents_root / f"{_FIXED_LABELS[writer]}.plist"
            if not path.exists():
                # POST_CUTOVER_PG is not executable without the required W07 worker.
                raise CleanerCutoverControlError("CLEANER_PREPARED_PLIST_MISSING", writer)
            try:
                doc = plistlib.loads(path.read_bytes())
            except (OSError, plistlib.InvalidFileException) as error:
                raise CleanerCutoverControlError("CLEANER_PREPARED_PLIST_INVALID", writer) from error
            env = doc.get("EnvironmentVariables") if isinstance(doc, dict) else None
            if not isinstance(env, Mapping):
                raise CleanerCutoverControlError("CLEANER_PREPARED_PLIST_INVALID", writer)
            if writer in {"W01", "W03"} and (
                env.get(_AUTHORITY_ENV) != runtime.authority.value
                or env.get(_INGRESS_ENV) != ("true" if runtime.pg_ingress_enabled else "false")
                or env.get(_EPOCH_ENV) != str(runtime.authority_epoch)
            ):
                raise CleanerCutoverControlError("CLEANER_PREPARED_RUNTIME_TUPLE_DRIFT", writer)
            if writer in {"W06", "W07"} and env.get(_TOPOLOGY_ENV) != runtime.topology.value:
                raise CleanerCutoverControlError("CLEANER_PREPARED_TOPOLOGY_DRIFT", writer)
            if writer == "W07" and env.get(_AUTHORITY_ENV) != CleanerAuthorityMode.POSTGRES.value:
                raise CleanerCutoverControlError("CLEANER_PREPARED_W07_AUTHORITY_DRIFT")
            if self.product_commit == _DL98_PRODUCT_COMMIT and self.dcs_schema_version == 10:
                expected_startup = self._expected_startup_environment(writer)
                if any(env.get(key) != value for key, value in expected_startup.items()):
                    raise CleanerCutoverControlError("CLEANER_PREPARED_STARTUP_AUTHORITY_DRIFT", writer)
            if any(isinstance(value, str) and _CUTOVER_SENTINEL in value for value in env.values()):
                raise CleanerCutoverControlError("CLEANER_PREPARED_RUNTIME_PLACEHOLDER_REMAINS", writer)
            prepared_docs[writer] = doc
            values["writers"][writer] = hashlib.sha256(path.read_bytes()).hexdigest()

        # PREPARED means bytes are staged while every cutover-relevant process is
        # still physically quiesced.  Plist/env claims are not physical authority.
        try:
            inventory = self.authority.discover()
        except BaseException as error:
            raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_DISCOVERY_FAILED") from error
        by_id: dict[str, DcsWriterInventoryEntry] = {}
        for entry in inventory.entries:
            if entry.writer_id in by_id:
                raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_WRITER_DUPLICATE", entry.writer_id)
            by_id[entry.writer_id] = entry

        def require_quiesced(writer: str, *, state: str, load_state: str, enabled_state: str) -> None:
            if state != "INACTIVE" or load_state != "UNLOADED" or enabled_state != "DISABLED":
                raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_TOPOLOGY_DRIFT", writer)
            values["physical"][writer] = {
                "state": state, "load_state": load_state, "enabled_state": enabled_state
            }

        # W01/W03/W04/W05/W06 are pre-existing DCS-managed writers.  W02 is
        # deliberately excluded and therefore neither required nor interpreted here.
        for writer in ("W01", "W03", "W04", "W05", "W06"):
            entry = by_id.get(writer)
            if entry is None or entry.launchd_label != _FIXED_LABELS[writer]:
                raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_WRITER_MISSING", writer)
            require_quiesced(
                writer,
                state=entry.state,
                load_state=entry.load_state,
                enabled_state=entry.enabled_state,
            )

        # W07 may be newly staged and intentionally absent from the pre-cutover DCS
        # inventory.  Read it with the same accepted launchd state primitives instead
        # of inventing a new DCS registration or writer authority model.
        w07_entry = by_id.get("W07")
        if w07_entry is not None:
            if w07_entry.launchd_label != _FIXED_LABELS["W07"]:
                raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_WRITER_MISSING", "W07")
            require_quiesced(
                "W07",
                state=w07_entry.state,
                load_state=w07_entry.load_state,
                enabled_state=w07_entry.enabled_state,
            )
        else:
            arguments = prepared_docs["W07"].get("ProgramArguments")
            if (
                not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(value, str) or not value for value in arguments)
            ):
                raise CleanerCutoverControlError("CLEANER_PREPARED_PLIST_INVALID", "W07")
            try:
                launch_state = self.authority._launch_state(_FIXED_LABELS["W07"], tuple(arguments))
                enabled_state = self.authority._enabled_state(_FIXED_LABELS["W07"])
            except BaseException as error:
                raise CleanerCutoverControlError("CLEANER_PREPARED_PHYSICAL_DISCOVERY_FAILED", "W07") from error
            require_quiesced(
                "W07",
                state=launch_state.runtime_state,
                load_state=launch_state.load_state,
                enabled_state=enabled_state,
            )
        return values

    def _expected_startup_environment(self, writer: str) -> Mapping[str, str]:
        return {
            _STARTUP_PRODUCT_ROOT_ENV: os.fspath(self.product_release_root),
            _STARTUP_PRODUCT_COMMIT_ENV: self.product_commit,
            _DCS_PATH_ENV: os.fspath(self.authority.dcs_path),
            _RUNTIME_IDENTITY_PATH_ENV: os.fspath(
                self.authority.runtime_root / f"{writer}.runtime.json"
            ),
            _AUTHORIZED_IDENTITY_PATH_ENV: os.fspath(
                self.authority.runtime_root / f"{writer}.authorized.json"
            ),
        }

    def _authorized_identity_payload(self, writer: str) -> bytes:
        accepted_product = self.product_commit == _DL98_PRODUCT_COMMIT or (
            writer == "W07" and self.product_commit == _TELEGRAM_T1_W07_PRODUCT_COMMIT
        )
        if writer not in _POST_CUTOVER_SERVICE_CODES or not accepted_product:
            raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_BINDING_INVALID", writer)
        artifact = f"source-commit:{self.product_commit}"
        document = {
            "authorized_at": None,
            "config_artifact_identity": None,
            "global_writer_client_build": _AUTHORIZED_THIN_STARTUP_V10.client_build_identity,
            "product_build_commit": self.product_commit,
            "product_build_identity": (
                f"product:PropertyAI@g{self.product_commit[:12]}|source={self.product_commit}"
                f"|artifact={artifact}"
            ),
            "schema_version": 2,
            "service_code": _POST_CUTOVER_SERVICE_CODES[writer],
            "source_root_or_artifact_identity": artifact,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def materialize_w07_authorized_identity(
        self, snapshot: CleanerRuntimeSnapshot, runtime: CleanerRuntimeTuple
    ) -> str:
        """Stage only the four fixed post-cutover startup identities under W08.

        W01/W03/W06 must move to the same Product identity as newly introduced
        W07; otherwise inactive startup attestation would correctly reject the
        integrated runtime before activation.
        """
        if (
            self.product_commit != _DL98_PRODUCT_COMMIT
            or self.dcs_schema_version != 10
            or runtime.authority is not CleanerAuthorityMode.POSTGRES
            or runtime.pg_ingress_enabled is not True
            or runtime.topology is not CleanerRuntimeTopology.POST_CUTOVER_PG
        ):
            raise CleanerCutoverControlError("CLEANER_DL98_RUNTIME_AUTHORITY_REQUIRED")
        snap_by_id = {writer: (path, raw, sha) for writer, path, raw, sha in snapshot.prior_authorized_identities}
        if set(snap_by_id) != set(_POST_CUTOVER_SERVICE_CODES):
            raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_SNAPSHOT_INCOMPLETE")
        hashes: dict[str, str] = {}
        for writer in (*_POST_CUTOVER_SCHEDULED_WRITERS, *_POST_CUTOVER_ACTIVE_WRITERS):
            revalidate_current_controlled_deployment_lease()
            path, _raw, _sha = snap_by_id[writer]
            expected_path = self.authority.runtime_root / f"{writer}.authorized.json"
            if path != expected_path or path.is_symlink():
                raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_TARGET_INVALID", writer)
            payload = self._authorized_identity_payload(writer)
            self._atomic_replace(path, payload)
            if path.read_bytes() != payload or (path.stat().st_mode & 0o777) != 0o600:
                raise CleanerCutoverControlError("CLEANER_AUTHORIZED_IDENTITY_READBACK_DRIFT", writer)
            hashes[writer] = hashlib.sha256(payload).hexdigest()
        return hashes["W07"]

    @staticmethod
    def _postcutover_entry(entry: DcsWriterInventoryEntry, *, active: bool) -> DcsWriterInventoryEntry:
        # ``state`` and ``before_class`` select the fixed resume target.  Keep the
        # factual pre-start physical fields so thin artifact attestation cannot
        # mistake a not-yet-started writer for a live incarnation.
        return replace(
            entry,
            state="ACTIVE" if active else "INACTIVE",
            before_class="A" if active else "B",
        )

    def activate_postgres_runtime(
        self,
        snapshot: CleanerRuntimeSnapshot,
        runtime: CleanerRuntimeTuple,
        w07_authorized_identity_sha256: str,
    ) -> Mapping[str, Any]:
        if self.product_commit != _DL98_PRODUCT_COMMIT or self.dcs_schema_version != 10:
            raise CleanerCutoverControlError("CLEANER_DL98_RUNTIME_AUTHORITY_REQUIRED")
        self.readback_prepared(runtime)
        observed = self.authority.discover()
        by_id = {entry.writer_id: entry for entry in observed.entries}
        expected_ids = {entry.writer_id for entry in snapshot.inventory.entries} | {"W07"}
        if len(by_id) != len(observed.entries) or set(by_id) != expected_ids:
            raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_WRITER_INVENTORY_DRIFT")
        desired_entries: list[DcsWriterInventoryEntry] = []
        for writer in (*_POST_CUTOVER_ACTIVE_WRITERS, *_POST_CUTOVER_SCHEDULED_WRITERS):
            entry = by_id.get(writer)
            if (
                entry is None
                or entry.launchd_label != _FIXED_LABELS[writer]
                or entry.product_build_commit != self.product_commit
                or entry.state != "INACTIVE"
                or entry.load_state != "UNLOADED"
                or entry.enabled_state != "DISABLED"
            ):
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_STARTUP_IDENTITY_INVALID", writer)
            self.authority._require_restore_client_compatible(entry, 10)
            desired_entries.append(
                self._postcutover_entry(entry, active=writer in _POST_CUTOVER_ACTIVE_WRITERS)
            )
        for writer in _POST_CUTOVER_RETIRED_WRITERS:
            entry = by_id.get(writer)
            if entry is None or (entry.state, entry.load_state, entry.enabled_state) != (
                "INACTIVE", "UNLOADED", "DISABLED"
            ):
                raise CleanerCutoverControlError("CLEANER_RETIRED_WRITER_EFFECTIVE", writer)
        desired_inventory = DcsWriterInventory(
            tuple(desired_entries),
            hashlib.sha256(
                json.dumps(
                    [entry.stable_identity for entry in desired_entries], separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest(),
        )
        token = _QuiescenceToken(
            before=desired_inventory,
            quiesced_stable_identities=tuple(entry.stable_identity for entry in desired_entries),
            before_classes=tuple(
                (entry.writer_id, "A" if entry.writer_id in _POST_CUTOVER_ACTIVE_WRITERS else "B")
                for entry in desired_entries
            ),
        )
        self.authority.resume_fenced(
            token,
            schema_version=10,
            assert_current=revalidate_current_controlled_deployment_lease,
            assert_event_guard=revalidate_current_controlled_deployment_lease,
        )
        active_desired = tuple(
            entry for entry in desired_entries if entry.writer_id in _POST_CUTOVER_ACTIVE_WRITERS
        )
        stabilized = self.authority._wait_for_stable_active_resume(
            active_desired, deadline=time.monotonic() + 15.0
        )
        if set(stabilized) != set(_POST_CUTOVER_ACTIVE_WRITERS):
            raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_ACTIVE_HEALTH_INVALID")
        for writer in stabilized:
            self.authority._active_resume_pending.pop(writer, None)
        return self.readback_effective(snapshot, runtime, w07_authorized_identity_sha256)

    def readback_effective(
        self,
        snapshot: CleanerRuntimeSnapshot,
        runtime: CleanerRuntimeTuple,
        w07_authorized_identity_sha256: str,
    ) -> Mapping[str, Any]:
        if runtime != CleanerRuntimeTuple(
            CleanerAuthorityMode.POSTGRES,
            True,
            runtime.authority_epoch,
            CleanerRuntimeTopology.POST_CUTOVER_PG,
        ):
            raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_RUNTIME_TUPLE_INVALID")
        runtime_documents: dict[str, str] = {}
        for writer in ("W01", "W03", "W06", "W07"):
            path = self.authority.launch_agents_root / f"{_FIXED_LABELS[writer]}.plist"
            try:
                raw = path.read_bytes()
                document = plistlib.loads(raw)
            except (OSError, plistlib.InvalidFileException) as error:
                raise CleanerCutoverControlError(
                    "CLEANER_POST_CUTOVER_RUNTIME_DOCUMENT_INVALID", writer
                ) from error
            environment = document.get("EnvironmentVariables") if isinstance(document, Mapping) else None
            if (
                not isinstance(environment, Mapping)
                or document.get("WorkingDirectory") != os.fspath(self.product_release_root)
                or any(
                    environment.get(key) != value
                    for key, value in self._expected_startup_environment(writer).items()
                )
                or any(
                    isinstance(value, str) and _CUTOVER_SENTINEL in value
                    for value in environment.values()
                )
            ):
                raise CleanerCutoverControlError(
                    "CLEANER_POST_CUTOVER_RUNTIME_DOCUMENT_DRIFT", writer
                )
            if writer in {"W01", "W03"} and (
                environment.get(_AUTHORITY_ENV) != CleanerAuthorityMode.POSTGRES.value
                or environment.get(_INGRESS_ENV) != "true"
                or environment.get(_EPOCH_ENV) != str(runtime.authority_epoch)
            ):
                raise CleanerCutoverControlError(
                    "CLEANER_POST_CUTOVER_RUNTIME_TUPLE_DRIFT", writer
                )
            if writer in {"W06", "W07"} and (
                environment.get(_TOPOLOGY_ENV) != CleanerRuntimeTopology.POST_CUTOVER_PG.value
            ):
                raise CleanerCutoverControlError(
                    "CLEANER_POST_CUTOVER_TOPOLOGY_DRIFT", writer
                )
            if writer == "W07" and environment.get(_AUTHORITY_ENV) != CleanerAuthorityMode.POSTGRES.value:
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_W07_AUTHORITY_DRIFT")
            runtime_documents[writer] = hashlib.sha256(raw).hexdigest()
        w07_authorized = self.authority.runtime_root / "W07.authorized.json"
        if (
            not w07_authorized.is_file()
            or w07_authorized.is_symlink()
            or hashlib.sha256(w07_authorized.read_bytes()).hexdigest()
            != w07_authorized_identity_sha256
        ):
            raise CleanerCutoverControlError("CLEANER_W07_AUTHORIZED_IDENTITY_DRIFT")
        observed = self.authority.discover()
        by_id = {entry.writer_id: entry for entry in observed.entries}
        expected_ids = {entry.writer_id for entry in snapshot.inventory.entries} | {"W07"}
        if len(by_id) != len(observed.entries) or set(by_id) != expected_ids:
            raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_WRITER_INVENTORY_DRIFT")
        physical: dict[str, Any] = {}
        for writer in (*_POST_CUTOVER_ACTIVE_WRITERS, *_POST_CUTOVER_SCHEDULED_WRITERS):
            entry = by_id[writer]
            expected = (
                ("ACTIVE", "LOADED", "ENABLED")
                if writer in _POST_CUTOVER_ACTIVE_WRITERS
                else ("INACTIVE", "LOADED", "ENABLED")
            )
            if (
                (entry.state, entry.load_state, entry.enabled_state) != expected
                or entry.product_build_commit != self.product_commit
                or entry.client.build_identity != _AUTHORIZED_THIN_STARTUP_V10.client_build_identity
            ):
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_PHYSICAL_READBACK_INVALID", writer)
            self.authority._require_restore_client_compatible(entry, 10)
            physical[writer] = {
                "state": entry.state,
                "load_state": entry.load_state,
                "enabled_state": entry.enabled_state,
                "stable_identity": entry.stable_identity,
            }
        for writer in _POST_CUTOVER_RETIRED_WRITERS:
            entry = by_id[writer]
            if (entry.state, entry.load_state, entry.enabled_state) != (
                "INACTIVE", "UNLOADED", "DISABLED"
            ):
                raise CleanerCutoverControlError("CLEANER_RETIRED_WRITER_EFFECTIVE", writer)
            physical[writer] = {
                "state": entry.state,
                "load_state": entry.load_state,
                "enabled_state": entry.enabled_state,
                "stable_identity": entry.stable_identity,
            }
        before_w02 = {entry.writer_id: entry for entry in snapshot.inventory.entries}.get("W02")
        after_w02 = by_id.get("W02")
        if before_w02 is not None and (
            after_w02 is None
            or after_w02.stable_identity != before_w02.stable_identity
            or (after_w02.state, after_w02.load_state, after_w02.enabled_state)
            != (before_w02.state, before_w02.load_state, before_w02.enabled_state)
        ):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")
        return {
            "runtime": runtime,
            "product_commit": self.product_commit,
            "dcs_schema_version": self.dcs_schema_version,
            "w07_authorized_identity_sha256": w07_authorized_identity_sha256,
            "runtime_document_sha256": tuple(sorted(runtime_documents.items())),
            "physical": physical,
            "first_business_command_executed": False,
        }

    def quiesce_after_failed_activation(self, snapshot: CleanerRuntimeSnapshot) -> None:
        """Leave the successor epoch safe and non-effective; never restore old authority."""
        # Snapshot may predate staged plists. Rebind current exact startup bytes
        # without depending on a restart-loop service being physically healthy.
        for writer in ("W06", "W01", "W03", "W07", "W04", "W05"):
            entry = self._bind_quiescence_definition(writer)
            self._fence_one(entry)
        after = self.authority.discover()
        after_by_id = {entry.writer_id: entry for entry in after.entries}
        for writer in ("W01", "W03", "W04", "W05", "W06", "W07"):
            entry = after_by_id.get(writer)
            if entry is None or (entry.state, entry.load_state, entry.enabled_state) != (
                "INACTIVE", "UNLOADED", "DISABLED"
            ):
                raise CleanerCutoverControlError("CLEANER_RECONCILIATION_QUIESCENCE_FAILED", writer)
        before_w02 = {entry.writer_id: entry for entry in snapshot.inventory.entries}.get("W02")
        after_w02 = after_by_id.get("W02")
        if before_w02 is not None and (
            after_w02 is None or after_w02.stable_identity != before_w02.stable_identity
        ):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")

    def _bind_quiescence_definition(self, writer: str) -> DcsWriterInventoryEntry:
        """Resolve exact startup/service bytes solely for stopping, never activation."""
        labels = {**_FIXED_LABELS, "W02": "com.propertyai.telegram-ops"}
        if writer not in labels:
            raise CleanerCutoverControlError("CLEANER_WRITER_IDENTITY_INVALID", writer)
        label = labels[writer]
        path = self.authority.launch_agents_root / f"{label}.plist"
        if path.is_symlink() or not path.is_file():
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_DEFINITION_INVALID", writer)
        raw = path.read_bytes()
        doc = plistlib.loads(raw)
        env = doc.get("EnvironmentVariables", {})
        args = doc.get("ProgramArguments")
        if (doc.get("Label") != label or not isinstance(args, list) or not args
            or any(not isinstance(arg, str) or not arg for arg in args)
            or env.get(_DCS_PATH_ENV) != os.fspath(self.authority.dcs_path)
            or env.get(_RUNTIME_IDENTITY_PATH_ENV) != os.fspath(self.authority.runtime_root / f"{writer}.runtime.json")
            or env.get(_AUTHORIZED_IDENTITY_PATH_ENV) != os.fspath(self.authority.runtime_root / f"{writer}.authorized.json")):
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_DEFINITION_INVALID", writer)
        authorized_path = self.authority.runtime_root / f"{writer}.authorized.json"
        if authorized_path.is_symlink() or not authorized_path.is_file():
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_AUTHORITY_INVALID", writer)
        authorized_raw = authorized_path.read_bytes()
        authorized = json.loads(authorized_raw)
        service = authorized.get("service_code", "")
        if not isinstance(service, str) or not service.startswith(f"PROPERTYAI_{writer}_"):
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_AUTHORITY_INVALID", writer)
        startup = self.authority._resolve_inactive_startup_authority(
            document=doc, writer_id=writer, label=label
        )
        if not self.authority._startup_matches_authorized(startup, authorized, service):
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_AUTHORITY_INVALID", writer)
        if writer in _RUNTIME_SOURCE and (
            startup.resolved_propertyai_source_commit != self.product_commit
            or any(env.get(key) != value for key, value in self._expected_startup_environment(writer).items())
        ):
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_PRODUCT_DRIFT", writer)
        if path.read_bytes() != raw or authorized_path.read_bytes() != authorized_raw:
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_DEFINITION_DRIFT", writer)
        source = startup.resolved_propertyai_source_commit
        return DcsWriterInventoryEntry(
            writer_id=writer, launchd_label=label, service_code=service,
            runtime_identity_path=self.authority.runtime_root / f"{writer}.runtime.json",
            authorized_identity_path=authorized_path, pid=None,
            process_incarnation_id="QUIESCENCE_DEFINITION_ONLY", product_build_commit=source,
            product_build_identity=str(authorized.get("product_build_identity")),
            source_root_or_artifact_identity=f"source-commit:{source}",
            client=_parse_client_identity(startup.client_build_identity), state="UNRESOLVED",
            service_config_fingerprint=startup.service_config_fingerprint,
            authority_source="QUIESCENCE_DEFINITION_ONLY", startup_resolution=startup,
            plist_path=path, plist_realpath=path.resolve(strict=True),
            plist_sha256=hashlib.sha256(raw).hexdigest(), program_arguments=tuple(args),
        )

    def quiesce_post_cas_reconciliation(self) -> Mapping[str, Any]:
        """Stop only the fixed Cleaner topology, even during a W07 restart loop."""
        self.validate_activation_binding()
        order = ("W06", "W01", "W03", "W07", "W04", "W05")
        entries = {writer: self._bind_quiescence_definition(writer) for writer in (*order, "W02")}
        w02 = entries["W02"]
        before = self.authority._launch_state(w02.launchd_label, w02.program_arguments)
        enabled = self.authority._enabled_state(w02.launchd_label)
        if before.runtime_state != "ACTIVE" or before.load_state != "LOADED" or enabled != "ENABLED":
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")
        for writer in order:
            self._fence_one(entries[writer])
        observed = self.authority.discover()
        by_id = {entry.writer_id: entry for entry in observed.entries}
        if len(by_id) != len(observed.entries) or set(by_id) != set(entries):
            raise CleanerCutoverControlError("CLEANER_RECONCILIATION_WRITER_SET_INVALID")
        for writer in order:
            entry = by_id[writer]
            if entry.launchd_label != _FIXED_LABELS[writer] or (
                entry.state, entry.load_state, entry.enabled_state
            ) != ("INACTIVE", "UNLOADED", "DISABLED"):
                raise CleanerCutoverControlError("CLEANER_RECONCILIATION_QUIESCENCE_FAILED", writer)
            self.authority._service_definition_for_entry(entries[writer])
        self.authority._service_definition_for_entry(w02)
        if (self.authority._launch_state(w02.launchd_label, w02.program_arguments) != before
            or self.authority._enabled_state(w02.launchd_label) != enabled):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")
        return {"quiesced_writers": order, "w02_unchanged": True,
                "w02_pid": before.pid_field,
                "definition_sha256": {writer: entries[writer].plist_sha256 for writer in entries}}

    def readback_w07_only(self, baseline: DcsWriterInventory | None = None,
                          *, active: bool = False) -> DcsWriterInventory:
        """Read physical isolation, including stray processes and unchanged W02."""
        return self._readback_w07_topology(baseline, active=active, prior_staging=False)

    def _readback_w07_topology(self, baseline: DcsWriterInventory | None,
                              *, active: bool, prior_staging: bool) -> DcsWriterInventory:
        self.validate_activation_binding()
        if prior_staging and active:
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_MUST_BE_STOPPED")
        inventory = self.authority.discover()
        entries = {e.writer_id: e for e in inventory.entries}
        if len(entries) != len(inventory.entries) or set(entries) != {*_FIXED_LABELS, "W02"}:
            raise CleanerCutoverControlError("CLEANER_W07_WRITER_SET_INVALID")
        prior = {e.writer_id: e for e in baseline.entries} if baseline is not None else {}
        for writer, entry in entries.items():
            expected = ("ACTIVE", "LOADED", "ENABLED") if writer == "W02" or (writer == "W07" and active) else ("INACTIVE", "UNLOADED", "DISABLED")
            if (entry.state, entry.load_state, entry.enabled_state) != expected:
                raise CleanerCutoverControlError("CLEANER_W07_ISOLATION_INVALID", writer)
            if entry.launchd_label != (_FIXED_LABELS.get(writer) or "com.propertyai.telegram-ops"):
                raise CleanerCutoverControlError("CLEANER_W07_WRITER_IDENTITY_INVALID", writer)
            _path, arguments = self.authority._service_definition_for_entry(entry)
            pids = tuple(self.authority.process_scan(arguments))
            if pids != ((entry.pid,) if expected[0] == "ACTIVE" else ()):
                raise CleanerCutoverControlError("CLEANER_W07_PROCESS_ISOLATION_INVALID", writer)
            if writer != "W07" and baseline is not None and (
                writer not in prior or entry.stable_identity != prior[writer].stable_identity
                or entry.plist_sha256 != prior[writer].plist_sha256
                or entry.pid != prior[writer].pid
            ):
                raise CleanerCutoverControlError("CLEANER_W07_UNRELATED_WRITER_CHANGED", writer)
            if writer != "W07" and baseline is not None and hasattr(self, "_w07_prior_authorizations"):
                auth_path, captured_auth = self._w07_prior_authorizations[writer]
                if auth_path.is_symlink() or auth_path.read_bytes() != captured_auth:
                    raise CleanerCutoverControlError("CLEANER_W07_PRIOR_AUTHORITY_DRIFT", writer)
            if writer == "W07":
                if prior_staging:
                    if entry.product_build_commit not in _W07_ACCEPTED_PREDECESSOR_TREES:
                        raise CleanerCutoverControlError("CLEANER_W07_PRODUCT_DRIFT")
                elif entry.product_build_commit != self.product_commit:
                    raise CleanerCutoverControlError("CLEANER_W07_PRODUCT_DRIFT")
                self.authority._require_restore_client_compatible(entry, 10)
        return inventory

    def readback_w07_staging_baseline(self, baseline: DcsWriterInventory | None = None) -> DcsWriterInventory:
        """Admit only explicitly sealed stopped W07 predecessors; never autodetect."""
        inventory = self._readback_w07_topology(baseline, active=False, prior_staging=True)
        entry = self._inventory_entry(inventory, "W07")
        self._validate_w07_prior_definition(entry)
        if baseline is not None:
            prior = self._inventory_entry(baseline, "W07")
            if (entry.stable_identity, entry.plist_sha256) != (prior.stable_identity, prior.plist_sha256):
                raise CleanerCutoverControlError("CLEANER_W07_PRIOR_DEFINITION_DRIFT")
        captured = {}
        for item in inventory.entries:
            path = self.authority.runtime_root / f"{item.writer_id}.authorized.json"
            if path.is_symlink() or not path.is_file():
                raise CleanerCutoverControlError("CLEANER_W07_PRIOR_AUTHORITY_INVALID")
            captured[item.writer_id] = (path, path.read_bytes())
        if baseline is None:
            self._w07_prior_authorizations = captured
        elif captured != self._w07_prior_authorizations:
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_AUTHORITY_DRIFT")
        return inventory

    def _validate_w07_prior_definition(self, entry: DcsWriterInventoryEntry) -> None:
        startup = entry.startup_resolution
        if startup is None:
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_STARTUP_INVALID")
        prior_commit = startup.resolved_propertyai_source_commit
        prior_tree = _W07_ACCEPTED_PREDECESSOR_TREES.get(prior_commit)
        if prior_tree is None:
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_STARTUP_INVALID")
        root = startup.resolved_propertyai_release
        if root != self.product_release_root.parent / prior_commit:
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_RELEASE_INVALID")
        try:
            commit_tree = subprocess.run(["git", "-C", os.fspath(root), "rev-parse", "HEAD", "HEAD^{tree}"],
                check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()
            dirty = subprocess.run(["git", "-C", os.fspath(root), "status", "--porcelain", "--untracked-files=no"],
                check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            path, _args = self.authority._service_definition_for_entry(entry)
            doc = plistlib.loads(path.read_bytes())
            auth_path = self.authority.runtime_root / "W07.authorized.json"
            if auth_path.is_symlink():
                raise ValueError("authority path")
            authorized = json.loads(auth_path.read_bytes())
        except (OSError, ValueError, subprocess.SubprocessError):
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_SOURCE_UNRESOLVED") from None
        expected = dict(self._expected_startup_environment("W07"))
        expected[_STARTUP_PRODUCT_ROOT_ENV] = os.fspath(root)
        expected[_STARTUP_PRODUCT_COMMIT_ENV] = prior_commit
        env = doc.get("EnvironmentVariables", {})
        if (commit_tree != [prior_commit, prior_tree] or dirty
            or doc.get("WorkingDirectory") != os.fspath(root)
            or any(env.get(k) != v for k,v in expected.items())
            or env.get(_AUTHORITY_ENV) != "POSTGRES" or env.get(_TOPOLOGY_ENV) != "POST_CUTOVER_PG"
            or not self.authority._startup_matches_authorized(startup, authorized, _W07_SERVICE_CODE)):
            raise CleanerCutoverControlError("CLEANER_W07_PRIOR_SOURCE_AUTHORITY_DRIFT")

    def stage_w07_only(self, baseline: DcsWriterInventory) -> Mapping[str, str]:
        """Replace only the fixed stopped W07 service/authorized identity bytes."""
        revalidate_current_controlled_deployment_lease()
        inventory = self.readback_w07_staging_baseline(baseline)
        runtime = CleanerRuntimeTuple(CleanerAuthorityMode.POSTGRES, True, 2,
                                      CleanerRuntimeTopology.POST_CUTOVER_PG)
        plist_path = self.authority.launch_agents_root / f"{_FIXED_LABELS['W07']}.plist"
        identity_path = self.authority.runtime_root / "W07.authorized.json"
        if any(path.is_symlink() or not path.is_file() for path in (plist_path, identity_path)):
            raise CleanerCutoverControlError("CLEANER_W07_STAGING_TARGET_INVALID")
        payload = self._render("W07", runtime)
        authorized = self._authorized_identity_payload("W07")
        doc = plistlib.loads(payload)
        prior = self._inventory_entry(inventory, "W07")
        self._w07_staged_stop_definition = replace(prior,
            plist_sha256=hashlib.sha256(payload).hexdigest(),
            program_arguments=tuple(doc["ProgramArguments"]),
            service_config_fingerprint=_service_config_fingerprint(doc))
        self._w07_staged_authorized_bytes = authorized
        for path, raw in ((plist_path, payload), (identity_path, authorized)):
            revalidate_current_controlled_deployment_lease()
            self._atomic_replace(path, raw)
            if path.read_bytes() != raw or path.stat().st_mode & 0o777 != 0o600:
                raise CleanerCutoverControlError("CLEANER_W07_STAGING_READBACK_INVALID")
        self.readback_w07_only(baseline)
        return {"plist_sha256": hashlib.sha256(payload).hexdigest(),
                "authorized_sha256": hashlib.sha256(authorized).hexdigest()}

    def activate_w07_only(self, baseline: DcsWriterInventory) -> DcsWriterInventory:
        revalidate_current_controlled_deployment_lease()
        inventory = self.readback_w07_only(baseline)
        self.verify_w07_database_runtime(inventory)
        entry = self._postcutover_entry(self._inventory_entry(inventory, "W07"), active=True)
        selected = DcsWriterInventory((entry,), hashlib.sha256(repr(entry.stable_identity).encode()).hexdigest())
        token = _QuiescenceToken(before=selected,
            quiesced_stable_identities=(entry.stable_identity,), before_classes=(("W07", "A"),))
        self.authority.resume_fenced(token, schema_version=10,
            assert_current=revalidate_current_controlled_deployment_lease,
            assert_event_guard=revalidate_current_controlled_deployment_lease)
        stabilized = self.authority._wait_for_stable_active_resume((entry,), deadline=time.monotonic()+15.0)
        if set(stabilized) != {"W07"}:
            raise CleanerCutoverControlError("CLEANER_W07_ACTIVE_HEALTH_INVALID")
        self.authority._active_resume_pending.pop("W07", None)
        return self.readback_w07_only(baseline, active=True)

    def verify_w07_database_runtime(self, inventory: DcsWriterInventory) -> Mapping[str, Any]:
        """Run the accepted Product's sealed role/full-ACL read-only health probe."""
        entry = self._inventory_entry(inventory, "W07")
        path, arguments = self.authority._service_definition_for_entry(entry)
        document = plistlib.loads(path.read_bytes())
        env = document.get("EnvironmentVariables", {})
        if env.get(_W07_CREDENTIAL_ENV) != _W07_CREDENTIAL_REF or any(
            key.startswith("PROPERTYAI_CLEANER_POSTGRES_APP_") for key in env
        ):
            raise CleanerCutoverControlError("CLEANER_W07_WORKER_CREDENTIAL_BINDING_INVALID")
        code = (
            "import json\n"
            "from propertyai_core.runtime.cleaner_pg_outbox_service import read_worker_database_health\n"
            "try:\n print(json.dumps(read_worker_database_health(),sort_keys=True))\n"
            "except BaseException:\n raise SystemExit(1)\n"
        )
        try:
            result = subprocess.run([arguments[0], "-c", code], cwd=self.product_release_root,
                env=dict(env), capture_output=True, text=True, timeout=20, check=False)
            facts = json.loads(result.stdout) if result.returncode == 0 else None
        except (OSError, ValueError, subprocess.SubprocessError):
            facts = None
        expected = {"status": "PASS", "session_user": "propertyai_cleaner_worker",
            "current_user": "propertyai_async_worker", "database_name": CLEANER_DATABASE,
            "credential_ref": _W07_CREDENTIAL_REF, "privilege_contract": "W07_FROZEN_V221"}
        if facts != expected:
            raise CleanerCutoverControlError("CLEANER_W07_DATABASE_RUNTIME_READINESS_FAILED")
        return expected

    def read_w07_worker_health(self, entry: DcsWriterInventoryEntry) -> Mapping[str, Any]:
        path = self.authority.runtime_root / "W07.worker-health.json"
        try:
            parent = path.parent.lstat()
            if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != self.authority.uid or parent.st_mode & 0o777 != 0o700:
                raise ValueError("health metadata")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_uid != self.authority.uid or before.st_mode & 0o777 != 0o600:
                    raise ValueError("health metadata")
                doc = json.load(stream)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            if (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_size) != (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_size) or (current.st_dev,current.st_ino) != (after.st_dev,after.st_ino):
                raise ValueError("health changed during read")
            observed = datetime.fromisoformat(doc["observed_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - observed).total_seconds()
        except (OSError, ValueError, TypeError, KeyError):
            raise CleanerCutoverControlError("CLEANER_W07_HEALTH_UNRESOLVED") from None
        exact = {"schema_version": 1, "pid": entry.pid,
            "process_incarnation_id": entry.process_incarnation_id,
            "product_build_commit": self.product_commit,
            "product_build_identity": entry.product_build_identity,
            "session_user": "propertyai_cleaner_worker", "current_user": "propertyai_async_worker",
            "database_name": CLEANER_DATABASE, "credential_ref": _W07_CREDENTIAL_REF,
            "privilege_contract": "W07_FROZEN_V221", "database_health": "PASS"}
        if not 0 <= age <= 20 or any(doc.get(k) != v for k, v in exact.items()):
            raise CleanerCutoverControlError("CLEANER_W07_HEALTH_IDENTITY_DRIFT")
        if type(doc.get("idle_cycles")) is not int or doc["idle_cycles"] < 0:
            raise CleanerCutoverControlError("CLEANER_W07_HEALTH_COUNTER_INVALID")
        return {**exact, "observed_at": doc["observed_at"], "status": doc.get("status"),
                "idle_cycles": doc["idle_cycles"], "writer_lease": doc.get("writer_lease")}

    def wait_w07_control_health(self, entry: DcsWriterInventoryEntry) -> Mapping[str, Any]:
        # Startup identity and its first health document are separate atomic
        # publications. Wait only for the initial document, never accept an old
        # process/role identity as a transient success.
        deadline = time.monotonic() + 5.0
        while True:
            revalidate_current_controlled_deployment_lease()
            try:
                return self.read_w07_worker_health(entry)
            except CleanerCutoverControlError as error:
                if error.code != "CLEANER_W07_HEALTH_UNRESOLVED" or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    def stop_w07_only(self, baseline: DcsWriterInventory) -> Mapping[str, Any]:
        """Fence only captured prior/new W07 bytes, including mixed publication.

        This stop-only proof never treats a mixed plist/authorization as a valid
        startup identity. It reports that condition for exact reconciliation.
        """
        prior = self._inventory_entry(baseline, "W07")
        path = self.authority.launch_agents_root / f"{_FIXED_LABELS['W07']}.plist"
        if path.is_symlink() or not path.is_file():
            raise CleanerCutoverControlError("CLEANER_W07_STOP_DEFINITION_UNRESOLVED")
        observed_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        staged = getattr(self, "_w07_staged_stop_definition", None)
        if observed_sha == prior.plist_sha256:
            selected = prior
        elif staged is not None and observed_sha == staged.plist_sha256:
            selected = staged
        else:
            raise CleanerCutoverControlError("CLEANER_W07_STOP_DEFINITION_UNRESOLVED")
        self._fence_one(selected)
        # Full discovery may reject an intentionally unfinished publication.
        # Read each unchanged accepted definition and physical process directly.
        for entry in baseline.entries:
            if entry.writer_id == "W07":
                continue
            _path, args = self.authority._service_definition_for_entry(entry)
            observed = self.authority._launch_state(entry.launchd_label, args)
            expected = ("ACTIVE", "LOADED", "ENABLED") if entry.writer_id == "W02" else ("INACTIVE", "UNLOADED", "DISABLED")
            if (observed.runtime_state, observed.load_state, self.authority._enabled_state(entry.launchd_label)) != expected or observed.pid_field != entry.pid or tuple(self.authority.process_scan(args)) != ((entry.pid,) if entry.writer_id == "W02" else ()):
                raise CleanerCutoverControlError("CLEANER_W07_UNRELATED_WRITER_CHANGED", entry.writer_id)
            auth_path, raw = self._w07_prior_authorizations[entry.writer_id]
            if auth_path.is_symlink() or auth_path.read_bytes() != raw:
                raise CleanerCutoverControlError("CLEANER_W07_PRIOR_AUTHORITY_DRIFT")
        auth_path, prior_auth = self._w07_prior_authorizations["W07"]
        if auth_path.is_symlink() or not auth_path.is_file():
            raise CleanerCutoverControlError("CLEANER_W07_STOP_AUTHORITY_UNRESOLVED")
        actual_auth = auth_path.read_bytes()
        staged_auth = getattr(self, "_w07_staged_authorized_bytes", None)
        if selected is prior and actual_auth == prior_auth:
            status = "PRIOR_EXACT_STOPPED"
        elif selected is staged and actual_auth == staged_auth:
            status = "SUCCESSOR_EXACT_STOPPED"
        elif actual_auth in (prior_auth, staged_auth):
            status = "PARTIAL_STAGING_STOPPED_RECONCILIATION_REQUIRED"
        else:
            raise CleanerCutoverControlError("CLEANER_W07_STOP_AUTHORITY_UNRESOLVED")
        return {"physical_quiescence": True, "configuration_status": status}


def revert_cleaner_pre_ponr(
    runtime_port: CleanerRuntimePort,
    snapshot: CleanerRuntimeSnapshot,
) -> None:
    """Exact separately-invoked PRE-PONR runtime reversal; requires a current W08 lease."""
    revalidate_current_controlled_deployment_lease()
    runtime_port.restore_pre_cutover(snapshot)
    revalidate_current_controlled_deployment_lease()


@dataclass(frozen=True)
class PrepareCleanerCutoverRequest:
    operation_id: str
    approved_target_epoch: int

    def __post_init__(self) -> None:
        if not self.operation_id or self.operation_id != self.operation_id.strip():
            raise CleanerCutoverControlError("CLEANER_CUTOVER_OPERATION_ID_INVALID")
        if isinstance(self.approved_target_epoch, bool) or not isinstance(self.approved_target_epoch, int) or self.approved_target_epoch < 1:
            raise CleanerCutoverControlError("CLEANER_CUTOVER_TARGET_EPOCH_INVALID")


@dataclass(frozen=True)
class RecoverCleanerPostCasRequest:
    operation_id: str
    original_operation_id: str
    predecessor_epoch: int
    successor_epoch: int

    def __post_init__(self) -> None:
        for value in (self.operation_id, self.original_operation_id):
            if not value or value != value.strip():
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_OPERATION_ID_INVALID")
        if (self.predecessor_epoch, self.successor_epoch) != (1, 2):
            raise CleanerCutoverControlError("CLEANER_DL98_POST_CAS_RECOVERY_EPOCH_INVALID")


def _read_cleaner_business_effect_counts() -> Mapping[str, Any]:
    return _json_query(
        _canonical_cleaner_postgres_policy(),
        database=CLEANER_DATABASE,
        sql=(
            "SELECT json_build_object("
            "'receipts',(SELECT count(*) FROM propertyai.command_receipt),"
            "'reservations',(SELECT count(*) FROM propertyai.reservation),"
            "'domain_events',(SELECT count(*) FROM propertyai.domain_event),"
            "'outbox',(SELECT count(*) FROM propertyai.integration_outbox))::text"
        ),
    )


def execute_cleaner_post_cas_recovery(
    store: ControlStore,
    *,
    change_id: str,
    request: RecoverCleanerPostCasRequest,
    authority: ProductionMutationAuthority,
    runtime_port: CleanerRuntimePort,
    epoch_port: CleanerEpochPort,
    persist_result: Callable[[tuple[Any, ...]], Any],
    control_decision_ref: str,
    start_heartbeat: bool = True,
):
    """Activate the exact quiesced epoch-2 state left by one failed DL-98 attempt.

    This sealed recovery performs no CAS, accepts no arbitrary epoch, requires the
    original acquire/release history, and refuses any PostgreSQL business effect.
    Every failure remains forward-safe and quiesced.
    """

    state: dict[str, Any] = {"snapshot": None, "stage": "NOT_STARTED"}

    def reconcile(error: BaseException) -> None:
        snapshot = state["snapshot"]
        quiesced = False
        if snapshot is not None:
            try:
                runtime_port.quiesce_after_failed_activation(snapshot)
                quiesced = True
            except BaseException:
                quiesced = False
        raise CleanerCutoverReconciliationRequired(
            CleanerCutoverReconciliationEvidence(
                operation_id=request.operation_id,
                stage=str(state["stage"]),
                current_epoch=request.predecessor_epoch,
                target_epoch=request.successor_epoch,
                epoch_advanced=True,
                selected_writer_ids=(
                    snapshot.selected_writer_ids if snapshot is not None else ()
                ),
                prior_plist_sha256=(
                    tuple((writer, sha) for writer, _path, _raw, sha in snapshot.prior_plists)
                    if snapshot is not None else ()
                ),
                safe_quiescence_attempted=snapshot is not None,
                safe_quiescence_confirmed=quiesced,
                failure_type=type(error).__name__,
            )
        ) from error

    def effect() -> CleanerCutoverActivated:
        try:
            state["stage"] = "BINDING_VALIDATION"
            runtime_port.validate_activation_binding()
            rows = store.connection.execute(
                """
                SELECT event_type FROM global_production_writer_event
                 WHERE (event_type='ACQUIRE' AND new_slice_id=?)
                    OR (event_type='RELEASE' AND prior_slice_id=?)
                 ORDER BY event_seq
                """,
                (request.original_operation_id, request.original_operation_id),
            ).fetchall()
            if [row["event_type"] for row in rows] != ["ACQUIRE", "RELEASE"]:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_ORIGINAL_W08_HISTORY_INVALID")
            state["stage"] = "EPOCH_READ"
            if epoch_port.read_current() != request.successor_epoch:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_EPOCH_DRIFT")
            if _read_cleaner_business_effect_counts() != {
                "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
            }:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT")
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES,
                True,
                request.successor_epoch,
                CleanerRuntimeTopology.POST_CUTOVER_PG,
            )
            state["stage"] = "STAGED_RECONCILIATION"
            snapshot, w07_sha = runtime_port.reconcile_post_cas_staged(runtime)
            state["snapshot"] = snapshot
            state["stage"] = "RUNTIME_ACTIVATION"
            physical = runtime_port.activate_postgres_runtime(snapshot, runtime, w07_sha)
            state["stage"] = "EFFECTIVE_READBACK"
            effective = runtime_port.readback_effective(snapshot, runtime, w07_sha)
            if physical != effective or epoch_port.read_current() != request.successor_epoch:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_READBACK_DRIFT")
            if _read_cleaner_business_effect_counts() != {
                "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
            }:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT")
            state["stage"] = "EFFECT_COMPLETE"
            return CleanerCutoverActivated(
                request.predecessor_epoch,
                request.successor_epoch,
                runtime,
                snapshot.selected_writer_ids,
                tuple((writer, sha) for writer, _path, _raw, sha in snapshot.prior_plists),
                w07_sha,
                effective,
            )
        except CleanerCutoverReconciliationRequired:
            raise
        except BaseException as error:
            reconcile(error)

    def readback(result: CleanerCutoverActivated) -> Mapping[str, Any]:
        snapshot = state["snapshot"]
        if snapshot is None:
            raise CleanerCutoverControlError("CLEANER_CUTOVER_SNAPSHOT_MISSING")
        try:
            value = runtime_port.readback_effective(
                snapshot, result.runtime_tuple, result.w07_authorized_identity_sha256
            )
            if epoch_port.read_current() != request.successor_epoch:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_EPOCH_DRIFT")
            if _read_cleaner_business_effect_counts() != {
                "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
            }:
                raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT")
            return value
        except BaseException as error:
            reconcile(error)

    def persist(evidence: tuple[Any, ...]) -> Any:
        try:
            state["stage"] = "DURABLE_RECOVERY_RECEIPT"
            value = persist_result(evidence)
            state["stage"] = "DURABLE_RECOVERY_RECEIPT_COMPLETE"
            return value
        except BaseException as error:
            reconcile(error)

    evidence = run_controlled_deployment(
        store,
        change_id=change_id,
        deployment_id=request.operation_id,
        authority=authority,
        steps=(DeploymentStep("CLEANER_POST_CAS_RECOVERY_ACTIVATE", effect, readback),),
        persist_result=persist,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or not isinstance(evidence[0].effect_result, CleanerCutoverActivated):
        raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_RECEIPT_MISSING")
    return evidence


def execute_cleaner_post_cas_quiescence(
    store: ControlStore,
    *,
    change_id: str,
    request: RecoverCleanerPostCasRequest,
    authority: ProductionMutationAuthority,
    runtime_port: LaunchdCleanerRuntimePort,
    epoch_port: CleanerEpochPort,
    persist_result: Callable[[tuple[Any, ...]], Any],
    control_decision_ref: str,
    start_heartbeat: bool = True,
):
    """Reconcile DL98 partial activation to stopped epoch-2 state under fresh W08.

    No epoch transition, runtime document write, activation, or authority reversal
    is available through this operation. A failed stop remains reconciliation-required.
    """
    def guards() -> None:
        revalidate_current_controlled_deployment_lease()
        runtime_port.validate_activation_binding()
        rows = store.connection.execute(
            "SELECT event_type FROM global_production_writer_event "
            "WHERE (event_type='ACQUIRE' AND new_slice_id=?) "
            "OR (event_type='RELEASE' AND prior_slice_id=?) ORDER BY event_seq",
            (request.original_operation_id, request.original_operation_id),
        ).fetchall()
        if [row["event_type"] for row in rows] != ["ACQUIRE", "RELEASE"]:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_ORIGINAL_W08_HISTORY_INVALID")
        if epoch_port.read_current() != 2:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_EPOCH_DRIFT")
        if _read_cleaner_business_effect_counts() != {
            "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
        }:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT")

    def effect() -> Mapping[str, Any]:
        guards()
        result = runtime_port.quiesce_post_cas_reconciliation()
        guards()
        return result

    def readback(result: Mapping[str, Any]) -> Mapping[str, Any]:
        guards()
        observed = runtime_port.authority.discover()
        entries = {entry.writer_id: entry for entry in observed.entries}
        for writer in result["quiesced_writers"]:
            entry = entries.get(writer)
            if entry is None or (entry.state, entry.load_state, entry.enabled_state) != (
                "INACTIVE", "UNLOADED", "DISABLED"
            ):
                raise CleanerCutoverControlError("CLEANER_RECONCILIATION_QUIESCENCE_FAILED", writer)
            if entry.plist_sha256 != result["definition_sha256"][writer]:
                raise CleanerCutoverControlError("CLEANER_RECONCILIATION_DEFINITION_DRIFT", writer)
        w02 = entries.get("W02")
        if w02 is None or (w02.state, w02.load_state, w02.enabled_state, w02.pid, w02.plist_sha256) != (
            "ACTIVE", "LOADED", "ENABLED", result["w02_pid"], result["definition_sha256"]["W02"]
        ):
            raise CleanerCutoverControlError("CLEANER_W02_UNRELATED_WRITER_CHANGED")
        return result

    return run_controlled_deployment(
        store, change_id=change_id, deployment_id=request.operation_id,
        authority=authority,
        steps=(DeploymentStep("CLEANER_POST_CAS_RECONCILIATION_QUIESCE", effect, readback),),
        persist_result=persist_result, control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    )


def _verify_w07_worker_login() -> Mapping[str, Any]:
    from adcp.cleaner_worker_control import _read_cleaner_worker_runtime_readiness
    return _read_cleaner_worker_runtime_readiness()


def _verify_w07_dcs_health(store: ControlStore) -> None:
    from adcp.store.migrations import schema_profile_identity
    connection = store.connection
    schema = connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
    if (schema != 10 or schema_profile_identity(connection, schema) !=
        "sha256:1bfa57994e2ea90b11146d32839ca6a8875ad94bb0eea9128fb3b8fb3c5ce7e9"
        or connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
        or connection.execute("PRAGMA foreign_key_check").fetchall()):
        raise CleanerCutoverControlError("CLEANER_W07_DCS_HEALTH_INVALID")


def execute_cleaner_w07_recovery(
    store: ControlStore, *, change_id: str, request: RecoverCleanerPostCasRequest,
    authority: ProductionMutationAuthority, runtime_port: LaunchdCleanerRuntimePort,
    epoch_port: CleanerEpochPort, persist_result: Callable[[tuple[Any, ...]], Any],
    control_decision_ref: str, start_heartbeat: bool = True,
):
    """Stage/start only W07 under W08; this is not a successful no-work proof.

    Worker credential materialization is a separate explicitly authorized typed
    operation. This executor first requires its factual authentication proof.
    Idle polling may begin only after W08 release and is evaluated separately.
    """
    state: dict[str, Any] = {"baseline": None, "stage": "NOT_STARTED"}

    def guards() -> None:
        revalidate_current_controlled_deployment_lease()
        _verify_w07_dcs_health(store)
        runtime_port.validate_activation_binding()
        if request.original_operation_id != "CHAT.PROJ.HQ:TK43:DL98:PRODUCTION_AUTHORITY_CUTOVER:V1":
            raise CleanerCutoverControlError("CLEANER_W07_ORIGINAL_OPERATION_INVALID")
        rows = store.connection.execute(
            "SELECT event_type FROM global_production_writer_event "
            "WHERE (event_type='ACQUIRE' AND new_slice_id=?) "
            "OR (event_type='RELEASE' AND prior_slice_id=?) ORDER BY event_seq",
            (request.original_operation_id, request.original_operation_id),
        ).fetchall()
        if [r["event_type"] for r in rows] != ["ACQUIRE", "RELEASE"]:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_ORIGINAL_W08_HISTORY_INVALID")
        if epoch_port.read_current() != 2:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_EPOCH_DRIFT")
        if _read_cleaner_business_effect_counts() != {
            "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
        }:
            raise CleanerCutoverControlError("CLEANER_POST_CAS_RECOVERY_BUSINESS_EFFECT_PRESENT")

    def fail(error: BaseException) -> None:
        stopped = False
        if state["baseline"] is not None:
            try:
                stop_result = runtime_port.stop_w07_only(state["baseline"])
                if isinstance(stop_result, Mapping):
                    state["stage"] += ":" + str(stop_result["configuration_status"])
                stopped = True
            except BaseException:
                pass
        raise CleanerCutoverReconciliationRequired(CleanerCutoverReconciliationEvidence(
            operation_id=request.operation_id, stage=state["stage"], current_epoch=2,
            target_epoch=2, epoch_advanced=False, selected_writer_ids=("W07",),
            prior_plist_sha256=(), safe_quiescence_attempted=state["baseline"] is not None,
            safe_quiescence_confirmed=stopped, failure_type=type(error).__name__,
        )) from None

    def effect() -> Mapping[str, Any]:
        try:
            guards()
            state["stage"] = "WORKER_LOGIN_PREFLIGHT"
            _verify_w07_worker_login()
            state["baseline"] = runtime_port.readback_w07_staging_baseline()
            state["stage"] = "W07_ONLY_STAGING"
            staged = runtime_port.stage_w07_only(state["baseline"])
            guards()
            state["stage"] = "W07_ONLY_ACTIVATION"
            observed = runtime_port.activate_w07_only(state["baseline"])
            guards()
            w07 = runtime_port._inventory_entry(observed, "W07")
            health = runtime_port.wait_w07_control_health(w07)
            if health["status"] not in {"READY", "WAITING_CONTROL"} or health["writer_lease"] != "NOT_ACQUIRED":
                raise CleanerCutoverControlError("CLEANER_W07_W08_POLL_ISOLATION_INVALID")
            return {**staged, "epoch": 2, "writer_id": "W07", "pid": w07.pid,
                "process_incarnation_id": w07.process_incarnation_id,
                "product_commit": runtime_port.product_commit,
                "no_work_proof": "PENDING_AFTER_W08_RELEASE", "first_business_command": False}
        except BaseException as error:
            fail(error)

    def readback(result: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            guards()
            observed = runtime_port.readback_w07_only(state["baseline"], active=True)
            w07 = runtime_port._inventory_entry(observed, "W07")
            if (w07.pid, w07.process_incarnation_id, w07.plist_sha256) != (
                result["pid"], result["process_incarnation_id"], result["plist_sha256"]
            ):
                raise CleanerCutoverControlError("CLEANER_W07_RESTART_OR_DEFINITION_DRIFT")
            path = runtime_port.authority.runtime_root / "W07.authorized.json"
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != result["authorized_sha256"]:
                raise CleanerCutoverControlError("CLEANER_W07_AUTHORIZED_IDENTITY_DRIFT")
            health = runtime_port.read_w07_worker_health(w07)
            if health["status"] not in {"READY", "WAITING_CONTROL"} or health["writer_lease"] != "NOT_ACQUIRED":
                raise CleanerCutoverControlError("CLEANER_W07_W08_POLL_ISOLATION_INVALID")
            return result
        except BaseException as error:
            fail(error)

    def persist(evidence: tuple[Any, ...]) -> Any:
        try:
            state["stage"] = "DURABLE_W07_RECOVERY_RECEIPT"
            return persist_result(evidence)
        except BaseException as error:
            fail(error)

    return run_controlled_deployment(store, change_id=change_id,
        deployment_id=request.operation_id, authority=authority,
        steps=(DeploymentStep("CLEANER_W07_ONLY_RECOVERY", effect, readback),),
        persist_result=persist, control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat)


def observe_cleaner_w07_no_work(
    store: ControlStore, *, runtime_port: LaunchdCleanerRuntimePort,
    epoch_port: CleanerEpochPort,
) -> Mapping[str, Any]:
    """Three fresh, spaced idle proofs after W08 release; acquires no lease.

    Exact successful W07 ACQUIRE/RELEASE polling pairs are permitted. Takeover,
    leaked leases, unrelated acquisitions and restarts fail closed. A failure
    returns no stable proof and performs no automatic topology mutation.
    """
    def free() -> None:
        _verify_w07_dcs_health(store)
        row = store.connection.execute(
            "SELECT state,owner_id,owner_execution_id,expires_at FROM global_production_writer_lease "
            "WHERE resource_key='GLOBAL_PRODUCTION'"
        ).fetchone()
        if row is None or tuple(row) != ("FREE", None, None, None):
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_GLOBAL_NOT_FREE")

    free()
    baseline = runtime_port.readback_w07_only(active=True)
    entry = runtime_port._inventory_entry(baseline, "W07")
    event_start = store.connection.execute("SELECT coalesce(max(event_seq),0) FROM global_production_writer_event").fetchone()[0]
    owner = f"{_W07_SERVICE_CODE}:{entry.pid}:{entry.process_incarnation_id[:16]}"
    observations = []
    for index in range(3):
        # Fixed ten-second spacing covers at least one accepted five-second poll.
        time.sleep(10.0)
        free()
        if epoch_port.read_current() != 2 or _read_cleaner_business_effect_counts() != {
            "receipts": 0, "reservations": 0, "domain_events": 0, "outbox": 0
        }:
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_BUSINESS_OR_EPOCH_DRIFT")
        current = runtime_port._inventory_entry(runtime_port.readback_w07_only(baseline, active=True), "W07")
        if current.stable_identity != entry.stable_identity or current.pid != entry.pid:
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_RESTART")
        health = runtime_port.read_w07_worker_health(current)
        if health["status"] != "IDLE" or health["writer_lease"] != "RELEASED" or health["idle_cycles"] < 1:
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_IDLE_NOT_PROVEN")
        if observations and (health["idle_cycles"] <= observations[-1]["idle_cycles"]
                             or health["observed_at"] <= observations[-1]["observed_at"]):
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_HEALTH_STALE")
        observations.append(health)
    free()
    rows = store.connection.execute(
        "SELECT event_type,new_owner_id,prior_owner_id,new_owner_execution_id,prior_owner_execution_id,"
        "from_fencing_token,to_fencing_token,new_writer_class,prior_writer_class "
        "FROM global_production_writer_event WHERE event_seq>? ORDER BY event_seq", (event_start,)
    ).fetchall()
    if not rows or len(rows) % 2:
        raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_LEASE_HISTORY_INVALID")
    for acquire, release in zip(rows[::2], rows[1::2]):
        if (acquire["event_type"], release["event_type"], acquire["new_owner_id"], release["prior_owner_id"],
            acquire["new_owner_execution_id"], release["prior_owner_execution_id"],
            acquire["new_writer_class"], release["prior_writer_class"]) != (
            "ACQUIRE", "RELEASE", owner, owner, entry.process_incarnation_id, entry.process_incarnation_id,
            "W07", "W07"
        ) or acquire["to_fencing_token"] != release["from_fencing_token"] or release["to_fencing_token"] != release["from_fencing_token"]:
            raise CleanerCutoverControlError("CLEANER_W07_NO_WORK_LEASE_HISTORY_INVALID")
    return {"status": "PASS_W07_STABLE_NO_WORK", "epoch": 2, "observations": observations,
            "successful_poll_lease_pairs": len(rows)//2, "global_control": "FREE",
            "business_mutation": 0, "first_business_command": False, "ponr": False}


def prepare_cleaner_postgres_cutover(
    store: ControlStore,
    *,
    change_id: str,
    request: PrepareCleanerCutoverRequest,
    authority: ProductionMutationAuthority,
    runtime_port: CleanerRuntimePort,
    epoch_port: CleanerEpochPort,
    persist_result: Callable[[tuple[Any, ...]], Any],
    control_decision_ref: str,
    start_heartbeat: bool = True,
):
    """Prepare PG authority under W08 without starting any autonomous Product writer."""

    def effect() -> CleanerCutoverPrepared:
        snapshot = runtime_port.quiesce_for_cutover()
        current = epoch_port.read_current()
        try:
            transition = CleanerEpochTransition(current, request.approved_target_epoch)
            target = epoch_port.advance(transition)
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES,
                True,
                target,
                CleanerRuntimeTopology.POST_CUTOVER_PG,
            )
            plists = runtime_port.materialize_postgres_runtime(snapshot, runtime)
            return CleanerCutoverPrepared(current, target, runtime, snapshot.selected_writer_ids, plists)
        except BaseException:
            # Safe pre-PONR physical/config restoration only. The advanced DB epoch,
            # if any, is never decremented or reused by this source capability.
            runtime_port.restore_pre_cutover(snapshot)
            raise

    evidence = run_controlled_deployment(
        store,
        change_id=change_id,
        deployment_id=request.operation_id,
        authority=authority,
        steps=(DeploymentStep("CLEANER_CUTOVER_PREPARE", effect, lambda result: runtime_port.readback_prepared(result.runtime_tuple)),),
        persist_result=persist_result,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    )
    if (
        len(evidence) != 1
        or not isinstance(evidence[0].effect_result, CleanerCutoverPrepared)
    ):
        raise CleanerCutoverControlError("CLEANER_CUTOVER_PREPARE_RECEIPT_MISSING")
    return evidence


def execute_cleaner_postgres_cutover(
    store: ControlStore,
    *,
    change_id: str,
    request: PrepareCleanerCutoverRequest,
    authority: ProductionMutationAuthority,
    runtime_port: CleanerRuntimePort,
    epoch_port: CleanerEpochPort,
    persist_result: Callable[[tuple[Any, ...]], Any],
    control_decision_ref: str,
    start_heartbeat: bool = True,
):
    """Perform the fixed DL-98 control-plane cutover inside one W08 run.

    The operation stops before the first business command.  Prior runtime bytes
    are restored only while the epoch is factually unchanged.  Once the CAS has
    advanced, a failure is left physically quiesced and emits typed evidence for
    pre-PONR reconciliation; the old epoch or legacy runtime is never restored.
    """

    state: dict[str, Any] = {
        "snapshot": None,
        "current": -1,
        "target": request.approved_target_epoch,
        "epoch_advanced": False,
        "stage": "NOT_STARTED",
        "quiesced_after_failure": False,
    }

    def reconciliation(error: BaseException) -> None:
        snapshot = state["snapshot"]
        attempted = False
        if snapshot is not None:
            attempted = True
            try:
                runtime_port.quiesce_after_failed_activation(snapshot)
                state["quiesced_after_failure"] = True
            except BaseException:
                state["quiesced_after_failure"] = False
        prior_hashes = (
            tuple(
                (writer, sha)
                for writer, _path, _raw, sha in getattr(snapshot, "prior_plists", ())
            )
            if snapshot is not None
            else ()
        )
        evidence = CleanerCutoverReconciliationEvidence(
            operation_id=request.operation_id,
            stage=str(state["stage"]),
            current_epoch=int(state["current"]),
            target_epoch=int(state["target"]),
            epoch_advanced=bool(state["epoch_advanced"]),
            selected_writer_ids=(snapshot.selected_writer_ids if snapshot is not None else ()),
            prior_plist_sha256=prior_hashes,
            safe_quiescence_attempted=attempted,
            safe_quiescence_confirmed=bool(state["quiesced_after_failure"]),
            failure_type=type(error).__name__,
        )
        raise CleanerCutoverReconciliationRequired(evidence) from error

    def effect() -> CleanerCutoverActivated:
        state["stage"] = "BINDING_VALIDATION"
        runtime_port.validate_activation_binding()
        state["stage"] = "QUIESCE"
        snapshot = runtime_port.quiesce_for_cutover()
        state["snapshot"] = snapshot
        try:
            state["stage"] = "EPOCH_READ"
            current = epoch_port.read_current()
            state["current"] = current
            state["stage"] = "EPOCH_TRANSITION_VALIDATION"
            transition = CleanerEpochTransition(current, request.approved_target_epoch)
            state["stage"] = "EPOCH_CAS"
            target = epoch_port.advance(transition)
            state["epoch_advanced"] = True
            state["stage"] = "RUNTIME_MATERIALIZATION"
            runtime = CleanerRuntimeTuple(
                CleanerAuthorityMode.POSTGRES,
                True,
                target,
                CleanerRuntimeTopology.POST_CUTOVER_PG,
            )
            plists = runtime_port.materialize_postgres_runtime(snapshot, runtime)
            state["stage"] = "STARTUP_AUTHORITY_MATERIALIZATION"
            w07_sha = runtime_port.materialize_w07_authorized_identity(snapshot, runtime)
            state["stage"] = "PREPARED_READBACK"
            runtime_port.readback_prepared(runtime)
            state["stage"] = "RUNTIME_ACTIVATION"
            physical = runtime_port.activate_postgres_runtime(snapshot, runtime, w07_sha)
            state["stage"] = "EFFECTIVE_READBACK"
            effective = runtime_port.readback_effective(snapshot, runtime, w07_sha)
            if effective != physical:
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_READBACK_DRIFT")
            if epoch_port.read_current() != target:
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_EPOCH_DRIFT")
            state["stage"] = "EFFECT_COMPLETE"
            return CleanerCutoverActivated(
                current,
                target,
                runtime,
                tuple(dict.fromkeys((*snapshot.selected_writer_ids, "W07"))),
                plists,
                w07_sha,
                effective,
            )
        except BaseException as error:
            if state["stage"] in {"EPOCH_READ", "EPOCH_TRANSITION_VALIDATION"}:
                state["stage"] = "PRE_CAS_RESTORE"
                runtime_port.restore_pre_cutover(snapshot)
                raise
            # A CAS can apply and still lose its postcondition readback.  Decide
            # from a fresh factual epoch; uncertainty is never treated as absence.
            try:
                factual_epoch = epoch_port.read_current()
            except BaseException:
                reconciliation(error)
            if factual_epoch == request.approved_target_epoch:
                state["epoch_advanced"] = True
                reconciliation(error)
            if factual_epoch != state["current"]:
                reconciliation(error)
            state["stage"] = "PRE_CAS_RESTORE"
            runtime_port.restore_pre_cutover(snapshot)
            raise

    def readback(result: CleanerCutoverActivated) -> Mapping[str, Any]:
        snapshot = state["snapshot"]
        if snapshot is None:
            raise CleanerCutoverControlError("CLEANER_CUTOVER_SNAPSHOT_MISSING")
        try:
            state["stage"] = "RUNNER_READBACK"
            value = runtime_port.readback_effective(
                snapshot, result.runtime_tuple, result.w07_authorized_identity_sha256
            )
            if epoch_port.read_current() != result.target_epoch:
                raise CleanerCutoverControlError("CLEANER_POST_CUTOVER_EPOCH_DRIFT")
            state["stage"] = "RUNNER_READBACK_COMPLETE"
            return value
        except BaseException as error:
            reconciliation(error)

    def persist(evidence: tuple[Any, ...]) -> Any:
        try:
            state["stage"] = "DURABLE_RECEIPT"
            value = persist_result(evidence)
            state["stage"] = "DURABLE_RECEIPT_COMPLETE"
            return value
        except BaseException as error:
            reconciliation(error)

    evidence = run_controlled_deployment(
        store,
        change_id=change_id,
        deployment_id=request.operation_id,
        authority=authority,
        steps=(DeploymentStep("CLEANER_CUTOVER_ACTIVATE", effect, readback),),
        persist_result=persist,
        control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
    )
    if len(evidence) != 1 or not isinstance(evidence[0].effect_result, CleanerCutoverActivated):
        raise CleanerCutoverControlError("CLEANER_CUTOVER_ACTIVATION_RECEIPT_MISSING")
    return evidence


__all__ = [
    "CanonicalCleanerEpochPort",
    "CleanerAuthorityMode",
    "CleanerCutoverControlError",
    "CleanerCutoverActivated",
    "CleanerCutoverPrepared",
    "CleanerCutoverReconciliationEvidence",
    "CleanerCutoverReconciliationRequired",
    "CleanerCutbackReconciliationInventory",
    "CleanerEmergencyCutbackRequest",
    "CleanerEmergencyCutbackSourcePrepared",
    "CleanerEpochTransition",
    "CleanerRuntimeSnapshot",
    "CleanerRuntimeTopology",
    "CleanerRuntimeTuple",
    "LaunchdCleanerRuntimePort",
    "PrepareCleanerCutoverRequest",
    "RecoverCleanerPostCasRequest",
    "execute_cleaner_post_cas_recovery",
    "execute_cleaner_post_cas_quiescence",
    "prepare_cleaner_emergency_cutback_source",
    "prepare_cleaner_postgres_cutover",
    "execute_cleaner_postgres_cutover",
    "revert_cleaner_pre_ponr",
]
