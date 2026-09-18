"""CUT-1/CUT-2 readiness plus CUT-3-E1 isolated control-state rehearsal.

This module deliberately has no operational Registry, Handoff, or Notion
transport.  Its only durable writer targets an explicitly supplied isolated
Control Store.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Iterable, Mapping

from adcp.canonical import canonical_json, canonical_sha256
from adcp.domain import (
    ActorRole,
    Environment,
    ExecutionCreate,
    RiskLevel,
    StoreError,
    operation_key,
)
from adcp.store.migrations import SCHEMA_VERSION
from adcp.store.sqlite import (
    CONTROL_STATE_INPUT_FIELDS,
    ControlStore,
    DEFAULT_RUNTIME_ROOT,
    control_state_authority_fingerprint,
)


ACCEPTED_ADCP_BASELINE = "23423df894bc8a2a3d952def0664b0b9a639c4b4"
AUTHORITY_MODE = "TRANSITIONAL_AUTHORITY"
CP_SLICE_ID = "CP-01A-2"
MANIFEST_VERSION = 1
PROJECTION_VERSION = 1

UNBOUND = "UNBOUND"
NONE = "NONE"
UNRESOLVED_BASE = "RESOLVE_AT_CODEX_PREFLIGHT"

CP01A2_EXECUTION_PACKET_REF = "packet://openclaw/cp-01a-2"
CP01A2_CONTRACT_REF = "contract://openclaw/cp-01a-2"
PHASE1_EXECUTION_PACKET_REF = "packet://openclaw/phase1/ops-briefing"
PHASE2_CONTRACT_REF = "contract://openclaw/phase2"


class CutoverError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class MigrationClass(StrEnum):
    READY = "MIGRATE_AS_READY_CURRENT_STATE"
    DEFER_BINDING = "DEFER_SEED_UNTIL_BRANCH_BASE_PREFLIGHT"
    DEFER_PREREQUISITE = "DEFER_SEED_UNTIL_PREREQUISITE"


class SeedEligibility(StrEnum):
    ELIGIBLE = "ELIGIBLE_FOR_REHEARSAL_SEED"
    DEFER_BINDING = "INELIGIBLE_UNTIL_BRANCH_AND_BASE_PREFLIGHT"
    DEFER_PREREQUISITE = "INELIGIBLE_UNTIL_PREREQUISITES"


_ENTRY_FIELDS = (
    "slice_id",
    "registry_stage",
    "registry_status",
    "logical_source_root",
    "repository_toplevel",
    "execution_worktree",
    "branch",
    "base_commit",
    "implementation_result_commit",
    "current_branch_head",
    "execution_packet_url",
    "contract_url",
    "migration_class",
    "seed_eligibility",
    "seed_defer_reason",
)


@dataclass(frozen=True)
class MigrationSlice:
    slice_id: str
    registry_stage: str
    registry_status: str
    logical_source_root: str
    repository_toplevel: str
    execution_worktree: str
    branch: str
    base_commit: str
    implementation_result_commit: str
    current_branch_head: str
    execution_packet_url: str
    contract_url: str
    migration_class: str
    seed_eligibility: str
    seed_defer_reason: str
    snapshot_fingerprint: str = ""

    def semantic_dict(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in _ENTRY_FIELDS}

    def computed_fingerprint(self) -> str:
        return canonical_sha256(self.semantic_dict())

    def as_dict(self) -> dict[str, str]:
        return {**self.semantic_dict(), "snapshot_fingerprint": self.snapshot_fingerprint}

    def finalized(self) -> "MigrationSlice":
        return MigrationSlice(**self.semantic_dict(), snapshot_fingerprint=self.computed_fingerprint())

    def validate(self) -> None:
        if not all(isinstance(getattr(self, field), str) and getattr(self, field) for field in _ENTRY_FIELDS):
            raise CutoverError("MANIFEST_FIELD_REQUIRED", self.slice_id)
        if self.snapshot_fingerprint != self.computed_fingerprint():
            raise CutoverError("SNAPSHOT_FINGERPRINT_MISMATCH", self.slice_id)
        try:
            MigrationClass(self.migration_class)
            SeedEligibility(self.seed_eligibility)
        except ValueError as error:
            raise CutoverError("MANIFEST_ENUM_INVALID", self.slice_id) from error
        if self.implementation_result_commit == self.current_branch_head and self.slice_id == CP_SLICE_ID:
            raise CutoverError("COMMIT_ROLES_COLLAPSED", self.slice_id)
        if self.seed_eligibility == SeedEligibility.ELIGIBLE:
            for field in ("execution_worktree", "branch", "base_commit", "current_branch_head"):
                if getattr(self, field) in {NONE, UNBOUND, UNRESOLVED_BASE}:
                    raise CutoverError("IMMUTABLE_BINDING_UNRESOLVED", f"{self.slice_id}:{field}")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MigrationSlice":
        expected = {*_ENTRY_FIELDS, "snapshot_fingerprint"}
        if set(value) != expected or any(not isinstance(value[field], str) for field in expected):
            raise CutoverError("MANIFEST_SHAPE_INVALID")
        entry = cls(**{field: value[field] for field in expected})
        entry.validate()
        return entry


@dataclass(frozen=True)
class MigrationManifest:
    slices: tuple[MigrationSlice, ...]
    manifest_version: int = MANIFEST_VERSION

    def validate(self) -> None:
        if self.manifest_version != MANIFEST_VERSION:
            raise CutoverError("MANIFEST_VERSION_UNSUPPORTED")
        if len(self.slices) != 5:
            raise CutoverError("MANIFEST_SLICE_COUNT_INVALID", str(len(self.slices)))
        ids = [entry.slice_id for entry in self.slices]
        if len(set(ids)) != len(ids):
            raise CutoverError("MANIFEST_DUPLICATE_SLICE")
        for entry in self.slices:
            entry.validate()

    def payload(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "slices": [entry.as_dict() for entry in self.slices],
        }

    def canonical_payload(self) -> str:
        self.validate()
        return canonical_json(self.payload())

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(self.payload())

    def entry(self, slice_id: str) -> MigrationSlice:
        try:
            return next(entry for entry in self.slices if entry.slice_id == slice_id)
        except StopIteration as error:
            raise CutoverError("MANIFEST_SLICE_MISSING", slice_id) from error

    @classmethod
    def from_json(cls, payload: str) -> "MigrationManifest":
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as error:
            raise CutoverError("MANIFEST_JSON_INVALID") from error
        if not isinstance(value, dict) or set(value) != {"manifest_version", "slices"}:
            raise CutoverError("MANIFEST_SHAPE_INVALID")
        if not isinstance(value["slices"], list):
            raise CutoverError("MANIFEST_SHAPE_INVALID")
        manifest = cls(
            tuple(MigrationSlice.from_dict(item) for item in value["slices"]),
            value["manifest_version"],
        )
        manifest.validate()
        return manifest


@dataclass(frozen=True)
class GitBindingEvidence:
    execution_worktree: str
    repository_toplevel: str
    branch: str
    head: str
    clean: bool
    base_commit_exists: bool
    implementation_result_commit_exists: bool
    implementation_result_reachable: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "execution_worktree": self.execution_worktree,
            "repository_toplevel": self.repository_toplevel,
            "branch": self.branch,
            "head": self.head,
            "clean": self.clean,
            "base_commit_exists": self.base_commit_exists,
            "implementation_result_commit_exists": self.implementation_result_commit_exists,
            "implementation_result_reachable": self.implementation_result_reachable,
        }


@dataclass(frozen=True)
class EligibilityDecision:
    eligibility: SeedEligibility
    reason: str


def _git(path: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if check and result.returncode:
        raise CutoverError("GIT_BINDING_INSPECTION_FAILED", result.stderr.strip())
    return result


def inspect_git_binding(entry: MigrationSlice) -> GitBindingEvidence:
    """Read-only inspection of an entry's isolated execution provenance."""

    worktree = Path(entry.execution_worktree).expanduser().resolve(strict=True)
    repository = Path(entry.repository_toplevel).expanduser().resolve(strict=True)
    observed_top = Path(_git(worktree, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    branch = _git(worktree, "symbolic-ref", "--short", "-q", "HEAD").stdout.strip()
    head = _git(worktree, "rev-parse", "HEAD").stdout.strip()
    clean = not _git(worktree, "status", "--porcelain", "--untracked-files=all").stdout
    worktree_common = Path(
        _git(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    ).resolve()
    repository_common = Path(
        _git(repository, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    ).resolve()
    repository_binding = str(repository) if worktree_common == repository_common else str(observed_top)
    base_exists = not _git(worktree, "cat-file", "-e", f"{entry.base_commit}^{{commit}}", check=False).returncode
    result_exists = not _git(
        worktree, "cat-file", "-e", f"{entry.implementation_result_commit}^{{commit}}", check=False
    ).returncode
    reachable = result_exists and not _git(
        worktree,
        "merge-base",
        "--is-ancestor",
        entry.implementation_result_commit,
        entry.current_branch_head,
        check=False,
    ).returncode
    return GitBindingEvidence(
        str(worktree), repository_binding, branch, head, clean, base_exists, result_exists, reachable
    )


def classify_seed_eligibility(
    entry: MigrationSlice,
    binding: GitBindingEvidence | None = None,
) -> EligibilityDecision:
    """Classify one Slice with explicit, fail-closed immutable binding rules."""

    entry.validate()
    if entry.migration_class == MigrationClass.DEFER_BINDING:
        return EligibilityDecision(SeedEligibility.DEFER_BINDING, entry.seed_defer_reason)
    if entry.migration_class == MigrationClass.DEFER_PREREQUISITE:
        return EligibilityDecision(SeedEligibility.DEFER_PREREQUISITE, entry.seed_defer_reason)
    if entry.migration_class != MigrationClass.READY or entry.slice_id != CP_SLICE_ID:
        raise CutoverError("SEED_CLASSIFICATION_UNSUPPORTED", entry.slice_id)
    if binding is None:
        return EligibilityDecision(SeedEligibility.DEFER_BINDING, "BINDING_EVIDENCE_REQUIRED")
    expected = {
        "execution_worktree": str(Path(entry.execution_worktree).expanduser().resolve(strict=False)),
        "repository_toplevel": str(Path(entry.repository_toplevel).expanduser().resolve(strict=False)),
        "branch": entry.branch,
        "head": entry.current_branch_head,
        "clean": True,
        "base_commit_exists": True,
        "implementation_result_commit_exists": True,
        "implementation_result_reachable": True,
    }
    if binding.as_dict() != expected:
        return EligibilityDecision(SeedEligibility.DEFER_BINDING, "IMMUTABLE_BINDING_DRIFT")
    return EligibilityDecision(SeedEligibility.ELIGIBLE, NONE)


def _slice(**values: str) -> MigrationSlice:
    return MigrationSlice(**values).finalized()


def frozen_cut1_manifest() -> MigrationManifest:
    """Return the five accepted CUT-0 inputs in their frozen packet order."""

    phase2_contract = PHASE2_CONTRACT_REF
    common = {
        "logical_source_root": "/Users/kate/PropertyAI/openclaw-workspace",
        "repository_toplevel": "/Users/kate/PropertyAI/openclaw-workspace",
        "execution_worktree": UNBOUND,
        "base_commit": NONE,
        "implementation_result_commit": NONE,
        "current_branch_head": UNBOUND,
        "execution_packet_url": NONE,
        "contract_url": phase2_contract,
        "migration_class": MigrationClass.DEFER_PREREQUISITE,
        "seed_eligibility": SeedEligibility.DEFER_PREREQUISITE,
        "seed_defer_reason": "UPSTREAM_OR_USER_PREREQUISITE_UNRESOLVED",
    }
    manifest = MigrationManifest(
        (
            _slice(
                slice_id=CP_SLICE_ID,
                registry_stage="S6_EVIDENCE",
                registry_status="READY_FOR_CODEX",
                logical_source_root="/Users/kate/PropertyAI/openclaw-workspace/propertyai_core",
                repository_toplevel="/Users/kate/PropertyAI/openclaw-workspace",
                execution_worktree="/Users/kate/PropertyAI/worktrees/cp-01a-2",
                branch="cp-01a-2-cleaner-application-commands",
                base_commit="7bf113f1938fc91d3bb9321e32b25514a47b211f",
                implementation_result_commit="c5793b7f7ec975f581355ea8ed53a36451b55807",
                current_branch_head="3d8491a6ce1a39c23dca0206e11d00c180276afd",
                execution_packet_url=CP01A2_EXECUTION_PACKET_REF,
                contract_url=CP01A2_CONTRACT_REF,
                migration_class=MigrationClass.READY,
                seed_eligibility=SeedEligibility.ELIGIBLE,
                seed_defer_reason=NONE,
            ),
            _slice(
                slice_id="OPENCLAW.PHASE1.OPS_BRIEFING",
                registry_stage="S4_EXECUTION_FROZEN",
                registry_status="READY_FOR_CODEX",
                logical_source_root="/Users/kate/PropertyAI/openclaw-workspace",
                repository_toplevel="/Users/kate/PropertyAI/openclaw-workspace",
                execution_worktree=UNBOUND,
                branch="phase-1-ops-briefing",
                base_commit=UNRESOLVED_BASE,
                implementation_result_commit=NONE,
                current_branch_head=UNBOUND,
                execution_packet_url=PHASE1_EXECUTION_PACKET_REF,
                contract_url=NONE,
                migration_class=MigrationClass.DEFER_BINDING,
                seed_eligibility=SeedEligibility.DEFER_BINDING,
                seed_defer_reason="IMMUTABLE_EXECUTION_BINDING_NOT_YET_RESOLVED",
            ),
            _slice(slice_id="OPENCLAW.PHASE2A.PHOTO_REVIEW", registry_stage="S1_LOGICAL_CONTRACT", registry_status="WAITING_USER", branch="phase-2a-photo-review", **common),
            _slice(slice_id="OPENCLAW.PHASE2B.INCIDENT_DIAGNOSIS", registry_stage="S1_LOGICAL_CONTRACT", registry_status="WAITING_USER", branch="phase-2b-incident-diagnosis", **common),
            _slice(slice_id="OPENCLAW.PHASE2C.WEB_RESEARCH", registry_stage="S1_LOGICAL_CONTRACT", registry_status="WAITING_USER", branch="phase-2c-web-research", **common),
        )
    )
    manifest.validate()
    return manifest


@dataclass(frozen=True)
class SeedResult:
    execution_id: str
    manifest_fingerprint: str
    entry_fingerprint: str
    state: str
    state_version: int
    result_commit: str
    authority_mode: str
    replayed: bool


@dataclass(frozen=True)
class FiveSliceRehearsalResult:
    store_path: Path
    execution_id: str
    slice_rows: tuple[dict[str, Any], ...]
    slice_snapshot_fingerprint: str
    rollback_snapshot_fingerprint: str
    authority_generation: int
    authority_mode: str
    replayed: bool


def _isolated_store_path(path: str | Path) -> Path:
    supplied = Path(path).expanduser()
    if not supplied.is_absolute():
        raise CutoverError("EXPLICIT_ABSOLUTE_ISOLATED_STORE_REQUIRED")
    resolved = supplied.resolve(strict=False)
    operational_root = DEFAULT_RUNTIME_ROOT.resolve(strict=False)
    if resolved == operational_root or resolved.is_relative_to(operational_root):
        raise CutoverError("OPERATIONAL_STORE_FORBIDDEN")
    return resolved


def seed_isolated_cp(
    store_path: str | Path,
    manifest: MigrationManifest,
    binding: GitBindingEvidence,
    *,
    clock=None,
) -> SeedResult:
    """Idempotently seed CP into an explicit, non-authoritative store."""

    path = _isolated_store_path(store_path)
    manifest.validate()
    entry = manifest.entry(CP_SLICE_ID)
    decision = classify_seed_eligibility(entry, binding)
    if decision.eligibility is not SeedEligibility.ELIGIBLE:
        raise CutoverError("SEED_INELIGIBLE", decision.reason)
    path.parent.mkdir(parents=True, exist_ok=True)
    store = ControlStore(path, backup_root=path.parent / "backups", **({"clock": clock} if clock else {}))
    execution_id = "cut2-rehearsal-cp-01a-2"
    replayed = False
    try:
        existing = store.connection.execute(
            "SELECT * FROM slice_execution WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        expected = {
            "slice_id": entry.slice_id,
            "source_root": str(Path(entry.repository_toplevel).resolve(strict=True)),
            "branch": entry.branch,
            "base_commit": entry.base_commit,
            "result_commit": entry.implementation_result_commit,
            "contract_fingerprint": canonical_sha256({"contract_url": entry.contract_url}),
            "authority_fingerprint": entry.snapshot_fingerprint,
        }
        if existing is not None:
            if any(existing[field] != value for field, value in expected.items()):
                raise CutoverError("SEED_FINGERPRINT_CONFLICT", execution_id)
            replayed = True
        else:
            row = store.create_execution(
                ExecutionCreate(
                    execution_id=execution_id,
                    slice_id=entry.slice_id,
                    risk_level=RiskLevel.NORMAL,
                    environment=Environment.TEST,
                    contract_fingerprint=expected["contract_fingerprint"],
                    authority_fingerprint=entry.snapshot_fingerprint,
                    source_root=entry.repository_toplevel,
                    branch=entry.branch,
                    base_commit=entry.base_commit,
                ),
                operation_key("cut1-isolated-seed", {"entry_fingerprint": entry.snapshot_fingerprint}),
            )
            row = store.acquire_lease(
                execution_id,
                row["state_version"],
                operation_key("cut1-isolated-seed-lease", {"entry_fingerprint": entry.snapshot_fingerprint}),
                "cut1-isolated-importer",
            )
            row = store.register_result_commit(
                execution_id,
                row["state_version"],
                operation_key("cut1-isolated-seed-result", {"entry_fingerprint": entry.snapshot_fingerprint}),
                entry.implementation_result_commit,
                lease_owner="cut1-isolated-importer",
                lease_generation=row["lease_generation"],
                actor_role=ActorRole.CONTROLLER,
                actor_id="cut1-isolated-importer",
            )
            row = store.release_lease(
                execution_id,
                row["state_version"],
                operation_key("cut1-isolated-seed-release", {"entry_fingerprint": entry.snapshot_fingerprint}),
                "cut1-isolated-importer",
                row["lease_generation"],
            )
            existing = row
        return SeedResult(
            execution_id,
            manifest.fingerprint,
            entry.snapshot_fingerprint,
            existing["state"],
            existing["state_version"],
            existing["result_commit"],
            AUTHORITY_MODE,
            replayed,
        )
    except StoreError as error:
        raise CutoverError("ISOLATED_SEED_FAILED", error.code) from error
    finally:
        store.close()


def _nullable_manifest_value(value: str) -> str | None:
    return None if value in {NONE, UNBOUND, UNRESOLVED_BASE} else value


def control_state_target(
    entry: MigrationSlice,
    *,
    active_execution_id: str | None = None,
) -> dict[str, Any]:
    """Translate frozen human control semantics to normalized schema-v2 state."""

    entry.validate()
    if entry.migration_class == MigrationClass.READY:
        migration_class = "MIGRATE_AS_READY_CURRENT_STATE"
        execution_eligibility = "ELIGIBLE_BOUND"
        defer_reason = None
        if not active_execution_id:
            raise CutoverError("ACTIVE_EXECUTION_REQUIRED", entry.slice_id)
    elif entry.migration_class == MigrationClass.DEFER_BINDING:
        migration_class = "DEFER_BINDING"
        execution_eligibility = "INELIGIBLE_UNTIL_PREFLIGHT"
        defer_reason = entry.seed_defer_reason
        active_execution_id = None
    elif entry.migration_class == MigrationClass.DEFER_PREREQUISITE:
        migration_class = "DEFER_PREREQUISITE"
        execution_eligibility = "INELIGIBLE_UNTIL_PREREQUISITE"
        defer_reason = entry.seed_defer_reason
        active_execution_id = None
    else:  # pragma: no cover - entry validation owns this boundary
        raise CutoverError("CONTROL_STATE_MIGRATION_CLASS_INVALID", entry.slice_id)

    target: dict[str, Any] = {
        "slice_id": entry.slice_id,
        "stage": entry.registry_stage,
        "status": entry.registry_status,
        "migration_class": migration_class,
        "execution_eligibility": execution_eligibility,
        "defer_reason": defer_reason,
        "logical_source_root": entry.logical_source_root,
        "repository_toplevel": (
            str(Path(entry.repository_toplevel).expanduser().resolve(strict=False))
            if _nullable_manifest_value(entry.repository_toplevel) is not None
            else None
        ),
        "branch": _nullable_manifest_value(entry.branch),
        "base_commit": _nullable_manifest_value(entry.base_commit),
        "implementation_result_commit": _nullable_manifest_value(
            entry.implementation_result_commit
        ),
        "current_branch_head": _nullable_manifest_value(entry.current_branch_head),
        "active_execution_id": active_execution_id,
    }
    if migration_class != "MIGRATE_AS_READY_CURRENT_STATE":
        for field in ("base_commit", "implementation_result_commit", "current_branch_head"):
            target[field] = None
    target["authority_fingerprint"] = control_state_authority_fingerprint(target)
    return {field: target[field] for field in CONTROL_STATE_INPUT_FIELDS}


def control_snapshot_material(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return deterministic five-Slice snapshot material without volatile time."""

    fields = (*CONTROL_STATE_INPUT_FIELDS, "state_version")
    slices = [{field: row.get(field) for field in fields} for row in rows]
    slices.sort(key=lambda item: item["slice_id"])
    payload = {
        "snapshot_version": 2,
        "authority_mode": AUTHORITY_MODE,
        "slice_control_states": slices,
    }
    return {**payload, "snapshot_fingerprint": canonical_sha256(payload)}


def seed_isolated_five_slice_control_state(
    store_path: str | Path,
    manifest: MigrationManifest,
    binding: GitBindingEvidence,
    *,
    clock=None,
) -> FiveSliceRehearsalResult:
    """Seed exactly five normalized Slice rows while remaining Transitional."""

    path = _isolated_store_path(store_path)
    cp_seed = seed_isolated_cp(path, manifest, binding, clock=clock)
    store = ControlStore(
        path,
        backup_root=path.parent / "backups",
        **({"clock": clock} if clock else {}),
    )
    replayed = cp_seed.replayed
    try:
        for entry in manifest.slices:
            target = control_state_target(
                entry,
                active_execution_id=(cp_seed.execution_id if entry.slice_id == CP_SLICE_ID else None),
            )
            current = store.connection.execute(
                "SELECT state_version FROM slice_control_state WHERE slice_id = ?",
                (entry.slice_id,),
            ).fetchone()
            expected = current["state_version"] if current is not None else -1
            _, was_replayed = store.reconcile_slice_control_state(
                target,
                expected,
                operation_key(
                    "cut3-e1-control-state-seed",
                    {
                        "slice_id": entry.slice_id,
                        "authority_fingerprint": target["authority_fingerprint"],
                    },
                ),
                reason_code="CUT3_E1_ISOLATED_RECONCILE",
                metadata={"manifest_fingerprint": manifest.fingerprint},
            )
            replayed = replayed and was_replayed

        rows = tuple(dict(row) for row in store.slice_control_states())
        if len(rows) != 5:
            raise CutoverError("CONTROL_STATE_SLICE_COUNT_INVALID", str(len(rows)))
        snapshot = control_snapshot_material(rows)
        rollback_payload = {
            "snapshot_version": 2,
            "authority_mode": AUTHORITY_MODE,
            "authority_generation": 0,
            "slice_control_states": [],
        }
        rollback_fingerprint = canonical_sha256(rollback_payload)
        authority = store.get_control_authority_state()
        authority, authority_replayed = store.reconcile_transitional_authority(
            authority["authority_generation"],
            snapshot["snapshot_fingerprint"],
            rollback_fingerprint,
        )
        replayed = replayed and authority_replayed
        return FiveSliceRehearsalResult(
            path,
            cp_seed.execution_id,
            rows,
            snapshot["snapshot_fingerprint"],
            rollback_fingerprint,
            authority["authority_generation"],
            authority["mode"],
            replayed,
        )
    except StoreError as error:
        raise CutoverError("E1_ISOLATED_REHEARSAL_FAILED", error.code) from error
    finally:
        store.close()


_ACTIONS = {
    CP_SLICE_ID: (
        "D4=1 approved; S6-C1 Controlled Notion Validation ready",
        "Run the accepted S6-C1 packet; retain Transitional Authority",
    ),
    "OPENCLAW.PHASE1.OPS_BRIEFING": (
        "Execution packet v1.2 frozen",
        "Resolve branch and Base Commit in Maker preflight before seed",
    ),
    "OPENCLAW.PHASE2A.PHOTO_REVIEW": (
        "Logical contract awaiting prerequisites",
        "Complete Phase 1 acceptance and user decisions",
    ),
    "OPENCLAW.PHASE2B.INCIDENT_DIAGNOSIS": (
        "Logical contract awaiting prerequisites",
        "Resolve Phase 1 logging and recovery ownership",
    ),
    "OPENCLAW.PHASE2C.WEB_RESEARCH": (
        "Logical contract awaiting prerequisites",
        "Resolve sandbox, cookie, and Research Inbox prerequisites",
    ),
}


def registry_projection(
    entry: MigrationSlice,
    execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render existing Registry semantics without writing the Registry."""

    entry.validate()
    if entry.seed_eligibility == SeedEligibility.ELIGIBLE:
        if execution is None:
            raise CutoverError("SEEDED_EXECUTION_REQUIRED", entry.slice_id)
        required = {
            "slice_id": entry.slice_id,
            "base_commit": entry.base_commit,
            "result_commit": entry.implementation_result_commit,
            "branch": entry.branch,
            "authority_fingerprint": entry.snapshot_fingerprint,
        }
        if any(execution.get(field) != value for field, value in required.items()):
            raise CutoverError("PROJECTION_BINDING_MISMATCH", entry.slice_id)
    current, next_action = _ACTIONS[entry.slice_id]
    semantic_view = {
        "Stage": entry.registry_stage,
        "Status": entry.registry_status,
        "Base Commit": entry.base_commit,
        "Result Commit": entry.implementation_result_commit,
        "Current Action": current,
        "Next Action": next_action,
    }
    metadata = {
        "control_execution_id": execution.get("execution_id") if execution else None,
        "projection_version": PROJECTION_VERSION,
        "projection_status": "ISOLATED_COMPARISON_ONLY",
        "implementation_result_commit": entry.implementation_result_commit,
        "current_branch_head": entry.current_branch_head,
        "snapshot_fingerprint": entry.snapshot_fingerprint,
    }
    payload = {"slice_id": entry.slice_id, "semantic_view": semantic_view, "metadata": metadata}
    return {**payload, "projection_fingerprint": canonical_sha256(payload)}


def handoff_projection(
    manifest: MigrationManifest,
    registry_views: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Render a deterministic transitional Handoff comparison payload."""

    manifest.validate()
    views = sorted((dict(view) for view in registry_views), key=lambda item: item["slice_id"])
    payload = {
        "handoff_projection_version": PROJECTION_VERSION,
        "current_role": "TRANSITIONAL_HUMAN_CONTROL_VIEW",
        "development_control_store_authority": "NO",
        "authority_mode": AUTHORITY_MODE,
        "manifest_fingerprint": manifest.fingerprint,
        "slices": views,
    }
    return {**payload, "projection_fingerprint": canonical_sha256(payload)}


def snapshot_restore_material(
    store_path: str | Path,
    manifest: MigrationManifest,
    executions: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build deterministic logical restore inputs; never performs a rollback."""

    path = _isolated_store_path(store_path)
    manifest.validate()
    logical_executions = []
    fields = (
        "execution_id", "slice_id", "risk_level", "environment", "state", "state_version",
        "contract_fingerprint", "authority_fingerprint", "source_root", "branch", "base_commit",
        "result_commit", "current_actor_role",
    )
    for execution in executions:
        logical_executions.append({field: execution.get(field) for field in fields})
    logical_executions.sort(key=lambda item: item["execution_id"])
    payload = {
        "snapshot_version": 1,
        "purpose": "CUT1_TEST_ISOLATED_PRE_CUTOVER",
        "accepted_adcp_repository_baseline": ACCEPTED_ADCP_BASELINE,
        "authority_mode": AUTHORITY_MODE,
        "sqlite_schema_version": SCHEMA_VERSION,
        "manifest_canonical_payload": manifest.canonical_payload(),
        "manifest_fingerprint": manifest.fingerprint,
        "slice_dispositions": [
            {
                "slice_id": entry.slice_id,
                "migration_class": entry.migration_class,
                "seed_eligibility": entry.seed_eligibility,
                "seed_defer_reason": entry.seed_defer_reason,
            }
            for entry in manifest.slices
        ],
        "isolated_store_path": str(path),
        "isolated_store_identity": canonical_sha256({"isolated_store_path": str(path)}),
        "restore_inputs": {"slice_executions": logical_executions},
    }
    return {**payload, "snapshot_fingerprint": canonical_sha256(payload)}


__all__ = [
    "ACCEPTED_ADCP_BASELINE",
    "AUTHORITY_MODE",
    "CP_SLICE_ID",
    "CutoverError",
    "EligibilityDecision",
    "FiveSliceRehearsalResult",
    "GitBindingEvidence",
    "MigrationClass",
    "MigrationManifest",
    "MigrationSlice",
    "SeedEligibility",
    "SeedResult",
    "classify_seed_eligibility",
    "control_snapshot_material",
    "control_state_target",
    "frozen_cut1_manifest",
    "handoff_projection",
    "inspect_git_binding",
    "registry_projection",
    "seed_isolated_cp",
    "seed_isolated_five_slice_control_state",
    "snapshot_restore_material",
]
