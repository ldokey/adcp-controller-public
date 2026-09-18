"""Domain primitives for the ADCP control store core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
from pathlib import Path
from typing import Any

from adcp.canonical import canonical_json, canonical_sha256


class StoreError(RuntimeError):
    """A fail-closed control-store error with a stable machine code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class ExecutionState(StrEnum):
    READY = "READY"
    MAKER_RUNNING = "MAKER_RUNNING"
    VERIFYING = "VERIFYING"
    EVALUATING = "EVALUATING"
    REWORK_READY = "REWORK_READY"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    BLOCKED = "BLOCKED"
    DESIGN_ESCALATION = "DESIGN_ESCALATION"
    ACCEPTED = "ACCEPTED"
    CANCELLED = "CANCELLED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"


class Environment(StrEnum):
    TEST = "TEST"
    SHADOW = "SHADOW"
    PRODUCTION = "PRODUCTION"


class ActorRole(StrEnum):
    CONTROLLER = "CONTROLLER"
    MAKER = "MAKER"
    EVALUATOR = "EVALUATOR"
    HUMAN = "HUMAN"


class AgentAttemptStatus(StrEnum):
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    LOST = "LOST"


class ReviewTargetType(StrEnum):
    """The two deliberately non-interchangeable review target kinds."""

    GIT_COMMIT = "GIT_COMMIT"
    UNCOMMITTED_CANDIDATE = "UNCOMMITTED_CANDIDATE"


@dataclass(frozen=True)
class CandidateWriteFence:
    """Caller-held authority, never reconstructed from a live lease at mutation."""

    execution_id: str
    expected_state_version: int
    lease_owner: str
    lease_generation: int
    authority_generation: int
    contract_fingerprint: str
    authority_fingerprint: str


@dataclass(frozen=True)
class CandidateManifestEntry:
    operation: str
    path: str
    mode: str
    byte_length: int | None
    content_sha256: str | None
    base_object_id: str | None = None

    def validate(self) -> None:
        if self.operation not in {"A", "M", "D"}:
            raise StoreError("INVALID_CANDIDATE_MANIFEST", "operation")
        if not self.path or self.path.startswith("/") or "\\" in self.path:
            raise StoreError("INVALID_CANDIDATE_PATH", self.path)
        parts = self.path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise StoreError("INVALID_CANDIDATE_PATH", self.path)
        try:
            if self.path.encode("utf-8").decode("utf-8") != self.path:
                raise UnicodeError
        except UnicodeError as error:
            raise StoreError("INVALID_CANDIDATE_PATH", "UTF-8 required") from error
        if self.mode not in {"100644", "100755", "120000"}:
            raise StoreError("INVALID_CANDIDATE_MANIFEST", "mode")
        if self.operation == "D":
            if self.byte_length is not None or self.content_sha256 is not None or not self.base_object_id:
                raise StoreError("INVALID_CANDIDATE_MANIFEST", "deletion binding")
            require_commit(self.base_object_id, "base_object_id")
        else:
            if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int) or self.byte_length < 0:
                raise StoreError("INVALID_CANDIDATE_MANIFEST", "byte_length")
            if self.content_sha256 is None:
                raise StoreError("INVALID_CANDIDATE_MANIFEST", "content_sha256")
            require_sha256(self.content_sha256, "content_sha256")


class EvaluatorArtifactSealPhase(StrEnum):
    PRE_EXECUTION = "PRE_EXECUTION"
    POST_EXECUTION = "POST_EXECUTION"
    LEGACY_ATTESTED = "LEGACY_ATTESTED"


class EvaluatorArtifactProducerKind(StrEnum):
    CONTROLLER_RUNNER = "CONTROLLER_RUNNER"
    EXECUTION_ADAPTER = "EXECUTION_ADAPTER"
    LEGACY_HUMAN_ATTESTATION = "LEGACY_HUMAN_ATTESTATION"


MAX_AUTO_REWORKS = {
    RiskLevel.LOW: 2,
    RiskLevel.NORMAL: 2,
    RiskLevel.HIGH: 0,
}

TERMINAL_STATES = frozenset(
    {
        ExecutionState.ACCEPTED,
        ExecutionState.CANCELLED,
        ExecutionState.DESIGN_ESCALATION,
    }
)

BLOCKED_RESUME_STATES = frozenset(
    {
        ExecutionState.READY,
        ExecutionState.VERIFYING,
        ExecutionState.EVALUATING,
        ExecutionState.REWORK_READY,
    }
)

TRANSITIONS = {
    ExecutionState.READY: {
        ExecutionState.MAKER_RUNNING,
        ExecutionState.BLOCKED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.MAKER_RUNNING: {
        ExecutionState.VERIFYING,
        ExecutionState.BLOCKED,
        ExecutionState.DESIGN_ESCALATION,
        ExecutionState.CANCELLED,
    },
    ExecutionState.VERIFYING: {
        ExecutionState.EVALUATING,
        ExecutionState.REWORK_READY,
        ExecutionState.DESIGN_ESCALATION,
        ExecutionState.BLOCKED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.EVALUATING: {
        ExecutionState.ACCEPTED,
        ExecutionState.REWORK_READY,
        ExecutionState.DESIGN_ESCALATION,
        ExecutionState.WAITING_APPROVAL,
        ExecutionState.BLOCKED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.REWORK_READY: {
        ExecutionState.MAKER_RUNNING,
        ExecutionState.BLOCKED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.WAITING_APPROVAL: {
        ExecutionState.EVALUATING,
        ExecutionState.DESIGN_ESCALATION,
        ExecutionState.CANCELLED,
    },
    ExecutionState.BLOCKED: set(),  # The stored resume_state is checked dynamically.
    ExecutionState.DESIGN_ESCALATION: set(),
    ExecutionState.ACCEPTED: set(),
    ExecutionState.CANCELLED: set(),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StoreError("INVALID_TIMESTAMP", "timezone-aware UTC input required")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def operation_key(operation_type: str, semantic_inputs: Any) -> str:
    material = f"v1|{operation_type}|{canonical_json(semantic_inputs)}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def require_sha256(value: str, field: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise StoreError("INVALID_INPUT", f"{field} must be lowercase SHA-256")


def require_commit(value: str, field: str = "commit") -> None:
    if len(value) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise StoreError("INVALID_INPUT", f"{field} must be a 40- or 64-character hex id")


def validate_transition(
    from_state: ExecutionState,
    to_state: ExecutionState,
    *,
    stored_resume_state: ExecutionState | None,
    new_resume_state: ExecutionState | None,
) -> None:
    if from_state is ExecutionState.BLOCKED:
        allowed = stored_resume_state is not None and to_state is stored_resume_state
        allowed = allowed or to_state is ExecutionState.CANCELLED
    else:
        allowed = to_state in TRANSITIONS[from_state]
    if not allowed:
        raise StoreError("INVALID_TRANSITION", f"{from_state.value}->{to_state.value}")

    if to_state is ExecutionState.WAITING_APPROVAL:
        if new_resume_state is not ExecutionState.EVALUATING:
            raise StoreError("INVALID_TRANSITION", "WAITING_APPROVAL resumes to EVALUATING")
    elif to_state is ExecutionState.BLOCKED:
        if new_resume_state not in BLOCKED_RESUME_STATES:
            raise StoreError("INVALID_TRANSITION", "invalid BLOCKED resume_state")
    elif new_resume_state is not None:
        raise StoreError("INVALID_TRANSITION", "resume_state is not allowed")


@dataclass(frozen=True)
class EvaluatorArtifactSealCreate:
    seal_id: str
    execution_id: str
    result_commit: str
    verification_id: str
    evaluator_attempt_id: str
    context_snapshot_id: str
    context_fingerprint: str
    contract_fingerprint: str
    authority_fingerprint: str
    phase: EvaluatorArtifactSealPhase
    producer_kind: EvaluatorArtifactProducerKind
    producer_ref: str
    evidence_root: str
    manifest_version: int
    manifest_json: str
    manifest_sha256: str
    authority_generation: int
    operation_key: str
    approval_id: str | None = None

    def validate(self) -> None:
        for field, value in (
            ("seal_id", self.seal_id),
            ("execution_id", self.execution_id),
            ("verification_id", self.verification_id),
            ("evaluator_attempt_id", self.evaluator_attempt_id),
            ("context_snapshot_id", self.context_snapshot_id),
            ("producer_ref", self.producer_ref),
            ("evidence_root", self.evidence_root),
        ):
            if not isinstance(value, str) or not value:
                raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", field)
        require_commit(self.result_commit, "result_commit")
        for field, value in (
            ("context_fingerprint", self.context_fingerprint),
            ("contract_fingerprint", self.contract_fingerprint),
            ("authority_fingerprint", self.authority_fingerprint),
            ("manifest_sha256", self.manifest_sha256),
            ("operation_key", self.operation_key),
        ):
            require_sha256(value, field)
        if self.manifest_version != 1:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "manifest_version")
        if isinstance(self.authority_generation, bool) or not isinstance(self.authority_generation, int) or self.authority_generation < 0:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "authority_generation")
        if not Path(self.evidence_root).is_absolute():
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "evidence_root")
        try:
            manifest = json.loads(self.manifest_json)
        except (TypeError, json.JSONDecodeError) as error:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "manifest_json") from error
        if canonical_json(manifest) != self.manifest_json or canonical_sha256(manifest) != self.manifest_sha256:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "manifest_hash")
        if self.phase is EvaluatorArtifactSealPhase.LEGACY_ATTESTED:
            if self.producer_kind is not EvaluatorArtifactProducerKind.LEGACY_HUMAN_ATTESTATION or not self.approval_id:
                raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "legacy_attestation")
        elif self.producer_kind not in {EvaluatorArtifactProducerKind.CONTROLLER_RUNNER, EvaluatorArtifactProducerKind.EXECUTION_ADAPTER} or self.approval_id is not None:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL", "producer_kind")


@dataclass(frozen=True)
class ExecutionCreate:
    execution_id: str
    slice_id: str
    risk_level: RiskLevel
    environment: Environment
    contract_fingerprint: str
    authority_fingerprint: str
    source_root: str
    branch: str
    base_commit: str
    current_actor_role: ActorRole = ActorRole.CONTROLLER

    @property
    def max_auto_reworks(self) -> int:
        return MAX_AUTO_REWORKS[self.risk_level]

    def validate(self) -> None:
        for field, value in (
            ("execution_id", self.execution_id),
            ("slice_id", self.slice_id),
            ("branch", self.branch),
        ):
            if not value:
                raise StoreError("INVALID_INPUT", f"{field} is required")
        require_sha256(self.contract_fingerprint, "contract_fingerprint")
        require_sha256(self.authority_fingerprint, "authority_fingerprint")
        require_commit(self.base_commit, "base_commit")
