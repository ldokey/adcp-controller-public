"""Fail-closed crash recovery over the durable C4 Controller state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import subprocess
from typing import Any

from adcp.canonical import canonical_sha256
from adcp.controller import ApprovalBinding, Controller, ControllerError
from adcp.domain import ActorRole, ExecutionState, StoreError, operation_key, timestamp
from adcp.evaluator import (
    EvaluatorBoundaryError,
    build_evaluation_result,
    decode_durable_evaluator_result_bytes_for_recovery,
    evaluation_result_identity,
)
from adcp.projection import ProjectionService
from adcp.store.sqlite import ControlStore


class RecoveryAction(StrEnum):
    SCHEDULE_MAKER = "SCHEDULE_MAKER"
    WAIT_MAKER = "WAIT_MAKER"
    MAKER_LOST = "MAKER_LOST"
    AWAIT_VERIFICATION = "AWAIT_VERIFICATION"
    SCHEDULE_EVALUATOR = "SCHEDULE_EVALUATOR"
    AWAIT_EVALUATOR = "AWAIT_EVALUATOR"
    WAIT_APPROVAL = "WAIT_APPROVAL"
    ACCEPTED = "ACCEPTED"
    PROJECTED = "PROJECTED"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True)
class RecoveryDecision:
    action: RecoveryAction
    state: ExecutionState
    detail: str | None = None


class RecoveryManager:
    """Resume persisted boundaries without replaying completed semantic work."""

    def __init__(
        self,
        store: ControlStore,
        controller: Controller,
        *,
        projection: ProjectionService | None = None,
    ) -> None:
        if controller.store is not store:
            raise ControllerError("RECOVERY_STORE_MISMATCH")
        self.store = store
        self.controller = controller
        self.projection = projection

    def resume_once(
        self,
        execution_id: str,
        *,
        approval_required: bool = False,
    ) -> RecoveryDecision:
        row = self.store.get_execution(execution_id)
        state = ExecutionState(row["state"])
        if state is ExecutionState.ACCEPTED:
            if self.projection is None:
                return RecoveryDecision(RecoveryAction.ACCEPTED, state)
            self.projection.project(execution_id)
            return RecoveryDecision(RecoveryAction.PROJECTED, state)
        if state in {
            ExecutionState.CANCELLED,
            ExecutionState.DESIGN_ESCALATION,
            ExecutionState.BLOCKED,
        }:
            return RecoveryDecision(RecoveryAction.TERMINAL, state)

        row, lease_recovered = self._ensure_fence(execution_id)
        state = ExecutionState(row["state"])
        if state in {ExecutionState.READY, ExecutionState.REWORK_READY}:
            return RecoveryDecision(RecoveryAction.SCHEDULE_MAKER, state)
        if state is ExecutionState.MAKER_RUNNING:
            return self._resume_maker(row, lease_recovered)
        if state is ExecutionState.VERIFYING:
            return self._resume_verification(row)
        if state is ExecutionState.EVALUATING:
            return self._resume_evaluation(row, approval_required, lease_recovered)
        if state is ExecutionState.WAITING_APPROVAL:
            return self._resume_approval(row, approval_required)
        raise ControllerError("RECOVERY_STATE_UNSUPPORTED", state.value)

    def _ensure_fence(self, execution_id: str) -> tuple[Any, bool]:
        row = self.store.get_execution(execution_id)
        now = timestamp(self.store._now())
        if (
            row["lease_owner"] == self.controller.controller_id
            and row["lease_expires_at"] is not None
            and row["lease_expires_at"] > now
        ):
            return row, False
        recovered = row["lease_owner"] is not None
        leased = self.store.acquire_lease(
            execution_id,
            row["state_version"],
            operation_key(
                "recovery-lease",
                {
                    "execution_id": execution_id,
                    "version": row["state_version"],
                    "owner": self.controller.controller_id,
                    "prior_generation": row["lease_generation"],
                },
            ),
            self.controller.controller_id,
        )
        return leased, recovered

    def _latest_attempt(self, execution_id: str, role: str):
        return self.store.connection.execute(
            """SELECT * FROM agent_attempt WHERE execution_id = ? AND role = ?
                 ORDER BY attempt_no DESC LIMIT 1""",
            (execution_id, role),
        ).fetchone()

    def _maker_resume_state(self, row: Any) -> ExecutionState:
        attempt = self._latest_attempt(row["execution_id"], "MAKER")
        return (
            ExecutionState.REWORK_READY
            if row["maker_rework_count"] or (attempt is not None and attempt["attempt_no"] > 1)
            else ExecutionState.READY
        )

    def _resume_maker(self, row: Any, lease_recovered: bool) -> RecoveryDecision:
        execution_id = row["execution_id"]
        attempt = self._latest_attempt(execution_id, "MAKER")
        if attempt is None:
            self.controller._transition(
                execution_id,
                ExecutionState.BLOCKED,
                reason="RECOVERY_MAKER_EVIDENCE_MISSING",
                resume_state=ExecutionState.READY,
                blocker_code="BLOCKED_EVIDENCE",
            )
            return RecoveryDecision(
                RecoveryAction.TERMINAL, ExecutionState.BLOCKED, "BLOCKED_EVIDENCE"
            )
        if (
            row["result_commit"] is not None
            and attempt["result_commit"] is not None
            and row["result_commit"] != attempt["result_commit"]
        ):
            return self._block_maker_evidence(row, "RESULT_COMMIT_BINDING_MISMATCH")
        result_commit = row["result_commit"] or attempt["result_commit"]
        if attempt["status"] == "SUCCEEDED" and result_commit is not None:
            if not self._candidate_commit_is_valid(attempt, result_commit):
                return self._block_maker_evidence(row, "CANDIDATE_COMMIT_INVALID")
            if row["result_commit"] is None:
                current = self.store.get_execution(execution_id)
                controlled = self.store.connection.execute(
                    "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
                    (execution_id,),
                ).fetchone()
                if controlled is not None and controlled["migration_class"] == "DEFER_BINDING":
                    invalid = self._finalize_deferred_maker_result(
                        current, attempt, controlled, result_commit
                    )
                    if invalid is not None:
                        return invalid
                else:
                    self.store.register_result_commit(
                        execution_id,
                        current["state_version"],
                        operation_key(
                            "candidate-result",
                            {"execution_id": execution_id, "commit": result_commit},
                        ),
                        result_commit,
                        lease_owner=self.controller.controller_id,
                        lease_generation=current["lease_generation"],
                        actor_role=ActorRole.CONTROLLER,
                        actor_id=self.controller.controller_id,
                    )
            elif self._deferred_slice_requires_finalization(row):
                return self._block_maker_evidence(
                    row, "PREBIND_RESULT_PARTIAL_BINDING"
                )
            self.controller._transition(
                execution_id, ExecutionState.VERIFYING, reason="MAKER_SUCCEEDED"
            )
            return RecoveryDecision(
                RecoveryAction.AWAIT_VERIFICATION, ExecutionState.VERIFYING
            )
        if row["result_commit"] is not None:
            return self._block_maker_evidence(row, "MAKER_RESULT_BINDING_INVALID")
        if attempt["status"] == "RUNNING" and lease_recovered:
            self.store.finish_agent_attempt(
                attempt["attempt_id"],
                status="LOST",
                ended_at=timestamp(self.store._now()),
                failure_code="LOST_CONTROLLER_LEASE",
            )
            resume = self._maker_resume_state(row)
            self.controller._transition(
                execution_id,
                ExecutionState.BLOCKED,
                reason="LOST_MAKER_ATTEMPT",
                resume_state=resume,
                blocker_code="BLOCKED_ENVIRONMENT",
            )
            return RecoveryDecision(
                RecoveryAction.MAKER_LOST,
                ExecutionState.BLOCKED,
                "LOST_CONTROLLER_LEASE",
            )
        if attempt["status"] == "RUNNING":
            return RecoveryDecision(RecoveryAction.WAIT_MAKER, ExecutionState.MAKER_RUNNING)
        self.controller._transition(
            execution_id,
            ExecutionState.BLOCKED,
            reason="RECOVERY_MAKER_NOT_SUCCESSFUL",
            resume_state=self._maker_resume_state(row),
            blocker_code="BLOCKED_EVIDENCE",
        )
        return RecoveryDecision(
            RecoveryAction.TERMINAL, ExecutionState.BLOCKED, "BLOCKED_EVIDENCE"
        )

    def _candidate_commit_is_valid(self, attempt: Any, result_commit: str) -> bool:
        root = self.controller.worktrees.source_root
        exists = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{result_commit}^{{commit}}"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if exists.returncode != 0:
            return False
        parent = subprocess.run(
            ["git", "-C", str(root), "rev-parse", f"{result_commit}^"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
        return parent.returncode == 0 and parent.stdout.strip() == attempt["base_commit"]

    def _deferred_slice_requires_finalization(self, row: Any) -> bool:
        controlled = self.store.connection.execute(
            "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
            (row["execution_id"],),
        ).fetchone()
        return bool(
            controlled is not None
            and controlled["migration_class"] == "DEFER_BINDING"
            and controlled["execution_eligibility"] == "ELIGIBLE_PREEXECUTION_BOUND"
        )

    def _finalize_deferred_maker_result(
        self,
        row: Any,
        attempt: Any,
        controlled: Any,
        result_commit: str,
    ) -> RecoveryDecision | None:
        execution_id = row["execution_id"]
        if (
            controlled["execution_eligibility"] != "ELIGIBLE_PREEXECUTION_BOUND"
            or controlled["active_execution_id"] != execution_id
            or controlled["repository_toplevel"] != row["source_root"]
            or controlled["branch"] != row["branch"]
            or controlled["base_commit"] != row["base_commit"]
            or controlled["current_branch_head"] != row["base_commit"]
            or controlled["implementation_result_commit"] is not None
            or attempt["base_commit"] != row["base_commit"]
        ):
            return self._block_maker_evidence(row, "PREEXECUTION_BIND_CONFLICT")

        try:
            binding = self.store.get_deferred_binding(execution_id)
        except StoreError as error:
            return self._block_maker_evidence(row, error.code)

        expected_binding = {
            "execution_id": execution_id,
            "slice_id": row["slice_id"],
            "repository_toplevel": row["source_root"],
            "branch": row["branch"],
            "base_commit": row["base_commit"],
            "contract_fingerprint": row["contract_fingerprint"],
            "authority_fingerprint": row["authority_fingerprint"],
            "risk_level": row["risk_level"],
            "environment": row["environment"],
        }
        if any(binding[field] != value for field, value in expected_binding.items()):
            return self._block_maker_evidence(row, "PREEXECUTION_BIND_CONFLICT")

        try:
            self.controller.worktrees.reuse_bound(
                execution_id,
                Path(binding["worktree_path"]),
                row["branch"],
                result_commit,
                branch_created=bool(binding["branch_created"]),
                worktree_created=bool(binding["worktree_created"]),
            )
        except ControllerError as error:
            return self._block_maker_evidence(row, error.code)

        self.store.finalize_deferred_result_commit(
            execution_id,
            row["state_version"],
            controlled["state_version"],
            operation_key(
                "candidate-result",
                {"execution_id": execution_id, "commit": result_commit},
            ),
            result_commit,
            expected_current_branch_head=controlled["current_branch_head"],
            lease_owner=self.controller.controller_id,
            lease_generation=row["lease_generation"],
            actor_role=ActorRole.CONTROLLER,
            actor_id=self.controller.controller_id,
        )
        return None

    def _block_maker_evidence(self, row: Any, detail: str) -> RecoveryDecision:
        self.controller._transition(
            row["execution_id"],
            ExecutionState.BLOCKED,
            reason="RECOVERY_MAKER_EVIDENCE_INVALID",
            resume_state=self._maker_resume_state(row),
            blocker_code="BLOCKED_EVIDENCE",
            blocker_detail=detail,
        )
        return RecoveryDecision(
            RecoveryAction.TERMINAL, ExecutionState.BLOCKED, detail
        )

    def _bound_result(self, table: str, sequence: str, row: Any):
        if row["result_commit"] is None:
            return None
        return self.store.connection.execute(
            f"""SELECT * FROM {table}
                  WHERE execution_id = ? AND result_commit = ?
                    AND contract_fingerprint = ? AND authority_fingerprint = ?
                  ORDER BY {sequence} DESC LIMIT 1""",
            (
                row["execution_id"],
                row["result_commit"],
                row["contract_fingerprint"],
                row["authority_fingerprint"],
            ),
        ).fetchone()

    def _resume_verification(self, row: Any) -> RecoveryDecision:
        verification = self._bound_result(
            "verification_result", "verification_seq", row
        )
        if verification is None:
            return RecoveryDecision(
                RecoveryAction.AWAIT_VERIFICATION, ExecutionState.VERIFYING
            )
        if verification["verdict"] == "PASS":
            self.controller._transition(
                row["execution_id"],
                ExecutionState.EVALUATING,
                reason="VERIFICATION_PASSED",
            )
            return RecoveryDecision(
                RecoveryAction.SCHEDULE_EVALUATOR, ExecutionState.EVALUATING
            )
        self.controller._transition(
            row["execution_id"],
            ExecutionState.BLOCKED,
            reason="VERIFICATION_BLOCKED",
            resume_state=ExecutionState.VERIFYING,
            blocker_code=(
                "BLOCKED_ENVIRONMENT"
                if verification["verdict"] == "BLOCKED_ENVIRONMENT"
                else "VERIFICATION_FAILED"
            ),
        )
        return RecoveryDecision(RecoveryAction.TERMINAL, ExecutionState.BLOCKED)

    def _resume_evaluation(
        self, row: Any, approval_required: bool, lease_recovered: bool
    ) -> RecoveryDecision:
        evaluation = self._bound_result(
            "evaluation_result", "evaluation_seq", row
        )
        if evaluation is not None:
            attempt = self.store.get_agent_attempt(evaluation["evaluator_attempt_id"])
            seal = self.store.find_authoritative_evaluator_artifact_seal(
                attempt["attempt_id"]
            )
            try:
                if seal is None:
                    raise StoreError("EVALUATOR_ARTIFACT_SEAL_REQUIRED")
                self.store.verify_evaluator_artifact_seal(
                    seal["seal_id"], expected_attempt_id=attempt["attempt_id"]
                )
            except StoreError:
                self.controller._transition(
                    row["execution_id"],
                    ExecutionState.BLOCKED,
                    reason="RECOVERY_EVALUATOR_SEAL_INVALID",
                    resume_state=ExecutionState.EVALUATING,
                    blocker_code="BLOCKED_EVIDENCE",
                )
                return RecoveryDecision(
                    RecoveryAction.TERMINAL,
                    ExecutionState.BLOCKED,
                    "BLOCKED_EVIDENCE",
                )

        if evaluation is None:
            attempt = self._latest_attempt(row["execution_id"], "EVALUATOR")
            if attempt is None:
                return RecoveryDecision(
                    RecoveryAction.SCHEDULE_EVALUATOR, ExecutionState.EVALUATING
                )
            seal = self.store.find_authoritative_evaluator_artifact_seal(
                attempt["attempt_id"]
            )
            if attempt["status"] == "RUNNING" and not lease_recovered:
                return RecoveryDecision(
                    RecoveryAction.AWAIT_EVALUATOR, ExecutionState.EVALUATING
                )
            if attempt["status"] == "RUNNING" and seal is not None:
                try:
                    self.store.verify_evaluator_artifact_seal(
                        seal["seal_id"], expected_attempt_id=attempt["attempt_id"]
                    )
                    self.store.finish_agent_attempt(
                        attempt["attempt_id"],
                        status="SUCCEEDED",
                        result_commit=row["result_commit"],
                        exit_code=0,
                        ended_at=timestamp(self.store._now()),
                        post_execution_seal_id=seal["seal_id"],
                        lease_owner=self.controller.controller_id,
                        lease_generation=row["lease_generation"],
                        required_execution_state=ExecutionState.EVALUATING,
                    )
                    attempt = self.store.get_agent_attempt(attempt["attempt_id"])
                except StoreError:
                    blocker = "BLOCKED_EVIDENCE"
                else:
                    blocker = None
            elif attempt["status"] == "RUNNING":
                self.store.finish_agent_attempt(
                    attempt["attempt_id"],
                    status="LOST",
                    result_commit=attempt["result_commit"],
                    ended_at=timestamp(self.store._now()),
                    failure_code="EVALUATOR_POST_SEAL_MISSING",
                )
                blocker = "BLOCKED_EVIDENCE"
            elif attempt["status"] in {"FAILED", "ABORTED", "LOST"}:
                blocker = "BLOCKED_ENVIRONMENT"
            else:
                blocker = None
            if attempt["status"] == "SUCCEEDED" and blocker is None:
                record = self._recoverable_evaluation_record(row, attempt)
                if record is not None:
                    evaluation = self.store.register_evaluation_result(
                        record,
                        lease_owner=self.controller.controller_id,
                        lease_generation=row["lease_generation"],
                        required_execution_state=ExecutionState.EVALUATING,
                    )
                else:
                    blocker = "BLOCKED_EVIDENCE"
            if evaluation is None:
                self.controller._transition(
                    row["execution_id"],
                    ExecutionState.BLOCKED,
                    reason="RECOVERY_EVALUATOR_INCOMPLETE",
                    resume_state=ExecutionState.EVALUATING,
                    blocker_code=blocker,
                )
                return RecoveryDecision(
                    RecoveryAction.TERMINAL, ExecutionState.BLOCKED, blocker
                )
        verdict = evaluation["verdict"]
        if verdict == "PASS":
            approval = self._development_acceptance_approval(row["execution_id"])
            if approval is not None and approval["consumed_at"] is not None:
                raise ControllerError("RECOVERY_APPROVAL_ALREADY_CONSUMED")
            if approval is not None and approval["status"] == "APPROVED":
                self._validate_approval_binding(
                    approval, row, evaluation, state_version=row["state_version"] - 1
                )
                accepted = self.controller.accept(
                    row["execution_id"],
                    approval=ApprovalBinding(
                        approval["approval_id"], approval["authority_ref"]
                    ),
                )
                return RecoveryDecision(
                    RecoveryAction.ACCEPTED, ExecutionState(accepted["state"])
                )
            if approval_required:
                if approval is not None:
                    self._validate_approval_binding(
                        approval, row, evaluation, state_version=row["state_version"] + 1
                    )
                waiting = self.controller._transition(
                    row["execution_id"],
                    ExecutionState.WAITING_APPROVAL,
                    reason="HUMAN_APPROVAL_REQUIRED",
                    resume_state=ExecutionState.EVALUATING,
                )
                self._ensure_approval(waiting, evaluation)
                return RecoveryDecision(
                    RecoveryAction.WAIT_APPROVAL, ExecutionState.WAITING_APPROVAL
                )
            accepted = self.controller.accept(row["execution_id"])
            return RecoveryDecision(
                RecoveryAction.ACCEPTED, ExecutionState(accepted["state"])
            )
        if verdict == "REWORK_REQUIRED":
            target = (
                ExecutionState.DESIGN_ESCALATION
                if row["maker_rework_count"] >= row["max_auto_reworks"]
                else ExecutionState.REWORK_READY
            )
            self.controller._transition(
                row["execution_id"],
                target,
                reason=(
                    "REWORK_BUDGET_EXHAUSTED"
                    if target is ExecutionState.DESIGN_ESCALATION
                    else "REWORK_REQUIRED"
                ),
                blocker_code=(
                    "REWORK_BUDGET_EXHAUSTED"
                    if target is ExecutionState.DESIGN_ESCALATION
                    else None
                ),
            )
        elif verdict == "DESIGN_REVIEW_REQUIRED":
            self.controller._transition(
                row["execution_id"],
                ExecutionState.DESIGN_ESCALATION,
                reason="DESIGN_REVIEW_REQUIRED",
                blocker_code="DESIGN_REVIEW_REQUIRED",
            )
        else:
            self.controller._transition(
                row["execution_id"],
                ExecutionState.BLOCKED,
                reason=verdict,
                resume_state=ExecutionState.EVALUATING,
                blocker_code=verdict,
            )
        current = self.store.get_execution(row["execution_id"])
        return RecoveryDecision(
            RecoveryAction.TERMINAL, ExecutionState(current["state"]), verdict
        )

    def _recoverable_evaluation_record(self, row: Any, attempt: Any):
        """Rebuild only from an authoritative seal; never reseal evaluator output."""

        if (
            attempt["execution_id"] != row["execution_id"]
            or attempt["role"] != "EVALUATOR"
            or attempt["status"] != "SUCCEEDED"
            or attempt["result_commit"] != row["result_commit"]
            or attempt["exit_code"] != 0
            or attempt["failure_code"] is not None
            or attempt["ended_at"] is None
        ):
            return None
        try:
            seal = self.store.find_authoritative_evaluator_artifact_seal(
                attempt["attempt_id"]
            )
            if seal is None:
                return None
            _, view = self.store.verify_evaluator_artifact_seal(
                seal["seal_id"], expected_attempt_id=attempt["attempt_id"]
            )
            context = self.store.get_context_snapshot(attempt["context_snapshot_id"])
            if (
                context["execution_id"] != row["execution_id"]
                or context["role"] != "EVALUATOR"
            ):
                return None
            result = decode_durable_evaluator_result_bytes_for_recovery(
                view.bytes_for_role("result")
            )
            evaluation_id, result_operation_key = evaluation_result_identity(
                attempt["attempt_id"]
            )
            record = build_evaluation_result(
                evaluation_id=evaluation_id,
                operation_key=result_operation_key,
                execution_id=row["execution_id"],
                evaluator_attempt_id=attempt["attempt_id"],
                context_snapshot_id=attempt["context_snapshot_id"],
                result_commit=row["result_commit"],
                contract_fingerprint=row["contract_fingerprint"],
                authority_fingerprint=row["authority_fingerprint"],
                verdict=result["verdict"],
                result=result,
                started_at=attempt["started_at"],
                ended_at=attempt["ended_at"],
            )
            self.store.validate_evaluation_completion_binding(
                record, artifact_seal_id=seal["seal_id"]
            )
            return record
        except (EvaluatorBoundaryError, StoreError, TypeError, ValueError):
            return None

    def _resume_approval(
        self, row: Any, approval_required: bool
    ) -> RecoveryDecision:
        approval = self._development_acceptance_approval(row["execution_id"])
        evaluation = self._bound_result(
            "evaluation_result", "evaluation_seq", row
        )
        if approval is None:
            if not approval_required or evaluation is None or evaluation["verdict"] != "PASS":
                raise ControllerError("RECOVERY_APPROVAL_BINDING_MISSING")
            approval = self._ensure_approval(row, evaluation)
        else:
            if evaluation is None:
                raise ControllerError("RECOVERY_STALE_APPROVAL")
            self._validate_approval_binding(approval, row, evaluation)
        if approval["status"] == "PENDING":
            return RecoveryDecision(
                RecoveryAction.WAIT_APPROVAL, ExecutionState.WAITING_APPROVAL
            )
        if approval["status"] == "APPROVED":
            self.controller._transition(
                row["execution_id"],
                ExecutionState.EVALUATING,
                reason="APPROVAL_RECORDED",
            )
            accepted = self.controller.accept(
                row["execution_id"],
                approval=ApprovalBinding(
                    approval["approval_id"], approval["authority_ref"]
                ),
            )
            return RecoveryDecision(
                RecoveryAction.ACCEPTED, ExecutionState(accepted["state"])
            )
        if approval["status"] == "REJECTED":
            self.controller._transition(
                row["execution_id"],
                ExecutionState.DESIGN_ESCALATION,
                reason="APPROVAL_REJECTED",
                blocker_code="APPROVAL_REJECTED",
            )
            return RecoveryDecision(
                RecoveryAction.TERMINAL, ExecutionState.DESIGN_ESCALATION
            )
        raise ControllerError("RECOVERY_APPROVAL_ALREADY_CONSUMED")

    def _development_acceptance_approval(self, execution_id: str):
        approvals = self.store.connection.execute(
            """SELECT * FROM approval_request WHERE execution_id = ?
                 AND approval_type = 'DEVELOPMENT_ACCEPTANCE'
                 ORDER BY requested_at DESC""",
            (execution_id,),
        ).fetchall()
        if len(approvals) > 1:
            raise ControllerError("RECOVERY_STALE_APPROVAL")
        return approvals[0] if approvals else None

    def _validate_approval_binding(
        self,
        approval: Any,
        row: Any,
        evaluation: Any,
        *,
        state_version: int | None = None,
    ) -> None:
        if approval["authority_ref"] != self._approval_ref(
            row, evaluation, state_version=state_version
        ):
            raise ControllerError("RECOVERY_STALE_APPROVAL")
        if approval["consumed_at"] is not None:
            raise ControllerError("RECOVERY_APPROVAL_ALREADY_CONSUMED")

    def _ensure_approval(self, row: Any, evaluation: Any):
        existing = self._development_acceptance_approval(row["execution_id"])
        if existing is not None:
            self._validate_approval_binding(existing, row, evaluation)
            return existing
        authority_ref = self._approval_ref(row, evaluation)
        approval_id = f"approval-recovery-{evaluation['evaluation_id']}"
        return self.store.request_approval(
            approval_id=approval_id,
            idempotency_key=operation_key(
                "approval-request", {"approval_id": approval_id}
            ),
            execution_id=row["execution_id"],
            approval_type="DEVELOPMENT_ACCEPTANCE",
            authority_ref=authority_ref,
            expected_state_version=row["state_version"],
            lease_owner=self.controller.controller_id,
            lease_generation=row["lease_generation"],
        )

    @staticmethod
    def _approval_ref(
        row: Any, evaluation: Any, *, state_version: int | None = None
    ) -> str:
        return canonical_sha256(
            {
                "execution_id": row["execution_id"],
                "state_version": (
                    row["state_version"] if state_version is None else state_version
                ),
                "result_commit": row["result_commit"],
                "evaluation_id": evaluation["evaluation_id"],
                "contract_fingerprint": row["contract_fingerprint"],
                "authority_fingerprint": row["authority_fingerprint"],
            }
        )


__all__ = ["RecoveryAction", "RecoveryDecision", "RecoveryManager"]
