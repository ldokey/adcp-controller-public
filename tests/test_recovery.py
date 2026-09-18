from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from adcp.capsule import build_maker_capsule
from adcp.controller import Controller, ControllerError
from adcp.domain import (
    ActorRole,
    Environment,
    ExecutionCreate,
    ExecutionState,
    RiskLevel,
    StoreError,
    operation_key,
    timestamp,
)
from adcp.projection import InMemoryProjectionTarget, ProjectionService
from adcp.recovery import RecoveryAction, RecoveryManager
from adcp.store.sqlite import control_state_authority_fingerprint
from tests._helpers import ControllerFixture, HASH_A, HASH_B


class RecoveryTests(ControllerFixture, unittest.TestCase):
    PREBOUND_SLICE_ID = "slice-prebound-recovery"
    PREBOUND_EXECUTION_ID = "execution-prebound-recovery"
    PREBOUND_BRANCH = "prebound-recovery"
    PREBOUND_PACKET_REF = "ADCP-C5A-PREBIND-RECOVERY-R1:test"

    def recovery(self, *, projection: ProjectionService | None = None) -> RecoveryManager:
        return RecoveryManager(self.store, self.controller, projection=projection)

    def seed_prebound_slice(self) -> None:
        target = {
            "slice_id": self.PREBOUND_SLICE_ID,
            "stage": "S4_EXECUTION_FROZEN",
            "status": "WAITING_PREFLIGHT",
            "authority_fingerprint": "0" * 64,
            "migration_class": "DEFER_BINDING",
            "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
            "defer_reason": "DEFER_SEED_UNTIL_BRANCH_BASE_PREFLIGHT",
            "logical_source_root": str(self.controller.worktrees.source_root),
            "repository_toplevel": str(self.controller.worktrees.source_root),
            "branch": self.PREBOUND_BRANCH,
            "base_commit": None,
            "implementation_result_commit": None,
            "current_branch_head": None,
            "active_execution_id": None,
        }
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        self.store.reconcile_slice_control_state(
            target,
            -1,
            operation_key("seed-prebound-recovery", {"slice_id": self.PREBOUND_SLICE_ID}),
            reason_code="CUTOVER_DEFER_BINDING",
        )

    def prebound_capsule(self):
        return build_maker_capsule(
            slice={"slice_id": self.PREBOUND_SLICE_ID},
            current_task={"capability": "ADCP-C5A-PREBIND-RECOVERY-R1"},
            contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B,
            source_root=str(
                self.controller.worktrees.expected_bound_path(self.PREBOUND_EXECUTION_ID)
            ),
            branch=self.PREBOUND_BRANCH,
            base_commit=self.base_commit,
            current_commit=self.base_commit,
            acceptance_criteria=["recover existing candidate"],
            constraints=["temporary fixtures only"],
            risk="NORMAL",
            environment="TEST",
            allowed_actions=["recover isolated candidate"],
            forbidden_actions=["production write"],
            relevant_authority_refs=[self.PREBOUND_PACKET_REF],
            relevant_authority_excerpts=["preserve PREBIND finalization"],
        )

    def prepare_prebound_succeeded_candidate(self):
        self.seed_prebound_slice()
        self.controller.bind_deferred_execution(
            ExecutionCreate(
                execution_id=self.PREBOUND_EXECUTION_ID,
                slice_id=self.PREBOUND_SLICE_ID,
                risk_level=RiskLevel.NORMAL,
                environment=Environment.TEST,
                contract_fingerprint=HASH_A,
                authority_fingerprint=HASH_B,
                source_root=str(self.repo),
                branch=self.PREBOUND_BRANCH,
                base_commit=self.base_commit,
            ),
            expected_state_version=0,
            maker_capsule=self.prebound_capsule(),
            packet_ref=self.PREBOUND_PACKET_REF,
            provision_branch_if_missing=True,
        )
        leased = self.controller.acquire(self.PREBOUND_EXECUTION_ID)
        run = self.controller.begin_maker(
            self.PREBOUND_EXECUTION_ID, self.prebound_capsule()
        )
        (run.candidate.path / "tracked.txt").write_text(
            "prebound recovered candidate\n", encoding="utf-8"
        )
        result_commit = self.controller.worktrees.create_candidate_commit(
            run.candidate, run.before, message="prebound recovered candidate"
        )
        self.store.finish_agent_attempt(
            run.attempt_id,
            status="SUCCEEDED",
            result_commit=result_commit,
            exit_code=0,
            ended_at=timestamp(self.store._now()),
        )
        return run, result_commit, leased

    def recovered_prebound_controller(self) -> Controller:
        return Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "worktrees",
            controller_id="controller-recovery",
        )

    def test_resume_ready_execution_does_not_duplicate_attempt(self) -> None:
        self.create_controller_execution()
        recovery = self.recovery()

        first = recovery.resume_once("execution-1")
        second = recovery.resume_once("execution-1")

        self.assertEqual(first.action, RecoveryAction.SCHEDULE_MAKER)
        self.assertEqual(second.action, RecoveryAction.SCHEDULE_MAKER)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt"
        ).fetchone()[0], 0)

    def test_resume_lost_maker_attempt_uses_fencing_and_no_duplicate_commit(self) -> None:
        self.create_controller_execution()
        self.controller.begin_maker("execution-1", self.maker_capsule())
        old_generation = self.store.get_execution("execution-1")["lease_generation"]
        self.clock.advance(61)
        recovered_controller = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "recovered-worktrees",
            controller_id="controller-recovery",
        )

        decision = RecoveryManager(self.store, recovered_controller).resume_once(
            "execution-1"
        )

        self.assertEqual(decision.action, RecoveryAction.MAKER_LOST)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "BLOCKED")
        self.assertEqual(self.store.connection.execute(
            "SELECT status FROM agent_attempt"
        ).fetchone()[0], "LOST")
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt"
        ).fetchone()[0], 1)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE event_type = 'RESULT_COMMIT_REGISTERED'"
        ).fetchone()[0], 0)
        row = self.store.get_execution("execution-1")
        with self.assertRaisesRegex(StoreError, "STALE_FENCING_TOKEN"):
            self.store.transition(
                "execution-1",
                row["state_version"],
                operation_key("stale-recovery", {"version": row["state_version"]}),
                ExecutionState.READY,
                actor_role=ActorRole.CONTROLLER,
                actor_id="old-controller",
                lease_owner="controller-test",
                lease_generation=old_generation,
            )

    def test_human_high_maker_two_recovery_never_falls_back_to_ready(self) -> None:
        self.create_controller_execution(risk=RiskLevel.HIGH)
        _, old_result = self.complete_maker_attempt(marker="high-recovery-initial")
        self.record_verification(old_result, verdict="FAIL")
        approval = self.controller.request_high_rework_approval("execution-1")
        self.controller.resolve_approval("execution-1", approval, approved=True)
        self.controller.authorize_high_rework("execution-1", approval)
        run = self.controller.begin_human_authorized_high_rework(
            "execution-1", self.maker_capsule(), approval
        )
        self.assertEqual(2, self.store.get_agent_attempt(run.attempt_id)["attempt_no"])
        self.assertEqual((0, 0), (
            self.store.get_execution("execution-1")["maker_rework_count"],
            self.store.get_execution("execution-1")["max_auto_reworks"],
        ))
        self.clock.advance(61)
        recovered_controller = Controller(
            self.store, source_root=self.repo,
            worktree_root=self.root / "recovered-high-worktrees",
            controller_id="controller-recovery",
        )
        decision = RecoveryManager(self.store, recovered_controller).resume_once("execution-1")
        row = self.store.get_execution("execution-1")
        self.assertEqual(RecoveryAction.TERMINAL, decision.action)
        self.assertEqual(("BLOCKED", "REWORK_READY"), (row["state"], row["resume_state"]))
        self.assertEqual((0, 0), (row["maker_rework_count"], row["max_auto_reworks"]))

    def test_resume_prebound_succeeded_attempt_reuses_candidate_and_atomic_finalizer(self) -> None:
        run, result_commit, leased = self.prepare_prebound_succeeded_candidate()
        old_generation = leased["lease_generation"]
        self.clock.advance(61)
        recovered_controller = self.recovered_prebound_controller()

        with (
            patch.object(
                recovered_controller.worktrees,
                "create_candidate_commit",
                side_effect=AssertionError("duplicate candidate commit"),
            ) as create_commit,
            patch.object(
                self.store,
                "register_result_commit",
                side_effect=AssertionError("generic result registration"),
            ) as generic_register,
            patch.object(
                self.store,
                "finalize_deferred_result_commit",
                wraps=self.store.finalize_deferred_result_commit,
            ) as prebind_finalize,
        ):
            decision = RecoveryManager(self.store, recovered_controller).resume_once(
                self.PREBOUND_EXECUTION_ID
            )

        execution = self.store.get_execution(self.PREBOUND_EXECUTION_ID)
        state = self.store.get_slice_control_state(self.PREBOUND_SLICE_ID)
        self.assertEqual(decision.action, RecoveryAction.AWAIT_VERIFICATION)
        self.assertEqual(("VERIFYING", result_commit), (execution["state"], execution["result_commit"]))
        self.assertGreater(execution["lease_generation"], old_generation)
        self.assertEqual("controller-recovery", execution["lease_owner"])
        self.assertEqual(
            ("ELIGIBLE_BOUND", result_commit, result_commit),
            (
                state["execution_eligibility"],
                state["implementation_result_commit"],
                state["current_branch_head"],
            ),
        )
        create_commit.assert_not_called()
        generic_register.assert_not_called()
        prebind_finalize.assert_called_once()
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM transition_event "
                "WHERE execution_id=? AND event_type='RESULT_COMMIT_REGISTERED'",
                (self.PREBOUND_EXECUTION_ID,),
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM slice_control_event "
                "WHERE slice_id=? AND reason_code='RESULT_COMMIT_BOUND'",
                (self.PREBOUND_SLICE_ID,),
            ).fetchone()[0],
        )
        self.assertEqual(
            "1",
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(run.candidate.path),
                    "rev-list",
                    "--count",
                    f"{self.base_commit}..HEAD",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        )

    def test_resume_prebound_revalidates_exact_bound_branch_before_finalization(self) -> None:
        run, result_commit, _ = self.prepare_prebound_succeeded_candidate()
        subprocess.run(
            ["git", "-C", str(run.candidate.path), "switch", "-q", "-c", "wrong-recovery-branch"],
            check=True,
        )
        self.clock.advance(61)
        recovered_controller = self.recovered_prebound_controller()

        decision = RecoveryManager(self.store, recovered_controller).resume_once(
            self.PREBOUND_EXECUTION_ID
        )

        execution = self.store.get_execution(self.PREBOUND_EXECUTION_ID)
        state = self.store.get_slice_control_state(self.PREBOUND_SLICE_ID)
        self.assertEqual(decision.action, RecoveryAction.TERMINAL)
        self.assertEqual(decision.detail, "BOUND_WORKTREE_CONFLICT")
        self.assertEqual("BLOCKED", execution["state"])
        self.assertIsNone(execution["result_commit"])
        self.assertEqual(
            ("ELIGIBLE_PREEXECUTION_BOUND", None, self.base_commit),
            (
                state["execution_eligibility"],
                state["implementation_result_commit"],
                state["current_branch_head"],
            ),
        )
        self.assertEqual(
            result_commit,
            subprocess.run(
                ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        )

    def test_resume_prebound_finalization_failure_leaves_no_partial_binding(self) -> None:
        _, _, _ = self.prepare_prebound_succeeded_candidate()
        self.clock.advance(61)
        recovered_controller = self.recovered_prebound_controller()
        original_finalize = self.store.finalize_deferred_result_commit

        def fail_during_slice_event(*args, **kwargs):
            def inject(boundary: str) -> None:
                if boundary == "slice_event":
                    raise RuntimeError("injected prebind recovery finalization failure")

            return original_finalize(*args, **kwargs, fault_injector=inject)

        with patch.object(
            self.store,
            "finalize_deferred_result_commit",
            side_effect=fail_during_slice_event,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "injected prebind recovery finalization failure"
            ):
                RecoveryManager(self.store, recovered_controller).resume_once(
                    self.PREBOUND_EXECUTION_ID
                )

        execution = self.store.get_execution(self.PREBOUND_EXECUTION_ID)
        state = self.store.get_slice_control_state(self.PREBOUND_SLICE_ID)
        self.assertEqual("MAKER_RUNNING", execution["state"])
        self.assertIsNone(execution["result_commit"])
        self.assertEqual(
            ("ELIGIBLE_PREEXECUTION_BOUND", None, self.base_commit),
            (
                state["execution_eligibility"],
                state["implementation_result_commit"],
                state["current_branch_head"],
            ),
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM transition_event "
                "WHERE execution_id=? AND event_type='RESULT_COMMIT_REGISTERED'",
                (self.PREBOUND_EXECUTION_ID,),
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM slice_control_event "
                "WHERE slice_id=? AND reason_code='RESULT_COMMIT_BOUND'",
                (self.PREBOUND_SLICE_ID,),
            ).fetchone()[0],
        )

    def test_resume_after_candidate_commit_does_not_recommit(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        (run.candidate.path / "tracked.txt").write_text("recovered\n", encoding="utf-8")
        commit = self.controller.worktrees.create_candidate_commit(
            run.candidate, run.before, message="candidate recovered"
        )
        self.store.finish_agent_attempt(
            run.attempt_id,
            status="SUCCEEDED",
            result_commit=commit,
            exit_code=0,
            ended_at=timestamp(self.store._now()),
        )
        row = self.store.get_execution("execution-1")
        self.store.register_result_commit(
            "execution-1",
            row["state_version"],
            operation_key("candidate-result", {"execution_id": "execution-1", "commit": commit}),
            commit,
            lease_owner=self.controller.controller_id,
            lease_generation=row["lease_generation"],
            actor_role=ActorRole.CONTROLLER,
            actor_id=self.controller.controller_id,
        )

        decision = self.recovery().resume_once("execution-1")

        self.assertEqual(decision.action, RecoveryAction.AWAIT_VERIFICATION)
        self.assertEqual(self.store.get_execution("execution-1")["result_commit"], commit)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE event_type = 'RESULT_COMMIT_REGISTERED'"
        ).fetchone()[0], 1)

    def test_resume_after_verification_does_not_duplicate_result(self) -> None:
        self.create_controller_execution()
        _, commit = self.complete_maker_attempt()
        self.persist_verification_result(commit)

        decision = self.recovery().resume_once("execution-1")

        self.assertEqual(decision.action, RecoveryAction.SCHEDULE_EVALUATOR)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "EVALUATING")
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM verification_result"
        ).fetchone()[0], 1)

    def test_resume_evaluating_schedules_then_awaits_one_attempt(self) -> None:
        self.create_controller_execution()
        _, commit = self.complete_maker_attempt()
        self.record_verification(commit)
        recovery = self.recovery()

        before = recovery.resume_once("execution-1")
        self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        after = recovery.resume_once("execution-1")

        self.assertEqual(before.action, RecoveryAction.SCHEDULE_EVALUATOR)
        self.assertEqual(after.action, RecoveryAction.AWAIT_EVALUATOR)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt WHERE role = 'EVALUATOR'"
        ).fetchone()[0], 1)

    def test_resume_lost_evaluator_blocks_without_duplicate_attempt(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.clock.advance(61)
        recovered_controller = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "recovered-evaluator-worktrees",
            controller_id="controller-recovery",
        )

        decision = RecoveryManager(self.store, recovered_controller).resume_once(
            "execution-1"
        )

        self.assertEqual(decision.action, RecoveryAction.TERMINAL)
        self.assertEqual(decision.detail, "BLOCKED_EVIDENCE")
        self.assertEqual(self.store.get_agent_attempt(evaluator)["status"], "LOST")
        self.assertEqual(self.store.get_execution("execution-1")["state"], "BLOCKED")
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt WHERE role = 'EVALUATOR'"
        ).fetchone()[0], 1)

    def test_resume_after_evaluation_does_not_duplicate_evaluation(self) -> None:
        self.create_controller_execution()
        _, _, attempt = self.reach_evaluating()
        self.persist_evaluation_result(attempt)

        decision = self.recovery().resume_once("execution-1")

        self.assertEqual(decision.action, RecoveryAction.ACCEPTED)
        self.assertEqual(self.store.get_execution("execution-1")["state"], "ACCEPTED")
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM evaluation_result"
        ).fetchone()[0], 1)

    def test_resume_waiting_approval_preserves_single_use(self) -> None:
        self.create_controller_execution()
        _, _, attempt = self.reach_evaluating()
        binding = self.complete_evaluator_sealed(
            attempt,
            verdict="PASS",
            result={"verdict": "PASS"},
            approval_required=True,
        )
        assert binding is not None
        self.store.resolve_approval(
            binding.approval_id,
            execution_id="execution-1",
            authority_ref=binding.authority_ref,
            approved=True,
        )

        decision = self.recovery().resume_once("execution-1", approval_required=True)
        again = self.recovery().resume_once("execution-1", approval_required=True)

        self.assertEqual(decision.action, RecoveryAction.ACCEPTED)
        self.assertEqual(again.action, RecoveryAction.ACCEPTED)
        approval = self.store.get_approval(binding.approval_id)
        self.assertIsNotNone(approval["consumed_at"])
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM approval_request"
        ).fetchone()[0], 1)

    def test_historical_consumed_high_rework_does_not_block_development_acceptance_recovery(self) -> None:
        self.create_controller_execution(risk=RiskLevel.HIGH)
        _, old_result = self.complete_maker_attempt(marker="high-approval-history")
        self.record_verification(old_result, verdict="FAIL")
        high_binding = self.controller.request_high_rework_approval("execution-1")
        self.controller.resolve_approval("execution-1", high_binding, approved=True)
        self.controller.authorize_high_rework("execution-1", high_binding)
        run = self.controller.begin_human_authorized_high_rework(
            "execution-1", self.maker_capsule(), high_binding
        )
        (run.candidate.path / "tracked.txt").write_text(
            "high-rework-success\n", encoding="utf-8"
        )
        new_result = self.controller.complete_maker(
            run, commit_message="human high rework succeeds"
        )
        self.record_verification(new_result, verdict="PASS")
        evaluator = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )
        self.persist_evaluation_result(evaluator, verdict="PASS")
        high_before = dict(self.store.get_approval(high_binding.approval_id))
        self.assertEqual("HIGH_REWORK", high_before["approval_type"])
        self.assertIsNotNone(high_before["consumed_at"])

        waiting = self.recovery().resume_once(
            "execution-1", approval_required=True
        )

        self.assertEqual(RecoveryAction.WAIT_APPROVAL, waiting.action)
        self.assertEqual(
            "WAITING_APPROVAL", self.store.get_execution("execution-1")["state"]
        )
        development = self.store.connection.execute(
            """SELECT * FROM approval_request WHERE execution_id = ?
                 AND approval_type = 'DEVELOPMENT_ACCEPTANCE'""",
            ("execution-1",),
        ).fetchone()
        self.assertIsNotNone(development)
        self.assertEqual("PENDING", development["status"])
        self.assertEqual(2, self.store.connection.execute(
            "SELECT count(*) FROM approval_request WHERE execution_id = ?",
            ("execution-1",),
        ).fetchone()[0])
        self.assertEqual(
            high_before, dict(self.store.get_approval(high_binding.approval_id))
        )

        self.store.resolve_approval(
            development["approval_id"],
            execution_id="execution-1",
            authority_ref=development["authority_ref"],
            approved=True,
        )
        accepted = self.recovery().resume_once(
            "execution-1", approval_required=True
        )

        self.assertEqual(RecoveryAction.ACCEPTED, accepted.action)
        self.assertEqual("ACCEPTED", self.store.get_execution("execution-1")["state"])
        self.assertIsNotNone(
            self.store.get_approval(development["approval_id"])["consumed_at"]
        )
        self.assertEqual(
            high_before, dict(self.store.get_approval(high_binding.approval_id))
        )

    def test_stale_development_acceptance_fails_before_waiting_transition(self) -> None:
        self.create_controller_execution()
        _, _, attempt = self.reach_evaluating()
        binding = self.complete_evaluator_sealed(
            attempt,
            verdict="PASS",
            result={"verdict": "PASS"},
            approval_required=True,
        )
        assert binding is not None
        self.controller._transition(
            "execution-1",
            ExecutionState.EVALUATING,
            reason="TEST_STALE_APPROVAL_TOPOLOGY",
        )
        before = self.store.get_execution("execution-1")
        before_events = len(self.store.events("execution-1"))

        with self.assertRaisesRegex(ControllerError, "RECOVERY_STALE_APPROVAL"):
            self.recovery().resume_once("execution-1", approval_required=True)

        after = self.store.get_execution("execution-1")
        self.assertEqual("EVALUATING", after["state"])
        self.assertEqual(before["state_version"], after["state_version"])
        self.assertEqual(before_events, len(self.store.events("execution-1")))
        self.assertEqual(
            "PENDING", self.store.get_approval(binding.approval_id)["status"]
        )

    def test_consumed_development_acceptance_fails_closed(self) -> None:
        self.create_controller_execution()
        _, _, attempt = self.reach_evaluating()
        binding = self.complete_evaluator_sealed(
            attempt,
            verdict="PASS",
            result={"verdict": "PASS"},
            approval_required=True,
        )
        assert binding is not None
        self.store.resolve_approval(
            binding.approval_id,
            execution_id="execution-1",
            authority_ref=binding.authority_ref,
            approved=True,
        )
        self.store.connection.execute(
            "UPDATE approval_request SET consumed_at=? WHERE approval_id=?",
            (timestamp(self.store._now()), binding.approval_id),
        )
        before = self.store.get_execution("execution-1")
        before_events = len(self.store.events("execution-1"))

        with self.assertRaisesRegex(
            ControllerError, "RECOVERY_APPROVAL_ALREADY_CONSUMED"
        ):
            self.recovery().resume_once("execution-1", approval_required=True)

        after = self.store.get_execution("execution-1")
        self.assertEqual("WAITING_APPROVAL", after["state"])
        self.assertEqual(before["state_version"], after["state_version"])
        self.assertEqual(before_events, len(self.store.events("execution-1")))

    def test_expired_waiting_approval_is_rejected_as_stale(self) -> None:
        self.create_controller_execution()
        _, _, attempt = self.reach_evaluating()
        self.complete_evaluator_sealed(
            attempt,
            verdict="PASS",
            result={"verdict": "PASS"},
            approval_required=True,
        )
        self.clock.advance(61)
        recovered_controller = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "approval-recovery-worktrees",
            controller_id="controller-recovery",
        )

        with self.assertRaisesRegex(ControllerError, "RECOVERY_STALE_APPROVAL"):
            RecoveryManager(self.store, recovered_controller).resume_once(
                "execution-1", approval_required=True
            )

        self.assertEqual(self.store.get_execution("execution-1")["state"], "WAITING_APPROVAL")
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM approval_request WHERE status = 'PENDING'"
        ).fetchone()[0], 1)

    def test_resume_acceptance_retry_no_duplicate_event(self) -> None:
        self.create_controller_execution()
        self.reach_accepted()
        accepted_events = self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE event_type = 'ACCEPTED'"
        ).fetchone()[0]

        self.recovery().resume_once("execution-1")
        self.recovery().resume_once("execution-1")

        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE event_type = 'ACCEPTED'"
        ).fetchone()[0], accepted_events)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM evidence_manifest"
        ).fetchone()[0], 1)

    def test_resume_after_accepted_projects_only(self) -> None:
        self.create_controller_execution()
        self.reach_accepted()
        target = InMemoryProjectionTarget()
        service = ProjectionService(self.store, target)
        events_before = len(self.store.events("execution-1"))
        attempts_before = self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt"
        ).fetchone()[0]

        first = self.recovery(projection=service).resume_once("execution-1")
        second = self.recovery(projection=service).resume_once("execution-1")

        self.assertEqual(first.action, RecoveryAction.PROJECTED)
        self.assertEqual(second.action, RecoveryAction.PROJECTED)
        self.assertEqual(len(self.store.events("execution-1")), events_before)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt"
        ).fetchone()[0], attempts_before)
        self.assertEqual(self.store.connection.execute(
            "SELECT count(*) FROM projection_record"
        ).fetchone()[0], 1)

    def test_active_foreign_controller_cannot_resume(self) -> None:
        self.create_controller_execution()
        foreign = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "foreign-worktrees",
            controller_id="foreign-controller",
        )

        with self.assertRaisesRegex(StoreError, "LEASE_HELD"):
            RecoveryManager(self.store, foreign).resume_once("execution-1")


if __name__ == "__main__":
    unittest.main()
