from __future__ import annotations

from pathlib import Path
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import adcp.controller as controller_module
from adcp.canonical import canonical_json
from adcp.capsule import CapsuleRole, build_context_capsule, build_maker_capsule
from adcp.controller import Controller, ControllerError
from adcp.domain import Environment, ExecutionCreate, RiskLevel, StoreError, operation_key, timestamp
from adcp.verifier import VerificationCommand, build_verification_result
from adcp.store.sqlite import ControlStore, control_state_authority_fingerprint
from _helpers import ControllerFixture, HASH_A, HASH_B


SLICE_ID = "OPENCLAW.PHASE1.OPS_BRIEFING"
EXECUTION_ID = "phase1-execution"
BRANCH = "phase-1-ops-briefing"
PACKET_REF = "ADCP-PREBIND-01:Implementation-Packet-v1.0"


class DeferredPrebindTests(ControllerFixture, unittest.TestCase):
    def seed_deferred_slice(self) -> None:
        target = {
            "slice_id": SLICE_ID,
            "stage": "S4_EXECUTION_FROZEN",
            "status": "WAITING_PREFLIGHT",
            "authority_fingerprint": "0" * 64,
            "migration_class": "DEFER_BINDING",
            "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
            "defer_reason": "DEFER_SEED_UNTIL_BRANCH_BASE_PREFLIGHT",
            "logical_source_root": str(self.controller.worktrees.source_root),
            "repository_toplevel": str(self.controller.worktrees.source_root),
            "branch": BRANCH,
            "base_commit": None,
            "implementation_result_commit": None,
            "current_branch_head": None,
            "active_execution_id": None,
        }
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        self.store.reconcile_slice_control_state(
            target,
            -1,
            operation_key("seed-deferred", {"slice_id": SLICE_ID}),
            reason_code="CUTOVER_DEFER_BINDING",
        )

    def prebind_spec(
        self,
        *,
        execution_id: str = EXECUTION_ID,
        branch: str = BRANCH,
        base_commit: str | None = None,
        contract_fingerprint: str = HASH_A,
        authority_fingerprint: str = HASH_B,
        risk_level: RiskLevel = RiskLevel.NORMAL,
    ) -> ExecutionCreate:
        return ExecutionCreate(
            execution_id=execution_id,
            slice_id=SLICE_ID,
            risk_level=risk_level,
            environment=Environment.TEST,
            contract_fingerprint=contract_fingerprint,
            authority_fingerprint=authority_fingerprint,
            source_root=str(self.repo),
            branch=branch,
            base_commit=base_commit or self.base_commit,
        )

    def prebind_capsule(
        self,
        *,
        execution_id: str = EXECUTION_ID,
        branch: str = BRANCH,
        base_commit: str | None = None,
        **overrides,
    ):
        values = {
            "slice": {"slice_id": SLICE_ID},
            "current_task": {"capability": "ADCP-PREBIND-01"},
            "contract_fingerprint": HASH_A,
            "authority_fingerprint": HASH_B,
            "source_root": str(self.controller.worktrees.expected_bound_path(execution_id)),
            "branch": branch,
            "base_commit": base_commit or self.base_commit,
            "current_commit": base_commit or self.base_commit,
            "acceptance_criteria": ["AC-01", "AC-12"],
            "constraints": ["temporary fixtures only"],
            "risk": "NORMAL",
            "environment": "TEST",
            "allowed_actions": ["edit isolated candidate"],
            "forbidden_actions": ["production write"],
            "relevant_authority_refs": [PACKET_REF],
            "relevant_authority_excerpts": ["bounded deferred binding"],
        }
        values.update(overrides)
        return build_maker_capsule(**values)

    def bind(self, **kwargs):
        return self.controller.bind_deferred_execution(
            kwargs.pop("spec", self.prebind_spec()),
            expected_state_version=kwargs.pop("expected_state_version", 0),
            maker_capsule=kwargs.pop("maker_capsule", self.prebind_capsule()),
            packet_ref=kwargs.pop("packet_ref", PACKET_REF),
            provision_branch_if_missing=kwargs.pop(
                "provision_branch_if_missing", True
            ),
            **kwargs,
        )

    def release(self, **kwargs):
        return self.controller.release_prebound_execution(
            kwargs.pop("execution_id", EXECUTION_ID),
            kwargs.pop("slice_id", SLICE_ID),
            expected_execution_state_version=kwargs.pop(
                "expected_execution_state_version", 0
            ),
            expected_slice_state_version=kwargs.pop(
                "expected_slice_state_version", 1
            ),
            release_reason=kwargs.pop("release_reason", "BASE_STALE"),
            authority_ref=kwargs.pop("authority_ref", "authority:release-v2"),
            **kwargs,
        )

    def test_ac01_ordinary_create_cannot_bypass_deferred_slice(self) -> None:
        self.seed_deferred_slice()
        with self.assertRaisesRegex(ControllerError, "SLICE_EXECUTION_INELIGIBLE"):
            self.controller.create_execution(self.prebind_spec())
        self.assertEqual(
            0, self.store.connection.execute("SELECT count(*) FROM slice_execution").fetchone()[0]
        )

    def test_ac02_happy_path_creates_one_atomic_preexecution_binding(self) -> None:
        self.seed_deferred_slice()
        result = self.bind()

        execution = result["execution"]
        state = result["slice_control_state"]
        context = result["context_snapshot"]
        self.assertEqual(("READY", BRANCH, self.base_commit), (
            execution["state"], execution["branch"], execution["base_commit"]
        ))
        self.assertEqual(
            (
                "DEFER_BINDING",
                "ELIGIBLE_PREEXECUTION_BOUND",
                EXECUTION_ID,
                self.base_commit,
                self.base_commit,
                None,
                None,
            ),
            (
                state["migration_class"],
                state["execution_eligibility"],
                state["active_execution_id"],
                state["base_commit"],
                state["current_branch_head"],
                state["implementation_result_commit"],
                state["defer_reason"],
            ),
        )
        self.assertEqual(("MAKER", self.prebind_capsule().fingerprint), (
            context["role"], context["fingerprint"]
        ))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM transition_event WHERE event_type='EXECUTION_CREATED'"
            ).fetchone()[0],
        )
        self.assertEqual(2, len(self.store.slice_control_events(SLICE_ID)))
        self.assertEqual("PREEXECUTION_BIND", self.store.slice_control_events(SLICE_ID)[-1]["reason_code"])
        self.assertEqual(BRANCH, subprocess.run(
            ["git", "-C", result["worktree_path"], "branch", "--show-current"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())

    def test_ac03_each_bind_write_boundary_rolls_back_and_compensates_git(self) -> None:
        self.seed_deferred_slice()
        for boundary in (
            "execution",
            "execution_event",
            "context_snapshot",
            "slice_event",
            "slice_state",
        ):
            with self.subTest(boundary=boundary):
                def fail(observed: str) -> None:
                    if observed == boundary:
                        raise RuntimeError(f"fault:{boundary}")

                with self.assertRaisesRegex(RuntimeError, f"fault:{boundary}"):
                    self.bind(fault_injector=fail)
                self.assertEqual(
                    (0, 0, 1),
                    (
                        self.store.connection.execute(
                            "SELECT count(*) FROM slice_execution"
                        ).fetchone()[0],
                        self.store.connection.execute(
                            "SELECT count(*) FROM context_snapshot"
                        ).fetchone()[0],
                        self.store.connection.execute(
                            "SELECT count(*) FROM slice_control_event"
                        ).fetchone()[0],
                    ),
                )
                state = self.store.get_slice_control_state(SLICE_ID)
                self.assertEqual((0, "INELIGIBLE_UNTIL_PREFLIGHT", None), (
                    state["state_version"], state["execution_eligibility"],
                    state["active_execution_id"],
                ))
                self.assertFalse(
                    self.controller.worktrees.expected_bound_path(EXECUTION_ID).exists()
                )
                self.assertNotEqual(0, subprocess.run(
                    ["git", "-C", str(self.repo), "show-ref", "--verify", f"refs/heads/{BRANCH}"],
                    check=False, capture_output=True,
                ).returncode)

    def test_ac04_stale_cas_exact_replay_and_conflicting_replay(self) -> None:
        self.seed_deferred_slice()
        with self.assertRaisesRegex(StoreError, "STALE_CONTROL_STATE_VERSION"):
            self.bind(expected_state_version=1)
        first = self.bind()
        second = self.bind()
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(
            (1, 1, 2),
            (
                self.store.connection.execute(
                    "SELECT count(*) FROM slice_execution"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT count(*) FROM context_snapshot"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT count(*) FROM slice_control_event"
                ).fetchone()[0],
            ),
        )
        with self.assertRaisesRegex(StoreError, "PREEXECUTION_BIND_CONFLICT"):
            self.bind(packet_ref="conflicting-packet")

    def test_ac05_git_mismatch_guards_prevent_store_binding(self) -> None:
        self.seed_deferred_slice()
        missing = self.prebind_spec(base_commit="f" * 40)
        missing_capsule = self.prebind_capsule(base_commit="f" * 40)
        with self.assertRaisesRegex(ControllerError, "BASE_COMMIT_NOT_FOUND"):
            self.bind(spec=missing, maker_capsule=missing_capsule)

        with self.assertRaisesRegex(ControllerError, "BOUND_WORKTREE_CONFLICT"):
            self.bind(
                spec=self.prebind_spec(branch="main"),
                maker_capsule=self.prebind_capsule(branch="main"),
                provision_branch_if_missing=False,
            )
        self.assertEqual(
            0, self.store.connection.execute("SELECT count(*) FROM slice_execution").fetchone()[0]
        )

    def test_prefrozen_slice_repository_and_branch_cannot_be_overwritten(self) -> None:
        self.seed_deferred_slice()
        target = {
            field: self.store.get_slice_control_state(SLICE_ID)[field]
            for field in (
                "slice_id",
                "stage",
                "status",
                "migration_class",
                "execution_eligibility",
                "defer_reason",
                "logical_source_root",
                "repository_toplevel",
                "branch",
                "base_commit",
                "implementation_result_commit",
                "current_branch_head",
                "active_execution_id",
                "authority_fingerprint",
            )
        }
        target["branch"] = "authority-declared-branch"
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        self.store.reconcile_slice_control_state(
            target,
            0,
            operation_key("declare-different-branch", {}),
            reason_code="AUTHORITY_BRANCH_DECLARED",
        )

        with self.assertRaisesRegex(StoreError, "PREEXECUTION_BIND_CONFLICT"):
            self.bind(expected_state_version=1)
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])
        self.assertFalse(self.controller.worktrees.expected_bound_path(EXECUTION_ID).exists())

    def test_ac05_existing_logical_branch_at_wrong_head_fails_closed(self) -> None:
        self.seed_deferred_slice()
        (self.repo / "tracked.txt").write_text("new head\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.repo),
                "-c", "user.name=Fixture", "-c", "user.email=fixture@local.invalid",
                "commit", "-q", "-m", "new head",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "branch", BRANCH, "HEAD"], check=True
        )
        with self.assertRaisesRegex(ControllerError, "BOUND_BRANCH_HEAD_MISMATCH"):
            self.bind(provision_branch_if_missing=False)
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])

    def test_ac05_unrelated_worktree_and_dirty_reuse_fail_closed(self) -> None:
        self.seed_deferred_slice()
        subprocess.run(
            ["git", "-C", str(self.repo), "branch", BRANCH, self.base_commit], check=True
        )
        unrelated = self.root / "unrelated"
        subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "add", str(unrelated), BRANCH],
            check=True, capture_output=True,
        )
        with self.assertRaisesRegex(ControllerError, "BOUND_WORKTREE_CONFLICT"):
            self.bind(provision_branch_if_missing=False)
        subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "remove", str(unrelated)], check=True
        )
        subprocess.run(["git", "-C", str(self.repo), "branch", "-D", BRANCH], check=True)

        result = self.bind()
        (Path(result["worktree_path"]) / "tracked.txt").write_text(
            "dirty\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ControllerError, "BOUND_WORKTREE_DIRTY"):
            self.bind()
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])

    def test_ac06_and_ac09_restart_reuses_exact_logical_candidate(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        self.store.close()
        self.store = ControlStore(
            self.root / "control.sqlite3",
            backup_root=self.root / "backups",
            clock=self.clock,
        )
        restarted = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "worktrees",
            controller_id="controller-test",
        )
        restarted.acquire(EXECUTION_ID)
        run = restarted.begin_maker(EXECUTION_ID, self.prebind_capsule())
        self.assertEqual(BRANCH, run.candidate.branch)
        self.assertEqual(Path(bound["worktree_path"]), run.candidate.path)
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM context_snapshot WHERE execution_id = ? AND role = 'MAKER'",
            (EXECUTION_ID,),
        ).fetchone()[0])
        branches = subprocess.run(
            ["git", "-C", str(self.repo), "for-each-ref", "--format=%(refname:short)", "refs/heads"],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        self.assertFalse(any(branch.startswith("adcp/") for branch in branches))

    def test_ac09_restart_revalidation_rejects_changed_bound_head(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        worktree = Path(bound["worktree_path"])
        (worktree / "tracked.txt").write_text("drifted head\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(worktree), "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git", "-C", str(worktree),
                "-c", "user.name=Fixture", "-c", "user.email=fixture@local.invalid",
                "commit", "-q", "-m", "unexpected drift",
            ],
            check=True,
        )
        self.store.close()
        self.store = ControlStore(
            self.root / "control.sqlite3",
            backup_root=self.root / "backups",
            clock=self.clock,
        )
        restarted = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "worktrees",
            controller_id="controller-test",
        )
        restarted.acquire(EXECUTION_ID)
        with self.assertRaisesRegex(ControllerError, "BOUND_BRANCH_HEAD_MISMATCH"):
            restarted.begin_maker(EXECUTION_ID, self.prebind_capsule())
        self.assertEqual("READY", self.store.get_execution(EXECUTION_ID)["state"])

    def test_ac07_capsule_contract_authority_branch_base_and_environment_stale(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        self.controller.acquire(EXECUTION_ID)
        cases = (
            ("contract_fingerprint", "c" * 64, "CONTRACT_FINGERPRINT_MISMATCH"),
            ("authority_fingerprint", "d" * 64, "AUTHORITY_FINGERPRINT_MISMATCH"),
            ("branch", "different-branch", "CAPSULE_BINDING_MISMATCH"),
            ("base_commit", "e" * 40, "CAPSULE_BINDING_MISMATCH"),
            ("environment", "SHADOW", "CAPSULE_BINDING_MISMATCH"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                capsule = build_context_capsule(
                    CapsuleRole.MAKER,
                    {**self.prebind_capsule().content, field: value},
                )
                with self.assertRaisesRegex(ControllerError, code):
                    self.controller.begin_maker(EXECUTION_ID, capsule)
        self.assertEqual("READY", self.store.get_execution(EXECUTION_ID)["state"])

    def test_ac07r_release_is_atomic_idempotent_and_preserves_history(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        context_id = bound["context_snapshot"]["context_snapshot_id"]
        first = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", first["result"]
        )
        self.assertFalse(first["replayed"])
        self.assertFalse(first["git_cleanup_complete"])
        self.assertFalse(Path(bound["worktree_path"]).exists())
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        execution = self.store.get_execution(EXECUTION_ID)
        state = self.store.get_slice_control_state(SLICE_ID)
        self.assertEqual(("CANCELLED", 1), (execution["state"], execution["state_version"]))
        self.assertEqual(
            ("DEFER_BINDING", "INELIGIBLE_UNTIL_PREFLIGHT", "PREEXECUTION_BIND_SUPERSEDED", 2),
            (
                state["migration_class"], state["execution_eligibility"],
                state["defer_reason"], state["state_version"],
            ),
        )
        self.assertTrue(all(state[field] is None for field in (
            "repository_toplevel", "branch", "base_commit",
            "implementation_result_commit", "current_branch_head", "active_execution_id",
        )))
        self.assertEqual(EXECUTION_ID, self.store.get_deferred_binding(EXECUTION_ID)["execution_id"])
        self.assertEqual(context_id, self.store.get_context_snapshot(context_id)["context_snapshot_id"])
        second = self.release()
        self.assertTrue(second["replayed"])
        self.assertEqual(first["result"], second["result"])
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE reason_code='PREEXECUTION_BIND_RELEASED'"
        ).fetchone()[0])
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM slice_control_event WHERE reason_code='PREEXECUTION_RELEASE'"
        ).fetchone()[0])

    def test_ac07r_each_release_write_boundary_rolls_back(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        for boundary in ("execution_state", "execution_event", "slice_event", "slice_state"):
            with self.subTest(boundary=boundary):
                def fail(observed: str) -> None:
                    if observed == boundary:
                        raise RuntimeError(f"fault:{boundary}")

                with self.assertRaisesRegex(RuntimeError, f"fault:{boundary}"):
                    self.release(fault_injector=fail)
                execution = self.store.get_execution(EXECUTION_ID)
                state = self.store.get_slice_control_state(SLICE_ID)
                self.assertEqual(("READY", 0), (execution["state"], execution["state_version"]))
                self.assertEqual(
                    ("ELIGIBLE_PREEXECUTION_BOUND", 1, EXECUTION_ID, self.base_commit),
                    (
                        state["execution_eligibility"], state["state_version"],
                        state["active_execution_id"], state["current_branch_head"],
                    ),
                )
                self.assertEqual(0, self.store.connection.execute(
                    "SELECT count(*) FROM transition_event WHERE reason_code='PREEXECUTION_BIND_RELEASED'"
                ).fetchone()[0])
                self.assertEqual(0, self.store.connection.execute(
                    "SELECT count(*) FROM slice_control_event WHERE reason_code='PREEXECUTION_RELEASE'"
                ).fetchone()[0])
                self.assertTrue(Path(bound["worktree_path"]).exists())

    def test_ac07r_crash_after_store_commit_replays_cleanup_after_restart(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        with patch.object(
            self.controller.worktrees, "cleanup_released", side_effect=SystemExit("crash")
        ):
            with self.assertRaisesRegex(SystemExit, "crash"):
                self.release()
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertTrue(Path(bound["worktree_path"]).exists())
        self.store.close()
        self.store = ControlStore(
            self.root / "control.sqlite3", backup_root=self.root / "backups", clock=self.clock
        )
        self.controller = Controller(
            self.store, source_root=self.repo, worktree_root=self.root / "worktrees",
            controller_id="controller-test",
        )
        replay = self.release()
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", replay["result"]
        )
        self.assertFalse(Path(bound["worktree_path"]).exists())
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        replay_again = self.release()
        self.assertTrue(replay_again["replayed"])
        self.assertEqual(replay["result"], replay_again["result"])
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM transition_event WHERE reason_code='PREEXECUTION_BIND_RELEASED'"
        ).fetchone()[0])
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM slice_control_event WHERE reason_code='PREEXECUTION_RELEASE'"
        ).fetchone()[0])
        self.assertEqual(2, self.store.get_slice_control_state(SLICE_ID)["state_version"])

    def test_ac07r_untracked_worktree_is_preserved_after_store_release(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        (Path(bound["worktree_path"]) / "untracked.txt").write_text("unsafe\n", encoding="utf-8")
        result = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertEqual("BOUND_WORKTREE_DIRTY", result["git_cleanup_error"])
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertIsNone(self.store.get_slice_control_state(SLICE_ID)["active_execution_id"])
        self.assertTrue(Path(bound["worktree_path"]).exists())

    def test_ac07r_dirty_worktree_is_preserved_after_store_release(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        (Path(bound["worktree_path"]) / "tracked.txt").write_text(
            "tracked dirt\n", encoding="utf-8"
        )
        result = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertEqual("BOUND_WORKTREE_DIRTY", result["git_cleanup_error"])
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertIsNone(self.store.get_slice_control_state(SLICE_ID)["active_execution_id"])
        self.assertTrue(Path(bound["worktree_path"]).exists())

    def test_ac07r_lease_attempt_stale_and_conflicting_replay_guards(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        self.controller.acquire(EXECUTION_ID)
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_LEASE_CONFLICT"):
            self.release(expected_execution_state_version=1)
        self.store.connection.execute(
            "UPDATE slice_execution SET lease_owner=NULL, lease_expires_at=NULL WHERE execution_id=?",
            (EXECUTION_ID,),
        )
        with self.assertRaisesRegex(StoreError, "STALE_EXECUTION_STATE_VERSION"):
            self.release()
        self.store.connection.execute(
            """INSERT INTO agent_attempt(
                attempt_id, operation_key, execution_id, role, attempt_no, model,
                reasoning_effort, session_mode, session_id, sandbox_mode,
                context_snapshot_id, base_commit, status, started_at, ended_at
            ) VALUES ('attempt-history', ?, ?, 'MAKER', 1, 'test', 'medium', 'FRESH',
                      'session-history', 'workspace-write', ?, ?, 'FAILED', ?, ?)""",
            (
                operation_key("attempt-history", {}), EXECUTION_ID,
                self.store.get_deferred_binding(EXECUTION_ID)["context_snapshot_id"],
                self.base_commit, self.store.get_execution(EXECUTION_ID)["created_at"],
                self.store.get_execution(EXECUTION_ID)["created_at"],
            ),
        )
        evaluator = build_context_capsule(
            CapsuleRole.EVALUATOR, {"bounded": "historical evaluator context"}
        )
        evaluator_context = self.store.register_context_snapshot(
            "context-evaluator-history", EXECUTION_ID, CapsuleRole.EVALUATOR,
            evaluator.capsule_version, evaluator,
        )
        self.store.connection.execute(
            """INSERT INTO agent_attempt(
                attempt_id, operation_key, execution_id, role, attempt_no, model,
                reasoning_effort, session_mode, session_id, sandbox_mode,
                context_snapshot_id, base_commit, result_commit, status, started_at, ended_at
            ) VALUES ('evaluator-attempt-history', ?, ?, 'EVALUATOR', 1, 'test', 'medium',
                      'FRESH', 'evaluator-session-history', 'read-only', ?, ?, ?, 'FAILED', ?, ?)""",
            (
                operation_key("evaluator-attempt-history", {}), EXECUTION_ID,
                evaluator_context["context_snapshot_id"], self.base_commit, "f" * 40,
                self.store.get_execution(EXECUTION_ID)["created_at"],
                self.store.get_execution(EXECUTION_ID)["created_at"],
            ),
        )
        self.assertEqual(2, self.store.connection.execute(
            "SELECT count(*) FROM agent_attempt WHERE execution_id=?", (EXECUTION_ID,)
        ).fetchone()[0])
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_ATTEMPT_EXISTS"):
            self.release(expected_execution_state_version=1)

    def test_ac07r_conflicting_replay_fails_closed(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        self.release()
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_IDEMPOTENCY_CONFLICT"):
            self.release(release_reason="AUTHORITY_STALE")
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_IDEMPOTENCY_CONFLICT"):
            self.release(authority_ref="authority:changed")

    def test_ac07r_result_nonready_wrong_slice_and_stale_slice_guards(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        with self.assertRaisesRegex(StoreError, "STALE_CONTROL_STATE_VERSION"):
            self.release(expected_slice_state_version=0)
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_EXECUTION_MISMATCH"):
            self.release(slice_id="different-slice")
        self.store.connection.execute(
            "UPDATE slice_execution SET result_commit=? WHERE execution_id=?",
            ("f" * 40, EXECUTION_ID),
        )
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_RESULT_EXISTS"):
            self.release()
        self.store.connection.execute(
            "UPDATE slice_execution SET result_commit=NULL, state='MAKER_RUNNING' WHERE execution_id=?",
            (EXECUTION_ID,),
        )
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_STATE_INVALID"):
            self.release()

    def test_ac07r_immutable_binding_mismatch_fails_closed(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        self.store.connection.execute(
            "UPDATE slice_execution SET contract_fingerprint=? WHERE execution_id=?",
            ("c" * 64, EXECUTION_ID),
        )
        with self.assertRaisesRegex(StoreError, "PREBOUND_RELEASE_BINDING_MISMATCH"):
            self.release()
        self.assertEqual("READY", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertEqual(
            EXECUTION_ID, self.store.get_slice_control_state(SLICE_ID)["active_execution_id"]
        )

    def test_ac07r_post_store_cleanup_failure_is_review_required(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        with patch.object(
            self.controller.worktrees,
            "cleanup_released",
            side_effect=ControllerError("BOUND_WORKTREE_CONFLICT"),
        ):
            result = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertTrue(Path(bound["worktree_path"]).exists())

    def test_ac07r_diverged_branch_after_store_commit_is_not_cleaned(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        original = self.controller.worktrees.cleanup_released

        def diverge(candidate):
            worktree = Path(bound["worktree_path"])
            (worktree / "tracked.txt").write_text("diverged\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(worktree), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(worktree), "-c", "user.name=Fixture",
                 "-c", "user.email=fixture@local.invalid", "commit", "-q", "-m", "diverged"],
                check=True,
            )
            return original(candidate)

        with patch.object(self.controller.worktrees, "cleanup_released", side_effect=diverge):
            result = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertEqual("BOUND_BRANCH_HEAD_MISMATCH", result["git_cleanup_error"])
        self.assertTrue(Path(bound["worktree_path"]).exists())

    def test_ac07r_ref_move_during_worktree_cleanup_preserves_moved_ref(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        (self.repo / "tracked.txt").write_text("moved branch\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture",
             "-c", "user.email=fixture@local.invalid", "commit", "-q", "-m", "moved"],
            check=True,
        )
        moved_commit = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        original_run_git = controller_module._run_git
        race_injected = False

        def move_ref_during_cleanup(repository, *args, **kwargs):
            nonlocal race_injected
            if args[:2] == ("worktree", "remove"):
                completed = original_run_git(repository, *args, **kwargs)
                race_injected = True
                subprocess.run(
                    ["git", "-C", str(self.repo), "branch", "-f", BRANCH, moved_commit],
                    check=True, capture_output=True,
                )
                return completed
            return original_run_git(repository, *args, **kwargs)

        with patch("adcp.controller._run_git", side_effect=move_ref_during_cleanup):
            result = self.release()

        self.assertTrue(race_injected)
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertIsNone(result["git_cleanup_error"])
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertIsNone(
            self.store.get_slice_control_state(SLICE_ID)["active_execution_id"]
        )
        self.assertFalse(Path(bound["worktree_path"]).exists())
        self.assertEqual(moved_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())

    def test_ac07r_branch_checked_out_elsewhere_is_preserved(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        raced_worktree = self.root / "raced-worktree"
        original_run_git = controller_module._run_git
        race_injected = False

        def checkout_during_cleanup(repository, *args, **kwargs):
            nonlocal race_injected
            if args[:2] == ("worktree", "remove"):
                completed = original_run_git(repository, *args, **kwargs)
                race_injected = True
                subprocess.run(
                    ["git", "-C", str(self.repo), "worktree", "add", "-q",
                     str(raced_worktree), BRANCH],
                    check=True, capture_output=True,
                )
                return completed
            return original_run_git(repository, *args, **kwargs)

        try:
            with patch("adcp.controller._run_git", side_effect=checkout_during_cleanup):
                result = self.release()

            self.assertTrue(race_injected)
            self.assertEqual(
                "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
            )
            self.assertIsNone(result["git_cleanup_error"])
            self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
            self.assertIsNone(
                self.store.get_slice_control_state(SLICE_ID)["active_execution_id"]
            )
            self.assertFalse(Path(bound["worktree_path"]).exists())
            self.assertTrue(raced_worktree.exists())
            self.assertEqual(BRANCH, subprocess.run(
                ["git", "-C", str(raced_worktree), "branch", "--show-current"],
                check=True, capture_output=True, text=True,
            ).stdout.strip())
            self.assertEqual(self.base_commit, subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
                check=True, capture_output=True, text=True,
            ).stdout.strip())
        finally:
            if raced_worktree.exists():
                subprocess.run(
                    ["git", "-C", str(self.repo), "worktree", "remove",
                     str(raced_worktree)],
                    check=True, capture_output=True,
                )

    def test_ac07r_non_controller_created_artifacts_are_preserved(self) -> None:
        self.seed_deferred_slice()
        target = self.controller.worktrees.expected_bound_path(EXECUTION_ID)
        subprocess.run(
            ["git", "-C", str(self.repo), "branch", BRANCH, self.base_commit], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "add", str(target), BRANCH],
            check=True, capture_output=True,
        )
        bound = self.bind(provision_branch_if_missing=False)
        binding = self.store.get_deferred_binding(EXECUTION_ID)
        self.assertFalse(binding["branch_created"])
        self.assertFalse(binding["worktree_created"])
        result = self.release()
        self.assertEqual("PREEXECUTION_RELEASED", result["result"])
        self.assertTrue(Path(bound["worktree_path"]).exists())
        self.assertEqual(0, subprocess.run(
            ["git", "-C", str(self.repo), "show-ref", "--verify", f"refs/heads/{BRANCH}"],
            check=False, capture_output=True,
        ).returncode)

    def test_ac07r_existing_branch_has_no_artificial_review_debt(self) -> None:
        self.seed_deferred_slice()
        subprocess.run(
            ["git", "-C", str(self.repo), "branch", BRANCH, self.base_commit], check=True
        )
        bound = self.bind(provision_branch_if_missing=False)
        binding = self.store.get_deferred_binding(EXECUTION_ID)
        self.assertFalse(binding["branch_created"])
        self.assertTrue(binding["worktree_created"])

        result = self.release()

        self.assertEqual("PREEXECUTION_RELEASED", result["result"])
        self.assertTrue(result["git_cleanup_complete"])
        self.assertFalse(Path(bound["worktree_path"]).exists())
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())

    def test_ac07r_cleanup_uses_no_branch_delete_or_hook_override(self) -> None:
        self.seed_deferred_slice()
        bound = self.bind()
        hook_marker = self.root / "hook-invoked"
        hook = self.repo / ".git" / "hooks" / "reference-transaction"
        hook.write_text(
            f"#!/bin/sh\necho invoked > {hook_marker}\nexit 1\n", encoding="utf-8"
        )
        hook.chmod(0o700)
        observed: list[tuple[str, ...]] = []
        original_run_git = controller_module._run_git

        def record_git(repository, *args, **kwargs):
            observed.append(args)
            return original_run_git(repository, *args, **kwargs)

        with patch("adcp.controller._run_git", side_effect=record_git):
            result = self.release()

        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", result["result"]
        )
        self.assertFalse(Path(bound["worktree_path"]).exists())
        self.assertFalse(hook_marker.exists())
        self.assertFalse(any(
            "branch" in args and ("-d" in args or "-D" in args)
            for args in observed
        ))
        self.assertFalse(any(
            "update-ref" in args and "-d" in args for args in observed
        ))
        self.assertFalse(any(
            any("core.hooksPath" in value or "reference-transaction" in value for value in args)
            for args in observed
        ))
        self.assertEqual([], list(self.root.glob("**/adcp-branch-cleanup-*")))

    def test_ac07r_generic_reconcile_and_cancel_remain_closed(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        current = self.store.get_slice_control_state(SLICE_ID)
        target = {field: current[field] for field in (
            "slice_id", "stage", "status", "migration_class", "execution_eligibility",
            "defer_reason", "logical_source_root", "repository_toplevel", "branch",
            "base_commit", "implementation_result_commit", "current_branch_head",
            "active_execution_id", "authority_fingerprint",
        )}
        target.update(
            execution_eligibility="INELIGIBLE_UNTIL_PREFLIGHT",
            defer_reason="PREEXECUTION_BIND_SUPERSEDED",
            repository_toplevel=None, branch=None, base_commit=None,
            implementation_result_commit=None, current_branch_head=None,
            active_execution_id=None,
        )
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        with self.assertRaisesRegex(StoreError, "ACTIVE_EXECUTION_REBIND_FORBIDDEN"):
            self.store.reconcile_slice_control_state(
                target, 1, operation_key("generic-release", {}),
                reason_code="PREEXECUTION_RELEASE",
                metadata={"released_execution_id": EXECUTION_ID},
            )
        self.controller.acquire(EXECUTION_ID)
        self.controller.cancel(EXECUTION_ID)
        state = self.store.get_slice_control_state(SLICE_ID)
        self.assertEqual(EXECUTION_ID, state["active_execution_id"])
        self.assertEqual(self.base_commit, state["base_commit"])
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_control_event WHERE reason_code='PREEXECUTION_RELEASE'"
        ).fetchone()[0])

    def test_ac07r_release_allows_fresh_binding_at_new_base_and_branch(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        released = self.release()
        self.assertEqual(
            "PREEXECUTION_RELEASED_GIT_CLEANUP_REVIEW_REQUIRED", released["result"]
        )
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        (self.repo / "tracked.txt").write_text("base B\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture",
             "-c", "user.email=fixture@local.invalid", "commit", "-q", "-m", "base B"],
            check=True,
        )
        base_b = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        execution_b = "phase1-execution-b"
        branch_b = "phase-1-ops-briefing-b"
        rebound = self.bind(
            spec=self.prebind_spec(
                execution_id=execution_b, branch=branch_b, base_commit=base_b
            ),
            maker_capsule=self.prebind_capsule(
                execution_id=execution_b, branch=branch_b, base_commit=base_b
            ),
            expected_state_version=2,
        )
        state = rebound["slice_control_state"]
        self.assertEqual(
            (execution_b, branch_b, base_b, base_b, "ELIGIBLE_PREEXECUTION_BOUND"),
            (
                state["active_execution_id"], state["branch"], state["base_commit"],
                state["current_branch_head"], state["execution_eligibility"],
            ),
        )
        self.assertEqual("CANCELLED", self.store.get_execution(EXECUTION_ID)["state"])
        self.assertEqual(self.base_commit, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{BRANCH}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        self.assertEqual(base_b, subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", f"refs/heads/{branch_b}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        self.assertEqual(1, self.store.connection.execute(
            "SELECT count(*) FROM slice_control_event WHERE reason_code='PREEXECUTION_RELEASE'"
        ).fetchone()[0])

    def test_schema_v5_rebinding_trigger_has_only_exact_release_exception(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        now = self.store.get_slice_control_state(SLICE_ID)["updated_at"]

        self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            self.store.connection.execute(
                """INSERT INTO slice_execution(
                    execution_id, create_idempotency_key, slice_id, risk_level, environment,
                    state, state_version, contract_fingerprint, authority_fingerprint,
                    source_root, branch, base_commit, max_auto_reworks, current_actor_role,
                    created_at, updated_at
                ) VALUES ('other-execution', ?, ?, 'NORMAL', 'TEST', 'CANCELLED', 0,
                          ?, ?, ?, ?, ?, 2, 'CONTROLLER', ?, ?)""",
                (
                    operation_key("other-execution", {}), SLICE_ID, HASH_A, HASH_B,
                    str(self.repo.resolve()), BRANCH, self.base_commit, now, now,
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "ACTIVE_EXECUTION_REBIND_FORBIDDEN"
            ):
                self.store.connection.execute(
                    "UPDATE slice_control_state SET active_execution_id='other-execution' WHERE slice_id=?",
                    (SLICE_ID,),
                )
        finally:
            self.store.connection.execute("ROLLBACK")

        def attempt(name: str, *, reason: str = "PREEXECUTION_RELEASE",
                    released_execution: str = EXECUTION_ID, changes: dict | None = None,
                    with_event: bool = True) -> str:
            values = {
                "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
                "defer_reason": "PREEXECUTION_BIND_SUPERSEDED",
                "repository_toplevel": None,
                "branch": None,
                "base_commit": None,
                "implementation_result_commit": None,
                "current_branch_head": None,
                "active_execution_id": None,
            }
            values.update(changes or {})
            self.store.connection.execute("BEGIN IMMEDIATE")
            try:
                if with_event:
                    payload = canonical_json({
                        "reason_code": reason,
                        "target": {},
                        "metadata": {"released_execution_id": released_execution},
                    })
                    self.store.connection.execute(
                        """INSERT INTO slice_control_event(
                            operation_key, slice_id, from_state_version, to_state_version,
                            reason_code, metadata_json, created_at
                        ) VALUES (?, ?, 1, 2, ?, ?, ?)""",
                        (operation_key(f"trigger-{name}", {}), SLICE_ID, reason, payload, now),
                    )
                assignments = ", ".join(f"{field} = ?" for field in values)
                try:
                    self.store.connection.execute(
                        f"UPDATE slice_control_state SET {assignments}, state_version=2 WHERE slice_id=?",
                        (*values.values(), SLICE_ID),
                    )
                except sqlite3.IntegrityError as error:
                    return str(error)
                return "ACCEPTED"
            finally:
                self.store.connection.execute("ROLLBACK")

        self.assertIn("ACTIVE_EXECUTION_REBIND_FORBIDDEN", attempt("no-event", with_event=False))
        self.assertIn("ACTIVE_EXECUTION_REBIND_FORBIDDEN", attempt("wrong-reason", reason="OTHER"))
        self.assertIn(
            "ACTIVE_EXECUTION_REBIND_FORBIDDEN",
            attempt("wrong-execution", released_execution="other-execution"),
        )
        self.assertIn(
            "ACTIVE_EXECUTION_REBIND_FORBIDDEN",
            attempt("wrong-new-eligibility", changes={"execution_eligibility": "ELIGIBLE_BOUND"}),
        )
        self.assertIn(
            "ACTIVE_EXECUTION_REBIND_FORBIDDEN",
            attempt("wrong-defer-reason", changes={"defer_reason": "OTHER"}),
        )
        for field, value in (
            ("repository_toplevel", str(self.repo.resolve())),
            ("branch", BRANCH),
            ("base_commit", self.base_commit),
            ("current_branch_head", self.base_commit),
        ):
            with self.subTest(field=field):
                self.assertIn(
                    "ACTIVE_EXECUTION_REBIND_FORBIDDEN",
                    attempt(f"uncleared-{field}", changes={field: value}),
                )
        self.assertEqual("ACCEPTED", attempt("valid"))

        self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            result_commit = "f" * 40
            self.store.connection.execute(
                "UPDATE slice_execution SET result_commit=? WHERE execution_id=?",
                (result_commit, EXECUTION_ID),
            )
            self.store.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, 1, 2, 'RESULT_COMMIT_BOUND', '{}', ?)""",
                (operation_key("old-eligibility-bound", {}), SLICE_ID, now),
            )
            self.store.connection.execute(
                """UPDATE slice_control_state
                      SET execution_eligibility='ELIGIBLE_BOUND',
                          implementation_result_commit=?, current_branch_head=?, state_version=2
                    WHERE slice_id=?""",
                (result_commit, result_commit, SLICE_ID),
            )
            self.store.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, 2, 3, 'PREEXECUTION_RELEASE', ?, ?)""",
                (
                    operation_key("release-from-bound", {}), SLICE_ID,
                    canonical_json({"metadata": {"released_execution_id": EXECUTION_ID}}), now,
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "ACTIVE_EXECUTION_REBIND_FORBIDDEN"
            ):
                self.store.connection.execute(
                    """UPDATE slice_control_state
                          SET execution_eligibility='INELIGIBLE_UNTIL_PREFLIGHT',
                              defer_reason='PREEXECUTION_BIND_SUPERSEDED',
                              repository_toplevel=NULL, branch=NULL, base_commit=NULL,
                              implementation_result_commit=NULL, current_branch_head=NULL,
                              active_execution_id=NULL, state_version=3
                        WHERE slice_id=?""",
                    (SLICE_ID,),
                )
        finally:
            self.store.connection.execute("ROLLBACK")

        self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "CONTROL_EVENT_VERSION_MISMATCH"):
                self.store.connection.execute(
                    """INSERT INTO slice_control_event(
                        operation_key, slice_id, from_state_version, to_state_version,
                        reason_code, metadata_json, created_at
                    ) VALUES (?, ?, 2, 3, 'PREEXECUTION_RELEASE', ?, ?)""",
                    (
                        operation_key("wrong-release-version", {}), SLICE_ID,
                        canonical_json({"metadata": {"released_execution_id": EXECUTION_ID}}), now,
                    ),
                )
        finally:
            self.store.connection.execute("ROLLBACK")

    def test_initial_contract_mismatch_compensates_without_store_state(self) -> None:
        self.seed_deferred_slice()
        capsule = build_context_capsule(
            CapsuleRole.MAKER,
            {**self.prebind_capsule().content, "contract_fingerprint": "c" * 64},
        )
        with self.assertRaisesRegex(ControllerError, "CONTRACT_FINGERPRINT_MISMATCH"):
            self.bind(maker_capsule=capsule)
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])
        self.assertFalse(self.controller.worktrees.expected_bound_path(EXECUTION_ID).exists())

    def test_initial_capsule_requires_complete_frozen_maker_context(self) -> None:
        self.seed_deferred_slice()
        incomplete = build_context_capsule(
            CapsuleRole.MAKER,
            {
                "slice": {"slice_id": SLICE_ID},
                "contract_fingerprint": HASH_A,
                "authority_fingerprint": HASH_B,
                "source_root": str(
                    self.controller.worktrees.expected_bound_path(EXECUTION_ID)
                ),
                "branch": BRANCH,
                "base_commit": self.base_commit,
                "current_commit": self.base_commit,
                "risk": "NORMAL",
                "environment": "TEST",
            },
        )
        with self.assertRaisesRegex(ControllerError, "CAPSULE_BINDING_MISMATCH"):
            self.bind(maker_capsule=incomplete)
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])

    def test_open_execution_has_distinct_fail_closed_code(self) -> None:
        self.seed_deferred_slice()
        orphan = self.prebind_spec(execution_id="orphan", branch="orphan")
        self.store.create_execution(orphan, operation_key("orphan", {}))
        with self.assertRaisesRegex(StoreError, "OPEN_EXECUTION_EXISTS"):
            self.bind()
        self.assertEqual(
            "INELIGIBLE_UNTIL_PREFLIGHT",
            self.store.get_slice_control_state(SLICE_ID)["execution_eligibility"],
        )

    def test_active_lease_has_distinct_fail_closed_code(self) -> None:
        self.seed_deferred_slice()
        orphan = self.prebind_spec(execution_id="orphan", branch="orphan")
        self.store.create_execution(orphan, operation_key("orphan", {}))
        self.store.acquire_lease(
            "orphan",
            0,
            operation_key("orphan-lease", {}),
            "foreign-controller",
        )
        with self.assertRaisesRegex(StoreError, "ACTIVE_ATTEMPT_OR_LEASE_CONFLICT"):
            self.bind()
        self.assertEqual(
            "INELIGIBLE_UNTIL_PREFLIGHT",
            self.store.get_slice_control_state(SLICE_ID)["execution_eligibility"],
        )

    def test_uncompensatable_git_after_db_failure_has_distinct_review_code(self) -> None:
        self.seed_deferred_slice()

        def fail(boundary: str) -> None:
            if boundary == "execution_event":
                raise RuntimeError("database fault")

        with patch.object(
            self.controller.worktrees, "compensate_bound", return_value=False
        ):
            with self.assertRaisesRegex(
                ControllerError, "GIT_PROVISIONED_DB_BIND_FAILED_REVIEW_REQUIRED"
            ):
                self.bind(fault_injector=fail)
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM slice_execution"
        ).fetchone()[0])

    def test_schema_v5_trigger_rejects_manual_preexecution_context_omission(self) -> None:
        self.seed_deferred_slice()
        spec = self.prebind_spec()
        self.store.create_execution(spec, operation_key("internal-create", {}))
        current = dict(self.store.get_slice_control_state(SLICE_ID))
        target = {field: current[field] for field in (
            "slice_id", "stage", "status", "migration_class", "execution_eligibility",
            "defer_reason", "logical_source_root", "repository_toplevel", "branch",
            "base_commit", "implementation_result_commit", "current_branch_head",
            "active_execution_id", "authority_fingerprint",
        )}
        target.update(
            execution_eligibility="ELIGIBLE_PREEXECUTION_BOUND",
            defer_reason=None,
            repository_toplevel=str(self.repo.resolve()),
            branch=BRANCH,
            base_commit=self.base_commit,
            current_branch_head=self.base_commit,
            active_execution_id=EXECUTION_ID,
        )
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            self.store.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, 0, 1, 'PREEXECUTION_BIND', '{}', ?)""",
                (operation_key("manual-prebind", {}), SLICE_ID, current["updated_at"]),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "PREEXECUTION_CONTEXT_BINDING_MISMATCH"
            ):
                self.store.connection.execute(
                    """UPDATE slice_control_state SET
                        authority_fingerprint = ?, execution_eligibility = ?,
                        defer_reason = NULL, repository_toplevel = ?, branch = ?,
                        base_commit = ?, current_branch_head = ?, active_execution_id = ?,
                        state_version = 1
                      WHERE slice_id = ?""",
                    (
                        target["authority_fingerprint"],
                        target["execution_eligibility"],
                        target["repository_toplevel"],
                        target["branch"],
                        target["base_commit"],
                        target["current_branch_head"],
                        target["active_execution_id"],
                        SLICE_ID,
                    ),
                )
        finally:
            self.store.connection.execute("ROLLBACK")
        self.assertEqual(1, len(self.store.slice_control_events(SLICE_ID)))

    def test_high_human_rework_replaces_existing_prebound_result_atomically(self) -> None:
        self.seed_deferred_slice()
        self.bind(
            spec=self.prebind_spec(risk_level=RiskLevel.HIGH),
            maker_capsule=self.prebind_capsule(risk="HIGH"),
        )
        self.controller.acquire(EXECUTION_ID)
        first = self.controller.begin_maker(
            EXECUTION_ID, self.prebind_capsule(risk="HIGH")
        )
        (first.candidate.path / "tracked.txt").write_text("prebound-old\n", encoding="utf-8")
        old_result = self.controller.complete_maker(first, commit_message="prebound old")
        state = self.store.get_slice_control_state(SLICE_ID)
        self.assertEqual(
            ("ELIGIBLE_BOUND", old_result, old_result),
            (state["execution_eligibility"], state["implementation_result_commit"],
             state["current_branch_head"]),
        )

        failed = build_verification_result(
            verification_id="verification-prebind-high-fail",
            operation_key=operation_key("prebind-high-fail", {"result": old_result}),
            execution_id=EXECUTION_ID,
            result_commit=old_result,
            contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B,
            verdict="FAIL",
            commands=[VerificationCommand(
                name="unit-tests", argv=["python3.13", "-m", "unittest"],
                cwd=str(first.candidate.path), env_names=["PYTHONPATH"],
                timeout_seconds=120, required=True, exit_code=1,
            )],
            result={"failures": 1},
            started_at=timestamp(self.store._now()),
            ended_at=timestamp(self.store._now()),
        )
        self.controller.record_verification(failed)
        approval = self.controller.request_high_rework_approval(EXECUTION_ID)
        self.controller.resolve_approval(EXECUTION_ID, approval, approved=True)
        self.controller.authorize_high_rework(EXECUTION_ID, approval)

        second = self.controller.begin_human_authorized_high_rework(
            EXECUTION_ID,
            self.prebind_capsule(risk="HIGH", current_commit=old_result),
            approval,
        )
        self.assertEqual(2, self.store.get_agent_attempt(second.attempt_id)["attempt_no"])
        (second.candidate.path / "tracked.txt").write_text("prebound-new\n", encoding="utf-8")
        new_result = self.controller.complete_maker(second, commit_message="prebound human high rework")

        execution = self.store.get_execution(EXECUTION_ID)
        state = self.store.get_slice_control_state(SLICE_ID)
        self.assertEqual(("VERIFYING", new_result, 0, 0), (
            execution["state"], execution["result_commit"],
            execution["maker_rework_count"], execution["max_auto_reworks"],
        ))
        self.assertEqual(("ELIGIBLE_BOUND", new_result, new_result), (
            state["execution_eligibility"], state["implementation_result_commit"],
            state["current_branch_head"],
        ))
        self.assertEqual(
            old_result,
            subprocess.run(
                ["git", "-C", str(second.candidate.path), "rev-parse", "HEAD^"],
                check=True, capture_output=True, text=True,
            ).stdout.strip(),
        )
        subprocess.run(
            ["git", "-C", str(second.candidate.path), "cat-file", "-e", f"{old_result}^{{commit}}"],
            check=True,
        )
        self.assertFalse(self.store.has_verification_pass(
            EXECUTION_ID, new_result, execution["contract_fingerprint"],
            execution["authority_fingerprint"],
        ))
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT count(*) FROM slice_control_event WHERE slice_id=? AND reason_code='RESULT_COMMIT_BOUND'",
                (SLICE_ID,),
            ).fetchone()[0],
        )

    def test_ac08_result_finalization_is_atomic_at_each_store_boundary(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        leased = self.controller.acquire(EXECUTION_ID)
        self.controller.begin_maker(EXECUTION_ID, self.prebind_capsule())
        execution = self.store.get_execution(EXECUTION_ID)
        state = self.store.get_slice_control_state(SLICE_ID)
        result_commit = "f" * 40
        for boundary in (
            "execution_result",
            "execution_event",
            "slice_event",
            "slice_state",
        ):
            with self.subTest(boundary=boundary):
                def fail(observed: str) -> None:
                    if observed == boundary:
                        raise RuntimeError(f"fault:{boundary}")

                with self.assertRaisesRegex(RuntimeError, f"fault:{boundary}"):
                    self.store.finalize_deferred_result_commit(
                        EXECUTION_ID,
                        execution["state_version"],
                        state["state_version"],
                        operation_key("fault-result", {"boundary": boundary}),
                        result_commit,
                        expected_current_branch_head=self.base_commit,
                        lease_owner="controller-test",
                        lease_generation=leased["lease_generation"],
                        actor_id="controller-test",
                        fault_injector=fail,
                    )
                self.assertIsNone(self.store.get_execution(EXECUTION_ID)["result_commit"])
                current = self.store.get_slice_control_state(SLICE_ID)
                self.assertEqual(("ELIGIBLE_PREEXECUTION_BOUND", None, self.base_commit), (
                    current["execution_eligibility"],
                    current["implementation_result_commit"],
                    current["current_branch_head"],
                ))
                self.assertEqual(0, self.store.connection.execute(
                    "SELECT count(*) FROM transition_event WHERE event_type='RESULT_COMMIT_REGISTERED'"
                ).fetchone()[0])

    def test_ac08_controller_completion_atomically_promotes_slice_to_bound(self) -> None:
        self.seed_deferred_slice()
        self.bind()
        self.controller.acquire(EXECUTION_ID)
        run = self.controller.begin_maker(EXECUTION_ID, self.prebind_capsule())
        (run.candidate.path / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        result_commit = self.controller.complete_maker(
            run, commit_message="prebound candidate"
        )
        execution = self.store.get_execution(EXECUTION_ID)
        state = self.store.get_slice_control_state(SLICE_ID)
        self.assertEqual(("VERIFYING", result_commit), (
            execution["state"], execution["result_commit"]
        ))
        self.assertEqual(("ELIGIBLE_BOUND", result_commit, result_commit), (
            state["execution_eligibility"], state["implementation_result_commit"],
            state["current_branch_head"],
        ))
        self.assertEqual("RESULT_COMMIT_BOUND", self.store.slice_control_events(SLICE_ID)[-1]["reason_code"])
        replay = self.bind()
        self.assertTrue(replay["replayed"])
        self.assertEqual(result_commit, replay["execution"]["result_commit"])
        self.assertEqual("ok", self.store.connection.execute("PRAGMA integrity_check").fetchone()[0])
        self.assertEqual([], list(self.store.connection.execute("PRAGMA foreign_key_check")))


if __name__ == "__main__":
    unittest.main()
