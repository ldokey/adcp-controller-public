from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from uuid import uuid4
import unittest
from unittest.mock import patch

from adcp.capsule import CapsuleRole, build_context_capsule
from adcp.canonical import canonical_json, canonical_sha256
from adcp.controller import Controller, ControllerError, CandidateWorktree, MakerRun, materialize_uncommitted_candidate
from adcp.domain import ActorRole, ExecutionState, StoreError, operation_key
from adcp.runner import ArtifactFile, ArtifactSet, CodexRunResult
from adcp.verifier import CandidateVerificationResultRecord, VerificationCommand, build_command_manifest, build_verification_result
from adcp.evaluator import CandidateEvaluationResultRecord
from adcp.domain import EvaluatorArtifactSealPhase, timestamp
from adcp.store.sqlite import ControlStore, control_state_authority_fingerprint
from adcp.store.migrations import migrate
from adcp.artifact_seal import collect_manifest
from _helpers import ControllerFixture, HASH_A, HASH_B


class PrecommitFixture:
    """Real subprocess evidence in disposable repositories; never HQ authority."""

    def candidate_start(self, content=b"precommit closure\n"):
        migrate(self.store.connection, target_version=9)
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        (run.candidate.path / "tracked.txt").write_bytes(content)
        binding = self.controller.complete_maker_precommit(run)
        return run, binding

    def actual_command(self, candidate, *, label, code=None):
        root = self.root / (label + "-" + uuid4().hex)
        root.mkdir()
        code = code or "from pathlib import Path; assert Path('tracked.txt').read_bytes(); print('synthetic check passed')"
        argv = [sys.executable, "-c", code]
        completed = subprocess.run(argv, cwd=candidate.path, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=20, check=False)
        stdout = self._fixture_artifact(root / "stdout.txt", completed.stdout)
        stderr = self._fixture_artifact(root / "stderr.txt", completed.stderr)
        command = VerificationCommand(label, argv, str(candidate.path), [], 20, True,
            completed.returncode, str(stdout.path), stdout.sha256, str(stderr.path), stderr.sha256)
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        return command, root, completed

    def candidate_verify(self, run, binding):
        command, root, _ = self.actual_command(run.candidate, label="candidate-check")
        manifest = build_command_manifest([command])
        now = timestamp(self.store._now())
        record = CandidateVerificationResultRecord(
            "candidate-verification-" + uuid4().hex, operation_key("candidate-verification", {"id":uuid4().hex}),
            "execution-1", binding.candidate_id, binding.candidate_content_sha256, HASH_A, HASH_B,
            self.store.get_control_authority_state()["authority_generation"], "PASS", canonical_json(manifest),
            canonical_sha256(manifest), canonical_json({"verdict":"PASS", "candidate_id":binding.candidate_id,
            "commands_passed":1}), now, now)
        self.controller.record_candidate_verification(run.candidate, record)
        return record

    def candidate_evaluate(self, run, binding, verification, *, finish=True):
        context = {
            "review_target_type":"UNCOMMITTED_CANDIDATE", "candidate_id":binding.candidate_id,
            "candidate_content_sha256":binding.candidate_content_sha256, "manifest_sha256":binding.manifest_sha256,
            "expected_parent":binding.expected_parent, "repository_identity":binding.repository_identity,
            "contract_fingerprint":HASH_A, "authority_fingerprint":HASH_B,
            "authority_generation":verification.authority_generation, "verification_id":verification.verification_id,
            "command_manifest_sha256":verification.command_manifest_sha256,
            "frozen_contract":{"test_only":True, "goal":"synthetic exact precommit lifecycle"},
            "acceptance_criteria":["nonempty content", "exact review target", "no actual HQ authority"],
        }
        capsule = build_context_capsule(CapsuleRole.EVALUATOR, context)
        attempt = self.controller.begin_precommit_evaluator("execution-1", run.candidate, capsule)
        root = self.root / ("candidate-evaluator-" + uuid4().hex)
        root.mkdir()
        paths = {}
        for role, data in {"context_snapshot":capsule.canonical_json,
                "prompt":"Evaluate only the synthetic disposable candidate, without source writes.",
                "output_schema":canonical_json({"type":"object", "required":["verdict","candidate_id"]})}.items():
            path = root / (role + ".txt"); path.write_text(data); paths[role] = path
        pre_json, pre_sha, _ = collect_manifest(root, paths)
        self.controller.seal_precommit_evaluator_artifacts(run.candidate, evaluator_attempt_id=attempt,
            phase=EvaluatorArtifactSealPhase.PRE_EXECUTION, evidence_root=root,
            manifest_json=pre_json, manifest_sha256=pre_sha)
        result = {"verdict":"PASS", "candidate_id":binding.candidate_id,
                  "candidate_content_sha256":binding.candidate_content_sha256, "test_only":True}
        result_json = canonical_json(result)
        argv = [sys.executable,"-c", "from pathlib import Path; import sys; "
            "assert Path('tracked.txt').read_bytes(); sys.stdout.write(" + repr(result_json) + ")"]
        completed = subprocess.run(argv,cwd=run.candidate.path,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,timeout=20,check=False)
        self.assertEqual(0, completed.returncode)
        post_paths = {}
        metadata = {"review_target_type":"UNCOMMITTED_CANDIDATE", "candidate_id":binding.candidate_id,
            "candidate_content_sha256":binding.candidate_content_sha256,"evaluator_attempt_id":attempt,
            "authority_generation":verification.authority_generation,"exit_code":completed.returncode,
            "timed_out":False,"command":argv,"producer_ref":"synthetic-subprocess-test-not-hq"}
        for role, data in {"stdout":completed.stdout,"stderr":completed.stderr,"result":completed.stdout,
                           "runner_metadata":canonical_json(metadata).encode()}.items():
            path = root / (role + ".json"); path.write_bytes(data); post_paths[role] = path
        post_json, post_sha, _ = collect_manifest(root, post_paths)
        self.controller.seal_precommit_evaluator_artifacts(run.candidate, evaluator_attempt_id=attempt,
            phase=EvaluatorArtifactSealPhase.POST_EXECUTION, evidence_root=root,
            manifest_json=post_json, manifest_sha256=post_sha)
        now = timestamp(self.store._now())
        record = CandidateEvaluationResultRecord("candidate-evaluation-"+uuid4().hex,
            operation_key("candidate-evaluation",{"id":uuid4().hex}),"execution-1",attempt,
            binding.candidate_id,binding.candidate_content_sha256,HASH_A,HASH_B,verification.authority_generation,
            "PASS",result_json,now,now)
        if not finish:
            return record, root
        approval = self.controller.complete_precommit_evaluator(run.candidate,record)
        self.assertIsNotNone(approval)
        self.controller.resolve_precommit_approval("execution-1",approval,approved=True)
        return record, approval

    def approved_candidate(self):
        run, binding = self.candidate_start()
        verification = self.candidate_verify(run, binding)
        evaluation, approval = self.candidate_evaluate(run, binding, verification)
        return run, binding, verification, evaluation, approval

    def close_test_candidate(self, packet):
        run,binding,verification,evaluation,approval = packet
        return self.controller.close_precommit_candidate(run.candidate,candidate_id=binding.candidate_id,
            evaluation_id=evaluation.evaluation_id,approval_id=approval.approval_id,commit_message="synthetic candidate closure")


class ControllerFlowTests(PrecommitFixture, ControllerFixture, unittest.TestCase):
    def test_complete_maker_precommit_persists_candidate_without_commit_or_index(self) -> None:
        migrate(self.store.connection, target_version=9)
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        (run.candidate.path / "tracked.txt").write_text("precommit\n", encoding="utf-8")
        binding = self.controller.complete_maker_precommit(run)
        execution = self.store.get_execution("execution-1")
        attempt = self.store.get_agent_attempt(run.attempt_id)
        self.assertEqual("VERIFYING", execution["state"])
        self.assertIsNone(execution["result_commit"])
        self.assertIsNone(attempt["result_commit"])
        self.assertEqual("SUCCEEDED", attempt["status"])
        self.assertEqual(self.base_commit, subprocess.check_output(
            ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD"], text=True
        ).strip())
        self.assertEqual(b"", subprocess.check_output(
            ["git", "-C", str(run.candidate.path), "diff", "--cached"]
        ))
        self.assertEqual(binding.candidate_content_sha256,
            self.store.get_candidate_binding(binding.candidate_id)["candidate_content_sha256"])

    def test_candidate_review_approval_and_exact_commit_closure(self) -> None:
        packet = self.approved_candidate()
        run,binding,verification,evaluation,approval = packet
        self.assertEqual("WAITING_APPROVAL", self.store.get_execution("execution-1")["state"])
        self.assertIsNone(self.store.get_execution("execution-1")["result_commit"])
        result = self.close_test_candidate(packet)
        self.assertEqual(result,self.store.get_execution("execution-1")["result_commit"])
        self.assertEqual("VERIFYING",self.store.get_execution("execution-1")["state"])
        self.assertEqual(binding.candidate_content_sha256,
            self.store.connection.execute("SELECT candidate_content_sha256 FROM candidate_commit_closure").fetchone()[0])
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM evaluation_result").fetchone()[0])
        # Candidate evaluation cannot stand in for the later commit-target run.
        with self.assertRaisesRegex(Exception,"EVALUATOR_STATE_INVALID"):
            self.controller.begin_evaluator("execution-1",self.evaluator_capsule())
        command, _, _ = self.actual_command(run.candidate,label="git-commit-check",
            code="import subprocess; assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()=="+repr(result)+"; print('exact commit verified')")
        now=timestamp(self.store._now())
        commit_verification=build_verification_result(verification_id="git-commit-verification",
            operation_key=operation_key("git-commit-verification",{"commit":result}),execution_id="execution-1",
            result_commit=result,contract_fingerprint=HASH_A,authority_fingerprint=HASH_B,verdict="PASS",
            commands=[command],result={"verdict":"PASS","review_target_type":"GIT_COMMIT"},started_at=now,ended_at=now)
        self.controller.record_verification(commit_verification)
        commit_attempt=self.controller.begin_evaluator("execution-1",self.evaluator_capsule())
        commit_result={"verdict":"PASS","review_target_type":"GIT_COMMIT","result_commit":result,"test_only":True}
        _, evidence, executed = self.actual_command(run.candidate,label="git-commit-evaluator",
            code="import subprocess,sys; assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()=="+repr(result)+"; sys.stdout.write("+repr(canonical_json(commit_result))+")")
        result_file=self._fixture_artifact(evidence/"result.json",executed.stdout)
        metadata=self._fixture_artifact(evidence/"metadata.json",canonical_json({"test_only":True,"exit_code":0}).encode())
        run_result=CodexRunResult(command=(sys.executable,"synthetic-commit-evaluator"),events=(),structured_result=commit_result,
            exit_code=0,timed_out=False,removed_environment_names=(),artifacts=ArtifactSet(
                ArtifactFile(evidence/"stdout.txt",hashlib.sha256(executed.stdout).hexdigest()),
                ArtifactFile(evidence/"stderr.txt",hashlib.sha256(executed.stderr).hexdigest()),result_file,metadata))
        self.complete_evaluator_sealed(commit_attempt,verdict="PASS",result=commit_result,run_result=run_result)
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM evaluation_result WHERE result_commit=?",(result,)).fetchone()[0])
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM candidate_evaluation_result").fetchone()[0])
        self.assertEqual(result,self.close_test_candidate(packet))
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM candidate_commit_closure").fetchone()[0])

    def crash_after_git_before_dcs(self, packet):
        self.clock.advance(61)  # Terminal test handoff; acquire a fresh lease in the child.
        run,binding,verification,evaluation,approval = packet
        config = {"database":str(self.root/"control.sqlite3"),"repo":str(self.repo),
            "worktree_root":str(self.root/"worktrees"),"candidate_path":str(run.candidate.path),
            "branch":run.candidate.branch,"base":self.base_commit,"now":timestamp(self.store._now()),
            "candidate_id":binding.candidate_id,"evaluation_id":evaluation.evaluation_id,"approval_id":approval.approval_id}
        child = """import json,os,sys
from datetime import datetime
from pathlib import Path
from adcp.controller import Controller,CandidateWorktree
from adcp.store.sqlite import ControlStore
config=json.loads(sys.argv[1])
now=datetime.fromisoformat(config['now'])
store=ControlStore(config['database'],migrate_schema=False,require_schema_version=9,clock=lambda:now)
controller=Controller(store,source_root=Path(config['repo']),worktree_root=Path(config['worktree_root']),controller_id='controller-test')
controller.acquire('execution-1')
candidate=CandidateWorktree('execution-1',Path(config['candidate_path']),config['branch'],config['base'])
def terminate_before_record(*args,**kwargs):
    os._exit(97)
store._record_candidate_commit_closure=terminate_before_record
controller.close_precommit_candidate(candidate,candidate_id=config['candidate_id'],evaluation_id=config['evaluation_id'],approval_id=config['approval_id'],commit_message='synthetic crash closure')
raise RuntimeError('crash injection was not reached')
"""
        crashed = subprocess.run([sys.executable,"-c",child,json.dumps(config)],
            cwd=self.repo,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        self.assertEqual(97,crashed.returncode,crashed.stderr.decode())
        intent = self.store.connection.execute("SELECT * FROM candidate_commit_intent").fetchone()
        self.assertIsNotNone(intent)
        plan = json.loads(intent["plan_json"])
        self.assertEqual(plan["result_commit"],subprocess.check_output(
            ["git","-C",str(run.candidate.path),"rev-parse","HEAD"],text=True).strip())
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_commit_closure").fetchone()[0])
        self.assertIsNone(self.store.get_approval(approval.approval_id)["consumed_at"])
        self.assertIsNone(self.store.get_execution("execution-1")["result_commit"])
        self.assertEqual("WAITING_APPROVAL",self.store.get_execution("execution-1")["state"])
        self.clock.advance(61)  # Child is terminal; retry must freshly acquire, not inherit its token.
        return intent, plan

    def test_precommit_real_process_crash_reconciles_exact_once(self) -> None:
        packet = self.approved_candidate()
        run,binding,verification,evaluation,approval = packet
        intent,plan = self.crash_after_git_before_dcs(packet)
        self.controller.acquire("execution-1")
        result = self.close_test_candidate(packet)
        self.assertEqual(plan["result_commit"],result)
        closure = self.store.connection.execute("SELECT * FROM candidate_commit_closure").fetchone()
        self.assertEqual(intent["closure_id"],closure["closure_id"])
        consumed = self.store.get_approval(approval.approval_id)["consumed_at"]
        self.assertIsNotNone(consumed)
        self.assertEqual(result,self.close_test_candidate(packet))
        self.assertEqual(consumed,self.store.get_approval(approval.approval_id)["consumed_at"])
        self.assertEqual("1",subprocess.check_output(["git","-C",str(run.candidate.path),
            "rev-list","--count",self.base_commit+"..HEAD"],text=True).strip())
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM candidate_commit_closure").fetchone()[0])
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM candidate_commit_intent").fetchone()[0])
        self.assertEqual(1,self.store.connection.execute("SELECT count(*) FROM transition_event WHERE reason_code='PRECOMMIT_COMMIT_CLOSED'").fetchone()[0])

    def test_precommit_crash_retry_rejects_byte_mode_path_and_identity_drift(self) -> None:
        packet = self.approved_candidate()
        run,binding,verification,evaluation,approval = packet
        intent,plan = self.crash_after_git_before_dcs(packet)
        self.controller.acquire("execution-1")
        target=run.candidate.path/"tracked.txt";original=target.read_bytes();mode=target.stat().st_mode
        cases=("bytes","mode","extra-path","approval")
        for case in cases:
            with self.subTest(case=case):
                if case=="bytes": target.write_bytes(original+b"drift")
                elif case=="mode": target.chmod(0o755)
                elif case=="extra-path": (run.candidate.path/"unexpected.txt").write_bytes(b"drift")
                try:
                    with self.assertRaises((ControllerError,StoreError)):
                        if case=="approval":
                            self.controller.close_precommit_candidate(run.candidate,candidate_id=binding.candidate_id,
                                evaluation_id=evaluation.evaluation_id,approval_id="not-the-approved-identity",commit_message="retry")
                        else: self.close_test_candidate(packet)
                finally:
                    if case=="bytes": target.write_bytes(original)
                    elif case=="mode": target.chmod(mode)
                    elif case=="extra-path": (run.candidate.path/"unexpected.txt").unlink()
                self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_commit_closure").fetchone()[0])
                self.assertIsNone(self.store.get_approval(approval.approval_id)["consumed_at"])
        self.assertEqual(plan["result_commit"],self.close_test_candidate(packet))

    def test_precommit_git_boundary_serializes_other_database_writer(self) -> None:
        packet=self.approved_candidate()
        other=ControlStore(self.root/"control.sqlite3",migrate_schema=False,require_schema_version=9,clock=self.clock)
        other.connection.execute("PRAGMA busy_timeout=0")
        original=self.controller._apply_candidate_git_plan
        observed=[]
        def under_lock(*args,**kwargs):
            with self.assertRaisesRegex(sqlite3.OperationalError,"locked"):
                other.connection.execute("BEGIN IMMEDIATE")
            observed.append("competing_writer_blocked")
            return original(*args,**kwargs)
        try:
            with patch.object(self.controller,"_apply_candidate_git_plan",side_effect=under_lock):
                self.close_test_candidate(packet)
        finally: other.close()
        self.assertEqual(["competing_writer_blocked"],observed)

    def test_precommit_stale_lease_and_authority_reject_before_git_effect(self) -> None:
        packet=self.approved_candidate();run=packet[0]
        self.clock.advance(61)
        replacement=Controller(self.store,source_root=self.repo,worktree_root=self.root/"worktrees",controller_id="fresh-controller")
        replacement.acquire("execution-1")
        with self.assertRaisesRegex(StoreError,"LEASE|FENC"):
            self.close_test_candidate(packet)
        self.assertEqual(self.base_commit,subprocess.check_output(["git","-C",str(run.candidate.path),"rev-parse","HEAD"],text=True).strip())
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_commit_intent").fetchone()[0])
        self.controller=replacement
        self.store.connection.execute("UPDATE control_authority_state SET authority_generation=authority_generation+1")
        with self.assertRaisesRegex(StoreError,"STALE_AUTHORITY_GENERATION"):
            self.close_test_candidate(packet)
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_commit_intent").fetchone()[0])

    def test_precommit_sealed_artifact_drift_and_lost_evaluator_are_rejected(self) -> None:
        run,binding=self.candidate_start();verification=self.candidate_verify(run,binding)
        record,root=self.candidate_evaluate(run,binding,verification,finish=False)
        path=root/"stdout.json";original=path.read_bytes();path.write_bytes(original+b"drift")
        with self.assertRaisesRegex(Exception,"SEALED_ARTIFACT_MISMATCH"):
            self.controller.complete_precommit_evaluator(run.candidate,record)
        path.write_bytes(original)
        self.store.connection.execute("UPDATE candidate_evaluator_attempt SET status='LOST',ended_at=? WHERE evaluator_attempt_id=?",
            (timestamp(self.store._now()),record.evaluator_attempt_id))
        with self.assertRaisesRegex(StoreError,"CANDIDATE_EVALUATOR_TARGET_MISMATCH"):
            self.controller.complete_precommit_evaluator(run.candidate,record)
        with self.assertRaisesRegex(sqlite3.IntegrityError,"TERMINAL_IMMUTABLE"):
            self.store.connection.execute("UPDATE candidate_evaluator_attempt SET status='RUNNING' WHERE evaluator_attempt_id=?",(record.evaluator_attempt_id,))
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_evaluation_result").fetchone()[0])

    def test_precommit_new_attempt_rebinds_same_bytes_without_reviving_lost_maker(self) -> None:
        migrate(self.store.connection,target_version=9)
        self.create_controller_execution()
        run=self.controller.begin_maker("execution-1",self.maker_capsule())
        path=run.candidate.path/"tracked.txt";path.write_bytes(b"preserve unfinished implementation\n")
        before=materialize_uncommitted_candidate(run.candidate,repository_identity=self.repo)
        before_stat=path.stat()
        self.clock.advance(61)
        fresh=Controller(self.store,source_root=self.repo,worktree_root=self.root/"worktrees",controller_id="new-authorized-controller")
        fresh.acquire("execution-1")
        self.store.finish_agent_attempt(run.attempt_id,status="LOST",ended_at=timestamp(self.store._now()),failure_code="LOST_CONTROLLER_LEASE")
        with self.assertRaisesRegex(StoreError,"FENC|LEASE"):
            self.controller.complete_maker_precommit(run)
        with self.assertRaisesRegex(StoreError,"CANDIDATE_MAKER_ATTEMPT_MISMATCH"):
            fresh.complete_maker_precommit(run)
        capsule=self.maker_capsule()
        context=self.store.register_context_snapshot("fresh-rebind-context","execution-1",capsule.role,capsule.capsule_version,capsule,
            candidate_write_fence=fresh._candidate_fence("execution-1"))
        self.store.register_agent_attempt(attempt_id="fresh-rebind-attempt",operation_key=operation_key("fresh-rebind",{"old":run.attempt_id}),
            execution_id="execution-1",role=CapsuleRole.MAKER,attempt_no=2,model=None,reasoning_effort=None,
            session_id="fresh-no-write-revalidation",context_snapshot_id=context["context_snapshot_id"],base_commit=self.base_commit,
            result_commit=None,started_at=timestamp(self.store._now()),candidate_write_fence=fresh._candidate_fence("execution-1"))
        rebound=fresh.complete_maker_precommit(MakerRun("fresh-rebind-attempt",run.candidate,run.before,capsule))
        self.assertEqual(before.candidate_id,rebound.candidate_id)
        self.assertEqual(before.candidate_content_sha256,rebound.candidate_content_sha256)
        self.assertEqual(before.manifest_sha256,rebound.manifest_sha256)
        self.assertEqual(before_stat.st_mtime_ns,path.stat().st_mtime_ns)
        self.assertEqual("LOST",self.store.get_agent_attempt(run.attempt_id)["status"])
        self.assertEqual("SUCCEEDED",self.store.get_agent_attempt("fresh-rebind-attempt")["status"])
        self.assertEqual(b"",subprocess.check_output(["git","-C",str(run.candidate.path),"diff","--cached"]))
        self.assertEqual(self.base_commit,subprocess.check_output(["git","-C",str(run.candidate.path),"rev-parse","HEAD"],text=True).strip())

    def test_precommit_cas_snapshot_is_not_refreshed_after_materialization(self) -> None:
        migrate(self.store.connection,target_version=9)
        self.create_controller_execution()
        run=self.controller.begin_maker("execution-1",self.maker_capsule())
        (run.candidate.path/"tracked.txt").write_bytes(b"candidate bytes\n")
        original=materialize_uncommitted_candidate
        def concurrent_version_change(*args,**kwargs):
            binding=original(*args,**kwargs)
            self.store.connection.execute("UPDATE slice_execution SET state_version=state_version+1 WHERE execution_id='execution-1'")
            return binding
        with patch("adcp.controller.materialize_uncommitted_candidate",side_effect=concurrent_version_change):
            with self.assertRaisesRegex(StoreError,"STALE_STATE_VERSION"):
                self.controller.complete_maker_precommit(run)
        self.assertEqual(0,self.store.connection.execute("SELECT count(*) FROM candidate_content_binding").fetchone()[0])
        self.assertEqual("RUNNING",self.store.get_agent_attempt(run.attempt_id)["status"])

    def test_uncommitted_candidate_v1_is_reproducible_and_does_not_move_head(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        target = run.candidate.path / "candidate.txt"
        target.write_bytes(b"candidate bytes\n")
        first = materialize_uncommitted_candidate(run.candidate, repository_identity=self.repo)
        second = materialize_uncommitted_candidate(run.candidate, repository_identity=self.repo)
        self.assertEqual(first, second)
        self.assertEqual(self.base_commit, subprocess.check_output(
            ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD"], text=True
        ).strip())
        self.assertEqual(b"", subprocess.check_output(
            ["git", "-C", str(run.candidate.path), "diff", "--cached"]
        ))

    def test_candidate_digest_changes_on_byte_and_path_set_drift(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        target = run.candidate.path / "candidate.txt"
        target.write_bytes(b"one")
        original = materialize_uncommitted_candidate(run.candidate, repository_identity=self.repo)
        target.write_bytes(b"two")
        byte_drift = materialize_uncommitted_candidate(run.candidate, repository_identity=self.repo)
        (run.candidate.path / "extra.txt").write_bytes(b"extra")
        path_drift = materialize_uncommitted_candidate(run.candidate, repository_identity=self.repo)
        self.assertNotEqual(original.candidate_content_sha256, byte_drift.candidate_content_sha256)
        self.assertNotEqual(byte_drift.candidate_content_sha256, path_drift.candidate_content_sha256)

    def test_controller_happy_path_accepts_only_after_verify_and_evaluator_pass(self) -> None:
        self.create_controller_execution()
        run, result_commit = self.complete_maker_attempt()
        self.assertNotEqual(self.base_commit, result_commit)
        with self.assertRaisesRegex(Exception, "EVALUATOR_STATE_INVALID"):
            self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        self.record_verification(result_commit)
        evaluator = self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        self.complete_evaluator_sealed(evaluator, verdict="PASS", result={"summary": "pass"})
        accepted = self.controller.accept("execution-1")
        self.assertEqual("ACCEPTED", accepted["state"])
        self.assertEqual(1, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])

    def test_maker_cannot_accept(self) -> None:
        self.create_controller_execution()
        row = self.store.get_execution("execution-1")
        for state in (ExecutionState.MAKER_RUNNING, ExecutionState.VERIFYING, ExecutionState.EVALUATING):
            row = self.store.transition(
                "execution-1", row["state_version"],
                operation_key("fixture-transition", {"state": state.value}), state,
                actor_role=ActorRole.CONTROLLER, actor_id="controller-test",
                lease_owner="controller-test", lease_generation=row["lease_generation"],
            )
        with self.assertRaisesRegex(StoreError, "CONTROLLER_ACCEPTANCE_REQUIRED"):
            self.store.transition(
                "execution-1", row["state_version"], operation_key("maker-accept", {}),
                ExecutionState.ACCEPTED, actor_role=ActorRole.MAKER, actor_id="maker",
                lease_owner="controller-test", lease_generation=row["lease_generation"],
            )

    def test_independent_evaluator_cannot_transition_store(self) -> None:
        self.create_controller_execution()
        row = self.store.get_execution("execution-1")
        with self.assertRaisesRegex(StoreError, "EVALUATOR_STATE_TRANSITION_FORBIDDEN"):
            self.store.transition(
                "execution-1", row["state_version"], operation_key("evaluator-transition", {}),
                ExecutionState.MAKER_RUNNING, actor_role=ActorRole.EVALUATOR,
                actor_id="evaluator", lease_owner="controller-test",
                lease_generation=row["lease_generation"],
            )

    def test_result_commit_bound_to_execution_by_controller(self) -> None:
        self.create_controller_execution()
        run, result_commit = self.complete_maker_attempt()
        row = self.store.get_execution("execution-1")
        self.assertEqual(result_commit, row["result_commit"])
        event = [event for event in self.store.events("execution-1") if event["event_type"] == "RESULT_COMMIT_REGISTERED"][0]
        self.assertEqual("CONTROLLER", event["actor_role"])
        self.assertEqual(run.attempt_id, self.store.connection.execute(
            "SELECT attempt_id FROM agent_attempt WHERE result_commit = ? AND role = 'MAKER'", (result_commit,)
        ).fetchone()[0])

    def test_verification_failure_prevents_evaluator(self) -> None:
        self.create_controller_execution()
        _, result_commit = self.complete_maker_attempt()
        self.record_verification(result_commit, verdict="FAIL")
        self.assertEqual("BLOCKED", self.store.get_execution("execution-1")["state"])
        with self.assertRaisesRegex(Exception, "EVALUATOR_STATE_INVALID"):
            self.controller.begin_evaluator("execution-1", self.evaluator_capsule())

    def test_evaluator_context_cannot_include_maker_reasoning_or_transcript(self) -> None:
        self.create_controller_execution()
        _, result_commit = self.complete_maker_attempt()
        self.record_verification(result_commit)
        capsule = build_context_capsule(
            CapsuleRole.EVALUATOR,
            {**self.evaluator_capsule().content, "maker_transcript": "forbidden"},
        )
        with self.assertRaisesRegex(Exception, "EVALUATOR_CONTEXT_BOUNDARY_INVALID"):
            self.controller.begin_evaluator("execution-1", capsule)

    def test_controller_reuses_fresh_read_only_c3_evaluator_boundary(self) -> None:
        self.create_controller_execution()
        run, result_commit = self.complete_maker_attempt()
        self.record_verification(result_commit)
        artifact_root = self.root / "artifacts"
        artifact_root.mkdir()
        structured_result = {
            "verdict": "PASS", "attempts": [], "summary": "pass"
        }

        def fake_codex(invocation):
            root = invocation.artifact_directory
            root.mkdir(parents=True, exist_ok=True)
            files = []
            for name in ("stdout", "stderr", "result", "metadata"):
                path = root / name
                content = canonical_json(structured_result) if name == "result" else name
                path.write_text(content, encoding="utf-8")
                files.append(
                    ArtifactFile(path, hashlib.sha256(path.read_bytes()).hexdigest())
                )
            return CodexRunResult(
                command=("codex",), events=(),
                structured_result=structured_result,
                exit_code=0, timed_out=False, removed_environment_names=(),
                artifacts=ArtifactSet(*files),
            )

        with patch("adcp.controller.run_codex", side_effect=fake_codex) as mocked:
            self.controller.run_evaluator(
                "execution-1", run.candidate, self.evaluator_capsule(),
                binary=self.repo / ".git" / "not-used-because-mocked",
                artifact_directory=artifact_root / "evaluator",
            )
        invocation = mocked.call_args.args[0]
        self.assertEqual("read-only", invocation.sandbox)
        self.assertTrue(invocation.ephemeral)
        self.assertTrue(invocation.ignore_user_config)
        self.assertFalse(invocation.ignore_rules)
        self.assertIsNone(invocation.model)
        self.assertIsNone(invocation.reasoning_effort)

    def test_non_pass_evaluator_prevents_acceptance(self) -> None:
        self.create_controller_execution()
        _, _, evaluator = self.reach_evaluating()
        self.complete_evaluator_sealed(evaluator, verdict="BLOCKED_EVIDENCE", result={"summary": "missing"})
        with self.assertRaisesRegex(Exception, "ACCEPTANCE_STATE_INVALID"):
            self.controller.accept("execution-1")


class SliceRegistrationTests(ControllerFixture, unittest.TestCase):
    REGISTRATION_REF = "ADCP-SLICEREG-01:packet-v1.0"

    def activate_control_authority(self) -> None:
        current = self.store.get_control_authority_state()
        reconciled, _ = self.store.reconcile_transitional_authority(
            current["authority_generation"], "a" * 64, "b" * 64
        )
        self.store.switch_control_authority(
            expected_generation=reconciled["authority_generation"],
            expected_slice_snapshot_fingerprint=reconciled["slice_snapshot_fingerprint"],
            expected_rollback_snapshot_fingerprint=reconciled[
                "rollback_snapshot_fingerprint"
            ],
            cutover_id="isolated-cutover",
            human_decision_ref="isolated-human-cutover-go",
            operation_key="c" * 64,
        )

    def registration(self, **overrides):
        values = {
            "slice_id": "NEW-SLICE-01",
            "stage": "S4_EXECUTION_FROZEN",
            "status": "READY_FOR_CODEX",
            "migration_class": "DEFER_BINDING",
            "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
            "defer_reason": "AWAITING_PREEXECUTION_BINDING",
            "logical_source_root": str(self.controller.worktrees.source_root),
            "registration_ref": self.REGISTRATION_REF,
            "expected_authority_generation": 2,
        }
        values.update(overrides)
        return self.controller.register_slice(**values)

    def table_counts(self) -> dict[str, int]:
        tables = [
            row[0]
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            table: self.store.connection.execute(
                f'SELECT count(*) FROM "{table}"'
            ).fetchone()[0]
            for table in tables
        }

    def test_defer_binding_registration_is_one_row_one_event_only(self) -> None:
        self.activate_control_authority()
        authority_before = tuple(self.store.get_control_authority_state())
        authority_events_before = [tuple(row) for row in self.store.authority_transition_events()]
        counts_before = self.table_counts()
        branches_before = subprocess.run(
            ["git", "-C", str(self.repo), "branch", "--format=%(refname)"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        worktrees_before = subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "list", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

        result = self.registration()

        row = result["slice_control_state"]
        events = self.store.slice_control_events("NEW-SLICE-01")
        counts_after = self.table_counts()
        self.assertFalse(result["replayed"])
        self.assertEqual(0, row["state_version"])
        self.assertEqual((None, None, None, None, None, None), tuple(
            row[field]
            for field in (
                "repository_toplevel",
                "branch",
                "base_commit",
                "implementation_result_commit",
                "current_branch_head",
                "active_execution_id",
            )
        ))
        self.assertEqual(row["authority_fingerprint"], control_state_authority_fingerprint(row))
        self.assertEqual(1, len(events))
        self.assertEqual((-1, 0, "SLICE_REGISTERED"), tuple(
            events[0][field]
            for field in ("from_state_version", "to_state_version", "reason_code")
        ))
        metadata = json.loads(events[0]["metadata_json"])
        self.assertEqual(self.REGISTRATION_REF, metadata["metadata"]["registration_ref"])
        for table, before in counts_before.items():
            expected_delta = 1 if table in {"slice_control_state", "slice_control_event"} else 0
            self.assertEqual(before + expected_delta, counts_after[table], table)
        self.assertEqual(authority_before, tuple(self.store.get_control_authority_state()))
        self.assertEqual(
            authority_events_before,
            [tuple(row) for row in self.store.authority_transition_events()],
        )
        self.assertEqual(
            7,
            self.store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0],
        )
        self.assertEqual(branches_before, subprocess.run(
            ["git", "-C", str(self.repo), "branch", "--format=%(refname)"],
            check=True, capture_output=True, text=True,
        ).stdout)
        self.assertEqual(worktrees_before, subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "list", "--porcelain"],
            check=True, capture_output=True, text=True,
        ).stdout)

    def test_defer_prerequisite_registration_is_allowed(self) -> None:
        self.activate_control_authority()
        result = self.registration(
            migration_class="DEFER_PREREQUISITE",
            execution_eligibility="INELIGIBLE_UNTIL_PREREQUISITE",
            defer_reason="AWAITING_APPROVED_PREREQUISITE",
        )
        row = result["slice_control_state"]
        self.assertEqual(
            ("DEFER_PREREQUISITE", "INELIGIBLE_UNTIL_PREREQUISITE"),
            (row["migration_class"], row["execution_eligibility"]),
        )

    def test_exact_replay_is_idempotent_and_conflicts_do_not_mutate(self) -> None:
        self.activate_control_authority()
        first = self.registration()
        counts = self.table_counts()
        second = self.registration()
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(counts, self.table_counts())

        for overrides in (
            {"status": "CONFLICTING_STATUS"},
            {"registration_ref": "different-provenance"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(
                    ControllerError, "SLICE_ALREADY_REGISTERED_CONFLICT"
                ):
                    self.registration(**overrides)
                self.assertEqual(counts, self.table_counts())

    def test_operation_key_collision_is_a_distinct_idempotency_conflict(self) -> None:
        target = {
            "slice_id": "NEW-SLICE-01",
            "stage": "S4_EXECUTION_FROZEN",
            "status": "READY_FOR_CODEX",
            "migration_class": "DEFER_BINDING",
            "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
            "defer_reason": "AWAITING_PREEXECUTION_BINDING",
            "logical_source_root": str(self.controller.worktrees.source_root),
            "repository_toplevel": None,
            "branch": None,
            "base_commit": None,
            "implementation_result_commit": None,
            "current_branch_head": None,
            "active_execution_id": None,
        }
        target["authority_fingerprint"] = control_state_authority_fingerprint(target)
        key = operation_key(
            "controller-register-slice",
            {
                "target": target,
                "registration_ref": self.REGISTRATION_REF,
                "expected_authority_generation": 2,
            },
        )
        conflicting = dict(target)
        conflicting["slice_id"] = "COLLIDING-SLICE"
        conflicting["authority_fingerprint"] = control_state_authority_fingerprint(conflicting)
        self.store.reconcile_slice_control_state(
            conflicting,
            -1,
            key,
            reason_code="COLLIDING_FIXTURE",
        )
        self.activate_control_authority()
        counts = self.table_counts()

        with self.assertRaisesRegex(
            ControllerError, "SLICE_REGISTRATION_IDEMPOTENCY_CONFLICT"
        ):
            self.registration()
        self.assertEqual(counts, self.table_counts())

    def test_executable_or_bound_registration_is_forbidden(self) -> None:
        self.activate_control_authority()
        cases = (
            {
                "migration_class": "DEFER_BINDING",
                "execution_eligibility": "ELIGIBLE_PREEXECUTION_BOUND",
            },
            {"base_commit": "1" * 40},
            {"active_execution_id": "execution-forbidden"},
            {"repository_toplevel": str(self.repo)},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(
                    ControllerError, "SLICE_REGISTRATION_EXECUTABLE_STATE_FORBIDDEN"
                ):
                    self.registration(**overrides)
        self.assertEqual(0, len(self.store.slice_control_states()))

    def test_unapproved_deferred_disposition_is_forbidden(self) -> None:
        self.activate_control_authority()
        with self.assertRaisesRegex(
            ControllerError, "SLICE_REGISTRATION_DISPOSITION_FORBIDDEN"
        ):
            self.registration(execution_eligibility="INELIGIBLE_UNTIL_PREREQUISITE")
        self.assertEqual(0, len(self.store.slice_control_states()))

    def test_authority_mode_and_generation_guards_write_nothing(self) -> None:
        counts = self.table_counts()
        with self.assertRaisesRegex(ControllerError, "CONTROL_AUTHORITY_MODE_REQUIRED"):
            self.registration(expected_authority_generation=0)
        self.assertEqual(counts, self.table_counts())

        self.activate_control_authority()
        counts = self.table_counts()
        with self.assertRaisesRegex(ControllerError, "STALE_AUTHORITY_GENERATION"):
            self.registration(expected_authority_generation=1)
        self.assertEqual(counts, self.table_counts())

    def test_source_root_mismatch_and_missing_registration_ref_write_nothing(self) -> None:
        self.activate_control_authority()
        other = self.root / "other-source"
        other.mkdir()
        subprocess.run(["git", "init", "-q", str(other)], check=True)
        counts = self.table_counts()
        with self.assertRaisesRegex(ControllerError, "SOURCE_ROOT_MISMATCH"):
            self.registration(logical_source_root=str(other))
        with self.assertRaisesRegex(ControllerError, "SOURCE_ROOT_MISMATCH"):
            self.registration(logical_source_root="")
        with self.assertRaisesRegex(ControllerError, "REGISTRATION_REF_REQUIRED"):
            self.registration(registration_ref="   ")
        self.assertEqual(counts, self.table_counts())

    def test_existing_five_slice_rows_and_events_are_unchanged(self) -> None:
        for index in range(5):
            migration_class = "DEFER_BINDING" if index == 0 else "DEFER_PREREQUISITE"
            eligibility = (
                "INELIGIBLE_UNTIL_PREFLIGHT"
                if index == 0
                else "INELIGIBLE_UNTIL_PREREQUISITE"
            )
            target = {
                "slice_id": f"EXISTING-{index}",
                "stage": "S4_EXECUTION_FROZEN",
                "status": "EXISTING",
                "migration_class": migration_class,
                "execution_eligibility": eligibility,
                "defer_reason": "EXISTING_DEFER_REASON",
                "logical_source_root": str(self.repo),
                "repository_toplevel": None,
                "branch": None,
                "base_commit": None,
                "implementation_result_commit": None,
                "current_branch_head": None,
                "active_execution_id": None,
            }
            target["authority_fingerprint"] = control_state_authority_fingerprint(target)
            self.store.reconcile_slice_control_state(
                target,
                -1,
                operation_key("existing-slice", {"index": index}),
                reason_code="EXISTING_FIXTURE",
            )
        self.activate_control_authority()
        rows_before = [tuple(row) for row in self.store.slice_control_states()]
        events_before = [
            tuple(row)
            for row in self.store.connection.execute(
                "SELECT * FROM slice_control_event ORDER BY event_seq"
            )
        ]

        self.registration()

        rows_after = [
            tuple(row)
            for row in self.store.connection.execute(
                "SELECT * FROM slice_control_state WHERE slice_id LIKE 'EXISTING-%' ORDER BY slice_id"
            )
        ]
        events_after = [
            tuple(row)
            for row in self.store.connection.execute(
                "SELECT * FROM slice_control_event WHERE slice_id LIKE 'EXISTING-%' ORDER BY event_seq"
            )
        ]
        self.assertEqual(rows_before, rows_after)
        self.assertEqual(events_before, events_after)


if __name__ == "__main__":
    unittest.main()
