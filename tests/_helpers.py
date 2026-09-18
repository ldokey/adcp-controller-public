from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import subprocess
from tempfile import TemporaryDirectory

from adcp.domain import (
    Environment,
    EvaluatorArtifactProducerKind,
    EvaluatorArtifactSealPhase,
    ExecutionCreate,
    RiskLevel,
    operation_key,
    timestamp,
)
from adcp.canonical import canonical_json
from adcp.artifact_seal import collect_manifest, post_execution_roles
from adcp.capsule import CapsuleRole, build_context_capsule, build_evaluator_capsule
from adcp.controller import Controller
from adcp.store.sqlite import ControlStore
from adcp.runner import ArtifactFile, ArtifactSet, CodexRunResult
from adcp.verifier import VerificationCommand, build_verification_result


HASH_A = "a" * 64
HASH_B = "b" * 64
COMMIT_A = "1" * 40
COMMIT_B = "2" * 40


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 11, 1, 2, 3, 456789, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class StoreFixture:
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repo)], check=True, capture_output=True
        )
        self.clock = FakeClock()
        self.store = ControlStore(
            self.root / "control.sqlite3",
            backup_root=self.root / "backups",
            clock=self.clock,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def spec(
        self,
        execution_id: str = "execution-1",
        slice_id: str = "slice-1",
        source_root: Path | None = None,
        risk: RiskLevel = RiskLevel.NORMAL,
    ) -> ExecutionCreate:
        return ExecutionCreate(
            execution_id=execution_id,
            slice_id=slice_id,
            risk_level=risk,
            environment=Environment.TEST,
            contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B,
            source_root=str(source_root or self.repo),
            branch="wcp-06-mvp-a",
            base_commit=COMMIT_A,
        )

    def create(self, execution_id: str = "execution-1", slice_id: str = "slice-1"):
        spec = self.spec(execution_id, slice_id)
        return self.store.create_execution(
            spec, operation_key("create-execution", {"execution_id": execution_id})
        )

    def acquire(self, execution_id: str = "execution-1", version: int = 0, owner: str = "owner-1"):
        return self.store.acquire_lease(
            execution_id,
            version,
            operation_key(
                "lease-acquisition",
                {"execution_id": execution_id, "version": version, "owner": owner},
            ),
            owner,
        )


class ControllerFixture:
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        (self.repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture",
             "-c", "user.email=fixture@local.invalid", "commit", "-q", "-m", "baseline"],
            check=True,
        )
        self.base_commit = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.clock = FakeClock()
        self.store = ControlStore(
            self.root / "control.sqlite3", backup_root=self.root / "backups", clock=self.clock
        )
        self.controller = Controller(
            self.store,
            source_root=self.repo,
            worktree_root=self.root / "worktrees",
            controller_id="controller-test",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def create_controller_execution(
        self,
        *,
        execution_id: str = "execution-1",
        slice_id: str = "slice-1",
        risk: RiskLevel = RiskLevel.NORMAL,
    ):
        row = self.controller.create_execution(
            ExecutionCreate(
                execution_id=execution_id,
                slice_id=slice_id,
                risk_level=risk,
                environment=Environment.TEST,
                contract_fingerprint=HASH_A,
                authority_fingerprint=HASH_B,
                source_root=str(self.repo),
                branch="main",
                base_commit=self.base_commit,
            )
        )
        return self.controller.acquire(row["execution_id"])

    def maker_capsule(self):
        return build_context_capsule(CapsuleRole.MAKER, {"task": "edit tracked.txt"})

    def evaluator_capsule(self):
        row = self.store.get_execution("execution-1")
        verification = self.store.find_verification_pass(
            "execution-1", row["result_commit"], row["contract_fingerprint"],
            row["authority_fingerprint"],
        )
        return build_evaluator_capsule(
            frozen_contract={"id": "contract"},
            acceptance_criteria=["tests pass"],
            base_commit=self.base_commit,
            result_commit=row["result_commit"],
            changed_file_manifest=["tracked.txt"],
            diff="tracked.txt changed",
            deterministic_verification_result={
                "verification_id": verification["verification_id"] if verification else None,
                "result_commit": row["result_commit"],
                "contract_fingerprint": row["contract_fingerprint"],
                "authority_fingerprint": row["authority_fingerprint"],
                "verdict": "PASS" if verification else None,
            },
            relevant_authority_refs=[],
            relevant_authority_excerpts=[],
        )

    def complete_maker_attempt(self, *, marker: str = "candidate"):
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        (run.candidate.path / "tracked.txt").write_text(f"{marker}\n", encoding="utf-8")
        result_commit = self.controller.complete_maker(run, commit_message=f"candidate {marker}")
        return run, result_commit

    def record_verification(self, result_commit: str, *, verdict: str = "PASS"):
        command = VerificationCommand(
            name="unit-tests",
            argv=["python3.13", "-m", "unittest"],
            cwd=str(self.root / "worktrees"),
            env_names=["PYTHONPATH"],
            timeout_seconds=120,
            required=True,
            exit_code=0 if verdict == "PASS" else 1,
        )
        record = build_verification_result(
            verification_id=f"verification-{marker_id()}",
            operation_key=operation_key("verification", {"id": marker_id()}),
            execution_id="execution-1",
            result_commit=result_commit,
            contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B,
            verdict=verdict,
            commands=[command],
            result={"failures": 0 if verdict == "PASS" else 1},
            started_at="2026-08-11T01:02:03.456789+00:00",
            ended_at="2026-08-11T01:03:03.456789+00:00",
        )
        return self.controller.record_verification(record)

    def persist_verification_result(self, result_commit: str, *, verdict: str = "PASS"):
        record = build_verification_result(
            verification_id=f"verification-{marker_id()}",
            operation_key=operation_key("verification", {"id": marker_id()}),
            execution_id="execution-1",
            result_commit=result_commit,
            contract_fingerprint=HASH_A,
            authority_fingerprint=HASH_B,
            verdict=verdict,
            commands=[
                VerificationCommand(
                    name="unit-tests",
                    argv=["python3.13", "-m", "unittest"],
                    cwd=str(self.root),
                    env_names=[],
                    timeout_seconds=120,
                    required=True,
                    exit_code=0 if verdict == "PASS" else 1,
                )
            ],
            result={"verdict": verdict},
            started_at=timestamp(self.store._now()),
            ended_at=timestamp(self.store._now()),
        )
        return self.store.register_verification_result(record)

    @staticmethod
    def _fixture_artifact(path: Path, content: bytes) -> ArtifactFile:
        path.write_bytes(content)
        return ArtifactFile(path, hashlib.sha256(content).hexdigest())

    def evaluator_run_result(
        self,
        result: dict,
        *,
        directory: str | None = None,
    ) -> CodexRunResult:
        root = self.root / (directory or f"evaluator-result-{marker_id()}")
        root.mkdir()
        stdout = self._fixture_artifact(
            root / "stdout.jsonl", b'{"type":"turn.completed"}\n'
        )
        stderr = self._fixture_artifact(root / "stderr.log", b"")
        result_artifact = self._fixture_artifact(
            root / "result.json", canonical_json(result).encode("utf-8")
        )
        metadata = self._fixture_artifact(
            root / "runner-metadata.json", canonical_json({"fixture": True}).encode()
        )
        return CodexRunResult(
            command=("fixture-evaluator",),
            events=(),
            structured_result=result,
            exit_code=0,
            timed_out=False,
            removed_environment_names=(),
            artifacts=ArtifactSet(stdout, stderr, result_artifact, metadata),
        )

    def seal_evaluator_run_result(
        self,
        attempt_id: str,
        run_result: CodexRunResult,
    ):
        root = run_result.artifacts.result.path.parent
        artifact_paths = (
            run_result.artifacts.stdout.path,
            run_result.artifacts.stderr.path,
            run_result.artifacts.result.path,
            run_result.artifacts.metadata.path,
        )
        if any(path.parent != root for path in artifact_paths):
            raise AssertionError("fixture evaluator artifacts must share one root")
        pre_root = root / ".adcp-pre"
        pre_root.mkdir()
        attempt = self.store.get_agent_attempt(attempt_id)
        context = self.store.get_context_snapshot(attempt["context_snapshot_id"])
        context_path = pre_root / "context-snapshot.json"
        prompt_path = pre_root / "prompt.txt"
        schema_path = pre_root / "output-schema.json"
        context_path.write_text(context["canonical_json"], encoding="utf-8")
        prompt_path.write_text("fixture-evaluator-prompt", encoding="utf-8")
        schema_path.write_text(canonical_json({"type": "object"}), encoding="utf-8")
        pre_json, pre_sha, _ = collect_manifest(
            root,
            {
                "context_snapshot": context_path,
                "prompt": prompt_path,
                "output_schema": schema_path,
            },
        )
        self.controller._persist_evaluator_artifact_seal(
            attempt_id,
            phase=EvaluatorArtifactSealPhase.PRE_EXECUTION,
            evidence_root=root,
            manifest_json=pre_json,
            manifest_sha256=pre_sha,
            producer_kind=EvaluatorArtifactProducerKind.EXECUTION_ADAPTER,
            producer_ref="fixture-execution-adapter",
        )
        roles = post_execution_roles(
            root,
            stdout_path=run_result.artifacts.stdout.path,
            stderr_path=run_result.artifacts.stderr.path,
            result_path=run_result.artifacts.result.path,
            metadata_path=run_result.artifacts.metadata.path,
        )
        post_json, post_sha, _ = collect_manifest(root, roles)
        return self.controller._persist_evaluator_artifact_seal(
            attempt_id,
            phase=EvaluatorArtifactSealPhase.POST_EXECUTION,
            evidence_root=root,
            manifest_json=post_json,
            manifest_sha256=post_sha,
            producer_kind=EvaluatorArtifactProducerKind.EXECUTION_ADAPTER,
            producer_ref="fixture-execution-adapter",
        )

    def complete_evaluator_sealed(
        self,
        attempt_id: str,
        *,
        verdict: str,
        result: dict,
        run_result: CodexRunResult | None = None,
        **kwargs,
    ):
        # Canonicalization remains a pre-seal boundary: invalid fresh floats must
        # still fail before any durable evaluator lifecycle mutation.
        canonical_json(result)
        if run_result is None:
            run_result = self.evaluator_run_result(result)
        post = self.seal_evaluator_run_result(attempt_id, run_result)
        return self.controller.complete_evaluator(
            attempt_id,
            verdict=verdict,
            result=result,
            run_result=run_result,
            post_execution_seal_id=post["seal_id"],
            **kwargs,
        )

    def persist_evaluation_result(self, attempt_id: str, *, verdict: str = "PASS"):
        attempt = self.store.get_agent_attempt(attempt_id)
        row = self.store.get_execution("execution-1")
        result = {"verdict": verdict}
        run_result = self.evaluator_run_result(result)
        post = self.seal_evaluator_run_result(attempt_id, run_result)
        self.store.finish_agent_attempt(
            attempt_id,
            status="SUCCEEDED",
            result_commit=row["result_commit"],
            exit_code=0,
            ended_at=timestamp(self.store._now()),
            stdout_artifact=str(run_result.artifacts.stdout.path),
            stdout_sha256=run_result.artifacts.stdout.sha256,
            stderr_artifact=str(run_result.artifacts.stderr.path),
            stderr_sha256=run_result.artifacts.stderr.sha256,
            result_artifact=str(run_result.artifacts.result.path),
            result_sha256=run_result.artifacts.result.sha256,
            post_execution_seal_id=post["seal_id"],
        )
        attempt = self.store.get_agent_attempt(attempt_id)
        return self.store.register_evaluation_result(
            evaluation_id=f"evaluation-{marker_id()}",
            operation_key=operation_key("evaluation-result", {"id": marker_id()}),
            execution_id="execution-1",
            evaluator_attempt_id=attempt_id,
            context_snapshot_id=attempt["context_snapshot_id"],
            result_commit=row["result_commit"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            verdict=verdict,
            result=result,
            started_at=attempt["started_at"],
            ended_at=attempt["ended_at"],
        )

    def reach_evaluating(self):
        run, commit = self.complete_maker_attempt()
        self.record_verification(commit)
        attempt = self.controller.begin_evaluator("execution-1", self.evaluator_capsule())
        return run, commit, attempt

    def reach_accepted(self):
        run, commit, attempt = self.reach_evaluating()
        self.complete_evaluator_sealed(
            attempt, verdict="PASS", result={"verdict": "PASS"}
        )
        accepted = self.controller.accept("execution-1")
        return run, commit, accepted


def marker_id() -> str:
    from uuid import uuid4

    return uuid4().hex
