from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from adcp.canonical import CanonicalizationError, canonical_json
from adcp.capsule import build_evaluator_capsule
from adcp.domain import RiskLevel, StoreError, operation_key, timestamp
from adcp.evaluator import (
    LEGACY_R4_EVALUATOR_RESULT_SCHEMA,
    EvaluatorBoundaryError,
    build_evaluation_result,
    decode_durable_evaluator_result_for_recovery,
    evaluation_result_identity,
)
from adcp.recovery import RecoveryAction, RecoveryManager
from adcp.runner import ArtifactFile, ArtifactSet, CodexRunResult
from adcp.verifier import VerificationCommand, build_verification_result
from _helpers import ControllerFixture


class EvaluatorCompletionIntegrityTests(ControllerFixture, unittest.TestCase):
    def evaluator_run_result(
        self, result: dict, *, directory: str = "evaluator-result"
    ) -> CodexRunResult:
        root = self.root / directory
        root.mkdir()
        contents = {
            "stdout": b'{"type":"turn.completed"}\n',
            "stderr": b"",
            "result": canonical_json(result).encode("utf-8"),
            "metadata": b"{}",
        }
        artifacts = []
        for name, content in contents.items():
            path = root / f"{name}.json"
            path.write_bytes(content)
            artifacts.append(
                ArtifactFile(path, hashlib.sha256(content).hexdigest())
            )
        return CodexRunResult(
            command=("codex",),
            events=(),
            structured_result=result,
            exit_code=0,
            timed_out=False,
            removed_environment_names=(),
            artifacts=ArtifactSet(*artifacts),
        )

    @staticmethod
    def crash_at(target: str):
        def inject(boundary: str) -> None:
            if boundary == target:
                raise RuntimeError(f"fault:{boundary}")

        return inject

    @staticmethod
    def _artifact(path, content: bytes) -> ArtifactFile:
        path.write_bytes(content)
        return ArtifactFile(path, hashlib.sha256(content).hexdigest())

    def strong_evaluator_attempt(self):
        self.create_controller_execution()
        _, result_commit = self.complete_maker_attempt()
        verification = self.record_verification(result_commit)
        row = self.store.get_execution("execution-1")
        frozen_contract = {
            "change_id": row["slice_id"],
            "execution_id": row["execution_id"],
            "result_commit": row["result_commit"],
            "verification_id": verification["verification_id"],
            "contract_fingerprint": row["contract_fingerprint"],
            "authority_fingerprint": row["authority_fingerprint"],
        }
        capsule = build_evaluator_capsule(
            frozen_contract=frozen_contract,
            acceptance_criteria=["tests pass"],
            base_commit=row["base_commit"],
            result_commit=row["result_commit"],
            changed_file_manifest=["tracked.txt"],
            diff="tracked.txt changed",
            deterministic_verification_result={
                "verification_id": verification["verification_id"],
                "result_commit": row["result_commit"],
                "contract_fingerprint": row["contract_fingerprint"],
                "authority_fingerprint": row["authority_fingerprint"],
                "verdict": "PASS",
            },
            relevant_authority_refs=[],
            relevant_authority_excerpts=[],
        )
        attempt_id = self.controller.begin_evaluator("execution-1", capsule)
        return row, verification, attempt_id

    def strong_evaluator_bundle(self, directory: str = "strong-evaluator"):
        row, verification, attempt_id = self.strong_evaluator_attempt()
        attempt = self.store.get_agent_attempt(attempt_id)
        context = self.store.get_context_snapshot(attempt["context_snapshot_id"])
        root = self.root / directory
        root.mkdir()
        stdout = self._artifact(root / "evaluator.stdout", b'{"type":"turn.completed"}\n')
        stderr = self._artifact(root / "evaluator.stderr", b"")
        script = self._artifact(root / "evaluator.py", b"print('probe')\n")
        manifest = self._artifact(
            root / "evaluator-command-manifest.json",
            canonical_json({"commands": [], "manifest_version": 1}).encode(),
        )
        regression_stdout = self._artifact(root / "regression.stdout", b"1 passed\n")
        regression_stderr = self._artifact(root / "regression.stderr", b"")
        regression = {
            "elapsed_ms": 125,
            "exit_code": 0,
            "name": "unit",
            "stderr_path": str(regression_stderr.path),
            "stderr_sha256": regression_stderr.sha256,
            "stdout_path": str(regression_stdout.path),
            "stdout_sha256": regression_stdout.sha256,
            "summary": "1 passed",
            "timed_out": False,
        }
        command_results = self._artifact(
            root / "evaluator-command-results.json",
            canonical_json({"results": [regression]}).encode(),
        )
        references = self._artifact(
            root / "evaluator-reference-attacks.json",
            canonical_json({"attacks": []}).encode(),
        )
        result = {
            "schema": LEGACY_R4_EVALUATOR_RESULT_SCHEMA,
            "change_id": row["slice_id"],
            "execution_id": row["execution_id"],
            "result_head": row["result_commit"],
            "result_parent": row["base_commit"],
            "git": {
                "head": row["result_commit"],
                "parent": row["base_commit"],
            },
            "verification_id": verification["verification_id"],
            "verification_verdict": "PASS",
            "evaluator_attempt_id": attempt_id,
            "evaluator_attempt_no": attempt["attempt_no"],
            "evaluator_attempt_status": "RUNNING",
            "evaluator_context_snapshot_id": context["context_snapshot_id"],
            "evaluator_context_fingerprint": context["fingerprint"],
            "evaluator_capsule_fingerprint": context["fingerprint"],
            "contract_fingerprint": row["contract_fingerprint"],
            "authority_fingerprint": row["authority_fingerprint"],
            "independent_regression_results": [regression],
            "artifacts": {
                "evidence_dir": str(root),
                "script_path": str(script.path),
                "script_sha256_pre": script.sha256,
                "script_sha256_post": script.sha256,
                "command_manifest_sha256": manifest.sha256,
                "command_results_sha256": command_results.sha256,
                "reference_attacks_sha256": references.sha256,
                "successful_probe_stdout_sha256": stdout.sha256,
                "successful_probe_stderr_sha256": stderr.sha256,
            },
            "verdict": "REWORK_REQUIRED",
        }
        result_artifact = self._artifact(
            root / "evaluator-result.json", canonical_json(result).encode()
        )
        metadata = self._artifact(root / "metadata.json", b"{}")
        run_result = CodexRunResult(
            command=("codex",),
            events=(),
            structured_result=result,
            exit_code=0,
            timed_out=False,
            removed_environment_names=(),
            artifacts=ArtifactSet(stdout, stderr, result_artifact, metadata),
        )
        return attempt_id, result, run_result

    def succeeded_strong_evaluator_without_result(self, directory: str = "strong-evaluator"):
        attempt_id, result, run_result = self.strong_evaluator_bundle(directory)
        with self.assertRaisesRegex(RuntimeError, "fault:attempt_succeeded"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="REWORK_REQUIRED",
                result=result,
                run_result=run_result,
                fault_injector=self.crash_at("attempt_succeeded"),
            )
        return attempt_id, result, run_result

    def replace_terminal_result_artifact(self, attempt_id: str, result: dict) -> None:
        attempt = self.store.get_agent_attempt(attempt_id)
        path = run_path = self.root / "forged-result.json"
        raw = canonical_json(result).encode()
        run_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        trigger = self.store.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='agent_attempt_terminal_immutable'"
        ).fetchone()[0]
        self.store.connection.execute("DROP TRIGGER agent_attempt_terminal_immutable")
        try:
            self.store.connection.execute(
                "UPDATE agent_attempt SET result_artifact=?, result_sha256=? WHERE attempt_id=?",
                (str(path), digest, attempt["attempt_id"]),
            )
        finally:
            self.store.connection.execute(trigger)

    def rewrite_run_result(self, run_result: CodexRunResult, result: dict) -> CodexRunResult:
        raw = canonical_json(result).encode()
        run_result.artifacts.result.path.write_bytes(raw)
        result_artifact = ArtifactFile(
            run_result.artifacts.result.path, hashlib.sha256(raw).hexdigest()
        )
        return CodexRunResult(
            command=run_result.command,
            events=run_result.events,
            structured_result=result,
            exit_code=run_result.exit_code,
            timed_out=run_result.timed_out,
            removed_environment_names=run_result.removed_environment_names,
            artifacts=ArtifactSet(
                run_result.artifacts.stdout,
                run_result.artifacts.stderr,
                result_artifact,
                run_result.artifacts.metadata,
            ),
        )

    def cross_execution_verification(self) -> str:
        self.create_controller_execution(execution_id="execution-2", slice_id="slice-2")
        run = self.controller.begin_maker("execution-2", self.maker_capsule())
        (run.candidate.path / "tracked.txt").write_text("candidate-2\n", encoding="utf-8")
        result_commit = self.controller.complete_maker(run, commit_message="candidate 2")
        row = self.store.get_execution("execution-2")
        verification_id = "verification-cross-execution"
        record = build_verification_result(
            verification_id=verification_id,
            operation_key=operation_key("verification", {"id": verification_id}),
            execution_id="execution-2",
            result_commit=result_commit,
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            verdict="PASS",
            commands=[
                VerificationCommand(
                    name="unit-tests",
                    argv=["python3.13", "-m", "unittest"],
                    cwd=str(self.root),
                    env_names=[],
                    timeout_seconds=120,
                    required=True,
                    exit_code=0,
                )
            ],
            result={"verdict": "PASS"},
            started_at=timestamp(self.store._now()),
            ended_at=timestamp(self.store._now()),
        )
        self.controller.record_verification(record)
        return verification_id

    def second_succeeded_evaluator_attempt(self, source_attempt_id: str) -> str:
        source = self.store.get_agent_attempt(source_attempt_id)
        attempt_id = "evaluator-second-succeeded"
        self.store.register_agent_attempt(
            attempt_id=attempt_id,
            operation_key=operation_key("evaluator-attempt", {"attempt_id": attempt_id}),
            execution_id=source["execution_id"],
            role="EVALUATOR",
            attempt_no=source["attempt_no"] + 1,
            model="gpt",
            reasoning_effort="high",
            session_id="session-second-evaluator",
            context_snapshot_id=source["context_snapshot_id"],
            base_commit=source["base_commit"],
            result_commit=source["result_commit"],
            started_at=timestamp(self.store._now()),
        )
        result = {"verdict": "PASS", "summary": "second evaluator"}
        run_result = self.evaluator_run_result(
            result, directory="second-succeeded-evaluator"
        )
        post = self.seal_evaluator_run_result(attempt_id, run_result)
        self.store.finish_agent_attempt(
            attempt_id,
            status="SUCCEEDED",
            result_commit=source["result_commit"],
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
        return attempt_id

    def test_nested_float_rejected_before_any_durable_attempt_mutation(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        attempt_before = dict(self.store.get_agent_attempt(attempt_id))
        execution_before = dict(self.store.get_execution("execution-1"))

        with self.assertRaisesRegex(CanonicalizationError, "float forbidden"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result={"details": [{"elapsed_seconds": 0.125}]},
            )

        self.assertEqual(attempt_before, dict(self.store.get_agent_attempt(attempt_id)))
        self.assertEqual(execution_before, dict(self.store.get_execution("execution-1")))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )

    def test_timing_is_explicit_nonnegative_integer_elapsed_ms(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        self.complete_evaluator_sealed(
            attempt_id,
            verdict="PASS",
            result={"verdict": "PASS", "timing": {"elapsed_ms": 125}},
        )
        result = self.store.connection.execute(
            "SELECT result_json FROM evaluation_result"
        ).fetchone()[0]
        self.assertEqual(
            {"timing": {"elapsed_ms": 125}, "verdict": "PASS"},
            json.loads(result),
        )

    def test_integer_elapsed_seconds_is_not_silently_reinterpreted(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()

        with self.assertRaisesRegex(
            EvaluatorBoundaryError, "EVALUATION_TIMING_REPRESENTATION_INVALID"
        ):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result={"timing": {"elapsed_seconds": 1}},
            )

        self.assertEqual("RUNNING", self.store.get_agent_attempt(attempt_id)["status"])

    def test_legacy_durable_timing_compatibility_matrix(self) -> None:
        def write(name: str, payload: dict, *, allow_nan: bool = False):
            path = self.root / f"{name}.json"
            raw = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=allow_nan,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            path.write_bytes(raw)
            return path, hashlib.sha256(raw).hexdigest()

        legacy = {
            "schema": LEGACY_R4_EVALUATOR_RESULT_SCHEMA,
            "verdict": "PASS",
            "independent_regression_results": [{"name": "unit", "elapsed_seconds": 0.125}],
        }
        path, digest = write("l01", legacy)
        decoded = decode_durable_evaluator_result_for_recovery(path, digest)
        self.assertEqual(125, decoded["independent_regression_results"][0]["elapsed_ms"])
        self.assertNotIn("elapsed_seconds", decoded["independent_regression_results"][0])

        invalid = {
            "L02": {**legacy, "independent_regression_results": [{"elapsed_seconds": -0.125}]},
            "L03": {**legacy, "independent_regression_results": [{"elapsed_seconds": float("nan")}]},
            "L04": {**legacy, "independent_regression_results": [{"elapsed_seconds": float("inf")}]},
            "L05": {**legacy, "confidence": 0.5},
            "L06": {**legacy, "independent_regression_results": [{"elapsed_seconds": 0.125, "elapsed_ms": 125}]},
            "L07": {**legacy, "unsupported": {"elapsed_seconds": 0.125}},
        }
        for name, payload in invalid.items():
            with self.subTest(case=name):
                path, digest = write(name.lower(), payload, allow_nan=True)
                with self.assertRaises(EvaluatorBoundaryError):
                    decode_durable_evaluator_result_for_recovery(path, digest)

        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        with self.assertRaises((CanonicalizationError, EvaluatorBoundaryError)):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result={"independent_regression_results": [{"elapsed_seconds": 0.125}]},
            )
        self.assertEqual("RUNNING", self.store.get_agent_attempt(attempt_id)["status"])

        current = {
            "schema": LEGACY_R4_EVALUATOR_RESULT_SCHEMA,
            "verdict": "PASS",
            "independent_regression_results": [{"name": "unit", "elapsed_ms": 125}],
        }
        current_path = self.root / "l09.json"
        current_raw = canonical_json(current).encode()
        current_path.write_bytes(current_raw)
        current_decoded = decode_durable_evaluator_result_for_recovery(
            current_path, hashlib.sha256(current_raw).hexdigest()
        )
        self.assertEqual(current, current_decoded)
        self.assertEqual(canonical_json(decoded), canonical_json(current_decoded))
        shared = {
            "evaluation_id": "evaluation-timing-equivalence",
            "operation_key": operation_key("evaluation-result", {"id": "timing-equivalence"}),
            "execution_id": "execution-timing-equivalence",
            "evaluator_attempt_id": "evaluator-timing-equivalence",
            "context_snapshot_id": "context-timing-equivalence",
            "result_commit": "1" * 40,
            "contract_fingerprint": "a" * 64,
            "authority_fingerprint": "b" * 64,
            "verdict": "PASS",
            "started_at": "2026-08-31T00:00:00+00:00",
            "ended_at": "2026-08-31T00:00:01+00:00",
        }
        legacy_record = build_evaluation_result(result=decoded, **shared)
        current_record = build_evaluation_result(result=current_decoded, **shared)
        self.assertEqual(
            legacy_record.canonical_payload_json,
            current_record.canonical_payload_json,
        )

    def test_semantically_invalid_fresh_completion_does_not_finish_attempt(self) -> None:
        attempt_id, result, run_result = self.strong_evaluator_bundle()
        invalid = deepcopy(result)
        invalid["execution_id"] = "wrong-execution"
        run_result = self.rewrite_run_result(run_result, invalid)

        with self.assertRaisesRegex(Exception, "EVALUATOR_EXECUTION_BINDING_MISMATCH"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="REWORK_REQUIRED",
                result=invalid,
                run_result=run_result,
            )

        self.assertEqual("RUNNING", self.store.get_agent_attempt(attempt_id)["status"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )

    def test_recovery_semantic_forgery_matrix_fails_closed(self) -> None:
        cases = (
            "F01_WRONG_EXECUTION",
            "F02_WRONG_RESULT_HEAD",
            "F03_WRONG_VERIFICATION",
            "F04_CROSS_EXECUTION_VERIFICATION",
            "F05_WRONG_EVALUATOR_ATTEMPT",
            "F06_OTHER_SUCCEEDED_EVALUATOR_ATTEMPT",
            "F07_WRONG_CONTEXT_ID",
            "F08_WRONG_CONTEXT_FINGERPRINT",
            "F09_WRONG_CONTRACT",
            "F10_WRONG_AUTHORITY",
            "F11_WRONG_SCRIPT_HASH",
            "F12_WRONG_COMMAND_MANIFEST_HASH",
            "F13_WRONG_COMMAND_RESULTS_HASH",
            "F14_WRONG_PROBE_HASH",
            "F15_MISSING_REFERENCED_ARTIFACT",
            "F16_ALTERED_SEMANTIC_PAYLOAD",
        )
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.tearDown()
                    self.setUp()
                attempt_id, result, run_result = self.succeeded_strong_evaluator_without_result(
                    f"strong-{case.lower()}"
                )
                forged = deepcopy(result)
                if case == "F01_WRONG_EXECUTION":
                    forged["execution_id"] = "wrong-execution"
                elif case == "F02_WRONG_RESULT_HEAD":
                    forged["result_head"] = "f" * 40
                elif case == "F03_WRONG_VERIFICATION":
                    forged["verification_id"] = "missing-verification"
                elif case == "F04_CROSS_EXECUTION_VERIFICATION":
                    forged["verification_id"] = self.cross_execution_verification()
                elif case == "F05_WRONG_EVALUATOR_ATTEMPT":
                    forged["evaluator_attempt_id"] = "missing-evaluator"
                elif case == "F06_OTHER_SUCCEEDED_EVALUATOR_ATTEMPT":
                    forged["evaluator_attempt_id"] = self.second_succeeded_evaluator_attempt(attempt_id)
                elif case == "F07_WRONG_CONTEXT_ID":
                    forged["evaluator_context_snapshot_id"] = "wrong-context"
                elif case == "F08_WRONG_CONTEXT_FINGERPRINT":
                    forged["evaluator_context_fingerprint"] = "1" * 64
                elif case == "F09_WRONG_CONTRACT":
                    forged["contract_fingerprint"] = "2" * 64
                elif case == "F10_WRONG_AUTHORITY":
                    forged["authority_fingerprint"] = "3" * 64
                elif case == "F11_WRONG_SCRIPT_HASH":
                    forged["artifacts"]["script_sha256_pre"] = "4" * 64
                elif case == "F12_WRONG_COMMAND_MANIFEST_HASH":
                    forged["artifacts"]["command_manifest_sha256"] = "5" * 64
                elif case == "F13_WRONG_COMMAND_RESULTS_HASH":
                    forged["artifacts"]["command_results_sha256"] = "6" * 64
                elif case == "F14_WRONG_PROBE_HASH":
                    forged["artifacts"]["successful_probe_stdout_sha256"] = "7" * 64
                elif case == "F15_MISSING_REFERENCED_ARTIFACT":
                    (run_result.artifacts.result.path.parent / "evaluator-reference-attacks.json").unlink()
                elif case == "F16_ALTERED_SEMANTIC_PAYLOAD":
                    forged["git"]["head"] = "8" * 40
                if case != "F15_MISSING_REFERENCED_ARTIFACT":
                    self.replace_terminal_result_artifact(attempt_id, forged)

                decision = RecoveryManager(self.store, self.controller).resume_once(
                    "execution-1"
                )

                self.assertEqual(
                    (RecoveryAction.TERMINAL, "BLOCKED_EVIDENCE"),
                    (decision.action, decision.detail),
                )
                self.assertEqual("BLOCKED", self.store.get_execution("execution-1")["state"])
                self.assertEqual(
                    0,
                    self.store.connection.execute(
                        "SELECT count(*) FROM evaluation_result"
                    ).fetchone()[0],
                )

    def test_store_rejects_direct_semantically_misbound_completed_evidence(self) -> None:
        attempt_id, result, _ = self.succeeded_strong_evaluator_without_result()
        attempt = self.store.get_agent_attempt(attempt_id)
        row = self.store.get_execution("execution-1")
        forged = deepcopy(result)
        forged["authority_fingerprint"] = "f" * 64
        self.replace_terminal_result_artifact(attempt_id, forged)
        evaluation_id, key = evaluation_result_identity(attempt_id)
        record = build_evaluation_result(
            evaluation_id=evaluation_id,
            operation_key=key,
            execution_id=row["execution_id"],
            evaluator_attempt_id=attempt_id,
            context_snapshot_id=attempt["context_snapshot_id"],
            result_commit=row["result_commit"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            verdict="REWORK_REQUIRED",
            result=forged,
            started_at=attempt["started_at"],
            ended_at=attempt["ended_at"],
        )

        with self.assertRaises(StoreError):
            self.store.register_evaluation_result(record)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )

    def test_recovery_materializes_exact_succeeded_attempt_evidence_once(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        result = {"verdict": "PASS", "attempts": [], "summary": "pass"}
        run_result = self.evaluator_run_result(result)

        with self.assertRaisesRegex(RuntimeError, "fault:attempt_succeeded"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result=result,
                run_result=run_result,
                fault_injector=self.crash_at("attempt_succeeded"),
            )

        terminal_attempt = dict(self.store.get_agent_attempt(attempt_id))
        self.assertEqual("SUCCEEDED", terminal_attempt["status"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )
        with (
            patch.object(
                self.store,
                "finish_agent_attempt",
                side_effect=AssertionError("recovery refinalized evaluator attempt"),
            ),
            patch.object(
                self.controller,
                "begin_evaluator",
                side_effect=AssertionError("recovery reran evaluator"),
            ),
        ):
            decision = RecoveryManager(self.store, self.controller).resume_once(
                "execution-1"
            )

        self.assertEqual(RecoveryAction.ACCEPTED, decision.action)
        self.assertEqual(terminal_attempt, dict(self.store.get_agent_attempt(attempt_id)))
        evaluation = self.store.connection.execute(
            "SELECT * FROM evaluation_result"
        ).fetchone()
        self.assertEqual(attempt_id, evaluation["evaluator_attempt_id"])
        self.assertEqual(
            terminal_attempt["result_sha256"],
            hashlib.sha256(evaluation["result_json"].encode("utf-8")).hexdigest(),
        )
        RecoveryManager(self.store, self.controller).resume_once("execution-1")
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM evidence_manifest"
            ).fetchone()[0],
        )

    def test_corrupt_succeeded_attempt_evidence_fails_closed(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        result = {"verdict": "PASS", "attempts": [], "summary": "pass"}
        run_result = self.evaluator_run_result(result)
        with self.assertRaises(RuntimeError):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result=result,
                run_result=run_result,
                fault_injector=self.crash_at("attempt_succeeded"),
            )
        run_result.artifacts.result.path.write_text("{}", encoding="utf-8")

        decision = RecoveryManager(self.store, self.controller).resume_once(
            "execution-1"
        )

        self.assertEqual((RecoveryAction.TERMINAL, "BLOCKED_EVIDENCE"), (
            decision.action, decision.detail
        ))
        self.assertEqual("SUCCEEDED", self.store.get_agent_attempt(attempt_id)["status"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )

    def test_fault_after_evaluation_result_recovers_without_duplicate(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        result = {"verdict": "PASS", "attempts": [], "summary": "pass"}
        with self.assertRaisesRegex(RuntimeError, "fault:evaluation_result"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result=result,
                run_result=self.evaluator_run_result(result),
                fault_injector=self.crash_at("evaluation_result"),
            )

        decision = RecoveryManager(self.store, self.controller).resume_once(
            "execution-1"
        )

        self.assertEqual(RecoveryAction.ACCEPTED, decision.action)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )

    def test_approval_boundaries_recover_one_result_and_one_approval(self) -> None:
        for boundary in ("state_transition", "approval_request"):
            with self.subTest(boundary=boundary):
                if boundary != "state_transition":
                    self.tearDown()
                    self.setUp()
                self.create_controller_execution()
                _, _, attempt_id = self.reach_evaluating()
                result = {"verdict": "PASS", "attempts": [], "summary": "pass"}
                with self.assertRaisesRegex(RuntimeError, f"fault:{boundary}"):
                    self.complete_evaluator_sealed(
                        attempt_id,
                        verdict="PASS",
                        result=result,
                        approval_required=True,
                        run_result=self.evaluator_run_result(result),
                        fault_injector=self.crash_at(boundary),
                    )

                decision = RecoveryManager(self.store, self.controller).resume_once(
                    "execution-1", approval_required=True
                )

                self.assertEqual(RecoveryAction.WAIT_APPROVAL, decision.action)
                self.assertEqual("WAITING_APPROVAL", decision.state)
                self.assertEqual(
                    1,
                    self.store.connection.execute(
                        "SELECT count(*) FROM evaluation_result"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    1,
                    self.store.connection.execute(
                        "SELECT count(*) FROM approval_request"
                    ).fetchone()[0],
                )

    def test_high_rework_recovery_escalates_without_automatic_rework(self) -> None:
        self.create_controller_execution(risk=RiskLevel.HIGH)
        _, _, attempt_id = self.reach_evaluating()
        result = {
            "verdict": "REWORK_REQUIRED",
            "attempts": [],
            "summary": "rework",
        }
        with self.assertRaisesRegex(RuntimeError, "fault:evaluation_result"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="REWORK_REQUIRED",
                result=result,
                run_result=self.evaluator_run_result(result),
                fault_injector=self.crash_at("evaluation_result"),
            )

        with patch.object(
            self.controller,
            "begin_maker",
            side_effect=AssertionError("automatic HIGH rework was scheduled"),
        ):
            decision = RecoveryManager(self.store, self.controller).resume_once(
                "execution-1"
            )

        row = self.store.get_execution("execution-1")
        self.assertEqual(RecoveryAction.TERMINAL, decision.action)
        self.assertEqual(
            ("DESIGN_ESCALATION", 0, 0),
            (row["state"], row["maker_rework_count"], row["max_auto_reworks"]),
        )

    def test_expired_fence_rejects_completion_before_attempt_mutation(self) -> None:
        self.create_controller_execution()
        _, _, attempt_id = self.reach_evaluating()
        self.clock.advance(61)

        with self.assertRaisesRegex(Exception, "STALE_FENCING_TOKEN"):
            self.complete_evaluator_sealed(
                attempt_id,
                verdict="PASS",
                result={"verdict": "PASS"},
            )

        self.assertEqual("RUNNING", self.store.get_agent_attempt(attempt_id)["status"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT count(*) FROM evaluation_result"
            ).fetchone()[0],
        )


if __name__ == "__main__":
    unittest.main()
