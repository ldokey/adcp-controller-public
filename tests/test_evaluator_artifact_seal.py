from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import socket
import sqlite3
import unittest
from unittest.mock import patch

from adcp.artifact_seal import (
    ArtifactSealError,
    collect_manifest,
    verify_manifest_bytes,
)
from adcp.controller import ControllerError
from adcp.domain import (
    EvaluatorArtifactProducerKind,
    EvaluatorArtifactSealCreate,
    EvaluatorArtifactSealPhase,
    StoreError,
    operation_key,
)
from adcp.runner import ArtifactFile, ArtifactSet, CodexRunResult
from _helpers import COMMIT_A, ControllerFixture


class EvaluatorArtifactFilesystemSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        from tempfile import TemporaryDirectory
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name) / "evidence"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_all_symlink_and_escape_shapes_fail_closed(self) -> None:
        outside = self.root.parent / "outside.txt"
        outside.write_text("outside")
        real = self.root / "real.txt"
        real.write_text("inside")

        final_link = self.root / "final-link"
        final_link.symlink_to(real)
        with self.assertRaisesRegex(ArtifactSealError, "SYMLINK_FORBIDDEN"):
            collect_manifest(self.root, {"result": final_link})
        final_link.unlink()

        outside_link = self.root / "outside-link"
        outside_link.symlink_to(outside)
        with self.assertRaisesRegex(ArtifactSealError, "SYMLINK_FORBIDDEN"):
            collect_manifest(self.root, {"result": outside_link})
        outside_link.unlink()

        real_dir = self.root / "real-dir"
        real_dir.mkdir()
        (real_dir / "child").write_text("child")
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(real_dir, target_is_directory=True)
        with self.assertRaisesRegex(ArtifactSealError, "SYMLINK_FORBIDDEN"):
            collect_manifest(self.root, {"result": parent_link / "child"})

        with self.assertRaisesRegex(ArtifactSealError, "PATH_TRAVERSAL"):
            collect_manifest(self.root, {"result": "../outside.txt"})
        with self.assertRaisesRegex(ArtifactSealError, "PATH_ESCAPE"):
            collect_manifest(self.root, {"result": outside})

    def test_hardlink_is_rejected(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        first.write_text("same inode")
        os.link(first, second)
        with self.assertRaisesRegex(ArtifactSealError, "HARDLINK_FORBIDDEN"):
            collect_manifest(self.root, {"result": first})

    def test_final_fifo_without_writer_is_rejected_as_non_regular(self) -> None:
        fifo = self.root / "artifact.fifo"
        os.mkfifo(fifo)

        with self.assertRaisesRegex(ArtifactSealError, "ARTIFACT_NOT_REGULAR"):
            collect_manifest(self.root, {"result": fifo})

    def test_final_fifo_with_connected_peer_is_rejected_as_non_regular(self) -> None:
        fifo = self.root / "artifact-connected.fifo"
        os.mkfifo(fifo)
        peer_fd = os.open(fifo, os.O_RDWR | getattr(os, "O_NONBLOCK", 0))
        try:
            with self.assertRaisesRegex(ArtifactSealError, "ARTIFACT_NOT_REGULAR"):
                collect_manifest(self.root, {"result": fifo})
        finally:
            os.close(peer_fd)

    def test_directory_and_unix_socket_are_rejected(self) -> None:
        directory = self.root / "artifact-dir"
        directory.mkdir()
        with self.assertRaises(ArtifactSealError):
            collect_manifest(self.root, {"result": directory})

        socket_path = self.root / "artifact.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(socket_path))
            with self.assertRaises(ArtifactSealError):
                collect_manifest(self.root, {"result": socket_path})
        finally:
            server.close()

    def test_regular_file_preserves_exact_hash_and_bytes(self) -> None:
        target = self.root / "result.json"
        payload = b"exact regular artifact bytes\n"
        target.write_bytes(payload)

        manifest_json, manifest_sha, entries = collect_manifest(
            self.root, {"result": target}
        )
        verified = verify_manifest_bytes(self.root, manifest_json, manifest_sha)

        self.assertEqual(entries[0].sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(entries[0].byte_size, len(payload))
        self.assertEqual(verified.bytes_for_role("result"), payload)

    def test_post_seal_mutation_matrix_rejects_every_artifact(self) -> None:
        names = (
            "script.py",
            "evaluator-command-manifest.json",
            "evaluator-command-results.json",
            "evaluator-reference-attacks.json",
            "probe.stdout",
            "probe.stderr",
            "stdout.jsonl",
            "stderr.log",
            "result.json",
        )
        for name in names:
            with self.subTest(name=name):
                case = self.root / name.replace(".", "-")
                case.mkdir()
                target = case / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"sealed")
                manifest_json, manifest_sha, _ = collect_manifest(
                    case, {"artifact": target}
                )
                target.write_bytes(b"replacement")
                _recomputed_attacker_hash = hashlib.sha256(target.read_bytes()).hexdigest()
                with self.assertRaisesRegex(
                    ArtifactSealError, "SEALED_ARTIFACT_MISMATCH"
                ):
                    verify_manifest_bytes(case, manifest_json, manifest_sha)

    def test_same_size_in_place_mutation_during_revalidation_is_detected_as_toctou(self) -> None:
        target = self.root / "result.json"
        target.write_bytes(b"AAAAAA")
        manifest_json, manifest_sha, _ = collect_manifest(
            self.root, {"result": target}
        )
        real_read = os.read
        mutated = False

        def mutating_read(fd: int, size: int):
            nonlocal mutated
            data = real_read(fd, size)
            if data and not mutated:
                mutated = True
                target.write_bytes(b"BBBBBB")
            return data

        with patch("adcp.artifact_seal.os.read", side_effect=mutating_read):
            with self.assertRaisesRegex(ArtifactSealError, "TOCTOU_DETECTED"):
                verify_manifest_bytes(self.root, manifest_json, manifest_sha)

    def test_descriptor_identity_change_is_detected_as_toctou(self) -> None:
        target = self.root / "result.json"
        target.write_text("stable")
        real_fstat = os.fstat
        calls = 0

        def drifting(fd: int):
            nonlocal calls
            calls += 1
            result = real_fstat(fd)
            if calls == 3:
                values = list(result)
                values[6] = result.st_size + 1
                return os.stat_result(values)
            return result

        with patch("adcp.artifact_seal.os.fstat", side_effect=drifting):
            with self.assertRaisesRegex(ArtifactSealError, "TOCTOU_DETECTED"):
                collect_manifest(self.root, {"result": target})


class EvaluatorArtifactSealLifecycleTests(ControllerFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create_controller_execution()
        _, result_commit = self.complete_maker_attempt()
        self.record_verification(result_commit)
        self.attempt = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )

    def _sealed(self, result: dict | None = None):
        result = result or {"summary": "sealed"}
        run = self.evaluator_run_result(result)
        post = self.seal_evaluator_run_result(self.attempt, run)
        return result, run, post

    @staticmethod
    def _spec_from_row(row) -> EvaluatorArtifactSealCreate:
        return EvaluatorArtifactSealCreate(
            seal_id=row["seal_id"],
            execution_id=row["execution_id"],
            result_commit=row["result_commit"],
            verification_id=row["verification_id"],
            evaluator_attempt_id=row["evaluator_attempt_id"],
            context_snapshot_id=row["context_snapshot_id"],
            context_fingerprint=row["context_fingerprint"],
            contract_fingerprint=row["contract_fingerprint"],
            authority_fingerprint=row["authority_fingerprint"],
            phase=EvaluatorArtifactSealPhase(row["phase"]),
            producer_kind=EvaluatorArtifactProducerKind(row["producer_kind"]),
            producer_ref=row["producer_ref"],
            evidence_root=row["evidence_root"],
            manifest_version=row["manifest_version"],
            manifest_json=row["manifest_json"],
            manifest_sha256=row["manifest_sha256"],
            authority_generation=row["authority_generation"],
            operation_key=row["operation_key"],
            approval_id=row["approval_id"],
        )

    def test_unsealed_finish_and_complete_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreError, "POST_EXECUTION_SEAL_REQUIRED"):
            self.store.finish_agent_attempt(
                self.attempt,
                status="SUCCEEDED",
                result_commit=self.store.get_execution("execution-1")["result_commit"],
                exit_code=0,
                ended_at="2026-09-01T00:00:00+00:00",
            )
        with self.assertRaisesRegex(ControllerError, "POST_EXECUTION_SEAL_REQUIRED"):
            self.controller.complete_evaluator(
                self.attempt, verdict="PASS", result={"summary": "unsealed"}
            )
        self.assertEqual("RUNNING", self.store.get_agent_attempt(self.attempt)["status"])
        self.assertEqual(0, self.store.connection.execute(
            "SELECT count(*) FROM evaluation_result"
        ).fetchone()[0])

    def test_recomputed_caller_hash_cannot_replace_sealed_result_bytes(self) -> None:
        result, run, post = self._sealed({"summary": "original"})
        replacement = b'{"summary":"attacker"}'
        run.artifacts.result.path.write_bytes(replacement)
        forged = CodexRunResult(
            command=run.command,
            events=run.events,
            structured_result={"summary": "attacker"},
            exit_code=0,
            timed_out=False,
            removed_environment_names=run.removed_environment_names,
            artifacts=ArtifactSet(
                run.artifacts.stdout,
                run.artifacts.stderr,
                ArtifactFile(
                    run.artifacts.result.path,
                    hashlib.sha256(replacement).hexdigest(),
                ),
                run.artifacts.metadata,
            ),
        )
        with self.assertRaisesRegex(ControllerError, "SEALED_ARTIFACT_MISMATCH"):
            self.controller.complete_evaluator(
                self.attempt,
                verdict="PASS",
                result={"summary": "attacker"},
                run_result=forged,
                post_execution_seal_id=post["seal_id"],
            )
        self.assertEqual("RUNNING", self.store.get_agent_attempt(self.attempt)["status"])

    def test_seal_is_immutable_and_exact_replay_is_idempotent(self) -> None:
        _, _, post = self._sealed()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_EVALUATOR_ARTIFACT_SEAL"):
            self.store.connection.execute(
                "UPDATE evaluator_artifact_seal SET producer_ref='forged' WHERE seal_id=?",
                (post["seal_id"],),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_EVALUATOR_ARTIFACT_SEAL"):
            self.store.connection.execute(
                "DELETE FROM evaluator_artifact_seal WHERE seal_id=?", (post["seal_id"],)
            )
        spec = self._spec_from_row(post)
        replay = self.store.create_evaluator_artifact_seal(
            spec,
            lease_owner=self.controller.controller_id,
            lease_generation=self.store.get_execution("execution-1")["lease_generation"],
        )
        self.assertEqual(post["seal_id"], replay["seal_id"])
        self.store.finish_agent_attempt(
            self.attempt,
            status="SUCCEEDED",
            result_commit=post["result_commit"],
            exit_code=0,
            ended_at="2026-09-01T00:00:00+00:00",
            post_execution_seal_id=post["seal_id"],
            lease_owner=self.controller.controller_id,
            lease_generation=self.store.get_execution("execution-1")["lease_generation"],
            required_execution_state=__import__("adcp.domain", fromlist=["ExecutionState"]).ExecutionState.EVALUATING,
        )
        replay_after_terminal = self.store.create_evaluator_artifact_seal(
            spec,
            lease_owner=self.controller.controller_id,
            lease_generation=self.store.get_execution("execution-1")["lease_generation"],
        )
        self.assertEqual(post["seal_id"], replay_after_terminal["seal_id"])
        conflict = replace(
            spec,
            seal_id="seal-conflict",
            producer_ref="different",
            operation_key=operation_key("seal-conflict", {"attempt": self.attempt}),
        )
        with self.assertRaisesRegex(StoreError, "EVALUATOR_FRESH_SEAL_ATTEMPT_INVALID"):
            self.store.create_evaluator_artifact_seal(
                conflict,
                lease_owner=self.controller.controller_id,
                lease_generation=self.store.get_execution("execution-1")["lease_generation"],
            )

    def test_cross_attempt_context_execution_and_result_substitution_fail(self) -> None:
        _, _, post = self._sealed()
        spec = self._spec_from_row(post)
        second_attempt = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )
        second = self.store.get_agent_attempt(second_attempt)
        second_context = self.store.get_context_snapshot(second["context_snapshot_id"])
        variants = (
            replace(
                spec,
                seal_id="seal-cross-attempt",
                evaluator_attempt_id=second_attempt,
                operation_key=operation_key("cross", {"n": 1}),
            ),
            replace(
                spec,
                seal_id="seal-cross-context",
                context_snapshot_id=second_context["context_snapshot_id"],
                context_fingerprint=second_context["fingerprint"],
                operation_key=operation_key("cross", {"n": 2}),
            ),
            replace(
                spec,
                seal_id="seal-cross-execution",
                execution_id="missing-execution",
                operation_key=operation_key("cross", {"n": 3}),
            ),
            replace(
                spec,
                seal_id="seal-cross-result",
                result_commit=COMMIT_A,
                operation_key=operation_key("cross", {"n": 4}),
            ),
        )
        for variant in variants:
            with self.subTest(seal_id=variant.seal_id):
                with self.assertRaises(StoreError):
                    self.store.create_evaluator_artifact_seal(
                        variant,
                        lease_owner=self.controller.controller_id,
                        lease_generation=self.store.get_execution("execution-1")["lease_generation"],
                    )

    def test_isolated_legacy_attestation_one_byte_mutation_and_cross_attempt_reuse_fail(self) -> None:
        root = self.root / "legacy-isolated"
        root.mkdir()
        stdout = root / "stdout.log"
        stderr = root / "stderr.log"
        result = root / "result.json"
        stdout.write_bytes(b"legacy stdout")
        stderr.write_bytes(b"")
        result.write_bytes(b'{"verdict":"REWORK_REQUIRED"}')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.store.connection.execute(
            """UPDATE agent_attempt SET status='SUCCEEDED',exit_code=0,ended_at=?,
                      stdout_artifact=?,stdout_sha256=?,stderr_artifact=?,stderr_sha256=?,
                      result_artifact=?,result_sha256=?
                 WHERE attempt_id=? AND status='RUNNING'""",
            (
                "2026-09-01T00:00:00+00:00",
                str(stdout), digest(stdout), str(stderr), digest(stderr),
                str(result), digest(result), self.attempt,
            ),
        )
        seal = self.controller.attest_legacy_evaluator_artifacts(
            self.attempt,
            approval_id="ISOLATED-LEGACY-APPROVAL",
            producer_ref="isolated-unit-test",
        )
        original = result.read_bytes()
        result.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(StoreError, "SEALED_ARTIFACT_MISMATCH"):
            self.store.verify_evaluator_artifact_seal(seal["seal_id"])
        result.write_bytes(original)

        second_attempt = self.controller.begin_evaluator(
            "execution-1", self.evaluator_capsule()
        )
        second = self.store.get_agent_attempt(second_attempt)
        second_context = self.store.get_context_snapshot(second["context_snapshot_id"])
        spec = self._spec_from_row(seal)
        forged = replace(
            spec,
            seal_id="legacy-cross-attempt",
            evaluator_attempt_id=second_attempt,
            context_snapshot_id=second_context["context_snapshot_id"],
            context_fingerprint=second_context["fingerprint"],
            operation_key=operation_key("legacy-cross-attempt", {"attempt": second_attempt}),
        )
        with self.assertRaises(StoreError):
            self.store.create_evaluator_artifact_seal(
                forged,
                lease_owner=self.controller.controller_id,
                lease_generation=self.store.get_execution("execution-1")["lease_generation"],
            )

    def test_authority_generation_drift_invalidates_durable_seal(self) -> None:
        _, _, post = self._sealed()
        self.store.connection.execute(
            "UPDATE control_authority_state SET authority_generation=authority_generation+1 "
            "WHERE singleton_id='GLOBAL'"
        )
        with self.assertRaisesRegex(StoreError, "STALE_AUTHORITY_GENERATION"):
            self.store.verify_evaluator_artifact_seal(post["seal_id"])


if __name__ == "__main__":
    unittest.main()
