from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from adcp.domain import RiskLevel, StoreError, operation_key
from adcp.store.sqlite import RuntimePaths, canonical_source_root, validate_runtime_paths
from adcp.store.migrations import migrate
from _helpers import COMMIT_A, COMMIT_B, HASH_A, HASH_B, StoreFixture


class StoreTests(StoreFixture, unittest.TestCase):
    def test_create_and_read_execution_with_transition_evidence(self) -> None:
        row = self.create()
        self.assertEqual("READY", row["state"])
        self.assertEqual(0, row["state_version"])
        self.assertEqual(2, row["max_auto_reworks"])
        self.assertEqual(str(self.repo.resolve()), row["source_root"])
        self.assertRegex(row["created_at"], r"\+00:00$")
        events = self.store.events("execution-1")
        self.assertEqual(1, len(events))
        self.assertEqual(
            ("EXECUTION_CREATED", None, "READY", -1, 0),
            tuple(events[0][key] for key in ("event_type", "from_state", "to_state", "from_state_version", "to_state_version")),
        )

    def test_risk_rework_freeze_in_domain_and_database(self) -> None:
        high = self.store.create_execution(
            self.spec("high", "high-slice", risk=RiskLevel.HIGH),
            operation_key("create-execution", {"execution_id": "high"}),
        )
        self.assertEqual(0, high["max_auto_reworks"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                "UPDATE slice_execution SET max_auto_reworks = 1 WHERE execution_id = 'high'"
            )

    def test_open_execution_uniqueness(self) -> None:
        self.create()
        with self.assertRaisesRegex(StoreError, "OPEN_EXECUTION_EXISTS"):
            self.store.create_execution(
                self.spec("execution-2", "slice-1"),
                operation_key("create-execution", {"execution_id": "execution-2"}),
            )

    def test_canonical_source_path_alias_collapses(self) -> None:
        alias = self.repo / "folder" / ".."
        (self.repo / "folder").mkdir()
        self.assertEqual(self.repo.resolve(), canonical_source_root(alias))

    def test_repository_subdirectory_is_rejected(self) -> None:
        child = self.repo / "child"
        child.mkdir()
        with self.assertRaisesRegex(StoreError, "INVALID_SOURCE_ROOT"):
            canonical_source_root(child)

    def test_symlink_source_alias_cannot_bypass_open_execution_unique(self) -> None:
        alias = self.root / "source-alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        self.create()
        with self.assertRaisesRegex(StoreError, "OPEN_EXECUTION_EXISTS"):
            self.store.create_execution(
                self.spec("execution-2", "slice-1", alias),
                operation_key("create-execution", {"execution_id": "execution-2"}),
            )

    def test_runtime_symlink_into_source_rejected(self) -> None:
        nested = self.repo / "unsafe-runtime"
        nested.mkdir()
        alias = self.root / "runtime-link"
        alias.symlink_to(nested, target_is_directory=True)
        with self.assertRaisesRegex(StoreError, "RUNTIME_PATH_INSIDE_SOURCE"):
            validate_runtime_paths(self.repo, RuntimePaths.configured(alias))

    def test_runtime_prefix_string_does_not_false_match(self) -> None:
        runtime = self.root / "source-runtime"
        validated = validate_runtime_paths(self.repo, RuntimePaths.configured(runtime))
        self.assertEqual(runtime.resolve(), validated.runtime_root)

    def test_runtime_containment_rejects_escape_and_source_contains_runtime(self) -> None:
        runtime = self.root / "runtime"
        escaped = RuntimePaths(
            runtime,
            self.root / "outside.sqlite3",
            runtime / "artifacts",
            runtime / "worktrees",
            runtime / "backups",
        )
        with self.assertRaisesRegex(StoreError, "RUNTIME_PATH_INSIDE_SOURCE"):
            validate_runtime_paths(self.repo, escaped)
        with self.assertRaisesRegex(StoreError, "RUNTIME_PATH_INSIDE_SOURCE"):
            validate_runtime_paths(self.repo, RuntimePaths.configured(self.repo / "runtime"))


class CrossRowIntegrityTests(StoreFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create("execution-1", "slice-1")
        self.create("execution-2", "slice-2")
        connection = self.store.connection
        now = "2026-08-11T01:02:03.456789+00:00"
        for context_id, execution_id, role in (
            ("ctx-m1", "execution-1", "MAKER"),
            ("ctx-e1", "execution-1", "EVALUATOR"),
            ("ctx-m2", "execution-2", "MAKER"),
            ("ctx-e2", "execution-2", "EVALUATOR"),
        ):
            connection.execute(
                "INSERT INTO context_snapshot VALUES (?, ?, ?, 1, ?, '{}', ?)",
                (context_id, execution_id, role, operation_key("context", {"id": context_id}), now),
            )
        connection.execute(
            "UPDATE slice_execution SET result_commit=? WHERE execution_id IN ('execution-1','execution-2')",
            (COMMIT_B,),
        )
        self._attempt("maker-1", "execution-1", "MAKER", 1, "ctx-m1", "SUCCEEDED")
        self._attempt("evaluator-1", "execution-1", "EVALUATOR", 1, "ctx-e1", "SUCCEEDED")
        self._attempt("maker-2", "execution-2", "MAKER", 1, "ctx-m2", "SUCCEEDED")
        self._attempt("evaluator-2", "execution-2", "EVALUATOR", 1, "ctx-e2", "SUCCEEDED")
        self._verification("verification-1", "execution-1")
        self._legacy_seal("seal-evaluator-1", "execution-1", "evaluator-1", "ctx-e1")
        self._evaluation("evaluation-1", "execution-1", "evaluator-1", "ctx-e1")

    def _attempt(
        self,
        attempt_id: str,
        execution_id: str,
        role: str,
        attempt_no: int,
        context_id: str,
        status: str,
    ) -> None:
        ended = None if status == "RUNNING" else "2026-08-11T01:03:03.456789+00:00"
        self.store.connection.execute(
            """INSERT INTO agent_attempt(
                attempt_id, operation_key, execution_id, role, attempt_no, model,
                reasoning_effort, session_mode, session_id, sandbox_mode,
                context_snapshot_id, base_commit, result_commit, status, started_at, ended_at
            ) VALUES (?, ?, ?, ?, ?, 'gpt', 'high', 'FRESH', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                attempt_id,
                operation_key("attempt", {"id": attempt_id}),
                execution_id,
                role,
                attempt_no,
                f"session-{attempt_id}",
                "workspace-write" if role == "MAKER" else "read-only",
                context_id,
                COMMIT_A,
                COMMIT_B if role == "EVALUATOR" or status == "SUCCEEDED" else None,
                status,
                "2026-08-11T01:02:03.456789+00:00",
                ended,
            ),
        )

    def _verification(self, verification_id: str, execution_id: str) -> None:
        self.store.connection.execute(
            """INSERT INTO verification_result(
                verification_id, operation_key, execution_id, result_commit,
                contract_fingerprint, authority_fingerprint, verdict, command_manifest,
                command_manifest_sha256, result_json, started_at, ended_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'PASS', '[]', ?, '{}', ?, ?)""",
            (
                verification_id,
                operation_key("verification", {"id": verification_id}),
                execution_id,
                COMMIT_B,
                HASH_A,
                HASH_B,
                "c" * 64,
                "2026-08-11T01:02:03.456789+00:00",
                "2026-08-11T01:03:03.456789+00:00",
            ),
        )

    def _legacy_seal(
        self, seal_id: str, execution_id: str, attempt_id: str, context_id: str
    ) -> None:
        context = self.store.connection.execute(
            "SELECT fingerprint FROM context_snapshot WHERE context_snapshot_id=?",
            (context_id,),
        ).fetchone()
        authority_generation = self.store.connection.execute(
            "SELECT authority_generation FROM control_authority_state WHERE singleton_id='GLOBAL'"
        ).fetchone()[0]
        manifest_json = (
            '{"artifacts":[{"byte_size":2,"relative_path":"result.json","role":"result",'
            '"sha256":"' + ('a' * 64) + '"}],"manifest_version":1}'
        )
        self.store.connection.execute(
            """INSERT INTO evaluator_artifact_seal(
                seal_id,execution_id,result_commit,verification_id,evaluator_attempt_id,
                context_snapshot_id,context_fingerprint,contract_fingerprint,
                authority_fingerprint,phase,producer_kind,producer_ref,evidence_root,
                manifest_version,manifest_json,manifest_sha256,authority_generation,
                operation_key,approval_id,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,'LEGACY_ATTESTED','LEGACY_HUMAN_ATTESTATION',
                      'store-fixture','/isolated/store-fixture',1,?,?,?,?,?,?)""",
            (
                seal_id, execution_id, COMMIT_B, "verification-1", attempt_id, context_id,
                context[0], HASH_A, HASH_B, manifest_json, "b" * 64, authority_generation,
                operation_key("fixture-seal", {"id": seal_id}), "fixture-approval",
                "2026-08-11T01:03:30.456789+00:00",
            ),
        )

    def _evaluation(
        self, evaluation_id: str, execution_id: str, attempt_id: str, context_id: str
    ) -> None:
        self.store.connection.execute(
            """INSERT INTO evaluation_result(
                evaluation_id, operation_key, execution_id, evaluator_attempt_id,
                context_snapshot_id, result_commit, contract_fingerprint,
                authority_fingerprint, verdict, result_json, started_at, ended_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PASS', '{}', ?, ?)""",
            (
                evaluation_id,
                operation_key("evaluation", {"id": evaluation_id}),
                execution_id,
                attempt_id,
                context_id,
                COMMIT_B,
                HASH_A,
                HASH_B,
                "2026-08-11T01:02:03.456789+00:00",
                "2026-08-11T01:03:03.456789+00:00",
            ),
        )

    def _manifest_values(self, **overrides):
        values = {
            "manifest_id": "manifest-1",
            "execution_id": "execution-1",
            "slice_id": "slice-1",
            "contract_fingerprint": HASH_A,
            "authority_fingerprint": HASH_B,
            "base_commit": COMMIT_A,
            "result_commit": COMMIT_B,
            "maker_attempt_id": "maker-1",
            "verification_id": "verification-1",
            "evaluator_attempt_id": "evaluator-1",
            "evaluation_id": "evaluation-1",
            "approval_refs_json": "[]",
            "context_fingerprints_json": "[]",
            "transition_evidence_json": "[]",
            "canonical_json": "{}",
            "created_at": "2026-08-11T01:04:03.456789+00:00",
            "manifest_sha256": "d" * 64,
        }
        values.update(overrides)
        return tuple(values.values())

    def _insert_manifest(self, **overrides) -> None:
        self.store.connection.execute(
            "INSERT INTO evidence_manifest VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._manifest_values(**overrides),
        )

    def test_cross_execution_context_binding_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._attempt("bad-cross", "execution-2", "MAKER", 2, "ctx-m1", "RUNNING")

    def test_maker_context_bound_to_evaluator_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._attempt("bad-role", "execution-1", "EVALUATOR", 2, "ctx-m1", "RUNNING")

    def test_evaluation_attempt_execution_mismatch_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "EVALUATOR_ATTEMPT_REQUIRED"):
            self._evaluation("bad-eval-execution", "execution-2", "evaluator-1", "ctx-e1")

    def test_evaluation_context_attempt_mismatch_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "EVALUATOR_ATTEMPT_REQUIRED"):
            self._evaluation("bad-eval-context", "execution-1", "evaluator-1", "ctx-e2")

    def test_evidence_cross_execution_binding_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_manifest(execution_id="execution-2", slice_id="slice-2")

    def test_evidence_wrong_maker_role_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "EVIDENCE_ATTEMPT_BINDING_MISMATCH"):
            self._insert_manifest(maker_attempt_id="evaluator-1")

    def test_evidence_wrong_evaluator_role_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "EVIDENCE_ATTEMPT_BINDING_MISMATCH"):
            self._insert_manifest(evaluator_attempt_id="maker-1")

    def test_evidence_result_commit_mismatch_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_manifest(result_commit="3" * 40)

    def test_evidence_contract_fingerprint_mismatch_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_manifest(contract_fingerprint="e" * 64)

    def test_evidence_authority_fingerprint_mismatch_rejected(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_manifest(authority_fingerprint="e" * 64)

    def test_terminal_agent_attempt_update_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AGENT_ATTEMPT"):
            self.store.connection.execute(
                "UPDATE agent_attempt SET result_artifact = 'changed' WHERE attempt_id = 'maker-1'"
            )

    def test_running_agent_attempt_can_finish_once(self) -> None:
        self._attempt("running-finish", "execution-1", "MAKER", 2, "ctx-m1", "RUNNING")
        self.store.connection.execute(
            "UPDATE agent_attempt SET status = 'SUCCEEDED', result_commit = ?, ended_at = ? WHERE attempt_id = 'running-finish'",
            (COMMIT_B, "2026-08-11T01:05:03.456789+00:00"),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AGENT_ATTEMPT"):
            self.store.connection.execute(
                "UPDATE agent_attempt SET result_artifact = 'again' WHERE attempt_id = 'running-finish'"
            )

    def test_agent_attempt_delete_rejected(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AGENT_ATTEMPT"):
            self.store.connection.execute("DELETE FROM agent_attempt WHERE attempt_id = 'maker-1'")

    def test_agent_attempt_identity_mutation_rejected(self) -> None:
        self._attempt("running-1", "execution-1", "MAKER", 2, "ctx-m1", "RUNNING")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_AGENT_ATTEMPT"):
            self.store.connection.execute(
                "UPDATE agent_attempt SET model = 'other' WHERE attempt_id = 'running-1'"
            )

    def test_immutable_record_update_and_delete_rejected(self) -> None:
        for sql in (
            "UPDATE context_snapshot SET canonical_json = '{\"x\":1}' WHERE context_snapshot_id = 'ctx-m1'",
            "DELETE FROM transition_event WHERE execution_id = 'execution-1'",
            "UPDATE verification_result SET result_json = '{\"x\":1}' WHERE verification_id = 'verification-1'",
            "DELETE FROM evaluation_result WHERE evaluation_id = 'evaluation-1'",
        ):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_RECORD"):
                self.store.connection.execute(sql)

    def test_valid_evidence_binding_inserts_then_is_immutable(self) -> None:
        self._insert_manifest()
        self.assertEqual(1, self.store.connection.execute("SELECT count(*) FROM evidence_manifest").fetchone()[0])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "IMMUTABLE_RECORD"):
            self.store.connection.execute("DELETE FROM evidence_manifest WHERE manifest_id = 'manifest-1'")

    def test_composite_foreign_keys_are_enforced(self) -> None:
        self.assertEqual(1, self.store.connection.execute("PRAGMA foreign_keys").fetchone()[0])
        with self.assertRaises(sqlite3.IntegrityError):
            self._attempt("violation", "execution-2", "MAKER", 2, "ctx-m1", "RUNNING")
        self.assertEqual([], list(self.store.connection.execute("PRAGMA foreign_key_check")))


class CandidateSchemaV9Tests(unittest.TestCase):
    def test_representative_v8_migrates_additively_to_v9(self) -> None:
        connection = sqlite3.connect(":memory:")
        migrate(connection, target_version=8)
        connection.execute("PRAGMA foreign_keys=ON")
        before = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        result = migrate(connection, target_version=9)
        after = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        self.assertEqual(9, result.version)
        self.assertTrue(before.issubset(after))
        self.assertIn("candidate_content_binding", after)
        self.assertIn("candidate_commit_closure", after)

    def test_candidate_binding_is_immutable_and_typed(self) -> None:
        connection = sqlite3.connect(":memory:")
        migrate(connection, target_version=9)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""INSERT INTO candidate_content_binding(candidate_id,execution_id,
                review_target_type,serialization_format,serialization_version,repository_identity,
                expected_parent,manifest_json,manifest_sha256,candidate_content_sha256,created_at)
                VALUES('c','missing','GIT_COMMIT','ADCP_INTEGRATED_CANDIDATE_V1',1,'repo',?, '{}',?,?, 'now')""",
                (COMMIT_A,HASH_A,HASH_B))


if __name__ == "__main__":
    unittest.main()
