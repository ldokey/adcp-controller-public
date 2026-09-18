"""SQLite connection policy, path safety, and transactional control-store API."""

from __future__ import annotations

from contextlib import contextmanager
import contextvars
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from typing import Any, Callable, Iterator, Mapping
from uuid import uuid4

from adcp.canonical import canonical_json, canonical_sha256
from adcp.artifact_seal import (
    ArtifactSealError,
    VerifiedArtifactManifest,
    parse_manifest,
    relative_artifact_path,
    verify_manifest_bytes,
)
from adcp.capsule import CapsuleRole, ContextCapsule
from adcp.domain import (
    ActorRole,
    CandidateWriteFence,
    EvaluatorArtifactProducerKind,
    EvaluatorArtifactSealCreate,
    EvaluatorArtifactSealPhase,
    ExecutionCreate,
    ExecutionState,
    StoreError,
    TERMINAL_STATES,
    require_commit,
    require_sha256,
    timestamp,
    utc_now,
    validate_transition,
)
from adcp.evaluator import (
    EvaluationResultRecord,
    EvaluatorArtifactBinding,
    EvaluatorBoundaryError,
    build_evaluation_result,
    decode_durable_evaluator_result_bytes_for_recovery,
    decode_durable_evaluator_result_for_recovery,
    validate_durable_evaluator_completion_binding,
)
from adcp.verifier import VerificationResultRecord, validate_candidate_verification_payload
from adcp.evidence import EvidenceManifest
from .migrations import migrate


DEFAULT_RUNTIME_ROOT = Path("/Users/kate/DKATE/adcp-runtime")
CANONICAL_PRODUCTION_CONTROL_STORE = DEFAULT_RUNTIME_ROOT / "control.sqlite3"
DEFAULT_LEASE_TTL_SECONDS = 60
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 20
MIN_LEASE_TTL_SECONDS = 15
MAX_LEASE_TTL_SECONDS = 300

GLOBAL_PRODUCTION_RESOURCE_KEY = "GLOBAL_PRODUCTION"
GLOBAL_WRITER_CONTEXT_FIELDS = (
    "owner_id",
    "owner_execution_id",
    "change_id",
    "slice_id",
    "writer_class",
    "owner_session_role",
    "track",
    "repository_or_runtime",
    "operation_class",
    "target",
)
GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS = (
    "owner_id",
    "change_id",
    "writer_class",
    "owner_session_role",
    "track",
    "repository_or_runtime",
    "operation_class",
    "target",
)
GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS = ("owner_execution_id", "slice_id")

CONTROL_STATE_SEMANTIC_FIELDS = (
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
)
CONTROL_STATE_INPUT_FIELDS = (*CONTROL_STATE_SEMANTIC_FIELDS, "authority_fingerprint")


def control_state_authority_fingerprint(state: Mapping[str, Any]) -> str:
    """Hash the normalized, nullable Slice control semantics canonically."""

    return canonical_sha256({field: state.get(field) for field in CONTROL_STATE_SEMANTIC_FIELDS})


@dataclass(frozen=True)
class RuntimePaths:
    runtime_root: Path
    control_store: Path
    artifact_root: Path
    worktree_root: Path
    backup_root: Path

    @classmethod
    def configured(cls, runtime_root: str | Path | None = None) -> "RuntimePaths":
        root = Path(runtime_root or os.environ.get("ADCP_RUNTIME_ROOT", DEFAULT_RUNTIME_ROOT))
        return cls(
            runtime_root=root,
            control_store=root / "control.sqlite3",
            artifact_root=root / "artifacts",
            worktree_root=root / "worktrees",
            backup_root=root / "backups",
        )


def _resolved(path: str | Path, *, strict: bool) -> Path:
    return Path(path).expanduser().resolve(strict=strict)


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def canonical_source_root(raw_source_root: str | Path) -> Path:
    candidate = _resolved(raw_source_root, strict=True)
    if not candidate.is_dir():
        raise StoreError("INVALID_SOURCE_ROOT", "source root must be a directory")
    completed = subprocess.run(
        ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise StoreError("INVALID_SOURCE_ROOT", "source root must be a Git repository")
    git_root = _resolved(completed.stdout.strip(), strict=True)
    if git_root != candidate:
        raise StoreError("INVALID_SOURCE_ROOT", "repository subdirectory is not an identity")
    return git_root


def validate_runtime_paths(source_root: str | Path, paths: RuntimePaths) -> RuntimePaths:
    """Resolve aliases and enforce ancestry rather than string-prefix safety."""

    source = canonical_source_root(source_root)
    runtime = _resolved(paths.runtime_root, strict=False)
    control = _resolved(paths.control_store, strict=False)
    artifacts = _resolved(paths.artifact_root, strict=False)
    worktrees = _resolved(paths.worktree_root, strict=False)
    backups = _resolved(paths.backup_root, strict=False)

    unsafe = _inside(runtime, source) or _inside(source, runtime)
    children = (control, artifacts, worktrees, backups)
    unsafe = unsafe or any(not _inside(child, runtime) for child in children)
    unsafe = unsafe or any(_inside(child, source) for child in (control, artifacts, backups))
    unsafe = unsafe or any(_inside(child, worktrees) for child in (control, artifacts, backups))
    if unsafe:
        raise StoreError("RUNTIME_PATH_INSIDE_SOURCE")
    return RuntimePaths(runtime, control, artifacts, worktrees, backups)


def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        Path(path), isolation_level=None, timeout=5.0
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


class ControlStore:
    """C1/C2 store primitives; orchestration and conditional gates are deferred."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        backup_root: str | Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        migrate_schema: bool = True,
        require_schema_version: int | None = None,
        global_writer_guard_required: bool | None = None,
        allow_canonical_production_bootstrap: bool = False,
    ) -> None:
        self.database_path = Path(database_path).expanduser().resolve(strict=False)
        self.clock = clock
        canonical_production = CANONICAL_PRODUCTION_CONTROL_STORE.resolve(strict=False)
        is_canonical_production = self.database_path == canonical_production
        if is_canonical_production and migrate_schema and not allow_canonical_production_bootstrap:
            # 01C owns canonical Production bootstrap/migration. Reject before connect() so
            # even SQLite journal/pragma setup cannot mutate the operational store.
            raise StoreError("CANONICAL_PRODUCTION_BOOTSTRAP_REQUIRED")
        if is_canonical_production and not migrate_schema and require_schema_version is not None:
            # Validate readiness through an immutable read-only handle before connect(),
            # because connect() intentionally configures WAL/synchronous pragmas.
            try:
                uri = self.database_path.as_uri() + "?mode=ro&immutable=1"
                readonly = sqlite3.connect(uri, uri=True)
                try:
                    row = readonly.execute("SELECT max(version) FROM schema_migration").fetchone()
                finally:
                    readonly.close()
            except sqlite3.Error as error:
                raise StoreError("CONTROL_STORE_SCHEMA_VERSION_MISMATCH", str(error)) from error
            version = None if row is None else row[0]
            if version != require_schema_version:
                raise StoreError(
                    "CONTROL_STORE_SCHEMA_VERSION_MISMATCH",
                    f"expected={require_schema_version},actual={version}",
                )
        self.global_writer_guard_required = (
            is_canonical_production
            if global_writer_guard_required is None
            else bool(global_writer_guard_required)
        )
        self._ordinary_global_writer_authority: contextvars.ContextVar[tuple[str, int] | None] = (
            contextvars.ContextVar(
                f"adcp_ordinary_global_writer_authority_{id(self)}", default=None
            )
        )
        self.connection = connect(self.database_path)
        try:
            if migrate_schema:
                migrate(
                    self.connection,
                    backup_root=Path(backup_root) if backup_root is not None else None,
                    now=self._now(),
                )
            if require_schema_version is not None:
                row = self.connection.execute(
                    "SELECT max(version) AS version FROM schema_migration"
                ).fetchone()
                version = None if row is None else row["version"]
                if version != require_schema_version:
                    raise StoreError(
                        "CONTROL_STORE_SCHEMA_VERSION_MISMATCH",
                        f"expected={require_schema_version},actual={version}",
                    )
        except BaseException:
            self.connection.close()
            raise

    def __enter__(self) -> "ControlStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def _require_candidate_fence(
        self, execution_id: str, fence: CandidateWriteFence, *, check_version: bool = True
    ) -> sqlite3.Row:
        if not isinstance(fence, CandidateWriteFence) or fence.execution_id != execution_id:
            raise StoreError("CANDIDATE_FENCING_TOKEN_REQUIRED")
        row = self.get_execution(execution_id)
        self._require_fence(row, fence.lease_owner, fence.lease_generation, timestamp(self._now()))
        if check_version and row["state_version"] != fence.expected_state_version:
            raise StoreError("STALE_STATE_VERSION")
        if self.get_control_authority_state()["authority_generation"] != fence.authority_generation:
            raise StoreError("STALE_AUTHORITY_GENERATION")
        if (row["contract_fingerprint"] != fence.contract_fingerprint
                or row["authority_fingerprint"] != fence.authority_fingerprint):
            raise StoreError("CANDIDATE_AUTHORITY_BINDING_MISMATCH")
        return row

    @contextmanager
    def _candidate_transaction(self, execution_id: str, fence: CandidateWriteFence):
        # BEGIN IMMEDIATE serializes candidate writes with lease/authority CAS.
        # Existing default/global-writer transaction policy is deliberately reused.
        self._begin()
        try:
            row = self._require_candidate_fence(execution_id, fence)
            yield row
            self._require_candidate_fence(execution_id, fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

    def get_candidate_binding(self, candidate_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM candidate_content_binding WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if row is None:
            raise StoreError("CANDIDATE_BINDING_NOT_FOUND", candidate_id)
        return row

    def find_current_candidate_binding(self, execution_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            """SELECT b.* FROM candidate_content_binding b
                 JOIN candidate_provenance p ON p.candidate_id=b.candidate_id
                WHERE b.execution_id=? ORDER BY p.created_at DESC, p.rowid DESC LIMIT 1""",
            (execution_id,),
        ).fetchone()

    def bind_precommit_candidate(
        self, binding: Any, *, maker_attempt_id: str, canonical_source_root: str,
        worktree_identity: str, branch: str, contract_fingerprint: str,
        authority_fingerprint: str, authority_generation: int,
        fence: CandidateWriteFence,
    ) -> sqlite3.Row:
        """Atomically append immutable content/provenance and finish this Maker."""
        require_sha256(binding.candidate_content_sha256, "candidate_content_sha256")
        require_sha256(binding.manifest_sha256, "manifest_sha256")
        if canonical_sha256(json.loads(binding.manifest_json)) != binding.manifest_sha256:
            raise StoreError("CANDIDATE_MANIFEST_HASH_MISMATCH")
        if authority_generation != fence.authority_generation:
            raise StoreError("STALE_AUTHORITY_GENERATION")
        now = timestamp(self._now())
        self._begin()
        try:
            self._require_candidate_fence(binding.execution_id, fence)
            execution = self.get_execution(binding.execution_id)
            attempt = self.get_agent_attempt(maker_attempt_id)
            if execution["state"] != ExecutionState.MAKER_RUNNING.value or execution["result_commit"] is not None:
                raise StoreError("MAKER_COMPLETION_STATE_INVALID")
            if attempt["execution_id"] != binding.execution_id or attempt["role"] != "MAKER" or attempt["status"] != "RUNNING":
                raise StoreError("CANDIDATE_MAKER_ATTEMPT_MISMATCH")
            existing = self.connection.execute(
                "SELECT * FROM candidate_content_binding WHERE execution_id=? AND manifest_sha256=?",
                (binding.execution_id, binding.manifest_sha256),
            ).fetchone()
            dimensions = (
                binding.serialization_format, binding.serialization_version,
                binding.repository_identity, binding.expected_parent,
                binding.manifest_json, binding.manifest_sha256,
            )
            if existing is None:
                self.connection.execute(
                    """INSERT INTO candidate_content_binding(candidate_id,execution_id,review_target_type,
                       serialization_format,serialization_version,repository_identity,expected_parent,
                       manifest_json,manifest_sha256,candidate_content_sha256,created_at)
                       VALUES(?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,?,?,?,?)""",
                    (binding.candidate_id,binding.execution_id,*dimensions,binding.candidate_content_sha256,now),
                )
                candidate_id = binding.candidate_id
            else:
                fields = ("serialization_format","serialization_version","repository_identity","expected_parent","manifest_json","manifest_sha256")
                if tuple(existing[field] for field in fields) != dimensions:
                    raise StoreError("CANDIDATE_DIGEST_SUBSTITUTION")
                candidate_id = existing["candidate_id"]
            provenance_id = f"provenance-{maker_attempt_id}"
            self.connection.execute(
                """INSERT INTO candidate_provenance(provenance_id,candidate_id,execution_id,maker_attempt_id,
                   canonical_source_root,worktree_identity,branch,contract_fingerprint,authority_fingerprint,
                   authority_generation,candidate_content_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (provenance_id,candidate_id,binding.execution_id,maker_attempt_id,canonical_source_root,
                 worktree_identity,branch,contract_fingerprint,authority_fingerprint,authority_generation,
                 binding.candidate_content_sha256,now),
            )
            self.connection.execute(
                "UPDATE agent_attempt SET status='SUCCEEDED',exit_code=0,ended_at=? WHERE attempt_id=? AND status='RUNNING'",
                (now,maker_attempt_id),
            )
            self._require_candidate_fence(binding.execution_id, fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_candidate_binding(candidate_id)

    def register_candidate_verification(self, *, verification_id: str, operation_key: str,
        execution_id: str, candidate_id: str, candidate_content_sha256: str,
        contract_fingerprint: str, authority_fingerprint: str, authority_generation: int,
        verdict: str, command_manifest: str, command_manifest_sha256: str,
        result_json: str, started_at: str, ended_at: str,
        fence: CandidateWriteFence) -> sqlite3.Row:
        if verdict not in {"PASS","FAIL","BLOCKED_ENVIRONMENT"}:
            raise StoreError("INVALID_VERIFICATION_VERDICT")
        for value, field in ((operation_key,"operation_key"),(candidate_content_sha256,"candidate_content_sha256"),
                             (contract_fingerprint,"contract_fingerprint"),(authority_fingerprint,"authority_fingerprint"),
                             (command_manifest_sha256,"command_manifest_sha256")):
            require_sha256(value, field)
        validate_candidate_verification_payload(command_manifest, command_manifest_sha256, result_json, verdict)
        if authority_generation != fence.authority_generation:
            raise StoreError("STALE_AUTHORITY_GENERATION")
        binding = self.get_candidate_binding(candidate_id)
        execution = self.get_execution(execution_id)
        if (binding["execution_id"] != execution_id or binding["candidate_content_sha256"] != candidate_content_sha256
                or execution["result_commit"] is not None or execution["contract_fingerprint"] != contract_fingerprint
                or execution["authority_fingerprint"] != authority_fingerprint):
            raise StoreError("CANDIDATE_BINDING_MISMATCH")
        self._begin()
        try:
            current = self._require_candidate_fence(execution_id, fence)
            if current["state"] != "VERIFYING" or current["result_commit"] is not None:
                raise StoreError("CANDIDATE_LIFECYCLE_STATE_MISMATCH")
            self.connection.execute(
                """INSERT INTO candidate_verification_result(verification_id,operation_key,execution_id,
                   review_target_type,candidate_id,candidate_content_sha256,contract_fingerprint,authority_fingerprint,
                   authority_generation,verdict,command_manifest,command_manifest_sha256,result_json,started_at,ended_at)
                   VALUES(?,?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,?,?,?,?,?,?,?)""",
                (verification_id,operation_key,execution_id,candidate_id,candidate_content_sha256,
                 contract_fingerprint,authority_fingerprint,authority_generation,verdict,command_manifest,
                 command_manifest_sha256,result_json,started_at,ended_at),
            )
            self._require_candidate_fence(execution_id, fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback(); raise
        return self.connection.execute("SELECT * FROM candidate_verification_result WHERE verification_id=?",(verification_id,)).fetchone()

    def begin_candidate_evaluator_attempt(self, *, evaluator_attempt_id: str, execution_id: str,
        candidate_id: str, verification_id: str, context_snapshot_id: str,
        fence: CandidateWriteFence) -> sqlite3.Row:
        binding = self.get_candidate_binding(candidate_id)
        verification = self.connection.execute(
            "SELECT * FROM candidate_verification_result WHERE verification_id=?", (verification_id,)
        ).fetchone()
        execution = self.get_execution(execution_id)
        conflict = self.connection.execute(
            "SELECT 1 FROM agent_attempt WHERE execution_id=? AND role='MAKER' AND status='RUNNING'",
            (execution_id,),
        ).fetchone()
        if (execution["state"] != "EVALUATING" or execution["result_commit"] is not None
                or verification is None or verification["verdict"] != "PASS"
                or verification["candidate_id"] != candidate_id or binding["execution_id"] != execution_id
                or conflict is not None):
            raise StoreError("CANDIDATE_EVALUATOR_ENTRY_FORBIDDEN")
        self._begin()
        try:
            current = self._require_candidate_fence(execution_id, fence)
            if current["state"] != "EVALUATING" or current["result_commit"] is not None:
                raise StoreError("CANDIDATE_LIFECYCLE_STATE_MISMATCH")
            if (verification["authority_generation"] != fence.authority_generation
                    or verification["contract_fingerprint"] != fence.contract_fingerprint
                    or verification["authority_fingerprint"] != fence.authority_fingerprint):
                raise StoreError("CANDIDATE_VERIFICATION_STALE")
            self.connection.execute(
                """INSERT INTO candidate_evaluator_attempt(evaluator_attempt_id,execution_id,candidate_id,
                   verification_id,context_snapshot_id,review_target_type,candidate_content_sha256,lease_owner,lease_generation,authority_generation,status,started_at)
                   VALUES(?,?,?,?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,'RUNNING',?)""",
                (evaluator_attempt_id,execution_id,candidate_id,verification_id,context_snapshot_id,
                 binding["candidate_content_sha256"],fence.lease_owner,fence.lease_generation,fence.authority_generation,timestamp(self._now())),
            )
            self._require_candidate_fence(execution_id, fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback(); raise
        return self.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?",(evaluator_attempt_id,)).fetchone()

    def register_candidate_evaluation(self, *, evaluation_id: str, operation_key: str,
        execution_id: str, evaluator_attempt_id: str, candidate_id: str,
        candidate_content_sha256: str, contract_fingerprint: str, authority_fingerprint: str,
        authority_generation: int, verdict: str, result_json: str,
        started_at: str, ended_at: str, fence: CandidateWriteFence) -> sqlite3.Row:
        if verdict not in {"PASS","REWORK_REQUIRED","DESIGN_REVIEW_REQUIRED","BLOCKED_ENVIRONMENT","BLOCKED_EVIDENCE"}:
            raise StoreError("INVALID_EVALUATION_VERDICT")
        for value, field in ((operation_key,"operation_key"),(candidate_content_sha256,"candidate_content_sha256"),
                             (contract_fingerprint,"contract_fingerprint"),(authority_fingerprint,"authority_fingerprint")):
            require_sha256(value,field)
        execution = self.get_execution(execution_id)
        attempt = self.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?",(evaluator_attempt_id,)).fetchone()
        if (execution["state"] != "EVALUATING" or attempt is None or attempt["status"] != "RUNNING"
                or attempt["candidate_id"] != candidate_id or attempt["candidate_content_sha256"] != candidate_content_sha256):
            raise StoreError("CANDIDATE_EVALUATOR_TARGET_MISMATCH")
        self._begin()
        try:
            current = self._require_candidate_fence(execution_id, fence)
            if current["state"] != "EVALUATING" or current["result_commit"] is not None:
                raise StoreError("CANDIDATE_LIFECYCLE_STATE_MISMATCH")
            attempt = self.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?", (evaluator_attempt_id,)).fetchone()
            if (attempt["status"] != "RUNNING" or attempt["execution_id"] != execution_id
                    or attempt["lease_owner"] != fence.lease_owner or attempt["lease_generation"] != fence.lease_generation
                    or attempt["authority_generation"] != authority_generation or authority_generation != fence.authority_generation
                    or contract_fingerprint != fence.contract_fingerprint or authority_fingerprint != fence.authority_fingerprint):
                raise StoreError("CANDIDATE_EVALUATOR_TARGET_MISMATCH")
            parsed_result = json.loads(result_json)
            if parsed_result.get("verdict") != verdict or parsed_result.get("candidate_id") != candidate_id:
                raise StoreError("CANDIDATE_EVALUATION_RESULT_BINDING_MISMATCH")
            self._verify_candidate_evaluator_seals(evaluator_attempt_id, result_json=result_json)
            self.connection.execute(
                """INSERT INTO candidate_evaluation_result(evaluation_id,operation_key,execution_id,
                   evaluator_attempt_id,candidate_id,review_target_type,candidate_content_sha256,
                   contract_fingerprint,authority_fingerprint,authority_generation,verdict,result_json,started_at,ended_at)
                   VALUES(?,?,?,?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,?,?,?,?)""",
                (evaluation_id,operation_key,execution_id,evaluator_attempt_id,candidate_id,
                 candidate_content_sha256,contract_fingerprint,authority_fingerprint,authority_generation,
                 verdict,result_json,started_at,ended_at),
            )
            self.connection.execute(
                "UPDATE candidate_evaluator_attempt SET status='SUCCEEDED',ended_at=? WHERE evaluator_attempt_id=? AND status='RUNNING'",
                (ended_at,evaluator_attempt_id),
            )
            self._require_candidate_fence(execution_id, fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback(); raise
        return self.connection.execute("SELECT * FROM candidate_evaluation_result WHERE evaluation_id=?",(evaluation_id,)).fetchone()

    def create_candidate_evaluator_artifact_seal(self, *, seal_id: str,
        evaluator_attempt_id: str, phase: str, manifest_json: str,
        manifest_sha256: str, evidence_root: str, fence: CandidateWriteFence) -> sqlite3.Row:
        require_sha256(manifest_sha256,"manifest_sha256")
        if phase not in {"PRE_EXECUTION","POST_EXECUTION"}:
            raise StoreError("INVALID_EVALUATOR_ARTIFACT_SEAL")
        attempt=self.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?",(evaluator_attempt_id,)).fetchone()
        if attempt is None:
            raise StoreError("CANDIDATE_EVALUATOR_ATTEMPT_NOT_FOUND")
        if canonical_sha256(json.loads(manifest_json)) != manifest_sha256 or canonical_json(json.loads(manifest_json)) != manifest_json:
            raise StoreError("EVALUATOR_ARTIFACT_MANIFEST_HASH_MISMATCH")
        self._begin()
        try:
            self._require_candidate_fence(attempt["execution_id"], fence)
            attempt = self.connection.execute("SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?", (evaluator_attempt_id,)).fetchone()
            if (attempt["status"] != "RUNNING" or attempt["lease_owner"] != fence.lease_owner
                    or attempt["lease_generation"] != fence.lease_generation
                    or attempt["authority_generation"] != fence.authority_generation):
                raise StoreError("CANDIDATE_EVALUATOR_TARGET_MISMATCH")
            verified = verify_manifest_bytes(evidence_root, manifest_json, manifest_sha256)
            required_roles = {"context_snapshot", "prompt", "output_schema"} if phase == "PRE_EXECUTION" else {"stdout", "stderr", "result", "runner_metadata"}
            if not required_roles.issubset({entry.role for entry in verified.entries}):
                raise StoreError("CANDIDATE_EVALUATOR_REQUIRED_ARTIFACT_MISSING")
            if phase == "PRE_EXECUTION":
                context = self.get_context_snapshot(attempt["context_snapshot_id"])
                if verified.bytes_for_role("context_snapshot") != context["canonical_json"].encode("utf-8"):
                    raise StoreError("CANDIDATE_EVALUATOR_CONTEXT_MISMATCH")
            else:
                self._verify_candidate_evaluator_seals(evaluator_attempt_id, require_post=False)
            self.connection.execute(
                """INSERT INTO candidate_evaluator_artifact_seal(seal_id,execution_id,evaluator_attempt_id,
                   candidate_id,review_target_type,candidate_content_sha256,phase,evidence_root,manifest_json,manifest_sha256,created_at)
                   VALUES(?,?,?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,?,?)""",
                (seal_id,attempt["execution_id"],evaluator_attempt_id,attempt["candidate_id"],
                 attempt["candidate_content_sha256"],phase,evidence_root,manifest_json,manifest_sha256,timestamp(self._now())),
            )
            self._require_candidate_fence(attempt["execution_id"], fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback(); raise
        return self.connection.execute("SELECT * FROM candidate_evaluator_artifact_seal WHERE seal_id=?",(seal_id,)).fetchone()

    def _verify_candidate_evaluator_seals(
        self, evaluator_attempt_id: str, *, result_json: str | None = None, require_post: bool = True
    ) -> None:
        seals = {row["phase"]: row for row in self.connection.execute(
            "SELECT * FROM candidate_evaluator_artifact_seal WHERE evaluator_attempt_id=?", (evaluator_attempt_id,)
        )}
        required = ("PRE_EXECUTION", "POST_EXECUTION") if require_post else ("PRE_EXECUTION",)
        for phase in required:
            seal = seals.get(phase)
            if seal is None:
                raise StoreError("CANDIDATE_EVALUATOR_SEAL_REQUIRED", phase)
            verified = verify_manifest_bytes(seal["evidence_root"], seal["manifest_json"], seal["manifest_sha256"])
            if phase == "POST_EXECUTION" and result_json is not None:
                if canonical_json(json.loads(result_json)) != result_json or verified.bytes_for_role("result") != result_json.encode("utf-8"):
                    raise StoreError("CANDIDATE_EVALUATION_RESULT_ARTIFACT_MISMATCH")
                attempt = self.connection.execute(
                    "SELECT * FROM candidate_evaluator_attempt WHERE evaluator_attempt_id=?", (evaluator_attempt_id,)
                ).fetchone()
                metadata = json.loads(verified.bytes_for_role("runner_metadata"))
                expected = {"review_target_type":"UNCOMMITTED_CANDIDATE", "evaluator_attempt_id":evaluator_attempt_id,
                    "candidate_id":attempt["candidate_id"], "candidate_content_sha256":attempt["candidate_content_sha256"],
                    "authority_generation":attempt["authority_generation"], "exit_code":0, "timed_out":False}
                if (not isinstance(metadata, dict) or any(metadata.get(key) != value for key,value in expected.items())
                        or not isinstance(metadata.get("command"), list) or not metadata["command"]
                        or not metadata.get("producer_ref")):
                    raise StoreError("CANDIDATE_EVALUATOR_RUNTIME_BINDING_MISMATCH")

    def bind_candidate_approval(self, *, approval_id: str, evaluation_id: str,
        candidate_id: str, authority_generation: int, fence: CandidateWriteFence) -> sqlite3.Row:
        evaluation = self.connection.execute("SELECT * FROM candidate_evaluation_result WHERE evaluation_id=?",(evaluation_id,)).fetchone()
        approval = self.get_approval(approval_id)
        if (evaluation is None or evaluation["verdict"] != "PASS" or approval["execution_id"] != evaluation["execution_id"]
                or evaluation["candidate_id"] != candidate_id):
            raise StoreError("CANDIDATE_APPROVAL_BINDING_MISMATCH")
        self._begin()
        try:
            self._require_candidate_fence(evaluation["execution_id"], fence)
            if (authority_generation != fence.authority_generation
                    or evaluation["authority_generation"] != authority_generation
                    or evaluation["authority_fingerprint"] != fence.authority_fingerprint
                    or approval["approval_type"] != "DEVELOPMENT_ACCEPTANCE"):
                raise StoreError("CANDIDATE_APPROVAL_BINDING_MISMATCH")
            self._verify_candidate_evaluator_seals(evaluation["evaluator_attempt_id"], result_json=evaluation["result_json"])
            self.connection.execute(
                """INSERT INTO approval_candidate_binding(approval_id,execution_id,review_target_type,candidate_id,
                   evaluation_id,authority_fingerprint,authority_generation,created_at)
                   VALUES(?,?,'UNCOMMITTED_CANDIDATE',?,?,?,?,?)""",
                (approval_id,evaluation["execution_id"],candidate_id,evaluation_id,
                 evaluation["authority_fingerprint"],authority_generation,timestamp(self._now())),
            )
            self._require_candidate_fence(evaluation["execution_id"], fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback(); raise
        return self.connection.execute("SELECT * FROM approval_candidate_binding WHERE approval_id=?",(approval_id,)).fetchone()

    def _candidate_closure_authority(
        self, execution_id: str, candidate_id: str, evaluation_id: str,
        approval_id: str, fence: CandidateWriteFence, *, allow_consumed: bool = False,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        execution = self._require_candidate_fence(execution_id, fence)
        binding = self.get_candidate_binding(candidate_id)
        approval = self.get_approval(approval_id)
        linked = self.connection.execute(
            "SELECT * FROM approval_candidate_binding WHERE approval_id=?", (approval_id,)
        ).fetchone()
        evaluation = self.connection.execute(
            "SELECT * FROM candidate_evaluation_result WHERE evaluation_id=?", (evaluation_id,)
        ).fetchone()
        if (binding["execution_id"] != execution_id or linked is None or evaluation is None
                or approval["execution_id"] != execution_id or approval["status"] != "APPROVED"
                or approval["approval_type"] != "DEVELOPMENT_ACCEPTANCE"
                or (approval["consumed_at"] is not None and not allow_consumed)
                or linked["candidate_id"] != candidate_id or linked["evaluation_id"] != evaluation_id
                or linked["execution_id"] != execution_id or evaluation["execution_id"] != execution_id
                or evaluation["candidate_id"] != candidate_id or evaluation["verdict"] != "PASS"
                or linked["authority_generation"] != fence.authority_generation
                or linked["authority_fingerprint"] != fence.authority_fingerprint
                or evaluation["authority_generation"] != fence.authority_generation
                or evaluation["contract_fingerprint"] != fence.contract_fingerprint
                or evaluation["authority_fingerprint"] != fence.authority_fingerprint
                or evaluation["candidate_content_sha256"] != binding["candidate_content_sha256"]):
            raise StoreError("CANDIDATE_APPROVAL_BINDING_MISMATCH")
        if not allow_consumed and (execution["state"] != "WAITING_APPROVAL" or execution["result_commit"] is not None):
            raise StoreError("CANDIDATE_COMMIT_CLOSURE_STATE_INVALID")
        self._verify_candidate_evaluator_seals(evaluation["evaluator_attempt_id"], result_json=evaluation["result_json"])
        return execution, binding

    def prepare_candidate_commit(
        self, *, execution_id: str, candidate_id: str, evaluation_id: str, approval_id: str,
        closure_id: str, fence: CandidateWriteFence, prepare: Callable[[], Mapping[str, Any]],
    ) -> sqlite3.Row:
        """Durably bind one exact future commit before updating any Git reference."""
        with self._candidate_transaction(execution_id, fence):
            existing = self.connection.execute(
                "SELECT * FROM candidate_commit_intent WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            closed = self.connection.execute(
                "SELECT 1 FROM candidate_commit_closure WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            _, binding = self._candidate_closure_authority(
                execution_id, candidate_id, evaluation_id, approval_id, fence, allow_consumed=closed is not None
            )
            identities = {"closure_id": closure_id, "execution_id": execution_id,
                          "candidate_id": candidate_id, "evaluation_id": evaluation_id, "approval_id": approval_id}
            if existing is not None:
                if any(existing[key] != value for key, value in identities.items()):
                    raise StoreError("CANDIDATE_COMMIT_INTENT_CONFLICT")
                if canonical_sha256(json.loads(existing["plan_json"])) != existing["plan_sha256"]:
                    raise StoreError("CANDIDATE_COMMIT_INTENT_CORRUPT")
                return existing
            plan = dict(prepare())
            if any(plan.get(key) != value for key, value in identities.items()):
                raise StoreError("CANDIDATE_COMMIT_INTENT_CONFLICT")
            if (plan.get("expected_parent") != binding["expected_parent"]
                    or plan.get("manifest_sha256") != binding["manifest_sha256"]
                    or plan.get("candidate_content_sha256") != binding["candidate_content_sha256"]):
                raise StoreError("CANDIDATE_COMMIT_INTENT_CONFLICT")
            require_commit(plan["expected_tree"], "expected_tree")
            require_commit(plan["result_commit"], "result_commit")
            self._require_candidate_fence(execution_id, fence)
            self.connection.execute(
                """INSERT INTO candidate_commit_intent(closure_id,execution_id,candidate_id,approval_id,
                    evaluation_id,plan_json,plan_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (closure_id,execution_id,candidate_id,approval_id,evaluation_id,
                 canonical_json(plan),canonical_sha256(plan),timestamp(self._now())),
            )
        return self.connection.execute("SELECT * FROM candidate_commit_intent WHERE closure_id=?", (closure_id,)).fetchone()

    def close_candidate_to_commit(
        self, *, closure_id: str, execution_id: str, candidate_id: str,
        approval_id: str, evaluation_id: str, fence: CandidateWriteFence,
        apply: Callable[[Mapping[str, Any]], str],
    ) -> sqlite3.Row:
        # This transaction spans the Git CAS. Competing lease/authority writers
        # cannot acquire a newer generation between the precheck and the effect.
        with self._candidate_transaction(execution_id, fence):
            intent = self.connection.execute("SELECT * FROM candidate_commit_intent WHERE closure_id=?", (closure_id,)).fetchone()
            if intent is None or any(intent[key] != value for key, value in {
                "execution_id":execution_id,"candidate_id":candidate_id,
                "approval_id":approval_id,"evaluation_id":evaluation_id,
            }.items()):
                raise StoreError("CANDIDATE_COMMIT_INTENT_CONFLICT")
            plan = json.loads(intent["plan_json"])
            if canonical_sha256(plan) != intent["plan_sha256"]:
                raise StoreError("CANDIDATE_COMMIT_INTENT_CORRUPT")
            existing = self.connection.execute("SELECT * FROM candidate_commit_closure WHERE closure_id=?", (closure_id,)).fetchone()
            execution, binding = self._candidate_closure_authority(
                execution_id,candidate_id,evaluation_id,approval_id,fence,allow_consumed=existing is not None
            )
            if existing is not None and (execution["result_commit"] != existing["result_commit"]
                    or existing["result_commit"] != plan["result_commit"]
                    or self.get_approval(approval_id)["consumed_at"] is None):
                raise StoreError("CANDIDATE_COMMIT_CLOSURE_CONFLICT")
            # Even replay must verify the intent, exact Git tree and worktree;
            # an observed HEAD by itself is never successful reconciliation.
            result_commit = apply(plan)
            if result_commit != plan["result_commit"]:
                raise StoreError("CANDIDATE_COMMIT_INTENT_CONFLICT")
            self._require_candidate_fence(execution_id, fence)
            if existing is not None:
                return existing
            self._record_candidate_commit_closure(
                closure_id, execution, binding, approval_id, evaluation_id, result_commit, fence
            )
        return self.connection.execute("SELECT * FROM candidate_commit_closure WHERE closure_id=?", (closure_id,)).fetchone()

    def _record_candidate_commit_closure(
        self, closure_id: str, execution: sqlite3.Row, binding: sqlite3.Row,
        approval_id: str, evaluation_id: str, result_commit: str, fence: CandidateWriteFence,
    ) -> None:
        """Post-Git durable boundary; a process-crash test is injected here."""
        now = timestamp(self._now())
        execution_id = execution["execution_id"]
        candidate_id = binding["candidate_id"]
        self.connection.execute(
            """INSERT INTO candidate_commit_closure(closure_id,execution_id,candidate_id,approval_id,
               evaluation_id,result_commit,expected_parent,candidate_content_sha256,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (closure_id,execution_id,candidate_id,approval_id,evaluation_id,result_commit,
             binding["expected_parent"],binding["candidate_content_sha256"],now),
        )
        consumed = self.connection.execute(
            "UPDATE approval_request SET consumed_at=? WHERE approval_id=? AND consumed_at IS NULL AND status='APPROVED'", (now,approval_id)
        )
        if consumed.rowcount != 1:
            raise StoreError("APPROVAL_ALREADY_CONSUMED")
        updated = self.connection.execute(
            """UPDATE slice_execution SET result_commit=?,state='VERIFYING',resume_state=NULL,
               state_version=state_version+1,current_actor_role='CONTROLLER',updated_at=?
               WHERE execution_id=? AND result_commit IS NULL AND state='WAITING_APPROVAL' AND state_version=?""",
            (result_commit,now,execution_id,execution["state_version"]),
        )
        if updated.rowcount != 1:
            raise StoreError("STALE_STATE_VERSION")
        payload = canonical_json({"candidate_id":candidate_id,"evaluation_id":evaluation_id,
            "approval_id":approval_id,"result_commit":result_commit,"closure_id":closure_id})
        self._insert_event(execution_id=execution_id,operation_key=canonical_sha256({"closure_id":closure_id}),
            event_type="STATE_TRANSITION",from_state="WAITING_APPROVAL",to_state="VERIFYING",
            from_version=execution["state_version"],to_version=execution["state_version"]+1,
            actor_role=ActorRole.CONTROLLER,actor_id=fence.lease_owner,lease_generation=fence.lease_generation,
            reason_code="PRECOMMIT_COMMIT_CLOSED",reason_detail=None,metadata_json=payload,created_at=now)

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise StoreError("INVALID_TIMESTAMP", "clock must return an aware datetime")
        return value.astimezone(timezone.utc)

    def _begin_unchecked(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def _begin(self) -> None:
        if not self.global_writer_guard_required:
            self._begin_unchecked()
            return
        authority = self._ordinary_global_writer_authority.get()
        if authority is None:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_REQUIRED")
        self._begin_unchecked()
        try:
            row = self.get_global_production_writer_lease()
            self._require_current_global_writer(row, authority[0], authority[1], self._now())
        except BaseException:
            self._rollback()
            raise

    @contextmanager
    def ordinary_global_writer_authority(
        self, owner_id: str, fencing_token: int
    ) -> Iterator[None]:
        """Bind current GLOBAL_PRODUCTION authority for ordinary ControlStore writes.

        Global Writer self-primitives deliberately bypass this binding: acquisition,
        assertion, heartbeat, release and force-revoke must remain non-recursive.
        """
        if self._ordinary_global_writer_authority.get() is not None:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_NESTED_AUTHORITY_FORBIDDEN")
        self.assert_current_global_writer(owner_id, fencing_token)
        token = self._ordinary_global_writer_authority.set((owner_id, fencing_token))
        try:
            yield
        finally:
            self._ordinary_global_writer_authority.reset(token)

    def _rollback(self) -> None:
        if self.connection.in_transaction:
            self.connection.execute("ROLLBACK")

    def get_execution(self, execution_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM slice_execution WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if row is None:
            raise StoreError("EXECUTION_NOT_FOUND", execution_id)
        return row

    def events(self, execution_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM transition_event WHERE execution_id = ? ORDER BY event_seq",
                (execution_id,),
            )
        )

    def get_slice_control_state(self, slice_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM slice_control_state WHERE slice_id = ?", (slice_id,)
        ).fetchone()
        if row is None:
            raise StoreError("SLICE_CONTROL_STATE_NOT_FOUND", slice_id)
        return row

    def slice_control_states(self) -> list[sqlite3.Row]:
        return list(self.connection.execute("SELECT * FROM slice_control_state ORDER BY slice_id"))

    def slice_control_events(self, slice_id: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM slice_control_event WHERE slice_id = ? ORDER BY event_seq",
                (slice_id,),
            )
        )

    def get_control_authority_state(self) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM control_authority_state WHERE singleton_id = 'GLOBAL'"
        ).fetchone()
        if row is None:
            raise StoreError("AUTHORITY_SINGLETON_MISSING")
        return row

    def authority_transition_events(self) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM authority_transition_event ORDER BY event_seq"
            )
        )

    def _begin_global_writer(self) -> None:
        try:
            self._begin_unchecked()
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error

    def _global_writer_timestamp(self, value: Any, field: str) -> float:
        if not isinstance(value, str):
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        try:
            row = self.connection.execute(
                """SELECT julianday(?)
                     WHERE length(?) > 0
                       AND julianday(?) IS NOT NULL
                       AND substr(?, -6) = '+00:00'""",
                (value, value, value, value),
            ).fetchone()
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        if row is None:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        # This deliberately mirrors the Schema v6 CHECK language and its time
        # comparison precision. Generic datetime.fromisoformat() accepts a
        # strictly wider language (for example basic ISO and comma fractions).
        return float(row[0])

    def _validate_global_writer_row(self, row: sqlite3.Row) -> sqlite3.Row:
        if row["resource_key"] != GLOBAL_PRODUCTION_RESOURCE_KEY:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "resource_key")
        if row["state"] not in {"FREE", "HELD"}:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "state")
        token = row["fencing_token"]
        if not isinstance(token, int) or token < 0:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "fencing_token")
        updated = self._global_writer_timestamp(row["updated_at"], "updated_at")

        if row["state"] == "FREE":
            for field in (*GLOBAL_WRITER_CONTEXT_FIELDS, "acquired_at", "expires_at", "heartbeat_at"):
                if row[field] is not None:
                    raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
            return row

        for field in GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS:
            if not isinstance(row[field], str) or not row[field]:
                raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        for field in GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS:
            if row[field] is not None and (not isinstance(row[field], str) or not row[field]):
                raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", field)
        acquired = self._global_writer_timestamp(row["acquired_at"], "acquired_at")
        expires = self._global_writer_timestamp(row["expires_at"], "expires_at")
        heartbeat = self._global_writer_timestamp(row["heartbeat_at"], "heartbeat_at")
        if not (acquired <= heartbeat == updated < expires):
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "lease timestamps")
        return row

    def get_global_production_writer_lease(self) -> sqlite3.Row:
        try:
            row = self.connection.execute(
                "SELECT * FROM global_production_writer_lease WHERE resource_key = ?",
                (GLOBAL_PRODUCTION_RESOURCE_KEY,),
            ).fetchone()
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        if row is None:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_STATE_INVALID", "singleton missing")
        return self._validate_global_writer_row(row)

    def global_production_writer_events(self) -> list[sqlite3.Row]:
        try:
            return list(
                self.connection.execute(
                    "SELECT * FROM global_production_writer_event ORDER BY event_seq"
                )
            )
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error

    def typed_postgres_operation_receipt_events(self, operation_id: str) -> list[sqlite3.Row]:
        """Return append-only typed PostgreSQL receipt events for one operation."""

        if not isinstance(operation_id, str) or not operation_id:
            raise StoreError("INVALID_INPUT", "operation_id")
        try:
            return list(
                self.connection.execute(
                    """SELECT * FROM typed_postgres_operation_receipt_event
                         WHERE operation_id = ? ORDER BY event_seq""",
                    (operation_id,),
                )
            )
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error

    def get_typed_postgres_operation_receipt_event(
        self, operation_id: str, receipt_phase: str
    ) -> sqlite3.Row | None:
        if not isinstance(operation_id, str) or not operation_id:
            raise StoreError("INVALID_INPUT", "operation_id")
        if receipt_phase not in {"PREPARED", "FINAL"}:
            raise StoreError("INVALID_INPUT", "receipt_phase")
        try:
            return self.connection.execute(
                """SELECT * FROM typed_postgres_operation_receipt_event
                     WHERE operation_id = ? AND receipt_phase = ?""",
                (operation_id, receipt_phase),
            ).fetchone()
        except sqlite3.Error as error:
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error

    def typed_postgres_operation_receipt_state(
        self, operation_id: str, request_fingerprint: str
    ) -> dict[str, Any]:
        """Classify ABSENT/PREPARED_ONLY/FINAL and reject fingerprint conflicts."""

        require_sha256(request_fingerprint, "request_fingerprint")
        rows = self.typed_postgres_operation_receipt_events(operation_id)
        if not rows:
            return {"state": "ABSENT", "prepared": None, "final": None}
        if any(row["request_fingerprint"] != request_fingerprint for row in rows):
            raise StoreError("TYPED_POSTGRES_OPERATION_REQUEST_CONFLICT", operation_id)
        prepared = next((row for row in rows if row["receipt_phase"] == "PREPARED"), None)
        final = next((row for row in rows if row["receipt_phase"] == "FINAL"), None)
        if prepared is None:
            raise StoreError("TYPED_POSTGRES_RECEIPT_STATE_INVALID", "PREPARED missing")
        return {
            "state": "FINAL" if final is not None else "PREPARED_ONLY",
            "prepared": prepared,
            "final": final,
        }

    def append_typed_postgres_operation_receipt_event(
        self,
        *,
        receipt_version: int,
        change_id: str,
        control_decision_ref: str,
        deployment_id: str,
        operation_id: str,
        operation_type: str,
        receipt_phase: str,
        target_service: str,
        target_database: str | None,
        principal_identity: str | None,
        credential_reference: str | None,
        artifact_path: str | None,
        artifact_sha256: str | None,
        request_fingerprint: str,
        before_state_fingerprint: str,
        after_state_fingerprint: str | None,
        effect_status: str,
        w08_fencing_token: int,
        created_at: str,
    ) -> sqlite3.Row:
        """Append one W08-bound typed PostgreSQL receipt and acknowledge exact durability.

        Success means INSERT transaction COMMIT completed and a post-COMMIT exact
        readback matched every supplied semantic field.  This method never updates
        or deletes prior receipt facts.
        """

        required_strings = {
            "change_id": change_id,
            "control_decision_ref": control_decision_ref,
            "deployment_id": deployment_id,
            "operation_id": operation_id,
            "operation_type": operation_type,
            "target_service": target_service,
            "created_at": created_at,
        }
        if receipt_version != 1:
            raise StoreError("INVALID_INPUT", "receipt_version")
        for field, value in required_strings.items():
            if not isinstance(value, str) or not value:
                raise StoreError("INVALID_INPUT", field)
        if receipt_phase not in {"PREPARED", "FINAL"}:
            raise StoreError("INVALID_INPUT", "receipt_phase")
        if effect_status not in {"PENDING", "APPLIED", "NOOP_EXACT"}:
            raise StoreError("INVALID_INPUT", "effect_status")
        if receipt_phase == "PREPARED" and (effect_status != "PENDING" or after_state_fingerprint is not None):
            raise StoreError("INVALID_INPUT", "prepared receipt shape")
        if receipt_phase == "FINAL" and (effect_status not in {"APPLIED", "NOOP_EXACT"} or after_state_fingerprint is None):
            raise StoreError("INVALID_INPUT", "final receipt shape")
        require_sha256(request_fingerprint, "request_fingerprint")
        require_sha256(before_state_fingerprint, "before_state_fingerprint")
        if after_state_fingerprint is not None:
            require_sha256(after_state_fingerprint, "after_state_fingerprint")
        if artifact_sha256 is not None:
            require_sha256(artifact_sha256, "artifact_sha256")
        for field, value in {
            "target_database": target_database,
            "principal_identity": principal_identity,
            "credential_reference": credential_reference,
            "artifact_path": artifact_path,
        }.items():
            if value is not None and (not isinstance(value, str) or not value):
                raise StoreError("INVALID_INPUT", field)
        if not isinstance(w08_fencing_token, int) or w08_fencing_token <= 0:
            raise StoreError("INVALID_INPUT", "w08_fencing_token")

        authority = self._ordinary_global_writer_authority.get()
        if authority is None:
            raise StoreError("TYPED_POSTGRES_W08_RECEIPT_AUTHORITY_REQUIRED")
        owner_id, bound_token = authority
        if bound_token != w08_fencing_token:
            raise StoreError("TYPED_POSTGRES_W08_RECEIPT_FENCING_MISMATCH")
        lease = self.assert_current_global_writer(owner_id, bound_token)
        if lease["writer_class"] != "W08_CONTROLLED_PRODUCTION_DEPLOYMENT":
            raise StoreError("TYPED_POSTGRES_W08_RECEIPT_WRITER_CLASS_INVALID")
        if lease["change_id"] != change_id or lease["slice_id"] != deployment_id:
            raise StoreError("TYPED_POSTGRES_W08_RECEIPT_CONTEXT_MISMATCH")
        acquire = self.connection.execute(
            """SELECT * FROM global_production_writer_event
                 WHERE event_type IN ('ACQUIRE','EXPIRED_TAKEOVER')
                   AND new_owner_id = ? AND to_fencing_token = ?
                 ORDER BY event_seq DESC LIMIT 1""",
            (owner_id, bound_token),
        ).fetchone()
        if acquire is None or acquire["control_decision_ref"] != control_decision_ref:
            raise StoreError("TYPED_POSTGRES_CONTROL_DECISION_BINDING_MISMATCH")

        semantic_fields = (
            "receipt_version", "change_id", "control_decision_ref", "deployment_id",
            "operation_id", "operation_type", "receipt_phase", "target_service",
            "target_database", "principal_identity", "credential_reference", "artifact_path",
            "artifact_sha256", "request_fingerprint", "before_state_fingerprint",
            "after_state_fingerprint", "effect_status", "w08_fencing_token", "created_at",
        )
        values = (
            receipt_version, change_id, control_decision_ref, deployment_id,
            operation_id, operation_type, receipt_phase, target_service,
            target_database, principal_identity, credential_reference, artifact_path,
            artifact_sha256, request_fingerprint, before_state_fingerprint,
            after_state_fingerprint, effect_status, w08_fencing_token, created_at,
        )
        receipt_id = str(uuid4())
        self._begin()
        try:
            self.connection.execute(
                """INSERT INTO typed_postgres_operation_receipt_event(
                    receipt_id, receipt_version, change_id, control_decision_ref,
                    deployment_id, operation_id, operation_type, receipt_phase,
                    target_service, target_database, principal_identity, credential_reference,
                    artifact_path, artifact_sha256, request_fingerprint,
                    before_state_fingerprint, after_state_fingerprint, effect_status,
                    w08_fencing_token, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (receipt_id, *values),
            )
            self.connection.execute("COMMIT")
        except StoreError:
            self._rollback()
            raise
        except sqlite3.IntegrityError as error:
            self._rollback()
            raise StoreError("TYPED_POSTGRES_RECEIPT_CONFLICT", type(error).__name__) from error
        except sqlite3.Error as error:
            self._rollback()
            raise StoreError("CONTROL_STORE_ERROR", type(error).__name__) from error
        except BaseException:
            self._rollback()
            raise

        # Durability acknowledgement is not the COMMIT call alone.  Read the exact
        # row after COMMIT and verify identity/fingerprint plus every sanitized fact.
        row = self.get_typed_postgres_operation_receipt_event(operation_id, receipt_phase)
        if row is None or row["receipt_id"] != receipt_id:
            raise StoreError("TYPED_POSTGRES_RECEIPT_DURABILITY_ACK_FAILED", "identity")
        if tuple(row[field] for field in semantic_fields) != values:
            raise StoreError("TYPED_POSTGRES_RECEIPT_DURABILITY_ACK_FAILED", "readback")
        return row

    def _global_writer_context_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {field: row[field] for field in GLOBAL_WRITER_CONTEXT_FIELDS}

    def _validate_global_writer_context(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if set(context) != set(GLOBAL_WRITER_CONTEXT_FIELDS):
            raise StoreError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", "shape")
        normalized = dict(context)
        for field in GLOBAL_WRITER_REQUIRED_CONTEXT_FIELDS:
            if not isinstance(normalized[field], str) or not normalized[field]:
                raise StoreError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", field)
        for field in GLOBAL_WRITER_OPTIONAL_CONTEXT_FIELDS:
            value = normalized[field]
            if value is not None and (not isinstance(value, str) or not value):
                raise StoreError("GLOBAL_PRODUCTION_WRITER_CONTEXT_INVALID", field)
        return normalized

    def _existing_global_writer_event(
        self,
        operation_key: str,
        allowed_event_types: set[str],
        request_json: str,
    ) -> sqlite3.Row | None:
        row = self.connection.execute(
            "SELECT * FROM global_production_writer_event WHERE operation_key = ?",
            (operation_key,),
        ).fetchone()
        if row is None:
            return None
        if row["event_type"] not in allowed_event_types or row["request_json"] != request_json:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_IDEMPOTENCY_CONFLICT")
        return row

    def _insert_global_writer_event(
        self,
        *,
        operation_key: str,
        event_type: str,
        from_fencing_token: int,
        to_fencing_token: int,
        prior_context: Mapping[str, Any] | None,
        new_context: Mapping[str, Any] | None,
        reason: str,
        control_decision_ref: str | None,
        request_json: str,
        created_at: str,
    ) -> None:
        prior = {field: None for field in GLOBAL_WRITER_CONTEXT_FIELDS}
        current = {field: None for field in GLOBAL_WRITER_CONTEXT_FIELDS}
        if prior_context is not None:
            prior.update(prior_context)
        if new_context is not None:
            current.update(new_context)
        self.connection.execute(
            """INSERT INTO global_production_writer_event(
                event_id, operation_key, resource_key, event_type,
                from_fencing_token, to_fencing_token,
                prior_owner_id, prior_owner_execution_id, prior_change_id, prior_slice_id,
                prior_writer_class, prior_owner_session_role, prior_track,
                prior_repository_or_runtime, prior_operation_class, prior_target,
                new_owner_id, new_owner_execution_id, new_change_id, new_slice_id,
                new_writer_class, new_owner_session_role, new_track,
                new_repository_or_runtime, new_operation_class, new_target,
                reason, control_decision_ref, request_json, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )""",
            (
                str(uuid4()), operation_key, GLOBAL_PRODUCTION_RESOURCE_KEY, event_type,
                from_fencing_token, to_fencing_token,
                prior["owner_id"], prior["owner_execution_id"], prior["change_id"],
                prior["slice_id"], prior["writer_class"], prior["owner_session_role"],
                prior["track"], prior["repository_or_runtime"], prior["operation_class"],
                prior["target"], current["owner_id"], current["owner_execution_id"],
                current["change_id"], current["slice_id"], current["writer_class"],
                current["owner_session_role"], current["track"],
                current["repository_or_runtime"], current["operation_class"], current["target"],
                reason, control_decision_ref, request_json, created_at,
            ),
        )

    def _require_current_global_writer(
        self,
        row: sqlite3.Row,
        owner_id: str,
        fencing_token: int,
        now: datetime,
    ) -> sqlite3.Row:
        if row["fencing_token"] != fencing_token:
            raise StoreError("STALE_FENCING_TOKEN")
        if row["state"] != "HELD":
            raise StoreError("GLOBAL_PRODUCTION_WRITER_NOT_HELD")
        if row["owner_id"] != owner_id:
            raise StoreError("GLOBAL_PRODUCTION_WRITER_OWNER_MISMATCH")
        if self._global_writer_timestamp(
            row["expires_at"], "expires_at"
        ) <= self._global_writer_timestamp(timestamp(now), "current_time"):
            raise StoreError("GLOBAL_PRODUCTION_WRITER_LEASE_EXPIRED")
        return row

    def assert_current_global_writer(
        self,
        owner_id: str,
        fencing_token: int,
    ) -> sqlite3.Row:
        """Revalidate DCS serialization authority, not target-native fencing.

        01B integrations must keep the lease held with heartbeat healthy, invoke this
        immediately before each irreversible external Production call, and must not place
        unbounded/blocking work between this guard and that call. Notion, Google Calendar,
        launchctl, and other external targets do not consume this fencing token, so a
        residual TOCTOU window remains.
        """
        if not isinstance(owner_id, str) or not owner_id:
            raise StoreError("INVALID_INPUT", "owner_id is required")
        if not isinstance(fencing_token, int) or fencing_token < 0:
            raise StoreError("INVALID_INPUT", "fencing_token")
        row = self.get_global_production_writer_lease()
        return self._require_current_global_writer(row, owner_id, fencing_token, self._now())

    def acquire_global_production_writer(
        self,
        *,
        operation_key: str,
        owner_id: str,
        change_id: str,
        writer_class: str,
        owner_session_role: str,
        track: str,
        repository_or_runtime: str,
        operation_class: str,
        target: str,
        owner_execution_id: str | None = None,
        slice_id: str | None = None,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        control_decision_ref: str | None = None,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise StoreError("INVALID_LEASE_TTL")
        if control_decision_ref is not None and (
            not isinstance(control_decision_ref, str) or not control_decision_ref
        ):
            raise StoreError("INVALID_INPUT", "control_decision_ref")
        context = self._validate_global_writer_context(
            {
                "owner_id": owner_id,
                "owner_execution_id": owner_execution_id,
                "change_id": change_id,
                "slice_id": slice_id,
                "writer_class": writer_class,
                "owner_session_role": owner_session_role,
                "track": track,
                "repository_or_runtime": repository_or_runtime,
                "operation_class": operation_class,
                "target": target,
            }
        )
        request_json = canonical_json(
            {
                "context": context,
                "ttl_seconds": ttl_seconds,
                "control_decision_ref": control_decision_ref,
            }
        )
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin_global_writer()
        try:
            existing = self._existing_global_writer_event(
                operation_key, {"ACQUIRE", "EXPIRED_TAKEOVER"}, request_json
            )
            if existing is not None:
                current = self.get_global_production_writer_lease()
                if (
                    current["state"] != "HELD"
                    or current["fencing_token"] != existing["to_fencing_token"]
                    or self._global_writer_context_from_row(current) != context
                ):
                    raise StoreError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return self.assert_current_global_writer(owner_id, current["fencing_token"])

            prior = self.get_global_production_writer_lease()
            prior_context = (
                self._global_writer_context_from_row(prior) if prior["state"] == "HELD" else None
            )
            if prior["state"] == "HELD":
                prior_expiry = self._global_writer_timestamp(prior["expires_at"], "expires_at")
                if prior_expiry > self._global_writer_timestamp(now, "current_time"):
                    raise StoreError("GLOBAL_PRODUCTION_WRITER_HELD")
                event_type = "EXPIRED_TAKEOVER"
                reason = "GLOBAL_PRODUCTION_WRITER_EXPIRED_TAKEOVER"
            else:
                event_type = "ACQUIRE"
                reason = "GLOBAL_PRODUCTION_WRITER_ACQUIRED"
            new_token = prior["fencing_token"] + 1
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state = 'HELD', owner_id = ?, owner_execution_id = ?,
                          change_id = ?, slice_id = ?, writer_class = ?, owner_session_role = ?,
                          track = ?, repository_or_runtime = ?, operation_class = ?, target = ?,
                          fencing_token = ?, acquired_at = ?, expires_at = ?, heartbeat_at = ?,
                          updated_at = ?
                    WHERE resource_key = ? AND fencing_token = ?""",
                (
                    context["owner_id"], context["owner_execution_id"], context["change_id"],
                    context["slice_id"], context["writer_class"], context["owner_session_role"],
                    context["track"], context["repository_or_runtime"], context["operation_class"],
                    context["target"], new_token, now, expires, now, now,
                    GLOBAL_PRODUCTION_RESOURCE_KEY, prior["fencing_token"],
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("CONTROL_STORE_ERROR", "global writer singleton update lost")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_global_writer_event(
                operation_key=operation_key,
                event_type=event_type,
                from_fencing_token=prior["fencing_token"],
                to_fencing_token=new_token,
                prior_context=prior_context,
                new_context=context,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except StoreError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise

        current = self.assert_current_global_writer(owner_id, new_token)
        if self._global_writer_context_from_row(current) != context:
            raise StoreError("CONTROL_STORE_ERROR", "global writer readback mismatch")
        return current

    def heartbeat_global_production_writer(
        self,
        owner_id: str,
        fencing_token: int,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    ) -> sqlite3.Row:
        if not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise StoreError("INVALID_LEASE_TTL")
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin_global_writer()
        try:
            row = self.get_global_production_writer_lease()
            self._require_current_global_writer(row, owner_id, fencing_token, now_value)
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET expires_at = ?, heartbeat_at = ?, updated_at = ?
                    WHERE resource_key = ? AND state = 'HELD' AND owner_id = ?
                      AND fencing_token = ? AND expires_at > ?""",
                (
                    expires, now, now, GLOBAL_PRODUCTION_RESOURCE_KEY,
                    owner_id, fencing_token, now,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_FENCING_TOKEN")
            self.connection.execute("COMMIT")
        except StoreError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        return self.assert_current_global_writer(owner_id, fencing_token)

    def release_global_production_writer(
        self,
        *,
        operation_key: str,
        owner_id: str,
        fencing_token: int,
        reason: str = "GLOBAL_PRODUCTION_WRITER_RELEASED",
        control_decision_ref: str | None = None,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if not isinstance(reason, str) or not reason:
            raise StoreError("INVALID_INPUT", "reason")
        if control_decision_ref is not None and (
            not isinstance(control_decision_ref, str) or not control_decision_ref
        ):
            raise StoreError("INVALID_INPUT", "control_decision_ref")
        if not isinstance(fencing_token, int) or fencing_token < 0:
            raise StoreError("INVALID_INPUT", "fencing_token")
        request_json = canonical_json(
            {
                "owner_id": owner_id,
                "fencing_token": fencing_token,
                "reason": reason,
                "control_decision_ref": control_decision_ref,
            }
        )
        now_value = self._now()
        now = timestamp(now_value)
        self._begin_global_writer()
        try:
            existing = self._existing_global_writer_event(operation_key, {"RELEASE"}, request_json)
            if existing is not None:
                current = self.get_global_production_writer_lease()
                if current["state"] != "FREE" or current["fencing_token"] != existing["to_fencing_token"]:
                    raise StoreError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return current

            prior = self.get_global_production_writer_lease()
            self._require_current_global_writer(prior, owner_id, fencing_token, now_value)
            prior_context = self._global_writer_context_from_row(prior)
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state = 'FREE', owner_id = NULL, owner_execution_id = NULL,
                          change_id = NULL, slice_id = NULL, writer_class = NULL,
                          owner_session_role = NULL, track = NULL, repository_or_runtime = NULL,
                          operation_class = NULL, target = NULL, acquired_at = NULL,
                          expires_at = NULL, heartbeat_at = NULL, updated_at = ?
                    WHERE resource_key = ? AND state = 'HELD' AND owner_id = ?
                      AND fencing_token = ? AND expires_at > ?""",
                (now, GLOBAL_PRODUCTION_RESOURCE_KEY, owner_id, fencing_token, now),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_FENCING_TOKEN")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_global_writer_event(
                operation_key=operation_key,
                event_type="RELEASE",
                from_fencing_token=fencing_token,
                to_fencing_token=fencing_token,
                prior_context=prior_context,
                new_context=None,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except StoreError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        current = self.get_global_production_writer_lease()
        if current["state"] != "FREE" or current["fencing_token"] != fencing_token:
            raise StoreError("CONTROL_STORE_ERROR", "global writer release readback mismatch")
        return current

    def force_revoke_global_production_writer(
        self,
        *,
        operation_key: str,
        reason: str,
        control_decision_ref: str,
        expected_owner_id: str,
        expected_fencing_token: int,
        _fault_injector: Callable[[str], None] | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        for field, value in (
            ("reason", reason),
            ("control_decision_ref", control_decision_ref),
            ("expected_owner_id", expected_owner_id),
        ):
            if not isinstance(value, str) or not value:
                raise StoreError("INVALID_INPUT", field)
        if not isinstance(expected_fencing_token, int) or expected_fencing_token < 0:
            raise StoreError("INVALID_INPUT", "expected_fencing_token")
        request_json = canonical_json(
            {
                "reason": reason,
                "control_decision_ref": control_decision_ref,
                "expected_owner_id": expected_owner_id,
                "expected_fencing_token": expected_fencing_token,
            }
        )
        now_value = self._now()
        now = timestamp(now_value)
        self._begin_global_writer()
        try:
            existing = self._existing_global_writer_event(
                operation_key, {"FORCE_REVOKE"}, request_json
            )
            if existing is not None:
                current = self.get_global_production_writer_lease()
                if current["state"] != "FREE" or current["fencing_token"] != existing["to_fencing_token"]:
                    raise StoreError("GLOBAL_PRODUCTION_WRITER_OPERATION_REPLAY_STALE")
                self.connection.execute("COMMIT")
                return current

            prior = self.get_global_production_writer_lease()
            self._require_current_global_writer(
                prior, expected_owner_id, expected_fencing_token, now_value
            )
            prior_context = self._global_writer_context_from_row(prior)
            new_token = expected_fencing_token + 1
            updated = self.connection.execute(
                """UPDATE global_production_writer_lease
                      SET state = 'FREE', owner_id = NULL, owner_execution_id = NULL,
                          change_id = NULL, slice_id = NULL, writer_class = NULL,
                          owner_session_role = NULL, track = NULL, repository_or_runtime = NULL,
                          operation_class = NULL, target = NULL, fencing_token = ?,
                          acquired_at = NULL, expires_at = NULL, heartbeat_at = NULL, updated_at = ?
                    WHERE resource_key = ? AND state = 'HELD' AND owner_id = ?
                      AND fencing_token = ? AND expires_at > ?""",
                (
                    new_token, now, GLOBAL_PRODUCTION_RESOURCE_KEY,
                    expected_owner_id, expected_fencing_token, now,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("GLOBAL_PRODUCTION_WRITER_FORCE_REVOKE_MISMATCH")
            if _fault_injector is not None:
                _fault_injector("after_state_update")
            self._insert_global_writer_event(
                operation_key=operation_key,
                event_type="FORCE_REVOKE",
                from_fencing_token=expected_fencing_token,
                to_fencing_token=new_token,
                prior_context=prior_context,
                new_context=None,
                reason=reason,
                control_decision_ref=control_decision_ref,
                request_json=request_json,
                created_at=now,
            )
            if _fault_injector is not None:
                _fault_injector("after_event_insert")
            self.connection.execute("COMMIT")
        except StoreError:
            self._rollback()
            raise
        except sqlite3.Error as error:
            self._rollback()
            raise StoreError("CONTROL_STORE_ERROR", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        current = self.get_global_production_writer_lease()
        if current["state"] != "FREE" or current["fencing_token"] != new_token:
            raise StoreError("CONTROL_STORE_ERROR", "global writer revoke readback mismatch")
        return current

    def _validate_slice_control_target(self, target: Mapping[str, Any]) -> dict[str, Any]:
        if set(target) != set(CONTROL_STATE_INPUT_FIELDS):
            raise StoreError("SLICE_CONTROL_STATE_SHAPE_INVALID")
        value = {field: target[field] for field in CONTROL_STATE_INPUT_FIELDS}
        for field in ("slice_id", "stage", "status", "logical_source_root"):
            if not isinstance(value[field], str) or not value[field]:
                raise StoreError("SLICE_CONTROL_STATE_FIELD_REQUIRED", field)
        for field in ("repository_toplevel", "branch", "defer_reason", "active_execution_id"):
            if value[field] is not None and (
                not isinstance(value[field], str) or not value[field]
            ):
                raise StoreError("SLICE_CONTROL_STATE_FIELD_INVALID", field)
        for field in ("base_commit", "implementation_result_commit", "current_branch_head"):
            if value[field] is not None:
                require_commit(value[field], field)
        require_sha256(value["authority_fingerprint"], "authority_fingerprint")
        if value["authority_fingerprint"] != control_state_authority_fingerprint(value):
            raise StoreError("CONTROL_AUTHORITY_FINGERPRINT_MISMATCH")

        disposition = (value["migration_class"], value["execution_eligibility"])
        if disposition in {
            ("MIGRATE_AS_READY_CURRENT_STATE", "ELIGIBLE_BOUND"),
            ("DEFER_BINDING", "ELIGIBLE_BOUND"),
        }:
            if value["defer_reason"] is not None:
                raise StoreError("EXECUTABLE_SLICE_DEFER_REASON_FORBIDDEN")
            for field in (
                "repository_toplevel",
                "branch",
                "base_commit",
                "implementation_result_commit",
                "current_branch_head",
                "active_execution_id",
            ):
                if value[field] is None:
                    raise StoreError("EXECUTABLE_SLICE_BINDING_REQUIRED", field)
            if (
                disposition == ("DEFER_BINDING", "ELIGIBLE_BOUND")
                and value["current_branch_head"]
                != value["implementation_result_commit"]
            ):
                raise StoreError("BOUND_RESULT_HEAD_MISMATCH")
        elif disposition == ("DEFER_BINDING", "ELIGIBLE_PREEXECUTION_BOUND"):
            if value["defer_reason"] is not None:
                raise StoreError("EXECUTABLE_SLICE_DEFER_REASON_FORBIDDEN")
            for field in (
                "repository_toplevel",
                "branch",
                "base_commit",
                "current_branch_head",
                "active_execution_id",
            ):
                if value[field] is None:
                    raise StoreError("PREEXECUTION_BINDING_REQUIRED", field)
            if value["implementation_result_commit"] is not None:
                raise StoreError("PREEXECUTION_RESULT_COMMIT_FORBIDDEN")
            if value["current_branch_head"] != value["base_commit"]:
                raise StoreError("PREEXECUTION_HEAD_MISMATCH")
        elif disposition in {
            ("DEFER_BINDING", "INELIGIBLE_UNTIL_PREFLIGHT"),
            ("DEFER_PREREQUISITE", "INELIGIBLE_UNTIL_PREREQUISITE"),
        }:
            if value["defer_reason"] is None:
                raise StoreError("DEFER_REASON_REQUIRED")
            for field in (
                "base_commit",
                "implementation_result_commit",
                "current_branch_head",
                "active_execution_id",
            ):
                if value[field] is not None:
                    raise StoreError("DEFERRED_EXECUTION_FORBIDDEN", field)
        else:
            raise StoreError("SLICE_CONTROL_DISPOSITION_INVALID")
        return value

    def reconcile_slice_control_state(
        self,
        target: Mapping[str, Any],
        expected_state_version: int,
        operation_key: str,
        *,
        reason_code: str,
        metadata: Mapping[str, Any] | None = None,
        required_authority_mode: str | None = None,
        expected_authority_generation: int | None = None,
        insert_only: bool = False,
    ) -> tuple[sqlite3.Row, bool]:
        """CAS reconcile one Slice row and append exactly one immutable event."""

        value = self._validate_slice_control_target(target)
        require_sha256(operation_key, "operation_key")
        if not isinstance(expected_state_version, int) or expected_state_version < -1:
            raise StoreError("INVALID_EXPECTED_STATE_VERSION")
        if not isinstance(reason_code, str) or not reason_code:
            raise StoreError("REASON_CODE_REQUIRED")
        event_payload = canonical_json(
            {"reason_code": reason_code, "target": value, "metadata": dict(metadata or {})}
        )
        now = timestamp(self._now())
        self._begin()
        try:
            if required_authority_mode is not None:
                authority = self.get_control_authority_state()
                if authority["mode"] != required_authority_mode:
                    raise StoreError("CONTROL_AUTHORITY_MODE_REQUIRED")
                if authority["authority_generation"] != expected_authority_generation:
                    raise StoreError("STALE_AUTHORITY_GENERATION")

            replay = self.connection.execute(
                "SELECT * FROM slice_control_event WHERE operation_key = ?", (operation_key,)
            ).fetchone()
            if replay is not None:
                if replay["slice_id"] != value["slice_id"] or replay["metadata_json"] != event_payload:
                    raise StoreError(
                        "SLICE_REGISTRATION_IDEMPOTENCY_CONFLICT"
                        if insert_only
                        else "IDEMPOTENCY_CONFLICT"
                    )
                row = self.get_slice_control_state(value["slice_id"])
                if not all(row[field] == value[field] for field in CONTROL_STATE_INPUT_FIELDS):
                    raise StoreError(
                        "SLICE_REGISTRATION_IDEMPOTENCY_CONFLICT"
                        if insert_only
                        else "IDEMPOTENCY_CONFLICT"
                    )
                self.connection.execute("COMMIT")
                return row, True

            current = self.connection.execute(
                "SELECT * FROM slice_control_state WHERE slice_id = ?", (value["slice_id"],)
            ).fetchone()
            if current is not None and all(current[field] == value[field] for field in CONTROL_STATE_INPUT_FIELDS):
                if insert_only:
                    raise StoreError("SLICE_ALREADY_REGISTERED_CONFLICT")
                self.connection.execute("COMMIT")
                return current, True

            if current is not None and insert_only:
                raise StoreError("SLICE_ALREADY_REGISTERED_CONFLICT")

            if current is None:
                if expected_state_version != -1:
                    raise StoreError("STALE_CONTROL_STATE_VERSION")
                from_version = -1
                to_version = 0
            else:
                if current["state_version"] != expected_state_version:
                    raise StoreError("STALE_CONTROL_STATE_VERSION")
                if (
                    current["active_execution_id"] is not None
                    and value["active_execution_id"] != current["active_execution_id"]
                ):
                    raise StoreError("ACTIVE_EXECUTION_REBIND_FORBIDDEN")
                from_version = expected_state_version
                to_version = expected_state_version + 1

            self.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    operation_key,
                    value["slice_id"],
                    from_version,
                    to_version,
                    reason_code,
                    event_payload,
                    now,
                ),
            )

            if current is None:
                columns = ", ".join(CONTROL_STATE_INPUT_FIELDS)
                placeholders = ", ".join("?" for _ in CONTROL_STATE_INPUT_FIELDS)
                self.connection.execute(
                    f"INSERT INTO slice_control_state({columns}, state_version, created_at, updated_at) "
                    f"VALUES ({placeholders}, 0, ?, ?)",
                    (*[value[field] for field in CONTROL_STATE_INPUT_FIELDS], now, now),
                )
            else:
                mutable_fields = tuple(
                    field for field in CONTROL_STATE_INPUT_FIELDS if field != "slice_id"
                )
                assignments = ", ".join(f"{field} = ?" for field in mutable_fields)
                updated = self.connection.execute(
                    f"UPDATE slice_control_state SET {assignments}, "
                    "state_version = state_version + 1, updated_at = ? "
                    "WHERE slice_id = ? AND state_version = ?",
                    (
                        *[value[field] for field in mutable_fields],
                        now,
                        value["slice_id"],
                        expected_state_version,
                    ),
                )
                if updated.rowcount != 1:
                    raise StoreError("STALE_CONTROL_STATE_VERSION")
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_slice_control_state(value["slice_id"]), False

    def reconcile_transitional_authority(
        self,
        expected_generation: int,
        slice_snapshot_fingerprint: str,
        rollback_snapshot_fingerprint: str,
    ) -> tuple[sqlite3.Row, bool]:
        """CAS-update only E1 snapshot material; authority mode cannot change here."""

        require_sha256(slice_snapshot_fingerprint, "slice_snapshot_fingerprint")
        require_sha256(rollback_snapshot_fingerprint, "rollback_snapshot_fingerprint")
        now = timestamp(self._now())
        self._begin()
        try:
            row = self.get_control_authority_state()
            if row["mode"] != "TRANSITIONAL_AUTHORITY":
                raise StoreError("AUTHORITY_SWITCH_FORBIDDEN_BY_E1")
            if (
                row["slice_snapshot_fingerprint"] == slice_snapshot_fingerprint
                and row["rollback_snapshot_fingerprint"] == rollback_snapshot_fingerprint
            ):
                self.connection.execute("COMMIT")
                return row, True
            if row["authority_generation"] != expected_generation:
                raise StoreError("STALE_AUTHORITY_GENERATION")
            updated = self.connection.execute(
                """UPDATE control_authority_state
                   SET authority_generation = authority_generation + 1,
                       slice_snapshot_fingerprint = ?, rollback_snapshot_fingerprint = ?,
                       updated_at = ?
                 WHERE singleton_id = 'GLOBAL' AND authority_generation = ?""",
                (
                    slice_snapshot_fingerprint,
                    rollback_snapshot_fingerprint,
                    now,
                    expected_generation,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_AUTHORITY_GENERATION")
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_control_authority_state(), False

    def switch_control_authority(
        self,
        *,
        expected_generation: int,
        expected_slice_snapshot_fingerprint: str,
        expected_rollback_snapshot_fingerprint: str,
        cutover_id: str,
        human_decision_ref: str,
        operation_key: str,
    ) -> tuple[sqlite3.Row, bool]:
        """Atomically record and apply one global forward authority switch."""

        return self._transition_authority(
            event_type="AUTHORITY_SWITCH",
            expected_generation=expected_generation,
            expected_slice_snapshot_fingerprint=expected_slice_snapshot_fingerprint,
            expected_rollback_snapshot_fingerprint=expected_rollback_snapshot_fingerprint,
            cutover_id=cutover_id,
            human_decision_ref=human_decision_ref,
            operation_key=operation_key,
        )

    def rollback_control_authority(
        self,
        *,
        expected_generation: int,
        expected_slice_snapshot_fingerprint: str,
        expected_rollback_snapshot_fingerprint: str,
        cutover_id: str,
        rollback_authorization_ref: str,
        operation_key: str,
    ) -> tuple[sqlite3.Row, bool]:
        """Atomically record and apply one explicitly authorized global rollback."""

        return self._transition_authority(
            event_type="AUTHORITY_ROLLBACK",
            expected_generation=expected_generation,
            expected_slice_snapshot_fingerprint=expected_slice_snapshot_fingerprint,
            expected_rollback_snapshot_fingerprint=expected_rollback_snapshot_fingerprint,
            cutover_id=cutover_id,
            human_decision_ref=rollback_authorization_ref,
            operation_key=operation_key,
        )

    def _transition_authority(
        self,
        *,
        event_type: str,
        expected_generation: int,
        expected_slice_snapshot_fingerprint: str,
        expected_rollback_snapshot_fingerprint: str,
        cutover_id: str,
        human_decision_ref: str,
        operation_key: str,
    ) -> tuple[sqlite3.Row, bool]:
        if type(expected_generation) is not int or expected_generation < 0:
            raise StoreError("INVALID_EXPECTED_AUTHORITY_GENERATION")
        require_sha256(
            expected_slice_snapshot_fingerprint,
            "expected_slice_snapshot_fingerprint",
        )
        require_sha256(
            expected_rollback_snapshot_fingerprint,
            "expected_rollback_snapshot_fingerprint",
        )
        require_sha256(operation_key, "operation_key")
        if not isinstance(cutover_id, str) or not cutover_id.strip():
            raise StoreError("CUTOVER_ID_REQUIRED")
        if not isinstance(human_decision_ref, str) or not human_decision_ref.strip():
            raise StoreError("HUMAN_DECISION_REF_REQUIRED")

        if event_type == "AUTHORITY_SWITCH":
            from_mode = "TRANSITIONAL_AUTHORITY"
            to_mode = "CONTROL_STORE_AUTHORITY"
        elif event_type == "AUTHORITY_ROLLBACK":
            from_mode = "CONTROL_STORE_AUTHORITY"
            to_mode = "TRANSITIONAL_AUTHORITY"
        else:
            raise StoreError("AUTHORITY_EVENT_TYPE_INVALID")

        expected_event = {
            "operation_key": operation_key,
            "cutover_id": cutover_id,
            "event_type": event_type,
            "from_mode": from_mode,
            "to_mode": to_mode,
            "from_generation": expected_generation,
            "to_generation": expected_generation + 1,
            "slice_snapshot_fingerprint": expected_slice_snapshot_fingerprint,
            "rollback_snapshot_fingerprint": expected_rollback_snapshot_fingerprint,
            "human_decision_ref": human_decision_ref,
        }

        self._begin()
        try:
            replay = self.connection.execute(
                "SELECT * FROM authority_transition_event WHERE operation_key = ?",
                (operation_key,),
            ).fetchone()
            if replay is not None:
                if any(replay[field] != value for field, value in expected_event.items()):
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                row = self.get_control_authority_state()
                expected_cutover = cutover_id if event_type == "AUTHORITY_SWITCH" else None
                expected_switched_at = (
                    replay["created_at"] if event_type == "AUTHORITY_SWITCH" else None
                )
                if not (
                    row["mode"] == to_mode
                    and row["authority_generation"] == expected_generation + 1
                    and row["cutover_id"] == expected_cutover
                    and row["slice_snapshot_fingerprint"]
                    == expected_slice_snapshot_fingerprint
                    and row["rollback_snapshot_fingerprint"]
                    == expected_rollback_snapshot_fingerprint
                    and row["switched_at"] == expected_switched_at
                    and row["updated_at"] == replay["created_at"]
                ):
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                self.connection.execute("COMMIT")
                return row, True

            current = self.get_control_authority_state()
            if current["mode"] != from_mode:
                raise StoreError("AUTHORITY_MODE_CONFLICT")
            if current["authority_generation"] != expected_generation:
                raise StoreError("STALE_AUTHORITY_GENERATION")
            if (
                current["slice_snapshot_fingerprint"]
                != expected_slice_snapshot_fingerprint
            ):
                raise StoreError("SLICE_SNAPSHOT_FINGERPRINT_MISMATCH")
            if (
                current["rollback_snapshot_fingerprint"]
                != expected_rollback_snapshot_fingerprint
            ):
                raise StoreError("ROLLBACK_SNAPSHOT_FINGERPRINT_MISMATCH")
            if event_type == "AUTHORITY_SWITCH":
                if current["cutover_id"] is not None or current["switched_at"] is not None:
                    raise StoreError("AUTHORITY_MODE_CONFLICT")
            elif current["cutover_id"] != cutover_id or current["switched_at"] is None:
                raise StoreError("CUTOVER_ID_MISMATCH")

            created_at = timestamp(self._now())
            self.connection.execute(
                """INSERT INTO authority_transition_event(
                    event_id, operation_key, cutover_id, event_type, from_mode, to_mode,
                    from_generation, to_generation, slice_snapshot_fingerprint,
                    rollback_snapshot_fingerprint, human_decision_ref, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid4()),
                    operation_key,
                    cutover_id,
                    event_type,
                    from_mode,
                    to_mode,
                    expected_generation,
                    expected_generation + 1,
                    expected_slice_snapshot_fingerprint,
                    expected_rollback_snapshot_fingerprint,
                    human_decision_ref,
                    created_at,
                ),
            )
            row = self.get_control_authority_state()
            expected_cutover = cutover_id if event_type == "AUTHORITY_SWITCH" else None
            expected_switched_at = created_at if event_type == "AUTHORITY_SWITCH" else None
            if not (
                row["mode"] == to_mode
                and row["authority_generation"] == expected_generation + 1
                and row["cutover_id"] == expected_cutover
                and row["slice_snapshot_fingerprint"]
                == expected_slice_snapshot_fingerprint
                and row["rollback_snapshot_fingerprint"]
                == expected_rollback_snapshot_fingerprint
                and row["switched_at"] == expected_switched_at
                and row["updated_at"] == created_at
            ):
                raise StoreError("AUTHORITY_TRANSITION_RESULT_MISMATCH")
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError as error:
            self._rollback()
            raise StoreError("AUTHORITY_TRANSITION_REJECTED", str(error)) from error
        except BaseException:
            self._rollback()
            raise
        return row, False

    def _existing_event(
        self, execution_id: str, key: str, event_type: str, payload_json: str
    ) -> sqlite3.Row | None:
        event = self.connection.execute(
            "SELECT * FROM transition_event WHERE execution_id = ? AND operation_key = ?",
            (execution_id, key),
        ).fetchone()
        if event is None:
            return None
        if event["event_type"] != event_type or event["metadata_json"] != payload_json:
            raise StoreError("IDEMPOTENCY_CONFLICT")
        return event

    def _insert_event(
        self,
        *,
        execution_id: str,
        operation_key: str,
        event_type: str,
        from_state: str | None,
        to_state: str,
        from_version: int,
        to_version: int,
        actor_role: ActorRole,
        actor_id: str,
        lease_generation: int,
        reason_code: str,
        reason_detail: str | None,
        metadata_json: str,
        created_at: str,
    ) -> None:
        self.connection.execute(
            """INSERT INTO transition_event(
                event_id, execution_id, operation_key, event_type, from_state, to_state,
                from_state_version, to_state_version, actor_role, actor_id,
                lease_generation, reason_code, reason_detail, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid4()),
                execution_id,
                operation_key,
                event_type,
                from_state,
                to_state,
                from_version,
                to_version,
                actor_role.value,
                actor_id,
                lease_generation,
                reason_code,
                reason_detail,
                metadata_json,
                created_at,
            ),
        )

    def create_execution(self, spec: ExecutionCreate, operation_key: str) -> sqlite3.Row:
        spec.validate()
        require_sha256(operation_key, "operation_key")
        source_root = str(canonical_source_root(spec.source_root))
        payload = {
            "execution_id": spec.execution_id,
            "slice_id": spec.slice_id,
            "risk_level": spec.risk_level.value,
            "environment": spec.environment.value,
            "contract_fingerprint": spec.contract_fingerprint,
            "authority_fingerprint": spec.authority_fingerprint,
            "source_root": source_root,
            "branch": spec.branch,
            "base_commit": spec.base_commit,
            "current_actor_role": spec.current_actor_role.value,
        }
        payload_json = canonical_json(payload)
        now = timestamp(self._now())
        self._begin()
        try:
            existing = self.connection.execute(
                "SELECT execution_id FROM slice_execution WHERE create_idempotency_key = ?",
                (operation_key,),
            ).fetchone()
            if existing is not None:
                self._existing_event(
                    existing["execution_id"], operation_key, "EXECUTION_CREATED", payload_json
                )
                self.connection.execute("COMMIT")
                return self.get_execution(existing["execution_id"])
            self.connection.execute(
                """INSERT INTO slice_execution(
                    execution_id, create_idempotency_key, slice_id, risk_level, environment,
                    state, state_version, contract_fingerprint, authority_fingerprint,
                    source_root, branch, base_commit, max_auto_reworks, current_actor_role,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'READY', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    spec.execution_id,
                    operation_key,
                    spec.slice_id,
                    spec.risk_level.value,
                    spec.environment.value,
                    spec.contract_fingerprint,
                    spec.authority_fingerprint,
                    source_root,
                    spec.branch,
                    spec.base_commit,
                    spec.max_auto_reworks,
                    spec.current_actor_role.value,
                    now,
                    now,
                ),
            )
            self._insert_event(
                execution_id=spec.execution_id,
                operation_key=operation_key,
                event_type="EXECUTION_CREATED",
                from_state=None,
                to_state=ExecutionState.READY.value,
                from_version=-1,
                to_version=0,
                actor_role=spec.current_actor_role,
                actor_id="controller",
                lease_generation=0,
                reason_code="EXECUTION_CREATED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError as error:
            self._rollback()
            if "slice_execution.source_root, slice_execution.slice_id" in str(error):
                raise StoreError("OPEN_EXECUTION_EXISTS") from error
            raise
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(spec.execution_id)

    def _validate_preexecution_capsule(
        self,
        spec: ExecutionCreate,
        capsule: ContextCapsule,
        *,
        worktree_path: str,
    ) -> None:
        if capsule.role is not CapsuleRole.MAKER:
            raise StoreError("CAPSULE_BINDING_MISMATCH", "Maker capsule required")
        required_fields = {
            "slice",
            "current_task",
            "contract_fingerprint",
            "authority_fingerprint",
            "source_root",
            "branch",
            "base_commit",
            "current_commit",
            "acceptance_criteria",
            "constraints",
            "risk",
            "environment",
            "allowed_actions",
            "forbidden_actions",
            "relevant_authority_refs",
            "relevant_authority_excerpts",
        }
        missing = required_fields.difference(capsule.content)
        if missing:
            raise StoreError(
                "CAPSULE_BINDING_MISMATCH", f"missing:{','.join(sorted(missing))}"
            )
        slice_content = capsule.content["slice"]
        capsule_slice_id = (
            slice_content.get("slice_id")
            if isinstance(slice_content, dict)
            else slice_content
        )
        if capsule_slice_id != spec.slice_id:
            raise StoreError("CAPSULE_BINDING_MISMATCH", "slice")
        expected = {
            "contract_fingerprint": spec.contract_fingerprint,
            "authority_fingerprint": spec.authority_fingerprint,
            "source_root": worktree_path,
            "branch": spec.branch,
            "base_commit": spec.base_commit,
            "current_commit": spec.base_commit,
            "risk": spec.risk_level.value,
            "environment": spec.environment.value,
        }
        for field, value in expected.items():
            if capsule.content.get(field) != value:
                code = {
                    "contract_fingerprint": "CONTRACT_FINGERPRINT_MISMATCH",
                    "authority_fingerprint": "AUTHORITY_FINGERPRINT_MISMATCH",
                }.get(field, "CAPSULE_BINDING_MISMATCH")
                raise StoreError(code, field)

    def get_deferred_binding(self, execution_id: str) -> dict[str, Any]:
        """Return the immutable PREEXECUTION_BIND metadata for one execution."""

        event = self.connection.execute(
            """SELECT event.metadata_json
                 FROM slice_control_event AS event
                WHERE event.reason_code = 'PREEXECUTION_BIND'
                  AND json_extract(event.metadata_json, '$.metadata.execution_id') = ?
                ORDER BY event.event_seq
                LIMIT 1""",
            (execution_id,),
        ).fetchone()
        if event is None:
            raise StoreError("PREEXECUTION_BINDING_NOT_FOUND", execution_id)
        try:
            payload = json.loads(event["metadata_json"])
            metadata = payload["metadata"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise StoreError("PREEXECUTION_BINDING_CORRUPT") from error
        required = {
            "execution_id",
            "slice_id",
            "repository_toplevel",
            "worktree_path",
            "branch",
            "base_commit",
            "contract_fingerprint",
            "authority_fingerprint",
            "risk_level",
            "environment",
            "packet_ref",
            "context_snapshot_id",
            "context_fingerprint",
            "branch_created",
            "worktree_created",
        }
        if not isinstance(metadata, dict) or not required.issubset(metadata):
            raise StoreError("PREEXECUTION_BINDING_CORRUPT")
        if metadata["execution_id"] != execution_id:
            raise StoreError("PREEXECUTION_BINDING_CORRUPT")
        return dict(metadata)

    def release_deferred_preexecution_binding(
        self,
        execution_id: str,
        slice_id: str,
        expected_execution_state_version: int,
        expected_slice_state_version: int,
        operation_key: str,
        *,
        release_reason: str,
        authority_ref: str,
        actor_id: str = "controller",
        fault_injector: Callable[[str], None] | None = None,
    ) -> tuple[sqlite3.Row, sqlite3.Row, dict[str, Any], bool]:
        """Atomically cancel and unbind one untouched READY prebound execution."""

        require_sha256(operation_key, "operation_key")
        if not execution_id or not slice_id or not release_reason or not authority_ref:
            raise StoreError("INVALID_INPUT", "release identity is incomplete")
        if release_reason not in {
            "BASE_STALE",
            "CONTRACT_STALE",
            "AUTHORITY_STALE",
            "BRANCH_STALE",
            "ENVIRONMENT_STALE",
            "PREMAKER_PREREQUISITE_CHANGED",
        }:
            raise StoreError("PREBOUND_RELEASE_REASON_INVALID")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (expected_execution_state_version, expected_slice_state_version)
        ):
            raise StoreError("INVALID_EXPECTED_STATE_VERSION")

        self._begin()
        try:
            release_event = self.connection.execute(
                "SELECT * FROM slice_control_event WHERE operation_key = ?",
                (operation_key,),
            ).fetchone()
            if release_event is not None:
                try:
                    release_payload = json.loads(release_event["metadata_json"])
                    release_metadata = release_payload["metadata"]
                except (KeyError, TypeError, json.JSONDecodeError) as error:
                    raise StoreError("PREBOUND_RELEASE_IDEMPOTENCY_CONFLICT") from error
                execution = self.get_execution(execution_id)
                state = self.get_slice_control_state(slice_id)
                transition = self.connection.execute(
                    """SELECT * FROM transition_event
                         WHERE execution_id = ? AND operation_key = ?""",
                    (execution_id, operation_key),
                ).fetchone()
                if (
                    release_event["slice_id"] != slice_id
                    or release_event["reason_code"] != "PREEXECUTION_RELEASE"
                    or release_payload.get("reason_code") != "PREEXECUTION_RELEASE"
                    or release_metadata.get("released_execution_id") != execution_id
                    or release_metadata.get("release_reason") != release_reason
                    or release_metadata.get("authority_ref") != authority_ref
                    or release_event["from_state_version"] != expected_slice_state_version
                    or release_event["to_state_version"] != expected_slice_state_version + 1
                    or transition is None
                    or transition["reason_code"] != "PREEXECUTION_BIND_RELEASED"
                    or transition["from_state_version"] != expected_execution_state_version
                    or transition["to_state_version"] != expected_execution_state_version + 1
                    or execution["state"] != ExecutionState.CANCELLED.value
                    or execution["state_version"] != expected_execution_state_version + 1
                    or state["state_version"] != expected_slice_state_version + 1
                    or state["migration_class"] != "DEFER_BINDING"
                    or state["execution_eligibility"] != "INELIGIBLE_UNTIL_PREFLIGHT"
                    or state["defer_reason"] != "PREEXECUTION_BIND_SUPERSEDED"
                    or any(
                        state[field] is not None
                        for field in (
                            "repository_toplevel", "branch", "base_commit",
                            "implementation_result_commit", "current_branch_head",
                            "active_execution_id",
                        )
                    )
                ):
                    raise StoreError("PREBOUND_RELEASE_IDEMPOTENCY_CONFLICT")
                self.connection.execute("COMMIT")
                return execution, state, dict(release_metadata), True

            prior_release = self.connection.execute(
                """SELECT 1 FROM slice_control_event
                     WHERE reason_code = 'PREEXECUTION_RELEASE'
                       AND json_extract(metadata_json, '$.metadata.released_execution_id') = ?""",
                (execution_id,),
            ).fetchone()
            if prior_release is not None:
                raise StoreError("PREBOUND_RELEASE_IDEMPOTENCY_CONFLICT")

            execution = self.get_execution(execution_id)
            state = self.get_slice_control_state(slice_id)
            if execution["slice_id"] != slice_id:
                raise StoreError("PREBOUND_RELEASE_EXECUTION_MISMATCH")
            if execution["state_version"] != expected_execution_state_version:
                raise StoreError("STALE_EXECUTION_STATE_VERSION")
            if state["state_version"] != expected_slice_state_version:
                raise StoreError("STALE_CONTROL_STATE_VERSION")
            if state["active_execution_id"] != execution_id:
                raise StoreError("PREBOUND_RELEASE_EXECUTION_MISMATCH")
            if (
                execution["result_commit"] is not None
                or state["implementation_result_commit"] is not None
            ):
                raise StoreError("PREBOUND_RELEASE_RESULT_EXISTS")
            if execution["lease_owner"] is not None:
                raise StoreError("PREBOUND_RELEASE_LEASE_CONFLICT")
            attempts = self.connection.execute(
                """SELECT count(*) FROM agent_attempt
                     WHERE execution_id = ? AND role IN ('MAKER', 'EVALUATOR')""",
                (execution_id,),
            ).fetchone()[0]
            if attempts:
                raise StoreError("PREBOUND_RELEASE_ATTEMPT_EXISTS")
            if (
                state["migration_class"] != "DEFER_BINDING"
                or state["execution_eligibility"] != "ELIGIBLE_PREEXECUTION_BOUND"
                or state["repository_toplevel"] is None
                or state["branch"] is None
                or state["base_commit"] is None
                or state["implementation_result_commit"] is not None
                or state["current_branch_head"] != state["base_commit"]
                or execution["state"] != ExecutionState.READY.value
            ):
                raise StoreError("PREBOUND_RELEASE_STATE_INVALID")
            validate_transition(
                ExecutionState.READY,
                ExecutionState.CANCELLED,
                stored_resume_state=None,
                new_resume_state=None,
            )

            binding = self.get_deferred_binding(execution_id)
            try:
                context = self.get_context_snapshot(binding["context_snapshot_id"])
                capsule = json.loads(context["canonical_json"])
                content = capsule["content"]
            except (KeyError, TypeError, json.JSONDecodeError, StoreError) as error:
                raise StoreError("PREBOUND_RELEASE_BINDING_MISMATCH") from error
            coherent = (
                binding["slice_id"] == slice_id
                and binding["repository_toplevel"] == execution["source_root"]
                and binding["repository_toplevel"] == state["repository_toplevel"]
                and binding["branch"] == execution["branch"] == state["branch"]
                and binding["base_commit"] == execution["base_commit"] == state["base_commit"]
                and binding["contract_fingerprint"] == execution["contract_fingerprint"]
                and binding["authority_fingerprint"] == execution["authority_fingerprint"]
                and binding["risk_level"] == execution["risk_level"]
                and binding["environment"] == execution["environment"]
                and isinstance(binding["packet_ref"], str)
                and bool(binding["packet_ref"].strip())
                and binding["context_fingerprint"] == context["fingerprint"]
                and context["execution_id"] == execution_id
                and context["role"] == CapsuleRole.MAKER.value
                and content.get("contract_fingerprint") == execution["contract_fingerprint"]
                and content.get("authority_fingerprint") == execution["authority_fingerprint"]
                and content.get("source_root") == binding["worktree_path"]
                and content.get("branch") == execution["branch"]
                and content.get("base_commit") == execution["base_commit"]
                and content.get("current_commit") == execution["base_commit"]
                and content.get("risk") == execution["risk_level"]
                and content.get("environment") == execution["environment"]
                and (
                    content.get("slice", {}).get("slice_id")
                    if isinstance(content.get("slice"), dict)
                    else content.get("slice")
                ) == slice_id
            )
            if not coherent:
                raise StoreError("PREBOUND_RELEASE_BINDING_MISMATCH")

            target = {field: state[field] for field in CONTROL_STATE_INPUT_FIELDS}
            target.update(
                execution_eligibility="INELIGIBLE_UNTIL_PREFLIGHT",
                defer_reason="PREEXECUTION_BIND_SUPERSEDED",
                repository_toplevel=None,
                branch=None,
                base_commit=None,
                implementation_result_commit=None,
                current_branch_head=None,
                active_execution_id=None,
            )
            target["authority_fingerprint"] = control_state_authority_fingerprint(target)
            target = self._validate_slice_control_target(target)
            metadata = {
                "released_execution_id": execution_id,
                "old_repository_toplevel": binding["repository_toplevel"],
                "old_worktree_path": binding["worktree_path"],
                "old_branch": binding["branch"],
                "old_base_commit": binding["base_commit"],
                "old_contract_fingerprint": binding["contract_fingerprint"],
                "old_authority_fingerprint": binding["authority_fingerprint"],
                "old_context_snapshot_id": binding["context_snapshot_id"],
                "old_context_fingerprint": binding["context_fingerprint"],
                "branch_created": bool(binding["branch_created"]),
                "worktree_created": bool(binding["worktree_created"]),
                "release_reason": release_reason,
                "authority_ref": authority_ref,
            }
            slice_payload = canonical_json(
                {"reason_code": "PREEXECUTION_RELEASE", "target": target, "metadata": metadata}
            )
            execution_payload = canonical_json(
                {
                    "execution_id": execution_id,
                    "slice_id": slice_id,
                    "expected_execution_state_version": expected_execution_state_version,
                    "expected_slice_state_version": expected_slice_state_version,
                    "release_reason": release_reason,
                    "authority_ref": authority_ref,
                }
            )
            now = timestamp(self._now())
            updated = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'CANCELLED', state_version = state_version + 1,
                          current_actor_role = 'CONTROLLER', updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_execution_state_version),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_EXECUTION_STATE_VERSION")
            if fault_injector is not None:
                fault_injector("execution_state")
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="STATE_TRANSITION",
                from_state=ExecutionState.READY.value,
                to_state=ExecutionState.CANCELLED.value,
                from_version=expected_execution_state_version,
                to_version=expected_execution_state_version + 1,
                actor_role=ActorRole.CONTROLLER,
                actor_id=actor_id,
                lease_generation=execution["lease_generation"],
                reason_code="PREEXECUTION_BIND_RELEASED",
                reason_detail=release_reason,
                metadata_json=execution_payload,
                created_at=now,
            )
            if fault_injector is not None:
                fault_injector("execution_event")
            self.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, 'PREEXECUTION_RELEASE', ?, ?)""",
                (
                    operation_key, slice_id, expected_slice_state_version,
                    expected_slice_state_version + 1, slice_payload, now,
                ),
            )
            if fault_injector is not None:
                fault_injector("slice_event")
            updated = self.connection.execute(
                """UPDATE slice_control_state
                      SET authority_fingerprint = ?,
                          execution_eligibility = 'INELIGIBLE_UNTIL_PREFLIGHT',
                          defer_reason = 'PREEXECUTION_BIND_SUPERSEDED',
                          repository_toplevel = NULL, branch = NULL, base_commit = NULL,
                          implementation_result_commit = NULL, current_branch_head = NULL,
                          active_execution_id = NULL, state_version = state_version + 1,
                          updated_at = ?
                    WHERE slice_id = ? AND state_version = ?""",
                (
                    target["authority_fingerprint"], now, slice_id,
                    expected_slice_state_version,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_CONTROL_STATE_VERSION")
            if fault_injector is not None:
                fault_injector("slice_state")
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return (
            self.get_execution(execution_id),
            self.get_slice_control_state(slice_id),
            metadata,
            False,
        )

    def bind_deferred_execution(
        self,
        spec: ExecutionCreate,
        expected_state_version: int,
        operation_key: str,
        *,
        maker_context_snapshot_id: str,
        maker_capsule: ContextCapsule,
        packet_ref: str,
        worktree_path: str,
        branch_created: bool,
        worktree_created: bool,
        actor_id: str = "controller",
        fault_injector: Callable[[str], None] | None = None,
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row, bool]:
        """Atomically bind a deferred Slice, READY execution, and Maker capsule."""

        spec.validate()
        require_sha256(operation_key, "operation_key")
        if spec.current_actor_role is not ActorRole.CONTROLLER:
            raise StoreError("INVALID_INPUT", "deferred binding is Controller-owned")
        if (
            isinstance(expected_state_version, bool)
            or not isinstance(expected_state_version, int)
            or expected_state_version < 0
        ):
            raise StoreError("INVALID_EXPECTED_STATE_VERSION")
        if not maker_context_snapshot_id or not packet_ref.strip() or not worktree_path:
            raise StoreError("CAPSULE_BINDING_MISMATCH", "binding identity is incomplete")
        try:
            json_capability = self.connection.execute(
                "SELECT json_extract('{\"value\":1}', '$.value')"
            ).fetchone()[0]
        except sqlite3.OperationalError as error:
            raise StoreError(
                "DESIGN_ESCALATION_REQUIRED", "SQLite JSON extraction unavailable"
            ) from error
        if json_capability != 1:
            raise StoreError(
                "DESIGN_ESCALATION_REQUIRED", "SQLite JSON extraction is incompatible"
            )
        source_root = str(canonical_source_root(spec.source_root))
        self._validate_preexecution_capsule(
            spec, maker_capsule, worktree_path=worktree_path
        )
        execution_payload = {
            "execution_id": spec.execution_id,
            "slice_id": spec.slice_id,
            "risk_level": spec.risk_level.value,
            "environment": spec.environment.value,
            "contract_fingerprint": spec.contract_fingerprint,
            "authority_fingerprint": spec.authority_fingerprint,
            "source_root": source_root,
            "branch": spec.branch,
            "base_commit": spec.base_commit,
            "current_actor_role": spec.current_actor_role.value,
        }
        execution_payload_json = canonical_json(execution_payload)
        binding_metadata = {
            "execution_id": spec.execution_id,
            "slice_id": spec.slice_id,
            "repository_toplevel": source_root,
            "worktree_path": worktree_path,
            "branch": spec.branch,
            "base_commit": spec.base_commit,
            "contract_fingerprint": spec.contract_fingerprint,
            "authority_fingerprint": spec.authority_fingerprint,
            "risk_level": spec.risk_level.value,
            "environment": spec.environment.value,
            "packet_ref": packet_ref,
            "context_snapshot_id": maker_context_snapshot_id,
            "context_fingerprint": maker_capsule.fingerprint,
            "branch_created": bool(branch_created),
            "worktree_created": bool(worktree_created),
        }
        now = timestamp(self._now())
        self._begin()
        try:
            current = self.connection.execute(
                "SELECT * FROM slice_control_state WHERE slice_id = ?",
                (spec.slice_id,),
            ).fetchone()
            if current is None:
                raise StoreError("SLICE_NOT_DEFERRED_BINDING")
            if current["migration_class"] != "DEFER_BINDING":
                raise StoreError("SLICE_NOT_DEFERRED_BINDING")
            for field, expected in (
                ("repository_toplevel", source_root),
                ("branch", spec.branch),
            ):
                if current[field] is not None and current[field] != expected:
                    raise StoreError("PREEXECUTION_BIND_CONFLICT", field)
            target = {field: current[field] for field in CONTROL_STATE_INPUT_FIELDS}
            target.update(
                {
                    "execution_eligibility": "ELIGIBLE_PREEXECUTION_BOUND",
                    "defer_reason": None,
                    "repository_toplevel": source_root,
                    "branch": spec.branch,
                    "base_commit": spec.base_commit,
                    "implementation_result_commit": None,
                    "current_branch_head": spec.base_commit,
                    "active_execution_id": spec.execution_id,
                }
            )
            target["authority_fingerprint"] = control_state_authority_fingerprint(target)
            target = self._validate_slice_control_target(target)
            slice_payload_json = canonical_json(
                {
                    "reason_code": "PREEXECUTION_BIND",
                    "target": target,
                    "metadata": binding_metadata,
                }
            )

            replay = self.connection.execute(
                "SELECT * FROM slice_control_event WHERE operation_key = ?",
                (operation_key,),
            ).fetchone()
            if replay is not None:
                if (
                    replay["slice_id"] != spec.slice_id
                    or replay["reason_code"] != "PREEXECUTION_BIND"
                    or replay["metadata_json"] != slice_payload_json
                ):
                    raise StoreError("PREEXECUTION_BIND_CONFLICT")
                execution = self.get_execution(spec.execution_id)
                if execution["create_idempotency_key"] != operation_key:
                    raise StoreError("PREEXECUTION_BIND_CONFLICT")
                self._existing_event(
                    spec.execution_id,
                    operation_key,
                    "EXECUTION_CREATED",
                    execution_payload_json,
                )
                context = self.get_context_snapshot(maker_context_snapshot_id)
                if (
                    context["execution_id"] != spec.execution_id
                    or context["role"] != CapsuleRole.MAKER.value
                    or context["fingerprint"] != maker_capsule.fingerprint
                    or context["canonical_json"] != maker_capsule.canonical_json
                ):
                    raise StoreError("PREEXECUTION_BIND_CONFLICT")
                if (
                    current["active_execution_id"] != spec.execution_id
                    or current["repository_toplevel"] != source_root
                    or current["branch"] != spec.branch
                    or current["base_commit"] != spec.base_commit
                ):
                    raise StoreError("PREEXECUTION_BIND_CONFLICT")
                self.connection.execute("COMMIT")
                return execution, current, context, True

            if current["active_execution_id"] is not None or current[
                "execution_eligibility"
            ] == "ELIGIBLE_PREEXECUTION_BOUND":
                raise StoreError("PREEXECUTION_BIND_CONFLICT")
            if current["execution_eligibility"] != "INELIGIBLE_UNTIL_PREFLIGHT":
                raise StoreError("SLICE_NOT_DEFERRED_BINDING")
            if current["state_version"] != expected_state_version:
                raise StoreError("STALE_CONTROL_STATE_VERSION")

            conflict = self.connection.execute(
                """SELECT 1
                     FROM slice_execution AS execution
                    WHERE execution.slice_id = ?
                      AND (
                          (execution.lease_owner IS NOT NULL
                           AND execution.lease_expires_at > ?)
                          OR EXISTS (
                              SELECT 1 FROM agent_attempt AS attempt
                               WHERE attempt.execution_id = execution.execution_id
                                 AND attempt.status = 'RUNNING'
                          )
                      )
                    LIMIT 1""",
                (spec.slice_id, now),
            ).fetchone()
            if conflict is not None:
                raise StoreError("ACTIVE_ATTEMPT_OR_LEASE_CONFLICT")
            open_execution = self.connection.execute(
                """SELECT 1 FROM slice_execution
                    WHERE source_root = ? AND slice_id = ?
                      AND state IN (
                          'READY', 'MAKER_RUNNING', 'VERIFYING', 'EVALUATING',
                          'REWORK_READY', 'WAITING_APPROVAL', 'BLOCKED'
                      )
                    LIMIT 1""",
                (source_root, spec.slice_id),
            ).fetchone()
            if open_execution is not None:
                raise StoreError("OPEN_EXECUTION_EXISTS")
            if self.connection.execute(
                "SELECT 1 FROM slice_execution WHERE execution_id = ?",
                (spec.execution_id,),
            ).fetchone() is not None:
                raise StoreError("PREEXECUTION_BIND_CONFLICT")

            self.connection.execute(
                """INSERT INTO slice_execution(
                    execution_id, create_idempotency_key, slice_id, risk_level, environment,
                    state, state_version, contract_fingerprint, authority_fingerprint,
                    source_root, branch, base_commit, max_auto_reworks, current_actor_role,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'READY', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    spec.execution_id,
                    operation_key,
                    spec.slice_id,
                    spec.risk_level.value,
                    spec.environment.value,
                    spec.contract_fingerprint,
                    spec.authority_fingerprint,
                    source_root,
                    spec.branch,
                    spec.base_commit,
                    spec.max_auto_reworks,
                    spec.current_actor_role.value,
                    now,
                    now,
                ),
            )
            if fault_injector is not None:
                fault_injector("execution")
            self._insert_event(
                execution_id=spec.execution_id,
                operation_key=operation_key,
                event_type="EXECUTION_CREATED",
                from_state=None,
                to_state=ExecutionState.READY.value,
                from_version=-1,
                to_version=0,
                actor_role=ActorRole.CONTROLLER,
                actor_id=actor_id,
                lease_generation=0,
                reason_code="EXECUTION_CREATED",
                reason_detail=None,
                metadata_json=execution_payload_json,
                created_at=now,
            )
            if fault_injector is not None:
                fault_injector("execution_event")
            self.connection.execute(
                """INSERT INTO context_snapshot(
                    context_snapshot_id, execution_id, role, capsule_version,
                    fingerprint, canonical_json, created_at
                ) VALUES (?, ?, 'MAKER', ?, ?, ?, ?)""",
                (
                    maker_context_snapshot_id,
                    spec.execution_id,
                    maker_capsule.capsule_version,
                    maker_capsule.fingerprint,
                    maker_capsule.canonical_json,
                    now,
                ),
            )
            if fault_injector is not None:
                fault_injector("context_snapshot")
            self.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, 'PREEXECUTION_BIND', ?, ?)""",
                (
                    operation_key,
                    spec.slice_id,
                    expected_state_version,
                    expected_state_version + 1,
                    slice_payload_json,
                    now,
                ),
            )
            if fault_injector is not None:
                fault_injector("slice_event")
            updated = self.connection.execute(
                """UPDATE slice_control_state
                      SET authority_fingerprint = ?, execution_eligibility = ?,
                          defer_reason = NULL, repository_toplevel = ?, branch = ?,
                          base_commit = ?, implementation_result_commit = NULL,
                          current_branch_head = ?, active_execution_id = ?,
                          state_version = state_version + 1, updated_at = ?
                    WHERE slice_id = ? AND state_version = ?""",
                (
                    target["authority_fingerprint"],
                    target["execution_eligibility"],
                    source_root,
                    spec.branch,
                    spec.base_commit,
                    spec.base_commit,
                    spec.execution_id,
                    now,
                    spec.slice_id,
                    expected_state_version,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_CONTROL_STATE_VERSION")
            if fault_injector is not None:
                fault_injector("slice_state")
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError as error:
            self._rollback()
            detail = str(error)
            if "slice_execution.source_root, slice_execution.slice_id" in detail:
                raise StoreError("OPEN_EXECUTION_EXISTS") from error
            if "PREEXECUTION_CONTEXT_BINDING_MISMATCH" in detail:
                raise StoreError("CAPSULE_BINDING_MISMATCH") from error
            raise
        except BaseException:
            self._rollback()
            raise
        return (
            self.get_execution(spec.execution_id),
            self.get_slice_control_state(spec.slice_id),
            self.get_context_snapshot(maker_context_snapshot_id),
            False,
        )

    def finalize_deferred_result_commit(
        self,
        execution_id: str,
        expected_state_version: int,
        expected_slice_state_version: int,
        operation_key: str,
        result_commit: str,
        *,
        expected_current_branch_head: str,
        lease_owner: str,
        lease_generation: int,
        actor_role: ActorRole = ActorRole.CONTROLLER,
        actor_id: str = "controller",
        fault_injector: Callable[[str], None] | None = None,
    ) -> tuple[sqlite3.Row, sqlite3.Row, bool]:
        """Atomically bind a result commit to an execution and its deferred Slice."""

        require_sha256(operation_key, "operation_key")
        require_commit(result_commit, "result_commit")
        require_commit(expected_current_branch_head, "expected_current_branch_head")
        if actor_role is not ActorRole.CONTROLLER:
            raise StoreError("CONTROLLER_RESULT_FINALIZATION_REQUIRED")
        payload = {
            "execution_id": execution_id,
            "expected_state_version": expected_state_version,
            "expected_slice_state_version": expected_slice_state_version,
            "expected_current_branch_head": expected_current_branch_head,
            "result_commit": result_commit,
            "lease_owner": lease_owner,
            "lease_generation": lease_generation,
            "actor_role": actor_role.value,
            "actor_id": actor_id,
        }
        payload_json = canonical_json(payload)
        now = timestamp(self._now())
        self._begin()
        try:
            existing_execution_event = self._existing_event(
                execution_id,
                operation_key,
                "RESULT_COMMIT_REGISTERED",
                payload_json,
            )
            existing_slice_event = self.connection.execute(
                "SELECT * FROM slice_control_event WHERE operation_key = ?",
                (operation_key,),
            ).fetchone()
            if existing_execution_event is not None or existing_slice_event is not None:
                if existing_execution_event is None or existing_slice_event is None:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                try:
                    existing_slice_payload = json.loads(
                        existing_slice_event["metadata_json"]
                    )
                except json.JSONDecodeError as error:
                    raise StoreError("IDEMPOTENCY_CONFLICT") from error
                if (
                    existing_slice_event["reason_code"] != "RESULT_COMMIT_BOUND"
                    or existing_slice_payload.get("metadata") != payload
                ):
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                execution = self.get_execution(execution_id)
                state = self.connection.execute(
                    "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
                    (execution_id,),
                ).fetchone()
                if (
                    state is None
                    or execution["result_commit"] != result_commit
                    or state["implementation_result_commit"] != result_commit
                    or state["current_branch_head"] != result_commit
                    or state["execution_eligibility"] != "ELIGIBLE_BOUND"
                ):
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                self.connection.execute("COMMIT")
                return execution, state, True

            execution = self.get_execution(execution_id)
            self._require_fence(execution, lease_owner, lease_generation, now)
            if execution["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if execution["state"] != ExecutionState.MAKER_RUNNING.value:
                raise StoreError("MAKER_COMPLETION_STATE_INVALID")
            state = self.connection.execute(
                "SELECT * FROM slice_control_state WHERE active_execution_id = ?",
                (execution_id,),
            ).fetchone()
            if (
                state is None
                or state["migration_class"] != "DEFER_BINDING"
                or state["execution_eligibility"]
                not in {"ELIGIBLE_PREEXECUTION_BOUND", "ELIGIBLE_BOUND"}
            ):
                raise StoreError("SLICE_NOT_DEFERRED_BINDING")
            if state["state_version"] != expected_slice_state_version:
                raise StoreError("STALE_CONTROL_STATE_VERSION")
            if (
                state["repository_toplevel"] != execution["source_root"]
                or state["branch"] != execution["branch"]
                or state["base_commit"] != execution["base_commit"]
                or state["current_branch_head"] != expected_current_branch_head
                or state["implementation_result_commit"] != execution["result_commit"]
            ):
                raise StoreError("PREEXECUTION_BIND_CONFLICT")

            target = {field: state[field] for field in CONTROL_STATE_INPUT_FIELDS}
            target.update(
                {
                    "execution_eligibility": "ELIGIBLE_BOUND",
                    "defer_reason": None,
                    "implementation_result_commit": result_commit,
                    "current_branch_head": result_commit,
                }
            )
            target["authority_fingerprint"] = control_state_authority_fingerprint(target)
            target = self._validate_slice_control_target(target)
            slice_payload_json = canonical_json(
                {
                    "reason_code": "RESULT_COMMIT_BOUND",
                    "target": target,
                    "metadata": payload,
                }
            )

            updated = self.connection.execute(
                """UPDATE slice_execution
                      SET result_commit = ?, state_version = state_version + 1, updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (result_commit, now, execution_id, expected_state_version),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            if fault_injector is not None:
                fault_injector("execution_result")
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="RESULT_COMMIT_REGISTERED",
                from_state=execution["state"],
                to_state=execution["state"],
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=actor_role,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code="RESULT_COMMIT_REGISTERED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            if fault_injector is not None:
                fault_injector("execution_event")
            self.connection.execute(
                """INSERT INTO slice_control_event(
                    operation_key, slice_id, from_state_version, to_state_version,
                    reason_code, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, 'RESULT_COMMIT_BOUND', ?, ?)""",
                (
                    operation_key,
                    state["slice_id"],
                    expected_slice_state_version,
                    expected_slice_state_version + 1,
                    slice_payload_json,
                    now,
                ),
            )
            if fault_injector is not None:
                fault_injector("slice_event")
            updated = self.connection.execute(
                """UPDATE slice_control_state
                      SET authority_fingerprint = ?, execution_eligibility = 'ELIGIBLE_BOUND',
                          defer_reason = NULL, implementation_result_commit = ?,
                          current_branch_head = ?, state_version = state_version + 1,
                          updated_at = ?
                    WHERE slice_id = ? AND state_version = ?""",
                (
                    target["authority_fingerprint"],
                    result_commit,
                    result_commit,
                    now,
                    state["slice_id"],
                    expected_slice_state_version,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_CONTROL_STATE_VERSION")
            if fault_injector is not None:
                fault_injector("slice_state")
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return (
            self.get_execution(execution_id),
            self.get_slice_control_state(state["slice_id"]),
            False,
        )

    def _require_fence(
        self,
        row: sqlite3.Row,
        lease_owner: str,
        lease_generation: int,
        now_text: str,
    ) -> None:
        if (
            row["lease_owner"] != lease_owner
            or row["lease_generation"] != lease_generation
            or row["lease_expires_at"] is None
            or row["lease_expires_at"] <= now_text
        ):
            raise StoreError("STALE_FENCING_TOKEN")

    def acquire_lease(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        lease_owner: str,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if not lease_owner:
            raise StoreError("INVALID_INPUT", "lease_owner is required")
        if not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise StoreError("INVALID_LEASE_TTL")
        payload_json = canonical_json(
            {
                "execution_id": execution_id,
                "expected_state_version": expected_state_version,
                "lease_owner": lease_owner,
                "ttl_seconds": ttl_seconds,
            }
        )
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin()
        try:
            if self._existing_event(
                execution_id, operation_key, "LEASE_ACQUIRED", payload_json
            ) is not None:
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            row = self.get_execution(execution_id)
            if ExecutionState(row["state"]) in TERMINAL_STATES:
                raise StoreError("INVALID_TRANSITION", "terminal execution cannot be leased")
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if row["lease_owner"] is not None and row["lease_expires_at"] > now:
                raise StoreError("LEASE_HELD")
            generation = row["lease_generation"] + 1
            updated = self.connection.execute(
                """UPDATE slice_execution
                   SET lease_owner = ?, lease_generation = ?, lease_expires_at = ?,
                       state_version = state_version + 1, updated_at = ?
                 WHERE execution_id = ? AND state_version = ?""",
                (lease_owner, generation, expires, now, execution_id, expected_state_version),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="LEASE_ACQUIRED",
                from_state=row["state"],
                to_state=row["state"],
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER,
                actor_id=lease_owner,
                lease_generation=generation,
                reason_code="LEASE_ACQUIRED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def heartbeat(
        self,
        execution_id: str,
        expected_state_version: int,
        lease_owner: str,
        lease_generation: int,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    ) -> sqlite3.Row:
        if not MIN_LEASE_TTL_SECONDS <= ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise StoreError("INVALID_LEASE_TTL")
        now_value = self._now()
        now = timestamp(now_value)
        expires = timestamp(now_value + timedelta(seconds=ttl_seconds))
        self._begin()
        try:
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            updated = self.connection.execute(
                """UPDATE slice_execution SET lease_expires_at = ?, updated_at = ?
                   WHERE execution_id = ? AND state_version = ? AND lease_owner = ?
                     AND lease_generation = ? AND lease_expires_at > ?""",
                (
                    expires,
                    now,
                    execution_id,
                    expected_state_version,
                    lease_owner,
                    lease_generation,
                    now,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_FENCING_TOKEN")
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def release_lease(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        lease_owner: str,
        lease_generation: int,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        payload_json = canonical_json(
            {
                "execution_id": execution_id,
                "expected_state_version": expected_state_version,
                "lease_owner": lease_owner,
                "lease_generation": lease_generation,
            }
        )
        now = timestamp(self._now())
        self._begin()
        try:
            if self._existing_event(
                execution_id, operation_key, "LEASE_RELEASED", payload_json
            ) is not None:
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            self.connection.execute(
                """UPDATE slice_execution
                   SET lease_owner = NULL, lease_expires_at = NULL,
                       state_version = state_version + 1, updated_at = ?
                 WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_state_version),
            )
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="LEASE_RELEASED",
                from_state=row["state"],
                to_state=row["state"],
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER,
                actor_id=lease_owner,
                lease_generation=lease_generation,
                reason_code="LEASE_RELEASED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def transition(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        to_state: ExecutionState,
        *,
        actor_role: ActorRole,
        actor_id: str,
        lease_owner: str,
        lease_generation: int,
        resume_state: ExecutionState | None = None,
        blocker_code: str | None = None,
        blocker_detail: str | None = None,
        reason_code: str = "STATE_TRANSITION",
        reason_detail: str | None = None,
        candidate_write_fence: CandidateWriteFence | None = None,
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        if actor_role is ActorRole.EVALUATOR:
            raise StoreError("EVALUATOR_STATE_TRANSITION_FORBIDDEN")
        if to_state is ExecutionState.ACCEPTED and actor_role is not ActorRole.CONTROLLER:
            raise StoreError("CONTROLLER_ACCEPTANCE_REQUIRED")
        payload_json = canonical_json(
            {
                "execution_id": execution_id,
                "expected_state_version": expected_state_version,
                "to_state": to_state.value,
                "actor_role": actor_role.value,
                "actor_id": actor_id,
                "lease_owner": lease_owner,
                "lease_generation": lease_generation,
                "resume_state": resume_state.value if resume_state else None,
                "blocker_code": blocker_code,
                "blocker_detail": blocker_detail,
                "reason_code": reason_code,
                "reason_detail": reason_detail,
            }
        )
        event_type = "ACCEPTED" if to_state is ExecutionState.ACCEPTED else "STATE_TRANSITION"
        now = timestamp(self._now())
        self._begin()
        try:
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence)
            if self._existing_event(
                execution_id, operation_key, event_type, payload_json
            ) is not None:
                if candidate_write_fence is not None:
                    self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            from_state = ExecutionState(row["state"])
            stored_resume = (
                ExecutionState(row["resume_state"]) if row["resume_state"] else None
            )
            validate_transition(
                from_state,
                to_state,
                stored_resume_state=stored_resume,
                new_resume_state=resume_state,
            )
            if to_state in (ExecutionState.BLOCKED, ExecutionState.DESIGN_ESCALATION):
                if not blocker_code:
                    raise StoreError("INVALID_TRANSITION", "blocker_code is required")
            elif blocker_code is not None or blocker_detail is not None:
                raise StoreError("INVALID_TRANSITION", "blocker fields are not allowed")
            accepted_at = now if to_state is ExecutionState.ACCEPTED else None
            updated = self.connection.execute(
                """UPDATE slice_execution
                   SET state = ?, resume_state = ?, state_version = state_version + 1,
                       current_actor_role = ?, blocker_code = ?, blocker_detail = ?,
                       accepted_at = ?, updated_at = ?
                 WHERE execution_id = ? AND state_version = ?""",
                (
                    to_state.value,
                    resume_state.value if resume_state else None,
                    actor_role.value,
                    blocker_code,
                    blocker_detail,
                    accepted_at,
                    now,
                    execution_id,
                    expected_state_version,
                ),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type=event_type,
                from_state=from_state.value,
                to_state=to_state.value,
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=actor_role,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code=reason_code,
                reason_detail=reason_detail,
                metadata_json=payload_json,
                created_at=now,
            )
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def register_result_commit(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        result_commit: str,
        *,
        lease_owner: str,
        lease_generation: int,
        actor_role: ActorRole = ActorRole.MAKER,
        actor_id: str = "maker",
    ) -> sqlite3.Row:
        require_sha256(operation_key, "operation_key")
        require_commit(result_commit, "result_commit")
        payload_json = canonical_json(
            {
                "execution_id": execution_id,
                "expected_state_version": expected_state_version,
                "result_commit": result_commit,
                "lease_owner": lease_owner,
                "lease_generation": lease_generation,
                "actor_role": actor_role.value,
                "actor_id": actor_id,
            }
        )
        now = timestamp(self._now())
        self._begin()
        try:
            if self._existing_event(
                execution_id, operation_key, "RESULT_COMMIT_REGISTERED", payload_json
            ) is not None:
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            self.connection.execute(
                """UPDATE slice_execution
                   SET result_commit = ?, state_version = state_version + 1, updated_at = ?
                 WHERE execution_id = ? AND state_version = ?""",
                (result_commit, now, execution_id, expected_state_version),
            )
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="RESULT_COMMIT_REGISTERED",
                from_state=row["state"],
                to_state=row["state"],
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=actor_role,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code="RESULT_COMMIT_REGISTERED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def register_context_snapshot(
        self,
        context_snapshot_id: str,
        execution_id: str,
        role: CapsuleRole | str,
        capsule_version: int,
        content: dict[str, object] | ContextCapsule,
        candidate_write_fence: CandidateWriteFence | None = None,
    ) -> sqlite3.Row:
        """Register an immutable capsule envelope, replaying exact content."""

        if not context_snapshot_id:
            raise StoreError("INVALID_INPUT", "context_snapshot_id is required")
        try:
            normalized_role = CapsuleRole(role)
        except ValueError as error:
            raise StoreError("INVALID_INPUT", "context role must be MAKER or EVALUATOR") from error
        if isinstance(content, ContextCapsule):
            if content.role is not normalized_role or content.capsule_version != capsule_version:
                raise StoreError("CONTEXT_CAPSULE_BINDING_MISMATCH")
            capsule_content = content.content
        else:
            capsule_content = content
        if not isinstance(capsule_content, dict):
            raise StoreError("INVALID_INPUT", "capsule content must be an object")
        if (
            isinstance(capsule_version, bool)
            or not isinstance(capsule_version, int)
            or capsule_version <= 0
        ):
            raise StoreError("INVALID_INPUT", "capsule_version must be positive")
        envelope = {
            "capsule_version": capsule_version,
            "role": normalized_role.value,
            "content": capsule_content,
        }
        serialized = canonical_json(envelope)
        fingerprint = canonical_sha256(envelope)
        created_at = timestamp(self._now())
        self._begin()
        try:
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence)
            existing = self.connection.execute(
                """SELECT * FROM context_snapshot
                    WHERE execution_id = ? AND role = ? AND fingerprint = ?""",
                (execution_id, normalized_role.value, fingerprint),
            ).fetchone()
            if existing is not None:
                if (
                    existing["canonical_json"] != serialized
                    or existing["capsule_version"] != capsule_version
                ):
                    raise StoreError("CONTEXT_FINGERPRINT_CONFLICT")
                if candidate_write_fence is not None:
                    self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
                self.connection.execute("COMMIT")
                return existing
            identity = self.connection.execute(
                "SELECT * FROM context_snapshot WHERE context_snapshot_id = ?",
                (context_snapshot_id,),
            ).fetchone()
            if identity is not None:
                raise StoreError("CONTEXT_SNAPSHOT_ID_CONFLICT")
            self.connection.execute(
                """INSERT INTO context_snapshot(
                    context_snapshot_id, execution_id, role, capsule_version,
                    fingerprint, canonical_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    context_snapshot_id,
                    execution_id,
                    normalized_role.value,
                    capsule_version,
                    fingerprint,
                    serialized,
                    created_at,
                ),
            )
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_context_snapshot(context_snapshot_id)

    def get_context_snapshot(self, context_snapshot_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM context_snapshot WHERE context_snapshot_id = ?",
            (context_snapshot_id,),
        ).fetchone()
        if row is None:
            raise StoreError("CONTEXT_SNAPSHOT_NOT_FOUND", context_snapshot_id)
        return row

    def register_verification_result(
        self, record: VerificationResultRecord
    ) -> sqlite3.Row:
        """Persist one immutable canonical result with operation-key replay."""

        manifest_json = canonical_json(record.command_manifest)
        result_json = canonical_json(record.result)
        if (
            manifest_json != record.command_manifest_json
            or canonical_sha256(record.command_manifest) != record.command_manifest_sha256
            or result_json != record.result_json
        ):
            raise StoreError("VERIFICATION_CANONICAL_MISMATCH")
        self._begin()
        try:
            existing = self.connection.execute(
                "SELECT * FROM verification_result WHERE operation_key = ?",
                (record.operation_key,),
            ).fetchone()
            if existing is not None:
                expected = (
                    record.verification_id,
                    record.execution_id,
                    record.result_commit,
                    record.contract_fingerprint,
                    record.authority_fingerprint,
                    record.verdict,
                    record.command_manifest_json,
                    record.command_manifest_sha256,
                    record.result_json,
                    record.started_at,
                    record.ended_at,
                )
                actual = tuple(
                    existing[field]
                    for field in (
                        "verification_id",
                        "execution_id",
                        "result_commit",
                        "contract_fingerprint",
                        "authority_fingerprint",
                        "verdict",
                        "command_manifest",
                        "command_manifest_sha256",
                        "result_json",
                        "started_at",
                        "ended_at",
                    )
                )
                if actual != expected:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                self.connection.execute("COMMIT")
                return existing
            self.connection.execute(
                """INSERT INTO verification_result(
                    verification_id, operation_key, execution_id, result_commit,
                    contract_fingerprint, authority_fingerprint, verdict,
                    command_manifest, command_manifest_sha256, result_json,
                    started_at, ended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.verification_id,
                    record.operation_key,
                    record.execution_id,
                    record.result_commit,
                    record.contract_fingerprint,
                    record.authority_fingerprint,
                    record.verdict,
                    record.command_manifest_json,
                    record.command_manifest_sha256,
                    record.result_json,
                    record.started_at,
                    record.ended_at,
                ),
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_verification_result(record.verification_id)

    def get_verification_result(self, verification_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM verification_result WHERE verification_id = ?",
            (verification_id,),
        ).fetchone()
        if row is None:
            raise StoreError("VERIFICATION_RESULT_NOT_FOUND", verification_id)
        return row

    def find_verification_pass(
        self,
        execution_id: str,
        result_commit: str,
        contract_fingerprint: str,
        authority_fingerprint: str,
    ) -> sqlite3.Row | None:
        """Return only a PASS bound to all four frozen identity dimensions."""

        require_commit(result_commit, "result_commit")
        require_sha256(contract_fingerprint, "contract_fingerprint")
        require_sha256(authority_fingerprint, "authority_fingerprint")
        return self.connection.execute(
            """SELECT * FROM verification_result
                WHERE execution_id = ?
                  AND result_commit = ?
                  AND contract_fingerprint = ?
                  AND authority_fingerprint = ?
                  AND verdict = 'PASS'
                ORDER BY verification_seq DESC
                LIMIT 1""",
            (
                execution_id,
                result_commit,
                contract_fingerprint,
                authority_fingerprint,
            ),
        ).fetchone()

    def find_verification_failure(
        self,
        execution_id: str,
        result_commit: str,
        contract_fingerprint: str,
        authority_fingerprint: str,
    ) -> sqlite3.Row | None:
        """Return the latest FAIL bound to the exact frozen execution identity."""

        require_commit(result_commit, "result_commit")
        require_sha256(contract_fingerprint, "contract_fingerprint")
        require_sha256(authority_fingerprint, "authority_fingerprint")
        return self.connection.execute(
            """SELECT * FROM verification_result
                WHERE execution_id = ?
                  AND result_commit = ?
                  AND contract_fingerprint = ?
                  AND authority_fingerprint = ?
                  AND verdict = 'FAIL'
                ORDER BY verification_seq DESC
                LIMIT 1""",
            (
                execution_id,
                result_commit,
                contract_fingerprint,
                authority_fingerprint,
            ),
        ).fetchone()

    def has_verification_pass(
        self,
        execution_id: str,
        result_commit: str,
        contract_fingerprint: str,
        authority_fingerprint: str,
    ) -> bool:
        return (
            self.find_verification_pass(
                execution_id,
                result_commit,
                contract_fingerprint,
                authority_fingerprint,
            )
            is not None
        )

    def register_agent_attempt(
        self,
        *,
        attempt_id: str,
        operation_key: str,
        execution_id: str,
        role: CapsuleRole | str,
        attempt_no: int,
        model: str | None,
        reasoning_effort: str | None,
        session_id: str,
        context_snapshot_id: str,
        base_commit: str,
        result_commit: str | None,
        started_at: str,
        candidate_write_fence: CandidateWriteFence | None = None,
    ) -> sqlite3.Row:
        """Register one fresh running Maker or Evaluator attempt."""

        require_sha256(operation_key, "operation_key")
        require_commit(base_commit, "base_commit")
        normalized_role = CapsuleRole(role)
        if result_commit is not None:
            require_commit(result_commit, "result_commit")
        if normalized_role is CapsuleRole.EVALUATOR and result_commit is None:
            raise StoreError("EVALUATOR_RESULT_COMMIT_REQUIRED")
        if (
            not attempt_id
            or not session_id
            or isinstance(attempt_no, bool)
            or not isinstance(attempt_no, int)
            or attempt_no < 1
        ):
            raise StoreError("INVALID_AGENT_ATTEMPT")
        values = (
            attempt_id,
            operation_key,
            execution_id,
            normalized_role.value,
            attempt_no,
            model or "<unspecified>",
            reasoning_effort or "<unspecified>",
            "FRESH",
            session_id,
            "workspace-write" if normalized_role is CapsuleRole.MAKER else "read-only",
            context_snapshot_id,
            base_commit,
            result_commit,
            "RUNNING",
            started_at,
        )
        self._begin()
        try:
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence)
            existing = self.connection.execute(
                "SELECT * FROM agent_attempt WHERE operation_key = ?", (operation_key,)
            ).fetchone()
            if existing is not None:
                fields = (
                    "attempt_id", "operation_key", "execution_id", "role", "attempt_no",
                    "model", "reasoning_effort", "session_mode", "session_id",
                    "sandbox_mode", "context_snapshot_id", "base_commit", "result_commit",
                    "status", "started_at",
                )
                if tuple(existing[field] for field in fields) != values:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                if candidate_write_fence is not None:
                    self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
                self.connection.execute("COMMIT")
                return existing
            self.connection.execute(
                """INSERT INTO agent_attempt(
                    attempt_id, operation_key, execution_id, role, attempt_no, model,
                    reasoning_effort, session_mode, session_id, sandbox_mode,
                    context_snapshot_id, base_commit, result_commit, status, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_agent_attempt(attempt_id)

    def get_agent_attempt(self, attempt_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM agent_attempt WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise StoreError("AGENT_ATTEMPT_NOT_FOUND", attempt_id)
        return row

    def get_evaluator_artifact_seal(self, seal_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM evaluator_artifact_seal WHERE seal_id = ?", (seal_id,)
        ).fetchone()
        if row is None:
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_NOT_FOUND", seal_id)
        return row

    def find_evaluator_artifact_seal(
        self, attempt_id: str, phase: EvaluatorArtifactSealPhase | str
    ) -> sqlite3.Row | None:
        value = phase.value if isinstance(phase, EvaluatorArtifactSealPhase) else str(phase)
        return self.connection.execute(
            "SELECT * FROM evaluator_artifact_seal WHERE evaluator_attempt_id=? AND phase=?",
            (attempt_id, value),
        ).fetchone()

    def find_authoritative_evaluator_artifact_seal(
        self, attempt_id: str
    ) -> sqlite3.Row | None:
        post = self.find_evaluator_artifact_seal(
            attempt_id, EvaluatorArtifactSealPhase.POST_EXECUTION
        )
        if post is not None:
            return post
        return self.find_evaluator_artifact_seal(
            attempt_id, EvaluatorArtifactSealPhase.LEGACY_ATTESTED
        )

    @staticmethod
    def _seal_fields() -> tuple[str, ...]:
        return (
            "seal_id", "execution_id", "result_commit", "verification_id",
            "evaluator_attempt_id", "context_snapshot_id", "context_fingerprint",
            "contract_fingerprint", "authority_fingerprint", "phase", "producer_kind",
            "producer_ref", "evidence_root", "manifest_version", "manifest_json",
            "manifest_sha256", "authority_generation", "operation_key", "approval_id",
        )

    def create_evaluator_artifact_seal(
        self,
        spec: EvaluatorArtifactSealCreate,
        *,
        lease_owner: str,
        lease_generation: int,
        required_execution_state: ExecutionState = ExecutionState.EVALUATING,
    ) -> sqlite3.Row:
        """Persist one immutable, fenced seal from trusted-parent observed bytes."""

        spec.validate()
        try:
            observed = verify_manifest_bytes(
                spec.evidence_root, spec.manifest_json, spec.manifest_sha256
            )
            entries = observed.entries
        except ArtifactSealError as error:
            raise StoreError(error.code, error.detail) from error
        roles = {entry.role for entry in entries}
        required_roles = {
            EvaluatorArtifactSealPhase.PRE_EXECUTION: {"context_snapshot", "prompt", "output_schema"},
            EvaluatorArtifactSealPhase.POST_EXECUTION: {"stdout", "stderr", "result", "runner_metadata"},
            EvaluatorArtifactSealPhase.LEGACY_ATTESTED: {"stdout", "stderr", "result"},
        }[spec.phase]
        if not required_roles.issubset(roles):
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_REQUIRED_ROLE_MISSING")
        values = (
            spec.seal_id,
            spec.execution_id,
            spec.result_commit,
            spec.verification_id,
            spec.evaluator_attempt_id,
            spec.context_snapshot_id,
            spec.context_fingerprint,
            spec.contract_fingerprint,
            spec.authority_fingerprint,
            spec.phase.value,
            spec.producer_kind.value,
            spec.producer_ref,
            spec.evidence_root,
            spec.manifest_version,
            spec.manifest_json,
            spec.manifest_sha256,
            spec.authority_generation,
            spec.operation_key,
            spec.approval_id,
        )
        self._begin()
        try:
            execution = self.get_execution(spec.execution_id)
            self._require_fence(
                execution, lease_owner, lease_generation, timestamp(self._now())
            )
            if execution["state"] != required_execution_state.value:
                raise StoreError("EVALUATOR_ARTIFACT_SEAL_STATE_INVALID")
            authority = self.get_control_authority_state()
            if authority["authority_generation"] != spec.authority_generation:
                raise StoreError("STALE_AUTHORITY_GENERATION")
            if (
                execution["result_commit"] != spec.result_commit
                or execution["contract_fingerprint"] != spec.contract_fingerprint
                or execution["authority_fingerprint"] != spec.authority_fingerprint
            ):
                raise StoreError("EVALUATOR_ARTIFACT_SEAL_EXECUTION_BINDING_MISMATCH")
            attempt = self.get_agent_attempt(spec.evaluator_attempt_id)
            context = self.get_context_snapshot(spec.context_snapshot_id)
            verification = self.connection.execute(
                "SELECT * FROM verification_result WHERE verification_id=?",
                (spec.verification_id,),
            ).fetchone()
            if (
                attempt["execution_id"] != spec.execution_id
                or attempt["role"] != "EVALUATOR"
                or attempt["result_commit"] != spec.result_commit
                or attempt["context_snapshot_id"] != spec.context_snapshot_id
                or context["execution_id"] != spec.execution_id
                or context["role"] != "EVALUATOR"
                or context["fingerprint"] != spec.context_fingerprint
                or verification is None
                or verification["execution_id"] != spec.execution_id
                or verification["result_commit"] != spec.result_commit
                or verification["contract_fingerprint"] != spec.contract_fingerprint
                or verification["authority_fingerprint"] != spec.authority_fingerprint
                or verification["verdict"] != "PASS"
            ):
                raise StoreError("EVALUATOR_ARTIFACT_SEAL_BINDING_MISMATCH")
            existing = self.connection.execute(
                "SELECT * FROM evaluator_artifact_seal WHERE operation_key=?",
                (spec.operation_key,),
            ).fetchone()
            if existing is not None:
                if tuple(existing[field] for field in self._seal_fields()) != values:
                    raise StoreError("EVALUATOR_ARTIFACT_SEAL_IDEMPOTENCY_CONFLICT")
                # Exact replay remains idempotent even after the attempt became
                # terminal. The persisted bytes were revalidated above and all
                # immutable DCS bindings/fencing remain exact.
                self.connection.execute("COMMIT")
                return existing
            if spec.phase is EvaluatorArtifactSealPhase.LEGACY_ATTESTED:
                if attempt["status"] != "SUCCEEDED":
                    raise StoreError("EVALUATOR_LEGACY_ATTESTATION_ATTEMPT_INVALID")
                if self.find_evaluator_artifact_seal(
                    spec.evaluator_attempt_id, EvaluatorArtifactSealPhase.POST_EXECUTION
                ) is not None:
                    raise StoreError("EVALUATOR_LEGACY_SEAL_FRESH_POST_EXISTS")
            else:
                if attempt["status"] != "RUNNING":
                    raise StoreError("EVALUATOR_FRESH_SEAL_ATTEMPT_INVALID")
                if spec.phase is EvaluatorArtifactSealPhase.POST_EXECUTION:
                    pre = self.find_evaluator_artifact_seal(
                        spec.evaluator_attempt_id, EvaluatorArtifactSealPhase.PRE_EXECUTION
                    )
                    if pre is None:
                        raise StoreError("EVALUATOR_POST_SEAL_PRE_REQUIRED")
                    for field in (
                        "execution_id", "result_commit", "verification_id",
                        "evaluator_attempt_id", "context_snapshot_id", "context_fingerprint",
                        "contract_fingerprint", "authority_fingerprint", "evidence_root",
                        "authority_generation",
                    ):
                        if pre[field] != values[self._seal_fields().index(field)]:
                            raise StoreError("EVALUATOR_POST_SEAL_PRE_BINDING_MISMATCH", field)
            logical = self.connection.execute(
                "SELECT * FROM evaluator_artifact_seal WHERE evaluator_attempt_id=? AND phase=?",
                (spec.evaluator_attempt_id, spec.phase.value),
            ).fetchone()
            if logical is not None:
                raise StoreError("EVALUATOR_ARTIFACT_SEAL_CONFLICT")
            self.connection.execute(
                """INSERT INTO evaluator_artifact_seal(
                    seal_id, execution_id, result_commit, verification_id,
                    evaluator_attempt_id, context_snapshot_id, context_fingerprint,
                    contract_fingerprint, authority_fingerprint, phase, producer_kind,
                    producer_ref, evidence_root, manifest_version, manifest_json,
                    manifest_sha256, authority_generation, operation_key, approval_id, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*values, timestamp(self._now())),
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_evaluator_artifact_seal(spec.seal_id)

    def verify_evaluator_artifact_seal(
        self,
        seal_id: str,
        *,
        expected_attempt_id: str | None = None,
        require_authority_generation: bool = True,
    ) -> tuple[sqlite3.Row, VerifiedArtifactManifest]:
        seal = self.get_evaluator_artifact_seal(seal_id)
        if expected_attempt_id is not None and seal["evaluator_attempt_id"] != expected_attempt_id:
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_ATTEMPT_MISMATCH")
        execution = self.get_execution(seal["execution_id"])
        attempt = self.get_agent_attempt(seal["evaluator_attempt_id"])
        context = self.get_context_snapshot(seal["context_snapshot_id"])
        verification = self.connection.execute(
            "SELECT * FROM verification_result WHERE verification_id=?",
            (seal["verification_id"],),
        ).fetchone()
        if (
            execution["result_commit"] != seal["result_commit"]
            or execution["contract_fingerprint"] != seal["contract_fingerprint"]
            or execution["authority_fingerprint"] != seal["authority_fingerprint"]
            or attempt["execution_id"] != seal["execution_id"]
            or attempt["role"] != "EVALUATOR"
            or attempt["result_commit"] != seal["result_commit"]
            or attempt["context_snapshot_id"] != seal["context_snapshot_id"]
            or context["execution_id"] != seal["execution_id"]
            or context["role"] != "EVALUATOR"
            or context["fingerprint"] != seal["context_fingerprint"]
            or verification is None
            or verification["execution_id"] != seal["execution_id"]
            or verification["result_commit"] != seal["result_commit"]
            or verification["contract_fingerprint"] != seal["contract_fingerprint"]
            or verification["authority_fingerprint"] != seal["authority_fingerprint"]
            or verification["verdict"] != "PASS"
        ):
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_BINDING_MISMATCH")
        if require_authority_generation:
            authority = self.get_control_authority_state()
            if authority["authority_generation"] != seal["authority_generation"]:
                raise StoreError("STALE_AUTHORITY_GENERATION")
        try:
            view = verify_manifest_bytes(
                seal["evidence_root"], seal["manifest_json"], seal["manifest_sha256"]
            )
        except ArtifactSealError as error:
            raise StoreError(error.code, error.detail) from error
        return seal, view

    def finish_agent_attempt(
        self,
        attempt_id: str,
        *,
        status: str,
        ended_at: str,
        result_commit: str | None = None,
        exit_code: int | None = None,
        stdout_artifact: str | None = None,
        stdout_sha256: str | None = None,
        stderr_artifact: str | None = None,
        stderr_sha256: str | None = None,
        result_artifact: str | None = None,
        result_sha256: str | None = None,
        post_execution_seal_id: str | None = None,
        failure_code: str | None = None,
        lease_owner: str | None = None,
        lease_generation: int | None = None,
        required_execution_state: ExecutionState | None = None,
    ) -> sqlite3.Row:
        """Finish once; evaluator success is derived from a durable POST seal."""

        if status not in {"SUCCEEDED", "FAILED", "ABORTED", "LOST"}:
            raise StoreError("INVALID_AGENT_ATTEMPT_STATUS")
        if result_commit is not None:
            require_commit(result_commit, "result_commit")
        for value, field in (
            (stdout_sha256, "stdout_sha256"),
            (stderr_sha256, "stderr_sha256"),
            (result_sha256, "result_sha256"),
        ):
            if value is not None:
                require_sha256(value, field)

        self._begin()
        try:
            row = self.get_agent_attempt(attempt_id)
            execution = None
            if (
                lease_owner is not None
                or lease_generation is not None
                or required_execution_state is not None
            ):
                if lease_owner is None or lease_generation is None:
                    raise StoreError("INCOMPLETE_FENCING_TOKEN")
                execution = self.get_execution(row["execution_id"])
                self._require_fence(
                    execution,
                    lease_owner,
                    lease_generation,
                    timestamp(self._now()),
                )
                if (
                    required_execution_state is not None
                    and execution["state"] != required_execution_state.value
                ):
                    raise StoreError("AGENT_ATTEMPT_COMPLETION_STATE_INVALID")

            if row["role"] == "EVALUATOR" and status == "SUCCEEDED":
                if post_execution_seal_id is None:
                    raise StoreError("EVALUATOR_POST_EXECUTION_SEAL_REQUIRED")
                seal, view = self.verify_evaluator_artifact_seal(
                    post_execution_seal_id, expected_attempt_id=attempt_id
                )
                if seal["phase"] != EvaluatorArtifactSealPhase.POST_EXECUTION.value:
                    raise StoreError("EVALUATOR_POST_EXECUTION_SEAL_REQUIRED")
                result_entry = view.entry_for_role("result")
                stdout_entry = view.entry_for_role("stdout")
                stderr_entry = view.entry_for_role("stderr")

                def authoritative_path(entry: Any) -> str:
                    return str(view.evidence_root / Path(entry.relative_path))

                authoritative = {
                    "result_commit": seal["result_commit"],
                    "stdout_artifact": authoritative_path(stdout_entry),
                    "stdout_sha256": stdout_entry.sha256,
                    "stderr_artifact": authoritative_path(stderr_entry),
                    "stderr_sha256": stderr_entry.sha256,
                    "result_artifact": authoritative_path(result_entry),
                    "result_sha256": result_entry.sha256,
                }
                claims = {
                    "result_commit": result_commit,
                    "stdout_artifact": stdout_artifact,
                    "stdout_sha256": stdout_sha256,
                    "stderr_artifact": stderr_artifact,
                    "stderr_sha256": stderr_sha256,
                    "result_artifact": result_artifact,
                    "result_sha256": result_sha256,
                }
                for field, claim in claims.items():
                    if claim is None:
                        continue
                    expected = authoritative[field]
                    if field.endswith("_artifact"):
                        try:
                            claim_relative = relative_artifact_path(
                                claim, view.evidence_root
                            )
                            expected_relative = relative_artifact_path(
                                expected, view.evidence_root
                            )
                        except ArtifactSealError as error:
                            raise StoreError(error.code, error.detail) from error
                        if claim_relative != expected_relative:
                            raise StoreError(
                                "EVALUATOR_CALLER_ARTIFACT_CLAIM_MISMATCH", field
                            )
                    elif claim != expected:
                        raise StoreError(
                            "EVALUATOR_CALLER_ARTIFACT_CLAIM_MISMATCH", field
                        )
                result_commit = authoritative["result_commit"]
                stdout_artifact = authoritative["stdout_artifact"]
                stdout_sha256 = authoritative["stdout_sha256"]
                stderr_artifact = authoritative["stderr_artifact"]
                stderr_sha256 = authoritative["stderr_sha256"]
                result_artifact = authoritative["result_artifact"]
                result_sha256 = authoritative["result_sha256"]

            terminal = (
                result_commit, status, exit_code, stdout_artifact, stdout_sha256,
                stderr_artifact, stderr_sha256, result_artifact, result_sha256,
                failure_code, ended_at,
            )
            fields = (
                "result_commit", "status", "exit_code", "stdout_artifact", "stdout_sha256",
                "stderr_artifact", "stderr_sha256", "result_artifact", "result_sha256",
                "failure_code", "ended_at",
            )
            if row["status"] != "RUNNING":
                if tuple(row[field] for field in fields) != terminal:
                    raise StoreError("AGENT_ATTEMPT_ALREADY_FINISHED")
                self.connection.execute("COMMIT")
                return row
            updated = self.connection.execute(
                """UPDATE agent_attempt SET
                    result_commit = ?, status = ?, exit_code = ?, stdout_artifact = ?,
                    stdout_sha256 = ?, stderr_artifact = ?, stderr_sha256 = ?,
                    result_artifact = ?, result_sha256 = ?, failure_code = ?, ended_at = ?
                  WHERE attempt_id = ? AND status = 'RUNNING'""",
                (*terminal, attempt_id),
            )
            if updated.rowcount != 1:
                raise StoreError("AGENT_ATTEMPT_ALREADY_FINISHED")
            self.connection.execute("COMMIT")
        except (ArtifactSealError,) as error:
            self._rollback()
            raise StoreError(error.code, error.detail) from error
        except BaseException:
            self._rollback()
            raise
        return self.get_agent_attempt(attempt_id)

    def validate_evaluation_completion_binding(
        self,
        record: EvaluationResultRecord,
        *,
        artifact_seal_id: str | None = None,
        artifact_bundle: EvaluatorArtifactBinding | None = None,
        allowed_attempt_statuses: tuple[str, ...] = ("SUCCEEDED",),
    ) -> None:
        """Bind semantic completion to a persisted seal and revalidated bytes."""

        execution = self.get_execution(record.execution_id)
        attempt = self.get_agent_attempt(record.evaluator_attempt_id)
        context = self.get_context_snapshot(record.context_snapshot_id)
        seal = (
            self.get_evaluator_artifact_seal(artifact_seal_id)
            if artifact_seal_id is not None
            else self.find_authoritative_evaluator_artifact_seal(
                record.evaluator_attempt_id
            )
        )
        if seal is None:
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_REQUIRED")
        seal, sealed_artifacts = self.verify_evaluator_artifact_seal(
            seal["seal_id"], expected_attempt_id=record.evaluator_attempt_id
        )
        if seal["phase"] not in {
            EvaluatorArtifactSealPhase.POST_EXECUTION.value,
            EvaluatorArtifactSealPhase.LEGACY_ATTESTED.value,
        }:
            raise StoreError("EVALUATOR_AUTHORITATIVE_SEAL_PHASE_INVALID")
        if (
            seal["execution_id"] != record.execution_id
            or seal["result_commit"] != record.result_commit
            or seal["context_snapshot_id"] != record.context_snapshot_id
            or seal["contract_fingerprint"] != record.contract_fingerprint
            or seal["authority_fingerprint"] != record.authority_fingerprint
        ):
            raise StoreError("EVALUATOR_ARTIFACT_SEAL_BINDING_MISMATCH")
        try:
            durable_result = decode_durable_evaluator_result_bytes_for_recovery(
                sealed_artifacts.bytes_for_role("result")
            )
        except (EvaluatorBoundaryError, ArtifactSealError, ValueError) as error:
            code = getattr(error, "code", "EVALUATOR_RESULT_ARTIFACT_INVALID")
            raise StoreError(code, str(error)) from error
        if canonical_json(durable_result) != record.result_json:
            raise StoreError("EVALUATOR_DURABLE_RESULT_MISMATCH")

        if artifact_bundle is None:
            values = tuple(
                attempt[field]
                for field in (
                    "result_artifact", "result_sha256", "stdout_artifact",
                    "stdout_sha256", "stderr_artifact", "stderr_sha256",
                )
            )
            if all(isinstance(value, str) and value for value in values):
                artifact_bundle = EvaluatorArtifactBinding(*values)
        verification = self.connection.execute(
            "SELECT * FROM verification_result WHERE verification_id=?",
            (seal["verification_id"],),
        ).fetchone()
        try:
            validate_durable_evaluator_completion_binding(
                execution=dict(execution),
                evaluator_attempt=dict(attempt),
                verification=dict(verification) if verification is not None else None,
                context_snapshot=dict(context),
                artifact_bundle=artifact_bundle,
                sealed_artifacts=sealed_artifacts,
                result_payload=record.result,
                allowed_attempt_statuses=allowed_attempt_statuses,
            )
        except EvaluatorBoundaryError as error:
            raise StoreError(error.code, error.detail) from error

    def register_evaluation_result(
        self,
        record: EvaluationResultRecord | None = None,
        *,
        evaluation_id: str | None = None,
        operation_key: str | None = None,
        execution_id: str | None = None,
        evaluator_attempt_id: str | None = None,
        context_snapshot_id: str | None = None,
        result_commit: str | None = None,
        contract_fingerprint: str | None = None,
        authority_fingerprint: str | None = None,
        verdict: str | None = None,
        result: Mapping[str, Any] | None = None,
        started_at: str | None = None,
        ended_at: str | None = None,
        lease_owner: str | None = None,
        lease_generation: int | None = None,
        required_execution_state: ExecutionState | None = None,
    ) -> sqlite3.Row:
        if record is None:
            if any(
                value is None
                for value in (
                    evaluation_id,
                    operation_key,
                    execution_id,
                    evaluator_attempt_id,
                    context_snapshot_id,
                    result_commit,
                    contract_fingerprint,
                    authority_fingerprint,
                    verdict,
                    result,
                    started_at,
                    ended_at,
                )
            ):
                raise StoreError("EVALUATION_RESULT_INVALID")
            try:
                record = build_evaluation_result(
                    evaluation_id=evaluation_id,
                    operation_key=operation_key,
                    execution_id=execution_id,
                    evaluator_attempt_id=evaluator_attempt_id,
                    context_snapshot_id=context_snapshot_id,
                    result_commit=result_commit,
                    contract_fingerprint=contract_fingerprint,
                    authority_fingerprint=authority_fingerprint,
                    verdict=verdict,
                    result=result,
                    started_at=started_at,
                    ended_at=ended_at,
                )
            except ValueError as error:
                if str(error) == "EVALUATION_VERDICT_INVALID":
                    raise StoreError("INVALID_EVALUATION_VERDICT") from error
                raise
        elif any(
            value is not None
            for value in (
                evaluation_id,
                operation_key,
                execution_id,
                evaluator_attempt_id,
                context_snapshot_id,
                result_commit,
                contract_fingerprint,
                authority_fingerprint,
                verdict,
                result,
                started_at,
                ended_at,
            )
        ):
            raise StoreError("EVALUATION_RESULT_ARGUMENT_CONFLICT")
        payload_json = canonical_json(record.semantic_payload())
        result_json = canonical_json(record.result)
        if (
            payload_json != record.canonical_payload_json
            or result_json != record.result_json
        ):
            raise StoreError("EVALUATION_CANONICAL_MISMATCH")
        self.validate_evaluation_completion_binding(record)
        values = (
            record.evaluation_id, record.operation_key, record.execution_id,
            record.evaluator_attempt_id, record.context_snapshot_id,
            record.result_commit, record.contract_fingerprint,
            record.authority_fingerprint, record.verdict, record.result_json,
            record.started_at, record.ended_at,
        )
        self._begin()
        try:
            if (
                lease_owner is not None
                or lease_generation is not None
                or required_execution_state is not None
            ):
                if lease_owner is None or lease_generation is None:
                    raise StoreError("INCOMPLETE_FENCING_TOKEN")
                execution = self.get_execution(record.execution_id)
                self._require_fence(
                    execution,
                    lease_owner,
                    lease_generation,
                    timestamp(self._now()),
                )
                if (
                    required_execution_state is not None
                    and execution["state"] != required_execution_state.value
                ):
                    raise StoreError("EVALUATOR_COMPLETION_STATE_INVALID")
            existing = self.connection.execute(
                "SELECT * FROM evaluation_result WHERE operation_key = ?",
                (record.operation_key,),
            ).fetchone()
            if existing is not None:
                fields = (
                    "evaluation_id", "operation_key", "execution_id",
                    "evaluator_attempt_id", "context_snapshot_id", "result_commit",
                    "contract_fingerprint", "authority_fingerprint", "verdict",
                    "result_json", "started_at", "ended_at",
                )
                if tuple(existing[field] for field in fields) != values:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                self.connection.execute("COMMIT")
                return existing
            execution = self.get_execution(record.execution_id)
            if (
                execution["result_commit"] != record.result_commit
                or execution["contract_fingerprint"] != record.contract_fingerprint
                or execution["authority_fingerprint"] != record.authority_fingerprint
            ):
                raise StoreError("EVALUATION_EXECUTION_BINDING_MISMATCH")
            attempt = self.get_agent_attempt(record.evaluator_attempt_id)
            if (
                attempt["execution_id"] != record.execution_id
                or attempt["role"] != CapsuleRole.EVALUATOR.value
                or attempt["context_snapshot_id"] != record.context_snapshot_id
                or attempt["result_commit"] != record.result_commit
                or attempt["status"] != "SUCCEEDED"
            ):
                raise StoreError("EVALUATOR_ATTEMPT_BINDING_MISMATCH")
            self.connection.execute(
                """INSERT INTO evaluation_result(
                    evaluation_id, operation_key, execution_id, evaluator_attempt_id,
                    context_snapshot_id, result_commit, contract_fingerprint,
                    authority_fingerprint, verdict, result_json, started_at, ended_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_evaluation_result(record.evaluation_id)

    def get_evaluation_result(self, evaluation_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM evaluation_result WHERE evaluation_id = ?", (evaluation_id,)
        ).fetchone()
        if row is None:
            raise StoreError("EVALUATION_RESULT_NOT_FOUND", evaluation_id)
        return row

    def find_evaluation_pass(
        self,
        execution_id: str,
        result_commit: str,
        contract_fingerprint: str,
        authority_fingerprint: str,
    ) -> sqlite3.Row | None:
        return self.connection.execute(
            """SELECT evaluation_result.* FROM evaluation_result
                JOIN agent_attempt ON agent_attempt.attempt_id = evaluation_result.evaluator_attempt_id
               WHERE evaluation_result.execution_id = ?
                 AND evaluation_result.result_commit = ?
                 AND evaluation_result.contract_fingerprint = ?
                 AND evaluation_result.authority_fingerprint = ?
                 AND evaluation_result.verdict = 'PASS'
                 AND agent_attempt.role = 'EVALUATOR'
                 AND agent_attempt.status = 'SUCCEEDED'
               ORDER BY evaluation_result.evaluation_seq DESC LIMIT 1""",
            (execution_id, result_commit, contract_fingerprint, authority_fingerprint),
        ).fetchone()

    def _require_single_completed_maker_for_high_rework(
        self, execution_id: str, result_commit: str
    ) -> None:
        attempts = self.connection.execute(
            """SELECT count(*) AS total,
                      sum(CASE WHEN status='SUCCEEDED' AND result_commit=? THEN 1 ELSE 0 END) AS matching
                 FROM agent_attempt WHERE execution_id=? AND role='MAKER'""",
            (result_commit, execution_id),
        ).fetchone()
        if attempts["total"] != 1 or attempts["matching"] != 1:
            raise StoreError("HIGH_REWORK_ATTEMPT_TOPOLOGY_INVALID")

    def request_approval(
        self,
        *,
        approval_id: str,
        idempotency_key: str,
        execution_id: str,
        approval_type: str,
        authority_ref: str,
        expected_state_version: int,
        lease_owner: str,
        lease_generation: int,
        candidate_write_fence: CandidateWriteFence | None = None,
    ) -> sqlite3.Row:
        require_sha256(idempotency_key, "idempotency_key")
        now = timestamp(self._now())
        self._begin()
        try:
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence)
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if approval_type == "HIGH_REWORK":
                if (
                    row["risk_level"] != "HIGH"
                    or row["max_auto_reworks"] != 0
                    or row["maker_rework_count"] != 0
                    or row["state"] != ExecutionState.BLOCKED.value
                    or row["resume_state"] != ExecutionState.VERIFYING.value
                    or row["blocker_code"] != "VERIFICATION_FAILED"
                    or row["result_commit"] is None
                ):
                    raise StoreError("HIGH_REWORK_APPROVAL_NOT_EXPECTED")
                self._require_single_completed_maker_for_high_rework(
                    execution_id, row["result_commit"]
                )
            elif row["state"] != ExecutionState.WAITING_APPROVAL.value:
                raise StoreError("APPROVAL_NOT_EXPECTED")
            existing = self.connection.execute(
                "SELECT * FROM approval_request WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            expected = (
                approval_id, idempotency_key, execution_id, approval_type, 1,
                authority_ref,
            )
            if existing is not None:
                fields = (
                    "approval_id", "idempotency_key", "execution_id", "approval_type",
                    "required", "authority_ref",
                )
                if tuple(existing[field] for field in fields) != expected:
                    raise StoreError("IDEMPOTENCY_CONFLICT")
                if candidate_write_fence is not None:
                    self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
                self.connection.execute("COMMIT")
                return existing
            self.connection.execute(
                """INSERT INTO approval_request(
                    approval_id, idempotency_key, execution_id, approval_type,
                    required, status, authority_ref, requested_at
                ) VALUES (?, ?, ?, ?, 1, 'PENDING', ?, ?)""",
                (approval_id, idempotency_key, execution_id, approval_type, authority_ref, now),
            )
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_approval(approval_id)

    def get_approval(self, approval_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM approval_request WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            raise StoreError("APPROVAL_NOT_FOUND", approval_id)
        return row

    def resolve_approval(
        self,
        approval_id: str,
        *,
        execution_id: str,
        authority_ref: str,
        approved: bool,
        candidate_write_fence: CandidateWriteFence | None = None,
    ) -> sqlite3.Row:
        status = "APPROVED" if approved else "REJECTED"
        now = timestamp(self._now())
        self._begin()
        try:
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence)
            row = self.get_approval(approval_id)
            if row["execution_id"] != execution_id:
                raise StoreError("APPROVAL_EXECUTION_MISMATCH")
            if row["authority_ref"] != authority_ref:
                raise StoreError("STALE_APPROVAL")
            if row["consumed_at"] is not None:
                raise StoreError("APPROVAL_ALREADY_CONSUMED")
            if row["status"] == status:
                if candidate_write_fence is not None:
                    self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
                self.connection.execute("COMMIT")
                return row
            if row["status"] != "PENDING":
                raise StoreError("APPROVAL_ALREADY_RESOLVED")
            self.connection.execute(
                "UPDATE approval_request SET status = ?, resolved_at = ? WHERE approval_id = ?",
                (status, now, approval_id),
            )
            if candidate_write_fence is not None:
                self._require_candidate_fence(execution_id, candidate_write_fence, check_version=False)
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_approval(approval_id)

    def authorize_high_rework(
        self,
        execution_id: str,
        expected_state_version: int,
        resume_operation_key: str,
        ready_operation_key: str,
        *,
        approval_id: str,
        authority_ref: str,
        verification_id: str,
        result_commit: str,
        contract_fingerprint: str,
        authority_fingerprint: str,
        lease_owner: str,
        lease_generation: int,
        actor_id: str = "controller",
    ) -> sqlite3.Row:
        """Apply one approved HIGH disposition using only existing C4 states."""

        require_sha256(resume_operation_key, "resume_operation_key")
        require_sha256(ready_operation_key, "ready_operation_key")
        require_commit(result_commit, "result_commit")
        require_sha256(contract_fingerprint, "contract_fingerprint")
        require_sha256(authority_fingerprint, "authority_fingerprint")
        if not approval_id or not authority_ref or not verification_id:
            raise StoreError("INVALID_INPUT", "HIGH rework binding is incomplete")
        now = timestamp(self._now())
        binding_payload = {
            "execution_id": execution_id,
            "authorized_from_state_version": expected_state_version,
            "approval_id": approval_id,
            "authority_ref": authority_ref,
            "verification_id": verification_id,
            "result_commit": result_commit,
            "contract_fingerprint": contract_fingerprint,
            "authority_fingerprint": authority_fingerprint,
            "lease_owner": lease_owner,
            "lease_generation": lease_generation,
        }
        self._begin()
        try:
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if (
                row["risk_level"] != "HIGH"
                or row["max_auto_reworks"] != 0
                or row["maker_rework_count"] != 0
                or row["state"] != ExecutionState.BLOCKED.value
                or row["resume_state"] != ExecutionState.VERIFYING.value
                or row["blocker_code"] != "VERIFICATION_FAILED"
            ):
                raise StoreError("HIGH_REWORK_STATE_INVALID")
            if (
                row["result_commit"] != result_commit
                or row["contract_fingerprint"] != contract_fingerprint
                or row["authority_fingerprint"] != authority_fingerprint
            ):
                raise StoreError("HIGH_REWORK_EXECUTION_BINDING_MISMATCH")
            self._require_single_completed_maker_for_high_rework(
                execution_id, result_commit
            )
            verification = self.get_verification_result(verification_id)
            if (
                verification["execution_id"] != execution_id
                or verification["result_commit"] != result_commit
                or verification["contract_fingerprint"] != contract_fingerprint
                or verification["authority_fingerprint"] != authority_fingerprint
                or verification["verdict"] != "FAIL"
            ):
                raise StoreError("HIGH_REWORK_VERIFICATION_BINDING_MISMATCH")
            approval = self.get_approval(approval_id)
            if approval["execution_id"] != execution_id:
                raise StoreError("APPROVAL_EXECUTION_MISMATCH")
            if approval["approval_type"] != "HIGH_REWORK":
                raise StoreError("HIGH_REWORK_APPROVAL_TYPE_MISMATCH")
            if approval["authority_ref"] != authority_ref:
                raise StoreError("STALE_APPROVAL")
            if approval["consumed_at"] is not None:
                raise StoreError("APPROVAL_ALREADY_CONSUMED")
            if approval["status"] != "APPROVED":
                raise StoreError("HIGH_REWORK_APPROVAL_REQUIRED")

            validate_transition(
                ExecutionState.BLOCKED,
                ExecutionState.VERIFYING,
                stored_resume_state=ExecutionState.VERIFYING,
                new_resume_state=None,
            )
            first = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'VERIFYING', resume_state = NULL,
                          state_version = state_version + 1,
                          current_actor_role = 'CONTROLLER', blocker_code = NULL,
                          blocker_detail = NULL, updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_state_version),
            )
            if first.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            self._insert_event(
                execution_id=execution_id,
                operation_key=resume_operation_key,
                event_type="STATE_TRANSITION",
                from_state=ExecutionState.BLOCKED.value,
                to_state=ExecutionState.VERIFYING.value,
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code="HUMAN_HIGH_REWORK_RESUME",
                reason_detail=None,
                metadata_json=canonical_json({**binding_payload, "step": "resume_verifying"}),
                created_at=now,
            )

            validate_transition(
                ExecutionState.VERIFYING,
                ExecutionState.REWORK_READY,
                stored_resume_state=None,
                new_resume_state=None,
            )
            second = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'REWORK_READY', state_version = state_version + 1,
                          current_actor_role = 'CONTROLLER', updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_state_version + 1),
            )
            if second.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            self._insert_event(
                execution_id=execution_id,
                operation_key=ready_operation_key,
                event_type="STATE_TRANSITION",
                from_state=ExecutionState.VERIFYING.value,
                to_state=ExecutionState.REWORK_READY.value,
                from_version=expected_state_version + 1,
                to_version=expected_state_version + 2,
                actor_role=ActorRole.CONTROLLER,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code="HUMAN_AUTHORIZED_HIGH_REWORK",
                reason_detail=None,
                metadata_json=canonical_json({**binding_payload, "step": "rework_ready"}),
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def schedule_human_authorized_rework(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        *,
        approval_id: str,
        authority_ref: str,
        lease_owner: str,
        lease_generation: int,
        actor_id: str = "controller",
    ) -> sqlite3.Row:
        """Consume Human authority and schedule the one explicit HIGH Maker rework."""

        require_sha256(operation_key, "operation_key")
        now = timestamp(self._now())
        self._begin()
        try:
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if (
                row["risk_level"] != "HIGH"
                or row["max_auto_reworks"] != 0
                or row["state"] != ExecutionState.REWORK_READY.value
                or row["maker_rework_count"] != 0
            ):
                raise StoreError("HIGH_REWORK_SCHEDULING_STATE_INVALID")
            if row["result_commit"] is None:
                raise StoreError("HIGH_REWORK_EXECUTION_BINDING_MISMATCH")
            self._require_single_completed_maker_for_high_rework(
                execution_id, row["result_commit"]
            )
            approval = self.get_approval(approval_id)
            if approval["execution_id"] != execution_id:
                raise StoreError("APPROVAL_EXECUTION_MISMATCH")
            if approval["approval_type"] != "HIGH_REWORK":
                raise StoreError("HIGH_REWORK_APPROVAL_TYPE_MISMATCH")
            if approval["authority_ref"] != authority_ref:
                raise StoreError("STALE_APPROVAL")
            if approval["status"] != "APPROVED":
                raise StoreError("HIGH_REWORK_APPROVAL_REQUIRED")
            if approval["consumed_at"] is not None:
                raise StoreError("APPROVAL_ALREADY_CONSUMED")
            authorization = self.connection.execute(
                """SELECT * FROM transition_event
                     WHERE execution_id = ?
                       AND reason_code = 'HUMAN_AUTHORIZED_HIGH_REWORK'
                     ORDER BY event_seq DESC LIMIT 1""",
                (execution_id,),
            ).fetchone()
            if authorization is None or authorization["to_state_version"] != expected_state_version:
                raise StoreError("HIGH_REWORK_AUTHORIZATION_REQUIRED")
            try:
                metadata = json.loads(authorization["metadata_json"])
            except json.JSONDecodeError as error:
                raise StoreError("HIGH_REWORK_AUTHORIZATION_INVALID") from error
            if (
                metadata.get("approval_id") != approval_id
                or metadata.get("authority_ref") != authority_ref
                or metadata.get("result_commit") != row["result_commit"]
                or metadata.get("contract_fingerprint") != row["contract_fingerprint"]
                or metadata.get("authority_fingerprint") != row["authority_fingerprint"]
            ):
                raise StoreError("HIGH_REWORK_AUTHORIZATION_STALE")

            consumed = self.connection.execute(
                """UPDATE approval_request SET consumed_at = ?
                     WHERE approval_id = ? AND status = 'APPROVED' AND consumed_at IS NULL""",
                (now, approval_id),
            )
            if consumed.rowcount != 1:
                raise StoreError("APPROVAL_ALREADY_CONSUMED")
            updated = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'MAKER_RUNNING', state_version = state_version + 1,
                          current_actor_role = 'CONTROLLER', updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_state_version),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            payload_json = canonical_json(
                {
                    "execution_id": execution_id,
                    "expected_state_version": expected_state_version,
                    "approval_id": approval_id,
                    "authority_ref": authority_ref,
                    "authorization_event_seq": authorization["event_seq"],
                    "lease_owner": lease_owner,
                    "lease_generation": lease_generation,
                }
            )
            self._insert_event(
                execution_id=execution_id,
                operation_key=operation_key,
                event_type="STATE_TRANSITION",
                from_state=ExecutionState.REWORK_READY.value,
                to_state=ExecutionState.MAKER_RUNNING.value,
                from_version=expected_state_version,
                to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER,
                actor_id=actor_id,
                lease_generation=lease_generation,
                reason_code="HUMAN_AUTHORIZED_MAKER_REWORK_SCHEDULED",
                reason_detail=None,
                metadata_json=payload_json,
                created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def schedule_rework(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        *,
        lease_owner: str,
        lease_generation: int,
        actor_id: str = "controller",
    ) -> sqlite3.Row:
        """Consume rework budget only when a new Maker attempt is scheduled."""

        require_sha256(operation_key, "operation_key")
        payload_json = canonical_json(
            {"execution_id": execution_id, "expected_state_version": expected_state_version,
             "lease_owner": lease_owner, "lease_generation": lease_generation}
        )
        now = timestamp(self._now())
        self._begin()
        try:
            if self._existing_event(execution_id, operation_key, "STATE_TRANSITION", payload_json):
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            row = self.get_execution(execution_id)
            self._require_fence(row, lease_owner, lease_generation, now)
            if row["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if row["state"] != ExecutionState.REWORK_READY.value:
                raise StoreError("INVALID_TRANSITION", "rework scheduling requires REWORK_READY")
            if row["maker_rework_count"] >= row["max_auto_reworks"]:
                raise StoreError("REWORK_BUDGET_EXHAUSTED")
            updated = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'MAKER_RUNNING', state_version = state_version + 1,
                          maker_rework_count = maker_rework_count + 1,
                          current_actor_role = 'CONTROLLER', updated_at = ?
                    WHERE execution_id = ? AND state_version = ?""",
                (now, execution_id, expected_state_version),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_STATE_VERSION")
            self._insert_event(
                execution_id=execution_id, operation_key=operation_key,
                event_type="STATE_TRANSITION", from_state=ExecutionState.REWORK_READY.value,
                to_state=ExecutionState.MAKER_RUNNING.value,
                from_version=expected_state_version, to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER, actor_id=actor_id,
                lease_generation=lease_generation, reason_code="MAKER_REWORK_SCHEDULED",
                reason_detail=None, metadata_json=payload_json, created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)

    def accept_execution(
        self,
        execution_id: str,
        expected_state_version: int,
        operation_key: str,
        manifest: EvidenceManifest,
        *,
        lease_owner: str,
        lease_generation: int,
        approval_id: str | None = None,
        approval_authority_ref: str | None = None,
        actor_id: str = "controller",
    ) -> sqlite3.Row:
        """Atomically revalidate all evidence, consume approval, and ACCEPT."""

        require_sha256(operation_key, "operation_key")
        fields = manifest.materialized_fields
        if canonical_json(fields) != manifest.canonical_json or canonical_sha256(fields) != manifest.manifest_sha256:
            raise StoreError("EVIDENCE_MANIFEST_CANONICAL_MISMATCH")
        maker_id = fields.get("maker_attempt_evidence", {}).get("attempt_id")
        verification_id = fields.get("verification_evidence", {}).get("verification_id")
        evaluator_id = fields.get("evaluator_attempt_evidence", {}).get("attempt_id")
        evaluation_id = fields.get("evaluation_evidence", {}).get("evaluation_id")
        if not all(isinstance(value, str) and value for value in (maker_id, verification_id, evaluator_id, evaluation_id)):
            raise StoreError("EVIDENCE_MANIFEST_INVALID")
        payload_json = canonical_json(
            {"execution_id": execution_id, "expected_state_version": expected_state_version,
             "manifest_sha256": manifest.manifest_sha256, "approval_id": approval_id,
             "approval_authority_ref": approval_authority_ref,
             "lease_owner": lease_owner, "lease_generation": lease_generation}
        )
        now = timestamp(self._now())
        self._begin()
        try:
            if self._existing_event(execution_id, operation_key, "ACCEPTED", payload_json):
                self.connection.execute("COMMIT")
                return self.get_execution(execution_id)
            execution = self.get_execution(execution_id)
            self._require_fence(execution, lease_owner, lease_generation, now)
            if execution["state_version"] != expected_state_version:
                raise StoreError("STALE_STATE_VERSION")
            if execution["state"] != ExecutionState.EVALUATING.value:
                raise StoreError("ACCEPTANCE_STATE_INVALID")
            binding = (
                fields.get("execution_id") == execution_id
                and fields.get("slice_id") == execution["slice_id"]
                and fields.get("contract_fingerprint") == execution["contract_fingerprint"]
                and fields.get("authority_fingerprint") == execution["authority_fingerprint"]
                and fields.get("base_commit") == execution["base_commit"]
                and fields.get("result_commit") == execution["result_commit"]
            )
            if not binding or execution["result_commit"] is None:
                raise StoreError("ACCEPTANCE_BINDING_MISMATCH")
            maker = self.get_agent_attempt(maker_id)
            evaluator = self.get_agent_attempt(evaluator_id)
            verification = self.get_verification_result(verification_id)
            evaluation = self.get_evaluation_result(evaluation_id)
            exact = (
                maker["execution_id"] == execution_id
                and maker["role"] == "MAKER"
                and maker["status"] == "SUCCEEDED"
                and maker["result_commit"] == execution["result_commit"]
                and evaluator["execution_id"] == execution_id
                and evaluator["role"] == "EVALUATOR"
                and evaluator["status"] == "SUCCEEDED"
                and evaluator["result_commit"] == execution["result_commit"]
                and verification["execution_id"] == execution_id
                and verification["result_commit"] == execution["result_commit"]
                and verification["contract_fingerprint"] == execution["contract_fingerprint"]
                and verification["authority_fingerprint"] == execution["authority_fingerprint"]
                and verification["verdict"] == "PASS"
                and evaluation["execution_id"] == execution_id
                and evaluation["evaluator_attempt_id"] == evaluator_id
                and evaluation["result_commit"] == execution["result_commit"]
                and evaluation["contract_fingerprint"] == execution["contract_fingerprint"]
                and evaluation["authority_fingerprint"] == execution["authority_fingerprint"]
                and evaluation["verdict"] == "PASS"
                and fields["maker_attempt_evidence"].get("status") == "SUCCEEDED"
                and fields["verification_evidence"].get("verdict") == "PASS"
                and fields["evaluator_attempt_evidence"].get("status") == "SUCCEEDED"
                and fields["evaluation_evidence"].get("verdict") == "PASS"
            )
            if not exact:
                raise StoreError("ACCEPTANCE_BINDING_MISMATCH")
            expected_contexts = {
                (maker["role"], maker["context_snapshot_id"], self.get_context_snapshot(maker["context_snapshot_id"])["fingerprint"]),
                (evaluator["role"], evaluator["context_snapshot_id"], self.get_context_snapshot(evaluator["context_snapshot_id"])["fingerprint"]),
            }
            manifested_contexts = {
                (item.get("role"), item.get("context_snapshot_id"), item.get("fingerprint"))
                for item in fields.get("context_fingerprints", [])
                if isinstance(item, dict)
            }
            if expected_contexts != manifested_contexts:
                raise StoreError("ACCEPTANCE_CONTEXT_MISMATCH")
            expected_transitions = [
                {
                    "event_id": event["event_id"],
                    "event_type": event["event_type"],
                    "to_state": event["to_state"],
                    "to_state_version": event["to_state_version"],
                }
                for event in self.events(execution_id)
            ]
            if canonical_json(fields.get("transition_evidence", [])) != canonical_json(
                expected_transitions
            ):
                raise StoreError("ACCEPTANCE_TRANSITION_EVIDENCE_MISMATCH")
            required = self.connection.execute(
                "SELECT count(*) FROM approval_request WHERE execution_id = ? AND required = 1",
                (execution_id,),
            ).fetchone()[0]
            if required:
                if approval_id is None or approval_authority_ref is None:
                    raise StoreError("APPROVAL_REQUIRED")
                approval = self.get_approval(approval_id)
                expected_approval_ref = canonical_sha256(
                    {
                        "execution_id": execution_id,
                        "state_version": expected_state_version - 1,
                        "result_commit": execution["result_commit"],
                        "evaluation_id": evaluation_id,
                        "contract_fingerprint": execution["contract_fingerprint"],
                        "authority_fingerprint": execution["authority_fingerprint"],
                    }
                )
                if (
                    approval["execution_id"] != execution_id
                    or approval["authority_ref"] != approval_authority_ref
                    or approval_authority_ref != expected_approval_ref
                    or approval["status"] != "APPROVED"
                    or approval["consumed_at"] is not None
                ):
                    raise StoreError("APPROVAL_BINDING_MISMATCH")
                approval_refs = fields.get("approval_refs", [])
                if not any(
                    isinstance(item, dict)
                    and item.get("approval_id") == approval_id
                    and item.get("authority_ref") == approval_authority_ref
                    and item.get("status") == "APPROVED"
                    for item in approval_refs
                ):
                    raise StoreError("APPROVAL_BINDING_MISMATCH")
                updated_approval = self.connection.execute(
                    "UPDATE approval_request SET consumed_at = ? WHERE approval_id = ? AND consumed_at IS NULL",
                    (now, approval_id),
                )
                if updated_approval.rowcount != 1:
                    raise StoreError("APPROVAL_ALREADY_CONSUMED")
            elif approval_id is not None:
                raise StoreError("UNEXPECTED_APPROVAL")
            elif fields.get("approval_refs", []):
                raise StoreError("UNEXPECTED_APPROVAL")
            self.connection.execute(
                """INSERT INTO evidence_manifest(
                    manifest_id, execution_id, slice_id, contract_fingerprint,
                    authority_fingerprint, base_commit, result_commit, maker_attempt_id,
                    verification_id, evaluator_attempt_id, evaluation_id, approval_refs_json,
                    context_fingerprints_json, transition_evidence_json, canonical_json,
                    created_at, manifest_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fields["manifest_id"], execution_id, fields["slice_id"],
                    fields["contract_fingerprint"], fields["authority_fingerprint"],
                    fields["base_commit"], fields["result_commit"], maker_id,
                    verification_id, evaluator_id, evaluation_id,
                    canonical_json(fields.get("approval_refs", [])),
                    canonical_json(fields.get("context_fingerprints", [])),
                    canonical_json(fields.get("transition_evidence", [])),
                    manifest.canonical_json, fields["created_at"], manifest.manifest_sha256,
                ),
            )
            updated = self.connection.execute(
                """UPDATE slice_execution
                      SET state = 'ACCEPTED', resume_state = NULL,
                          state_version = state_version + 1,
                          current_actor_role = 'CONTROLLER', accepted_at = ?, updated_at = ?
                    WHERE execution_id = ? AND state_version = ?
                      AND lease_owner = ? AND lease_generation = ? AND lease_expires_at > ?""",
                (now, now, execution_id, expected_state_version, lease_owner, lease_generation, now),
            )
            if updated.rowcount != 1:
                raise StoreError("STALE_FENCING_TOKEN")
            self._insert_event(
                execution_id=execution_id, operation_key=operation_key,
                event_type="ACCEPTED", from_state=ExecutionState.EVALUATING.value,
                to_state=ExecutionState.ACCEPTED.value,
                from_version=expected_state_version, to_version=expected_state_version + 1,
                actor_role=ActorRole.CONTROLLER, actor_id=actor_id,
                lease_generation=lease_generation, reason_code="EVIDENCE_ACCEPTED",
                reason_detail=None, metadata_json=payload_json, created_at=now,
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.get_execution(execution_id)
