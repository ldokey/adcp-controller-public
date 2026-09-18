"""Deterministic SQLite migration registry through registered schema v10; canonical adoption remains v7."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from functools import lru_cache
import os
from pathlib import Path
import sqlite3

from adcp.domain import StoreError


SCHEMA_VERSION = 7
REGISTERED_SCHEMA_VERSION = 10
MIGRATION_1_NAME = "0001_mvp_a_control_store"
MIGRATION_2_NAME = "0002_slice_control_state"
MIGRATION_3_NAME = "0003_authority_transition_control"
MIGRATION_4_NAME = "0004_deferred_preexecution_binding"
MIGRATION_5_NAME = "0005_prebound_release_invariant"
MIGRATION_6_NAME = "0006_global_production_writer_lease"
MIGRATION_7_NAME = "0007_evaluator_artifact_seal"
MIGRATION_9_NAME = "0009_uncommitted_candidate_review"
MIGRATION_10_NAME = "0010_typed_postgres_operation_receipt_provision_principal"
MIGRATION_8_NAME = "0008_typed_postgres_operation_receipt_event"
# Compatibility aliases for callers that refer to the frozen v1 migration.
MIGRATION_NAME = MIGRATION_1_NAME

SCHEMA_MIGRATION_SQL = """
CREATE TABLE schema_migration (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    checksum TEXT NOT NULL CHECK (length(checksum) = 64),
    applied_at TEXT NOT NULL CHECK (length(applied_at) > 0)
);
"""

MIGRATION_1_SQL = r"""
CREATE TABLE slice_execution (
    execution_id TEXT PRIMARY KEY CHECK (length(execution_id) > 0),
    create_idempotency_key TEXT NOT NULL UNIQUE CHECK (length(create_idempotency_key) = 64),
    slice_id TEXT NOT NULL CHECK (length(slice_id) > 0),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'NORMAL', 'HIGH')),
    environment TEXT NOT NULL CHECK (environment IN ('TEST', 'SHADOW', 'PRODUCTION')),
    state TEXT NOT NULL CHECK (state IN ('READY', 'MAKER_RUNNING', 'VERIFYING', 'EVALUATING', 'REWORK_READY', 'WAITING_APPROVAL', 'BLOCKED', 'DESIGN_ESCALATION', 'ACCEPTED', 'CANCELLED')),
    resume_state TEXT,
    state_version INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint) = 64),
    authority_fingerprint TEXT NOT NULL CHECK (length(authority_fingerprint) = 64),
    source_root TEXT NOT NULL CHECK (length(source_root) > 0),
    branch TEXT NOT NULL CHECK (length(branch) > 0),
    base_commit TEXT NOT NULL CHECK (length(base_commit) IN (40, 64)),
    result_commit TEXT CHECK (result_commit IS NULL OR length(result_commit) IN (40, 64)),
    maker_rework_count INTEGER NOT NULL DEFAULT 0 CHECK (maker_rework_count >= 0),
    max_auto_reworks INTEGER NOT NULL CHECK (max_auto_reworks >= 0),
    current_actor_role TEXT NOT NULL CHECK (current_actor_role IN ('CONTROLLER', 'MAKER', 'EVALUATOR', 'HUMAN')),
    lease_owner TEXT,
    lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at TEXT,
    blocker_code TEXT,
    blocker_detail TEXT CHECK (blocker_detail IS NULL OR length(blocker_detail) <= 2000),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    accepted_at TEXT,
    CHECK (maker_rework_count <= max_auto_reworks),
    CHECK ((risk_level IN ('LOW', 'NORMAL') AND max_auto_reworks = 2) OR (risk_level = 'HIGH' AND max_auto_reworks = 0)),
    CHECK ((state = 'WAITING_APPROVAL' AND resume_state = 'EVALUATING') OR (state = 'BLOCKED' AND resume_state IN ('READY', 'VERIFYING', 'EVALUATING', 'REWORK_READY')) OR (state NOT IN ('WAITING_APPROVAL', 'BLOCKED') AND resume_state IS NULL)),
    CHECK ((lease_owner IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((state = 'ACCEPTED' AND accepted_at IS NOT NULL) OR (state <> 'ACCEPTED' AND accepted_at IS NULL)),
    CHECK (((state IN ('BLOCKED', 'DESIGN_ESCALATION')) AND blocker_code IS NOT NULL) OR (state NOT IN ('BLOCKED', 'DESIGN_ESCALATION') AND blocker_code IS NULL AND blocker_detail IS NULL))
);
CREATE UNIQUE INDEX uq_slice_execution_open ON slice_execution(source_root, slice_id) WHERE state IN ('READY', 'MAKER_RUNNING', 'VERIFYING', 'EVALUATING', 'REWORK_READY', 'WAITING_APPROVAL', 'BLOCKED');
CREATE INDEX idx_slice_execution_state ON slice_execution(state, updated_at);

CREATE TABLE context_snapshot (
    context_snapshot_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('MAKER', 'EVALUATOR')),
    capsule_version INTEGER NOT NULL CHECK (capsule_version > 0),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) > 0),
    created_at TEXT NOT NULL,
    UNIQUE (execution_id, role, fingerprint),
    CONSTRAINT uq_context_snapshot_binding UNIQUE (context_snapshot_id, execution_id, role)
);
CREATE INDEX idx_context_snapshot_execution ON context_snapshot(execution_id, role, created_at);

CREATE TABLE agent_attempt (
    attempt_id TEXT PRIMARY KEY,
    operation_key TEXT NOT NULL UNIQUE CHECK (length(operation_key) = 64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('MAKER', 'EVALUATOR')),
    attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
    model TEXT NOT NULL CHECK (length(model) > 0),
    reasoning_effort TEXT NOT NULL CHECK (length(reasoning_effort) > 0),
    session_mode TEXT NOT NULL CHECK (session_mode = 'FRESH'),
    session_id TEXT NOT NULL UNIQUE CHECK (length(session_id) > 0),
    sandbox_mode TEXT NOT NULL CHECK (sandbox_mode IN ('workspace-write', 'read-only')),
    context_snapshot_id TEXT NOT NULL REFERENCES context_snapshot(context_snapshot_id),
    base_commit TEXT NOT NULL CHECK (length(base_commit) IN (40, 64)),
    result_commit TEXT CHECK (result_commit IS NULL OR length(result_commit) IN (40, 64)),
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'SUCCEEDED', 'FAILED', 'ABORTED', 'LOST')),
    exit_code INTEGER,
    stdout_artifact TEXT,
    stdout_sha256 TEXT CHECK (stdout_sha256 IS NULL OR length(stdout_sha256) = 64),
    stderr_artifact TEXT,
    stderr_sha256 TEXT CHECK (stderr_sha256 IS NULL OR length(stderr_sha256) = 64),
    result_artifact TEXT,
    result_sha256 TEXT CHECK (result_sha256 IS NULL OR length(result_sha256) = 64),
    failure_code TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE (execution_id, role, attempt_no),
    CONSTRAINT uq_agent_attempt_execution UNIQUE (attempt_id, execution_id),
    CONSTRAINT uq_agent_attempt_execution_context UNIQUE (attempt_id, execution_id, context_snapshot_id),
    CONSTRAINT fk_agent_attempt_context_binding FOREIGN KEY (context_snapshot_id, execution_id, role) REFERENCES context_snapshot (context_snapshot_id, execution_id, role) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK ((role = 'MAKER' AND sandbox_mode = 'workspace-write') OR (role = 'EVALUATOR' AND sandbox_mode = 'read-only')),
    CHECK ((status = 'RUNNING' AND ended_at IS NULL) OR (status <> 'RUNNING' AND ended_at IS NOT NULL)),
    CHECK (role <> 'EVALUATOR' OR result_commit IS NOT NULL)
);
CREATE INDEX idx_agent_attempt_execution ON agent_attempt(execution_id, role, attempt_no);

CREATE TABLE transition_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    operation_key TEXT NOT NULL CHECK (length(operation_key) = 64),
    event_type TEXT NOT NULL CHECK (event_type IN ('EXECUTION_CREATED', 'STATE_TRANSITION', 'LEASE_ACQUIRED', 'LEASE_RELEASED', 'RESULT_COMMIT_REGISTERED', 'ACCEPTED')),
    from_state TEXT,
    to_state TEXT NOT NULL,
    from_state_version INTEGER NOT NULL,
    to_state_version INTEGER NOT NULL,
    actor_role TEXT NOT NULL CHECK (actor_role IN ('CONTROLLER', 'MAKER', 'EVALUATOR', 'HUMAN')),
    actor_id TEXT NOT NULL,
    lease_generation INTEGER NOT NULL CHECK (lease_generation >= 0),
    reason_code TEXT NOT NULL,
    reason_detail TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE (execution_id, operation_key),
    UNIQUE (execution_id, to_state_version),
    CHECK ((event_type = 'EXECUTION_CREATED' AND from_state IS NULL AND from_state_version = -1 AND to_state = 'READY' AND to_state_version = 0) OR (event_type <> 'EXECUTION_CREATED' AND from_state IS NOT NULL AND to_state_version = from_state_version + 1))
);
CREATE INDEX idx_transition_event_execution ON transition_event(execution_id, event_seq);

CREATE TABLE verification_result (
    verification_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    verification_id TEXT NOT NULL UNIQUE,
    operation_key TEXT NOT NULL UNIQUE CHECK (length(operation_key) = 64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    result_commit TEXT NOT NULL CHECK (length(result_commit) IN (40, 64)),
    contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint) = 64),
    authority_fingerprint TEXT NOT NULL CHECK (length(authority_fingerprint) = 64),
    verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'BLOCKED_ENVIRONMENT')),
    command_manifest TEXT NOT NULL,
    command_manifest_sha256 TEXT NOT NULL CHECK (length(command_manifest_sha256) = 64),
    result_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    CONSTRAINT uq_verification_manifest_binding UNIQUE (verification_id, execution_id, result_commit, contract_fingerprint, authority_fingerprint)
);
CREATE INDEX idx_verification_binding ON verification_result(execution_id, result_commit, contract_fingerprint, authority_fingerprint, verification_seq);

CREATE TABLE evaluation_result (
    evaluation_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id TEXT NOT NULL UNIQUE,
    operation_key TEXT NOT NULL UNIQUE CHECK (length(operation_key) = 64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    evaluator_attempt_id TEXT NOT NULL UNIQUE REFERENCES agent_attempt(attempt_id),
    context_snapshot_id TEXT NOT NULL REFERENCES context_snapshot(context_snapshot_id),
    result_commit TEXT NOT NULL CHECK (length(result_commit) IN (40, 64)),
    contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint) = 64),
    authority_fingerprint TEXT NOT NULL CHECK (length(authority_fingerprint) = 64),
    verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'REWORK_REQUIRED', 'DESIGN_REVIEW_REQUIRED', 'BLOCKED_ENVIRONMENT', 'BLOCKED_EVIDENCE')),
    result_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    CONSTRAINT uq_evaluation_manifest_binding UNIQUE (evaluation_id, execution_id, evaluator_attempt_id, result_commit, contract_fingerprint, authority_fingerprint),
    CONSTRAINT fk_evaluation_attempt_binding FOREIGN KEY (evaluator_attempt_id, execution_id, context_snapshot_id) REFERENCES agent_attempt (attempt_id, execution_id, context_snapshot_id) ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE INDEX idx_evaluation_binding ON evaluation_result(execution_id, result_commit, contract_fingerprint, authority_fingerprint, evaluation_seq);

CREATE TABLE approval_request (
    approval_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) = 64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE CASCADE,
    approval_type TEXT NOT NULL CHECK (length(approval_type) > 0),
    required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),
    authority_ref TEXT NOT NULL CHECK (length(authority_ref) > 0),
    requested_at TEXT NOT NULL,
    resolved_at TEXT,
    consumed_at TEXT,
    UNIQUE (execution_id, approval_type, authority_ref),
    CHECK ((status = 'PENDING' AND resolved_at IS NULL AND consumed_at IS NULL) OR (status = 'APPROVED' AND resolved_at IS NOT NULL) OR (status IN ('REJECTED', 'CANCELLED') AND resolved_at IS NOT NULL AND consumed_at IS NULL))
);
CREATE INDEX idx_approval_request_execution ON approval_request(execution_id, status, required);

CREATE TABLE evidence_manifest (
    manifest_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    slice_id TEXT NOT NULL,
    contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint) = 64),
    authority_fingerprint TEXT NOT NULL CHECK (length(authority_fingerprint) = 64),
    base_commit TEXT NOT NULL CHECK (length(base_commit) IN (40, 64)),
    result_commit TEXT NOT NULL CHECK (length(result_commit) IN (40, 64)),
    maker_attempt_id TEXT NOT NULL REFERENCES agent_attempt(attempt_id),
    verification_id TEXT NOT NULL REFERENCES verification_result(verification_id),
    evaluator_attempt_id TEXT NOT NULL REFERENCES agent_attempt(attempt_id),
    evaluation_id TEXT NOT NULL REFERENCES evaluation_result(evaluation_id),
    approval_refs_json TEXT NOT NULL,
    context_fingerprints_json TEXT NOT NULL,
    transition_evidence_json TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL UNIQUE CHECK (length(manifest_sha256) = 64),
    CONSTRAINT fk_manifest_maker_attempt FOREIGN KEY (maker_attempt_id, execution_id) REFERENCES agent_attempt (attempt_id, execution_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_manifest_verification FOREIGN KEY (verification_id, execution_id, result_commit, contract_fingerprint, authority_fingerprint) REFERENCES verification_result (verification_id, execution_id, result_commit, contract_fingerprint, authority_fingerprint) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_manifest_evaluation FOREIGN KEY (evaluation_id, execution_id, evaluator_attempt_id, result_commit, contract_fingerprint, authority_fingerprint) REFERENCES evaluation_result (evaluation_id, execution_id, evaluator_attempt_id, result_commit, contract_fingerprint, authority_fingerprint) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE projection_record (
    projection_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    manifest_id TEXT NOT NULL REFERENCES evidence_manifest(manifest_id) ON DELETE RESTRICT,
    target_type TEXT NOT NULL CHECK (length(target_type) > 0),
    target_ref TEXT NOT NULL CHECK (length(target_ref) > 0),
    projection_version INTEGER NOT NULL CHECK (projection_version > 0),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'SUCCEEDED', 'FAILED')),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) = 64),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error TEXT,
    created_at TEXT NOT NULL,
    last_attempt_at TEXT,
    next_attempt_at TEXT,
    projected_at TEXT,
    UNIQUE (execution_id, target_type, target_ref, projection_version),
    CHECK ((status = 'SUCCEEDED' AND projected_at IS NOT NULL) OR (status <> 'SUCCEEDED' AND projected_at IS NULL))
);
CREATE INDEX idx_projection_retry ON projection_record(status, next_attempt_at, created_at);

CREATE TRIGGER context_snapshot_immutable_update BEFORE UPDATE ON context_snapshot BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER context_snapshot_immutable_delete BEFORE DELETE ON context_snapshot BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER transition_event_immutable_update BEFORE UPDATE ON transition_event BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER transition_event_immutable_delete BEFORE DELETE ON transition_event BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER verification_result_immutable_update BEFORE UPDATE ON verification_result BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER verification_result_immutable_delete BEFORE DELETE ON verification_result BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER evaluation_result_immutable_update BEFORE UPDATE ON evaluation_result BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER evaluation_result_immutable_delete BEFORE DELETE ON evaluation_result BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER evidence_manifest_immutable_update BEFORE UPDATE ON evidence_manifest BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;
CREATE TRIGGER evidence_manifest_immutable_delete BEFORE DELETE ON evidence_manifest BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECORD'); END;

CREATE TRIGGER evaluation_result_require_evaluator_insert
BEFORE INSERT ON evaluation_result
WHEN NOT EXISTS (SELECT 1 FROM agent_attempt AS attempt WHERE attempt.attempt_id = NEW.evaluator_attempt_id AND attempt.execution_id = NEW.execution_id AND attempt.context_snapshot_id = NEW.context_snapshot_id AND attempt.role = 'EVALUATOR')
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_ATTEMPT_REQUIRED'); END;
CREATE TRIGGER evaluation_result_require_evaluator_update
BEFORE UPDATE OF evaluator_attempt_id, execution_id, context_snapshot_id ON evaluation_result
WHEN NOT EXISTS (SELECT 1 FROM agent_attempt AS attempt WHERE attempt.attempt_id = NEW.evaluator_attempt_id AND attempt.execution_id = NEW.execution_id AND attempt.context_snapshot_id = NEW.context_snapshot_id AND attempt.role = 'EVALUATOR')
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_ATTEMPT_REQUIRED'); END;

CREATE TRIGGER evidence_manifest_require_succeeded_attempts
BEFORE INSERT ON evidence_manifest
WHEN NOT EXISTS (SELECT 1 FROM agent_attempt WHERE attempt_id = NEW.maker_attempt_id AND execution_id = NEW.execution_id AND role = 'MAKER' AND status = 'SUCCEEDED')
 OR NOT EXISTS (SELECT 1 FROM agent_attempt WHERE attempt_id = NEW.evaluator_attempt_id AND execution_id = NEW.execution_id AND role = 'EVALUATOR' AND status = 'SUCCEEDED')
BEGIN SELECT RAISE(ABORT, 'EVIDENCE_ATTEMPT_BINDING_MISMATCH'); END;

CREATE TRIGGER agent_attempt_running_finish_only
BEFORE UPDATE ON agent_attempt
WHEN OLD.status = 'RUNNING' AND COALESCE(NEW.status, '') NOT IN ('SUCCEEDED', 'FAILED', 'ABORTED', 'LOST')
BEGIN SELECT RAISE(ABORT, 'INVALID_AGENT_ATTEMPT_TRANSITION'); END;
CREATE TRIGGER agent_attempt_identity_immutable
BEFORE UPDATE OF attempt_id, operation_key, execution_id, role, attempt_no, model, reasoning_effort, session_mode, session_id, sandbox_mode, context_snapshot_id, base_commit, started_at ON agent_attempt
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AGENT_ATTEMPT'); END;
CREATE TRIGGER agent_attempt_terminal_immutable
BEFORE UPDATE ON agent_attempt WHEN OLD.status <> 'RUNNING'
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AGENT_ATTEMPT'); END;
CREATE TRIGGER agent_attempt_delete_forbidden
BEFORE DELETE ON agent_attempt
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AGENT_ATTEMPT'); END;
"""

MIGRATION_2_SQL = r"""
CREATE TABLE slice_control_state (
    slice_id TEXT PRIMARY KEY CHECK (length(slice_id) > 0),
    stage TEXT NOT NULL CHECK (length(stage) > 0),
    status TEXT NOT NULL CHECK (length(status) > 0),
    authority_fingerprint TEXT NOT NULL CHECK (
        length(authority_fingerprint) = 64
        AND authority_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    migration_class TEXT NOT NULL CHECK (
        migration_class IN ('MIGRATE_AS_READY_CURRENT_STATE', 'DEFER_BINDING', 'DEFER_PREREQUISITE')
    ),
    execution_eligibility TEXT NOT NULL CHECK (
        execution_eligibility IN (
            'ELIGIBLE_BOUND',
            'INELIGIBLE_UNTIL_PREFLIGHT',
            'INELIGIBLE_UNTIL_PREREQUISITE'
        )
    ),
    defer_reason TEXT CHECK (defer_reason IS NULL OR length(defer_reason) > 0),
    logical_source_root TEXT NOT NULL CHECK (length(logical_source_root) > 0),
    repository_toplevel TEXT CHECK (repository_toplevel IS NULL OR length(repository_toplevel) > 0),
    branch TEXT CHECK (branch IS NULL OR length(branch) > 0),
    base_commit TEXT CHECK (
        base_commit IS NULL OR (
            length(base_commit) IN (40, 64) AND base_commit NOT GLOB '*[^0-9a-f]*'
        )
    ),
    implementation_result_commit TEXT CHECK (
        implementation_result_commit IS NULL OR (
            length(implementation_result_commit) IN (40, 64)
            AND implementation_result_commit NOT GLOB '*[^0-9a-f]*'
        )
    ),
    current_branch_head TEXT CHECK (
        current_branch_head IS NULL OR (
            length(current_branch_head) IN (40, 64)
            AND current_branch_head NOT GLOB '*[^0-9a-f]*'
        )
    ),
    active_execution_id TEXT REFERENCES slice_execution(execution_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    CHECK (
        (migration_class = 'MIGRATE_AS_READY_CURRENT_STATE'
         AND execution_eligibility = 'ELIGIBLE_BOUND'
         AND defer_reason IS NULL
         AND repository_toplevel IS NOT NULL
         AND branch IS NOT NULL
         AND base_commit IS NOT NULL
         AND implementation_result_commit IS NOT NULL
         AND current_branch_head IS NOT NULL
         AND active_execution_id IS NOT NULL)
        OR
        (migration_class = 'DEFER_BINDING'
         AND execution_eligibility = 'INELIGIBLE_UNTIL_PREFLIGHT'
         AND defer_reason IS NOT NULL
         AND base_commit IS NULL
         AND implementation_result_commit IS NULL
         AND current_branch_head IS NULL
         AND active_execution_id IS NULL)
        OR
        (migration_class = 'DEFER_PREREQUISITE'
         AND execution_eligibility = 'INELIGIBLE_UNTIL_PREREQUISITE'
         AND defer_reason IS NOT NULL
         AND base_commit IS NULL
         AND implementation_result_commit IS NULL
         AND current_branch_head IS NULL
         AND active_execution_id IS NULL)
    )
);
CREATE INDEX idx_slice_control_state_status
ON slice_control_state(stage, status, execution_eligibility, slice_id);

CREATE TABLE slice_control_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key TEXT NOT NULL UNIQUE CHECK (
        length(operation_key) = 64 AND operation_key NOT GLOB '*[^0-9a-f]*'
    ),
    slice_id TEXT NOT NULL REFERENCES slice_control_state(slice_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    from_state_version INTEGER NOT NULL CHECK (from_state_version >= -1),
    to_state_version INTEGER NOT NULL CHECK (to_state_version >= 0),
    reason_code TEXT NOT NULL CHECK (length(reason_code) > 0),
    metadata_json TEXT NOT NULL CHECK (length(metadata_json) > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (slice_id, to_state_version),
    CHECK (to_state_version = from_state_version + 1)
);
CREATE INDEX idx_slice_control_event_slice
ON slice_control_event(slice_id, event_seq);

CREATE TABLE control_authority_state (
    singleton_id TEXT PRIMARY KEY CHECK (singleton_id = 'GLOBAL'),
    mode TEXT NOT NULL CHECK (mode IN ('TRANSITIONAL_AUTHORITY', 'CONTROL_STORE_AUTHORITY')),
    authority_generation INTEGER NOT NULL CHECK (authority_generation >= 0),
    cutover_id TEXT CHECK (cutover_id IS NULL OR length(cutover_id) > 0),
    slice_snapshot_fingerprint TEXT NOT NULL CHECK (
        length(slice_snapshot_fingerprint) = 64
        AND slice_snapshot_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    rollback_snapshot_fingerprint TEXT NOT NULL CHECK (
        length(rollback_snapshot_fingerprint) = 64
        AND rollback_snapshot_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    switched_at TEXT,
    CHECK (
        (mode = 'TRANSITIONAL_AUTHORITY' AND cutover_id IS NULL AND switched_at IS NULL)
        OR
        (mode = 'CONTROL_STORE_AUTHORITY' AND cutover_id IS NOT NULL AND switched_at IS NOT NULL)
    )
);

INSERT INTO control_authority_state(
    singleton_id, mode, authority_generation, cutover_id,
    slice_snapshot_fingerprint, rollback_snapshot_fingerprint, updated_at, switched_at
) VALUES (
    'GLOBAL', 'TRANSITIONAL_AUTHORITY', 0, NULL,
    '4037d3d9c28b4d9e20010370539058384d6dba0566c89901895f0d6ff702d518',
    '45ef2ee50e7393592e766ecf0b16d51a59f130c571d213c70e033e6119b565f9',
    '1970-01-01T00:00:00.000000+00:00', NULL
);

CREATE TRIGGER slice_control_event_immutable_update
BEFORE UPDATE ON slice_control_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_EVENT'); END;
CREATE TRIGGER slice_control_event_immutable_delete
BEFORE DELETE ON slice_control_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_EVENT'); END;

CREATE TRIGGER slice_control_event_monotonic_insert
BEFORE INSERT ON slice_control_event
WHEN (NEW.from_state_version = -1 AND (
        NEW.to_state_version <> 0
        OR EXISTS (SELECT 1 FROM slice_control_state WHERE slice_id = NEW.slice_id)
        OR EXISTS (SELECT 1 FROM slice_control_event WHERE slice_id = NEW.slice_id)
    ))
 OR (NEW.from_state_version >= 0 AND (
        NOT EXISTS (
            SELECT 1 FROM slice_control_state
            WHERE slice_id = NEW.slice_id AND state_version = NEW.from_state_version
        )
        OR NOT EXISTS (
            SELECT 1 FROM slice_control_event
            WHERE slice_id = NEW.slice_id AND to_state_version = NEW.from_state_version
        )
    ))
BEGIN SELECT RAISE(ABORT, 'CONTROL_EVENT_VERSION_MISMATCH'); END;

CREATE TRIGGER slice_control_state_event_required_insert
BEFORE INSERT ON slice_control_state
WHEN NOT EXISTS (
    SELECT 1 FROM slice_control_event
    WHERE slice_id = NEW.slice_id AND from_state_version = -1 AND to_state_version = 0
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_EVENT_REQUIRED'); END;

CREATE TRIGGER slice_control_state_version_monotonic
BEFORE UPDATE ON slice_control_state
WHEN NEW.state_version <> OLD.state_version + 1
 OR NOT EXISTS (
    SELECT 1 FROM slice_control_event
    WHERE slice_id = NEW.slice_id
      AND from_state_version = OLD.state_version
      AND to_state_version = NEW.state_version
 )
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_VERSION_MISMATCH'); END;

CREATE TRIGGER slice_control_state_identity_immutable
BEFORE UPDATE OF slice_id, created_at ON slice_control_state
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_STATE_IDENTITY'); END;

CREATE TRIGGER slice_control_state_delete_forbidden
BEFORE DELETE ON slice_control_state
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_DELETE_FORBIDDEN'); END;

CREATE TRIGGER slice_control_state_rebinding_forbidden
BEFORE UPDATE OF active_execution_id ON slice_control_state
WHEN OLD.active_execution_id IS NOT NULL
 AND NEW.active_execution_id IS NOT OLD.active_execution_id
BEGIN SELECT RAISE(ABORT, 'ACTIVE_EXECUTION_REBIND_FORBIDDEN'); END;

CREATE TRIGGER slice_control_state_execution_binding_insert
BEFORE INSERT ON slice_control_state
WHEN NEW.active_execution_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM slice_execution AS execution
    WHERE execution.execution_id = NEW.active_execution_id
      AND execution.slice_id = NEW.slice_id
      AND execution.source_root = NEW.repository_toplevel
      AND execution.branch = NEW.branch
      AND execution.base_commit = NEW.base_commit
      AND execution.result_commit = NEW.implementation_result_commit
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_EXECUTION_BINDING_MISMATCH'); END;

CREATE TRIGGER slice_control_state_execution_binding_update
BEFORE UPDATE ON slice_control_state
WHEN NEW.active_execution_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM slice_execution AS execution
    WHERE execution.execution_id = NEW.active_execution_id
      AND execution.slice_id = NEW.slice_id
      AND execution.source_root = NEW.repository_toplevel
      AND execution.branch = NEW.branch
      AND execution.base_commit = NEW.base_commit
      AND execution.result_commit = NEW.implementation_result_commit
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_EXECUTION_BINDING_MISMATCH'); END;

CREATE TRIGGER control_authority_state_insert_forbidden
BEFORE INSERT ON control_authority_state
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_SINGLETON_EXISTS'); END;
CREATE TRIGGER control_authority_state_delete_forbidden
BEFORE DELETE ON control_authority_state
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_SINGLETON_IMMUTABLE'); END;
CREATE TRIGGER control_authority_state_e1_switch_forbidden
BEFORE UPDATE ON control_authority_state
WHEN NEW.mode <> 'TRANSITIONAL_AUTHORITY'
 OR NEW.mode <> OLD.mode
 OR NEW.cutover_id IS NOT NULL
 OR NEW.switched_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_SWITCH_FORBIDDEN_BY_E1'); END;
CREATE TRIGGER control_authority_state_generation_monotonic
BEFORE UPDATE ON control_authority_state
WHEN NEW.singleton_id <> OLD.singleton_id
 OR NEW.authority_generation <> OLD.authority_generation + 1
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_GENERATION_CONFLICT'); END;
"""

MIGRATION_3_SQL = r"""
DROP TRIGGER control_authority_state_e1_switch_forbidden;
DROP TRIGGER control_authority_state_generation_monotonic;

CREATE TABLE authority_transition_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(trim(event_id)) > 0),
    operation_key TEXT NOT NULL UNIQUE CHECK (
        length(operation_key) = 64 AND operation_key NOT GLOB '*[^0-9a-f]*'
    ),
    cutover_id TEXT NOT NULL CHECK (length(trim(cutover_id)) > 0),
    event_type TEXT NOT NULL CHECK (
        event_type IN ('AUTHORITY_SWITCH', 'AUTHORITY_ROLLBACK')
    ),
    from_mode TEXT NOT NULL CHECK (
        from_mode IN ('TRANSITIONAL_AUTHORITY', 'CONTROL_STORE_AUTHORITY')
    ),
    to_mode TEXT NOT NULL CHECK (
        to_mode IN ('TRANSITIONAL_AUTHORITY', 'CONTROL_STORE_AUTHORITY')
    ),
    from_generation INTEGER NOT NULL CHECK (from_generation >= 0),
    to_generation INTEGER NOT NULL CHECK (to_generation = from_generation + 1),
    slice_snapshot_fingerprint TEXT NOT NULL CHECK (
        length(slice_snapshot_fingerprint) = 64
        AND slice_snapshot_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    rollback_snapshot_fingerprint TEXT NOT NULL CHECK (
        length(rollback_snapshot_fingerprint) = 64
        AND rollback_snapshot_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    human_decision_ref TEXT NOT NULL CHECK (length(trim(human_decision_ref)) > 0),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    UNIQUE (from_generation),
    UNIQUE (to_generation),
    UNIQUE (cutover_id, event_type),
    CHECK (
        (event_type = 'AUTHORITY_SWITCH'
         AND from_mode = 'TRANSITIONAL_AUTHORITY'
         AND to_mode = 'CONTROL_STORE_AUTHORITY')
        OR
        (event_type = 'AUTHORITY_ROLLBACK'
         AND from_mode = 'CONTROL_STORE_AUTHORITY'
         AND to_mode = 'TRANSITIONAL_AUTHORITY')
    )
);
CREATE INDEX idx_authority_transition_event_cutover
ON authority_transition_event(cutover_id, event_seq);

CREATE TRIGGER authority_transition_event_immutable_update
BEFORE UPDATE ON authority_transition_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AUTHORITY_EVENT'); END;
CREATE TRIGGER authority_transition_event_immutable_delete
BEFORE DELETE ON authority_transition_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AUTHORITY_EVENT'); END;

CREATE TRIGGER authority_transition_event_state_guard
BEFORE INSERT ON authority_transition_event
WHEN NOT EXISTS (
    SELECT 1
    FROM control_authority_state AS authority
    WHERE authority.singleton_id = 'GLOBAL'
      AND authority.mode = NEW.from_mode
      AND authority.authority_generation = NEW.from_generation
      AND authority.slice_snapshot_fingerprint = NEW.slice_snapshot_fingerprint
      AND authority.rollback_snapshot_fingerprint = NEW.rollback_snapshot_fingerprint
      AND (
          (NEW.event_type = 'AUTHORITY_SWITCH'
           AND authority.cutover_id IS NULL
           AND authority.switched_at IS NULL)
          OR
          (NEW.event_type = 'AUTHORITY_ROLLBACK'
           AND authority.cutover_id = NEW.cutover_id
           AND authority.switched_at IS NOT NULL)
      )
)
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_TRANSITION_STATE_MISMATCH'); END;

CREATE TRIGGER authority_transition_event_apply
AFTER INSERT ON authority_transition_event
BEGIN
    UPDATE control_authority_state
       SET mode = NEW.to_mode,
           authority_generation = NEW.to_generation,
           cutover_id = CASE
               WHEN NEW.event_type = 'AUTHORITY_SWITCH' THEN NEW.cutover_id
               ELSE NULL
           END,
           switched_at = CASE
               WHEN NEW.event_type = 'AUTHORITY_SWITCH' THEN NEW.created_at
               ELSE NULL
           END,
           updated_at = NEW.created_at
     WHERE singleton_id = 'GLOBAL';
END;

CREATE TRIGGER control_authority_state_transition_guard
BEFORE UPDATE ON control_authority_state
WHEN NOT (
        OLD.mode = 'TRANSITIONAL_AUTHORITY'
        AND NEW.mode = OLD.mode
        AND NEW.cutover_id IS OLD.cutover_id
        AND NEW.switched_at IS OLD.switched_at
     )
 AND NOT EXISTS (
    SELECT 1
    FROM authority_transition_event AS event
    WHERE event.from_mode = OLD.mode
      AND event.to_mode = NEW.mode
      AND event.from_generation = OLD.authority_generation
      AND event.to_generation = NEW.authority_generation
      AND event.slice_snapshot_fingerprint = OLD.slice_snapshot_fingerprint
      AND event.slice_snapshot_fingerprint = NEW.slice_snapshot_fingerprint
      AND event.rollback_snapshot_fingerprint = OLD.rollback_snapshot_fingerprint
      AND event.rollback_snapshot_fingerprint = NEW.rollback_snapshot_fingerprint
      AND event.created_at = NEW.updated_at
      AND (
          (event.event_type = 'AUTHORITY_SWITCH'
           AND OLD.cutover_id IS NULL
           AND OLD.switched_at IS NULL
           AND NEW.cutover_id = event.cutover_id
           AND NEW.switched_at = event.created_at)
          OR
          (event.event_type = 'AUTHORITY_ROLLBACK'
           AND OLD.cutover_id = event.cutover_id
           AND OLD.switched_at IS NOT NULL
           AND NEW.cutover_id IS NULL
           AND NEW.switched_at IS NULL)
      )
 )
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_TRANSITION_EVENT_REQUIRED'); END;

CREATE TRIGGER control_authority_state_generation_monotonic
BEFORE UPDATE ON control_authority_state
WHEN NEW.singleton_id <> OLD.singleton_id
 OR NEW.authority_generation <> OLD.authority_generation + 1
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_GENERATION_CONFLICT'); END;
"""

MIGRATION_4_SQL = r"""
DROP TRIGGER slice_control_event_immutable_update;
DROP TRIGGER slice_control_event_immutable_delete;
DROP TRIGGER slice_control_event_monotonic_insert;
DROP TRIGGER slice_control_state_event_required_insert;
DROP TRIGGER slice_control_state_version_monotonic;
DROP TRIGGER slice_control_state_identity_immutable;
DROP TRIGGER slice_control_state_delete_forbidden;
DROP TRIGGER slice_control_state_rebinding_forbidden;
DROP TRIGGER slice_control_state_execution_binding_insert;
DROP TRIGGER slice_control_state_execution_binding_update;

ALTER TABLE slice_control_event RENAME TO slice_control_event_v3;
ALTER TABLE slice_control_state RENAME TO slice_control_state_v3;

CREATE TABLE slice_control_state (
    slice_id TEXT PRIMARY KEY CHECK (length(slice_id) > 0),
    stage TEXT NOT NULL CHECK (length(stage) > 0),
    status TEXT NOT NULL CHECK (length(status) > 0),
    authority_fingerprint TEXT NOT NULL CHECK (
        length(authority_fingerprint) = 64
        AND authority_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    migration_class TEXT NOT NULL CHECK (
        migration_class IN ('MIGRATE_AS_READY_CURRENT_STATE', 'DEFER_BINDING', 'DEFER_PREREQUISITE')
    ),
    execution_eligibility TEXT NOT NULL CHECK (
        execution_eligibility IN (
            'ELIGIBLE_BOUND',
            'ELIGIBLE_PREEXECUTION_BOUND',
            'INELIGIBLE_UNTIL_PREFLIGHT',
            'INELIGIBLE_UNTIL_PREREQUISITE'
        )
    ),
    defer_reason TEXT CHECK (defer_reason IS NULL OR length(defer_reason) > 0),
    logical_source_root TEXT NOT NULL CHECK (length(logical_source_root) > 0),
    repository_toplevel TEXT CHECK (repository_toplevel IS NULL OR length(repository_toplevel) > 0),
    branch TEXT CHECK (branch IS NULL OR length(branch) > 0),
    base_commit TEXT CHECK (
        base_commit IS NULL OR (
            length(base_commit) IN (40, 64) AND base_commit NOT GLOB '*[^0-9a-f]*'
        )
    ),
    implementation_result_commit TEXT CHECK (
        implementation_result_commit IS NULL OR (
            length(implementation_result_commit) IN (40, 64)
            AND implementation_result_commit NOT GLOB '*[^0-9a-f]*'
        )
    ),
    current_branch_head TEXT CHECK (
        current_branch_head IS NULL OR (
            length(current_branch_head) IN (40, 64)
            AND current_branch_head NOT GLOB '*[^0-9a-f]*'
        )
    ),
    active_execution_id TEXT REFERENCES slice_execution(execution_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    CHECK (
        (migration_class = 'MIGRATE_AS_READY_CURRENT_STATE'
         AND execution_eligibility = 'ELIGIBLE_BOUND'
         AND defer_reason IS NULL
         AND repository_toplevel IS NOT NULL
         AND branch IS NOT NULL
         AND base_commit IS NOT NULL
         AND implementation_result_commit IS NOT NULL
         AND current_branch_head IS NOT NULL
         AND active_execution_id IS NOT NULL)
        OR
        (migration_class = 'DEFER_BINDING'
         AND execution_eligibility = 'INELIGIBLE_UNTIL_PREFLIGHT'
         AND defer_reason IS NOT NULL
         AND base_commit IS NULL
         AND implementation_result_commit IS NULL
         AND current_branch_head IS NULL
         AND active_execution_id IS NULL)
        OR
        (migration_class = 'DEFER_BINDING'
         AND execution_eligibility = 'ELIGIBLE_PREEXECUTION_BOUND'
         AND defer_reason IS NULL
         AND repository_toplevel IS NOT NULL
         AND branch IS NOT NULL
         AND base_commit IS NOT NULL
         AND implementation_result_commit IS NULL
         AND current_branch_head = base_commit
         AND active_execution_id IS NOT NULL)
        OR
        (migration_class = 'DEFER_BINDING'
         AND execution_eligibility = 'ELIGIBLE_BOUND'
         AND defer_reason IS NULL
         AND repository_toplevel IS NOT NULL
         AND branch IS NOT NULL
         AND base_commit IS NOT NULL
         AND implementation_result_commit IS NOT NULL
         AND current_branch_head = implementation_result_commit
         AND active_execution_id IS NOT NULL)
        OR
        (migration_class = 'DEFER_PREREQUISITE'
         AND execution_eligibility = 'INELIGIBLE_UNTIL_PREREQUISITE'
         AND defer_reason IS NOT NULL
         AND base_commit IS NULL
         AND implementation_result_commit IS NULL
         AND current_branch_head IS NULL
         AND active_execution_id IS NULL)
    )
);

CREATE TABLE slice_control_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_key TEXT NOT NULL UNIQUE CHECK (
        length(operation_key) = 64 AND operation_key NOT GLOB '*[^0-9a-f]*'
    ),
    slice_id TEXT NOT NULL REFERENCES slice_control_state(slice_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    from_state_version INTEGER NOT NULL CHECK (from_state_version >= -1),
    to_state_version INTEGER NOT NULL CHECK (to_state_version >= 0),
    reason_code TEXT NOT NULL CHECK (length(reason_code) > 0),
    metadata_json TEXT NOT NULL CHECK (length(metadata_json) > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (slice_id, to_state_version),
    CHECK (to_state_version = from_state_version + 1)
);

INSERT INTO slice_control_state(
    slice_id, stage, status, authority_fingerprint, migration_class,
    execution_eligibility, defer_reason, logical_source_root,
    repository_toplevel, branch, base_commit, implementation_result_commit,
    current_branch_head, active_execution_id, state_version, created_at, updated_at
)
SELECT
    slice_id, stage, status, authority_fingerprint, migration_class,
    execution_eligibility, defer_reason, logical_source_root,
    repository_toplevel, branch, base_commit, implementation_result_commit,
    current_branch_head, active_execution_id, state_version, created_at, updated_at
FROM slice_control_state_v3;

INSERT INTO slice_control_event(
    event_seq, operation_key, slice_id, from_state_version, to_state_version,
    reason_code, metadata_json, created_at
)
SELECT
    event_seq, operation_key, slice_id, from_state_version, to_state_version,
    reason_code, metadata_json, created_at
FROM slice_control_event_v3;

DROP TABLE slice_control_event_v3;
DROP TABLE slice_control_state_v3;

CREATE INDEX idx_slice_control_state_status
ON slice_control_state(stage, status, execution_eligibility, slice_id);
CREATE INDEX idx_slice_control_event_slice
ON slice_control_event(slice_id, event_seq);

CREATE TRIGGER slice_control_event_immutable_update
BEFORE UPDATE ON slice_control_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_EVENT'); END;
CREATE TRIGGER slice_control_event_immutable_delete
BEFORE DELETE ON slice_control_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_EVENT'); END;

CREATE TRIGGER slice_control_event_monotonic_insert
BEFORE INSERT ON slice_control_event
WHEN (NEW.from_state_version = -1 AND (
        NEW.to_state_version <> 0
        OR EXISTS (SELECT 1 FROM slice_control_state WHERE slice_id = NEW.slice_id)
        OR EXISTS (SELECT 1 FROM slice_control_event WHERE slice_id = NEW.slice_id)
    ))
 OR (NEW.from_state_version >= 0 AND (
        NOT EXISTS (
            SELECT 1 FROM slice_control_state
            WHERE slice_id = NEW.slice_id AND state_version = NEW.from_state_version
        )
        OR NOT EXISTS (
            SELECT 1 FROM slice_control_event
            WHERE slice_id = NEW.slice_id AND to_state_version = NEW.from_state_version
        )
    ))
BEGIN SELECT RAISE(ABORT, 'CONTROL_EVENT_VERSION_MISMATCH'); END;

CREATE TRIGGER slice_control_state_event_required_insert
BEFORE INSERT ON slice_control_state
WHEN NOT EXISTS (
    SELECT 1 FROM slice_control_event
    WHERE slice_id = NEW.slice_id AND from_state_version = -1 AND to_state_version = 0
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_EVENT_REQUIRED'); END;

CREATE TRIGGER slice_control_state_version_monotonic
BEFORE UPDATE ON slice_control_state
WHEN NEW.state_version <> OLD.state_version + 1
 OR NOT EXISTS (
    SELECT 1 FROM slice_control_event
    WHERE slice_id = NEW.slice_id
      AND from_state_version = OLD.state_version
      AND to_state_version = NEW.state_version
 )
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_VERSION_MISMATCH'); END;

CREATE TRIGGER slice_control_state_identity_immutable
BEFORE UPDATE OF slice_id, created_at ON slice_control_state
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CONTROL_STATE_IDENTITY'); END;

CREATE TRIGGER slice_control_state_delete_forbidden
BEFORE DELETE ON slice_control_state
BEGIN SELECT RAISE(ABORT, 'CONTROL_STATE_DELETE_FORBIDDEN'); END;

CREATE TRIGGER slice_control_state_rebinding_forbidden
BEFORE UPDATE OF active_execution_id ON slice_control_state
WHEN OLD.active_execution_id IS NOT NULL
 AND NEW.active_execution_id IS NOT OLD.active_execution_id
BEGIN SELECT RAISE(ABORT, 'ACTIVE_EXECUTION_REBIND_FORBIDDEN'); END;

CREATE TRIGGER slice_control_state_execution_binding_insert
BEFORE INSERT ON slice_control_state
WHEN NEW.active_execution_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM slice_execution AS execution
    WHERE execution.execution_id = NEW.active_execution_id
      AND execution.slice_id = NEW.slice_id
      AND execution.source_root = NEW.repository_toplevel
      AND execution.branch = NEW.branch
      AND execution.base_commit = NEW.base_commit
      AND execution.result_commit IS NEW.implementation_result_commit
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_EXECUTION_BINDING_MISMATCH'); END;

CREATE TRIGGER slice_control_state_execution_binding_update
BEFORE UPDATE ON slice_control_state
WHEN NEW.active_execution_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM slice_execution AS execution
    WHERE execution.execution_id = NEW.active_execution_id
      AND execution.slice_id = NEW.slice_id
      AND execution.source_root = NEW.repository_toplevel
      AND execution.branch = NEW.branch
      AND execution.base_commit = NEW.base_commit
      AND execution.result_commit IS NEW.implementation_result_commit
)
BEGIN SELECT RAISE(ABORT, 'CONTROL_EXECUTION_BINDING_MISMATCH'); END;

CREATE TRIGGER slice_control_state_preexecution_context_insert
BEFORE INSERT ON slice_control_state
WHEN NEW.execution_eligibility = 'ELIGIBLE_PREEXECUTION_BOUND'
 AND NOT EXISTS (
    SELECT 1
    FROM slice_execution AS execution
    JOIN slice_control_event AS event
      ON event.slice_id = NEW.slice_id
     AND event.to_state_version = NEW.state_version
    JOIN context_snapshot AS context
      ON context.context_snapshot_id = json_extract(
          event.metadata_json, '$.metadata.context_snapshot_id'
      )
    WHERE execution.execution_id = NEW.active_execution_id
      AND event.reason_code = 'PREEXECUTION_BIND'
      AND context.execution_id = execution.execution_id
      AND context.role = 'MAKER'
      AND context.fingerprint = json_extract(
          event.metadata_json, '$.metadata.context_fingerprint'
      )
      AND json_extract(context.canonical_json, '$.content.contract_fingerprint')
          = execution.contract_fingerprint
      AND json_extract(context.canonical_json, '$.content.authority_fingerprint')
          = execution.authority_fingerprint
      AND json_extract(context.canonical_json, '$.content.branch') = execution.branch
      AND json_extract(context.canonical_json, '$.content.base_commit') = execution.base_commit
      AND json_extract(context.canonical_json, '$.content.current_commit') = execution.base_commit
      AND json_extract(context.canonical_json, '$.content.environment') = execution.environment
      AND json_extract(context.canonical_json, '$.content.risk') = execution.risk_level
      AND json_extract(context.canonical_json, '$.content.source_root')
          = json_extract(event.metadata_json, '$.metadata.worktree_path')
      AND json_extract(event.metadata_json, '$.metadata.repository_toplevel')
          = execution.source_root
      AND json_extract(event.metadata_json, '$.metadata.branch') = execution.branch
      AND json_extract(event.metadata_json, '$.metadata.base_commit') = execution.base_commit
      AND json_extract(event.metadata_json, '$.metadata.contract_fingerprint')
          = execution.contract_fingerprint
      AND json_extract(event.metadata_json, '$.metadata.authority_fingerprint')
          = execution.authority_fingerprint
      AND length(json_extract(event.metadata_json, '$.metadata.packet_ref')) > 0
)
BEGIN SELECT RAISE(ABORT, 'PREEXECUTION_CONTEXT_BINDING_MISMATCH'); END;

CREATE TRIGGER slice_control_state_preexecution_context_update
BEFORE UPDATE ON slice_control_state
WHEN NEW.execution_eligibility = 'ELIGIBLE_PREEXECUTION_BOUND'
 AND NOT EXISTS (
    SELECT 1
    FROM slice_execution AS execution
    JOIN slice_control_event AS event
      ON event.slice_id = NEW.slice_id
     AND event.to_state_version = NEW.state_version
    JOIN context_snapshot AS context
      ON context.context_snapshot_id = json_extract(
          event.metadata_json, '$.metadata.context_snapshot_id'
      )
    WHERE execution.execution_id = NEW.active_execution_id
      AND event.reason_code = 'PREEXECUTION_BIND'
      AND context.execution_id = execution.execution_id
      AND context.role = 'MAKER'
      AND context.fingerprint = json_extract(
          event.metadata_json, '$.metadata.context_fingerprint'
      )
      AND json_extract(context.canonical_json, '$.content.contract_fingerprint')
          = execution.contract_fingerprint
      AND json_extract(context.canonical_json, '$.content.authority_fingerprint')
          = execution.authority_fingerprint
      AND json_extract(context.canonical_json, '$.content.branch') = execution.branch
      AND json_extract(context.canonical_json, '$.content.base_commit') = execution.base_commit
      AND json_extract(context.canonical_json, '$.content.current_commit') = execution.base_commit
      AND json_extract(context.canonical_json, '$.content.environment') = execution.environment
      AND json_extract(context.canonical_json, '$.content.risk') = execution.risk_level
      AND json_extract(context.canonical_json, '$.content.source_root')
          = json_extract(event.metadata_json, '$.metadata.worktree_path')
      AND json_extract(event.metadata_json, '$.metadata.repository_toplevel')
          = execution.source_root
      AND json_extract(event.metadata_json, '$.metadata.branch') = execution.branch
      AND json_extract(event.metadata_json, '$.metadata.base_commit') = execution.base_commit
      AND json_extract(event.metadata_json, '$.metadata.contract_fingerprint')
          = execution.contract_fingerprint
      AND json_extract(event.metadata_json, '$.metadata.authority_fingerprint')
          = execution.authority_fingerprint
      AND length(json_extract(event.metadata_json, '$.metadata.packet_ref')) > 0
)
BEGIN SELECT RAISE(ABORT, 'PREEXECUTION_CONTEXT_BINDING_MISMATCH'); END;
"""

MIGRATION_5_SQL = r"""
DROP TRIGGER slice_control_state_rebinding_forbidden;

CREATE TRIGGER slice_control_state_rebinding_forbidden
BEFORE UPDATE OF active_execution_id ON slice_control_state
WHEN OLD.active_execution_id IS NOT NULL
 AND NEW.active_execution_id IS NOT OLD.active_execution_id
 AND NOT (
    OLD.migration_class = 'DEFER_BINDING'
    AND OLD.execution_eligibility = 'ELIGIBLE_PREEXECUTION_BOUND'
    AND NEW.migration_class = 'DEFER_BINDING'
    AND NEW.execution_eligibility = 'INELIGIBLE_UNTIL_PREFLIGHT'
    AND NEW.defer_reason = 'PREEXECUTION_BIND_SUPERSEDED'
    AND NEW.repository_toplevel IS NULL
    AND NEW.branch IS NULL
    AND NEW.base_commit IS NULL
    AND NEW.implementation_result_commit IS NULL
    AND NEW.current_branch_head IS NULL
    AND NEW.active_execution_id IS NULL
    AND NEW.state_version = OLD.state_version + 1
    AND EXISTS (
        SELECT 1
          FROM slice_control_event AS event
         WHERE event.slice_id = NEW.slice_id
           AND event.from_state_version = OLD.state_version
           AND event.to_state_version = NEW.state_version
           AND event.reason_code = 'PREEXECUTION_RELEASE'
           AND json_extract(
               event.metadata_json, '$.metadata.released_execution_id'
           ) = OLD.active_execution_id
    )
 )
BEGIN SELECT RAISE(ABORT, 'ACTIVE_EXECUTION_REBIND_FORBIDDEN'); END;
"""

MIGRATION_6_SQL = r"""
CREATE TABLE global_production_writer_lease (
    resource_key TEXT PRIMARY KEY CHECK (resource_key = 'GLOBAL_PRODUCTION'),
    state TEXT NOT NULL CHECK (state IN ('FREE', 'HELD')),
    owner_id TEXT,
    owner_execution_id TEXT,
    change_id TEXT,
    slice_id TEXT,
    writer_class TEXT,
    owner_session_role TEXT,
    track TEXT,
    repository_or_runtime TEXT,
    operation_class TEXT,
    target TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    acquired_at TEXT,
    expires_at TEXT,
    heartbeat_at TEXT,
    updated_at TEXT NOT NULL CHECK (
        length(updated_at) > 0
        AND julianday(updated_at) IS NOT NULL
        AND substr(updated_at, -6) = '+00:00'
    ),
    CHECK (owner_execution_id IS NULL OR length(owner_execution_id) > 0),
    CHECK (slice_id IS NULL OR length(slice_id) > 0),
    CHECK (
        (state = 'FREE'
         AND owner_id IS NULL
         AND owner_execution_id IS NULL
         AND change_id IS NULL
         AND slice_id IS NULL
         AND writer_class IS NULL
         AND owner_session_role IS NULL
         AND track IS NULL
         AND repository_or_runtime IS NULL
         AND operation_class IS NULL
         AND target IS NULL
         AND acquired_at IS NULL
         AND expires_at IS NULL
         AND heartbeat_at IS NULL)
        OR
        (state = 'HELD'
         AND owner_id IS NOT NULL AND length(owner_id) > 0
         AND change_id IS NOT NULL AND length(change_id) > 0
         AND writer_class IS NOT NULL AND length(writer_class) > 0
         AND owner_session_role IS NOT NULL AND length(owner_session_role) > 0
         AND track IS NOT NULL AND length(track) > 0
         AND repository_or_runtime IS NOT NULL AND length(repository_or_runtime) > 0
         AND operation_class IS NOT NULL AND length(operation_class) > 0
         AND target IS NOT NULL AND length(target) > 0
         AND acquired_at IS NOT NULL AND length(acquired_at) > 0
         AND expires_at IS NOT NULL AND length(expires_at) > 0
         AND heartbeat_at IS NOT NULL AND length(heartbeat_at) > 0
         AND julianday(acquired_at) IS NOT NULL
         AND julianday(expires_at) IS NOT NULL
         AND julianday(heartbeat_at) IS NOT NULL
         AND substr(acquired_at, -6) = '+00:00'
         AND substr(expires_at, -6) = '+00:00'
         AND substr(heartbeat_at, -6) = '+00:00'
         AND julianday(acquired_at) <= julianday(heartbeat_at)
         AND julianday(heartbeat_at) = julianday(updated_at)
         AND julianday(updated_at) < julianday(expires_at))
    )
);

INSERT INTO global_production_writer_lease(
    resource_key, state, fencing_token, updated_at
) VALUES (
    'GLOBAL_PRODUCTION', 'FREE', 0, '1970-01-01T00:00:00.000000+00:00'
);

CREATE TABLE global_production_writer_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) > 0),
    operation_key TEXT NOT NULL UNIQUE CHECK (
        length(operation_key) = 64 AND operation_key NOT GLOB '*[^0-9a-f]*'
    ),
    resource_key TEXT NOT NULL CHECK (resource_key = 'GLOBAL_PRODUCTION')
        REFERENCES global_production_writer_lease(resource_key)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (
        event_type IN ('ACQUIRE', 'RELEASE', 'EXPIRED_TAKEOVER', 'FORCE_REVOKE')
    ),
    from_fencing_token INTEGER NOT NULL CHECK (from_fencing_token >= 0),
    to_fencing_token INTEGER NOT NULL CHECK (to_fencing_token >= 0),
    prior_owner_id TEXT,
    prior_owner_execution_id TEXT,
    prior_change_id TEXT,
    prior_slice_id TEXT,
    prior_writer_class TEXT,
    prior_owner_session_role TEXT,
    prior_track TEXT,
    prior_repository_or_runtime TEXT,
    prior_operation_class TEXT,
    prior_target TEXT,
    new_owner_id TEXT,
    new_owner_execution_id TEXT,
    new_change_id TEXT,
    new_slice_id TEXT,
    new_writer_class TEXT,
    new_owner_session_role TEXT,
    new_track TEXT,
    new_repository_or_runtime TEXT,
    new_operation_class TEXT,
    new_target TEXT,
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    control_decision_ref TEXT CHECK (
        control_decision_ref IS NULL OR length(control_decision_ref) > 0
    ),
    request_json TEXT NOT NULL CHECK (length(request_json) > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    CHECK (
        (event_type = 'RELEASE' AND to_fencing_token = from_fencing_token)
        OR
        (event_type IN ('ACQUIRE', 'EXPIRED_TAKEOVER', 'FORCE_REVOKE')
         AND to_fencing_token = from_fencing_token + 1)
    ),
    CHECK (
        (event_type = 'ACQUIRE' AND prior_owner_id IS NULL AND new_owner_id IS NOT NULL)
        OR
        (event_type = 'EXPIRED_TAKEOVER'
         AND prior_owner_id IS NOT NULL AND new_owner_id IS NOT NULL)
        OR
        (event_type IN ('RELEASE', 'FORCE_REVOKE')
         AND prior_owner_id IS NOT NULL AND new_owner_id IS NULL)
    ),
    CHECK (event_type <> 'FORCE_REVOKE' OR control_decision_ref IS NOT NULL)
);

CREATE TRIGGER global_production_writer_lease_insert_forbidden
BEFORE INSERT ON global_production_writer_lease
BEGIN SELECT RAISE(ABORT, 'GLOBAL_PRODUCTION_WRITER_SINGLETON_INSERT_FORBIDDEN'); END;
CREATE TRIGGER global_production_writer_lease_delete_forbidden
BEFORE DELETE ON global_production_writer_lease
BEGIN SELECT RAISE(ABORT, 'GLOBAL_PRODUCTION_WRITER_SINGLETON_DELETE_FORBIDDEN'); END;
CREATE TRIGGER global_production_writer_lease_identity_immutable
BEFORE UPDATE OF resource_key ON global_production_writer_lease
WHEN NEW.resource_key IS NOT OLD.resource_key
BEGIN SELECT RAISE(ABORT, 'GLOBAL_PRODUCTION_WRITER_RESOURCE_IMMUTABLE'); END;
CREATE TRIGGER global_production_writer_lease_fencing_monotonic
BEFORE UPDATE OF fencing_token ON global_production_writer_lease
WHEN NEW.fencing_token < OLD.fencing_token
BEGIN SELECT RAISE(ABORT, 'GLOBAL_PRODUCTION_WRITER_FENCING_DECREMENT_FORBIDDEN'); END;

CREATE TRIGGER global_production_writer_event_immutable_update
BEFORE UPDATE ON global_production_writer_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_GLOBAL_PRODUCTION_WRITER_EVENT'); END;
CREATE TRIGGER global_production_writer_event_immutable_delete
BEFORE DELETE ON global_production_writer_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_GLOBAL_PRODUCTION_WRITER_EVENT'); END;
"""


MIGRATION_7_SQL = r"""
CREATE TABLE evaluator_artifact_seal (
    seal_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_id TEXT NOT NULL UNIQUE CHECK (length(seal_id) > 0),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    result_commit TEXT NOT NULL CHECK (
        length(result_commit) IN (40,64) AND result_commit NOT GLOB '*[^0-9a-f]*'
    ),
    verification_id TEXT NOT NULL REFERENCES verification_result(verification_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    evaluator_attempt_id TEXT NOT NULL REFERENCES agent_attempt(attempt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    context_snapshot_id TEXT NOT NULL REFERENCES context_snapshot(context_snapshot_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    context_fingerprint TEXT NOT NULL CHECK (
        length(context_fingerprint)=64 AND context_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    contract_fingerprint TEXT NOT NULL CHECK (
        length(contract_fingerprint)=64 AND contract_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    authority_fingerprint TEXT NOT NULL CHECK (
        length(authority_fingerprint)=64 AND authority_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    phase TEXT NOT NULL CHECK (
        phase IN ('PRE_EXECUTION','POST_EXECUTION','LEGACY_ATTESTED')
    ),
    producer_kind TEXT NOT NULL CHECK (
        producer_kind IN ('CONTROLLER_RUNNER','EXECUTION_ADAPTER','LEGACY_HUMAN_ATTESTATION')
    ),
    producer_ref TEXT NOT NULL CHECK (length(producer_ref) > 0),
    evidence_root TEXT NOT NULL CHECK (length(evidence_root) > 0),
    manifest_version INTEGER NOT NULL CHECK (manifest_version = 1),
    manifest_json TEXT NOT NULL CHECK (length(manifest_json) > 0),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    authority_generation INTEGER NOT NULL CHECK (authority_generation >= 0),
    operation_key TEXT NOT NULL UNIQUE CHECK (
        length(operation_key)=64 AND operation_key NOT GLOB '*[^0-9a-f]*'
    ),
    approval_id TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE(evaluator_attempt_id, phase),
    CHECK (
        (phase='LEGACY_ATTESTED'
         AND producer_kind='LEGACY_HUMAN_ATTESTATION'
         AND approval_id IS NOT NULL AND length(approval_id) > 0)
        OR
        (phase IN ('PRE_EXECUTION','POST_EXECUTION')
         AND producer_kind IN ('CONTROLLER_RUNNER','EXECUTION_ADAPTER')
         AND approval_id IS NULL)
    )
);

CREATE INDEX idx_evaluator_artifact_seal_binding
ON evaluator_artifact_seal(
    execution_id, result_commit, verification_id, evaluator_attempt_id,
    context_snapshot_id, phase
);

CREATE TRIGGER evaluator_artifact_seal_immutable_update
BEFORE UPDATE ON evaluator_artifact_seal
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_EVALUATOR_ARTIFACT_SEAL'); END;

CREATE TRIGGER evaluator_artifact_seal_immutable_delete
BEFORE DELETE ON evaluator_artifact_seal
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_EVALUATOR_ARTIFACT_SEAL'); END;

CREATE TRIGGER evaluator_artifact_seal_binding_insert
BEFORE INSERT ON evaluator_artifact_seal
WHEN NOT EXISTS (
    SELECT 1
      FROM slice_execution e
      JOIN agent_attempt a ON a.execution_id=e.execution_id
      JOIN context_snapshot c ON c.context_snapshot_id=a.context_snapshot_id
      JOIN verification_result v ON v.execution_id=e.execution_id
      JOIN control_authority_state ca ON ca.singleton_id='GLOBAL'
     WHERE e.execution_id=NEW.execution_id
       AND e.result_commit=NEW.result_commit
       AND e.contract_fingerprint=NEW.contract_fingerprint
       AND e.authority_fingerprint=NEW.authority_fingerprint
       AND a.attempt_id=NEW.evaluator_attempt_id
       AND a.role='EVALUATOR'
       AND a.result_commit=NEW.result_commit
       AND a.context_snapshot_id=NEW.context_snapshot_id
       AND c.execution_id=NEW.execution_id
       AND c.role='EVALUATOR'
       AND c.fingerprint=NEW.context_fingerprint
       AND v.verification_id=NEW.verification_id
       AND v.result_commit=NEW.result_commit
       AND v.contract_fingerprint=NEW.contract_fingerprint
       AND v.authority_fingerprint=NEW.authority_fingerprint
       AND v.verdict='PASS'
       AND ca.authority_generation=NEW.authority_generation
       AND (
            (NEW.phase IN ('PRE_EXECUTION','POST_EXECUTION') AND a.status='RUNNING')
            OR (NEW.phase='LEGACY_ATTESTED' AND a.status='SUCCEEDED')
       )
)
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_ARTIFACT_SEAL_BINDING_MISMATCH'); END;

CREATE TRIGGER evaluator_artifact_seal_post_requires_pre
BEFORE INSERT ON evaluator_artifact_seal
WHEN NEW.phase='POST_EXECUTION'
 AND NOT EXISTS (
    SELECT 1 FROM evaluator_artifact_seal pre
     WHERE pre.evaluator_attempt_id=NEW.evaluator_attempt_id
       AND pre.phase='PRE_EXECUTION'
       AND pre.execution_id=NEW.execution_id
       AND pre.result_commit=NEW.result_commit
       AND pre.verification_id=NEW.verification_id
       AND pre.context_snapshot_id=NEW.context_snapshot_id
       AND pre.context_fingerprint=NEW.context_fingerprint
       AND pre.contract_fingerprint=NEW.contract_fingerprint
       AND pre.authority_fingerprint=NEW.authority_fingerprint
       AND pre.evidence_root=NEW.evidence_root
       AND pre.authority_generation=NEW.authority_generation
 )
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_POST_SEAL_PRE_REQUIRED'); END;

CREATE TRIGGER evaluator_artifact_seal_legacy_fresh_post_forbidden
BEFORE INSERT ON evaluator_artifact_seal
WHEN NEW.phase='LEGACY_ATTESTED'
 AND EXISTS (
    SELECT 1 FROM evaluator_artifact_seal post
     WHERE post.evaluator_attempt_id=NEW.evaluator_attempt_id
       AND post.phase='POST_EXECUTION'
 )
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_LEGACY_SEAL_FRESH_POST_EXISTS'); END;

CREATE TRIGGER evaluation_result_require_artifact_seal_insert
BEFORE INSERT ON evaluation_result
WHEN EXISTS (
    SELECT 1 FROM agent_attempt a
     WHERE a.attempt_id=NEW.evaluator_attempt_id
       AND a.execution_id=NEW.execution_id
       AND a.context_snapshot_id=NEW.context_snapshot_id
       AND a.role='EVALUATOR'
)
 AND NOT EXISTS (
    SELECT 1 FROM evaluator_artifact_seal s
     WHERE s.evaluator_attempt_id=NEW.evaluator_attempt_id
       AND s.execution_id=NEW.execution_id
       AND s.result_commit=NEW.result_commit
       AND s.context_snapshot_id=NEW.context_snapshot_id
       AND s.contract_fingerprint=NEW.contract_fingerprint
       AND s.authority_fingerprint=NEW.authority_fingerprint
       AND s.phase IN ('POST_EXECUTION','LEGACY_ATTESTED')
 )
BEGIN SELECT RAISE(ABORT, 'EVALUATOR_ARTIFACT_SEAL_REQUIRED'); END;
"""

MIGRATION_8_SQL = r"""
CREATE TABLE typed_postgres_operation_receipt_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE CHECK (length(receipt_id) > 0),
    receipt_version INTEGER NOT NULL CHECK (receipt_version = 1),
    change_id TEXT NOT NULL CHECK (length(change_id) > 0),
    control_decision_ref TEXT NOT NULL CHECK (length(control_decision_ref) > 0),
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) > 0),
    operation_type TEXT NOT NULL CHECK (
        operation_type IN (
            'EXECUTE_AUTHORIZED_SQL_FILE',
            'TRANSITION_DATABASE_OWNER',
            'APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE'
        )
    ),
    receipt_phase TEXT NOT NULL CHECK (receipt_phase IN ('PREPARED','FINAL')),
    target_service TEXT NOT NULL CHECK (length(target_service) > 0),
    target_database TEXT,
    principal_identity TEXT,
    credential_reference TEXT,
    artifact_path TEXT,
    artifact_sha256 TEXT CHECK (
        artifact_sha256 IS NULL OR (
            length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    request_fingerprint TEXT NOT NULL CHECK (
        length(request_fingerprint)=64 AND request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    before_state_fingerprint TEXT NOT NULL CHECK (
        length(before_state_fingerprint)=64 AND before_state_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    after_state_fingerprint TEXT CHECK (
        after_state_fingerprint IS NULL OR (
            length(after_state_fingerprint)=64 AND after_state_fingerprint NOT GLOB '*[^0-9a-f]*'
        )
    ),
    effect_status TEXT NOT NULL CHECK (effect_status IN ('PENDING','APPLIED','NOOP_EXACT')),
    w08_fencing_token INTEGER NOT NULL CHECK (w08_fencing_token > 0),
    created_at TEXT NOT NULL CHECK (
        length(created_at) > 0
        AND julianday(created_at) IS NOT NULL
        AND substr(created_at, -6) = '+00:00'
    ),
    UNIQUE(operation_id, receipt_phase),
    CHECK (
        (receipt_phase='PREPARED' AND effect_status='PENDING' AND after_state_fingerprint IS NULL)
        OR
        (receipt_phase='FINAL' AND effect_status IN ('APPLIED','NOOP_EXACT') AND after_state_fingerprint IS NOT NULL)
    )
);

CREATE INDEX idx_typed_postgres_receipt_operation
ON typed_postgres_operation_receipt_event(operation_id, event_seq);

CREATE TRIGGER typed_postgres_operation_receipt_event_immutable_update
BEFORE UPDATE ON typed_postgres_operation_receipt_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT'); END;

CREATE TRIGGER typed_postgres_operation_receipt_event_immutable_delete
BEFORE DELETE ON typed_postgres_operation_receipt_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT'); END;

CREATE TRIGGER typed_postgres_operation_receipt_event_final_requires_prepared
BEFORE INSERT ON typed_postgres_operation_receipt_event
WHEN NEW.receipt_phase='FINAL'
 AND NOT EXISTS (
    SELECT 1
      FROM typed_postgres_operation_receipt_event prepared
     WHERE prepared.operation_id=NEW.operation_id
       AND prepared.receipt_phase='PREPARED'
       AND prepared.receipt_version=NEW.receipt_version
       AND prepared.change_id=NEW.change_id
       AND prepared.control_decision_ref=NEW.control_decision_ref
       AND prepared.deployment_id=NEW.deployment_id
       AND prepared.operation_type=NEW.operation_type
       AND prepared.target_service=NEW.target_service
       AND prepared.target_database IS NEW.target_database
       AND prepared.principal_identity IS NEW.principal_identity
       AND prepared.credential_reference IS NEW.credential_reference
       AND prepared.artifact_path IS NEW.artifact_path
       AND prepared.artifact_sha256 IS NEW.artifact_sha256
       AND prepared.request_fingerprint=NEW.request_fingerprint
       AND prepared.before_state_fingerprint=NEW.before_state_fingerprint
       AND prepared.w08_fencing_token=NEW.w08_fencing_token
 )
BEGIN SELECT RAISE(ABORT, 'TYPED_POSTGRES_FINAL_PREPARED_BINDING_REQUIRED'); END;
"""

MIGRATION_9_SQL = r"""
CREATE TABLE candidate_content_binding (
    candidate_id TEXT PRIMARY KEY CHECK (length(candidate_id) > 0),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK (review_target_type='UNCOMMITTED_CANDIDATE'),
    serialization_format TEXT NOT NULL CHECK (serialization_format='ADCP_INTEGRATED_CANDIDATE_V1'),
    serialization_version INTEGER NOT NULL CHECK (serialization_version=1),
    repository_identity TEXT NOT NULL CHECK (length(repository_identity) > 0),
    expected_parent TEXT NOT NULL CHECK (length(expected_parent) IN (40,64)),
    manifest_json TEXT NOT NULL CHECK (length(manifest_json) > 2),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256)=64),
    candidate_content_sha256 TEXT NOT NULL CHECK (length(candidate_content_sha256)=64),
    created_at TEXT NOT NULL,
    UNIQUE(execution_id, manifest_sha256),
    UNIQUE(candidate_id, execution_id, candidate_content_sha256)
);
CREATE TABLE candidate_provenance (
    provenance_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    execution_id TEXT NOT NULL,
    maker_attempt_id TEXT NOT NULL UNIQUE REFERENCES agent_attempt(attempt_id) ON DELETE RESTRICT,
    canonical_source_root TEXT NOT NULL,
    worktree_identity TEXT NOT NULL,
    branch TEXT NOT NULL,
    contract_fingerprint TEXT NOT NULL CHECK(length(contract_fingerprint)=64),
    authority_fingerprint TEXT NOT NULL CHECK(length(authority_fingerprint)=64),
    authority_generation INTEGER NOT NULL CHECK(authority_generation>=0),
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64),
    created_at TEXT NOT NULL,
    FOREIGN KEY(candidate_id,execution_id,candidate_content_sha256)
      REFERENCES candidate_content_binding(candidate_id,execution_id,candidate_content_sha256)
      ON UPDATE RESTRICT ON DELETE RESTRICT
);
CREATE TABLE candidate_verification_result (
    verification_id TEXT PRIMARY KEY,
    operation_key TEXT NOT NULL UNIQUE CHECK(length(operation_key)=64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK(review_target_type='UNCOMMITTED_CANDIDATE'),
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64),
    contract_fingerprint TEXT NOT NULL CHECK(length(contract_fingerprint)=64),
    authority_fingerprint TEXT NOT NULL CHECK(length(authority_fingerprint)=64),
    authority_generation INTEGER NOT NULL CHECK(authority_generation>=0),
    verdict TEXT NOT NULL CHECK(verdict IN ('PASS','FAIL','BLOCKED_ENVIRONMENT')),
    command_manifest TEXT NOT NULL, command_manifest_sha256 TEXT NOT NULL CHECK(length(command_manifest_sha256)=64),
    result_json TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
    FOREIGN KEY(candidate_id,execution_id,candidate_content_sha256)
      REFERENCES candidate_content_binding(candidate_id,execution_id,candidate_content_sha256)
);
CREATE TABLE candidate_evaluator_attempt (
    evaluator_attempt_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    verification_id TEXT NOT NULL UNIQUE REFERENCES candidate_verification_result(verification_id) ON DELETE RESTRICT,
    context_snapshot_id TEXT NOT NULL REFERENCES context_snapshot(context_snapshot_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK(review_target_type='UNCOMMITTED_CANDIDATE'),
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64),
    lease_owner TEXT NOT NULL, lease_generation INTEGER NOT NULL, authority_generation INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('RUNNING','SUCCEEDED','FAILED','ABORTED','LOST')),
    started_at TEXT NOT NULL, ended_at TEXT,
    CHECK((status='RUNNING' AND ended_at IS NULL) OR (status<>'RUNNING' AND ended_at IS NOT NULL)),
    FOREIGN KEY(candidate_id,execution_id,candidate_content_sha256)
      REFERENCES candidate_content_binding(candidate_id,execution_id,candidate_content_sha256)
);
CREATE TABLE candidate_evaluation_result (
    evaluation_id TEXT PRIMARY KEY, operation_key TEXT NOT NULL UNIQUE CHECK(length(operation_key)=64),
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    evaluator_attempt_id TEXT NOT NULL UNIQUE REFERENCES candidate_evaluator_attempt(evaluator_attempt_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK(review_target_type='UNCOMMITTED_CANDIDATE'),
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64),
    contract_fingerprint TEXT NOT NULL CHECK(length(contract_fingerprint)=64),
    authority_fingerprint TEXT NOT NULL CHECK(length(authority_fingerprint)=64), authority_generation INTEGER NOT NULL CHECK(authority_generation>=0),
    verdict TEXT NOT NULL CHECK(verdict IN ('PASS','REWORK_REQUIRED','DESIGN_REVIEW_REQUIRED','BLOCKED_ENVIRONMENT','BLOCKED_EVIDENCE')),
    result_json TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
    FOREIGN KEY(candidate_id,execution_id,candidate_content_sha256)
      REFERENCES candidate_content_binding(candidate_id,execution_id,candidate_content_sha256)
);
CREATE TABLE candidate_evaluator_artifact_seal (
    seal_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    evaluator_attempt_id TEXT NOT NULL REFERENCES candidate_evaluator_attempt(evaluator_attempt_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK(review_target_type='UNCOMMITTED_CANDIDATE'),
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64),
    phase TEXT NOT NULL CHECK(phase IN ('PRE_EXECUTION','POST_EXECUTION')),
    evidence_root TEXT NOT NULL,
    manifest_json TEXT NOT NULL, manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), created_at TEXT NOT NULL,
    UNIQUE(evaluator_attempt_id,phase),
    FOREIGN KEY(candidate_id,execution_id,candidate_content_sha256)
      REFERENCES candidate_content_binding(candidate_id,execution_id,candidate_content_sha256)
);
CREATE TABLE approval_candidate_binding (
    approval_id TEXT PRIMARY KEY REFERENCES approval_request(approval_id) ON DELETE RESTRICT,
    execution_id TEXT NOT NULL REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    review_target_type TEXT NOT NULL CHECK(review_target_type='UNCOMMITTED_CANDIDATE'),
    candidate_id TEXT NOT NULL REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    evaluation_id TEXT NOT NULL UNIQUE REFERENCES candidate_evaluation_result(evaluation_id) ON DELETE RESTRICT,
    authority_fingerprint TEXT NOT NULL CHECK(length(authority_fingerprint)=64), authority_generation INTEGER NOT NULL CHECK(authority_generation>=0),
    created_at TEXT NOT NULL
);
CREATE TABLE candidate_commit_intent (
    closure_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL UNIQUE REFERENCES approval_candidate_binding(approval_id) ON DELETE RESTRICT,
    evaluation_id TEXT NOT NULL UNIQUE REFERENCES candidate_evaluation_result(evaluation_id) ON DELETE RESTRICT,
    plan_json TEXT NOT NULL, plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),
    created_at TEXT NOT NULL
);
CREATE TABLE candidate_commit_closure (
    closure_id TEXT PRIMARY KEY REFERENCES candidate_commit_intent(closure_id) ON DELETE RESTRICT, execution_id TEXT NOT NULL UNIQUE REFERENCES slice_execution(execution_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL UNIQUE REFERENCES candidate_content_binding(candidate_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL UNIQUE REFERENCES approval_candidate_binding(approval_id) ON DELETE RESTRICT,
    evaluation_id TEXT NOT NULL UNIQUE REFERENCES candidate_evaluation_result(evaluation_id) ON DELETE RESTRICT,
    result_commit TEXT NOT NULL UNIQUE CHECK(length(result_commit) IN (40,64)), expected_parent TEXT NOT NULL CHECK(length(expected_parent) IN (40,64)),
    candidate_content_sha256 TEXT NOT NULL CHECK(length(candidate_content_sha256)=64), created_at TEXT NOT NULL
);
CREATE TRIGGER candidate_evaluator_terminal_once BEFORE UPDATE ON candidate_evaluator_attempt
WHEN OLD.status <> 'RUNNING' OR NEW.status = 'RUNNING'
BEGIN SELECT RAISE(ABORT,'CANDIDATE_EVALUATOR_TERMINAL_IMMUTABLE'); END;
CREATE TRIGGER candidate_evaluator_identity_immutable BEFORE UPDATE OF evaluator_attempt_id,execution_id,candidate_id,verification_id,context_snapshot_id,review_target_type,candidate_content_sha256,lease_owner,lease_generation,authority_generation,started_at ON candidate_evaluator_attempt
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CANDIDATE_RECORD'); END;
CREATE TRIGGER candidate_evaluator_delete_forbidden BEFORE DELETE ON candidate_evaluator_attempt
BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CANDIDATE_RECORD'); END;
CREATE INDEX idx_candidate_binding_execution ON candidate_content_binding(execution_id,candidate_content_sha256);
CREATE INDEX idx_candidate_verification_binding ON candidate_verification_result(execution_id,candidate_id,verdict);
CREATE INDEX idx_candidate_evaluation_binding ON candidate_evaluation_result(execution_id,candidate_id,verdict);

CREATE TRIGGER candidate_provenance_same_execution BEFORE INSERT ON candidate_provenance
WHEN NOT EXISTS(SELECT 1 FROM agent_attempt a WHERE a.attempt_id=NEW.maker_attempt_id AND a.execution_id=NEW.execution_id AND a.role='MAKER')
BEGIN SELECT RAISE(ABORT,'CANDIDATE_MAKER_ATTEMPT_MISMATCH'); END;
CREATE TRIGGER candidate_verification_exact_binding BEFORE INSERT ON candidate_verification_result
WHEN NOT EXISTS(SELECT 1 FROM candidate_content_binding b WHERE b.candidate_id=NEW.candidate_id AND b.execution_id=NEW.execution_id AND b.candidate_content_sha256=NEW.candidate_content_sha256)
BEGIN SELECT RAISE(ABORT,'CANDIDATE_BINDING_MISMATCH'); END;
CREATE TRIGGER candidate_evaluation_exact_attempt BEFORE INSERT ON candidate_evaluation_result
WHEN NOT EXISTS(SELECT 1 FROM candidate_evaluator_attempt a WHERE a.evaluator_attempt_id=NEW.evaluator_attempt_id AND a.execution_id=NEW.execution_id AND a.candidate_id=NEW.candidate_id AND a.candidate_content_sha256=NEW.candidate_content_sha256)
BEGIN SELECT RAISE(ABORT,'CANDIDATE_EVALUATOR_TARGET_MISMATCH'); END;
CREATE TRIGGER candidate_seal_exact_attempt BEFORE INSERT ON candidate_evaluator_artifact_seal
WHEN NOT EXISTS(SELECT 1 FROM candidate_evaluator_attempt a WHERE a.evaluator_attempt_id=NEW.evaluator_attempt_id AND a.execution_id=NEW.execution_id AND a.candidate_id=NEW.candidate_id AND a.candidate_content_sha256=NEW.candidate_content_sha256)
BEGIN SELECT RAISE(ABORT,'CANDIDATE_EVALUATOR_TARGET_MISMATCH'); END;
CREATE TRIGGER candidate_seal_post_requires_pre BEFORE INSERT ON candidate_evaluator_artifact_seal
WHEN NEW.phase='POST_EXECUTION' AND NOT EXISTS(SELECT 1 FROM candidate_evaluator_artifact_seal s WHERE s.evaluator_attempt_id=NEW.evaluator_attempt_id AND s.phase='PRE_EXECUTION' AND s.candidate_id=NEW.candidate_id AND s.candidate_content_sha256=NEW.candidate_content_sha256)
BEGIN SELECT RAISE(ABORT,'CANDIDATE_PRE_SEAL_REQUIRED'); END;
CREATE TRIGGER candidate_evaluation_requires_post_seal BEFORE INSERT ON candidate_evaluation_result
WHEN NOT EXISTS(SELECT 1 FROM candidate_evaluator_artifact_seal s WHERE s.evaluator_attempt_id=NEW.evaluator_attempt_id AND s.phase='POST_EXECUTION' AND s.candidate_id=NEW.candidate_id AND s.candidate_content_sha256=NEW.candidate_content_sha256)
BEGIN SELECT RAISE(ABORT,'CANDIDATE_POST_SEAL_REQUIRED'); END;
CREATE TRIGGER candidate_closure_exact_binding BEFORE INSERT ON candidate_commit_closure
WHEN NOT EXISTS(SELECT 1 FROM approval_candidate_binding a JOIN candidate_evaluation_result e ON e.evaluation_id=a.evaluation_id WHERE a.approval_id=NEW.approval_id AND a.execution_id=NEW.execution_id AND a.candidate_id=NEW.candidate_id AND a.evaluation_id=NEW.evaluation_id AND e.verdict='PASS')
BEGIN SELECT RAISE(ABORT,'CANDIDATE_APPROVAL_BINDING_MISMATCH'); END;
"""

# Every v9 candidate/evidence row is append-only. Terminal status changes are the
# sole deliberate updates and are guarded in ControlStore transactions.
_V9_IMMUTABLE_TABLES = (
    "candidate_content_binding", "candidate_provenance", "candidate_verification_result",
    "candidate_evaluation_result", "candidate_evaluator_artifact_seal",
    "approval_candidate_binding", "candidate_commit_intent", "candidate_commit_closure",
)
MIGRATION_9_SQL += "\n".join(
    f"CREATE TRIGGER {name}_immutable_update BEFORE UPDATE ON {name} BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CANDIDATE_RECORD'); END;\n"
    f"CREATE TRIGGER {name}_immutable_delete BEFORE DELETE ON {name} BEGIN SELECT RAISE(ABORT,'IMMUTABLE_CANDIDATE_RECORD'); END;"
    for name in _V9_IMMUTABLE_TABLES
)


# Schema v10 widens only the durable typed-PostgreSQL receipt operation kind.
# Migration v8 remains immutable; the ledger is rebuilt transactionally so every
# pre-existing receipt fact, sequence, index, and trigger contract is preserved.
MIGRATION_10_SQL = r"""
DROP TRIGGER typed_postgres_operation_receipt_event_final_requires_prepared;
DROP TRIGGER typed_postgres_operation_receipt_event_immutable_delete;
DROP TRIGGER typed_postgres_operation_receipt_event_immutable_update;
DROP INDEX idx_typed_postgres_receipt_operation;

ALTER TABLE typed_postgres_operation_receipt_event
RENAME TO typed_postgres_operation_receipt_event_v9;

CREATE TABLE typed_postgres_operation_receipt_event (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE CHECK (length(receipt_id) > 0),
    receipt_version INTEGER NOT NULL CHECK (receipt_version = 1),
    change_id TEXT NOT NULL CHECK (length(change_id) > 0),
    control_decision_ref TEXT NOT NULL CHECK (length(control_decision_ref) > 0),
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) > 0),
    operation_type TEXT NOT NULL CHECK (
        operation_type IN (
            'EXECUTE_AUTHORIZED_SQL_FILE',
            'TRANSITION_DATABASE_OWNER',
            'APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE',
            'PROVISION_CLEANER_APP_PRINCIPAL'
        )
    ),
    receipt_phase TEXT NOT NULL CHECK (receipt_phase IN ('PREPARED','FINAL')),
    target_service TEXT NOT NULL CHECK (length(target_service) > 0),
    target_database TEXT,
    principal_identity TEXT,
    credential_reference TEXT,
    artifact_path TEXT,
    artifact_sha256 TEXT CHECK (
        artifact_sha256 IS NULL OR (
            length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    request_fingerprint TEXT NOT NULL CHECK (
        length(request_fingerprint)=64 AND request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    before_state_fingerprint TEXT NOT NULL CHECK (
        length(before_state_fingerprint)=64 AND before_state_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    after_state_fingerprint TEXT CHECK (
        after_state_fingerprint IS NULL OR (
            length(after_state_fingerprint)=64 AND after_state_fingerprint NOT GLOB '*[^0-9a-f]*'
        )
    ),
    effect_status TEXT NOT NULL CHECK (effect_status IN ('PENDING','APPLIED','NOOP_EXACT')),
    w08_fencing_token INTEGER NOT NULL CHECK (w08_fencing_token > 0),
    created_at TEXT NOT NULL CHECK (
        length(created_at) > 0
        AND julianday(created_at) IS NOT NULL
        AND substr(created_at, -6) = '+00:00'
    ),
    UNIQUE(operation_id, receipt_phase),
    CHECK (
        (receipt_phase='PREPARED' AND effect_status='PENDING' AND after_state_fingerprint IS NULL)
        OR
        (receipt_phase='FINAL' AND effect_status IN ('APPLIED','NOOP_EXACT') AND after_state_fingerprint IS NOT NULL)
    )
);

INSERT INTO typed_postgres_operation_receipt_event(
    event_seq, receipt_id, receipt_version, change_id, control_decision_ref,
    deployment_id, operation_id, operation_type, receipt_phase, target_service,
    target_database, principal_identity, credential_reference, artifact_path,
    artifact_sha256, request_fingerprint, before_state_fingerprint,
    after_state_fingerprint, effect_status, w08_fencing_token, created_at
)
SELECT
    event_seq, receipt_id, receipt_version, change_id, control_decision_ref,
    deployment_id, operation_id, operation_type, receipt_phase, target_service,
    target_database, principal_identity, credential_reference, artifact_path,
    artifact_sha256, request_fingerprint, before_state_fingerprint,
    after_state_fingerprint, effect_status, w08_fencing_token, created_at
FROM typed_postgres_operation_receipt_event_v9
ORDER BY event_seq;

DROP TABLE typed_postgres_operation_receipt_event_v9;

CREATE INDEX idx_typed_postgres_receipt_operation
ON typed_postgres_operation_receipt_event(operation_id, event_seq);

CREATE TRIGGER typed_postgres_operation_receipt_event_immutable_update
BEFORE UPDATE ON typed_postgres_operation_receipt_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT'); END;

CREATE TRIGGER typed_postgres_operation_receipt_event_immutable_delete
BEFORE DELETE ON typed_postgres_operation_receipt_event
BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_TYPED_POSTGRES_OPERATION_RECEIPT_EVENT'); END;

CREATE TRIGGER typed_postgres_operation_receipt_event_final_requires_prepared
BEFORE INSERT ON typed_postgres_operation_receipt_event
WHEN NEW.receipt_phase='FINAL'
 AND NOT EXISTS (
    SELECT 1
      FROM typed_postgres_operation_receipt_event prepared
     WHERE prepared.operation_id=NEW.operation_id
       AND prepared.receipt_phase='PREPARED'
       AND prepared.receipt_version=NEW.receipt_version
       AND prepared.change_id=NEW.change_id
       AND prepared.control_decision_ref=NEW.control_decision_ref
       AND prepared.deployment_id=NEW.deployment_id
       AND prepared.operation_type=NEW.operation_type
       AND prepared.target_service=NEW.target_service
       AND prepared.target_database IS NEW.target_database
       AND prepared.principal_identity IS NEW.principal_identity
       AND prepared.credential_reference IS NEW.credential_reference
       AND prepared.artifact_path IS NEW.artifact_path
       AND prepared.artifact_sha256 IS NEW.artifact_sha256
       AND prepared.request_fingerprint=NEW.request_fingerprint
       AND prepared.before_state_fingerprint=NEW.before_state_fingerprint
       AND prepared.w08_fencing_token=NEW.w08_fencing_token
 )
BEGIN SELECT RAISE(ABORT, 'TYPED_POSTGRES_FINAL_PREPARED_BINDING_REQUIRED'); END;
"""


EXPECTED_TABLES = frozenset(
    {
        "schema_migration",
        "slice_execution",
        "context_snapshot",
        "agent_attempt",
        "transition_event",
        "verification_result",
        "evaluation_result",
        "approval_request",
        "evidence_manifest",
        "projection_record",
        "slice_control_state",
        "slice_control_event",
        "control_authority_state",
        "authority_transition_event",
        "global_production_writer_lease",
        "global_production_writer_event",
        "evaluator_artifact_seal",
    }
)
EXPECTED_INDEXES = frozenset(
    {
        "uq_slice_execution_open",
        "idx_slice_execution_state",
        "idx_context_snapshot_execution",
        "idx_agent_attempt_execution",
        "idx_transition_event_execution",
        "idx_verification_binding",
        "idx_evaluation_binding",
        "idx_approval_request_execution",
        "idx_projection_retry",
        "idx_slice_control_state_status",
        "idx_slice_control_event_slice",
        "idx_authority_transition_event_cutover",
        "idx_evaluator_artifact_seal_binding",
    }
)
EXPECTED_TRIGGERS = frozenset(
    {
        f"{table}_immutable_{action}"
        for table in (
            "context_snapshot",
            "transition_event",
            "verification_result",
            "evaluation_result",
            "evidence_manifest",
        )
        for action in ("update", "delete")
    }
    | {
        "evaluation_result_require_evaluator_insert",
        "evaluation_result_require_evaluator_update",
        "evidence_manifest_require_succeeded_attempts",
        "agent_attempt_running_finish_only",
        "agent_attempt_identity_immutable",
        "agent_attempt_terminal_immutable",
        "agent_attempt_delete_forbidden",
        "slice_control_event_immutable_update",
        "slice_control_event_immutable_delete",
        "slice_control_event_monotonic_insert",
        "slice_control_state_event_required_insert",
        "slice_control_state_version_monotonic",
        "slice_control_state_identity_immutable",
        "slice_control_state_delete_forbidden",
        "slice_control_state_rebinding_forbidden",
        "slice_control_state_execution_binding_insert",
        "slice_control_state_execution_binding_update",
        "slice_control_state_preexecution_context_insert",
        "slice_control_state_preexecution_context_update",
        "control_authority_state_insert_forbidden",
        "control_authority_state_delete_forbidden",
        "authority_transition_event_immutable_update",
        "authority_transition_event_immutable_delete",
        "authority_transition_event_state_guard",
        "authority_transition_event_apply",
        "control_authority_state_transition_guard",
        "control_authority_state_generation_monotonic",
        "global_production_writer_lease_insert_forbidden",
        "global_production_writer_lease_delete_forbidden",
        "global_production_writer_lease_identity_immutable",
        "global_production_writer_lease_fencing_monotonic",
        "global_production_writer_event_immutable_update",
        "global_production_writer_event_immutable_delete",
        "evaluator_artifact_seal_immutable_update",
        "evaluator_artifact_seal_immutable_delete",
        "evaluator_artifact_seal_binding_insert",
        "evaluator_artifact_seal_post_requires_pre",
        "evaluator_artifact_seal_legacy_fresh_post_forbidden",
        "evaluation_result_require_artifact_seal_insert",
    }
)


def canonical_sql_bytes(sql: str) -> bytes:
    normalized = sql.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    return normalized.encode("utf-8")


def migration_checksum(sql: str = MIGRATION_1_SQL) -> str:
    return hashlib.sha256(canonical_sql_bytes(sql)).hexdigest()


MIGRATION_1_CHECKSUM = migration_checksum(MIGRATION_1_SQL)
MIGRATION_2_CHECKSUM = migration_checksum(MIGRATION_2_SQL)
MIGRATION_3_CHECKSUM = migration_checksum(MIGRATION_3_SQL)
MIGRATION_4_CHECKSUM = migration_checksum(MIGRATION_4_SQL)
MIGRATION_5_CHECKSUM = migration_checksum(MIGRATION_5_SQL)
MIGRATION_6_CHECKSUM = migration_checksum(MIGRATION_6_SQL)
MIGRATION_7_CHECKSUM = migration_checksum(MIGRATION_7_SQL)
MIGRATION_8_CHECKSUM = migration_checksum(MIGRATION_8_SQL)
MIGRATION_9_CHECKSUM = migration_checksum(MIGRATION_9_SQL)
MIGRATION_10_CHECKSUM = migration_checksum(MIGRATION_10_SQL)
# Compatibility alias for the immutable schema-v1 checksum.
MIGRATION_CHECKSUM = MIGRATION_1_CHECKSUM


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


MIGRATIONS = (
    Migration(1, MIGRATION_1_NAME, MIGRATION_1_SQL, MIGRATION_1_CHECKSUM),
    Migration(2, MIGRATION_2_NAME, MIGRATION_2_SQL, MIGRATION_2_CHECKSUM),
    Migration(3, MIGRATION_3_NAME, MIGRATION_3_SQL, MIGRATION_3_CHECKSUM),
    Migration(4, MIGRATION_4_NAME, MIGRATION_4_SQL, MIGRATION_4_CHECKSUM),
    Migration(5, MIGRATION_5_NAME, MIGRATION_5_SQL, MIGRATION_5_CHECKSUM),
    Migration(6, MIGRATION_6_NAME, MIGRATION_6_SQL, MIGRATION_6_CHECKSUM),
    Migration(7, MIGRATION_7_NAME, MIGRATION_7_SQL, MIGRATION_7_CHECKSUM),
    Migration(8, MIGRATION_8_NAME, MIGRATION_8_SQL, MIGRATION_8_CHECKSUM),
    Migration(9, MIGRATION_9_NAME, MIGRATION_9_SQL, MIGRATION_9_CHECKSUM),
    Migration(10, MIGRATION_10_NAME, MIGRATION_10_SQL, MIGRATION_10_CHECKSUM),
)


@dataclass(frozen=True)
class MigrationResult:
    previous_version: int
    version: int
    applied: bool
    backup_path: Path | None


def _user_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = connection.execute(
        "SELECT type, name FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'trigger', 'view')"
    )
    return {(row[0], row[1]) for row in rows}


def _execute_statements(connection: sqlite3.Connection, sql: str) -> None:
    statement = ""
    for line in canonical_sql_bytes(sql).decode("utf-8").splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        raise StoreError("MIGRATION_INVALID_SQL", "incomplete SQL statement")


def schema_object_fingerprint(sql: str) -> str:
    normalized = sql.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def pending_migrations(
    current_version: int,
    target_version: int,
    *,
    migrations: tuple[Migration, ...] = MIGRATIONS,
) -> tuple[Migration, ...]:
    """Select only migrations inside the explicit inclusive target ceiling."""

    if target_version < 0:
        raise StoreError("MIGRATION_TARGET_VERSION_INVALID", str(target_version))
    registered_versions = {migration.version for migration in migrations}
    if target_version != 0 and target_version not in registered_versions:
        raise StoreError("MIGRATION_TARGET_VERSION_UNREGISTERED", str(target_version))
    if current_version > target_version:
        raise StoreError(
            "FAIL_CLOSED_TARGET_VERSION_OVERSHOOT",
            f"current={current_version},target={target_version}",
        )
    return tuple(
        migration
        for migration in migrations
        if current_version < migration.version <= target_version
    )


@lru_cache(maxsize=None)
def expected_schema_object_fingerprints(
    target_version: int = SCHEMA_VERSION,
) -> tuple[tuple[str, str, str], ...]:
    """Canonical sqlite_schema fingerprints through an explicit schema target."""

    selected = pending_migrations(0, target_version)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(SCHEMA_MIGRATION_SQL)
        for migration in selected:
            _execute_statements(connection, migration.sql)
        rows = connection.execute(
            "SELECT type,name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view')"
        )
        fingerprints = []
        for kind, name, sql in rows:
            if not isinstance(sql, str):
                raise StoreError("MIGRATION_SCHEMA_INVALID", f"missing canonical SQL for {kind}:{name}")
            fingerprints.append((kind, name, schema_object_fingerprint(sql)))
        return tuple(sorted(fingerprints))
    finally:
        connection.close()


def _schema_history(connection: sqlite3.Connection) -> tuple[tuple[int, str, str], ...]:
    return tuple(
        (int(version), str(name), str(checksum))
        for version, name, checksum in connection.execute(
            "SELECT version,name,checksum FROM schema_migration ORDER BY version"
        )
    )


def schema_profile_identity(connection: sqlite3.Connection, target_version: int) -> str:
    """Compute the same exact profile identity frozen into the thin-client contract."""

    validate_schema(connection, target_version=target_version)
    history = _schema_history(connection)
    expected_history = tuple(
        (migration.version, migration.name, migration.checksum)
        for migration in pending_migrations(0, target_version)
    )
    if history != expected_history:
        raise StoreError("MIGRATION_CHECKSUM_MISMATCH")
    fingerprints = expected_schema_object_fingerprints(target_version)
    payload = {
        "schema_version": target_version,
        "migration_history": [list(item) for item in history],
        "expected_tables": sorted(name for kind, name, _ in fingerprints if kind == "table"),
        "expected_indexes": sorted(name for kind, name, _ in fingerprints if kind == "index"),
        "expected_triggers": sorted(name for kind, name, _ in fingerprints if kind == "trigger"),
        "expected_object_fingerprints": [list(item) for item in fingerprints],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def validate_schema(
    connection: sqlite3.Connection,
    *,
    target_version: int = SCHEMA_VERSION,
) -> None:
    expected_fingerprints = {
        (kind, name): digest
        for kind, name, digest in expected_schema_object_fingerprints(target_version)
    }
    actual_fingerprints: dict[tuple[str, str], str] = {}
    for kind, name, sql in connection.execute(
        "SELECT type,name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view')"
    ):
        if not isinstance(sql, str):
            raise StoreError("MIGRATION_SCHEMA_INVALID", f"missing SQL for {kind}:{name}")
        actual_fingerprints[(kind, name)] = schema_object_fingerprint(sql)
    if actual_fingerprints != expected_fingerprints:
        raise StoreError("MIGRATION_SCHEMA_INVALID", "schema object definition mismatch")
    integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
    if integrity != ["ok"]:
        raise StoreError("MIGRATION_INTEGRITY_FAILED", repr(integrity))
    foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
    if foreign_keys:
        raise StoreError("MIGRATION_FOREIGN_KEY_FAILED", repr(foreign_keys))


def _backup(
    connection: sqlite3.Connection,
    backup_root: Path,
    current_version: int,
    checksum: str,
    now: datetime,
) -> Path:
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = backup_root / f"control.sqlite3.v{current_version}.{stamp}.{checksum[:12]}.bak"
    temporary = target.with_name(target.name + ".tmp")
    destination = sqlite3.connect(temporary, isolation_level=None)
    try:
        try:
            connection.backup(destination)
            result = [row[0] for row in destination.execute("PRAGMA integrity_check")]
            if result != ["ok"]:
                raise StoreError("MIGRATION_BACKUP_INVALID", repr(result))
        finally:
            destination.close()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, target)
    return target


def _prune_backups(backup_root: Path) -> None:
    backups = sorted(backup_root.glob("control.sqlite3.v*.bak"), reverse=True)
    for old in backups[5:]:
        old.unlink()


def migrate_to_v7(
    connection: sqlite3.Connection,
    *,
    backup_root: Path | None = None,
    now: datetime | None = None,
) -> MigrationResult:
    """Frozen schema-v6/v7 production-compatible boundary with an exact target of 7."""

    return migrate(
        connection,
        backup_root=backup_root,
        now=now,
        target_version=7,
    )


def migrate(
    connection: sqlite3.Connection,
    *,
    backup_root: Path | None = None,
    now: datetime | None = None,
    migration_sql: str = MIGRATION_1_SQL,
    migration_2_sql: str = MIGRATION_2_SQL,
    migration_3_sql: str = MIGRATION_3_SQL,
    migration_4_sql: str = MIGRATION_4_SQL,
    migration_5_sql: str = MIGRATION_5_SQL,
    migration_6_sql: str = MIGRATION_6_SQL,
    migration_7_sql: str = MIGRATION_7_SQL,
    migration_8_sql: str = MIGRATION_8_SQL,
    migration_9_sql: str = MIGRATION_9_SQL,
    migration_10_sql: str = MIGRATION_10_SQL,
    target_version: int = SCHEMA_VERSION,
) -> MigrationResult:
    """Recognize and migrate only through an explicit schema-version ceiling."""

    current_objects = _user_objects(connection)
    bootstrap_created = False
    if not current_objects:
        connection.execute(SCHEMA_MIGRATION_SQL)
        bootstrap_created = True
        current_objects = _user_objects(connection)
    elif ("table", "schema_migration") not in current_objects:
        raise StoreError("UNRECOGNIZED_DATABASE")

    rows = list(
        connection.execute(
            "SELECT version, name, checksum FROM schema_migration ORDER BY version"
        )
    )
    max_registered_version = max(migration.version for migration in MIGRATIONS)
    if rows and rows[-1][0] > max_registered_version:
        raise StoreError("MIGRATION_VERSION_AHEAD")
    registered = {migration.version: migration for migration in MIGRATIONS}
    if [row[0] for row in rows] != list(range(1, len(rows) + 1)):
        raise StoreError("MIGRATION_CHECKSUM_MISMATCH")
    for version, name, checksum in rows:
        expected = registered.get(version)
        if expected is None or name != expected.name or checksum != expected.checksum:
            raise StoreError("MIGRATION_CHECKSUM_MISMATCH")

    current_version = rows[-1][0] if rows else 0
    selected = pending_migrations(current_version, target_version)
    if current_version == target_version:
        validate_schema(connection, target_version=target_version)
        return MigrationResult(current_version, current_version, False, None)

    allowed_v0 = {("table", "schema_migration")}
    if current_version == 0 and current_objects != allowed_v0:
        raise StoreError("UNRECOGNIZED_DATABASE")

    sql_by_version = {
        1: migration_sql,
        2: migration_2_sql,
        3: migration_3_sql,
        4: migration_4_sql,
        5: migration_5_sql,
        6: migration_6_sql,
        7: migration_7_sql,
        8: migration_8_sql,
        9: migration_9_sql,
        10: migration_10_sql,
    }
    pending = selected
    if not pending:
        raise StoreError(
            "MIGRATION_TARGET_VERSION_UNREACHABLE",
            f"current={current_version},target={target_version}",
        )
    checksum = migration_checksum(sql_by_version[pending[0].version])
    backup_path = None
    if not bootstrap_created and backup_root is not None:
        backup_path = _backup(
            connection,
            backup_root,
            current_version,
            checksum,
            now or datetime.now(timezone.utc),
        )

    connection.execute("BEGIN IMMEDIATE")
    try:
        applied_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        )
        for migration in pending:
            sql = sql_by_version[migration.version]
            applied_checksum = migration_checksum(sql)
            _execute_statements(connection, sql)
            connection.execute(
                "INSERT INTO schema_migration(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, applied_checksum, applied_at),
            )
        actual_version = connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0]
        if actual_version != target_version:
            raise StoreError(
                "FAIL_CLOSED_TARGET_VERSION_OVERSHOOT",
                f"actual={actual_version},target={target_version}",
            )
        validate_schema(connection, target_version=target_version)
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise

    if backup_root is not None:
        _prune_backups(backup_root)
    return MigrationResult(current_version, target_version, True, backup_path)
