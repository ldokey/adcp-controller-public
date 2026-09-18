"""Canonical, transport-independent shadow projection for the Control Store."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import sqlite3
from typing import Any, Mapping, Protocol

from adcp.canonical import canonical_json, canonical_sha256
from adcp.domain import timestamp
from adcp.store.sqlite import ControlStore


PROJECTION_SCHEMA_VERSION = 1


class ProjectionError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class ProjectionTargetUnavailable(ProjectionError):
    def __init__(self, detail: str = "") -> None:
        super().__init__("PROJECTION_TARGET_UNAVAILABLE", detail)


class ProjectionDrift(StrEnum):
    NO_DRIFT = "NO_DRIFT"
    PROJECTION_MISSING_OR_STALE = "PROJECTION_MISSING_OR_STALE"
    PROJECTION_CONTENT_MISMATCH = "PROJECTION_CONTENT_MISMATCH"
    PROJECTION_TARGET_UNAVAILABLE = "PROJECTION_TARGET_UNAVAILABLE"


@dataclass(frozen=True)
class ProjectionEnvelope:
    payload: dict[str, Any]
    projection_payload_hash: str
    projection_identity: str

    def as_dict(self) -> dict[str, Any]:
        return {**self.payload, "projection_payload_hash": self.projection_payload_hash}


@dataclass(frozen=True)
class DriftReport:
    classification: ProjectionDrift
    expected_hash: str
    observed_hash: str | None
    blocks_cutover: bool


class ProjectionTarget(Protocol):
    target_type: str
    target_ref: str

    def read(self, execution_id: str) -> Mapping[str, Any] | None: ...

    def write(
        self,
        execution_id: str,
        projection_identity: str,
        payload: Mapping[str, Any],
    ) -> None: ...


class InMemoryProjectionTarget:
    """Deterministic fake transport used by normal C5A tests."""

    target_type = "MEMORY"

    def __init__(self, target_ref: str = "memory://shadow") -> None:
        self.target_ref = target_ref
        self.values: dict[str, tuple[str, dict[str, Any]]] = {}
        self.available = True
        self.fail_writes = 0
        self.lose_response_once = False
        self.write_count = 0

    def read(self, execution_id: str) -> Mapping[str, Any] | None:
        if not self.available:
            raise ProjectionTargetUnavailable(self.target_ref)
        item = self.values.get(execution_id)
        return None if item is None else json.loads(canonical_json(item[1]))

    def write(
        self,
        execution_id: str,
        projection_identity: str,
        payload: Mapping[str, Any],
    ) -> None:
        if not self.available:
            raise ProjectionTargetUnavailable(self.target_ref)
        self.write_count += 1
        if self.fail_writes > 0:
            self.fail_writes -= 1
            raise ProjectionTargetUnavailable("deterministic write failure")
        materialized = json.loads(canonical_json(dict(payload)))
        supplied_hash = materialized.pop("projection_payload_hash", None)
        valid = (
            isinstance(supplied_hash, str)
            and canonical_sha256(materialized) == supplied_hash
            and canonical_sha256(
                {
                    "control_execution_id": execution_id,
                    "projection_payload_hash": supplied_hash,
                }
            )
            == projection_identity
        )
        if not valid:
            raise ProjectionError("PROJECTION_IDENTITY_MISMATCH")
        materialized["projection_payload_hash"] = supplied_hash
        existing = self.values.get(execution_id)
        if existing is not None and existing[0] == projection_identity:
            if canonical_json(existing[1]) != canonical_json(materialized):
                self.values[execution_id] = (projection_identity, materialized)
        else:
            self.values[execution_id] = (projection_identity, materialized)
        if self.lose_response_once:
            self.lose_response_once = False
            raise ProjectionTargetUnavailable("response lost after write")


def _row_dict(row: sqlite3.Row | None, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if row is None:
        return None
    return {field: row[field] for field in fields}


def _latest_bound_row(
    store: ControlStore,
    table: str,
    sequence: str,
    execution: sqlite3.Row,
) -> sqlite3.Row | None:
    if execution["result_commit"] is None:
        return None
    return store.connection.execute(
        f"""SELECT * FROM {table}
              WHERE execution_id = ? AND result_commit = ?
                AND contract_fingerprint = ? AND authority_fingerprint = ?
              ORDER BY {sequence} DESC LIMIT 1""",
        (
            execution["execution_id"],
            execution["result_commit"],
            execution["contract_fingerprint"],
            execution["authority_fingerprint"],
        ),
    ).fetchone()


def build_projection(store: ControlStore, execution_id: str) -> ProjectionEnvelope:
    """Build one projection solely from current durable Control Store rows."""

    execution = store.get_execution(execution_id)
    attempts = list(
        store.connection.execute(
            """SELECT role, attempt_no, status, failure_code, started_at, ended_at
                 FROM agent_attempt WHERE execution_id = ? ORDER BY role, attempt_no""",
            (execution_id,),
        )
    )
    attempt_summary = {
        role: {
            "count": len(items),
            "latest_attempt_no": items[-1]["attempt_no"],
            "latest_status": items[-1]["status"],
            "latest_failure_code": items[-1]["failure_code"],
        }
        for role in ("MAKER", "EVALUATOR")
        if (items := [attempt for attempt in attempts if attempt["role"] == role])
    }
    verification = _latest_bound_row(
        store, "verification_result", "verification_seq", execution
    )
    evaluation = _latest_bound_row(
        store, "evaluation_result", "evaluation_seq", execution
    )
    approval = store.connection.execute(
        """SELECT status, requested_at, resolved_at, consumed_at
             FROM approval_request WHERE execution_id = ?
             ORDER BY requested_at DESC LIMIT 1""",
        (execution_id,),
    ).fetchone()
    manifest = store.connection.execute(
        "SELECT manifest_sha256, created_at FROM evidence_manifest WHERE execution_id = ?",
        (execution_id,),
    ).fetchone()
    evidence_times = [execution["updated_at"]]
    for attempt in attempts:
        evidence_times.append(attempt["ended_at"] or attempt["started_at"])
    if verification is not None:
        evidence_times.append(verification["ended_at"])
    if evaluation is not None:
        evidence_times.append(evaluation["ended_at"])
    if approval is not None:
        evidence_times.append(
            approval["consumed_at"] or approval["resolved_at"] or approval["requested_at"]
        )
    if manifest is not None:
        evidence_times.append(manifest["created_at"])
    projected_at = max(value for value in evidence_times if value is not None)
    blocker = None
    if execution["blocker_code"] is not None:
        blocker = {
            "code": execution["blocker_code"],
            "detail": execution["blocker_detail"],
            "resume_state": execution["resume_state"],
        }
    semantic = {
        "projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "control_execution_id": execution_id,
        "execution_state": execution["state"],
        "state_version": execution["state_version"],
        "source_root": execution["source_root"],
        "base_commit": execution["base_commit"],
        "result_commit": execution["result_commit"],
        "risk": execution["risk_level"],
        "blocker_or_escalation": blocker,
        "attempt_summary": attempt_summary,
        "verification_status": _row_dict(
            verification, ("verification_id", "verdict", "result_commit")
        ),
        "evaluator_verdict": _row_dict(
            evaluation, ("evaluation_id", "verdict", "result_commit")
        ),
        "approval_status": _row_dict(
            approval, ("status", "requested_at", "resolved_at", "consumed_at")
        ),
        "evidence_manifest_hash": manifest["manifest_sha256"] if manifest else None,
        "projected_at": projected_at,
    }
    projection_version = execution["state_version"]
    payload = {
        "projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "control_execution_id": execution_id,
        "projection_version": projection_version,
        **{key: value for key, value in semantic.items() if key not in {
            "projection_schema_version", "control_execution_id"
        }},
    }
    payload_hash = canonical_sha256(payload)
    identity = canonical_sha256(
        {"control_execution_id": execution_id, "projection_payload_hash": payload_hash}
    )
    return ProjectionEnvelope(payload, payload_hash, identity)


def compare_projection(
    expected: ProjectionEnvelope,
    target: ProjectionTarget,
) -> DriftReport:
    try:
        observed = target.read(expected.payload["control_execution_id"])
    except ProjectionTargetUnavailable:
        return DriftReport(
            ProjectionDrift.PROJECTION_TARGET_UNAVAILABLE,
            expected.projection_payload_hash,
            None,
            True,
        )
    if observed is None:
        return DriftReport(
            ProjectionDrift.PROJECTION_MISSING_OR_STALE,
            expected.projection_payload_hash,
            None,
            True,
        )
    observed_hash = observed.get("projection_payload_hash")
    observed_without_hash = dict(observed)
    observed_without_hash.pop("projection_payload_hash", None)
    internally_valid = (
        isinstance(observed_hash, str)
        and canonical_sha256(observed_without_hash) == observed_hash
    )
    if internally_valid and canonical_json(observed) == canonical_json(expected.as_dict()):
        return DriftReport(
            ProjectionDrift.NO_DRIFT,
            expected.projection_payload_hash,
            observed_hash,
            False,
        )
    observed_version = observed.get("projection_version")
    expected_version = expected.payload["projection_version"]
    classification = (
        ProjectionDrift.PROJECTION_MISSING_OR_STALE
        if isinstance(observed_version, int) and observed_version != expected_version
        else ProjectionDrift.PROJECTION_CONTENT_MISMATCH
    )
    return DriftReport(classification, expected.projection_payload_hash, observed_hash, True)


class ProjectionService:
    def __init__(self, store: ControlStore, target: ProjectionTarget) -> None:
        self.store = store
        self.target = target

    def project(self, execution_id: str) -> ProjectionEnvelope:
        envelope = build_projection(self.store, execution_id)
        idempotency_key = canonical_sha256(
            {
                "projection_identity": envelope.projection_identity,
                "target_type": self.target.target_type,
                "target_ref": self.target.target_ref,
            }
        )
        projection_id = f"projection-{idempotency_key}"
        now = timestamp(self.store._now())
        self.store._begin()
        try:
            existing = self.store.connection.execute(
                "SELECT * FROM projection_record WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is None:
                self.store.connection.execute(
                    """INSERT INTO projection_record(
                        projection_id, execution_id, manifest_id, target_type, target_ref,
                        projection_version, status, idempotency_key, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)""",
                    (
                        projection_id,
                        execution_id,
                        self._manifest_id(execution_id),
                        self.target.target_type,
                        self.target.target_ref,
                        envelope.payload["projection_version"],
                        idempotency_key,
                        now,
                    ),
                )
            else:
                exact = (
                    existing["projection_id"] == projection_id
                    and existing["execution_id"] == execution_id
                    and existing["target_type"] == self.target.target_type
                    and existing["target_ref"] == self.target.target_ref
                    and existing["projection_version"] == envelope.payload["projection_version"]
                )
                if not exact:
                    raise ProjectionError("PROJECTION_IDEMPOTENCY_CONFLICT")
            self.store.connection.execute(
                """UPDATE projection_record
                      SET status = 'PENDING', attempt_count = attempt_count + 1,
                          last_attempt_at = ?, last_error = NULL, projected_at = NULL
                    WHERE idempotency_key = ?""",
                (now, idempotency_key),
            )
            self.store.connection.execute("COMMIT")
        except BaseException:
            if self.store.connection.in_transaction:
                self.store.connection.execute("ROLLBACK")
            raise
        try:
            self.target.write(execution_id, envelope.projection_identity, envelope.as_dict())
        except Exception as error:
            code = (
                error.code
                if isinstance(error, ProjectionError)
                else "PROJECTION_TRANSPORT_FAILURE"
            )
            try:
                # Post-external durable status is an ordinary Production DCS mutation.
                # On guarded Production stores, _begin() freshly reasserts authority.
                self.store._begin()
                self.store.connection.execute(
                    """UPDATE projection_record SET status = 'FAILED', last_error = ?
                         WHERE idempotency_key = ?""",
                    (code, idempotency_key),
                )
                self.store.connection.execute("COMMIT")
            except BaseException:
                if self.store.connection.in_transaction:
                    self.store.connection.execute("ROLLBACK")
                raise
            if isinstance(error, ProjectionError):
                raise
            raise ProjectionError(code) from error
        completed_at = timestamp(self.store._now())
        try:
            # SC-13: target success does not authorize a stale owner to persist SUCCEEDED.
            self.store._begin()
            self.store.connection.execute(
                """UPDATE projection_record
                      SET status = 'SUCCEEDED', projected_at = ?, last_error = NULL
                    WHERE idempotency_key = ?""",
                (completed_at, idempotency_key),
            )
            self.store.connection.execute("COMMIT")
        except BaseException:
            if self.store.connection.in_transaction:
                self.store.connection.execute("ROLLBACK")
            raise
        return envelope

    def reconcile(self, execution_id: str) -> DriftReport:
        expected = build_projection(self.store, execution_id)
        report = compare_projection(expected, self.target)
        if report.classification is not ProjectionDrift.NO_DRIFT:
            self.project(execution_id)
            report = compare_projection(build_projection(self.store, execution_id), self.target)
        return report

    def _manifest_id(self, execution_id: str) -> str:
        row = self.store.connection.execute(
            "SELECT manifest_id FROM evidence_manifest WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise ProjectionError("EVIDENCE_MANIFEST_REQUIRED")
        return row["manifest_id"]


__all__ = [
    "DriftReport",
    "InMemoryProjectionTarget",
    "PROJECTION_SCHEMA_VERSION",
    "ProjectionDrift",
    "ProjectionEnvelope",
    "ProjectionError",
    "ProjectionService",
    "ProjectionTarget",
    "ProjectionTargetUnavailable",
    "build_projection",
    "compare_projection",
]
