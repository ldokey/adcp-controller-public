"""Fail-closed typed PostgreSQL projection of already-granted HQ approval evidence.

Notion/HQ remains the human authority.  Files validated here are immutable machine
projections only; they cannot mint authority and callers cannot select arbitrary paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping


class PostgresApprovalEvidenceError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class ProtectedApprovalEvidenceSource:
    root: Path
    expected_owner_uid: int


@dataclass(frozen=True)
class ExpectedProductionOperationApprovalBinding:
    project_code: str
    change_id: str
    gate_or_control_id: str
    operation_kind: str
    authorized_effect_scope: tuple[str, ...]
    controller_commit: str
    controller_tree: str
    controller_entrypoint: str
    target_identity: Mapping[str, Any]
    operation_artifact_identity: Mapping[str, Any] | None


@dataclass(frozen=True)
class ProductionOperationApprovalEvidenceV1:
    approval_id: str
    decision_stable_id: str
    decision_page_identity: str
    project_code: str
    change_id: str
    gate_or_control_id: str
    operation_kind: str
    issued_at: str
    expires_at: str
    evidence_sha256: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _require_protected_directory(source: ProtectedApprovalEvidenceSource) -> Path:
    root = Path(os.path.abspath(source.root))
    try:
        meta = root.lstat()
    except OSError as error:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_SOURCE_UNAVAILABLE") from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_SOURCE_INVALID")
    if stat.S_IMODE(meta.st_mode) != 0o700 or meta.st_uid != source.expected_owner_uid:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_SOURCE_UNPROTECTED")
    return root


def _read_protected_projection(source: ProtectedApprovalEvidenceSource, reference: str) -> bytes:
    if not isinstance(reference, str) or not reference or len(reference) > 512:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_CONTROL_DECISION_REF_REQUIRED")
    root = _require_protected_directory(source)
    name = hashlib.sha256(reference.encode("utf-8")).hexdigest() + ".json"
    path = root / name
    try:
        before = path.lstat()
    except OSError as error:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_NOT_FOUND") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_FILE_INVALID")
    if before.st_uid != source.expected_owner_uid or stat.S_IMODE(before.st_mode) != 0o600:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_FILE_UNPROTECTED")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_OPEN_REJECTED") from error
    try:
        opened = os.fstat(fd)
        if _fingerprint(opened) != _fingerprint(before):
            raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_SUBSTITUTION_DETECTED")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if _fingerprint(after) != _fingerprint(opened):
            raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_MUTATED_DURING_READ")
    finally:
        os.close(fd)
    current = path.lstat()
    if _fingerprint(current) != _fingerprint(before):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_MUTATED_AFTER_READ")
    return b"".join(chunks)


def controller_git_identity(root: Path) -> tuple[str, str]:
    root = Path(root).expanduser().resolve(strict=True)
    top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=False, capture_output=True, text=True,
    )
    if top.returncode != 0 or Path(top.stdout.strip()).resolve(strict=True) != root:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_CONTROLLER_SOURCE_ROOT_MISMATCH")
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if dirty:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_CONTROLLER_SOURCE_DIRTY")
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return commit, tree


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PostgresApprovalEvidenceError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PostgresApprovalEvidenceError(code) from error
    if parsed.tzinfo is None:
        raise PostgresApprovalEvidenceError(code)
    return parsed.astimezone(timezone.utc)


def resolve_production_operation_approval_evidence(
    source: ProtectedApprovalEvidenceSource,
    *,
    control_decision_ref: str,
    expected: ExpectedProductionOperationApprovalBinding,
    now: datetime | None = None,
) -> ProductionOperationApprovalEvidenceV1:
    raw = _read_protected_projection(source, control_decision_ref)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_MALFORMED") from error
    if not isinstance(payload, dict):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_MALFORMED")
    required = {
        "schema_version", "approval_id", "approval_status", "decision_identity",
        "project_code", "change_id", "gate_or_control_id", "operation_kind",
        "authorized_effect_scope", "controller_source", "target_identity",
        "operation_artifact_identity", "issued_at", "expires_at",
        "supersession_or_disposition", "evidence_sha256",
    }
    if set(payload) != required or payload.get("schema_version") != 1:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_SCHEMA_INVALID")
    supplied_hash = payload.get("evidence_sha256")
    if not isinstance(supplied_hash, str) or len(supplied_hash) != 64:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_HASH_INVALID")
    unhashed = dict(payload)
    del unhashed["evidence_sha256"]
    actual_hash = hashlib.sha256(_canonical_json(unhashed).encode("utf-8")).hexdigest()
    if supplied_hash != actual_hash:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EVIDENCE_HASH_MISMATCH")
    approval_id = payload.get("approval_id")
    decision = payload.get("decision_identity")
    if (
        not isinstance(approval_id, str) or not approval_id
        or not isinstance(decision, dict)
        or set(decision) != {"stable_id", "canonical_page_identity"}
        or not isinstance(decision.get("stable_id"), str) or not decision.get("stable_id")
        or not isinstance(decision.get("canonical_page_identity"), str)
        or not decision.get("canonical_page_identity")
    ):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_DECISION_IDENTITY_INVALID")
    if control_decision_ref not in {approval_id, decision["stable_id"]}:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_CONTROL_DECISION_REF_MISMATCH")
    if payload.get("approval_status") != "GRANTED":
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_NOT_GRANTED")
    if payload.get("supersession_or_disposition") != "ACTIVE":
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_STALE_OR_REVOKED")
    issued = _parse_timestamp(payload.get("issued_at"), "TYPED_POSTGRES_APPROVAL_ISSUED_AT_INVALID")
    expires = _parse_timestamp(payload.get("expires_at"), "TYPED_POSTGRES_APPROVAL_EXPIRES_AT_INVALID")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued > current or expires <= issued or current >= expires:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_EXPIRED_OR_NOT_YET_VALID")
    controller = payload.get("controller_source")
    if not isinstance(controller, dict) or set(controller) != {"commit", "tree", "entrypoint"}:
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_CONTROLLER_SOURCE_INVALID")
    exact_pairs = (
        ("project_code", payload.get("project_code"), expected.project_code),
        ("change_id", payload.get("change_id"), expected.change_id),
        ("gate_or_control_id", payload.get("gate_or_control_id"), expected.gate_or_control_id),
        ("operation_kind", payload.get("operation_kind"), expected.operation_kind),
        ("authorized_effect_scope", payload.get("authorized_effect_scope"), list(expected.authorized_effect_scope)),
        ("controller_commit", controller.get("commit"), expected.controller_commit),
        ("controller_tree", controller.get("tree"), expected.controller_tree),
        ("controller_entrypoint", controller.get("entrypoint"), expected.controller_entrypoint),
        ("target_identity", payload.get("target_identity"), dict(expected.target_identity)),
        ("operation_artifact_identity", payload.get("operation_artifact_identity"), None if expected.operation_artifact_identity is None else dict(expected.operation_artifact_identity)),
    )
    for name, actual, wanted in exact_pairs:
        if actual != wanted:
            raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_BINDING_MISMATCH", name)
    return ProductionOperationApprovalEvidenceV1(
        approval_id=approval_id,
        decision_stable_id=decision["stable_id"],
        decision_page_identity=decision["canonical_page_identity"],
        project_code=expected.project_code,
        change_id=expected.change_id,
        gate_or_control_id=expected.gate_or_control_id,
        operation_kind=expected.operation_kind,
        issued_at=payload["issued_at"],
        expires_at=payload["expires_at"],
        evidence_sha256=supplied_hash,
    )


@dataclass(frozen=True)
class GrantedProductionOperationApprovalProjectionV1:
    """Typed Control-plane input for serializing an already-GRANTED HQ decision.

    This type is deliberately not an authority issuer.  The caller must already
    hold the human/HQ grant; this object only freezes that grant into the DL-35
    machine projection consumed by ``resolve_production_operation_approval_evidence``.
    """

    lookup_reference: str
    approval_id: str
    decision_stable_id: str
    decision_page_identity: str
    project_code: str
    change_id: str
    gate_or_control_id: str
    operation_kind: str
    authorized_effect_scope: tuple[str, ...]
    controller_commit: str
    controller_tree: str
    controller_entrypoint: str
    target_identity: Mapping[str, Any]
    operation_artifact_identity: Mapping[str, Any] | None
    issued_at: str
    expires_at: str


def _is_lower_hex(value: str, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _materialization_root(source: ProtectedApprovalEvidenceSource) -> Path:
    """Create only missing 0700 descendants of an already protected ancestor."""

    root = Path(os.path.abspath(source.root))
    missing: list[Path] = []
    current = root
    while True:
        try:
            meta = current.lstat()
            break
        except FileNotFoundError:
            if current == current.parent:
                raise PostgresApprovalEvidenceError(
                    "TYPED_POSTGRES_APPROVAL_EVIDENCE_PARENT_UNPROTECTED"
                )
            missing.append(current)
            current = current.parent
        except OSError as error:
            raise PostgresApprovalEvidenceError(
                "TYPED_POSTGRES_APPROVAL_EVIDENCE_PARENT_UNAVAILABLE"
            ) from error

    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_EVIDENCE_PARENT_UNPROTECTED"
        )
    if meta.st_uid != source.expected_owner_uid or stat.S_IMODE(meta.st_mode) & 0o022:
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_EVIDENCE_PARENT_UNPROTECTED"
        )

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        created = directory.lstat()
        if (
            stat.S_ISLNK(created.st_mode)
            or not stat.S_ISDIR(created.st_mode)
            or created.st_uid != source.expected_owner_uid
            or stat.S_IMODE(created.st_mode) != 0o700
        ):
            raise PostgresApprovalEvidenceError(
                "TYPED_POSTGRES_APPROVAL_EVIDENCE_SOURCE_UNPROTECTED"
            )
    return _require_protected_directory(source)


def _projection_payload(
    projection: GrantedProductionOperationApprovalProjectionV1,
) -> dict[str, Any]:
    required_text = {
        "lookup_reference": projection.lookup_reference,
        "approval_id": projection.approval_id,
        "decision_stable_id": projection.decision_stable_id,
        "decision_page_identity": projection.decision_page_identity,
        "project_code": projection.project_code,
        "change_id": projection.change_id,
        "gate_or_control_id": projection.gate_or_control_id,
        "operation_kind": projection.operation_kind,
        "controller_entrypoint": projection.controller_entrypoint,
    }
    if any(not isinstance(value, str) or not value for value in required_text.values()):
        raise PostgresApprovalEvidenceError("TYPED_POSTGRES_APPROVAL_PROJECTION_INPUT_INVALID")
    if projection.lookup_reference not in {
        projection.approval_id,
        projection.decision_stable_id,
    }:
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_PROJECTION_LOOKUP_REF_INVALID"
        )
    if not _is_lower_hex(projection.controller_commit, 40) or not _is_lower_hex(
        projection.controller_tree, 40
    ):
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_PROJECTION_CONTROLLER_IDENTITY_INVALID"
        )
    if (
        not projection.authorized_effect_scope
        or any(
            not isinstance(item, str) or not item
            for item in projection.authorized_effect_scope
        )
        or len(set(projection.authorized_effect_scope))
        != len(projection.authorized_effect_scope)
    ):
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_PROJECTION_SCOPE_INVALID"
        )
    issued = _parse_timestamp(
        projection.issued_at, "TYPED_POSTGRES_APPROVAL_PROJECTION_ISSUED_AT_INVALID"
    )
    expires = _parse_timestamp(
        projection.expires_at, "TYPED_POSTGRES_APPROVAL_PROJECTION_EXPIRES_AT_INVALID"
    )
    if expires <= issued:
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_PROJECTION_FRESHNESS_INVALID"
        )

    payload: dict[str, Any] = {
        "schema_version": 1,
        "approval_id": projection.approval_id,
        "approval_status": "GRANTED",
        "decision_identity": {
            "stable_id": projection.decision_stable_id,
            "canonical_page_identity": projection.decision_page_identity,
        },
        "project_code": projection.project_code,
        "change_id": projection.change_id,
        "gate_or_control_id": projection.gate_or_control_id,
        "operation_kind": projection.operation_kind,
        "authorized_effect_scope": list(projection.authorized_effect_scope),
        "controller_source": {
            "commit": projection.controller_commit,
            "tree": projection.controller_tree,
            "entrypoint": projection.controller_entrypoint,
        },
        "target_identity": dict(projection.target_identity),
        "operation_artifact_identity": (
            None
            if projection.operation_artifact_identity is None
            else dict(projection.operation_artifact_identity)
        ),
        "issued_at": projection.issued_at,
        "expires_at": projection.expires_at,
        "supersession_or_disposition": "ACTIVE",
    }
    # Canonical serialization is also an early JSON-shape validation.  No arbitrary
    # caller JSON bytes are ever written to the protected projection root.
    canonical = _canonical_json(payload)
    payload["evidence_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def materialize_granted_production_operation_approval_projection(
    source: ProtectedApprovalEvidenceSource,
    *,
    projection: GrantedProductionOperationApprovalProjectionV1,
) -> Path:
    """Freeze one already-granted HQ decision as an immutable DL-35 projection.

    Missing protected descendants may be created under an existing owner-only
    ancestor.  Existing identical bytes are accepted idempotently; conflicting
    bytes are never replaced.  This helper neither queries nor grants HQ authority.
    """

    root = _materialization_root(source)
    payload = _projection_payload(projection)
    raw = (_canonical_json(payload) + "\n").encode("utf-8")
    name = hashlib.sha256(projection.lookup_reference.encode("utf-8")).hexdigest() + ".json"
    path = root / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = _read_protected_projection(source, projection.lookup_reference)
        if existing != raw:
            raise PostgresApprovalEvidenceError(
                "TYPED_POSTGRES_APPROVAL_PROJECTION_IMMUTABLE_CONFLICT"
            )
        return path
    except OSError as error:
        raise PostgresApprovalEvidenceError(
            "TYPED_POSTGRES_APPROVAL_PROJECTION_CREATE_REJECTED"
        ) from error
    try:
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            if count <= 0:
                raise PostgresApprovalEvidenceError(
                    "TYPED_POSTGRES_APPROVAL_PROJECTION_WRITE_FAILED"
                )
            written += count
        os.fsync(fd)
        current = os.fstat(fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != source.expected_owner_uid
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise PostgresApprovalEvidenceError(
                "TYPED_POSTGRES_APPROVAL_PROJECTION_FILE_UNPROTECTED"
            )
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)

    directory_fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return path
