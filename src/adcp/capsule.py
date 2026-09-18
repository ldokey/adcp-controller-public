"""Role-separated context capsule builders."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
from typing import Any, Mapping

from adcp.canonical import canonical_json, canonical_sha256


class CapsuleRole(StrEnum):
    MAKER = "MAKER"
    EVALUATOR = "EVALUATOR"


def _materialize(value: Any) -> Any:
    """Validate and detach a value into ordinary canonical JSON containers."""

    return json.loads(canonical_json(value))


@dataclass(frozen=True)
class ContextCapsule:
    capsule_version: int
    role: CapsuleRole
    content: dict[str, Any]
    canonical_json: str
    fingerprint: str

    @property
    def envelope(self) -> dict[str, Any]:
        return {
            "capsule_version": self.capsule_version,
            "role": self.role.value,
            "content": self.content,
        }


@dataclass(frozen=True)
class MakerCapsulePayload:
    slice: Any
    current_task: Any
    contract_fingerprint: str
    authority_fingerprint: str
    source_root: str
    branch: str
    base_commit: str
    current_commit: str
    acceptance_criteria: Any
    constraints: Any
    risk: str
    environment: str
    allowed_actions: Any
    forbidden_actions: Any
    relevant_authority_refs: Any
    relevant_authority_excerpts: Any
    previous_structured_rework_feedback: Any | None = None

    def to_content(self) -> dict[str, Any]:
        content = {
            "slice": self.slice,
            "current_task": self.current_task,
            "contract_fingerprint": self.contract_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "source_root": self.source_root,
            "branch": self.branch,
            "base_commit": self.base_commit,
            "current_commit": self.current_commit,
            "acceptance_criteria": self.acceptance_criteria,
            "constraints": self.constraints,
            "risk": self.risk,
            "environment": self.environment,
            "allowed_actions": self.allowed_actions,
            "forbidden_actions": self.forbidden_actions,
            "relevant_authority_refs": self.relevant_authority_refs,
            "relevant_authority_excerpts": self.relevant_authority_excerpts,
        }
        feedback = self.previous_structured_rework_feedback
        if feedback is not None:
            if not isinstance(feedback, (dict, list)):
                raise ValueError("STRUCTURED_REWORK_FEEDBACK_REQUIRED")
            content["previous_structured_rework_feedback"] = feedback
        return _materialize(content)


@dataclass(frozen=True)
class EvaluatorCapsulePayload:
    frozen_contract: Any
    acceptance_criteria: Any
    base_commit: str
    result_commit: str
    changed_file_manifest: Any
    diff: str
    deterministic_verification_result: Any
    relevant_authority_refs: Any
    relevant_authority_excerpts: Any

    def to_content(self) -> dict[str, Any]:
        return _materialize(
            {
                "frozen_contract": self.frozen_contract,
                "acceptance_criteria": self.acceptance_criteria,
                "base_commit": self.base_commit,
                "result_commit": self.result_commit,
                "changed_file_manifest": self.changed_file_manifest,
                "diff": self.diff,
                "deterministic_verification_result": self.deterministic_verification_result,
                "relevant_authority_refs": self.relevant_authority_refs,
                "relevant_authority_excerpts": self.relevant_authority_excerpts,
            }
        )


def build_context_capsule(
    role: CapsuleRole | str,
    content: dict[str, Any],
    *,
    capsule_version: int = 1,
) -> ContextCapsule:
    if isinstance(capsule_version, bool) or not isinstance(capsule_version, int):
        raise ValueError("CAPSULE_VERSION_INVALID")
    if capsule_version <= 0:
        raise ValueError("CAPSULE_VERSION_INVALID")
    if not isinstance(content, dict):
        raise ValueError("CAPSULE_CONTENT_OBJECT_REQUIRED")
    normalized_role = CapsuleRole(role)
    materialized_content = _materialize(content)
    envelope = {
        "capsule_version": capsule_version,
        "role": normalized_role.value,
        "content": materialized_content,
    }
    serialized = canonical_json(envelope)
    return ContextCapsule(
        capsule_version=capsule_version,
        role=normalized_role,
        content=materialized_content,
        canonical_json=serialized,
        fingerprint=canonical_sha256(envelope),
    )


def build_maker_capsule(
    payload: MakerCapsulePayload | Mapping[str, Any] | None = None,
    *,
    capsule_version: int = 1,
    **fields: Any,
) -> ContextCapsule:
    if payload is not None and fields:
        raise TypeError("provide payload or keyword fields, not both")
    if payload is None:
        payload = MakerCapsulePayload(**fields)
    elif isinstance(payload, Mapping):
        payload = MakerCapsulePayload(**payload)
    if not isinstance(payload, MakerCapsulePayload):
        raise TypeError("MakerCapsulePayload required")
    return build_context_capsule(
        CapsuleRole.MAKER, payload.to_content(), capsule_version=capsule_version
    )


def build_evaluator_capsule(
    payload: EvaluatorCapsulePayload | Mapping[str, Any] | None = None,
    *,
    capsule_version: int = 1,
    **fields: Any,
) -> ContextCapsule:
    if payload is not None and fields:
        raise TypeError("provide payload or keyword fields, not both")
    if payload is None:
        payload = EvaluatorCapsulePayload(**fields)
    elif isinstance(payload, Mapping):
        payload = EvaluatorCapsulePayload(**payload)
    if not isinstance(payload, EvaluatorCapsulePayload):
        raise TypeError("EvaluatorCapsulePayload required")
    return build_context_capsule(
        CapsuleRole.EVALUATOR, payload.to_content(), capsule_version=capsule_version
    )
