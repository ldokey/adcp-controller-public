"""Pure canonical Evidence Manifest construction; database acceptance is deferred."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence

from adcp.canonical import canonical_json, canonical_sha256
from adcp.domain import require_commit, require_sha256


def _sorted_canonical(values: Sequence[Any]) -> list[Any]:
    materialized = [json.loads(canonical_json(value)) for value in values]
    return sorted(materialized, key=canonical_json)


def _normalize_context(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    materialized: list[dict[str, Any]] = []
    for value in values:
        item = json.loads(canonical_json(dict(value)))
        if not isinstance(item.get("role"), str) or not isinstance(
            item.get("context_snapshot_id"), str
        ):
            raise ValueError("CONTEXT_FINGERPRINT_EVIDENCE_INVALID")
        materialized.append(item)
    return sorted(
        materialized,
        key=lambda item: (
            item["role"],
            item["context_snapshot_id"],
            canonical_json(item),
        ),
    )


def _normalize_transitions(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    materialized: list[dict[str, Any]] = []
    for value in values:
        item = json.loads(canonical_json(dict(value)))
        version = item.get("to_state_version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("TRANSITION_EVIDENCE_INVALID")
        materialized.append(item)
    return sorted(
        materialized,
        key=lambda item: (item["to_state_version"], canonical_json(item)),
    )


def canonical_evidence_payload(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize ordered evidence fields and exclude derived hash material."""

    payload = dict(fields)
    payload.pop("manifest_sha256", None)
    payload.pop("canonical_json", None)
    payload["approval_refs"] = _sorted_canonical(payload.get("approval_refs", []))
    payload["context_fingerprints"] = _normalize_context(
        payload.get("context_fingerprints", [])
    )
    payload["transition_evidence"] = _normalize_transitions(
        payload.get("transition_evidence", [])
    )
    return json.loads(canonical_json(payload))


@dataclass(frozen=True)
class EvidenceManifest:
    materialized_fields: dict[str, Any]
    canonical_json: str
    manifest_sha256: str

    def as_record(self) -> dict[str, Any]:
        return {
            **self.materialized_fields,
            "canonical_json": self.canonical_json,
            "manifest_sha256": self.manifest_sha256,
        }


def build_evidence_manifest(
    *,
    manifest_id: str,
    execution_id: str,
    slice_id: str,
    contract_fingerprint: str,
    authority_fingerprint: str,
    base_commit: str,
    result_commit: str,
    maker_attempt_evidence: Any,
    verification_evidence: Any,
    evaluator_attempt_evidence: Any,
    evaluation_evidence: Any,
    approval_refs: Sequence[Any],
    context_fingerprints: Sequence[Mapping[str, Any]],
    transition_evidence: Sequence[Mapping[str, Any]],
    created_at: str,
) -> EvidenceManifest:
    if not manifest_id or not execution_id or not slice_id or not created_at:
        raise ValueError("EVIDENCE_MANIFEST_INVALID")
    require_sha256(contract_fingerprint, "contract_fingerprint")
    require_sha256(authority_fingerprint, "authority_fingerprint")
    require_commit(base_commit, "base_commit")
    require_commit(result_commit, "result_commit")
    fields = canonical_evidence_payload(
        {
            "manifest_id": manifest_id,
            "execution_id": execution_id,
            "slice_id": slice_id,
            "contract_fingerprint": contract_fingerprint,
            "authority_fingerprint": authority_fingerprint,
            "base_commit": base_commit,
            "result_commit": result_commit,
            "maker_attempt_evidence": maker_attempt_evidence,
            "verification_evidence": verification_evidence,
            "evaluator_attempt_evidence": evaluator_attempt_evidence,
            "evaluation_evidence": evaluation_evidence,
            "approval_refs": list(approval_refs),
            "context_fingerprints": list(context_fingerprints),
            "transition_evidence": list(transition_evidence),
            "created_at": created_at,
        }
    )
    serialized = canonical_json(fields)
    return EvidenceManifest(
        materialized_fields=fields,
        canonical_json=serialized,
        manifest_sha256=canonical_sha256(fields),
    )
