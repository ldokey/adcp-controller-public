from __future__ import annotations

import unittest

from adcp.canonical import canonical_json, canonical_sha256
from adcp.evidence import build_evidence_manifest, canonical_evidence_payload
from _helpers import COMMIT_A, COMMIT_B, HASH_A, HASH_B


def evidence(**overrides):
    values = {
        "manifest_id": "manifest-1",
        "execution_id": "execution-1",
        "slice_id": "WCP-06C2",
        "contract_fingerprint": HASH_A,
        "authority_fingerprint": HASH_B,
        "base_commit": COMMIT_A,
        "result_commit": COMMIT_B,
        "maker_attempt_evidence": {"attempt_id": "maker-1", "status": "SUCCEEDED"},
        "verification_evidence": {"verification_id": "verification-1", "verdict": "PASS"},
        "evaluator_attempt_evidence": {"attempt_id": "evaluator-1", "status": "SUCCEEDED"},
        "evaluation_evidence": {"evaluation_id": "evaluation-1", "verdict": "PASS"},
        "approval_refs": [
            {"approval_id": "approval-b"},
            {"approval_id": "approval-a"},
        ],
        "context_fingerprints": [
            {"role": "MAKER", "context_snapshot_id": "snapshot-b", "fingerprint": "b" * 64},
            {"role": "EVALUATOR", "context_snapshot_id": "snapshot-a", "fingerprint": "a" * 64},
            {"role": "MAKER", "context_snapshot_id": "snapshot-a", "fingerprint": "c" * 64},
        ],
        "transition_evidence": [
            {"event_id": "event-2", "to_state_version": 2},
            {"event_id": "event-0", "to_state_version": 0},
            {"event_id": "event-1", "to_state_version": 1},
        ],
        "created_at": "2026-08-11T01:04:03.456789+00:00",
    }
    values.update(overrides)
    return build_evidence_manifest(**values)


class EvidenceTests(unittest.TestCase):
    def test_evidence_input_order_normalized(self) -> None:
        first = evidence()
        second = evidence(approval_refs=list(reversed(first.materialized_fields["approval_refs"])))
        self.assertEqual(first.canonical_json, second.canonical_json)
        self.assertEqual(
            ["approval-a", "approval-b"],
            [item["approval_id"] for item in first.materialized_fields["approval_refs"]],
        )

    def test_evidence_context_order_normalized(self) -> None:
        first = evidence()
        contexts = first.materialized_fields["context_fingerprints"]
        self.assertEqual(
            [("EVALUATOR", "snapshot-a"), ("MAKER", "snapshot-a"), ("MAKER", "snapshot-b")],
            [(item["role"], item["context_snapshot_id"]) for item in contexts],
        )
        second = evidence(context_fingerprints=list(reversed(contexts)))
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)

    def test_evidence_transition_order_normalized(self) -> None:
        first = evidence()
        transitions = first.materialized_fields["transition_evidence"]
        self.assertEqual([0, 1, 2], [item["to_state_version"] for item in transitions])
        second = evidence(transition_evidence=list(reversed(transitions)))
        self.assertEqual(first.canonical_json, second.canonical_json)

    def test_evidence_hash_excludes_manifest_sha256(self) -> None:
        manifest = evidence()
        with_hash = {**manifest.materialized_fields, "manifest_sha256": "f" * 64}
        without_hash = canonical_evidence_payload(manifest.materialized_fields)
        normalized_with_hash = canonical_evidence_payload(with_hash)
        self.assertEqual(without_hash, normalized_with_hash)
        self.assertEqual(manifest.manifest_sha256, canonical_sha256(normalized_with_hash))

    def test_evidence_hash_reproducible_and_matches_canonical_payload(self) -> None:
        first = evidence()
        second = evidence()
        self.assertEqual(first.canonical_json, second.canonical_json)
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)
        self.assertEqual(first.canonical_json, canonical_json(first.materialized_fields))
        self.assertEqual(first.manifest_sha256, canonical_sha256(first.materialized_fields))
        self.assertEqual(first.as_record()["manifest_sha256"], first.manifest_sha256)


if __name__ == "__main__":
    unittest.main()
