from __future__ import annotations

import os
from pathlib import Path
import unittest

from adcp.evaluator import run_real_evaluator_contract


class RealCodexSandboxContractTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("ADCP_RUN_REAL_CODEX_CONTRACT") == "1",
        "real Codex inference contract is an explicit test gate",
    )
    def test_real_evaluator_mutations_are_conclusively_blocked(self) -> None:
        binary = os.environ.get("ADCP_REAL_CODEX_BINARY")
        self.assertIsNotNone(
            binary,
            "ADCP_REAL_CODEX_BINARY must provide an absolute executable path",
        )
        evidence_root = os.environ.get("ADCP_REAL_CODEX_EVIDENCE_ROOT")
        self.assertIsNotNone(
            evidence_root,
            "ADCP_REAL_CODEX_EVIDENCE_ROOT must provide a durable Change evidence root",
        )
        session_root = os.environ.get("ADCP_REAL_CODEX_SESSION_ROOT")
        result = run_real_evaluator_contract(
            binary=Path(binary),
            evidence_root=Path(evidence_root),
            session_root=Path(session_root) if session_root else None,
            model=os.environ.get("ADCP_REAL_EVALUATOR_MODEL"),
            reasoning_effort=os.environ.get("ADCP_REAL_EVALUATOR_REASONING"),
            timeout_seconds=300,
        )
        self.assertFalse(result.parent_sandbox_masking, result.detail)
        self.assertEqual(result.changed_fields, (), result.detail)
        self.assertEqual(
            set(result.attempt_evidence),
            {"SOURCE", "GIT_CONTROL", "OUTSIDE_SENTINEL"},
            result.detail,
        )
        self.assertIsNotNone(result.evidence_directory, result.detail)
        assert result.evidence_directory is not None
        self.assertTrue(result.evidence_directory.is_dir(), result.detail)
        self.assertTrue((result.evidence_directory / "contract-result.json").is_file())
        self.assertTrue(
            (result.evidence_directory / "normalized-execution-evidence.json").is_file()
        )
        self.assertIsNotNone(result.thread_id, result.detail)
        self.assertTrue(result.thread_id, result.detail)
        self.assertIsNotNone(result.rollout, result.detail)
        assert result.rollout is not None
        self.assertEqual(result.rollout.thread_id, result.thread_id, result.detail)
        self.assertTrue(result.rollout.captured.path.is_file(), result.detail)
        self.assertEqual(len(result.rollout.captured.sha256), 64, result.detail)
        self.assertEqual(
            {item.kind for item in result.normalized_execution_evidence},
            {"SOURCE", "GIT_CONTROL", "OUTSIDE_SENTINEL"},
            result.detail,
        )
        for item in result.normalized_execution_evidence:
            self.assertTrue(item.call_id, result.detail)
            self.assertTrue(item.call_family, result.detail)
            self.assertTrue(item.result_family, result.detail)
        self.assertIsNotNone(result.artifacts, result.detail)
        assert result.artifacts is not None
        for artifact in (
            result.artifacts.stdout,
            result.artifacts.stderr,
            result.artifacts.result,
            result.artifacts.metadata,
        ):
            self.assertTrue(artifact.path.is_file(), result.detail)
            self.assertEqual(len(artifact.sha256), 64, result.detail)
        self.assertEqual(result.classification, "PASS", result.detail)


if __name__ == "__main__":
    unittest.main()
