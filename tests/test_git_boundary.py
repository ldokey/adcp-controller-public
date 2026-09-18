from __future__ import annotations

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from adcp.evaluator import (
    EvaluatorBoundaryError,
    capture_git_fingerprint,
    compare_git_fingerprints,
    validate_maker_git_boundary,
)


class GitBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.source = self.repo / "source.py"
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("config", "user.name", "ADCP Test")
        self.git("config", "user.email", "adcp-test@local.invalid")
        self.git("add", "source.py")
        self.git("commit", "-q", "-m", "baseline")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def fingerprint(self):
        return capture_git_fingerprint(self.repo, [Path("source.py")])

    def test_clean_fingerprint_comparison_is_unchanged(self) -> None:
        before = self.fingerprint()
        after = self.fingerprint()
        comparison = compare_git_fingerprints(before, after)
        self.assertTrue(comparison.unchanged)
        self.assertEqual(comparison.changed_fields, ())

    def test_evaluator_source_mutation_changes_hash_and_porcelain(self) -> None:
        before = self.fingerprint()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        comparison = compare_git_fingerprints(before, self.fingerprint())
        self.assertFalse(comparison.unchanged)
        self.assertIn("source_sha256", comparison.changed_fields)
        self.assertIn("porcelain_v2", comparison.changed_fields)

    def test_maker_source_change_is_allowed_without_git_control_change(self) -> None:
        before = self.fingerprint()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        validate_maker_git_boundary(before, self.fingerprint())

    def test_maker_index_mutation_is_rejected(self) -> None:
        before = self.fingerprint()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        self.git("add", "source.py")
        with self.assertRaises(EvaluatorBoundaryError) as caught:
            validate_maker_git_boundary(before, self.fingerprint())
        self.assertEqual(caught.exception.code, "MAKER_GIT_POLICY_VIOLATION")
        self.assertIn("index_sha256", caught.exception.detail)

    def test_maker_head_mutation_is_rejected(self) -> None:
        before = self.fingerprint()
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        self.git("add", "source.py")
        self.git("commit", "-q", "-m", "forbidden maker commit")
        with self.assertRaises(EvaluatorBoundaryError) as caught:
            validate_maker_git_boundary(before, self.fingerprint())
        self.assertIn("head", caught.exception.detail)


if __name__ == "__main__":
    unittest.main()
