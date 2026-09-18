from __future__ import annotations

import subprocess
import unittest

from adcp.capsule import CapsuleRole, build_context_capsule
from adcp.controller import ControllerError
from _helpers import ControllerFixture


class WorktreeOrchestrationTests(ControllerFixture, unittest.TestCase):
    def test_controller_candidate_worktree_isolated(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        self.assertTrue(run.candidate.path.is_relative_to((self.root / "worktrees").resolve()))
        self.assertFalse(run.candidate.path.is_relative_to(self.repo.resolve()))
        self.assertEqual("baseline\n", (self.repo / "tracked.txt").read_text(encoding="utf-8"))

    def test_maker_context_is_rebound_to_candidate_worktree(self) -> None:
        self.create_controller_execution()
        capsule = build_context_capsule(
            CapsuleRole.MAKER,
            {"source_root": str(self.repo), "branch": "main",
             "base_commit": self.base_commit, "current_commit": self.base_commit},
        )
        run = self.controller.begin_maker("execution-1", capsule)
        self.assertEqual(str(run.candidate.path), run.capsule.content["source_root"])
        self.assertEqual(run.candidate.branch, run.capsule.content["branch"])
        self.assertNotIn(str(self.repo), run.capsule.canonical_json)

    def test_maker_git_policy_violation_blocks_candidate(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        subprocess.run(["git", "-C", str(run.candidate.path), "branch", "maker-owned-ref"], check=True)
        with self.assertRaisesRegex(ControllerError, "MAKER_GIT_POLICY_VIOLATION"):
            self.controller.complete_maker(run, commit_message="must fail")
        row = self.store.get_execution("execution-1")
        self.assertEqual(("BLOCKED", "MAKER_GIT_POLICY_VIOLATION", None),
                         (row["state"], row["blocker_code"], row["result_commit"]))

    def test_controller_only_creates_candidate_commit(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        before = subprocess.run(
            ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        (run.candidate.path / "tracked.txt").write_text("maker edit\n", encoding="utf-8")
        result = self.controller.complete_maker(run, commit_message="controller commit")
        self.assertEqual(before, subprocess.run(
            ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD^"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        self.assertEqual(result, subprocess.run(
            ["git", "-C", str(run.candidate.path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        author = subprocess.run(
            ["git", "-C", str(run.candidate.path), "show", "-s", "--format=%an <%ae>", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual("ADCP Controller <adcp-controller@local.invalid>", author)

    def test_failed_worktree_requires_disposition_before_removal(self) -> None:
        self.create_controller_execution()
        run = self.controller.begin_maker("execution-1", self.maker_capsule())
        with self.assertRaisesRegex(ControllerError, "WORKTREE_DISPOSITION_REQUIRED"):
            self.controller.worktrees.remove(run.candidate, disposition_record=self.root / "missing")
        record = self.controller.worktrees.record_disposition(run.candidate, "BLOCKED evidence preserved")
        self.controller.worktrees.remove(run.candidate, disposition_record=record)
        self.assertFalse(run.candidate.path.exists())


if __name__ == "__main__":
    unittest.main()
