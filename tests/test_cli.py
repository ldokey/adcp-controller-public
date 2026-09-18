from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from adcp.cli import main


class _Store:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Controller:
    def __init__(self) -> None:
        self.store = _Store()
        self.calls = []

    def inspect(self, execution_id: str):
        self.calls.append(("inspect", execution_id))
        return {"execution_id": execution_id, "state": "READY"}

    def bind_deferred_execution(self, spec, **kwargs):
        self.calls.append(("bind-deferred", spec, kwargs))
        return {"execution_id": spec.execution_id, "replayed": False}

    def release_prebound_execution(self, execution_id, slice_id, **kwargs):
        self.calls.append(("release-prebound", execution_id, slice_id, kwargs))
        return {"result": "PREEXECUTION_RELEASED", "replayed": False}

    def register_slice(self, **kwargs):
        self.calls.append(("register-slice", kwargs))
        return {"slice_control_state": {"slice_id": kwargs["slice_id"]}, "replayed": False}


class CliTests(unittest.TestCase):
    def test_cli_uses_controller_api_not_direct_store_state_machine(self) -> None:
        controller = _Controller()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                ["--database", "/tmp/control.sqlite3", "--source-root", "/tmp/source",
                 "--worktree-root", "/tmp/worktrees", "status", "execution-1"],
                controller_factory=lambda _args: controller,
            )
        self.assertEqual(0, code)
        self.assertEqual([("inspect", "execution-1")], controller.calls)
        self.assertTrue(controller.store.closed)
        self.assertIn('"state":"READY"', output.getvalue())
        source = Path(__file__).parents[1] / "src" / "adcp" / "cli.py"
        self.assertNotIn(".transition(", source.read_text(encoding="utf-8"))

    def test_production_prepare_is_explicit_and_has_no_path_override(self) -> None:
        result = type(
            "Result",
            (),
            {"as_dict": lambda self: {"execution_id": "production-import-cp-01a-2-v1"}},
        )()
        output = io.StringIO()
        accepted_head = "8" * 40
        with patch("adcp.cli.prepare_canonical_production", return_value=result) as prepare:
            with redirect_stdout(output):
                code = main(["production-prepare", "--accepted-adcp-head", accepted_head])
        self.assertEqual(0, code)
        prepare.assert_called_once_with(accepted_head)
        self.assertIn("production-import-cp-01a-2-v1", output.getvalue())

    def test_production_prepare_cli_rejects_runtime_path_bypass(self) -> None:
        with self.assertRaises(SystemExit):
            main(
                [
                    "production-prepare",
                    "--accepted-adcp-head",
                    "8" * 40,
                    "--runtime-root",
                    "/tmp/not-production",
                ]
            )

    def test_bind_deferred_cli_is_one_guarded_controller_operation(self) -> None:
        controller = _Controller()
        output = io.StringIO()
        with TemporaryDirectory() as temporary:
            capsule = Path(temporary) / "maker-capsule.json"
            capsule.write_text('{"task":"bounded prebind"}', encoding="utf-8")
            with redirect_stdout(output):
                code = main(
                    [
                        "--database", "/tmp/control.sqlite3",
                        "--source-root", "/tmp/source",
                        "--worktree-root", "/tmp/worktrees",
                        "bind-deferred", "execution-1", "slice-1",
                        "--expected-state-version", "0",
                        "--risk", "NORMAL",
                        "--environment", "TEST",
                        "--contract-fingerprint", "a" * 64,
                        "--authority-fingerprint", "b" * 64,
                        "--branch", "logical-branch",
                        "--base-commit", "1" * 40,
                        "--packet-ref", "packet-v1",
                        "--maker-capsule", str(capsule),
                        "--provision-branch-if-missing",
                    ],
                    controller_factory=lambda _args: controller,
                )
        self.assertEqual(0, code)
        self.assertEqual("bind-deferred", controller.calls[0][0])
        spec = controller.calls[0][1]
        options = controller.calls[0][2]
        self.assertEqual(("execution-1", "slice-1", "logical-branch"), (
            spec.execution_id, spec.slice_id, spec.branch
        ))
        self.assertEqual(0, options["expected_state_version"])
        self.assertTrue(options["provision_branch_if_missing"])
        self.assertEqual("MAKER", options["maker_capsule"].role.value)
        self.assertTrue(controller.store.closed)
        self.assertIn('"replayed":false', output.getvalue())

    def test_register_slice_cli_is_one_guarded_controller_operation(self) -> None:
        controller = _Controller()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "--database", "/tmp/control.sqlite3",
                    "--source-root", "/tmp/source",
                    "--worktree-root", "/tmp/worktrees",
                    "register-slice", "slice-1",
                    "--stage", "S4_EXECUTION_FROZEN",
                    "--status", "READY_FOR_CODEX",
                    "--migration-class", "DEFER_BINDING",
                    "--execution-eligibility", "INELIGIBLE_UNTIL_PREFLIGHT",
                    "--defer-reason", "AWAITING_PREEXECUTION_BINDING",
                    "--logical-source-root", "/tmp/source",
                    "--registration-ref", "packet-v1",
                    "--expected-authority-generation", "2",
                ],
                controller_factory=lambda _args: controller,
            )
        self.assertEqual(0, code)
        self.assertEqual("register-slice", controller.calls[0][0])
        self.assertEqual(
            {
                "slice_id": "slice-1",
                "stage": "S4_EXECUTION_FROZEN",
                "status": "READY_FOR_CODEX",
                "migration_class": "DEFER_BINDING",
                "execution_eligibility": "INELIGIBLE_UNTIL_PREFLIGHT",
                "defer_reason": "AWAITING_PREEXECUTION_BINDING",
                "logical_source_root": "/tmp/source",
                "registration_ref": "packet-v1",
                "expected_authority_generation": 2,
            },
            controller.calls[0][1],
        )
        self.assertTrue(controller.store.closed)
        self.assertIn('"slice_id":"slice-1"', output.getvalue())

    def test_release_prebound_cli_is_one_guarded_controller_operation(self) -> None:
        controller = _Controller()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "--database", "/tmp/control.sqlite3",
                    "--source-root", "/tmp/source",
                    "--worktree-root", "/tmp/worktrees",
                    "release-prebound", "execution-1", "slice-1",
                    "--expected-execution-state-version", "0",
                    "--expected-slice-state-version", "1",
                    "--reason", "BASE_STALE",
                    "--authority-ref", "authority:release-v2",
                ],
                controller_factory=lambda _args: controller,
            )
        self.assertEqual(0, code)
        self.assertEqual(
            (
                "release-prebound", "execution-1", "slice-1",
                {
                    "expected_execution_state_version": 0,
                    "expected_slice_state_version": 1,
                    "release_reason": "BASE_STALE",
                    "authority_ref": "authority:release-v2",
                },
            ),
            controller.calls[0],
        )
        self.assertTrue(controller.store.closed)
        self.assertIn("PREEXECUTION_RELEASED", output.getvalue())

    def test_release_prebound_cli_rejects_escape_hatches_and_arbitrary_reason(self) -> None:
        base = [
            "--database", "/tmp/control.sqlite3",
            "--source-root", "/tmp/source",
            "--worktree-root", "/tmp/worktrees",
            "release-prebound", "execution-1", "slice-1",
            "--expected-execution-state-version", "0",
            "--expected-slice-state-version", "1",
            "--reason", "ARBITRARY",
            "--authority-ref", "authority:release-v2",
        ]
        with self.assertRaises(SystemExit):
            main(base, controller_factory=lambda _args: _Controller())
        with self.assertRaises(SystemExit):
            main(
                [*base[:-4], "--reason", "BASE_STALE", "--authority-ref",
                 "authority:release-v2", "--force"],
                controller_factory=lambda _args: _Controller(),
            )

    def test_register_slice_cli_does_not_expose_bound_fields(self) -> None:
        with self.assertRaises(SystemExit):
            main(
                [
                    "--database", "/tmp/control.sqlite3",
                    "--source-root", "/tmp/source",
                    "--worktree-root", "/tmp/worktrees",
                    "register-slice", "slice-1",
                    "--stage", "S4_EXECUTION_FROZEN",
                    "--status", "READY_FOR_CODEX",
                    "--migration-class", "DEFER_BINDING",
                    "--execution-eligibility", "INELIGIBLE_UNTIL_PREFLIGHT",
                    "--defer-reason", "AWAITING_PREEXECUTION_BINDING",
                    "--logical-source-root", "/tmp/source",
                    "--registration-ref", "packet-v1",
                    "--expected-authority-generation", "2",
                    "--base-commit", "1" * 40,
                ],
                controller_factory=lambda _args: _Controller(),
            )


if __name__ == "__main__":
    unittest.main()
