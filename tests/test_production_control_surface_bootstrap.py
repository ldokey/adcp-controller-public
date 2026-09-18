from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class ProductionControlSurfaceBootstrapOriginTests(unittest.TestCase):
    """Execute the production-shaped ``python -I /absolute/bootstrap.py`` boundary."""

    def setUp(self) -> None:
        self.fixture_parent = Path(__file__).parents[1] / ".tk44-bootstrap-fixtures"
        self.fixture_parent.mkdir(exist_ok=True)
        self.temporary = TemporaryDirectory(dir=self.fixture_parent)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "controller"
        self.repo.mkdir()
        self.intended_marker = self.root / "intended-marker.json"
        self.entrypoint = self.repo / "src/adcp/production_control_surface_entrypoint.py"
        self.implementation = self.repo / "src/adcp/production_control_surface.py"
        self.entrypoint.parent.mkdir(parents=True)
        source_entrypoint = Path(__file__).parents[1] / "src/adcp/production_control_surface_entrypoint.py"
        self.entrypoint.write_text(source_entrypoint.read_text(encoding="utf-8"), encoding="utf-8")
        (self.entrypoint.parent / "__init__.py").write_text(
            '"""Disposable attested package."""\n', encoding="utf-8"
        )
        self.implementation.write_text(self._intended_source(), encoding="utf-8")
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "src"], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.repo), "-c", "user.name=Bootstrap Fixture",
                "-c", "user.email=bootstrap@example.invalid", "commit", "-qm", "fixture",
            ],
            check=True,
        )
        self.head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()
        try:
            self.fixture_parent.rmdir()
        except OSError:
            pass

    def _intended_source(self) -> str:
        marker = repr(str(self.intended_marker))
        return f"""from __future__ import annotations
import json
import os
from pathlib import Path
import sys

def main(stdin, stdout):
    request = json.load(stdin)
    capture = {{
        "isolated": sys.flags.isolated,
        "ignore_environment": sys.flags.ignore_environment,
        "safe_path": sys.flags.safe_path,
        "no_user_site": sys.flags.no_user_site,
        "sys_path": list(sys.path),
        "cwd": os.getcwd(),
        "module_file": __file__,
    }}
    Path({marker}).write_text(json.dumps(capture), encoding="utf-8")
    root = str(Path(__file__).resolve().parents[2])
    result = {{
        "doctor_version": 1, "status": "READY", "error_code": None,
        "controller_root": root, "controller_interpreter": str(Path(sys.executable).absolute()),
        "controller_python_version": ".".join(str(x) for x in sys.version_info[:3]),
        "controller_commit": request["expected_controller_commit"], "controller_tree": "a" * 40,
        "controller_source_clean": True, "dcs_path": "/tmp/disposable-control.sqlite3",
        "dcs_readable": True, "dcs_schema": 9, "dcs_schema_supported": True,
        "global_writer_state": "FREE", "global_writer_owner_if_any": None,
        "current_fencing_token": 0, "global_writer_lease": {{"state": "FREE", "fencing_token": 0}},
        "request_change_id": request["change_id"],
        "request_unit_or_subchange_id": request["unit_or_subchange_id"],
        "request_operation_id": request["operation_id"],
        "exact_operation_prior_acquisition_count": 0, "prior_operation_state": "NONE",
        "w08_control_path_available": True, "mutation_exercised": "NO", "w08_acquire_count": 0,
        "diagnostic_detail": None,
    }}
    stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\\n")
    return 0
"""

    def request_payload(self, *, expected_commit: str | None = None) -> dict[str, object]:
        return {
            "request_version": 1,
            "expected_controller_commit": expected_commit or self.head,
            "change_id": "PARENT-CHANGE",
            "unit_or_subchange_id": "EXACT-SUBCHANGE",
            "operation_id": "exact-operation",
        }

    def run_bootstrap(
        self,
        *,
        cwd: Path | None = None,
        env_updates: dict[str, str] | None = None,
        expected_commit: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        env = dict(os.environ)
        if env_updates:
            env.update(env_updates)
        completed = subprocess.run(
            [sys.executable, "-I", str(self.entrypoint)],
            cwd=str(cwd or self.repo),
            env=env,
            input=json.dumps(self.request_payload(expected_commit=expected_commit)) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return completed, json.loads(completed.stdout)

    @staticmethod
    def write_shadow(directory: Path, marker: Path, *, package: bool = True) -> None:
        if package:
            target = directory / "adcp"
            target.mkdir(parents=True, exist_ok=True)
            (target / "__init__.py").write_text("# shadow package\n", encoding="utf-8")
            module = target / "production_control_surface.py"
        else:
            directory.mkdir(parents=True, exist_ok=True)
            module = directory / "adcp.py"
        if package:
            fake_ready = {
                "doctor_version": 1, "status": "READY", "error_code": None,
                "controller_root": str(directory), "controller_interpreter": sys.executable,
                "controller_python_version": "3.13.0", "controller_commit": "f" * 40,
                "controller_tree": "a" * 40, "controller_source_clean": True,
                "dcs_path": "/tmp/fake.sqlite3", "dcs_readable": True, "dcs_schema": 9,
                "dcs_schema_supported": True, "global_writer_state": "FREE",
                "global_writer_owner_if_any": None, "current_fencing_token": 0,
                "global_writer_lease": {"state": "FREE", "fencing_token": 0},
                "request_change_id": "PARENT-CHANGE", "request_unit_or_subchange_id": "EXACT-SUBCHANGE",
                "request_operation_id": "exact-operation", "exact_operation_prior_acquisition_count": 0,
                "prior_operation_state": "NONE", "w08_control_path_available": True,
                "mutation_exercised": "NO", "w08_acquire_count": 0, "diagnostic_detail": None,
            }
            module.write_text(
                "import json\nfrom pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('EXECUTED', encoding='utf-8')\n"
                f"FAKE_READY = {fake_ready!r}\n"
                "if __name__ == '__main__':\n    print(json.dumps(FAKE_READY))\n",
                encoding="utf-8",
            )
        else:
            module.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('EXECUTED', encoding='utf-8')\n",
                encoding="utf-8",
            )

    def test_absolute_entrypoint_isolated_startup_and_intended_origin_pass(self):
        completed, result = self.run_bootstrap()
        self.assertEqual("READY", result["status"])
        self.assertTrue(self.entrypoint.is_absolute())
        capture = json.loads(self.intended_marker.read_text(encoding="utf-8"))
        self.assertEqual(1, capture["isolated"])
        self.assertEqual(1, capture["ignore_environment"])
        self.assertTrue(capture["safe_path"])
        self.assertEqual(1, capture["no_user_site"])
        self.assertEqual(str(self.implementation.resolve()), str(Path(capture["module_file"]).resolve()))
        self.assertEqual("", completed.stderr)

    def test_root_level_package_shadow_never_executes(self):
        shadow_marker = self.root / "root-shadow.marker"
        self.write_shadow(self.repo, shadow_marker)
        _, result = self.run_bootstrap()
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("CONTROLLER_DIRTY", result["error_code"])
        self.assertFalse(shadow_marker.exists())
        self.assertFalse(self.intended_marker.exists())

    def test_malicious_pythonpath_shadow_never_executes(self):
        shadow_root = self.root / "pythonpath-shadow"
        shadow_marker = self.root / "pythonpath-shadow.marker"
        self.write_shadow(shadow_root, shadow_marker)
        _, result = self.run_bootstrap(env_updates={"PYTHONPATH": str(shadow_root)})
        self.assertEqual("READY", result["status"])
        self.assertFalse(shadow_marker.exists())
        capture = json.loads(self.intended_marker.read_text(encoding="utf-8"))
        self.assertNotIn(str(shadow_root), capture["sys_path"])

    def test_malicious_cwd_shadow_never_executes(self):
        malicious_cwd = self.root / "cwd-shadow"
        shadow_marker = self.root / "cwd-shadow.marker"
        self.write_shadow(malicious_cwd, shadow_marker)
        _, result = self.run_bootstrap(cwd=malicious_cwd)
        self.assertEqual("READY", result["status"])
        self.assertFalse(shadow_marker.exists())
        capture = json.loads(self.intended_marker.read_text(encoding="utf-8"))
        self.assertNotIn(str(malicious_cwd), capture["sys_path"])

    def test_pythonhome_userbase_startup_redirection_is_ignored(self):
        fake_home = self.root / "python-home"
        fake_userbase = self.root / "python-userbase"
        user_site = (
            fake_userbase
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        user_site_marker = self.root / "user-site-shadow.marker"
        self.write_shadow(user_site, user_site_marker)
        startup = self.root / "startup.py"
        startup_marker = self.root / "startup.marker"
        startup.write_text(
            "from pathlib import Path\n"
            f"Path({str(startup_marker)!r}).write_text('EXECUTED', encoding='utf-8')\n",
            encoding="utf-8",
        )
        _, result = self.run_bootstrap(
            env_updates={
                "PYTHONHOME": str(fake_home),
                "PYTHONUSERBASE": str(fake_userbase),
                "PYTHONSTARTUP": str(startup),
            }
        )
        self.assertEqual("READY", result["status"])
        self.assertFalse(startup_marker.exists())
        self.assertFalse(user_site_marker.exists())
        capture = json.loads(self.intended_marker.read_text(encoding="utf-8"))
        self.assertNotIn(str(user_site), capture["sys_path"])

    def test_cwd_adcp_py_collision_never_executes(self):
        malicious_cwd = self.root / "sibling-collision"
        marker = self.root / "adcp-py.marker"
        self.write_shadow(malicious_cwd, marker, package=False)
        _, result = self.run_bootstrap(cwd=malicious_cwd)
        self.assertEqual("READY", result["status"])
        self.assertFalse(marker.exists())

    def test_dirty_source_fails_before_intended_module_execution(self):
        self.implementation.write_text(
            self.implementation.read_text(encoding="utf-8") + "\n# dirty\n", encoding="utf-8"
        )
        _, result = self.run_bootstrap()
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("CONTROLLER_DIRTY", result["error_code"])
        self.assertFalse(self.intended_marker.exists())

    def test_wrong_expected_commit_fails_before_intended_module_execution(self):
        _, result = self.run_bootstrap(expected_commit="f" * 40)
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("CONTROLLER_HEAD_MISMATCH", result["error_code"])
        self.assertFalse(self.intended_marker.exists())

    def test_symlink_entrypoint_escape_is_rejected_before_import(self):
        external = self.root / "external-entrypoint.py"
        external.write_text(self.entrypoint.read_text(encoding="utf-8"), encoding="utf-8")
        self.entrypoint.unlink()
        self.entrypoint.symlink_to(external)
        _, result = self.run_bootstrap()
        self.assertEqual("ERROR", result["status"])
        self.assertEqual("CONTROLLER_ENTRYPOINT_IDENTITY_MISMATCH", result["error_code"])
        self.assertFalse(self.intended_marker.exists())


    def test_bootstrap_failure_preserves_existing_result_wire_keys(self):
        self.implementation.write_text(
            self.implementation.read_text(encoding="utf-8") + "\n# dirty-wire-check\n",
            encoding="utf-8",
        )
        _, result = self.run_bootstrap()
        self.assertEqual(
            {
                "doctor_version", "status", "error_code", "controller_root",
                "controller_interpreter", "controller_python_version", "controller_commit",
                "controller_tree", "controller_source_clean", "dcs_path", "dcs_readable",
                "dcs_schema", "dcs_schema_supported", "global_writer_state",
                "global_writer_owner_if_any", "current_fencing_token", "global_writer_lease",
                "request_change_id", "request_unit_or_subchange_id", "request_operation_id",
                "exact_operation_prior_acquisition_count", "prior_operation_state",
                "w08_control_path_available", "mutation_exercised", "w08_acquire_count",
                "diagnostic_detail",
            },
            set(result),
        )

    def test_bootstrap_has_no_static_project_local_import_before_attestation(self):
        source = self.entrypoint.read_text(encoding="utf-8")
        import_lines = [
            line.strip()
            for line in source.splitlines()
            if line.startswith("import ") or line.startswith("from ")
        ]
        self.assertFalse(any(line.startswith("import adcp") or line.startswith("from adcp") for line in import_lines))
        main_source = source[source.index("def main()") :]
        self.assertLess(main_source.index("_attest_source"), main_source.index("_load_intended_module"))


if __name__ == "__main__":
    unittest.main()
