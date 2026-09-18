from __future__ import annotations

from pathlib import Path
import subprocess
import unittest
from unittest import mock

from adcp.production_dcs_v8_adoption import (
    ProductionDcsV8AdoptionError,
    _LaunchdWriterAuthority,
    _probe_service_process,
    _scan_service_processes,
)


EXPECTED_ARGUMENTS = ("/fixture/python", "-m", "propertyai.fixture", "--send")
LABEL = "com.propertyai.fixture"


class LaunchctlPrint:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args, **_kwargs):
        call = tuple(str(value) for value in args)
        self.calls.append(call)
        return subprocess.CompletedProcess(call, self.returncode, self.stdout, self.stderr)


def detector(
    output: str,
    *,
    process_live: bool = False,
    service_owned: bool = False,
    returncode: int = 0,
    stderr: str = "",
):
    runner = LaunchctlPrint(stdout=output, stderr=stderr, returncode=returncode)
    probes: list[tuple[int, tuple[str, ...]]] = []

    def process_probe(pid: int, expected_arguments) -> tuple[bool, bool]:
        probes.append((pid, tuple(expected_arguments)))
        return process_live, process_live and service_owned

    authority = _LaunchdWriterAuthority(
        dcs_path=Path("/tmp/fixture-dcs"),
        launch_agents_root=Path("/tmp/fixture-launch-agents"),
        runtime_root=Path("/tmp/fixture-runtime"),
        uid=501,
        runner=runner,
        process_probe=process_probe,
    )
    evidence = authority._launch_state(LABEL, EXPECTED_ARGUMENTS)
    return evidence, runner, probes


class LaunchdRuntimeStateDetectorTests(unittest.TestCase):
    def test_case_a_running_live_service_owned_pid_is_active(self) -> None:
        evidence, _runner, probes = detector(
            "    state = running\n    pid = 41001\n",
            process_live=True,
            service_owned=True,
        )
        self.assertEqual("ACTIVE", evidence.runtime_state)
        self.assertEqual("LOADED", evidence.load_state)
        self.assertEqual("running", evidence.launchd_declared_state)
        self.assertEqual(41001, evidence.pid_field)
        self.assertTrue(evidence.pid_liveness)
        self.assertTrue(evidence.pid_service_ownership)
        self.assertEqual([(41001, EXPECTED_ARGUMENTS)], probes)

    def test_case_b_exact_incident_inactive_stale_dead_pid_is_inactive(self) -> None:
        evidence, _runner, probes = detector(
            "    state = inactive\n    pid = 45015\n",
            process_live=False,
            service_owned=False,
        )
        self.assertEqual("INACTIVE", evidence.runtime_state)
        self.assertEqual(45015, evidence.pid_field)
        self.assertFalse(evidence.pid_liveness)
        self.assertFalse(evidence.pid_service_ownership)
        self.assertTrue(evidence.stale_pid)
        self.assertEqual([(45015, EXPECTED_ARGUMENTS)], probes)

    def test_case_c_inactive_without_pid_is_inactive(self) -> None:
        evidence, _runner, probes = detector("    state = inactive\n")
        self.assertEqual("INACTIVE", evidence.runtime_state)
        self.assertIsNone(evidence.pid_field)
        self.assertEqual([], probes)

    def test_case_d_running_without_pid_fails_closed(self) -> None:
        evidence, _runner, probes = detector("    state = running\n")
        self.assertEqual("UNRESOLVED", evidence.runtime_state)
        self.assertEqual([], probes)

    def test_case_e_running_with_dead_pid_fails_closed(self) -> None:
        evidence, _runner, _probes = detector(
            "    state = running\n    pid = 41002\n",
            process_live=False,
        )
        self.assertEqual("UNRESOLVED", evidence.runtime_state)

    def test_case_f_running_live_wrong_process_fails_closed(self) -> None:
        evidence, _runner, _probes = detector(
            "    state = running\n    pid = 41003\n",
            process_live=True,
            service_owned=False,
        )
        self.assertEqual("UNRESOLVED", evidence.runtime_state)
        self.assertTrue(evidence.pid_liveness)
        self.assertFalse(evidence.pid_service_ownership)

    def test_case_g_inactive_live_service_owned_process_is_inconsistent(self) -> None:
        evidence, _runner, _probes = detector(
            "    state = inactive\n    pid = 41004\n",
            process_live=True,
            service_owned=True,
        )
        self.assertEqual("INCONSISTENT", evidence.runtime_state)

    def test_case_h_loaded_scheduled_oneshot_between_runs_is_valid_inactive(self) -> None:
        evidence, runner, probes = detector(
            "    state = not running\n    runs = 37\n",
        )
        self.assertEqual("INACTIVE", evidence.runtime_state)
        self.assertIsNone(evidence.pid_field)
        self.assertEqual([], probes)
        self.assertEqual(1, len(runner.calls))
        self.assertEqual("print", runner.calls[0][1])
        self.assertFalse(
            any(token in {"enable", "disable", "kickstart", "kill"} for token in runner.calls[0])
        )

    def test_unknown_launchd_state_fails_closed(self) -> None:
        evidence, _runner, _probes = detector("    state = waiting-for-unknown\n")
        self.assertEqual("UNRESOLVED", evidence.runtime_state)

    def test_known_unloaded_service_is_runtime_inactive_without_mutation(self) -> None:
        evidence, runner, probes = detector(
            "",
            returncode=113,
            stderr="Could not find service; not loaded",
        )
        self.assertEqual("INACTIVE", evidence.runtime_state)
        self.assertEqual("UNLOADED", evidence.load_state)
        self.assertEqual([], probes)
        self.assertEqual(1, len(runner.calls))
        self.assertEqual("print", runner.calls[0][1])

    def test_pid_field_presence_alone_is_never_active(self) -> None:
        evidence, _runner, _probes = detector(
            "    state = inactive\n    pid = 45015\n",
            process_live=True,
            service_owned=False,
        )
        self.assertEqual("INACTIVE", evidence.runtime_state)
        self.assertNotEqual("ACTIVE", evidence.runtime_state)

    def test_default_process_probe_requires_exact_expected_service_command(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/bin/ps"],
            0,
            "S /fixture/python -m propertyai.fixture --send\n",
            "",
        )
        with mock.patch("adcp.production_dcs_v8_adoption.subprocess.run", return_value=completed) as run:
            self.assertEqual((True, True), _probe_service_process(42001, EXPECTED_ARGUMENTS))
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(["/bin/ps", "-ww", "-p", "42001", "-o", "state=", "-o", "command="], command)

    def test_default_process_probe_live_wrong_command_is_not_service_owned(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/bin/ps"],
            0,
            "S /fixture/python -m propertyai.other --send\n",
            "",
        )
        with mock.patch("adcp.production_dcs_v8_adoption.subprocess.run", return_value=completed):
            self.assertEqual((True, False), _probe_service_process(42002, EXPECTED_ARGUMENTS))

    def test_default_process_probe_missing_or_zombie_pid_is_not_live(self) -> None:
        missing = subprocess.CompletedProcess(["/bin/ps"], 1, "", "")
        with mock.patch("adcp.production_dcs_v8_adoption.subprocess.run", return_value=missing):
            self.assertEqual((False, False), _probe_service_process(42003, EXPECTED_ARGUMENTS))
        zombie = subprocess.CompletedProcess(
            ["/bin/ps"],
            0,
            "Z /fixture/python -m propertyai.fixture --send\n",
            "",
        )
        with mock.patch("adcp.production_dcs_v8_adoption.subprocess.run", return_value=zombie):
            self.assertEqual((False, False), _probe_service_process(42004, EXPECTED_ARGUMENTS))

    def test_service_process_scan_returns_only_live_exact_service_commands(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/bin/ps"],
            0,
            "\n".join(
                (
                    "42011 S /fixture/python -m propertyai.fixture --send",
                    "42012 S /fixture/python -m propertyai.other --send",
                    "42013 Z /fixture/python -m propertyai.fixture --send",
                    "",
                )
            ),
            "",
        )
        with mock.patch("adcp.production_dcs_v8_adoption.subprocess.run", return_value=completed) as run:
            self.assertEqual((42011,), _scan_service_processes(EXPECTED_ARGUMENTS))
        run.assert_called_once()
        self.assertEqual(
            ["/bin/ps", "-ww", "-axo", "pid=,state=,command="],
            run.call_args.args[0],
        )


    def test_enabled_state_reads_exact_print_disabled_override(self) -> None:
        class EnabledRunner:
            def __init__(self, output: str, returncode: int = 0) -> None:
                self.output = output
                self.returncode = returncode
                self.calls: list[tuple[str, ...]] = []
            def __call__(self, args, **_kwargs):
                call = tuple(str(value) for value in args)
                self.calls.append(call)
                return subprocess.CompletedProcess(call, self.returncode, self.output, "")

        production_enabled = EnabledRunner(
            'disabled services = {\n'
            '\t"com.propertyai.unrelated" => disabled\n'
            '\t"com.propertyai.fixture"    =>    enabled\n'
            '\t"com.propertyai.other" => enabled\n'
            '}\n'
        )
        enabled = _LaunchdWriterAuthority(
            dcs_path=Path("/tmp/dcs"), launch_agents_root=Path("/tmp/la"),
            runtime_root=Path("/tmp/runtime"), uid=501, runner=production_enabled,
        )
        self.assertEqual("ENABLED", enabled._enabled_state(LABEL))
        self.assertEqual(("/bin/launchctl", "print-disabled", "gui/501"), production_enabled.calls[0])

        production_disabled = EnabledRunner('{ "com.propertyai.fixture" => disabled }\n')
        disabled = _LaunchdWriterAuthority(
            dcs_path=Path("/tmp/dcs"), launch_agents_root=Path("/tmp/la"),
            runtime_root=Path("/tmp/runtime"), uid=501, runner=production_disabled,
        )
        self.assertEqual("DISABLED", disabled._enabled_state(LABEL))

        legacy_enabled = EnabledRunner('{ "com.propertyai.fixture" => false }\n')
        legacy_disabled = EnabledRunner('{ "com.propertyai.fixture" => true }\n')
        self.assertEqual(
            "ENABLED",
            _LaunchdWriterAuthority(uid=501, runner=legacy_enabled)._enabled_state(LABEL),
        )
        self.assertEqual(
            "DISABLED",
            _LaunchdWriterAuthority(uid=501, runner=legacy_disabled)._enabled_state(LABEL),
        )

    def test_enabled_state_missing_ambiguous_or_failed_readback_fails_closed(self) -> None:
        outputs = (
            ("missing", "{}\n", 0),
            (
                "duplicate",
                '{\n "com.propertyai.fixture" => enabled\n "com.propertyai.fixture" => enabled\n}\n',
                0,
            ),
            (
                "contradictory_duplicate",
                '{\n "com.propertyai.fixture" => enabled\n "com.propertyai.fixture" => disabled\n}\n',
                0,
            ),
            ("unknown_token", '{ "com.propertyai.fixture" => foo }\n', 0),
            ("malformed_delimiter", '{ "com.propertyai.fixture" = enabled }\n', 0),
            ("empty_value", '{ "com.propertyai.fixture" => }\n', 0),
            ("substring_only", '{ "com.propertyai.fixture-extra" => enabled }\n', 0),
            ("incomplete_map", '{ "com.propertyai.fixture" => enabled\n', 0),
            (
                "ambiguous_map_block",
                '{ "com.propertyai.fixture" => enabled }\n{ "com.propertyai.other" => disabled }\n',
                0,
            ),
            ("command_failure", "permission denied", 1),
        )
        for name, output, returncode in outputs:
            with self.subTest(name=name, output=output, returncode=returncode):
                runner = LaunchctlPrint(stdout=output, returncode=returncode)
                authority = _LaunchdWriterAuthority(
                    dcs_path=Path("/tmp/dcs"), launch_agents_root=Path("/tmp/la"),
                    runtime_root=Path("/tmp/runtime"), uid=501, runner=runner,
                )
                with self.assertRaises(ProductionDcsV8AdoptionError) as caught:
                    authority._enabled_state(LABEL)
                self.assertEqual("PRODUCTION_DCS_WRITER_ENABLED_STATE_UNRESOLVED", caught.exception.code)

    def test_runtime_detector_never_queries_enable_or_load_authority(self) -> None:
        _evidence, runner, _probes = detector("    state = inactive\n")
        self.assertEqual(1, len(runner.calls))
        self.assertEqual("/bin/launchctl", runner.calls[0][0])
        self.assertEqual("print", runner.calls[0][1])
        flattened = [" ".join(call) for call in runner.calls]
        self.assertFalse(any("print-disabled" in call for call in flattened))
        self.assertFalse(any(" enable " in f" {call} " for call in flattened))
        self.assertFalse(any(" disable " in f" {call} " for call in flattened))


if __name__ == "__main__":
    unittest.main()
