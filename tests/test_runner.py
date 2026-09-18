from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from adcp.runner import (
    CodexEvidenceCapture,
    CodexInvocation,
    RunnerError,
    build_codex_command,
    run_codex,
    sanitize_environment,
)


RESULT_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}


def make_fake_codex(root: Path) -> Path:
    executable = root / "fake-codex"
    executable.write_text(
        f"""#!{sys.executable}
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
if "--version" in args:
    print("fake-codex 1.0")
    raise SystemExit(0)
prompt = sys.stdin.buffer.read().decode("utf-8")
mode = os.environ.get("ADCP_FAKE_MODE", "success")
if mode == "timeout":
    time.sleep(30)
if mode == "nonzero":
    print(json.dumps({{"type": "turn.failed", "prompt": prompt}}))
    sys.stderr.write("controlled failure")
    raise SystemExit(7)
final = Path(args[args.index("--output-last-message") + 1])
result = {{"unexpected": True}} if mode == "invalid-schema" else {{"ok": True}}
final.write_text(json.dumps(result), encoding="utf-8")
session_root = os.environ.get("ADCP_FAKE_SESSION_ROOT")
thread_id = os.environ.get("ADCP_FAKE_THREAD_ID", "01a08000-0000-7000-8000-000000000001")
if session_root:
    print(json.dumps({{"type": "thread.started", "thread_id": thread_id}}))
    day = datetime.now()
    directory = Path(session_root) / f"{{day.year:04d}}" / f"{{day.month:02d}}" / f"{{day.day:02d}}"
    directory.mkdir(parents=True, exist_ok=True)
    def write_rollout(prefix, embedded_thread):
        path = directory / f"rollout-{{prefix}}-{{thread_id}}.jsonl"
        path.write_text(json.dumps({{"type":"session_meta","payload":{{"id":embedded_thread}}}}) + "\\n", encoding="utf-8")
    if mode == "ambiguous-rollout":
        write_rollout("first", thread_id)
        write_rollout("second", thread_id)
    elif mode == "wrong-thread-rollout":
        write_rollout("wrong", "01a08000-0000-7000-8000-000000000099")
    elif mode != "missing-rollout":
        write_rollout("fixture", thread_id)
else:
    print(json.dumps({{"type": "item.completed", "item": {{"type": "command_execution", "command": "fixture"}}, "prompt": prompt}}))
sys.stderr.write("fixture diagnostic")
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.binary = make_fake_codex(self.root)
        self.session_root = self.root / "sessions"
        self.session_root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invocation(self, name: str = "artifacts", **changes: object) -> CodexInvocation:
        values: dict[str, object] = {
            "workspace": self.workspace,
            "prompt": "prompt over stdin",
            "output_schema": RESULT_SCHEMA,
            "artifact_directory": self.root / name,
            "sandbox": "workspace-write",
            "model": "test-model",
            "reasoning_effort": "high",
            "binary": self.binary,
            "timeout_seconds": 5,
            "termination_grace_seconds": 1,
        }
        values.update(changes)
        return CodexInvocation(**values)  # type: ignore[arg-type]

    def evidence_invocation(
        self, name: str = "evidence-artifacts", *, mode: str = "success"
    ) -> CodexInvocation:
        return self.invocation(
            name,
            ephemeral=False,
            evidence_capture=CodexEvidenceCapture(self.session_root),
            extra_environment={
                "ADCP_FAKE_SESSION_ROOT": str(self.session_root),
                "ADCP_FAKE_THREAD_ID": "01a08000-0000-7000-8000-000000000001",
                "ADCP_FAKE_MODE": mode,
            },
        )

    def test_command_is_shell_free_contract_with_prompt_sentinel(self) -> None:
        invocation = self.invocation()
        command = build_codex_command(
            invocation, self.root / "schema.json", self.root / "final.json"
        )
        self.assertEqual(command[0], str(self.binary.resolve(strict=True)))
        self.assertEqual(command[1:3], ("-a", "never"))
        self.assertIn('model_reasoning_effort="high"', command)
        self.assertEqual(command[command.index("--model") + 1], "test-model")
        self.assertIn("features.code_mode=false", command)
        self.assertIn("exec", command)
        self.assertIn("--ephemeral", command)
        self.assertIn("workspace-write", command)
        self.assertEqual(command[-1], "-")
        self.assertNotIn(invocation.prompt, command)

    def test_evidence_capture_is_explicit_and_omits_ephemeral_only_when_selected(self) -> None:
        invocation = self.evidence_invocation()
        command = build_codex_command(
            invocation, self.root / "schema.json", self.root / "final.json"
        )
        self.assertIsNotNone(invocation.evidence_capture)
        self.assertFalse(invocation.ephemeral)
        self.assertNotIn("--ephemeral", command)
        with self.assertRaises(RunnerError) as caught:
            self.invocation(
                evidence_capture=CodexEvidenceCapture(self.session_root), ephemeral=True
            ).validate()
        self.assertEqual(
            caught.exception.code, "EVIDENCE_CAPTURE_REQUIRES_PERSISTED_SESSION"
        )

    def test_evidence_capture_preserves_thread_raw_streams_metadata_and_rollout(self) -> None:
        result = run_codex(self.evidence_invocation())
        self.assertEqual(
            result.thread_id, "01a08000-0000-7000-8000-000000000001"
        )
        self.assertIn(result.thread_id, result.artifacts.stdout.path.read_text())
        self.assertIn("fixture diagnostic", result.artifacts.stderr.path.read_text())
        metadata = json.loads(result.artifacts.metadata.path.read_text())
        self.assertTrue(metadata["evidence_capture"])
        self.assertEqual(metadata["thread_id"], result.thread_id)
        self.assertEqual(metadata["binary"], str(self.binary.resolve(strict=True)))
        self.assertEqual(metadata["binary_version"], "fake-codex 1.0")
        self.assertEqual(metadata["cwd"], str(self.workspace.resolve(strict=True)))
        self.assertFalse(metadata["effective_execution_config"]["ephemeral"])
        self.assertIsNone(
            metadata["effective_execution_config"]["unified_exec_override"]
        )
        self.assertNotIn("--ephemeral", metadata["command"])
        self.assertIsNotNone(result.rollout)
        assert result.rollout is not None
        self.assertEqual(result.rollout.thread_id, result.thread_id)
        self.assertTrue(result.rollout.captured.path.is_file())
        self.assertEqual(
            result.rollout.captured.sha256,
            hashlib.sha256(result.rollout.captured.path.read_bytes()).hexdigest(),
        )
        self.assertEqual(metadata["rollout"]["sha256"], result.rollout.captured.sha256)
        self.assertEqual(metadata["rollout"]["size"], result.rollout.size)

    def test_evidence_capture_rejects_missing_rollout(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            run_codex(self.evidence_invocation(mode="missing-rollout"))
        self.assertEqual(caught.exception.code, "CODEX_ROLLOUT_NOT_FOUND")
        self.assertIsNotNone(caught.exception.artifacts)

    def test_evidence_capture_rejects_wrong_thread_rollout(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            run_codex(self.evidence_invocation(mode="wrong-thread-rollout"))
        self.assertEqual(caught.exception.code, "CODEX_ROLLOUT_THREAD_ID_MISMATCH")

    def test_evidence_capture_rejects_ambiguous_exact_thread_rollout(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            run_codex(self.evidence_invocation(mode="ambiguous-rollout"))
        self.assertEqual(caught.exception.code, "CODEX_ROLLOUT_AMBIGUOUS")

    def test_binary_is_required_runtime_configuration(self) -> None:
        parameter = inspect.signature(CodexInvocation).parameters["binary"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(RunnerError) as caught:
            self.invocation(binary=None).validate()
        self.assertEqual(caught.exception.code, "CODEX_BINARY_NOT_CONFIGURED")

    def test_unspecified_model_and_reasoning_are_omitted(self) -> None:
        command = build_codex_command(
            self.invocation(model=None, reasoning_effort=None),
            self.root / "schema.json",
            self.root / "final.json",
        )
        self.assertNotIn("--model", command)
        self.assertFalse(
            any(value.startswith("model_reasoning_effort=") for value in command)
        )

    def test_stdout_stderr_and_structured_result_are_separate(self) -> None:
        result = run_codex(self.invocation())
        self.assertEqual(result.structured_result, {"ok": True})
        self.assertEqual(len(result.events), 1)
        self.assertIn("fixture diagnostic", result.artifacts.stderr.path.read_text())
        self.assertNotIn("fixture diagnostic", result.artifacts.stdout.path.read_text())
        self.assertEqual(result.artifacts.result.path.read_text(), '{"ok":true}')

    def test_artifacts_have_matching_sha256(self) -> None:
        result = run_codex(self.invocation())
        for artifact in (
            result.artifacts.stdout,
            result.artifacts.stderr,
            result.artifacts.result,
            result.artifacts.metadata,
        ):
            self.assertEqual(
                artifact.sha256, hashlib.sha256(artifact.path.read_bytes()).hexdigest()
            )

    def test_nonzero_exit_is_fail_closed_with_artifacts(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            run_codex(
                self.invocation(
                    extra_environment={"ADCP_FAKE_MODE": "nonzero"}
                )
            )
        self.assertEqual(caught.exception.code, "CODEX_NONZERO_EXIT")
        self.assertIsNotNone(caught.exception.artifacts)

    def test_structured_result_schema_mismatch_is_rejected(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            run_codex(
                self.invocation(
                    extra_environment={"ADCP_FAKE_MODE": "invalid-schema"}
                )
            )
        self.assertEqual(caught.exception.code, "STRUCTURED_RESULT_SCHEMA_MISMATCH")

    def test_timeout_terminates_process_group_and_keeps_artifacts(self) -> None:
        started = time.monotonic()
        with self.assertRaises(RunnerError) as caught:
            run_codex(
                self.invocation(
                    timeout_seconds=1,
                    termination_grace_seconds=1,
                    extra_environment={"ADCP_FAKE_MODE": "timeout"},
                )
            )
        self.assertEqual(caught.exception.code, "CODEX_TIMEOUT")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNotNone(caught.exception.artifacts)

    def test_artifact_overwrite_is_rejected(self) -> None:
        run_codex(self.invocation())
        with self.assertRaises(RunnerError) as caught:
            run_codex(self.invocation())
        self.assertEqual(caught.exception.code, "ARTIFACT_ALREADY_EXISTS")

    def test_sensitive_environment_is_removed_without_values(self) -> None:
        parent = {
            "HOME": "/safe/home",
            "PATH": "/safe/bin",
            "ADCP_RUNTIME_ROOT": "/runtime",
            "CONTROL_STORE_PATH": "/runtime/control.sqlite3",
            "DATABASE_URL": "secret-db",
            "NOTION_TOKEN": "notion-secret",
            "GMAIL_PASSWORD": "mail-secret",
            "TELEGRAM_BOT_TOKEN": "telegram-secret",
            "SERVICE_API_KEY": "api-secret",
            "UNRELATED": "not-copied",
        }
        child, removed = sanitize_environment(parent)
        self.assertEqual(child, {"HOME": "/safe/home", "PATH": "/safe/bin"})
        self.assertEqual(
            set(removed),
            {
                "ADCP_RUNTIME_ROOT",
                "CONTROL_STORE_PATH",
                "DATABASE_URL",
                "NOTION_TOKEN",
                "GMAIL_PASSWORD",
                "TELEGRAM_BOT_TOKEN",
                "SERVICE_API_KEY",
            },
        )
        self.assertFalse(any(value.endswith("secret") for value in child.values()))

    def test_sensitive_extra_environment_is_rejected(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            sanitize_environment({}, {"APPLICATION_PASSWORD": "do-not-copy"})
        self.assertEqual(caught.exception.code, "SENSITIVE_CHILD_ENVIRONMENT")


if __name__ == "__main__":
    unittest.main()
