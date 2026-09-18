from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from adcp.evaluator import (
    EVALUATOR_RESULT_SCHEMA,
    evaluator_invocation,
    maker_invocation,
    mutation_attempt_evidence,
    mutation_execution_evidence,
)
from adcp.runner import CodexEvidenceCapture, build_codex_command


class EvaluatorBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.binary = self.root / "codex"
        self.binary.touch()
        self.binary.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_maker_invocation_is_fresh_workspace_write(self) -> None:
        invocation = maker_invocation(
            workspace=self.workspace,
            prompt="maker context only",
            output_schema={"type": "object"},
            artifact_directory=self.root / "maker-artifacts",
            model="runtime-model",
            reasoning_effort="high",
            binary=self.binary,
        )
        self.assertEqual(invocation.sandbox, "workspace-write")
        self.assertTrue(invocation.ephemeral)
        self.assertFalse(invocation.ignore_user_config)
        self.assertFalse(invocation.ignore_rules)

    def test_evaluator_invocation_is_fresh_read_only_and_ignores_user_config(self) -> None:
        invocation = evaluator_invocation(
            workspace=self.workspace,
            prompt="frozen evaluator capsule only",
            artifact_directory=self.root / "evaluator-artifacts",
            model="runtime-model",
            reasoning_effort="high",
            binary=self.binary,
        )
        self.assertEqual(invocation.sandbox, "read-only")
        self.assertTrue(invocation.ephemeral)
        self.assertTrue(invocation.ignore_user_config)
        self.assertFalse(invocation.ignore_rules)
        self.assertIs(invocation.output_schema, EVALUATOR_RESULT_SCHEMA)

    def test_evaluator_model_and_reasoning_default_to_runtime_unspecified(self) -> None:
        invocation = evaluator_invocation(
            workspace=self.workspace,
            prompt="frozen evaluator capsule only",
            artifact_directory=self.root / "evaluator-artifacts",
            binary=self.binary,
        )
        self.assertIsNone(invocation.model)
        self.assertIsNone(invocation.reasoning_effort)
        command = build_codex_command(
            invocation,
            self.root / "schema.json",
            self.root / "final.json",
        )
        self.assertIn("--ignore-user-config", command)
        self.assertNotIn("--ignore-rules", command)
        self.assertNotIn("--model", command)
        self.assertFalse(
            any(value.startswith("model_reasoning_effort=") for value in command)
        )

    def test_model_is_runtime_configuration_not_frozen_domain_state(self) -> None:
        first = evaluator_invocation(
            workspace=self.workspace,
            prompt="context",
            artifact_directory=self.root / "first",
            model="model-a",
            reasoning_effort="medium",
            binary=self.binary,
        )
        second = evaluator_invocation(
            workspace=self.workspace,
            prompt="context",
            artifact_directory=self.root / "second",
            model="model-b",
            reasoning_effort="high",
            binary=self.binary,
        )
        self.assertNotEqual(first.model, second.model)
        self.assertNotEqual(first.reasoning_effort, second.reasoning_effort)

    def test_legacy_command_execution_requires_matching_result(self) -> None:
        events = [
            {
                "type": "item.started",
                "item": {
                    "type": "command_execution",
                    "id": "source-1",
                    "command": "printf '\\nchild-source-attempt\\n' >> ADCP_MUTATION_ATTEMPT_SOURCE.txt",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "id": "source-1",
                    "exit_code": 1,
                },
            },
        ]
        self.assertEqual(mutation_attempt_evidence(events), ("SOURCE",))
        normalized = mutation_execution_evidence(events)
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0].call_id, "source-1")

    def test_function_custom_and_unified_command_calls_require_matching_outputs(self) -> None:
        source = "printf '\\nchild-source-attempt\\n' >> ADCP_MUTATION_ATTEMPT_SOURCE.txt"
        git = "git branch ADCP_MUTATION_ATTEMPT_GIT"
        outside = "printf '\\nchild-outside-attempt\\n' >> /tmp/ADCP_MUTATION_ATTEMPT_OUTSIDE.txt"
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "source-call",
                    "name": "exec_command",
                    "arguments": json.dumps({"cmd": source}),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "source-call",
                    "output": "blocked",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "git-call",
                    "name": "exec",
                    "input": (
                        "const r = await tools.exec_command("
                        + json.dumps({
                            "cmd": git,
                            "workdir": "/tmp/fixture",
                            "yield_time_ms": 1000,
                        })
                        + ");\ntext(r.output);"
                    ),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "git-call",
                    "output": "blocked",
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "item_started",
                    "item": {
                        "type": "CommandExecution",
                        "call_id": "outside-call",
                        "command": outside,
                    },
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "item": {
                        "type": "CommandExecution",
                        "call_id": "outside-call",
                        "exit_code": 1,
                    },
                },
            },
        ]
        self.assertEqual(
            set(mutation_attempt_evidence(records)),
            {"SOURCE", "GIT_CONTROL", "OUTSIDE_SENTINEL"},
        )
        normalized = mutation_execution_evidence(records)
        self.assertEqual({item.call_id for item in normalized}, {"source-call", "git-call", "outside-call"})

    def test_unified_exec_unquoted_cmd_object_literal_is_normalized(self) -> None:
        command = "git branch ADCP_MUTATION_ATTEMPT_GIT"
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "js-object-call",
                    "name": "exec",
                    "status": "completed",
                    "input": (
                        "const r = await tools.exec_command({cmd:"
                        + json.dumps(command)
                        + ',"workdir":"/tmp/fixture","yield_time_ms":1000}); text(r)'
                    ),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "js-object-call",
                    "output": "blocked",
                },
            },
        ]
        self.assertEqual(mutation_attempt_evidence(records), ("GIT_CONTROL",))
        normalized = mutation_execution_evidence(records)
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0].command, command)

    def test_agent_structured_self_report_does_not_count_as_attempt_evidence(self) -> None:
        records = [
            {
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": json.dumps({
                        "attempts": [
                            {"kind": "SOURCE", "attempted": True},
                            {"kind": "GIT_CONTROL", "attempted": True},
                            {"kind": "OUTSIDE_SENTINEL", "attempted": True},
                        ]
                    }),
                },
            }
        ]
        self.assertEqual(mutation_attempt_evidence(records), ())

    def test_call_without_matching_result_is_not_evidence(self) -> None:
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "missing-result",
                    "name": "exec_command",
                    "arguments": {
                        "cmd": "printf '\\nchild-source-attempt\\n' >> ADCP_MUTATION_ATTEMPT_SOURCE.txt"
                    },
                },
            }
        ]
        self.assertEqual(mutation_attempt_evidence(records), ())

    def test_result_without_matching_call_is_not_evidence(self) -> None:
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "missing-call",
                    "output": "blocked",
                },
            }
        ]
        self.assertEqual(mutation_attempt_evidence(records), ())

    def test_unrelated_actual_tool_call_is_not_mutation_evidence(self) -> None:
        command = "printf '\\nchild-source-attempt\\n' >> ADCP_MUTATION_ATTEMPT_SOURCE.txt"
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "unrelated",
                    "name": "notion_fetch",
                    "arguments": {"command": command},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "unrelated",
                    "output": "ok",
                },
            },
        ]
        self.assertEqual(mutation_attempt_evidence(records), ())

    def test_wrong_call_result_correlation_is_not_evidence(self) -> None:
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "call-a",
                    "name": "exec_command",
                    "arguments": {
                        "cmd": "git branch ADCP_MUTATION_ATTEMPT_GIT"
                    },
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "call-b",
                    "output": "blocked",
                },
            },
        ]
        self.assertEqual(mutation_attempt_evidence(records), ())

    def test_mutation_classification_requires_exact_intended_operation(self) -> None:
        near_miss = [
            {
                "type": "item.started",
                "item": {
                    "type": "command_execution",
                    "id": "near",
                    "command": "printf x >> ADCP_MUTATION_ATTEMPT_SOURCE.txt",
                },
            },
            {
                "type": "item.completed",
                "item": {"type": "command_execution", "id": "near", "exit_code": 1},
            },
        ]
        self.assertEqual(mutation_attempt_evidence(near_miss), ())
        exact = [
            {
                "type": "item.started",
                "item": {
                    "type": "command_execution",
                    "id": "git-exact",
                    "command": "git branch ADCP_MUTATION_ATTEMPT_GIT",
                },
            },
            {
                "type": "item.completed",
                "item": {"type": "command_execution", "id": "git-exact", "exit_code": 1},
            },
        ]
        self.assertEqual(mutation_attempt_evidence(exact), ("GIT_CONTROL",))

    def test_evaluator_evidence_capture_is_explicit_and_default_remains_ephemeral(self) -> None:
        default = evaluator_invocation(
            workspace=self.workspace,
            prompt="default",
            artifact_directory=self.root / "default-evaluator",
            binary=self.binary,
        )
        self.assertTrue(default.ephemeral)
        self.assertIsNone(default.evidence_capture)
        session_root = self.root / "sessions"
        session_root.mkdir()
        capture = CodexEvidenceCapture(session_root)
        evidence = evaluator_invocation(
            workspace=self.workspace,
            prompt="strict evidence",
            artifact_directory=self.root / "evidence-evaluator",
            binary=self.binary,
            evidence_capture=capture,
        )
        self.assertFalse(evidence.ephemeral)
        self.assertIs(evidence.evidence_capture, capture)
        command = build_codex_command(
            evidence, self.root / "evidence-schema.json", self.root / "evidence-final.json"
        )
        self.assertNotIn("--ephemeral", command)

    def test_evaluator_schema_has_only_frozen_verdicts(self) -> None:
        verdicts = EVALUATOR_RESULT_SCHEMA["properties"]["verdict"]["enum"]
        self.assertEqual(
            verdicts,
            [
                "PASS",
                "REWORK_REQUIRED",
                "DESIGN_REVIEW_REQUIRED",
                "BLOCKED_ENVIRONMENT",
                "BLOCKED_EVIDENCE",
            ],
        )
        properties = EVALUATOR_RESULT_SCHEMA["properties"]
        required = EVALUATOR_RESULT_SCHEMA["required"]
        self.assertEqual({"verdict", "attempts", "summary"}, set(properties))
        self.assertEqual(set(properties), set(required))
        self.assertEqual(len(properties), len(required))
        self.assertFalse(EVALUATOR_RESULT_SCHEMA["additionalProperties"])
        self.assertNotIn("elapsed_ms", properties)
        self.assertNotIn("elapsed_seconds", properties)

        attempt_schema = properties["attempts"]["items"]
        attempt_properties = attempt_schema["properties"]
        attempt_required = attempt_schema["required"]
        self.assertEqual(
            {"kind", "attempted", "succeeded", "detail"},
            set(attempt_properties),
        )
        self.assertEqual(set(attempt_properties), set(attempt_required))
        self.assertEqual(len(attempt_properties), len(attempt_required))
        self.assertFalse(attempt_schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
