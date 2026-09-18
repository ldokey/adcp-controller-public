from __future__ import annotations

import unittest

from adcp.domain import StoreError, operation_key
from adcp.verifier import (
    VerificationCommand,
    build_command_manifest,
    build_verification_result,
)
from _helpers import COMMIT_A, COMMIT_B, HASH_A, HASH_B, StoreFixture


def command(**overrides):
    values = {
        "name": "unit-tests",
        "argv": ["python", "-m", "unittest"],
        "cwd": "/source",
        "env_names": ["PYTHONPATH", "PYTHONDONTWRITEBYTECODE"],
        "timeout_seconds": 120,
        "required": True,
        "exit_code": 0,
        "stdout_artifact": "artifacts/stdout.txt",
        "stdout_sha256": "c" * 64,
        "stderr_artifact": "artifacts/stderr.txt",
        "stderr_sha256": "d" * 64,
    }
    values.update(overrides)
    return values


def verification_record(**overrides):
    values = {
        "verification_id": "verification-1",
        "operation_key": operation_key("verification-result", {"execution": "execution-1"}),
        "execution_id": "execution-1",
        "result_commit": COMMIT_B,
        "contract_fingerprint": HASH_A,
        "authority_fingerprint": HASH_B,
        "verdict": "PASS",
        "commands": [command()],
        "result": {"test_count": 56, "failures": 0},
        "started_at": "2026-08-11T01:02:03.456789+00:00",
        "ended_at": "2026-08-11T01:03:03.456789+00:00",
    }
    values.update(overrides)
    return build_verification_result(**values)


class VerificationRepresentationTests(unittest.TestCase):
    def test_verification_manifest_hash_stable(self) -> None:
        first = verification_record()
        reordered = command(env_names=["PYTHONDONTWRITEBYTECODE", "PYTHONPATH"])
        second = verification_record(commands=[dict(reversed(list(reordered.items())))])
        self.assertEqual(first.command_manifest_json, second.command_manifest_json)
        self.assertEqual(first.command_manifest_sha256, second.command_manifest_sha256)

    def test_verification_environment_values_not_supported(self) -> None:
        with self.assertRaises(TypeError):
            build_command_manifest([command(env={"TOKEN": "secret"})])
        with self.assertRaisesRegex(ValueError, "VERIFICATION_ENV_NAMES_INVALID"):
            build_command_manifest([command(env_names=["TOKEN=secret"])])

    def test_verification_uses_structured_argv(self) -> None:
        manifest = build_command_manifest([command()])
        self.assertIsInstance(manifest["commands"][0]["argv"], list)
        self.assertNotIn("env", manifest["commands"][0])


class VerificationStoreTests(StoreFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create()

    def test_verification_exact_binding_query(self) -> None:
        stored = self.store.register_verification_result(verification_record())
        self.assertEqual("PASS", stored["verdict"])
        self.assertTrue(
            self.store.has_verification_pass(
                "execution-1", COMMIT_B, HASH_A, HASH_B
            )
        )
        self.assertFalse(
            self.store.has_verification_pass(
                "execution-1", COMMIT_B, "e" * 64, HASH_B
            )
        )
        self.assertFalse(
            self.store.has_verification_pass(
                "execution-1", COMMIT_B, HASH_A, "e" * 64
            )
        )

    def test_verification_other_commit_pass_not_current(self) -> None:
        self.store.register_verification_result(verification_record(result_commit=COMMIT_A))
        self.assertTrue(
            self.store.has_verification_pass(
                "execution-1", COMMIT_A, HASH_A, HASH_B
            )
        )
        self.assertFalse(
            self.store.has_verification_pass(
                "execution-1", COMMIT_B, HASH_A, HASH_B
            )
        )

    def test_verification_same_operation_replay(self) -> None:
        record = verification_record()
        first = self.store.register_verification_result(record)
        second = self.store.register_verification_result(record)
        self.assertEqual(first["verification_seq"], second["verification_seq"])
        self.assertEqual(1, self.store.connection.execute("SELECT count(*) FROM verification_result").fetchone()[0])

    def test_verification_operation_payload_conflict(self) -> None:
        original = verification_record()
        self.store.register_verification_result(original)
        changed = verification_record(result={"test_count": 57, "failures": 0})
        with self.assertRaisesRegex(StoreError, "IDEMPOTENCY_CONFLICT"):
            self.store.register_verification_result(changed)
        self.assertEqual(1, self.store.connection.execute("SELECT count(*) FROM verification_result").fetchone()[0])

    def test_non_pass_verdict_does_not_satisfy_binding(self) -> None:
        self.store.register_verification_result(verification_record(verdict="FAIL"))
        self.assertFalse(
            self.store.has_verification_pass(
                "execution-1", COMMIT_B, HASH_A, HASH_B
            )
        )


if __name__ == "__main__":
    unittest.main()
