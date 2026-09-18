"""Canonical verification representations; command execution is intentionally absent."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, Sequence

from adcp.canonical import canonical_json, canonical_sha256
from adcp.domain import require_commit, require_sha256


VERIFICATION_MANIFEST_VERSION = 1
VERIFICATION_VERDICTS = frozenset({"PASS", "FAIL", "BLOCKED_ENVIRONMENT"})
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class VerificationCommand:
    name: str
    argv: list[str]
    cwd: str
    env_names: list[str]
    timeout_seconds: int
    required: bool
    exit_code: int
    stdout_artifact: str | None = None
    stdout_sha256: str | None = None
    stderr_artifact: str | None = None
    stderr_sha256: str | None = None

    @classmethod
    def from_value(
        cls, value: "VerificationCommand | Mapping[str, Any]"
    ) -> "VerificationCommand":
        if isinstance(value, cls):
            command = value
        elif isinstance(value, Mapping):
            command = cls(**value)
        else:
            raise TypeError("VerificationCommand or mapping required")
        command.validate()
        return command

    def validate(self) -> None:
        if not self.name or not self.cwd:
            raise ValueError("VERIFICATION_COMMAND_INVALID")
        if not isinstance(self.argv, list) or not self.argv or not all(
            isinstance(argument, str) for argument in self.argv
        ):
            raise ValueError("VERIFICATION_ARGV_INVALID")
        if not isinstance(self.env_names, list) or not all(
            isinstance(name, str) and _ENV_NAME.fullmatch(name)
            for name in self.env_names
        ):
            raise ValueError("VERIFICATION_ENV_NAMES_INVALID")
        if len(set(self.env_names)) != len(self.env_names):
            raise ValueError("VERIFICATION_ENV_NAMES_INVALID")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("VERIFICATION_TIMEOUT_INVALID")
        if not isinstance(self.required, bool):
            raise ValueError("VERIFICATION_REQUIRED_INVALID")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise ValueError("VERIFICATION_EXIT_CODE_INVALID")
        for value, field in (
            (self.stdout_sha256, "stdout_sha256"),
            (self.stderr_sha256, "stderr_sha256"),
        ):
            if value is not None:
                require_sha256(value, field)

    def materialize(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env_names": sorted(self.env_names),
            "timeout_seconds": self.timeout_seconds,
            "required": self.required,
            "exit_code": self.exit_code,
            "stdout_artifact": self.stdout_artifact,
            "stdout_sha256": self.stdout_sha256,
            "stderr_artifact": self.stderr_artifact,
            "stderr_sha256": self.stderr_sha256,
        }


def build_command_manifest(
    commands: Sequence[VerificationCommand | Mapping[str, Any]],
) -> dict[str, Any]:
    if isinstance(commands, (str, bytes)):
        raise TypeError("structured command sequence required")
    return {
        "manifest_version": VERIFICATION_MANIFEST_VERSION,
        "commands": [VerificationCommand.from_value(command).materialize() for command in commands],
    }


@dataclass(frozen=True)
class CandidateVerificationResultRecord:
    verification_id: str
    operation_key: str
    execution_id: str
    candidate_id: str
    candidate_content_sha256: str
    contract_fingerprint: str
    authority_fingerprint: str
    authority_generation: int
    verdict: str
    command_manifest: str
    command_manifest_sha256: str
    result_json: str
    started_at: str
    ended_at: str


@dataclass(frozen=True)
class VerificationResultRecord:
    verification_id: str
    operation_key: str
    execution_id: str
    result_commit: str
    contract_fingerprint: str
    authority_fingerprint: str
    verdict: str
    command_manifest: dict[str, Any]
    command_manifest_json: str
    command_manifest_sha256: str
    result: Any
    result_json: str
    started_at: str
    ended_at: str

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "execution_id": self.execution_id,
            "result_commit": self.result_commit,
            "contract_fingerprint": self.contract_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "verdict": self.verdict,
            "command_manifest": self.command_manifest,
            "command_manifest_sha256": self.command_manifest_sha256,
            "result": self.result,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


def build_verification_result(
    *,
    verification_id: str,
    operation_key: str,
    execution_id: str,
    result_commit: str,
    contract_fingerprint: str,
    authority_fingerprint: str,
    verdict: str,
    commands: Sequence[VerificationCommand | Mapping[str, Any]],
    result: Any,
    started_at: str,
    ended_at: str,
) -> VerificationResultRecord:
    if not verification_id or not execution_id or not started_at or not ended_at:
        raise ValueError("VERIFICATION_RESULT_INVALID")
    require_sha256(operation_key, "operation_key")
    require_commit(result_commit, "result_commit")
    require_sha256(contract_fingerprint, "contract_fingerprint")
    require_sha256(authority_fingerprint, "authority_fingerprint")
    if verdict not in VERIFICATION_VERDICTS:
        raise ValueError("VERIFICATION_VERDICT_INVALID")
    manifest = build_command_manifest(commands)
    manifest_json = canonical_json(manifest)
    result_json = canonical_json(result)
    return VerificationResultRecord(
        verification_id=verification_id,
        operation_key=operation_key,
        execution_id=execution_id,
        result_commit=result_commit,
        contract_fingerprint=contract_fingerprint,
        authority_fingerprint=authority_fingerprint,
        verdict=verdict,
        command_manifest=json.loads(manifest_json),
        command_manifest_json=manifest_json,
        command_manifest_sha256=canonical_sha256(manifest),
        result=json.loads(result_json),
        result_json=result_json,
        started_at=started_at,
        ended_at=ended_at,
    )


def validate_candidate_verification_payload(
    command_manifest: str, command_manifest_sha256: str, result_json: str, verdict: str
) -> tuple[VerificationCommand, ...]:
    """Validate the new candidate route without weakening the legacy commit API."""
    manifest = json.loads(command_manifest)
    result = json.loads(result_json)
    if canonical_json(manifest) != command_manifest or canonical_sha256(manifest) != command_manifest_sha256:
        raise ValueError("CANDIDATE_VERIFICATION_MANIFEST_MISMATCH")
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != VERIFICATION_MANIFEST_VERSION:
        raise ValueError("CANDIDATE_VERIFICATION_MANIFEST_INVALID")
    commands = tuple(VerificationCommand.from_value(value) for value in manifest.get("commands", []))
    if not commands or not any(command.required for command in commands):
        raise ValueError("CANDIDATE_REQUIRED_COMMANDS_EMPTY")
    if build_command_manifest(commands) != manifest:
        raise ValueError("CANDIDATE_VERIFICATION_MANIFEST_INVALID")
    if verdict not in VERIFICATION_VERDICTS:
        raise ValueError("VERIFICATION_VERDICT_INVALID")
    if verdict == "PASS" and any(command.required and command.exit_code != 0 for command in commands):
        raise ValueError("CANDIDATE_VERIFICATION_FALSE_PASS")
    if not isinstance(result, dict) or not result or canonical_json(result) != result_json:
        raise ValueError("CANDIDATE_VERIFICATION_RESULT_INVALID")
    return commands
