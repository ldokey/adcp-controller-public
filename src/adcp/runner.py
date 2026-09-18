"""Bounded, shell-free Codex subprocess execution and artifact capture."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from typing import Any, Iterable, Mapping, Sequence

from adcp.canonical import canonical_bytes, canonical_json


DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_TERMINATION_GRACE_SECONDS = 5

_SAFE_PARENT_ENV = frozenset(
    {
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TERM",
        "TMPDIR",
        "USER",
    }
)
_BLOCKED_EXACT = frozenset(
    {
        "ADCP_RUNTIME_ROOT",
        "CONTROL_STORE_PATH",
        "DATABASE_URL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }
)
_BLOCKED_PREFIXES = ("NOTION", "GMAIL", "TELEGRAM")
_BLOCKED_SUFFIXES = (
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_API_KEY",
    "_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_CREDENTIAL",
    "_CREDENTIALS",
)


class RunnerError(RuntimeError):
    def __init__(self, code: str, detail: str = "", artifacts: "ArtifactSet | None" = None) -> None:
        self.code = code
        self.detail = detail
        self.artifacts = artifacts
        super().__init__(f"{code}: {detail}" if detail else code)


def is_sensitive_environment_name(name: str) -> bool:
    upper = name.upper()
    return (
        upper in _BLOCKED_EXACT
        or upper.startswith(_BLOCKED_PREFIXES)
        or upper.endswith(_BLOCKED_SUFFIXES)
    )


def sanitize_environment(
    parent: Mapping[str, str],
    extra: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Build a small child environment without copying parent secrets."""

    child = {
        name: value
        for name, value in parent.items()
        if name in _SAFE_PARENT_ENV and not is_sensitive_environment_name(name)
    }
    removed = tuple(
        sorted(
            name
            for name in parent
            if name not in child
            and (is_sensitive_environment_name(name) or name in _BLOCKED_EXACT)
        )
    )
    for name, value in (extra or {}).items():
        if is_sensitive_environment_name(name):
            raise RunnerError("SENSITIVE_CHILD_ENVIRONMENT", name)
        child[name] = value
    child.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    return child, removed


@dataclass(frozen=True)
class CodexEvidenceCapture:
    """Explicit opt-in to persisted Codex telemetry for strict evidence runs."""

    session_root: Path

    def validate(self) -> None:
        if not self.session_root.is_absolute() or not self.session_root.is_dir():
            raise RunnerError("INVALID_CODEX_SESSION_ROOT", str(self.session_root))


@dataclass(frozen=True)
class CodexInvocation:
    workspace: Path
    prompt: str
    output_schema: dict[str, Any]
    artifact_directory: Path
    sandbox: str
    binary: Path | None
    model: str | None = None
    reasoning_effort: str | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    termination_grace_seconds: int = DEFAULT_TERMINATION_GRACE_SECONDS
    ephemeral: bool = True
    ignore_user_config: bool = False
    ignore_rules: bool = False
    extra_environment: Mapping[str, str] | None = None
    evidence_capture: CodexEvidenceCapture | None = None

    def validate(self) -> None:
        if self.sandbox not in {"workspace-write", "read-only"}:
            raise RunnerError("INVALID_SANDBOX_MODE", self.sandbox)
        if self.binary is None:
            raise RunnerError("CODEX_BINARY_NOT_CONFIGURED")
        if (
            not isinstance(self.binary, Path)
            or not self.binary.is_absolute()
            or not self.binary.is_file()
            or not os.access(self.binary, os.X_OK)
        ):
            raise RunnerError("CODEX_BINARY_NOT_FOUND", str(self.binary))
        if not self.workspace.is_absolute() or not self.workspace.is_dir():
            raise RunnerError("INVALID_WORKSPACE", str(self.workspace))
        if not self.prompt:
            raise RunnerError("EMPTY_PROMPT")
        if self.model is not None and not self.model:
            raise RunnerError("INVALID_MODEL_CONFIGURATION")
        if self.reasoning_effort is not None and not self.reasoning_effort:
            raise RunnerError("INVALID_MODEL_CONFIGURATION")
        if self.timeout_seconds <= 0 or self.termination_grace_seconds <= 0:
            raise RunnerError("INVALID_TIMEOUT")
        if self.evidence_capture is not None:
            self.evidence_capture.validate()
            if self.ephemeral:
                raise RunnerError("EVIDENCE_CAPTURE_REQUIRES_PERSISTED_SESSION")


@dataclass(frozen=True)
class ArtifactFile:
    path: Path
    sha256: str


@dataclass(frozen=True)
class ArtifactSet:
    stdout: ArtifactFile
    stderr: ArtifactFile
    result: ArtifactFile
    metadata: ArtifactFile


@dataclass(frozen=True)
class RolloutEvidence:
    source_path: Path
    captured: ArtifactFile
    size: int
    mtime_ns: int
    mtime_utc: str
    thread_id: str


@dataclass(frozen=True)
class CodexRunResult:
    command: tuple[str, ...]
    events: tuple[dict[str, Any], ...]
    structured_result: dict[str, Any]
    exit_code: int
    timed_out: bool
    removed_environment_names: tuple[str, ...]
    artifacts: ArtifactSet
    thread_id: str | None = None
    rollout: RolloutEvidence | None = None


def build_codex_command(
    invocation: CodexInvocation,
    schema_path: Path,
    final_output_path: Path,
) -> tuple[str, ...]:
    invocation.validate()
    # Resolve a configured symlink before exec. Bundled Codex sidecars are
    # discovered relative to argv[0], so executing a symlink from another
    # directory can otherwise make a valid installation appear incomplete.
    executable = invocation.binary.resolve(strict=True)
    command = [str(executable), "-a", "never"]
    if invocation.reasoning_effort is not None:
        command.extend(
            ["-c", f'model_reasoning_effort="{invocation.reasoning_effort}"']
        )
    command.extend(["-c", "features.code_mode=false", "exec"])
    if invocation.ephemeral:
        command.append("--ephemeral")
    if invocation.ignore_user_config:
        command.append("--ignore-user-config")
    if invocation.ignore_rules:
        command.append("--ignore-rules")
    command.extend(
        ["--sandbox", invocation.sandbox, "--cd", str(invocation.workspace)]
    )
    if invocation.model is not None:
        command.extend(["--model", invocation.model])
    command.extend(
        [
            "--output-schema",
            str(schema_path),
            "--json",
            "--output-last-message",
            str(final_output_path),
            "-",
        ]
    )
    return tuple(command)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, content: bytes) -> ArtifactFile:
    path.write_bytes(content)
    return ArtifactFile(path=path, sha256=_sha256(path))


def _parse_events(stdout: bytes) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(stdout.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RunnerError("INVALID_JSONL_EVENT", f"line {line_number}") from error
        if not isinstance(value, dict):
            raise RunnerError("INVALID_JSONL_EVENT", f"line {line_number} is not an object")
        events.append(value)
    if not events:
        raise RunnerError("MISSING_JSONL_EVENTS")
    return tuple(events)


def _thread_id_from_events(
    events: Iterable[Mapping[str, Any]], *, required: bool
) -> str | None:
    identifiers = {
        value
        for event in events
        if str(event.get("type", "")).lower() == "thread.started"
        for value in [event.get("thread_id")]
        if isinstance(value, str) and value
    }
    if len(identifiers) == 1:
        return next(iter(identifiers))
    if required:
        code = "MISSING_CODEX_THREAD_ID" if not identifiers else "AMBIGUOUS_CODEX_THREAD_ID"
        raise RunnerError(code)
    return None


def _contains_exact_string(value: Any, target: str) -> bool:
    if isinstance(value, str):
        return value == target
    if isinstance(value, Mapping):
        return any(_contains_exact_string(item, target) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_exact_string(item, target) for item in value)
    return False


def _rollout_contains_thread_id(path: Path, thread_id: str) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if _contains_exact_string(record, thread_id):
                    return True
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return False


def _bounded_session_directories(
    session_root: Path, started_at_ns: int, ended_at_ns: int
) -> tuple[Path, ...]:
    dates = set()
    for value in (started_at_ns, ended_at_ns):
        seconds = value / 1_000_000_000
        dates.add(datetime.fromtimestamp(seconds).date())
        dates.add(datetime.fromtimestamp(seconds, timezone.utc).date())
    expanded = {day + timedelta(days=offset) for day in dates for offset in (-1, 0, 1)}
    return tuple(
        session_root / f"{day.year:04d}" / f"{day.month:02d}" / f"{day.day:02d}"
        for day in sorted(expanded)
    )


def _capture_rollout(
    capture: CodexEvidenceCapture,
    *,
    thread_id: str,
    started_at_ns: int,
    ended_at_ns: int,
    artifact_directory: Path,
) -> RolloutEvidence:
    root = capture.session_root.resolve(strict=True)
    named: list[Path] = []
    for directory in _bounded_session_directories(root, started_at_ns, ended_at_ns):
        if not directory.is_dir():
            continue
        named.extend(
            candidate
            for candidate in directory.glob(f"rollout-*-{thread_id}.jsonl")
            if candidate.is_file()
        )
    named = sorted({candidate.resolve(strict=True) for candidate in named})
    if not named:
        raise RunnerError("CODEX_ROLLOUT_NOT_FOUND", thread_id)
    content_matches = [
        candidate for candidate in named if _rollout_contains_thread_id(candidate, thread_id)
    ]
    if not content_matches:
        raise RunnerError("CODEX_ROLLOUT_THREAD_ID_MISMATCH", thread_id)
    slop_ns = 120 * 1_000_000_000
    timed = [
        candidate
        for candidate in content_matches
        if started_at_ns - slop_ns <= candidate.stat().st_mtime_ns <= ended_at_ns + slop_ns
    ]
    if not timed:
        raise RunnerError("CODEX_ROLLOUT_TIME_WINDOW_MISMATCH", thread_id)
    if len(timed) != 1:
        raise RunnerError("CODEX_ROLLOUT_AMBIGUOUS", thread_id)
    source = timed[0]
    stat_result = source.stat()
    raw = source.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    target = artifact_directory / f"rollout-{sha256}.jsonl"
    if target.exists():
        raise RunnerError("ARTIFACT_ALREADY_EXISTS", str(target))
    captured = _write(target, raw)
    return RolloutEvidence(
        source_path=source,
        captured=captured,
        size=len(raw),
        mtime_ns=stat_result.st_mtime_ns,
        mtime_utc=datetime.fromtimestamp(stat_result.st_mtime, timezone.utc).isoformat(),
        thread_id=thread_id,
    )


def _codex_binary_version(invocation: CodexInvocation, environment: Mapping[str, str]) -> str:
    assert invocation.binary is not None
    executable = invocation.binary.resolve(strict=True)
    try:
        completed = subprocess.run(
            [str(executable), "--version"],
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerError("CODEX_VERSION_UNAVAILABLE", str(executable)) from error
    text = (completed.stdout or completed.stderr).decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not text:
        raise RunnerError("CODEX_VERSION_UNAVAILABLE", str(executable))
    return text


def _validate_schema(value: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path}.{name} required")
        if schema.get("additionalProperties") is False:
            unexpected = set(value) - set(properties)
            if unexpected:
                raise RunnerError(
                    "STRUCTURED_RESULT_SCHEMA_MISMATCH",
                    f"{path} unexpected {sorted(unexpected)}",
                )
        for name, item in value.items():
            if name in properties:
                _validate_schema(item, properties[name], f"{path}.{name}")
    elif expected_type == "array":
        if not isinstance(value, list):
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} array")
        item_schema = schema.get("items", {})
        for index, item in enumerate(value):
            _validate_schema(item, item_schema, f"{path}[{index}]")
    elif expected_type == "string":
        if not isinstance(value, str):
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} string")
    elif expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} integer")
    elif expected_type == "boolean":
        if not isinstance(value, bool):
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} boolean")
    elif expected_type == "null":
        if value is not None:
            raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} null")
    elif expected_type is not None:
        raise RunnerError("UNSUPPORTED_OUTPUT_SCHEMA", str(expected_type))
    if "enum" in schema and value not in schema["enum"]:
        raise RunnerError("STRUCTURED_RESULT_SCHEMA_MISMATCH", f"{path} enum")


def _artifact_targets(directory: Path) -> tuple[Path, Path, Path, Path]:
    return (
        directory / "stdout.jsonl",
        directory / "stderr.log",
        directory / "result.json",
        directory / "runner-metadata.json",
    )


def run_codex(invocation: CodexInvocation) -> CodexRunResult:
    invocation.validate()
    artifact_directory = invocation.artifact_directory
    artifact_directory.mkdir(parents=True, exist_ok=True)
    targets = _artifact_targets(artifact_directory)
    if any(path.exists() for path in targets):
        raise RunnerError("ARTIFACT_ALREADY_EXISTS", str(artifact_directory))
    child_environment, removed_names = sanitize_environment(
        os.environ, invocation.extra_environment
    )
    binary_version = (
        _codex_binary_version(invocation, child_environment)
        if invocation.evidence_capture is not None
        else None
    )
    with tempfile.TemporaryDirectory(
        prefix="adcp-runner-", dir=artifact_directory.parent
    ) as temporary:
        private = Path(temporary)
        schema_path = private / "output-schema.json"
        final_output_path = private / "final-output.json"
        schema_path.write_bytes(canonical_bytes(invocation.output_schema))
        command = build_codex_command(invocation, schema_path, final_output_path)
        started_at_ns = time.time_ns()
        process = subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(
                invocation.prompt.encode("utf-8"),
                timeout=invocation.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(
                    timeout=invocation.termination_grace_seconds
                )
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        ended_at_ns = time.time_ns()

        stdout_file = _write(targets[0], stdout)
        stderr_file = _write(targets[1], stderr)
        raw_final = final_output_path.read_bytes() if final_output_path.exists() else b""
        structured: dict[str, Any] | None = None
        parse_error: RunnerError | None = None
        evidence_error: RunnerError | None = None
        thread_id: str | None = None
        rollout: RolloutEvidence | None = None
        try:
            events = _parse_events(stdout)
            thread_id = _thread_id_from_events(
                events, required=invocation.evidence_capture is not None
            )
            if not raw_final:
                raise RunnerError("MISSING_STRUCTURED_RESULT")
            parsed = json.loads(raw_final)
            if not isinstance(parsed, dict):
                raise RunnerError("INVALID_STRUCTURED_RESULT", "object required")
            _validate_schema(parsed, invocation.output_schema)
            structured = parsed
            canonical_result = canonical_bytes(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            events = tuple()
            canonical_result = raw_final
            parse_error = RunnerError("INVALID_STRUCTURED_RESULT", artifacts=None)
            parse_error.__cause__ = error
        except RunnerError as error:
            events = tuple()
            canonical_result = raw_final
            parse_error = error

        if invocation.evidence_capture is not None and thread_id is not None:
            try:
                rollout = _capture_rollout(
                    invocation.evidence_capture,
                    thread_id=thread_id,
                    started_at_ns=started_at_ns,
                    ended_at_ns=ended_at_ns,
                    artifact_directory=artifact_directory,
                )
            except RunnerError as error:
                evidence_error = error

        result_file = _write(targets[2], canonical_result)
        rollout_value = None
        if rollout is not None:
            rollout_value = {
                "source_path": str(rollout.source_path),
                "captured_path": str(rollout.captured.path),
                "sha256": rollout.captured.sha256,
                "size": rollout.size,
                "mtime_ns": rollout.mtime_ns,
                "mtime_utc": rollout.mtime_utc,
                "thread_id": rollout.thread_id,
            }
        metadata_value = {
            "command": list(command),
            "cwd": str(invocation.workspace.resolve(strict=True)),
            "binary": str(invocation.binary.resolve(strict=True)) if invocation.binary else None,
            "binary_version": binary_version,
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "started_at_ns": started_at_ns,
            "ended_at_ns": ended_at_ns,
            "thread_id": thread_id,
            "removed_environment_names": list(removed_names),
            "stdout_sha256": stdout_file.sha256,
            "stderr_sha256": stderr_file.sha256,
            "result_sha256": result_file.sha256,
            "evidence_capture": invocation.evidence_capture is not None,
            "effective_execution_config": {
                "approval_policy": "never",
                "sandbox": invocation.sandbox,
                "ephemeral": invocation.ephemeral,
                "ignore_user_config": invocation.ignore_user_config,
                "ignore_rules": invocation.ignore_rules,
                "model": invocation.model,
                "reasoning_effort": invocation.reasoning_effort,
                "features.code_mode": False,
                "unified_exec_override": None,
            },
            "rollout": rollout_value,
        }
        metadata_file = _write(targets[3], canonical_bytes(metadata_value))
        artifacts = ArtifactSet(stdout_file, stderr_file, result_file, metadata_file)
        if timed_out:
            raise RunnerError("CODEX_TIMEOUT", artifacts=artifacts)
        if process.returncode != 0:
            raise RunnerError(
                "CODEX_NONZERO_EXIT", str(process.returncode), artifacts=artifacts
            )
        if parse_error is not None:
            parse_error.artifacts = artifacts
            raise parse_error
        if evidence_error is not None:
            evidence_error.artifacts = artifacts
            raise evidence_error
        assert structured is not None
        return CodexRunResult(
            command=command,
            events=events,
            structured_result=structured,
            exit_code=process.returncode,
            timed_out=False,
            removed_environment_names=removed_names,
            artifacts=artifacts,
            thread_id=thread_id,
            rollout=rollout,
        )
